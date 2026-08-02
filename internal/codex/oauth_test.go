package codex

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestGeneratePKCEUsesS256Challenge(t *testing.T) {
	pkce, err := GeneratePKCE()
	if err != nil {
		t.Fatalf("generate PKCE: %v", err)
	}
	if pkce.Verifier == "" || pkce.Challenge == "" {
		t.Fatal("PKCE values are empty")
	}
	digest := sha256.Sum256([]byte(pkce.Verifier))
	want := base64.RawURLEncoding.EncodeToString(digest[:])
	if pkce.Challenge != want {
		t.Fatalf("challenge = %q, want %q", pkce.Challenge, want)
	}
}

func TestDeviceIntervalDecodesStringAndNumber(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want deviceInterval
	}{
		{name: "number", raw: `{"device_auth_id":"id","user_code":"code","interval":7}`, want: 7},
		{name: "string", raw: `{"device_auth_id":"id","user_code":"code","interval":"7"}`, want: 7},
		{name: "zero", raw: `{"device_auth_id":"id","user_code":"code","interval":"0"}`, want: 0},
		{name: "usercode alias", raw: `{"device_auth_id":"id","usercode":"code","interval":7}`, want: 7},
		{name: "absent", raw: `{"device_auth_id":"id","user_code":"code"}`, want: 0},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var response deviceCodeResponse
			if err := json.Unmarshal([]byte(test.raw), &response); err != nil {
				t.Fatalf("decode device response: %v", err)
			}
			if response.Interval != test.want {
				t.Fatalf("interval = %d, want %d", response.Interval, test.want)
			}
			if response.UserCode != "code" {
				t.Fatalf("user code = %q, want code", response.UserCode)
			}
		})
	}
}

func TestDeviceLoginRejectsNegativeProviderInterval(t *testing.T) {
	var pollCount atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/api/accounts/deviceauth/usercode":
			writer.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(writer, `{"device_auth_id":"device-id","user_code":"ABCD-1234","interval":-1,"expires_in":900}`)
		case "/api/accounts/deviceauth/token":
			pollCount.Add(1)
			http.Error(writer, "unexpected poll", http.StatusInternalServerError)
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()

	_, err := Login(context.Background(), LoginOptions{
		Issuer:       server.URL,
		Device:       true,
		HTTPClient:   server.Client(),
		PollInterval: time.Millisecond,
		OnDeviceCode: func(string, string) {
			t.Fatal("device code callback called for invalid interval")
		},
	})
	if err == nil || !strings.Contains(err.Error(), "device polling interval is out of range") {
		t.Fatalf("negative interval error = %v", err)
	}
	if pollCount.Load() != 0 {
		t.Fatalf("token endpoint polled %d times", pollCount.Load())
	}
}

func TestDeviceLoginHonorsContextCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/api/accounts/deviceauth/usercode" {
			http.NotFound(writer, request)
			return
		}
		writer.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(writer, `{"device_auth_id":"device-id","user_code":"ABCD-1234","interval":0,"expires_in":900}`)
	}))
	defer server.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_, err := Login(ctx, LoginOptions{
		Issuer:       server.URL,
		Device:       true,
		HTTPClient:   server.Client(),
		PollInterval: 1 * time.Millisecond,
		OnDeviceCode: func(string, string) {
			cancel()
		},
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("device login error = %v, want context cancellation", err)
	}
}

func TestValidateOAuthCallbackChecksStateAndCode(t *testing.T) {
	state := "state-123"
	valid := "/auth/callback?code=authorization-code&state=" + url.QueryEscape(state)
	code, err := ValidateOAuthCallback(valid, state)
	if err != nil || code != "authorization-code" {
		t.Fatalf("valid callback = %q, %v", code, err)
	}
	cases := []struct {
		name string
		raw  string
	}{
		{"missing state", "/auth/callback?code=code"},
		{"wrong state", "/auth/callback?code=code&state=wrong"},
		{"missing code", "/auth/callback?state=state-123"},
		{"wrong path", "/other?code=code&state=state-123"},
		{"provider error", "/auth/callback?error=access_denied&error_description=private-token&state=state-123"},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			_, err := ValidateOAuthCallback(test.raw, state)
			if err == nil {
				t.Fatal("invalid callback was accepted")
			}
			if strings.Contains(err.Error(), "private-token") {
				t.Fatal("private callback description reached error")
			}
		})
	}
}

func TestExchangeCodeBuildsUsableCredential(t *testing.T) {
	idToken := testJWT(t, map[string]any{
		"https://api.openai.com/profile": map[string]string{"email": "login@example.com"},
		"https://api.openai.com/auth": map[string]any{
			"chatgpt_account_id": "workspace-login",
			"chatgpt_user_id":    "user-login",
			"chatgpt_plan_type":  "plus",
		},
	})
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/oauth/token" {
			http.NotFound(writer, request)
			return
		}
		if err := request.ParseForm(); err != nil {
			t.Fatal(err)
		}
		if request.Form.Get("grant_type") != "authorization_code" || request.Form.Get("code") != "code-123" || request.Form.Get("code_verifier") != "verifier-123" {
			t.Errorf("token form = %v", request.Form)
		}
		writer.Header().Set("Content-Type", "application/json")
		json.NewEncoder(writer).Encode(map[string]any{
			"access_token":  "access-login",
			"refresh_token": "refresh-login",
			"id_token":      idToken,
			"expires_in":    3600,
		})
	}))
	defer server.Close()

	credential, err := ExchangeCode(context.Background(), server.Client(), server.URL, "client", "http://localhost/callback", "code-123", "verifier-123")
	if err != nil {
		t.Fatalf("exchange code: %v", err)
	}
	if credential.AccessToken != "access-login" || credential.RefreshToken != "refresh-login" || credential.AccountID != "workspace-login" || credential.UserID != "user-login" {
		t.Fatalf("credential = %#v", credential)
	}
	if credential.ExpiresAt.Before(time.Now().Add(3500 * time.Second)) {
		t.Fatalf("credential expiry = %s", credential.ExpiresAt)
	}
}

func TestExchangeCodeDoesNotReturnTokenEndpointBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		http.Error(writer, `{"error":"secret-refresh-token"}`, http.StatusBadGateway)
	}))
	defer server.Close()
	_, err := ExchangeCode(context.Background(), server.Client(), server.URL, "client", "http://localhost/callback", "code", "verifier")
	if err == nil {
		t.Fatal("failed token exchange returned nil error")
	}
	if strings.Contains(err.Error(), "secret-refresh-token") {
		t.Fatal("token endpoint body reached error")
	}
}

func TestBrowserLoginValidatesCallbackAndStoresCredential(t *testing.T) {
	idToken := testJWT(t, map[string]any{
		"https://api.openai.com/auth": map[string]string{"chatgpt_account_id": "browser-workspace"},
	})
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/oauth/token" {
			http.NotFound(writer, request)
			return
		}
		writer.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(writer, `{"access_token":"browser-access","refresh_token":"browser-refresh","id_token":"`+idToken+`","expires_in":3600}`)
	}))
	defer server.Close()
	callbackDone := make(chan error, 1)
	credential, err := Login(context.Background(), LoginOptions{
		Issuer:       server.URL,
		CallbackPort: 0,
		OnAuthorizationURL: func(authorizationURL string) {
			parsed, parseErr := url.Parse(authorizationURL)
			if parseErr != nil {
				callbackDone <- parseErr
				return
			}
			redirect := parsed.Query().Get("redirect_uri")
			state := parsed.Query().Get("state")
			requestURL := redirect + "?code=browser-code&state=" + url.QueryEscape(state)
			response, requestErr := http.Get(requestURL)
			if requestErr != nil {
				callbackDone <- requestErr
				return
			}
			response.Body.Close()
			callbackDone <- nil
		},
	})
	if err != nil {
		t.Fatalf("browser login: %v", err)
	}
	if callbackErr := <-callbackDone; callbackErr != nil {
		t.Fatalf("callback request: %v", callbackErr)
	}
	if credential.AccessToken != "browser-access" || credential.AccountID != "browser-workspace" {
		t.Fatalf("credential = %#v", credential)
	}
}

func TestDeviceLoginPollsPendingAndSavesIdentity(t *testing.T) {
	idToken := testJWT(t, map[string]any{
		"https://api.openai.com/auth": map[string]string{"chatgpt_account_id": "device-workspace"},
	})
	var polls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/api/accounts/deviceauth/usercode":
			writer.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(writer, `{"device_auth_id":"device-id","user_code":"ABCD-1234","interval":"0","expires_in":900}`)
		case "/api/accounts/deviceauth/token":
			if polls.Add(1) == 1 {
				writer.WriteHeader(http.StatusForbidden)
				return
			}
			writer.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(writer, `{"authorization_code":"device-code","code_verifier":"device-verifier"}`)
		case "/oauth/token":
			writer.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(writer, `{"access_token":"device-access","refresh_token":"device-refresh","id_token":"`+idToken+`","expires_in":3600}`)
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()
	credential, err := Login(context.Background(), LoginOptions{
		Issuer:       server.URL,
		Device:       true,
		HTTPClient:   server.Client(),
		PollInterval: 1 * time.Millisecond,
		MaxPolls:     3,
		OnDeviceCode: func(string, string) {},
	})
	if err != nil {
		t.Fatalf("device login: %v", err)
	}
	if polls.Load() != 2 || credential.AccessToken != "device-access" || credential.AccountID != "device-workspace" {
		t.Fatalf("polls = %d, credential = %#v", polls.Load(), credential)
	}
}

func TestBrowserLoginStopsOnProviderErrorWithoutLeakingDescription(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	callbackDone := make(chan error, 1)
	_, err := Login(ctx, LoginOptions{
		Issuer:       "http://127.0.0.1:1",
		CallbackPort: 0,
		OnAuthorizationURL: func(authorizationURL string) {
			parsed, parseErr := url.Parse(authorizationURL)
			if parseErr != nil {
				callbackDone <- parseErr
				return
			}
			redirect := parsed.Query().Get("redirect_uri")
			state := parsed.Query().Get("state")
			response, requestErr := http.Get(redirect + "?error=access_denied&error_description=secret-description&state=" + url.QueryEscape(state))
			if requestErr != nil {
				callbackDone <- requestErr
				return
			}
			response.Body.Close()
			callbackDone <- nil
		},
	})
	if err == nil || strings.Contains(err.Error(), "secret-description") {
		t.Fatalf("provider error = %v", err)
	}
	if callbackErr := <-callbackDone; callbackErr != nil {
		t.Fatalf("callback request: %v", callbackErr)
	}
}

func TestBrowserLoginIgnoresMalformedStateMatchedCallback(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	callbackDone := make(chan error, 1)
	_, err := Login(ctx, LoginOptions{
		Issuer:       "http://127.0.0.1:1",
		CallbackPort: 0,
		OnAuthorizationURL: func(authorizationURL string) {
			parsed, parseErr := url.Parse(authorizationURL)
			if parseErr != nil {
				callbackDone <- parseErr
				return
			}
			redirect := parsed.Query().Get("redirect_uri")
			state := parsed.Query().Get("state")
			response, requestErr := http.Get(redirect + "?state=" + url.QueryEscape(state))
			if requestErr != nil {
				callbackDone <- requestErr
				return
			}
			response.Body.Close()
			callbackDone <- nil
			cancel()
		},
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("malformed callback error = %v, want context cancellation", err)
	}
	if callbackErr := <-callbackDone; callbackErr != nil {
		t.Fatalf("malformed callback request: %v", callbackErr)
	}
}

func TestBrowserLoginHonorsContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := Login(ctx, LoginOptions{
		Issuer:       "http://127.0.0.1:1",
		CallbackPort: 0,
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("browser login error = %v, want context cancellation", err)
	}
}
