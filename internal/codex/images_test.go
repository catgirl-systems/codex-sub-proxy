package codex

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/catgirl-systems/codex-sub-proxy/internal/envelope"
)

const testCodexImageDataURL = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII="

func TestImagesClientGenerateWireAndDecode(t *testing.T) {
	responseBody := readImageFixture(t, "images_generation.json")
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requests.Add(1)
		if request.Method != http.MethodPost || request.URL.Path != "/backend-api/codex/images/generations" {
			t.Errorf("request = %s %s", request.Method, request.URL.Path)
		}
		assertImageHeaders(t, request, "access-token", "account-123", "image-turn-123")
		if got := request.Header.Get("Content-Type"); got != "application/json" {
			t.Errorf("content type = %q", got)
		}
		var body CodexImageRequest
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			t.Errorf("decode request: %v", err)
		}
		if body.Model != "gpt-image-2" || body.Prompt != "fixture generated icon" || body.N != 1 ||
			body.Size != "1024x1024" || body.Quality != "standard" || body.ResponseFormat != "b64_json" {
			t.Errorf("body = %#v", body)
		}
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write(responseBody)
	}))
	defer server.Close()
	client := newTestImagesClient(t, server, "access-token", "account-123")
	result, err := client.Generate(context.Background(), CodexImageRequest{
		Model: "gpt-image-2", Prompt: "fixture generated icon", N: 1,
		Size: "1024x1024", Quality: "standard", ResponseFormat: "b64_json",
	})
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if requests.Load() != 1 || result.Created != 1738888894 || len(result.Images) != 1 {
		t.Fatalf("result = %#v, requests = %d", result, requests.Load())
	}
	if result.Images[0].MIMEType != "image/png" || len(result.Images[0].Bytes) == 0 ||
		result.Images[0].RevisedPrompt != "a synthetic generated icon" {
		t.Fatalf("image = %#v", result.Images[0])
	}
	if result.Usage == nil || result.Usage.TotalTokens != 11 || result.Usage.InputTokensDetails == nil ||
		result.Usage.OutputTokensDetails == nil {
		t.Fatalf("usage = %#v", result.Usage)
	}
}

func TestImagesClientEditWireAndDecode(t *testing.T) {
	responseBody := readImageFixture(t, "images_edit.json")
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/backend-api/codex/images/edits" {
			t.Errorf("path = %q", request.URL.Path)
		}
		assertImageHeaders(t, request, "access-token", "account-123", "image-turn-123")
		var body CodexImageRequest
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			t.Errorf("decode request: %v", err)
		}
		if body.Model != "gpt-image-2" || body.Prompt != "fixture edited icon" || body.N != 1 ||
			body.Size != "1024x1024" || body.Quality != "standard" || body.ResponseFormat != "b64_json" ||
			len(body.Images) != 1 || body.Images[0] != testCodexImageDataURL {
			t.Errorf("body = %#v", body)
		}
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write(responseBody)
	}))
	defer server.Close()
	client := newTestImagesClient(t, server, "access-token", "account-123")
	result, err := client.Edit(context.Background(), CodexImageRequest{
		Model: "gpt-image-2", Prompt: "fixture edited icon", N: 1,
		Size: "1024x1024", Quality: "standard", ResponseFormat: "b64_json",
		Images: []string{testCodexImageDataURL},
	})
	if err != nil {
		t.Fatalf("edit: %v", err)
	}
	if len(result.Images) != 1 || result.Images[0].MIMEType != "image/png" || len(result.Images[0].Bytes) == 0 {
		t.Fatalf("result = %#v", result)
	}
}

func TestImagesClientRefreshesOnceAfterUnauthorized(t *testing.T) {
	responseBody := readImageFixture(t, "images_generation.json")
	var imageRequests, refreshRequests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/backend-api/codex/images/generations":
			imageRequests.Add(1)
			if request.Header.Get(AuthorizationHeader) == "Bearer old-access" {
				writer.WriteHeader(http.StatusUnauthorized)
				_, _ = io.WriteString(writer, `{"error":{"code":"unauthorized","message":"private image secret"}}`)
				return
			}
			if request.Header.Get(AuthorizationHeader) != "Bearer new-access" {
				t.Errorf("authorization = %q", request.Header.Get(AuthorizationHeader))
			}
			writer.Header().Set("Content-Type", "application/json")
			_, _ = writer.Write(responseBody)
		case "/oauth/token":
			refreshRequests.Add(1)
			if err := request.ParseForm(); err != nil || request.Form.Get("refresh_token") != "old-refresh" {
				t.Errorf("refresh form = %v", request.Form)
			}
			writer.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(writer, `{"access_token":"new-access","refresh_token":"new-refresh","expires_in":3600,"account_id":"account-123"}`)
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()
	path := filepath.Join(t.TempDir(), "credential.enc")
	keys := testCredentialKeys(t)
	if err := SaveCredential(path, Credential{
		AccessToken: "old-access", RefreshToken: "old-refresh", ExpiresAt: time.Now().Add(time.Hour), AccountID: "account-123",
	}, keys); err != nil {
		t.Fatal(err)
	}
	refresher, err := NewRefresher(path, keys, RefresherOptions{Issuer: server.URL, HTTPClient: server.Client()})
	if err != nil {
		t.Fatal(err)
	}
	client, err := NewImagesClient(ImagesClientOptions{
		GenerationsURL: server.URL + "/backend-api/codex/images/generations",
		EditsURL:       server.URL + "/backend-api/codex/images/edits",
		HTTPClient:     server.Client(), Refresher: refresher,
		Headers: HeaderConfig{ImageTurnID: "image-turn-123"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Generate(context.Background(), CodexImageRequest{Model: "gpt-image-2", Prompt: "rotate"}); err != nil {
		t.Fatalf("generate after refresh: %v", err)
	}
	if imageRequests.Load() != 2 || refreshRequests.Load() != 1 {
		t.Fatalf("image requests = %d, refresh requests = %d", imageRequests.Load(), refreshRequests.Load())
	}
}

func TestImagesClientRejectsInvalidInputBeforeDispatch(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requests.Add(1)
		writer.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()
	client := newTestImagesClient(t, server, "access-token", "account-123")
	tests := []struct {
		name    string
		edit    bool
		request CodexImageRequest
	}{
		{name: "model", request: CodexImageRequest{Model: "gpt-image-1", Prompt: "x"}},
		{name: "prompt", request: CodexImageRequest{Model: "gpt-image-2"}},
		{name: "count", request: CodexImageRequest{Model: "gpt-image-2", Prompt: "x", N: maxCodexImageCount + 1}},
		{name: "quality", request: CodexImageRequest{Model: "gpt-image-2", Prompt: "x", Quality: "extreme"}},
		{name: "size", request: CodexImageRequest{Model: "gpt-image-2", Prompt: "x", Size: "17x17"}},
		{name: "background", request: CodexImageRequest{Model: "gpt-image-2", Prompt: "x", Background: "transparent"}},
		{name: "output format", request: CodexImageRequest{Model: "gpt-image-2", Prompt: "x", OutputFormat: "gif"}},
		{name: "response format", request: CodexImageRequest{Model: "gpt-image-2", Prompt: "x", ResponseFormat: "url"}},
		{name: "generation image", request: CodexImageRequest{Model: "gpt-image-2", Prompt: "x", Image: testCodexImageDataURL}},
		{name: "edit no image", edit: true, request: CodexImageRequest{Model: "gpt-image-2", Prompt: "x"}},
		{name: "edit too many", edit: true, request: CodexImageRequest{Model: "gpt-image-2", Prompt: "x", Images: []string{testCodexImageDataURL, testCodexImageDataURL, testCodexImageDataURL, testCodexImageDataURL, testCodexImageDataURL, testCodexImageDataURL}}},
		{name: "edit bad base64", edit: true, request: CodexImageRequest{Model: "gpt-image-2", Prompt: "x", Images: []string{"data:image/png;base64,not-base64"}}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var err error
			if test.edit {
				_, err = client.Edit(context.Background(), test.request)
			} else {
				_, err = client.Generate(context.Background(), test.request)
			}
			if err == nil {
				t.Fatal("invalid request returned no error")
			}
		})
	}
	if requests.Load() != 0 {
		t.Fatalf("invalid requests reached upstream: %d", requests.Load())
	}
}

func TestImagesClientRejectsMalformedAndOversizedOutput(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{name: "malformed JSON", body: "{"},
		{name: "bad base64", body: `{"data":[{"b64_json":"not-base64"}]}`},
		{name: "non-image base64", body: `{"data":[{"b64_json":"aGVsbG8="}]}`},
		{name: "too many images", body: `{"data":[{"b64_json":"` + testCodexImageDataURL[len("data:image/png;base64,"):] + `"},{"b64_json":"` + testCodexImageDataURL[len("data:image/png;base64,"):] + `"},{"b64_json":"` + testCodexImageDataURL[len("data:image/png;base64,"):] + `"},{"b64_json":"` + testCodexImageDataURL[len("data:image/png;base64,"):] + `"},{"b64_json":"` + testCodexImageDataURL[len("data:image/png;base64,"):] + `"},{"b64_json":"` + testCodexImageDataURL[len("data:image/png;base64,"):] + `"}]}`},
		{name: "oversized body", body: strings.Repeat("x", maxCodexImageResponseBytes+1)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				_, _ = io.WriteString(writer, test.body)
			}))
			defer server.Close()
			client := newTestImagesClient(t, server, "access-token", "account-123")
			_, err := client.Generate(context.Background(), CodexImageRequest{Model: "gpt-image-2", Prompt: "x"})
			if err == nil {
				t.Fatal("invalid response returned no error")
			}
		})
	}
}

func TestImagesClientMapsProviderErrorWithoutBodyLeak(t *testing.T) {
	secret := "private-image-provider-secret"
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("X-Request-ID", "request-123")
		writer.WriteHeader(http.StatusTooManyRequests)
		_, _ = io.WriteString(writer, `{"error":{"code":"rate_limit_exceeded","message":"`+secret+`"}}`)
	}))
	defer server.Close()
	client := newTestImagesClient(t, server, "access-token", "account-123")
	_, err := client.Generate(context.Background(), CodexImageRequest{Model: "gpt-image-2", Prompt: "x"})
	var safeError *SafeError
	if err == nil || !errors.As(err, &safeError) || safeError.Category != CategoryRateLimit ||
		strings.Contains(err.Error(), secret) {
		t.Fatalf("error = %v", err)
	}
}

func TestImagesClientCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		select {
		case <-request.Context().Done():
		case <-time.After(100 * time.Millisecond):
		}
		writer.WriteHeader(http.StatusRequestTimeout)
	}))
	defer server.Close()
	client := newTestImagesClient(t, server, "access-token", "account-123")
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	_, err := client.Generate(ctx, CodexImageRequest{Model: "gpt-image-2", Prompt: "x"})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("error = %v", err)
	}
}

func TestImagesClientLiveOptIn(t *testing.T) {
	if os.Getenv("CSP_LIVE_CODEX_IMAGES") != "1" {
		t.Skip("set CSP_LIVE_CODEX_IMAGES=1 to run the live Codex Images check")
	}
	credentialPath := strings.TrimSpace(os.Getenv("CSP_CODEX_CREDENTIAL_FILE"))
	keyValue := os.Getenv("CSP_CREDENTIAL_ENCRYPTION_KEY")
	if credentialPath == "" || keyValue == "" {
		t.Skip("set CSP_CODEX_CREDENTIAL_FILE and CSP_CREDENTIAL_ENCRYPTION_KEY for the live check")
	}
	keys, err := newLiveCredentialKeys(keyValue)
	if err != nil {
		t.Skip("CSP_CREDENTIAL_ENCRYPTION_KEY is not a usable credential key")
	}
	refresher, err := NewRefresher(credentialPath, keys, RefresherOptions{})
	if err != nil {
		t.Fatal(err)
	}
	client, err := NewImagesClient(ImagesClientOptions{
		Refresher: refresher,
		Headers:   HeaderConfig{ImageTurnID: "csp-live-image-turn"},
	})
	if err != nil {
		t.Fatal(err)
	}
	generation, err := client.Generate(context.Background(), CodexImageRequest{
		Model: "gpt-image-2", Prompt: "a small synthetic blue square", N: 1,
		Size: "1024x1024", Quality: "standard",
	})
	if err != nil {
		t.Fatalf("live generation: %v", err)
	}
	if len(generation.Images) != 1 || generation.Images[0].MIMEType == "" || len(generation.Images[0].Bytes) == 0 {
		t.Fatalf("live generation result has no detected image")
	}
	edit, err := client.Edit(context.Background(), CodexImageRequest{
		Model: "gpt-image-2", Prompt: "add one small white dot", N: 1,
		Size: "1024x1024", Quality: "standard",
		Images: []string{"data:" + generation.Images[0].MIMEType + ";base64," + encodeLiveImage(generation.Images[0].Bytes)},
	})
	if err != nil {
		t.Fatalf("live edit: %v", err)
	}
	if len(edit.Images) != 1 || edit.Images[0].MIMEType == "" || len(edit.Images[0].Bytes) == 0 {
		t.Fatalf("live edit result has no detected image")
	}
}

func assertImageHeaders(t *testing.T, request *http.Request, accessToken, accountID, imageTurnID string) {
	t.Helper()
	for name, want := range map[string]string{
		AuthorizationHeader: "Bearer " + accessToken,
		AccountIDHeader:     accountID,
		BetaHeader:          DefaultBeta,
		OriginatorHeader:    DefaultOriginator,
		VersionHeader:       DefaultVersion,
		ImageTurnIDHeader:   imageTurnID,
	} {
		if got := request.Header.Get(name); got != want {
			t.Errorf("header %s = %q, want %q", name, got, want)
		}
	}
}

func newTestImagesClient(t *testing.T, server *httptest.Server, accessToken, accountID string) *ImagesClient {
	t.Helper()
	path := filepath.Join(t.TempDir(), "credential.enc")
	keys := testCredentialKeys(t)
	if err := SaveCredential(path, Credential{
		AccessToken: accessToken, RefreshToken: "refresh-token", ExpiresAt: time.Now().Add(time.Hour), AccountID: accountID,
	}, keys); err != nil {
		t.Fatal(err)
	}
	refresher, err := NewRefresher(path, keys, RefresherOptions{HTTPClient: server.Client()})
	if err != nil {
		t.Fatal(err)
	}
	client, err := NewImagesClient(ImagesClientOptions{
		GenerationsURL: server.URL + "/backend-api/codex/images/generations",
		EditsURL:       server.URL + "/backend-api/codex/images/edits",
		HTTPClient:     server.Client(), Refresher: refresher,
		Headers: HeaderConfig{
			ImageTurnID: "image-turn-123",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func readImageFixture(t *testing.T, name string) []byte {
	t.Helper()
	body, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func newLiveCredentialKeys(value string) (envelope.KeySet, error) {
	key, err := envelope.NewKey(1, []byte(value))
	if err != nil {
		return envelope.KeySet{}, err
	}
	return envelope.NewKeySet(key)
}

func encodeLiveImage(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}
