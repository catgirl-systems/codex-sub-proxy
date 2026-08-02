package codex

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	defaultIssuer            = "https://auth.openai.com"
	defaultClientID          = "app_EMoamEEZ73f0CkXaXp7hrann"
	defaultCallbackPort      = 1455
	oauthCallbackPath        = "/auth/callback"
	deviceRedirectPath       = "/deviceauth/callback"
	oauthScope               = "openid profile email offline_access api.connectors.read api.connectors.invoke"
	maxOAuthURLBytes         = 8 << 10
	maxOAuthValueBytes       = 64 << 10
	maxOAuthBodyBytes        = 64 << 10
	oauthRequestTimeout      = 15 * time.Second
	devicePollInterval       = 5 * time.Second
	devicePollLifetime       = 15 * time.Minute
	browserCallbackLifetime  = 5 * time.Minute
	maxDeviceLifetimeSeconds = int64((1<<63 - 1) / int64(time.Second))
)

// PKCE contains the verifier and S256 challenge for one OAuth attempt.
type PKCE struct {
	Verifier  string
	Challenge string
}

// LoginOptions controls the standalone browser or device login flow.
type LoginOptions struct {
	Issuer             string
	ClientID           string
	CallbackPort       int
	Device             bool
	HTTPClient         *http.Client
	PollInterval       time.Duration
	MaxPolls           int
	OnAuthorizationURL func(string)
	OnDeviceCode       func(string, string)
}

type tokenResponse struct {
	AccessToken      string `json:"access_token"`
	RefreshToken     string `json:"refresh_token"`
	IDToken          string `json:"id_token"`
	ExpiresIn        int64  `json:"expires_in"`
	AccountID        string `json:"account_id"`
	UserID           string `json:"user_id"`
	WorkspaceID      string `json:"workspace_id"`
	PlanType         string `json:"plan_type"`
	AccountIsFedRAMP bool   `json:"account_is_fedramp"`
	Email            string `json:"email"`
}

type deviceInterval int64

func (interval *deviceInterval) UnmarshalJSON(data []byte) error {
	value := strings.TrimSpace(string(data))
	if value == "" || value == "null" {
		*interval = 0
		return nil
	}
	if strings.HasPrefix(value, `"`) {
		var text string
		if err := json.Unmarshal(data, &text); err != nil {
			return errors.New("invalid device polling interval")
		}
		value = strings.TrimSpace(text)
	}
	parsed, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return errors.New("invalid device polling interval")
	}
	*interval = deviceInterval(parsed)
	return nil
}

type deviceCodeResponse struct {
	DeviceAuthID string         `json:"device_auth_id"`
	UserCode     string         `json:"user_code"`
	Interval     deviceInterval `json:"interval"`
	ExpiresIn    int64          `json:"expires_in"`
}

func (response *deviceCodeResponse) UnmarshalJSON(data []byte) error {
	var decoded struct {
		DeviceAuthID string         `json:"device_auth_id"`
		UserCode     string         `json:"user_code"`
		UserCodeAlt  string         `json:"usercode"`
		Interval     deviceInterval `json:"interval"`
		ExpiresIn    int64          `json:"expires_in"`
	}
	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}
	response.DeviceAuthID = decoded.DeviceAuthID
	response.UserCode = decoded.UserCode
	if strings.TrimSpace(response.UserCode) == "" {
		response.UserCode = decoded.UserCodeAlt
	}
	response.Interval = decoded.Interval
	response.ExpiresIn = decoded.ExpiresIn
	return nil
}

type deviceTokenResponse struct {
	AuthorizationCode string `json:"authorization_code"`
	CodeVerifier      string `json:"code_verifier"`
}

type callbackResult struct {
	code string
	err  error
}

// GeneratePKCE creates a cryptographically random verifier and S256 challenge.
func GeneratePKCE() (PKCE, error) {
	verifierBytes := make([]byte, 32)
	if _, err := rand.Read(verifierBytes); err != nil {
		return PKCE{}, fmt.Errorf("generate PKCE verifier: %w", err)
	}
	verifier := base64.RawURLEncoding.EncodeToString(verifierBytes)
	digest := sha256.Sum256([]byte(verifier))
	return PKCE{Verifier: verifier, Challenge: base64.RawURLEncoding.EncodeToString(digest[:])}, nil
}

// GenerateOAuthState creates the state value used to bind a callback to a login.
func GenerateOAuthState() (string, error) {
	stateBytes := make([]byte, 32)
	if _, err := rand.Read(stateBytes); err != nil {
		return "", fmt.Errorf("generate OAuth state: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(stateBytes), nil
}

// BuildAuthorizationURL builds the Codex browser authorization URL.
func BuildAuthorizationURL(issuer, clientID, redirectURI string, pkce PKCE, state string) (string, error) {
	issuer, err := validateIssuer(issuer)
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(clientID) == "" {
		return "", errors.New("OAuth client ID is empty")
	}
	if len(clientID) > maxOAuthValueBytes {
		return "", errors.New("OAuth client ID is too large")
	}
	if strings.TrimSpace(redirectURI) == "" {
		return "", errors.New("OAuth redirect URI is empty")
	}
	if len(redirectURI) > maxOAuthValueBytes {
		return "", errors.New("OAuth redirect URI is too large")
	}
	if pkce.Verifier == "" || pkce.Challenge == "" {
		return "", errors.New("PKCE values are empty")
	}
	if strings.TrimSpace(state) == "" {
		return "", errors.New("OAuth state is empty")
	}
	if len(state) > maxOAuthValueBytes {
		return "", errors.New("OAuth state is too large")
	}
	query := url.Values{
		"response_type":              {"code"},
		"client_id":                  {clientID},
		"redirect_uri":               {redirectURI},
		"scope":                      {oauthScope},
		"code_challenge":             {pkce.Challenge},
		"code_challenge_method":      {"S256"},
		"id_token_add_organizations": {"true"},
		"codex_cli_simplified_flow":  {"true"},
		"state":                      {state},
		"originator":                 {"pi"},
	}
	authorizationURL := issuer + "/oauth/authorize?" + query.Encode()
	if len(authorizationURL) > maxOAuthURLBytes {
		return "", errors.New("OAuth authorization URL is too large")
	}
	return authorizationURL, nil
}

// ValidateOAuthCallback checks the callback path, state, and authorization code.
func ValidateOAuthCallback(rawURL, expectedState string) (string, error) {
	if len(rawURL) > maxOAuthURLBytes {
		return "", errors.New("OAuth callback is too large")
	}
	if strings.TrimSpace(expectedState) == "" {
		return "", errors.New("OAuth state is empty")
	}
	if len(expectedState) > maxOAuthValueBytes {
		return "", errors.New("OAuth state is too large")
	}
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return "", errors.New("invalid OAuth callback URL")
	}
	if parsed.IsAbs() && parsed.Hostname() != "localhost" && parsed.Hostname() != "127.0.0.1" {
		return "", errors.New("invalid OAuth callback host")
	}
	if parsed.Path != oauthCallbackPath || parsed.Fragment != "" {
		return "", errors.New("invalid OAuth callback path")
	}
	query := parsed.Query()
	states, ok := query["state"]
	if !ok || len(states) != 1 || len(states[0]) > maxOAuthValueBytes {
		return "", errors.New("OAuth callback state is missing")
	}
	if subtle.ConstantTimeCompare([]byte(states[0]), []byte(expectedState)) != 1 {
		return "", errors.New("OAuth callback state mismatch")
	}
	if errorValues := query["error"]; len(errorValues) > 0 {
		if len(errorValues) != 1 || strings.TrimSpace(errorValues[0]) == "" {
			return "", errors.New("OAuth callback error is invalid")
		}
		return "", fmt.Errorf("OAuth provider rejected login: %s", safeOAuthCode(errorValues[0]))
	}
	codes, ok := query["code"]
	if !ok || len(codes) != 1 || strings.TrimSpace(codes[0]) == "" {
		return "", errors.New("OAuth callback authorization code is missing")
	}
	if len(codes[0]) > maxOAuthValueBytes {
		return "", errors.New("OAuth callback authorization code is too large")
	}
	return codes[0], nil
}

// ExchangeCode exchanges one authorization code for an encrypted-store-ready credential.
func ExchangeCode(ctx context.Context, client *http.Client, issuer, clientID, redirectURI, code, verifier string) (Credential, error) {
	if ctx == nil {
		return Credential{}, errors.New("OAuth exchange context is nil")
	}
	issuer, err := validateIssuer(issuer)
	if err != nil {
		return Credential{}, err
	}
	if strings.TrimSpace(clientID) == "" {
		return Credential{}, errors.New("OAuth client ID is empty")
	}
	if len(clientID) > maxOAuthValueBytes {
		return Credential{}, errors.New("OAuth client ID is too large")
	}
	if strings.TrimSpace(redirectURI) == "" {
		return Credential{}, errors.New("OAuth redirect URI is empty")
	}
	if len(redirectURI) > maxOAuthValueBytes {
		return Credential{}, errors.New("OAuth redirect URI is too large")
	}
	if strings.TrimSpace(code) == "" {
		return Credential{}, errors.New("OAuth authorization code is empty")
	}
	if len(code) > maxOAuthValueBytes {
		return Credential{}, errors.New("OAuth authorization code is too large")
	}
	if strings.TrimSpace(verifier) == "" {
		return Credential{}, errors.New("OAuth PKCE verifier is empty")
	}
	if len(verifier) > maxOAuthValueBytes {
		return Credential{}, errors.New("OAuth PKCE verifier is too large")
	}
	values := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {clientID},
		"code":          {code},
		"code_verifier": {verifier},
		"redirect_uri":  {redirectURI},
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, issuer+"/oauth/token", strings.NewReader(values.Encode()))
	if err != nil {
		return Credential{}, fmt.Errorf("build OAuth token request: %w", err)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, err := oauthClient(client).Do(request)
	if err != nil {
		return Credential{}, fmt.Errorf("OAuth token exchange: %w", err)
	}
	defer response.Body.Close()
	body, err := readOAuthBody(response.Body)
	if err != nil {
		return Credential{}, err
	}
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return Credential{}, fmt.Errorf("OAuth token endpoint returned status %d", response.StatusCode)
	}
	var token tokenResponse
	if err := json.Unmarshal(body, &token); err != nil {
		return Credential{}, errors.New("invalid OAuth token response")
	}
	if token.ExpiresIn <= 0 || token.ExpiresIn > 365*24*60*60 {
		return Credential{}, errors.New("OAuth token expiry is out of range")
	}
	return buildCredential(token.AccessToken, token.RefreshToken, token.IDToken, time.Now().Add(time.Duration(token.ExpiresIn)*time.Second), token.AccountID, token.UserID, token.WorkspaceID, token.PlanType, token.AccountIsFedRAMP, token.Email, true)
}

// Login runs the standalone browser or device OAuth flow.
func Login(ctx context.Context, options LoginOptions) (Credential, error) {
	if ctx == nil {
		return Credential{}, errors.New("OAuth login context is nil")
	}
	options = normalizeLoginOptions(options)
	if options.Device {
		return deviceLogin(ctx, options)
	}
	return browserLogin(ctx, options)
}

// LoginAndSave logs in and stores the resulting credential in encrypted form.
func LoginAndSave(ctx context.Context, options LoginOptions, path string, key []byte) (Credential, error) {
	credential, err := Login(ctx, options)
	if err != nil {
		return Credential{}, err
	}
	if err := SaveCredential(path, credential, key); err != nil {
		return Credential{}, fmt.Errorf("save OAuth credential: %w", err)
	}
	return credential, nil
}

func normalizeLoginOptions(options LoginOptions) LoginOptions {
	if strings.TrimSpace(options.Issuer) == "" {
		options.Issuer = defaultIssuer
	}
	if strings.TrimSpace(options.ClientID) == "" {
		options.ClientID = defaultClientID
	}
	if options.CallbackPort == 0 && !options.Device {
		options.CallbackPort = defaultCallbackPort
	}
	if options.PollInterval <= 0 {
		options.PollInterval = devicePollInterval
	}
	if options.PollInterval > time.Minute {
		options.PollInterval = time.Minute
	}
	if options.MaxPolls < 0 {
		options.MaxPolls = 0
	}
	return options
}

func browserLogin(ctx context.Context, options LoginOptions) (Credential, error) {
	if options.CallbackPort < 0 || options.CallbackPort > 65535 {
		return Credential{}, errors.New("OAuth callback port is invalid")
	}
	pkce, err := GeneratePKCE()
	if err != nil {
		return Credential{}, err
	}
	state, err := GenerateOAuthState()
	if err != nil {
		return Credential{}, err
	}
	listener, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", options.CallbackPort))
	if err != nil {
		return Credential{}, fmt.Errorf("listen for OAuth callback: %w", err)
	}
	actualPort := listener.Addr().(*net.TCPAddr).Port
	redirectURI := fmt.Sprintf("http://localhost:%d%s", actualPort, oauthCallbackPath)
	authorizationURL, err := BuildAuthorizationURL(options.Issuer, options.ClientID, redirectURI, pkce, state)
	if err != nil {
		_ = listener.Close()
		return Credential{}, err
	}

	callbackContext, cancel := context.WithTimeout(ctx, browserCallbackLifetime)
	defer cancel()
	resultChannel := make(chan callbackResult, 1)
	server := &http.Server{
		Handler: http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			if request.Method != http.MethodGet {
				writer.Header().Set("Allow", http.MethodGet)
				http.Error(writer, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			if len(request.RequestURI) > maxOAuthURLBytes {
				http.Error(writer, "callback too large", http.StatusRequestURITooLong)
				return
			}
			code, callbackErr := ValidateOAuthCallback(request.URL.RequestURI(), state)
			if callbackErr != nil {
				http.Error(writer, callbackErr.Error(), http.StatusBadRequest)
				if callbackStateMatches(request.URL, state) && callbackHasProviderError(request.URL) {
					select {
					case resultChannel <- callbackResult{err: callbackErr}:
					default:
					}
				}
				return
			}
			writer.Header().Set("Content-Type", "text/plain; charset=utf-8")
			_, _ = io.WriteString(writer, "login complete\n")
			select {
			case resultChannel <- callbackResult{code: code}:
			default:
			}
		}),
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       30 * time.Second,
	}
	serveDone := make(chan error, 1)
	go func() { serveDone <- server.Serve(listener) }()

	if options.OnAuthorizationURL != nil {
		options.OnAuthorizationURL(authorizationURL)
	} else {
		fmt.Fprintln(os.Stdout, authorizationURL)
	}

	var result callbackResult
	select {
	case result = <-resultChannel:
	case <-callbackContext.Done():
		result.err = callbackContext.Err()
	}
	shutdownContext, cancel := context.WithTimeout(context.Background(), time.Second)
	_ = server.Shutdown(shutdownContext)
	cancel()
	<-serveDone
	if result.err != nil {
		return Credential{}, result.err
	}
	return ExchangeCode(ctx, options.HTTPClient, options.Issuer, options.ClientID, redirectURI, result.code, pkce.Verifier)
}

func deviceLogin(ctx context.Context, options LoginOptions) (Credential, error) {
	issuer, err := validateIssuer(options.Issuer)
	if err != nil {
		return Credential{}, err
	}
	initBody, err := json.Marshal(struct {
		ClientID string `json:"client_id"`
	}{options.ClientID})
	if err != nil {
		return Credential{}, errors.New("encode device authorization request")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, issuer+"/api/accounts/deviceauth/usercode", bytes.NewReader(initBody))
	if err != nil {
		return Credential{}, fmt.Errorf("build device authorization request: %w", err)
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := oauthClient(options.HTTPClient).Do(request)
	if err != nil {
		return Credential{}, fmt.Errorf("device authorization request: %w", err)
	}
	body, bodyErr := readAndCloseOAuthBody(response)
	if bodyErr != nil {
		return Credential{}, bodyErr
	}
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return Credential{}, fmt.Errorf("device authorization endpoint returned status %d", response.StatusCode)
	}
	var device deviceCodeResponse
	if err := json.Unmarshal(body, &device); err != nil || strings.TrimSpace(device.DeviceAuthID) == "" || strings.TrimSpace(device.UserCode) == "" {
		return Credential{}, errors.New("invalid device authorization response")
	}
	if device.ExpiresIn < 0 || device.ExpiresIn > maxDeviceLifetimeSeconds {
		return Credential{}, errors.New("device authorization lifetime is out of range")
	}
	interval := options.PollInterval
	if device.Interval > 60 {
		return Credential{}, errors.New("device polling interval is out of range")
	}
	if device.Interval > 0 {
		interval = time.Duration(device.Interval) * time.Second
	}
	if interval <= 0 {
		interval = devicePollInterval
	}
	lifetime := devicePollLifetime
	if device.ExpiresIn > 0 {
		lifetime = time.Duration(device.ExpiresIn) * time.Second
	}
	pollContext, cancel := context.WithTimeout(ctx, lifetime)
	defer cancel()
	if options.OnDeviceCode != nil {
		options.OnDeviceCode(issuer+"/codex/device", device.UserCode)
	} else {
		fmt.Fprintf(os.Stdout, "Open %s and enter the displayed code.\n", issuer+"/codex/device")
		fmt.Fprintln(os.Stdout, device.UserCode)
	}

	polls := 0
	for {
		if options.MaxPolls > 0 && polls >= options.MaxPolls {
			return Credential{}, errors.New("device authorization timed out")
		}
		timer := time.NewTimer(interval)
		select {
		case <-timer.C:
		case <-pollContext.Done():
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			if err := ctx.Err(); err != nil {
				return Credential{}, err
			}
			return Credential{}, errors.New("device authorization timed out")
		}
		polls++
		pollBody, err := json.Marshal(struct {
			DeviceAuthID string `json:"device_auth_id"`
			UserCode     string `json:"user_code"`
		}{device.DeviceAuthID, device.UserCode})
		if err != nil {
			return Credential{}, errors.New("encode device token request")
		}
		pollRequest, err := http.NewRequestWithContext(pollContext, http.MethodPost, issuer+"/api/accounts/deviceauth/token", bytes.NewReader(pollBody))
		if err != nil {
			return Credential{}, fmt.Errorf("build device token request: %w", err)
		}
		pollRequest.Header.Set("Content-Type", "application/json")
		pollResponse, err := oauthClient(options.HTTPClient).Do(pollRequest)
		if err != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return Credential{}, ctxErr
			}
			if pollContext.Err() != nil {
				return Credential{}, errors.New("device authorization timed out")
			}
			return Credential{}, fmt.Errorf("device token request: %w", err)
		}
		pollBodyBytes, bodyErr := readAndCloseOAuthBody(pollResponse)
		if bodyErr != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return Credential{}, ctxErr
			}
			if pollContext.Err() != nil {
				return Credential{}, errors.New("device authorization timed out")
			}
			return Credential{}, bodyErr
		}
		if pollResponse.StatusCode == http.StatusForbidden || pollResponse.StatusCode == http.StatusNotFound {
			continue
		}
		if pollResponse.StatusCode < http.StatusOK || pollResponse.StatusCode >= http.StatusMultipleChoices {
			return Credential{}, fmt.Errorf("device token endpoint returned status %d", pollResponse.StatusCode)
		}
		var token deviceTokenResponse
		if err := json.Unmarshal(pollBodyBytes, &token); err != nil || strings.TrimSpace(token.AuthorizationCode) == "" || strings.TrimSpace(token.CodeVerifier) == "" {
			return Credential{}, errors.New("invalid device token response")
		}
		return ExchangeCode(pollContext, options.HTTPClient, issuer, options.ClientID, issuer+deviceRedirectPath, token.AuthorizationCode, token.CodeVerifier)
	}
}

func validateIssuer(issuer string) (string, error) {
	issuer = strings.TrimRight(strings.TrimSpace(issuer), "/")
	parsed, err := url.Parse(issuer)
	if err != nil || parsed.Host == "" || (parsed.Scheme != "https" && parsed.Scheme != "http") || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", errors.New("OAuth issuer URL is invalid")
	}
	return issuer, nil
}

func callbackStateMatches(parsed *url.URL, expectedState string) bool {
	if parsed == nil {
		return false
	}
	states := parsed.Query()["state"]
	return len(states) == 1 && subtle.ConstantTimeCompare([]byte(states[0]), []byte(expectedState)) == 1
}

func callbackHasProviderError(parsed *url.URL) bool {
	if parsed == nil {
		return false
	}
	for _, value := range parsed.Query()["error"] {
		if strings.TrimSpace(value) != "" {
			return true
		}
	}
	return false
}

func safeOAuthCode(value string) string {
	value = strings.TrimSpace(value)
	if len(value) > 64 || value == "" {
		return "provider_error"
	}
	for _, character := range value {
		if (character < 'a' || character > 'z') && (character < 'A' || character > 'Z') && (character < '0' || character > '9') && character != '_' && character != '-' && character != '.' {
			return "provider_error"
		}
	}
	return value
}

func oauthClient(client *http.Client) *http.Client {
	if client == nil {
		return &http.Client{Timeout: oauthRequestTimeout, CheckRedirect: noOAuthRedirect}
	}
	copy := *client
	if copy.Timeout == 0 {
		copy.Timeout = oauthRequestTimeout
	}
	copy.CheckRedirect = noOAuthRedirect
	return &copy
}

func noOAuthRedirect(_ *http.Request, _ []*http.Request) error {
	return http.ErrUseLastResponse
}

func readAndCloseOAuthBody(response *http.Response) ([]byte, error) {
	if response == nil || response.Body == nil {
		return nil, errors.New("OAuth response body is missing")
	}
	defer response.Body.Close()
	return readOAuthBody(response.Body)
}

func readOAuthBody(reader io.Reader) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(reader, maxOAuthBodyBytes+1))
	if err != nil {
		return nil, errors.New("read OAuth response")
	}
	if len(body) > maxOAuthBodyBytes {
		return nil, errors.New("OAuth response is too large")
	}
	return body, nil
}
