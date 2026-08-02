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
	"github.com/catgirl-systems/codex-sub-proxy/internal/envelope"
	"github.com/go-playground/validator/v10"
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
	oauthCallbackPath        = "/auth/callback"
	deviceRedirectPath       = "/deviceauth/callback"
	oauthScope               = "openid profile email offline_access api.connectors.read api.connectors.invoke"
	maxOAuthURLBytes         = 8 << 10
	maxOAuthValueBytes       = 64 << 10
	maxOAuthBodyBytes        = 64 << 10
	oauthRequestTimeout      = 15 * time.Second
	devicePollLifetime       = 15 * time.Minute
	browserCallbackLifetime  = 5 * time.Minute
	maxDeviceLifetimeSeconds = int64((1<<63 - 1) / int64(time.Second))
)

// PKCE contains the verifier and S256 challenge for one OAuth attempt.
type PKCE struct {
	Verifier  string `validate:"required,max=65536"`
	Challenge string `validate:"required,max=65536"`
}

// LoginOptions controls the standalone browser or device login flow.
type LoginOptions struct {
	Issuer             string `validate:"required,max=65536,url,issuer"`
	ClientID           string `validate:"required,max=65536"`
	CallbackPort       int    `validate:"gte=0,lte=65535"`
	Device             bool
	HTTPClient         *http.Client
	PollInterval       time.Duration `validate:"omitempty,gt=0,lte=60000000000"`
	MaxPolls           int           `validate:"gte=0"`
	OnAuthorizationURL func(string)
	OnDeviceCode       func(string, string)
}

type oauthAuthorizationRequest struct {
	Issuer      string `validate:"required,max=65536,url,issuer"`
	ClientID    string `validate:"required,max=65536"`
	RedirectURI string `validate:"required,max=65536,url"`
	PKCE        PKCE   `validate:"required"`
	State       string `validate:"required,max=65536"`
}

type oauthExchangeRequest struct {
	Issuer      string `validate:"required,max=65536,url,issuer"`
	ClientID    string `validate:"required,max=65536"`
	RedirectURI string `validate:"required,max=65536,url"`
	Code        string `validate:"required,max=65536"`
	Verifier    string `validate:"required,max=65536"`
}

type oauthCallback struct {
	Path     string `validate:"required"`
	Fragment string `validate:"max=0"`
	Host     string
	Absolute bool
	State    []string `validate:"required,len=1,dive,required,max=65536"`
	Code     []string `validate:"max=1,dive,required,max=65536"`
	Error    []string `validate:"max=1,dive,required,max=65536"`
}

var oauthValidation = func() *validator.Validate {
	instance := validator.New()
	_ = instance.RegisterValidation("issuer", issuerURLValidation)
	instance.RegisterStructValidation(loginOptionsStructValidation, LoginOptions{})
	instance.RegisterStructValidation(oauthCallbackStructValidation, oauthCallback{})
	return instance
}()

func issuerURLValidation(fl validator.FieldLevel) bool {
	issuer, ok := fl.Field().Interface().(string)
	if !ok {
		return false
	}
	parsed, err := url.Parse(issuer)
	return err == nil &&
		parsed.Host != "" &&
		(parsed.Scheme == "https" || parsed.Scheme == "http") &&
		parsed.User == nil &&
		parsed.RawQuery == "" &&
		parsed.Fragment == "" &&
		!strings.HasSuffix(issuer, "/")
}

func loginOptionsStructValidation(sl validator.StructLevel) {
	options, ok := sl.Current().Interface().(LoginOptions)
	if !ok {
		return
	}
	if options.Device && options.PollInterval <= 0 {
		sl.ReportError(options.PollInterval, "PollInterval", "PollInterval", "required_for_device", "")
	}
}

func oauthCallbackStructValidation(sl validator.StructLevel) {
	callback, ok := sl.Current().Interface().(oauthCallback)
	if !ok {
		return
	}
	if callback.Path != oauthCallbackPath {
		sl.ReportError(callback.Path, "Path", "Path", "oauth_callback_path", oauthCallbackPath)
	}
	if callback.Absolute && callback.Host != "localhost" && callback.Host != "127.0.0.1" {
		sl.ReportError(callback.Host, "Host", "Host", "oauth_callback_host", "localhost")
	}
	if (len(callback.Code) == 0) == (len(callback.Error) == 0) {
		sl.ReportError(callback.Code, "Code", "Code", "success_or_error", "")
	}
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
	input := oauthAuthorizationRequest{
		Issuer:      issuer,
		ClientID:    clientID,
		RedirectURI: redirectURI,
		PKCE:        pkce,
		State:       state,
	}
	if err := oauthValidation.Struct(input); err != nil {
		return "", fmt.Errorf("invalid OAuth authorization request: %w", err)
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

func parseOAuthCallback(rawURL, expectedState string) (string, error) {
	if len(rawURL) > maxOAuthURLBytes {
		return "", errors.New("OAuth callback is too large")
	}
	if expectedState == "" {
		return "", errors.New("OAuth state is empty")
	}
	if len(expectedState) > maxOAuthValueBytes {
		return "", errors.New("OAuth state is too large")
	}
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return "", errors.New("invalid OAuth callback URL")
	}
	query := parsed.Query()
	callback := oauthCallback{
		Path:     parsed.Path,
		Fragment: parsed.Fragment,
		Host:     parsed.Hostname(),
		Absolute: parsed.IsAbs(),
		State:    query["state"],
		Code:     query["code"],
		Error:    query["error"],
	}
	if callback.Absolute && callback.Host != "localhost" && callback.Host != "127.0.0.1" {
		return "", errors.New("invalid OAuth callback host")
	}
	if callback.Path != oauthCallbackPath || callback.Fragment != "" {
		return "", errors.New("invalid OAuth callback path")
	}
	if len(callback.State) != 1 || len(callback.State[0]) > maxOAuthValueBytes {
		return "", errors.New("OAuth callback state is missing")
	}
	if subtle.ConstantTimeCompare([]byte(callback.State[0]), []byte(expectedState)) != 1 {
		return "", errors.New("OAuth callback state mismatch")
	}
	if len(callback.Error) > 0 {
		if len(callback.Error) != 1 || strings.TrimSpace(callback.Error[0]) == "" {
			return "", errors.New("OAuth callback error is invalid")
		}
		if len(callback.Code) > 0 {
			return "", errors.New("OAuth callback success and error are both present")
		}
		if err := oauthValidation.Struct(callback); err != nil {
			return "", errors.New("invalid OAuth callback")
		}
		return "", fmt.Errorf("OAuth provider rejected login: %s", safeOAuthCode(callback.Error[0]))
	}
	if len(callback.Code) != 1 || strings.TrimSpace(callback.Code[0]) == "" {
		return "", errors.New("OAuth callback authorization code is missing")
	}
	if err := oauthValidation.Struct(callback); err != nil {
		return "", errors.New("invalid OAuth callback")
	}
	return callback.Code[0], nil
}

// ExchangeCode exchanges one authorization code for an encrypted-store-ready credential.
func ExchangeCode(ctx context.Context, client *http.Client, issuer, clientID, redirectURI, code, verifier string) (Credential, error) {
	if ctx == nil {
		return Credential{}, errors.New("OAuth exchange context is nil")
	}
	input := oauthExchangeRequest{
		Issuer:      issuer,
		ClientID:    clientID,
		RedirectURI: redirectURI,
		Code:        code,
		Verifier:    verifier,
	}
	if err := oauthValidation.Struct(input); err != nil {
		return Credential{}, fmt.Errorf("invalid OAuth exchange request: %w", err)
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
	if err := oauthValidation.Struct(options); err != nil {
		return Credential{}, fmt.Errorf("invalid OAuth login options: %w", err)
	}
	if options.Device {
		return deviceLogin(ctx, options)
	}
	return browserLogin(ctx, options)
}

// LoginAndSave logs in and stores the resulting credential in encrypted form.
func LoginAndSave(ctx context.Context, options LoginOptions, path string, keys envelope.KeySet) (Credential, error) {
	credential, err := Login(ctx, options)
	if err != nil {
		return Credential{}, err
	}
	if err := saveCredential(ctx, path, credential, keys); err != nil {
		return Credential{}, fmt.Errorf("save OAuth credential: %w", err)
	}
	return credential, nil
}

func browserLogin(ctx context.Context, options LoginOptions) (Credential, error) {
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
			code, callbackErr := parseOAuthCallback(request.URL.RequestURI(), state)
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
	issuer := options.Issuer
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
	if device.Interval < 0 || device.Interval > 60 {
		return Credential{}, errors.New("device polling interval is out of range")
	}
	if device.Interval > 0 {
		interval = time.Duration(device.Interval) * time.Second
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
		return nil, fmt.Errorf("read OAuth response: %w", err)
	}
	if len(body) > maxOAuthBodyBytes {
		return nil, errors.New("OAuth response is too large")
	}
	return body, nil
}
