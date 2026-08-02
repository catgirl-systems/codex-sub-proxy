package codex

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/catgirl-systems/codex-sub-proxy/internal/envelope"
)

const refreshSkew = 5 * time.Minute

// CredentialStatus describes the current credential state without secret data.
type CredentialStatus string

const (
	CredentialStatusMissing          CredentialStatus = "missing"
	CredentialStatusCurrent          CredentialStatus = "current"
	CredentialStatusRefreshable      CredentialStatus = "refreshable"
	CredentialStatusExpired          CredentialStatus = "expired"
	CredentialStatusRefreshing       CredentialStatus = "refreshing"
	CredentialStatusTransientFailure CredentialStatus = "transient_failure"
	CredentialStatusPermanentFailure CredentialStatus = "permanent_failure"
)

// RefresherOptions selects the OAuth endpoint and HTTP client.
type RefresherOptions struct {
	Issuer     string
	ClientID   string
	HTTPClient *http.Client
}

// ErrRefreshRequiresLogin means that the stored refresh token is no longer usable.
var ErrRefreshRequiresLogin = errors.New("credential refresh requires login")

// ErrRefreshTemporary means that a refresh can be tried by a later request.
var ErrRefreshTemporary = errors.New("credential refresh failed temporarily")

// RefreshError reports a safe refresh failure classification.
type RefreshError struct {
	permanent bool
	status    int
}

func (e *RefreshError) Error() string {
	if e == nil {
		return "credential refresh failed"
	}
	if e.permanent {
		return ErrRefreshRequiresLogin.Error()
	}
	return ErrRefreshTemporary.Error()
}

func (e *RefreshError) Unwrap() error {
	if e != nil && e.permanent {
		return ErrRefreshRequiresLogin
	}
	return ErrRefreshTemporary
}

// Permanent reports whether the refresh failure requires a new login.
func (e *RefreshError) Permanent() bool {
	return e != nil && e.permanent
}

// StatusCode returns the OAuth status code, or zero for a local failure.
func (e *RefreshError) StatusCode() int {
	if e == nil {
		return 0
	}
	return e.status
}

// Refresher obtains a usable credential and serializes refresh work for one file.
type Refresher struct {
	mu sync.Mutex

	path     string
	keys     envelope.KeySet
	issuer   string
	clientID string
	client   *http.Client

	inFlight       *refreshCall
	permanentToken string
	transientToken string
}

type refreshCall struct {
	done       chan struct{}
	credential Credential
	err        error
}

// NewRefresher creates a caller-driven credential refresher.
func NewRefresher(path string, keys envelope.KeySet, options RefresherOptions) (*Refresher, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, errors.New("credential path is empty")
	}
	if err := keys.Validate(); err != nil {
		return nil, err
	}
	issuer := strings.TrimSpace(options.Issuer)
	if issuer == "" {
		issuer = defaultIssuer
	}
	var err error
	issuer, err = validateIssuer(issuer)
	if err != nil {
		return nil, err
	}
	clientID := strings.TrimSpace(options.ClientID)
	if clientID == "" {
		clientID = defaultClientID
	}
	if len(clientID) > maxOAuthValueBytes {
		return nil, errors.New("OAuth client ID is too large")
	}
	return &Refresher{
		path:     path,
		keys:     keys,
		issuer:   issuer,
		clientID: clientID,
		client:   oauthClient(options.HTTPClient),
	}, nil
}

// Credential returns the current credential or performs one proactive refresh.
func (r *Refresher) Credential(ctx context.Context) (Credential, error) {
	if ctx == nil {
		return Credential{}, errors.New("credential context is nil")
	}
	if err := ctx.Err(); err != nil {
		return Credential{}, err
	}
	credential, err := LoadCredential(r.path, r.keys)
	if err != nil {
		return Credential{}, err
	}
	r.clearChangedFailures(credential)
	if r.hasPermanentFailure(credential) {
		return Credential{}, ErrRefreshRequiresLogin
	}
	if !r.needsRefresh(credential) {
		r.mu.Lock()
		call := r.inFlight
		r.mu.Unlock()
		if call != nil {
			return waitForRefresh(ctx, call)
		}
		return credential, nil
	}
	return r.refreshSingleFlight(ctx, false, credential)
}

// Available reports whether a non-expired credential can serve a request now.
func (r *Refresher) Available() bool {
	credential, err := LoadCredential(r.path, r.keys)
	if err != nil {
		return false
	}
	r.clearChangedFailures(credential)
	if r.hasPermanentFailure(credential) {
		return false
	}
	return credential.AccountID != "" && credential.ExpiresAt.After(time.Now())
}

// Status reports credential readiness without returning token material.
func (r *Refresher) Status() CredentialStatus {
	credential, err := LoadCredential(r.path, r.keys)
	r.mu.Lock()
	inFlight := r.inFlight != nil
	permanent := r.permanentToken != ""
	transient := r.transientToken != ""
	if err == nil {
		if permanent && credential.RefreshToken != r.permanentToken {
			r.permanentToken = ""
			permanent = false
		}
		if transient && credential.RefreshToken != r.transientToken {
			r.transientToken = ""
			transient = false
		}
	}
	r.mu.Unlock()
	if inFlight {
		return CredentialStatusRefreshing
	}
	if err != nil {
		return CredentialStatusMissing
	}
	if permanent {
		return CredentialStatusPermanentFailure
	}
	if transient {
		return CredentialStatusTransientFailure
	}
	now := time.Now()
	if credential.ExpiresAt.IsZero() || !credential.ExpiresAt.After(now) {
		return CredentialStatusExpired
	}
	if !credential.ExpiresAt.After(now.Add(refreshSkew)) {
		return CredentialStatusRefreshable
	}
	return CredentialStatusCurrent
}

// Do sends one request and retries it once after a 401 when replaySafe is true.
func (r *Refresher) Do(ctx context.Context, replaySafe bool, send func(context.Context, Credential) (*http.Response, error)) (*http.Response, error) {
	if ctx == nil {
		return nil, errors.New("credential request context is nil")
	}
	if send == nil {
		return nil, errors.New("credential request callback is nil")
	}
	credential, err := r.Credential(ctx)
	if err != nil {
		return nil, err
	}
	response, err := send(ctx, credential)
	if err != nil {
		return nil, err
	}
	if response == nil {
		return nil, errors.New("credential request callback returned no response")
	}
	if response.StatusCode != http.StatusUnauthorized || !replaySafe {
		return response, nil
	}
	if response.Body != nil {
		_ = response.Body.Close()
	}
	credential, err = r.refreshAfterAuthFailure(ctx, credential)
	if err != nil {
		return nil, err
	}
	response, err = send(ctx, credential)
	if err != nil {
		return nil, err
	}
	if response == nil {
		return nil, errors.New("credential request callback returned no response")
	}
	return response, nil
}

func (r *Refresher) refreshAfterAuthFailure(ctx context.Context, previous Credential) (Credential, error) {
	current, err := LoadCredential(r.path, r.keys)
	if err != nil {
		return Credential{}, err
	}
	r.clearChangedFailures(current)
	if r.hasPermanentFailure(current) {
		return Credential{}, ErrRefreshRequiresLogin
	}
	if !sameCredential(current, previous) {
		return current, nil
	}
	return r.refreshSingleFlight(ctx, true, previous)
}

func (r *Refresher) refreshSingleFlight(ctx context.Context, force bool, observed Credential) (Credential, error) {
	if err := ctx.Err(); err != nil {
		return Credential{}, err
	}
	r.mu.Lock()
	if call := r.inFlight; call != nil {
		r.mu.Unlock()
		return waitForRefresh(ctx, call)
	}
	call := &refreshCall{done: make(chan struct{})}
	r.inFlight = call
	r.mu.Unlock()

	credential, err := LoadCredential(r.path, r.keys)
	if err == nil {
		r.clearChangedFailures(credential)
		if r.hasPermanentFailure(credential) {
			err = ErrRefreshRequiresLogin
		} else if (force && !sameCredential(credential, observed)) || (!force && !r.needsRefresh(credential)) {
			call.credential = credential
		}
	}
	if err == nil && call.credential.AccessToken == "" {
		call.credential, err = r.refresh(ctx, credential)
	}
	if err == nil && call.credential.AccessToken != "" {
		r.finishRefresh(call, call.credential, nil, credential)
		return call.credential, nil
	}
	r.finishRefresh(call, Credential{}, err, credential)
	return Credential{}, err
}

func waitForRefresh(ctx context.Context, call *refreshCall) (Credential, error) {
	select {
	case <-ctx.Done():
		return Credential{}, ctx.Err()
	case <-call.done:
		return call.credential, call.err
	}
}

func (r *Refresher) refresh(ctx context.Context, current Credential) (Credential, error) {
	values := url.Values{
		"grant_type":    {"refresh_token"},
		"client_id":     {r.clientID},
		"refresh_token": {current.RefreshToken},
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, r.issuer+"/oauth/token", strings.NewReader(values.Encode()))
	if err != nil {
		return Credential{}, &RefreshError{status: 0}
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, err := r.client.Do(request)
	if err != nil {
		if ctx.Err() != nil {
			return Credential{}, ctx.Err()
		}
		return Credential{}, &RefreshError{status: 0}
	}
	body, readErr := readAndCloseOAuthBody(response)
	if readErr != nil {
		return Credential{}, &RefreshError{status: response.StatusCode}
	}
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return Credential{}, refreshHTTPError(response.StatusCode, body)
	}
	var token tokenResponse
	if err := json.Unmarshal(body, &token); err != nil {
		return Credential{}, &RefreshError{status: response.StatusCode}
	}
	if token.ExpiresIn <= 0 || token.ExpiresIn > 365*24*60*60 || strings.TrimSpace(token.AccessToken) == "" {
		return Credential{}, &RefreshError{status: response.StatusCode}
	}
	credential, err := buildCredential(
		token.AccessToken,
		firstNonEmpty(token.RefreshToken, current.RefreshToken),
		firstNonEmpty(token.IDToken, current.IDToken),
		time.Now().Add(time.Duration(token.ExpiresIn)*time.Second),
		firstNonEmpty(token.AccountID, current.AccountID),
		firstNonEmpty(token.UserID, current.UserID),
		firstNonEmpty(token.WorkspaceID, current.WorkspaceID),
		firstNonEmpty(token.PlanType, current.PlanType),
		current.AccountIsFedRAMP || token.AccountIsFedRAMP,
		firstNonEmpty(token.Email, current.Email),
		false,
	)
	if err != nil {
		return Credential{}, &RefreshError{status: response.StatusCode}
	}
	if err := SaveCredential(r.path, credential, r.keys); err != nil {
		return Credential{}, &RefreshError{status: response.StatusCode}
	}
	return credential, nil
}

func refreshHTTPError(status int, body []byte) error {
	var failure CodexRefreshFailure
	if json.Unmarshal(body, &failure) == nil {
		failure.Status = status
		return &RefreshError{permanent: failure.IsPermanent(), status: status}
	}
	return &RefreshError{permanent: status == http.StatusUnauthorized, status: status}
}

func (r *Refresher) finishRefresh(call *refreshCall, credential Credential, err error, source Credential) {
	r.mu.Lock()
	call.credential = credential
	call.err = err
	if err == nil {
		r.permanentToken = ""
		r.transientToken = ""
	} else if errors.Is(err, ErrRefreshRequiresLogin) {
		r.permanentToken = source.RefreshToken
		r.transientToken = ""
	} else if !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
		r.transientToken = source.RefreshToken
	}
	if r.inFlight == call {
		r.inFlight = nil
	}
	close(call.done)
	r.mu.Unlock()
}

func (r *Refresher) clearChangedFailures(credential Credential) {
	r.mu.Lock()
	if r.permanentToken != "" && r.permanentToken != credential.RefreshToken {
		r.permanentToken = ""
	}
	if r.transientToken != "" && r.transientToken != credential.RefreshToken {
		r.transientToken = ""
	}
	r.mu.Unlock()
}

func (r *Refresher) hasPermanentFailure(credential Credential) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.permanentToken != "" && r.permanentToken == credential.RefreshToken
}

func (r *Refresher) needsRefresh(credential Credential) bool {
	return credential.ExpiresAt.IsZero() || !credential.ExpiresAt.After(time.Now().Add(refreshSkew))
}

func sameCredential(left, right Credential) bool {
	return left.AccessToken == right.AccessToken &&
		left.IDToken == right.IDToken &&
		left.RefreshToken == right.RefreshToken &&
		left.ExpiresAt.Equal(right.ExpiresAt)
}
