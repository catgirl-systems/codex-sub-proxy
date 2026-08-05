package codex

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/catgirl-systems/codex-sub-proxy/internal/envelope"
)

const (
	refreshSkew             = 5 * time.Minute
	refreshOperationTimeout = 15 * time.Second
)

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

// CredentialSnapshot is one coherent readiness observation.
type CredentialSnapshot struct {
	Available bool
	State     CredentialStatus
}

// RefresherOptions selects the OAuth endpoint and HTTP client.
type RefresherOptions struct {
	Issuer     string `validate:"required,max=65536,url,issuer"`
	ClientID   string `validate:"required,max=65536"`
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
	generation     uint64
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
	validatedKeys, err := envelope.NewKeySet(keys.Active, keys.Previous...)
	if err != nil {
		return nil, fmt.Errorf("invalid credential encryption keys: %w", err)
	}
	if err := oauthValidation.Struct(options); err != nil {
		return nil, fmt.Errorf("invalid OAuth refresh options: %w", err)
	}
	return &Refresher{
		path:     path,
		keys:     validatedKeys,
		issuer:   options.Issuer,
		clientID: options.ClientID,
		client:   oauthClient(options.HTTPClient),
	}, nil
}

// Credential returns the current credential or performs one proactive refresh.
func (r *Refresher) Credential(ctx context.Context) (Credential, error) {
	if ctx == nil {
		return Credential{}, errors.New("credential context is nil")
	}
	for {
		if err := ctx.Err(); err != nil {
			return Credential{}, err
		}
		r.mu.Lock()
		generation := r.generation
		inFlight := r.inFlight
		permanentToken := r.permanentToken
		transientToken := r.transientToken
		r.mu.Unlock()

		credential, loadErr := LoadCredential(r.path, r.keys)
		if err := ctx.Err(); err != nil {
			return Credential{}, err
		}
		r.mu.Lock()
		if generation != r.generation {
			call := r.inFlight
			r.mu.Unlock()
			if call != nil {
				if _, err := waitForRefresh(ctx, call); err != nil {
					return Credential{}, err
				}
			}
			continue
		}
		r.mu.Unlock()
		if loadErr != nil {
			return Credential{}, loadErr
		}
		if permanentToken != "" && permanentToken != credential.RefreshToken ||
			transientToken != "" && transientToken != credential.RefreshToken {
			r.clearChangedFailures(credential)
			continue
		}
		if permanentToken != "" && permanentToken == credential.RefreshToken {
			return Credential{}, ErrRefreshRequiresLogin
		}
		if inFlight != nil {
			if _, err := waitForRefresh(ctx, inFlight); err != nil {
				return Credential{}, err
			}
			continue
		}
		if !r.needsRefresh(credential) {
			return credential, nil
		}
		return r.refreshSingleFlight(ctx, false, credential)
	}
}

// Snapshot reports availability and state from one credential observation.
func (r *Refresher) Snapshot() CredentialSnapshot {
	for {
		r.mu.Lock()
		generation := r.generation
		inFlight := r.inFlight
		permanentToken := r.permanentToken
		transientToken := r.transientToken
		r.mu.Unlock()

		credential, loadErr := LoadCredential(r.path, r.keys)
		now := time.Now()
		r.mu.Lock()
		if generation != r.generation {
			r.mu.Unlock()
			continue
		}
		r.mu.Unlock()
		if loadErr != nil {
			return CredentialSnapshot{State: CredentialStatusMissing}
		}
		if permanentToken != "" && permanentToken != credential.RefreshToken ||
			transientToken != "" && transientToken != credential.RefreshToken {
			r.clearChangedFailures(credential)
			continue
		}
		available := credentialAvailableAt(credential, now)
		if permanentToken != "" && permanentToken == credential.RefreshToken {
			return CredentialSnapshot{Available: false, State: CredentialStatusPermanentFailure}
		}
		if inFlight != nil {
			return CredentialSnapshot{Available: available, State: CredentialStatusRefreshing}
		}
		if transientToken != "" && transientToken == credential.RefreshToken {
			return CredentialSnapshot{Available: available, State: CredentialStatusTransientFailure}
		}
		if credential.ExpiresAt.IsZero() || !credential.ExpiresAt.After(now) {
			return CredentialSnapshot{Available: false, State: CredentialStatusExpired}
		}
		if !credential.ExpiresAt.After(now.Add(refreshSkew)) {
			return CredentialSnapshot{Available: available, State: CredentialStatusRefreshable}
		}
		return CredentialSnapshot{Available: available, State: CredentialStatusCurrent}
	}
}

// Available reports whether a non-expired credential can serve a request now.
func (r *Refresher) Available() bool {
	return r.Snapshot().Available
}

// Status reports credential readiness without returning token material.
func (r *Refresher) Status() CredentialStatus {
	return r.Snapshot().State
}

func credentialAvailableAt(credential Credential, now time.Time) bool {
	return strings.TrimSpace(credential.AccessToken) != "" &&
		strings.TrimSpace(credential.RefreshToken) != "" &&
		strings.TrimSpace(credential.AccountID) != "" &&
		!credential.ExpiresAt.IsZero() &&
		credential.ExpiresAt.After(now)
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
	r.generation++
	r.mu.Unlock()
	go r.runRefresh(call, force, observed)
	return waitForRefresh(ctx, call)
}

func (r *Refresher) runRefresh(call *refreshCall, force bool, observed Credential) {
	operationContext, cancel := context.WithTimeout(context.Background(), refreshOperationTimeout)
	defer cancel()
	source, err := LoadCredential(r.path, r.keys)
	if err == nil {
		r.clearChangedFailures(source)
		if r.hasPermanentFailure(source) {
			err = ErrRefreshRequiresLogin
		} else if (force && !sameCredential(source, observed)) || (!force && !r.needsRefresh(source)) {
			r.finishRefresh(call, source, nil, source)
			return
		}
	}
	if err == nil {
		var credential Credential
		credential, err = r.refresh(operationContext, source)
		if err == nil {
			r.finishRefresh(call, credential, nil, source)
			return
		}
	}
	r.finishRefresh(call, Credential{}, err, source)
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
	if token.ExpiresIn <= 0 || token.ExpiresIn > 365*24*60*60 ||
		strings.TrimSpace(token.AccessToken) == "" || strings.TrimSpace(token.RefreshToken) == "" {
		return Credential{}, &RefreshError{status: response.StatusCode}
	}
	credential, err := buildCredential(
		token.AccessToken,
		token.RefreshToken,
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
	stored, saved, err := saveCredentialIfUnchanged(ctx, r.path, current, credential, r.keys)
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return Credential{}, err
		}
		return Credential{}, &RefreshError{status: response.StatusCode}
	}
	if !saved {
		return stored, nil
	}
	return credential, nil
}

func refreshHTTPError(status int, body []byte) error {
	var failure CodexRefreshFailure
	if json.Unmarshal(body, &failure) == nil {
		failure.Status = status
		return &RefreshError{permanent: failure.IsPermanent(), status: status}
	}
	permanent := status == http.StatusUnauthorized && !isTransientRefreshText(strings.ToLower(string(body)))
	return &RefreshError{permanent: permanent, status: status}
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
	r.generation++
	close(call.done)
	r.mu.Unlock()
}

func (r *Refresher) clearChangedFailures(credential Credential) {
	r.mu.Lock()
	changed := false
	if r.permanentToken != "" && r.permanentToken != credential.RefreshToken {
		r.permanentToken = ""
		changed = true
	}
	if r.transientToken != "" && r.transientToken != credential.RefreshToken {
		r.transientToken = ""
		changed = true
	}
	if changed {
		r.generation++
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
		left.ExpiresAt.Equal(right.ExpiresAt) &&
		left.AccountID == right.AccountID &&
		left.UserID == right.UserID &&
		left.WorkspaceID == right.WorkspaceID &&
		left.PlanType == right.PlanType &&
		left.AccountIsFedRAMP == right.AccountIsFedRAMP &&
		left.Email == right.Email
}
