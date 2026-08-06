package server

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/catgirl-systems/codex-sub-proxy/internal/codex"
)

// UpstreamBroker is the only server boundary for Codex Responses, Chat, and
// Images dispatch. Implementations bind the selected account before output.
type UpstreamBroker interface {
	DoResponses(ctx context.Context, request codex.SelectionRequest, private codex.CodexResponseRequest, forcedAccountID string, bind func(codex.Account) error) (BrokerResponsesResult, error)
	StreamResponses(ctx context.Context, request codex.SelectionRequest, private codex.CodexResponseRequest, forcedAccountID string, bind func(codex.Account) error, onEvent func(codex.CodexResponseStreamEvent) error) (BrokerResponsesResult, error)
	Compact(ctx context.Context, request codex.SelectionRequest, private codex.CodexCompactRequest, bind func(codex.Account) error) (BrokerCompactResult, error)
	GenerateImage(ctx context.Context, request codex.SelectionRequest, private codex.CodexImageGenerationRequest, bind func(codex.Account) error) (BrokerImageResult, error)
	EditImage(ctx context.Context, request codex.SelectionRequest, private codex.CodexImageEditRequest, bind func(codex.Account) error) (BrokerImageResult, error)
}

// BrokerResponsesResult is a Responses result together with its selected
// non-secret account identity.
type BrokerResponsesResult struct {
	Result  codex.CodexStreamResult
	Account codex.Account
}

// BrokerCompactResult is a compact result together with its selected account.
type BrokerCompactResult struct {
	Result  codex.CodexCompactResult
	Account codex.Account
}

// BrokerImageResult is an Images result together with its selected account.
type BrokerImageResult struct {
	Result  codex.CodexImageResult
	Account codex.Account
}

var (
	ErrBrokerUnavailable = errors.New("upstream broker is unavailable")
	ErrBrokerBind        = errors.New("upstream broker account bind failed")
)

// BrokerProfile connects one profile's credential refresher and transports.
type BrokerProfile struct {
	Account   codex.Account
	Refresher *codex.Refresher
	Responses *codex.ResponsesTransport
	Images    *codex.ImagesClient
}

// ProfileBroker selects among immutable per-profile clients.
type ProfileBroker struct {
	selector codex.AccountSelector
	mu       sync.RWMutex
	profiles map[string]BrokerProfile
}

// NewProfileBroker validates and creates a broker for profile clients.
func NewProfileBroker(selector codex.AccountSelector, profiles []BrokerProfile) (*ProfileBroker, error) {
	if selector == nil {
		selector = codex.SingleSelector{}
	}
	if len(profiles) == 0 {
		return nil, errors.New("upstream broker requires one profile")
	}
	result := &ProfileBroker{selector: selector, profiles: make(map[string]BrokerProfile, len(profiles))}
	for _, profile := range profiles {
		if profile.Account.ID == "" {
			return nil, errors.New("upstream broker profile ID is empty")
		}
		if profile.Responses == nil && profile.Images == nil {
			return nil, fmt.Errorf("upstream broker profile %q has no transport", profile.Account.ID)
		}
		if _, exists := result.profiles[profile.Account.ID]; exists {
			return nil, fmt.Errorf("upstream broker profile %q is duplicated", profile.Account.ID)
		}
		profile.Account.Models = append([]string(nil), profile.Account.Models...)
		if profile.Account.Quota != nil {
			quota := *profile.Account.Quota
			profile.Account.Quota = &quota
		}
		result.profiles[profile.Account.ID] = profile
	}
	return result, nil
}

func (broker *ProfileBroker) profile(ctx context.Context, request codex.SelectionRequest, forcedAccountID string) (BrokerProfile, error) {
	if ctx == nil {
		return BrokerProfile{}, errors.New("upstream broker context is nil")
	}
	if err := ctx.Err(); err != nil {
		return BrokerProfile{}, err
	}
	broker.mu.RLock()
	accounts := make([]codex.Account, 0, len(broker.profiles))
	accountByID := make(map[string]codex.Account, len(broker.profiles))
	for _, profile := range broker.profiles {
		account := currentProfileAccount(profile)
		accounts = append(accounts, account)
		accountByID[account.ID] = account
	}
	if forcedAccountID = strings.TrimSpace(forcedAccountID); forcedAccountID != "" {
		profile, ok := broker.profiles[forcedAccountID]
		broker.mu.RUnlock()
		if !ok {
			return BrokerProfile{}, codex.ErrNoAvailableAccount
		}
		account, exists := accountByID[forcedAccountID]
		if !exists || !account.Usable(request.Model) {
			return BrokerProfile{}, codex.ErrNoAvailableAccount
		}
		profile.Account = account
		return profile, nil
	}
	broker.mu.RUnlock()
	account, err := broker.selector.Select(ctx, request, accounts)
	if err != nil {
		return BrokerProfile{}, err
	}
	broker.mu.RLock()
	profile, ok := broker.profiles[account.ID]
	broker.mu.RUnlock()
	if !ok {
		return BrokerProfile{}, errors.New("selected upstream account is unavailable")
	}
	if current, exists := accountByID[account.ID]; exists {
		profile.Account = current
	}
	return profile, nil
}

func credentialSnapshotUsable(snapshot codex.CredentialSnapshot) bool {
	switch snapshot.State {
	case codex.CredentialStatusExpired, codex.CredentialStatusRefreshing, codex.CredentialStatusTransientFailure:
		return true
	default:
		return snapshot.Available
	}
}

func currentProfileAccount(profile BrokerProfile) codex.Account {
	account := profile.Account
	if profile.Refresher != nil {
		account.Available = credentialSnapshotUsable(profile.Refresher.Snapshot())
	}
	return account
}

func (broker *ProfileBroker) requestHeaders(request codex.SelectionRequest, account codex.Account, private *codex.CodexResponseRequest) codex.RequestHeaderConfig {
	headers := request.Headers
	headers.ResponsesLiteRequested = headers.ResponsesLiteRequested || account.ResponsesLite || private.ResponsesLite
	private.ResponsesLite = private.ResponsesLite || headers.ResponsesLiteRequested
	return headers
}

func bindSelected(bind func(codex.Account) error, account codex.Account) error {
	if bind == nil {
		return fmt.Errorf("%w: account bind callback is required", ErrBrokerBind)
	}
	if err := bind(account); err != nil {
		return fmt.Errorf("%w for account %q: %w", ErrBrokerBind, account.ID, err)
	}
	return nil
}

func (broker *ProfileBroker) DoResponses(ctx context.Context, request codex.SelectionRequest, private codex.CodexResponseRequest, forcedAccountID string, bind func(codex.Account) error) (BrokerResponsesResult, error) {
	profile, err := broker.profile(ctx, request, forcedAccountID)
	if err != nil {
		return BrokerResponsesResult{}, err
	}
	if err := bindSelected(bind, profile.Account); err != nil {
		return BrokerResponsesResult{Account: profile.Account}, err
	}
	if profile.Responses == nil {
		return BrokerResponsesResult{Account: profile.Account}, fmt.Errorf("%w: selected profile Responses transport is unavailable", ErrBrokerUnavailable)
	}
	requestHeaders := broker.requestHeaders(request, profile.Account, &private)
	result, err := profile.Responses.DoWithHeaders(ctx, private, requestHeaders)
	return BrokerResponsesResult{Result: result, Account: profile.Account}, err
}

func (broker *ProfileBroker) StreamResponses(ctx context.Context, request codex.SelectionRequest, private codex.CodexResponseRequest, forcedAccountID string, bind func(codex.Account) error, onEvent func(codex.CodexResponseStreamEvent) error) (BrokerResponsesResult, error) {
	profile, err := broker.profile(ctx, request, forcedAccountID)
	if err != nil {
		return BrokerResponsesResult{}, err
	}
	if err := bindSelected(bind, profile.Account); err != nil {
		return BrokerResponsesResult{Account: profile.Account}, err
	}
	if profile.Responses == nil {
		return BrokerResponsesResult{Account: profile.Account}, fmt.Errorf("%w: selected profile Responses transport is unavailable", ErrBrokerUnavailable)
	}
	requestHeaders := broker.requestHeaders(request, profile.Account, &private)
	err = profile.Responses.StreamWithHeaders(ctx, private, requestHeaders, onEvent)
	return BrokerResponsesResult{Account: profile.Account}, err
}

func (broker *ProfileBroker) Compact(ctx context.Context, request codex.SelectionRequest, private codex.CodexCompactRequest, bind func(codex.Account) error) (BrokerCompactResult, error) {
	profile, err := broker.profile(ctx, request, "")
	if err != nil {
		return BrokerCompactResult{}, err
	}
	if err := bindSelected(bind, profile.Account); err != nil {
		return BrokerCompactResult{Account: profile.Account}, err
	}
	if profile.Responses == nil {
		return BrokerCompactResult{Account: profile.Account}, fmt.Errorf("%w: selected profile Responses transport is unavailable", ErrBrokerUnavailable)
	}
	headers := request.Headers
	headers.ResponsesLiteRequested = headers.ResponsesLiteRequested || profile.Account.ResponsesLite || private.ResponsesLite
	private.ResponsesLite = private.ResponsesLite || headers.ResponsesLiteRequested
	result, err := profile.Responses.CompactWithHeaders(ctx, private, headers)
	return BrokerCompactResult{Result: result, Account: profile.Account}, err
}

func (broker *ProfileBroker) GenerateImage(ctx context.Context, request codex.SelectionRequest, private codex.CodexImageGenerationRequest, bind func(codex.Account) error) (BrokerImageResult, error) {
	profile, err := broker.profile(ctx, request, "")
	if err != nil {
		return BrokerImageResult{}, err
	}
	if err := bindSelected(bind, profile.Account); err != nil {
		return BrokerImageResult{Account: profile.Account}, err
	}
	if profile.Images == nil {
		return BrokerImageResult{Account: profile.Account}, fmt.Errorf("%w: selected profile Images client is unavailable", ErrBrokerUnavailable)
	}
	result, err := profile.Images.GenerateWithHeaders(ctx, private, request.Headers)
	return BrokerImageResult{Result: result, Account: profile.Account}, err
}

func (broker *ProfileBroker) EditImage(ctx context.Context, request codex.SelectionRequest, private codex.CodexImageEditRequest, bind func(codex.Account) error) (BrokerImageResult, error) {
	profile, err := broker.profile(ctx, request, "")
	if err != nil {
		return BrokerImageResult{}, err
	}
	if err := bindSelected(bind, profile.Account); err != nil {
		return BrokerImageResult{Account: profile.Account}, err
	}
	if profile.Images == nil {
		return BrokerImageResult{Account: profile.Account}, fmt.Errorf("%w: selected profile Images client is unavailable", ErrBrokerUnavailable)
	}
	result, err := profile.Images.EditWithHeaders(ctx, private, request.Headers)
	return BrokerImageResult{Result: result, Account: profile.Account}, err
}

func (broker *ProfileBroker) Accounts() []codex.Account {
	broker.mu.RLock()
	defer broker.mu.RUnlock()
	accounts := make([]codex.Account, 0, len(broker.profiles))
	for _, profile := range broker.profiles {
		accounts = append(accounts, currentProfileAccount(profile))
	}
	return codex.CloneAccounts(accounts)
}
