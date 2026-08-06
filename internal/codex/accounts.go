package codex

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"path/filepath"
	"sort"
	"strings"
	"sync/atomic"
	"time"
)

// RequestHeaderConfig contains the bounded, per-call header variations that
// may be forwarded to Codex. Authentication and provider account identity are
// deliberately absent.
type RequestHeaderConfig struct {
	SessionID              string
	ThreadID               string
	ResponsesLiteRequested bool
}

// Validate checks the downstream-derived values before they become upstream
// headers.
func (config RequestHeaderConfig) Validate() error {
	for name, value := range map[string]string{
		"session_id": config.SessionID,
		"thread-id":  config.ThreadID,
	} {
		if len(value) > 256 || strings.ContainsAny(value, "\x00\r\n") {
			return fmt.Errorf("%s header value is invalid", name)
		}
	}
	return nil
}

// SelectionRequest describes one account selection without exposing secrets.
type SelectionRequest struct {
	Endpoint, Model, APIKeyID, PreviousResponseID string
	Headers                                       RequestHeaderConfig
	// AffinityAccountID is a best-effort session affinity hint. For a
	// continuation, PreviousResponseID makes the hint authoritative so the
	// response remains bound to its owning account; otherwise the broker must
	// fall back to its selector when the hinted account is no longer usable.
	AffinityAccountID string
}

// QuotaSnapshot is the bounded quota observation used by QuotaAwareSelector.
type QuotaSnapshot struct {
	UsedPercent float64
	Known       bool
}

// Account is the non-secret profile state exposed to selectors and brokers.
type Account struct {
	ID                  string
	ProviderAccountID   string
	CredentialPath      string
	Enabled             bool
	IsDefault           bool
	Available           bool
	CooldownUntil       time.Time
	PlanType            string
	Models              []string
	CatalogConfigured   bool
	CatalogLoaded       bool
	ResponsesLite       bool
	ResponsesLiteModels map[string]bool
	Quota               *QuotaSnapshot
	UsedPercent         float64
	QuotaKnown          bool
}

// Usable reports whether the account can serve model now.
func (account Account) Usable(model string) bool {
	return accountUsable(account, model)
}

// AccountSelector chooses one usable account for a request.
type AccountSelector interface {
	Select(ctx context.Context, req SelectionRequest, accounts []Account) (Account, error)
}

var ErrNoAvailableAccount = errors.New("no available Codex account")

// SingleSelector selects only the default profile.
type SingleSelector struct{}

func (SingleSelector) Select(ctx context.Context, req SelectionRequest, accounts []Account) (Account, error) {
	if err := selectionContext(ctx); err != nil {
		return Account{}, err
	}
	for _, account := range sortedAccounts(accounts) {
		if account.IsDefault && accountUsable(account, req.Model) {
			return account, nil
		}
	}
	return Account{}, ErrNoAvailableAccount
}

// RoundRobinSelector cycles through eligible profiles in stable ID order.
type RoundRobinSelector struct{ next atomic.Uint64 }

func (selector *RoundRobinSelector) Select(ctx context.Context, req SelectionRequest, accounts []Account) (Account, error) {
	if err := selectionContext(ctx); err != nil {
		return Account{}, err
	}
	eligible := eligibleAccounts(accounts, req.Model)
	if len(eligible) == 0 {
		return Account{}, ErrNoAvailableAccount
	}
	index := selector.next.Add(1) - 1
	return eligible[index%uint64(len(eligible))], nil
}

// QuotaAwareSelector chooses the least-used eligible profile and rotates ties.
type QuotaAwareSelector struct{ next atomic.Uint64 }

func (selector *QuotaAwareSelector) Select(ctx context.Context, req SelectionRequest, accounts []Account) (Account, error) {
	if err := selectionContext(ctx); err != nil {
		return Account{}, err
	}
	eligible := eligibleAccounts(accounts, req.Model)
	if len(eligible) == 0 {
		return Account{}, ErrNoAvailableAccount
	}
	best := 0.0
	for index, account := range eligible {
		used := accountQuotaPercent(account)
		if index == 0 || used < best {
			best = used
		}
	}
	tied := make([]Account, 0, len(eligible))
	for _, account := range eligible {
		if accountQuotaPercent(account) == best {
			tied = append(tied, account)
		}
	}
	index := selector.next.Add(1) - 1
	return tied[index%uint64(len(tied))], nil
}

func selectionContext(ctx context.Context) error {
	if ctx == nil {
		return errors.New("account selection context is nil")
	}
	return ctx.Err()
}

func sortedAccounts(accounts []Account) []Account {
	result := append([]Account(nil), accounts...)
	sort.SliceStable(result, func(i, j int) bool { return result[i].ID < result[j].ID })
	return result
}

func eligibleAccounts(accounts []Account, model string) []Account {
	result := make([]Account, 0, len(accounts))
	now := time.Now()
	for _, account := range sortedAccounts(accounts) {
		if accountUsableAt(account, model, now) {
			result = append(result, account)
		}
	}
	return result
}

func accountUsable(account Account, model string) bool {
	return accountUsableAt(account, model, time.Now())
}
func accountUsableAt(account Account, model string, now time.Time) bool {
	if !account.Enabled || !account.Available || (!account.CooldownUntil.IsZero() && account.CooldownUntil.After(now)) {
		return false
	}
	if account.CatalogConfigured && !account.CatalogLoaded {
		return false
	}
	if model == "" {
		return true
	}
	if account.CatalogLoaded && len(account.Models) == 0 {
		return false
	}
	if len(account.Models) == 0 {
		return true
	}
	for _, candidate := range account.Models {
		if candidate == model {
			return true
		}
	}
	return false
}
func accountQuotaPercent(account Account) float64 {
	if account.Quota != nil && account.Quota.Known && validQuotaPercent(account.Quota.UsedPercent) {
		return account.Quota.UsedPercent
	}
	if account.QuotaKnown && validQuotaPercent(account.UsedPercent) {
		return account.UsedPercent
	}
	return 0
}

func validQuotaPercent(value float64) bool {
	return !math.IsNaN(value) && !math.IsInf(value, 0) && value >= 0
}

// ProfileCredentialPath maps a profile name to its encrypted credential file.
// The historical default profile remains exactly at credentialFile.
func ProfileCredentialPath(credentialFile, profile string) (string, error) {
	credentialFile = strings.TrimSpace(credentialFile)
	profile = strings.TrimSpace(profile)
	if credentialFile == "" {
		return "", errors.New("credential file is empty")
	}
	if profile == "" || profile == "." || profile == ".." || len(profile) > 255 || strings.ContainsAny(profile, "/\\\r\n") {
		return "", errors.New("credential profile is invalid")
	}
	if profile == "default" {
		return credentialFile, nil
	}
	digest := sha256.Sum256([]byte(profile))
	return filepath.Join(credentialFile+".d", hex.EncodeToString(digest[:])+".enc"), nil
}

// CloneAccounts returns a stable copy for callers that may mutate their input.
func CloneAccounts(accounts []Account) []Account {
	result := append([]Account(nil), accounts...)
	for index := range result {
		result[index].Models = append([]string(nil), result[index].Models...)
		if result[index].ResponsesLiteModels != nil {
			result[index].ResponsesLiteModels = make(map[string]bool, len(result[index].ResponsesLiteModels))
			for model, enabled := range accounts[index].ResponsesLiteModels {
				result[index].ResponsesLiteModels[model] = enabled
			}
		}
		if result[index].Quota != nil {
			quota := *result[index].Quota
			result[index].Quota = &quota
		}
	}
	return result
}

func mergeRequestHeaders(base HeaderConfig, request RequestHeaderConfig) HeaderConfig {
	if request.SessionID != "" {
		base.SessionID = request.SessionID
	}
	if request.ThreadID != "" {
		base.ThreadID = request.ThreadID
	}
	base.ResponsesLite = base.ResponsesLite || request.ResponsesLiteRequested
	return base
}
