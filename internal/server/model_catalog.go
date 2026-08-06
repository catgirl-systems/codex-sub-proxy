package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/catgirl-systems/codex-sub-proxy/internal/codex"
	"gorm.io/gorm"
)

const (
	defaultModelCatalogTTL            = 5 * time.Minute
	defaultModelCatalogRequestTimeout = 10 * time.Second
	modelCatalogWorkers               = 8
)

const maxModelCatalogETagBytes = 512

func normalizeModelCatalogETag(value string) string {
	value = strings.TrimSpace(value)
	if len(value) > maxModelCatalogETagBytes || strings.ContainsAny(value, "\r\n") {
		return ""
	}
	return value
}

// ModelCatalogStore persists validated provider catalogs independently of
// credentials and request payloads.
type ModelCatalogStore struct {
	db *gorm.DB
}

func NewModelCatalogStore(db *gorm.DB) (*ModelCatalogStore, error) {
	if db == nil {
		return nil, errors.New("model catalog database is nil")
	}
	return &ModelCatalogStore{db: db}, nil
}

func (store *ModelCatalogStore) Load(ctx context.Context, accountID string) (modelCatalogState, bool, error) {
	if ctx == nil {
		return modelCatalogState{}, false, errors.New("model catalog context is nil")
	}
	if strings.TrimSpace(accountID) == "" {
		return modelCatalogState{}, false, errors.New("model catalog account ID is empty")
	}
	var record ModelCatalogRecord
	err := store.db.WithContext(ctx).Where("account_id = ? AND length(CAST(catalog_json AS BLOB)) <= ?", accountID, codex.MaxModelCatalogBytes).First(&record).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return modelCatalogState{}, false, nil
	}
	if err != nil {
		return modelCatalogState{}, false, fmt.Errorf("load model catalog: %w", err)
	}
	catalogJSON := strings.TrimSpace(record.CatalogJSON)
	if catalogJSON == "" || len(catalogJSON) > codex.MaxModelCatalogBytes || record.FetchedAt.IsZero() {
		return modelCatalogState{}, false, nil
	}
	models, err := codex.DecodeModelCatalog([]byte(catalogJSON))
	if err != nil {
		// A persisted row is an untrusted cache. Ignore a malformed row and
		// let the bounded provider refresh replace it.
		return modelCatalogState{}, false, nil
	}
	return modelCatalogState{models: models, etag: normalizeModelCatalogETag(record.ETag), fetchedAt: record.FetchedAt.UTC(), loaded: true}, true, nil
}

func (store *ModelCatalogStore) Save(ctx context.Context, accountID string, models []codex.ModelInfo, etag string, fetchedAt time.Time) error {
	return store.SaveWithSource(ctx, accountID, models, etag, fetchedAt, true)
}

func (store *ModelCatalogStore) SaveWithSource(ctx context.Context, accountID string, models []codex.ModelInfo, etag string, fetchedAt time.Time, provider bool) error {
	if ctx == nil {
		return errors.New("model catalog context is nil")
	}
	if strings.TrimSpace(accountID) == "" {
		return errors.New("model catalog account ID is empty")
	}
	if fetchedAt.IsZero() {
		return errors.New("model catalog fetched time is zero")
	}
	var encodedEnvelope []byte
	var err error
	if provider {
		encodedEnvelope, err = json.Marshal(struct {
			Models []codex.ModelInfo `json:"models"`
		}{Models: models})
	} else {
		encodedEnvelope, err = json.Marshal(struct {
			Data []codex.ModelInfo `json:"data"`
		}{Data: models})
	}
	if err != nil {
		return fmt.Errorf("encode model catalog for validation: %w", err)
	}
	validated, err := codex.DecodeModelCatalog(encodedEnvelope)
	if err != nil {
		return fmt.Errorf("validate model catalog: %w", err)
	}
	if len(validated) != len(models) {
		return errors.New("validate model catalog: filtered model entry")
	}
	if len(encodedEnvelope) > codex.MaxModelCatalogBytes {
		return errors.New("model catalog exceeds size limit")
	}
	record := ModelCatalogRecord{AccountID: accountID, CatalogJSON: string(encodedEnvelope), ETag: normalizeModelCatalogETag(etag), FetchedAt: fetchedAt.UTC()}
	if err := store.db.WithContext(ctx).Save(&record).Error; err != nil {
		return fmt.Errorf("save model catalog: %w", err)
	}
	return nil
}

func (store *ModelCatalogStore) Touch(ctx context.Context, accountID, etag string, fetchedAt time.Time) error {
	if ctx == nil {
		return errors.New("model catalog context is nil")
	}
	if strings.TrimSpace(accountID) == "" {
		return errors.New("model catalog account ID is empty")
	}
	if fetchedAt.IsZero() {
		return errors.New("model catalog fetched time is zero")
	}
	result := store.db.WithContext(ctx).Model(&ModelCatalogRecord{}).Where("account_id = ?", accountID).Updates(map[string]any{
		"etag":       normalizeModelCatalogETag(etag),
		"fetched_at": fetchedAt.UTC(),
	})
	if result.Error != nil {
		return fmt.Errorf("renew model catalog: %w", result.Error)
	}
	if result.RowsAffected != 1 {
		return errors.New("renew model catalog: account cache is missing")
	}
	return nil
}

type modelCatalogState struct {
	models    []codex.ModelInfo
	etag      string
	fetchedAt time.Time
	loaded    bool
}

type modelCatalogAccount struct {
	id      string
	enabled bool
	client  *codex.ModelsClient
}

// ModelCatalogAccountSnapshot is the non-secret catalog view used by the
// downstream models handler.
type ModelCatalogAccountSnapshot struct {
	AccountID string
	Models    []codex.ModelInfo
	ETag      string
	FetchedAt time.Time
	Loaded    bool
}

// ModelCatalogManager owns parallel startup and expiry refreshes.
type ModelCatalogManager struct {
	store          *ModelCatalogStore
	broker         *ProfileBroker
	ttl            time.Duration
	requestTimeout time.Duration
	mu             sync.RWMutex
	accounts       map[string]modelCatalogAccount
	states         map[string]modelCatalogState
	lifecycleCtx   context.Context
	startCancel    context.CancelFunc
	started        bool
	closed         bool
	closeDone      chan struct{}
	workers        sync.WaitGroup
	operationalErr error
}

// ModelCatalogOptions controls persistence and bounded refresh behavior.
type ModelCatalogOptions struct {
	TTL            time.Duration
	RequestTimeout time.Duration
}

func NewModelCatalogManager(store *ModelCatalogStore, broker *ProfileBroker, options ModelCatalogOptions) (*ModelCatalogManager, error) {
	if store == nil || store.db == nil {
		return nil, errors.New("model catalog store is nil")
	}
	if broker == nil {
		return nil, errors.New("model catalog broker is nil")
	}
	ttl := options.TTL
	if ttl <= 0 {
		ttl = defaultModelCatalogTTL
	}
	requestTimeout := options.RequestTimeout
	if requestTimeout <= 0 {
		requestTimeout = defaultModelCatalogRequestTimeout
	}
	manager := &ModelCatalogManager{
		store: store, broker: broker, ttl: ttl, requestTimeout: requestTimeout,
		accounts: make(map[string]modelCatalogAccount), states: make(map[string]modelCatalogState),
		closeDone: make(chan struct{}),
	}
	broker.mu.RLock()
	profiles := make([]BrokerProfile, 0, len(broker.profiles))
	for _, profile := range broker.profiles {
		profiles = append(profiles, profile)
	}
	broker.mu.RUnlock()
	for _, profile := range profiles {
		manager.accounts[profile.Account.ID] = modelCatalogAccount{
			id: profile.Account.ID, enabled: profile.Account.Enabled, client: profile.Models,
		}
		if err := broker.UpdateModelCatalog(profile.Account.ID, nil, false); err != nil {
			return nil, fmt.Errorf("initialize model catalog profile %q: %w", profile.Account.ID, err)
		}
	}
	broker.attachModelCatalog(manager)
	return manager, nil
}

// Start loads persisted catalogs, refreshes all enabled profiles in parallel
// before serving, and then refreshes expired catalogs in the background.
func (manager *ModelCatalogManager) Start(ctx context.Context) error {
	if ctx == nil {
		return errors.New("model catalog context is nil")
	}
	manager.mu.Lock()
	if manager.closed {
		manager.mu.Unlock()
		return errors.New("model catalog manager is closed")
	}
	if manager.started {
		manager.mu.Unlock()
		return nil
	}
	manager.started = true
	lifecycleCtx, cancel := context.WithCancel(ctx)
	manager.lifecycleCtx = lifecycleCtx
	manager.startCancel = cancel
	manager.workers.Add(1)
	manager.mu.Unlock()
	defer manager.workers.Done()

	if err := manager.loadPersisted(lifecycleCtx); err != nil {
		cancel()
		manager.mu.Lock()
		manager.started = false
		manager.lifecycleCtx = nil
		manager.startCancel = nil
		manager.mu.Unlock()
		return err
	}
	if err := manager.refreshAll(lifecycleCtx); err != nil {
		cancel()
		manager.mu.Lock()
		manager.started = false
		manager.lifecycleCtx = nil
		manager.startCancel = nil
		manager.mu.Unlock()
		return err
	}
	manager.mu.Lock()
	if manager.closed {
		manager.mu.Unlock()
		cancel()
		return errors.New("model catalog manager is closed")
	}
	manager.workers.Add(1)
	manager.mu.Unlock()
	go manager.refreshLoop(lifecycleCtx)
	return nil
}

func (manager *ModelCatalogManager) loadPersisted(ctx context.Context) error {
	manager.mu.RLock()
	accounts := make([]modelCatalogAccount, 0, len(manager.accounts))
	for _, account := range manager.accounts {
		accounts = append(accounts, account)
	}
	manager.mu.RUnlock()
	for _, account := range accounts {
		state, found, err := manager.store.Load(ctx, account.id)
		if err != nil {
			return err
		}
		if !found {
			continue
		}
		manager.mu.Lock()
		manager.states[account.id] = state
		manager.mu.Unlock()
		if err := manager.broker.UpdateModelCatalog(account.id, state.models, true); err != nil {
			return err
		}
	}
	return nil
}

func (manager *ModelCatalogManager) refreshLoop(ctx context.Context) {
	defer manager.workers.Done()
	interval := manager.ttl / 2
	if interval < 10*time.Millisecond {
		interval = 10 * time.Millisecond
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			if err := manager.refreshExpired(ctx); err != nil && ctx.Err() == nil {
				manager.recordOperationalError(err)
			}
		case <-ctx.Done():
			return
		}
	}
}

func (manager *ModelCatalogManager) recordOperationalError(err error) {
	if err == nil {
		return
	}
	manager.mu.Lock()
	if manager.operationalErr == nil {
		manager.operationalErr = err
	}
	manager.mu.Unlock()
}

// OperationalError reports the first non-provider operational failure from a
// background refresh, such as a cache persistence or broker update failure.
func (manager *ModelCatalogManager) OperationalError() error {
	manager.mu.RLock()
	defer manager.mu.RUnlock()
	return manager.operationalErr
}
func (manager *ModelCatalogManager) refreshAll(ctx context.Context) error {
	if ctx == nil {
		return errors.New("model catalog context is nil")
	}
	manager.mu.Lock()
	if manager.closed {
		manager.mu.Unlock()
		return errors.New("model catalog manager is closed")
	}
	if manager.lifecycleCtx != nil {
		ctx = manager.lifecycleCtx
	}
	manager.workers.Add(1)
	accounts := make([]modelCatalogAccount, 0, len(manager.accounts))
	for _, account := range manager.accounts {
		if account.enabled && account.client != nil {
			accounts = append(accounts, account)
		}
	}
	manager.mu.Unlock()
	defer manager.workers.Done()
	return manager.refreshAccounts(ctx, accounts)
}

func (manager *ModelCatalogManager) refreshExpired(ctx context.Context) error {
	now := time.Now().UTC()
	manager.mu.RLock()
	accounts := make([]modelCatalogAccount, 0, len(manager.accounts))
	for _, account := range manager.accounts {
		state, ok := manager.states[account.id]
		if account.enabled && account.client != nil && (!ok || !state.loaded || state.fetchedAt.IsZero() || !now.Before(state.fetchedAt.Add(manager.ttl))) {
			accounts = append(accounts, account)
		}
	}
	manager.mu.RUnlock()
	return manager.refreshAccounts(ctx, accounts)
}

func (manager *ModelCatalogManager) refreshAccounts(ctx context.Context, accounts []modelCatalogAccount) error {
	if len(accounts) == 0 {
		return nil
	}
	workerCount := len(accounts)
	if workerCount > modelCatalogWorkers {
		workerCount = modelCatalogWorkers
	}
	jobs := make(chan modelCatalogAccount)
	var workers sync.WaitGroup
	var firstErr error
	var errMu sync.Mutex
	for index := 0; index < workerCount; index++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for account := range jobs {
				if err := manager.refreshAccount(ctx, account); err != nil {
					errMu.Lock()
					if firstErr == nil {
						firstErr = err
					}
					errMu.Unlock()
				}
			}
		}()
	}
	for _, account := range accounts {
		select {
		case jobs <- account:
		case <-ctx.Done():
			close(jobs)
			workers.Wait()
			return ctx.Err()
		}
	}
	close(jobs)
	workers.Wait()
	return firstErr
}

func (manager *ModelCatalogManager) refreshAccount(ctx context.Context, account modelCatalogAccount) error {
	manager.mu.RLock()
	state := manager.states[account.id]
	manager.mu.RUnlock()
	requestContext, cancel := context.WithTimeout(ctx, manager.requestTimeout)
	defer cancel()
	result, err := account.client.List(requestContext, state.etag)
	if err != nil {
		if contextErr := ctx.Err(); contextErr != nil {
			return contextErr
		}
		// A previously validated cache remains authoritative during network,
		// provider-server, authentication, and malformed-response failures.
		// The expiry loop retries the account later.
		return nil
	}
	now := time.Now().UTC()
	if result.NotModified {
		if !state.loaded {
			return nil
		}
		etag := normalizeModelCatalogETag(result.ETag)
		if etag == "" {
			etag = state.etag
		}
		if err := manager.store.Touch(ctx, account.id, etag, now); err != nil {
			return err
		}
		state.etag, state.fetchedAt = etag, now
		manager.mu.Lock()
		manager.states[account.id] = state
		manager.mu.Unlock()
		return nil
	}
	etag := normalizeModelCatalogETag(result.ETag)
	if etag == "" {
		etag = modelCatalogETag(result.Models)
	}
	if err := manager.store.SaveWithSource(ctx, account.id, result.Models, etag, now, result.Provider); err != nil {
		return err
	}
	state = modelCatalogState{models: append([]codex.ModelInfo(nil), result.Models...), etag: etag, fetchedAt: now, loaded: true}
	manager.mu.Lock()
	manager.states[account.id] = state
	manager.mu.Unlock()
	return manager.broker.UpdateModelCatalog(account.id, result.Models, true)
}

func modelCatalogETag(models []codex.ModelInfo) string {
	encoded, _ := json.Marshal(models)
	digest := sha256.Sum256(encoded)
	return `"` + hex.EncodeToString(digest[:]) + `"`
}

// Snapshot returns account catalogs in stable account ID order.
func (manager *ModelCatalogManager) Snapshot() []ModelCatalogAccountSnapshot {
	manager.mu.RLock()
	result := make([]ModelCatalogAccountSnapshot, 0, len(manager.states))
	for accountID, state := range manager.states {
		result = append(result, ModelCatalogAccountSnapshot{AccountID: accountID, Models: append([]codex.ModelInfo(nil), state.models...), ETag: state.etag, FetchedAt: state.fetchedAt, Loaded: state.loaded})
	}
	manager.mu.RUnlock()
	sort.Slice(result, func(i, j int) bool { return result[i].AccountID < result[j].AccountID })
	return result
}

// Ready reports whether at least one enabled credential has a catalog.
func (manager *ModelCatalogManager) Ready(accounts []codex.Account) bool {
	manager.mu.RLock()
	defer manager.mu.RUnlock()
	if manager.operationalErr != nil {
		return false
	}
	for _, account := range accounts {
		if account.Enabled && account.Available && account.CatalogLoaded {
			return true
		}
	}
	return false
}

// CloseDone is closed after all manager workers have exited.
func (manager *ModelCatalogManager) CloseDone() <-chan struct{} {
	return manager.closeDone
}

func (manager *ModelCatalogManager) Close(ctx context.Context) error {
	if ctx == nil {
		return errors.New("model catalog shutdown context is nil")
	}
	manager.mu.Lock()
	if manager.closed {
		done := manager.closeDone
		manager.mu.Unlock()
		select {
		case <-done:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	manager.closed = true
	cancel := manager.startCancel
	done := manager.closeDone
	manager.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	go func() {
		manager.workers.Wait()
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
func (manager *ModelCatalogManager) PublicModels(allowedModels []string) ([]modelObject, []codex.ModelInfo, bool) {
	accounts := manager.broker.Accounts()
	accountByID := make(map[string]codex.Account, len(accounts))
	for _, account := range accounts {
		accountByID[account.ID] = account
	}
	defaultAccountID := ""
	for _, account := range accounts {
		if account.IsDefault {
			defaultAccountID = account.ID
			break
		}
	}
	snapshots := manager.Snapshot()
	byID := make(map[string][]codex.ModelInfo)
	sort.Slice(snapshots, func(i, j int) bool {
		iDefault := snapshots[i].AccountID == defaultAccountID
		jDefault := snapshots[j].AccountID == defaultAccountID
		if iDefault != jDefault {
			return iDefault
		}
		return snapshots[i].AccountID < snapshots[j].AccountID
	})
	for _, snapshot := range snapshots {
		account, ok := accountByID[snapshot.AccountID]
		if !ok || !account.Enabled || !account.Available || !account.CatalogLoaded || !snapshot.Loaded {
			continue
		}
		for _, model := range snapshot.Models {
			if !model.CatalogUsable() {
				continue
			}
			id := strings.TrimSpace(model.Slug)
			if id == "" {
				id = strings.TrimSpace(model.ID)
			}
			if id == "" {
				continue
			}
			byID[id] = append(byID[id], model)
		}
	}
	ids := make([]string, 0, len(allowedModels))
	seen := make(map[string]struct{}, len(allowedModels))
	for _, id := range allowedModels {
		id = strings.TrimSpace(id)
		if id == "" {
			continue
		}
		if _, exists := byID[id]; !exists {
			continue
		}
		if _, exists := seen[id]; exists {
			continue
		}
		seen[id] = struct{}{}
		ids = append(ids, id)
	}
	merged := make([]codex.ModelInfo, 0, len(ids))
	for _, id := range ids {
		merged = append(merged, mergeModelInfo(id, byID[id]))
	}
	data := make([]modelObject, 0, len(merged))
	for _, model := range merged {
		data = append(data, modelObjectFromInfo(model))
	}
	ready := false
	if manager.OperationalError() == nil {
		for _, account := range accounts {
			if account.Enabled && account.Available && account.CatalogLoaded {
				ready = true
				break
			}
		}
	}
	return data, merged, ready
}
func mergeModelInfo(id string, models []codex.ModelInfo) codex.ModelInfo {
	if len(models) == 0 {
		return codex.ModelInfo{ID: id, Slug: id}
	}
	common := make(map[string]json.RawMessage)
	first, _ := json.Marshal(models[0])
	_ = json.Unmarshal(first, &common)
	delete(common, "id")
	for _, model := range models[1:] {
		encoded, _ := json.Marshal(model)
		var fields map[string]json.RawMessage
		_ = json.Unmarshal(encoded, &fields)
		for key, value := range common {
			candidate, ok := fields[key]
			if !ok || !bytes.Equal(value, candidate) {
				delete(common, key)
			}
		}
	}
	for _, key := range []string{"display_name", "description", "source", "model_messages"} {
		delete(common, key)
	}
	encoded, _ := json.Marshal(common)
	var result codex.ModelInfo
	_ = json.Unmarshal(encoded, &result)
	result.ID = id
	result.Slug = id
	result.DisplayName = models[0].DisplayName
	result.Description = models[0].Description
	result.Source = models[0].Source
	if allModelMessagesEqual(models) {
		result.ModelMessages = append([]byte(nil), models[0].ModelMessages...)
	} else {
		result.ModelMessages = nil
	}
	result.Capabilities = mergeCapabilities(models)
	result.SupportedInAPI = allModelBools(models, func(model codex.ModelInfo) bool { return model.SupportedInAPI })
	result.Visibility = models[0].Visibility
	result.UseResponsesLite = allModelBools(models, func(model codex.ModelInfo) bool { return model.UseResponsesLite })
	result.IncludeSkillsUsageInstructions = allModelBools(models, func(model codex.ModelInfo) bool { return model.IncludeSkillsUsageInstructions })
	result.IncludePluginUsageInstructions = allModelBools(models, func(model codex.ModelInfo) bool { return model.IncludePluginUsageInstructions })
	result.IncludeAppsUsageInstructions = allModelBools(models, func(model codex.ModelInfo) bool { return model.IncludeAppsUsageInstructions })
	result.SupportsReasoningSummary = allModelBools(models, func(model codex.ModelInfo) bool { return model.SupportsReasoningSummary })
	result.SupportsVerbosity = allModelBools(models, func(model codex.ModelInfo) bool { return model.SupportsVerbosity })
	result.SupportsParallelToolCalls = allModelBools(models, func(model codex.ModelInfo) bool { return model.SupportsParallelToolCalls })
	result.SupportsImageDetailOriginal = allModelBools(models, func(model codex.ModelInfo) bool { return model.SupportsImageDetailOriginal })
	result.SupportsSearchTool = allModelBools(models, func(model codex.ModelInfo) bool { return model.SupportsSearchTool })
	result.ReasoningEfforts = intersectStrings(models, func(model codex.ModelInfo) []string { return model.ReasoningEfforts })
	result.InputModalities = intersectStrings(models, func(model codex.ModelInfo) []string { return model.InputModalities })
	result.AdditionalSpeedTiers = intersectStrings(models, func(model codex.ModelInfo) []string { return model.AdditionalSpeedTiers })
	result.ExperimentalSupportedTools = intersectStrings(models, func(model codex.ModelInfo) []string { return model.ExperimentalSupportedTools })
	result.ContextWindow = minimumPositiveInt64(models, func(model codex.ModelInfo) int64 { return model.ContextWindow })
	result.MaxContextWindow = minimumPositiveInt64(models, func(model codex.ModelInfo) int64 { return model.MaxContextWindow })
	result.MaxOutputTokens = minimumPositiveInt64(models, func(model codex.ModelInfo) int64 { return model.MaxOutputTokens })
	result.AutoCompactTokenLimit = minimumPositiveInt64(models, func(model codex.ModelInfo) int64 { return model.AutoCompactTokenLimit })
	if result.Object == "" {
		result.Object = "model"
	}
	if result.OwnedBy == "" {
		result.OwnedBy = "openai"
	}
	return result
}

func mergeCapabilities(models []codex.ModelInfo) codex.ModelCapabilities {
	if len(models) == 0 {
		return nil
	}
	result := make(codex.ModelCapabilities)
	for key, first := range models[0].Capabilities {
		values := make([]any, len(models))
		values[0] = first
		present := true
		for index := 1; index < len(models); index++ {
			value, ok := models[index].Capabilities[key]
			if !ok {
				present = false
				break
			}
			values[index] = value
		}
		if !present {
			continue
		}
		value, ok := mergeCapabilityValues(values)
		if ok {
			result[key] = value
		}
	}
	if len(result) == 0 {
		return nil
	}
	return result
}

func mergeCapabilityValues(values []any) (any, bool) {
	if len(values) == 0 {
		return nil, false
	}
	switch first := values[0].(type) {
	case bool:
		for _, value := range values[1:] {
			if other, ok := value.(bool); !ok {
				return nil, false
			} else if !other {
				return false, true
			}
		}
		return first, true
	case float64:
		minimum := first
		for _, value := range values[1:] {
			other, ok := value.(float64)
			if !ok {
				return nil, false
			}
			if other < minimum {
				minimum = other
			}
		}
		return minimum, true
	case []any:
		intersection := append([]any(nil), first...)
		for _, value := range values[1:] {
			other, ok := value.([]any)
			if !ok {
				return nil, false
			}
			filtered := intersection[:0]
			for _, candidate := range intersection {
				for _, item := range other {
					if sameJSONValue(candidate, item) {
						filtered = append(filtered, candidate)
						break
					}
				}
			}
			intersection = filtered
		}
		return intersection, true
	default:
		for _, value := range values[1:] {
			if !sameJSONValue(first, value) {
				return nil, false
			}
		}
		return first, true
	}
}

func allModelMessagesEqual(models []codex.ModelInfo) bool {
	if len(models) == 0 || len(models[0].ModelMessages) == 0 {
		return false
	}
	for _, model := range models[1:] {
		if !bytes.Equal(models[0].ModelMessages, model.ModelMessages) {
			return false
		}
	}
	return true
}

func allModelBools(models []codex.ModelInfo, value func(codex.ModelInfo) bool) bool {
	for _, model := range models {
		if !value(model) {
			return false
		}
	}
	return len(models) > 0
}

func intersectStrings(models []codex.ModelInfo, value func(codex.ModelInfo) []string) []string {
	if len(models) == 0 {
		return nil
	}
	result := append([]string(nil), value(models[0])...)
	for _, model := range models[1:] {
		allowed := make(map[string]struct{}, len(value(model)))
		for _, item := range value(model) {
			allowed[item] = struct{}{}
		}
		filtered := result[:0]
		for _, item := range result {
			if _, ok := allowed[item]; ok {
				filtered = append(filtered, item)
			}
		}
		result = filtered
	}
	if len(result) == 0 {
		return nil
	}
	return result
}

func minimumPositiveInt64(models []codex.ModelInfo, value func(codex.ModelInfo) int64) int64 {
	if len(models) == 0 {
		return 0
	}
	minimum := int64(0)
	for _, model := range models {
		current := value(model)
		if current <= 0 {
			return 0
		}
		if minimum == 0 || current < minimum {
			minimum = current
		}
	}
	return minimum
}

func sameJSONValue(left, right any) bool {
	leftBytes, leftErr := json.Marshal(left)
	rightBytes, rightErr := json.Marshal(right)
	return leftErr == nil && rightErr == nil && bytes.Equal(leftBytes, rightBytes)
}
func modelObjectFromInfo(model codex.ModelInfo) modelObject {
	return modelObject{
		ID: model.ID, Object: "model", Created: model.Created, OwnedBy: model.OwnedBy,
		DisplayName: model.DisplayName, Description: model.Description,
		ContextWindow: model.ContextWindow, MaxOutput: model.MaxOutputTokens,
		Capabilities: model.Capabilities, ModelMessages: append([]byte(nil), model.ModelMessages...),
	}
}

func modelETagMatches(header, etag string) bool {
	if len(header) > maxModelCatalogETagBytes*4 || strings.ContainsAny(header, "\r\n") {
		return false
	}
	etag = normalizeModelCatalogETag(etag)
	if etag == "" {
		return false
	}
	for _, candidate := range strings.Split(header, ",") {
		candidate = strings.TrimSpace(candidate)
		if candidate == "*" {
			return true
		}
		if strings.HasPrefix(candidate, "W/") {
			candidate = strings.TrimSpace(strings.TrimPrefix(candidate, "W/"))
		}
		if candidate == etag {
			return true
		}
	}
	return false
}
