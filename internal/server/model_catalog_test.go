package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/catgirl-systems/codex-sub-proxy/internal/apikey"
	"github.com/catgirl-systems/codex-sub-proxy/internal/codex"
	"github.com/catgirl-systems/codex-sub-proxy/internal/envelope"
	"github.com/catgirl-systems/codex-sub-proxy/internal/storage"
	"gorm.io/gorm"
)

func TestModelCatalogUnionMergeFilterAndAccountLite(t *testing.T) {
	var mu sync.Mutex
	mode := map[string]string{"account-a": "a", "account-b": "b"}
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		mu.Lock()
		current := mode[request.Header.Get(codex.AccountIDHeader)]
		mu.Unlock()
		writer.Header().Set("ETag", `"`+current+`"`)
		writer.Header().Set("Content-Type", "application/json")
		if current == "a" {
			_, _ = writer.Write([]byte(`{"models":[{"slug":"shared","display_name":"Shared","description":"description-a","supported_in_api":true,"visibility":"list","capabilities":{"supports_reasoning":true,"common":1},"model_messages":{"source":"a"},"use_responses_lite":true},{"slug":"hidden","supported_in_api":true,"visibility":"hide"}]}`))
			return
		}
		_, _ = writer.Write([]byte(`{"models":[{"slug":"shared","display_name":"Shared","description":"description-b","supported_in_api":true,"visibility":"list","capabilities":{"supports_reasoning":false,"common":1},"model_messages":{"source":"b"}},{"slug":"other","supported_in_api":true,"visibility":"list"}]}`))
	}))
	defer server.Close()
	db, err := storage.Open(context.Background(), filepath.Join(t.TempDir(), "catalog.sqlite"), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatal(err)
	}
	defer sqlDB.Close()
	if err := MigrateSchema(db); err != nil {
		t.Fatal(err)
	}
	keys := testModelCatalogKeys(t)
	profiles := make([]BrokerProfile, 0, 2)
	for _, accountID := range []string{"account-a", "account-b"} {
		credentialPath := filepath.Join(t.TempDir(), accountID+".enc")
		if err := codex.SaveCredential(credentialPath, codex.Credential{AccessToken: accountID + "-access", RefreshToken: accountID + "-refresh", AccountID: accountID, ExpiresAt: time.Now().Add(time.Hour)}, keys); err != nil {
			t.Fatal(err)
		}
		refresher, err := codex.NewRefresher(credentialPath, keys, codex.RefresherOptions{Issuer: server.URL, ClientID: "client", HTTPClient: server.Client()})
		if err != nil {
			t.Fatal(err)
		}
		models, err := codex.NewModelsClient(codex.ModelsClientOptions{ModelsURL: server.URL, ClientVersion: "test", HTTPClient: server.Client(), Refresher: refresher})
		if err != nil {
			t.Fatal(err)
		}
		profiles = append(profiles, BrokerProfile{Account: codex.Account{ID: accountID, Enabled: true, Available: true}, Responses: &codex.ResponsesTransport{}, Models: models})
	}
	broker, err := NewProfileBroker(&codex.RoundRobinSelector{}, profiles)
	if err != nil {
		t.Fatal(err)
	}
	store, err := NewModelCatalogStore(db)
	if err != nil {
		t.Fatal(err)
	}
	manager, err := NewModelCatalogManager(store, broker, ModelCatalogOptions{TTL: time.Hour, RequestTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	data, models, ready := manager.PublicModels([]string{"other", "shared"})
	if !ready || len(data) != 2 || len(models) != 2 || data[0].ID != "other" || data[1].ID != "shared" {
		t.Fatalf("filtered models = %#v/%#v, ready=%v", data, models, ready)
	}
	if models[1].Description != "description-a" || len(models[1].ModelMessages) != 0 || models[1].Capabilities["supports_reasoning"] != false || models[1].Capabilities["common"] != float64(1) {
		t.Fatalf("conservative model merge = %#v", models[1])
	}
	accounts := broker.Accounts()
	for _, account := range accounts {
		if account.ID == "account-a" && !account.ResponsesLiteModels["shared"] {
			t.Fatal("account A lost responses-lite capability")
		}
		if account.ID == "account-b" && account.ResponsesLiteModels["shared"] {
			t.Fatal("account B inherited account A responses-lite capability")
		}
	}
}

func TestModelCatalogMergeIntersectsCapabilitiesAndUsesDefaultDescription(t *testing.T) {
	merged := mergeModelInfo("shared", []codex.ModelInfo{
		{
			ID: "a", Slug: "shared", DisplayName: "Default", Description: "default description",
			InputModalities: []string{"text", "image"}, ReasoningEfforts: []string{"low", "high"},
			ContextWindow: 128, MaxOutputTokens: 4096, SupportsParallelToolCalls: true,
			Capabilities: codex.ModelCapabilities{"limits": float64(8), "features": []any{"a", "b"}, "safe": true},
		},
		{
			ID: "b", Slug: "shared", DisplayName: "Other", Description: "other description",
			InputModalities: []string{"text"}, ReasoningEfforts: []string{"low"},
			ContextWindow: 64, MaxOutputTokens: 2048, SupportsParallelToolCalls: false,
			Capabilities: codex.ModelCapabilities{"limits": float64(4), "features": []any{"b", "c"}, "safe": true},
		},
	})
	if merged.Description != "default description" || merged.DisplayName != "Default" {
		t.Fatalf("default descriptive metadata = %#v", merged)
	}
	if len(merged.InputModalities) != 1 || merged.InputModalities[0] != "text" || len(merged.ReasoningEfforts) != 1 || merged.ReasoningEfforts[0] != "low" {
		t.Fatalf("intersected model lists = %#v", merged)
	}
	if merged.ContextWindow != 64 || merged.MaxOutputTokens != 2048 || merged.SupportsParallelToolCalls {
		t.Fatalf("conservative model limits/bools = %#v", merged)
	}
	if merged.Capabilities["limits"] != float64(4) || merged.Capabilities["safe"] != true {
		t.Fatalf("intersected capabilities = %#v", merged.Capabilities)
	}
}

func TestModelCatalogStaleRefreshAndNoCacheReadiness(t *testing.T) {
	var mu sync.Mutex
	status := http.StatusOK
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		mu.Lock()
		current := status
		mu.Unlock()
		if current != http.StatusOK {
			writer.WriteHeader(current)
			return
		}
		writer.Header().Set("ETag", `"stable"`)
		_, _ = writer.Write([]byte(`{"models":[{"slug":"stable","supported_in_api":true,"visibility":"list"}]}`))
	}))
	defer server.Close()
	broker, manager, db := newModelCatalogTestBroker(t, server.URL, "account-a", 20*time.Millisecond)
	defer closeModelCatalogTestBroker(t, manager, db)
	if !broker.Ready() {
		t.Fatal("catalog startup was not ready")
	}
	mu.Lock()
	status = http.StatusInternalServerError
	mu.Unlock()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if len(manager.Snapshot()) == 1 && manager.Snapshot()[0].FetchedAt.Before(time.Now()) {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if !broker.Ready() {
		t.Fatal("stale catalog became unavailable after provider outage")
	}

	noCacheBroker, noCacheManager, noCacheDB := newModelCatalogTestBroker(t, server.URL, "account-b", time.Hour)
	defer closeModelCatalogTestBroker(t, noCacheManager, noCacheDB)
	mu.Lock()
	status = http.StatusInternalServerError
	mu.Unlock()
	if err := noCacheManager.refreshAll(context.Background()); err != nil {
		t.Fatal(err)
	}
	if noCacheBroker.Ready() {
		t.Fatal("no-cache broker reported ready during provider outage")
	}
}

func TestDynamicModelsEndpointETagAndOpenAIEnvelope(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		_, _ = writer.Write([]byte(`{"models":[{"slug":"visible","display_name":"Visible","supported_in_api":true,"visibility":"list","capabilities":{"supports_reasoning":true}}]}`))
	}))
	defer server.Close()
	broker, manager, db := newModelCatalogTestBroker(t, server.URL, "account-a", time.Hour)
	defer closeModelCatalogTestBroker(t, manager, db)
	key := []byte("model-endpoint-hmac-key-012345678901")
	if err := apikey.Migrate(db); err != nil {
		t.Fatal(err)
	}
	rawKey, _, err := apikey.Create(context.Background(), db, key, apikey.Policy{Name: "models", Owner: "models", AllowedEndpoints: []string{modelsEndpoint}, AllowedModels: []string{"visible"}})
	if err != nil {
		t.Fatal(err)
	}
	app, err := newDataApplication(NewReadiness(), db, key, broker, nil, nil, nil, false, applicationPolicy{listener: "data"})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, modelsEndpoint, nil)
	request.Header.Set("Authorization", "Bearer "+rawKey)
	response := httptest.NewRecorder()
	app.ServeHTTP(response, request)
	if response.Code != http.StatusOK || response.Header().Get("ETag") == "" {
		t.Fatalf("models response status/etag = %d/%q", response.Code, response.Header().Get("ETag"))
	}
	var envelope struct {
		Data   []map[string]any  `json:"data"`
		Models []codex.ModelInfo `json:"models"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	if len(envelope.Data) != 1 || len(envelope.Models) != 1 || envelope.Models[0].Capabilities["supports_reasoning"] != true {
		t.Fatalf("dual envelope = %#v", envelope)
	}
	request = httptest.NewRequest(http.MethodGet, modelsEndpoint, nil)
	request.Header.Set("Authorization", "Bearer "+rawKey)
	request.Header.Set("If-None-Match", `W/`+response.Header().Get("ETag")+`, "other"`)
	response = httptest.NewRecorder()
	app.ServeHTTP(response, request)
	if response.Code != http.StatusNotModified || response.Body.Len() != 0 {
		t.Fatalf("weak/list conditional models response = %d/%q", response.Code, response.Body.String())
	}
	request = httptest.NewRequest(http.MethodGet, modelsEndpoint, nil)
	request.Header.Set("Authorization", "Bearer "+rawKey)
	request.Header.Set("If-None-Match", "*")
	response = httptest.NewRecorder()
	app.ServeHTTP(response, request)
	if response.Code != http.StatusNotModified || response.Body.Len() != 0 {
		t.Fatalf("wildcard conditional models response = %d/%q", response.Code, response.Body.String())
	}
}

func TestModelCatalogStandardDataPersistsAcrossRestart(t *testing.T) {
	db, err := storage.Open(context.Background(), filepath.Join(t.TempDir(), "catalog.sqlite"), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatal(err)
	}
	defer sqlDB.Close()
	if err := MigrateSchema(db); err != nil {
		t.Fatal(err)
	}
	store, err := NewModelCatalogStore(db)
	if err != nil {
		t.Fatal(err)
	}
	models := []codex.ModelInfo{{ID: "standard", Slug: "standard", SupportedInAPI: false, Visibility: "hide"}}
	fetchedAt := time.Now().UTC()
	if err := store.SaveWithSource(context.Background(), "account", models, `"standard"`, fetchedAt, false); err != nil {
		t.Fatal(err)
	}
	var record ModelCatalogRecord
	if err := db.Where("account_id = ?", "account").First(&record).Error; err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(record.CatalogJSON, `"data"`) || strings.Contains(record.CatalogJSON, `"models"`) {
		t.Fatalf("standard catalog provenance = %s", record.CatalogJSON)
	}
	restartedStore, err := NewModelCatalogStore(db)
	if err != nil {
		t.Fatal(err)
	}
	state, found, err := restartedStore.Load(context.Background(), "account")
	if err != nil || !found || len(state.models) != 1 || state.models[0].ID != "standard" {
		t.Fatalf("restarted standard catalog = %#v, found=%v, err=%v", state, found, err)
	}
	if state.models[0].CatalogUsable() != true {
		t.Fatal("standard data catalog acquired provider filtering on restart")
	}
}

func TestModelCatalogBackgroundPersistenceFailureIsOperational(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		_, _ = writer.Write([]byte(`{"models":[{"slug":"stable","supported_in_api":true,"visibility":"list"}]}`))
	}))
	defer upstream.Close()
	broker, manager, db := newModelCatalogTestBroker(t, upstream.URL, "account", 10*time.Millisecond)
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatal(err)
	}
	if err := sqlDB.Close(); err != nil {
		t.Fatal(err)
	}
	defer manager.Close(context.Background())
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && manager.OperationalError() == nil {
		time.Sleep(5 * time.Millisecond)
	}
	if err := manager.OperationalError(); err == nil {
		t.Fatal("background persistence failure was discarded")
	}
	if broker.Ready() {
		t.Fatal("broker remained ready after cache persistence failure")
	}
}

func TestModelCatalogOversizedCacheIgnoredAndRefreshed(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		_, _ = writer.Write([]byte(`{"models":[{"slug":"fresh","supported_in_api":true,"visibility":"list"}]}`))
	}))
	defer upstream.Close()
	db, err := storage.Open(context.Background(), filepath.Join(t.TempDir(), "catalog.sqlite"), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatal(err)
	}
	defer sqlDB.Close()
	if err := MigrateSchema(db); err != nil {
		t.Fatal(err)
	}
	if err := db.Create(&ModelCatalogRecord{
		AccountID: "account", CatalogJSON: strings.Repeat("x", codex.MaxModelCatalogBytes+1), FetchedAt: time.Now().UTC(),
	}).Error; err != nil {
		t.Fatal(err)
	}
	store, err := NewModelCatalogStore(db)
	if err != nil {
		t.Fatal(err)
	}
	if _, found, err := store.Load(context.Background(), "account"); err != nil || found {
		t.Fatalf("oversized cache load = found=%v, err=%v", found, err)
	}
	multibyte := strings.Repeat("é", codex.MaxModelCatalogBytes/2+1)
	if len(multibyte) <= codex.MaxModelCatalogBytes || utf8.RuneCountInString(multibyte) >= codex.MaxModelCatalogBytes {
		t.Fatalf("multibyte bound fixture has unexpected size: bytes=%d runes=%d", len(multibyte), utf8.RuneCountInString(multibyte))
	}
	if err := db.Create(&ModelCatalogRecord{
		AccountID: "multibyte", CatalogJSON: multibyte, FetchedAt: time.Now().UTC(),
	}).Error; err != nil {
		t.Fatal(err)
	}
	if _, found, err := store.Load(context.Background(), "multibyte"); err != nil || found {
		t.Fatalf("multibyte oversized cache load = found=%v, err=%v", found, err)
	}
	keys := testModelCatalogKeys(t)
	credentialPath := filepath.Join(t.TempDir(), "credential.enc")
	if err := codex.SaveCredential(credentialPath, codex.Credential{AccessToken: "access", RefreshToken: "refresh", AccountID: "account", ExpiresAt: time.Now().Add(time.Hour)}, keys); err != nil {
		t.Fatal(err)
	}
	refresher, err := codex.NewRefresher(credentialPath, keys, codex.RefresherOptions{Issuer: upstream.URL, ClientID: "client"})
	if err != nil {
		t.Fatal(err)
	}
	models, err := codex.NewModelsClient(codex.ModelsClientOptions{ModelsURL: upstream.URL, ClientVersion: "test", HTTPClient: upstream.Client(), Refresher: refresher})
	if err != nil {
		t.Fatal(err)
	}
	broker, err := NewProfileBroker(codex.SingleSelector{}, []BrokerProfile{{Account: codex.Account{ID: "account", Enabled: true, Available: true}, Responses: &codex.ResponsesTransport{}, Models: models}})
	if err != nil {
		t.Fatal(err)
	}
	manager, err := NewModelCatalogManager(store, broker, ModelCatalogOptions{TTL: time.Hour, RequestTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer manager.Close(context.Background())
	snapshot := manager.Snapshot()
	if len(snapshot) != 1 || !snapshot[0].Loaded || len(snapshot[0].Models) != 1 || snapshot[0].Models[0].ID != "fresh" {
		t.Fatalf("refreshed catalog after oversized cache = %#v", snapshot)
	}
}

func TestModelCatalogRefreshAllCloseJoinsWorker(t *testing.T) {
	var mu sync.Mutex
	requests := 0
	started := make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		mu.Lock()
		requests++
		current := requests
		mu.Unlock()
		if current > 1 {
			close(started)
			<-request.Context().Done()
			return
		}
		_, _ = writer.Write([]byte(`{"models":[{"slug":"stable","supported_in_api":true,"visibility":"list"}]}`))
	}))
	defer upstream.Close()
	_, manager, db := newModelCatalogTestBroker(t, upstream.URL, "account", time.Hour)
	refreshDone := make(chan error, 1)
	go func() { refreshDone <- manager.refreshAll(context.Background()) }()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("refresh worker did not reach blocked upstream")
	}
	closeDone := make(chan error, 1)
	go func() { closeDone <- manager.Close(context.Background()) }()
	select {
	case err := <-closeDone:
		if err != nil {
			t.Fatalf("close while refreshing: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("close did not join refresh worker")
	}
	if err := <-refreshDone; !errors.Is(err, context.Canceled) {
		t.Fatalf("refresh result = %v, want context canceled", err)
	}
	sqlDB, err := db.DB()
	if err == nil {
		_ = sqlDB.Close()
	}
}

func TestModelCatalogCloseJoinsBlockedStoreOperation(t *testing.T) {
	var mu sync.Mutex
	requests := 0
	refreshRequest := make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		mu.Lock()
		requests++
		current := requests
		mu.Unlock()
		if current > 1 {
			close(refreshRequest)
		}
		_, _ = writer.Write([]byte(`{"models":[{"slug":"stable","supported_in_api":true,"visibility":"list"}]}`))
	}))
	defer upstream.Close()
	_, manager, db := newModelCatalogTestBroker(t, upstream.URL, "account", time.Hour)
	var databases []struct {
		File string `gorm:"column:file"`
	}
	if err := db.Raw("PRAGMA database_list").Scan(&databases).Error; err != nil || len(databases) != 1 || databases[0].File == "" {
		t.Fatalf("database path = %#v, err=%v", databases, err)
	}
	lockDB, err := storage.Open(context.Background(), databases[0].File, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if sqlDB, dbErr := lockDB.DB(); dbErr == nil {
			_ = sqlDB.Close()
		}
	}()
	lockTx := lockDB.Begin()
	if lockTx.Error != nil {
		t.Fatal(lockTx.Error)
	}
	if err := lockTx.Exec("UPDATE model_catalogs SET etag = etag WHERE account_id = ?", "account").Error; err != nil {
		t.Fatal(err)
	}
	refreshDone := make(chan error, 1)
	go func() { refreshDone <- manager.refreshAll(context.Background()) }()
	select {
	case <-refreshRequest:
	case <-time.After(time.Second):
		t.Fatal("refresh did not reach upstream")
	}
	closeContext, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	closeDone := make(chan error, 1)
	go func() { closeDone <- manager.Close(closeContext) }()
	time.AfterFunc(150*time.Millisecond, func() { _ = lockTx.Rollback().Error })
	select {
	case err := <-closeDone:
		if err != nil && !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("deadline close error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("deadline close did not return promptly")
	}
	secondDone := make(chan error, 1)
	go func() { secondDone <- manager.Close(context.Background()) }()
	select {
	case err := <-secondDone:
		if err != nil {
			t.Fatalf("joining close: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("second close did not join blocked store worker")
	}
	if err := <-refreshDone; err != nil && !errors.Is(err, context.Canceled) {
		t.Fatalf("refresh error = %v", err)
	}
}

func testModelCatalogKeys(t *testing.T) envelope.KeySet {
	t.Helper()
	key, err := envelope.NewKey(1, make([]byte, envelope.KeySize))
	if err != nil {
		t.Fatal(err)
	}
	keys, err := envelope.NewKeySet(key)
	if err != nil {
		t.Fatal(err)
	}
	return keys
}

func newModelCatalogTestBroker(t *testing.T, endpoint, accountID string, ttl time.Duration) (*ProfileBroker, *ModelCatalogManager, *gorm.DB) {
	t.Helper()
	db, err := storage.Open(context.Background(), filepath.Join(t.TempDir(), "catalog.sqlite"), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if err := MigrateSchema(db); err != nil {
		t.Fatal(err)
	}
	keys := testModelCatalogKeys(t)
	credentialPath := filepath.Join(t.TempDir(), "credential.enc")
	if err := codex.SaveCredential(credentialPath, codex.Credential{AccessToken: "access", RefreshToken: "refresh", AccountID: accountID, ExpiresAt: time.Now().Add(time.Hour)}, keys); err != nil {
		t.Fatal(err)
	}
	refresher, err := codex.NewRefresher(credentialPath, keys, codex.RefresherOptions{Issuer: endpoint, ClientID: "client"})
	if err != nil {
		t.Fatal(err)
	}
	models, err := codex.NewModelsClient(codex.ModelsClientOptions{ModelsURL: endpoint, ClientVersion: "test", Refresher: refresher})
	if err != nil {
		t.Fatal(err)
	}
	broker, err := NewProfileBroker(codex.SingleSelector{}, []BrokerProfile{{Account: codex.Account{ID: accountID, Enabled: true, Available: true}, Responses: &codex.ResponsesTransport{}, Models: models}})
	if err != nil {
		t.Fatal(err)
	}
	store, err := NewModelCatalogStore(db)
	if err != nil {
		t.Fatal(err)
	}
	manager, err := NewModelCatalogManager(store, broker, ModelCatalogOptions{TTL: ttl, RequestTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	return broker, manager, db
}

func closeModelCatalogTestBroker(t *testing.T, manager *ModelCatalogManager, db *gorm.DB) {
	t.Helper()
	if err := manager.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if db != nil {
		sqlDB, err := db.DB()
		if err != nil {
			t.Fatal(err)
		}
		_ = sqlDB.Close()
	}
}

func TestModelCatalogCloseCancelsBlockedRefresh(t *testing.T) {
	started := make(chan struct{})
	var startOnce sync.Once
	upstream := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		startOnce.Do(func() { close(started) })
		<-request.Context().Done()
	}))
	defer upstream.Close()

	db, err := storage.Open(context.Background(), filepath.Join(t.TempDir(), "catalog.sqlite"), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatal(err)
	}
	defer sqlDB.Close()
	if err := MigrateSchema(db); err != nil {
		t.Fatal(err)
	}
	keys := testModelCatalogKeys(t)
	credentialPath := filepath.Join(t.TempDir(), "credential.enc")
	if err := codex.SaveCredential(credentialPath, codex.Credential{
		AccessToken: "access", RefreshToken: "refresh", AccountID: "account",
		ExpiresAt: time.Now().Add(time.Hour),
	}, keys); err != nil {
		t.Fatal(err)
	}
	refresher, err := codex.NewRefresher(credentialPath, keys, codex.RefresherOptions{
		Issuer: upstream.URL, ClientID: "client", HTTPClient: upstream.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}
	models, err := codex.NewModelsClient(codex.ModelsClientOptions{
		ModelsURL: upstream.URL, ClientVersion: "test", HTTPClient: upstream.Client(),
		Refresher: refresher,
	})
	if err != nil {
		t.Fatal(err)
	}
	broker, err := NewProfileBroker(codex.SingleSelector{}, []BrokerProfile{{
		Account:   codex.Account{ID: "account", Enabled: true, Available: true},
		Responses: &codex.ResponsesTransport{}, Models: models,
	}})
	if err != nil {
		t.Fatal(err)
	}
	store, err := NewModelCatalogStore(db)
	if err != nil {
		t.Fatal(err)
	}
	manager, err := NewModelCatalogManager(store, broker, ModelCatalogOptions{
		TTL: time.Hour, RequestTimeout: time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	startDone := make(chan error, 1)
	go func() { startDone <- manager.Start(context.Background()) }()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("model catalog refresh did not reach blocked upstream")
	}
	closeDone := make(chan error, 1)
	go func() { closeDone <- manager.Close(context.Background()) }()
	select {
	case err := <-closeDone:
		if err != nil {
			t.Fatalf("close model catalog: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("model catalog close did not cancel blocked refresh")
	}
	select {
	case err := <-startDone:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("start error = %v, want context canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("initial refresh goroutine survived close")
	}
}
