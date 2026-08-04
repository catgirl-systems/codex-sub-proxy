package server

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/catgirl-systems/codex-sub-proxy/internal/apikey"
	"github.com/catgirl-systems/codex-sub-proxy/internal/storage"
)

func TestAdminAPIKeyUsageAggregatesCurrentQuotaWithoutCreatingRows(t *testing.T) {
	db, err := storage.Open(context.Background(), t.TempDir()+"/usage.sqlite3", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sqlDB.Close() })
	if err := apikey.Migrate(db); err != nil {
		t.Fatal(err)
	}
	adminStore := NewAdminTokenStore(db, []byte("admin-hmac"))
	if err := MigrateAdminTokens(db); err != nil {
		t.Fatal(err)
	}
	adminRaw := adminTestToken()
	if _, err := adminStore.MaterializeBootstrap(context.Background(), []byte(adminRaw)); err != nil {
		t.Fatal(err)
	}
	apiHMAC := []byte("api-key-hmac-key-for-usage-0123456789")
	policy := apikey.Policy{
		Name:                  "usage-key",
		Owner:                 "usage-owner",
		AllowedEndpoints:      []string{modelsEndpoint},
		AllowedModels:         []string{"gpt-a"},
		MaxConcurrentRequests: 2,
		RollingRequestCount:   5,
		RollingRequestWindow:  time.Minute,
		PeriodDuration:        time.Hour,
		PeriodTokenLimit:      10,
	}
	_, record, err := apikey.Create(context.Background(), db, apiHMAC, policy)
	if err != nil {
		t.Fatal(err)
	}
	apiStore := apikey.NewStore(db, apiHMAC)
	app, err := newAdminApplication(NewReadiness(), adminStore, apiStore)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(app)
	defer server.Close()
	usageURL := server.URL + adminAPIKeysEndpoint + "/" + record.ID + "/usage"
	getUsage := func() adminAPIKeyUsageResponse {
		t.Helper()
		request, requestErr := http.NewRequest(http.MethodGet, usageURL, nil)
		if requestErr != nil {
			t.Fatal(requestErr)
		}
		request.Header.Set("Authorization", "Bearer "+adminRaw)
		response, requestErr := http.DefaultClient.Do(request)
		if requestErr != nil {
			t.Fatal(requestErr)
		}
		defer response.Body.Close()
		if response.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(response.Body)
			t.Fatalf("usage status/body = %d/%s", response.StatusCode, body)
		}
		var usage adminAPIKeyUsageResponse
		if err := json.NewDecoder(response.Body).Decode(&usage); err != nil {
			t.Fatal(err)
		}
		return usage
	}
	initial := getUsage()
	if initial.Pending.Count != 0 || initial.Period.ReservedTokens != 0 || initial.Period.ActualTokens != 0 || initial.Rolling.Count != 0 {
		t.Fatalf("initial usage = %+v", initial)
	}
	var bucketCount, stateCount int64
	if err := db.Model(&apikey.QuotaBucket{}).Where("key_id = ?", record.ID).Count(&bucketCount).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Model(&apikey.QuotaState{}).Where("key_id = ?", record.ID).Count(&stateCount).Error; err != nil {
		t.Fatal(err)
	}
	if bucketCount != 0 || stateCount != 0 {
		t.Fatalf("usage read created quota rows: buckets=%d states=%d", bucketCount, stateCount)
	}
	quotaStore, err := apikey.NewQuotaStore(db)
	if err != nil {
		t.Fatal(err)
	}
	admission, err := quotaStore.Admit(context.Background(), record.ID, policy, apikey.QuotaRequest{Requests: 1, Tokens: 4})
	if err != nil {
		t.Fatal(err)
	}
	pending := getUsage()
	if pending.Pending.Count != 1 || pending.Period.ReservedTokens != 4 || pending.Period.ActualTokens != 0 || pending.Concurrency.Active != 1 || pending.Rolling.Count != 1 {
		t.Fatalf("pending usage = %+v", pending)
	}
	if err := quotaStore.Reconcile(context.Background(), admission.ID, apikey.QuotaUsage{Requests: 1, Tokens: 3}); err != nil {
		t.Fatal(err)
	}
	final := getUsage()
	if final.Pending.Count != 0 || final.Period.ReservedTokens != 0 || final.Period.ActualTokens != 3 || final.Concurrency.Active != 0 || final.Rolling.Count != 1 {
		t.Fatalf("reconciled usage = %+v", final)
	}
}
