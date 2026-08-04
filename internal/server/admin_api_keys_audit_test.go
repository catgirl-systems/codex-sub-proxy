package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/catgirl-systems/codex-sub-proxy/internal/apikey"
	"github.com/catgirl-systems/codex-sub-proxy/internal/storage"
)

func TestAdminAPIKeyIssueRollsBackWhenAuditFails(t *testing.T) {
	db, err := storage.Open(context.Background(), t.TempDir()+"/audit-rollback.sqlite3", time.Second)
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
	if err := db.Migrator().DropTable(&AuditRecord{}); err != nil {
		t.Fatal(err)
	}
	app, err := newAdminApplication(NewReadiness(), adminStore, apikey.NewStore(db, []byte("api-key-hmac-012345678901234567890")))
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(app)
	defer server.Close()
	body, err := json.Marshal(adminAPIKeyIssueBody{
		Name:  "rollback-key",
		Owner: "rollback-owner",
		Policy: adminAPIKeyPolicy{
			AllowedEndpoints: []string{modelsEndpoint},
			AllowedModels:    []string{"gpt-a"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequest(http.MethodPost, server.URL+adminAPIKeysEndpoint, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+adminRaw)
	request.Header.Set("Content-Type", "application/json")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusInternalServerError {
		t.Fatalf("issue status = %d, want 500", response.StatusCode)
	}
	var count int64
	if err := db.Model(&apikey.Record{}).Where("name = ?", "rollback-key").Count(&count).Error; err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("rolled-back key count = %d", count)
	}
}
