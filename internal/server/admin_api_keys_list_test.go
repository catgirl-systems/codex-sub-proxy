package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/catgirl-systems/codex-sub-proxy/internal/apikey"
	"github.com/catgirl-systems/codex-sub-proxy/internal/storage"
)

func TestAdminAPIKeyListCursorIsStableAndBounded(t *testing.T) {
	db, err := storage.Open(context.Background(), t.TempDir()+"/list.sqlite3", time.Second)
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
	apiHMAC := []byte("api-key-hmac-key-for-list-012345678901")
	for index := range 3 {
		if _, _, err := apikey.Create(context.Background(), db, apiHMAC, apikey.Policy{
			Name:             "list-" + string(rune('a'+index)),
			Owner:            "list-owner",
			AllowedEndpoints: []string{modelsEndpoint},
			AllowedModels:    []string{"gpt-a"},
		}); err != nil {
			t.Fatal(err)
		}
	}
	app, err := newAdminApplication(NewReadiness(), adminStore, apikey.NewStore(db, apiHMAC))
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(app)
	defer server.Close()
	seen := make(map[string]bool)
	cursor := ""
	for page := 0; page < 4; page++ {
		url := server.URL + adminAPIKeysEndpoint + "?limit=1"
		if cursor != "" {
			url += "&cursor=" + cursor
		}
		request, err := http.NewRequest(http.MethodGet, url, nil)
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Authorization", "Bearer "+adminRaw)
		response, err := http.DefaultClient.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		var payload struct {
			Data       []adminAPIKeyMetadata `json:"data"`
			NextCursor string                `json:"next_cursor"`
		}
		if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
			response.Body.Close()
			t.Fatal(err)
		}
		response.Body.Close()
		if response.StatusCode != http.StatusOK || len(payload.Data) > 1 {
			t.Fatalf("page status/count = %d/%d", response.StatusCode, len(payload.Data))
		}
		for _, record := range payload.Data {
			if seen[record.ID] {
				t.Fatalf("record %q repeated", record.ID)
			}
			seen[record.ID] = true
		}
		if payload.NextCursor == "" {
			break
		}
		if len(payload.NextCursor) > adminAPIKeyMaxCursor {
			t.Fatalf("cursor length = %d", len(payload.NextCursor))
		}
		cursor = payload.NextCursor
	}
	if len(seen) != 3 {
		t.Fatalf("seen records = %d, want 3", len(seen))
	}
	for _, query := range []string{"?limit=101", "?offset=1", "?unknown=x"} {
		request, err := http.NewRequest(http.MethodGet, server.URL+adminAPIKeysEndpoint+query, nil)
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Authorization", "Bearer "+adminRaw)
		response, err := http.DefaultClient.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		if response.StatusCode != http.StatusBadRequest {
			t.Fatalf("query %q status = %d, want 400", query, response.StatusCode)
		}
	}
}
