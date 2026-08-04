package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/catgirl-systems/codex-sub-proxy/internal/storage"
)

func TestAdminLifecycleRequestPaginationIsStableAtEqualTimestamps(t *testing.T) {
	db, err := storage.Open(context.Background(), t.TempDir()+"/lifecycle-page.sqlite3", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sqlDB.Close() })
	if err := MigrateJournal(db); err != nil {
		t.Fatal(err)
	}
	if err := MigrateAdminTokens(db); err != nil {
		t.Fatal(err)
	}
	raw := adminTestToken()
	store := NewAdminTokenStore(db, []byte("pagination-hmac"))
	if _, err := store.MaterializeBootstrap(context.Background(), []byte(raw)); err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
	for index := 0; index < adminLifecycleMaxLimit+1; index++ {
		id := fmt.Sprintf("%08d-0000-4000-8000-000000000000", index+1)
		replay := fmt.Sprintf("%08d-0000-4000-8000-000000000001", index+1)
		request := RequestRecord{ID: id, ReplayID: replay, ConversationID: "99999999-9999-4999-8999-999999999999", APIKeyID: "key-page", Endpoint: "/v1/responses", Model: "page-model", Mode: journalModeDurable, Status: requestStatusSucceeded, AcceptedAt: at, StartedAt: at, UpdatedAt: at, ExpiresAt: at.Add(time.Hour)}
		if err := db.Create(&request).Error; err != nil {
			t.Fatal(err)
		}
	}
	app, err := newAdminApplicationWithLifecycle(NewReadiness(), store, nil, adminLifecycleDependencies{db: db})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(app)
	defer server.Close()
	get := func(path string) *http.Response {
		t.Helper()
		req, err := http.NewRequest(http.MethodGet, server.URL+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer "+raw)
		response, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return response
	}
	first := get(adminRequestsEndpoint + "?limit=50")
	var firstPage adminLifecycleListResponse[adminRequestMetadata]
	if err := decodeAndClose(first, &firstPage); err != nil {
		t.Fatal(err)
	}
	if len(firstPage.Data) != 50 || firstPage.NextCursor == "" {
		t.Fatalf("first page = len %d cursor %q", len(firstPage.Data), firstPage.NextCursor)
	}
	second := get(adminRequestsEndpoint + "?limit=50&cursor=" + firstPage.NextCursor)
	var secondPage adminLifecycleListResponse[adminRequestMetadata]
	if err := decodeAndClose(second, &secondPage); err != nil {
		t.Fatal(err)
	}
	if len(secondPage.Data) != 50 || secondPage.NextCursor == "" {
		t.Fatalf("second page = len %d cursor %q", len(secondPage.Data), secondPage.NextCursor)
	}
	if secondPage.Data[0].ID == firstPage.Data[len(firstPage.Data)-1].ID {
		t.Fatal("cursor repeated the boundary request")
	}
	third := get(adminRequestsEndpoint + "?limit=50&cursor=" + secondPage.NextCursor)
	var thirdPage adminLifecycleListResponse[adminRequestMetadata]
	if err := decodeAndClose(third, &thirdPage); err != nil {
		t.Fatal(err)
	}
	if len(thirdPage.Data) != 1 || thirdPage.NextCursor != "" {
		t.Fatalf("third page = len %d cursor %q", len(thirdPage.Data), thirdPage.NextCursor)
	}
	filtered := get(adminRequestsEndpoint + "?limit=1&key_id=key-page&endpoint=%2Fv1%2Fresponses&state=succeeded&from=2026-01-02T03%3A04%3A05Z&to=2026-01-02T03%3A04%3A05Z")
	var filteredPage adminLifecycleListResponse[adminRequestMetadata]
	if err := decodeAndClose(filtered, &filteredPage); err != nil {
		t.Fatal(err)
	}
	if len(filteredPage.Data) != 1 || filteredPage.Data[0].APIKeyID != "key-page" {
		t.Fatalf("filtered page = %+v", filteredPage.Data)
	}
	invalid := get(adminRequestsEndpoint + "?limit=101&cursor=bad")
	if invalid.StatusCode != http.StatusBadRequest {
		invalid.Body.Close()
		t.Fatalf("invalid list status = %d", invalid.StatusCode)
	}
	invalid.Body.Close()
}

func decodeAndClose(response *http.Response, value any) error {
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("status %d", response.StatusCode)
	}
	return json.NewDecoder(response.Body).Decode(value)
}
