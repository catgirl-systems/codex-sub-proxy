package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
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
	for index := range adminLifecycleMaxLimit + 1 {
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

func TestAdminLifecycleConversationStateFiltersAndPagination(t *testing.T) {
	db, err := storage.Open(context.Background(), t.TempDir()+"/lifecycle-conversation-page.sqlite3", time.Second)
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
	store := NewAdminTokenStore(db, []byte("conversation-pagination-hmac"))
	if _, err := store.MaterializeBootstrap(context.Background(), []byte(raw)); err != nil {
		t.Fatal(err)
	}

	at := time.Date(2026, time.January, 3, 3, 4, 5, 0, time.UTC)
	const (
		targetKey      = "key-target"
		targetEndpoint = "/v1/responses"
	)
	names := []string{"empty", "running", "succeeded", "failed", "canceled", "mixed", "deleted-child", "deleting"}
	conversationIDs := make(map[string]string, len(names))
	for index, name := range names {
		id := fmt.Sprintf("%08d-0000-4000-8000-%012d", index+1, index+1)
		conversationIDs[name] = id
		var deletingAt *time.Time
		if name == "deleting" {
			value := at.Add(time.Minute)
			deletingAt = &value
		}
		if err := db.Create(&ConversationRecord{ID: id, CreatedAt: at, UpdatedAt: at, ExpiresAt: at.Add(time.Hour), DeletingAt: deletingAt}).Error; err != nil {
			t.Fatal(err)
		}
	}

	requestIDs := make(map[string]string)
	addRequest := func(index int, name, status, key, endpoint string, deleting bool) {
		t.Helper()
		id := fmt.Sprintf("%08d-0000-4000-8000-%012d", index+100, index+100)
		replayID := fmt.Sprintf("%08d-0000-4000-8000-%012d", index+200, index+200)
		requestIDs[fmt.Sprintf("%s-%d", name, index)] = id
		var terminalAt *time.Time
		if status != requestStatusRunning {
			value := at.Add(time.Minute)
			terminalAt = &value
		}
		var deletingAt *time.Time
		if deleting {
			value := at.Add(2 * time.Minute)
			deletingAt = &value
		}
		if err := db.Create(&RequestRecord{
			ID: id, ReplayID: replayID, ConversationID: conversationIDs[name],
			APIKeyID: key, Endpoint: endpoint, Model: "state-model", Mode: journalModeDurable,
			Status: status, AcceptedAt: at, StartedAt: at, UpdatedAt: at,
			TerminalAt: terminalAt, ExpiresAt: at.Add(time.Hour), DeletingAt: deletingAt,
		}).Error; err != nil {
			t.Fatal(err)
		}
	}
	addRequest(1, "running", requestStatusRunning, targetKey, targetEndpoint, false)
	addRequest(2, "succeeded", requestStatusSucceeded, targetKey, targetEndpoint, false)
	addRequest(3, "failed", requestStatusFailed, targetKey, targetEndpoint, false)
	addRequest(4, "canceled", requestStatusCanceled, targetKey, targetEndpoint, false)
	addRequest(5, "mixed", requestStatusRunning, targetKey, targetEndpoint, false)
	addRequest(6, "mixed", requestStatusSucceeded, "key-other", "/v1/other", false)
	addRequest(7, "deleted-child", requestStatusSucceeded, targetKey, targetEndpoint, true)

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
	getConversations := func(path string) adminLifecycleListResponse[adminConversationMetadata] {
		t.Helper()
		var page adminLifecycleListResponse[adminConversationMetadata]
		if err := decodeAndClose(get(path), &page); err != nil {
			t.Fatal(err)
		}
		return page
	}
	getRequests := func(path string) adminLifecycleListResponse[adminRequestMetadata] {
		t.Helper()
		var page adminLifecycleListResponse[adminRequestMetadata]
		if err := decodeAndClose(get(path), &page); err != nil {
			t.Fatal(err)
		}
		return page
	}
	conversationNames := func(page adminLifecycleListResponse[adminConversationMetadata]) map[string]bool {
		t.Helper()
		namesByID := make(map[string]string, len(conversationIDs))
		for name, id := range conversationIDs {
			namesByID[id] = name
		}
		got := make(map[string]bool, len(page.Data))
		for _, row := range page.Data {
			name, ok := namesByID[row.ID]
			if !ok {
				t.Fatalf("unexpected conversation %q", row.ID)
			}
			got[name] = true
		}
		return got
	}

	requestNames := func(page adminLifecycleListResponse[adminRequestMetadata]) map[string]bool {
		t.Helper()
		namesByID := make(map[string]string, len(requestIDs))
		for name, id := range requestIDs {
			namesByID[id] = name
		}
		got := make(map[string]bool, len(page.Data))
		for _, row := range page.Data {
			name, ok := namesByID[row.ID]
			if !ok {
				t.Fatalf("unexpected request %q", row.ID)
			}
			got[name] = true
		}
		return got
	}

	expectedStates := map[string]map[string]bool{
		"active":    {"empty": true, "running": true, "succeeded": true, "failed": true, "canceled": true, "mixed": true, "deleted-child": true},
		"deleting":  {"deleting": true},
		"running":   {"running": true, "mixed": true},
		"succeeded": {"succeeded": true, "mixed": true},
		"failed":    {"failed": true},
		"canceled":  {"canceled": true},
	}
	for state, want := range expectedStates {
		page := getConversations(adminConversationsEndpoint + "?limit=100&state=" + url.QueryEscape(state))
		got := conversationNames(page)
		if len(got) != len(want) {
			t.Fatalf("conversation state %q returned %v, want %v", state, got, want)
		}
		for name := range want {
			if !got[name] {
				t.Fatalf("conversation state %q omitted %q: %v", state, name, got)
			}
		}
	}
	filtered := getConversations(adminConversationsEndpoint + "?limit=100&state=succeeded&key_id=" + targetKey + "&endpoint=" + url.QueryEscape(targetEndpoint) + "&from=" + url.QueryEscape(at.Format(time.RFC3339Nano)) + "&to=" + url.QueryEscape(at.Format(time.RFC3339Nano)))
	if got := conversationNames(filtered); len(got) != 1 || !got["succeeded"] {
		t.Fatalf("combined conversation filter returned %v", got)
	}

	requestStates := map[string]map[string]bool{
		"active":    {"running-1": true, "succeeded-2": true, "failed-3": true, "canceled-4": true, "mixed-5": true, "mixed-6": true},
		"deleting":  {"deleted-child-7": true},
		"running":   {"running-1": true, "mixed-5": true},
		"succeeded": {"succeeded-2": true, "mixed-6": true},
		"failed":    {"failed-3": true},
		"canceled":  {"canceled-4": true},
	}
	for state, want := range requestStates {
		page := getRequests(adminRequestsEndpoint + "?limit=100&state=" + url.QueryEscape(state))
		got := requestNames(page)
		if len(got) != len(want) {
			t.Fatalf("request state %q returned %v, want %v", state, got, want)
		}
		for name := range want {
			if !got[name] {
				t.Fatalf("request state %q omitted %q: %v", state, name, got)
			}
		}
	}
	filteredRequests := getRequests(adminRequestsEndpoint + "?limit=100&state=succeeded&key_id=" + targetKey + "&endpoint=" + url.QueryEscape(targetEndpoint))
	if got := requestNames(filteredRequests); len(got) != 1 || !got["succeeded-2"] {
		t.Fatalf("combined request filter returned %v", got)
	}

	seen := make(map[string]bool, len(conversationIDs))
	path := adminConversationsEndpoint + "?limit=2"
	for range 8 {
		page := getConversations(path)
		for _, row := range page.Data {
			if seen[row.ID] {
				t.Fatalf("conversation %q repeated during pagination", row.ID)
			}
			seen[row.ID] = true
		}
		if page.NextCursor == "" {
			break
		}
		path = adminConversationsEndpoint + "?limit=2&cursor=" + url.QueryEscape(page.NextCursor)
	}
	if len(seen) != len(conversationIDs) {
		t.Fatalf("conversation pagination returned %d rows, want %d", len(seen), len(conversationIDs))
	}
}

func decodeAndClose(response *http.Response, value any) error {
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("status %d", response.StatusCode)
	}
	return json.NewDecoder(response.Body).Decode(value)
}
