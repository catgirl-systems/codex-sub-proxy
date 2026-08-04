package server

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/catgirl-systems/codex-sub-proxy/internal/envelope"
	"github.com/catgirl-systems/codex-sub-proxy/internal/storage"
)

func TestAdminLifecycleRoutesMetadataAndExport(t *testing.T) {
	db, err := storage.Open(context.Background(), t.TempDir()+"/lifecycle-admin.sqlite3", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatal(err)
	}
	defer sqlDB.Close()
	if err := MigrateJournal(db); err != nil {
		t.Fatal(err)
	}
	if err := MigrateAdminTokens(db); err != nil {
		t.Fatal(err)
	}
	adminRaw := adminTestToken()
	adminStore := NewAdminTokenStore(db, []byte("admin-hmac"))
	if _, err := adminStore.MaterializeBootstrap(context.Background(), []byte(adminRaw)); err != nil {
		t.Fatal(err)
	}
	principal, err := adminStore.Authenticate(context.Background(), []byte(adminRaw))
	if err != nil {
		t.Fatal(err)
	}
	metadataRaw, _, err := adminStore.Create(context.Background(), AdminTokenCreateRequest{
		Name: "metadata-only", Scopes: AdminTokenScopes{AdminScopeMetadata},
	}, principal)
	if err != nil {
		t.Fatal(err)
	}
	key, err := envelope.NewKey(1, bytes.Repeat([]byte{0x43}, envelope.KeySize))
	if err != nil {
		t.Fatal(err)
	}
	keys, err := envelope.NewKeySet(key)
	if err != nil {
		t.Fatal(err)
	}
	artifactStore, err := NewArtifactStore(db, t.TempDir()+"/artifacts", keys, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	defer artifactStore.Close()
	journal, err := newJournalWithKeys(db, journalModeDurable, 8, time.Second, keys)
	if err != nil {
		t.Fatal(err)
	}
	request, err := journal.BeginRequestWithMetadata(context.Background(), JournalRequestMetadata{Endpoint: "/v1/responses", Model: "test-model", APIKeyID: "key-1"}, []byte(`{"input":true}`))
	if err != nil {
		t.Fatal(err)
	}
	if err := journal.Replay(context.Background()); err != nil {
		t.Fatal(err)
	}
	artifactPlaintext := []byte{0x89, 'P', 'N', 'G', '\r', '\n', 0x1a, '\n', 7}
	if _, err := artifactStore.Save(context.Background(), ArtifactOwner{RequestID: request.ID, ConversationID: request.ConversationID, APIKeyID: request.APIKeyID}, 0, "image/png", artifactPlaintext); err != nil {
		t.Fatal(err)
	}
	if err := journal.Forward(context.Background(), request, "response.json", []byte(`{"output":true}`), func(context.Context, string) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if err := journal.RecordUsage(context.Background(), request, 1, 2, 3, 0); err != nil {
		t.Fatal(err)
	}
	if err := journal.CompleteRequest(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	if err := journal.Replay(context.Background()); err != nil {
		t.Fatal(err)
	}
	retention, err := NewRetentionRunner(db, artifactStore, RetentionConfig{BatchSize: 2})
	if err != nil {
		t.Fatal(err)
	}
	app, err := newAdminApplicationWithLifecycle(NewReadiness(), adminStore, nil, adminLifecycleDependencies{db: db, keys: keys, artifacts: artifactStore, retention: retention})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(app)
	defer server.Close()
	client := &http.Client{Timeout: 3 * time.Second}
	getWithToken := func(token, path string) *http.Response {
		t.Helper()
		req, reqErr := http.NewRequest(http.MethodGet, server.URL+path, nil)
		if reqErr != nil {
			t.Fatal(reqErr)
		}
		req.Header.Set("Authorization", "Bearer "+token)
		response, reqErr := client.Do(req)
		if reqErr != nil {
			t.Fatal(reqErr)
		}
		return response
	}
	get := func(path string) *http.Response {
		return getWithToken(adminRaw, path)
	}
	response := get(adminRequestsEndpoint)
	if response.StatusCode != http.StatusOK {
		response.Body.Close()
		t.Fatalf("request list status = %d", response.StatusCode)
	}
	var list adminLifecycleListResponse[adminRequestMetadata]
	if err := json.NewDecoder(response.Body).Decode(&list); err != nil {
		response.Body.Close()
		t.Fatal(err)
	}
	response.Body.Close()
	response = get(adminRequestsEndpoint + "/" + request.ID)
	detailBody := new(bytes.Buffer)
	_, _ = detailBody.ReadFrom(response.Body)
	response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("request detail status = %d body=%s", response.StatusCode, detailBody.String())
	}
	if strings.Contains(detailBody.String(), `"input"`) || strings.Contains(detailBody.String(), `"output"`) || strings.Contains(detailBody.String(), `"payload"`) {
		t.Fatalf("request metadata contains content: %s", detailBody.String())
	}
	response = getWithToken(metadataRaw, adminRequestsEndpoint+"/"+request.ID+"/export")
	metadataExportBody := new(bytes.Buffer)
	_, _ = metadataExportBody.ReadFrom(response.Body)
	response.Body.Close()
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("metadata token export status = %d body=%s", response.StatusCode, metadataExportBody.String())
	}
	if len(list.Data) != 1 || list.Data[0].ID != request.ID || list.Data[0].State != requestStatusCanceled {
		t.Fatalf("request list = %+v", list.Data)
	}
	response = get(adminRequestsEndpoint + "/" + request.ID + "/export")
	body := new(bytes.Buffer)
	_, _ = body.ReadFrom(response.Body)
	response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("request export status = %d body=%s", response.StatusCode, body.String())
	}
	if response.Header.Get("Cache-Control") != "no-store" || response.Header.Get("Pragma") != "no-cache" || response.Header.Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("export headers = %v", response.Header)
	}
	if !strings.Contains(body.String(), `"input":`) || !strings.Contains(body.String(), `"output":true`) {
		t.Fatalf("export body = %s", body.String())
	}
	if !strings.Contains(body.String(), `"mime":"image/png"`) || !strings.Contains(body.String(), base64.StdEncoding.EncodeToString([]byte{0x89, 'P', 'N', 'G', '\r', '\n', 0x1a, '\n', 7})) {
		t.Fatalf("request artifact export = %s", body.String())
	}
	var auditCount int64
	if err := db.Model(&AuditRecord{}).Where("action = ? AND target_id = ?", "request.content_export", request.ID).Count(&auditCount).Error; err != nil {
		t.Fatal(err)
	}
	if auditCount != 1 {
		t.Fatalf("content export audit count = %d", auditCount)
	}
	response = get(adminConversationsEndpoint)
	var conversations adminLifecycleListResponse[adminConversationMetadata]
	if err := json.NewDecoder(response.Body).Decode(&conversations); err != nil {
		response.Body.Close()
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusOK || len(conversations.Data) != 1 || conversations.Data[0].ID != request.ConversationID {
		t.Fatalf("conversation list status=%d data=%+v", response.StatusCode, conversations.Data)
	}
	response = get(adminConversationsEndpoint + "/" + request.ConversationID)
	conversationDetail := new(bytes.Buffer)
	_, _ = conversationDetail.ReadFrom(response.Body)
	response.Body.Close()
	if response.StatusCode != http.StatusOK || strings.Contains(conversationDetail.String(), `"payload"`) {
		t.Fatalf("conversation detail status=%d body=%s", response.StatusCode, conversationDetail.String())
	}
	response = get(adminConversationsEndpoint + "/" + request.ConversationID + "/export")
	conversationBody := new(bytes.Buffer)
	_, _ = conversationBody.ReadFrom(response.Body)
	response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("conversation export status = %d body=%s", response.StatusCode, conversationBody.String())
	}
	var conversationExport adminContentExport
	if err := json.Unmarshal(conversationBody.Bytes(), &conversationExport); err != nil {
		t.Fatal(err)
	}
	if conversationExport.Type != "conversation" || len(conversationExport.Requests) != 1 || conversationExport.Requests[0].Input == nil {
		t.Fatalf("conversation export = %+v", conversationExport)
	}
	if err := db.Model(&AuditRecord{}).Where("action = ? AND target_id = ?", "conversation.content_export", request.ConversationID).Count(&auditCount).Error; err != nil {
		t.Fatal(err)
	}
	if auditCount != 1 {
		t.Fatalf("conversation content export audit count = %d", auditCount)
	}
	if err := db.Exec("CREATE TRIGGER fail_content_export_audit BEFORE INSERT ON audit_records WHEN NEW.action = 'request.content_export' BEGIN SELECT RAISE(ABORT, 'audit blocked'); END").Error; err != nil {
		t.Fatal(err)
	}
	response = get(adminRequestsEndpoint + "/" + request.ID + "/export")
	auditFailureBody := new(bytes.Buffer)
	_, _ = auditFailureBody.ReadFrom(response.Body)
	response.Body.Close()
	if response.StatusCode != http.StatusInternalServerError {
		t.Fatalf("audit failure export status = %d body=%s", response.StatusCode, auditFailureBody.String())
	}
	if err := db.Exec("DROP TRIGGER fail_content_export_audit").Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Model(&AuditRecord{}).Where("action = ? AND target_id = ?", "request.content_export", request.ID).Count(&auditCount).Error; err != nil {
		t.Fatal(err)
	}
	if auditCount != 1 {
		t.Fatalf("audit failure changed audit count = %d", auditCount)
	}
	if err := db.Model(&JournalRecord{}).Where("request_id = ? AND event_type = ?", request.ID, "request.input").Update("payload", []byte{1}).Error; err != nil {
		t.Fatal(err)
	}
	response = get(adminRequestsEndpoint + "/" + request.ID + "/export")
	failedExportBody := new(bytes.Buffer)
	_, _ = failedExportBody.ReadFrom(response.Body)
	response.Body.Close()
	if response.StatusCode != http.StatusInternalServerError {
		t.Fatalf("corrupt request export status = %d body=%s", response.StatusCode, failedExportBody.String())
	}
	if err := db.Model(&AuditRecord{}).Where("action = ? AND target_id = ?", "request.content_export", request.ID).Count(&auditCount).Error; err != nil {
		t.Fatal(err)
	}
	if auditCount != 2 {
		t.Fatalf("failed request export audit count = %d", auditCount)
	}
	runningRequest, err := journal.BeginRequestWithMetadata(context.Background(), JournalRequestMetadata{Endpoint: "/v1/responses", Model: "running-model"}, []byte(`{"running":true}`))
	if err != nil {
		t.Fatal(err)
	}
	if err := journal.Replay(context.Background()); err != nil {
		t.Fatal(err)
	}
	deleteRequest, err := http.NewRequest(http.MethodDelete, server.URL+adminRequestsEndpoint+"/"+runningRequest.ID, nil)
	if err != nil {
		t.Fatal(err)
	}
	deleteRequest.Header.Set("Authorization", "Bearer "+adminRaw)
	deleteResponse, err := client.Do(deleteRequest)
	if err != nil {
		t.Fatal(err)
	}
	deleteResponse.Body.Close()
	if deleteResponse.StatusCode != http.StatusConflict {
		t.Fatalf("running request delete status = %d", deleteResponse.StatusCode)
	}
	if err := journal.CompleteRequest(context.Background(), runningRequest); err != nil {
		t.Fatal(err)
	}
	if err := journal.Replay(context.Background()); err != nil {
		t.Fatal(err)
	}
}
