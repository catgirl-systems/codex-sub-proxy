package server

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/catgirl-systems/codex-sub-proxy/internal/envelope"
	"github.com/catgirl-systems/codex-sub-proxy/internal/storage"
)

func TestAdminLifecycleExportRejectsJournalTampering(t *testing.T) {
	db, err := storage.Open(context.Background(), t.TempDir()+"/lifecycle-integrity.sqlite3", time.Second)
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
	adminStore := NewAdminTokenStore(db, []byte("lifecycle-integrity-admin-hmac"))
	if _, err := adminStore.MaterializeBootstrap(context.Background(), []byte(raw)); err != nil {
		t.Fatal(err)
	}
	key, err := envelope.NewKey(1, bytes.Repeat([]byte{0x54}, envelope.KeySize))
	if err != nil {
		t.Fatal(err)
	}
	keys, err := envelope.NewKeySet(key)
	if err != nil {
		t.Fatal(err)
	}
	journal, err := newJournalWithKeys(db, journalModeDurable, 8, time.Second, keys)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = journal.Close(context.Background()) })
	request, err := journal.BeginRequestWithMetadata(context.Background(), JournalRequestMetadata{Endpoint: "/v1/responses", Model: "integrity-model"}, []byte(`{"input":true}`))
	if err != nil {
		t.Fatal(err)
	}
	if err := journal.Replay(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := journal.Forward(context.Background(), request, "response.json", []byte(`{"output":true}`), func(context.Context, string) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if err := journal.Replay(context.Background()); err != nil {
		t.Fatal(err)
	}

	app, err := newAdminApplicationWithLifecycle(NewReadiness(), adminStore, nil, adminLifecycleDependencies{db: db, keys: keys})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(app)
	defer server.Close()
	getExport := func(path string) (int, string) {
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
		defer response.Body.Close()
		body, err := io.ReadAll(response.Body)
		if err != nil {
			t.Fatal(err)
		}
		return response.StatusCode, string(body)
	}
	countAudits := func(action, target string) int64 {
		t.Helper()
		var count int64
		if err := db.Model(&AuditRecord{}).Where("action = ? AND target_id = ?", action, target).Count(&count).Error; err != nil {
			t.Fatal(err)
		}
		return count
	}

	requestExportPath := adminRequestsEndpoint + "/" + request.ID + "/export"
	status, body := getExport(requestExportPath)
	if status != http.StatusOK || !strings.Contains(body, `"output":true`) {
		t.Fatalf("valid request export status=%d body=%s", status, body)
	}
	if got := countAudits("request.content_export", request.ID); got != 1 {
		t.Fatalf("valid request export audit count = %d", got)
	}

	var responseRecord JournalRecord
	if err := db.Where("request_id = ? AND event_type = ?", request.ID, "response.json").First(&responseRecord).Error; err != nil {
		t.Fatal(err)
	}
	writeRecord := func(record JournalRecord) {
		t.Helper()
		if err := db.Model(&JournalRecord{}).Where("replay_id = ?", responseRecord.ReplayID).Updates(map[string]any{
			"sequence": record.Sequence, "mode": record.Mode, "event_type": record.EventType,
			"event_version": record.EventVersion, "key_version": record.KeyVersion,
			"payload": record.Payload, "checksum": record.Checksum, "created_at": record.CreatedAt,
		}).Error; err != nil {
			t.Fatal(err)
		}
	}
	tamperCases := []struct {
		name   string
		mutate func(JournalRecord) JournalRecord
	}{
		{name: "checksum", mutate: func(record JournalRecord) JournalRecord {
			record.Checksum = []byte("tampered")
			return record
		}},
		{name: "event type", mutate: func(record JournalRecord) JournalRecord {
			record.EventType = ""
			return record
		}},
		{name: "sequence", mutate: func(record JournalRecord) JournalRecord {
			record.Sequence++
			return record
		}},
		{name: "created time", mutate: func(record JournalRecord) JournalRecord {
			record.CreatedAt = time.Time{}
			return record
		}},
		{name: "mode", mutate: func(record JournalRecord) JournalRecord {
			record.Mode = "tampered"
			return record
		}},
		{name: "event version", mutate: func(record JournalRecord) JournalRecord {
			record.EventVersion++
			return record
		}},
		{name: "key version", mutate: func(record JournalRecord) JournalRecord {
			record.KeyVersion = 0
			return record
		}},
		{name: "ciphertext", mutate: func(record JournalRecord) JournalRecord {
			record.Payload = append([]byte(nil), record.Payload...)
			record.Payload[len(record.Payload)-1] ^= 1
			record.Checksum = journalChecksum(record)
			return record
		}},
	}
	for index, testCase := range tamperCases {
		t.Run(testCase.name, func(t *testing.T) {
			tampered := testCase.mutate(responseRecord)
			writeRecord(tampered)
			status, body := getExport(requestExportPath)
			if status != http.StatusInternalServerError {
				t.Fatalf("tampered request export status = %d body=%s", status, body)
			}
			if strings.Contains(body, `"metadata"`) || strings.Contains(body, `"events"`) {
				t.Fatalf("tampered request export returned content body = %s", body)
			}
			if got, want := countAudits("request.content_export", request.ID), int64(index+2); got != want {
				t.Fatalf("tampered request export audit count = %d, want %d", got, want)
			}
			writeRecord(responseRecord)
		})
	}

	conversationExportPath := adminConversationsEndpoint + "/" + request.ConversationID + "/export"
	status, body = getExport(conversationExportPath)
	if status != http.StatusOK || !strings.Contains(body, `"output":true`) {
		t.Fatalf("valid conversation export status=%d body=%s", status, body)
	}
	if got := countAudits("conversation.content_export", request.ConversationID); got != 1 {
		t.Fatalf("valid conversation export audit count = %d", got)
	}
	conversationTampered := responseRecord
	conversationTampered.Mode = "tampered"
	writeRecord(conversationTampered)
	status, body = getExport(conversationExportPath)
	if status != http.StatusInternalServerError || strings.Contains(body, `"metadata"`) || strings.Contains(body, `"events"`) {
		t.Fatalf("tampered conversation export status=%d body=%s", status, body)
	}
	if got := countAudits("conversation.content_export", request.ConversationID); got != 2 {
		t.Fatalf("tampered conversation export audit count = %d", got)
	}
	writeRecord(responseRecord)
}
