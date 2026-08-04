package server

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/catgirl-systems/codex-sub-proxy/internal/envelope"
	"github.com/catgirl-systems/codex-sub-proxy/internal/storage"
)

func TestDeleteRequestIsBoundedIdempotentAndAudited(t *testing.T) {
	db, err := storage.Open(context.Background(), filepath.Join(t.TempDir(), "request-delete.sqlite3"), time.Second)
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
	key, err := envelope.NewKey(1, bytes.Repeat([]byte{0x71}, envelope.KeySize))
	if err != nil {
		t.Fatal(err)
	}
	keys, err := envelope.NewKeySet(key)
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(t.TempDir(), "artifacts")
	store, err := NewArtifactStore(db, root, keys, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	owner := ArtifactOwner{
		RequestID: "11111111-1111-4111-8111-111111111111", ConversationID: "22222222-2222-4222-8222-222222222222", APIKeyID: "key-delete",
	}
	createTestArtifactOwner(t, db, owner)
	artifact, err := store.Save(context.Background(), owner, 0, "image/png", []byte{0x89, 'P', 'N', 'G', '\r', '\n', 0x1a, '\n', 1})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if err := db.Model(&RequestRecord{}).Where("request_id = ?", owner.RequestID).Updates(map[string]any{
		"status": requestStatusSucceeded, "terminal_at": now, "updated_at": now,
	}).Error; err != nil {
		t.Fatal(err)
	}
	payloadID := "33333333-3333-4333-8333-333333333333"
	encoded, err := envelope.Encrypt([]byte(`{"secret":"request"}`), envelope.PayloadDomain, keys)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Create(&EncryptedPayloadRecord{ID: payloadID, ReplayID: payloadID, KeyVersion: 1, Envelope: encoded, CreatedAt: now, ExpiresAt: now.Add(time.Hour)}).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Create(&StreamEventRecord{ReplayID: "44444444-4444-4444-8444-444444444444", RequestID: owner.RequestID, Sequence: 1, EventType: "response.json", PayloadID: payloadID, CreatedAt: now}).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Create(&UsageRecord{ReplayID: "55555555-5555-4555-8555-555555555555", RequestID: owner.RequestID, InputTokens: 1, CreatedAt: now}).Error; err != nil {
		t.Fatal(err)
	}
	runner, err := NewRetentionRunner(db, store, RetentionConfig{BatchSize: 1, DrainDeadline: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	actor := AdminPrincipal{ID: "admin-id", Name: "Admin", Scopes: AdminTokenScopes{AdminScopeMetadata}}
	if err := runner.DeleteRequestAsAdmin(context.Background(), owner.RequestID, actor); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, artifact.RelativePath)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("artifact after request deletion = %v", err)
	}
	for _, model := range []any{RequestRecord{}, ArtifactRecord{}, EncryptedPayloadRecord{}, StreamEventRecord{}, UsageRecord{}, JournalRecord{}, JournalReceipt{}, JournalRequestRecord{}} {
		var count int64
		if err := db.Model(model).Count(&count).Error; err != nil {
			t.Fatal(err)
		}
		if count != 0 {
			t.Fatalf("%T rows after deletion = %d", model, count)
		}
	}
	var auditCount int64
	if err := db.Model(&AuditRecord{}).Where("action = ? AND target_id = ?", "request.delete", owner.RequestID).Count(&auditCount).Error; err != nil {
		t.Fatal(err)
	}
	if auditCount != 1 {
		t.Fatalf("request delete audits = %d", auditCount)
	}
	if err := runner.DeleteRequestAsAdmin(context.Background(), owner.RequestID, actor); err != nil {
		t.Fatal(err)
	}
	if err := runner.DeleteRequest(context.Background(), "66666666-6666-4666-8666-666666666666"); err != nil {
		t.Fatal(err)
	}
}

func TestDeleteRequestRejectsRunningRequest(t *testing.T) {
	db, err := storage.Open(context.Background(), filepath.Join(t.TempDir(), "request-running.sqlite3"), time.Second)
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
	owner := ArtifactOwner{RequestID: "77777777-7777-4777-8777-777777777777", ConversationID: "88888888-8888-4888-8888-888888888888", APIKeyID: "key-running"}
	createTestArtifactOwner(t, db, owner)
	runner, err := NewRetentionRunner(db, nil, RetentionConfig{BatchSize: 1, DrainDeadline: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	actor := AdminPrincipal{ID: "admin-id", Name: "Admin", Scopes: AdminTokenScopes{AdminScopeMetadata}}
	if err := runner.DeleteRequestAsAdmin(context.Background(), owner.RequestID, actor); !errors.Is(err, errRequestHasRunningRequest) {
		t.Fatalf("running request delete error = %v", err)
	}
}
