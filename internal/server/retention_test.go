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

func TestRetentionRemovesExpiredPayloadArtifactAndMetadataInBatches(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "retention.sqlite3")
	db, err := storage.Open(context.Background(), dbPath, time.Second)
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
	key, err := envelope.NewKey(1, bytes.Repeat([]byte{0x61}, envelope.KeySize))
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
	owner := ArtifactOwner{RequestID: "request-retention", ConversationID: "conversation-retention", APIKeyID: "key-retention"}
	now := time.Now().UTC()
	artifact, err := store.Save(context.Background(), owner, 0, "image/png", []byte{0x89, 'P', 'N', 'G', '\r', '\n', 0x1a, '\n', 9})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Model(&ArtifactRecord{}).Where("id = ?", artifact.ID).Updates(map[string]any{"expires_at": now.Add(-time.Minute)}).Error; err != nil {
		t.Fatal(err)
	}
	encoded, err := envelope.Encrypt([]byte(`{"secret":"payload"}`), envelope.PayloadDomain, keys)
	if err != nil {
		t.Fatal(err)
	}
	payload := EncryptedPayloadRecord{ID: "payload-retention", ReplayID: "payload-retention", KeyVersion: 1, Envelope: encoded, CreatedAt: now.Add(-time.Hour), ExpiresAt: now.Add(-time.Minute)}
	if err := db.Create(&payload).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Create(&ConversationRecord{ID: owner.ConversationID, CreatedAt: now.Add(-2 * time.Hour), UpdatedAt: now.Add(-time.Hour), ExpiresAt: now.Add(-time.Minute), RequestCount: 1}).Error; err != nil {
		t.Fatal(err)
	}
	terminalAt := now.Add(-time.Hour)
	if err := db.Create(&RequestRecord{ID: owner.RequestID, ReplayID: "accepted-retention", ConversationID: owner.ConversationID, APIKeyID: owner.APIKeyID, Endpoint: "/v1/images/generations", Model: "gpt-image-2", Mode: journalModeDurable, Status: requestStatusSucceeded, AcceptedAt: terminalAt, StartedAt: terminalAt, UpdatedAt: terminalAt, TerminalAt: &terminalAt, ExpiresAt: now.Add(-time.Minute)}).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Create(&StreamEventRecord{ReplayID: "event-retention", RequestID: owner.RequestID, Sequence: 1, EventType: "response.json", PayloadID: payload.ID, CreatedAt: terminalAt}).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Create(&UsageRecord{ReplayID: "usage-retention", RequestID: owner.RequestID, CreatedAt: terminalAt}).Error; err != nil {
		t.Fatal(err)
	}
	runner, err := NewRetentionRunner(db, store, RetentionConfig{PayloadTTL: time.Hour, MetadataTTL: time.Hour, SweepInterval: time.Hour, BatchSize: 1, DrainDeadline: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if err := runner.RunOnce(context.Background(), now); err != nil {
		t.Fatal(err)
	}
	var artifactCount int64
	if err := db.Model(&ArtifactRecord{}).Count(&artifactCount).Error; err != nil {
		t.Fatal(err)
	}
	if artifactCount != 0 {
		t.Fatalf("artifact count after retention = %d", artifactCount)
	}
	if _, err := os.Stat(filepath.Join(root, artifact.RelativePath)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("artifact file after retention err = %v", err)
	}
	var payloadCount int64
	if err := db.Model(&EncryptedPayloadRecord{}).Count(&payloadCount).Error; err != nil {
		t.Fatal(err)
	}
	if payloadCount != 0 {
		t.Fatalf("payload count after retention = %d", payloadCount)
	}
	var eventCount int64
	if err := db.Model(&StreamEventRecord{}).Count(&eventCount).Error; err != nil {
		t.Fatal(err)
	}
	if eventCount != 0 {
		t.Fatalf("event count after retention = %d", eventCount)
	}
	var requestCount, conversationCount int64
	if err := db.Model(&RequestRecord{}).Count(&requestCount).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Model(&ConversationRecord{}).Count(&conversationCount).Error; err != nil {
		t.Fatal(err)
	}
	if requestCount != 0 || conversationCount != 0 {
		t.Fatalf("metadata counts after retention = requests %d conversations %d", requestCount, conversationCount)
	}
}

func TestDeleteConversationIsIdempotentAndToleratesMissingArtifactFile(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "delete.sqlite3")
	db, err := storage.Open(context.Background(), dbPath, time.Second)
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
	key, err := envelope.NewKey(1, bytes.Repeat([]byte{0x62}, envelope.KeySize))
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
	owner := ArtifactOwner{RequestID: "request-delete", ConversationID: "conversation-delete", APIKeyID: "key-delete"}
	artifact, err := store.Save(context.Background(), owner, 0, "image/png", []byte{0x89, 'P', 'N', 'G', '\r', '\n', 0x1a, '\n', 1})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(root, artifact.RelativePath)); err != nil {
		t.Fatal(err)
	}
	if err := db.Create(&ConversationRecord{ID: owner.ConversationID, CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC(), ExpiresAt: time.Now().UTC().Add(time.Hour), RequestCount: 1}).Error; err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if err := db.Create(&RequestRecord{ID: owner.RequestID, ReplayID: "accepted-delete", ConversationID: owner.ConversationID, APIKeyID: owner.APIKeyID, Endpoint: "/v1/images/generations", Model: "gpt-image-2", Mode: journalModeDurable, Status: requestStatusFailed, AcceptedAt: now, StartedAt: now, UpdatedAt: now, TerminalAt: &now, ExpiresAt: now.Add(time.Hour)}).Error; err != nil {
		t.Fatal(err)
	}
	runner, err := NewRetentionRunner(db, store, RetentionConfig{BatchSize: 1, DrainDeadline: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if err := runner.DeleteConversation(context.Background(), owner.ConversationID); err != nil {
		t.Fatal(err)
	}
	if err := runner.DeleteConversation(context.Background(), owner.ConversationID); err != nil {
		t.Fatal(err)
	}
	var count int64
	for _, model := range []any{ArtifactRecord{}, RequestRecord{}, ConversationRecord{}, EncryptedPayloadRecord{}, StreamEventRecord{}, UsageRecord{}, AuditRecord{}} {
		if err := db.Model(model).Count(&count).Error; err != nil {
			t.Fatal(err)
		}
		if count != 0 {
			t.Fatalf("%T rows remain: %d", model, count)
		}
	}
	if err := runner.DeleteConversation(context.Background(), "missing-conversation"); err != nil {
		t.Fatal(err)
	}
}
