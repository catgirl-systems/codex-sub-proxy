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
	createTestArtifactOwner(t, db, owner)
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
	if err := db.Model(&ConversationRecord{}).Where("id = ?", owner.ConversationID).Updates(map[string]any{"created_at": now.Add(-2 * time.Hour), "updated_at": now.Add(-time.Hour), "expires_at": now.Add(-time.Minute), "request_count": 1}).Error; err != nil {
		t.Fatal(err)
	}
	terminalAt := now.Add(-time.Hour)
	if err := db.Model(&RequestRecord{}).Where("request_id = ?", owner.RequestID).Updates(map[string]any{"status": requestStatusSucceeded, "terminal_at": terminalAt, "updated_at": terminalAt, "expires_at": now.Add(-time.Minute)}).Error; err != nil {
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
	createTestArtifactOwner(t, db, owner)
	artifact, err := store.Save(context.Background(), owner, 0, "image/png", []byte{0x89, 'P', 'N', 'G', '\r', '\n', 0x1a, '\n', 1})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(root, artifact.RelativePath)); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if err := db.Model(&ConversationRecord{}).Where("id = ?", owner.ConversationID).Updates(map[string]any{"request_count": 1}).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Model(&RequestRecord{}).Where("request_id = ?", owner.RequestID).Updates(map[string]any{"status": requestStatusFailed, "terminal_at": now, "updated_at": now}).Error; err != nil {
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

func TestDeleteConversationExactBatchBoundAndResume(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "retention-bound.sqlite3")
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
	key, err := envelope.NewKey(1, bytes.Repeat([]byte{0x67}, envelope.KeySize))
	if err != nil {
		t.Fatal(err)
	}
	keys, err := envelope.NewKeySet(key)
	if err != nil {
		t.Fatal(err)
	}
	store, err := NewArtifactStore(db, filepath.Join(t.TempDir(), "artifacts"), keys, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	runner, err := NewRetentionRunner(db, store, RetentionConfig{PayloadTTL: time.Hour, MetadataTTL: time.Hour, SweepInterval: time.Hour, BatchSize: 1, DrainDeadline: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	createBoundedConversation := func(t *testing.T, suffix string, count int) string {
		t.Helper()
		owner := ArtifactOwner{RequestID: "request-bound-" + suffix, ConversationID: "conversation-bound-" + suffix, APIKeyID: "key-bound"}
		createTestArtifactOwner(t, db, owner)
		now := time.Now().UTC()
		if err := db.Model(&RequestRecord{}).Where("request_id = ?", owner.RequestID).Updates(map[string]any{"status": requestStatusSucceeded, "terminal_at": now, "updated_at": now}).Error; err != nil {
			t.Fatal(err)
		}
		records := make([]ArtifactRecord, 0, count)
		for index := 0; index < count; index++ {
			id, err := newJournalUUID()
			if err != nil {
				t.Fatal(err)
			}
			records = append(records, ArtifactRecord{
				ID: id, RequestID: owner.RequestID, ConversationID: owner.ConversationID, APIKeyID: owner.APIKeyID,
				ResultIndex: index, MIME: "image/png", PlaintextSize: 1, CiphertextSize: artifactHeaderSize + 1,
				CiphertextSHA256: make([]byte, 32), KeyVersion: 1, RelativePath: id + ".bin",
				CreatedAt: now, ExpiresAt: now.Add(time.Hour), State: artifactStateReady,
			})
		}
		if err := db.CreateInBatches(&records, 128).Error; err != nil {
			t.Fatal(err)
		}
		return owner.ConversationID
	}

	exactConversation := createBoundedConversation(t, "exact", retentionMaxDeleteBatches)
	if err := runner.DeleteConversation(context.Background(), exactConversation); err != nil {
		t.Fatalf("exact bound delete failed: %v", err)
	}
	var count int64
	if err := db.Model(&ConversationRecord{}).Where("id = ?", exactConversation).Count(&count).Error; err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("exact-bound conversation remains: %d", count)
	}

	resumeConversation := createBoundedConversation(t, "resume", retentionMaxDeleteBatches+1)
	if err := runner.DeleteConversation(context.Background(), resumeConversation); err == nil {
		t.Fatal("over-bound conversation deletion unexpectedly succeeded")
	}
	var deleting int64
	if err := db.Model(&ArtifactRecord{}).Where("conversation_id = ? AND state = ?", resumeConversation, artifactStateDeleting).Count(&deleting).Error; err != nil {
		t.Fatal(err)
	}
	if deleting != 1 {
		t.Fatalf("deleting artifacts = %d, want 1 resumable artifact", deleting)
	}
	if err := runner.DeleteConversation(context.Background(), resumeConversation); err != nil {
		t.Fatalf("resumed conversation delete failed: %v", err)
	}
	if err := db.Model(&ConversationRecord{}).Where("id = ?", resumeConversation).Count(&count).Error; err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("resumed conversation remains: %d", count)
	}
}

func TestRetentionCloseRetryAfterShortContext(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "retention-close.sqlite3")
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
	now := time.Now().UTC()
	if err := db.Create(&ConversationRecord{ID: "close-conversation", CreatedAt: now, UpdatedAt: now, ExpiresAt: now.Add(time.Hour)}).Error; err != nil {
		t.Fatal(err)
	}
	runner, err := NewRetentionRunner(db, nil, RetentionConfig{PayloadTTL: time.Hour, MetadataTTL: time.Hour, SweepInterval: time.Millisecond, BatchSize: 1, DrainDeadline: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if err := runner.Start(); err != nil {
		t.Fatal(err)
	}
	lock := db.Begin()
	if lock.Error != nil {
		t.Fatal(lock.Error)
	}
	if err := lock.Model(&ConversationRecord{}).Where("id = ?", "close-conversation").Update("updated_at", now).Error; err != nil {
		_ = lock.Rollback()
		t.Fatal(err)
	}
	time.Sleep(25 * time.Millisecond)
	short, cancel := context.WithTimeout(context.Background(), 2*time.Millisecond)
	defer cancel()
	if err := runner.Close(short); err == nil {
		_ = lock.Rollback()
		t.Fatal("short close unexpectedly completed while retention was locked")
	}
	if err := lock.Rollback().Error; err != nil {
		t.Fatal(err)
	}
	if err := runner.Close(context.Background()); err != nil {
		t.Fatalf("retry close: %v", err)
	}
}

func TestRetentionDefersActiveRequestPayloadUntilTerminal(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "retention-active.sqlite3")
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
	key, err := envelope.NewKey(1, bytes.Repeat([]byte{0x68}, envelope.KeySize))
	if err != nil {
		t.Fatal(err)
	}
	keys, err := envelope.NewKeySet(key)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	owner := ArtifactOwner{RequestID: "request-active", ConversationID: "conversation-active", APIKeyID: "key-active"}
	createTestArtifactOwner(t, db, owner)
	encoded, err := envelope.Encrypt([]byte(`{"active":"payload"}`), envelope.PayloadDomain, keys)
	if err != nil {
		t.Fatal(err)
	}
	payload := EncryptedPayloadRecord{ID: "payload-active", ReplayID: "payload-active", KeyVersion: 1, Envelope: encoded, CreatedAt: now.Add(-time.Hour), ExpiresAt: now.Add(-time.Minute)}
	if err := db.Create(&payload).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Create(&StreamEventRecord{ReplayID: "event-active", RequestID: owner.RequestID, Sequence: 1, EventType: "response.json", PayloadID: payload.ID, CreatedAt: now.Add(-time.Hour)}).Error; err != nil {
		t.Fatal(err)
	}
	runner, err := NewRetentionRunner(db, nil, RetentionConfig{PayloadTTL: time.Hour, MetadataTTL: time.Hour, SweepInterval: time.Hour, BatchSize: 1, DrainDeadline: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if err := runner.RunOnce(context.Background(), now); err != nil {
		t.Fatal(err)
	}
	var payloadCount, eventCount int64
	if err := db.Model(&EncryptedPayloadRecord{}).Where("id = ?", payload.ID).Count(&payloadCount).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Model(&StreamEventRecord{}).Where("payload_id = ?", payload.ID).Count(&eventCount).Error; err != nil {
		t.Fatal(err)
	}
	if payloadCount != 1 || eventCount != 1 {
		t.Fatalf("active payload/event counts = %d/%d, want 1/1", payloadCount, eventCount)
	}
	if err := db.Model(&RequestRecord{}).Where("request_id = ?", owner.RequestID).Updates(map[string]any{"status": requestStatusFailed, "terminal_at": now, "updated_at": now}).Error; err != nil {
		t.Fatal(err)
	}
	if err := runner.RunOnce(context.Background(), now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := db.Model(&EncryptedPayloadRecord{}).Where("id = ?", payload.ID).Count(&payloadCount).Error; err != nil {
		t.Fatal(err)
	}
	if payloadCount != 0 {
		t.Fatalf("terminal payload remains: %d", payloadCount)
	}
}
