package server

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/catgirl-systems/codex-sub-proxy/internal/envelope"
	"github.com/catgirl-systems/codex-sub-proxy/internal/storage"
	"gorm.io/gorm"
)

func createTestArtifactOwner(t *testing.T, db *gorm.DB, owner ArtifactOwner) {
	t.Helper()
	now := time.Now().UTC()
	if err := db.Create(&ConversationRecord{ID: owner.ConversationID, CreatedAt: now, UpdatedAt: now, ExpiresAt: now.Add(time.Hour)}).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Create(&RequestRecord{ID: owner.RequestID, ReplayID: owner.RequestID + "-replay", ConversationID: owner.ConversationID, APIKeyID: owner.APIKeyID, Endpoint: "/v1/images/generations", Model: "gpt-image-2", Mode: journalModeDurable, Status: requestStatusRunning, AcceptedAt: now, StartedAt: now, UpdatedAt: now, ExpiresAt: now.Add(time.Hour)}).Error; err != nil {
		t.Fatal(err)
	}
}

func TestArtifactStoreEncryptsChunksAndRotatesKeys(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "artifacts.sqlite3")
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
	oldKey, err := envelope.NewKey(1, bytes.Repeat([]byte{0x11}, envelope.KeySize))
	if err != nil {
		t.Fatal(err)
	}
	newKey, err := envelope.NewKey(2, bytes.Repeat([]byte{0x22}, envelope.KeySize))
	if err != nil {
		t.Fatal(err)
	}
	oldKeys, err := envelope.NewKeySet(oldKey)
	if err != nil {
		t.Fatal(err)
	}
	rotatedKeys, err := envelope.NewKeySet(newKey, oldKey)
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(t.TempDir(), "nested", "artifacts")
	oldStore, err := NewArtifactStore(db, root, oldKeys, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	overhead, err := encodeArtifactChunk(ArtifactOwner{RequestID: "request-1", ConversationID: "conversation-1", APIKeyID: "key-1"}, "00000000-0000-4000-8000-000000000001", "image/png", 0, 1, nil)
	if err != nil {
		t.Fatal(err)
	}
	chunkSize := envelope.MaxPlaintextSize - len(overhead)
	image := append([]byte{0x89, 'P', 'N', 'G', '\r', '\n', 0x1a, '\n'}, bytes.Repeat([]byte("x"), chunkSize)...)
	owner := ArtifactOwner{RequestID: "request-1", ConversationID: "conversation-1", APIKeyID: "key-1"}
	createTestArtifactOwner(t, db, owner)
	first, err := oldStore.Save(context.Background(), owner, 0, "image/png", image)
	if err != nil {
		t.Fatal(err)
	}
	if first.KeyVersion != 1 || first.PlaintextSize != int64(len(image)) {
		t.Fatalf("record = %#v", first)
	}
	fileBytes, err := os.ReadFile(filepath.Join(root, first.RelativePath))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(fileBytes, image) {
		t.Fatal("artifact file contains plaintext image")
	}
	if got := binary.BigEndian.Uint32(fileBytes[5:9]); got != 2 {
		t.Fatalf("chunk count = %d, want 2", got)
	}
	dbBytes, err := os.ReadFile(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, marker := range [][]byte{image, []byte(base64.StdEncoding.EncodeToString(image))} {
		if bytes.Contains(dbBytes, marker) {
			t.Fatalf("SQLite contains plaintext image marker")
		}
	}
	got, err := oldStore.Read(context.Background(), first.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, image) {
		t.Fatal("old key read changed plaintext")
	}
	rotatedStore, err := NewArtifactStore(db, root, rotatedKeys, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := rotatedStore.Read(context.Background(), first.ID); err != nil || !bytes.Equal(got, image) {
		t.Fatalf("rotated read = %d bytes, err = %v", len(got), err)
	}
	second, err := rotatedStore.Save(context.Background(), owner, 1, "image/png", []byte{0x89, 'P', 'N', 'G', '\r', '\n', 0x1a, '\n', 1})
	if err != nil {
		t.Fatal(err)
	}
	if second.KeyVersion != 2 {
		t.Fatalf("new artifact key version = %d", second.KeyVersion)
	}
	wrongKey, err := envelope.NewKey(3, bytes.Repeat([]byte{0x33}, envelope.KeySize))
	if err != nil {
		t.Fatal(err)
	}
	wrongKeys, err := envelope.NewKeySet(wrongKey)
	if err != nil {
		t.Fatal(err)
	}
	wrongStore, err := NewArtifactStore(db, root, wrongKeys, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := wrongStore.Read(context.Background(), first.ID); err == nil {
		t.Fatal("wrong key decrypted artifact")
	}
}

func TestArtifactStoreTamperAndPathChecks(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "artifacts.sqlite3")
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
	key, err := envelope.NewKey(1, bytes.Repeat([]byte{0x44}, envelope.KeySize))
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
	owner := ArtifactOwner{RequestID: "request-2", ConversationID: "conversation-2", APIKeyID: "key-2"}
	createTestArtifactOwner(t, db, owner)
	record, err := store.Save(context.Background(), owner, 0, "image/png", []byte{0x89, 'P', 'N', 'G', '\r', '\n', 0x1a, '\n', 2})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, record.RelativePath)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	data[len(data)-1] ^= 1
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Read(context.Background(), record.ID); err == nil {
		t.Fatal("tampered artifact was accepted")
	}
	if err := db.Model(&ArtifactRecord{}).Where("id = ?", record.ID).Update("relative_path", "../escape").Error; err != nil {
		t.Fatal(err)
	}
	if _, err := store.Read(context.Background(), record.ID); err == nil {
		t.Fatal("path traversal was accepted")
	}
	if err := db.Model(&ArtifactRecord{}).Where("id = ?", record.ID).Update("relative_path", record.RelativePath).Error; err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "hardlink")
	if err := os.Link(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Read(context.Background(), record.ID); err == nil {
		t.Fatal("hardlinked artifact was accepted")
	}
	if err := os.Remove(link); err != nil {
		t.Fatal(err)
	}
}

func TestArtifactStoreRejectsSymlinkRoot(t *testing.T) {
	target := t.TempDir()
	root := filepath.Join(t.TempDir(), "artifact-link")
	if err := os.Symlink(target, root); err != nil {
		t.Fatal(err)
	}
	key, err := envelope.NewKey(1, bytes.Repeat([]byte{0x55}, envelope.KeySize))
	if err != nil {
		t.Fatal(err)
	}
	keys, err := envelope.NewKeySet(key)
	if err != nil {
		t.Fatal(err)
	}
	dbPath := filepath.Join(t.TempDir(), "artifacts.sqlite3")
	db, err := storage.Open(context.Background(), dbPath, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sqlDB.Close() })
	if _, err := NewArtifactStore(db, root, keys, time.Hour); err == nil {
		t.Fatal("symlink root was accepted")
	}
}

func TestArtifactStoreRootOwnershipAndReconcile(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "artifacts.sqlite3")
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
	key, err := envelope.NewKey(1, bytes.Repeat([]byte{0x66}, envelope.KeySize))
	if err != nil {
		t.Fatal(err)
	}
	keys, err := envelope.NewKeySet(key)
	if err != nil {
		t.Fatal(err)
	}
	nonEmpty := filepath.Join(t.TempDir(), "non-empty")
	if err := os.Mkdir(nonEmpty, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(nonEmpty, "unrelated"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewArtifactStore(db, nonEmpty, keys, time.Hour); err == nil {
		t.Fatal("adopted a non-empty root without a sentinel")
	}
	shared := filepath.Join(t.TempDir(), "shared")
	if err := os.Mkdir(shared, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := NewArtifactStore(db, shared, keys, time.Hour); err == nil {
		t.Fatal("adopted a shared root")
	}
	if _, err := NewArtifactStore(db, string(filepath.Separator), keys, time.Hour); err == nil {
		t.Fatal("adopted the filesystem root")
	}

	root := filepath.Join(t.TempDir(), "private")
	store, err := NewArtifactStore(db, root, keys, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	rootInfo, err := os.Stat(root)
	if err != nil {
		t.Fatal(err)
	}
	if rootInfo.Mode().Perm() != 0o700 {
		t.Fatalf("root mode = %o, want 700", rootInfo.Mode().Perm())
	}
	sentinelInfo, err := os.Stat(filepath.Join(root, artifactRootSentinel))
	if err != nil {
		t.Fatal(err)
	}
	if sentinelInfo.Mode().Perm() != artifactSentinelMode {
		t.Fatalf("sentinel mode = %o, want %o", sentinelInfo.Mode().Perm(), artifactSentinelMode)
	}

	owner := ArtifactOwner{RequestID: "request-reconcile", ConversationID: "conversation-reconcile", APIKeyID: "key-reconcile"}
	createTestArtifactOwner(t, db, owner)
	record, err := store.Save(context.Background(), owner, 0, "image/png", []byte{0x89, 'P', 'N', 'G', '\r', '\n', 0x1a, '\n', 1})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Delete(&ArtifactRecord{}, "id = ?", record.ID).Error; err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".00000000-0000-4000-8000-000000000002.tmp"), []byte("stale"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := store.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	recovered, err := store.Save(context.Background(), owner, 1, "image/png", []byte{0x89, 'P', 'N', 'G', '\r', '\n', 0x1a, '\n', 2})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Model(&ArtifactRecord{}).Where("id = ?", recovered.ID).Update("state", artifactStateWriting).Error; err != nil {
		t.Fatal(err)
	}
	if err := store.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	var recoveredRecord ArtifactRecord
	if err := db.First(&recoveredRecord, "id = ?", recovered.ID).Error; err != nil {
		t.Fatal(err)
	}
	if recoveredRecord.State != artifactStateReady {
		t.Fatalf("recovered state = %q, want ready", recoveredRecord.State)
	}
	missing, err := store.Save(context.Background(), owner, 2, "image/png", []byte{0x89, 'P', 'N', 'G', '\r', '\n', 0x1a, '\n', 3})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(root, missing.RelativePath)); err != nil {
		t.Fatal(err)
	}
	if err := db.Model(&ArtifactRecord{}).Where("id = ?", missing.ID).Update("state", artifactStateWriting).Error; err != nil {
		t.Fatal(err)
	}
	if err := store.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := db.First(&ArtifactRecord{}, "id = ?", missing.ID).Error; err == nil {
		t.Fatal("missing writing artifact metadata survived reconciliation")
	}

	if _, err := os.Stat(filepath.Join(root, record.RelativePath)); !os.IsNotExist(err) {
		t.Fatalf("orphan artifact remains, stat err = %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, ".00000000-0000-4000-8000-000000000002.tmp")); !os.IsNotExist(err) {
		t.Fatalf("stale temporary artifact remains, stat err = %v", err)
	}
	outside := filepath.Join(t.TempDir(), "outside")
	if err := os.Mkdir(outside, 0o700); err != nil {
		t.Fatal(err)
	}
	movedRoot := root + "-moved"
	if err := os.Rename(root, movedRoot); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, root); err != nil {
		t.Fatal(err)
	}
	replaced, err := store.Save(context.Background(), owner, 3, "image/png", []byte{0x89, 'P', 'N', 'G', '\r', '\n', 0x1a, '\n', 4})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(movedRoot, replaced.RelativePath)); err != nil {
		t.Fatalf("descriptor-relative save missing from original root: %v", err)
	}
	if _, err := os.Stat(filepath.Join(outside, replaced.RelativePath)); !os.IsNotExist(err) {
		t.Fatalf("save escaped replaced root, stat err = %v", err)
	}
	if err := os.Remove(root); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(movedRoot, root); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(filepath.Join(root, "unknown"), []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := store.Reconcile(context.Background()); err == nil {
		t.Fatal("reconcile accepted an unknown root entry")
	}
	if _, err := os.Stat(filepath.Join(root, "unknown")); err != nil {
		t.Fatalf("unknown root entry was removed: %v", err)
	}
}

func TestArtifactSaveDeleteConversationRaceLeavesNoOrphan(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "artifact-race.sqlite3")
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
	key, err := envelope.NewKey(1, bytes.Repeat([]byte{0x69}, envelope.KeySize))
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
	owner := ArtifactOwner{RequestID: "request-race", ConversationID: "conversation-race", APIKeyID: "key-race"}
	createTestArtifactOwner(t, db, owner)
	runner, err := NewRetentionRunner(db, store, RetentionConfig{PayloadTTL: time.Hour, MetadataTTL: time.Hour, SweepInterval: time.Hour, BatchSize: 1, DrainDeadline: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	saveDone := make(chan error, 1)
	go func() {
		plaintext := append([]byte{0x89, 'P', 'N', 'G', '\r', '\n', 0x1a, '\n'}, bytes.Repeat([]byte{0x41}, 8<<20)...)
		_, saveErr := store.Save(context.Background(), owner, 0, "image/png", plaintext)
		saveDone <- saveErr
	}()
	tempDeadline := time.Now().Add(2 * time.Second)
	for {
		entries, readErr := os.ReadDir(root)
		if readErr != nil {
			t.Fatal(readErr)
		}
		sawTemp := false
		for _, entry := range entries {
			if strings.HasSuffix(entry.Name(), ".tmp") {
				sawTemp = true
				break
			}
		}
		if sawTemp || time.Now().After(tempDeadline) {
			break
		}
		time.Sleep(time.Millisecond)
	}
	now := time.Now().UTC()
	if err := db.Model(&RequestRecord{}).Where("request_id = ?", owner.RequestID).Updates(map[string]any{"status": requestStatusFailed, "terminal_at": now, "updated_at": now}).Error; err != nil {
		t.Fatal(err)
	}
	if err := runner.DeleteConversation(context.Background(), owner.ConversationID); err != nil {
		t.Fatal(err)
	}
	saveErr := <-saveDone
	if saveErr != nil {
		t.Logf("save rejected by concurrent tombstone: %v", saveErr)
	}
	var artifactCount, conversationCount int64
	if err := db.Model(&ArtifactRecord{}).Where("conversation_id = ?", owner.ConversationID).Count(&artifactCount).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Model(&ConversationRecord{}).Where("id = ?", owner.ConversationID).Count(&conversationCount).Error; err != nil {
		t.Fatal(err)
	}
	if artifactCount != 0 || conversationCount != 0 {
		t.Fatalf("race left metadata: artifacts=%d conversations=%d", artifactCount, conversationCount)
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if entry.Name() != artifactRootSentinel {
			t.Fatalf("race left root entry %q", entry.Name())
		}
	}
}
