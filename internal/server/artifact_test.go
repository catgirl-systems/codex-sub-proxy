package server

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/catgirl-systems/codex-sub-proxy/internal/envelope"
	"github.com/catgirl-systems/codex-sub-proxy/internal/storage"
)

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
