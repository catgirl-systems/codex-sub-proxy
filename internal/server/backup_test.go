package server

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/catgirl-systems/codex-sub-proxy/internal/envelope"
	"github.com/catgirl-systems/codex-sub-proxy/internal/storage"
)

func TestBackupRestorePreservesCiphertext(t *testing.T) {
	ctx := context.Background()
	sourceDir := t.TempDir()
	sourceDBPath := filepath.Join(sourceDir, "source.sqlite3")
	sourceDB, err := storage.Open(ctx, sourceDBPath, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	sourceSQL, err := sourceDB.DB()
	if err != nil {
		t.Fatal(err)
	}
	defer sourceSQL.Close()
	if err := MigrateSchema(sourceDB); err != nil {
		t.Fatal(err)
	}
	key, err := envelope.NewKey(1, bytes.Repeat([]byte{0x41}, envelope.KeySize))
	if err != nil {
		t.Fatal(err)
	}
	keys, err := envelope.NewKeySet(key)
	if err != nil {
		t.Fatal(err)
	}
	sourceRoot := filepath.Join(sourceDir, "artifacts")
	store, err := NewArtifactStore(sourceDB, sourceRoot, keys, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	owner := ArtifactOwner{RequestID: "11111111-1111-4111-8111-111111111111", ConversationID: "22222222-2222-4222-8222-222222222222", APIKeyID: "key"}
	createTestArtifactOwner(t, sourceDB, owner)
	record, err := store.Save(ctx, owner, 0, "image/png", []byte{0x89, 'P', 'N', 'G', '\r', '\n', 0x1a, '\n', 7})
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, err := os.ReadFile(filepath.Join(sourceRoot, record.RelativePath))
	if err != nil {
		t.Fatal(err)
	}
	archivePath := filepath.Join(sourceDir, "backup.tar")
	if err := CreateBackup(ctx, sourceDB, store, archivePath, "cli:test"); err != nil {
		t.Fatal(err)
	}
	targetDir := t.TempDir()
	targetDBPath := filepath.Join(targetDir, "restored.sqlite3")
	targetRoot := filepath.Join(targetDir, "restored-artifacts")
	if err := Restore(ctx, RestoreOptions{DatabasePath: targetDBPath, ArtifactRoot: targetRoot, Input: archivePath, PayloadKeyVersions: []uint32{1}, BusyTimeout: time.Second}); err != nil {
		t.Fatal(err)
	}
	restoredCiphertext, err := os.ReadFile(filepath.Join(targetRoot, record.RelativePath))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(restoredCiphertext, ciphertext) {
		t.Fatal("restored artifact ciphertext changed")
	}
}

func TestLiveBackupRestorePreservesSnapshotCiphertext(t *testing.T) {
	ctx := context.Background()
	sourceDir := t.TempDir()
	sourceDBPath := filepath.Join(sourceDir, "source.sqlite3")
	sourceDB, err := storage.Open(ctx, sourceDBPath, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	sourceSQL, err := sourceDB.DB()
	if err != nil {
		t.Fatal(err)
	}
	defer sourceSQL.Close()
	if err := MigrateSchema(sourceDB); err != nil {
		t.Fatal(err)
	}
	key, err := envelope.NewKey(1, bytes.Repeat([]byte{0x42}, envelope.KeySize))
	if err != nil {
		t.Fatal(err)
	}
	keys, err := envelope.NewKeySet(key)
	if err != nil {
		t.Fatal(err)
	}
	sourceRoot := filepath.Join(sourceDir, "artifacts")
	store, err := NewArtifactStore(sourceDB, sourceRoot, keys, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	owner := ArtifactOwner{RequestID: "33333333-3333-4333-8333-333333333333", ConversationID: "44444444-4444-4444-8444-444444444444", APIKeyID: "key"}
	createTestArtifactOwner(t, sourceDB, owner)
	plain, err := envelope.Encrypt([]byte("live-backup-payload"), envelope.PayloadDomain, keys)
	if err != nil {
		t.Fatal(err)
	}
	if err := sourceDB.Create(&EncryptedPayloadRecord{ID: "55555555-5555-4555-8555-555555555555", ReplayID: "55555555-5555-4555-8555-555555555555", KeyVersion: 1, Envelope: plain, CreatedAt: time.Now().UTC(), ExpiresAt: time.Now().UTC().Add(time.Hour)}).Error; err != nil {
		t.Fatal(err)
	}
	if _, err := store.Save(ctx, owner, 0, "image/png", []byte{0x89, 'P', 'N', 'G', 0x0d, 0x0a, 0x1a, 0x0a, 1}); err != nil {
		t.Fatal(err)
	}
	started := make(chan struct{})
	stop := make(chan struct{})
	writerErr := make(chan error, 1)
	writerDone := make(chan struct{})
	go func() {
		defer close(writerDone)
		for index := 1; ; index++ {
			select {
			case <-stop:
				return
			default:
			}
			if _, saveErr := store.Save(ctx, owner, index, "image/png", []byte{0x89, 'P', 'N', 'G', 0x0d, 0x0a, 0x1a, 0x0a, byte(index)}); saveErr != nil {
				writerErr <- saveErr
				return
			}
			select {
			case <-started:
			default:
				close(started)
			}
		}
	}()
	<-started
	archivePath := filepath.Join(sourceDir, "live-backup.tar")
	backupErr := CreateBackup(ctx, sourceDB, store, archivePath, "cli:test")
	close(stop)
	<-writerDone
	if writerErr := func() error {
		select {
		case err := <-writerErr:
			return err
		default:
			return nil
		}
	}(); writerErr != nil {
		t.Fatal(writerErr)
	}
	if backupErr != nil {
		t.Fatal(backupErr)
	}
	targetDir := t.TempDir()
	targetDBPath := filepath.Join(targetDir, "restored.sqlite3")
	targetRoot := filepath.Join(targetDir, "restored-artifacts")
	if err := Restore(ctx, RestoreOptions{DatabasePath: targetDBPath, ArtifactRoot: targetRoot, Input: archivePath, PayloadKeyVersions: []uint32{1}, BusyTimeout: time.Second}); err != nil {
		t.Fatal(err)
	}
	targetDB, err := storage.Open(ctx, targetDBPath, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	targetSQL, err := targetDB.DB()
	if err != nil {
		t.Fatal(err)
	}
	defer targetSQL.Close()
	var restoredArtifacts []ArtifactRecord
	if err := targetDB.Order("id ASC").Find(&restoredArtifacts).Error; err != nil {
		t.Fatal(err)
	}
	for _, restored := range restoredArtifacts {
		var source ArtifactRecord
		if err := sourceDB.Where("id = ?", restored.ID).First(&source).Error; err != nil {
			t.Fatal(err)
		}
		if restored.KeyVersion != source.KeyVersion || !bytes.Equal(restored.CiphertextSHA256, source.CiphertextSHA256) {
			t.Fatalf("artifact metadata changed for %s", restored.ID)
		}
		sourceBytes, err := os.ReadFile(filepath.Join(sourceRoot, source.RelativePath))
		if err != nil {
			t.Fatal(err)
		}
		targetBytes, err := os.ReadFile(filepath.Join(targetRoot, restored.RelativePath))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(sourceBytes, targetBytes) {
			t.Fatalf("artifact ciphertext changed for %s", restored.ID)
		}
	}
	var restoredPayloads, sourcePayloads []EncryptedPayloadRecord
	if err := targetDB.Order("id ASC").Find(&restoredPayloads).Error; err != nil {
		t.Fatal(err)
	}
	if err := sourceDB.Order("id ASC").Find(&sourcePayloads).Error; err != nil {
		t.Fatal(err)
	}
	for _, restored := range restoredPayloads {
		var source EncryptedPayloadRecord
		if err := sourceDB.Where("id = ?", restored.ID).First(&source).Error; err != nil {
			t.Fatal(err)
		}
		if restored.KeyVersion != source.KeyVersion || !bytes.Equal(restored.Envelope, source.Envelope) {
			t.Fatalf("payload ciphertext changed for %s", restored.ID)
		}
	}
	if len(restoredPayloads) == 0 || len(sourcePayloads) < len(restoredPayloads) {
		t.Fatal("restored payload snapshot is empty or larger than source")
	}
}
