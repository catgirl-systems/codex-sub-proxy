package payload

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/catgirl-systems/codex-sub-proxy/internal/envelope"
	"github.com/catgirl-systems/codex-sub-proxy/internal/storage"
	"gorm.io/gorm"
)

func TestSQLiteRecordsStayEncryptedAcrossRotation(t *testing.T) {
	db := openTestDatabase(t)
	oldKeys := makeKeys(t, 1, 0x11)
	oldBody := []byte("old conversation body")
	if err := Save(context.Background(), db, "old", oldBody, oldKeys); err != nil {
		t.Fatalf("save old payload: %v", err)
	}

	var oldRow struct {
		KeyVersion uint32 `gorm:"column:key_version"`
		Envelope   []byte `gorm:"column:encrypted_envelope"`
	}
	if err := db.Raw(
		"SELECT key_version, encrypted_envelope FROM conversation_payloads WHERE id = ?",
		"old",
	).Scan(&oldRow).Error; err != nil {
		t.Fatalf("read old raw payload: %v", err)
	}
	if oldRow.KeyVersion != 1 {
		t.Fatalf("old key version = %d, want 1", oldRow.KeyVersion)
	}
	if bytes.Contains(oldRow.Envelope, oldBody) {
		t.Fatal("plaintext body was stored in old row")
	}

	rotatedKeys := makeRotatedKeys(t)
	got, err := Load(context.Background(), db, "old", rotatedKeys)
	if err != nil {
		t.Fatalf("load old payload after rotation: %v", err)
	}
	if !bytes.Equal(got, oldBody) {
		t.Fatalf("old payload = %q, want %q", got, oldBody)
	}

	newBody := []byte("new conversation body")
	if err := Save(context.Background(), db, "new", newBody, rotatedKeys); err != nil {
		t.Fatalf("save new payload: %v", err)
	}
	var newRow struct {
		KeyVersion uint32 `gorm:"column:key_version"`
		Envelope   []byte `gorm:"column:encrypted_envelope"`
	}
	if err := db.Raw(
		"SELECT key_version, encrypted_envelope FROM conversation_payloads WHERE id = ?",
		"new",
	).Scan(&newRow).Error; err != nil {
		t.Fatalf("read new raw payload: %v", err)
	}
	if newRow.KeyVersion != 2 {
		t.Fatalf("new key version = %d, want 2", newRow.KeyVersion)
	}
	if bytes.Contains(newRow.Envelope, newBody) {
		t.Fatal("plaintext body was stored in new row")
	}
	if _, err := Load(context.Background(), db, "new", oldKeys); err == nil {
		t.Fatal("new payload decrypted without active key")
	}
}

func TestLoadReportsMissingAndOversizedRecords(t *testing.T) {
	db := openTestDatabase(t)
	keys := makeKeys(t, 1, 0x21)

	if _, err := Load(context.Background(), db, "missing", keys); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing payload error = %v, want not found", err)
	}
	if err := Save(context.Background(), db, "oversized", bytes.Repeat([]byte("x"), MaxBodySize+1), keys); err == nil {
		t.Fatal("oversized body was accepted")
	}
	if err := db.Exec(
		"INSERT INTO conversation_payloads (id, key_version, encrypted_envelope, created_at) VALUES (?, ?, ?, ?)",
		"oversized-row",
		1,
		bytes.Repeat([]byte("x"), MaxEnvelopeSize+1),
		time.Now().UTC(),
	).Error; err != nil {
		t.Fatalf("insert oversized raw row: %v", err)
	}
	if _, err := Load(context.Background(), db, "oversized-row", keys); err == nil {
		t.Fatal("oversized envelope was accepted")
	} else if strings.Contains(err.Error(), "xxxx") {
		t.Fatal("oversized envelope reached an error")
	}
}

func openTestDatabase(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := storage.Open(context.Background(), filepath.Join(t.TempDir(), "payload.sqlite3"), time.Second)
	if err != nil {
		t.Fatalf("open sqlite database: %v", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("get sqlite database: %v", err)
	}
	t.Cleanup(func() { _ = sqlDB.Close() })
	if err := Migrate(db); err != nil {
		t.Fatalf("migrate payload records: %v", err)
	}
	return db
}

func makeKeys(t *testing.T, version uint32, value byte) envelope.KeySet {
	t.Helper()
	key, err := envelope.NewKey(version, bytes.Repeat([]byte{value}, envelope.KeySize))
	if err != nil {
		t.Fatalf("new payload key: %v", err)
	}
	keys, err := envelope.NewKeySet(key)
	if err != nil {
		t.Fatalf("new payload key set: %v", err)
	}
	return keys
}

func makeRotatedKeys(t *testing.T) envelope.KeySet {
	t.Helper()
	active, err := envelope.NewKey(2, bytes.Repeat([]byte{0x22}, envelope.KeySize))
	if err != nil {
		t.Fatalf("new active payload key: %v", err)
	}
	previous, err := envelope.NewKey(1, bytes.Repeat([]byte{0x11}, envelope.KeySize))
	if err != nil {
		t.Fatalf("new previous payload key: %v", err)
	}
	keys, err := envelope.NewKeySet(active, previous)
	if err != nil {
		t.Fatalf("new rotated payload key set: %v", err)
	}
	return keys
}
