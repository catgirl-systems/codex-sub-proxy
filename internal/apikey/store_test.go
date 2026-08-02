package apikey

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/catgirl-systems/codex-sub-proxy/internal/storage"
	"gorm.io/gorm"
)

func testAPIKeyDatabase(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := storage.Open(context.Background(), ":memory:", time.Second)
	if err != nil {
		t.Fatalf("open database: %v", err)
	}
	if err := Migrate(db); err != nil {
		t.Fatalf("migrate API keys: %v", err)
	}
	t.Cleanup(func() {
		sqlDB, err := db.DB()
		if err == nil {
			_ = sqlDB.Close()
		}
	})
	return db
}

func TestCreateStoresOnlySafeKeyDataAndAuthorizesPolicy(t *testing.T) {
	db := testAPIKeyDatabase(t)
	hmacKey := []byte("01234567890123456789012345678901")
	rawKey, created, err := Create(context.Background(), db, hmacKey, Policy{
		Name:             "local key",
		Owner:            "owner",
		AllowedEndpoints: []string{"/v1/responses", "/v1/models", "/v1/models"},
		AllowedModels:    []string{"gpt-z", "gpt-a", "gpt-z"},
	})
	if err != nil {
		t.Fatalf("create API key: %v", err)
	}
	if !strings.HasPrefix(rawKey, KeyPrefix) || len(rawKey) > maxKeySize {
		t.Fatalf("generated key = %q", rawKey)
	}
	if created.ID == "" || created.Prefix == "" || len(created.Digest) != 32 {
		t.Fatalf("stored key metadata = %+v", created)
	}
	if strings.Contains(created.Prefix, rawKey) || strings.Contains(string(created.Digest), rawKey) {
		t.Fatal("full key was included in stored key fields")
	}
	var stored Record
	if err := db.First(&stored, "id = ?", created.ID).Error; err != nil {
		t.Fatalf("load stored API key: %v", err)
	}
	if strings.Contains(stored.AllowedEndpoints[0], rawKey) || strings.Contains(stored.AllowedModels[0], rawKey) {
		t.Fatal("full key was included in stored policy")
	}
	principal, err := Authorize(context.Background(), db, hmacKey, rawKey, "/v1/responses", "gpt-a")
	if err != nil {
		t.Fatalf("authorize valid key: %v", err)
	}
	if got, want := principal.AllowedModels, []string{"gpt-a", "gpt-z"}; !slicesEqual(got, want) {
		t.Fatalf("models = %v, want %v", got, want)
	}
	if _, err := Authorize(context.Background(), db, hmacKey, rawKey, "/v1/images/generations", "gpt-a"); !errors.Is(err, ErrForbidden) {
		t.Fatalf("endpoint error = %v, want forbidden", err)
	}
	if _, err := Authorize(context.Background(), db, hmacKey, rawKey, "/v1/responses", "gpt-no"); !errors.Is(err, ErrForbidden) {
		t.Fatalf("model error = %v, want forbidden", err)
	}
}

func TestAuthenticateRejectsMalformedExpiredAndDisabledKeys(t *testing.T) {
	db := testAPIKeyDatabase(t)
	hmacKey := []byte("01234567890123456789012345678901")
	rawKey, record, err := Create(context.Background(), db, hmacKey, Policy{
		Name:             "key",
		AllowedEndpoints: []string{"/v1/models"},
		AllowedModels:    []string{"gpt-a"},
	})
	if err != nil {
		t.Fatalf("create API key: %v", err)
	}
	for _, malformed := range []string{"", "csp_live_bad", "csp_live_abc_def", "CSP_LIVE_abc_def"} {
		if _, err := Authenticate(context.Background(), db, hmacKey, malformed); !errors.Is(err, ErrInvalidKey) {
			t.Errorf("malformed key %q error = %v", malformed, err)
		}
	}
	past := time.Now().UTC().Add(-time.Minute)
	if err := db.Model(&Record{}).Where("id = ?", record.ID).Update("expires_at", past).Error; err != nil {
		t.Fatalf("expire API key: %v", err)
	}
	if _, err := Authenticate(context.Background(), db, hmacKey, rawKey); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("expired key error = %v, want invalid key", err)
	}
	if err := db.Model(&Record{}).Where("id = ?", record.ID).Updates(map[string]any{"expires_at": nil, "disabled_at": time.Now().UTC()}).Error; err != nil {
		t.Fatalf("disable API key: %v", err)
	}
	if _, err := Authenticate(context.Background(), db, hmacKey, rawKey); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("disabled key error = %v, want invalid key", err)
	}
}

func TestParseBearerBoundsAndExactSyntax(t *testing.T) {
	rawKey := KeyPrefix + "0123456789abcdef_" + strings.Repeat("a", minSecretSize)
	valid := "Bearer " + rawKey
	if got, err := ParseBearer(valid); err != nil || got != rawKey {
		t.Fatalf("parse valid Bearer = %q, %v", got, err)
	}
	for _, header := range []string{
		"bearer " + rawKey,
		"Bearer  " + rawKey,
		"Bearer " + rawKey + " ",
		"Bearer\t" + rawKey,
		"Bearer " + rawKey + "\n",
		strings.Repeat("x", MaxAuthorizationHeaderSize+1),
	} {
		if _, err := ParseBearer(header); !errors.Is(err, ErrInvalidKey) {
			t.Errorf("header %q error = %v, want invalid key", header, err)
		}
	}
}

func TestAuthenticateDatabaseErrorDoesNotBecomeUnauthorized(t *testing.T) {
	db := testAPIKeyDatabase(t)
	hmacKey := []byte("01234567890123456789012345678901")
	rawKey := KeyPrefix + "0123456789abcdef_" + strings.Repeat("a", minSecretSize)
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("get SQL database: %v", err)
	}
	if err := sqlDB.Close(); err != nil {
		t.Fatalf("close database: %v", err)
	}
	gotErr := func() error {
		_, err := Authenticate(context.Background(), db, hmacKey, rawKey)
		return err
	}()
	if gotErr == nil || errors.Is(gotErr, ErrInvalidKey) || strings.Contains(gotErr.Error(), rawKey) {
		t.Fatalf("database error = %v", gotErr)
	}
}

func TestConcurrentAuthentication(t *testing.T) {
	db := testAPIKeyDatabase(t)
	hmacKey := []byte("01234567890123456789012345678901")
	rawKey, _, err := Create(context.Background(), db, hmacKey, Policy{
		Name:             "key",
		AllowedEndpoints: []string{"/v1/models"},
		AllowedModels:    []string{"gpt-a"},
	})
	if err != nil {
		t.Fatalf("create API key: %v", err)
	}
	var wait sync.WaitGroup
	errorsCh := make(chan error, 32)
	for range 32 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			_, err := Authorize(context.Background(), db, hmacKey, rawKey, "/v1/models", "")
			if err != nil {
				errorsCh <- err
			}
		}()
	}
	wait.Wait()
	close(errorsCh)
	for err := range errorsCh {
		t.Errorf("concurrent authorization: %v", err)
	}
}

func slicesEqual(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func TestCreateReturnsNoSecretOnStoreError(t *testing.T) {
	db := testAPIKeyDatabase(t)
	if err := db.Exec("CREATE TRIGGER reject_api_key BEFORE INSERT ON api_keys BEGIN SELECT RAISE(ABORT, 'reject'); END").Error; err != nil {
		t.Fatalf("create rejection trigger: %v", err)
	}
	rawKey, _, err := Create(context.Background(), db, []byte("01234567890123456789012345678901"), Policy{
		Name:             "key",
		AllowedEndpoints: []string{"/v1/models"},
		AllowedModels:    []string{"gpt-a"},
	})
	if err == nil {
		t.Fatal("API-key store error was accepted")
	}
	if rawKey != "" {
		t.Fatalf("secret returned after failed create: %q", rawKey)
	}
}
