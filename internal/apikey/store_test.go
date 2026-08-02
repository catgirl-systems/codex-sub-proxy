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
		AllowedEndpoints: []string{"/v1/responses", "/v1/models"},
		AllowedModels:    []string{"gpt-z", "gpt-a"},
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
	if got, want := principal.AllowedModels, []string{"gpt-z", "gpt-a"}; !slicesEqual(got, want) {
		t.Fatalf("models = %v, want %v", got, want)
	}
	if _, err := Authorize(context.Background(), db, hmacKey, rawKey, "/v1/images/generations", "gpt-a"); !errors.Is(err, ErrForbidden) {
		t.Fatalf("endpoint error = %v, want forbidden", err)
	}
	if _, err := Authorize(context.Background(), db, hmacKey, rawKey, "/v1/responses", "gpt-no"); !errors.Is(err, ErrForbidden) {
		t.Fatalf("model error = %v, want forbidden", err)
	}
}

func TestCreateRejectsDuplicatePolicyValues(t *testing.T) {
	db := testAPIKeyDatabase(t)
	cases := []Policy{
		{
			Name:             "duplicate endpoints",
			Owner:            "owner",
			AllowedEndpoints: []string{"/v1/models", "/v1/models"},
		},
		{
			Name:             "duplicate models",
			AllowedEndpoints: []string{"/v1/models"},
			Owner:            "owner",
			AllowedModels:    []string{"gpt-a", "gpt-a"},
		},
	}
	for _, policy := range cases {
		t.Run(policy.Name, func(t *testing.T) {
			if _, _, err := Create(context.Background(), db, []byte("x"), policy); err == nil {
				t.Fatal("duplicate policy values were accepted")
			}
		})
	}
}

func TestCreateRejectsMissingOwner(t *testing.T) {
	db := testAPIKeyDatabase(t)
	if _, _, err := Create(context.Background(), db, []byte("x"), Policy{
		Name:             "key",
		AllowedEndpoints: []string{"/v1/models"},
	}); err == nil {
		t.Fatal("missing owner was accepted")
	}
}

func TestAuthenticateRejectsMalformedExpiredAndDisabledKeys(t *testing.T) {
	db := testAPIKeyDatabase(t)
	hmacKey := []byte("01234567890123456789012345678901")
	rawKey, record, err := Create(context.Background(), db, hmacKey, Policy{
		Name:             "key",
		Owner:            "owner",
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

func TestAuthorizeHeaderBoundsAndExactSyntax(t *testing.T) {
	db := testAPIKeyDatabase(t)
	hmacKey := []byte("01234567890123456789012345678901")
	rawKey, _, err := Create(context.Background(), db, hmacKey, Policy{
		Name:             "key",
		Owner:            "owner",
		AllowedEndpoints: []string{"/v1/models"},
	})
	if err != nil {
		t.Fatalf("create API key: %v", err)
	}
	authorizer := NewAuthorizer(db, hmacKey)
	if _, err := authorizer.AuthorizeHeader(context.Background(), "Bearer "+rawKey, "/v1/models", ""); err != nil {
		t.Fatalf("authorize valid Bearer header: %v", err)
	}
	for _, header := range []string{
		"bearer " + rawKey,
		"Bearer  " + rawKey,
		"Bearer " + rawKey + " ",
		"Bearer\t" + rawKey,
		"Bearer " + rawKey + "\n",
		strings.Repeat("x", MaxAuthorizationHeaderSize+1),
	} {
		if _, err := authorizer.AuthorizeHeader(context.Background(), header, "/v1/models", ""); !errors.Is(err, ErrInvalidKey) {
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

func TestConcurrentAuthorization(t *testing.T) {
	db := testAPIKeyDatabase(t)
	hmacKey := []byte("01234567890123456789012345678901")
	rawKey, _, err := Create(context.Background(), db, hmacKey, Policy{
		Name:             "key",
		Owner:            "owner",
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

func TestAuthorizePersistsMonotonicLastUsedAtAndSkipsDeniedRequests(t *testing.T) {
	db := testAPIKeyDatabase(t)
	hmacKey := []byte("weak")
	rawKey, created, err := Create(context.Background(), db, hmacKey, Policy{
		Name:             "key",
		Owner:            "owner",
		AllowedEndpoints: []string{"/v1/models", "models"},
		AllowedModels:    []string{"gpt a"},
	})
	if err != nil {
		t.Fatalf("create API key: %v", err)
	}
	if _, err := Authorize(context.Background(), db, hmacKey, rawKey, "/v1/models", "gpt a"); err != nil {
		t.Fatalf("authorize valid policy: %v", err)
	}
	var used Record
	if err := db.First(&used, "id = ?", created.ID).Error; err != nil {
		t.Fatalf("load used API key: %v", err)
	}
	if used.LastUsedAt == nil {
		t.Fatal("last-used timestamp was not stored")
	}
	firstUse := *used.LastUsedAt
	if _, err := Authorize(context.Background(), db, hmacKey, rawKey, "/v1/denied", "gpt a"); !errors.Is(err, ErrForbidden) {
		t.Fatalf("denied endpoint error = %v, want forbidden", err)
	}
	var denied Record
	if err := db.First(&denied, "id = ?", created.ID).Error; err != nil {
		t.Fatalf("load denied API key: %v", err)
	}
	if denied.LastUsedAt == nil || denied.LastUsedAt.Before(firstUse) {
		t.Fatalf("last-used timestamp moved backward after denial: %v before %v", denied.LastUsedAt, firstUse)
	}
	future := time.Now().UTC().Add(time.Hour)
	if err := db.Model(&Record{}).Where("id = ?", created.ID).Update("last_used_at", future).Error; err != nil {
		t.Fatalf("set future last-used timestamp: %v", err)
	}
	if _, err := Authorize(context.Background(), db, hmacKey, rawKey, "models", "gpt a"); err != nil {
		t.Fatalf("authorize exact endpoint: %v", err)
	}
	var unchanged Record
	if err := db.First(&unchanged, "id = ?", created.ID).Error; err != nil {
		t.Fatalf("load future API key: %v", err)
	}
	if unchanged.LastUsedAt == nil || unchanged.LastUsedAt.Before(future) {
		t.Fatalf("last-used timestamp moved backward: %v before %v", unchanged.LastUsedAt, future)
	}
}

func TestAuthorizeFailsClosedWhenLastUsedUpdateFails(t *testing.T) {
	db := testAPIKeyDatabase(t)
	hmacKey := []byte("key")
	rawKey, created, err := Create(context.Background(), db, hmacKey, Policy{
		Name:             "key",
		Owner:            "owner",
		AllowedEndpoints: []string{"/v1/models"},
	})
	if err != nil {
		t.Fatalf("create API key: %v", err)
	}
	if err := db.Exec("CREATE TRIGGER reject_api_key_last_used BEFORE UPDATE OF last_used_at ON api_keys BEGIN SELECT RAISE(ABORT, 'reject last-used update'); END").Error; err != nil {
		t.Fatalf("create last-used rejection trigger: %v", err)
	}
	if _, err := Authorize(context.Background(), db, hmacKey, rawKey, "/v1/models", ""); err == nil || errors.Is(err, ErrForbidden) || errors.Is(err, ErrInvalidKey) {
		t.Fatalf("last-used update error = %v", err)
	}
	var stored Record
	if err := db.First(&stored, "id = ?", created.ID).Error; err != nil {
		t.Fatalf("load rejected API key: %v", err)
	}
	if stored.LastUsedAt != nil {
		t.Fatalf("last-used timestamp stored after rejected update: %v", stored.LastUsedAt)
	}
}

func TestRecordPolicyRejectsLegacyDuplicateValues(t *testing.T) {
	db := testAPIKeyDatabase(t)
	hmacKey := []byte("key")
	rawKey, created, err := Create(context.Background(), db, hmacKey, Policy{
		Name:             "key",
		AllowedEndpoints: []string{"/v1/models"},
		Owner:            "owner",
		AllowedModels:    []string{"gpt-a"},
	})
	if err != nil {
		t.Fatalf("create API key: %v", err)
	}
	encoded := `["gpt-a","gpt-a"]`
	if err := db.Model(&Record{}).Where("id = ?", created.ID).Update("allowed_models", encoded).Error; err != nil {
		t.Fatalf("store legacy duplicate policy: %v", err)
	}
	if _, err := Authenticate(context.Background(), db, hmacKey, rawKey); err == nil {
		t.Fatal("legacy duplicate policy was accepted")
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
		Owner:            "owner",
		AllowedModels:    []string{"gpt-a"},
	})
	if err == nil {
		t.Fatal("API-key store error was accepted")
	}
	if rawKey != "" {
		t.Fatalf("secret returned after failed create: %q", rawKey)
	}
}
