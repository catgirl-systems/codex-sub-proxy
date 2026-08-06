package main

import (
	"context"
	"errors"
	"github.com/catgirl-systems/codex-sub-proxy/internal/apikey"
	"github.com/catgirl-systems/codex-sub-proxy/internal/codex"
	"github.com/catgirl-systems/codex-sub-proxy/internal/config"
	"github.com/catgirl-systems/codex-sub-proxy/internal/envelope"
	"github.com/catgirl-systems/codex-sub-proxy/internal/server"
	"github.com/catgirl-systems/codex-sub-proxy/internal/storage"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestServerStoppedErrorPreservesShutdownFailure(t *testing.T) {
	serveErr := errors.New("serve failed")
	shutdownErr := errors.New("shutdown failed")

	err := serverStoppedError(serveErr, shutdownErr)
	if !errors.Is(err, serveErr) {
		t.Fatalf("server error = %v, want %v", err, serveErr)
	}
	if !errors.Is(err, shutdownErr) {
		t.Fatalf("shutdown error = %v, want %v", err, shutdownErr)
	}
}

func TestRunRejectsSecretCommandLineFlagsAndArguments(t *testing.T) {
	for name, args := range map[string][]string{
		"secret flag":     {"--bootstrap-admin-token", "secret"},
		"secret argument": {"secret"},
	} {
		t.Run(name, func(t *testing.T) {
			if err := run(args); err == nil {
				t.Fatal("secret command-line input was accepted")
			}
		})
	}
}

func TestRunRejectsEqualActiveEncryptionKeys(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(configPath, nil, 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	t.Setenv("CSP_PAYLOAD_ENCRYPTION_KEY", "same-key-material-01234567890123")
	t.Setenv("CSP_CREDENTIAL_ENCRYPTION_KEY", "same-key-material-01234567890123")
	t.Setenv("CSP_API_KEY_HMAC_KEY", "api-key")
	t.Setenv("CSP_ADMIN_TOKEN_HMAC_KEY", "admin-key")
	t.Setenv("CSP_STORAGE_SQLITE_PATH", filepath.Join(t.TempDir(), "service.sqlite3"))

	if err := run([]string{"--config", configPath}); err == nil {
		t.Fatal("equal active encryption keys were accepted at startup")
	}
}

func TestRunAPIKeyCreateRejectsMultipleExpiryOptions(t *testing.T) {
	err := run([]string{
		"api-key", "create",
		"--expires-at", "2030-01-01T00:00:00Z",
		"--expires", "1h",
	})
	if err == nil || err.Error() != "only one expiry option is allowed" {
		t.Fatalf("multiple expiry options error = %v", err)
	}
}
func TestRunImportRejectsEqualActiveKeysBeforeSideEffects(t *testing.T) {
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "config.toml")
	if err := os.WriteFile(configPath, nil, 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	sourcePath := filepath.Join(tempDir, "auth.json")
	source := []byte(`{"access_token":"access","refresh_token":"refresh","expires_at":4102444800,"account_id":"account"}`)
	if err := os.WriteFile(sourcePath, source, 0o600); err != nil {
		t.Fatalf("write source: %v", err)
	}
	destinationPath := filepath.Join(tempDir, "credential.enc")
	t.Setenv("CSP_CODEX_CREDENTIAL_FILE", destinationPath)
	sameKey := strings.Repeat("x", envelope.KeySize)
	t.Setenv("CSP_PAYLOAD_ENCRYPTION_KEY", sameKey)
	t.Setenv("CSP_CREDENTIAL_ENCRYPTION_KEY", sameKey)

	err := run([]string{"import", "--config", configPath, "--source", sourcePath})
	if err == nil || err.Error() != "active payload and credential encryption keys must differ" {
		t.Fatalf("import error = %v, want active-key independence error", err)
	}
	if _, statErr := os.Stat(destinationPath); !os.IsNotExist(statErr) {
		t.Fatalf("credential destination exists after rejected import: %v", statErr)
	}
}

func TestRunImportWithDistinctActiveKeysContinues(t *testing.T) {
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "config.toml")
	if err := os.WriteFile(configPath, nil, 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	sourcePath := filepath.Join(tempDir, "auth.json")
	source := []byte(`{"access_token":"access","refresh_token":"refresh","expires_at":4102444800,"account_id":"account"}`)
	if err := os.WriteFile(sourcePath, source, 0o600); err != nil {
		t.Fatalf("write source: %v", err)
	}
	destinationPath := filepath.Join(tempDir, "credential.enc")
	t.Setenv("CSP_CODEX_CREDENTIAL_FILE", destinationPath)
	t.Setenv("CSP_PAYLOAD_ENCRYPTION_KEY", strings.Repeat("p", envelope.KeySize))
	t.Setenv("CSP_CREDENTIAL_ENCRYPTION_KEY", strings.Repeat("c", envelope.KeySize))

	if err := run([]string{"import", "--config", configPath, "--source", sourcePath}); err != nil {
		t.Fatalf("import with distinct active keys: %v", err)
	}
	if info, err := os.Stat(destinationPath); err != nil || !info.Mode().IsRegular() || info.Size() == 0 {
		t.Fatalf("credential destination = %v, %v", info, err)
	}
}

func TestRunLoginRejectsEqualActiveKeysBeforeOAuth(t *testing.T) {
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "config.toml")
	if err := os.WriteFile(configPath, nil, 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	destinationPath := filepath.Join(tempDir, "credential.enc")
	t.Setenv("CSP_CODEX_CREDENTIAL_FILE", destinationPath)
	sameKey := strings.Repeat("x", envelope.KeySize)
	t.Setenv("CSP_PAYLOAD_ENCRYPTION_KEY", sameKey)
	t.Setenv("CSP_CREDENTIAL_ENCRYPTION_KEY", sameKey)

	err := run([]string{"login", "--config", configPath, "--device", "--issuer", "://invalid"})
	if err == nil || err.Error() != "active payload and credential encryption keys must differ" {
		t.Fatalf("login error = %v, want active-key independence error", err)
	}
	if _, statErr := os.Stat(destinationPath); !os.IsNotExist(statErr) {
		t.Fatalf("credential destination exists after rejected login: %v", statErr)
	}
}

func TestRunLoginWithDistinctActiveKeysContinues(t *testing.T) {
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "config.toml")
	if err := os.WriteFile(configPath, nil, 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	destinationPath := filepath.Join(tempDir, "credential.enc")
	t.Setenv("CSP_CODEX_CREDENTIAL_FILE", destinationPath)
	t.Setenv("CSP_PAYLOAD_ENCRYPTION_KEY", strings.Repeat("p", envelope.KeySize))
	t.Setenv("CSP_CREDENTIAL_ENCRYPTION_KEY", strings.Repeat("c", envelope.KeySize))

	err := run([]string{"login", "--config", configPath, "--device", "--issuer", "://invalid"})
	if err == nil {
		t.Fatal("invalid OAuth login options were accepted")
	}
	if _, statErr := os.Stat(destinationPath); !os.IsNotExist(statErr) {
		t.Fatalf("credential destination exists after failed login: %v", statErr)
	}
}

func TestRunLoginRejectsInvalidProfileBeforeOAuth(t *testing.T) {
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "config.toml")
	if err := os.WriteFile(configPath, nil, 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	t.Setenv("CSP_CODEX_CREDENTIAL_FILE", filepath.Join(tempDir, "credential.enc"))
	t.Setenv("CSP_PAYLOAD_ENCRYPTION_KEY", strings.Repeat("p", envelope.KeySize))
	t.Setenv("CSP_CREDENTIAL_ENCRYPTION_KEY", strings.Repeat("c", envelope.KeySize))

	err := run([]string{"login", "--config", configPath, "--profile", "../escape", "--device", "--issuer", "://invalid"})
	if err == nil || err.Error() != "credential profile is invalid" {
		t.Fatalf("invalid login profile error = %v", err)
	}
}

func TestSaveProfileCredentialHonorsCanceledContext(t *testing.T) {
	tempDir := t.TempDir()
	destinationPath := filepath.Join(tempDir, "credential.enc")
	databasePath := filepath.Join(tempDir, "service.sqlite3")
	activeKey, err := envelope.NewKey(1, make([]byte, envelope.KeySize))
	if err != nil {
		t.Fatal(err)
	}
	keys, err := envelope.NewKeySet(activeKey)
	if err != nil {
		t.Fatal(err)
	}
	credential := codex.Credential{
		AccessToken:  "access",
		RefreshToken: "refresh",
		AccountID:    "account",
		ExpiresAt:    time.Now().Add(time.Hour),
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err = saveProfileCredential(ctx, config.Config{
		Storage: config.StorageConfig{SQLitePath: databasePath, BusyTimeout: time.Second},
	}, destinationPath, "default", true, credential, keys)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("save profile error = %v, want context.Canceled", err)
	}
	if _, statErr := os.Stat(destinationPath); !os.IsNotExist(statErr) {
		t.Fatalf("credential destination exists after canceled save: %v", statErr)
	}
}

func TestCredentialProfileRollbackErrorPreservesBothCauses(t *testing.T) {
	registerErr := errors.New("account profile write failed")
	restoreErr := errors.New("credential restore failed")
	err := credentialProfileRollbackError(registerErr, restoreErr)
	if !errors.Is(err, registerErr) {
		t.Fatalf("rollback error does not preserve registration cause: %v", err)
	}
	if !errors.Is(err, restoreErr) {
		t.Fatalf("rollback error does not preserve restore cause: %v", err)
	}
}

func TestBuildUpstreamBrokerMigratesLegacyEmptyPathPlaceholder(t *testing.T) {
	tempDir := t.TempDir()
	credentialPath := filepath.Join(tempDir, "credential.enc")
	databasePath := filepath.Join(tempDir, "service.sqlite3")
	activeKey, err := envelope.NewKey(1, make([]byte, envelope.KeySize))
	if err != nil {
		t.Fatal(err)
	}
	keys, err := envelope.NewKeySet(activeKey)
	if err != nil {
		t.Fatal(err)
	}
	credential := codex.Credential{
		AccessToken:  "access",
		RefreshToken: "refresh",
		AccountID:    "account",
		ExpiresAt:    time.Now().Add(time.Hour),
	}
	if err := codex.SaveCredential(credentialPath, credential, keys); err != nil {
		t.Fatal(err)
	}
	db, err := storage.Open(context.Background(), databasePath, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatal(err)
	}
	if err := server.MigrateSchema(db); err != nil {
		t.Fatal(err)
	}
	defer sqlDB.Close()
	store, err := server.NewAccountStore(db)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Upsert(context.Background(), server.AccountRecord{
		ID: "legacy", Provider: "codex", ProviderAccountID: credential.AccountID,
		CredentialPath: "legacy-placeholder", Enabled: false,
	}); err != nil {
		t.Fatal(err)
	}
	if err := db.Model(&server.AccountRecord{}).Where("id = ?", "legacy").Updates(map[string]any{
		"credential_path": "", "enabled": false, "is_default": false,
	}).Error; err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	cfg.Codex.CredentialFile = credentialPath
	broker, _, err := buildUpstreamBroker(context.Background(), cfg, db, keys)
	if err != nil {
		t.Fatalf("build broker: %v", err)
	}
	if broker == nil {
		t.Fatal("legacy placeholder did not produce a broker")
	}
	records, err := store.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 || records[0].CredentialPath != credentialPath || !records[0].Enabled || !records[0].IsDefault {
		t.Fatalf("migrated legacy record = %#v", records)
	}
}

func TestBuildUpstreamBrokerDoesNotRecoverOverConfiguredDisabledProfile(t *testing.T) {
	tempDir := t.TempDir()
	historicalPath := filepath.Join(tempDir, "historical.enc")
	namedPath := filepath.Join(tempDir, "named.enc")
	databasePath := filepath.Join(tempDir, "service.sqlite3")
	activeKey, err := envelope.NewKey(1, make([]byte, envelope.KeySize))
	if err != nil {
		t.Fatal(err)
	}
	keys, err := envelope.NewKeySet(activeKey)
	if err != nil {
		t.Fatal(err)
	}
	for path, accountID := range map[string]string{historicalPath: "historical", namedPath: "named"} {
		if err := codex.SaveCredential(path, codex.Credential{
			AccessToken: "access", RefreshToken: "refresh", AccountID: accountID,
			ExpiresAt: time.Now().Add(time.Hour),
		}, keys); err != nil {
			t.Fatal(err)
		}
	}
	db, err := storage.Open(context.Background(), databasePath, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatal(err)
	}
	defer sqlDB.Close()
	if err := server.MigrateSchema(db); err != nil {
		t.Fatal(err)
	}
	store, err := server.NewAccountStore(db)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Upsert(context.Background(), server.AccountRecord{
		ID: "named", Provider: "codex", ProviderAccountID: "named",
		CredentialPath: namedPath, Enabled: false, IsDefault: false,
	}); err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	cfg.Codex.CredentialFile = historicalPath
	broker, _, err := buildUpstreamBroker(context.Background(), cfg, db, keys)
	if err != nil {
		t.Fatalf("build broker: %v", err)
	}
	if broker == nil {
		t.Fatal("configured disabled profile was lost")
	}
	records, err := store.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 || records[0].ID != "named" || records[0].CredentialPath != namedPath ||
		records[0].Enabled || records[0].IsDefault {
		t.Fatalf("configured disabled profile changed = %#v", records)
	}
}

func TestRunAPIKeyCreatePrintsSecretOnceAndStoresOnlyDigest(t *testing.T) {
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "config.toml")
	databasePath := filepath.Join(tempDir, "api.sqlite3")
	if err := os.WriteFile(configPath, nil, 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	t.Setenv("CSP_STORAGE_SQLITE_PATH", databasePath)
	t.Setenv("CSP_API_KEY_HMAC_KEY", "01234567890123456789012345678901")

	originalStdout := os.Stdout
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatalf("create output pipe: %v", err)
	}
	os.Stdout = writer
	runErr := run([]string{
		"api-key", "create",
		"--config", configPath,
		"--name", "test",
		"--owner", "owner",
		"--endpoint", "/v1/models",
		"--model", "gpt-a",
	})
	_ = writer.Close()
	os.Stdout = originalStdout
	output, readErr := io.ReadAll(reader)
	_ = reader.Close()
	if runErr != nil {
		t.Fatalf("create API key: %v", runErr)
	}
	if readErr != nil {
		t.Fatalf("read command output: %v", readErr)
	}
	rawKey := strings.TrimSpace(string(output))
	if strings.Count(string(output), apikey.KeyPrefix) != 1 || !strings.HasPrefix(rawKey, apikey.KeyPrefix) {
		t.Fatalf("command output = %q", output)
	}

	db, err := storage.Open(context.Background(), databasePath, time.Second)
	if err != nil {
		t.Fatalf("open created database: %v", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("get created SQL database: %v", err)
	}
	defer sqlDB.Close()
	var record apikey.Record
	if err := db.First(&record).Error; err != nil {
		t.Fatalf("load created API key: %v", err)
	}
	if strings.Contains(record.Prefix, rawKey) || strings.Contains(string(record.Digest), rawKey) {
		t.Fatal("full API key was stored")
	}
}
