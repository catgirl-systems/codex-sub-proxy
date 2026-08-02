package main

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/catgirl-systems/codex-sub-proxy/internal/apikey"
	"github.com/catgirl-systems/codex-sub-proxy/internal/envelope"
	"github.com/catgirl-systems/codex-sub-proxy/internal/storage"
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
	if err == nil || err.Error() != "OAuth issuer URL is invalid" {
		t.Fatalf("login error = %v, want issuer validation error", err)
	}
	if _, statErr := os.Stat(destinationPath); !os.IsNotExist(statErr) {
		t.Fatalf("credential destination exists after failed login: %v", statErr)
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
