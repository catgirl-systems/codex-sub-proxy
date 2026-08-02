package main

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
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
