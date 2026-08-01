package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoadEmptyFileAndEnvironmentOverrides(t *testing.T) {
	t.Setenv("CSP_SERVER_LISTEN", "127.0.0.1:4100")
	t.Setenv("CSP_STORAGE_BUSY_TIMEOUT", "2s")
	t.Setenv("CSP_CODEX_CREDENTIAL_FILE", "/tmp/credential.enc")

	path := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("load empty config: %v", err)
	}
	if cfg.Server.Listen != "127.0.0.1:4100" {
		t.Fatalf("listen = %q", cfg.Server.Listen)
	}
	if cfg.Storage.BusyTimeout != 2*time.Second {
		t.Fatalf("busy timeout = %s", cfg.Storage.BusyTimeout)
	}
	if cfg.Storage.SQLitePath != defaultSQLitePath {
		t.Fatalf("sqlite path = %q", cfg.Storage.SQLitePath)
	}
	if cfg.Codex.CredentialFile != "/tmp/credential.enc" {
		t.Fatalf("credential file = %q", cfg.Codex.CredentialFile)
	}
}

func TestKeysAvailableRequiresEveryConfiguredKey(t *testing.T) {
	keys := SecurityConfig{
		PayloadEncryptionKeyEnv:    "PAYLOAD_KEY",
		CredentialEncryptionKeyEnv: "CREDENTIAL_KEY",
		APIKeyHMACKeyEnv:           "API_KEY",
		AdminTokenHMACKeyEnv:       "ADMIN_KEY",
	}
	lookup := func(name string) (string, bool) {
		return map[string]string{
			"PAYLOAD_KEY":    "payload",
			"CREDENTIAL_KEY": "credential",
			"API_KEY":        "api",
		}[name], name != "ADMIN_KEY"
	}
	if keys.KeysAvailable(lookup) {
		t.Fatal("incomplete keys reported as available")
	}
}

func TestCredentialFileAvailableRequiresNonEmptyRegularFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "credential.enc")
	if CredentialFileAvailable(path) {
		t.Fatal("missing credential reported as available")
	}
	if err := os.WriteFile(path, []byte("encrypted"), 0o600); err != nil {
		t.Fatal(err)
	}
	if !CredentialFileAvailable(path) {
		t.Fatal("credential file reported as unavailable")
	}
}
