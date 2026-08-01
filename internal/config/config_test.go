package config

import (
	"os"
	"path/filepath"
	"syscall"
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

func TestLoadIgnoresUnsupportedEnvironmentOverrides(t *testing.T) {
	t.Setenv("CSP_ARTIFACTS_TYPE", "s3")
	t.Setenv("CSP_STREAMING_DRAIN_DEADLINE", "not-a-duration")
	t.Setenv("CSP_RETENTION_METADATA_DAYS", "not-an-integer")
	t.Setenv("CSP_PRICING_SUBSCRIPTION_MONTHLY_USD", "not-a-number")

	if _, err := Load(""); err != nil {
		t.Fatalf("load with unsupported environment values: %v", err)
	}
}

func TestCredentialFileAvailableRequiresReadableNonEmptyRegularFile(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, "missing.enc")
	if CredentialFileAvailable(missing) {
		t.Fatal("missing credential reported as available")
	}

	empty := filepath.Join(dir, "empty.enc")
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if CredentialFileAvailable(empty) {
		t.Fatal("empty credential reported as available")
	}

	invalid := filepath.Join(dir, "credential-dir")
	if err := os.Mkdir(invalid, 0o700); err != nil {
		t.Fatal(err)
	}
	if CredentialFileAvailable(invalid) {
		t.Fatal("non-regular credential reported as available")
	}

	unreadable := filepath.Join(dir, "unreadable.enc")
	if err := os.WriteFile(unreadable, []byte("encrypted"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(unreadable, 0); err != nil {
		t.Fatal(err)
	}
	if os.Geteuid() == 0 {
		t.Log("running as root; permission bits do not make the file unreadable")
	} else if CredentialFileAvailable(unreadable) {
		t.Fatal("unreadable credential reported as available")
	}

	valid := filepath.Join(dir, "valid.enc")
	if err := os.WriteFile(valid, []byte("encrypted"), 0o600); err != nil {
		t.Fatal(err)
	}
	if !CredentialFileAvailable(valid) {
		t.Fatal("readable credential reported as unavailable")
	}
}

func TestCredentialFileAvailableRejectsFIFOWithoutBlocking(t *testing.T) {
	path := filepath.Join(t.TempDir(), "credential.fifo")
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Fatalf("create credential FIFO: %v", err)
	}

	available := make(chan bool, 1)
	go func() {
		available <- CredentialFileAvailable(path)
	}()

	select {
	case got := <-available:
		if got {
			t.Fatal("FIFO credential reported as available")
		}
	case <-time.After(time.Second):
		t.Fatal("FIFO credential check blocked")
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
