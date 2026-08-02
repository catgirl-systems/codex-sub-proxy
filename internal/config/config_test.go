package config

import (
	"encoding/binary"
	"github.com/catgirl-systems/codex-sub-proxy/internal/envelope"
	"os"
	"path/filepath"
	"strings"
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

func TestResponsesTransportPolicyDefaultsToWebSocketAndRejectsUnknownValues(t *testing.T) {
	if got := Default().Codex.ResponsesTransport; got != ResponsesTransportWebSocketPreferred {
		t.Fatalf("default responses transport = %q, want %q", got, ResponsesTransportWebSocketPreferred)
	}
	path := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(path, []byte("[codex]\nresponses_transport = \"other\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("unknown responses transport was accepted")
	}
}

func TestLoadReadsSSEResponsesTransportPolicy(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(path, []byte("[codex]\nresponses_transport = \"sse\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Codex.ResponsesTransport != ResponsesTransportSSE {
		t.Fatalf("responses transport = %q, want %q", cfg.Codex.ResponsesTransport, ResponsesTransportSSE)
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

func TestCredentialKeySetLoadsActiveAndPreviousVersions(t *testing.T) {
	security := Default().Security
	security.CredentialEncryptionKeyVersion = 2
	security.CredentialEncryptionPreviousKeyEnvs = []string{"CSP_OLD_CREDENTIAL_KEY"}
	security.CredentialEncryptionPreviousKeyVersions = []uint32{1}
	lookup := func(name string) (string, bool) {
		switch name {
		case security.CredentialEncryptionKeyEnv:
			return strings.Repeat("n", 32), true
		case "CSP_OLD_CREDENTIAL_KEY":
			return strings.Repeat("o", 32), true
		default:
			return "", false
		}
	}
	keys, err := security.CredentialKeySet(lookup)
	if err != nil {
		t.Fatalf("load credential keys: %v", err)
	}
	if keys.Active.Version != 2 || len(keys.Previous) != 1 || keys.Previous[0].Version != 1 {
		t.Fatalf("keys = %#v", keys)
	}
}

func TestCredentialKeySetRejectsInvalidKeyLength(t *testing.T) {
	security := Default().Security
	keys, err := security.CredentialKeySet(func(name string) (string, bool) {
		return "short", true
	})
	if err == nil {
		t.Fatal("short credential key was accepted")
	}
	if keys.Active.Version != 0 {
		t.Fatalf("keys = %#v", keys)
	}
}

func TestCredentialKeyRotationReadsOldAndWritesNewVersion(t *testing.T) {
	oldSecurity := Default().Security
	oldSecurity.CredentialEncryptionKeyEnv = "CSP_OLD_CREDENTIAL_KEY"
	oldSecurity.CredentialEncryptionKeyVersion = 1
	lookup := func(name string) (string, bool) {
		switch name {
		case "CSP_OLD_CREDENTIAL_KEY":
			return strings.Repeat("o", 32), true
		case "CSP_NEW_CREDENTIAL_KEY":
			return strings.Repeat("n", 32), true
		default:
			return "", false
		}
	}
	oldKeys, err := oldSecurity.CredentialKeySet(lookup)
	if err != nil {
		t.Fatalf("load old keys: %v", err)
	}
	oldEnvelope, err := envelope.Encrypt([]byte("credential"), envelope.CredentialDomain, oldKeys)
	if err != nil {
		t.Fatalf("encrypt old credential: %v", err)
	}
	newSecurity := Default().Security
	newSecurity.CredentialEncryptionKeyEnv = "CSP_NEW_CREDENTIAL_KEY"
	newSecurity.CredentialEncryptionKeyVersion = 2
	newSecurity.CredentialEncryptionPreviousKeyEnvs = []string{"CSP_OLD_CREDENTIAL_KEY"}
	newSecurity.CredentialEncryptionPreviousKeyVersions = []uint32{1}
	newKeys, err := newSecurity.CredentialKeySet(lookup)
	if err != nil {
		t.Fatalf("load new keys: %v", err)
	}
	plaintext, err := envelope.Decrypt(oldEnvelope, envelope.CredentialDomain, newKeys)
	if err != nil || string(plaintext) != "credential" {
		t.Fatalf("decrypt old credential = %q, %v", plaintext, err)
	}
	newEnvelope, err := envelope.Encrypt([]byte("new credential"), envelope.CredentialDomain, newKeys)
	if err != nil {
		t.Fatalf("encrypt new credential: %v", err)
	}
	if got := binary.BigEndian.Uint32(newEnvelope[5:9]); got != 2 {
		t.Fatalf("new key version = %d, want 2", got)
	}
}

func TestRequireDistinctActiveKeysRejectsEqualBytes(t *testing.T) {
	value := strings.Repeat("x", envelope.KeySize)
	payloadKey, err := envelope.NewKey(1, []byte(value))
	if err != nil {
		t.Fatal(err)
	}
	credentialKey, err := envelope.NewKey(2, []byte(value))
	if err != nil {
		t.Fatal(err)
	}
	payloadKeys, err := envelope.NewKeySet(payloadKey)
	if err != nil {
		t.Fatal(err)
	}
	credentialKeys, err := envelope.NewKeySet(credentialKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := RequireDistinctActiveKeys(payloadKeys, credentialKeys); err == nil {
		t.Fatal("equal active encryption keys were accepted")
	}

	differentKey, err := envelope.NewKey(2, []byte(strings.Repeat("y", envelope.KeySize)))
	if err != nil {
		t.Fatal(err)
	}
	differentKeys, err := envelope.NewKeySet(differentKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := RequireDistinctActiveKeys(payloadKeys, differentKeys); err != nil {
		t.Fatalf("different active encryption keys rejected: %v", err)
	}
}

func TestAPIKeyHMACKeyLoadsConfiguredValueWithoutLengthValidation(t *testing.T) {
	security := Default().Security
	t.Setenv(security.APIKeyHMACKeyEnv, " x ")
	key, err := security.APIKeyHMACKey(os.LookupEnv)
	if err != nil {
		t.Fatalf("load API-key HMAC key: %v", err)
	}
	if got := string(key); got != " x " {
		t.Fatalf("HMAC key = %q", got)
	}
	t.Setenv(security.APIKeyHMACKeyEnv, "")
	if _, err := security.APIKeyHMACKey(os.LookupEnv); err == nil {
		t.Fatal("empty API-key HMAC key was accepted")
	}
}
