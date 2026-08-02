package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/catgirl-systems/codex-sub-proxy/internal/envelope"
)

const (
	defaultListen         = "127.0.0.1:4000"
	defaultAdminListen    = "127.0.0.1:4001"
	defaultSQLitePath     = "~/.local/share/codex-sub-proxy/csp.sqlite3"
	defaultBusyTimeout    = 5 * time.Second
	defaultCredentialFile = "~/.config/codex-sub-proxy/credential.enc"
)

type Config struct {
	Server   ServerConfig   `toml:"server"`
	Storage  StorageConfig  `toml:"storage"`
	Security SecurityConfig `toml:"security"`
	Codex    CodexConfig    `toml:"codex"`
}

type ServerConfig struct {
	Listen      string `toml:"listen"`
	AdminListen string `toml:"admin_listen"`
}

type StorageConfig struct {
	SQLitePath  string        `toml:"sqlite_path"`
	BusyTimeout time.Duration `toml:"busy_timeout"`
}

type SecurityConfig struct {
	PayloadEncryptionKeyEnv                 string   `toml:"payload_encryption_key_env"`
	PayloadEncryptionKeyVersion             uint32   `toml:"payload_encryption_key_version"`
	PayloadEncryptionPreviousKeyEnvs        []string `toml:"payload_encryption_previous_key_envs"`
	PayloadEncryptionPreviousKeyVersions    []uint32 `toml:"payload_encryption_previous_key_versions"`
	CredentialEncryptionKeyEnv              string   `toml:"credential_encryption_key_env"`
	CredentialEncryptionKeyVersion          uint32   `toml:"credential_encryption_key_version"`
	CredentialEncryptionPreviousKeyEnvs     []string `toml:"credential_encryption_previous_key_envs"`
	CredentialEncryptionPreviousKeyVersions []uint32 `toml:"credential_encryption_previous_key_versions"`
	APIKeyHMACKeyEnv                        string   `toml:"api_key_hmac_key_env"`
	AdminTokenHMACKeyEnv                    string   `toml:"admin_token_hmac_key_env"`
}

type CodexConfig struct {
	CredentialFile string `toml:"credential_file"`
}

func Default() Config {
	return Config{
		Server: ServerConfig{
			Listen:      defaultListen,
			AdminListen: defaultAdminListen,
		},
		Storage: StorageConfig{
			SQLitePath:  defaultSQLitePath,
			BusyTimeout: defaultBusyTimeout,
		},
		Security: SecurityConfig{
			PayloadEncryptionKeyEnv:        "CSP_PAYLOAD_ENCRYPTION_KEY",
			PayloadEncryptionKeyVersion:    1,
			CredentialEncryptionKeyEnv:     "CSP_CREDENTIAL_ENCRYPTION_KEY",
			CredentialEncryptionKeyVersion: 1,
			APIKeyHMACKeyEnv:               "CSP_API_KEY_HMAC_KEY",
			AdminTokenHMACKeyEnv:           "CSP_ADMIN_TOKEN_HMAC_KEY",
		},
		Codex: CodexConfig{
			CredentialFile: defaultCredentialFile,
		},
	}
}

func Load(path string) (Config, error) {
	cfg := Default()
	if path != "" {
		contents, err := os.ReadFile(path)
		if err != nil && !os.IsNotExist(err) {
			return Config{}, fmt.Errorf("read config %q: %w", path, err)
		}
		if err == nil && len(strings.TrimSpace(string(contents))) > 0 {
			if _, err := toml.Decode(string(contents), &cfg); err != nil {
				return Config{}, fmt.Errorf("decode config %q: %w", path, err)
			}
		}
	}
	if err := applyEnvironment(&cfg); err != nil {
		return Config{}, err
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func (c Config) Validate() error {
	if strings.TrimSpace(c.Server.Listen) == "" {
		return fmt.Errorf("server listen address is empty")
	}
	if strings.TrimSpace(c.Server.AdminListen) == "" {
		return fmt.Errorf("server admin listen address is empty")
	}
	if strings.TrimSpace(c.Storage.SQLitePath) == "" {
		return fmt.Errorf("storage sqlite path is empty")
	}
	if c.Storage.BusyTimeout <= 0 {
		return fmt.Errorf("storage busy timeout must be positive")
	}
	if c.Storage.BusyTimeout > 24*time.Hour {
		return fmt.Errorf("storage busy timeout is too large")
	}
	if err := c.Security.Validate(); err != nil {
		return fmt.Errorf("security configuration: %w", err)
	}
	return nil
}

// Validate checks key names, versions, and rotation bounds.
func (s SecurityConfig) Validate() error {
	if strings.TrimSpace(s.PayloadEncryptionKeyEnv) == "" ||
		strings.TrimSpace(s.CredentialEncryptionKeyEnv) == "" ||
		strings.TrimSpace(s.APIKeyHMACKeyEnv) == "" ||
		strings.TrimSpace(s.AdminTokenHMACKeyEnv) == "" {
		return fmt.Errorf("encryption and HMAC key environment names are required")
	}
	if s.PayloadEncryptionKeyVersion == 0 || s.CredentialEncryptionKeyVersion == 0 {
		return fmt.Errorf("encryption key versions must be positive")
	}
	if len(s.PayloadEncryptionPreviousKeyEnvs) != len(s.PayloadEncryptionPreviousKeyVersions) ||
		len(s.CredentialEncryptionPreviousKeyEnvs) != len(s.CredentialEncryptionPreviousKeyVersions) {
		return fmt.Errorf("previous encryption key names and versions must match")
	}
	if len(s.PayloadEncryptionPreviousKeyEnvs) > envelope.MaxPreviousKeys ||
		len(s.CredentialEncryptionPreviousKeyEnvs) > envelope.MaxPreviousKeys {
		return fmt.Errorf("too many previous encryption keys")
	}
	for index, version := range s.PayloadEncryptionPreviousKeyVersions {
		if version == 0 || version == s.PayloadEncryptionKeyVersion {
			return fmt.Errorf("payload encryption key versions are invalid")
		}
		for previousIndex := range index {
			if version == s.PayloadEncryptionPreviousKeyVersions[previousIndex] {
				return fmt.Errorf("payload encryption key versions are invalid")
			}
		}
	}
	for index, version := range s.CredentialEncryptionPreviousKeyVersions {
		if version == 0 || version == s.CredentialEncryptionKeyVersion {
			return fmt.Errorf("credential encryption key versions are invalid")
		}
		for previousIndex := range index {
			if version == s.CredentialEncryptionPreviousKeyVersions[previousIndex] {
				return fmt.Errorf("credential encryption key versions are invalid")
			}
		}
	}
	for _, name := range s.PayloadEncryptionPreviousKeyEnvs {
		if strings.TrimSpace(name) == "" {
			return fmt.Errorf("previous encryption key environment names are required")
		}
	}
	for _, name := range s.CredentialEncryptionPreviousKeyEnvs {
		if strings.TrimSpace(name) == "" {
			return fmt.Errorf("previous encryption key environment names are required")
		}
	}
	return nil
}

// KeysAvailable checks that all configured key variables are present.
func (s SecurityConfig) KeysAvailable(lookup func(string) (string, bool)) bool {
	names := []string{
		s.PayloadEncryptionKeyEnv,
		s.CredentialEncryptionKeyEnv,
		s.APIKeyHMACKeyEnv,
		s.AdminTokenHMACKeyEnv,
	}
	names = append(names, s.PayloadEncryptionPreviousKeyEnvs...)
	names = append(names, s.CredentialEncryptionPreviousKeyEnvs...)
	for _, name := range names {
		name = strings.TrimSpace(name)
		if name == "" {
			return false
		}
		value, ok := lookup(name)
		if !ok || strings.TrimSpace(value) == "" {
			return false
		}
	}
	return true
}

// PayloadKeySet loads the active and previous payload keys.
func (s SecurityConfig) PayloadKeySet(lookup func(string) (string, bool)) (envelope.KeySet, error) {
	return loadEncryptionKeySet(
		"payload",
		s.PayloadEncryptionKeyEnv,
		s.PayloadEncryptionKeyVersion,
		s.PayloadEncryptionPreviousKeyEnvs,
		s.PayloadEncryptionPreviousKeyVersions,
		lookup,
	)
}

// CredentialKeySet loads the active and previous credential keys.
func (s SecurityConfig) CredentialKeySet(lookup func(string) (string, bool)) (envelope.KeySet, error) {
	return loadEncryptionKeySet(
		"credential",
		s.CredentialEncryptionKeyEnv,
		s.CredentialEncryptionKeyVersion,
		s.CredentialEncryptionPreviousKeyEnvs,
		s.CredentialEncryptionPreviousKeyVersions,
		lookup,
	)
}

func loadEncryptionKeySet(kind, activeName string, activeVersion uint32, previousNames []string, previousVersions []uint32, lookup func(string) (string, bool)) (envelope.KeySet, error) {
	activeName = strings.TrimSpace(activeName)
	if activeName == "" {
		return envelope.KeySet{}, fmt.Errorf("%s encryption key environment name is empty", kind)
	}
	activeValue, ok := lookup(activeName)
	if !ok || strings.TrimSpace(activeValue) == "" {
		return envelope.KeySet{}, fmt.Errorf("%s encryption key is unavailable", kind)
	}
	active, err := envelope.NewKey(activeVersion, []byte(activeValue))
	if err != nil {
		return envelope.KeySet{}, fmt.Errorf("%s encryption key is invalid", kind)
	}
	if len(previousNames) != len(previousVersions) {
		return envelope.KeySet{}, fmt.Errorf("%s previous encryption keys are invalid", kind)
	}
	previous := make([]envelope.Key, 0, len(previousNames))
	for index, name := range previousNames {
		name = strings.TrimSpace(name)
		if name == "" {
			return envelope.KeySet{}, fmt.Errorf("%s previous encryption key environment name is empty", kind)
		}
		value, ok := lookup(name)
		if !ok || strings.TrimSpace(value) == "" {
			return envelope.KeySet{}, fmt.Errorf("%s previous encryption key is unavailable", kind)
		}
		key, err := envelope.NewKey(previousVersions[index], []byte(value))
		if err != nil {
			return envelope.KeySet{}, fmt.Errorf("%s previous encryption key is invalid", kind)
		}
		previous = append(previous, key)
	}
	keys, err := envelope.NewKeySet(active, previous...)
	if err != nil {
		return envelope.KeySet{}, fmt.Errorf("%s encryption key set is invalid", kind)
	}
	return keys, nil
}

func CredentialFileAvailable(path string) bool {
	expanded, err := ExpandPath(path)
	if err != nil || expanded == "" {
		return false
	}
	info, err := os.Stat(expanded)
	if err != nil || !info.Mode().IsRegular() || info.Size() == 0 {
		return false
	}
	file, err := os.Open(expanded)
	if err != nil {
		return false
	}
	defer file.Close()
	info, err = file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return false
	}
	var content [1]byte
	n, err := file.Read(content[:])
	return n > 0 && err == nil
}

func ExpandPath(path string) (string, error) {
	path = strings.TrimSpace(path)
	if path == "" || path == ":memory:" || strings.HasPrefix(path, "file:") {
		return path, nil
	}
	if path == "~" || strings.HasPrefix(path, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("find home directory: %w", err)
		}
		if path == "~" {
			return home, nil
		}
		path = filepath.Join(home, strings.TrimPrefix(path, "~/"))
	}
	return filepath.Clean(path), nil
}

func applyEnvironment(cfg *Config) error {
	overrideString(&cfg.Server.Listen, "CSP_SERVER_LISTEN", "CSP_LISTEN")
	overrideString(&cfg.Server.AdminListen, "CSP_SERVER_ADMIN_LISTEN", "CSP_ADMIN_LISTEN")
	overrideString(&cfg.Storage.SQLitePath, "CSP_STORAGE_SQLITE_PATH", "CSP_SQLITE_PATH")
	if err := overrideDuration(&cfg.Storage.BusyTimeout, "CSP_STORAGE_BUSY_TIMEOUT", "CSP_BUSY_TIMEOUT"); err != nil {
		return err
	}
	overrideString(&cfg.Security.PayloadEncryptionKeyEnv, "CSP_SECURITY_PAYLOAD_ENCRYPTION_KEY_ENV")
	overrideString(&cfg.Security.CredentialEncryptionKeyEnv, "CSP_SECURITY_CREDENTIAL_ENCRYPTION_KEY_ENV")
	overrideString(&cfg.Security.APIKeyHMACKeyEnv, "CSP_SECURITY_API_KEY_HMAC_KEY_ENV")
	overrideString(&cfg.Security.AdminTokenHMACKeyEnv, "CSP_SECURITY_ADMIN_TOKEN_HMAC_KEY_ENV")
	overrideString(&cfg.Codex.CredentialFile, "CSP_CODEX_CREDENTIAL_FILE")
	return nil
}

func overrideString(dst *string, names ...string) {
	for _, name := range names {
		if value, ok := os.LookupEnv(name); ok {
			*dst = value
			return
		}
	}
}

func overrideDuration(dst *time.Duration, names ...string) error {
	for _, name := range names {
		if value, ok := os.LookupEnv(name); ok {
			parsed, err := time.ParseDuration(strings.TrimSpace(value))
			if err != nil {
				return fmt.Errorf("parse %s: %w", name, err)
			}
			*dst = parsed
			return nil
		}
	}
	return nil
}
