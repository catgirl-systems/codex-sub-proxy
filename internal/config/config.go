package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
)

const (
	defaultListen            = "127.0.0.1:4000"
	defaultAdminListen       = "127.0.0.1:4001"
	defaultPublicBaseURL     = "http://127.0.0.1:4000"
	defaultSQLitePath        = "~/.local/share/codex-sub-proxy/csp.sqlite3"
	defaultBusyTimeout       = 5 * time.Second
	defaultArtifactDirectory = "~/.local/share/codex-sub-proxy/artifacts"
	defaultCredentialFile    = "~/.config/codex-sub-proxy/credential.enc"
	defaultJournalDirectory  = "~/.local/share/codex-sub-proxy/journal"
)

type Config struct {
	Server    ServerConfig    `toml:"server"`
	Storage   StorageConfig   `toml:"storage"`
	Artifacts ArtifactsConfig `toml:"artifacts"`
	Security  SecurityConfig  `toml:"security"`
	Codex     CodexConfig     `toml:"codex"`
	Streaming StreamingConfig `toml:"streaming"`
	Retention RetentionConfig `toml:"retention"`
	Pricing   PricingConfig   `toml:"pricing"`
}

type ServerConfig struct {
	Listen        string `toml:"listen"`
	AdminListen   string `toml:"admin_listen"`
	PublicBaseURL string `toml:"public_base_url"`
}

type StorageConfig struct {
	SQLitePath  string        `toml:"sqlite_path"`
	BusyTimeout time.Duration `toml:"busy_timeout"`
}

type ArtifactsConfig struct {
	Type      string `toml:"type"`
	Directory string `toml:"directory"`
}

type SecurityConfig struct {
	PayloadEncryptionKeyEnv    string `toml:"payload_encryption_key_env"`
	CredentialEncryptionKeyEnv string `toml:"credential_encryption_key_env"`
	APIKeyHMACKeyEnv           string `toml:"api_key_hmac_key_env"`
	AdminTokenHMACKeyEnv       string `toml:"admin_token_hmac_key_env"`
	BootstrapAdminTokenEnv     string `toml:"bootstrap_admin_token_env"`
}

type CodexConfig struct {
	CredentialFile     string `toml:"credential_file"`
	DefaultChatModel   string `toml:"default_chat_model"`
	ImageModel         string `toml:"image_model"`
	ResponsesTransport string `toml:"responses_transport"`
}

type StreamingConfig struct {
	DeliveryOrder    string        `toml:"delivery_order"`
	JournalDirectory string        `toml:"journal_directory"`
	DrainDeadline    time.Duration `toml:"drain_deadline"`
}

type RetentionConfig struct {
	MetadataDays int `toml:"metadata_days"`
	PayloadDays  int `toml:"payload_days"`
	ArtifactDays int `toml:"artifact_days"`
	AuditDays    int `toml:"audit_days"`
}

type PricingConfig struct {
	SubscriptionMonthlyUSD float64 `toml:"subscription_monthly_usd"`
}

func Default() Config {
	return Config{
		Server: ServerConfig{
			Listen:        defaultListen,
			AdminListen:   defaultAdminListen,
			PublicBaseURL: defaultPublicBaseURL,
		},
		Storage: StorageConfig{
			SQLitePath:  defaultSQLitePath,
			BusyTimeout: defaultBusyTimeout,
		},
		Artifacts: ArtifactsConfig{
			Type:      "filesystem",
			Directory: defaultArtifactDirectory,
		},
		Security: SecurityConfig{
			PayloadEncryptionKeyEnv:    "CSP_PAYLOAD_ENCRYPTION_KEY",
			CredentialEncryptionKeyEnv: "CSP_CREDENTIAL_ENCRYPTION_KEY",
			APIKeyHMACKeyEnv:           "CSP_API_KEY_HMAC_KEY",
			AdminTokenHMACKeyEnv:       "CSP_ADMIN_TOKEN_HMAC_KEY",
			BootstrapAdminTokenEnv:     "CSP_BOOTSTRAP_ADMIN_TOKEN",
		},
		Codex: CodexConfig{
			CredentialFile:     defaultCredentialFile,
			DefaultChatModel:   "gpt-5.6-sol",
			ImageModel:         "gpt-image-2",
			ResponsesTransport: "websocket_preferred",
		},
		Streaming: StreamingConfig{
			DeliveryOrder:    "durable_before_forward",
			JournalDirectory: defaultJournalDirectory,
			DrainDeadline:    10 * time.Second,
		},
		Retention: RetentionConfig{
			MetadataDays: 365,
			PayloadDays:  90,
			ArtifactDays: 30,
			AuditDays:    365,
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
	if c.Streaming.DrainDeadline <= 0 {
		return fmt.Errorf("streaming drain deadline must be positive")
	}
	return nil
}

func (s SecurityConfig) KeysAvailable(lookup func(string) (string, bool)) bool {
	for _, name := range []string{
		s.PayloadEncryptionKeyEnv,
		s.CredentialEncryptionKeyEnv,
		s.APIKeyHMACKeyEnv,
		s.AdminTokenHMACKeyEnv,
	} {
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

func CredentialFileAvailable(path string) bool {
	expanded, err := ExpandPath(path)
	if err != nil || expanded == "" {
		return false
	}
	info, err := os.Stat(expanded)
	return err == nil && info.Mode().IsRegular() && info.Size() > 0
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
	overrideString(&cfg.Server.PublicBaseURL, "CSP_SERVER_PUBLIC_BASE_URL", "CSP_PUBLIC_BASE_URL")
	overrideString(&cfg.Storage.SQLitePath, "CSP_STORAGE_SQLITE_PATH", "CSP_SQLITE_PATH")
	if err := overrideDuration(&cfg.Storage.BusyTimeout, "CSP_STORAGE_BUSY_TIMEOUT", "CSP_BUSY_TIMEOUT"); err != nil {
		return err
	}
	overrideString(&cfg.Artifacts.Type, "CSP_ARTIFACTS_TYPE")
	overrideString(&cfg.Artifacts.Directory, "CSP_ARTIFACTS_DIRECTORY")
	overrideString(&cfg.Security.PayloadEncryptionKeyEnv, "CSP_SECURITY_PAYLOAD_ENCRYPTION_KEY_ENV")
	overrideString(&cfg.Security.CredentialEncryptionKeyEnv, "CSP_SECURITY_CREDENTIAL_ENCRYPTION_KEY_ENV")
	overrideString(&cfg.Security.APIKeyHMACKeyEnv, "CSP_SECURITY_API_KEY_HMAC_KEY_ENV")
	overrideString(&cfg.Security.AdminTokenHMACKeyEnv, "CSP_SECURITY_ADMIN_TOKEN_HMAC_KEY_ENV")
	overrideString(&cfg.Security.BootstrapAdminTokenEnv, "CSP_SECURITY_BOOTSTRAP_ADMIN_TOKEN_ENV")
	overrideString(&cfg.Codex.CredentialFile, "CSP_CODEX_CREDENTIAL_FILE")
	overrideString(&cfg.Codex.DefaultChatModel, "CSP_CODEX_DEFAULT_CHAT_MODEL")
	overrideString(&cfg.Codex.ImageModel, "CSP_CODEX_IMAGE_MODEL")
	overrideString(&cfg.Codex.ResponsesTransport, "CSP_CODEX_RESPONSES_TRANSPORT")
	overrideString(&cfg.Streaming.DeliveryOrder, "CSP_STREAMING_DELIVERY_ORDER")
	overrideString(&cfg.Streaming.JournalDirectory, "CSP_STREAMING_JOURNAL_DIRECTORY")
	if err := overrideDuration(&cfg.Streaming.DrainDeadline, "CSP_STREAMING_DRAIN_DEADLINE"); err != nil {
		return err
	}
	if err := overrideInt(&cfg.Retention.MetadataDays, "CSP_RETENTION_METADATA_DAYS"); err != nil {
		return err
	}
	if err := overrideInt(&cfg.Retention.PayloadDays, "CSP_RETENTION_PAYLOAD_DAYS"); err != nil {
		return err
	}
	if err := overrideInt(&cfg.Retention.ArtifactDays, "CSP_RETENTION_ARTIFACT_DAYS"); err != nil {
		return err
	}
	if err := overrideInt(&cfg.Retention.AuditDays, "CSP_RETENTION_AUDIT_DAYS"); err != nil {
		return err
	}
	if err := overrideFloat(&cfg.Pricing.SubscriptionMonthlyUSD, "CSP_PRICING_SUBSCRIPTION_MONTHLY_USD"); err != nil {
		return err
	}
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

func overrideInt(dst *int, names ...string) error {
	for _, name := range names {
		if value, ok := os.LookupEnv(name); ok {
			parsed, err := strconv.Atoi(strings.TrimSpace(value))
			if err != nil {
				return fmt.Errorf("parse %s: %w", name, err)
			}
			*dst = parsed
			return nil
		}
	}
	return nil
}

func overrideFloat(dst *float64, names ...string) error {
	for _, name := range names {
		if value, ok := os.LookupEnv(name); ok {
			parsed, err := strconv.ParseFloat(strings.TrimSpace(value), 64)
			if err != nil {
				return fmt.Errorf("parse %s: %w", name, err)
			}
			*dst = parsed
			return nil
		}
	}
	return nil
}
