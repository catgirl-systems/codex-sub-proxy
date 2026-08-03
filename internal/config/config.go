package config

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/catgirl-systems/codex-sub-proxy/internal/envelope"
	"github.com/go-playground/validator/v10"
)

const (
	defaultListen                 = "127.0.0.1:4000"
	defaultAdminListen            = "127.0.0.1:4001"
	defaultSQLitePath             = "~/.local/share/codex-sub-proxy/csp.sqlite3"
	defaultArtifactRoot           = "~/.local/share/codex-sub-proxy/artifacts"
	defaultBusyTimeout            = 5 * time.Second
	defaultCredentialFile         = "~/.config/codex-sub-proxy/credential.enc"
	defaultJournalQueueCapacity   = 64
	defaultJournalDrainDeadline   = 10 * time.Second
	defaultArtifactTTL            = 24 * time.Hour
	defaultPayloadTTL             = 24 * time.Hour
	defaultMetadataTTL            = 7 * 24 * time.Hour
	defaultRetentionSweepInterval = time.Minute
	defaultRetentionBatchSize     = 64
	defaultRetentionDrainDeadline = 10 * time.Second
	maxRetentionDuration          = 365 * 24 * time.Hour
)

type Config struct {
	Server    ServerConfig    `toml:"server"`
	Storage   StorageConfig   `toml:"storage"`
	Security  SecurityConfig  `toml:"security"`
	Codex     CodexConfig     `toml:"codex"`
	Journal   JournalConfig   `toml:"journal"`
	Retention RetentionConfig `toml:"retention"`
}

type ServerConfig struct {
	Listen      string `toml:"listen" validate:"required"`
	AdminListen string `toml:"admin_listen" validate:"required"`
}

type StorageConfig struct {
	SQLitePath   string        `toml:"sqlite_path" validate:"required"`
	ArtifactRoot string        `toml:"artifact_root" validate:"required"`
	BusyTimeout  time.Duration `toml:"busy_timeout" validate:"gt=0,lte=86400000000000"`
}

type RetentionConfig struct {
	ArtifactTTL   time.Duration `toml:"artifact_ttl" validate:"gt=0,lte=31536000000000000"`
	PayloadTTL    time.Duration `toml:"payload_ttl" validate:"gt=0,lte=31536000000000000"`
	MetadataTTL   time.Duration `toml:"metadata_ttl" validate:"gt=0,lte=31536000000000000"`
	SweepInterval time.Duration `toml:"sweep_interval" validate:"gt=0,lte=86400000000000"`
	BatchSize     int           `toml:"batch_size" validate:"gt=0,lte=4096"`
	DrainDeadline time.Duration `toml:"drain_deadline" validate:"gt=0,lte=86400000000000"`
}

// JournalMode selects the append and forward ordering.
type JournalMode string

const (
	JournalModeDurable    JournalMode = "durable"
	JournalModeBestEffort JournalMode = "best-effort"
)

type JournalConfig struct {
	Mode          JournalMode   `toml:"mode" validate:"oneof=durable best-effort"`
	QueueCapacity int           `toml:"queue_capacity" validate:"gt=0,lte=4096"`
	DrainDeadline time.Duration `toml:"drain_deadline" validate:"gt=0,lte=86400000000000"`
}

type SecurityConfig struct {
	PayloadEncryptionKeyEnv                 string   `toml:"payload_encryption_key_env" validate:"required"`
	PayloadEncryptionKeyVersion             uint32   `toml:"payload_encryption_key_version" validate:"gt=0"`
	PayloadEncryptionPreviousKeyEnvs        []string `toml:"payload_encryption_previous_key_envs" validate:"max=4,unique,dive,required"`
	PayloadEncryptionPreviousKeyVersions    []uint32 `toml:"payload_encryption_previous_key_versions" validate:"max=4,unique,dive,gt=0"`
	CredentialEncryptionKeyEnv              string   `toml:"credential_encryption_key_env" validate:"required"`
	CredentialEncryptionKeyVersion          uint32   `toml:"credential_encryption_key_version" validate:"gt=0"`
	CredentialEncryptionPreviousKeyEnvs     []string `toml:"credential_encryption_previous_key_envs" validate:"max=4,unique,dive,required"`
	CredentialEncryptionPreviousKeyVersions []uint32 `toml:"credential_encryption_previous_key_versions" validate:"max=4,unique,dive,gt=0"`
	APIKeyHMACKeyEnv                        string   `toml:"api_key_hmac_key_env" validate:"required"`
	AdminTokenHMACKeyEnv                    string   `toml:"admin_token_hmac_key_env" validate:"required"`
}

type ResponsesTransport string

const (
	ResponsesTransportWebSocketPreferred ResponsesTransport = "websocket_preferred"
	ResponsesTransportSSE                ResponsesTransport = "sse"
)

type CodexConfig struct {
	CredentialFile     string             `toml:"credential_file" validate:"required"`
	ResponsesTransport ResponsesTransport `toml:"responses_transport" validate:"oneof=websocket_preferred sse"`
}

var configurationValidation = func() *validator.Validate {
	instance := validator.New()
	instance.RegisterStructValidation(securityConfigStructValidation, SecurityConfig{})
	instance.RegisterStructValidation(activeKeySetPairStructValidation, activeKeySetPair{})
	return instance
}()

type activeKeySetPair struct {
	Payload    envelope.KeySet
	Credential envelope.KeySet
}

func activeKeySetPairStructValidation(sl validator.StructLevel) {
	pair, ok := sl.Current().Interface().(activeKeySetPair)
	if !ok {
		return
	}
	if subtle.ConstantTimeCompare(pair.Payload.Active.Bytes[:], pair.Credential.Active.Bytes[:]) == 1 {
		sl.ReportError(
			pair.Credential.Active.Bytes,
			"CredentialActiveKey",
			"CredentialActiveKey",
			"different_from_payload",
			"",
		)
	}
}

func securityConfigStructValidation(sl validator.StructLevel) {
	security, ok := sl.Current().Interface().(SecurityConfig)
	if !ok {
		return
	}
	if len(security.PayloadEncryptionPreviousKeyEnvs) != len(security.PayloadEncryptionPreviousKeyVersions) {
		sl.ReportError(
			security.PayloadEncryptionPreviousKeyVersions,
			"PayloadEncryptionPreviousKeyVersions",
			"payload_encryption_previous_key_versions",
			"same_length",
			"PayloadEncryptionPreviousKeyEnvs",
		)
	}
	if len(security.CredentialEncryptionPreviousKeyEnvs) != len(security.CredentialEncryptionPreviousKeyVersions) {
		sl.ReportError(
			security.CredentialEncryptionPreviousKeyVersions,
			"CredentialEncryptionPreviousKeyVersions",
			"credential_encryption_previous_key_versions",
			"same_length",
			"CredentialEncryptionPreviousKeyEnvs",
		)
	}
	for _, version := range security.PayloadEncryptionPreviousKeyVersions {
		if version == security.PayloadEncryptionKeyVersion {
			sl.ReportError(
				security.PayloadEncryptionPreviousKeyVersions,
				"PayloadEncryptionPreviousKeyVersions",
				"payload_encryption_previous_key_versions",
				"different_from_active",
				"",
			)
			break
		}
	}
	for _, version := range security.CredentialEncryptionPreviousKeyVersions {
		if version == security.CredentialEncryptionKeyVersion {
			sl.ReportError(
				security.CredentialEncryptionPreviousKeyVersions,
				"CredentialEncryptionPreviousKeyVersions",
				"credential_encryption_previous_key_versions",
				"different_from_active",
				"",
			)
			break
		}
	}
}

func Default() Config {
	return Config{
		Server: ServerConfig{
			Listen:      defaultListen,
			AdminListen: defaultAdminListen,
		},
		Storage: StorageConfig{
			SQLitePath:   defaultSQLitePath,
			ArtifactRoot: defaultArtifactRoot,
			BusyTimeout:  defaultBusyTimeout,
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
			CredentialFile:     defaultCredentialFile,
			ResponsesTransport: ResponsesTransportWebSocketPreferred,
		},
		Journal: JournalConfig{
			Mode:          JournalModeDurable,
			QueueCapacity: defaultJournalQueueCapacity,
			DrainDeadline: defaultJournalDrainDeadline,
		},
		Retention: RetentionConfig{
			ArtifactTTL:   defaultArtifactTTL,
			PayloadTTL:    defaultPayloadTTL,
			MetadataTTL:   defaultMetadataTTL,
			SweepInterval: defaultRetentionSweepInterval,
			BatchSize:     defaultRetentionBatchSize,
			DrainDeadline: defaultRetentionDrainDeadline,
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
	artifactRoot, err := normalizeArtifactRoot(cfg.Storage.ArtifactRoot)
	if err != nil {
		return Config{}, err
	}
	cfg.Storage.ArtifactRoot = artifactRoot
	if err := configurationValidation.Struct(cfg); err != nil {
		return Config{}, fmt.Errorf("validate configuration: %w", err)
	}
	return cfg, nil
}

func normalizeArtifactRoot(path string) (string, error) {
	expanded, err := ExpandPath(path)
	if err != nil {
		return "", fmt.Errorf("expand artifact root: %w", err)
	}
	if expanded == "" || expanded == ":memory:" || strings.HasPrefix(expanded, "file:") {
		return "", errors.New("artifact root must be a filesystem directory")
	}
	if !filepath.IsAbs(expanded) {
		return "", errors.New("artifact root must be absolute")
	}
	cleaned := filepath.Clean(expanded)
	if cleaned != expanded {
		return "", errors.New("artifact root must be clean")
	}
	return cleaned, nil
}

// KeysAvailable checks that all configured key variables are present.
func (s SecurityConfig) KeysAvailable(lookup func(string) (string, bool)) bool {
	names := []string{
		s.PayloadEncryptionKeyEnv,
		s.CredentialEncryptionKeyEnv,
		s.AdminTokenHMACKeyEnv,
	}
	names = append(names, s.PayloadEncryptionPreviousKeyEnvs...)
	names = append(names, s.CredentialEncryptionPreviousKeyEnvs...)
	for _, name := range names {
		if strings.TrimSpace(name) == "" {
			return false
		}
		value, ok := lookup(name)
		if !ok || strings.TrimSpace(value) == "" {
			return false
		}
	}
	name := s.APIKeyHMACKeyEnv
	if strings.TrimSpace(name) == "" {
		return false
	}
	value, ok := lookup(name)
	if !ok || value == "" {
		return false
	}
	return true
}

// PayloadKeySet loads the active and previous payload keys.
func (s SecurityConfig) PayloadKeySet(lookup func(string) (string, bool)) (envelope.KeySet, error) {
	if err := configurationValidation.Struct(s); err != nil {
		return envelope.KeySet{}, fmt.Errorf("payload encryption configuration: %w", err)
	}
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
	if err := configurationValidation.Struct(s); err != nil {
		return envelope.KeySet{}, fmt.Errorf("credential encryption configuration: %w", err)
	}
	return loadEncryptionKeySet(
		"credential",
		s.CredentialEncryptionKeyEnv,
		s.CredentialEncryptionKeyVersion,
		s.CredentialEncryptionPreviousKeyEnvs,
		s.CredentialEncryptionPreviousKeyVersions,
		lookup,
	)
}

// APIKeyHMACKey loads the configured server-side API-key HMAC key.
func (s SecurityConfig) APIKeyHMACKey(lookup func(string) (string, bool)) ([]byte, error) {
	name := s.APIKeyHMACKeyEnv
	if strings.TrimSpace(name) == "" {
		return nil, fmt.Errorf("API-key HMAC key environment name is empty")
	}
	value, ok := lookup(name)
	if !ok || value == "" {
		return nil, fmt.Errorf("API-key HMAC key is unavailable")
	}
	return []byte(value), nil
}

// RequireDistinctActiveKeys rejects reuse of one active key across domains.
func RequireDistinctActiveKeys(payload, credential envelope.KeySet) error {
	if _, err := envelope.NewKeySet(payload.Active, payload.Previous...); err != nil {
		return fmt.Errorf("payload encryption keys: %w", err)
	}
	if _, err := envelope.NewKeySet(credential.Active, credential.Previous...); err != nil {
		return fmt.Errorf("credential encryption keys: %w", err)
	}
	if err := configurationValidation.Struct(activeKeySetPair{Payload: payload, Credential: credential}); err != nil {
		return errors.New("active payload and credential encryption keys must differ")
	}
	return nil
}
func loadEncryptionKeySet(kind, activeName string, activeVersion uint32, previousNames []string, previousVersions []uint32, lookup func(string) (string, bool)) (envelope.KeySet, error) {
	if strings.TrimSpace(activeName) == "" {
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
		if strings.TrimSpace(name) == "" {
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
	overrideString(&cfg.Storage.ArtifactRoot, "CSP_STORAGE_ARTIFACT_ROOT", "CSP_ARTIFACT_ROOT")
	if err := overrideDuration(&cfg.Storage.BusyTimeout, "CSP_STORAGE_BUSY_TIMEOUT", "CSP_BUSY_TIMEOUT"); err != nil {
		return err
	}
	overrideString(&cfg.Security.PayloadEncryptionKeyEnv, "CSP_SECURITY_PAYLOAD_ENCRYPTION_KEY_ENV")
	overrideString(&cfg.Security.CredentialEncryptionKeyEnv, "CSP_SECURITY_CREDENTIAL_ENCRYPTION_KEY_ENV")
	overrideString(&cfg.Security.APIKeyHMACKeyEnv, "CSP_SECURITY_API_KEY_HMAC_KEY_ENV")
	overrideString(&cfg.Security.AdminTokenHMACKeyEnv, "CSP_SECURITY_ADMIN_TOKEN_HMAC_KEY_ENV")
	overrideString(&cfg.Codex.CredentialFile, "CSP_CODEX_CREDENTIAL_FILE")
	journalMode := string(cfg.Journal.Mode)
	overrideString(&journalMode, "CSP_JOURNAL_MODE")
	cfg.Journal.Mode = JournalMode(journalMode)
	if err := overrideInt(&cfg.Journal.QueueCapacity, "CSP_JOURNAL_QUEUE_CAPACITY"); err != nil {
		return err
	}
	if err := overrideDuration(&cfg.Journal.DrainDeadline, "CSP_JOURNAL_DRAIN_DEADLINE"); err != nil {
		return err
	}
	if err := overrideDuration(&cfg.Retention.ArtifactTTL, "CSP_RETENTION_ARTIFACT_TTL", "CSP_ARTIFACT_TTL"); err != nil {
		return err
	}
	if err := overrideDuration(&cfg.Retention.PayloadTTL, "CSP_RETENTION_PAYLOAD_TTL", "CSP_PAYLOAD_TTL"); err != nil {
		return err
	}
	if err := overrideDuration(&cfg.Retention.MetadataTTL, "CSP_RETENTION_METADATA_TTL", "CSP_METADATA_TTL"); err != nil {
		return err
	}
	if err := overrideDuration(&cfg.Retention.SweepInterval, "CSP_RETENTION_SWEEP_INTERVAL", "CSP_RETENTION_INTERVAL"); err != nil {
		return err
	}
	if err := overrideInt(&cfg.Retention.BatchSize, "CSP_RETENTION_BATCH_SIZE"); err != nil {
		return err
	}
	if err := overrideDuration(&cfg.Retention.DrainDeadline, "CSP_RETENTION_DRAIN_DEADLINE"); err != nil {
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
