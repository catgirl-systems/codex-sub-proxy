package config

import (
	"bytes"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
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
const (
	defaultTelemetryExportInterval  = 30 * time.Second
	defaultTelemetryShutdownTimeout = 5 * time.Second
	maxTelemetryHeaderEnvs          = 16
	maxTelemetryDuration            = time.Hour
	maxCORSOrigins                  = 32
	maxTrustedProxyCIDRs            = 32
)

// TLSConfig contains one certificate and private key pair.
type TLSConfig struct {
	CertificateFile string `toml:"certificate_file"`
	PrivateKeyFile  string `toml:"private_key_file"`
}

// CORSConfig contains the exact data-plane origins that may call the API.
type CORSConfig struct {
	AllowedOrigins []string      `toml:"allowed_origins"`
	MaxAge         time.Duration `toml:"max_age"`
}

// TelemetryConfig contains bounded OpenTelemetry exporter settings.
type TelemetryConfig struct {
	Enabled         bool              `toml:"enabled"`
	Endpoint        string            `toml:"endpoint"`
	HeadersEnv      map[string]string `toml:"headers_env"`
	ExportInterval  time.Duration     `toml:"export_interval"`
	ShutdownTimeout time.Duration     `toml:"shutdown_timeout"`
	Insecure        bool              `toml:"insecure"`
}

// ResolveHeaders loads header values from the named environment variables.
func (t TelemetryConfig) ResolveHeaders(lookup func(string) (string, bool)) (map[string]string, error) {
	if lookup == nil {
		return nil, errors.New("telemetry header lookup is nil")
	}
	if len(t.HeadersEnv) > maxTelemetryHeaderEnvs {
		return nil, errors.New("telemetry has too many header variables")
	}
	headers := make(map[string]string, len(t.HeadersEnv))
	for header, envName := range t.HeadersEnv {
		header = strings.TrimSpace(header)
		envName = strings.TrimSpace(envName)
		if !validTelemetryHeaderName(header) || envName == "" || strings.ContainsAny(envName, "\r\n") {
			return nil, errors.New("telemetry header name or environment variable is invalid")
		}
		canonical := http.CanonicalHeaderKey(header)
		if canonical == "" {
			return nil, errors.New("telemetry header name is invalid")
		}
		if _, exists := headers[canonical]; exists {
			return nil, errors.New("telemetry header names must be unique")
		}
		value, ok := lookup(envName)
		if !ok || value == "" {
			return nil, errors.New("telemetry header environment variable is missing")
		}
		if len(value) > 4096 || strings.ContainsAny(value, "\r\n") {
			return nil, errors.New("telemetry header value is invalid")
		}
		headers[canonical] = value
	}
	return headers, nil
}

func validTelemetryHeaderName(name string) bool {
	if name == "" {
		return false
	}
	for index := 0; index < len(name); index++ {
		char := name[index]
		if (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') || (char >= '0' && char <= '9') {
			continue
		}
		switch char {
		case '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~':
		default:
			return false
		}
	}
	return true
}

type Config struct {
	Server    ServerConfig    `toml:"server"`
	Storage   StorageConfig   `toml:"storage"`
	Security  SecurityConfig  `toml:"security"`
	Codex     CodexConfig     `toml:"codex"`
	Journal   JournalConfig   `toml:"journal"`
	Retention RetentionConfig `toml:"retention"`
	Pricing   PricingConfig   `toml:"pricing"`
	CORS      CORSConfig      `toml:"cors"`
	Telemetry TelemetryConfig `toml:"telemetry"`
}

// PricingConfig contains immutable public pricing and subscription inputs.
type PricingConfig struct {
	Versions                       []PricingVersionConfig                `toml:"versions"`
	SubscriptionAllocationVersions []SubscriptionAllocationVersionConfig `toml:"subscription_allocation_versions"`
}

// PricingVersionConfig defines one public price catalog version.
type PricingVersionConfig struct {
	ID          string             `toml:"id" json:"id"`
	EffectiveAt time.Time          `toml:"effective_at" json:"effective_at"`
	Currency    string             `toml:"currency" json:"currency"`
	Models      []ModelPriceConfig `toml:"models" json:"models"`
}

// ModelPriceConfig defines integer public rates for one model.
type ModelPriceConfig struct {
	ModelID                         string `toml:"model_id" json:"model_id"`
	InputMicrounitsPerMillion       int64  `toml:"input_microunits_per_million" json:"input_microunits_per_million"`
	CachedInputMicrounitsPerMillion int64  `toml:"cached_input_microunits_per_million" json:"cached_input_microunits_per_million"`
	OutputMicrounitsPerMillion      int64  `toml:"output_microunits_per_million" json:"output_microunits_per_million"`
	ReasoningMicrounitsPerMillion   int64  `toml:"reasoning_microunits_per_million" json:"reasoning_microunits_per_million"`
	ImageMicrounitsPerImage         int64  `toml:"image_microunits_per_image" json:"image_microunits_per_image"`
}

// SubscriptionAllocationVersionConfig defines one monthly allocation input.
type SubscriptionAllocationVersionConfig struct {
	ID                    string    `toml:"id" json:"id"`
	EffectiveAt           time.Time `toml:"effective_at" json:"effective_at"`
	Currency              string    `toml:"currency" json:"currency"`
	MonthlyCostMicrounits int64     `toml:"monthly_cost_microunits" json:"monthly_cost_microunits"`
	AllocationBasis       string    `toml:"allocation_basis" json:"allocation_basis"`
}

type ServerConfig struct {
	Listen            string    `toml:"listen" validate:"required"`
	AdminListen       string    `toml:"admin_listen" validate:"required"`
	TrustedProxyCIDRs []string  `toml:"trusted_proxy_cidrs" validate:"max=32"`
	DataTLS           TLSConfig `toml:"data_tls"`
	AdminTLS          TLSConfig `toml:"admin_tls"`
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
	AdminBootstrapTokenEnv                  string   `toml:"admin_bootstrap_token_env" validate:"required"`
	AdminCookieSecure                       bool     `toml:"admin_cookie_secure"`
}

type ResponsesTransport string

const (
	ResponsesTransportWebSocketPreferred ResponsesTransport = "websocket_preferred"
	ResponsesTransportSSE                ResponsesTransport = "sse"
)

type CodexConfig struct {
	CredentialFile     string             `toml:"credential_file" validate:"required"`
	ResponsesTransport ResponsesTransport `toml:"responses_transport" validate:"oneof=websocket_preferred sse"`
	ResponsesURL       string             `toml:"responses_url"`
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
			AdminBootstrapTokenEnv:         "CSP_ADMIN_BOOTSTRAP_TOKEN",
			AdminCookieSecure:              true,
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
		CORS: CORSConfig{MaxAge: 10 * time.Minute},
		Telemetry: TelemetryConfig{
			ExportInterval:  defaultTelemetryExportInterval,
			ShutdownTimeout: defaultTelemetryShutdownTimeout,
		},
	}
}

func Load(path string) (Config, error) {
	cfg := Default()
	if path != "" {
		contents, err := os.ReadFile(path)
		if err != nil && !os.IsNotExist(err) {
			return Config{}, fmt.Errorf("read config: %w", err)
		}
		if err == nil && len(strings.TrimSpace(string(contents))) > 0 {
			metadata, err := toml.Decode(string(contents), &cfg)
			if err != nil {
				return Config{}, fmt.Errorf("decode config: %w", err)
			}
			if undecoded := metadata.Undecoded(); len(undecoded) != 0 {
				return Config{}, fmt.Errorf("decode config: unknown key")
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
	if err := validatePricingConfig(&cfg.Pricing); err != nil {
		return Config{}, fmt.Errorf("validate pricing configuration: %w", err)
	}
	if err := validateCORSConfig(&cfg.CORS); err != nil {
		return Config{}, fmt.Errorf("validate CORS configuration: %w", err)
	}
	if err := canonicalizeTrustedProxyCIDRs(&cfg.Server.TrustedProxyCIDRs); err != nil {
		return Config{}, fmt.Errorf("validate trusted proxy configuration: %w", err)
	}
	if err := validateTelemetryConfig(&cfg.Telemetry); err != nil {
		return Config{}, fmt.Errorf("validate telemetry configuration: %w", err)
	}
	if err := configurationValidation.Struct(cfg); err != nil {
		return Config{}, fmt.Errorf("validate configuration: %w", err)
	}
	if err := ValidateAdminCookieTransport(cfg.Server.AdminListen, cfg.Security.AdminCookieSecure); err != nil {
		return Config{}, fmt.Errorf("validate admin cookie transport: %w", err)
	}
	if err := ValidateListenerTLS(cfg.Server.Listen, cfg.Server.DataTLS, false); err != nil {
		return Config{}, fmt.Errorf("validate data listener security: %w", err)
	}
	if err := ValidateListenerTLS(cfg.Server.AdminListen, cfg.Server.AdminTLS, true); err != nil {
		return Config{}, fmt.Errorf("validate admin listener security: %w", err)
	}
	return cfg, nil
}

func validateCORSConfig(cors *CORSConfig) error {
	if cors == nil {
		return errors.New("CORS configuration is nil")
	}
	if len(cors.AllowedOrigins) > maxCORSOrigins {
		return errors.New("CORS has too many origins")
	}
	if cors.MaxAge <= 0 || cors.MaxAge > 24*time.Hour {
		return errors.New("CORS max age is out of bounds")
	}
	seen := make(map[string]struct{}, len(cors.AllowedOrigins))
	for index := range cors.AllowedOrigins {
		origin, err := CanonicalOrigin(cors.AllowedOrigins[index])
		if err != nil {
			return fmt.Errorf("origin %d: %w", index, err)
		}
		if _, ok := seen[origin]; ok {
			return errors.New("CORS origins must be unique")
		}
		seen[origin] = struct{}{}
		cors.AllowedOrigins[index] = origin
	}
	return nil
}

// CanonicalOrigin validates and canonicalizes one exact CORS origin.
func CanonicalOrigin(raw string) (string, error) {
	if raw == "" || len(raw) > 256 || strings.ContainsAny(raw, "*\r\n\t ") {
		return "", errors.New("origin is invalid")
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" || parsed.User != nil || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", errors.New("origin must contain only scheme and host")
	}
	scheme := strings.ToLower(parsed.Scheme)
	if scheme != "http" && scheme != "https" {
		return "", errors.New("origin scheme is unsupported")
	}
	host := strings.ToLower(parsed.Hostname())
	if host == "" {
		return "", errors.New("origin host is empty")
	}
	if strings.Contains(host, "%") {
		return "", errors.New("origin host zone is unsupported")
	}
	port := parsed.Port()
	if port != "" {
		portNumber, err := strconv.Atoi(port)
		if err != nil || portNumber < 1 || portNumber > 65535 {
			return "", errors.New("origin port is invalid")
		}
	}
	isLoopback := strings.EqualFold(host, "localhost")
	if ip, err := netip.ParseAddr(host); err == nil {
		isLoopback = ip.IsLoopback()
	}
	if scheme == "http" && !isLoopback {
		return "", errors.New("HTTP origins require loopback hosts")
	}
	if (scheme == "http" && port == "80") || (scheme == "https" && port == "443") {
		port = ""
	}
	canonicalHost := host
	if strings.Contains(host, ":") {
		canonicalHost = "[" + host + "]"
	}
	if port != "" {
		canonicalHost += ":" + port
	}
	return scheme + "://" + canonicalHost, nil
}

func canonicalizeTrustedProxyCIDRs(cidrs *[]string) error {
	if cidrs == nil {
		return errors.New("trusted proxy list is nil")
	}
	if len(*cidrs) > maxTrustedProxyCIDRs {
		return errors.New("trusted proxy list is too large")
	}
	seen := make(map[string]struct{}, len(*cidrs))
	for index, raw := range *cidrs {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(raw))
		if err != nil || !prefix.IsValid() {
			return fmt.Errorf("CIDR %d is invalid", index)
		}
		prefix = prefix.Masked()
		canonical := prefix.String()
		if _, ok := seen[canonical]; ok {
			return errors.New("trusted proxy CIDRs must be unique")
		}
		seen[canonical] = struct{}{}
		(*cidrs)[index] = canonical
	}
	return nil
}

// TrustedProxyPrefixes returns canonical prefixes for request boundary use.
func TrustedProxyPrefixes(cidrs []string) ([]netip.Prefix, error) {
	if len(cidrs) > maxTrustedProxyCIDRs {
		return nil, errors.New("trusted proxy list is too large")
	}
	prefixes := make([]netip.Prefix, 0, len(cidrs))
	seen := make(map[netip.Prefix]struct{}, len(cidrs))
	for _, raw := range cidrs {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(raw))
		if err != nil || !prefix.IsValid() {
			return nil, errors.New("trusted proxy CIDR is invalid")
		}
		prefix = prefix.Masked()
		if _, ok := seen[prefix]; ok {
			return nil, errors.New("trusted proxy CIDRs must be unique")
		}
		seen[prefix] = struct{}{}
		prefixes = append(prefixes, prefix)
	}
	return prefixes, nil
}

func validateTelemetryConfig(telemetry *TelemetryConfig) error {
	if telemetry == nil {
		return errors.New("telemetry configuration is nil")
	}
	if len(telemetry.HeadersEnv) > maxTelemetryHeaderEnvs {
		return errors.New("telemetry has too many header variables")
	}
	seenHeaders := make(map[string]struct{}, len(telemetry.HeadersEnv))
	for header, envName := range telemetry.HeadersEnv {
		header = strings.TrimSpace(header)
		envName = strings.TrimSpace(envName)
		if !validTelemetryHeaderName(header) || envName == "" || strings.ContainsAny(envName, "\r\n") {
			return errors.New("telemetry header name or environment variable is invalid")
		}
		canonical := http.CanonicalHeaderKey(header)
		if canonical == "" {
			return errors.New("telemetry header name is invalid")
		}
		if _, exists := seenHeaders[canonical]; exists {
			return errors.New("telemetry header names must be unique")
		}
		seenHeaders[canonical] = struct{}{}
	}
	if telemetry.ExportInterval <= 0 || telemetry.ExportInterval > maxTelemetryDuration {
		return errors.New("telemetry export interval is out of bounds")
	}
	if telemetry.ShutdownTimeout <= 0 || telemetry.ShutdownTimeout > time.Minute {
		return errors.New("telemetry shutdown timeout is out of bounds")
	}
	if !telemetry.Enabled {
		return nil
	}
	if telemetry.Endpoint == "" {
		return errors.New("telemetry endpoint is required when enabled")
	}
	parsed, err := url.Parse(telemetry.Endpoint)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.User != nil {
		return errors.New("telemetry endpoint is invalid")
	}
	if parsed.Scheme == "https" && telemetry.Insecure {
		return errors.New("insecure telemetry transport is invalid for HTTPS")
	}
	if parsed.Scheme != "https" {
		if parsed.Scheme != "http" || !telemetry.Insecure {
			return errors.New("telemetry endpoint requires HTTPS")
		}
		host := strings.ToLower(parsed.Hostname())
		ip, ipErr := netip.ParseAddr(host)
		if ipErr != nil && !strings.EqualFold(host, "localhost") {
			return errors.New("insecure telemetry endpoint must be loopback")
		}
		if ipErr == nil && !ip.IsLoopback() {
			return errors.New("insecure telemetry endpoint must be loopback")
		}
	}
	return nil
}

// ValidateListenerTLS enforces TLS and cookie policy for listener addresses.
func ValidateListenerTLS(listen string, tlsConfig TLSConfig, admin bool) error {
	if listen == "" {
		return errors.New("listener address is empty")
	}
	host, _, err := net.SplitHostPort(listen)
	if err != nil {
		return errors.New("listener address is invalid")
	}
	hasCertificate := strings.TrimSpace(tlsConfig.CertificateFile) != ""
	hasKey := strings.TrimSpace(tlsConfig.PrivateKeyFile) != ""
	if hasCertificate != hasKey {
		return errors.New("TLS certificate and private key must be configured together")
	}
	loopback := strings.EqualFold(host, "localhost")
	if ip, parseErr := netip.ParseAddr(host); parseErr == nil {
		loopback = ip.IsLoopback()
	}
	if host == "" || host == "*" {
		loopback = false
	}
	if !loopback && !hasCertificate {
		return errors.New("non-loopback listener requires TLS")
	}
	if admin && !loopback && !hasCertificate {
		return errors.New("non-loopback admin listener requires TLS and secure cookies")
	}
	return nil
}

// ValidateAdminCookieTransport requires insecure admin cookies to use an explicit loopback listener.
func ValidateAdminCookieTransport(adminListen string, secure bool) error {
	if secure {
		return nil
	}
	host, port, err := net.SplitHostPort(adminListen)
	if err != nil || host == "" {
		return errors.New("insecure admin cookies require an explicit loopback host and port")
	}
	portNumber, err := strconv.Atoi(port)
	if err != nil || portNumber < 0 || portNumber > 65535 {
		return errors.New("admin listener port is invalid for insecure cookies")
	}
	if strings.EqualFold(host, "localhost") {
		return nil
	}
	ip := net.ParseIP(host)
	if ip == nil || ip.To4() == nil || ip.To4()[0] != 127 {
		if ip == nil || !ip.Equal(net.ParseIP("::1")) {
			return errors.New("insecure admin cookies require a loopback AdminListen host")
		}
	}
	return nil
}

const (
	maxPricingVersionIDLength = 64
	maxPricingModels          = 4096
	pricingCurrencyUSD        = "USD"
	pricingAllocationBasis    = "proportional_public_estimated_cost"
)

func validatePricingConfig(pricing *PricingConfig) error {
	if pricing == nil {
		return errors.New("pricing configuration is nil")
	}
	if len(pricing.Versions) > 16 || len(pricing.SubscriptionAllocationVersions) > 16 {
		return errors.New("pricing configuration has too many versions")
	}
	pricingIDs := make(map[string]struct{}, len(pricing.Versions))
	pricingEffective := make(map[int64]struct{}, len(pricing.Versions))
	for index := range pricing.Versions {
		version := &pricing.Versions[index]
		if err := validatePricingVersion(version); err != nil {
			return fmt.Errorf("pricing version %d: %w", index, err)
		}
		if _, exists := pricingIDs[version.ID]; exists {
			return fmt.Errorf("duplicate pricing version ID %q", version.ID)
		}
		pricingIDs[version.ID] = struct{}{}
		effective := version.EffectiveAt.UTC().UnixNano()
		if _, exists := pricingEffective[effective]; exists {
			return fmt.Errorf("duplicate pricing effective time %s", version.EffectiveAt.Format(time.RFC3339Nano))
		}
		pricingEffective[effective] = struct{}{}
	}
	allocationIDs := make(map[string]struct{}, len(pricing.SubscriptionAllocationVersions))
	allocationEffective := make(map[int64]struct{}, len(pricing.SubscriptionAllocationVersions))
	for index := range pricing.SubscriptionAllocationVersions {
		version := &pricing.SubscriptionAllocationVersions[index]
		if err := validateSubscriptionAllocationVersion(version); err != nil {
			return fmt.Errorf("subscription allocation version %d: %w", index, err)
		}
		if _, exists := allocationIDs[version.ID]; exists {
			return fmt.Errorf("duplicate subscription allocation version ID %q", version.ID)
		}
		allocationIDs[version.ID] = struct{}{}
		effective := version.EffectiveAt.UTC().UnixNano()
		if _, exists := allocationEffective[effective]; exists {
			return fmt.Errorf("duplicate subscription allocation effective time %s", version.EffectiveAt.Format(time.RFC3339Nano))
		}
		allocationEffective[effective] = struct{}{}
	}
	return nil
}

func validatePricingVersion(version *PricingVersionConfig) error {
	if version == nil || strings.TrimSpace(version.ID) == "" || version.ID != strings.TrimSpace(version.ID) || len(version.ID) > maxPricingVersionIDLength {
		return errors.New("version ID is empty, too long, or not trimmed")
	}
	if version.EffectiveAt.IsZero() || version.EffectiveAt.Location() != time.UTC {
		return errors.New("effective time must be an explicit UTC instant")
	}
	if version.Currency != pricingCurrencyUSD {
		return errors.New("currency must be USD")
	}
	if len(version.Models) == 0 || len(version.Models) > maxPricingModels {
		return errors.New("model price list is empty or too large")
	}
	seen := make(map[string]struct{}, len(version.Models))
	for index := range version.Models {
		model := &version.Models[index]
		if err := validateModelPrice(model); err != nil {
			return fmt.Errorf("model price %d: %w", index, err)
		}
		if strings.TrimSpace(model.ModelID) == "" || model.ModelID != strings.TrimSpace(model.ModelID) || len(model.ModelID) > 256 {
			return errors.New("model ID is empty, too long, or not trimmed")
		}
		if _, exists := seen[model.ModelID]; exists {
			return fmt.Errorf("duplicate model ID %q", model.ModelID)
		}
		seen[model.ModelID] = struct{}{}
		rates := []int64{
			model.InputMicrounitsPerMillion,
			model.CachedInputMicrounitsPerMillion,
			model.OutputMicrounitsPerMillion,
			model.ReasoningMicrounitsPerMillion,
			model.ImageMicrounitsPerImage,
		}
		for _, rate := range rates {
			if rate < 0 {
				return errors.New("rates must not be negative")
			}
		}
	}
	return nil
}

func validateModelPrice(model *ModelPriceConfig) error {
	if model == nil {
		return errors.New("model price is nil")
	}
	rates := []int64{
		model.InputMicrounitsPerMillion,
		model.CachedInputMicrounitsPerMillion,
		model.OutputMicrounitsPerMillion,
		model.ReasoningMicrounitsPerMillion,
		model.ImageMicrounitsPerImage,
	}
	for _, rate := range rates {
		if rate < 0 {
			return errors.New("rates must not be negative")
		}
	}
	return nil
}

func validateSubscriptionAllocationVersion(version *SubscriptionAllocationVersionConfig) error {
	if version == nil || strings.TrimSpace(version.ID) == "" || version.ID != strings.TrimSpace(version.ID) || len(version.ID) > maxPricingVersionIDLength {
		return errors.New("version ID is empty, too long, or not trimmed")
	}
	if version.EffectiveAt.IsZero() || version.EffectiveAt.Location() != time.UTC {
		return errors.New("effective time must be an explicit UTC instant")
	}
	if version.Currency != pricingCurrencyUSD {
		return errors.New("currency must be USD")
	}
	if version.MonthlyCostMicrounits < 0 {
		return errors.New("monthly cost must not be negative")
	}
	if version.AllocationBasis != pricingAllocationBasis {
		return errors.New("allocation basis is unsupported")
	}
	return nil
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
	if cleaned == string(filepath.Separator) {
		return "", errors.New("artifact root must not be the filesystem root")
	}
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
	for _, name := range []string{s.APIKeyHMACKeyEnv, s.AdminTokenHMACKeyEnv} {
		if strings.TrimSpace(name) == "" {
			return false
		}
		value, ok := lookup(name)
		if !ok || value == "" {
			return false
		}
	}
	return true
}

// DataKeysAvailable checks only keys needed by the data plane.
func (s SecurityConfig) DataKeysAvailable(lookup func(string) (string, bool)) bool {
	if strings.TrimSpace(s.PayloadEncryptionKeyEnv) == "" || strings.TrimSpace(s.CredentialEncryptionKeyEnv) == "" || strings.TrimSpace(s.APIKeyHMACKeyEnv) == "" {
		return false
	}
	for _, name := range append(append([]string{s.PayloadEncryptionKeyEnv, s.CredentialEncryptionKeyEnv}, s.PayloadEncryptionPreviousKeyEnvs...), s.CredentialEncryptionPreviousKeyEnvs...) {
		value, ok := lookup(name)
		if !ok || strings.TrimSpace(value) == "" {
			return false
		}
	}
	value, ok := lookup(s.APIKeyHMACKeyEnv)
	return ok && value != ""
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

// AdminTokenHMACKey loads the admin token HMAC key without trimming its bytes.
func (s SecurityConfig) AdminTokenHMACKey(lookup func(string) (string, bool)) ([]byte, error) {
	name := s.AdminTokenHMACKeyEnv
	if strings.TrimSpace(name) == "" {
		return nil, errors.New("admin token HMAC key environment name is empty")
	}
	value, ok := lookup(name)
	if !ok || value == "" {
		return nil, errors.New("admin token HMAC key is unavailable")
	}
	return []byte(value), nil
}

// AdminBootstrapToken loads the optional full token from its dedicated lookup.
func (s SecurityConfig) AdminBootstrapToken(lookup func(string) (string, bool)) ([]byte, error) {
	name := s.AdminBootstrapTokenEnv
	if strings.TrimSpace(name) == "" {
		return nil, errors.New("admin bootstrap token environment name is empty")
	}
	value, ok := lookup(name)
	if !ok || value == "" {
		return nil, nil
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
	overrideString(&cfg.Server.DataTLS.CertificateFile, "CSP_SERVER_DATA_TLS_CERTIFICATE_FILE")
	overrideString(&cfg.Server.DataTLS.PrivateKeyFile, "CSP_SERVER_DATA_TLS_PRIVATE_KEY_FILE")
	overrideString(&cfg.Server.AdminTLS.CertificateFile, "CSP_SERVER_ADMIN_TLS_CERTIFICATE_FILE")
	overrideString(&cfg.Server.AdminTLS.PrivateKeyFile, "CSP_SERVER_ADMIN_TLS_PRIVATE_KEY_FILE")
	if value, ok := os.LookupEnv("CSP_SERVER_TRUSTED_PROXY_CIDRS"); ok {
		cfg.Server.TrustedProxyCIDRs = splitEnvironmentList(value)
	}
	overrideString(&cfg.Storage.SQLitePath, "CSP_STORAGE_SQLITE_PATH", "CSP_SQLITE_PATH")
	overrideString(&cfg.Storage.ArtifactRoot, "CSP_STORAGE_ARTIFACT_ROOT", "CSP_ARTIFACT_ROOT")
	if err := overrideDuration(&cfg.Storage.BusyTimeout, "CSP_STORAGE_BUSY_TIMEOUT", "CSP_BUSY_TIMEOUT"); err != nil {
		return err
	}
	if value, ok := os.LookupEnv("CSP_CORS_ALLOWED_ORIGINS"); ok {
		cfg.CORS.AllowedOrigins = splitEnvironmentList(value)
	}
	if err := overrideDuration(&cfg.CORS.MaxAge, "CSP_CORS_MAX_AGE"); err != nil {
		return err
	}
	if err := overrideBool(&cfg.Telemetry.Enabled, "CSP_OTEL_ENABLED", "CSP_TELEMETRY_ENABLED"); err != nil {
		return err
	}
	overrideString(&cfg.Telemetry.Endpoint, "CSP_OTEL_ENDPOINT", "CSP_TELEMETRY_ENDPOINT")
	if err := overrideDuration(&cfg.Telemetry.ExportInterval, "CSP_OTEL_EXPORT_INTERVAL", "CSP_TELEMETRY_EXPORT_INTERVAL"); err != nil {
		return err
	}
	if err := overrideDuration(&cfg.Telemetry.ShutdownTimeout, "CSP_OTEL_SHUTDOWN_TIMEOUT", "CSP_TELEMETRY_SHUTDOWN_TIMEOUT"); err != nil {
		return err
	}
	if err := overrideBool(&cfg.Telemetry.Insecure, "CSP_OTEL_INSECURE", "CSP_TELEMETRY_INSECURE"); err != nil {
		return err
	}
	if value, ok := os.LookupEnv("CSP_OTEL_HEADERS_ENV"); ok {
		headers, err := parseTelemetryHeaderEnvList(value)
		if err != nil {
			return err
		}
		cfg.Telemetry.HeadersEnv = headers
	}
	overrideString(&cfg.Security.PayloadEncryptionKeyEnv, "CSP_SECURITY_PAYLOAD_ENCRYPTION_KEY_ENV")
	overrideString(&cfg.Security.CredentialEncryptionKeyEnv, "CSP_SECURITY_CREDENTIAL_ENCRYPTION_KEY_ENV")
	overrideString(&cfg.Security.APIKeyHMACKeyEnv, "CSP_SECURITY_API_KEY_HMAC_KEY_ENV")
	overrideString(&cfg.Security.AdminTokenHMACKeyEnv, "CSP_SECURITY_ADMIN_TOKEN_HMAC_KEY_ENV")
	overrideString(&cfg.Security.AdminBootstrapTokenEnv, "CSP_SECURITY_ADMIN_BOOTSTRAP_TOKEN_ENV")
	overrideString(&cfg.Codex.ResponsesURL, "CSP_CODEX_RESPONSES_URL")
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
	if err := overrideDuration(&cfg.Retention.PayloadTTL, "CSP_RETENTION_PAYLOAD_TTL"); err != nil {
		return err
	}
	if err := overrideDuration(&cfg.Retention.MetadataTTL, "CSP_RETENTION_METADATA_TTL"); err != nil {
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
	return applyPricingEnvironment(&cfg.Pricing)
}

func applyPricingEnvironment(pricing *PricingConfig) error {
	if pricing == nil {
		return errors.New("pricing configuration is nil")
	}
	if value, ok := os.LookupEnv("CSP_PRICING_VERSIONS_JSON"); ok {
		var versions []PricingVersionConfig
		if err := decodeJSONStrict(value, &versions); err != nil {
			return fmt.Errorf("parse CSP_PRICING_VERSIONS_JSON: %w", err)
		}
		pricing.Versions = versions
	}
	if value, ok := os.LookupEnv("CSP_SUBSCRIPTION_ALLOCATION_VERSIONS_JSON"); ok {
		var versions []SubscriptionAllocationVersionConfig
		if err := decodeJSONStrict(value, &versions); err != nil {
			return fmt.Errorf("parse CSP_SUBSCRIPTION_ALLOCATION_VERSIONS_JSON: %w", err)
		}
		pricing.SubscriptionAllocationVersions = versions
	}
	if hasPricingVersionEnvironment() {
		version, err := pricingVersionFromEnvironment(*pricing)
		if err != nil {
			return err
		}
		if len(pricing.Versions) == 0 {
			pricing.Versions = []PricingVersionConfig{version}
		} else {
			pricing.Versions[0] = version
		}
	}
	if hasSubscriptionEnvironment() {
		version, err := subscriptionVersionFromEnvironment(*pricing)
		if err != nil {
			return err
		}
		if len(pricing.SubscriptionAllocationVersions) == 0 {
			pricing.SubscriptionAllocationVersions = []SubscriptionAllocationVersionConfig{version}
		} else {
			pricing.SubscriptionAllocationVersions[0] = version
		}
	}
	return nil
}

func hasPricingVersionEnvironment() bool {
	for _, name := range []string{"CSP_PRICING_VERSION_ID", "CSP_PRICING_EFFECTIVE_AT", "CSP_PRICING_CURRENCY", "CSP_PRICING_MODELS_JSON"} {
		if _, ok := os.LookupEnv(name); ok {
			return true
		}
	}
	return false
}

func pricingVersionFromEnvironment(pricing PricingConfig) (PricingVersionConfig, error) {
	version := PricingVersionConfig{Currency: pricingCurrencyUSD}
	if len(pricing.Versions) != 0 {
		version = pricing.Versions[0]
	}
	overrideString(&version.ID, "CSP_PRICING_VERSION_ID")
	overrideString(&version.Currency, "CSP_PRICING_CURRENCY")
	if value, ok := os.LookupEnv("CSP_PRICING_EFFECTIVE_AT"); ok {
		effective, err := parseUTCInstant(value)
		if err != nil {
			return PricingVersionConfig{}, fmt.Errorf("parse CSP_PRICING_EFFECTIVE_AT: %w", err)
		}
		version.EffectiveAt = effective
	}
	if value, ok := os.LookupEnv("CSP_PRICING_MODELS_JSON"); ok {
		var models []ModelPriceConfig
		if err := decodeJSONStrict(value, &models); err != nil {
			return PricingVersionConfig{}, fmt.Errorf("parse CSP_PRICING_MODELS_JSON: %w", err)
		}
		version.Models = models
	}
	return version, nil
}

func hasSubscriptionEnvironment() bool {
	for _, name := range []string{"CSP_SUBSCRIPTION_ALLOCATION_VERSION_ID", "CSP_SUBSCRIPTION_ALLOCATION_EFFECTIVE_AT", "CSP_SUBSCRIPTION_ALLOCATION_CURRENCY", "CSP_SUBSCRIPTION_ALLOCATION_MONTHLY_COST_MICROUNITS", "CSP_SUBSCRIPTION_ALLOCATION_BASIS"} {
		if _, ok := os.LookupEnv(name); ok {
			return true
		}
	}
	return false
}

func subscriptionVersionFromEnvironment(pricing PricingConfig) (SubscriptionAllocationVersionConfig, error) {
	version := SubscriptionAllocationVersionConfig{Currency: pricingCurrencyUSD, AllocationBasis: pricingAllocationBasis}
	if len(pricing.SubscriptionAllocationVersions) != 0 {
		version = pricing.SubscriptionAllocationVersions[0]
	}
	overrideString(&version.ID, "CSP_SUBSCRIPTION_ALLOCATION_VERSION_ID")
	overrideString(&version.Currency, "CSP_SUBSCRIPTION_ALLOCATION_CURRENCY")
	overrideString(&version.AllocationBasis, "CSP_SUBSCRIPTION_ALLOCATION_BASIS")
	if value, ok := os.LookupEnv("CSP_SUBSCRIPTION_ALLOCATION_EFFECTIVE_AT"); ok {
		effective, err := parseUTCInstant(value)
		if err != nil {
			return SubscriptionAllocationVersionConfig{}, fmt.Errorf("parse CSP_SUBSCRIPTION_ALLOCATION_EFFECTIVE_AT: %w", err)
		}
		version.EffectiveAt = effective
	}
	if value, ok := os.LookupEnv("CSP_SUBSCRIPTION_ALLOCATION_MONTHLY_COST_MICROUNITS"); ok {
		cost, err := strconv.ParseInt(strings.TrimSpace(value), 10, 64)
		if err != nil {
			return SubscriptionAllocationVersionConfig{}, fmt.Errorf("parse CSP_SUBSCRIPTION_ALLOCATION_MONTHLY_COST_MICROUNITS: %w", err)
		}
		version.MonthlyCostMicrounits = cost
	}
	return version, nil
}

func decodeJSONStrict(value string, target any) error {
	decoder := json.NewDecoder(bytes.NewReader([]byte(value)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return errors.New("trailing JSON value")
		}
		return err
	}
	return nil
}

func parseUTCInstant(value string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(value))
	if err != nil {
		return time.Time{}, err
	}
	if parsed.Location() != time.UTC {
		return time.Time{}, errors.New("timestamp must use UTC Z")
	}
	return parsed, nil
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

func overrideBool(dst *bool, names ...string) error {
	for _, name := range names {
		if value, ok := os.LookupEnv(name); ok {
			parsed, err := strconv.ParseBool(strings.TrimSpace(value))
			if err != nil {
				return fmt.Errorf("parse %s: %w", name, err)
			}
			*dst = parsed
			return nil
		}
	}
	return nil
}

func splitEnvironmentList(value string) []string {
	parts := strings.Split(value, ",")
	items := make([]string, 0, len(parts))
	for _, part := range parts {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			items = append(items, trimmed)
		}
	}
	return items
}

func parseTelemetryHeaderEnvList(value string) (map[string]string, error) {
	parts := splitEnvironmentList(value)
	headers := make(map[string]string, len(parts))
	for _, part := range parts {
		name, envName, ok := strings.Cut(part, "=")
		if !ok || strings.TrimSpace(name) == "" || strings.TrimSpace(envName) == "" {
			return nil, errors.New("telemetry header environment mapping is invalid")
		}
		name = strings.TrimSpace(name)
		envName = strings.TrimSpace(envName)
		if !validTelemetryHeaderName(name) || strings.ContainsAny(envName, "\r\n") {
			return nil, errors.New("telemetry header environment mapping is invalid")
		}
		canonical := http.CanonicalHeaderKey(name)
		if canonical == "" {
			return nil, errors.New("telemetry header environment mapping is invalid")
		}
		if _, exists := headers[canonical]; exists {
			return nil, errors.New("telemetry header environment mappings must be unique")
		}
		headers[canonical] = envName
	}
	return headers, nil
}
