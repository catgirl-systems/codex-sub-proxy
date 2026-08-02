package apikey

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql/driver"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
	"unicode"
)

const (
	KeyPrefix                  = "csp_live_"
	ModelOwner                 = "openai"
	MaxAuthorizationHeaderSize = 4096
	maxKeySize                 = 256
	minPublicPrefixSize        = 8
	maxPublicPrefixSize        = 32
	minSecretSize              = 32
	maxSecretSize              = 128
	publicPrefixRandomBytes    = 8
	secretRandomBytes          = 32
	recordIDRandomBytes        = 16
	maxPolicyItems             = 64
	maxPolicyValueSize         = 128
	maxNameSize                = 255
	maxOwnerSize               = 255
	maxPrefixCandidates        = 16
)

var (
	ErrInvalidKey  = errors.New("invalid API key")
	ErrForbidden   = errors.New("API key permission denied")
	ErrUnavailable = errors.New("API key authentication is unavailable")
)

// StringList stores a bounded JSON string list in one SQLite column.
type StringList []string

func (list StringList) Value() (driver.Value, error) {
	if list == nil {
		list = StringList{}
	}
	encoded, err := json.Marshal(list)
	if err != nil {
		return nil, fmt.Errorf("encode string list: %w", err)
	}
	return encoded, nil
}

func (list *StringList) Scan(value any) error {
	if list == nil {
		return errors.New("string list destination is nil")
	}
	if value == nil {
		*list = nil
		return nil
	}
	var encoded []byte
	switch value := value.(type) {
	case []byte:
		encoded = value
	case string:
		encoded = []byte(value)
	default:
		return fmt.Errorf("scan string list from %T", value)
	}
	if len(encoded) == 0 {
		return errors.New("stored string list is empty")
	}
	var decoded []string
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		return fmt.Errorf("decode string list: %w", err)
	}
	canonical, err := normalizeValues(decoded, "stored policy value")
	if err != nil {
		return err
	}
	*list = StringList(canonical)
	return nil
}

// Policy controls the operations that one API key can access.
type Policy struct {
	Name             string
	Owner            string
	AllowedEndpoints []string
	AllowedModels    []string
	ExpiresAt        *time.Time
}

// Record is the durable, non-secret API key record.
type Record struct {
	ID               string     `gorm:"column:id;primaryKey;size:32"`
	Name             string     `gorm:"column:name;not null;size:255"`
	Owner            string     `gorm:"column:owner;not null;size:255"`
	Prefix           string     `gorm:"column:prefix;not null;size:64;uniqueIndex"`
	Digest           []byte     `gorm:"column:digest;not null;size:32"`
	AllowedEndpoints StringList `gorm:"column:allowed_endpoints;type:text;not null"`
	AllowedModels    StringList `gorm:"column:allowed_models;type:text;not null"`
	CreatedAt        time.Time  `gorm:"column:created_at;not null"`
	ExpiresAt        *time.Time `gorm:"column:expires_at"`
	DisabledAt       *time.Time `gorm:"column:disabled_at"`
	LastUsedAt       *time.Time `gorm:"column:last_used_at"`
}

func (Record) TableName() string {
	return "api_keys"
}

func (record Record) Policy() (Policy, error) {
	endpoints, err := normalizeValues([]string(record.AllowedEndpoints), "stored endpoint")
	if err != nil {
		return Policy{}, err
	}
	models, err := normalizeValues([]string(record.AllowedModels), "stored model")
	if err != nil {
		return Policy{}, err
	}
	return Policy{
		Name:             record.Name,
		Owner:            record.Owner,
		AllowedEndpoints: endpoints,
		AllowedModels:    models,
		ExpiresAt:        record.ExpiresAt,
	}, nil
}

func validateHMACKey(key []byte) error {
	if len(key) == 0 {
		return fmt.Errorf("%w: HMAC key is empty", ErrUnavailable)
	}
	if len(key) > 4096 {
		return fmt.Errorf("%w: HMAC key is too large", ErrUnavailable)
	}
	return nil
}

func ValidatePolicy(policy Policy) (Policy, error) {
	policy.Name = strings.TrimSpace(policy.Name)
	policy.Owner = strings.TrimSpace(policy.Owner)
	if policy.Name == "" {
		return Policy{}, errors.New("API key name is required")
	}
	if len(policy.Name) > maxNameSize || hasControl(policy.Name) {
		return Policy{}, errors.New("API key name is invalid")
	}
	if policy.Owner == "" {
		policy.Owner = "local"
	}
	if len(policy.Owner) > maxOwnerSize || hasControl(policy.Owner) {
		return Policy{}, errors.New("API key owner is invalid")
	}
	endpoints, err := normalizeEndpoints(policy.AllowedEndpoints)
	if err != nil {
		return Policy{}, err
	}
	models, err := normalizeModels(policy.AllowedModels)
	if err != nil {
		return Policy{}, err
	}
	if policy.ExpiresAt != nil {
		expires := policy.ExpiresAt.UTC()
		if !expires.After(time.Now().UTC()) {
			return Policy{}, errors.New("API key expiry must be in the future")
		}
		policy.ExpiresAt = &expires
	}
	policy.AllowedEndpoints = endpoints
	policy.AllowedModels = models
	return policy, nil
}

func normalizeEndpoints(values []string) ([]string, error) {
	if len(values) == 0 {
		return nil, errors.New("at least one API key endpoint is required")
	}
	if len(values) > maxPolicyItems {
		return nil, errors.New("too many API key endpoints")
	}
	result := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "models" {
			value = "/v1/models"
		} else if strings.HasPrefix(value, "v1/") {
			value = "/" + value
		}
		if len(value) == 0 || len(value) > maxPolicyValueSize || !strings.HasPrefix(value, "/v1/") || value == "/v1/" || strings.ContainsAny(value, "?#") || hasControl(value) {
			return nil, fmt.Errorf("API key endpoint %q is invalid", value)
		}
		for _, character := range value {
			if unicode.IsSpace(character) {
				return nil, fmt.Errorf("API key endpoint %q is invalid", value)
			}
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	sort.Strings(result)
	return result, nil
}

func normalizeModels(values []string) ([]string, error) {
	if len(values) > maxPolicyItems {
		return nil, errors.New("too many API key models")
	}
	result := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if len(value) == 0 || len(value) > maxPolicyValueSize || hasControl(value) {
			return nil, fmt.Errorf("API key model %q is invalid", value)
		}
		for _, character := range value {
			if unicode.IsSpace(character) {
				return nil, fmt.Errorf("API key model %q is invalid", value)
			}
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	sort.Strings(result)
	return result, nil
}

func normalizeValues(values []string, kind string) ([]string, error) {
	if len(values) > maxPolicyItems {
		return nil, fmt.Errorf("too many %s values", kind)
	}
	result := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" || len(value) > maxPolicyValueSize || hasControl(value) {
			return nil, fmt.Errorf("%s is invalid", kind)
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	sort.Strings(result)
	return result, nil
}

func hasControl(value string) bool {
	for _, character := range value {
		if unicode.IsControl(character) {
			return true
		}
	}
	return false
}

func generateRecord(hmacKey []byte, policy Policy) (string, Record, error) {
	if err := validateHMACKey(hmacKey); err != nil {
		return "", Record{}, err
	}
	publicBytes := make([]byte, publicPrefixRandomBytes)
	secretBytes := make([]byte, secretRandomBytes)
	if _, err := rand.Read(publicBytes); err != nil {
		return "", Record{}, fmt.Errorf("generate API key prefix: %w", err)
	}
	if _, err := rand.Read(secretBytes); err != nil {
		return "", Record{}, fmt.Errorf("generate API key secret: %w", err)
	}
	public := hex.EncodeToString(publicBytes)
	secret := hex.EncodeToString(secretBytes)
	rawKey := KeyPrefix + public + "_" + secret
	idBytes := make([]byte, recordIDRandomBytes)
	if _, err := rand.Read(idBytes); err != nil {
		return "", Record{}, fmt.Errorf("generate API key ID: %w", err)
	}
	id := hex.EncodeToString(idBytes)
	digest := digestKey(hmacKey, rawKey)
	record := Record{
		ID:               id,
		Name:             policy.Name,
		Owner:            policy.Owner,
		Prefix:           KeyPrefix + public,
		Digest:           append([]byte(nil), digest[:]...),
		AllowedEndpoints: StringList(append([]string(nil), policy.AllowedEndpoints...)),
		AllowedModels:    StringList(append([]string(nil), policy.AllowedModels...)),
		CreatedAt:        time.Now().UTC(),
		ExpiresAt:        policy.ExpiresAt,
	}
	return rawKey, record, nil
}

func digestKey(hmacKey []byte, rawKey string) [sha256.Size]byte {
	mac := hmac.New(sha256.New, hmacKey)
	mac.Write([]byte(rawKey))
	var digest [sha256.Size]byte
	copy(digest[:], mac.Sum(nil))
	return digest
}

func parseRawKey(rawKey string) (string, error) {
	if len(rawKey) == 0 || len(rawKey) > maxKeySize || !strings.HasPrefix(rawKey, KeyPrefix) {
		return "", ErrInvalidKey
	}
	rest := strings.TrimPrefix(rawKey, KeyPrefix)
	separator := strings.IndexByte(rest, '_')
	if separator < minPublicPrefixSize || separator > maxPublicPrefixSize || separator == len(rest)-1 {
		return "", ErrInvalidKey
	}
	public := rest[:separator]
	secret := rest[separator+1:]
	if len(secret) < minSecretSize || len(secret) > maxSecretSize || !tokenPart(public) || !tokenPart(secret) {
		return "", ErrInvalidKey
	}
	return KeyPrefix + public, nil
}

func tokenPart(value string) bool {
	if value == "" {
		return false
	}
	for _, character := range value {
		if (character < 'a' || character > 'z') && (character < 'A' || character > 'Z') && (character < '0' || character > '9') && character != '-' && character != '_' {
			return false
		}
	}
	return true
}

// ParseBearer accepts only one bounded, exact Bearer header value.
func ParseBearer(header string) (string, error) {
	if len(header) > MaxAuthorizationHeaderSize || !strings.HasPrefix(header, "Bearer ") {
		return "", ErrInvalidKey
	}
	rawKey := strings.TrimPrefix(header, "Bearer ")
	if strings.ContainsAny(rawKey, " \t\r\n") {
		return "", ErrInvalidKey
	}
	if _, err := parseRawKey(rawKey); err != nil {
		return "", err
	}
	return rawKey, nil
}
