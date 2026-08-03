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
	"time"
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
	maxPrefixCandidates        = 16
)

var (
	ErrInvalidKey  = errors.New("invalid API key")
	ErrForbidden   = errors.New("API key permission denied")
	ErrUnavailable = errors.New("API key authentication is unavailable")
)

// StringList stores a JSON string list in one SQLite column.
type StringList []string

func (list StringList) Value() (driver.Value, error) {
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
	*list = StringList(decoded)
	return nil
}

// Policy controls the operations that one API key can access.
type Policy struct {
	Name             string   `validate:"required,max=255"`
	Owner            string   `validate:"required,max=255"`
	AllowedEndpoints []string `validate:"required,max=64,unique,dive,required,max=128"`
	AllowedModels    []string `validate:"max=64,unique,dive,required,max=128"`
	ExpiresAt        *time.Time

	// Zero disables a quota limit. A non-zero reservation default is used when
	// a request does not provide a more specific amount.
	MaxConcurrentRequests           int64         `validate:"gte=0"`
	RollingRequestCount             int64         `validate:"gte=0"`
	RollingRequestWindow            time.Duration `validate:"gte=0"`
	PeriodRequestLimit              int64         `validate:"gte=0"`
	PeriodTokenLimit                int64         `validate:"gte=0"`
	PeriodImageLimit                int64         `validate:"gte=0"`
	PeriodCostMicrounitLimit        int64         `validate:"gte=0"`
	PeriodDuration                  time.Duration `validate:"gte=0"`
	TokenReservationDefault         int64         `validate:"gte=0"`
	TokenReservationCeiling         int64         `validate:"gte=0"`
	ImageReservationDefault         int64         `validate:"gte=0"`
	ImageReservationCeiling         int64         `validate:"gte=0"`
	CostMicrounitReservationDefault int64         `validate:"gte=0"`
	CostMicrounitReservationCeiling int64         `validate:"gte=0"`
}

// Record is the durable, non-secret API key record.
type Record struct {
	ID                              string     `gorm:"column:id;primaryKey;size:32"`
	Name                            string     `gorm:"column:name;not null;size:255"`
	Owner                           string     `gorm:"column:owner;not null;size:255"`
	Prefix                          string     `gorm:"column:prefix;not null;size:64;uniqueIndex"`
	Digest                          []byte     `gorm:"column:digest;not null;size:32"`
	AllowedEndpoints                StringList `gorm:"column:allowed_endpoints;type:text;not null"`
	AllowedModels                   StringList `gorm:"column:allowed_models;type:text;not null"`
	CreatedAt                       time.Time  `gorm:"column:created_at;not null"`
	ExpiresAt                       *time.Time `gorm:"column:expires_at"`
	DisabledAt                      *time.Time `gorm:"column:disabled_at"`
	LastUsedAt                      *time.Time `gorm:"column:last_used_at"`
	MaxConcurrentRequests           int64      `gorm:"column:max_concurrent_requests;not null;default:0"`
	RollingRequestCount             int64      `gorm:"column:rolling_request_count;not null;default:0"`
	RollingRequestWindow            int64      `gorm:"column:rolling_request_window;not null;default:0"`
	PeriodRequestLimit              int64      `gorm:"column:period_request_limit;not null;default:0"`
	PeriodTokenLimit                int64      `gorm:"column:period_token_limit;not null;default:0"`
	PeriodImageLimit                int64      `gorm:"column:period_image_limit;not null;default:0"`
	PeriodCostMicrounitLimit        int64      `gorm:"column:period_cost_microunit_limit;not null;default:0"`
	PeriodDuration                  int64      `gorm:"column:period_duration;not null;default:0"`
	TokenReservationDefault         int64      `gorm:"column:token_reservation_default;not null;default:0"`
	TokenReservationCeiling         int64      `gorm:"column:token_reservation_ceiling;not null;default:0"`
	ImageReservationDefault         int64      `gorm:"column:image_reservation_default;not null;default:0"`
	ImageReservationCeiling         int64      `gorm:"column:image_reservation_ceiling;not null;default:0"`
	CostMicrounitReservationDefault int64      `gorm:"column:cost_microunit_reservation_default;not null;default:0"`
	CostMicrounitReservationCeiling int64      `gorm:"column:cost_microunit_reservation_ceiling;not null;default:0"`
}

func (Record) TableName() string {
	return "api_keys"
}

func (record Record) Policy() (Policy, error) {
	policy := Policy{
		Name:                            record.Name,
		Owner:                           record.Owner,
		AllowedEndpoints:                []string(record.AllowedEndpoints),
		AllowedModels:                   []string(record.AllowedModels),
		ExpiresAt:                       record.ExpiresAt,
		MaxConcurrentRequests:           record.MaxConcurrentRequests,
		RollingRequestCount:             record.RollingRequestCount,
		RollingRequestWindow:            time.Duration(record.RollingRequestWindow),
		PeriodRequestLimit:              record.PeriodRequestLimit,
		PeriodTokenLimit:                record.PeriodTokenLimit,
		PeriodImageLimit:                record.PeriodImageLimit,
		PeriodCostMicrounitLimit:        record.PeriodCostMicrounitLimit,
		PeriodDuration:                  time.Duration(record.PeriodDuration),
		TokenReservationDefault:         record.TokenReservationDefault,
		TokenReservationCeiling:         record.TokenReservationCeiling,
		ImageReservationDefault:         record.ImageReservationDefault,
		ImageReservationCeiling:         record.ImageReservationCeiling,
		CostMicrounitReservationDefault: record.CostMicrounitReservationDefault,
		CostMicrounitReservationCeiling: record.CostMicrounitReservationCeiling,
	}
	if err := validatePolicy(policy); err != nil {
		return Policy{}, fmt.Errorf("validate stored API key policy: %w", err)
	}
	return policy, nil
}

func generateRecord(hmacKey []byte, policy Policy) (string, Record, error) {
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
		ID:                              id,
		Name:                            policy.Name,
		Owner:                           policy.Owner,
		Prefix:                          KeyPrefix + public,
		Digest:                          append([]byte(nil), digest[:]...),
		AllowedEndpoints:                StringList(append([]string(nil), policy.AllowedEndpoints...)),
		AllowedModels:                   StringList(append([]string(nil), policy.AllowedModels...)),
		CreatedAt:                       time.Now().UTC(),
		ExpiresAt:                       policy.ExpiresAt,
		MaxConcurrentRequests:           policy.MaxConcurrentRequests,
		RollingRequestCount:             policy.RollingRequestCount,
		RollingRequestWindow:            int64(policy.RollingRequestWindow),
		PeriodRequestLimit:              policy.PeriodRequestLimit,
		PeriodTokenLimit:                policy.PeriodTokenLimit,
		PeriodImageLimit:                policy.PeriodImageLimit,
		PeriodCostMicrounitLimit:        policy.PeriodCostMicrounitLimit,
		PeriodDuration:                  int64(policy.PeriodDuration),
		TokenReservationDefault:         policy.TokenReservationDefault,
		TokenReservationCeiling:         policy.TokenReservationCeiling,
		ImageReservationDefault:         policy.ImageReservationDefault,
		ImageReservationCeiling:         policy.ImageReservationCeiling,
		CostMicrounitReservationDefault: policy.CostMicrounitReservationDefault,
		CostMicrounitReservationCeiling: policy.CostMicrounitReservationCeiling,
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
