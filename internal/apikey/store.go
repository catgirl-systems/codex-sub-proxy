package apikey

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"time"
	"unicode"

	"gorm.io/gorm"
)

// Migrate creates the durable API-key table and its prefix index.
func Migrate(db *gorm.DB) error {
	if db == nil {
		return fmt.Errorf("migrate API keys: %w", ErrUnavailable)
	}
	if err := db.AutoMigrate(&Record{}); err != nil {
		return fmt.Errorf("migrate API keys: %w", err)
	}
	return nil
}

// Create generates and stores one API key in one transaction.
func Create(ctx context.Context, db *gorm.DB, hmacKey []byte, policy Policy) (string, Record, error) {
	if ctx == nil {
		return "", Record{}, errors.New("API key context is nil")
	}
	if db == nil {
		return "", Record{}, fmt.Errorf("create API key: %w", ErrUnavailable)
	}
	if err := validateHMACKey(hmacKey); err != nil {
		return "", Record{}, err
	}
	validated, err := ValidatePolicy(policy)
	if err != nil {
		return "", Record{}, err
	}

	var rawKey string
	var record Record
	err = db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var buildErr error
		rawKey, record, buildErr = generateRecord(hmacKey, validated)
		if buildErr != nil {
			return buildErr
		}
		if err := tx.Create(&record).Error; err != nil {
			return fmt.Errorf("store API key: %w", err)
		}
		return nil
	})
	if err != nil {
		return "", Record{}, err
	}
	return rawKey, record, nil
}

// Principal contains only the policy and identity needed by request handlers.
type Principal struct {
	ID               string
	Prefix           string
	Name             string
	Owner            string
	AllowedEndpoints []string
	AllowedModels    []string
}

// Authorizer checks API keys against the configured SQLite store.
type Authorizer struct {
	db      *gorm.DB
	hmacKey []byte
}

func NewAuthorizer(db *gorm.DB, hmacKey []byte) *Authorizer {
	return &Authorizer{db: db, hmacKey: append([]byte(nil), hmacKey...)}
}

// AuthorizeHeader parses one exact Bearer value and checks endpoint and model policy.
func (a *Authorizer) AuthorizeHeader(ctx context.Context, header string, endpoint, model string) (Principal, error) {
	if a == nil {
		return Principal{}, fmt.Errorf("authorize API key: %w", ErrUnavailable)
	}
	rawKey, err := ParseBearer(header)
	if err != nil {
		return Principal{}, err
	}
	return a.Authorize(ctx, rawKey, endpoint, model)
}

// Authorize authenticates a key and checks endpoint and model policy.
func (a *Authorizer) Authorize(ctx context.Context, rawKey, endpoint, model string) (Principal, error) {
	principal, err := a.Authenticate(ctx, rawKey)
	if err != nil {
		return Principal{}, err
	}
	endpoint, err = normalizeEndpointForRequest(endpoint)
	if err != nil || !contains(principal.AllowedEndpoints, endpoint) {
		return Principal{}, ErrForbidden
	}
	if model != "" {
		if len(model) > maxPolicyValueSize || hasControl(model) {
			return Principal{}, ErrForbidden
		}
		for _, character := range model {
			if unicode.IsSpace(character) {
				return Principal{}, ErrForbidden
			}
		}
		if !contains(principal.AllowedModels, model) {
			return Principal{}, ErrForbidden
		}
	}
	return principal, nil
}

// Authenticate verifies the key without granting endpoint or model access.
func (a *Authorizer) Authenticate(ctx context.Context, rawKey string) (Principal, error) {
	if a == nil {
		return Principal{}, fmt.Errorf("authenticate API key: %w", ErrUnavailable)
	}
	if ctx == nil {
		return Principal{}, errors.New("API key context is nil")
	}
	if a.db == nil {
		return Principal{}, fmt.Errorf("authenticate API key: %w", ErrUnavailable)
	}
	if err := validateHMACKey(a.hmacKey); err != nil {
		return Principal{}, err
	}
	prefix, err := parseRawKey(rawKey)
	if err != nil {
		return Principal{}, err
	}

	var candidates []Record
	query := a.db.WithContext(ctx).Where("prefix = ?", prefix).Limit(maxPrefixCandidates + 1).Find(&candidates)
	if query.Error != nil {
		return Principal{}, fmt.Errorf("load API key candidates: %w", query.Error)
	}
	if len(candidates) > maxPrefixCandidates {
		return Principal{}, ErrInvalidKey
	}

	digest := digestKey(a.hmacKey, rawKey)
	matched := -1
	for index := range candidates {
		var stored [len(digest)]byte
		copy(stored[:], candidates[index].Digest)
		match := subtle.ConstantTimeCompare(digest[:], stored[:]) &
			subtle.ConstantTimeEq(int32(len(candidates[index].Digest)), int32(len(digest)))
		if match == 1 {
			matched = index
		}
	}
	if matched < 0 {
		return Principal{}, ErrInvalidKey
	}
	record := candidates[matched]
	now := time.Now().UTC()
	if record.DisabledAt != nil || (record.ExpiresAt != nil && !now.Before(record.ExpiresAt.UTC())) {
		return Principal{}, ErrInvalidKey
	}
	policy, err := record.Policy()
	if err != nil {
		return Principal{}, fmt.Errorf("read API key policy: %w", err)
	}
	return Principal{
		ID:               record.ID,
		Prefix:           record.Prefix,
		Name:             policy.Name,
		Owner:            policy.Owner,
		AllowedEndpoints: append([]string(nil), policy.AllowedEndpoints...),
		AllowedModels:    append([]string(nil), policy.AllowedModels...),
	}, nil
}

// Authenticate verifies a key against the given store.
func Authenticate(ctx context.Context, db *gorm.DB, hmacKey []byte, rawKey string) (Principal, error) {
	return NewAuthorizer(db, hmacKey).Authenticate(ctx, rawKey)
}

// Authorize checks a key, endpoint, and model against the given store.
func Authorize(ctx context.Context, db *gorm.DB, hmacKey []byte, rawKey, endpoint, model string) (Principal, error) {
	return NewAuthorizer(db, hmacKey).Authorize(ctx, rawKey, endpoint, model)
}

// AuthorizeHeader parses and checks one exact Bearer value.
func AuthorizeHeader(ctx context.Context, db *gorm.DB, hmacKey []byte, header, endpoint, model string) (Principal, error) {
	return NewAuthorizer(db, hmacKey).AuthorizeHeader(ctx, header, endpoint, model)
}

func normalizeEndpointForRequest(endpoint string) (string, error) {
	if endpoint == "models" {
		endpoint = "/v1/models"
	} else if len(endpoint) >= len("v1/") && endpoint[:len("v1/")] == "v1/" {
		endpoint = "/" + endpoint
	}
	if _, err := normalizeEndpoints([]string{endpoint}); err != nil {
		return "", err
	}
	return endpoint, nil
}

func contains(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}
