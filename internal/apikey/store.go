package apikey

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"strings"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// Store owns durable API-key records and their HMAC generator.
// Its transaction methods are intentionally concrete so callers can include
// related lifecycle writes, such as administrative audit records, in one tx.
type Store struct {
	db      *gorm.DB
	hmacKey []byte
	now     func() time.Time
}

// NewStore creates an API-key store backed by db.
func NewStore(db *gorm.DB, hmacKey []byte) *Store {
	return &Store{
		db:      db,
		hmacKey: append([]byte(nil), hmacKey...),
		now:     func() time.Time { return time.Now().UTC() },
	}
}

// DB returns the store database for an enclosing transaction.
func (s *Store) DB() *gorm.DB {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Session(&gorm.Session{Logger: logger.Discard})
}

// Transaction runs fn in a bounded store transaction.
func (s *Store) Transaction(ctx context.Context, fn func(*gorm.DB) error) error {
	if s == nil || s.db == nil {
		return fmt.Errorf("API key transaction: %w", ErrUnavailable)
	}
	if ctx == nil {
		return errors.New("API key transaction context is nil")
	}
	if fn == nil {
		return errors.New("API key transaction function is nil")
	}
	return s.DB().WithContext(ctx).Transaction(fn)
}

// CreateTx generates and inserts a key. The caller owns transaction scope.
func (s *Store) CreateTx(tx *gorm.DB, policy Policy) (string, Record, error) {
	if s == nil || len(s.hmacKey) == 0 {
		return "", Record{}, fmt.Errorf("create API key: %w", ErrUnavailable)
	}
	if tx == nil {
		return "", Record{}, errors.New("create API key transaction is nil")
	}
	if err := validatePolicy(policy); err != nil {
		return "", Record{}, err
	}
	if policy.ExpiresAt != nil && !policy.ExpiresAt.After(s.currentTime()) {
		return "", Record{}, errors.New("API key expiry must be in the future")
	}
	rawKey, record, err := generateRecord(s.hmacKey, policy)
	if err != nil {
		return "", Record{}, err
	}
	if err := tx.Create(&record).Error; err != nil {
		return "", Record{}, fmt.Errorf("store API key: %w", err)
	}
	return rawKey, record, nil
}

func (s *Store) currentTime() time.Time {
	if s == nil || s.now == nil {
		return time.Now().UTC()
	}
	return s.now().UTC()
}

// Migrate creates the durable API-key and quota tables and their indexes.
func Migrate(db *gorm.DB) error {
	if db == nil {
		return fmt.Errorf("migrate API keys: %w", ErrUnavailable)
	}
	if err := db.AutoMigrate(&Record{}); err != nil {
		return fmt.Errorf("migrate API keys: %w", err)
	}
	if err := MigrateQuota(db); err != nil {
		return err
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
	if err := validatePolicy(policy); err != nil {
		return "", Record{}, err
	}
	if policy.ExpiresAt != nil && !policy.ExpiresAt.After(time.Now().UTC()) {
		return "", Record{}, errors.New("API key expiry must be in the future")
	}

	var rawKey string
	var record Record
	err := db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var buildErr error
		rawKey, record, buildErr = generateRecord(hmacKey, policy)
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

// Principal contains the identity and current policy needed by request handlers.
type Principal struct {
	ID               string
	Prefix           string
	Name             string
	Owner            string
	AllowedEndpoints []string
	AllowedModels    []string
	Policy           Policy
}

// Authorizer checks API keys against the configured SQLite store.
type Authorizer struct {
	db      *gorm.DB
	hmacKey []byte
}

func NewAuthorizer(db *gorm.DB, hmacKey []byte) *Authorizer {
	return &Authorizer{db: db, hmacKey: append([]byte(nil), hmacKey...)}
}

// AuthenticateHeader parses one exact Bearer value without granting policy access.
func (a *Authorizer) AuthenticateHeader(ctx context.Context, header string) (Principal, error) {
	if a == nil {
		return Principal{}, fmt.Errorf("authenticate API key header: %w", ErrUnavailable)
	}
	if len(header) > MaxAuthorizationHeaderSize || !strings.HasPrefix(header, "Bearer ") {
		return Principal{}, ErrInvalidKey
	}
	rawKey := header[len("Bearer "):]
	if strings.ContainsAny(rawKey, " \t\r\n") {
		return Principal{}, ErrInvalidKey
	}
	return a.Authenticate(ctx, rawKey)
}

// AuthorizePrincipal applies endpoint and model policy and records successful use.
func (a *Authorizer) AuthorizePrincipal(ctx context.Context, principal Principal, endpoint, model string) error {
	if a == nil {
		return fmt.Errorf("authorize API key principal: %w", ErrUnavailable)
	}
	if ctx == nil {
		return errors.New("API key context is nil")
	}
	if a.db == nil {
		return fmt.Errorf("authorize API key principal: %w", ErrUnavailable)
	}
	if !contains(principal.AllowedEndpoints, endpoint) {
		return ErrForbidden
	}
	if model != "" && !contains(principal.AllowedModels, model) {
		return ErrForbidden
	}
	now := time.Now().UTC()
	result := a.db.WithContext(ctx).Model(&Record{}).
		Where("id = ? AND revoked_at IS NULL AND disabled_at IS NULL AND (expires_at IS NULL OR expires_at > ?)", principal.ID, now).
		UpdateColumn("last_used_at", gorm.Expr(
			"CASE WHEN last_used_at IS NULL OR last_used_at < ? THEN ? ELSE last_used_at END",
			now,
			now,
		))
	if result.Error != nil {
		return fmt.Errorf("update API key last used time: %w", result.Error)
	}
	if result.RowsAffected != 1 {
		return ErrInvalidKey
	}
	return nil
}

// AuthorizeHeader authenticates a Bearer value and applies endpoint/model policy.
func (a *Authorizer) AuthorizeHeader(ctx context.Context, header string, endpoint, model string) (Principal, error) {
	principal, err := a.AuthenticateHeader(ctx, header)
	if err != nil {
		return Principal{}, err
	}
	if err := a.AuthorizePrincipal(ctx, principal, endpoint, model); err != nil {
		return Principal{}, err
	}
	return principal, nil
}

// Authorize authenticates a key and applies endpoint/model policy.
func (a *Authorizer) Authorize(ctx context.Context, rawKey, endpoint, model string) (Principal, error) {
	principal, err := a.Authenticate(ctx, rawKey)
	if err != nil {
		return Principal{}, err
	}
	if err := a.AuthorizePrincipal(ctx, principal, endpoint, model); err != nil {
		return Principal{}, err
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
	if len(rawKey) == 0 || len(rawKey) > maxKeySize || !strings.HasPrefix(rawKey, KeyPrefix) {
		return Principal{}, ErrInvalidKey
	}
	rest := rawKey[len(KeyPrefix):]
	separator := strings.IndexByte(rest, '_')
	if separator < minPublicPrefixSize || separator > maxPublicPrefixSize || separator == len(rest)-1 {
		return Principal{}, ErrInvalidKey
	}
	public := rest[:separator]
	secret := rest[separator+1:]
	if len(secret) < minSecretSize || len(secret) > maxSecretSize {
		return Principal{}, ErrInvalidKey
	}
	for index := range public {
		character := public[index]
		if (character < 'a' || character > 'z') &&
			(character < 'A' || character > 'Z') &&
			(character < '0' || character > '9') &&
			character != '-' && character != '_' {
			return Principal{}, ErrInvalidKey
		}
	}
	for index := range secret {
		character := secret[index]
		if (character < 'a' || character > 'z') &&
			(character < 'A' || character > 'Z') &&
			(character < '0' || character > '9') &&
			character != '-' && character != '_' {
			return Principal{}, ErrInvalidKey
		}
	}
	prefix := KeyPrefix + public

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
	if record.RevokedAt != nil || record.DisabledAt != nil || (record.ExpiresAt != nil && !now.Before(record.ExpiresAt.UTC())) {
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
		Policy:           policy,
	}, nil
}

func contains(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}
