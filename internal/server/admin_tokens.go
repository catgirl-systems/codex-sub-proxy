package server

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql/driver"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/go-playground/validator/v10"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

const (
	AdminTokenPrefix          = "csp_admin_"
	adminTokenPrefixBytes     = 8
	adminTokenSecretBytes     = 32
	adminTokenIDBytes         = 16
	maxAdminTokenSize         = len(AdminTokenPrefix) + adminTokenPrefixBytes*2 + 1 + adminTokenSecretBytes*2
	maxAdminTokenNameBytes    = 128
	maxAdminPrefixCandidates  = 16
	maxAdminListLimit         = 100
	maxAdminListOffset        = 1000
	maxAdminAuditMetadataSize = 4096
	adminAuditTTL             = 7 * 24 * time.Hour
	maxAdminTokenLifetime     = 365 * 24 * time.Hour
)

var (
	ErrAdminTokenInvalid   = errors.New("invalid admin token")
	ErrAdminTokenForbidden = errors.New("admin token permission denied")
	ErrAdminUnavailable    = errors.New("admin token authentication is unavailable")
	ErrAdminTokenNotFound  = errors.New("admin token not found")
	ErrAdminTokenRequest   = errors.New("invalid admin token request")
	ErrAdminTokenNameTaken = errors.New("admin token name is already in use")
)

// AdminTokenScope is one permission that an admin token can carry.
type AdminTokenScope string

const (
	AdminScopeMetadata AdminTokenScope = "metadata"
	AdminScopeContent  AdminTokenScope = "content"
)

// AdminTokenScopes stores the canonical scope set used by an admin token.
type AdminTokenScopes []AdminTokenScope

func (scopes AdminTokenScopes) Value() (driver.Value, error) {
	canonical, err := canonicalAdminScopes(scopes)
	if err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(canonical)
	if err != nil {
		return nil, fmt.Errorf("encode admin token scopes: %w", err)
	}
	return encoded, nil
}

func (scopes *AdminTokenScopes) Scan(value any) error {
	if scopes == nil {
		return errors.New("admin token scopes destination is nil")
	}
	if value == nil {
		return errors.New("admin token scopes are missing")
	}
	var encoded []byte
	switch value := value.(type) {
	case []byte:
		encoded = value
	case string:
		encoded = []byte(value)
	default:
		return fmt.Errorf("scan admin token scopes from %T", value)
	}
	if len(encoded) == 0 {
		return errors.New("admin token scopes are empty")
	}
	var decoded []AdminTokenScope
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		return fmt.Errorf("decode admin token scopes: %w", err)
	}
	canonical, err := canonicalAdminScopes(decoded)
	if err != nil {
		return err
	}
	*scopes = canonical
	return nil
}

func canonicalAdminScopes(scopes AdminTokenScopes) (AdminTokenScopes, error) {
	var metadata, content bool
	for _, scope := range scopes {
		switch scope {
		case AdminScopeMetadata:
			if metadata {
				return nil, errors.New("admin token scopes contain a duplicate")
			}
			metadata = true
		case AdminScopeContent:
			if content {
				return nil, errors.New("admin token scopes contain a duplicate")
			}
			content = true
		default:
			return nil, fmt.Errorf("unknown admin token scope %q", scope)
		}
	}
	if !metadata && !content {
		return nil, errors.New("admin token scopes are empty")
	}
	canonical := make(AdminTokenScopes, 0, 2)
	if metadata {
		canonical = append(canonical, AdminScopeMetadata)
	}
	if content {
		canonical = append(canonical, AdminScopeContent)
	}
	return canonical, nil
}

func (scopes AdminTokenScopes) Has(scope AdminTokenScope) bool {
	for _, value := range scopes {
		if value == scope {
			return true
		}
	}
	return false
}

// AdminToken is the durable, non-secret admin token record.
type AdminToken struct {
	ID         string           `gorm:"column:id;primaryKey;size:36"`
	Name       string           `gorm:"column:name;not null;size:128;uniqueIndex"`
	Prefix     string           `gorm:"column:prefix;not null;size:32;uniqueIndex"`
	Digest     []byte           `gorm:"column:digest;not null;size:32"`
	Scopes     AdminTokenScopes `gorm:"column:scopes;type:text;not null"`
	CreatedAt  time.Time        `gorm:"column:created_at;not null;index"`
	ExpiresAt  *time.Time       `gorm:"column:expires_at;index"`
	RevokedAt  *time.Time       `gorm:"column:revoked_at;index"`
	LastUsedAt *time.Time       `gorm:"column:last_used_at;index"`
	CreatedBy  string           `gorm:"column:created_by;not null;size:36"`
	RevokedBy  string           `gorm:"column:revoked_by;size:36"`
	Bootstrap  bool             `gorm:"column:bootstrap;not null;default:false;index"`
}

func (AdminToken) TableName() string { return "admin_tokens" }

// AdminPrincipal identifies the token that authorized one admin request.
type AdminPrincipal struct {
	ID        string
	Name      string
	Scopes    AdminTokenScopes
	Bootstrap bool
}

func (principal AdminPrincipal) HasScope(scope AdminTokenScope) bool {
	return principal.Scopes.Has(scope)
}

// AdminTokenCreateRequest describes one named token to create.
type AdminTokenCreateRequest struct {
	Name      string           `validate:"required,max=128"`
	Scopes    AdminTokenScopes `validate:"required,min=1,max=2"`
	ExpiresAt *time.Time
}

var adminTokenValidator = validator.New()

// AdminTokenStore authenticates and mutates admin token records.
type AdminTokenStore struct {
	db           *gorm.DB
	hmacKey      []byte
	now          func() time.Time
	cookieSecure bool
}

func NewAdminTokenStore(db *gorm.DB, hmacKey []byte) *AdminTokenStore {
	return &AdminTokenStore{db: db, hmacKey: append([]byte(nil), hmacKey...), now: func() time.Time { return time.Now().UTC() }, cookieSecure: true}
}

func newAdminTokenStoreWithClock(db *gorm.DB, hmacKey []byte, now func() time.Time) *AdminTokenStore {
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	return &AdminTokenStore{db: db, hmacKey: append([]byte(nil), hmacKey...), now: now, cookieSecure: true}
}

func (s *AdminTokenStore) setCookieSecure(secure bool) {
	if s != nil {
		s.cookieSecure = secure
	}
}

// MigrateAdminTokens creates admin token, session, nonce, and audit tables.
func MigrateAdminTokens(db *gorm.DB) error {
	if db == nil {
		return fmt.Errorf("migrate admin tokens: %w", ErrAdminUnavailable)
	}
	if err := db.AutoMigrate(&AdminToken{}, &AdminSession{}, &AdminLoginNonce{}, &AuditRecord{}); err != nil {
		return fmt.Errorf("migrate admin tokens: %w", err)
	}
	return nil
}

func (s *AdminTokenStore) configuredForAuth() error {
	if s == nil || s.db == nil || len(s.hmacKey) == 0 {
		return ErrAdminUnavailable
	}
	return nil
}

func (s *AdminTokenStore) availableForAuth(ctx context.Context) error {
	if ctx == nil {
		return errors.New("admin token context is nil")
	}
	if err := s.configuredForAuth(); err != nil {
		return err
	}
	var count int64
	if err := s.silentDB().WithContext(ctx).Model(&AdminToken{}).
		Where("revoked_at IS NULL AND (expires_at IS NULL OR expires_at > ?)", s.currentTime()).
		Count(&count).Error; err != nil || count == 0 {
		return ErrAdminUnavailable
	}
	return nil
}

// Available reports whether the admin plane has a usable HMAC key and a stored token.
func (s *AdminTokenStore) Available(ctx context.Context) bool {
	if ctx == nil {
		return false
	}
	if err := s.configuredForAuth(); err != nil {
		return false
	}
	var count int64
	if err := s.silentDB().WithContext(ctx).Model(&AdminToken{}).
		Where("revoked_at IS NULL AND (expires_at IS NULL OR expires_at > ?)", s.currentTime()).
		Count(&count).Error; err != nil {
		return false
	}
	return count > 0
}

// MaterializeBootstrap stores the dedicated bootstrap token only on first use.
func (s *AdminTokenStore) MaterializeBootstrap(ctx context.Context, raw []byte) (bool, error) {
	if ctx == nil {
		return false, errors.New("admin bootstrap context is nil")
	}
	if len(raw) == 0 {
		return false, nil
	}
	if err := s.configuredForAuth(); err != nil {
		return false, err
	}
	parsed, err := parseAdminToken(raw)
	if err != nil {
		return false, err
	}
	createdAt := s.currentTime()
	digest := adminTokenDigest(s.hmacKey, raw)
	scopes := AdminTokenScopes{AdminScopeMetadata, AdminScopeContent}
	scopesValue, err := scopes.Value()
	if err != nil {
		return false, err
	}
	id, err := randomAdminTokenID()
	if err != nil {
		return false, err
	}
	record := AdminToken{
		ID:        id,
		Name:      "bootstrap",
		Prefix:    parsed.Prefix,
		Digest:    append([]byte(nil), digest[:]...),
		Scopes:    scopes,
		CreatedAt: createdAt,
		CreatedBy: "bootstrap",
		Bootstrap: true,
	}
	materialized := false
	err = s.silentDB().WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		result := tx.Exec(`
INSERT INTO admin_tokens
    (id, name, prefix, digest, scopes, created_at, created_by, bootstrap)
SELECT ?, ?, ?, ?, ?, ?, ?, ?
WHERE NOT EXISTS (SELECT 1 FROM admin_tokens)`,
			record.ID, record.Name, record.Prefix, record.Digest, scopesValue, record.CreatedAt, record.CreatedBy, record.Bootstrap)
		if result.Error != nil {
			return fmt.Errorf("materialize bootstrap token: %w", result.Error)
		}
		if result.RowsAffected == 0 {
			return nil
		}
		materialized = true
		return writeAdminAudit(tx, AdminPrincipal{ID: "bootstrap", Name: "bootstrap", Scopes: scopes, Bootstrap: true}, "admin_token.bootstrap", record.ID, adminAuditMetadata{Bootstrap: true}, createdAt)
	})
	if err != nil {
		return false, err
	}
	return materialized, nil
}

// Create generates and stores a token and its audit record in one transaction.
func (s *AdminTokenStore) Create(ctx context.Context, request AdminTokenCreateRequest, actor AdminPrincipal) (string, AdminToken, error) {
	if ctx == nil {
		return "", AdminToken{}, errors.New("admin token context is nil")
	}
	if err := s.availableForAuth(ctx); err != nil {
		return "", AdminToken{}, err
	}
	if err := validateAdminTokenCreateRequest(request, s.currentTime()); err != nil {
		return "", AdminToken{}, err
	}
	canonical, err := canonicalAdminScopes(request.Scopes)
	if err != nil {
		return "", AdminToken{}, fmt.Errorf("%w: scope", ErrAdminTokenRequest)
	}
	request.Scopes = canonical
	if request.ExpiresAt != nil {
		expiresAt := request.ExpiresAt.UTC()
		request.ExpiresAt = &expiresAt
	}
	if !actor.HasScope(AdminScopeMetadata) || strings.TrimSpace(actor.ID) == "" || strings.TrimSpace(actor.Name) == "" {
		return "", AdminToken{}, ErrAdminTokenForbidden
	}
	createdAt := s.currentTime()
	raw, record, err := generateAdminToken(s.hmacKey, request, actor, createdAt)
	if err != nil {
		return "", AdminToken{}, err
	}
	err = s.silentDB().WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var existing AdminToken
		if err := tx.Select("id").Where("name = ?", record.Name).First(&existing).Error; err == nil {
			return ErrAdminTokenNameTaken
		} else if !errors.Is(err, gorm.ErrRecordNotFound) {
			return fmt.Errorf("check admin token name: %w", err)
		}
		if err := tx.Create(&record).Error; err != nil {
			return fmt.Errorf("store admin token: %w", err)
		}
		metadata := adminAuditMetadata{Name: record.Name, Scopes: record.Scopes, ExpiresAt: record.ExpiresAt}
		return writeAdminAudit(tx, actor, "admin_token.create", record.ID, metadata, record.CreatedAt)
	})
	if err != nil {
		return "", AdminToken{}, err
	}
	return raw, record, nil
}

// List returns bounded safe token metadata. It never selects the digest.
func (s *AdminTokenStore) List(ctx context.Context, limit, offset int) ([]AdminToken, error) {
	if ctx == nil {
		return nil, errors.New("admin token context is nil")
	}
	if err := s.availableForAuth(ctx); err != nil {
		return nil, err
	}
	if limit <= 0 || limit > maxAdminListLimit || offset < 0 || offset > maxAdminListOffset {
		return nil, errors.New("admin token list bounds are invalid")
	}
	var records []AdminToken
	query := s.silentDB().WithContext(ctx).Select("id", "name", "prefix", "scopes", "created_at", "expires_at", "revoked_at", "last_used_at", "created_by", "revoked_by", "bootstrap").
		Order("created_at DESC, id DESC").Limit(limit).Offset(offset).Find(&records)
	if query.Error != nil {
		return nil, fmt.Errorf("list admin tokens: %w", query.Error)
	}
	return records, nil
}

// RecordListAudit appends the audit fact for a successful metadata list.
func (s *AdminTokenStore) RecordListAudit(ctx context.Context, actor AdminPrincipal, count int) error {
	if ctx == nil {
		return errors.New("admin audit context is nil")
	}
	if err := s.availableForAuth(ctx); err != nil {
		return err
	}
	if !actor.HasScope(AdminScopeMetadata) {
		return ErrAdminTokenForbidden
	}
	if count < 0 || count > maxAdminListLimit {
		return errors.New("admin audit count is invalid")
	}
	return s.silentDB().WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		return writeAdminAudit(tx, actor, "admin_token.list", "admin_tokens", adminAuditMetadata{Count: count}, s.currentTime())
	})
}

// Revoke marks a token revoked. Repeating the operation is idempotent.
func (s *AdminTokenStore) Revoke(ctx context.Context, id string, actor AdminPrincipal) (AdminToken, error) {
	if ctx == nil {
		return AdminToken{}, errors.New("admin token context is nil")
	}
	if err := s.availableForAuth(ctx); err != nil {
		return AdminToken{}, err
	}
	if !actor.HasScope(AdminScopeMetadata) || strings.TrimSpace(actor.ID) == "" || strings.TrimSpace(actor.Name) == "" {
		return AdminToken{}, ErrAdminTokenForbidden
	}
	if !validAdminTokenID(id) {
		return AdminToken{}, ErrAdminTokenNotFound
	}
	var record AdminToken
	err := s.silentDB().WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("id = ?", id).First(&record).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrAdminTokenNotFound
			}
			return fmt.Errorf("load admin token for revoke: %w", err)
		}
		if record.RevokedAt == nil {
			revokedAt := s.currentTime()
			result := tx.Model(&AdminToken{}).Where("id = ? AND revoked_at IS NULL", id).Updates(map[string]any{
				"revoked_at": revokedAt,
				"revoked_by": actor.ID,
			})
			if result.Error != nil {
				return fmt.Errorf("revoke admin token: %w", result.Error)
			}
			if result.RowsAffected == 1 {
				record.RevokedAt = &revokedAt
				record.RevokedBy = actor.ID
			}
		}
		return writeAdminAudit(tx, actor, "admin_token.revoke", record.ID, adminAuditMetadata{Name: record.Name}, s.currentTime())
	})
	if err != nil {
		return AdminToken{}, err
	}
	return record, nil
}

// AuthenticateHeaders rejects missing and duplicate authorization headers.
func (s *AdminTokenStore) AuthenticateHeaders(ctx context.Context, headers []string) (AdminPrincipal, error) {
	if err := s.availableForAuth(ctx); err != nil {
		return AdminPrincipal{}, err
	}
	if len(headers) != 1 {
		return AdminPrincipal{}, ErrAdminTokenInvalid
	}
	return s.AuthenticateHeader(ctx, headers[0])
}

// AuthenticateHeader parses and verifies one exact Bearer token.
func (s *AdminTokenStore) AuthenticateHeader(ctx context.Context, header string) (AdminPrincipal, error) {
	if err := s.availableForAuth(ctx); err != nil {
		return AdminPrincipal{}, err
	}
	if len(header) > maxAdminTokenSize+len("Bearer ") || !strings.HasPrefix(header, "Bearer ") {
		return AdminPrincipal{}, ErrAdminTokenInvalid
	}
	return s.Authenticate(ctx, []byte(header[len("Bearer "):]))
}

// Authenticate verifies a token without granting a scope.
func (s *AdminTokenStore) Authenticate(ctx context.Context, raw []byte) (AdminPrincipal, error) {
	if ctx == nil {
		return AdminPrincipal{}, errors.New("admin token context is nil")
	}
	if err := s.availableForAuth(ctx); err != nil {
		return AdminPrincipal{}, err
	}
	parsed, err := parseAdminToken(raw)
	if err != nil {
		return AdminPrincipal{}, err
	}
	var candidates []AdminToken
	query := s.silentDB().WithContext(ctx).Where("prefix = ?", parsed.Prefix).Limit(maxAdminPrefixCandidates + 1).Find(&candidates)
	if query.Error != nil {
		return AdminPrincipal{}, fmt.Errorf("load admin token candidates: %w", query.Error)
	}
	if len(candidates) > maxAdminPrefixCandidates {
		return AdminPrincipal{}, ErrAdminTokenInvalid
	}
	digest := adminTokenDigest(s.hmacKey, raw)
	matched := -1
	for index := range candidates {
		var stored [sha256.Size]byte
		copy(stored[:], candidates[index].Digest)
		match := subtle.ConstantTimeCompare(digest[:], stored[:]) & subtle.ConstantTimeEq(int32(len(candidates[index].Digest)), sha256.Size)
		if match == 1 {
			matched = index
		}
	}
	if matched < 0 {
		return AdminPrincipal{}, ErrAdminTokenInvalid
	}
	record := candidates[matched]
	now := s.currentTime()
	if record.RevokedAt != nil || (record.ExpiresAt != nil && !now.Before(record.ExpiresAt.UTC())) {
		return AdminPrincipal{}, ErrAdminTokenInvalid
	}
	return AdminPrincipal{ID: record.ID, Name: record.Name, Scopes: append(AdminTokenScopes(nil), record.Scopes...), Bootstrap: record.Bootstrap}, nil
}

// Authorize applies one scope and updates last-use time only after that check.
func (s *AdminTokenStore) Authorize(ctx context.Context, principal AdminPrincipal, required AdminTokenScope) error {
	if ctx == nil {
		return errors.New("admin token context is nil")
	}
	if err := s.availableForAuth(ctx); err != nil {
		return err
	}
	if required != AdminScopeMetadata && required != AdminScopeContent {
		return ErrAdminTokenForbidden
	}
	if !principal.HasScope(required) {
		return ErrAdminTokenForbidden
	}
	now := s.currentTime()
	result := s.silentDB().WithContext(ctx).Model(&AdminToken{}).
		Where("id = ? AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at > ?)", principal.ID, now).
		UpdateColumn("last_used_at", gorm.Expr("CASE WHEN last_used_at IS NULL OR last_used_at < ? THEN ? ELSE last_used_at END", now, now))
	if result.Error != nil {
		return fmt.Errorf("update admin token last used time: %w", result.Error)
	}
	if result.RowsAffected != 1 {
		return ErrAdminTokenInvalid
	}
	return nil

}
func (s *AdminTokenStore) currentTime() time.Time {
	if s == nil || s.now == nil {
		return time.Now().UTC()
	}
	return s.now().UTC()
}
func (s *AdminTokenStore) silentDB() *gorm.DB {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Session(&gorm.Session{Logger: logger.Discard})
}

type parsedAdminToken struct {
	Prefix string
}

func parseAdminToken(raw []byte) (parsedAdminToken, error) {
	if len(raw) != maxAdminTokenSize || !strings.HasPrefix(string(raw), AdminTokenPrefix) {
		return parsedAdminToken{}, ErrAdminTokenInvalid
	}
	rest := raw[len(AdminTokenPrefix):]
	separator := strings.IndexByte(string(rest), '_')
	if separator != adminTokenPrefixBytes*2 || separator == len(rest)-1 {
		return parsedAdminToken{}, ErrAdminTokenInvalid
	}
	if strings.IndexByte(string(rest[separator+1:]), '_') >= 0 {
		return parsedAdminToken{}, ErrAdminTokenInvalid
	}
	prefixHex := rest[:separator]
	secretHex := rest[separator+1:]
	prefixBytes, err := hex.DecodeString(string(prefixHex))
	if err != nil || len(prefixBytes) != adminTokenPrefixBytes {
		return parsedAdminToken{}, ErrAdminTokenInvalid
	}
	secretBytes, err := hex.DecodeString(string(secretHex))
	if err != nil || len(secretBytes) != adminTokenSecretBytes {
		return parsedAdminToken{}, ErrAdminTokenInvalid
	}
	return parsedAdminToken{Prefix: AdminTokenPrefix + string(prefixHex)}, nil
}

func generateAdminToken(hmacKey []byte, request AdminTokenCreateRequest, actor AdminPrincipal, createdAt time.Time) (string, AdminToken, error) {
	prefixBytes := make([]byte, adminTokenPrefixBytes)
	secretBytes := make([]byte, adminTokenSecretBytes)
	if _, err := rand.Read(prefixBytes); err != nil {
		return "", AdminToken{}, fmt.Errorf("generate admin token prefix: %w", err)
	}
	if _, err := rand.Read(secretBytes); err != nil {
		return "", AdminToken{}, fmt.Errorf("generate admin token secret: %w", err)
	}
	id, err := randomAdminTokenID()
	if err != nil {
		return "", AdminToken{}, err
	}
	prefix := AdminTokenPrefix + hex.EncodeToString(prefixBytes)
	raw := prefix + "_" + hex.EncodeToString(secretBytes)
	digest := adminTokenDigest(hmacKey, []byte(raw))
	return raw, AdminToken{
		ID:        id,
		Name:      request.Name,
		Prefix:    prefix,
		Digest:    append([]byte(nil), digest[:]...),
		Scopes:    append(AdminTokenScopes(nil), request.Scopes...),
		CreatedAt: createdAt,
		ExpiresAt: request.ExpiresAt,
		CreatedBy: actor.ID,
	}, nil
}

func randomAdminTokenID() (string, error) {
	idBytes := make([]byte, adminTokenIDBytes)
	if _, err := rand.Read(idBytes); err != nil {
		return "", fmt.Errorf("generate admin token ID: %w", err)
	}
	idBytes[6] = (idBytes[6] & 0x0f) | 0x40
	idBytes[8] = (idBytes[8] & 0x3f) | 0x80
	encoded := hex.EncodeToString(idBytes)
	return encoded[:8] + "-" + encoded[8:12] + "-" + encoded[12:16] + "-" + encoded[16:20] + "-" + encoded[20:], nil
}

func adminTokenDigest(hmacKey, raw []byte) [sha256.Size]byte {
	mac := hmac.New(sha256.New, hmacKey)
	_, _ = mac.Write(raw)
	var digest [sha256.Size]byte
	copy(digest[:], mac.Sum(nil))
	return digest
}

func validateAdminTokenCreateRequest(request AdminTokenCreateRequest, now time.Time) error {
	if err := adminTokenValidator.Struct(request); err != nil {
		return ErrAdminTokenRequest
	}
	if request.Name == "" || len(request.Name) > maxAdminTokenNameBytes {
		return fmt.Errorf("%w: name", ErrAdminTokenRequest)
	}
	canonical, err := canonicalAdminScopes(request.Scopes)
	if err != nil {
		return fmt.Errorf("%w: scope", ErrAdminTokenRequest)
	}
	request.Scopes = canonical
	if request.ExpiresAt != nil {
		expiresAt := request.ExpiresAt.UTC()
		if !expiresAt.After(now) || expiresAt.After(now.Add(maxAdminTokenLifetime)) {
			return fmt.Errorf("%w: expiry", ErrAdminTokenRequest)
		}
	}
	return nil
}

func validAdminTokenID(id string) bool {
	if len(id) != 36 || id[8] != '-' || id[13] != '-' || id[18] != '-' || id[23] != '-' {
		return false
	}
	for index, character := range id {
		if index == 8 || index == 13 || index == 18 || index == 23 {
			continue
		}
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') && (character < 'A' || character > 'F') {
			return false
		}
	}
	return true
}

type adminAuditMetadata struct {
	Name      string           `json:"name,omitempty"`
	Scopes    AdminTokenScopes `json:"scopes,omitempty"`
	ExpiresAt *time.Time       `json:"expires_at,omitempty"`
	Count     int              `json:"count,omitempty"`
	Bootstrap bool             `json:"bootstrap,omitempty"`
	Fields    []string         `json:"fields,omitempty"`
	Filters   []string         `json:"filters,omitempty"`
}

func writeAdminAudit(tx *gorm.DB, principal AdminPrincipal, action, targetID string, metadata adminAuditMetadata, createdAt time.Time) error {
	if tx == nil {
		return errors.New("admin audit transaction is nil")
	}
	if strings.TrimSpace(principal.ID) == "" || strings.TrimSpace(principal.Name) == "" {
		return errors.New("admin audit principal is missing")
	}
	if action == "" || targetID == "" {
		return errors.New("admin audit action or target is missing")
	}
	encoded, err := json.Marshal(metadata)
	if err != nil {
		return fmt.Errorf("encode admin audit metadata: %w", err)
	}
	if len(encoded) > maxAdminAuditMetadataSize {
		return errors.New("admin audit metadata is too large")
	}
	auditID, err := randomAdminTokenID()
	if err != nil {
		return err
	}
	record := AuditRecord{
		ID:            auditID,
		EventType:     action,
		Status:        200,
		CreatedAt:     createdAt,
		ExpiresAt:     createdAt.Add(adminAuditTTL),
		PrincipalID:   principal.ID,
		PrincipalName: principal.Name,
		Action:        action,
		TargetID:      targetID,
		Metadata:      string(encoded),
	}
	if err := tx.Create(&record).Error; err != nil {
		return fmt.Errorf("store admin audit: %w", err)
	}
	return nil
}
