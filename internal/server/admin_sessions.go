package server

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"gorm.io/gorm"
)

const (
	adminSessionCookieName        = "__Host-csp_admin_session"
	adminLoginNonceCookieName     = "__Host-csp_admin_login_nonce"
	adminSessionCookiePrefix      = "csp_admin_session_"
	adminLoginNoncePrefix         = "csp_admin_nonce_"
	adminSessionIDBytes           = 32
	adminSessionPrefixBytes       = 8
	adminSessionTTL               = 8 * time.Hour
	adminSessionIdleTTL           = 30 * time.Minute
	adminLoginNonceTTL            = 10 * time.Minute
	adminSessionMaxCandidates     = 16
	adminLoginNonceMaxCandidates  = 16
	adminLoginNonceMaxOutstanding = 64
)

var (
	errAdminSessionInvalid = errors.New("invalid admin session")
	errAdminLoginNonceCap  = errors.New("admin login is temporarily unavailable")
)

// AdminSession stores only a digest of the browser session and CSRF secret.
type AdminSession struct {
	ID            string     `gorm:"column:id;primaryKey;size:36"`
	Prefix        string     `gorm:"column:prefix;not null;size:48;index"`
	Digest        []byte     `gorm:"column:digest;not null;size:32;uniqueIndex"`
	AdminTokenID  string     `gorm:"column:admin_token_id;not null;size:36;index"`
	CreatedAt     time.Time  `gorm:"column:created_at;not null;index"`
	ExpiresAt     time.Time  `gorm:"column:expires_at;not null;index"`
	IdleExpiresAt time.Time  `gorm:"column:idle_expires_at;not null;index"`
	LastUsedAt    time.Time  `gorm:"column:last_used_at;not null;index"`
	RevokedAt     *time.Time `gorm:"column:revoked_at;index"`
	CSRFDigest    []byte     `gorm:"column:csrf_digest;not null;size:32"`
}

// AdminLoginNonce is a one-use, short-lived login proof.
type AdminLoginNonce struct {
	ID        string     `gorm:"column:id;primaryKey;size:36"`
	Prefix    string     `gorm:"column:prefix;not null;size:48;index"`
	Digest    []byte     `gorm:"column:digest;not null;size:32;uniqueIndex"`
	CreatedAt time.Time  `gorm:"column:created_at;not null;index"`
	ExpiresAt time.Time  `gorm:"column:expires_at;not null;index:idx_admin_login_nonce_live,priority:2"`
	UsedAt    *time.Time `gorm:"column:used_at;index:idx_admin_login_nonce_live,priority:1"`
}

func (AdminLoginNonce) TableName() string { return "admin_login_nonces" }

type parsedAdminSession struct {
	Raw    []byte
	Prefix string
}

type adminSessionAuth struct {
	ID         string
	CSRFDigest []byte
}

func (s *AdminTokenStore) CreateSession(ctx context.Context, principal AdminPrincipal) (string, string, AdminSession, error) {
	if ctx == nil {
		return "", "", AdminSession{}, errors.New("admin session context is nil")
	}

	if strings.TrimSpace(principal.ID) == "" || strings.TrimSpace(principal.Name) == "" {
		return "", "", AdminSession{}, ErrAdminTokenInvalid
	}
	cookie, sessionRaw, err := newAdminOpaqueValue(adminSessionCookiePrefix, adminSessionIDBytes, adminSessionPrefixBytes)
	if err != nil {
		return "", "", AdminSession{}, err
	}
	_, csrfRaw, err := newAdminOpaqueValue("", adminSessionIDBytes, 0)
	if err != nil {
		return "", "", AdminSession{}, err
	}
	now := s.currentTime()
	expires := now.Add(adminSessionTTL)
	idleExpires := now.Add(adminSessionIdleTTL)
	if idleExpires.After(expires) {
		idleExpires = expires
	}
	recordID, err := randomAdminTokenID()
	if err != nil {
		return "", "", AdminSession{}, err
	}
	digest := adminTokenDigest(s.hmacKey, sessionRaw)
	csrfDigest := adminTokenDigest(s.hmacKey, csrfRaw)
	record := AdminSession{
		ID:            recordID,
		Prefix:        cookie[:len(adminSessionCookiePrefix)+adminSessionPrefixBytes*2],
		Digest:        append([]byte(nil), digest[:]...),
		AdminTokenID:  principal.ID,
		CreatedAt:     now,
		ExpiresAt:     expires,
		IdleExpiresAt: idleExpires,
		LastUsedAt:    now,
		CSRFDigest:    append([]byte(nil), csrfDigest[:]...),
	}
	var current AdminPrincipal
	err = s.silentDB().WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var token AdminToken
		if err := tx.Where("id = ?", principal.ID).First(&token).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrAdminTokenInvalid
			}
			return fmt.Errorf("load admin token for session: %w", err)
		}
		if token.RevokedAt != nil || (token.ExpiresAt != nil && !now.Before(token.ExpiresAt.UTC())) {
			return ErrAdminTokenInvalid
		}
		current = AdminPrincipal{ID: token.ID, Name: token.Name, Scopes: append(AdminTokenScopes(nil), token.Scopes...), Bootstrap: token.Bootstrap}
		record.AdminTokenID = token.ID
		if err := tx.Create(&record).Error; err != nil {
			return fmt.Errorf("store admin session: %w", err)
		}
		return writeAdminAudit(tx, current, "dashboard.login", record.ID, adminAuditMetadata{}, now)
	})
	if err != nil {
		return "", "", AdminSession{}, err
	}
	return cookie, hex.EncodeToString(csrfRaw), record, nil
}

func (s *AdminTokenStore) AuthenticateSession(ctx context.Context, cookie string) (AdminPrincipal, adminSessionAuth, error) {
	if ctx == nil {
		return AdminPrincipal{}, adminSessionAuth{}, errors.New("admin session context is nil")
	}
	if err := s.availableForAuth(ctx); err != nil {
		return AdminPrincipal{}, adminSessionAuth{}, err
	}
	parsed, err := parseAdminSessionCookie(cookie)
	if err != nil {
		return AdminPrincipal{}, adminSessionAuth{}, err
	}
	now := s.currentTime()
	var principal AdminPrincipal
	var auth adminSessionAuth
	err = s.silentDB().WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var candidates []AdminSession
		query := tx.Where("prefix = ?", parsed.Prefix).Limit(adminSessionMaxCandidates + 1).Find(&candidates)
		if query.Error != nil {
			return fmt.Errorf("load admin session candidates: %w", query.Error)
		}
		if len(candidates) > adminSessionMaxCandidates {
			return errAdminSessionInvalid
		}
		digest := adminTokenDigest(s.hmacKey, parsed.Raw)
		matched := -1
		for index := range candidates {
			match := subtle.ConstantTimeCompare(digest[:], candidates[index].Digest) & subtle.ConstantTimeEq(int32(len(candidates[index].Digest)), int32(len(digest)))
			if match == 1 {
				matched = index
			}
		}
		if matched < 0 {
			return errAdminSessionInvalid
		}
		record := candidates[matched]
		if record.RevokedAt != nil || !now.Before(record.ExpiresAt.UTC()) || !now.Before(record.IdleExpiresAt.UTC()) {
			return errAdminSessionInvalid
		}
		var token AdminToken
		if err := tx.Where("id = ?", record.AdminTokenID).First(&token).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return errAdminSessionInvalid
			}
			return fmt.Errorf("load admin token for session: %w", err)
		}
		if token.RevokedAt != nil || (token.ExpiresAt != nil && !now.Before(token.ExpiresAt.UTC())) {
			return errAdminSessionInvalid
		}
		if len(record.CSRFDigest) != 32 {
			return errAdminSessionInvalid
		}
		lastUsed := record.LastUsedAt.UTC()
		if now.After(lastUsed) {
			lastUsed = now
		}
		idleExpires := now.Add(adminSessionIdleTTL)
		if idleExpires.Before(record.IdleExpiresAt.UTC()) {
			idleExpires = record.IdleExpiresAt.UTC()
		}
		if idleExpires.After(record.ExpiresAt.UTC()) {
			idleExpires = record.ExpiresAt.UTC()
		}
		result := tx.Model(&AdminSession{}).Where("id = ? AND revoked_at IS NULL AND expires_at > ? AND idle_expires_at > ?", record.ID, now, now).Updates(map[string]any{
			"last_used_at":    lastUsed,
			"idle_expires_at": idleExpires,
		})
		if result.Error != nil {
			return fmt.Errorf("update admin session use: %w", result.Error)
		}
		if result.RowsAffected != 1 {
			return errAdminSessionInvalid
		}
		principal = AdminPrincipal{ID: token.ID, Name: token.Name, Scopes: append(AdminTokenScopes(nil), token.Scopes...), Bootstrap: token.Bootstrap}
		auth = adminSessionAuth{ID: record.ID, CSRFDigest: append([]byte(nil), record.CSRFDigest...)}
		return nil
	})
	if err != nil {
		return AdminPrincipal{}, adminSessionAuth{}, err
	}
	return principal, auth, nil
}

func (s *AdminTokenStore) ValidateSessionCSRF(raw string, auth adminSessionAuth) bool {
	if s == nil || len(s.hmacKey) == 0 || len(raw) != adminSessionIDBytes*2 || len(auth.CSRFDigest) != 32 {
		return false
	}
	decoded := make([]byte, adminSessionIDBytes)
	if _, err := hex.Decode(decoded, []byte(raw)); err != nil {
		return false
	}
	digest := adminTokenDigest(s.hmacKey, decoded)
	return subtle.ConstantTimeCompare(digest[:], auth.CSRFDigest) == 1 && subtle.ConstantTimeEq(int32(len(auth.CSRFDigest)), int32(len(digest))) == 1
}

func (s *AdminTokenStore) RevokeSession(ctx context.Context, auth adminSessionAuth) error {
	if ctx == nil {
		return errors.New("admin session context is nil")
	}

	if auth.ID == "" {
		return errAdminSessionInvalid
	}
	now := s.currentTime()
	return s.silentDB().WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Model(&AdminSession{}).Where("id = ? AND revoked_at IS NULL", auth.ID).Update("revoked_at", now).Error; err != nil {
			return fmt.Errorf("revoke admin session: %w", err)
		}
		if err := tx.Where("id = ?", auth.ID).Delete(&AdminSession{}).Error; err != nil {
			return fmt.Errorf("delete admin session: %w", err)
		}
		return nil
	})
}

func (s *AdminTokenStore) LogoutSession(ctx context.Context, auth adminSessionAuth, principal AdminPrincipal) error {
	if ctx == nil {
		return errors.New("admin session context is nil")
	}

	if auth.ID == "" || principal.ID == "" || principal.Name == "" {
		return errAdminSessionInvalid
	}
	now := s.currentTime()
	return s.silentDB().WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var record AdminSession
		if err := tx.Where("id = ?", auth.ID).First(&record).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return errAdminSessionInvalid
			}
			return fmt.Errorf("load admin session for logout: %w", err)
		}
		if err := writeAdminAudit(tx, principal, "dashboard.logout", record.ID, adminAuditMetadata{}, now); err != nil {
			return err
		}
		if err := tx.Model(&AdminSession{}).Where("id = ? AND revoked_at IS NULL", record.ID).Update("revoked_at", now).Error; err != nil {
			return fmt.Errorf("revoke admin session: %w", err)
		}
		if err := tx.Where("id = ?", record.ID).Delete(&AdminSession{}).Error; err != nil {
			return fmt.Errorf("delete admin session: %w", err)
		}
		return nil
	})
}

func (s *AdminTokenStore) CreateLoginNonce(ctx context.Context) (string, error) {
	if ctx == nil {
		return "", errors.New("admin login nonce context is nil")
	}

	rawValue, raw, err := newAdminOpaqueValue(adminLoginNoncePrefix, adminSessionIDBytes, adminSessionPrefixBytes)
	if err != nil {
		return "", err
	}
	now := s.currentTime()
	digest := adminTokenDigest(s.hmacKey, raw)
	id, err := randomAdminTokenID()
	if err != nil {
		return "", err
	}
	record := AdminLoginNonce{ID: id, Prefix: rawValue[:len(adminLoginNoncePrefix)+adminSessionPrefixBytes*2], Digest: append([]byte(nil), digest[:]...), CreatedAt: now, ExpiresAt: now.Add(adminLoginNonceTTL)}
	err = s.silentDB().WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if result := tx.Where("used_at IS NOT NULL OR expires_at <= ?", now).Delete(&AdminLoginNonce{}); result.Error != nil {
			return fmt.Errorf("prune admin login nonces: %w", result.Error)
		}
		var outstanding int64
		if err := tx.Model(&AdminLoginNonce{}).Where("used_at IS NULL AND expires_at > ?", now).Count(&outstanding).Error; err != nil {
			return fmt.Errorf("count admin login nonces: %w", err)
		}
		if outstanding >= adminLoginNonceMaxOutstanding {
			return errAdminLoginNonceCap
		}
		if err := tx.Create(&record).Error; err != nil {
			return fmt.Errorf("store admin login nonce: %w", err)
		}
		return nil
	})
	if err != nil {
		return "", err
	}
	return rawValue, nil
}

func (s *AdminTokenStore) ConsumeLoginNonce(ctx context.Context, cookie, formValue string) error {
	if ctx == nil {
		return errors.New("admin login nonce context is nil")
	}

	if subtle.ConstantTimeCompare([]byte(cookie), []byte(formValue)) != 1 {
		return errAdminSessionInvalid
	}
	parsed, err := parseAdminLoginNonce(cookie)
	if err != nil {
		return err
	}
	now := s.currentTime()
	return s.silentDB().WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var candidates []AdminLoginNonce
		if err := tx.Where("prefix = ?", parsed.Prefix).Limit(adminLoginNonceMaxCandidates + 1).Find(&candidates).Error; err != nil {
			return fmt.Errorf("load admin login nonce candidates: %w", err)
		}
		if len(candidates) > adminLoginNonceMaxCandidates {
			return errAdminSessionInvalid
		}
		digest := adminTokenDigest(s.hmacKey, parsed.Raw)
		matched := -1
		for index := range candidates {
			match := subtle.ConstantTimeCompare(digest[:], candidates[index].Digest) & subtle.ConstantTimeEq(int32(len(candidates[index].Digest)), int32(len(digest)))
			if match == 1 {
				matched = index
			}
		}
		if matched < 0 || candidates[matched].UsedAt != nil || !now.Before(candidates[matched].ExpiresAt.UTC()) {
			return errAdminSessionInvalid
		}
		result := tx.Model(&AdminLoginNonce{}).Where("id = ? AND used_at IS NULL AND expires_at > ?", candidates[matched].ID, now).Update("used_at", now)
		if result.Error != nil {
			return fmt.Errorf("consume admin login nonce: %w", result.Error)
		}
		if result.RowsAffected != 1 {
			return errAdminSessionInvalid
		}
		return nil
	})
}

func newAdminOpaqueValue(prefix string, size, prefixBytes int) (string, []byte, error) {
	raw := make([]byte, size)
	if _, err := rand.Read(raw); err != nil {
		return "", nil, fmt.Errorf("generate admin opaque value: %w", err)
	}
	encoded := hex.EncodeToString(raw)
	if prefixBytes == 0 {
		return encoded, raw, nil
	}
	return prefix + encoded[:prefixBytes*2] + "_" + encoded, raw, nil
}

func parseAdminSessionCookie(value string) (parsedAdminSession, error) {
	return parseAdminPrefixedValue(value, adminSessionCookiePrefix)
}

func parseAdminLoginNonce(value string) (parsedAdminSession, error) {
	return parseAdminPrefixedValue(value, adminLoginNoncePrefix)
}

func parseAdminPrefixedValue(value, prefix string) (parsedAdminSession, error) {
	expected := len(prefix) + adminSessionPrefixBytes*2 + 1 + adminSessionIDBytes*2
	if len(value) != expected || !strings.HasPrefix(value, prefix) {
		return parsedAdminSession{}, errAdminSessionInvalid
	}
	rest := value[len(prefix):]
	if rest[adminSessionPrefixBytes*2] != '_' {
		return parsedAdminSession{}, errAdminSessionInvalid
	}
	prefixHex := rest[:adminSessionPrefixBytes*2]
	fullHex := rest[adminSessionPrefixBytes*2+1:]
	decoded := make([]byte, adminSessionIDBytes)
	if _, err := hex.Decode(decoded, []byte(fullHex)); err != nil || hex.EncodeToString(decoded[:adminSessionPrefixBytes]) != prefixHex {
		return parsedAdminSession{}, errAdminSessionInvalid
	}
	return parsedAdminSession{Raw: decoded, Prefix: prefix + prefixHex}, nil
}
