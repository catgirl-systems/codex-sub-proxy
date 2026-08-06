package server

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/catgirl-systems/codex-sub-proxy/internal/codex"
	"gorm.io/gorm"
)

// AccountStore serializes profile registry mutations independently from
// credential-file writes. It never stores or returns credential tokens.
type AccountStore struct {
	db *gorm.DB
	mu sync.Mutex
}

func NewAccountStore(db *gorm.DB) (*AccountStore, error) {
	if db == nil {
		return nil, errors.New("account registry database is nil")
	}
	return &AccountStore{db: db}, nil
}

func (store *AccountStore) List(ctx context.Context) ([]AccountRecord, error) {
	if ctx == nil {
		return nil, errors.New("account registry context is nil")
	}
	var records []AccountRecord
	if err := store.db.WithContext(ctx).Order("id ASC").Find(&records).Error; err != nil {
		return nil, fmt.Errorf("list account profiles: %w", err)
	}
	return records, nil
}

// Upsert writes one profile and, when requested, clears the previous default
// in the same transaction.
func (store *AccountStore) Upsert(ctx context.Context, record AccountRecord) error {
	if ctx == nil {
		return errors.New("account registry context is nil")
	}
	if err := validateAccountRecord(record); err != nil {
		return err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var conflict AccountRecord
		if err := tx.Where("provider_account_id = ? AND id <> ?", record.ProviderAccountID, record.ID).First(&conflict).Error; err == nil {
			return errors.New("provider account ID is already registered")
		} else if !errors.Is(err, gorm.ErrRecordNotFound) {
			return fmt.Errorf("check provider account profile: %w", err)
		}
		if record.IsDefault {
			if err := tx.Model(&AccountRecord{}).Where("id <> ?", record.ID).Update("is_default", false).Error; err != nil {
				return fmt.Errorf("clear default account profile: %w", err)
			}
		}
		var existing AccountRecord
		err := tx.Where("id = ?", record.ID).First(&existing).Error
		switch {
		case errors.Is(err, gorm.ErrRecordNotFound):
			if record.CreatedAt.IsZero() {
				record.CreatedAt = time.Now().UTC()
			}
			if record.UpdatedAt.IsZero() {
				record.UpdatedAt = record.CreatedAt
			}
			if err := tx.Create(&record).Error; err != nil {
				return fmt.Errorf("create account profile: %w", err)
			}
		case err != nil:
			return fmt.Errorf("load account profile: %w", err)
		default:
			record.CreatedAt = existing.CreatedAt
			record.UpdatedAt = time.Now().UTC()
			if err := tx.Model(&AccountRecord{}).Where("id = ?", record.ID).Updates(map[string]any{
				"provider": record.Provider, "provider_account_id": record.ProviderAccountID,
				"credential_path": record.CredentialPath, "enabled": record.Enabled,
				"is_default": record.IsDefault, "plan_type": record.PlanType, "email": record.Email,
				"updated_at": record.UpdatedAt, "last_seen_at": record.LastSeenAt,
				"cooldown_until": record.CooldownUntil, "last_error_class": record.LastErrorClass,
			}).Error; err != nil {
				return fmt.Errorf("update account profile: %w", err)
			}
		}
		return nil
	})
}

func validateAccountRecord(record AccountRecord) error {
	if strings.TrimSpace(record.ID) == "" || len(record.ID) > 255 || strings.ContainsAny(record.ID, "\r\n") {
		return errors.New("account profile ID is invalid")
	}
	if record.Provider != "codex" {
		return errors.New("account profile provider must be codex")
	}
	if strings.TrimSpace(record.ProviderAccountID) == "" || len(record.ProviderAccountID) > 255 || strings.ContainsAny(record.ProviderAccountID, "\r\n") {
		return errors.New("provider account ID is invalid")
	}
	if strings.TrimSpace(record.CredentialPath) == "" || len(record.CredentialPath) > 1024 {
		return errors.New("account credential path is invalid")
	}
	return nil
}

// MaterializeDefault registers the historical credential without moving it.
func (store *AccountStore) MaterializeDefault(ctx context.Context, credentialPath string, credential codex.Credential) error {
	if credential.AccountID == "" {
		return errors.New("default credential account ID is empty")
	}
	now := time.Now().UTC()
	return store.Upsert(ctx, AccountRecord{
		ID: "default", Provider: "codex", ProviderAccountID: credential.AccountID,
		CredentialPath: credentialPath, Enabled: true, IsDefault: true,
		PlanType: credential.PlanType, Email: credential.Email, CreatedAt: now, UpdatedAt: now,
		LastSeenAt: &now,
	})
}

// MaterializeLegacyDefault atomically renames one migrated empty-path profile
// to the historical default profile while preserving its registry metadata.
func (store *AccountStore) MaterializeLegacyDefault(ctx context.Context, legacyID, credentialPath string, credential codex.Credential) error {
	if ctx == nil {
		return errors.New("account registry context is nil")
	}
	if strings.TrimSpace(legacyID) == "" || legacyID == "default" {
		return errors.New("legacy account profile ID is invalid")
	}
	if err := validateAccountRecord(AccountRecord{
		ID: "default", Provider: "codex", ProviderAccountID: credential.AccountID,
		CredentialPath: credentialPath,
	}); err != nil {
		return err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var existing AccountRecord
		if err := tx.Where("id = ?", legacyID).First(&existing).Error; err != nil {
			return fmt.Errorf("load legacy account profile: %w", err)
		}
		if existing.Provider != "codex" || existing.ProviderAccountID != credential.AccountID ||
			strings.TrimSpace(existing.CredentialPath) != "" {
			return errors.New("legacy account profile is not an empty-path default placeholder")
		}
		var conflict AccountRecord
		if err := tx.Where("id = ?", "default").First(&conflict).Error; err == nil {
			return errors.New("default account profile already exists")
		} else if !errors.Is(err, gorm.ErrRecordNotFound) {
			return fmt.Errorf("check default account profile: %w", err)
		}
		if err := tx.Model(&AccountRecord{}).Where("id = ?", legacyID).Updates(map[string]any{
			"id": "default", "credential_path": credentialPath, "enabled": true,
			"is_default": true, "updated_at": time.Now().UTC(),
		}).Error; err != nil {
			return fmt.Errorf("rename legacy account profile: %w", err)
		}
		return nil
	})
}
