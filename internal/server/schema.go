package server

import (
	"errors"
	"fmt"

	"github.com/catgirl-systems/codex-sub-proxy/internal/apikey"
	"github.com/catgirl-systems/codex-sub-proxy/internal/payload"
	"gorm.io/gorm"
)

const currentSchemaVersion uint = 2

type schemaMigration struct {
	Version uint   `gorm:"column:version;primaryKey"`
	Name    string `gorm:"column:name;not null;size:128"`
}

func (schemaMigration) TableName() string { return "schema_migrations" }

// MigrateSchema applies all data migrations under one SQLite transaction.
func MigrateSchema(db *gorm.DB) error {
	if db == nil {
		return errors.New("schema database is nil")
	}
	return db.Transaction(func(tx *gorm.DB) error {
		if err := tx.AutoMigrate(&schemaMigration{}); err != nil {
			return fmt.Errorf("create schema migration table: %w", err)
		}
		var applied schemaMigration
		result := tx.Order("version DESC").First(&applied)
		if result.Error != nil && !errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return fmt.Errorf("read schema migration version: %w", result.Error)
		}
		if result.Error == nil && applied.Version > currentSchemaVersion {
			return fmt.Errorf("database schema version %d is newer than supported version %d", applied.Version, currentSchemaVersion)
		}
		if result.Error == nil && applied.Version == currentSchemaVersion {
			return nil
		}
		if err := payload.Migrate(tx); err != nil {
			return fmt.Errorf("apply payload schema migration: %w", err)
		}
		if err := apikey.Migrate(tx); err != nil {
			return fmt.Errorf("apply API-key schema migration: %w", err)
		}
		if err := MigrateJournal(tx); err != nil {
			return fmt.Errorf("apply journal schema migration: %w", err)
		}
		if err := tx.Create(&schemaMigration{Version: currentSchemaVersion, Name: "accounts_and_continuations"}).Error; err != nil {
			return fmt.Errorf("record schema migration: %w", err)
		}
		return nil
	})
}
