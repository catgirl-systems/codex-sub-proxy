package payload

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/catgirl-systems/codex-sub-proxy/internal/envelope"
	"gorm.io/gorm"
)

const (
	// MaxBodySize bounds the plaintext held in one conversation record.
	MaxBodySize = envelope.MaxPlaintextSize
	// MaxEnvelopeSize bounds the encrypted envelope held in one conversation record.
	MaxEnvelopeSize       = envelope.MaxEnvelopeSize
	envelopeKeyVersionEnd = 9
	maxRecordIDSize       = 255
)

// ErrNotFound indicates that a conversation payload record does not exist.
var ErrNotFound = gorm.ErrRecordNotFound

// Record stores one encrypted conversation payload and non-secret metadata.
type Record struct {
	ID         string    `gorm:"column:id;primaryKey;size:255"`
	KeyVersion uint32    `gorm:"column:key_version;not null"`
	Envelope   []byte    `gorm:"column:encrypted_envelope;not null"`
	CreatedAt  time.Time `gorm:"column:created_at;not null"`
}

// TableName keeps payload records separate from unrelated application data.
func (Record) TableName() string {
	return "conversation_payloads"
}

// Migrate creates or updates the conversation payload table.
func Migrate(db *gorm.DB) error {
	if db == nil {
		return errors.New("payload database is nil")
	}
	if err := db.AutoMigrate(&Record{}); err != nil {
		return fmt.Errorf("migrate conversation payload records: %w", err)
	}
	return nil
}

// Save encrypts body with the active payload key and stores its record.
func Save(ctx context.Context, db *gorm.DB, id string, body []byte, keys envelope.KeySet) error {
	if err := validateCall(ctx, db, id); err != nil {
		return err
	}
	validatedKeys, err := envelope.NewKeySet(keys.Active, keys.Previous...)
	if err != nil {
		return fmt.Errorf("validate payload encryption keys: %w", err)
	}
	keys = validatedKeys
	if len(body) > MaxBodySize {
		return errors.New("conversation body is too large")
	}
	encoded, err := envelope.Encrypt(body, envelope.PayloadDomain, keys)
	if err != nil {
		return fmt.Errorf("encrypt conversation payload: %w", err)
	}
	if len(encoded) > MaxEnvelopeSize {
		return errors.New("conversation payload envelope is too large")
	}

	record := Record{
		ID:         id,
		KeyVersion: keys.Active.Version,
		Envelope:   encoded,
		CreatedAt:  time.Now().UTC(),
	}
	if err := db.WithContext(ctx).Save(&record).Error; err != nil {
		return fmt.Errorf("save conversation payload: %w", err)
	}
	return nil
}

// Load finds a record and decrypts it with the active or previous payload key.
func Load(ctx context.Context, db *gorm.DB, id string, keys envelope.KeySet) ([]byte, error) {
	if err := validateCall(ctx, db, id); err != nil {
		return nil, err
	}
	validatedKeys, err := envelope.NewKeySet(keys.Active, keys.Previous...)
	if err != nil {
		return nil, fmt.Errorf("validate payload encryption keys: %w", err)
	}
	keys = validatedKeys

	var record struct {
		KeyVersion   uint32 `gorm:"column:key_version"`
		Envelope     []byte `gorm:"column:encrypted_envelope"`
		EnvelopeSize int64  `gorm:"column:envelope_size"`
	}
	err = db.WithContext(ctx).
		Model(&Record{}).
		Select(
			"id, key_version, "+
				"CASE WHEN length(encrypted_envelope) <= ? THEN encrypted_envelope ELSE NULL END AS encrypted_envelope, "+
				"length(encrypted_envelope) AS envelope_size",
			MaxEnvelopeSize,
		).
		Where("id = ?", id).
		Take(&record).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, fmt.Errorf("load conversation payload: %w", ErrNotFound)
	}
	if err != nil {
		return nil, fmt.Errorf("load conversation payload: %w", err)
	}
	if record.KeyVersion == 0 ||
		len(record.Envelope) < envelopeKeyVersionEnd ||
		binary.BigEndian.Uint32(record.Envelope[5:envelopeKeyVersionEnd]) != record.KeyVersion ||
		record.EnvelopeSize <= 0 ||
		record.EnvelopeSize > MaxEnvelopeSize ||
		len(record.Envelope) == 0 {
		return nil, errors.New("stored conversation payload envelope is invalid")
	}
	body, err := envelope.Decrypt(record.Envelope, envelope.PayloadDomain, keys)
	if err != nil {
		return nil, fmt.Errorf("decrypt conversation payload: %w", err)
	}
	return body, nil
}

func validateCall(ctx context.Context, db *gorm.DB, id string) error {
	if ctx == nil {
		return errors.New("payload context is nil")
	}
	if db == nil {
		return errors.New("payload database is nil")
	}
	if strings.TrimSpace(id) == "" {
		return errors.New("conversation payload id is empty")
	}
	if len(id) > maxRecordIDSize {
		return errors.New("conversation payload id is too long")
	}
	return nil
}
