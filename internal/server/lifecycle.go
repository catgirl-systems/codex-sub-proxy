package server

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/catgirl-systems/codex-sub-proxy/internal/envelope"
	"gorm.io/gorm"
)

const (
	lifecycleEventVersion  uint16 = 1
	lifecycleMaxString            = 512
	lifecycleMaxDetail            = envelope.MaxPlaintextSize
	requestStatusRunning          = "running"
	requestStatusSucceeded        = "succeeded"
	requestStatusFailed           = "failed"
	requestStatusCanceled         = "canceled"
)

var (
	terminalStates = map[string]struct{}{
		requestStatusSucceeded: {},
		requestStatusFailed:    {},
		requestStatusCanceled:  {},
	}
)

// JournalRequestMetadata contains safe request metadata. It never contains a secret.
type JournalRequestMetadata struct {
	Endpoint         string
	Model            string
	APIKeyID         string
	ConversationHint string
}

// AccountRecord stores provider identity without credentials.
type AccountRecord struct {
	ID        string    `gorm:"column:id;primaryKey;size:255"`
	Provider  string    `gorm:"column:provider;not null;size:128;index"`
	AccountID string    `gorm:"column:account_id;not null;size:255;index"`
	CreatedAt time.Time `gorm:"column:created_at;not null"`
	UpdatedAt time.Time `gorm:"column:updated_at;not null"`
}

func (AccountRecord) TableName() string { return "accounts" }

// ConversationRecord stores one stable conversation identity.
type ConversationRecord struct {
	ID           string    `gorm:"column:id;primaryKey;size:36"`
	AccountID    string    `gorm:"column:account_id;size:255;index"`
	CreatedAt    time.Time `gorm:"column:created_at;not null"`
	UpdatedAt    time.Time `gorm:"column:updated_at;not null"`
	RequestCount int64     `gorm:"column:request_count;not null;default:0"`
}

func (ConversationRecord) TableName() string { return "conversations" }

// RequestRecord is the searchable lifecycle projection for one accepted request.
type RequestRecord struct {
	ID               string     `gorm:"column:request_id;primaryKey;size:36"`
	ReplayID         string     `gorm:"column:accepted_replay_id;not null;uniqueIndex"`
	ConversationID   string     `gorm:"column:conversation_id;not null;size:36;index"`
	APIKeyID         string     `gorm:"column:api_key_id;size:255;index"`
	Endpoint         string     `gorm:"column:endpoint;not null;size:128;index"`
	Model            string     `gorm:"column:model;not null;size:256;index"`
	Mode             string     `gorm:"column:journal_mode;not null;size:16"`
	Status           string     `gorm:"column:status;not null;size:16;index"`
	AcceptedAt       time.Time  `gorm:"column:accepted_at;not null;index"`
	StartedAt        time.Time  `gorm:"column:started_at;not null"`
	UpdatedAt        time.Time  `gorm:"column:updated_at;not null;index"`
	TerminalAt       *time.Time `gorm:"column:terminal_at;index"`
	TerminalReplayID string     `gorm:"column:terminal_replay_id;size:36"`
	TerminalConflict bool       `gorm:"column:terminal_conflict;not null;default:false"`
}

func (RequestRecord) TableName() string { return "requests" }

// EncryptedPayloadRecord stores one authenticated payload envelope.
type EncryptedPayloadRecord struct {
	ID         string    `gorm:"column:id;primaryKey;size:36"`
	ReplayID   string    `gorm:"column:replay_id;not null;uniqueIndex"`
	KeyVersion uint32    `gorm:"column:key_version;not null"`
	Envelope   []byte    `gorm:"column:encrypted_envelope;not null"`
	CreatedAt  time.Time `gorm:"column:created_at;not null"`
}

func (EncryptedPayloadRecord) TableName() string { return "encrypted_payloads" }

// StreamEventRecord stores safe event metadata and its encrypted body reference.
type StreamEventRecord struct {
	ReplayID  string    `gorm:"column:replay_id;primaryKey;size:36"`
	RequestID string    `gorm:"column:request_id;not null;size:36;index"`
	Sequence  uint64    `gorm:"column:sequence;not null;index"`
	EventType string    `gorm:"column:event_type;not null;size:128;index"`
	PayloadID string    `gorm:"column:payload_id;not null;size:36;index"`
	CreatedAt time.Time `gorm:"column:created_at;not null;index"`
}

func (StreamEventRecord) TableName() string { return "stream_events" }

// UsageRecord stores bounded, non-secret usage counters.
type UsageRecord struct {
	ReplayID     string    `gorm:"column:replay_id;primaryKey;size:36"`
	RequestID    string    `gorm:"column:request_id;not null;size:36;index"`
	InputTokens  int64     `gorm:"column:input_tokens;not null;default:0"`
	OutputTokens int64     `gorm:"column:output_tokens;not null;default:0"`
	TotalTokens  int64     `gorm:"column:total_tokens;not null;default:0"`
	ImageCount   int64     `gorm:"column:image_count;not null;default:0"`
	CreatedAt    time.Time `gorm:"column:created_at;not null;index"`
}

func (UsageRecord) TableName() string { return "usage" }

// AuditRecord stores a safe audit fact and an optional encrypted detail envelope.
type AuditRecord struct {
	ID        string    `gorm:"column:id;primaryKey;size:36"`
	RequestID string    `gorm:"column:request_id;size:36;index"`
	APIKeyID  string    `gorm:"column:api_key_id;size:255;index"`
	Endpoint  string    `gorm:"column:endpoint;size:128;index"`
	EventType string    `gorm:"column:event_type;not null;size:128;index"`
	Status    int       `gorm:"column:status;not null;index"`
	PayloadID string    `gorm:"column:payload_id;size:36;index"`
	CreatedAt time.Time `gorm:"column:created_at;not null;index"`
}

func (AuditRecord) TableName() string { return "audit_records" }

type lifecycleAcceptedPayload struct {
	Version        uint16 `json:"version"`
	RequestID      string `json:"request_id"`
	ConversationID string `json:"conversation_id"`
	Endpoint       string `json:"endpoint"`
	Model          string `json:"model"`
	APIKeyID       string `json:"api_key_id,omitempty"`
	Mode           string `json:"mode"`
}

type lifecycleTerminalPayload struct {
	Version uint16 `json:"version"`
	State   string `json:"state"`
	Detail  string `json:"detail,omitempty"`
}

type lifecycleUsagePayload struct {
	Version      uint16 `json:"version"`
	InputTokens  int64  `json:"input_tokens"`
	OutputTokens int64  `json:"output_tokens"`
	TotalTokens  int64  `json:"total_tokens"`
	ImageCount   int64  `json:"image_count"`
}

func migrateLifecycle(db *gorm.DB) error {
	if db == nil {
		return errors.New("lifecycle database is nil")
	}
	if err := db.AutoMigrate(
		&AccountRecord{},
		&ConversationRecord{},
		&RequestRecord{},
		&EncryptedPayloadRecord{},
		&StreamEventRecord{},
		&UsageRecord{},
		&AuditRecord{},
	); err != nil {
		return fmt.Errorf("migrate lifecycle projections: %w", err)
	}
	return nil
}

func lifecycleAcceptedBytes(request JournalRequest) ([]byte, error) {
	value := lifecycleAcceptedPayload{
		Version:        lifecycleEventVersion,
		RequestID:      request.ID,
		ConversationID: request.ConversationID,
		Endpoint:       request.Endpoint,
		Model:          request.Model,
		APIKeyID:       request.APIKeyID,
		Mode:           request.Mode,
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("encode accepted lifecycle event: %w", err)
	}
	return encoded, nil
}

func lifecycleTerminalBytes(state string, detail []byte) ([]byte, error) {
	if _, ok := terminalStates[state]; !ok {
		return nil, errors.New("terminal lifecycle state is invalid")
	}
	if len(detail) > lifecycleMaxDetail {
		return nil, errors.New("terminal lifecycle detail is too large")
	}
	value := lifecycleTerminalPayload{Version: lifecycleEventVersion, State: state}
	if len(detail) != 0 {
		value.Detail = string(detail)
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("encode terminal lifecycle event: %w", err)
	}
	return encoded, nil
}

func lifecycleUsageBytes(input, output, total, images int64) ([]byte, error) {
	if input < 0 || output < 0 || total < 0 || images < 0 {
		return nil, errors.New("usage counters are negative")
	}
	value := lifecycleUsagePayload{
		Version: lifecycleEventVersion, InputTokens: input, OutputTokens: output,
		TotalTokens: total, ImageCount: images,
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("encode usage lifecycle event: %w", err)
	}
	return encoded, nil
}

func decodeLifecycleJSON(data []byte, target any, limit int) error {
	if len(data) == 0 || len(data) > limit {
		return errors.New("lifecycle payload size is invalid")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("decode lifecycle payload: %w", err)
	}
	var extra json.RawMessage
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return errors.New("lifecycle payload has multiple values")
		}
		return fmt.Errorf("decode lifecycle payload trailer: %w", err)
	}
	return nil
}

func validateLifecycleAccepted(value lifecycleAcceptedPayload, request JournalRequest) error {
	if value.Version != lifecycleEventVersion || value.RequestID != request.ID || value.ConversationID != request.ConversationID {
		return errors.New("accepted lifecycle payload identity is invalid")
	}
	if value.Endpoint != request.Endpoint || value.Model != request.Model || value.APIKeyID != request.APIKeyID || value.Mode != request.Mode {
		return errors.New("accepted lifecycle payload metadata is invalid")
	}
	for name, item := range map[string]string{
		"endpoint":   value.Endpoint,
		"model":      value.Model,
		"API key ID": value.APIKeyID,
	} {
		if len(item) > lifecycleMaxString {
			return fmt.Errorf("lifecycle %s is too long", name)
		}
	}
	return nil
}

func validateLifecycleTerminal(value lifecycleTerminalPayload) error {
	if value.Version != lifecycleEventVersion {
		return errors.New("terminal lifecycle payload version is unsupported")
	}
	if _, ok := terminalStates[value.State]; !ok {
		return errors.New("terminal lifecycle state is invalid")
	}
	if len(value.Detail) > lifecycleMaxDetail {
		return errors.New("terminal lifecycle detail is too large")
	}
	return nil
}

func validateLifecycleUsage(value lifecycleUsagePayload) error {
	if value.Version != lifecycleEventVersion || value.InputTokens < 0 || value.OutputTokens < 0 || value.TotalTokens < 0 || value.ImageCount < 0 {
		return errors.New("usage lifecycle payload is invalid")
	}
	const maxCounter = 1 << 31
	if value.InputTokens > maxCounter || value.OutputTokens > maxCounter || value.TotalTokens > maxCounter || value.ImageCount > maxCounter {
		return errors.New("usage lifecycle payload is too large")
	}
	return nil
}

func (j *Journal) materializeRecord(tx *gorm.DB, source JournalRecord, request JournalRequest) error {
	plain, err := j.decryptJournalPayload(source)
	if err != nil {
		return err
	}
	if len(plain) > lifecycleMaxDetail {
		return errors.New("decrypted lifecycle payload is too large")
	}
	switch {
	case source.EventType == journalRequestEventType:
		var accepted lifecycleAcceptedPayload
		if err := decodeLifecycleJSON(plain, &accepted, lifecycleMaxDetail); err != nil {
			return err
		}
		if err := validateLifecycleAccepted(accepted, request); err != nil {
			return err
		}
		if err := j.materializeAccepted(tx, source, accepted); err != nil {
			return err
		}
	case source.EventType == "request.running":
		var row RequestRecord
		if err := tx.Where("request_id = ?", source.RequestID).First(&row).Error; err != nil {
			return fmt.Errorf("load lifecycle request: %w", err)
		}
		if row.TerminalAt == nil {
			result := tx.Model(&RequestRecord{}).Where("request_id = ? AND terminal_at IS NULL", source.RequestID).Updates(map[string]any{
				"status":     requestStatusRunning,
				"started_at": source.CreatedAt,
				"updated_at": source.CreatedAt,
			})
			if result.Error != nil {
				return fmt.Errorf("mark lifecycle request running: %w", result.Error)
			}
		}
	case source.EventType == "request.input":
		if !json.Valid(plain) {
			return errors.New("lifecycle input is not valid JSON")
		}
		if err := j.ensureEncryptedPayload(tx, source, plain); err != nil {
			return err
		}
	case source.EventType == "usage.update":
		var usage lifecycleUsagePayload
		if err := decodeLifecycleJSON(plain, &usage, lifecycleMaxDetail); err != nil {
			return err
		}
		if err := validateLifecycleUsage(usage); err != nil {
			return err
		}
		if err := j.ensureUsage(tx, source, usage); err != nil {
			return err
		}
	case source.EventType == "request.terminal":
		var terminal lifecycleTerminalPayload
		if err := decodeLifecycleJSON(plain, &terminal, lifecycleMaxDetail); err != nil {
			return err
		}
		if err := validateLifecycleTerminal(terminal); err != nil {
			return err
		}
		if err := j.ensureTerminal(tx, source, terminal); err != nil {
			return err
		}
	default:
		if !knownStreamEvent(source.EventType) {
			return fmt.Errorf("unknown lifecycle event type %q", source.EventType)
		}
		if err := validateStreamPayload(plain); err != nil {
			return err
		}
		if err := j.ensureEncryptedPayload(tx, source, plain); err != nil {
			return err
		}
		if err := j.ensureStreamEvent(tx, source); err != nil {
			return err
		}
	}
	return nil
}

func (j *Journal) materializeAccepted(tx *gorm.DB, source JournalRecord, accepted lifecycleAcceptedPayload) error {
	conversation := ConversationRecord{ID: accepted.ConversationID, CreatedAt: source.CreatedAt, UpdatedAt: source.CreatedAt}
	var existingConversation ConversationRecord
	err := tx.Where("id = ?", conversation.ID).First(&existingConversation).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		if err := tx.Create(&conversation).Error; err != nil {
			return fmt.Errorf("store lifecycle conversation: %w", err)
		}
	} else if err != nil {
		return fmt.Errorf("load lifecycle conversation: %w", err)
	}
	var row RequestRecord
	err = tx.Where("request_id = ?", accepted.RequestID).First(&row).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		row = RequestRecord{
			ID: accepted.RequestID, ReplayID: source.ReplayID, ConversationID: accepted.ConversationID,
			APIKeyID: accepted.APIKeyID, Endpoint: accepted.Endpoint, Model: accepted.Model,
			Mode: accepted.Mode, Status: requestStatusRunning, AcceptedAt: source.CreatedAt,
			StartedAt: source.CreatedAt, UpdatedAt: source.CreatedAt,
		}
		if err := tx.Create(&row).Error; err != nil {
			return fmt.Errorf("store lifecycle request: %w", err)
		}
	} else if err != nil {
		return fmt.Errorf("load lifecycle request: %w", err)
	} else if row.ReplayID != source.ReplayID || row.ConversationID != accepted.ConversationID || row.Endpoint != accepted.Endpoint || row.Model != accepted.Model || row.APIKeyID != accepted.APIKeyID || row.Mode != accepted.Mode {
		return errors.New("lifecycle request metadata conflicts")
	}
	result := tx.Model(&ConversationRecord{}).Where("id = ?", conversation.ID).Updates(map[string]any{
		"updated_at":    source.CreatedAt,
		"request_count": gorm.Expr("request_count + 1"),
	})
	if result.Error != nil {
		return fmt.Errorf("update lifecycle conversation: %w", result.Error)
	}
	return nil
}

func (j *Journal) ensureEncryptedPayload(tx *gorm.DB, source JournalRecord, plain []byte) error {
	if len(source.Payload) == 0 || source.KeyVersion == 0 {
		return errors.New("journal payload envelope is missing")
	}
	var existing EncryptedPayloadRecord
	err := tx.Where("id = ?", source.ReplayID).First(&existing).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		record := EncryptedPayloadRecord{
			ID: source.ReplayID, ReplayID: source.ReplayID, KeyVersion: source.KeyVersion,
			Envelope: append([]byte(nil), source.Payload...), CreatedAt: source.CreatedAt,
		}
		if err := tx.Create(&record).Error; err != nil {
			return fmt.Errorf("store encrypted lifecycle payload: %w", err)
		}
		return nil
	}
	if err != nil {
		return fmt.Errorf("load encrypted lifecycle payload: %w", err)
	}
	if existing.KeyVersion != source.KeyVersion || !bytes.Equal(existing.Envelope, source.Payload) {
		return errors.New("encrypted lifecycle payload conflicts")
	}
	return nil
}

func (j *Journal) ensureStreamEvent(tx *gorm.DB, source JournalRecord) error {
	var existing StreamEventRecord
	err := tx.Where("replay_id = ?", source.ReplayID).First(&existing).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		row := StreamEventRecord{ReplayID: source.ReplayID, RequestID: source.RequestID, Sequence: source.Sequence, EventType: source.EventType, PayloadID: source.ReplayID, CreatedAt: source.CreatedAt}
		if err := tx.Create(&row).Error; err != nil {
			return fmt.Errorf("store lifecycle stream event: %w", err)
		}
		return nil
	}
	if err != nil {
		return fmt.Errorf("load lifecycle stream event: %w", err)
	}
	if existing.RequestID != source.RequestID || existing.Sequence != source.Sequence || existing.EventType != source.EventType || existing.PayloadID != source.ReplayID {
		return errors.New("lifecycle stream event conflicts")
	}
	return nil
}

func (j *Journal) ensureUsage(tx *gorm.DB, source JournalRecord, usage lifecycleUsagePayload) error {
	if err := j.ensureRequestExists(tx, source.RequestID); err != nil {
		return err
	}
	var existing UsageRecord
	err := tx.Where("replay_id = ?", source.ReplayID).First(&existing).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		row := UsageRecord{ReplayID: source.ReplayID, RequestID: source.RequestID, InputTokens: usage.InputTokens, OutputTokens: usage.OutputTokens, TotalTokens: usage.TotalTokens, ImageCount: usage.ImageCount, CreatedAt: source.CreatedAt}
		if err := tx.Create(&row).Error; err != nil {
			return fmt.Errorf("store lifecycle usage: %w", err)
		}
		return nil
	}
	if err != nil {
		return fmt.Errorf("load lifecycle usage: %w", err)
	}
	if existing.RequestID != source.RequestID || existing.InputTokens != usage.InputTokens || existing.OutputTokens != usage.OutputTokens || existing.TotalTokens != usage.TotalTokens || existing.ImageCount != usage.ImageCount {
		return errors.New("lifecycle usage conflicts")
	}
	return nil
}

func (j *Journal) ensureTerminal(tx *gorm.DB, source JournalRecord, terminal lifecycleTerminalPayload) error {
	if err := j.ensureRequestExists(tx, source.RequestID); err != nil {
		return err
	}
	if err := j.ensureEncryptedPayload(tx, source, mustJSON(terminal)); err != nil {
		return err
	}
	var row RequestRecord
	if err := tx.Where("request_id = ?", source.RequestID).First(&row).Error; err != nil {
		return fmt.Errorf("load lifecycle terminal request: %w", err)
	}
	if row.TerminalAt == nil {
		now := source.CreatedAt
		result := tx.Model(&RequestRecord{}).Where("request_id = ? AND terminal_at IS NULL", source.RequestID).Updates(map[string]any{
			"status":             terminal.State,
			"terminal_at":        now,
			"terminal_replay_id": source.ReplayID,
			"updated_at":         now,
		})
		if result.Error != nil {
			return fmt.Errorf("set lifecycle terminal state: %w", result.Error)
		}
		if result.RowsAffected == 1 {
			return nil
		}
		if err := tx.Where("request_id = ?", source.RequestID).First(&row).Error; err != nil {
			return err
		}
	}
	if row.TerminalReplayID == source.ReplayID || row.Status == terminal.State {
		return nil
	}
	result := tx.Model(&RequestRecord{}).Where("request_id = ?", source.RequestID).Update("terminal_conflict", true)
	if result.Error != nil {
		return fmt.Errorf("flag lifecycle terminal conflict: %w", result.Error)
	}
	auditID, err := newJournalUUID()
	if err != nil {
		return fmt.Errorf("generate terminal conflict audit ID: %w", err)
	}
	audit := AuditRecord{ID: auditID, RequestID: source.RequestID, EventType: "terminal.conflict", Status: 409, PayloadID: source.ReplayID, CreatedAt: source.CreatedAt}
	if err := tx.Create(&audit).Error; err != nil {
		return fmt.Errorf("store terminal conflict audit: %w", err)
	}
	return nil
}

func (j *Journal) ensureRequestExists(tx *gorm.DB, requestID string) error {
	var row RequestRecord
	if err := tx.Where("request_id = ?", requestID).First(&row).Error; err != nil {
		return fmt.Errorf("load lifecycle request: %w", err)
	}
	return nil
}

func (j *Journal) decryptJournalPayload(record JournalRecord) ([]byte, error) {
	if record.KeyVersion == 0 || record.EventVersion != lifecycleEventVersion {
		return nil, errors.New("journal payload uses an unsupported legacy version")
	}
	if len(record.Payload) == 0 {
		return nil, errors.New("journal payload envelope is empty")
	}
	if len(record.Payload) < 9 || binary.BigEndian.Uint32(record.Payload[5:9]) != record.KeyVersion {
		return nil, errors.New("journal payload key version does not match envelope")
	}
	plain, err := envelope.Decrypt(record.Payload, envelope.PayloadDomain, j.keys)
	if err != nil {
		return nil, fmt.Errorf("decrypt journal payload: %w", err)
	}
	return plain, nil
}

func knownStreamEvent(eventType string) bool {
	if eventType == "sse.event" || eventType == "stream.done" || eventType == "response.json" {
		return true
	}
	return strings.HasPrefix(eventType, "response.") || eventType == "error"
}

func validateStreamPayload(payload []byte) error {
	if len(payload) == 0 || len(payload) > lifecycleMaxDetail {
		return errors.New("stream lifecycle payload size is invalid")
	}
	if bytes.HasPrefix(bytes.TrimSpace(payload), []byte("data:")) {
		return nil
	}
	if !json.Valid(payload) {
		return errors.New("stream lifecycle payload is invalid JSON")
	}
	return nil
}

func mustJSON(value any) []byte {
	encoded, _ := json.Marshal(value)
	return encoded
}

func deriveConversationID(hint string) string {
	hint = strings.TrimSpace(hint)
	if hint == "" {
		return ""
	}
	digest := sha256.Sum256([]byte("codex-sub-proxy conversation v1\x00" + hint))
	var value [16]byte
	copy(value[:], digest[:16])
	value[6] = (value[6] & 0x0f) | 0x50
	value[8] = (value[8] & 0x3f) | 0x80
	var encoded [36]byte
	hex.Encode(encoded[0:8], value[0:4])
	encoded[8] = '-'
	hex.Encode(encoded[9:13], value[4:6])
	encoded[13] = '-'
	hex.Encode(encoded[14:18], value[6:8])
	encoded[18] = '-'
	hex.Encode(encoded[19:23], value[8:10])
	encoded[23] = '-'
	hex.Encode(encoded[24:36], value[10:16])
	return string(encoded[:])
}
