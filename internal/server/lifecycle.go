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
	lifecycleEventVersion  uint16 = 2
	lifecycleMaxString            = 512
	lifecycleMaxDetail            = envelope.MaxPlaintextSize
	requestStatusRunning          = "running"
	requestStatusSucceeded        = "succeeded"
	requestStatusFailed           = "failed"
	requestStatusCanceled         = "canceled"
)

func supportedLifecycleEventVersion(version uint16) bool {
	return version == 1 || version == lifecycleEventVersion
}

var terminalStates = map[string]struct{}{
	requestStatusSucceeded: {},
	requestStatusFailed:    {},
	requestStatusCanceled:  {},
}

// JournalRequestMetadata contains safe request metadata. It never contains a secret.
type JournalRequestMetadata struct {
	Endpoint           string
	Model              string
	APIKeyID           string
	ConversationHint   string
	ConversationID     string
	AccountID          string
	PreviousResponseID string
}

// AccountRecord stores provider identity without credentials.
type AccountRecord struct {
	ID                string     `gorm:"column:id;primaryKey;size:255"`
	Provider          string     `gorm:"column:provider;not null;size:128;index"`
	ProviderAccountID string     `gorm:"column:provider_account_id;not null;size:255;uniqueIndex"`
	CredentialPath    string     `gorm:"column:credential_path;not null;size:1024"`
	Enabled           bool       `gorm:"column:enabled;not null;default:false;index"`
	IsDefault         bool       `gorm:"column:is_default;not null;default:false;index"`
	PlanType          string     `gorm:"column:plan_type;size:128"`
	Email             string     `gorm:"column:email;size:320"`
	CreatedAt         time.Time  `gorm:"column:created_at;not null"`
	UpdatedAt         time.Time  `gorm:"column:updated_at;not null"`
	LastSeenAt        *time.Time `gorm:"column:last_seen_at"`
	CooldownUntil     *time.Time `gorm:"column:cooldown_until;index"`
	LastErrorClass    string     `gorm:"column:last_error_class;size:128"`
}

func (AccountRecord) TableName() string { return "accounts" }

// ConversationRecord stores one stable conversation identity.
type ConversationRecord struct {
	ID           string     `gorm:"column:id;primaryKey;size:36"`
	AccountID    string     `gorm:"column:account_id;size:255;index"`
	CreatedAt    time.Time  `gorm:"column:created_at;not null"`
	UpdatedAt    time.Time  `gorm:"column:updated_at;not null"`
	ExpiresAt    time.Time  `gorm:"column:expires_at;not null;index"`
	RequestCount int64      `gorm:"column:request_count;not null;default:0"`
	DeletingAt   *time.Time `gorm:"column:deleting_at;index"`
}

func (ConversationRecord) TableName() string { return "conversations" }

// RequestRecord is the searchable lifecycle projection for one accepted request.
type RequestRecord struct {
	ID               string     `gorm:"column:request_id;primaryKey;size:36"`
	ReplayID         string     `gorm:"column:accepted_replay_id;not null;uniqueIndex"`
	ConversationID   string     `gorm:"column:conversation_id;not null;size:36;index"`
	APIKeyID         string     `gorm:"column:api_key_id;size:255;index"`
	AccountID        string     `gorm:"column:account_id;size:255;index"`
	Endpoint         string     `gorm:"column:endpoint;not null;size:128;index"`
	Model            string     `gorm:"column:model;not null;size:256;index"`
	RequestedModel   string     `gorm:"column:requested_model;size:256;index"`
	ResolvedModel    string     `gorm:"column:resolved_model;size:256;index"`
	Mode             string     `gorm:"column:journal_mode;not null;size:16"`
	Status           string     `gorm:"column:status;not null;size:16;index"`
	CreatedAt        time.Time  `gorm:"column:created_at;not null;index:idx_requests_created"`
	AcceptedAt       time.Time  `gorm:"column:accepted_at;not null;index"`
	StartedAt        time.Time  `gorm:"column:started_at;not null"`
	UpdatedAt        time.Time  `gorm:"column:updated_at;not null;index"`
	TerminalAt       *time.Time `gorm:"column:terminal_at;index"`
	ExpiresAt        time.Time  `gorm:"column:expires_at;not null;index"`
	TerminalReplayID string     `gorm:"column:terminal_replay_id;size:36"`
	TerminalConflict bool       `gorm:"column:terminal_conflict;not null;default:false"`
	ErrorCode        string     `gorm:"column:error_code;size:128;index"`
	ErrorClass       string     `gorm:"column:error_class;size:128;index"`
	DeletingAt       *time.Time `gorm:"column:deleting_at;index"`
}

// ResponseLinkRecord maps an upstream response ID to its durable request identity.
type ResponseLinkRecord struct {
	ResponseID     string    `gorm:"column:response_id;primaryKey;size:256"`
	RequestID      string    `gorm:"column:request_id;not null;uniqueIndex;size:36"`
	ConversationID string    `gorm:"column:conversation_id;not null;index;size:36"`
	AccountID      string    `gorm:"column:account_id;index;size:255"`
	APIKeyID       string    `gorm:"column:api_key_id;index;size:255"`
	CreatedAt      time.Time `gorm:"column:created_at;not null"`
	ExpiresAt      time.Time `gorm:"column:expires_at;not null;index"`
}

// SessionAffinityRecord binds one downstream session identity to an account.
type SessionAffinityRecord struct {
	APIKeyID    string    `gorm:"column:api_key_id;primaryKey;size:255"`
	SessionHash string    `gorm:"column:session_hash;primaryKey;size:128"`
	AccountID   string    `gorm:"column:account_id;not null;index;size:255"`
	CreatedAt   time.Time `gorm:"column:created_at;not null"`
	UpdatedAt   time.Time `gorm:"column:updated_at;not null"`
	ExpiresAt   time.Time `gorm:"column:expires_at;not null;index"`
}

func (SessionAffinityRecord) TableName() string { return "session_affinities" }

func (ResponseLinkRecord) TableName() string { return "response_links" }
func (RequestRecord) TableName() string      { return "requests" }

// EncryptedPayloadRecord stores one authenticated payload envelope.
type EncryptedPayloadRecord struct {
	ID         string     `gorm:"column:id;primaryKey;size:36"`
	ReplayID   string     `gorm:"column:replay_id;not null;uniqueIndex"`
	KeyVersion uint32     `gorm:"column:key_version;not null"`
	Envelope   []byte     `gorm:"column:encrypted_envelope;not null"`
	CreatedAt  time.Time  `gorm:"column:created_at;not null"`
	ExpiresAt  time.Time  `gorm:"column:expires_at;not null;index"`
	DeletedAt  *time.Time `gorm:"column:deleted_at;index"`
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

// UsageRecord stores bounded, non-secret usage counters and reproducible estimates.
type UsageRecord struct {
	ReplayID                            string    `gorm:"column:replay_id;primaryKey;size:36"`
	RequestID                           string    `gorm:"column:request_id;not null;size:36;index"`
	InputTokens                         int64     `gorm:"column:input_tokens;not null;default:0"`
	CachedInputTokens                   int64     `gorm:"column:cached_input_tokens;not null;default:0"`
	CachedInputTokensKnown              bool      `gorm:"column:cached_input_tokens_known;not null;default:false"`
	OutputTokens                        int64     `gorm:"column:output_tokens;not null;default:0"`
	ReasoningTokens                     int64     `gorm:"column:reasoning_tokens;not null;default:0"`
	ReasoningTokensKnown                bool      `gorm:"column:reasoning_tokens_known;not null;default:false"`
	TotalTokens                         int64     `gorm:"column:total_tokens;not null;default:0"`
	ImageCount                          int64     `gorm:"column:image_count;not null;default:0"`
	PricedModel                         string    `gorm:"column:priced_model;size:256;index"`
	PricingVersionID                    *string   `gorm:"column:pricing_version_id;size:64;index"`
	EstimatedPublicCostMicrounits       *int64    `gorm:"column:estimated_public_cost_microunits"`
	AllocationVersionID                 *string   `gorm:"column:allocation_version_id;size:64;index"`
	AllocatedSubscriptionCostMicrounits *int64    `gorm:"column:allocated_subscription_cost_microunits"`
	CreatedAt                           time.Time `gorm:"column:created_at;not null;index"`
}

func (UsageRecord) TableName() string { return "usage" }

// AuditRecord stores a safe audit fact and an optional encrypted detail envelope.
type AuditRecord struct {
	ID            string    `gorm:"column:id;primaryKey;size:36"`
	RequestID     string    `gorm:"column:request_id;size:36;index:idx_audit_standalone_expiry"`
	APIKeyID      string    `gorm:"column:api_key_id;size:255;index"`
	Endpoint      string    `gorm:"column:endpoint;size:128;index"`
	EventType     string    `gorm:"column:event_type;not null;size:128;index"`
	Status        int       `gorm:"column:status;not null;index"`
	PayloadID     string    `gorm:"column:payload_id;size:36;index"`
	CreatedAt     time.Time `gorm:"column:created_at;not null;index"`
	ExpiresAt     time.Time `gorm:"column:expires_at;not null;index:idx_audit_standalone_expiry"`
	PrincipalID   string    `gorm:"column:principal_id;size:36;index"`
	PrincipalName string    `gorm:"column:principal_name;size:128"`
	Action        string    `gorm:"column:action;size:128;index"`
	TargetID      string    `gorm:"column:target_id;size:36;index"`
	Metadata      string    `gorm:"column:metadata;type:text"`
}

func (AuditRecord) TableName() string { return "audit_records" }

type lifecycleAcceptedPayload struct {
	Version        uint16 `json:"version"`
	RequestID      string `json:"request_id"`
	ConversationID string `json:"conversation_id"`
	AccountID      string `json:"account_id,omitempty"`
	Endpoint       string `json:"endpoint"`
	Model          string `json:"model"`
	APIKeyID       string `json:"api_key_id,omitempty"`
	Mode           string `json:"mode"`
}

type lifecycleAccountBoundPayload struct {
	Version        uint16 `json:"version"`
	RequestID      string `json:"request_id"`
	ConversationID string `json:"conversation_id"`
	AccountID      string `json:"account_id"`
	SessionHash    string `json:"session_hash,omitempty"`
}

type lifecycleTerminalPayload struct {
	Version uint16 `json:"version"`
	State   string `json:"state"`
	Detail  string `json:"detail,omitempty"`
}

type lifecycleUsagePayload struct {
	Version                uint16 `json:"version"`
	InputTokens            int64  `json:"input_tokens"`
	CachedInputTokens      int64  `json:"cached_input_tokens,omitempty"`
	CachedInputTokensKnown bool   `json:"cached_input_tokens_known,omitempty"`
	OutputTokens           int64  `json:"output_tokens"`
	ReasoningTokens        int64  `json:"reasoning_tokens,omitempty"`
	ReasoningTokensKnown   bool   `json:"reasoning_tokens_known,omitempty"`
	TotalTokens            int64  `json:"total_tokens"`
	ImageCount             int64  `json:"image_count"`
	ResolvedModel          string `json:"resolved_model,omitempty"`
}

func migrateAccounts(db *gorm.DB) error {
	if !db.Migrator().HasTable(&AccountRecord{}) {
		if err := db.Exec(`
			CREATE TABLE accounts (
				id TEXT PRIMARY KEY NOT NULL,
				provider TEXT NOT NULL,
				provider_account_id TEXT NOT NULL,
				credential_path TEXT NOT NULL DEFAULT '',
				enabled INTEGER NOT NULL DEFAULT 0,
				is_default INTEGER NOT NULL DEFAULT 0,
				plan_type TEXT NOT NULL DEFAULT '',
				email TEXT NOT NULL DEFAULT '',
				created_at DATETIME NOT NULL,
				updated_at DATETIME NOT NULL,
				last_seen_at DATETIME,
				cooldown_until DATETIME,
				last_error_class TEXT NOT NULL DEFAULT '',
				CHECK (provider = 'codex')
			)`).Error; err != nil {
			return fmt.Errorf("create accounts table: %w", err)
		}
	} else if !db.Migrator().HasColumn(&AccountRecord{}, "provider_account_id") {
		if err := db.Exec("ALTER TABLE accounts RENAME TO accounts_v1").Error; err != nil {
			return fmt.Errorf("rename legacy accounts table: %w", err)
		}
		if err := db.Exec(`
			CREATE TABLE accounts (
				id TEXT PRIMARY KEY NOT NULL,
				provider TEXT NOT NULL,
				provider_account_id TEXT NOT NULL,
				credential_path TEXT NOT NULL DEFAULT '',
				enabled INTEGER NOT NULL DEFAULT 0,
				is_default INTEGER NOT NULL DEFAULT 0,
				plan_type TEXT NOT NULL DEFAULT '',
				email TEXT NOT NULL DEFAULT '',
				created_at DATETIME NOT NULL,
				updated_at DATETIME NOT NULL,
				last_seen_at DATETIME,
				cooldown_until DATETIME,
				last_error_class TEXT NOT NULL DEFAULT '',
				CHECK (provider = 'codex')
			)`).Error; err != nil {
			return fmt.Errorf("create migrated accounts table: %w", err)
		}
		if err := db.Exec(`
			INSERT INTO accounts
				(id, provider, provider_account_id, credential_path, enabled, is_default,
				 plan_type, email, created_at, updated_at, last_seen_at, cooldown_until, last_error_class)
			SELECT id, provider, account_id, '', 0, 0, '', '', created_at, updated_at, NULL, NULL, ''
			FROM accounts_v1`).Error; err != nil {
			return fmt.Errorf("copy legacy accounts: %w", err)
		}
		if err := db.Exec("DROP TABLE accounts_v1").Error; err != nil {
			return fmt.Errorf("drop legacy accounts table: %w", err)
		}
	}
	if err := db.Exec("CREATE UNIQUE INDEX IF NOT EXISTS idx_accounts_provider_account_id ON accounts(provider_account_id)").Error; err != nil {
		return fmt.Errorf("index account identities: %w", err)
	}
	if err := db.Exec("CREATE UNIQUE INDEX IF NOT EXISTS idx_accounts_default ON accounts(is_default) WHERE is_default = 1").Error; err != nil {
		return fmt.Errorf("index default account: %w", err)
	}
	return nil
}

func migrateLifecycle(db *gorm.DB) error {
	if db == nil {
		return errors.New("lifecycle database is nil")
	}
	if err := migrateAccounts(db); err != nil {
		return err
	}
	if err := db.AutoMigrate(
		&AccountRecord{},
		&ConversationRecord{},
		&RequestRecord{},
		&ResponseLinkRecord{},
		&SessionAffinityRecord{},
		&EncryptedPayloadRecord{},
		&ArtifactRecord{},
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
		AccountID:      request.AccountID,
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

func lifecycleUsageDetailsBytes(value lifecycleUsagePayload) ([]byte, error) {
	if value.InputTokens < 0 || value.CachedInputTokens < 0 || value.OutputTokens < 0 || value.ReasoningTokens < 0 || value.TotalTokens < 0 || value.ImageCount < 0 {
		return nil, errors.New("usage counters are negative")
	}
	if value.CachedInputTokens > value.InputTokens || value.ReasoningTokens > value.OutputTokens {
		return nil, errors.New("usage breakdown is invalid")
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
	if !supportedLifecycleEventVersion(value.Version) || value.RequestID != request.ID || value.ConversationID != request.ConversationID {
		return errors.New("accepted lifecycle payload identity is invalid")
	}
	if value.Version >= 2 && value.AccountID != "" && value.AccountID != request.AccountID {
		return errors.New("accepted lifecycle payload account identity is invalid")
	}
	if value.Version == 1 && value.AccountID != "" {
		return errors.New("accepted lifecycle payload account version is invalid")
	}
	if value.Endpoint != request.Endpoint || value.Model != request.Model || value.APIKeyID != request.APIKeyID || value.Mode != request.Mode {
		return errors.New("accepted lifecycle payload metadata is invalid")
	}
	for name, item := range map[string]string{
		"endpoint":   value.Endpoint,
		"model":      value.Model,
		"API key ID": value.APIKeyID,
		"account ID": value.AccountID,
	} {
		if len(item) > lifecycleMaxString {
			return fmt.Errorf("lifecycle %s is too long", name)
		}
	}
	return nil
}
func validateLifecycleTerminal(value lifecycleTerminalPayload) error {
	if !supportedLifecycleEventVersion(value.Version) {
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
	if !supportedLifecycleEventVersion(value.Version) || value.InputTokens < 0 || value.CachedInputTokens < 0 || value.OutputTokens < 0 || value.ReasoningTokens < 0 || value.TotalTokens < 0 || value.ImageCount < 0 {
		return errors.New("usage lifecycle payload is invalid")
	}
	if value.CachedInputTokens > value.InputTokens || value.ReasoningTokens > value.OutputTokens {
		return errors.New("usage lifecycle payload breakdown is invalid")
	}
	const maxCounter = 1 << 31
	if value.InputTokens > maxCounter || value.CachedInputTokens > maxCounter || value.OutputTokens > maxCounter || value.ReasoningTokens > maxCounter || value.TotalTokens > maxCounter || value.ImageCount > maxCounter {
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
		if accepted.AccountID == "" {
			accepted.AccountID = request.AccountID
		}
		if err := j.materializeAccepted(tx, source, accepted); err != nil {
			return err
		}
	case source.EventType == "lifecycle.account_bound":
		var bound lifecycleAccountBoundPayload
		if err := decodeLifecycleJSON(plain, &bound, lifecycleMaxDetail); err != nil {
			return err
		}
		if err := validateLifecycleAccountBound(bound, source.RequestID); err != nil {
			return err
		}
		if err := j.materializeAccountBound(tx, source, bound); err != nil {
			return err
		}
	case source.EventType == "request.running":
		if err := j.ensureLifecycleOwner(tx, request); err != nil {
			return err
		}
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
		if err := j.ensureLifecycleOwner(tx, request); err != nil {
			return err
		}
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
		if err := j.ensureLifecycleOwner(tx, request); err != nil {
			return err
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
		if responseID, ok, err := responseLinkPayload(source.EventType, plain); err != nil {
			return err
		} else if ok {
			if err := ensureResponseLink(tx, request, responseID, source.CreatedAt, j.metadataTTL); err != nil {
				return err
			}
		}
	}
	return nil
}

func (j *Journal) materializeAccepted(tx *gorm.DB, source JournalRecord, accepted lifecycleAcceptedPayload) error {
	conversation := ConversationRecord{
		ID: accepted.ConversationID, AccountID: accepted.AccountID,
		CreatedAt: source.CreatedAt, UpdatedAt: source.CreatedAt, ExpiresAt: source.CreatedAt.Add(j.metadataTTL),
	}
	var existingConversation ConversationRecord
	err := tx.Where("id = ?", conversation.ID).First(&existingConversation).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		if err := tx.Create(&conversation).Error; err != nil {
			return fmt.Errorf("store lifecycle conversation: %w", err)
		}
	} else if err != nil {
		return fmt.Errorf("load lifecycle conversation: %w", err)
	} else if existingConversation.DeletingAt != nil {
		return errors.New("lifecycle conversation is deleting")
	} else {
		if accepted.AccountID != "" && existingConversation.AccountID != "" && existingConversation.AccountID != accepted.AccountID {
			return errors.New("lifecycle conversation account conflicts")
		}
		conversation = existingConversation
		if conversation.AccountID == "" && accepted.AccountID != "" {
			conversation.AccountID = accepted.AccountID
			if err := tx.Model(&ConversationRecord{}).Where("id = ?", conversation.ID).Update("account_id", accepted.AccountID).Error; err != nil {
				return fmt.Errorf("bind lifecycle conversation account: %w", err)
			}
		}
	}
	var row RequestRecord
	err = tx.Where("request_id = ?", accepted.RequestID).First(&row).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		row = RequestRecord{
			ID: accepted.RequestID, ReplayID: source.ReplayID, ConversationID: accepted.ConversationID,
			AccountID: accepted.AccountID, APIKeyID: accepted.APIKeyID, Endpoint: accepted.Endpoint, Model: accepted.Model,
			RequestedModel: accepted.Model, Mode: accepted.Mode, Status: requestStatusRunning,
			CreatedAt: source.CreatedAt, AcceptedAt: source.CreatedAt,
			StartedAt: source.CreatedAt, UpdatedAt: source.CreatedAt,
			ExpiresAt: source.CreatedAt.Add(j.metadataTTL),
		}
		if err := tx.Create(&row).Error; err != nil {
			return fmt.Errorf("store lifecycle request: %w", err)
		}
	} else if err != nil {
		return fmt.Errorf("load lifecycle request: %w", err)
	} else if row.DeletingAt != nil {
		return errors.New("lifecycle request is deleting")
	} else if row.ReplayID != source.ReplayID || row.ConversationID != accepted.ConversationID || row.Endpoint != accepted.Endpoint || row.Model != accepted.Model || row.APIKeyID != accepted.APIKeyID || row.Mode != accepted.Mode {
		return errors.New("lifecycle request metadata conflicts")
	} else if accepted.AccountID != "" && row.AccountID != accepted.AccountID {
		return errors.New("lifecycle request account conflicts")
	}
	result := tx.Model(&ConversationRecord{}).Where("id = ? AND deleting_at IS NULL", conversation.ID).Updates(map[string]any{
		"updated_at":    source.CreatedAt,
		"request_count": gorm.Expr("request_count + 1"),
	})
	if result.Error != nil {
		return fmt.Errorf("update lifecycle conversation: %w", result.Error)
	}
	if result.RowsAffected != 1 {
		return errors.New("lifecycle conversation was deleted during materialization")
	}
	return nil
}
func (j *Journal) ensureLifecycleOwner(tx *gorm.DB, request JournalRequest) error {
	var row RequestRecord
	if err := tx.Where("request_id = ?", request.ID).First(&row).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return errors.New("lifecycle request is missing")
		}
		return fmt.Errorf("load lifecycle request: %w", err)
	}
	if row.DeletingAt != nil {
		return errors.New("lifecycle request is deleting")
	}
	if row.ConversationID != request.ConversationID || row.AccountID != request.AccountID {
		return errors.New("lifecycle request identity conflicts")
	}
	var conversation ConversationRecord
	if err := tx.Where("id = ?", request.ConversationID).First(&conversation).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return errors.New("lifecycle conversation is missing")
		}
		return fmt.Errorf("load lifecycle conversation: %w", err)
	}
	if conversation.DeletingAt != nil {
		return errors.New("lifecycle conversation is deleting")
	}
	if conversation.AccountID != "" && conversation.AccountID != request.AccountID {
		return errors.New("lifecycle conversation account conflicts")
	}
	return nil
}

func validateLifecycleAccountBound(value lifecycleAccountBoundPayload, requestID string) error {
	if value.Version != lifecycleEventVersion || value.RequestID != requestID || value.ConversationID == "" || value.AccountID == "" {
		return errors.New("account bound lifecycle payload identity is invalid")
	}
	if len(value.AccountID) > lifecycleMaxString || len(value.SessionHash) > lifecycleMaxString {
		return errors.New("account bound lifecycle payload is too long")
	}
	return nil
}

func propagateConversationAccount(tx *gorm.DB, conversationID, accountID string, conversation ConversationRecord) error {
	if conversation.ID != conversationID {
		return errors.New("lifecycle conversation identity conflicts")
	}
	if conversation.AccountID != "" && conversation.AccountID != accountID {
		return errors.New("lifecycle conversation account conflicts")
	}
	var journalRows []JournalRequestRecord
	if err := tx.Where("conversation_id = ?", conversationID).Limit(maxConversationInputItems + 1).Find(&journalRows).Error; err != nil {
		return fmt.Errorf("load conversation journal requests for account binding: %w", err)
	}
	if len(journalRows) > maxConversationInputItems {
		return errors.New("conversation account binding request limit exceeded")
	}
	for _, row := range journalRows {
		if row.AccountID != "" && row.AccountID != accountID {
			return errors.New("conversation journal request account conflicts")
		}
	}
	var requestRows []RequestRecord
	if err := tx.Where("conversation_id = ?", conversationID).Limit(maxConversationInputItems + 1).Find(&requestRows).Error; err != nil {
		return fmt.Errorf("load conversation requests for account binding: %w", err)
	}
	if len(requestRows) > maxConversationInputItems {
		return errors.New("conversation account binding request limit exceeded")
	}
	for _, row := range requestRows {
		if row.AccountID != "" && row.AccountID != accountID {
			return errors.New("conversation request account conflicts")
		}
	}
	var links []ResponseLinkRecord
	if err := tx.Where("conversation_id = ?", conversationID).Limit(maxConversationInputItems + 1).Find(&links).Error; err != nil {
		return fmt.Errorf("load conversation response links for account binding: %w", err)
	}
	if len(links) > maxConversationInputItems {
		return errors.New("conversation response link limit exceeded")
	}
	for _, link := range links {
		if link.AccountID != "" && link.AccountID != accountID {
			return errors.New("response link account conflicts")
		}
	}
	if err := tx.Model(&JournalRequestRecord{}).Where("conversation_id = ? AND (account_id IS NULL OR account_id = '')", conversationID).Update("account_id", accountID).Error; err != nil {
		return fmt.Errorf("bind conversation journal request accounts: %w", err)
	}
	if err := tx.Model(&RequestRecord{}).Where("conversation_id = ? AND (account_id IS NULL OR account_id = '')", conversationID).Update("account_id", accountID).Error; err != nil {
		return fmt.Errorf("bind conversation request accounts: %w", err)
	}
	if err := tx.Model(&ResponseLinkRecord{}).Where("conversation_id = ? AND (account_id IS NULL OR account_id = '')", conversationID).Update("account_id", accountID).Error; err != nil {
		return fmt.Errorf("bind conversation response link accounts: %w", err)
	}
	if err := tx.Model(&ConversationRecord{}).Where("id = ? AND (account_id IS NULL OR account_id = '')", conversationID).Update("account_id", accountID).Error; err != nil {
		return fmt.Errorf("bind lifecycle conversation account: %w", err)
	}
	return nil
}

func (j *Journal) materializeAccountBound(tx *gorm.DB, source JournalRecord, bound lifecycleAccountBoundPayload) error {
	var request RequestRecord
	if err := tx.Where("request_id = ?", bound.RequestID).First(&request).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return errors.New("account bound lifecycle request is missing")
		}
		return fmt.Errorf("load account bound lifecycle request: %w", err)
	}
	if request.ConversationID != bound.ConversationID {
		return errors.New("account bound lifecycle conversation conflicts")
	}
	if request.AccountID != "" && request.AccountID != bound.AccountID {
		return errors.New("account bound lifecycle account conflicts")
	}
	var conversation ConversationRecord
	if err := tx.Where("id = ?", bound.ConversationID).First(&conversation).Error; err != nil {
		return fmt.Errorf("load account bound lifecycle conversation: %w", err)
	}
	if err := propagateConversationAccount(tx, bound.ConversationID, bound.AccountID, conversation); err != nil {
		return err
	}
	if err := ensureSessionAffinity(tx, request.APIKeyID, bound.SessionHash, bound.AccountID, source.CreatedAt, conversation.ExpiresAt); err != nil {
		return err
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
			ExpiresAt: source.CreatedAt.Add(j.payloadTTL),
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
	if err := j.ensureLifecycleOwnerByID(tx, source.RequestID); err != nil {
		return err
	}
	var existing UsageRecord
	err := tx.Where("replay_id = ?", source.ReplayID).First(&existing).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		row := UsageRecord{
			ReplayID: source.ReplayID, RequestID: source.RequestID,
			InputTokens: usage.InputTokens, CachedInputTokens: usage.CachedInputTokens,
			CachedInputTokensKnown: usage.CachedInputTokensKnown,
			OutputTokens:           usage.OutputTokens, ReasoningTokens: usage.ReasoningTokens,
			ReasoningTokensKnown: usage.ReasoningTokensKnown, TotalTokens: usage.TotalTokens,
			ImageCount: usage.ImageCount, CreatedAt: source.CreatedAt,
		}
		if err := tx.Create(&row).Error; err != nil {
			return fmt.Errorf("store lifecycle usage: %w", err)
		}
		if usage.ResolvedModel != "" {
			if err := setResolvedModel(tx, source.RequestID, usage.ResolvedModel); err != nil {
				return err
			}
		}
		return nil
	}
	if err != nil {
		return fmt.Errorf("load lifecycle usage: %w", err)
	}
	if existing.RequestID != source.RequestID ||
		existing.InputTokens != usage.InputTokens ||
		existing.CachedInputTokens != usage.CachedInputTokens ||
		existing.CachedInputTokensKnown != usage.CachedInputTokensKnown ||
		existing.OutputTokens != usage.OutputTokens ||
		existing.ReasoningTokens != usage.ReasoningTokens ||
		existing.ReasoningTokensKnown != usage.ReasoningTokensKnown ||
		existing.TotalTokens != usage.TotalTokens ||
		existing.ImageCount != usage.ImageCount {
		return errors.New("lifecycle usage conflicts")
	}
	if usage.ResolvedModel != "" {
		if err := setResolvedModel(tx, source.RequestID, usage.ResolvedModel); err != nil {
			return err
		}
	}
	return nil
}
func setResolvedModel(tx *gorm.DB, requestID, resolved string) error {
	var row RequestRecord
	if err := tx.Select("resolved_model").Where("request_id = ?", requestID).First(&row).Error; err != nil {
		return fmt.Errorf("load resolved model: %w", err)
	}
	if row.ResolvedModel != "" && row.ResolvedModel != resolved {
		return errors.New("lifecycle resolved model conflicts")
	}
	if row.ResolvedModel == "" {
		if err := tx.Model(&RequestRecord{}).Where("request_id = ? AND resolved_model = ?", requestID, "").Update("resolved_model", resolved).Error; err != nil {
			return fmt.Errorf("store resolved model: %w", err)
		}
	}
	return nil
}

func (j *Journal) ensureTerminal(tx *gorm.DB, source JournalRecord, terminal lifecycleTerminalPayload) error {
	if err := j.ensureLifecycleOwnerByID(tx, source.RequestID); err != nil {
		return err
	}
	if err := j.ensureEncryptedPayload(tx, source, mustJSON(terminal)); err != nil {
		return err
	}
	var row RequestRecord
	if err := tx.Where("request_id = ?", source.RequestID).First(&row).Error; err != nil {
		return fmt.Errorf("load lifecycle terminal request: %w", err)
	}
	errorCode, errorClass := "", ""
	if terminal.State == requestStatusFailed {
		errorCode, errorClass = "request_failed", "upstream"
	} else if terminal.State == requestStatusCanceled {
		errorCode, errorClass = "request_canceled", "canceled"
	}
	terminalUpdates := map[string]any{
		"status": terminal.State, "terminal_at": source.CreatedAt,
		"terminal_replay_id": source.ReplayID, "updated_at": source.CreatedAt,
		"expires_at": source.CreatedAt.Add(j.metadataTTL),
		"error_code": errorCode, "error_class": errorClass,
	}
	if row.TerminalAt == nil {
		now := source.CreatedAt
		result := tx.Model(&RequestRecord{}).Where("request_id = ? AND terminal_at IS NULL", source.RequestID).Updates(terminalUpdates)
		if result.Error != nil {
			return fmt.Errorf("set lifecycle terminal state: %w", result.Error)
		}
		if result.RowsAffected == 1 {
			if err := j.reconcileUsagePricing(tx, source.RequestID, now); err != nil {
				return err
			}
			if err := tx.Model(&ConversationRecord{}).Where("id = ?", row.ConversationID).Updates(map[string]any{"updated_at": now, "expires_at": now.Add(j.metadataTTL)}).Error; err != nil {
				return fmt.Errorf("update lifecycle conversation expiry: %w", err)
			}
			return nil
		}
		if err := tx.Where("request_id = ?", source.RequestID).First(&row).Error; err != nil {
			return err
		}
	}
	if row.TerminalReplayID == source.ReplayID {
		return nil
	}
	result := tx.Model(&RequestRecord{}).Where("request_id = ?", source.RequestID).Update("terminal_conflict", true)
	if result.Error != nil {
		return fmt.Errorf("flag lifecycle terminal conflict: %w", result.Error)
	}
	var existingAudit AuditRecord
	err := tx.Where("request_id = ? AND event_type = ? AND payload_id = ?", source.RequestID, "terminal.conflict", source.ReplayID).First(&existingAudit).Error
	if err == nil {
		return nil
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return fmt.Errorf("load terminal conflict audit: %w", err)
	}
	auditID, err := newJournalUUID()
	if err != nil {
		return fmt.Errorf("generate terminal conflict audit ID: %w", err)
	}
	audit := AuditRecord{ID: auditID, RequestID: source.RequestID, EventType: "terminal.conflict", Status: 409, PayloadID: source.ReplayID, CreatedAt: source.CreatedAt, ExpiresAt: source.CreatedAt.Add(j.metadataTTL)}
	if err := tx.Create(&audit).Error; err != nil {
		return fmt.Errorf("store terminal conflict audit: %w", err)
	}
	return nil
}

func (j *Journal) ensureLifecycleOwnerByID(tx *gorm.DB, requestID string) error {
	var row RequestRecord
	if err := tx.Where("request_id = ?", requestID).First(&row).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return errors.New("lifecycle request is missing")
		}
		return fmt.Errorf("load lifecycle request: %w", err)
	}
	return j.ensureLifecycleOwner(tx, JournalRequest{ID: row.ID, ConversationID: row.ConversationID, AccountID: row.AccountID})
}

func (j *Journal) decryptJournalPayload(record JournalRecord) ([]byte, error) {
	if record.KeyVersion == 0 || !supportedLifecycleEventVersion(record.EventVersion) {
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
