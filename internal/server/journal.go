package server

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/catgirl-systems/codex-sub-proxy/internal/envelope"
	"github.com/mattn/go-sqlite3"
	"gorm.io/gorm"
)

const (
	journalModeDurable       = "durable"
	journalModeBestEffort    = "best-effort"
	journalRequestEventType  = "request.accepted"
	maxJournalEventTypeBytes = 128
	maxJournalPayloadBytes   = envelope.MaxPlaintextSize
	defaultJournalQueueSize  = 64
	maxJournalQueueSize      = 4096
	defaultJournalDrain      = 10 * time.Second
	journalReplayBatchSize   = 64
)

var (
	// ErrJournalClosed indicates that the journal no longer accepts records.
	ErrJournalClosed = errors.New("journal is closed")

	// ErrSessionAffinityNotFound indicates that no nonexpired affinity exists.
	ErrSessionAffinityNotFound = errors.New("session affinity not found")

	// ErrSessionAffinityConflict indicates that another request owns a new session.
	ErrSessionAffinityConflict = errors.New("session affinity account conflict")

	// ErrConversationInputBounds indicates that reconstructed history exceeds
	// the bounded continuation contract.
	ErrConversationInputBounds = errors.New("conversation input bounds exceeded")
)

// JournalRequestRecord stores the next sequence number and safe metadata for one request.
type JournalRequestRecord struct {
	RequestID      string    `gorm:"column:request_id;primaryKey;size:36"`
	Mode           string    `gorm:"column:mode;not null;size:16"`
	NextSequence   uint64    `gorm:"column:next_sequence;not null"`
	ConversationID string    `gorm:"column:conversation_id;not null;size:36;index"`
	Endpoint       string    `gorm:"column:endpoint;not null;size:128;index"`
	Model          string    `gorm:"column:model;not null;size:256;index"`
	APIKeyID       string    `gorm:"column:api_key_id;size:255;index"`
	AccountID      string    `gorm:"column:account_id;size:255;index"`
	CreatedAt      time.Time `gorm:"column:created_at;not null"`
}

func (JournalRequestRecord) TableName() string { return "journal_requests" }

// JournalRecord is one immutable encrypted journal record and its delivery state.
type JournalRecord struct {
	ReplayID     string     `gorm:"column:replay_id;primaryKey;size:36"`
	RequestID    string     `gorm:"column:request_id;not null;size:36;index:idx_journal_request_sequence,unique"`
	Sequence     uint64     `gorm:"column:sequence;not null;index:idx_journal_request_sequence,unique"`
	Mode         string     `gorm:"column:mode;not null;size:16"`
	EventType    string     `gorm:"column:event_type;not null;size:128;index"`
	EventVersion uint16     `gorm:"column:event_version;not null"`
	KeyVersion   uint32     `gorm:"column:key_version;not null"`
	Payload      []byte     `gorm:"column:payload;not null"`
	Checksum     []byte     `gorm:"column:checksum;not null;size:32"`
	CreatedAt    time.Time  `gorm:"column:created_at;not null;index:idx_journal_created"`
	Applied      bool       `gorm:"column:applied;not null;index"`
	AppliedAt    *time.Time `gorm:"column:applied_at"`
}

func (JournalRecord) TableName() string { return "journal_records" }

// JournalReceipt is the durable spool state for one journal record.
type JournalReceipt struct {
	ReplayID       string     `gorm:"column:replay_id;primaryKey;size:36"`
	RequestID      string     `gorm:"column:request_id;not null;size:36;index"`
	Sequence       uint64     `gorm:"column:sequence;not null"`
	Mode           string     `gorm:"column:mode;not null;size:16"`
	EventType      string     `gorm:"column:event_type;not null;size:128;index"`
	EventVersion   uint16     `gorm:"column:event_version;not null"`
	KeyVersion     uint32     `gorm:"column:key_version;not null"`
	Payload        []byte     `gorm:"column:payload;not null"`
	Checksum       []byte     `gorm:"column:checksum;not null;size:32"`
	CreatedAt      time.Time  `gorm:"column:created_at;not null"`
	Materialized   bool       `gorm:"column:materialized;not null;index"`
	MaterializedAt *time.Time `gorm:"column:materialized_at"`
}

func (JournalReceipt) TableName() string { return "journal_receipts" }

// JournalRequest identifies one accepted request and its safe searchable metadata.
type JournalRequest struct {
	ID             string
	Mode           string
	ConversationID string
	Endpoint       string
	Model          string
	AccountID      string
	APIKeyID       string
}

type journalRequestState struct {
	mu              sync.Mutex
	request         JournalRequest
	requestRecord   JournalRecord
	nextSequence    uint64
	terminalClaimed bool
	terminalRecord  bool
}

type journalWork struct {
	records []JournalRecord
}

const (
	maxConversationInputItems    = 1024
	maxConversationInputBytes    = 4 * 1024 * 1024
	maxConversationJournalEvents = maxConversationInputItems*2 + 2
	maxConversationJournalBytes  = maxConversationInputBytes + 1024*1024
)

// Journal appends encrypted records and owns one bounded materializer worker.
type Journal struct {
	db            *gorm.DB
	keys          envelope.KeySet
	pricing       *PricingStore
	mode          string
	queue         chan journalWork
	replayQueue   chan string
	drainDeadline time.Duration
	payloadTTL    time.Duration
	metadataTTL   time.Duration
	lifecycleMu   sync.RWMutex
	accepting     bool
	closed        chan struct{}
	closeOnce     sync.Once
	closedOnce    sync.Once
	inFlight      sync.WaitGroup

	enqueueMu      sync.Mutex
	closing        bool
	enqueueErr     error
	workerMu       sync.Mutex
	workerStarted  bool
	workerCancel   context.CancelFunc
	workerStop     chan struct{}
	workerDone     chan struct{}
	workerStopOnce sync.Once

	requestsMu sync.Mutex
	replayMu   sync.Mutex
	requests   map[string]*journalRequestState

	errorMu   sync.Mutex
	workerErr error
	errorSink chan<- error
}

func (j *Journal) setPricingStore(pricing *PricingStore) {
	j.pricing = pricing
}

// MigrateJournal creates the journal, receipt, and lifecycle projection tables.
func MigrateJournal(db *gorm.DB) error {
	if db == nil {
		return errors.New("journal database is nil")
	}
	if err := db.AutoMigrate(&JournalRequestRecord{}, &JournalRecord{}, &JournalReceipt{}); err != nil {
		return fmt.Errorf("migrate journal: %w", err)
	}
	if err := MigratePricing(db); err != nil {
		return err
	}
	if err := migrateLifecycle(db); err != nil {
		return err
	}
	return nil
}

// newJournal keeps the old test constructor. Production startup passes keys through newJournalWithKeys.
func newJournal(db *gorm.DB, mode string, queueCapacity int, drainDeadline time.Duration) (*Journal, error) {
	key, err := envelope.NewKey(1, bytes.Repeat([]byte{0x6d}, envelope.KeySize))
	if err != nil {
		return nil, err
	}
	keys, err := envelope.NewKeySet(key)
	if err != nil {
		return nil, err
	}
	return newJournalWithKeys(db, mode, queueCapacity, drainDeadline, keys)
}

func newJournalWithKeys(db *gorm.DB, mode string, queueCapacity int, drainDeadline time.Duration, keys envelope.KeySet) (*Journal, error) {
	return newJournalWithKeysAndTTLs(db, mode, queueCapacity, drainDeadline, 24*time.Hour, 7*24*time.Hour, keys)
}

func newJournalWithKeysAndTTLs(db *gorm.DB, mode string, queueCapacity int, drainDeadline, payloadTTL, metadataTTL time.Duration, keys envelope.KeySet) (*Journal, error) {
	if db == nil {
		return nil, errors.New("journal database is nil")
	}
	validatedKeys, err := envelope.NewKeySet(keys.Active, keys.Previous...)
	if err != nil {
		return nil, fmt.Errorf("validate journal payload keys: %w", err)
	}
	if mode == "" {
		mode = journalModeDurable
	}
	if mode != journalModeDurable && mode != journalModeBestEffort {
		return nil, fmt.Errorf("journal mode %q is not supported", mode)
	}
	if queueCapacity == 0 {
		queueCapacity = defaultJournalQueueSize
	}
	if queueCapacity < 1 || queueCapacity > maxJournalQueueSize {
		return nil, fmt.Errorf("journal queue capacity must be between 1 and %d", maxJournalQueueSize)
	}
	if drainDeadline == 0 {
		drainDeadline = defaultJournalDrain
	}
	if drainDeadline <= 0 {
		return nil, errors.New("journal drain deadline must be positive")
	}
	if payloadTTL == 0 {
		payloadTTL = 24 * time.Hour
	}
	if metadataTTL == 0 {
		metadataTTL = 7 * 24 * time.Hour
	}
	if payloadTTL <= 0 || metadataTTL <= 0 {
		return nil, errors.New("journal retention durations must be positive")
	}
	return &Journal{
		db:            db,
		keys:          validatedKeys,
		mode:          mode,
		drainDeadline: drainDeadline,
		payloadTTL:    payloadTTL,
		metadataTTL:   metadataTTL,
		accepting:     true,
		closed:        make(chan struct{}),
		queue:         make(chan journalWork, queueCapacity),
		replayQueue:   make(chan string, queueCapacity),
		requests:      make(map[string]*journalRequestState),
	}, nil
}

// Start starts the single materializer worker.
func (j *Journal) Start() error {
	j.workerMu.Lock()
	defer j.workerMu.Unlock()
	if j.workerStarted {
		return nil
	}
	j.lifecycleMu.RLock()
	defer j.lifecycleMu.RUnlock()
	if !j.accepting {
		return ErrJournalClosed
	}
	ctx, cancel := context.WithCancel(context.Background())
	j.workerCancel = cancel
	j.workerStop = make(chan struct{})
	j.workerDone = make(chan struct{})
	j.workerStarted = true
	go j.runWorker(ctx)
	return nil
}

func (j *Journal) beginOperation() error {
	j.lifecycleMu.RLock()
	defer j.lifecycleMu.RUnlock()
	if !j.accepting {
		return ErrJournalClosed
	}
	j.inFlight.Add(1)
	return nil
}

func (j *Journal) endOperation() { j.inFlight.Done() }

// ErrPreviousResponseNotFound hides expired and cross-key response identities.
var ErrPreviousResponseNotFound = errors.New("previous response not found")

// ResolvePreviousResponse resolves a terminal response ID to the request metadata
// needed to continue its conversation.
func (j *Journal) ResolvePreviousResponse(ctx context.Context, responseID, apiKeyID string) (JournalRequestMetadata, error) {
	if ctx == nil {
		return JournalRequestMetadata{}, errors.New("previous response context is nil")
	}
	if responseID == "" || len(responseID) > 256 || apiKeyID == "" {
		return JournalRequestMetadata{}, ErrPreviousResponseNotFound
	}
	var link ResponseLinkRecord
	err := j.db.WithContext(ctx).Where("response_id = ? AND api_key_id = ? AND expires_at > ?", responseID, apiKeyID, time.Now().UTC()).First(&link).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return JournalRequestMetadata{}, ErrPreviousResponseNotFound
	}
	if err != nil {
		return JournalRequestMetadata{}, fmt.Errorf("resolve previous response: %w", err)
	}
	var request RequestRecord
	err = j.db.WithContext(ctx).Where("request_id = ?", link.RequestID).First(&request).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		var journalRequest JournalRequestRecord
		if err := j.db.WithContext(ctx).Where("request_id = ?", link.RequestID).First(&journalRequest).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return JournalRequestMetadata{}, ErrPreviousResponseNotFound
			}
			return JournalRequestMetadata{}, fmt.Errorf("load previous response journal request: %w", err)
		}
		request = RequestRecord{
			ID: journalRequest.RequestID, ConversationID: journalRequest.ConversationID,
			Endpoint: journalRequest.Endpoint, Model: journalRequest.Model,
			APIKeyID: journalRequest.APIKeyID, AccountID: journalRequest.AccountID,
		}
	} else if err != nil {
		return JournalRequestMetadata{}, fmt.Errorf("load previous response request: %w", err)
	}
	if request.DeletingAt != nil {
		return JournalRequestMetadata{}, ErrPreviousResponseNotFound
	}
	var conversation ConversationRecord
	conversationErr := j.db.WithContext(ctx).Where("id = ?", link.ConversationID).First(&conversation).Error
	if conversationErr == nil {
		if conversation.DeletingAt != nil {
			return JournalRequestMetadata{}, ErrPreviousResponseNotFound
		}
	} else if !errors.Is(conversationErr, gorm.ErrRecordNotFound) {
		return JournalRequestMetadata{}, fmt.Errorf("load previous response conversation: %w", conversationErr)
	}
	if request.ConversationID != link.ConversationID || request.APIKeyID != link.APIKeyID || request.AccountID != link.AccountID {
		return JournalRequestMetadata{}, ErrPreviousResponseNotFound
	}
	return JournalRequestMetadata{
		Endpoint: request.Endpoint, Model: request.Model, APIKeyID: link.APIKeyID,
		ConversationID: link.ConversationID, AccountID: link.AccountID,
		SourceRequestID: link.RequestID,
	}, nil
}

// ResolveSessionAffinity returns the account bound to one nonexpired session hash.
func (j *Journal) ResolveSessionAffinity(ctx context.Context, apiKeyID, sessionHash string) (string, error) {
	if ctx == nil {
		return "", errors.New("session affinity context is nil")
	}
	if apiKeyID == "" || len(apiKeyID) > lifecycleMaxString ||
		len(sessionHash) != sha256.Size*2 {
		return "", ErrSessionAffinityNotFound
	}
	if _, err := hex.DecodeString(sessionHash); err != nil {
		return "", ErrSessionAffinityNotFound
	}
	var affinity SessionAffinityRecord
	err := j.db.WithContext(ctx).Where(
		"api_key_id = ? AND session_hash = ? AND expires_at > ?",
		apiKeyID, sessionHash, time.Now().UTC(),
	).First(&affinity).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return "", ErrSessionAffinityNotFound
	}
	if err != nil {
		return "", fmt.Errorf("resolve session affinity: %w", err)
	}
	if affinity.AccountID == "" {
		return "", ErrSessionAffinityNotFound
	}
	return affinity.AccountID, nil
}

// LoadConversationInput reconstructs bounded input and output items from the
// encrypted journal records for one conversation.
func (j *Journal) LoadConversationInput(ctx context.Context, conversationID string) ([]json.RawMessage, error) {
	return j.LoadConversationInputThrough(ctx, conversationID, "")
}

// LoadConversationInputThrough reconstructs history up to and including the
// request identified by cutoffRequestID. An empty cutoff includes the full
// conversation.
func (j *Journal) LoadConversationInputThrough(ctx context.Context, conversationID, cutoffRequestID string) ([]json.RawMessage, error) {
	if ctx == nil {
		return nil, errors.New("conversation input context is nil")
	}
	if conversationID == "" {
		return nil, errors.New("conversation ID is empty")
	}
	type conversationRequest struct {
		record     RequestRecord
		acceptedAt time.Time
	}
	var cutoffAcceptedAt time.Time
	if cutoffRequestID != "" {
		if len(cutoffRequestID) > 36 {
			return nil, ErrPreviousResponseNotFound
		}
		var cutoff RequestRecord
		err := j.db.WithContext(ctx).Where("request_id = ?", cutoffRequestID).First(&cutoff).Error
		if errors.Is(err, gorm.ErrRecordNotFound) {
			var journalCutoff JournalRequestRecord
			if fallbackErr := j.db.WithContext(ctx).Where("request_id = ?", cutoffRequestID).First(&journalCutoff).Error; fallbackErr != nil {
				if errors.Is(fallbackErr, gorm.ErrRecordNotFound) {
					return nil, ErrPreviousResponseNotFound
				}
				return nil, fmt.Errorf("load conversation cutoff journal request: %w", fallbackErr)
			}
			cutoff = RequestRecord{
				ID: journalCutoff.RequestID, ConversationID: journalCutoff.ConversationID,
				AcceptedAt: journalCutoff.CreatedAt,
			}
		} else if err != nil {
			return nil, fmt.Errorf("load conversation cutoff request: %w", err)
		}
		if cutoff.ConversationID != conversationID || cutoff.AcceptedAt.IsZero() {
			return nil, ErrPreviousResponseNotFound
		}
		cutoffAcceptedAt = cutoff.AcceptedAt
	}
	requestsByID := make(map[string]conversationRequest, maxConversationInputItems+1)
	lifecycleQuery := j.db.WithContext(ctx).Where("conversation_id = ?", conversationID)
	if cutoffRequestID != "" {
		lifecycleQuery = lifecycleQuery.Where(
			"(accepted_at < ? OR (accepted_at = ? AND request_id <= ?))",
			cutoffAcceptedAt, cutoffAcceptedAt, cutoffRequestID,
		)
	}
	var lifecycleRequests []RequestRecord
	if err := lifecycleQuery.Order("accepted_at ASC, request_id ASC").Limit(maxConversationInputItems + 1).Find(&lifecycleRequests).Error; err != nil {
		return nil, fmt.Errorf("load conversation requests: %w", err)
	}
	if len(lifecycleRequests) > maxConversationInputItems {
		return nil, fmt.Errorf("%w: conversation input item limit exceeded", ErrConversationInputBounds)
	}
	for _, request := range lifecycleRequests {
		requestsByID[request.ID] = conversationRequest{record: request, acceptedAt: request.AcceptedAt}
	}
	journalQuery := j.db.WithContext(ctx).Where("conversation_id = ?", conversationID)
	if cutoffRequestID != "" {
		journalQuery = journalQuery.Where(
			"(created_at < ? OR (created_at = ? AND request_id <= ?))",
			cutoffAcceptedAt, cutoffAcceptedAt, cutoffRequestID,
		)
	}
	var journalRequests []JournalRequestRecord
	if err := journalQuery.Order("created_at ASC, request_id ASC").Limit(maxConversationInputItems + 1).Find(&journalRequests).Error; err != nil {
		return nil, fmt.Errorf("load conversation journal requests: %w", err)
	}
	if len(journalRequests) > maxConversationInputItems {
		return nil, fmt.Errorf("%w: conversation input item limit exceeded", ErrConversationInputBounds)
	}
	for _, journalRequest := range journalRequests {
		if existing, ok := requestsByID[journalRequest.RequestID]; ok {
			if existing.acceptedAt.IsZero() {
				existing.acceptedAt = journalRequest.CreatedAt
				existing.record.AcceptedAt = journalRequest.CreatedAt
				requestsByID[journalRequest.RequestID] = existing
			}
			continue
		}
		requestsByID[journalRequest.RequestID] = conversationRequest{
			record: RequestRecord{
				ID: journalRequest.RequestID, ConversationID: journalRequest.ConversationID,
				APIKeyID: journalRequest.APIKeyID, AccountID: journalRequest.AccountID,
				Endpoint: journalRequest.Endpoint, Model: journalRequest.Model, Mode: journalRequest.Mode,
				AcceptedAt: journalRequest.CreatedAt,
			},
			acceptedAt: journalRequest.CreatedAt,
		}
	}
	requests := make([]RequestRecord, 0, len(requestsByID))
	for _, candidate := range requestsByID {
		if cutoffRequestID != "" &&
			(candidate.acceptedAt.After(cutoffAcceptedAt) ||
				(candidate.acceptedAt.Equal(cutoffAcceptedAt) && candidate.record.ID > cutoffRequestID)) {
			continue
		}
		requests = append(requests, candidate.record)
	}
	sort.Slice(requests, func(left, right int) bool {
		if requests[left].AcceptedAt.Equal(requests[right].AcceptedAt) {
			return requests[left].ID < requests[right].ID
		}
		return requests[left].AcceptedAt.Before(requests[right].AcceptedAt)
	})
	if len(requests) > maxConversationInputItems {
		return nil, fmt.Errorf("%w: conversation input item limit exceeded", ErrConversationInputBounds)
	}
	var records []json.RawMessage
	totalBytes := 0
	appendItem := func(item []byte) error {
		item = bytes.TrimSpace(item)
		if len(item) == 0 || !json.Valid(item) {
			return errors.New("conversation input item is invalid JSON")
		}
		if len(records) >= maxConversationInputItems || totalBytes+len(item) > maxConversationInputBytes {
			return fmt.Errorf("%w: conversation input bounds exceeded", ErrConversationInputBounds)
		}
		records = append(records, append(json.RawMessage(nil), item...))
		totalBytes += len(item)
		return nil
	}
	validateOutputItem := func(item []byte) (json.RawMessage, error) {
		item = bytes.TrimSpace(item)
		if len(item) == 0 || !json.Valid(item) {
			return nil, errors.New("conversation input item is invalid JSON")
		}
		return append(json.RawMessage(nil), item...), nil
	}
	eventCount := 0
	eventBytes := 0
	for _, request := range requests {
		var terminalOutput []json.RawMessage
		var terminalFound bool
		var streamedOutput []json.RawMessage
		requestSucceeded := false
		rows, err := j.db.WithContext(ctx).Model(&JournalRecord{}).Where("request_id = ? AND event_type IN ?", request.ID, []string{"request.input", "request.terminal", "response.json", "response.completed", "response.incomplete", "response.output_item.done"}).Order("sequence ASC").Rows()
		if err != nil {
			return nil, fmt.Errorf("load conversation journal events: %w", err)
		}
		for rows.Next() {
			eventCount++
			var event JournalRecord
			if err := j.db.ScanRows(rows, &event); err != nil {
				_ = rows.Close()
				return nil, fmt.Errorf("scan conversation journal event: %w", err)
			}
			if err := validateJournalRecord(event); err != nil {
				_ = rows.Close()
				return nil, fmt.Errorf("validate conversation journal event %q: %w", event.ReplayID, err)
			}
			eventBytes += len(event.Payload)
			if eventCount > maxConversationJournalEvents || eventBytes > maxConversationJournalBytes {
				_ = rows.Close()
				return nil, fmt.Errorf("%w: conversation journal bounds exceeded", ErrConversationInputBounds)
			}
			plain, err := j.decryptJournalPayload(event)
			if err != nil {
				_ = rows.Close()
				return nil, fmt.Errorf("decrypt conversation journal event %q: %w", event.ReplayID, err)
			}
			switch event.EventType {
			case "request.input":
				var envelope struct {
					Input json.RawMessage `json:"input"`
				}
				if len(bytes.TrimSpace(plain)) > 0 && bytes.TrimSpace(plain)[0] == '{' {
					if err := json.Unmarshal(plain, &envelope); err != nil {
						_ = rows.Close()
						return nil, fmt.Errorf("decode conversation request input: %w", err)
					}
					plain = envelope.Input
				}
				if len(bytes.TrimSpace(plain)) == 0 || bytes.Equal(bytes.TrimSpace(plain), []byte("null")) {
					continue
				}
				var items []json.RawMessage
				if err := json.Unmarshal(plain, &items); err == nil {
					for _, item := range items {
						if err := appendItem(item); err != nil {
							_ = rows.Close()
							return nil, err
						}
					}
					continue
				}
				if err := appendItem(plain); err != nil {
					_ = rows.Close()
					return nil, err
				}
			case "request.terminal":
				var terminal lifecycleTerminalPayload
				if err := decodeLifecycleJSON(plain, &terminal, lifecycleMaxDetail); err != nil {
					_ = rows.Close()
					return nil, fmt.Errorf("decode conversation terminal event: %w", err)
				}
				if err := validateLifecycleTerminal(terminal); err != nil {
					_ = rows.Close()
					return nil, fmt.Errorf("validate conversation terminal event: %w", err)
				}
				if terminal.State == requestStatusSucceeded {
					requestSucceeded = true
				}
			case "response.json", "response.completed", "response.incomplete":
				data := bytes.TrimSpace(plain)
				if bytes.HasPrefix(data, []byte("data:")) {
					data = bytes.TrimSpace(bytes.TrimPrefix(data, []byte("data:")))
					if index := bytes.IndexByte(data, '\n'); index >= 0 {
						data = bytes.TrimSpace(data[:index])
					}
				}
				var response struct {
					Status   string            `json:"status"`
					Object   string            `json:"object"`
					Output   []json.RawMessage `json:"output"`
					Response *struct {
						Status string            `json:"status"`
						Object string            `json:"object"`
						Output []json.RawMessage `json:"output"`
					} `json:"response,omitempty"`
				}
				if err := json.Unmarshal(data, &response); err != nil {
					_ = rows.Close()
					return nil, fmt.Errorf("decode conversation response: %w", err)
				}
				status, object, output := response.Status, response.Object, response.Output
				if response.Response != nil {
					status, object, output = response.Response.Status, response.Response.Object, response.Response.Output
				}
				if object != "response.compaction" &&
					status != "completed" && status != "incomplete" {
					continue
				}
				if output == nil {
					if event.EventType == "response.json" {
						_ = rows.Close()
						return nil, errors.New("conversation terminal response output is missing")
					}
					continue
				}
				var validatedOutput []json.RawMessage
				for _, item := range output {
					validated, err := validateOutputItem(item)
					if err != nil {
						_ = rows.Close()
						return nil, err
					}
					validatedOutput = append(validatedOutput, validated)
				}
				terminalFound = true
				terminalOutput = validatedOutput
			case "response.output_item.done":
				data := bytes.TrimSpace(plain)
				if bytes.HasPrefix(data, []byte("data:")) {
					data = bytes.TrimSpace(bytes.TrimPrefix(data, []byte("data:")))
					if index := bytes.IndexByte(data, '\n'); index >= 0 {
						data = bytes.TrimSpace(data[:index])
					}
				}
				var event struct {
					Item json.RawMessage `json:"item"`
				}
				if err := json.Unmarshal(data, &event); err != nil {
					_ = rows.Close()
					return nil, fmt.Errorf("decode conversation output event: %w", err)
				}
				validated, err := validateOutputItem(event.Item)
				if err != nil {
					_ = rows.Close()
					return nil, err
				}
				streamedOutput = append(streamedOutput, validated)
			}
		}
		if err := rows.Err(); err != nil {
			_ = rows.Close()
			return nil, fmt.Errorf("iterate conversation journal events: %w", err)
		}
		if err := rows.Close(); err != nil {
			return nil, fmt.Errorf("close conversation journal events: %w", err)
		}
		if terminalFound {
			for _, item := range terminalOutput {
				if err := appendItem(item); err != nil {
					return nil, err
				}
			}
		} else if requestSucceeded {
			for _, item := range streamedOutput {
				if err := appendItem(item); err != nil {
					return nil, err
				}
			}
		}
	}
	return records, nil
}

// BeginRequest creates an identity for one accepted request.
func (j *Journal) BeginRequest(ctx context.Context) (JournalRequest, error) {
	return j.BeginRequestWithMetadata(ctx, JournalRequestMetadata{Endpoint: "unknown", Model: "unknown"}, nil)
}

// BeginRequestWithMetadata appends accepted, running, and input lifecycle events.
func (j *Journal) BeginRequestWithMetadata(ctx context.Context, metadata JournalRequestMetadata, input []byte) (JournalRequest, error) {
	if ctx == nil {

		return JournalRequest{}, errors.New("journal request context is nil")
	}
	if err := validateJournalEvent("request.input", input); err != nil {
		return JournalRequest{}, err
	}
	if err := j.beginOperation(); err != nil {
		return JournalRequest{}, err
	}
	defer j.endOperation()
	requestID, err := newJournalUUID()
	if err != nil {
		return JournalRequest{}, fmt.Errorf("generate journal request ID: %w", err)
	}
	endpoint := metadata.Endpoint
	if endpoint == "" {
		endpoint = "unknown"
	}
	model := metadata.Model
	if model == "" {
		model = "unknown"
	}
	conversationID := metadata.ConversationID
	if conversationID == "" {
		conversationID = deriveConversationID(metadata.ConversationHint)
	}
	if conversationID == "" {
		conversationID, err = newJournalUUID()
		if err != nil {
			return JournalRequest{}, fmt.Errorf("generate conversation ID: %w", err)
		}
	}
	request := JournalRequest{
		ID: requestID, Mode: j.mode, ConversationID: conversationID,
		Endpoint: endpoint, Model: model, APIKeyID: metadata.APIKeyID, AccountID: metadata.AccountID,
	}
	acceptedPayload, err := lifecycleAcceptedBytes(request)
	if err != nil {
		return JournalRequest{}, err
	}
	requestReplayID, err := newJournalUUID()
	if err != nil {
		return JournalRequest{}, fmt.Errorf("generate accepted replay ID: %w", err)
	}
	requestRecord, err := j.newEncryptedRecord(requestReplayID, request.ID, 0, request.Mode, journalRequestEventType, acceptedPayload, true)
	if err != nil {
		return JournalRequest{}, err
	}
	state := &journalRequestState{request: request, requestRecord: requestRecord, nextSequence: 1}
	j.requestsMu.Lock()
	if err := j.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var conversation ConversationRecord
		conversationErr := tx.Select("deleting_at").Where("id = ?", conversationID).First(&conversation).Error
		if conversationErr == nil && conversation.DeletingAt != nil {
			return ErrPreviousResponseNotFound
		}
		if conversationErr != nil && !errors.Is(conversationErr, gorm.ErrRecordNotFound) {
			return fmt.Errorf("check journal conversation lifecycle: %w", conversationErr)
		}
		if metadata.PreviousResponseID != "" {
			var link ResponseLinkRecord
			linkErr := tx.Where("response_id = ? AND api_key_id = ? AND expires_at > ?", metadata.PreviousResponseID, metadata.APIKeyID, time.Now().UTC()).First(&link).Error
			if errors.Is(linkErr, gorm.ErrRecordNotFound) {
				return ErrPreviousResponseNotFound
			}
			if linkErr != nil {
				return fmt.Errorf("load previous response link for journal request: %w", linkErr)
			}
			if link.ConversationID != conversationID || link.AccountID != metadata.AccountID {
				return ErrPreviousResponseNotFound
			}
			var owner RequestRecord
			ownerErr := tx.Where("request_id = ?", link.RequestID).First(&owner).Error
			if errors.Is(ownerErr, gorm.ErrRecordNotFound) {
				var ownerJournal JournalRequestRecord
				ownerJournalErr := tx.Where("request_id = ?", link.RequestID).First(&ownerJournal).Error
				if errors.Is(ownerJournalErr, gorm.ErrRecordNotFound) {
					return ErrPreviousResponseNotFound
				}
				if ownerJournalErr != nil {
					return fmt.Errorf("load previous response journal request: %w", ownerJournalErr)
				}
				if ownerJournal.ConversationID != link.ConversationID || ownerJournal.APIKeyID != link.APIKeyID || ownerJournal.AccountID != link.AccountID {
					return ErrPreviousResponseNotFound
				}
			} else if ownerErr != nil {
				return fmt.Errorf("load previous response owner: %w", ownerErr)
			} else if owner.DeletingAt != nil || owner.ConversationID != link.ConversationID || owner.APIKeyID != link.APIKeyID || owner.AccountID != link.AccountID {
				return ErrPreviousResponseNotFound
			}
		}
		row := JournalRequestRecord{
			RequestID: request.ID, Mode: request.Mode, NextSequence: 1,
			ConversationID: request.ConversationID, Endpoint: request.Endpoint,
			Model: request.Model, APIKeyID: request.APIKeyID, AccountID: request.AccountID,
			CreatedAt: requestRecord.CreatedAt,
		}
		if err := tx.Create(&row).Error; err != nil {
			return fmt.Errorf("store journal request: %w", err)
		}
		if err := validateJournalRecord(requestRecord); err != nil {
			return err
		}
		if err := tx.Create(&requestRecord).Error; err != nil {
			return fmt.Errorf("store journal request record: %w", err)
		}
		return nil
	}); err != nil {
		j.requestsMu.Unlock()
		return JournalRequest{}, err
	}
	j.requests[request.ID] = state
	j.requestsMu.Unlock()
	if len(input) != 0 {
		if err := j.appendInternal(ctx, state, "request.running", nil); err != nil {
			j.deleteRequest(request.ID)
			return JournalRequest{}, err
		}
		if err := j.appendInternal(ctx, state, "request.input", input); err != nil {
			j.deleteRequest(request.ID)
			return JournalRequest{}, err
		}
	}
	return request, nil
}

func (j *Journal) newEncryptedRecord(replayID, requestID string, sequence uint64, mode, eventType string, plain []byte, applied bool) (JournalRecord, error) {
	if !validJournalUUID(replayID) || !validJournalUUID(requestID) {
		return JournalRecord{}, errors.New("journal record ID is invalid")
	}
	if err := validateJournalMode(mode); err != nil {
		return JournalRecord{}, err
	}
	if err := validateJournalEvent(eventType, plain); err != nil {
		return JournalRecord{}, err
	}
	encrypted, err := envelope.Encrypt(plain, envelope.PayloadDomain, j.keys)
	if err != nil {
		return JournalRecord{}, fmt.Errorf("encrypt journal payload: %w", err)
	}
	if err := validateJournalEnvelope(encrypted); err != nil {
		return JournalRecord{}, err
	}
	record := JournalRecord{
		ReplayID: replayID, RequestID: requestID, Sequence: sequence, Mode: mode,
		EventType: eventType, EventVersion: lifecycleEventVersion, KeyVersion: j.keys.Active.Version,
		Payload: encrypted, CreatedAt: time.Now().UTC(), Applied: applied,
	}
	record.Checksum = journalChecksum(record)
	return record, nil
}
func responseLinkPayload(eventType string, payload []byte) (string, bool, error) {
	if eventType != "response.json" && eventType != "response.completed" && eventType != "response.incomplete" {
		return "", false, nil
	}
	data := bytes.TrimSpace(payload)
	if bytes.HasPrefix(data, []byte("data:")) {
		data = bytes.TrimSpace(bytes.TrimPrefix(data, []byte("data:")))
		if index := bytes.IndexByte(data, '\n'); index >= 0 {
			data = bytes.TrimSpace(data[:index])
		}
	}
	var envelope struct {
		Type     string `json:"type"`
		Object   string `json:"object"`
		ID       string `json:"id"`
		Status   string `json:"status"`
		Response *struct {
			ID     string `json:"id"`
			Status string `json:"status"`
		} `json:"response,omitempty"`
	}
	if err := json.Unmarshal(data, &envelope); err != nil {
		return "", false, nil
	}
	id, status := envelope.ID, envelope.Status
	switch eventType {
	case "response.completed", "response.incomplete":
		if envelope.Response == nil {
			return "", false, nil
		}
		if envelope.Type != "" && envelope.Type != eventType {
			return "", false, nil
		}
		id, status = envelope.Response.ID, envelope.Response.Status
		expectedStatus := "completed"
		if eventType == "response.incomplete" {
			expectedStatus = "incomplete"
		}
		if status != "" && status != expectedStatus {
			return "", false, nil
		}
		status = expectedStatus
	}
	if eventType == "response.json" && envelope.Object == "response.compaction" {
		if id == "" {
			return "", false, nil
		}
		if len(id) > 256 {
			return "", false, errors.New("terminal response link ID is too long")
		}
		return id, true, nil
	}
	if id == "" || (status != "completed" && status != "incomplete") {
		return "", false, nil
	}
	if len(id) > 256 {
		return "", false, errors.New("terminal response link ID is too long")
	}
	return id, true, nil
}
func ensureResponseLink(tx *gorm.DB, request JournalRequest, responseID string, createdAt time.Time, metadataTTL time.Duration) error {
	if responseID == "" {
		return nil
	}
	link := ResponseLinkRecord{
		ResponseID: responseID, RequestID: request.ID, ConversationID: request.ConversationID,
		AccountID: request.AccountID, APIKeyID: request.APIKeyID,
		CreatedAt: createdAt, ExpiresAt: createdAt.Add(metadataTTL),
	}
	var lifecycle RequestRecord
	err := tx.Where("request_id = ?", request.ID).First(&lifecycle).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		var journalRow JournalRequestRecord
		if err := tx.Where("request_id = ?", request.ID).First(&journalRow).Error; err != nil {
			return fmt.Errorf("load journal request for response link: %w", err)
		}
	} else if err != nil {
		return fmt.Errorf("load response link request: %w", err)
	}
	var existing ResponseLinkRecord
	err = tx.Where("response_id = ?", responseID).First(&existing).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		if err := tx.Create(&link).Error; err != nil {
			return fmt.Errorf("store response link: %w", err)
		}
		return nil
	}
	if err != nil {
		return fmt.Errorf("load response link: %w", err)
	}
	if existing.RequestID != link.RequestID || existing.ConversationID != link.ConversationID || existing.AccountID != link.AccountID || existing.APIKeyID != link.APIKeyID {
		return errors.New("response link identity conflicts")
	}
	if existing.ExpiresAt.Before(link.ExpiresAt) {
		if err := tx.Model(&ResponseLinkRecord{}).Where("response_id = ?", responseID).Update("expires_at", link.ExpiresAt).Error; err != nil {
			return fmt.Errorf("refresh response link expiry: %w", err)
		}
	}
	return nil
}

func isUniqueSessionAffinityInsertError(err error) bool {
	var sqliteErr sqlite3.Error
	if !errors.As(err, &sqliteErr) {
		return false
	}
	return sqliteErr.ExtendedCode == sqlite3.ErrConstraintUnique ||
		sqliteErr.ExtendedCode == sqlite3.ErrConstraintPrimaryKey
}

func ensureSessionAffinity(tx *gorm.DB, apiKeyID, sessionHash, accountID string, createdAt, expiresAt time.Time) error {
	if sessionHash == "" {
		return nil
	}
	affinity := SessionAffinityRecord{
		APIKeyID: apiKeyID, SessionHash: sessionHash, AccountID: accountID,
		CreatedAt: createdAt, UpdatedAt: createdAt, ExpiresAt: expiresAt,
	}
	var existing SessionAffinityRecord
	err := tx.Where("api_key_id = ? AND session_hash = ?", apiKeyID, sessionHash).First(&existing).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		if err := tx.Create(&affinity).Error; err != nil {
			if !isUniqueSessionAffinityInsertError(err) {
				return fmt.Errorf("store session affinity: %w", err)
			}
			if lookupErr := tx.Where("api_key_id = ? AND session_hash = ?", apiKeyID, sessionHash).First(&existing).Error; lookupErr != nil {
				if errors.Is(lookupErr, gorm.ErrRecordNotFound) {
					return fmt.Errorf("store session affinity: %w", err)
				}
				return fmt.Errorf("load concurrent session affinity: %w", lookupErr)
			}
		} else {
			return nil
		}
	} else if err != nil {
		return fmt.Errorf("load session affinity: %w", err)
	}
	if existing.AccountID != accountID && existing.ExpiresAt.After(createdAt) {
		return fmt.Errorf("%w: account %q already owns the session", ErrSessionAffinityConflict, existing.AccountID)
	}
	if err := tx.Model(&SessionAffinityRecord{}).Where("api_key_id = ? AND session_hash = ?", apiKeyID, sessionHash).Updates(map[string]any{
		"account_id": accountID, "created_at": createdAt, "updated_at": createdAt, "expires_at": expiresAt,
	}).Error; err != nil {
		return fmt.Errorf("refresh session affinity: %w", err)
	}
	return nil
}

// BindAccount durably binds one accepted request and its conversation to an account.
func (j *Journal) BindAccount(ctx context.Context, requestID, accountID, sessionHash string) error {
	if ctx == nil {
		return errors.New("journal bind context is nil")
	}
	if requestID == "" || accountID == "" || len(accountID) > lifecycleMaxString || len(sessionHash) > lifecycleMaxString {
		return errors.New("journal account binding is invalid")
	}
	if sessionHash != "" {
		if len(sessionHash) != sha256.Size*2 {
			return errors.New("journal account binding session hash is invalid")
		}
		if _, err := hex.DecodeString(sessionHash); err != nil {
			return errors.New("journal account binding session hash is invalid")
		}
	}
	if err := j.beginOperation(); err != nil {
		return err
	}
	defer j.endOperation()
	j.requestsMu.Lock()
	defer j.requestsMu.Unlock()
	state := j.requests[requestID]
	if state == nil {
		return fmt.Errorf("journal request %q is unknown", requestID)
	}
	conversationStates := make([]*journalRequestState, 0, maxConversationInputItems+1)
	for _, candidate := range j.requests {
		if candidate.request.ConversationID != state.request.ConversationID {
			continue
		}
		conversationStates = append(conversationStates, candidate)
		if len(conversationStates) > maxConversationInputItems {
			return errors.New("journal conversation request limit exceeded")
		}
	}
	sort.Slice(conversationStates, func(left, right int) bool {
		return conversationStates[left].request.ID < conversationStates[right].request.ID
	})
	for _, candidate := range conversationStates {
		candidate.mu.Lock()
	}
	defer func() {
		for index := len(conversationStates) - 1; index >= 0; index-- {
			conversationStates[index].mu.Unlock()
		}
	}()
	alreadyBound := state.request.AccountID == accountID && sessionHash == ""
	if state.request.AccountID != "" && state.request.AccountID != accountID {
		return errors.New("journal request account conflicts")
	}
	replayID, err := newJournalUUID()
	if err != nil {
		return fmt.Errorf("generate account binding replay ID: %w", err)
	}
	payload, err := json.Marshal(lifecycleAccountBoundPayload{
		Version: lifecycleEventVersion, RequestID: requestID,
		ConversationID: state.request.ConversationID, AccountID: accountID, SessionHash: sessionHash,
	})
	if err != nil {
		return fmt.Errorf("encode account binding lifecycle event: %w", err)
	}
	record, err := j.newEncryptedRecord(replayID, requestID, state.nextSequence, state.request.Mode, "lifecycle.account_bound", payload, true)
	if err != nil {
		return err
	}
	if err := j.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var journalRow JournalRequestRecord
		if err := tx.Where("request_id = ?", requestID).First(&journalRow).Error; err != nil {
			return fmt.Errorf("load journal request for account binding: %w", err)
		}
		if journalRow.AccountID != "" && journalRow.AccountID != accountID {
			return errors.New("journal request account conflicts")
		}
		var lifecycle RequestRecord
		lifecycleErr := tx.Where("request_id = ?", requestID).First(&lifecycle).Error
		if errors.Is(lifecycleErr, gorm.ErrRecordNotFound) {
			if err := j.materializeRecord(tx, state.requestRecord, state.request); err != nil {
				return fmt.Errorf("materialize accepted request for account binding: %w", err)
			}
			var receipt JournalReceipt
			receiptErr := tx.Where("replay_id = ?", state.requestRecord.ReplayID).First(&receipt).Error
			if errors.Is(receiptErr, gorm.ErrRecordNotFound) {
				now := time.Now().UTC()
				receipt = JournalReceipt{
					ReplayID: state.requestRecord.ReplayID, RequestID: state.requestRecord.RequestID,
					Sequence: state.requestRecord.Sequence, Mode: state.requestRecord.Mode,
					EventType: state.requestRecord.EventType, EventVersion: state.requestRecord.EventVersion,
					KeyVersion: state.requestRecord.KeyVersion, Payload: append([]byte(nil), state.requestRecord.Payload...),
					Checksum: append([]byte(nil), state.requestRecord.Checksum...), CreatedAt: state.requestRecord.CreatedAt,
					Materialized: true, MaterializedAt: &now,
				}
				if err := tx.Create(&receipt).Error; err != nil {
					return fmt.Errorf("store accepted account-binding receipt: %w", err)
				}
			} else if receiptErr != nil {
				return fmt.Errorf("load accepted account-binding receipt: %w", receiptErr)
			}
			if err := tx.Where("request_id = ?", requestID).First(&lifecycle).Error; err != nil {
				return fmt.Errorf("load materialized lifecycle request for account binding: %w", err)
			}
		} else if lifecycleErr != nil {
			return fmt.Errorf("load lifecycle request for account binding: %w", lifecycleErr)
		}
		if lifecycle.AccountID != "" && lifecycle.AccountID != accountID {
			return errors.New("lifecycle request account conflicts")
		}
		var conversation ConversationRecord
		conversationErr := tx.Where("id = ?", state.request.ConversationID).First(&conversation).Error
		if errors.Is(conversationErr, gorm.ErrRecordNotFound) {
			conversation = ConversationRecord{
				ID: state.request.ConversationID, AccountID: accountID,
				CreatedAt: state.requestRecord.CreatedAt, UpdatedAt: state.requestRecord.CreatedAt,
				ExpiresAt: state.requestRecord.CreatedAt.Add(j.metadataTTL), RequestCount: 1,
			}
			if err := tx.Create(&conversation).Error; err != nil {
				return fmt.Errorf("create lifecycle conversation for account binding: %w", err)
			}
		} else if conversationErr != nil {
			return fmt.Errorf("load lifecycle conversation for account binding: %w", conversationErr)
		}
		if err := propagateConversationAccount(tx, state.request.ConversationID, accountID, conversation); err != nil {
			return err
		}
		if err := ensureSessionAffinity(tx, state.request.APIKeyID, sessionHash, accountID, time.Now().UTC(), conversation.ExpiresAt); err != nil {
			return err
		}
		if !alreadyBound {
			if err := tx.Model(&JournalRequestRecord{}).Where("request_id = ?", requestID).Update("next_sequence", journalRow.NextSequence+1).Error; err != nil {
				return fmt.Errorf("advance journal request %q after account binding: %w", requestID, err)
			}
			record.Sequence = journalRow.NextSequence
			record.Checksum = journalChecksum(record)
			if err := validateJournalRecord(record); err != nil {
				return err
			}
			if err := tx.Create(&record).Error; err != nil {
				return fmt.Errorf("store account binding lifecycle event: %w", err)
			}
		}
		return nil
	}); err != nil {
		return err
	}
	for _, candidate := range conversationStates {
		if candidate.request.AccountID == "" {
			candidate.request.AccountID = accountID
		}
	}
	state.request.AccountID = accountID
	if !alreadyBound {
		state.nextSequence++
		j.enqueueReplay(replayID)
	}
	return nil
}

// Forward appends an encrypted event before invoking its live receiver.
func (j *Journal) Forward(ctx context.Context, request JournalRequest, eventType string, payload []byte, apply func(context.Context, string) error) error {
	if ctx == nil {
		return errors.New("journal forward context is nil")
	}
	if apply == nil {
		return errors.New("journal forward callback is nil")
	}
	if err := j.beginOperation(); err != nil {
		return err
	}
	defer j.endOperation()
	state := j.requestState(request)
	if state == nil {
		return fmt.Errorf("journal request %q is unknown", request.ID)
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	request = state.request
	responseID, responseLinkOK, err := responseLinkPayload(eventType, payload)
	if err != nil {
		return err
	}
	replayID, err := newJournalUUID()
	if err != nil {
		return fmt.Errorf("generate journal replay ID: %w", err)
	}
	record, err := j.newEncryptedRecord(replayID, request.ID, state.nextSequence, request.Mode, eventType, payload, false)
	if err != nil {
		return err
	}
	if !responseLinkOK {
		responseID = ""
	}
	if err := j.appendRecord(ctx, state, record, responseID); err != nil {
		return err
	}
	state.nextSequence++
	if err := apply(ctx, replayID); err != nil {
		j.enqueueReplay(replayID)
		return err
	}
	if err := j.markApplied(ctx, replayID); err != nil {
		j.enqueueReplay(replayID)
		return fmt.Errorf("mark journal replay %q applied: %w", replayID, err)
	}
	j.enqueueReplay(replayID)
	return nil
}

func (j *Journal) appendRecord(ctx context.Context, state *journalRequestState, record JournalRecord, responseID string) error {
	return j.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var requestRow JournalRequestRecord
		if err := tx.Where("request_id = ?", state.request.ID).First(&requestRow).Error; err != nil {
			return fmt.Errorf("load journal request %q: %w", state.request.ID, err)
		}
		var lifecycle RequestRecord
		lifecycleErr := tx.Select("deleting_at").Where("request_id = ?", state.request.ID).First(&lifecycle).Error
		if lifecycleErr == nil && lifecycle.DeletingAt != nil {
			return errors.New("journal request is deleting")
		}
		if lifecycleErr != nil && !errors.Is(lifecycleErr, gorm.ErrRecordNotFound) {
			return fmt.Errorf("check lifecycle request deletion: %w", lifecycleErr)
		}
		record.Sequence = requestRow.NextSequence
		record.Checksum = journalChecksum(record)
		if err := tx.Model(&JournalRequestRecord{}).Where("request_id = ?", state.request.ID).Update("next_sequence", requestRow.NextSequence+1).Error; err != nil {
			return fmt.Errorf("advance journal request %q: %w", state.request.ID, err)
		}
		if err := validateJournalRecord(record); err != nil {
			return err
		}
		if responseID != "" {
			if err := ensureResponseLink(tx, state.request, responseID, record.CreatedAt, j.metadataTTL); err != nil {
				return err
			}
		}
		if err := tx.Create(&record).Error; err != nil {
			return fmt.Errorf("append journal record: %w", err)
		}
		return nil
	})
}

func (j *Journal) appendInternal(ctx context.Context, state *journalRequestState, eventType string, payload []byte) error {
	replayID, err := newJournalUUID()
	if err != nil {
		return fmt.Errorf("generate lifecycle replay ID: %w", err)
	}
	record, err := j.newEncryptedRecord(replayID, state.request.ID, state.nextSequence, state.request.Mode, eventType, payload, true)
	if err != nil {
		return err
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	if err := j.appendRecord(ctx, state, record, ""); err != nil {
		return err
	}
	state.nextSequence++
	j.enqueueReplay(replayID)
	return nil
}

// JournalUsage contains the durable usage fields needed for reconciliation.
type JournalUsage struct {
	InputTokens            int64
	CachedInputTokens      int64
	CachedInputTokensKnown bool
	OutputTokens           int64
	ReasoningTokens        int64
	ReasoningTokensKnown   bool
	TotalTokens            int64
	ImageCount             int64
	ResolvedModel          string
}

// RecordUsage appends one bounded usage update.
func (j *Journal) RecordUsage(ctx context.Context, request JournalRequest, input, output, total, images int64) error {
	return j.RecordUsageDetails(ctx, request, JournalUsage{
		InputTokens: input, OutputTokens: output, TotalTokens: total, ImageCount: images,
	})
}

// RecordUsageDetails appends usage with optional cache, reasoning, and model data.
func (j *Journal) RecordUsageDetails(ctx context.Context, request JournalRequest, usage JournalUsage) error {
	payload, err := lifecycleUsageDetailsBytes(lifecycleUsagePayload{
		Version: lifecycleEventVersion, InputTokens: usage.InputTokens,
		CachedInputTokens: usage.CachedInputTokens, CachedInputTokensKnown: usage.CachedInputTokensKnown,
		OutputTokens: usage.OutputTokens, ReasoningTokens: usage.ReasoningTokens,
		ReasoningTokensKnown: usage.ReasoningTokensKnown, TotalTokens: usage.TotalTokens,
		ImageCount: usage.ImageCount, ResolvedModel: usage.ResolvedModel,
	})
	if err != nil {
		return err
	}
	return j.forwardInternal(ctx, request, "usage.update", payload)
}

// RecordTerminal appends one terminal lifecycle event. A successful append claims
// the request terminal under the request mutex; a failed append releases that
// claim so a later terminal can still be recorded.
func (j *Journal) RecordTerminal(ctx context.Context, request JournalRequest, state string, detail []byte) error {
	if ctx == nil {
		return errors.New("journal terminal context is nil")
	}
	payload, err := lifecycleTerminalBytes(state, detail)
	if err != nil {
		return err
	}
	if err := j.beginOperation(); err != nil {
		return err
	}
	defer j.endOperation()
	requestState := j.requestState(request)
	if requestState == nil {
		return fmt.Errorf("journal request %q is unknown", request.ID)
	}
	requestState.mu.Lock()
	if requestState.terminalRecord {
		requestState.mu.Unlock()
		return nil
	}
	requestState.terminalClaimed = true
	err = j.appendTerminalRecord(ctx, requestState, payload)
	if err != nil {
		requestState.terminalClaimed = false
		requestState.mu.Unlock()
		return err
	}
	requestState.terminalRecord = true
	requestState.terminalClaimed = false
	requestState.mu.Unlock()
	return nil
}

func (j *Journal) appendTerminalRecord(ctx context.Context, state *journalRequestState, payload []byte) error {
	replayID, err := newJournalUUID()
	if err != nil {
		return fmt.Errorf("generate terminal replay ID: %w", err)
	}
	record, err := j.newEncryptedRecord(replayID, state.request.ID, state.nextSequence, state.request.Mode, "request.terminal", payload, true)
	if err != nil {
		return err
	}
	if err := j.appendRecord(ctx, state, record, ""); err != nil {
		return err
	}
	state.nextSequence++
	j.enqueueReplay(replayID)
	return nil
}

// forwardInternal appends one internal lifecycle event.
func (j *Journal) forwardInternal(ctx context.Context, request JournalRequest, eventType string, payload []byte) error {
	if ctx == nil {
		return errors.New("journal lifecycle context is nil")
	}
	if err := j.beginOperation(); err != nil {
		return err
	}
	defer j.endOperation()
	state := j.requestState(request)
	if state == nil {
		return fmt.Errorf("journal request %q is unknown", request.ID)
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	replayID, err := newJournalUUID()
	if err != nil {
		return fmt.Errorf("generate lifecycle replay ID: %w", err)
	}
	record, err := j.newEncryptedRecord(replayID, request.ID, state.nextSequence, request.Mode, eventType, payload, true)
	if err != nil {
		return err
	}
	if err := j.appendRecord(ctx, state, record, ""); err != nil {
		return err
	}
	state.nextSequence++
	j.enqueueReplay(replayID)
	return nil
}

// CompleteRequest closes an accepted request as canceled when no terminal exists.
func (j *Journal) CompleteRequest(ctx context.Context, request JournalRequest) error {
	return j.CompleteRequestWithState(ctx, request, requestStatusCanceled)
}

func (j *Journal) CompleteRequestWithState(ctx context.Context, request JournalRequest, terminalState string) error {
	if ctx == nil {
		return errors.New("journal completion context is nil")
	}
	if terminalState != requestStatusSucceeded && terminalState != requestStatusFailed && terminalState != requestStatusCanceled {
		return fmt.Errorf("journal completion state %q is invalid", terminalState)
	}
	if err := j.RecordTerminal(ctx, request, terminalState, nil); err != nil {
		return err
	}
	j.deleteRequest(request.ID)
	return nil
}

func (j *Journal) deleteRequest(requestID string) {
	j.requestsMu.Lock()
	delete(j.requests, requestID)
	j.requestsMu.Unlock()
}

func (j *Journal) requestState(request JournalRequest) *journalRequestState {
	j.requestsMu.Lock()
	defer j.requestsMu.Unlock()
	state := j.requests[request.ID]
	if state == nil || state.request.Mode != request.Mode || state.request.ConversationID != request.ConversationID {
		return nil
	}
	return state
}

func (j *Journal) enqueueReplay(replayID string) {
	if replayID == "" || j.replayQueue == nil {
		return
	}
	select {
	case j.replayQueue <- replayID:
	default:
		// The source record remains durable. The next append or explicit drain scans it.
	}
}

func (j *Journal) discardReplaySignals() {
	for {
		select {
		case <-j.replayQueue:
		default:
			return
		}
	}
}

// enqueue is kept for bounded internal work and never used by live forwarding.
func (j *Journal) enqueue(ctx context.Context, work journalWork) error {
	if ctx == nil {
		return errors.New("journal queue context is nil")
	}
	if j.queue == nil {
		return errors.New("journal worker is not running")
	}
	select {
	case <-ctx.Done():
		return fmt.Errorf("journal queue backpressure: %w", ctx.Err())
	case j.queue <- work:
		return nil
	case <-j.closed:
		return ErrJournalClosed
	}
}

func (j *Journal) runWorker(ctx context.Context) {
	defer close(j.workerDone)
	for {
		select {
		case <-j.replayQueue:
			if err := j.Replay(ctx); err != nil {
				j.recordWorkerError(err)
				j.discardReplaySignals()
			}
		case work := <-j.queue:
			j.writeWork(ctx, work)
		case <-j.workerStop:
			j.drainWorker(ctx)
			return
		}
	}
}

func (j *Journal) drainWorker(ctx context.Context) {
	for {
		select {
		case work := <-j.queue:
			j.writeWork(ctx, work)
		case <-j.replayQueue:
			if err := j.Replay(ctx); err != nil {
				j.recordWorkerError(err)
			}
		default:
			if err := j.Replay(ctx); err != nil {
				j.recordWorkerError(err)
			}
			return
		}
	}
}

func (j *Journal) writeWork(ctx context.Context, work journalWork) {
	if len(work.records) == 0 {
		return
	}
	err := j.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		for _, record := range work.records {
			if err := validateJournalRecord(record); err != nil {
				return err
			}
			if err := tx.Create(&record).Error; err != nil {
				return fmt.Errorf("append journal record: %w", err)
			}
		}
		return nil
	})
	if err != nil {
		j.recordWorkerError(err)
	}
}

func (j *Journal) recordWorkerError(err error) {
	if err == nil {
		return
	}
	j.errorMu.Lock()
	if j.workerErr == nil {
		j.workerErr = err
	}
	j.errorMu.Unlock()
}

func (j *Journal) recordError(err error) {
	if err == nil {
		return
	}
	j.errorMu.Lock()
	if j.workerErr != nil {
		j.errorMu.Unlock()
		return
	}
	j.workerErr = err
	sink := j.errorSink
	j.errorMu.Unlock()
	if sink != nil {
		select {
		case sink <- err:
		default:
		}
	}
}

func (j *Journal) setErrorSink(sink chan<- error) {
	j.errorMu.Lock()
	j.errorSink = sink
	j.errorMu.Unlock()
}

// Replay materializes stable bounded batches from the durable spool.
func (j *Journal) Replay(ctx context.Context) error {
	if ctx == nil {
		return errors.New("journal replay context is nil")
	}
	j.replayMu.Lock()
	defer j.replayMu.Unlock()
	for {
		var records []JournalRecord
		result := j.db.WithContext(ctx).Where("NOT EXISTS (SELECT 1 FROM journal_receipts WHERE journal_receipts.replay_id = journal_records.replay_id AND journal_receipts.materialized = ?)", true).
			Order("created_at asc").Order("replay_id asc").Limit(journalReplayBatchSize).Find(&records)
		if result.Error != nil {
			return fmt.Errorf("load pending journal records: %w", result.Error)
		}
		if len(records) == 0 {
			return nil
		}
		for _, record := range records {
			if err := j.applyReceipt(ctx, record); err != nil {
				return fmt.Errorf("apply journal replay %q: %w", record.ReplayID, err)
			}
		}
	}
}

func (j *Journal) applyReceipt(ctx context.Context, record JournalRecord) error {
	var source JournalRecord
	if err := j.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("replay_id = ?", record.ReplayID).First(&source).Error; err != nil {
			return fmt.Errorf("load journal source: %w", err)
		}
		if err := validateJournalRecord(source); err != nil {
			return err
		}
		var requestRow JournalRequestRecord
		if err := tx.Where("request_id = ?", source.RequestID).First(&requestRow).Error; err != nil {
			return fmt.Errorf("load journal request metadata: %w", err)
		}
		request := JournalRequest{ID: source.RequestID, Mode: source.Mode, ConversationID: requestRow.ConversationID, Endpoint: requestRow.Endpoint, Model: requestRow.Model, APIKeyID: requestRow.APIKeyID, AccountID: requestRow.AccountID}
		var receipt JournalReceipt
		receiptResult := tx.Where("replay_id = ?", source.ReplayID).First(&receipt).Error
		if receiptResult == nil && receipt.Materialized {
			return nil
		}
		if receiptResult != nil && !errors.Is(receiptResult, gorm.ErrRecordNotFound) {
			return fmt.Errorf("load journal receipt: %w", receiptResult)
		}
		if err := j.materializeRecord(tx, source, request); err != nil {
			return err
		}
		if errors.Is(receiptResult, gorm.ErrRecordNotFound) {
			receipt = JournalReceipt{
				ReplayID: source.ReplayID, RequestID: source.RequestID, Sequence: source.Sequence,
				Mode: source.Mode, EventType: source.EventType, EventVersion: source.EventVersion,
				KeyVersion: source.KeyVersion, Payload: append([]byte(nil), source.Payload...),
				Checksum: append([]byte(nil), source.Checksum...), CreatedAt: source.CreatedAt,
				Materialized: true,
			}
			now := time.Now().UTC()
			receipt.MaterializedAt = &now
			if err := tx.Create(&receipt).Error; err != nil {
				return fmt.Errorf("store journal receipt: %w", err)
			}
		} else {
			now := time.Now().UTC()
			result := tx.Model(&JournalReceipt{}).Where("replay_id = ?", source.ReplayID).Updates(map[string]any{"materialized": true, "materialized_at": now})
			if result.Error != nil {
				return fmt.Errorf("mark journal receipt materialized: %w", result.Error)
			}
		}
		now := time.Now().UTC()
		result := tx.Model(&JournalRecord{}).Where("replay_id = ? AND applied = ?", source.ReplayID, false).Updates(map[string]any{"applied": true, "applied_at": now})
		if result.Error != nil {
			return fmt.Errorf("mark journal source applied: %w", result.Error)
		}
		return nil
	}); err != nil {
		return err
	}
	if source.EventType != "usage.update" {
		return nil
	}
	var requestRow RequestRecord
	if err := j.db.WithContext(ctx).Select("terminal_at").Where("request_id = ?", source.RequestID).First(&requestRow).Error; err != nil {
		return fmt.Errorf("load terminal request after usage: %w", err)
	}
	if requestRow.TerminalAt == nil {
		return nil
	}
	return j.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		return j.reconcileUsagePricing(tx, source.RequestID, *requestRow.TerminalAt)
	})
}

func (j *Journal) markApplied(ctx context.Context, replayID string) error {
	return j.db.WithContext(context.WithoutCancel(ctx)).Transaction(func(tx *gorm.DB) error {
		now := time.Now().UTC()
		result := tx.Model(&JournalRecord{}).Where("replay_id = ? AND applied = ?", replayID, false).Updates(map[string]any{"applied": true, "applied_at": now})
		if result.Error != nil {
			return result.Error
		}
		if result.RowsAffected == 0 {
			var record JournalRecord
			if err := tx.Where("replay_id = ?", replayID).First(&record).Error; err != nil {
				return err
			}
			if !record.Applied {
				return errors.New("journal replay record was not marked applied")
			}
		}
		return nil
	})
}

// Close stops intake and drains accepted records within the configured deadline.
func (j *Journal) Close(ctx context.Context) error {
	if ctx == nil {
		return errors.New("journal close context is nil")
	}
	drainContext, cancel := context.WithTimeout(ctx, j.drainDeadline)
	defer cancel()
	j.closeOnce.Do(func() {
		j.lifecycleMu.Lock()
		j.accepting = false
		j.lifecycleMu.Unlock()
	})
	inFlightDone := make(chan struct{})
	go func() {
		j.inFlight.Wait()
		close(inFlightDone)
	}()
	select {
	case <-inFlightDone:
	case <-drainContext.Done():
		j.stopEnqueue(drainContext.Err())
		j.stopWorker(true)
		j.waitWorker()
		return j.closeError(drainContext.Err())
	}
	j.stopWorker(false)
	j.workerMu.Lock()
	workerStarted, workerDone := j.workerStarted, j.workerDone
	j.workerMu.Unlock()
	if workerStarted {
		select {
		case <-workerDone:
		case <-drainContext.Done():
			j.stopWorker(true)
			j.waitWorker()
			j.stopEnqueue(drainContext.Err())
			return j.closeError(drainContext.Err())
		}
	} else if err := j.Replay(drainContext); err != nil {
		j.stopEnqueue(err)
		return j.closeError(err)
	}
	j.stopEnqueue(nil)
	return j.closeError(nil)
}

func (j *Journal) stopEnqueue(cause error) {
	j.enqueueMu.Lock()
	j.closing = true
	if j.enqueueErr == nil {
		if cause == nil {
			cause = ErrJournalClosed
		}
		j.enqueueErr = cause
	}
	j.closedOnce.Do(func() { close(j.closed) })
	j.enqueueMu.Unlock()
}

func (j *Journal) stopWorker(cancel bool) {
	j.workerMu.Lock()
	workerCancel, workerStarted, workerStop := j.workerCancel, j.workerStarted, j.workerStop
	j.workerMu.Unlock()
	if !workerStarted {
		return
	}
	if cancel && workerCancel != nil {
		workerCancel()
	}
	j.workerStopOnce.Do(func() { close(workerStop) })
}

func (j *Journal) waitWorker() {
	j.workerMu.Lock()
	workerStarted, workerDone := j.workerStarted, j.workerDone
	j.workerMu.Unlock()
	if workerStarted {
		<-workerDone
	}
}

func (j *Journal) closeError(cause error) error {
	j.errorMu.Lock()
	defer j.errorMu.Unlock()
	if cause == nil {
		return j.workerErr
	}
	if j.workerErr == nil {
		return cause
	}
	return errors.Join(cause, j.workerErr)
}

func validateJournalMode(mode string) error {
	if mode != journalModeDurable && mode != journalModeBestEffort {
		return fmt.Errorf("journal mode %q is invalid", mode)
	}
	return nil
}

func validateJournalEvent(eventType string, payload []byte) error {
	if len(eventType) == 0 || len(eventType) > maxJournalEventTypeBytes {
		return errors.New("journal event type is empty or too large")
	}
	if len(payload) > maxJournalPayloadBytes {
		return errors.New("journal payload is too large")
	}
	return nil
}

func validateJournalEnvelope(payload []byte) error {
	if len(payload) == 0 || len(payload) > envelope.MaxEnvelopeSize {
		return errors.New("journal envelope size is invalid")
	}
	return nil
}

func validateJournalRecord(record JournalRecord) error {
	if !validJournalUUID(record.ReplayID) || !validJournalUUID(record.RequestID) {
		return errors.New("journal record ID is invalid")
	}
	if err := validateJournalMode(record.Mode); err != nil {
		return err
	}
	if err := validateJournalEvent(record.EventType, nil); err != nil {
		return err
	}
	if err := validateJournalEnvelope(record.Payload); err != nil {
		return err
	}
	if !supportedLifecycleEventVersion(record.EventVersion) || record.KeyVersion == 0 {
		return errors.New("journal record uses an unsupported legacy version")
	}
	if len(record.Payload) < 9 || binary.BigEndian.Uint32(record.Payload[5:9]) != record.KeyVersion {
		return errors.New("journal record envelope version does not match metadata")
	}
	if len(record.Checksum) != sha256.Size || !bytes.Equal(record.Checksum, journalChecksum(record)) {
		return errors.New("journal record checksum is invalid")
	}
	if record.CreatedAt.IsZero() {
		return errors.New("journal record created time is missing")
	}
	return nil
}

func journalChecksum(record JournalRecord) []byte {
	hash := sha256.New()
	_, _ = hash.Write([]byte("codex-sub-proxy journal record v2"))
	writeBytes := func(value []byte) {
		var length [8]byte
		binary.BigEndian.PutUint64(length[:], uint64(len(value)))
		_, _ = hash.Write(length[:])
		_, _ = hash.Write(value)
	}
	writeString := func(value string) { writeBytes([]byte(value)) }
	writeString(record.ReplayID)
	writeString(record.RequestID)
	var sequence [8]byte
	binary.BigEndian.PutUint64(sequence[:], record.Sequence)
	_, _ = hash.Write(sequence[:])
	var version [2]byte
	binary.BigEndian.PutUint16(version[:], record.EventVersion)
	_, _ = hash.Write(version[:])
	var keyVersion [4]byte
	binary.BigEndian.PutUint32(keyVersion[:], record.KeyVersion)
	_, _ = hash.Write(keyVersion[:])
	writeString(record.Mode)
	writeString(record.EventType)
	var created [8]byte
	binary.BigEndian.PutUint64(created[:], uint64(record.CreatedAt.UTC().UnixNano()))
	_, _ = hash.Write(created[:])
	writeBytes(record.Payload)
	return hash.Sum(nil)
}

func newJournalUUID() (string, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", err
	}
	value[6] = (value[6] & 0x0f) | 0x40
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
	return string(encoded[:]), nil
}

func validJournalUUID(value string) bool {
	if len(value) != 36 || value[8] != '-' || value[13] != '-' || value[18] != '-' || value[23] != '-' {
		return false
	}
	for index, char := range value {
		if index == 8 || index == 13 || index == 18 || index == 23 {
			continue
		}
		if !((char >= '0' && char <= '9') || (char >= 'a' && char <= 'f') || (char >= 'A' && char <= 'F')) {
			return false
		}
	}
	return value[14] == '4' && (value[19] == '8' || value[19] == '9' || value[19] == 'a' || value[19] == 'b' || value[19] == 'A' || value[19] == 'B')
}

// JournalAuditMetadata contains safe fields for a rejection audit.
type JournalAuditMetadata struct {
	RequestID string
	APIKeyID  string
	Endpoint  string
	EventType string
	Status    int
}

// RecordAudit stores an encrypted detail envelope without creating a request projection.
func (j *Journal) RecordAudit(ctx context.Context, metadata JournalAuditMetadata, detail []byte) error {
	if ctx == nil {
		return errors.New("journal audit context is nil")
	}
	if len(detail) > lifecycleMaxDetail {
		return errors.New("journal audit detail is too large")
	}
	if err := j.beginOperation(); err != nil {
		return err
	}
	defer j.endOperation()
	auditID, err := newJournalUUID()
	if err != nil {
		return fmt.Errorf("generate audit ID: %w", err)
	}
	encoded, err := envelope.Encrypt(detail, envelope.PayloadDomain, j.keys)
	if err != nil {
		return fmt.Errorf("encrypt audit detail: %w", err)
	}
	if err := j.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		createdAt := time.Now().UTC()
		payload := EncryptedPayloadRecord{ID: auditID, ReplayID: auditID, KeyVersion: j.keys.Active.Version, Envelope: encoded, CreatedAt: createdAt, ExpiresAt: createdAt.Add(j.payloadTTL)}
		if err := tx.Create(&payload).Error; err != nil {
			return fmt.Errorf("store audit payload: %w", err)
		}
		audit := AuditRecord{ID: auditID, RequestID: metadata.RequestID, APIKeyID: metadata.APIKeyID, Endpoint: metadata.Endpoint, EventType: metadata.EventType, Status: metadata.Status, PayloadID: auditID, CreatedAt: createdAt, ExpiresAt: createdAt.Add(j.metadataTTL)}
		if err := tx.Create(&audit).Error; err != nil {
			return fmt.Errorf("store audit record: %w", err)
		}
		return nil
	}); err != nil {
		return err
	}
	return nil
}
