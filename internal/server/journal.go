package server

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/catgirl-systems/codex-sub-proxy/internal/envelope"
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

// Journal appends encrypted records and owns one bounded materializer worker.
type Journal struct {
	db            *gorm.DB
	keys          envelope.KeySet
	mode          string
	queue         chan journalWork
	replayQueue   chan string
	drainDeadline time.Duration
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
	requests   map[string]*journalRequestState

	errorMu   sync.Mutex
	workerErr error
	errorSink chan<- error
}

// MigrateJournal creates the journal, receipt, and lifecycle projection tables.
func MigrateJournal(db *gorm.DB) error {
	if db == nil {
		return errors.New("journal database is nil")
	}
	if err := db.AutoMigrate(&JournalRequestRecord{}, &JournalRecord{}, &JournalReceipt{}); err != nil {
		return fmt.Errorf("migrate journal: %w", err)
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
	return &Journal{
		db:            db,
		keys:          validatedKeys,
		mode:          mode,
		drainDeadline: drainDeadline,
		accepting:     true,
		closed:        make(chan struct{}),
		queue:         make(chan journalWork, queueCapacity),
		replayQueue:   make(chan string, queueCapacity),
		requests:      make(map[string]*journalRequestState),
	}, nil
}

// Start starts the single materializer worker.
func (j *Journal) Start() error {
	if j == nil {
		return errors.New("journal is nil")
	}
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
	if j == nil {
		return errors.New("journal is nil")
	}
	j.lifecycleMu.RLock()
	defer j.lifecycleMu.RUnlock()
	if !j.accepting {
		return ErrJournalClosed
	}
	j.inFlight.Add(1)
	return nil
}

func (j *Journal) endOperation() { j.inFlight.Done() }

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
	conversationID := deriveConversationID(metadata.ConversationHint)
	if conversationID == "" {
		conversationID, err = newJournalUUID()
		if err != nil {
			return JournalRequest{}, fmt.Errorf("generate conversation ID: %w", err)
		}
	}
	request := JournalRequest{ID: requestID, Mode: j.mode, ConversationID: conversationID, Endpoint: endpoint, Model: model, APIKeyID: metadata.APIKeyID}
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
	if err := j.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		row := JournalRequestRecord{
			RequestID: request.ID, Mode: request.Mode, NextSequence: 1,
			ConversationID: request.ConversationID, Endpoint: request.Endpoint,
			Model: request.Model, APIKeyID: request.APIKeyID, CreatedAt: requestRecord.CreatedAt,
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
		return JournalRequest{}, err
	}
	j.requestsMu.Lock()
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
	replayID, err := newJournalUUID()
	if err != nil {
		return fmt.Errorf("generate journal replay ID: %w", err)
	}
	record, err := j.newEncryptedRecord(replayID, request.ID, state.nextSequence, request.Mode, eventType, payload, false)
	if err != nil {
		return err
	}
	if err := j.appendRecord(ctx, state, record); err != nil {
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

func (j *Journal) appendRecord(ctx context.Context, state *journalRequestState, record JournalRecord) error {
	return j.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var requestRow JournalRequestRecord
		if err := tx.Where("request_id = ?", state.request.ID).First(&requestRow).Error; err != nil {
			return fmt.Errorf("load journal request %q: %w", state.request.ID, err)
		}
		record.Sequence = requestRow.NextSequence
		record.Checksum = journalChecksum(record)
		if err := tx.Model(&JournalRequestRecord{}).Where("request_id = ?", state.request.ID).Update("next_sequence", requestRow.NextSequence+1).Error; err != nil {
			return fmt.Errorf("advance journal request %q: %w", state.request.ID, err)
		}
		if err := validateJournalRecord(record); err != nil {
			return err
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
	if err := j.appendRecord(ctx, state, record); err != nil {
		return err
	}
	state.nextSequence++
	j.enqueueReplay(replayID)
	return nil
}

// RecordUsage appends one bounded usage update.
func (j *Journal) RecordUsage(ctx context.Context, request JournalRequest, input, output, total, images int64) error {
	payload, err := lifecycleUsageBytes(input, output, total, images)
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
	if err := j.appendRecord(ctx, state, record); err != nil {
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
	if err := j.appendRecord(ctx, state, record); err != nil {
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
	return j.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var source JournalRecord
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
		request := JournalRequest{ID: source.RequestID, Mode: source.Mode, ConversationID: requestRow.ConversationID, Endpoint: requestRow.Endpoint, Model: requestRow.Model, APIKeyID: requestRow.APIKeyID}
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
	if j == nil {
		return nil
	}
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
	if record.EventVersion != lifecycleEventVersion || record.KeyVersion == 0 {
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
		payload := EncryptedPayloadRecord{ID: auditID, ReplayID: auditID, KeyVersion: j.keys.Active.Version, Envelope: encoded, CreatedAt: time.Now().UTC()}
		if err := tx.Create(&payload).Error; err != nil {
			return fmt.Errorf("store audit payload: %w", err)
		}
		audit := AuditRecord{ID: auditID, RequestID: metadata.RequestID, APIKeyID: metadata.APIKeyID, Endpoint: metadata.Endpoint, EventType: metadata.EventType, Status: metadata.Status, PayloadID: auditID, CreatedAt: payload.CreatedAt}
		if err := tx.Create(&audit).Error; err != nil {
			return fmt.Errorf("store audit record: %w", err)
		}
		return nil
	}); err != nil {
		return err
	}
	return nil
}
