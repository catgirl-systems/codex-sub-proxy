package server

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	"gorm.io/gorm"
)

const (
	journalModeDurable       = "durable"
	journalModeBestEffort    = "best-effort"
	journalRequestEventType  = "request.accepted"
	maxJournalEventTypeBytes = 128
	maxJournalPayloadBytes   = 32 << 20
	defaultJournalQueueSize  = 64
	maxJournalQueueSize      = 4096
	defaultJournalDrain      = 10 * time.Second
)

var (
	// ErrJournalClosed indicates that the journal no longer accepts records.
	ErrJournalClosed = errors.New("journal is closed")
)

// JournalApply applies one journal record to an idempotent receiver.
//
// The receiver must use replayID as its durable uniqueness key. The journal
// marks a record applied only after this function returns nil.
type JournalApply func(ctx context.Context, replayID, eventType string, payload []byte) error

// JournalRequestRecord stores the next sequence number for one request.
type JournalRequestRecord struct {
	RequestID    string    `gorm:"column:request_id;primaryKey;size:36"`
	Mode         string    `gorm:"column:mode;not null;size:16"`
	NextSequence uint64    `gorm:"column:next_sequence;not null"`
	CreatedAt    time.Time `gorm:"column:created_at;not null"`
}

func (JournalRequestRecord) TableName() string {
	return "journal_requests"
}

// JournalRecord is one immutable journal record and its delivery state.
type JournalRecord struct {
	ReplayID  string     `gorm:"column:replay_id;primaryKey;size:36"`
	RequestID string     `gorm:"column:request_id;not null;size:36;index:idx_journal_request_sequence,unique"`
	Sequence  uint64     `gorm:"column:sequence;not null;index:idx_journal_request_sequence,unique"`
	Mode      string     `gorm:"column:mode;not null;size:16"`
	EventType string     `gorm:"column:event_type;not null;size:128"`
	Payload   []byte     `gorm:"column:payload;not null"`
	Checksum  []byte     `gorm:"column:checksum;not null;size:32"`
	CreatedAt time.Time  `gorm:"column:created_at;not null;index:idx_journal_created"`
	Applied   bool       `gorm:"column:applied;not null;index"`
	AppliedAt *time.Time `gorm:"column:applied_at"`
}

func (JournalRecord) TableName() string {
	return "journal_records"
}

// MigrateJournal creates the journal tables and their uniqueness indexes.
func MigrateJournal(db *gorm.DB) error {
	if db == nil {
		return errors.New("journal database is nil")
	}
	if err := db.AutoMigrate(&JournalRequestRecord{}, &JournalRecord{}); err != nil {
		return fmt.Errorf("migrate journal: %w", err)
	}
	return nil
}

// JournalRequest identifies one accepted request.
type JournalRequest struct {
	ID   string
	Mode string
}

type journalRequestState struct {
	mu            sync.Mutex
	request       JournalRequest
	requestRecord JournalRecord
	nextSequence  uint64
	requestQueued bool
}

type journalWork struct {
	records []JournalRecord
}

// Journal appends records and, in best-effort mode, drains one bounded queue.
type Journal struct {
	db            *gorm.DB
	mode          string
	queue         chan journalWork
	drainDeadline time.Duration

	lifecycleMu sync.RWMutex
	accepting   bool
	closed      chan struct{}
	closeOnce   sync.Once
	inFlight    sync.WaitGroup

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
}

func newJournal(db *gorm.DB, mode string, queueCapacity int, drainDeadline time.Duration) (*Journal, error) {
	if db == nil {
		return nil, errors.New("journal database is nil")
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
	journal := &Journal{
		db:            db,
		mode:          mode,
		drainDeadline: drainDeadline,
		accepting:     true,
		closed:        make(chan struct{}),
		requests:      make(map[string]*journalRequestState),
	}
	if mode == journalModeBestEffort {
		journal.queue = make(chan journalWork, queueCapacity)
	}
	return journal, nil
}

// Start starts the single best-effort journal worker.
func (j *Journal) Start() error {
	if j == nil {
		return errors.New("journal is nil")
	}
	j.workerMu.Lock()
	defer j.workerMu.Unlock()
	if j.mode == journalModeDurable || j.workerStarted {
		return nil
	}
	j.lifecycleMu.RLock()
	accepting := j.accepting
	j.lifecycleMu.RUnlock()
	if !accepting {
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

func (j *Journal) endOperation() {
	j.inFlight.Done()
}

// BeginRequest creates an identity for one accepted request.
func (j *Journal) BeginRequest(ctx context.Context) (JournalRequest, error) {
	if ctx == nil {
		return JournalRequest{}, errors.New("journal request context is nil")
	}
	if err := j.beginOperation(); err != nil {
		return JournalRequest{}, err
	}
	defer j.endOperation()

	requestID, err := newJournalUUID()
	if err != nil {
		return JournalRequest{}, fmt.Errorf("generate journal request ID: %w", err)
	}
	request := JournalRequest{ID: requestID, Mode: j.mode}
	requestRecord, err := j.newRequestRecord(request)
	if err != nil {
		return JournalRequest{}, err
	}
	state := &journalRequestState{
		request:       request,
		requestRecord: requestRecord,
		nextSequence:  1,
		requestQueued: j.mode == journalModeDurable,
	}
	if j.mode == journalModeDurable {
		if err := j.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
			row := JournalRequestRecord{
				RequestID:    request.ID,
				Mode:         request.Mode,
				NextSequence: 1,
				CreatedAt:    requestRecord.CreatedAt,
			}
			if err := tx.Create(&row).Error; err != nil {
				return fmt.Errorf("store journal request: %w", err)
			}
			if err := tx.Create(&requestRecord).Error; err != nil {
				return fmt.Errorf("store journal request record: %w", err)
			}
			return nil
		}); err != nil {
			return JournalRequest{}, err
		}
	}
	j.requestsMu.Lock()
	j.requests[request.ID] = state
	j.requestsMu.Unlock()
	return request, nil
}

func (j *Journal) newRequestRecord(request JournalRequest) (JournalRecord, error) {
	replayID, err := newJournalUUID()
	if err != nil {
		return JournalRecord{}, fmt.Errorf("generate journal request replay ID: %w", err)
	}
	return newJournalRecord(replayID, request.ID, 0, request.Mode, journalRequestEventType, nil, true)
}

// Forward appends one public output and invokes its receiver in journal order.
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
	if err := validateJournalEvent(eventType, payload); err != nil {
		return err
	}
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
	sequence := state.nextSequence
	record, err := newJournalRecord(replayID, request.ID, sequence, request.Mode, eventType, payload, false)
	if err != nil {
		return err
	}
	if j.mode == journalModeDurable {
		if err := j.appendDurable(ctx, state, record); err != nil {
			return err
		}
		applyErr := apply(ctx, replayID)
		if applyErr != nil {
			return applyErr
		}
		if err := j.markApplied(ctx, replayID); err != nil {
			return fmt.Errorf("mark journal replay %q applied: %w", replayID, err)
		}
		state.nextSequence++
		return nil
	}

	records := make([]JournalRecord, 0, 2)
	if !state.requestQueued {
		records = append(records, state.requestRecord)
	}
	records = append(records, record)
	applyErr := apply(ctx, replayID)
	queueErr := j.enqueue(ctx, journalWork{records: records})
	if queueErr == nil {
		state.requestQueued = true
		state.nextSequence++
	}
	if applyErr != nil && queueErr != nil {
		return errors.Join(applyErr, queueErr)
	}
	if applyErr != nil {
		return applyErr
	}
	return queueErr
}

func (j *Journal) requestState(request JournalRequest) *journalRequestState {
	j.requestsMu.Lock()
	defer j.requestsMu.Unlock()
	state := j.requests[request.ID]
	if state == nil || state.request.Mode != request.Mode {
		return nil
	}
	return state
}

func (j *Journal) appendDurable(ctx context.Context, state *journalRequestState, record JournalRecord) error {
	return j.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var requestRow JournalRequestRecord
		if err := tx.Where("request_id = ?", state.request.ID).First(&requestRow).Error; err != nil {
			return fmt.Errorf("load journal request %q: %w", state.request.ID, err)
		}
		record.Sequence = requestRow.NextSequence
		if err := tx.Model(&JournalRequestRecord{}).
			Where("request_id = ?", state.request.ID).
			Update("next_sequence", requestRow.NextSequence+1).Error; err != nil {
			return fmt.Errorf("advance journal request %q: %w", state.request.ID, err)
		}
		if err := tx.Create(&record).Error; err != nil {
			return fmt.Errorf("append journal record: %w", err)
		}
		return nil
	})
}

// CompleteRequest records a best-effort request that produced no output.
func (j *Journal) CompleteRequest(ctx context.Context, request JournalRequest) error {
	if ctx == nil {
		return errors.New("journal completion context is nil")
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
	if j.mode == journalModeBestEffort && !state.requestQueued {
		if err := j.enqueue(ctx, journalWork{records: []JournalRecord{state.requestRecord}}); err != nil {
			return err
		}
		state.requestQueued = true
	}
	j.requestsMu.Lock()
	delete(j.requests, request.ID)
	j.requestsMu.Unlock()
	return nil
}

func (j *Journal) enqueue(ctx context.Context, work journalWork) error {
	if j.queue == nil {
		return errors.New("journal worker is not running")
	}
	select {
	case j.queue <- work:
		return nil
	case <-ctx.Done():
		return fmt.Errorf("journal queue backpressure: %w", ctx.Err())
	case <-j.closed:
		return ErrJournalClosed
	}
}

func (j *Journal) runWorker(ctx context.Context) {
	defer close(j.workerDone)
	for {
		select {
		case work := <-j.queue:
			j.writeWork(ctx, work)
		case <-j.workerStop:
			for {
				select {
				case work := <-j.queue:
					j.writeWork(ctx, work)
				default:
					return
				}
			}
		case <-ctx.Done():
			return
		}
	}
}

func (j *Journal) writeWork(ctx context.Context, work journalWork) {
	err := j.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		for _, record := range work.records {
			if err := validateJournalRecord(record); err != nil {
				return err
			}
			if err := tx.Create(&record).Error; err != nil {
				return fmt.Errorf("append best-effort journal record: %w", err)
			}
		}
		return nil
	})
	if err != nil {
		j.recordError(err)
	}
}

func (j *Journal) recordError(err error) {
	if err == nil {
		return
	}
	j.errorMu.Lock()
	if j.workerErr == nil {
		j.workerErr = err
	}
	j.errorMu.Unlock()
}

// Replay applies pending records in stable database order.
func (j *Journal) Replay(ctx context.Context, apply JournalApply) error {
	if ctx == nil {
		return errors.New("journal replay context is nil")
	}
	if err := j.beginOperation(); err != nil {
		return err
	}
	defer j.endOperation()
	var pending int64
	if err := j.db.WithContext(ctx).
		Model(&JournalRecord{}).
		Where("applied = ?", false).
		Count(&pending).Error; err != nil {
		return fmt.Errorf("count pending journal records: %w", err)
	}
	if pending == 0 {
		return nil
	}
	if apply == nil {
		return errors.New("journal replay callback is required")
	}
	var oversized int64
	if err := j.db.WithContext(ctx).
		Model(&JournalRecord{}).
		Where("applied = ? AND length(payload) > ?", false, maxJournalPayloadBytes).
		Count(&oversized).Error; err != nil {
		return fmt.Errorf("check pending journal payload sizes: %w", err)
	}
	if oversized != 0 {
		return errors.New("pending journal payload exceeds limit")
	}
	for {
		var record JournalRecord
		result := j.db.WithContext(ctx).
			Model(&JournalRecord{}).
			Where("applied = ?", false).
			Order("created_at asc").
			Order("replay_id asc").
			Limit(1).
			Find(&record)
		if result.Error != nil {
			return fmt.Errorf("load pending journal records: %w", result.Error)
		}
		if result.RowsAffected == 0 {
			return nil
		}
		if err := validateJournalRecord(record); err != nil {
			return fmt.Errorf("validate journal replay %q: %w", record.ReplayID, err)
		}
		if err := apply(ctx, record.ReplayID, record.EventType, append([]byte(nil), record.Payload...)); err != nil {
			return fmt.Errorf("apply journal replay %q: %w", record.ReplayID, err)
		}
		if err := j.markApplied(ctx, record.ReplayID); err != nil {
			return fmt.Errorf("mark journal replay %q applied: %w", record.ReplayID, err)
		}
	}
}

func (j *Journal) markApplied(ctx context.Context, replayID string) error {
	return j.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		now := time.Now().UTC()
		result := tx.Model(&JournalRecord{}).
			Where("replay_id = ? AND applied = ?", replayID, false).
			Updates(map[string]any{"applied": true, "applied_at": now})
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

// Close stops intake and drains accepted best-effort records until ctx ends.
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
		close(j.closed)
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
		j.stopWorker(true)
		j.waitWorker()
		return j.closeError(drainContext.Err())
	}
	j.stopWorker(false)
	j.workerMu.Lock()
	workerStarted := j.workerStarted
	workerDone := j.workerDone
	j.workerMu.Unlock()
	if !workerStarted && len(j.queue) != 0 {
		return j.closeError(errors.New("journal worker was not started"))
	}
	if workerStarted {
		select {
		case <-workerDone:
		case <-drainContext.Done():
			j.stopWorker(true)
			j.waitWorker()
			return j.closeError(drainContext.Err())
		}
	}
	return j.closeError(nil)
}

func (j *Journal) stopWorker(cancel bool) {
	j.workerMu.Lock()
	workerCancel := j.workerCancel
	workerStarted := j.workerStarted
	workerStop := j.workerStop
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
	workerStarted := j.workerStarted
	workerDone := j.workerDone
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

func newJournalRecord(replayID, requestID string, sequence uint64, mode, eventType string, payload []byte, applied bool) (JournalRecord, error) {
	if err := validateJournalMode(mode); err != nil {
		return JournalRecord{}, err
	}
	if err := validateJournalEvent(eventType, payload); err != nil {
		return JournalRecord{}, err
	}
	return JournalRecord{
		ReplayID:  replayID,
		RequestID: requestID,
		Sequence:  sequence,
		Mode:      mode,
		EventType: eventType,
		Payload:   append([]byte{}, payload...),
		Checksum:  journalChecksum(payload),
		CreatedAt: time.Now().UTC(),
		Applied:   applied,
	}, nil
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

func validateJournalRecord(record JournalRecord) error {
	if !validJournalUUID(record.ReplayID) || !validJournalUUID(record.RequestID) {
		return errors.New("journal record ID is invalid")
	}
	if err := validateJournalMode(record.Mode); err != nil {
		return err
	}
	if err := validateJournalEvent(record.EventType, record.Payload); err != nil {
		return err
	}
	if len(record.Checksum) != sha256.Size || !bytes.Equal(record.Checksum, journalChecksum(record.Payload)) {
		return errors.New("journal record checksum is invalid")
	}
	if record.CreatedAt.IsZero() {
		return errors.New("journal record created time is missing")
	}
	return nil
}

func journalChecksum(payload []byte) []byte {
	sum := sha256.Sum256(payload)
	return append([]byte(nil), sum[:]...)
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
