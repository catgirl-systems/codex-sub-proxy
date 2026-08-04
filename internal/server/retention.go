package server

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"gorm.io/gorm"
)

const (
	retentionDefaultBatch     = 64
	retentionMaxBatch         = 4096
	retentionDefaultSweep     = time.Minute
	retentionDefaultDrain     = 10 * time.Second
	retentionMaxDeleteBatches = 1024
	retentionSweepDeadline    = 500 * time.Millisecond
)

var errConversationHasRunningRequest = errors.New("conversation has a running request")

// RetentionConfig controls one bounded lifecycle retention runner.
type RetentionConfig struct {
	ArtifactTTL   time.Duration
	PayloadTTL    time.Duration
	MetadataTTL   time.Duration
	SweepInterval time.Duration
	BatchSize     int
	DrainDeadline time.Duration
}

// RetentionRunner owns the only background retention worker.
type RetentionRunner struct {
	db            *gorm.DB
	artifacts     *ArtifactStore
	payloadTTL    time.Duration
	metadataTTL   time.Duration
	sweepInterval time.Duration
	batchSize     int
	drainDeadline time.Duration
	startMu       sync.Mutex
	started       bool
	cancel        context.CancelFunc
	done          chan struct{}
	stopOnce      sync.Once
	healthMu      sync.RWMutex
	lastErr       error
	deleteMu      sync.Mutex
}

// RetentionHealth is the runner's operational readiness state.
type RetentionHealth struct {
	Healthy bool
	Err     error
}

// NewRetentionRunner validates retention policy without starting background work.
func NewRetentionRunner(db *gorm.DB, artifacts *ArtifactStore, config RetentionConfig) (*RetentionRunner, error) {
	if db == nil {
		return nil, errors.New("retention database is nil")
	}
	if config.PayloadTTL == 0 {
		config.PayloadTTL = 24 * time.Hour
	}
	if config.MetadataTTL == 0 {
		config.MetadataTTL = 7 * 24 * time.Hour
	}
	if config.SweepInterval == 0 {
		config.SweepInterval = retentionDefaultSweep
	}
	if config.BatchSize == 0 {
		config.BatchSize = retentionDefaultBatch
	}
	if config.DrainDeadline == 0 {
		config.DrainDeadline = retentionDefaultDrain
	}
	if config.PayloadTTL <= 0 || config.MetadataTTL <= 0 || config.SweepInterval <= 0 || config.DrainDeadline <= 0 {
		return nil, errors.New("retention durations must be positive")
	}
	if config.BatchSize < 1 || config.BatchSize > retentionMaxBatch {
		return nil, fmt.Errorf("retention batch size must be between 1 and %d", retentionMaxBatch)
	}
	return &RetentionRunner{
		db:            db,
		artifacts:     artifacts,
		payloadTTL:    config.PayloadTTL,
		metadataTTL:   config.MetadataTTL,
		sweepInterval: config.SweepInterval,
		batchSize:     config.BatchSize,
		drainDeadline: config.DrainDeadline,
		done:          make(chan struct{}),
	}, nil
}

// Start performs one bounded startup sweep and then ticks at the configured interval.
func (r *RetentionRunner) Start() error {
	if r == nil {
		return errors.New("retention runner is nil")
	}
	r.startMu.Lock()
	defer r.startMu.Unlock()
	if r.started {
		return nil
	}
	if err := r.RunOnce(context.Background(), time.Now().UTC()); err != nil {
		r.setError(err)
		return err
	}
	ctx, cancel := context.WithCancel(context.Background())
	r.cancel = cancel
	r.started = true
	r.clearError()
	go r.run(ctx)
	return nil
}

func (r *RetentionRunner) run(ctx context.Context) {
	ticker := time.NewTicker(r.sweepInterval)
	defer ticker.Stop()
	defer close(r.done)
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			if err := r.RunOnce(ctx, now.UTC()); err != nil {
				r.setError(err)
			} else {
				r.clearError()
			}
		}
	}
}

// Close stops intake, waits for the worker, and performs one final bounded drain.
func (r *RetentionRunner) Close(ctx context.Context) error {
	if r == nil {
		return nil
	}
	if ctx == nil {
		return errors.New("retention close context is nil")
	}
	r.startMu.Lock()
	started := r.started
	cancel := r.cancel
	r.startMu.Unlock()
	r.stopOnce.Do(func() {
		if cancel != nil {
			cancel()
		}
	})
	if started {
		select {
		case <-r.done:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	drainCtx, cancelDrain := context.WithTimeout(ctx, r.drainDeadline)
	defer cancelDrain()
	err := r.RunOnce(drainCtx, time.Now().UTC())
	if err != nil {
		r.setError(err)
		return err
	}
	r.clearError()
	return nil
}

// Health returns the latest sweep result without interrupting callers.
func (r *RetentionRunner) Health() RetentionHealth {
	if r == nil {
		return RetentionHealth{Err: errors.New("retention runner is nil")}
	}
	r.healthMu.RLock()
	err := r.lastErr
	r.healthMu.RUnlock()
	return RetentionHealth{Healthy: err == nil, Err: err}
}

func (r *RetentionRunner) setError(err error) {
	if err == nil {
		return
	}
	r.healthMu.Lock()
	r.lastErr = err
	r.healthMu.Unlock()
}

func (r *RetentionRunner) clearError() {
	r.healthMu.Lock()
	r.lastErr = nil
	r.healthMu.Unlock()
}

func (r *RetentionRunner) workerDone() bool {
	if r == nil {
		return true
	}
	r.startMu.Lock()
	started := r.started
	r.startMu.Unlock()
	if !started {
		return true
	}
	select {
	case <-r.done:
		return true
	default:
		return false
	}
}

// RunOnce executes one bounded payload, artifact, metadata, audit, and admin-session sweep.
func (r *RetentionRunner) RunOnce(ctx context.Context, now time.Time) error {
	if r == nil {
		return errors.New("retention runner is nil")
	}
	if ctx == nil {
		return errors.New("retention context is nil")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	sweepCtx, cancel := context.WithTimeout(ctx, retentionSweepDeadline)
	defer cancel()
	var errs []error
	if err := r.sweepPayloads(sweepCtx, now); err != nil {
		errs = append(errs, err)
	}
	if err := r.sweepArtifacts(sweepCtx, now); err != nil {
		errs = append(errs, err)
	}
	if err := r.sweepMetadata(sweepCtx, now); err != nil {
		errs = append(errs, err)
	}
	if err := r.sweepStandaloneAudits(sweepCtx, now); err != nil {
		errs = append(errs, err)
	}
	if err := r.sweepAdminSessions(sweepCtx, now); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

func (r *RetentionRunner) sweepAdminSessions(ctx context.Context, now time.Time) error {
	if !r.db.Migrator().HasTable(&AdminSession{}) {
		return nil
	}
	var sessions []AdminSession
	if err := r.db.WithContext(ctx).
		Where("revoked_at IS NOT NULL OR expires_at <= ? OR idle_expires_at <= ?", now, now).
		Order("expires_at ASC").
		Limit(r.batchSize).
		Find(&sessions).Error; err != nil {
		return fmt.Errorf("load expired admin sessions: %w", err)
	}
	for _, session := range sessions {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := r.db.WithContext(ctx).Where("id = ?", session.ID).Delete(&AdminSession{}).Error; err != nil {
			return fmt.Errorf("delete expired admin session: %w", err)
		}
	}
	if !r.db.Migrator().HasTable(&AdminLoginNonce{}) {
		return nil
	}
	var nonces []AdminLoginNonce
	if err := r.db.WithContext(ctx).
		Where("used_at IS NOT NULL OR expires_at <= ?", now).
		Order("expires_at ASC").
		Limit(r.batchSize).
		Find(&nonces).Error; err != nil {
		return fmt.Errorf("load expired admin login nonces: %w", err)
	}
	for _, nonce := range nonces {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := r.db.WithContext(ctx).Where("id = ?", nonce.ID).Delete(&AdminLoginNonce{}).Error; err != nil {
			return fmt.Errorf("delete expired admin login nonce: %w", err)
		}
	}
	return nil
}

func (r *RetentionRunner) sweepStandaloneAudits(ctx context.Context, now time.Time) error {
	var audits []AuditRecord
	if err := r.db.WithContext(ctx).
		Where("request_id = ? AND expires_at > ? AND expires_at <= ?", "", time.Time{}, now).
		Order("expires_at ASC").
		Limit(r.batchSize).
		Find(&audits).Error; err != nil {
		return fmt.Errorf("load expired standalone audits: %w", err)
	}
	for _, audit := range audits {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := r.db.WithContext(ctx).
			Where("id = ? AND request_id = ? AND expires_at > ? AND expires_at <= ?", audit.ID, "", time.Time{}, now).
			Delete(&AuditRecord{}).Error; err != nil {
			return fmt.Errorf("delete expired standalone audit %q: %w", audit.ID, err)
		}
	}
	return nil
}

func (r *RetentionRunner) sweepPayloads(ctx context.Context, now time.Time) error {
	var records []EncryptedPayloadRecord
	if err := r.db.WithContext(ctx).Where("expires_at > ? AND expires_at <= ?", time.Time{}, now).Order("expires_at ASC").Limit(r.batchSize).Find(&records).Error; err != nil {
		return fmt.Errorf("load expired payloads: %w", err)
	}
	for _, record := range records {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := r.deleteExpiredPayload(ctx, record.ID); err != nil {
			return err
		}
	}
	return nil
}

func (r *RetentionRunner) deleteExpiredPayload(ctx context.Context, payloadID string) error {
	return r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		terminal, err := payloadOwnersTerminalTx(tx, payloadID)
		if err != nil {
			return fmt.Errorf("check expired payload ownership: %w", err)
		}
		if !terminal {
			return nil
		}
		if err := tx.Where("payload_id = ?", payloadID).Delete(&StreamEventRecord{}).Error; err != nil {
			return fmt.Errorf("delete expired stream events: %w", err)
		}
		if err := tx.Model(&AuditRecord{}).Where("payload_id = ?", payloadID).Update("payload_id", "").Error; err != nil {
			return fmt.Errorf("clear expired audit payload refs: %w", err)
		}
		if err := tx.Where("replay_id = ?", payloadID).Delete(&UsageRecord{}).Error; err != nil {
			return fmt.Errorf("delete expired usage: %w", err)
		}
		if err := tx.Where("replay_id = ?", payloadID).Delete(&JournalReceipt{}).Error; err != nil {
			return fmt.Errorf("delete expired journal receipts: %w", err)
		}
		if err := tx.Where("replay_id = ?", payloadID).Delete(&JournalRecord{}).Error; err != nil {
			return fmt.Errorf("delete expired journal records: %w", err)
		}
		if err := tx.Where("id = ?", payloadID).Delete(&EncryptedPayloadRecord{}).Error; err != nil {
			return fmt.Errorf("delete expired payload: %w", err)
		}
		return nil
	})
}

func payloadOwnersTerminalTx(tx *gorm.DB, payloadID string) (bool, error) {
	requestIDs := make(map[string]struct{})
	var streamOwners []string
	if err := tx.Model(&StreamEventRecord{}).Where("payload_id = ? AND request_id <> ''", payloadID).Distinct("request_id").Pluck("request_id", &streamOwners).Error; err != nil {
		return false, err
	}
	for _, id := range streamOwners {
		requestIDs[id] = struct{}{}
	}
	var journalOwners []string
	if err := tx.Model(&JournalRecord{}).Where("replay_id = ? AND request_id <> ''", payloadID).Distinct("request_id").Pluck("request_id", &journalOwners).Error; err != nil {
		return false, err
	}
	for _, id := range journalOwners {
		requestIDs[id] = struct{}{}
	}
	var auditOwners []string
	if err := tx.Model(&AuditRecord{}).Where("payload_id = ? AND request_id <> ''", payloadID).Distinct("request_id").Pluck("request_id", &auditOwners).Error; err != nil {
		return false, err
	}
	for _, id := range auditOwners {
		requestIDs[id] = struct{}{}
	}
	for id := range requestIDs {
		var request RequestRecord
		if err := tx.Select("terminal_at").Where("request_id = ?", id).First(&request).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return false, nil
			}
			return false, err
		}
		if request.TerminalAt == nil {
			return false, nil
		}
	}
	return true, nil
}

func (r *RetentionRunner) sweepArtifacts(ctx context.Context, now time.Time) error {
	if r.artifacts == nil {
		return nil
	}
	var records []ArtifactRecord
	query := r.db.WithContext(ctx).Where("state = ? OR (state = ? AND expires_at > ? AND expires_at <= ?)", artifactStateDeleting, artifactStateReady, time.Time{}, now).Order("expires_at ASC").Limit(r.batchSize)
	if err := query.Find(&records).Error; err != nil {
		return fmt.Errorf("load expired artifacts: %w", err)
	}
	if len(records) == 0 {
		return nil
	}
	ids := make([]string, len(records))
	for index := range records {
		ids[index] = records[index].ID
	}
	claimed, err := r.artifacts.MarkDeleting(ctx, ids)
	if err != nil {
		return err
	}
	return r.artifacts.RemoveMarked(ctx, claimed)
}

func (r *RetentionRunner) sweepMetadata(ctx context.Context, now time.Time) error {
	var requests []RequestRecord
	if err := r.db.WithContext(ctx).Where("terminal_at IS NOT NULL AND expires_at > ? AND expires_at <= ?", time.Time{}, now).Order("expires_at ASC").Limit(r.batchSize).Find(&requests).Error; err != nil {
		return fmt.Errorf("load expired lifecycle requests: %w", err)
	}
	for _, request := range requests {
		if err := ctx.Err(); err != nil {
			return err
		}
		var artifactCount int64
		if err := r.db.WithContext(ctx).Model(&ArtifactRecord{}).Where("request_id = ?", request.ID).Count(&artifactCount).Error; err != nil {
			return fmt.Errorf("check request artifacts: %w", err)
		}
		if artifactCount != 0 {
			continue
		}
		var contentCount int64
		if err := r.db.WithContext(ctx).Raw(
			"SELECT COUNT(*) FROM encrypted_payloads WHERE id IN (SELECT replay_id FROM journal_records WHERE request_id = ? UNION SELECT payload_id FROM audit_records WHERE request_id = ?) OR id = ?",
			request.ID, request.ID, request.ReplayID,
		).Scan(&contentCount).Error; err != nil {
			return fmt.Errorf("check request encrypted content: %w", err)
		}
		if contentCount != 0 {
			continue
		}
		var journalCount int64
		if err := r.db.WithContext(ctx).Model(&JournalRecord{}).Where("request_id = ?", request.ID).Count(&journalCount).Error; err != nil {
			return fmt.Errorf("check request journal content: %w", err)
		}
		if journalCount != 0 {
			continue
		}
		var eventCount int64
		if err := r.db.WithContext(ctx).Model(&StreamEventRecord{}).Where("request_id = ?", request.ID).Count(&eventCount).Error; err != nil {
			return fmt.Errorf("check request events: %w", err)
		}
		if eventCount != 0 {
			continue
		}
		if err := r.deleteExpiredRequest(ctx, request); err != nil {
			return err
		}
	}
	return r.deleteExpiredConversations(ctx, now)
}

func (r *RetentionRunner) deleteExpiredRequest(ctx context.Context, request RequestRecord) error {
	return r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("request_id = ?", request.ID).Delete(&UsageRecord{}).Error; err != nil {
			return fmt.Errorf("delete request usage: %w", err)
		}
		if err := tx.Where("request_id = ?", request.ID).Delete(&AuditRecord{}).Error; err != nil {
			return fmt.Errorf("delete request audits: %w", err)
		}
		if err := tx.Where("request_id = ?", request.ID).Delete(&JournalReceipt{}).Error; err != nil {
			return fmt.Errorf("delete request receipts: %w", err)
		}
		if err := tx.Where("request_id = ?", request.ID).Delete(&JournalRecord{}).Error; err != nil {
			return fmt.Errorf("delete request journal records: %w", err)
		}
		if err := tx.Where("request_id = ?", request.ID).Delete(&JournalRequestRecord{}).Error; err != nil {
			return fmt.Errorf("delete request journal metadata: %w", err)
		}
		if request.ReplayID != "" {
			if err := tx.Where("id = ?", request.ReplayID).Delete(&EncryptedPayloadRecord{}).Error; err != nil {
				return fmt.Errorf("delete request encrypted payload: %w", err)
			}
		}
		if err := tx.Where("request_id = ?", request.ID).Delete(&RequestRecord{}).Error; err != nil {
			return fmt.Errorf("delete request metadata: %w", err)
		}
		return nil
	})
}

func (r *RetentionRunner) deleteExpiredConversations(ctx context.Context, now time.Time) error {
	var conversations []ConversationRecord
	if err := r.db.WithContext(ctx).Where("(deleting_at IS NOT NULL) OR (expires_at > ? AND expires_at <= ?)", time.Time{}, now).Order("expires_at ASC").Limit(r.batchSize).Find(&conversations).Error; err != nil {
		return fmt.Errorf("load expired conversations: %w", err)
	}
	for _, conversation := range conversations {
		if err := r.DeleteConversation(ctx, conversation.ID); err != nil {
			if errors.Is(err, errConversationHasRunningRequest) {
				continue
			}
			return err
		}
	}
	return nil
}

func pendingConversationJournalRequests(tx *gorm.DB, conversationID string) (bool, error) {
	var pending int64
	if err := tx.Raw(
		"SELECT COUNT(*) FROM journal_requests jr WHERE jr.conversation_id = ? AND (NOT EXISTS (SELECT 1 FROM requests r WHERE r.request_id = jr.request_id) OR EXISTS (SELECT 1 FROM requests r WHERE r.request_id = jr.request_id AND r.terminal_at IS NULL))",
		conversationID,
	).Scan(&pending).Error; err != nil {
		return false, fmt.Errorf("check pending conversation journal requests: %w", err)
	}
	return pending != 0, nil
}

func (r *RetentionRunner) markConversationDeleting(ctx context.Context, id string, actor AdminPrincipal) (bool, error) {
	var marked bool
	err := r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var conversation ConversationRecord
		err := tx.Where("id = ?", id).First(&conversation).Error
		if errors.Is(err, gorm.ErrRecordNotFound) {
			var running int64
			if err := tx.Model(&RequestRecord{}).Where("conversation_id = ? AND terminal_at IS NULL", id).Count(&running).Error; err != nil {
				return fmt.Errorf("check running conversation requests: %w", err)
			}
			if running != 0 {
				return errConversationHasRunningRequest
			}
			pendingJournal, err := pendingConversationJournalRequests(tx, id)
			if err != nil {
				return err
			}
			if pendingJournal {
				return errConversationHasRunningRequest
			}
			var pending int64
			if err := tx.Raw(
				"SELECT (SELECT COUNT(*) FROM requests WHERE conversation_id = ?) + (SELECT COUNT(*) FROM artifacts WHERE conversation_id = ?)",
				id, id,
			).Scan(&pending).Error; err != nil {
				return fmt.Errorf("check pending conversation ownership: %w", err)
			}
			if pending == 0 {
				return nil
			}
			now := time.Now().UTC()
			if actor.ID != "" {
				if err := writeAdminAudit(tx, actor, "conversation.delete", id, adminAuditMetadata{Fields: []string{"metadata", "content", "artifacts"}}, now); err != nil {
					return fmt.Errorf("store conversation deletion audit: %w", err)
				}
			}
			conversation = ConversationRecord{ID: id, CreatedAt: now, UpdatedAt: now, ExpiresAt: now, DeletingAt: &now}
			if err := tx.Create(&conversation).Error; err != nil {
				return fmt.Errorf("create conversation tombstone: %w", err)
			}
			marked = true
			return nil
		}
		if err != nil {
			return fmt.Errorf("load conversation for deletion: %w", err)
		}
		var running int64
		if err := tx.Model(&RequestRecord{}).Where("conversation_id = ? AND terminal_at IS NULL", id).Count(&running).Error; err != nil {
			return fmt.Errorf("check running conversation requests: %w", err)
		}
		if running != 0 {
			return errConversationHasRunningRequest
		}
		if conversation.DeletingAt == nil {
			pendingJournal, err := pendingConversationJournalRequests(tx, id)
			if err != nil {
				return err
			}
			if pendingJournal {
				return errConversationHasRunningRequest
			}
		}
		if conversation.DeletingAt != nil {
			marked = true
			return nil
		}
		now := time.Now().UTC()
		if actor.ID != "" {
			if err := writeAdminAudit(tx, actor, "conversation.delete", id, adminAuditMetadata{Fields: []string{"metadata", "content", "artifacts"}}, now); err != nil {
				return fmt.Errorf("store conversation deletion audit: %w", err)
			}
		}
		result := tx.Model(&ConversationRecord{}).Where("id = ? AND deleting_at IS NULL", id).Update("deleting_at", now)
		if result.Error != nil {
			return fmt.Errorf("mark conversation deleting: %w", result.Error)
		}
		if result.RowsAffected != 1 {
			return errors.New("conversation deletion transition was lost")
		}
		marked = true
		return nil
	})
	return marked, err
}

// DeleteConversation removes one conversation and all owned content idempotently.
func (r *RetentionRunner) DeleteConversation(ctx context.Context, id string) error {
	return r.deleteConversation(ctx, id, AdminPrincipal{})
}

func (r *RetentionRunner) DeleteConversationAsAdmin(ctx context.Context, id string, actor AdminPrincipal) error {
	if strings.TrimSpace(actor.ID) == "" || strings.TrimSpace(actor.Name) == "" || !actor.HasScope(AdminScopeMetadata) {
		return ErrAdminTokenForbidden
	}
	return r.deleteConversation(ctx, id, actor)
}

func (r *RetentionRunner) deleteConversation(ctx context.Context, id string, actor AdminPrincipal) error {
	if r == nil {
		return errors.New("retention runner is nil")
	}
	if ctx == nil {
		return errors.New("conversation delete context is nil")
	}
	if id == "" || len(id) > artifactMaxOwnerFieldSize {
		return errors.New("conversation ID is invalid")
	}
	r.deleteMu.Lock()
	defer r.deleteMu.Unlock()
	marked, err := r.markConversationDeleting(ctx, id, actor)
	if err != nil {
		return err
	}
	if !marked {
		return nil
	}
	for range retentionMaxDeleteBatches {
		if err := ctx.Err(); err != nil {
			return err
		}
		records, err := r.claimConversationArtifacts(ctx, id)
		if err != nil {
			return err
		}
		if len(records) == 0 {
			break
		}
		if r.artifacts == nil {
			return errors.New("conversation artifacts are unavailable")
		}
		if err := r.artifacts.RemoveMarked(ctx, records); err != nil {
			return err
		}
	}
	var remaining int64
	if err := r.db.WithContext(ctx).Model(&ArtifactRecord{}).Where("conversation_id = ?", id).Count(&remaining).Error; err != nil {
		return fmt.Errorf("probe conversation artifacts: %w", err)
	}
	if remaining != 0 {
		if err := r.db.WithContext(ctx).Model(&ArtifactRecord{}).Where("conversation_id = ? AND state IN ?", id, []string{artifactStateWriting, artifactStateReady}).Update("state", artifactStateDeleting).Error; err != nil {
			return fmt.Errorf("mark resumable conversation artifacts deleting: %w", err)
		}
		return errors.New("conversation artifact deletion exceeded bound")
	}
	return r.finalizeConversationDelete(ctx, id)
}

func (r *RetentionRunner) claimConversationArtifacts(ctx context.Context, conversationID string) ([]ArtifactRecord, error) {
	var records []ArtifactRecord
	if err := r.db.WithContext(ctx).Where("conversation_id = ? AND state IN ?", conversationID, []string{artifactStateWriting, artifactStateReady, artifactStateDeleting}).Order("created_at ASC").Limit(r.batchSize).Find(&records).Error; err != nil {
		return nil, fmt.Errorf("load conversation artifacts: %w", err)
	}
	if len(records) == 0 {
		return nil, nil
	}
	ids := make([]string, len(records))
	for index := range records {
		ids[index] = records[index].ID
	}
	if err := r.db.WithContext(ctx).Model(&ArtifactRecord{}).Where("id IN ?", ids).Update("state", artifactStateDeleting).Error; err != nil {
		return nil, fmt.Errorf("mark conversation artifacts deleting: %w", err)
	}
	for index := range records {
		records[index].State = artifactStateDeleting
	}
	return records, nil
}

func (r *RetentionRunner) finalizeConversationDelete(ctx context.Context, conversationID string) error {
	for range retentionMaxDeleteBatches {
		var requests []RequestRecord
		if err := r.db.WithContext(ctx).Where("conversation_id = ?", conversationID).Order("request_id ASC").Limit(r.batchSize).Find(&requests).Error; err != nil {
			return fmt.Errorf("load conversation requests: %w", err)
		}
		if len(requests) == 0 {
			break
		}
		ids := make([]string, len(requests))
		for index := range requests {
			ids[index] = requests[index].ID
		}
		if err := r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
			var artifacts int64
			if err := tx.Model(&ArtifactRecord{}).Where("conversation_id = ?", conversationID).Count(&artifacts).Error; err != nil {
				return fmt.Errorf("check conversation artifacts: %w", err)
			}
			if artifacts != 0 {
				return errors.New("conversation artifacts remain")
			}
			var payloadIDs []string
			if err := tx.Model(&StreamEventRecord{}).Where("request_id IN ?", ids).Pluck("payload_id", &payloadIDs).Error; err != nil {
				return fmt.Errorf("load conversation event payloads: %w", err)
			}
			var requestPayloadIDs []string
			if err := tx.Model(&RequestRecord{}).Where("request_id IN ?", ids).Pluck("accepted_replay_id", &requestPayloadIDs).Error; err != nil {
				return fmt.Errorf("load conversation request payloads: %w", err)
			}
			var auditPayloadIDs []string
			if err := tx.Model(&AuditRecord{}).Where("request_id IN ?", ids).Pluck("payload_id", &auditPayloadIDs).Error; err != nil {
				return fmt.Errorf("load conversation audit payloads: %w", err)
			}
			var journalPayloadIDs []string
			if err := tx.Model(&JournalRecord{}).Where("request_id IN ?", ids).Pluck("replay_id", &journalPayloadIDs).Error; err != nil {
				return fmt.Errorf("load conversation journal payloads: %w", err)
			}
			payloadIDs = append(payloadIDs, requestPayloadIDs...)
			payloadIDs = append(payloadIDs, auditPayloadIDs...)
			payloadIDs = append(payloadIDs, journalPayloadIDs...)
			if err := tx.Where("request_id IN ?", ids).Delete(&StreamEventRecord{}).Error; err != nil {
				return fmt.Errorf("delete conversation stream events: %w", err)
			}
			if err := tx.Where("request_id IN ?", ids).Delete(&UsageRecord{}).Error; err != nil {
				return fmt.Errorf("delete conversation usage: %w", err)
			}
			if err := tx.Where("request_id IN ?", ids).Delete(&AuditRecord{}).Error; err != nil {
				return fmt.Errorf("delete conversation audits: %w", err)
			}
			if err := tx.Where("request_id IN ?", ids).Delete(&JournalReceipt{}).Error; err != nil {
				return fmt.Errorf("delete conversation receipts: %w", err)
			}
			if err := tx.Where("request_id IN ?", ids).Delete(&JournalRecord{}).Error; err != nil {
				return fmt.Errorf("delete conversation journal records: %w", err)
			}
			if len(payloadIDs) > 0 {
				if err := tx.Where("id IN ?", payloadIDs).Delete(&EncryptedPayloadRecord{}).Error; err != nil {
					return fmt.Errorf("delete conversation encrypted payloads: %w", err)
				}
			}
			if err := tx.Where("request_id IN ?", ids).Delete(&JournalRequestRecord{}).Error; err != nil {
				return fmt.Errorf("delete conversation journal metadata: %w", err)
			}
			if err := tx.Where("request_id IN ?", ids).Delete(&RequestRecord{}).Error; err != nil {
				return fmt.Errorf("delete conversation requests: %w", err)
			}
			return nil
		}); err != nil {
			return err
		}
	}
	var remaining int64
	if err := r.db.WithContext(ctx).Model(&RequestRecord{}).Where("conversation_id = ?", conversationID).Count(&remaining).Error; err != nil {
		return fmt.Errorf("probe conversation requests: %w", err)
	}
	if remaining != 0 {
		return errors.New("conversation request deletion exceeded bound")
	}
	return r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var conversation ConversationRecord
		if err := tx.Where("id = ? AND deleting_at IS NOT NULL", conversationID).First(&conversation).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return nil
			}
			return fmt.Errorf("check tombstoned conversation: %w", err)
		}
		var running int64
		if err := tx.Model(&RequestRecord{}).Where("conversation_id = ? AND terminal_at IS NULL", conversationID).Count(&running).Error; err != nil {
			return fmt.Errorf("check final running requests: %w", err)
		}
		if running != 0 {
			return errConversationHasRunningRequest
		}
		var orphanRequestIDs []string
		if err := tx.Model(&JournalRequestRecord{}).Where("conversation_id = ?", conversationID).Pluck("request_id", &orphanRequestIDs).Error; err != nil {
			return fmt.Errorf("load orphan conversation journal requests: %w", err)
		}
		if len(orphanRequestIDs) > 0 {
			var payloadIDs []string
			if err := tx.Model(&JournalRecord{}).Where("request_id IN ?", orphanRequestIDs).Pluck("replay_id", &payloadIDs).Error; err != nil {
				return fmt.Errorf("load orphan conversation journal payloads: %w", err)
			}
			if err := tx.Where("request_id IN ?", orphanRequestIDs).Delete(&StreamEventRecord{}).Error; err != nil {
				return fmt.Errorf("delete orphan conversation stream events: %w", err)
			}
			if err := tx.Where("request_id IN ?", orphanRequestIDs).Delete(&UsageRecord{}).Error; err != nil {
				return fmt.Errorf("delete orphan conversation usage: %w", err)
			}
			if err := tx.Where("request_id IN ?", orphanRequestIDs).Delete(&AuditRecord{}).Error; err != nil {
				return fmt.Errorf("delete orphan conversation audits: %w", err)
			}
			if err := tx.Where("request_id IN ?", orphanRequestIDs).Delete(&JournalReceipt{}).Error; err != nil {
				return fmt.Errorf("delete orphan conversation receipts: %w", err)
			}
			if err := tx.Where("request_id IN ?", orphanRequestIDs).Delete(&JournalRecord{}).Error; err != nil {
				return fmt.Errorf("delete orphan conversation journal records: %w", err)
			}
			if len(payloadIDs) > 0 {
				if err := tx.Where("id IN ?", payloadIDs).Delete(&EncryptedPayloadRecord{}).Error; err != nil {
					return fmt.Errorf("delete orphan conversation payloads: %w", err)
				}
			}
			if err := tx.Where("request_id IN ?", orphanRequestIDs).Delete(&JournalRequestRecord{}).Error; err != nil {
				return fmt.Errorf("delete orphan conversation journal metadata: %w", err)
			}
		}
		var artifacts int64
		if err := tx.Model(&ArtifactRecord{}).Where("conversation_id = ?", conversationID).Count(&artifacts).Error; err != nil {
			return fmt.Errorf("check final conversation artifacts: %w", err)
		}
		if artifacts != 0 {
			return errors.New("conversation artifacts remain")
		}
		var requests int64
		if err := tx.Model(&RequestRecord{}).Where("conversation_id = ?", conversationID).Count(&requests).Error; err != nil {
			return fmt.Errorf("check final conversation requests: %w", err)
		}
		if requests != 0 {
			return errors.New("conversation requests remain")
		}
		if err := tx.Where("conversation_id = ?", conversationID).Delete(&ArtifactRecord{}).Error; err != nil {
			return fmt.Errorf("delete conversation artifact metadata: %w", err)
		}
		if err := tx.Where("id = ?", conversationID).Delete(&ConversationRecord{}).Error; err != nil {
			return fmt.Errorf("delete conversation metadata: %w", err)
		}
		return nil
	})
}
