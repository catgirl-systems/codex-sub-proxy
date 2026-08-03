package server

import (
	"context"
	"errors"
	"fmt"
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
)

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
	cancel        context.CancelFunc
	done          chan struct{}
	startOnce     sync.Once
	stopOnce      sync.Once
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
	r.startOnce.Do(func() {
		_ = r.RunOnce(context.Background(), time.Now().UTC())
		ctx, cancel := context.WithCancel(context.Background())
		r.cancel = cancel
		go r.run(ctx)
	})
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
			_ = r.RunOnce(ctx, now.UTC())
		}
	}
}

// Close cancels the worker and drains one current bounded batch within the deadline.
func (r *RetentionRunner) Close(ctx context.Context) error {
	if r == nil {
		return nil
	}
	if ctx == nil {
		return errors.New("retention close context is nil")
	}
	var closeErr error
	r.stopOnce.Do(func() {
		if r.cancel == nil {
			return
		}
		r.cancel()
		select {
		case <-r.done:
		case <-ctx.Done():
			closeErr = ctx.Err()
			return
		}
		drainCtx, cancel := context.WithTimeout(ctx, r.drainDeadline)
		defer cancel()
		closeErr = r.RunOnce(drainCtx, time.Now().UTC())
	})
	return closeErr
}

// RunOnce executes one bounded payload, artifact, and metadata sweep.
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
	var errs []error
	if err := r.sweepPayloads(ctx, now); err != nil {
		errs = append(errs, err)
	}
	if err := r.sweepArtifacts(ctx, now); err != nil {
		errs = append(errs, err)
	}
	if err := r.sweepMetadata(ctx, now); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

func (r *RetentionRunner) sweepPayloads(ctx context.Context, now time.Time) error {
	var records []EncryptedPayloadRecord
	if err := r.db.WithContext(ctx).Where("expires_at > ? AND expires_at <= ?", time.Time{}, now).Order("expires_at ASC").Limit(r.batchSize).Find(&records).Error; err != nil {
		return fmt.Errorf("load expired payloads: %w", err)
	}
	if len(records) == 0 {
		return nil
	}
	return r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		ids := make([]string, len(records))
		for index := range records {
			ids[index] = records[index].ID
		}
		if err := tx.Where("payload_id IN ?", ids).Delete(&StreamEventRecord{}).Error; err != nil {
			return fmt.Errorf("delete expired stream events: %w", err)
		}
		if err := tx.Model(&AuditRecord{}).Where("payload_id IN ?", ids).Update("payload_id", "").Error; err != nil {
			return fmt.Errorf("clear expired audit payload refs: %w", err)
		}
		if err := tx.Where("replay_id IN ?", ids).Delete(&UsageRecord{}).Error; err != nil {
			return fmt.Errorf("delete expired usage: %w", err)
		}
		if err := tx.Where("replay_id IN ?", ids).Delete(&JournalReceipt{}).Error; err != nil {
			return fmt.Errorf("delete expired journal receipts: %w", err)
		}
		if err := tx.Where("replay_id IN ?", ids).Delete(&JournalRecord{}).Error; err != nil {
			return fmt.Errorf("delete expired journal records: %w", err)
		}
		if err := tx.Where("id IN ?", ids).Delete(&EncryptedPayloadRecord{}).Error; err != nil {
			return fmt.Errorf("delete expired payloads: %w", err)
		}
		return nil
	})
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
	if err := r.db.WithContext(ctx).Where("expires_at > ? AND expires_at <= ?", time.Time{}, now).Order("expires_at ASC").Limit(r.batchSize).Find(&conversations).Error; err != nil {
		return fmt.Errorf("load expired conversations: %w", err)
	}
	for _, conversation := range conversations {
		var requestCount int64
		if err := r.db.WithContext(ctx).Model(&RequestRecord{}).Where("conversation_id = ?", conversation.ID).Count(&requestCount).Error; err != nil {
			return fmt.Errorf("check conversation requests: %w", err)
		}
		if requestCount != 0 {
			continue
		}
		if err := r.db.WithContext(ctx).Where("id = ?", conversation.ID).Delete(&ConversationRecord{}).Error; err != nil {
			return fmt.Errorf("delete conversation metadata: %w", err)
		}
	}
	return nil
}

// DeleteConversation removes one conversation and all owned content idempotently.
func (r *RetentionRunner) DeleteConversation(ctx context.Context, id string) error {
	if r == nil {
		return errors.New("retention runner is nil")
	}
	if ctx == nil {
		return errors.New("conversation delete context is nil")
	}
	if id == "" || len(id) > artifactMaxOwnerFieldSize {
		return errors.New("conversation ID is invalid")
	}
	for batch := 0; batch < retentionMaxDeleteBatches; batch++ {
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
		if batch == retentionMaxDeleteBatches-1 {
			return errors.New("conversation artifact deletion exceeded bound")
		}
	}
	return r.finalizeConversationDelete(ctx, id)
}

func (r *RetentionRunner) claimConversationArtifacts(ctx context.Context, conversationID string) ([]ArtifactRecord, error) {
	var records []ArtifactRecord
	if err := r.db.WithContext(ctx).Where("conversation_id = ? AND state IN ?", conversationID, []string{artifactStateReady, artifactStateDeleting}).Order("created_at ASC").Limit(r.batchSize).Find(&records).Error; err != nil {
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
	for batch := 0; batch < retentionMaxDeleteBatches; batch++ {
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
			var auditPayloadIDs []string
			if err := tx.Model(&AuditRecord{}).Where("request_id IN ?", ids).Pluck("payload_id", &auditPayloadIDs).Error; err != nil {
				return fmt.Errorf("load conversation audit payloads: %w", err)
			}
			var journalPayloadIDs []string
			if err := tx.Model(&JournalRecord{}).Where("request_id IN ?", ids).Pluck("replay_id", &journalPayloadIDs).Error; err != nil {
				return fmt.Errorf("load conversation journal payloads: %w", err)
			}
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
		if batch == retentionMaxDeleteBatches-1 {
			return errors.New("conversation request deletion exceeded bound")
		}
	}
	return r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
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
