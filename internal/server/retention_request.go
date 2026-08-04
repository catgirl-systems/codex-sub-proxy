package server

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"gorm.io/gorm"
)

var errRequestHasRunningRequest = errors.New("request is running")

// DeleteRequest removes one terminal request and all owned content idempotently.
func (r *RetentionRunner) DeleteRequest(ctx context.Context, id string) error {
	return r.deleteRequest(ctx, id, AdminPrincipal{})
}

func (r *RetentionRunner) DeleteRequestAsAdmin(ctx context.Context, id string, actor AdminPrincipal) error {
	if strings.TrimSpace(actor.ID) == "" || strings.TrimSpace(actor.Name) == "" || !actor.HasScope(AdminScopeMetadata) {
		return ErrAdminTokenForbidden
	}
	return r.deleteRequest(ctx, id, actor)
}

func (r *RetentionRunner) deleteRequest(ctx context.Context, id string, actor AdminPrincipal) error {
	if r == nil {
		return errors.New("retention runner is nil")
	}
	if ctx == nil {
		return errors.New("request delete context is nil")
	}
	if !validJournalUUID(id) {
		return errors.New("request ID is invalid")
	}
	r.deleteMu.Lock()
	defer r.deleteMu.Unlock()
	marked, err := r.markRequestDeleting(ctx, id, actor)
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
		records, err := r.claimRequestArtifacts(ctx, id)
		if err != nil {
			return err
		}
		if len(records) == 0 {
			break
		}
		if r.artifacts == nil {
			return errors.New("request artifacts are unavailable")
		}
		if err := r.artifacts.RemoveMarked(ctx, records); err != nil {
			return err
		}
	}
	var remaining int64
	if err := r.db.WithContext(ctx).Model(&ArtifactRecord{}).Where("request_id = ?", id).Count(&remaining).Error; err != nil {
		return fmt.Errorf("probe request artifacts: %w", err)
	}
	if remaining != 0 {
		if err := r.db.WithContext(ctx).Model(&ArtifactRecord{}).Where("request_id = ? AND state IN ?", id, []string{artifactStateWriting, artifactStateReady}).Update("state", artifactStateDeleting).Error; err != nil {
			return fmt.Errorf("mark resumable request artifacts deleting: %w", err)
		}
		return errors.New("request artifact deletion exceeded bound")
	}
	return r.finalizeRequestDelete(ctx, id)
}

func (r *RetentionRunner) markRequestDeleting(ctx context.Context, id string, actor AdminPrincipal) (bool, error) {
	var marked bool
	err := r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var request RequestRecord
		err := tx.Where("request_id = ?", id).First(&request).Error
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("load request for deletion: %w", err)
		}
		if request.TerminalAt == nil {
			return errRequestHasRunningRequest
		}
		if request.DeletingAt != nil {
			marked = true
			return nil
		}
		now := time.Now().UTC()
		if actor.ID != "" {
			if err := writeAdminAudit(tx, actor, "request.delete", id, adminAuditMetadata{Fields: []string{"metadata", "content", "artifacts"}}, now); err != nil {
				return fmt.Errorf("store request deletion audit: %w", err)
			}
		}
		result := tx.Model(&RequestRecord{}).Where("request_id = ? AND terminal_at IS NOT NULL AND deleting_at IS NULL", id).Update("deleting_at", now)
		if result.Error != nil {
			return fmt.Errorf("mark request deleting: %w", result.Error)
		}
		if result.RowsAffected != 1 {
			return errors.New("request deletion transition was lost")
		}
		marked = true
		return nil
	})
	return marked, err
}

func (r *RetentionRunner) claimRequestArtifacts(ctx context.Context, requestID string) ([]ArtifactRecord, error) {
	var records []ArtifactRecord
	if err := r.db.WithContext(ctx).Where("request_id = ? AND state IN ?", requestID, []string{artifactStateWriting, artifactStateReady, artifactStateDeleting}).Order("created_at ASC").Order("id ASC").Limit(r.batchSize).Find(&records).Error; err != nil {
		return nil, fmt.Errorf("load request artifacts: %w", err)
	}
	if len(records) == 0 {
		return nil, nil
	}
	ids := make([]string, len(records))
	for index := range records {
		ids[index] = records[index].ID
	}
	if err := r.db.WithContext(ctx).Model(&ArtifactRecord{}).Where("id IN ?", ids).Update("state", artifactStateDeleting).Error; err != nil {
		return nil, fmt.Errorf("mark request artifacts deleting: %w", err)
	}
	for index := range records {
		records[index].State = artifactStateDeleting
	}
	return records, nil
}

func (r *RetentionRunner) finalizeRequestDelete(ctx context.Context, requestID string) error {
	return r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var request RequestRecord
		if err := tx.Where("request_id = ? AND deleting_at IS NOT NULL", requestID).First(&request).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return nil
			}
			return fmt.Errorf("check deleting request: %w", err)
		}
		var artifacts int64
		if err := tx.Model(&ArtifactRecord{}).Where("request_id = ?", requestID).Count(&artifacts).Error; err != nil {
			return fmt.Errorf("check request artifacts: %w", err)
		}
		if artifacts != 0 {
			return errors.New("request artifacts remain")
		}
		var running int64
		if err := tx.Model(&RequestRecord{}).Where("request_id = ? AND terminal_at IS NULL", requestID).Count(&running).Error; err != nil {
			return fmt.Errorf("check request state: %w", err)
		}
		if running != 0 {
			return errRequestHasRunningRequest
		}
		if err := tx.Exec(`
DELETE FROM encrypted_payloads
WHERE id = ?
   OR id IN (
       SELECT payload_id FROM stream_events WHERE request_id = ?
       UNION SELECT payload_id FROM audit_records WHERE request_id = ? AND payload_id <> ''
       UNION SELECT replay_id FROM journal_records WHERE request_id = ?
   )`, request.ReplayID, requestID, requestID, requestID).Error; err != nil {
			return fmt.Errorf("delete request encrypted payloads: %w", err)
		}
		for _, model := range []any{&StreamEventRecord{}, &UsageRecord{}, &AuditRecord{}, &JournalReceipt{}, &JournalRecord{}, &JournalRequestRecord{}} {
			if err := tx.Where("request_id = ?", requestID).Delete(model).Error; err != nil {
				return fmt.Errorf("delete request lifecycle rows: %w", err)
			}
		}
		if err := tx.Where("request_id = ? AND deleting_at IS NOT NULL", requestID).Delete(&RequestRecord{}).Error; err != nil {
			return fmt.Errorf("delete request metadata: %w", err)
		}
		if request.ConversationID != "" {
			if err := tx.Model(&ConversationRecord{}).Where("id = ? AND request_count > 0", request.ConversationID).UpdateColumn("request_count", gorm.Expr("request_count - 1")).Error; err != nil {
				return fmt.Errorf("update conversation request count: %w", err)
			}
		}
		return nil
	})
}
