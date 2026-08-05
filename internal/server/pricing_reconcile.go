package server

import (
	"context"
	"errors"
	"fmt"
	"time"

	"gorm.io/gorm"
)

const (
	pricingReconcileBatchSize = 64
	pricingReconcileMaxRows   = 8192
)

func (j *Journal) reconcileUsagePricing(tx *gorm.DB, requestID string, terminalAt time.Time) error {
	return reconcileUsagePricing(tx, j.pricing, requestID, terminalAt)
}

func reconcileUsagePricing(tx *gorm.DB, pricing *PricingStore, requestID string, terminalAt time.Time) error {
	var request RequestRecord
	if err := tx.Select("request_id, model, requested_model, resolved_model, created_at, accepted_at").Where("request_id = ?", requestID).First(&request).Error; err != nil {
		return fmt.Errorf("load request for pricing: %w", err)
	}
	modelID := request.ResolvedModel
	if modelID == "" {
		modelID = request.RequestedModel
	}
	if modelID == "" {
		modelID = request.Model
	}
	if modelID == "" {
		return nil
	}
	createdAt := request.CreatedAt
	if createdAt.IsZero() {
		createdAt = request.AcceptedAt
	}
	if createdAt.IsZero() {
		createdAt = terminalAt
	}
	var usages []UsageRecord
	if err := tx.Where("request_id = ?", requestID).Order("created_at ASC, replay_id ASC").Find(&usages).Error; err != nil {
		return fmt.Errorf("load usage for pricing: %w", err)
	}
	for _, usage := range usages {
		version, price, found, err := pricing.resolvePricing(tx, createdAt.UTC(), modelID)
		if err != nil {
			return err
		}
		if !found {
			continue
		}
		cost, reproducible, err := EstimateUsageCost(price, usage)
		if err != nil || !reproducible {
			continue
		}
		versionID := version.ID
		costValue := cost
		if err := tx.Model(&UsageRecord{}).Where("replay_id = ? AND (pricing_version_id IS NULL OR estimated_public_cost_microunits IS NULL OR priced_model = '')", usage.ReplayID).Updates(map[string]any{
			"priced_model":                     modelID,
			"pricing_version_id":               &versionID,
			"estimated_public_cost_microunits": &costValue,
		}).Error; err != nil {
			return fmt.Errorf("store usage pricing: %w", err)
		}
	}
	return nil
}

func reconcileTerminalUsagePricing(ctx context.Context, db *gorm.DB, pricing *PricingStore) error {
	if ctx == nil {
		return errors.New("pricing reconciliation context is nil")
	}
	const candidateWhere = "r.terminal_at IS NOT NULL AND (u.pricing_version_id IS NULL OR u.estimated_public_cost_microunits IS NULL OR u.priced_model = '')"
	processed := 0
	lastReplayID := ""
	for processed < pricingReconcileMaxRows {
		var candidates []struct {
			ReplayID  string    `gorm:"column:replay_id"`
			RequestID string    `gorm:"column:request_id"`
			Terminal  time.Time `gorm:"column:terminal_at"`
		}
		query := db.WithContext(ctx).Table("usage AS u").
			Select("u.replay_id, u.request_id, r.terminal_at").
			Joins("JOIN requests AS r ON r.request_id = u.request_id").
			Where(candidateWhere).
			Order("u.replay_id ASC").
			Limit(pricingReconcileBatchSize)
		if lastReplayID != "" {
			query = query.Where("u.replay_id > ?", lastReplayID)
		}
		if err := query.Find(&candidates).Error; err != nil {
			return fmt.Errorf("load pricing reconciliation batch: %w", err)
		}
		if len(candidates) == 0 {
			return nil
		}
		if err := db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
			for _, candidate := range candidates {
				if err := reconcileUsagePricing(tx, pricing, candidate.RequestID, candidate.Terminal); err != nil {
					return err
				}
			}
			return nil
		}); err != nil {
			return fmt.Errorf("reconcile usage pricing batch: %w", err)
		}
		processed += len(candidates)
		lastReplayID = candidates[len(candidates)-1].ReplayID
		if len(candidates) < pricingReconcileBatchSize {
			return nil
		}
	}
	var remaining int64
	if err := db.WithContext(ctx).Table("usage AS u").
		Joins("JOIN requests AS r ON r.request_id = u.request_id").
		Where(candidateWhere).
		Where("u.replay_id > ?", lastReplayID).
		Count(&remaining).Error; err != nil {
		return fmt.Errorf("check pricing reconciliation progress: %w", err)
	}
	if remaining != 0 {
		return fmt.Errorf("pricing reconciliation exceeded %d rows", pricingReconcileMaxRows)
	}
	return nil
}

func resolveSubscriptionVersion(tx *gorm.DB, month time.Time) (SubscriptionAllocationVersion, bool, error) {
	var version SubscriptionAllocationVersion
	if err := tx.Where("effective_at <= ?", month.UTC()).Order("effective_at DESC, id DESC").First(&version).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return SubscriptionAllocationVersion{}, false, nil
		}
		return SubscriptionAllocationVersion{}, false, fmt.Errorf("resolve subscription allocation version: %w", err)
	}
	return version, true, nil
}
