package server

import (
	"errors"
	"fmt"
	"time"

	"gorm.io/gorm"
)

func (j *Journal) reconcileUsagePricing(tx *gorm.DB, requestID string, terminalAt time.Time) error {
	if j == nil || j.pricing == nil || !j.pricing.Available() {
		return nil
	}
	var request RequestRecord
	if err := tx.Select("request_id, model, requested_model, resolved_model, created_at, accepted_at").Where("request_id = ?", requestID).First(&request).Error; err != nil {
		return fmt.Errorf("load request for pricing: %w", err)
	}
	modelID := request.ResolvedModel
	if modelID == "" {
		modelID = request.RequestedModel
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
		version, price, found, err := j.pricing.resolvePricing(tx, createdAt.UTC(), modelID)
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
		if err := tx.Model(&UsageRecord{}).Where("replay_id = ? AND pricing_version_id IS NULL", usage.ReplayID).Updates(map[string]any{
			"priced_model":                     modelID,
			"pricing_version_id":               &versionID,
			"estimated_public_cost_microunits": &costValue,
		}).Error; err != nil {
			return fmt.Errorf("store usage pricing: %w", err)
		}
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
