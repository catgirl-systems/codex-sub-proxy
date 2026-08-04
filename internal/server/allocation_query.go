package server

import (
	"errors"
	"fmt"
	"time"

	"gorm.io/gorm"
)

const maxAnalyticsAllocationRows = 100000

type allocationInputRow struct {
	RequestID string    `gorm:"column:request_id"`
	CreatedAt time.Time `gorm:"column:created_at"`
	Estimate  int64     `gorm:"column:estimate"`
}

// queryMonthlyAllocation derives one immutable monthly allocation without
// writing request rows. It rejects an input set above the bounded query cap.
func queryMonthlyAllocation(tx *gorm.DB, month, now time.Time) (AllocationResult, []allocationInputRow, bool, error) {
	if tx == nil {
		return AllocationResult{}, nil, false, errors.New("allocation transaction is nil")
	}
	month = time.Date(month.UTC().Year(), month.UTC().Month(), 1, 0, 0, 0, 0, time.UTC)
	monthEnd := month.AddDate(0, 1, 0)
	version, found, err := resolveSubscriptionVersion(tx, month)
	if err != nil || !found {
		return AllocationResult{}, nil, false, err
	}
	var rowCount int64
	countQuery := `SELECT COUNT(*) FROM requests AS r JOIN (SELECT request_id, SUM(estimated_public_cost_microunits) AS estimate FROM usage WHERE estimated_public_cost_microunits IS NOT NULL GROUP BY request_id) AS u ON u.request_id = r.request_id WHERE r.status = ? AND r.accepted_at >= ? AND r.accepted_at < ? AND u.estimate > 0`
	if err := tx.Raw(countQuery, requestStatusSucceeded, month, monthEnd).Scan(&rowCount).Error; err != nil {
		return AllocationResult{}, nil, false, fmt.Errorf("count monthly allocation inputs: %w", err)
	}
	if rowCount > maxAnalyticsAllocationRows {
		return AllocationResult{}, nil, false, errors.New("monthly allocation input set is too large")
	}
	rows := make([]allocationInputRow, 0, int(rowCount))
	inputQuery := `SELECT r.request_id AS request_id, r.accepted_at AS created_at, u.estimate AS estimate FROM requests AS r JOIN (SELECT request_id, SUM(estimated_public_cost_microunits) AS estimate FROM usage WHERE estimated_public_cost_microunits IS NOT NULL GROUP BY request_id) AS u ON u.request_id = r.request_id WHERE r.status = ? AND r.accepted_at >= ? AND r.accepted_at < ? AND u.estimate > 0 ORDER BY r.accepted_at ASC, r.request_id ASC LIMIT ?`
	if err := tx.Raw(inputQuery, requestStatusSucceeded, month, monthEnd, maxAnalyticsAllocationRows+1).Scan(&rows).Error; err != nil {
		return AllocationResult{}, nil, false, fmt.Errorf("load monthly allocation inputs: %w", err)
	}
	if len(rows) == 0 {
		return AllocationResult{}, rows, false, nil
	}
	requests := make([]AllocationRequest, 0, len(rows))
	for _, row := range rows {
		if row.Estimate <= 0 {
			continue
		}
		requests = append(requests, AllocationRequest{RequestID: row.RequestID, EstimateMicrounits: row.Estimate})
	}
	allocation, available, err := AllocateSubscriptionCost(version, month, now.UTC(), requests)
	if err != nil {
		return AllocationResult{}, nil, false, err
	}
	if !available || allocation.Denominator <= 0 {
		return AllocationResult{}, rows, false, nil
	}
	return allocation, rows, true, nil
}
