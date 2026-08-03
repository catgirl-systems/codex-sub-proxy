package apikey

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/go-playground/validator/v10"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

const (
	quotaBatchSize              = 256
	maxQuotaCount               = int64(1 << 60)
	maxQuotaWindow              = 365 * 24 * time.Hour
	reservationStatusOpen       = "pending"
	reservationStatusFinalizing = "finalizing"
	reservationStatusDone       = "closed"
	reservationStatusDrop       = "released"
)

var (
	// ErrQuotaExceeded identifies a safe 429 admission failure.
	ErrQuotaExceeded = errors.New("API key quota exceeded")
	// ErrQuotaReservationNotFound identifies a reservation that is not stored.
	ErrQuotaReservationNotFound = errors.New("quota reservation not found")
)

// QuotaError is a safe quota rejection with retry and reset data.
type QuotaError struct {
	Kind       string
	RetryAfter time.Duration
	ResetAt    time.Time
}

func (err *QuotaError) Error() string {
	if err == nil {
		return ErrQuotaExceeded.Error()
	}
	switch err.Kind {
	case "concurrency":
		return "API key concurrent request limit exceeded"
	case "rate":
		return "API key request rate limit exceeded"
	case "requests", "tokens", "images", "cost":
		return "API key quota limit exceeded"
	default:
		return ErrQuotaExceeded.Error()
	}
}

func (err *QuotaError) Unwrap() error { return ErrQuotaExceeded }

// QuotaRequest contains the amounts reserved before an upstream dispatch.
type QuotaRequest struct {
	Requests       int64
	Tokens         int64
	Images         int64
	CostMicrounits int64
}

// QuotaUsage contains the amounts reported by a terminal upstream result.
type QuotaUsage struct {
	Requests       int64
	Tokens         int64
	Images         int64
	CostMicrounits int64
}

// QuotaAdmission is the durable handle returned by a successful admission.
type QuotaAdmission struct {
	ID          string
	RequestID   string
	KeyID       string
	OwnerID     string
	PeriodStart time.Time
	BucketID    *string
	Requested   QuotaRequest
	Status      string
}

// QuotaState serializes mutable per-key admission state.
type QuotaState struct {
	KeyID          string    `gorm:"column:key_id;primaryKey;size:32"`
	ActiveRequests int64     `gorm:"column:active_requests;not null;default:0"`
	RollingCount   int64     `gorm:"column:rolling_count;not null;default:0"`
	UpdatedAt      time.Time `gorm:"column:updated_at;not null"`
}

func (QuotaState) TableName() string { return "quota_states" }

// QuotaBucket stores reserved and actual amounts for one key and UTC period.
type QuotaBucket struct {
	ID                     string    `gorm:"column:id;primaryKey;size:36"`
	KeyID                  string    `gorm:"column:key_id;not null;size:32;index:quota_buckets_key_period,unique"`
	PeriodStart            time.Time `gorm:"column:period_start;not null;index:quota_buckets_key_period,unique"`
	ReservedRequests       int64     `gorm:"column:reserved_requests;not null;default:0"`
	ActualRequests         int64     `gorm:"column:actual_requests;not null;default:0"`
	ReservedTokens         int64     `gorm:"column:reserved_tokens;not null;default:0"`
	ActualTokens           int64     `gorm:"column:actual_tokens;not null;default:0"`
	ReservedImages         int64     `gorm:"column:reserved_images;not null;default:0"`
	ActualImages           int64     `gorm:"column:actual_images;not null;default:0"`
	ReservedCostMicrounits int64     `gorm:"column:reserved_cost_microunits;not null;default:0"`
	ActualCostMicrounits   int64     `gorm:"column:actual_cost_microunits;not null;default:0"`
	CreatedAt              time.Time `gorm:"column:created_at;not null"`
	UpdatedAt              time.Time `gorm:"column:updated_at;not null"`
}

func (QuotaBucket) TableName() string { return "quota_buckets" }

// QuotaRollingAdmission stores one bounded rolling-window admission.
type QuotaRollingAdmission struct {
	ID        string    `gorm:"column:id;primaryKey;size:36"`
	KeyID     string    `gorm:"column:key_id;not null;size:32;index"`
	RequestID string    `gorm:"column:request_id;not null;size:36;index"`
	ExpiresAt time.Time `gorm:"column:expires_at;not null;index"`
	CreatedAt time.Time `gorm:"column:created_at;not null"`
}

func (QuotaRollingAdmission) TableName() string { return "quota_rolling_admissions" }

// QuotaReservation stores one pending, finalizing, reconciled, or released admission.
type QuotaReservation struct {
	ID                      string     `gorm:"column:id;primaryKey;size:36"`
	KeyID                   string     `gorm:"column:key_id;not null;size:32;index"`
	RequestID               string     `gorm:"column:request_id;not null;size:36;uniqueIndex"`
	OwnerID                 string     `gorm:"column:owner_id;not null;size:36;index"`
	PeriodStart             time.Time  `gorm:"column:period_start;not null;index"`
	BucketID                *string    `gorm:"column:bucket_id;size:36;index"`
	RequestedRequests       int64      `gorm:"column:requested_requests;not null"`
	RequestedTokens         int64      `gorm:"column:requested_tokens;not null"`
	RequestedImages         int64      `gorm:"column:requested_images;not null"`
	RequestedCostMicrounits int64      `gorm:"column:requested_cost_microunits;not null"`
	ActualRequests          int64      `gorm:"column:actual_requests;not null;default:0"`
	ActualTokens            int64      `gorm:"column:actual_tokens;not null;default:0"`
	ActualImages            int64      `gorm:"column:actual_images;not null;default:0"`
	ActualCostMicrounits    int64      `gorm:"column:actual_cost_microunits;not null;default:0"`
	Status                  string     `gorm:"column:status;not null;size:16;index"`
	CreatedAt               time.Time  `gorm:"column:created_at;not null;index"`
	ClosedAt                *time.Time `gorm:"column:closed_at"`
	RecoveryReason          string     `gorm:"column:recovery_reason;size:128"`
	RecoveryAt              *time.Time `gorm:"column:recovery_at"`
}

func (QuotaReservation) TableName() string { return "quota_reservations" }

// MigrateQuota creates the quota state, bucket, rolling, and reservation tables.
func MigrateQuota(db *gorm.DB) error {
	if db == nil {
		return fmt.Errorf("migrate quotas: %w", ErrUnavailable)
	}
	if err := db.AutoMigrate(&QuotaState{}, &QuotaBucket{}, &QuotaRollingAdmission{}, &QuotaReservation{}); err != nil {
		return fmt.Errorf("migrate quotas: %w", err)
	}
	return nil
}

// QuotaStore owns one process admission identity and its SQLite transactions.
type QuotaStore struct {
	db      *gorm.DB
	ownerID string
	now     func() time.Time
}

// NewQuotaStore creates a quota store with a new process owner ID.
func NewQuotaStore(db *gorm.DB) (*QuotaStore, error) {
	if db == nil {
		return nil, fmt.Errorf("create quota store: %w", ErrUnavailable)
	}
	ownerID, err := newQuotaUUID()
	if err != nil {
		return nil, fmt.Errorf("generate quota process ID: %w", err)
	}
	return &QuotaStore{db: db, ownerID: ownerID, now: func() time.Time { return time.Now().UTC() }}, nil
}

func newQuotaStore(db *gorm.DB, ownerID string, now func() time.Time) *QuotaStore {
	return &QuotaStore{db: db, ownerID: ownerID, now: now}
}

func validatePolicy(policy Policy) error {
	if err := validator.New().Struct(policy); err != nil {
		return fmt.Errorf("validate API key policy: %w", err)
	}
	if err := validateQuotaPolicy(policy); err != nil {
		return fmt.Errorf("validate API key quota policy: %w", err)
	}
	return nil
}

func validateQuotaPolicy(policy Policy) error {
	counts := []struct {
		name  string
		value int64
	}{
		{"max concurrent requests", policy.MaxConcurrentRequests},
		{"rolling request count", policy.RollingRequestCount},
		{"period request limit", policy.PeriodRequestLimit},
		{"period token limit", policy.PeriodTokenLimit},
		{"period image limit", policy.PeriodImageLimit},
		{"period cost microunit limit", policy.PeriodCostMicrounitLimit},
		{"token reservation default", policy.TokenReservationDefault},
		{"token reservation ceiling", policy.TokenReservationCeiling},
		{"image reservation default", policy.ImageReservationDefault},
		{"image reservation ceiling", policy.ImageReservationCeiling},
		{"cost microunit reservation default", policy.CostMicrounitReservationDefault},
		{"cost microunit reservation ceiling", policy.CostMicrounitReservationCeiling},
	}
	for _, count := range counts {
		if count.value < 0 || count.value > maxQuotaCount {
			return fmt.Errorf("%s is outside the supported range", count.name)
		}
	}
	if policy.RollingRequestWindow < 0 || policy.RollingRequestWindow > maxQuotaWindow {
		return errors.New("rolling request window is outside the supported range")
	}
	if (policy.RollingRequestCount == 0) != (policy.RollingRequestWindow == 0) {
		return errors.New("rolling request count and window must both be enabled or disabled")
	}
	if policy.PeriodDuration < 0 || policy.PeriodDuration > maxQuotaWindow {
		return errors.New("period duration is outside the supported range")
	}
	periodEnabled := policy.PeriodRequestLimit > 0 || policy.PeriodTokenLimit > 0 ||
		policy.PeriodImageLimit > 0 || policy.PeriodCostMicrounitLimit > 0
	if periodEnabled != (policy.PeriodDuration > 0) {
		return errors.New("period duration must match periodic limits")
	}
	if policy.TokenReservationCeiling > 0 && policy.TokenReservationDefault > policy.TokenReservationCeiling {
		return errors.New("token reservation default exceeds ceiling")
	}
	if policy.ImageReservationCeiling > 0 && policy.ImageReservationDefault > policy.ImageReservationCeiling {
		return errors.New("image reservation default exceeds ceiling")
	}
	if policy.CostMicrounitReservationCeiling > 0 && policy.CostMicrounitReservationDefault > policy.CostMicrounitReservationCeiling {
		return errors.New("cost microunit reservation default exceeds ceiling")
	}
	return nil
}

func quotaPolicyEnabled(policy Policy) bool {
	return policy.MaxConcurrentRequests > 0 || policy.RollingRequestCount > 0 ||
		policy.PeriodRequestLimit > 0 || policy.PeriodTokenLimit > 0 ||
		policy.PeriodImageLimit > 0 || policy.PeriodCostMicrounitLimit > 0 ||
		policy.TokenReservationDefault > 0 || policy.TokenReservationCeiling > 0 ||
		policy.ImageReservationDefault > 0 || policy.ImageReservationCeiling > 0 ||
		policy.CostMicrounitReservationDefault > 0 || policy.CostMicrounitReservationCeiling > 0
}

func periodQuotaEnabled(policy Policy) bool {
	return policy.PeriodRequestLimit > 0 || policy.PeriodTokenLimit > 0 ||
		policy.PeriodImageLimit > 0 || policy.PeriodCostMicrounitLimit > 0
}

// Admit atomically checks and reserves all configured quota dimensions.
func (store *QuotaStore) Admit(ctx context.Context, keyID string, policy Policy, request QuotaRequest) (*QuotaAdmission, error) {
	if store == nil || store.db == nil {
		return nil, fmt.Errorf("admit quota: %w", ErrUnavailable)
	}
	if ctx == nil {
		return nil, errors.New("admit quota context is nil")
	}
	if strings.TrimSpace(keyID) == "" {
		return nil, errors.New("admit quota key ID is empty")
	}
	if err := validateQuotaPolicy(policy); err != nil {
		return nil, err
	}
	if err := validateQuotaRequest(request); err != nil {
		return nil, err
	}
	now := store.now().UTC()
	if err := checkReservationCeilings(policy, request, now); err != nil {
		return nil, err
	}
	if !quotaPolicyEnabled(policy) {
		return nil, nil
	}
	reservationID, err := newQuotaUUID()
	if err != nil {
		return nil, fmt.Errorf("generate quota reservation ID: %w", err)
	}
	requestID, err := newQuotaUUID()
	if err != nil {
		return nil, fmt.Errorf("generate quota request ID: %w", err)
	}
	var reservation QuotaReservation
	err = store.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		state, err := lockQuotaState(tx, keyID, now)
		if err != nil {
			return err
		}
		if err := cleanupRollingAdmissions(tx, &state, keyID, now); err != nil {
			return err
		}
		if policy.MaxConcurrentRequests > 0 && state.ActiveRequests >= policy.MaxConcurrentRequests {
			return newQuotaError("concurrency", now, now.Add(time.Second))
		}
		if policy.RollingRequestCount > 0 && state.RollingCount >= policy.RollingRequestCount {
			resetAt, err := nextRollingReset(tx, keyID, now, policy.RollingRequestWindow)
			if err != nil {
				return err
			}
			return newQuotaError("rate", now, resetAt)
		}
		var (
			periodStart time.Time
			bucket      *QuotaBucket
			bucketID    *string
		)
		if periodQuotaEnabled(policy) {
			periodStart = periodStartAt(now, policy.PeriodDuration)
			lockedBucket, err := lockQuotaBucket(tx, keyID, periodStart, now)
			if err != nil {
				return err
			}
			bucket = &lockedBucket
			if err := checkBucketLimits(policy, *bucket, request, now); err != nil {
				return err
			}
			bucketID = &lockedBucket.ID
		}
		if state.ActiveRequests == math.MaxInt64 {
			return errors.New("quota concurrency state overflow")
		}
		state.ActiveRequests++
		if policy.RollingRequestCount > 0 {
			state.RollingCount++
		}
		if err := tx.Model(&QuotaState{}).Where("key_id = ?", keyID).Updates(map[string]any{
			"active_requests": state.ActiveRequests,
			"rolling_count":   state.RollingCount,
			"updated_at":      now,
		}).Error; err != nil {
			return fmt.Errorf("update quota state: %w", err)
		}
		if bucket != nil {
			var ok bool
			if bucket.ReservedRequests, ok = quotaAdd(bucket.ReservedRequests, request.Requests); !ok {
				return errors.New("quota request reservation overflow")
			}
			if bucket.ReservedTokens, ok = quotaAdd(bucket.ReservedTokens, request.Tokens); !ok {
				return errors.New("quota token reservation overflow")
			}
			if bucket.ReservedImages, ok = quotaAdd(bucket.ReservedImages, request.Images); !ok {
				return errors.New("quota image reservation overflow")
			}
			if bucket.ReservedCostMicrounits, ok = quotaAdd(bucket.ReservedCostMicrounits, request.CostMicrounits); !ok {
				return errors.New("quota cost reservation overflow")
			}
			if err := tx.Model(&QuotaBucket{}).Where("id = ?", bucket.ID).Updates(map[string]any{
				"reserved_requests":        bucket.ReservedRequests,
				"reserved_tokens":          bucket.ReservedTokens,
				"reserved_images":          bucket.ReservedImages,
				"reserved_cost_microunits": bucket.ReservedCostMicrounits,
				"updated_at":               now,
			}).Error; err != nil {
				return fmt.Errorf("update quota bucket: %w", err)
			}
		}
		if policy.RollingRequestCount > 0 {
			rollingID, err := newQuotaUUID()
			if err != nil {
				return fmt.Errorf("generate rolling admission ID: %w", err)
			}
			if err := tx.Create(&QuotaRollingAdmission{
				ID: rollingID, KeyID: keyID, RequestID: requestID,
				ExpiresAt: now.Add(policy.RollingRequestWindow), CreatedAt: now,
			}).Error; err != nil {
				return fmt.Errorf("store rolling admission: %w", err)
			}
		}
		reservation = QuotaReservation{
			ID: reservationID, KeyID: keyID, RequestID: requestID, OwnerID: store.ownerID,
			PeriodStart: periodStart, BucketID: bucketID,
			RequestedRequests: request.Requests, RequestedTokens: request.Tokens,
			RequestedImages: request.Images, RequestedCostMicrounits: request.CostMicrounits,
			Status: reservationStatusOpen, CreatedAt: now,
		}
		if err := tx.Create(&reservation).Error; err != nil {
			return fmt.Errorf("store quota reservation: %w", err)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &QuotaAdmission{
		ID: reservation.ID, RequestID: reservation.RequestID, KeyID: reservation.KeyID,
		OwnerID: reservation.OwnerID, PeriodStart: reservation.PeriodStart, BucketID: reservation.BucketID,
		Requested: request, Status: reservation.Status,
	}, nil
}

// Reconcile records success before it applies the reservation.
func (store *QuotaStore) Reconcile(ctx context.Context, reservationID string, usage QuotaUsage) error {
	if store == nil || store.db == nil {
		return fmt.Errorf("reconcile quota: %w", ErrUnavailable)
	}
	if ctx == nil {
		return errors.New("reconcile quota context is nil")
	}
	if strings.TrimSpace(reservationID) == "" {
		return ErrQuotaReservationNotFound
	}
	if err := validateQuotaUsage(usage); err != nil {
		return err
	}
	now := store.now().UTC()
	if err := store.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		return beginQuotaFinalization(tx, reservationID, usage)
	}); err != nil {
		return err
	}
	return store.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		return applyFinalizingReservation(tx, reservationID, now)
	})
}

func beginQuotaFinalization(tx *gorm.DB, reservationID string, usage QuotaUsage) error {
	var reservation QuotaReservation
	if err := tx.Where("id = ?", reservationID).First(&reservation).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ErrQuotaReservationNotFound
		}
		return fmt.Errorf("load quota reservation: %w", err)
	}
	if reservation.Status != reservationStatusOpen {
		return nil
	}
	if usage.Requests == 0 {
		usage.Requests = reservation.RequestedRequests
	}
	if usage.CostMicrounits == 0 {
		usage.CostMicrounits = reservation.RequestedCostMicrounits
	}
	if err := validateQuotaUsage(usage); err != nil {
		return err
	}
	result := tx.Model(&QuotaReservation{}).Where("id = ? AND status = ?", reservationID, reservationStatusOpen).
		Updates(map[string]any{
			"status":                 reservationStatusFinalizing,
			"actual_requests":        usage.Requests,
			"actual_tokens":          usage.Tokens,
			"actual_images":          usage.Images,
			"actual_cost_microunits": usage.CostMicrounits,
		})
	if result.Error != nil {
		return fmt.Errorf("record quota success: %w", result.Error)
	}
	return nil
}

// Release closes one reservation without charging its reserved amounts.
func (store *QuotaStore) Release(ctx context.Context, reservationID, reason string) error {
	if store == nil || store.db == nil {
		return fmt.Errorf("release quota: %w", ErrUnavailable)
	}
	if ctx == nil {
		return errors.New("release quota context is nil")
	}
	if strings.TrimSpace(reservationID) == "" {
		return ErrQuotaReservationNotFound
	}
	if len(reason) > 128 {
		reason = reason[:128]
	}
	now := store.now().UTC()
	return store.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var reservation QuotaReservation
		if err := tx.Where("id = ?", reservationID).First(&reservation).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrQuotaReservationNotFound
			}
			return fmt.Errorf("load quota reservation: %w", err)
		}
		if reservation.Status != reservationStatusOpen {
			return nil
		}
		return releasePendingReservation(tx, reservation, now, reason)
	})
}

func releasePendingReservation(tx *gorm.DB, reservation QuotaReservation, now time.Time, reason string) error {
	state, err := lockQuotaState(tx, reservation.KeyID, now)
	if err != nil {
		return err
	}
	var current QuotaReservation
	if err := tx.Where("id = ?", reservation.ID).First(&current).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil
		}
		return fmt.Errorf("reload quota reservation: %w", err)
	}
	if current.Status != reservationStatusOpen {
		return nil
	}
	reservation = current
	if err := decrementActive(&state); err != nil {
		return err
	}
	bucket, err := loadReservationBucket(tx, reservation)
	if err != nil {
		return err
	}
	if bucket != nil {
		if err := subtractReservation(bucket, reservation); err != nil {
			return err
		}
		if err := saveQuotaBucket(tx, *bucket, now); err != nil {
			return err
		}
	}
	if err := tx.Model(&QuotaState{}).Where("key_id = ?", reservation.KeyID).Updates(map[string]any{
		"active_requests": state.ActiveRequests, "updated_at": now,
	}).Error; err != nil {
		return fmt.Errorf("update quota concurrency: %w", err)
	}
	return markQuotaReservation(tx, reservation.ID, reservationStatusOpen, reservationStatusDrop, QuotaUsage{}, now, reason)
}

// RecoverPending applies recorded successes and releases in-flight reservations.
func (store *QuotaStore) RecoverPending(ctx context.Context) error {
	if store == nil || store.db == nil {
		return fmt.Errorf("recover quotas: %w", ErrUnavailable)
	}
	if ctx == nil {
		return errors.New("recover quotas context is nil")
	}
	now := store.now().UTC()
	return store.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		for {
			var finalizing []QuotaReservation
			result := tx.Where("status = ?", reservationStatusFinalizing).
				Order("id ASC").Limit(quotaBatchSize).Find(&finalizing)
			if result.Error != nil {
				return fmt.Errorf("load finalizing quota reservations: %w", result.Error)
			}
			var pending []QuotaReservation
			result = tx.Where("status = ? AND owner_id <> ?", reservationStatusOpen, store.ownerID).
				Order("id ASC").Limit(quotaBatchSize).Find(&pending)
			if result.Error != nil {
				return fmt.Errorf("load pending quota reservations: %w", result.Error)
			}
			if len(finalizing) == 0 && len(pending) == 0 {
				return nil
			}
			for _, candidate := range finalizing {
				if err := applyFinalizingReservation(tx, candidate.ID, now); err != nil {
					return err
				}
			}
			for _, candidate := range pending {
				var reservation QuotaReservation
				if err := tx.Where("id = ?", candidate.ID).First(&reservation).Error; err != nil {
					if errors.Is(err, gorm.ErrRecordNotFound) {
						continue
					}
					return fmt.Errorf("reload pending quota reservation: %w", err)
				}
				if reservation.Status != reservationStatusOpen || reservation.OwnerID == store.ownerID {
					continue
				}
				if err := releasePendingReservation(tx, reservation, now, "process crash recovery"); err != nil {
					return err
				}
			}
		}
	})
}

func applyFinalizingReservation(tx *gorm.DB, reservationID string, now time.Time) error {
	var reservation QuotaReservation
	if err := tx.Where("id = ?", reservationID).First(&reservation).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil
		}
		return fmt.Errorf("load finalizing quota reservation: %w", err)
	}
	if reservation.Status != reservationStatusFinalizing {
		return nil
	}
	state, err := lockQuotaState(tx, reservation.KeyID, now)
	if err != nil {
		return err
	}
	var current QuotaReservation
	if err := tx.Where("id = ?", reservation.ID).First(&current).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil
		}
		return fmt.Errorf("reload finalizing quota reservation: %w", err)
	}
	if current.Status != reservationStatusFinalizing {
		return nil
	}
	reservation = current
	usage := QuotaUsage{
		Requests:       reservation.ActualRequests,
		Tokens:         reservation.ActualTokens,
		Images:         reservation.ActualImages,
		CostMicrounits: reservation.ActualCostMicrounits,
	}
	if err := validateQuotaUsage(usage); err != nil {
		return fmt.Errorf("validate recorded quota success: %w", err)
	}
	if err := decrementActive(&state); err != nil {
		return err
	}
	bucket, err := loadReservationBucket(tx, reservation)
	if err != nil {
		return err
	}
	if bucket != nil {
		if err := moveReservationToUsage(tx, bucket, reservation, usage, now); err != nil {
			return err
		}
	}
	if err := tx.Model(&QuotaState{}).Where("key_id = ?", reservation.KeyID).Updates(map[string]any{
		"active_requests": state.ActiveRequests, "updated_at": now,
	}).Error; err != nil {
		return fmt.Errorf("update quota concurrency: %w", err)
	}
	return markQuotaReservation(tx, reservation.ID, reservationStatusFinalizing, reservationStatusDone, usage, now, "")
}

func validateQuotaRequest(request QuotaRequest) error {
	if request.Requests != 1 {
		return errors.New("quota request count must be one")
	}
	if request.Tokens < 0 || request.Images < 0 || request.CostMicrounits < 0 {
		return errors.New("quota reservation amounts cannot be negative")
	}
	if request.Tokens > maxQuotaCount || request.Images > maxQuotaCount || request.CostMicrounits > maxQuotaCount {
		return errors.New("quota reservation amount is outside the supported range")
	}
	return nil
}

func validateQuotaUsage(usage QuotaUsage) error {
	if usage.Requests < 0 || usage.Tokens < 0 || usage.Images < 0 || usage.CostMicrounits < 0 {
		return errors.New("quota usage amounts cannot be negative")
	}
	if usage.Requests > 1 || usage.Tokens > maxQuotaCount || usage.Images > maxQuotaCount || usage.CostMicrounits > maxQuotaCount {
		return errors.New("quota usage amount is outside the supported range")
	}
	return nil
}

func lockQuotaState(tx *gorm.DB, keyID string, now time.Time) (QuotaState, error) {
	seed := QuotaState{KeyID: keyID, UpdatedAt: now}
	if err := tx.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "key_id"}},
		DoUpdates: clause.Assignments(map[string]any{"updated_at": now}),
	}).Create(&seed).Error; err != nil {
		return QuotaState{}, fmt.Errorf("lock quota state: %w", err)
	}
	var state QuotaState
	if err := tx.Where("key_id = ?", keyID).First(&state).Error; err != nil {
		return QuotaState{}, fmt.Errorf("load quota state: %w", err)
	}
	return state, nil
}

func cleanupRollingAdmissions(tx *gorm.DB, state *QuotaState, keyID string, now time.Time) error {
	var expired []QuotaRollingAdmission
	if err := tx.Where("key_id = ? AND expires_at <= ?", keyID, now).
		Order("expires_at ASC").Limit(quotaBatchSize).Find(&expired).Error; err != nil {
		return fmt.Errorf("load expired quota admissions: %w", err)
	}
	if len(expired) == 0 {
		return nil
	}
	ids := make([]string, 0, len(expired))
	for _, entry := range expired {
		ids = append(ids, entry.ID)
	}
	result := tx.Where("id IN ?", ids).Delete(&QuotaRollingAdmission{})
	if result.Error != nil {
		return fmt.Errorf("delete expired quota admissions: %w", result.Error)
	}
	state.RollingCount -= result.RowsAffected
	if state.RollingCount < 0 {
		state.RollingCount = 0
	}
	if err := tx.Model(&QuotaState{}).Where("key_id = ?", keyID).UpdateColumn("rolling_count", state.RollingCount).Error; err != nil {
		return fmt.Errorf("update rolling quota count: %w", err)
	}
	return nil
}

func nextRollingReset(tx *gorm.DB, keyID string, now time.Time, window time.Duration) (time.Time, error) {
	var entry QuotaRollingAdmission
	result := tx.Where("key_id = ? AND expires_at > ?", keyID, now).Order("expires_at ASC").Limit(1).First(&entry)
	if result.Error == nil {
		return entry.ExpiresAt, nil
	}
	if errors.Is(result.Error, gorm.ErrRecordNotFound) {
		return now.Add(window), nil
	}
	return time.Time{}, fmt.Errorf("find quota rate reset: %w", result.Error)
}

func periodStartAt(now time.Time, duration time.Duration) time.Time {
	if duration <= 0 {
		return now.UTC()
	}
	return now.UTC().Truncate(duration)
}

func lockQuotaBucket(tx *gorm.DB, keyID string, periodStart, now time.Time) (QuotaBucket, error) {
	bucketID, err := newQuotaUUID()
	if err != nil {
		return QuotaBucket{}, fmt.Errorf("generate quota bucket ID: %w", err)
	}
	bucket := QuotaBucket{ID: bucketID, KeyID: keyID, PeriodStart: periodStart, CreatedAt: now, UpdatedAt: now}
	if err := tx.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "key_id"}, {Name: "period_start"}},
		DoUpdates: clause.Assignments(map[string]any{"updated_at": now}),
	}).Create(&bucket).Error; err != nil {
		return QuotaBucket{}, fmt.Errorf("lock quota bucket: %w", err)
	}
	return loadQuotaBucket(tx, keyID, periodStart)
}

func loadQuotaBucket(tx *gorm.DB, keyID string, periodStart time.Time) (QuotaBucket, error) {
	var bucket QuotaBucket
	if err := tx.Where("key_id = ? AND period_start = ?", keyID, periodStart).First(&bucket).Error; err != nil {
		return QuotaBucket{}, fmt.Errorf("load quota bucket: %w", err)
	}
	return bucket, nil
}

func loadReservationBucket(tx *gorm.DB, reservation QuotaReservation) (*QuotaBucket, error) {
	if reservation.BucketID != nil {
		bucketID := strings.TrimSpace(*reservation.BucketID)
		if bucketID != "" {
			var bucket QuotaBucket
			if err := tx.Where("id = ?", bucketID).First(&bucket).Error; err != nil {
				return nil, fmt.Errorf("load quota bucket: %w", err)
			}
			return &bucket, nil
		}
	}
	if reservation.PeriodStart.IsZero() {
		return nil, nil
	}
	bucket, err := loadQuotaBucket(tx, reservation.KeyID, reservation.PeriodStart)
	if err != nil {
		return nil, err
	}
	return &bucket, nil
}
func checkReservationCeilings(policy Policy, request QuotaRequest, now time.Time) error {
	checks := []struct {
		kind    string
		ceiling int64
		amount  int64
	}{
		{"tokens", policy.TokenReservationCeiling, request.Tokens},
		{"images", policy.ImageReservationCeiling, request.Images},
		{"cost", policy.CostMicrounitReservationCeiling, request.CostMicrounits},
	}
	for _, check := range checks {
		if check.ceiling > 0 && check.amount > check.ceiling {
			return newQuotaError(check.kind, now, now.Add(time.Second))
		}
	}
	return nil
}

func checkBucketLimits(policy Policy, bucket QuotaBucket, request QuotaRequest, now time.Time) error {
	checks := []struct {
		kind     string
		limit    int64
		reserved int64
		actual   int64
		amount   int64
	}{
		{"requests", policy.PeriodRequestLimit, bucket.ReservedRequests, bucket.ActualRequests, request.Requests},
		{"tokens", policy.PeriodTokenLimit, bucket.ReservedTokens, bucket.ActualTokens, request.Tokens},
		{"images", policy.PeriodImageLimit, bucket.ReservedImages, bucket.ActualImages, request.Images},
		{"cost", policy.PeriodCostMicrounitLimit, bucket.ReservedCostMicrounits, bucket.ActualCostMicrounits, request.CostMicrounits},
	}
	for _, check := range checks {
		if check.limit == 0 {
			continue
		}
		used, ok := quotaAdd(check.reserved, check.actual)
		if !ok || check.amount > check.limit-used {
			resetAt := now.Add(time.Second)
			if policy.PeriodDuration > 0 {
				resetAt = periodStartAt(now, policy.PeriodDuration).Add(policy.PeriodDuration)
			}
			return newQuotaError(check.kind, now, resetAt)
		}
	}
	return nil
}

func newQuotaError(kind string, now, resetAt time.Time) error {
	retryAfter := resetAt.Sub(now)
	if retryAfter <= 0 {
		retryAfter = time.Second
		resetAt = now.Add(retryAfter)
	}
	return &QuotaError{Kind: kind, RetryAfter: retryAfter, ResetAt: resetAt.UTC()}
}

func quotaAdd(left, right int64) (int64, bool) {
	if left < 0 || right < 0 || left > math.MaxInt64-right {
		return 0, false
	}
	return left + right, true
}

func decrementActive(state *QuotaState) error {
	if state.ActiveRequests <= 0 {
		return errors.New("quota concurrency state is inconsistent")
	}
	state.ActiveRequests--
	return nil
}

func subtractReservation(bucket *QuotaBucket, reservation QuotaReservation) error {
	values := []*int64{
		&bucket.ReservedRequests, &bucket.ReservedTokens, &bucket.ReservedImages, &bucket.ReservedCostMicrounits,
	}
	amounts := []int64{reservation.RequestedRequests, reservation.RequestedTokens, reservation.RequestedImages, reservation.RequestedCostMicrounits}
	for index, value := range values {
		if *value < amounts[index] {
			return errors.New("quota bucket reservation state is inconsistent")
		}
		*value -= amounts[index]
	}
	return nil
}

func moveReservationToUsage(tx *gorm.DB, bucket *QuotaBucket, reservation QuotaReservation, usage QuotaUsage, now time.Time) error {
	if err := subtractReservation(bucket, reservation); err != nil {
		return err
	}
	actual := []*int64{&bucket.ActualRequests, &bucket.ActualTokens, &bucket.ActualImages, &bucket.ActualCostMicrounits}
	amounts := []int64{usage.Requests, usage.Tokens, usage.Images, usage.CostMicrounits}
	for index, value := range actual {
		updated, ok := quotaAdd(*value, amounts[index])
		if !ok {
			return errors.New("quota bucket usage is outside the supported range")
		}
		*value = updated
	}
	return saveQuotaBucket(tx, *bucket, now)
}

func saveQuotaBucket(tx *gorm.DB, bucket QuotaBucket, now time.Time) error {
	if err := tx.Model(&QuotaBucket{}).Where("id = ?", bucket.ID).Updates(map[string]any{
		"reserved_requests":        bucket.ReservedRequests,
		"actual_requests":          bucket.ActualRequests,
		"reserved_tokens":          bucket.ReservedTokens,
		"actual_tokens":            bucket.ActualTokens,
		"reserved_images":          bucket.ReservedImages,
		"actual_images":            bucket.ActualImages,
		"reserved_cost_microunits": bucket.ReservedCostMicrounits,
		"actual_cost_microunits":   bucket.ActualCostMicrounits,
		"updated_at":               now,
	}).Error; err != nil {
		return fmt.Errorf("update quota bucket: %w", err)
	}
	return nil
}

func markQuotaReservation(tx *gorm.DB, id, fromStatus, status string, usage QuotaUsage, now time.Time, reason string) error {
	updates := map[string]any{
		"status":                 status,
		"actual_requests":        usage.Requests,
		"actual_tokens":          usage.Tokens,
		"actual_images":          usage.Images,
		"actual_cost_microunits": usage.CostMicrounits,
		"closed_at":              now,
	}
	if reason != "" {
		updates["recovery_reason"] = reason
		updates["recovery_at"] = now
	}
	result := tx.Model(&QuotaReservation{}).Where("id = ? AND status = ?", id, fromStatus).Updates(updates)
	if result.Error != nil {
		return fmt.Errorf("close quota reservation: %w", result.Error)
	}
	return nil
}

func newQuotaUUID() (string, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", err
	}
	value[6] = (value[6] & 0x0f) | 0x40
	value[8] = (value[8] & 0x3f) | 0x80
	encoded := make([]byte, 36)
	hex.Encode(encoded[0:8], value[0:4])
	encoded[8] = '-'
	hex.Encode(encoded[9:13], value[4:6])
	encoded[13] = '-'
	hex.Encode(encoded[14:18], value[6:8])
	encoded[18] = '-'
	hex.Encode(encoded[19:23], value[8:10])
	encoded[23] = '-'
	hex.Encode(encoded[24:36], value[10:16])
	return string(encoded), nil
}
