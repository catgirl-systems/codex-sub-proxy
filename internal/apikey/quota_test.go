package apikey

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/catgirl-systems/codex-sub-proxy/internal/storage"
)

func quotaTestStore(t *testing.T, now *atomic.Int64) (*QuotaStore, func()) {
	t.Helper()
	db, err := storage.Open(context.Background(), ":memory:", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if err := Migrate(db); err != nil {
		t.Fatal(err)
	}
	clock := func() time.Time { return time.Unix(0, now.Load()).UTC() }
	store := newQuotaStore(db, "owner-a", clock)
	closeDB := func() {
		sqlDB, err := db.DB()
		if err == nil {
			_ = sqlDB.Close()
		}
	}
	return store, closeDB
}

func TestQuotaAdmissionRejectsConcurrentAndBudgetOverspend(t *testing.T) {
	now := atomic.Int64{}
	now.Store(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC).UnixNano())
	store, closeDB := quotaTestStore(t, &now)
	defer closeDB()
	policy := Policy{MaxConcurrentRequests: 1, PeriodDuration: time.Hour, PeriodTokenLimit: 1}
	first, err := store.Admit(context.Background(), "key", policy, QuotaRequest{Requests: 1, Tokens: 1})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Admit(context.Background(), "key", policy, QuotaRequest{Requests: 1}); !errors.Is(err, ErrQuotaExceeded) {
		t.Fatalf("second admission error = %v", err)
	}
	if err := store.Reconcile(context.Background(), first.ID, QuotaUsage{Requests: 1, Tokens: 2}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Admit(context.Background(), "key", policy, QuotaRequest{Requests: 1}); !errors.Is(err, ErrQuotaExceeded) {
		t.Fatalf("overspent admission error = %v", err)
	}
}

func TestQuotaReleaseIsIdempotentAndCrashRecoveryClearsActive(t *testing.T) {
	now := atomic.Int64{}
	now.Store(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC).UnixNano())
	store, closeDB := quotaTestStore(t, &now)
	defer closeDB()
	policy := Policy{MaxConcurrentRequests: 1}
	admission, err := store.Admit(context.Background(), "key", policy, QuotaRequest{Requests: 1})
	if err != nil {
		t.Fatal(err)
	}
	crashed := newQuotaStore(store.db, "owner-b", store.now)
	if err := crashed.RecoverPending(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := crashed.Release(context.Background(), admission.ID, "second recovery"); err != nil {
		t.Fatal(err)
	}
	var state QuotaState
	if err := store.db.First(&state, "key_id = ?", "key").Error; err != nil {
		t.Fatal(err)
	}
	if state.ActiveRequests != 0 {
		t.Fatalf("active requests = %d", state.ActiveRequests)
	}
	var reservation QuotaReservation
	if err := store.db.First(&reservation, "id = ?", admission.ID).Error; err != nil {
		t.Fatal(err)
	}
	if reservation.Status != reservationStatusDrop || reservation.RecoveryReason != "process crash recovery" {
		t.Fatalf("reservation = %#v", reservation)
	}
}

func TestQuotaRollingAndPeriodBoundaries(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	now := atomic.Int64{}
	now.Store(base.UnixNano())
	store, closeDB := quotaTestStore(t, &now)
	defer closeDB()
	policy := Policy{RollingRequestCount: 1, RollingRequestWindow: time.Minute}
	first, err := store.Admit(context.Background(), "key", policy, QuotaRequest{Requests: 1})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Reconcile(context.Background(), first.ID, QuotaUsage{Requests: 1}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Admit(context.Background(), "key", policy, QuotaRequest{Requests: 1}); !errors.Is(err, ErrQuotaExceeded) {
		t.Fatalf("rolling rejection = %v", err)
	}
	now.Store(base.Add(time.Minute + time.Nanosecond).UnixNano())
	if _, err := store.Admit(context.Background(), "key", policy, QuotaRequest{Requests: 1}); err != nil {
		t.Fatalf("rolling boundary admission = %v", err)
	}
}

func TestQuotaPeriodReset(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	now := atomic.Int64{}
	now.Store(base.UnixNano())
	store, closeDB := quotaTestStore(t, &now)
	defer closeDB()
	policy := Policy{PeriodDuration: time.Minute, PeriodTokenLimit: 1}
	first, err := store.Admit(context.Background(), "key", policy, QuotaRequest{Requests: 1, Tokens: 1})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Reconcile(context.Background(), first.ID, QuotaUsage{Requests: 1, Tokens: 1}); err != nil {
		t.Fatal(err)
	}
	now.Store(base.Add(time.Minute).UnixNano())
	if _, err := store.Admit(context.Background(), "key", policy, QuotaRequest{Requests: 1, Tokens: 1}); err != nil {
		t.Fatalf("period reset admission = %v", err)
	}
}
func TestQuotaNilUsageChargesRequestAndReservedCost(t *testing.T) {
	now := atomic.Int64{}
	now.Store(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC).UnixNano())
	store, closeDB := quotaTestStore(t, &now)
	defer closeDB()
	policy := Policy{
		PeriodDuration:                  time.Hour,
		PeriodCostMicrounitLimit:        5,
		CostMicrounitReservationDefault: 5,
	}
	first, err := store.Admit(context.Background(), "key", policy, QuotaRequest{Requests: 1, CostMicrounits: 5})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Reconcile(context.Background(), first.ID, QuotaUsage{}); err != nil {
		t.Fatal(err)
	}
	var bucket QuotaBucket
	if err := store.db.First(&bucket, "key_id = ?", "key").Error; err != nil {
		t.Fatal(err)
	}
	if bucket.ReservedRequests != 0 || bucket.ActualRequests != 1 || bucket.ActualCostMicrounits != 5 {
		t.Fatalf("bucket = %#v", bucket)
	}
	if _, err := store.Admit(context.Background(), "key", policy, QuotaRequest{Requests: 1, CostMicrounits: 5}); !errors.Is(err, ErrQuotaExceeded) {
		t.Fatalf("second admission error = %v", err)
	}
}

func TestQuotaFinalizingRecoveryChargesOnce(t *testing.T) {
	now := atomic.Int64{}
	now.Store(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC).UnixNano())
	store, closeDB := quotaTestStore(t, &now)
	defer closeDB()
	policy := Policy{PeriodDuration: time.Hour, PeriodTokenLimit: 10}
	admission, err := store.Admit(context.Background(), "key", policy, QuotaRequest{Requests: 1, Tokens: 4})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.db.Model(&QuotaReservation{}).Where("id = ?", admission.ID).Updates(map[string]any{
		"status":                 reservationStatusFinalizing,
		"actual_requests":        1,
		"actual_tokens":          4,
		"actual_images":          0,
		"actual_cost_microunits": 0,
	}).Error; err != nil {
		t.Fatal(err)
	}
	if err := store.Release(context.Background(), admission.ID, "must not release success"); err != nil {
		t.Fatal(err)
	}
	recovered := newQuotaStore(store.db, "owner-b", store.now)
	if err := recovered.RecoverPending(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := recovered.RecoverPending(context.Background()); err != nil {
		t.Fatal(err)
	}
	var reservation QuotaReservation
	if err := store.db.First(&reservation, "id = ?", admission.ID).Error; err != nil {
		t.Fatal(err)
	}
	if reservation.Status != reservationStatusDone {
		t.Fatalf("reservation status = %q", reservation.Status)
	}
	var bucket QuotaBucket
	if err := store.db.First(&bucket, "key_id = ?", "key").Error; err != nil {
		t.Fatal(err)
	}
	if bucket.ReservedTokens != 0 || bucket.ActualTokens != 4 {
		t.Fatalf("bucket = %#v", bucket)
	}
	var state QuotaState
	if err := store.db.First(&state, "key_id = ?", "key").Error; err != nil {
		t.Fatal(err)
	}
	if state.ActiveRequests != 0 {
		t.Fatalf("active requests = %d", state.ActiveRequests)
	}
}

func TestQuotaNonPeriodicAdmissionHasNoBucket(t *testing.T) {
	now := atomic.Int64{}
	now.Store(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC).UnixNano())
	store, closeDB := quotaTestStore(t, &now)
	defer closeDB()
	cases := []struct {
		name   string
		policy Policy
	}{
		{name: "concurrency", policy: Policy{MaxConcurrentRequests: 1024}},
		{name: "rolling", policy: Policy{RollingRequestCount: 128, RollingRequestWindow: time.Hour}},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			for range 128 {
				admission, err := store.Admit(context.Background(), testCase.name, testCase.policy, QuotaRequest{Requests: 1})
				if err != nil {
					t.Fatal(err)
				}
				if admission.BucketID != nil || !admission.PeriodStart.IsZero() {
					t.Fatalf("admission bucket = %#v period = %v", admission.BucketID, admission.PeriodStart)
				}
				if err := store.Release(context.Background(), admission.ID, "test failure"); err != nil {
					t.Fatal(err)
				}
			}
			if testCase.name == "rolling" {
				if _, err := store.Admit(context.Background(), testCase.name, testCase.policy, QuotaRequest{Requests: 1}); !errors.Is(err, ErrQuotaExceeded) {
					t.Fatalf("rolling admission after release error = %v", err)
				}
			}
			var buckets []QuotaBucket
			if err := store.db.Find(&buckets).Error; err != nil {
				t.Fatal(err)
			}
			if len(buckets) != 0 {
				t.Fatalf("bucket count = %d", len(buckets))
			}
		})
	}
}
