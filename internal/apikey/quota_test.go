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
