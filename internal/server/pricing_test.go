package server

import (
	"context"
	"math"
	"testing"
	"time"

	"github.com/catgirl-systems/codex-sub-proxy/internal/config"
	"github.com/catgirl-systems/codex-sub-proxy/internal/storage"
)

func TestEstimateUsageCostHalfUpAndOverflow(t *testing.T) {
	price := ModelPrice{
		InputMicrounitsPerMillion:       1_000_000,
		CachedInputMicrounitsPerMillion: 2_000_000,
		OutputMicrounitsPerMillion:      3_000_000,
		ReasoningMicrounitsPerMillion:   4_000_000,
		ImageMicrounitsPerImage:         5,
	}
	usage := UsageRecord{
		InputTokens: 1_000_001, CachedInputTokens: 1, CachedInputTokensKnown: true,
		OutputTokens: 3, ReasoningTokens: 1, ReasoningTokensKnown: true, ImageCount: 2,
	}
	got, reproducible, err := EstimateUsageCost(price, usage)
	if err != nil || !reproducible {
		t.Fatalf("estimate failed: %v, reproducible=%v", err, reproducible)
	}
	if got != 1_000_022 {
		t.Fatalf("estimate = %d, want 1000022", got)
	}
	half, reproducible, err := EstimateUsageCost(ModelPrice{InputMicrounitsPerMillion: 500_000}, UsageRecord{InputTokens: 1})
	if err != nil || !reproducible || half != 1 {
		t.Fatalf("half-up estimate = %d, reproducible=%v, err=%v", half, reproducible, err)
	}
	if _, _, err := EstimateUsageCost(ModelPrice{InputMicrounitsPerMillion: math.MaxInt64}, UsageRecord{InputTokens: 1}); err == nil {
		t.Fatal("expected checked integer overflow")
	}
}

func TestAllocateSubscriptionCostLargestRemainder(t *testing.T) {
	version := SubscriptionAllocationVersion{ID: "monthly-v1", Currency: pricingCurrencyUSD, AllocationBasis: pricingAllocationBasis, MonthlyCostMicrounits: 10}
	month := time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)
	open, available, err := AllocateSubscriptionCost(version, month, month.Add(24*time.Hour), []AllocationRequest{{RequestID: "b", EstimateMicrounits: 1}, {RequestID: "a", EstimateMicrounits: 1}, {RequestID: "c", EstimateMicrounits: 1}})
	if err != nil || !available || !open.Provisional {
		t.Fatalf("open allocation failed: %+v, available=%v, err=%v", open, available, err)
	}
	if open.Rows[0].Microunits != 3 || open.Rows[1].Microunits != 4 || open.Rows[2].Microunits != 3 {
		t.Fatalf("tie allocation = %+v, want b=3,a=4,c=3", open.Rows)
	}
	var total int64
	for _, row := range open.Rows {
		total += row.Microunits
	}
	if total != version.MonthlyCostMicrounits {
		t.Fatalf("allocation total = %d, want %d", total, version.MonthlyCostMicrounits)
	}
	closed, available, err := AllocateSubscriptionCost(version, month, month.AddDate(0, 1, 0), []AllocationRequest{{RequestID: "a", EstimateMicrounits: 1}})
	if err != nil || !available || closed.Provisional {
		t.Fatalf("closed allocation = %+v, available=%v, err=%v", closed, available, err)
	}
}

func TestPricingStoreEffectiveBoundaryAndConflict(t *testing.T) {
	db, err := storage.Open(context.Background(), t.TempDir()+"/pricing.sqlite", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	connection, err := db.DB()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = connection.Close() })
	oldAt := time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)
	newAt := oldAt.AddDate(0, 1, 0)
	old := config.PricingVersionConfig{ID: "v1", EffectiveAt: oldAt, Currency: "USD", Models: []config.ModelPriceConfig{{ModelID: "model-a", InputMicrounitsPerMillion: 1}}}
	newVersion := config.PricingVersionConfig{ID: "v2", EffectiveAt: newAt, Currency: "USD", Models: []config.ModelPriceConfig{{ModelID: "model-a", InputMicrounitsPerMillion: 2}}}
	store, err := InitializePricing(db, config.PricingConfig{Versions: []config.PricingVersionConfig{old, newVersion}})
	if err != nil || !store.Available() {
		t.Fatalf("initialize pricing failed: %v", err)
	}
	version, price, found, err := store.resolvePricing(db, newAt.Add(-time.Nanosecond), "model-a")
	if err != nil || !found || version.ID != "v1" || price.InputMicrounitsPerMillion != 1 {
		t.Fatalf("before boundary = version=%+v price=%+v found=%v err=%v", version, price, found, err)
	}
	version, price, found, err = store.resolvePricing(db, newAt, "model-a")
	if err != nil || !found || version.ID != "v2" || price.InputMicrounitsPerMillion != 2 {
		t.Fatalf("at boundary = version=%+v price=%+v found=%v err=%v", version, price, found, err)
	}
	conflict := old
	conflict.Models[0].InputMicrounitsPerMillion = 9
	conflicted, err := InitializePricing(db, config.PricingConfig{Versions: []config.PricingVersionConfig{conflict}})
	if err != nil || conflicted.Available() || conflicted.Err() == nil {
		t.Fatalf("conflict availability = store=%+v err=%v", conflicted, err)
	}
	var count int64
	if err := db.Model(&PricingVersion{}).Count(&count).Error; err != nil {
		t.Fatal(err)
	}
	if count != 2 {
		t.Fatalf("pricing versions changed after conflict: %d", count)
	}
	if _, _, found, err := store.resolvePricing(db, oldAt, "missing-model"); err != nil || found {
		t.Fatalf("missing model resolution = found=%v err=%v", found, err)
	}
}
