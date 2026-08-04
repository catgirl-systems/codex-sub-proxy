package server

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"math/big"
	"sort"
	"strings"
	"time"

	"github.com/catgirl-systems/codex-sub-proxy/internal/config"
	"gorm.io/gorm"
)

const (
	pricingCurrencyUSD     = "USD"
	pricingAllocationBasis = "proportional_public_estimated_cost"
	pricingRoundingBasis   = "per_component_half_up_microunits_per_million"
	pricingScale           = int64(1_000_000)
)

// PricingVersion is an immutable public price catalog input.
type PricingVersion struct {
	ID            string    `gorm:"column:id;primaryKey;size:64"`
	EffectiveAt   time.Time `gorm:"column:effective_at;not null;index:idx_pricing_effective"`
	Currency      string    `gorm:"column:currency;not null;size:3"`
	InputChecksum string    `gorm:"column:input_checksum;not null;size:64"`
	CreatedAt     time.Time `gorm:"column:created_at;not null"`
}

func (PricingVersion) TableName() string { return "pricing_versions" }

func (PricingVersion) BeforeUpdate(*gorm.DB) error {
	return errors.New("pricing versions are immutable")
}

func (PricingVersion) BeforeDelete(*gorm.DB) error {
	return errors.New("pricing versions are immutable")
}

// ModelPrice is an immutable set of integer rates for one model.
type ModelPrice struct {
	PricingVersionID                string `gorm:"column:pricing_version_id;primaryKey;size:64;index"`
	ModelID                         string `gorm:"column:model_id;primaryKey;size:256;index"`
	InputMicrounitsPerMillion       int64  `gorm:"column:input_microunits_per_million;not null"`
	CachedInputMicrounitsPerMillion int64  `gorm:"column:cached_input_microunits_per_million;not null"`
	OutputMicrounitsPerMillion      int64  `gorm:"column:output_microunits_per_million;not null"`
	ReasoningMicrounitsPerMillion   int64  `gorm:"column:reasoning_microunits_per_million;not null"`
	ImageMicrounitsPerImage         int64  `gorm:"column:image_microunits_per_image;not null"`
}

func (ModelPrice) TableName() string { return "model_prices" }

func (ModelPrice) BeforeUpdate(*gorm.DB) error {
	return errors.New("model prices are immutable")
}

func (ModelPrice) BeforeDelete(*gorm.DB) error {
	return errors.New("model prices are immutable")
}

// SubscriptionAllocationVersion is an immutable monthly allocation input.
type SubscriptionAllocationVersion struct {
	ID                    string    `gorm:"column:id;primaryKey;size:64"`
	EffectiveAt           time.Time `gorm:"column:effective_at;not null;index:idx_subscription_effective"`
	Currency              string    `gorm:"column:currency;not null;size:3"`
	MonthlyCostMicrounits int64     `gorm:"column:monthly_cost_microunits;not null"`
	AllocationBasis       string    `gorm:"column:allocation_basis;not null;size:128"`
	InputChecksum         string    `gorm:"column:input_checksum;not null;size:64"`
	CreatedAt             time.Time `gorm:"column:created_at;not null"`
}

func (SubscriptionAllocationVersion) TableName() string { return "subscription_allocation_versions" }

func (SubscriptionAllocationVersion) BeforeUpdate(*gorm.DB) error {
	return errors.New("subscription allocation versions are immutable")
}

func (SubscriptionAllocationVersion) BeforeDelete(*gorm.DB) error {
	return errors.New("subscription allocation versions are immutable")
}

// PricingStore writes immutable inputs and resolves prices for request times.
type PricingStore struct {
	db        *gorm.DB
	available bool
	err       error
}

// MigratePricing creates the immutable pricing input tables.
func MigratePricing(db *gorm.DB) error {
	if db == nil {
		return errors.New("pricing database is nil")
	}
	if err := db.AutoMigrate(&PricingVersion{}, &ModelPrice{}, &SubscriptionAllocationVersion{}); err != nil {
		return fmt.Errorf("migrate pricing: %w", err)
	}
	return nil
}

// InitializePricing persists new configuration without changing old rows.
// A duplicate ID with a different checksum leaves analytics unavailable, while
// the caller can keep the data plane running with the returned store.
func InitializePricing(db *gorm.DB, pricing config.PricingConfig) (*PricingStore, error) {
	if db == nil {
		return nil, errors.New("pricing database is nil")
	}
	if err := MigratePricing(db); err != nil {
		return nil, err
	}
	store := &PricingStore{db: db, available: true}
	if err := validatePricingInputs(&pricing); err != nil {
		return nil, err
	}
	err := db.Transaction(func(tx *gorm.DB) error {
		for index := range pricing.Versions {
			version := pricing.Versions[index]
			if err := insertPricingVersion(tx, version); err != nil {
				if errors.Is(err, errPricingVersionConflict) {
					store.available = false
					store.err = err
					continue
				}
				return fmt.Errorf("persist pricing version %q: %w", version.ID, err)
			}
		}
		for index := range pricing.SubscriptionAllocationVersions {
			version := pricing.SubscriptionAllocationVersions[index]
			if err := insertSubscriptionVersion(tx, version); err != nil {
				if errors.Is(err, errPricingVersionConflict) {
					store.available = false
					store.err = err
					continue
				}
				return fmt.Errorf("persist subscription allocation version %q: %w", version.ID, err)
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return store, nil
}

var errPricingVersionConflict = errors.New("immutable pricing version input conflicts")

func validatePricingInputs(pricing *config.PricingConfig) error {
	if pricing == nil {
		return errors.New("pricing configuration is nil")
	}
	seenPricing := make(map[string]struct{}, len(pricing.Versions))
	for index := range pricing.Versions {
		version := &pricing.Versions[index]
		if err := validateConfigPricingVersion(version); err != nil {
			return fmt.Errorf("pricing version %d: %w", index, err)
		}
		if _, ok := seenPricing[version.ID]; ok {
			return fmt.Errorf("duplicate pricing version ID %q", version.ID)
		}
		seenPricing[version.ID] = struct{}{}
	}
	seenAllocation := make(map[string]struct{}, len(pricing.SubscriptionAllocationVersions))
	for index := range pricing.SubscriptionAllocationVersions {
		version := &pricing.SubscriptionAllocationVersions[index]
		if err := validateConfigSubscriptionVersion(version); err != nil {
			return fmt.Errorf("subscription allocation version %d: %w", index, err)
		}
		if _, ok := seenAllocation[version.ID]; ok {
			return fmt.Errorf("duplicate subscription allocation version ID %q", version.ID)
		}
		seenAllocation[version.ID] = struct{}{}
	}
	return nil
}

func validateConfigPricingVersion(version *config.PricingVersionConfig) error {
	if version == nil || strings.TrimSpace(version.ID) == "" || version.ID != strings.TrimSpace(version.ID) || len(version.ID) > 64 {
		return errors.New("version ID is invalid")
	}
	if version.EffectiveAt.IsZero() || version.EffectiveAt.Location() != time.UTC {
		return errors.New("effective time must be UTC")
	}
	if version.Currency != pricingCurrencyUSD || len(version.Models) == 0 {
		return errors.New("pricing currency or model list is invalid")
	}
	seen := make(map[string]struct{}, len(version.Models))
	for index := range version.Models {
		model := &version.Models[index]
		if model.InputMicrounitsPer1M != nil {
			model.InputMicrounitsPerMillion = *model.InputMicrounitsPer1M
		}
		if model.CachedInputMicrounitsPer1M != nil {
			model.CachedInputMicrounitsPerMillion = *model.CachedInputMicrounitsPer1M
		}
		if model.OutputMicrounitsPer1M != nil {
			model.OutputMicrounitsPerMillion = *model.OutputMicrounitsPer1M
		}
		if model.ReasoningMicrounitsPer1M != nil {
			model.ReasoningMicrounitsPerMillion = *model.ReasoningMicrounitsPer1M
		}
		if model.ModelID == "" || model.ModelID != strings.TrimSpace(model.ModelID) || len(model.ModelID) > 256 {
			return errors.New("model ID is invalid")
		}
		if _, ok := seen[model.ModelID]; ok {
			return fmt.Errorf("duplicate model ID %q", model.ModelID)
		}
		seen[model.ModelID] = struct{}{}
		for _, rate := range []int64{model.InputMicrounitsPerMillion, model.CachedInputMicrounitsPerMillion, model.OutputMicrounitsPerMillion, model.ReasoningMicrounitsPerMillion, model.ImageMicrounitsPerImage} {
			if rate < 0 {
				return errors.New("rate is negative")
			}
		}
	}
	return nil
}

func validateConfigSubscriptionVersion(version *config.SubscriptionAllocationVersionConfig) error {
	if version == nil || strings.TrimSpace(version.ID) == "" || version.ID != strings.TrimSpace(version.ID) || len(version.ID) > 64 {
		return errors.New("version ID is invalid")
	}
	if version.EffectiveAt.IsZero() || version.EffectiveAt.Location() != time.UTC {
		return errors.New("effective time must be UTC")
	}
	if version.Currency != pricingCurrencyUSD || version.MonthlyCostMicrounits < 0 || version.AllocationBasis != pricingAllocationBasis {
		return errors.New("subscription allocation input is invalid")
	}
	return nil
}

func insertPricingVersion(tx *gorm.DB, input config.PricingVersionConfig) error {
	checksum, err := pricingChecksum(input)
	if err != nil {
		return err
	}
	var existing PricingVersion
	result := tx.Where("id = ?", input.ID).First(&existing)
	if result.Error == nil {
		if existing.InputChecksum != checksum {
			return fmt.Errorf("%w: pricing version %q", errPricingVersionConflict, input.ID)
		}
		return nil
	}
	if !errors.Is(result.Error, gorm.ErrRecordNotFound) {
		return fmt.Errorf("load pricing version: %w", result.Error)
	}
	now := time.Now().UTC()
	row := PricingVersion{ID: input.ID, EffectiveAt: input.EffectiveAt, Currency: input.Currency, InputChecksum: checksum, CreatedAt: now}
	if err := tx.Create(&row).Error; err != nil {
		return fmt.Errorf("create pricing version: %w", err)
	}
	models := append([]config.ModelPriceConfig(nil), input.Models...)
	sort.Slice(models, func(i, j int) bool { return models[i].ModelID < models[j].ModelID })
	for _, model := range models {
		if err := tx.Create(&ModelPrice{
			PricingVersionID:                input.ID,
			ModelID:                         model.ModelID,
			InputMicrounitsPerMillion:       model.InputMicrounitsPerMillion,
			CachedInputMicrounitsPerMillion: model.CachedInputMicrounitsPerMillion,
			OutputMicrounitsPerMillion:      model.OutputMicrounitsPerMillion,
			ReasoningMicrounitsPerMillion:   model.ReasoningMicrounitsPerMillion,
			ImageMicrounitsPerImage:         model.ImageMicrounitsPerImage,
		}).Error; err != nil {
			return fmt.Errorf("create model price %q: %w", model.ModelID, err)
		}
	}
	return nil
}

func insertSubscriptionVersion(tx *gorm.DB, input config.SubscriptionAllocationVersionConfig) error {
	checksum, err := subscriptionChecksum(input)
	if err != nil {
		return err
	}
	var existing SubscriptionAllocationVersion
	result := tx.Where("id = ?", input.ID).First(&existing)
	if result.Error == nil {
		if existing.InputChecksum != checksum {
			return fmt.Errorf("%w: subscription allocation version %q", errPricingVersionConflict, input.ID)
		}
		return nil
	}
	if !errors.Is(result.Error, gorm.ErrRecordNotFound) {
		return fmt.Errorf("load subscription allocation version: %w", result.Error)
	}
	row := SubscriptionAllocationVersion{ID: input.ID, EffectiveAt: input.EffectiveAt, Currency: input.Currency, MonthlyCostMicrounits: input.MonthlyCostMicrounits, AllocationBasis: input.AllocationBasis, InputChecksum: checksum, CreatedAt: time.Now().UTC()}
	if err := tx.Create(&row).Error; err != nil {
		return fmt.Errorf("create subscription allocation version: %w", err)
	}
	return nil
}

func pricingChecksum(input config.PricingVersionConfig) (string, error) {
	models := append([]config.ModelPriceConfig(nil), input.Models...)
	sort.Slice(models, func(i, j int) bool { return models[i].ModelID < models[j].ModelID })
	type canonicalModel struct {
		ModelID                         string `json:"model_id"`
		InputMicrounitsPerMillion       int64  `json:"input_microunits_per_million"`
		CachedInputMicrounitsPerMillion int64  `json:"cached_input_microunits_per_million"`
		OutputMicrounitsPerMillion      int64  `json:"output_microunits_per_million"`
		ReasoningMicrounitsPerMillion   int64  `json:"reasoning_microunits_per_million"`
		ImageMicrounitsPerImage         int64  `json:"image_microunits_per_image"`
	}
	canonicalModels := make([]canonicalModel, 0, len(models))
	for _, model := range models {
		canonicalModels = append(canonicalModels, canonicalModel{
			ModelID:                         model.ModelID,
			InputMicrounitsPerMillion:       model.InputMicrounitsPerMillion,
			CachedInputMicrounitsPerMillion: model.CachedInputMicrounitsPerMillion,
			OutputMicrounitsPerMillion:      model.OutputMicrounitsPerMillion,
			ReasoningMicrounitsPerMillion:   model.ReasoningMicrounitsPerMillion,
			ImageMicrounitsPerImage:         model.ImageMicrounitsPerImage,
		})
	}
	canonical := struct {
		ID          string           `json:"id"`
		EffectiveAt string           `json:"effective_at"`
		Currency    string           `json:"currency"`
		Models      []canonicalModel `json:"models"`
	}{input.ID, input.EffectiveAt.UTC().Format(time.RFC3339Nano), input.Currency, canonicalModels}
	encoded, err := json.Marshal(canonical)
	if err != nil {
		return "", fmt.Errorf("encode pricing checksum: %w", err)
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}

func subscriptionChecksum(input config.SubscriptionAllocationVersionConfig) (string, error) {
	canonical := struct {
		ID                    string `json:"id"`
		EffectiveAt           string `json:"effective_at"`
		Currency              string `json:"currency"`
		MonthlyCostMicrounits int64  `json:"monthly_cost_microunits"`
		AllocationBasis       string `json:"allocation_basis"`
	}{input.ID, input.EffectiveAt.UTC().Format(time.RFC3339Nano), input.Currency, input.MonthlyCostMicrounits, input.AllocationBasis}
	encoded, err := json.Marshal(canonical)
	if err != nil {
		return "", fmt.Errorf("encode subscription checksum: %w", err)
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}

// Available reports whether immutable inputs agree with stored versions.
func (s *PricingStore) Available() bool { return s != nil && s.available }

// Err returns the immutable input conflict, if startup found one.
func (s *PricingStore) Err() error {
	if s == nil {
		return errors.New("pricing store is unavailable")
	}
	return s.err
}

func (s *PricingStore) resolvePricing(tx *gorm.DB, at time.Time, modelID string) (PricingVersion, ModelPrice, bool, error) {
	if s == nil || !s.available || tx == nil {
		return PricingVersion{}, ModelPrice{}, false, nil
	}
	var version PricingVersion
	if err := tx.Where("effective_at <= ?", at.UTC()).Order("effective_at DESC, id DESC").First(&version).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return PricingVersion{}, ModelPrice{}, false, nil
		}
		return PricingVersion{}, ModelPrice{}, false, fmt.Errorf("resolve pricing version: %w", err)
	}
	var price ModelPrice
	if err := tx.Where("pricing_version_id = ? AND model_id = ?", version.ID, modelID).First(&price).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return version, ModelPrice{}, false, nil
		}
		return PricingVersion{}, ModelPrice{}, false, fmt.Errorf("resolve model price: %w", err)
	}
	return version, price, true, nil
}

// PricingEstimate is the reproducible public estimate and its calculation basis.
type PricingEstimate struct {
	PricingVersionID string
	ModelID          string
	Currency         string
	Microunits       int64
	RoundingBasis    string
}

// EstimateUsageCost computes a checked integer estimate. It returns ok=false
// when the usage lacks a required reproducible breakdown.
func EstimateUsageCost(price ModelPrice, usage UsageRecord) (int64, bool, error) {
	if usage.InputTokens < 0 || usage.OutputTokens < 0 || usage.TotalTokens < 0 || usage.ImageCount < 0 || usage.CachedInputTokens < 0 || usage.ReasoningTokens < 0 {
		return 0, false, errors.New("usage counters are negative")
	}
	if usage.CachedInputTokens > usage.InputTokens || usage.ReasoningTokens > usage.OutputTokens {
		return 0, false, nil
	}
	if (!usage.CachedInputTokensKnown && price.CachedInputMicrounitsPerMillion != 0) || (!usage.ReasoningTokensKnown && price.ReasoningMicrounitsPerMillion != 0) {
		return 0, false, nil
	}
	input := usage.InputTokens - usage.CachedInputTokens
	output := usage.OutputTokens - usage.ReasoningTokens
	parts := []struct {
		count int64
		rate  int64
	}{
		{input, price.InputMicrounitsPerMillion},
		{usage.CachedInputTokens, price.CachedInputMicrounitsPerMillion},
		{output, price.OutputMicrounitsPerMillion},
		{usage.ReasoningTokens, price.ReasoningMicrounitsPerMillion},
	}
	var total int64
	for _, part := range parts {
		value, err := roundHalfUp(part.count, part.rate)
		if err != nil {
			return 0, false, err
		}
		if total > math.MaxInt64-value {
			return 0, false, errors.New("public estimate overflows int64")
		}
		total += value
	}
	if usage.ImageCount != 0 {
		if price.ImageMicrounitsPerImage > math.MaxInt64/usage.ImageCount {
			return 0, false, errors.New("image estimate overflows int64")
		}
		value := price.ImageMicrounitsPerImage * usage.ImageCount
		if total > math.MaxInt64-value {
			return 0, false, errors.New("public estimate overflows int64")
		}
		total += value
	}
	return total, true, nil
}

func roundHalfUp(count, rate int64) (int64, error) {
	if count < 0 || rate < 0 {
		return 0, errors.New("estimate input is negative")
	}
	if count == 0 || rate == 0 {
		return 0, nil
	}
	if count > math.MaxInt64/rate {
		return 0, errors.New("token estimate overflows int64")
	}
	product := count * rate
	if product > math.MaxInt64-pricingScale/2 {
		return 0, errors.New("token estimate rounding overflows int64")
	}
	return (product + pricingScale/2) / pricingScale, nil
}

// AllocationRequest is one successful priced request in a UTC month.
type AllocationRequest struct {
	RequestID          string
	EstimateMicrounits int64
}

// AllocationResult contains deterministic largest-remainder allocations.
type AllocationResult struct {
	VersionID   string
	Currency    string
	Basis       string
	Month       time.Time
	Denominator int64
	Provisional bool
	Rows        []AllocationRow
}

// AllocationRow is a derived estimate. It is not a billed or charged amount.
type AllocationRow struct {
	RequestID   string
	Numerator   int64
	Denominator int64
	Microunits  int64
}

// AllocateSubscriptionCost computes exact proportional monthly allocation.
func AllocateSubscriptionCost(version SubscriptionAllocationVersion, month time.Time, now time.Time, requests []AllocationRequest) (AllocationResult, bool, error) {
	if version.Currency != pricingCurrencyUSD || version.AllocationBasis != pricingAllocationBasis || version.MonthlyCostMicrounits < 0 {
		return AllocationResult{}, false, errors.New("subscription allocation version is invalid")
	}
	if month.Location() != time.UTC || now.Location() != time.UTC {
		return AllocationResult{}, false, errors.New("allocation times must be UTC")
	}
	month = month.UTC().Truncate(24 * time.Hour)
	month = time.Date(month.Year(), month.Month(), 1, 0, 0, 0, 0, time.UTC)
	denominator := int64(0)
	for _, request := range requests {
		if request.RequestID == "" || request.EstimateMicrounits <= 0 {
			continue
		}
		if denominator > math.MaxInt64-request.EstimateMicrounits {
			return AllocationResult{}, false, errors.New("allocation denominator overflows int64")
		}
		denominator += request.EstimateMicrounits
	}
	if denominator == 0 {
		return AllocationResult{}, false, nil
	}
	rows := make([]AllocationRow, 0, len(requests))
	type remainder struct {
		index int
		value *big.Int
	}
	remainders := make([]remainder, 0, len(requests))
	total := big.NewInt(0)
	for _, request := range requests {
		if request.RequestID == "" || request.EstimateMicrounits <= 0 {
			continue
		}
		numerator := new(big.Int).SetInt64(request.EstimateMicrounits)
		product := new(big.Int).Mul(numerator, big.NewInt(version.MonthlyCostMicrounits))
		quotient, rest := new(big.Int), new(big.Int)
		quotient.QuoRem(product, big.NewInt(denominator), rest)
		if !quotient.IsInt64() {
			return AllocationResult{}, false, errors.New("allocation amount overflows int64")
		}
		amount := quotient.Int64()
		if amount < 0 || !total.IsInt64() || total.Int64() > math.MaxInt64-amount {
			return AllocationResult{}, false, errors.New("allocation total overflows int64")
		}
		rowIndex := len(rows)
		rows = append(rows, AllocationRow{RequestID: request.RequestID, Numerator: request.EstimateMicrounits, Denominator: denominator, Microunits: amount})
		total.Add(total, quotient)
		remainders = append(remainders, remainder{index: rowIndex, value: rest})
	}
	if !total.IsInt64() {
		return AllocationResult{}, false, errors.New("allocation total overflows int64")
	}
	remaining := version.MonthlyCostMicrounits - total.Int64()
	if remaining < 0 || remaining > int64(len(rows)) {
		return AllocationResult{}, false, errors.New("allocation remainder is invalid")
	}
	sort.SliceStable(remainders, func(i, j int) bool {
		comparison := remainders[i].value.Cmp(remainders[j].value)
		if comparison != 0 {
			return comparison > 0
		}
		return rows[remainders[i].index].RequestID < rows[remainders[j].index].RequestID
	})
	for index := int64(0); index < remaining; index++ {
		row := &rows[remainders[index].index]
		if row.Microunits == math.MaxInt64 {
			return AllocationResult{}, false, errors.New("allocation amount overflows int64")
		}
		row.Microunits++
	}
	monthEnd := month.AddDate(0, 1, 0)
	return AllocationResult{VersionID: version.ID, Currency: version.Currency, Basis: version.AllocationBasis, Month: month, Denominator: denominator, Provisional: now.UTC().Before(monthEnd), Rows: rows}, true, nil
}
