package server

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/catgirl-systems/codex-sub-proxy/internal/apikey"
	"github.com/catgirl-systems/codex-sub-proxy/internal/storage"
)

func TestAnalyticsRangedUsageJoinUsesRequestAndUsageIndexes(t *testing.T) {
	db, err := storage.Open(context.Background(), t.TempDir()+"/analytics.sqlite", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	connection, err := db.DB()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = connection.Close() })
	if err := db.AutoMigrate(&RequestRecord{}, &UsageRecord{}); err != nil {
		t.Fatal(err)
	}
	from := time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)
	to := from.AddDate(0, 1, 0)
	join, args := analyticsUsageJoin(analyticsFilter{From: from, To: to})
	query := "EXPLAIN QUERY PLAN SELECT r.request_id FROM requests AS r " + join + " WHERE r.accepted_at >= ? AND r.accepted_at < ?"
	args = append(args, from, to)
	rows, err := db.Raw(query, args...).Rows()
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var details []string
	for rows.Next() {
		var id, parent, notUsed int
		var detail string
		if err := rows.Scan(&id, &parent, &notUsed, &detail); err != nil {
			t.Fatal(err)
		}
		details = append(details, detail)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	plan := strings.Join(details, "\n")
	if !strings.Contains(plan, "accepted_at") || !strings.Contains(plan, "request_id") {
		t.Fatalf("ranged usage plan does not use request and usage keys: %s", plan)
	}
	if strings.Contains(strings.ToUpper(plan), "SCAN UX") {
		t.Fatalf("ranged usage plan scans all usage rows: %s", plan)
	}
}

func TestAnalyticsBucketReturnsCachedAndReasoningTotals(t *testing.T) {
	db, err := storage.Open(context.Background(), t.TempDir()+"/analytics-bucket.sqlite", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	connection, err := db.DB()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = connection.Close() })
	if err := db.AutoMigrate(&RequestRecord{}, &UsageRecord{}); err != nil {
		t.Fatal(err)
	}
	accepted := time.Date(2026, time.January, 2, 3, 0, 0, 0, time.UTC)
	if err := db.Create(&RequestRecord{ID: "request-1", ReplayID: "replay-1", ConversationID: "conversation-1", Endpoint: "/v1/chat/completions", Model: "model-a", RequestedModel: "model-a", Status: requestStatusSucceeded, CreatedAt: accepted, AcceptedAt: accepted, StartedAt: accepted, UpdatedAt: accepted, ExpiresAt: accepted.Add(time.Hour)}).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Create(&UsageRecord{ReplayID: "usage-1", RequestID: "request-1", InputTokens: 10, CachedInputTokens: 2, CachedInputTokensKnown: true, OutputTokens: 8, ReasoningTokens: 3, ReasoningTokensKnown: true, TotalTokens: 18, CreatedAt: accepted}).Error; err != nil {
		t.Fatal(err)
	}
	filter := analyticsFilter{From: time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC), To: time.Date(2026, time.February, 1, 0, 0, 0, 0, time.UTC), Limit: 100, Interval: "day"}
	response, err := analyticsBuckets(db, filter, false)
	if err != nil {
		t.Fatal(err)
	}
	buckets, ok := response.Data.([]analyticsBucketRow)
	if !ok || len(buckets) != 1 {
		t.Fatalf("bucket response = %#v", response.Data)
	}
	if buckets[0].CachedInputTokens != 2 || buckets[0].ReasoningTokens != 3 {
		t.Fatalf("bucket usage = %+v", buckets[0])
	}
}
func TestAnalyticsOverviewAppliesCompleteFilter(t *testing.T) {
	db, err := storage.Open(context.Background(), t.TempDir()+"/analytics-overview.sqlite", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	connection, err := db.DB()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = connection.Close() })
	if err := db.AutoMigrate(&RequestRecord{}, &UsageRecord{}, &SubscriptionAllocationVersion{}); err != nil {
		t.Fatal(err)
	}
	from := time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)
	to := time.Date(2026, time.February, 1, 0, 0, 0, 0, time.UTC)
	terminal := from.Add(time.Hour)
	target := RequestRecord{
		ID: "target", ReplayID: "target-replay", ConversationID: "conversation", APIKeyID: "key-target",
		Endpoint: "/target", Model: "fallback", RequestedModel: "requested", ResolvedModel: "resolved",
		Status: requestStatusFailed, ErrorClass: "upstream", ErrorCode: "bad",
		CreatedAt: from, AcceptedAt: from, StartedAt: from, UpdatedAt: terminal, TerminalAt: &terminal, ExpiresAt: to,
	}
	unrelated := target
	unrelated.ID, unrelated.ReplayID, unrelated.APIKeyID = "unrelated", "unrelated-replay", "key-other"
	unrelated.Endpoint, unrelated.Status, unrelated.ErrorClass = "/other", requestStatusSucceeded, ""
	if err := db.Create(&target).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Create(&unrelated).Error; err != nil {
		t.Fatal(err)
	}
	cost := int64(11)
	if err := db.Create(&UsageRecord{ReplayID: "target-usage", RequestID: target.ID, InputTokens: 2, OutputTokens: 3, TotalTokens: 5, EstimatedPublicCostMicrounits: &cost, CreatedAt: from}).Error; err != nil {
		t.Fatal(err)
	}
	otherCost := int64(99)
	if err := db.Create(&UsageRecord{ReplayID: "other-usage", RequestID: unrelated.ID, InputTokens: 20, OutputTokens: 30, TotalTokens: 50, EstimatedPublicCostMicrounits: &otherCost, CreatedAt: from}).Error; err != nil {
		t.Fatal(err)
	}
	filter := analyticsFilter{
		From: from, To: to, RequestedModel: "requested", ResolvedModel: "resolved", Model: "resolved",
		APIKeyID: "key-target", Endpoint: "/target", State: requestStatusFailed, ErrorClass: "upstream", Limit: 50,
	}
	response, err := analyticsOverview(db, filter)
	if err != nil {
		t.Fatal(err)
	}
	if response.Requests.Count != 1 || response.Requests.Failed != 1 || response.ActiveKeys != 1 {
		t.Fatalf("filtered requests = %+v, active keys=%d", response.Requests, response.ActiveKeys)
	}
	if response.Usage.InputTokens != 2 || response.Usage.OutputTokens != 3 || response.Usage.TotalTokens != 5 {
		t.Fatalf("filtered usage = %+v", response.Usage)
	}
	if response.Costs.EstimatedPublicCostMicrounits == nil || *response.Costs.EstimatedPublicCostMicrounits != 11 {
		t.Fatalf("filtered cost = %+v", response.Costs.EstimatedPublicCostMicrounits)
	}
	if response.Latency.Count != 1 || len(response.States) != 1 || response.States[0].State != requestStatusFailed {
		t.Fatalf("filtered latency/states = %+v / %+v", response.Latency, response.States)
	}
}

func TestAnalyticsCursorValidationAndNullableResolvedGrouping(t *testing.T) {
	cursor := encodeAnalyticsCursor("models", "requested", "")
	if values, err := decodeAnalyticsCursor(cursor, "models"); err != nil || len(values) != 2 {
		t.Fatalf("decode canonical cursor = %v, %v", values, err)
	}
	if _, err := decodeAnalyticsCursor(cursor, "keys"); err == nil {
		t.Fatal("cross-endpoint cursor was accepted")
	}
	if _, err := decodeAnalyticsCursor(cursor+"A", "models"); err == nil {
		t.Fatal("non-canonical cursor was accepted")
	}

	db, err := storage.Open(context.Background(), t.TempDir()+"/analytics-models.sqlite", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	connection, err := db.DB()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = connection.Close() })
	if err := db.AutoMigrate(&RequestRecord{}, &UsageRecord{}); err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, time.January, 2, 0, 0, 0, 0, time.UTC)
	for _, request := range []RequestRecord{
		{ID: "null", ReplayID: "null-replay", ConversationID: "c", APIKeyID: "k", Endpoint: "/e", Model: "m", RequestedModel: "requested", Status: requestStatusSucceeded, AcceptedAt: at, CreatedAt: at, UpdatedAt: at, ExpiresAt: at.Add(time.Hour)},
		{ID: "empty", ReplayID: "empty-replay", ConversationID: "c", APIKeyID: "k", Endpoint: "/e", Model: "m", RequestedModel: "requested", ResolvedModel: "", Status: requestStatusSucceeded, AcceptedAt: at, CreatedAt: at, UpdatedAt: at, ExpiresAt: at.Add(time.Hour)},
	} {
		if err := db.Create(&request).Error; err != nil {
			t.Fatal(err)
		}
	}
	if err := db.Exec("UPDATE requests SET resolved_model = NULL WHERE request_id = ?", "null").Error; err != nil {
		t.Fatal(err)
	}
	response, err := analyticsModels(db, analyticsFilter{From: at.Add(-time.Hour), To: at.Add(time.Hour), Limit: 50})
	if err != nil {
		t.Fatal(err)
	}
	rows, ok := response.Data.([]analyticsModelRow)
	if !ok || len(rows) != 1 || rows[0].RequestCount != 2 || rows[0].ResolvedModel != "" {
		t.Fatalf("nullable resolved grouping = %#v", response.Data)
	}
}
func TestAnalyticsQuotaAndCostUseFilteredDurableUsage(t *testing.T) {
	db, err := storage.Open(context.Background(), t.TempDir()+"/analytics-quota.sqlite", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	connection, err := db.DB()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = connection.Close() })
	if err := db.AutoMigrate(&RequestRecord{}, &UsageRecord{}); err != nil {
		t.Fatal(err)
	}
	if err := apikey.MigrateQuota(db); err != nil {
		t.Fatal(err)
	}
	targetAt := time.Date(2026, time.January, 2, 2, 0, 0, 0, time.UTC)
	otherAt := targetAt.Add(2 * time.Hour)
	for _, request := range []RequestRecord{
		{ID: "quota-target", ReplayID: "quota-target-replay", ConversationID: "c", APIKeyID: "k", Endpoint: "/e", Model: "m", RequestedModel: "m", Status: requestStatusSucceeded, AcceptedAt: targetAt, CreatedAt: targetAt, UpdatedAt: targetAt, ExpiresAt: targetAt.Add(time.Hour)},
		{ID: "quota-other", ReplayID: "quota-other-replay", ConversationID: "c", APIKeyID: "other", Endpoint: "/e", Model: "m", RequestedModel: "m", Status: requestStatusSucceeded, AcceptedAt: otherAt, CreatedAt: otherAt, UpdatedAt: otherAt, ExpiresAt: otherAt.Add(time.Hour)},
	} {
		if err := db.Create(&request).Error; err != nil {
			t.Fatal(err)
		}
	}
	targetCost := int64(7)
	otherCost := int64(90)
	for _, usage := range []UsageRecord{
		{ReplayID: "quota-target-usage", RequestID: "quota-target", InputTokens: 2, TotalTokens: 5, EstimatedPublicCostMicrounits: &targetCost, CreatedAt: targetAt},
		{ReplayID: "quota-other-usage", RequestID: "quota-other", InputTokens: 20, TotalTokens: 50, EstimatedPublicCostMicrounits: &otherCost, CreatedAt: otherAt},
	} {
		if err := db.Create(&usage).Error; err != nil {
			t.Fatal(err)
		}
	}
	if err := db.Create(&apikey.QuotaReservation{
		ID: "pending-target", KeyID: "k", RequestID: "quota-target", OwnerID: "owner",
		PeriodStart: targetAt.Truncate(24 * time.Hour), RequestedRequests: 1, RequestedTokens: 5,
		Status: "pending", CreatedAt: targetAt,
	}).Error; err != nil {
		t.Fatal(err)
	}
	var beforeBuckets int64
	if err := db.Model(&apikey.QuotaBucket{}).Count(&beforeBuckets).Error; err != nil {
		t.Fatal(err)
	}
	filter := analyticsFilter{From: targetAt.Add(-time.Hour), To: targetAt.Add(time.Hour), APIKeyID: "k", Limit: 50, Interval: "hour"}
	quota, err := analyticsQuotas(db, filter)
	if err != nil {
		t.Fatal(err)
	}
	if quota.QuotaAccountedRequests != 1 || quota.QuotaAccountedTokens != 5 || quota.QuotaAccountedCostMicrounits != 7 || quota.PendingRequests != 1 {
		t.Fatalf("filtered quota = %+v", quota)
	}
	costs, err := analyticsBuckets(db, filter, true)
	if err != nil {
		t.Fatal(err)
	}
	rows := costs.Data.([]analyticsBucketRow)
	if len(rows) != 1 || rows[0].QuotaAccountedCost == nil || *rows[0].QuotaAccountedCost != 7 {
		t.Fatalf("filtered cost buckets = %+v", rows)
	}
	var afterBuckets int64
	if err := db.Model(&apikey.QuotaBucket{}).Count(&afterBuckets).Error; err != nil {
		t.Fatal(err)
	}
	if beforeBuckets != afterBuckets {
		t.Fatalf("analytics mutated quota buckets: before=%d after=%d", beforeBuckets, afterBuckets)
	}
}
func TestAnalyticsAllocationFilterUsesFullMonthDenominator(t *testing.T) {
	db, err := storage.Open(context.Background(), t.TempDir()+"/analytics-allocation.sqlite", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	connection, err := db.DB()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = connection.Close() })
	if err := db.AutoMigrate(&RequestRecord{}, &UsageRecord{}, &SubscriptionAllocationVersion{}); err != nil {
		t.Fatal(err)
	}
	month := time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)
	if err := db.Create(&SubscriptionAllocationVersion{ID: "allocation-v1", EffectiveAt: month.AddDate(-1, 0, 0), Currency: "USD", MonthlyCostMicrounits: 100, AllocationBasis: pricingAllocationBasis, InputChecksum: "checksum", CreatedAt: month}).Error; err != nil {
		t.Fatal(err)
	}
	accepted := month.Add(24 * time.Hour)
	for index, key := range []string{"key-one", "key-two"} {
		id := fmt.Sprintf("allocation-%d", index)
		if err := db.Create(&RequestRecord{ID: id, ReplayID: id + "-replay", ConversationID: "c", APIKeyID: key, Endpoint: "/e", Model: "m", RequestedModel: "m", Status: requestStatusSucceeded, AcceptedAt: accepted, CreatedAt: accepted, UpdatedAt: accepted, ExpiresAt: month.AddDate(0, 2, 0)}).Error; err != nil {
			t.Fatal(err)
		}
		estimate := int64(1)
		if err := db.Create(&UsageRecord{ReplayID: id + "-usage", RequestID: id, EstimatedPublicCostMicrounits: &estimate, CreatedAt: accepted}).Error; err != nil {
			t.Fatal(err)
		}
	}
	filter := analyticsFilter{From: accepted, To: accepted.Add(24 * time.Hour), APIKeyID: "key-one", Limit: 50, Interval: "day"}
	filtered, err := analyticsBuckets(db, filter, true)
	if err != nil {
		t.Fatal(err)
	}
	filteredRows := filtered.Data.([]analyticsBucketRow)
	if len(filteredRows) != 1 || filteredRows[0].AllocatedCost == nil || *filteredRows[0].AllocatedCost != 50 {
		t.Fatalf("filtered allocation = %+v", filteredRows)
	}
	filter.APIKeyID = ""
	unfiltered, err := analyticsBuckets(db, filter, true)
	if err != nil {
		t.Fatal(err)
	}
	unfilteredRows := unfiltered.Data.([]analyticsBucketRow)
	if len(unfilteredRows) != 1 || unfilteredRows[0].AllocatedCost == nil || *unfilteredRows[0].AllocatedCost != 100 {
		t.Fatalf("unfiltered allocation = %+v", unfilteredRows)
	}
}
