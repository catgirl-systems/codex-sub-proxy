package server

import (
	"context"
	"strings"
	"testing"
	"time"

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
