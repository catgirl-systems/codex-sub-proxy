package server

import (
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/kataras/iris/v12"
	"gorm.io/gorm"
	"math"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	adminAnalyticsEndpoint = "/admin/v1/analytics"
	analyticsDefaultLimit  = 50
	analyticsMaxLimit      = 100
	analyticsMaxCursor     = 256
	analyticsMaxRange      = 366 * 24 * time.Hour
)

type analyticsFilter struct {
	From           time.Time
	To             time.Time
	Interval       string
	Limit          int
	Cursor         string
	RequestedModel string
	ResolvedModel  string
	Model          string
	APIKeyID       string
	Endpoint       string
	State          string
	ErrorClass     string
}

type analyticsRequestTotals struct {
	Count     int64 `json:"count"`
	Running   int64 `json:"running"`
	Succeeded int64 `json:"succeeded"`
	Failed    int64 `json:"failed"`
	Canceled  int64 `json:"canceled"`
	Other     int64 `json:"other"`
}

type analyticsUsageTotals struct {
	InputTokens       int64 `json:"input_tokens"`
	CachedInputTokens int64 `json:"cached_input_tokens"`
	OutputTokens      int64 `json:"output_tokens"`
	ReasoningTokens   int64 `json:"reasoning_tokens"`
	TotalTokens       int64 `json:"total_tokens"`
	ImageCount        int64 `json:"image_count"`
}

type analyticsCostTotals struct {
	EstimatedPublicCostMicrounits       *int64 `json:"estimated_public_cost_microunits"`
	AllocatedSubscriptionCostMicrounits *int64 `json:"allocated_subscription_cost_microunits"`
	QuotaAccountedCostMicrounits        *int64 `json:"quota_accounted_cost_microunits"`
	Currency                            string `json:"currency,omitempty"`
	RoundingBasis                       string `json:"rounding_basis,omitempty"`
	AllocationBasis                     string `json:"allocation_basis,omitempty"`
}

type analyticsLatencyStats struct {
	Count int64 `json:"count"`
	MinMS int64 `json:"min_ms"`
	P50MS int64 `json:"p50_ms"`
	P95MS int64 `json:"p95_ms"`
	P99MS int64 `json:"p99_ms"`
	MaxMS int64 `json:"max_ms"`
}

type analyticsStateTotal struct {
	State string `json:"state"`
	Count int64  `json:"count"`
}

type analyticsOverviewResponse struct {
	From       time.Time              `json:"from"`
	To         time.Time              `json:"to"`
	Requests   analyticsRequestTotals `json:"requests"`
	Usage      analyticsUsageTotals   `json:"usage"`
	Costs      analyticsCostTotals    `json:"costs"`
	Latency    analyticsLatencyStats  `json:"latency"`
	States     []analyticsStateTotal  `json:"states"`
	ActiveKeys int64                  `json:"active_keys"`
}

type analyticsModelRow struct {
	RequestedModel    string `json:"requested_model"`
	ResolvedModel     string `json:"resolved_model"`
	RequestCount      int64  `json:"request_count"`
	InputTokens       int64  `json:"input_tokens"`
	CachedInputTokens int64  `json:"cached_input_tokens"`
	OutputTokens      int64  `json:"output_tokens"`
	ReasoningTokens   int64  `json:"reasoning_tokens"`
	TotalTokens       int64  `json:"total_tokens"`
	ImageCount        int64  `json:"image_count"`
	EstimatedCost     *int64 `json:"estimated_public_cost_microunits"`
	NextCursor        string `json:"-"`
}

type analyticsKeyRow struct {
	APIKeyID          string `json:"api_key_id"`
	RequestCount      int64  `json:"request_count"`
	InputTokens       int64  `json:"input_tokens"`
	CachedInputTokens int64  `json:"cached_input_tokens"`
	OutputTokens      int64  `json:"output_tokens"`
	ReasoningTokens   int64  `json:"reasoning_tokens"`
	TotalTokens       int64  `json:"total_tokens"`
	ImageCount        int64  `json:"image_count"`
	EstimatedCost     *int64 `json:"estimated_public_cost_microunits"`
}

type analyticsErrorRow struct {
	ErrorCode    string `json:"error_code"`
	ErrorClass   string `json:"error_class"`
	RequestCount int64  `json:"request_count"`
}

type analyticsBucketRow struct {
	Bucket              string `json:"bucket"`
	RequestCount        int64  `json:"request_count"`
	InputTokens         int64  `json:"input_tokens"`
	CachedInputTokens   int64  `json:"cached_input_tokens"`
	OutputTokens        int64  `json:"output_tokens"`
	ReasoningTokens     int64  `json:"reasoning_tokens"`
	TotalTokens         int64  `json:"total_tokens"`
	ImageCount          int64  `json:"image_count"`
	EstimatedCost       *int64 `json:"estimated_public_cost_microunits"`
	AllocatedCost       *int64 `json:"allocated_subscription_cost_microunits"`
	QuotaAccountedCost  *int64 `json:"quota_accounted_cost_microunits"`
	Currency            string `json:"currency,omitempty"`
	AllocationVersionID string `json:"allocation_input_version,omitempty"`
	AllocationBasis     string `json:"allocation_basis,omitempty"`
	Provisional         bool   `json:"provisional"`
}

type analyticsQuotaResponse struct {
	From                         time.Time `json:"from"`
	To                           time.Time `json:"to"`
	ReservedRequests             int64     `json:"reserved_requests"`
	QuotaAccountedRequests       int64     `json:"quota_accounted_requests"`
	ReservedTokens               int64     `json:"reserved_tokens"`
	QuotaAccountedTokens         int64     `json:"quota_accounted_tokens"`
	ReservedImages               int64     `json:"reserved_images"`
	QuotaAccountedImages         int64     `json:"quota_accounted_images"`
	ReservedCostMicrounits       int64     `json:"reserved_cost_microunits"`
	QuotaAccountedCostMicrounits int64     `json:"quota_accounted_cost_microunits"`
	PendingRequests              int64     `json:"pending_requests"`
}

type analyticsResponse struct {
	Data       any    `json:"data"`
	NextCursor string `json:"next_cursor,omitempty"`
}

func registerAdminAnalyticsRoutes(app *iris.Application, store *AdminTokenStore, dependencies adminLifecycleDependencies) {
	endpoints := []string{"overview", "models", "keys", "errors", "quotas", "latency", "usage", "costs"}
	for _, endpoint := range endpoints {
		endpoint := endpoint
		app.Get(adminAnalyticsEndpoint+"/"+endpoint, func(ctx iris.Context) {
			ctx.Header("Cache-Control", "no-store")
			principal, ok := authenticateAdminRequest(ctx, store)
			if !ok {
				return
			}
			if err := authorizeAdminScope(ctx, store, principal, AdminScopeMetadata); err != nil {
				writeAdminAuthError(ctx, err)
				return
			}
			if dependencies.db == nil || (dependencies.pricing != nil && !dependencies.pricing.Available()) {
				writeAdminError(ctx, http.StatusServiceUnavailable, "Analytics is unavailable.")
				return
			}
			filter, err := parseAnalyticsFilter(ctx, endpoint)
			if err != nil {
				writeAdminError(ctx, http.StatusBadRequest, "Invalid analytics query.")
				return
			}
			var value any
			err = dependencies.db.WithContext(ctx.Request().Context()).Transaction(func(tx *gorm.DB) error {
				var queryErr error
				switch endpoint {
				case "overview":
					value, queryErr = analyticsOverview(tx, filter)
				case "models":
					value, queryErr = analyticsModels(tx, filter)
				case "keys":
					value, queryErr = analyticsKeys(tx, filter)
				case "errors":
					value, queryErr = analyticsErrors(tx, filter)
				case "quotas":
					value, queryErr = analyticsQuotas(tx, filter)
				case "latency":
					value, queryErr = analyticsLatency(tx, filter)
				case "usage":
					value, queryErr = analyticsBuckets(tx, filter, false)
				case "costs":
					value, queryErr = analyticsBuckets(tx, filter, true)
				}
				if queryErr != nil {
					return queryErr
				}
				filters := filterAuditNames(filter, endpoint)
				return writeAdminAudit(tx, principal, "analytics."+endpoint, "analytics", adminAuditMetadata{Fields: analyticsAuditFields(endpoint), Filters: filters}, time.Now().UTC())
			})
			if err != nil {
				writeAdminError(ctx, http.StatusInternalServerError, "Analytics query failed.")
				return
			}
			_ = writeJSON(ctx, http.StatusOK, value)
		})
	}
}

func analyticsAuditFields(endpoint string) []string {
	fields := []string{"requests", "usage", "estimated_public_cost_microunits"}
	switch endpoint {
	case "latency":
		return []string{"accepted_at", "terminal_at", "latency_ms"}
	case "quotas":
		return []string{"policy", "current_bucket", "rolling", "pending"}
	case "models", "keys", "usage":
		return fields
	case "costs":
		return []string{"estimated_public_cost_microunits", "allocated_subscription_cost_microunits", "quota_accounted_cost_microunits", "provisional"}
	case "errors":
		return []string{"error_code", "error_class", "requests"}
	default:
		return []string{"requests", "usage", "costs", "latency"}
	}
}

func parseAnalyticsFilter(ctx iris.Context, endpoint string) (analyticsFilter, error) {
	query := ctx.Request().URL.Query()
	allowed := map[string]struct{}{"from": {}, "to": {}, "limit": {}, "cursor": {}, "interval": {}, "requested_model": {}, "resolved_model": {}, "model": {}, "api_key_id": {}, "endpoint": {}, "state": {}, "error_class": {}}
	for key := range query {
		if _, ok := allowed[key]; !ok {
			return analyticsFilter{}, errors.New("unknown analytics query parameter")
		}
	}
	from, err := parseAnalyticsTime(query.Get("from"))
	if err != nil {
		return analyticsFilter{}, err
	}
	to, err := parseAnalyticsTime(query.Get("to"))
	if err != nil || !to.After(from) || to.Sub(from) > analyticsMaxRange {
		return analyticsFilter{}, errors.New("analytics range is invalid")
	}
	filter := analyticsFilter{From: from, To: to, Limit: analyticsDefaultLimit, Interval: query.Get("interval"), Cursor: query.Get("cursor"), RequestedModel: query.Get("requested_model"), ResolvedModel: query.Get("resolved_model"), Model: query.Get("model"), APIKeyID: query.Get("api_key_id"), Endpoint: query.Get("endpoint"), State: query.Get("state"), ErrorClass: query.Get("error_class")}
	if filter.Interval == "" {
		filter.Interval = "day"
	}
	if filter.Interval != "hour" && filter.Interval != "day" && filter.Interval != "month" {
		return analyticsFilter{}, errors.New("analytics interval is invalid")
	}
	if raw := query.Get("limit"); raw != "" {
		filter.Limit, err = strconv.Atoi(raw)
		if err != nil {
			return analyticsFilter{}, err
		}
	}
	if filter.Limit <= 0 || filter.Limit > analyticsMaxLimit {
		return analyticsFilter{}, errors.New("analytics limit is invalid")
	}
	if len(filter.Cursor) > analyticsMaxCursor {
		return analyticsFilter{}, errors.New("analytics cursor is too large")
	}
	if filter.Cursor != "" {
		if _, err := base64.RawURLEncoding.DecodeString(filter.Cursor); err != nil {
			return analyticsFilter{}, errors.New("analytics cursor is invalid")
		}
	}
	if endpoint == "latency" || endpoint == "quotas" || endpoint == "overview" {
		filter.Interval = ""
	}
	return filter, nil
}

func parseAnalyticsTime(value string) (time.Time, error) {
	if value == "" {
		return time.Time{}, errors.New("analytics time is required")
	}
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil || parsed.Location() != time.UTC {
		return time.Time{}, errors.New("analytics time must be UTC RFC3339")
	}
	return parsed, nil
}

func filterAuditNames(filter analyticsFilter, endpoint string) []string {
	result := []string{"from", "to"}
	if filter.Interval != "" {
		result = append(result, "interval")
	}
	if filter.Limit != analyticsDefaultLimit {
		result = append(result, "limit")
	}
	if filter.Cursor != "" {
		result = append(result, "cursor")
	}
	if filter.RequestedModel != "" {
		result = append(result, "requested_model")
	}
	if filter.ResolvedModel != "" {
		result = append(result, "resolved_model")
	}
	if filter.Model != "" {
		result = append(result, "model")
	}
	if filter.APIKeyID != "" {
		result = append(result, "api_key_id")
	}
	if filter.Endpoint != "" {
		result = append(result, "endpoint")
	}
	if filter.State != "" {
		result = append(result, "state")
	}
	if filter.ErrorClass != "" {
		result = append(result, "error_class")
	}
	sort.Strings(result)
	return result
}

func analyticsWhere(query *gorm.DB, filter analyticsFilter, alias string) *gorm.DB {
	query = query.Where(alias+".accepted_at >= ? AND "+alias+".accepted_at < ?", filter.From, filter.To)
	if filter.APIKeyID != "" {
		query = query.Where(alias+".api_key_id = ?", filter.APIKeyID)
	}
	if filter.Endpoint != "" {
		query = query.Where(alias+".endpoint = ?", filter.Endpoint)
	}
	if filter.State != "" {
		query = query.Where(alias+".status = ?", filter.State)
	}
	if filter.RequestedModel != "" {
		query = query.Where("COALESCE(NULLIF("+alias+".requested_model, ''), "+alias+".model) = ?", filter.RequestedModel)
	}
	if filter.ResolvedModel != "" {
		query = query.Where(alias+".resolved_model = ?", filter.ResolvedModel)
	}
	if filter.Model != "" {
		query = query.Where("(COALESCE(NULLIF("+alias+".resolved_model, ''), COALESCE(NULLIF("+alias+".requested_model, ''), "+alias+".model)) = ?)", filter.Model)
	}
	if filter.ErrorClass != "" {
		query = query.Where(alias+".error_class = ?", filter.ErrorClass)
	}
	return query
}

func analyticsUsageJoin(filter analyticsFilter) (string, []any) {
	return "LEFT JOIN (SELECT ux.request_id, SUM(ux.input_tokens) AS input_tokens, SUM(ux.cached_input_tokens) AS cached_input_tokens, SUM(ux.output_tokens) AS output_tokens, SUM(ux.reasoning_tokens) AS reasoning_tokens, SUM(ux.total_tokens) AS total_tokens, SUM(ux.image_count) AS image_count, SUM(ux.estimated_public_cost_microunits) AS estimated_cost, SUM(ux.allocated_subscription_cost_microunits) AS allocated_cost FROM usage AS ux JOIN requests AS ur ON ur.request_id = ux.request_id WHERE ur.accepted_at >= ? AND ur.accepted_at < ? GROUP BY ux.request_id) AS u ON u.request_id = r.request_id", []any{filter.From, filter.To}
}

func analyticsOverview(tx *gorm.DB, filter analyticsFilter) (analyticsOverviewResponse, error) {
	var aggregate struct {
		Count     int64         `gorm:"column:count"`
		Running   int64         `gorm:"column:running"`
		Succeeded int64         `gorm:"column:succeeded"`
		Failed    int64         `gorm:"column:failed"`
		Canceled  int64         `gorm:"column:canceled"`
		Other     int64         `gorm:"column:other"`
		Input     sql.NullInt64 `gorm:"column:input_tokens"`
		Cached    sql.NullInt64 `gorm:"column:cached_input_tokens"`
		Output    sql.NullInt64 `gorm:"column:output_tokens"`
		Reasoning sql.NullInt64 `gorm:"column:reasoning_tokens"`
		Total     sql.NullInt64 `gorm:"column:total_tokens"`
		Images    sql.NullInt64 `gorm:"column:image_count"`
		Estimated sql.NullInt64 `gorm:"column:estimated_cost"`
		Allocated sql.NullInt64 `gorm:"column:allocated_cost"`
	}
	join, args := analyticsUsageJoin(filter)
	query := tx.Table("requests AS r").Joins(join, args...)
	query = analyticsWhere(query, filter, "r")
	if err := query.Select("COUNT(*) AS count, SUM(CASE WHEN r.status = 'running' THEN 1 ELSE 0 END) AS running, SUM(CASE WHEN r.status = 'succeeded' THEN 1 ELSE 0 END) AS succeeded, SUM(CASE WHEN r.status = 'failed' THEN 1 ELSE 0 END) AS failed, SUM(CASE WHEN r.status = 'canceled' THEN 1 ELSE 0 END) AS canceled, SUM(CASE WHEN r.status NOT IN ('running','succeeded','failed','canceled') THEN 1 ELSE 0 END) AS other, SUM(COALESCE(u.input_tokens,0)) AS input_tokens, SUM(COALESCE(u.cached_input_tokens,0)) AS cached_input_tokens, SUM(COALESCE(u.output_tokens,0)) AS output_tokens, SUM(COALESCE(u.reasoning_tokens,0)) AS reasoning_tokens, SUM(COALESCE(u.total_tokens,0)) AS total_tokens, SUM(COALESCE(u.image_count,0)) AS image_count, SUM(u.estimated_cost) AS estimated_cost, SUM(u.allocated_cost) AS allocated_cost").Scan(&aggregate).Error; err != nil {
		return analyticsOverviewResponse{}, fmt.Errorf("load analytics overview: %w", err)
	}
	states, err := analyticsStates(tx, filter)
	if err != nil {
		return analyticsOverviewResponse{}, err
	}
	latency, err := analyticsLatency(tx, filter)
	if err != nil {
		return analyticsOverviewResponse{}, err
	}
	var activeKeys int64
	keyQuery := tx.Model(&RequestRecord{}).Where("accepted_at >= ? AND accepted_at < ? AND api_key_id <> ''", filter.From, filter.To)
	if err := keyQuery.Distinct("api_key_id").Count(&activeKeys).Error; err != nil {
		return analyticsOverviewResponse{}, fmt.Errorf("count analytics keys: %w", err)
	}
	allocated := nullIntPtr(aggregate.Allocated)
	if filter.From.Day() == 1 && filter.From.Hour() == 0 && filter.From.Minute() == 0 && filter.From.Second() == 0 && filter.From.Nanosecond() == 0 && filter.To.Day() == 1 && filter.To.Hour() == 0 && filter.To.Minute() == 0 && filter.To.Second() == 0 && filter.To.Nanosecond() == 0 {
		buckets, allocationErr := analyticsAllocationBuckets(tx, filter)
		if allocationErr != nil {
			return analyticsOverviewResponse{}, allocationErr
		}
		var allocatedTotal int64
		var hasAllocation bool
		for _, bucket := range buckets {
			if !hasAllocation {
				hasAllocation = true
			}
			if allocatedTotal > math.MaxInt64-bucket.amount {
				return analyticsOverviewResponse{}, errors.New("analytics allocation total overflows int64")
			}
			allocatedTotal += bucket.amount
		}
		if hasAllocation {
			allocated = &allocatedTotal
		}
	}
	var quotaCost sql.NullInt64
	if err := tx.Table("quota_buckets").Where("period_start >= ? AND period_start < ?", filter.From, filter.To).Select("SUM(accounted_cost_microunits) AS quota_cost").Scan(&quotaCost).Error; err != nil {
		return analyticsOverviewResponse{}, fmt.Errorf("load quota accounted cost: %w", err)
	}
	return analyticsOverviewResponse{
		From: filter.From,
		To:   filter.To,
		Requests: analyticsRequestTotals{
			Count: aggregate.Count, Running: aggregate.Running, Succeeded: aggregate.Succeeded,
			Failed: aggregate.Failed, Canceled: aggregate.Canceled, Other: aggregate.Other,
		},
		Usage: analyticsUsageTotals{
			InputTokens: nullInt(aggregate.Input), CachedInputTokens: nullInt(aggregate.Cached),
			OutputTokens: nullInt(aggregate.Output), ReasoningTokens: nullInt(aggregate.Reasoning),
			TotalTokens: nullInt(aggregate.Total), ImageCount: nullInt(aggregate.Images),
		},
		Costs: analyticsCostTotals{
			EstimatedPublicCostMicrounits:       nullIntPtr(aggregate.Estimated),
			AllocatedSubscriptionCostMicrounits: allocated,
			QuotaAccountedCostMicrounits:        nullIntPtr(quotaCost),
			RoundingBasis:                       pricingRoundingBasis,
			AllocationBasis:                     pricingAllocationBasis,
		},
		Latency: latency, States: states, ActiveKeys: activeKeys,
	}, nil
}

func analyticsStates(tx *gorm.DB, filter analyticsFilter) ([]analyticsStateTotal, error) {
	var states []analyticsStateTotal
	query := analyticsWhere(tx.Table("requests AS requests"), filter, "requests")
	if err := query.Select("status AS state, COUNT(*) AS count").Group("status").Order("status ASC").Find(&states).Error; err != nil {
		return nil, fmt.Errorf("load analytics states: %w", err)
	}
	return states, nil
}

func analyticsModels(tx *gorm.DB, filter analyticsFilter) (analyticsResponse, error) {
	var rows []analyticsModelRow
	join, args := analyticsUsageJoin(filter)
	query := tx.Table("requests AS r").Joins(join, args...)
	if filter.Cursor != "" {
		if cursor, ok := decodeAnalyticsCursor(filter.Cursor); ok {
			parts := strings.SplitN(cursor, "\x00", 2)
			if len(parts) == 2 {
				requestedExpression := "COALESCE(NULLIF(r.requested_model, ''), r.model)"
				query = query.Where("("+requestedExpression+" > ? OR ("+requestedExpression+" = ? AND r.resolved_model > ?))", parts[0], parts[0], parts[1])
			}
		}
	}
	query = analyticsWhere(query, filter, "r")
	query = query.Select("COALESCE(NULLIF(r.requested_model, ''), r.model) AS requested_model, r.resolved_model AS resolved_model, COUNT(*) AS request_count, SUM(COALESCE(u.input_tokens,0)) AS input_tokens, SUM(COALESCE(u.cached_input_tokens,0)) AS cached_input_tokens, SUM(COALESCE(u.output_tokens,0)) AS output_tokens, SUM(COALESCE(u.reasoning_tokens,0)) AS reasoning_tokens, SUM(COALESCE(u.total_tokens,0)) AS total_tokens, SUM(COALESCE(u.image_count,0)) AS image_count, SUM(u.estimated_cost) AS estimated_cost").Group("requested_model, resolved_model").Order("requested_model ASC, resolved_model ASC").Limit(filter.Limit + 1)
	if err := query.Find(&rows).Error; err != nil {
		return analyticsResponse{}, fmt.Errorf("load analytics models: %w", err)
	}
	next := trimAnalyticsModelRows(&rows, filter.Limit)
	return analyticsResponse{Data: rows, NextCursor: next}, nil
}

func trimAnalyticsModelRows(rows *[]analyticsModelRow, limit int) string {
	if rows == nil || len(*rows) <= limit {
		return ""
	}
	page := (*rows)[:limit]
	last := page[len(page)-1]
	*rows = page
	return encodeAnalyticsCursor(last.RequestedModel + "\x00" + last.ResolvedModel)
}

func analyticsKeys(tx *gorm.DB, filter analyticsFilter) (analyticsResponse, error) {
	var rows []analyticsKeyRow
	join, args := analyticsUsageJoin(filter)
	query := tx.Table("requests AS r").Joins(join, args...)
	query = analyticsWhere(query, filter, "r")
	if filter.Cursor != "" {
		if cursor, ok := decodeAnalyticsCursor(filter.Cursor); ok {
			query = query.Where("r.api_key_id > ?", cursor)
		}
	}
	query = query.Select("r.api_key_id AS api_key_id, COUNT(*) AS request_count, SUM(COALESCE(u.input_tokens,0)) AS input_tokens, SUM(COALESCE(u.cached_input_tokens,0)) AS cached_input_tokens, SUM(COALESCE(u.output_tokens,0)) AS output_tokens, SUM(COALESCE(u.reasoning_tokens,0)) AS reasoning_tokens, SUM(COALESCE(u.total_tokens,0)) AS total_tokens, SUM(COALESCE(u.image_count,0)) AS image_count, SUM(u.estimated_cost) AS estimated_cost").Group("r.api_key_id").Order("r.api_key_id ASC").Limit(filter.Limit + 1)
	if err := query.Find(&rows).Error; err != nil {
		return analyticsResponse{}, fmt.Errorf("load analytics keys: %w", err)
	}
	next := ""
	if len(rows) > filter.Limit {
		next = encodeAnalyticsCursor(rows[filter.Limit-1].APIKeyID)
		rows = rows[:filter.Limit]
	}
	return analyticsResponse{Data: rows, NextCursor: next}, nil
}

func analyticsErrors(tx *gorm.DB, filter analyticsFilter) (analyticsResponse, error) {
	var rows []analyticsErrorRow
	query := analyticsWhere(tx.Model(&RequestRecord{}), filter, "requests")
	if filter.Cursor != "" {
		if cursor, ok := decodeAnalyticsCursor(filter.Cursor); ok {
			parts := strings.SplitN(cursor, "\x00", 2)
			if len(parts) == 2 {
				query = query.Where("(error_class > ? OR (error_class = ? AND error_code > ?))", parts[0], parts[0], parts[1])
			}
		}
	}
	query = query.Where("(error_code <> '' OR error_class <> '')").Select("error_code, error_class, COUNT(*) AS request_count").Group("error_code, error_class").Order("error_class ASC, error_code ASC").Limit(filter.Limit + 1)
	if err := query.Find(&rows).Error; err != nil {
		return analyticsResponse{}, fmt.Errorf("load analytics errors: %w", err)
	}
	next := ""
	if len(rows) > filter.Limit {
		next = encodeAnalyticsCursor(rows[filter.Limit-1].ErrorClass + "\x00" + rows[filter.Limit-1].ErrorCode)
		rows = rows[:filter.Limit]
	}
	return analyticsResponse{Data: rows, NextCursor: next}, nil
}

func analyticsLatency(tx *gorm.DB, filter analyticsFilter) (analyticsLatencyStats, error) {
	var result analyticsLatencyStats
	where := "accepted_at >= ? AND accepted_at < ? AND terminal_at IS NOT NULL"
	args := []any{filter.From, filter.To}
	if filter.APIKeyID != "" {
		where += " AND api_key_id = ?"
		args = append(args, filter.APIKeyID)
	}
	if filter.Endpoint != "" {
		where += " AND endpoint = ?"
		args = append(args, filter.Endpoint)
	}
	if filter.State != "" {
		where += " AND status = ?"
		args = append(args, filter.State)
	}
	query := `WITH durations AS (SELECT CAST((julianday(terminal_at) - julianday(accepted_at)) * 86400000 AS INTEGER) AS duration_ms FROM requests WHERE ` + where + `), ranked AS (SELECT duration_ms, ROW_NUMBER() OVER (ORDER BY duration_ms ASC) AS row_number, COUNT(*) OVER () AS total FROM durations) SELECT COALESCE(MAX(total),0) AS count, COALESCE(MIN(duration_ms),0) AS min_ms, COALESCE(MAX(duration_ms),0) AS max_ms, COALESCE(MAX(CASE WHEN row_number = (total + 1) / 2 THEN duration_ms END),0) AS p50_ms, COALESCE(MAX(CASE WHEN row_number = (total * 95 + 99) / 100 THEN duration_ms END),0) AS p95_ms, COALESCE(MAX(CASE WHEN row_number = (total * 99 + 99) / 100 THEN duration_ms END),0) AS p99_ms FROM ranked`
	if err := tx.Raw(query, args...).Scan(&result).Error; err != nil {
		return analyticsLatencyStats{}, fmt.Errorf("load analytics latency: %w", err)
	}
	return result, nil
}

func analyticsQuotas(tx *gorm.DB, filter analyticsFilter) (analyticsQuotaResponse, error) {
	var result analyticsQuotaResponse
	result.From, result.To = filter.From, filter.To
	var bucket struct{ ReservedRequests, AccountedRequests, ReservedTokens, AccountedTokens, ReservedImages, AccountedImages, ReservedCost, AccountedCost int64 }
	if err := tx.Table("quota_buckets").Where("period_start >= ? AND period_start < ?", filter.From, filter.To).Select("COALESCE(SUM(reserved_requests),0) AS reserved_requests, COALESCE(SUM(actual_requests),0) AS accounted_requests, COALESCE(SUM(reserved_tokens),0) AS reserved_tokens, COALESCE(SUM(actual_tokens),0) AS accounted_tokens, COALESCE(SUM(reserved_images),0) AS reserved_images, COALESCE(SUM(actual_images),0) AS accounted_images, COALESCE(SUM(reserved_cost_microunits),0) AS reserved_cost, COALESCE(SUM(actual_cost_microunits),0) AS accounted_cost").Scan(&bucket).Error; err != nil {
		return analyticsQuotaResponse{}, fmt.Errorf("load quota aggregates: %w", err)
	}
	if err := tx.Table("quota_reservations").Where("created_at >= ? AND created_at < ? AND status = ?", filter.From, filter.To, "pending").Count(&result.PendingRequests).Error; err != nil {
		return analyticsQuotaResponse{}, fmt.Errorf("load pending quota aggregates: %w", err)
	}
	result.ReservedRequests, result.QuotaAccountedRequests, result.ReservedTokens, result.QuotaAccountedTokens, result.ReservedImages, result.QuotaAccountedImages, result.ReservedCostMicrounits, result.QuotaAccountedCostMicrounits = bucket.ReservedRequests, bucket.AccountedRequests, bucket.ReservedTokens, bucket.AccountedTokens, bucket.ReservedImages, bucket.AccountedImages, bucket.ReservedCost, bucket.AccountedCost
	return result, nil
}

func analyticsBuckets(tx *gorm.DB, filter analyticsFilter, costs bool) (analyticsResponse, error) {
	bucketExpression := "strftime('%Y-%m-%dT00:00:00Z', r.accepted_at)"
	if filter.Interval == "hour" {
		bucketExpression = "strftime('%Y-%m-%dT%H:00:00Z', r.accepted_at)"
	}
	if filter.Interval == "month" {
		bucketExpression = "strftime('%Y-%m-01T00:00:00Z', r.accepted_at)"
	}
	var rows []analyticsBucketRow
	join, args := analyticsUsageJoin(filter)
	query := tx.Table("requests AS r").Joins(join, args...)
	query = analyticsWhere(query, filter, "r")
	if filter.Cursor != "" {
		if cursor, ok := decodeAnalyticsCursor(filter.Cursor); ok {
			query = query.Where(bucketExpression+" > ?", cursor)
		}
	}
	query = query.Select(bucketExpression + " AS bucket, COUNT(*) AS request_count, SUM(COALESCE(u.input_tokens,0)) AS input_tokens, SUM(COALESCE(u.cached_input_tokens,0)) AS cached_input_tokens, SUM(COALESCE(u.output_tokens,0)) AS output_tokens, SUM(COALESCE(u.reasoning_tokens,0)) AS reasoning_tokens, SUM(COALESCE(u.total_tokens,0)) AS total_tokens, SUM(COALESCE(u.image_count,0)) AS image_count, SUM(u.estimated_cost) AS estimated_cost, SUM(u.allocated_cost) AS allocated_cost").Group("bucket").Order("bucket ASC").Limit(filter.Limit + 1)
	if err := query.Find(&rows).Error; err != nil {
		return analyticsResponse{}, fmt.Errorf("load analytics buckets: %w", err)
	}
	if costs {
		allocationByBucket, err := analyticsAllocationBuckets(tx, filter)
		if err != nil {
			return analyticsResponse{}, err
		}
		for index := range rows {
			value, ok := allocationByBucket[rows[index].Bucket]
			if !ok {
				continue
			}
			allocated := value.amount
			rows[index].AllocatedCost = &allocated
			rows[index].Currency = value.currency
			rows[index].AllocationVersionID = value.versionID
			rows[index].AllocationBasis = value.basis
			rows[index].Provisional = value.provisional
		}
	}
	next := ""
	if len(rows) > filter.Limit {
		next = encodeAnalyticsCursor(rows[filter.Limit-1].Bucket)
		rows = rows[:filter.Limit]
	}
	if !costs {
		for index := range rows {
			rows[index].AllocatedCost = nil
			rows[index].Currency = ""
			rows[index].AllocationVersionID = ""
			rows[index].AllocationBasis = ""
			rows[index].Provisional = false
		}
	}
	return analyticsResponse{Data: rows, NextCursor: next}, nil
}

type analyticsAllocationBucket struct {
	amount      int64
	currency    string
	versionID   string
	basis       string
	provisional bool
}

func analyticsAllocationBuckets(tx *gorm.DB, filter analyticsFilter) (map[string]analyticsAllocationBucket, error) {
	// A partial calendar range cannot expose a complete monthly allocation.
	if filter.From.Day() != 1 || filter.From.Hour() != 0 || filter.From.Minute() != 0 || filter.From.Second() != 0 || filter.From.Nanosecond() != 0 {
		return map[string]analyticsAllocationBucket{}, nil
	}
	if filter.To.Day() != 1 || filter.To.Hour() != 0 || filter.To.Minute() != 0 || filter.To.Second() != 0 || filter.To.Nanosecond() != 0 {
		return map[string]analyticsAllocationBucket{}, nil
	}
	totals := make(map[string]analyticsAllocationBucket)
	for month := time.Date(filter.From.Year(), filter.From.Month(), 1, 0, 0, 0, 0, time.UTC); month.Before(filter.To); month = month.AddDate(0, 1, 0) {
		allocation, inputs, available, err := queryMonthlyAllocation(tx, month, time.Now().UTC())
		if err != nil {
			return nil, err
		}
		if !available {
			continue
		}
		amountByRequest := make(map[string]int64, len(allocation.Rows))
		for _, row := range allocation.Rows {
			amountByRequest[row.RequestID] = row.Microunits
		}
		for _, input := range inputs {
			amount, ok := amountByRequest[input.RequestID]
			if !ok {
				continue
			}
			bucket := analyticsBucketStart(input.CreatedAt, filter.Interval).Format(time.RFC3339Nano)
			value := totals[bucket]
			if value.amount > math.MaxInt64-amount {
				return nil, errors.New("analytics allocation total overflows int64")
			}
			value.amount += amount
			value.currency = allocation.Currency
			value.versionID = allocation.VersionID
			value.basis = allocation.Basis
			value.provisional = allocation.Provisional
			totals[bucket] = value
		}
	}
	return totals, nil
}

func analyticsBucketStart(value time.Time, interval string) time.Time {
	value = value.UTC()
	switch interval {
	case "hour":
		return time.Date(value.Year(), value.Month(), value.Day(), value.Hour(), 0, 0, 0, time.UTC)
	case "month":
		return time.Date(value.Year(), value.Month(), 1, 0, 0, 0, 0, time.UTC)
	default:
		return time.Date(value.Year(), value.Month(), value.Day(), 0, 0, 0, 0, time.UTC)
	}
}

func nullInt(value sql.NullInt64) int64 {
	if value.Valid {
		return value.Int64
	}
	return 0
}
func nullIntPtr(value sql.NullInt64) *int64 {
	if !value.Valid {
		return nil
	}
	result := value.Int64
	return &result
}
func encodeAnalyticsCursor(value string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(value))
}
func decodeAnalyticsCursor(value string) (string, bool) {
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	return string(decoded), err == nil
}

var _ = analyticsResponse{}
