package server

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/catgirl-systems/codex-sub-proxy/internal/envelope"
	"github.com/kataras/iris/v12"
	"gorm.io/gorm"
)

const (
	adminRequestsEndpoint        = "/admin/v1/requests"
	adminConversationsEndpoint   = "/admin/v1/conversations"
	adminLifecycleListLimit      = 50
	adminLifecycleMaxLimit       = 100
	adminLifecycleMaxCursor      = 256
	adminLifecycleMaxEvents      = 256
	adminLifecycleMaxArtifacts   = 64
	adminLifecycleMaxRequests    = 100
	adminLifecycleExportCap      = int64(4 << 20)
	adminLifecycleMaxTimeRange   = 366 * 24 * time.Hour
	adminPayloadEnvelopeOverhead = 4 + 1 + 4 + envelope.NonceSize + envelope.TagSize
)

var (
	errAdminLifecycleNotFound    = errors.New("lifecycle record not found")
	errAdminLifecycleConflict    = errors.New("lifecycle record is changing")
	errAdminLifecycleTooLarge    = errors.New("lifecycle export is too large")
	errAdminLifecycleUnavailable = errors.New("lifecycle storage is unavailable")
	errAdminLifecycleRequest     = errors.New("invalid lifecycle request")
)

type adminLifecycleDependencies struct {
	db        *gorm.DB
	keys      envelope.KeySet
	artifacts *ArtifactStore
	retention *RetentionRunner
}

type adminLifecycleCursor struct {
	CreatedAt time.Time
	ID        string
}

type adminLifecycleListFilter struct {
	Limit     int
	Cursor    adminLifecycleCursor
	HasCursor bool
	KeyID     string
	Endpoint  string
	State     string
	From      *time.Time
	To        *time.Time
}

type adminUsageMetadata struct {
	InputTokens  int64 `json:"input_tokens"`
	OutputTokens int64 `json:"output_tokens"`
	TotalTokens  int64 `json:"total_tokens"`
	ImageCount   int64 `json:"image_count"`
}

type adminEventMetadata struct {
	Type      string    `json:"type"`
	CreatedAt time.Time `json:"created_at"`
	Size      int64     `json:"size"`
}

type adminArtifactMetadata struct {
	ID            string    `json:"id"`
	MIME          string    `json:"mime"`
	PlaintextSize int64     `json:"plaintext_size"`
	ExpiresAt     time.Time `json:"expires_at"`
}

type adminRequestMetadata struct {
	ID               string                  `json:"id"`
	ConversationID   string                  `json:"conversation_id"`
	APIKeyID         string                  `json:"api_key_id,omitempty"`
	Endpoint         string                  `json:"endpoint"`
	Model            string                  `json:"model"`
	Mode             string                  `json:"mode"`
	State            string                  `json:"state"`
	AcceptedAt       time.Time               `json:"accepted_at"`
	StartedAt        time.Time               `json:"started_at"`
	UpdatedAt        time.Time               `json:"updated_at"`
	TerminalAt       *time.Time              `json:"terminal_at,omitempty"`
	ExpiresAt        time.Time               `json:"expires_at"`
	TerminalConflict bool                    `json:"terminal_conflict,omitempty"`
	Usage            adminUsageMetadata      `json:"usage"`
	EventCount       int64                   `json:"event_count,omitempty"`
	EventsTruncated  bool                    `json:"events_truncated,omitempty"`
	Events           []adminEventMetadata    `json:"events,omitempty"`
	ArtifactCount    int64                   `json:"artifact_count,omitempty"`
	ArtifactsTrunc   bool                    `json:"artifacts_truncated,omitempty"`
	Artifacts        []adminArtifactMetadata `json:"artifacts,omitempty"`
}

type adminConversationMetadata struct {
	ID                    string                 `json:"id"`
	CreatedAt             time.Time              `json:"created_at"`
	UpdatedAt             time.Time              `json:"updated_at"`
	ExpiresAt             time.Time              `json:"expires_at"`
	State                 string                 `json:"state"`
	RequestCount          int64                  `json:"request_count"`
	RunningRequestCount   int64                  `json:"running_request_count"`
	SucceededRequestCount int64                  `json:"succeeded_request_count"`
	FailedRequestCount    int64                  `json:"failed_request_count"`
	CanceledRequestCount  int64                  `json:"canceled_request_count"`
	FirstRequestAt        *time.Time             `json:"first_request_at,omitempty"`
	LastRequestAt         *time.Time             `json:"last_request_at,omitempty"`
	Usage                 adminUsageMetadata     `json:"usage"`
	Requests              []adminRequestMetadata `json:"requests,omitempty"`
	RequestsTruncated     bool                   `json:"requests_truncated,omitempty"`
}

type adminLifecycleListResponse[T any] struct {
	Data       []T    `json:"data"`
	NextCursor string `json:"next_cursor,omitempty"`
}

type adminLifecycleEventRow struct {
	EventType string    `gorm:"column:event_type"`
	CreatedAt time.Time `gorm:"column:created_at"`
	Size      int64     `gorm:"column:size"`
}

type adminConversationAggregate struct {
	RequestCount          int64 `gorm:"column:request_count"`
	RunningRequestCount   int64 `gorm:"column:running_request_count"`
	SucceededRequestCount int64 `gorm:"column:succeeded_request_count"`
	FailedRequestCount    int64 `gorm:"column:failed_request_count"`
	CanceledRequestCount  int64 `gorm:"column:canceled_request_count"`
	InputTokens           int64 `gorm:"column:input_tokens"`
	OutputTokens          int64 `gorm:"column:output_tokens"`
	TotalTokens           int64 `gorm:"column:total_tokens"`
	ImageCount            int64 `gorm:"column:image_count"`
}

type adminConversationListRow struct {
	ID                    string     `gorm:"column:id"`
	CreatedAt             time.Time  `gorm:"column:created_at"`
	UpdatedAt             time.Time  `gorm:"column:updated_at"`
	ExpiresAt             time.Time  `gorm:"column:expires_at"`
	DeletingAt            *time.Time `gorm:"column:deleting_at"`
	RequestCount          int64      `gorm:"column:request_count"`
	RunningRequestCount   int64      `gorm:"column:running_request_count"`
	SucceededRequestCount int64      `gorm:"column:succeeded_request_count"`
	FailedRequestCount    int64      `gorm:"column:failed_request_count"`
	CanceledRequestCount  int64      `gorm:"column:canceled_request_count"`
	InputTokens           int64      `gorm:"column:input_tokens"`
	OutputTokens          int64      `gorm:"column:output_tokens"`
	TotalTokens           int64      `gorm:"column:total_tokens"`
	ImageCount            int64      `gorm:"column:image_count"`
}

type adminExportValue struct {
	jsonValue json.RawMessage
	base64    string
}

func (value adminExportValue) MarshalJSON() ([]byte, error) {
	if len(value.jsonValue) != 0 {
		return value.jsonValue, nil
	}
	if value.base64 == "" {
		return []byte("null"), nil
	}
	return json.Marshal(struct {
		Encoding string `json:"encoding"`
		Data     string `json:"data"`
	}{Encoding: "base64", Data: value.base64})
}

type adminExportEvent struct {
	Type      string           `json:"type"`
	Sequence  uint64           `json:"sequence"`
	CreatedAt time.Time        `json:"created_at"`
	Payload   adminExportValue `json:"payload"`
}

type adminExportArtifact struct {
	ID            string    `json:"id"`
	MIME          string    `json:"mime"`
	PlaintextSize int64     `json:"plaintext_size"`
	ExpiresAt     time.Time `json:"expires_at"`
	Data          string    `json:"data"`
}

type adminRequestExport struct {
	Metadata  adminRequestMetadata  `json:"metadata"`
	Input     *adminExportValue     `json:"input,omitempty"`
	Events    []adminExportEvent    `json:"events"`
	Artifacts []adminExportArtifact `json:"artifacts"`
}

type adminExportMetadata struct {
	ID             string             `json:"id"`
	ConversationID string             `json:"conversation_id,omitempty"`
	APIKeyID       string             `json:"api_key_id,omitempty"`
	Endpoint       string             `json:"endpoint,omitempty"`
	Model          string             `json:"model,omitempty"`
	State          string             `json:"state"`
	CreatedAt      time.Time          `json:"created_at"`
	UpdatedAt      time.Time          `json:"updated_at"`
	ExpiresAt      time.Time          `json:"expires_at"`
	RequestCount   int64              `json:"request_count,omitempty"`
	Usage          adminUsageMetadata `json:"usage"`
}

type adminContentExport struct {
	Type     string               `json:"type"`
	Metadata adminExportMetadata  `json:"metadata"`
	Requests []adminRequestExport `json:"requests"`
}

type adminExportPayloadPlan struct {
	Type          string
	Sequence      uint64
	CreatedAt     time.Time
	Envelope      []byte
	Input         bool
	PlaintextSize int64
}

type adminRequestExportPlan struct {
	Metadata  adminRequestMetadata
	Payloads  []adminExportPayloadPlan
	Artifacts []ArtifactRecord
}

func registerAdminLifecycleRoutes(app *iris.Application, store *AdminTokenStore, lifecycle adminLifecycleDependencies) {
	app.Get(adminRequestsEndpoint, func(ctx iris.Context) {
		principal, ok := authenticateAdminRequest(ctx, store)
		if !ok {
			return
		}
		if err := authorizeAdminScope(ctx, store, principal, AdminScopeMetadata); err != nil {
			writeAdminAuthError(ctx, err)
			return
		}
		if lifecycle.db == nil {
			writeAdminLifecycleError(ctx, errAdminLifecycleUnavailable)
			return
		}
		filter, err := parseAdminLifecycleListFilter(ctx)
		if err != nil {
			writeAdminLifecycleError(ctx, err)
			return
		}
		rows, next, err := listAdminRequests(ctx, lifecycle.db, filter)
		if err != nil {
			writeAdminLifecycleError(ctx, err)
			return
		}
		if err := recordLifecycleAudit(ctx, lifecycle.db, principal, "request.list", "requests", filter.auditFilters()); err != nil {
			writeAdminLifecycleError(ctx, err)
			return
		}
		data := make([]adminRequestMetadata, 0, len(rows))
		for _, row := range rows {
			data = append(data, requestMetadataFromRecord(row))
		}
		_ = writeJSON(ctx, http.StatusOK, adminLifecycleListResponse[adminRequestMetadata]{Data: data, NextCursor: next})
	})
	app.Get(adminRequestsEndpoint+"/{id:string}/export", func(ctx iris.Context) {
		exportRequestAdmin(ctx, store, lifecycle)
	})
	app.Get(adminRequestsEndpoint+"/{id:string}", func(ctx iris.Context) {
		getRequestAdmin(ctx, store, lifecycle)
	})
	app.Delete(adminRequestsEndpoint+"/{id:string}", func(ctx iris.Context) {
		deleteRequestAdmin(ctx, store, lifecycle)
	})

	app.Get(adminConversationsEndpoint, func(ctx iris.Context) {
		principal, ok := authenticateAdminRequest(ctx, store)
		if !ok {
			return
		}
		if err := authorizeAdminScope(ctx, store, principal, AdminScopeMetadata); err != nil {
			writeAdminAuthError(ctx, err)
			return
		}
		if lifecycle.db == nil {
			writeAdminLifecycleError(ctx, errAdminLifecycleUnavailable)
			return
		}
		filter, err := parseAdminLifecycleListFilter(ctx)
		if err != nil {
			writeAdminLifecycleError(ctx, err)
			return
		}
		rows, next, err := listAdminConversations(ctx, lifecycle.db, filter)
		if err != nil {
			writeAdminLifecycleError(ctx, err)
			return
		}
		if err := recordLifecycleAudit(ctx, lifecycle.db, principal, "conversation.list", "conversations", filter.auditFilters()); err != nil {
			writeAdminLifecycleError(ctx, err)
			return
		}
		data := make([]adminConversationMetadata, 0, len(rows))
		for _, row := range rows {
			data = append(data, conversationMetadataFromListRow(row))
		}
		_ = writeJSON(ctx, http.StatusOK, adminLifecycleListResponse[adminConversationMetadata]{Data: data, NextCursor: next})
	})
	app.Get(adminConversationsEndpoint+"/{id:string}/export", func(ctx iris.Context) {
		exportConversationAdmin(ctx, store, lifecycle)
	})
	app.Get(adminConversationsEndpoint+"/{id:string}", func(ctx iris.Context) {
		getConversationAdmin(ctx, store, lifecycle)
	})
	app.Delete(adminConversationsEndpoint+"/{id:string}", func(ctx iris.Context) {
		deleteConversationAdmin(ctx, store, lifecycle)
	})
}

func getRequestAdmin(ctx iris.Context, store *AdminTokenStore, lifecycle adminLifecycleDependencies) {
	principal, ok := authenticateAdminRequest(ctx, store)
	if !ok {
		return
	}
	if err := authorizeAdminScope(ctx, store, principal, AdminScopeMetadata); err != nil {
		writeAdminAuthError(ctx, err)
		return
	}
	id := ctx.Params().Get("id")
	if !validJournalUUID(id) {
		writeAdminLifecycleError(ctx, errAdminLifecycleNotFound)
		return
	}
	if lifecycle.db == nil {
		writeAdminLifecycleError(ctx, errAdminLifecycleUnavailable)
		return
	}
	metadata, err := loadRequestMetadata(ctx, lifecycle.db, id)
	if err != nil {
		writeAdminLifecycleError(ctx, err)
		return
	}
	if err := recordLifecycleAudit(ctx, lifecycle.db, principal, "request.get", id, []string{"metadata"}); err != nil {
		writeAdminLifecycleError(ctx, err)
		return
	}
	_ = writeJSON(ctx, http.StatusOK, metadata)
}

func getConversationAdmin(ctx iris.Context, store *AdminTokenStore, lifecycle adminLifecycleDependencies) {
	principal, ok := authenticateAdminRequest(ctx, store)
	if !ok {
		return
	}
	if err := authorizeAdminScope(ctx, store, principal, AdminScopeMetadata); err != nil {
		writeAdminAuthError(ctx, err)
		return
	}
	id := ctx.Params().Get("id")
	if !validJournalUUID(id) {
		writeAdminLifecycleError(ctx, errAdminLifecycleNotFound)
		return
	}
	if lifecycle.db == nil {
		writeAdminLifecycleError(ctx, errAdminLifecycleUnavailable)
		return
	}
	metadata, err := loadConversationMetadata(ctx, lifecycle.db, id, true)
	if err != nil {
		writeAdminLifecycleError(ctx, err)
		return
	}
	if err := recordLifecycleAudit(ctx, lifecycle.db, principal, "conversation.get", id, []string{"metadata"}); err != nil {
		writeAdminLifecycleError(ctx, err)
		return
	}
	_ = writeJSON(ctx, http.StatusOK, metadata)
}

func deleteRequestAdmin(ctx iris.Context, store *AdminTokenStore, lifecycle adminLifecycleDependencies) {
	principal, ok := authenticateAdminRequest(ctx, store)
	if !ok {
		return
	}
	if err := authorizeAdminScope(ctx, store, principal, AdminScopeMetadata); err != nil {
		writeAdminAuthError(ctx, err)
		return
	}
	id := ctx.Params().Get("id")
	if !validJournalUUID(id) {
		writeAdminLifecycleError(ctx, errAdminLifecycleNotFound)
		return
	}
	if lifecycle.retention == nil {
		writeAdminLifecycleError(ctx, errAdminLifecycleUnavailable)
		return
	}
	if err := lifecycle.retention.DeleteRequestAsAdmin(ctx.Request().Context(), id, principal); err != nil {
		writeAdminLifecycleError(ctx, err)
		return
	}
	_ = writeJSON(ctx, http.StatusOK, struct {
		ID      string `json:"id"`
		Deleted bool   `json:"deleted"`
	}{ID: id, Deleted: true})
}

func deleteConversationAdmin(ctx iris.Context, store *AdminTokenStore, lifecycle adminLifecycleDependencies) {
	principal, ok := authenticateAdminRequest(ctx, store)
	if !ok {
		return
	}
	if err := authorizeAdminScope(ctx, store, principal, AdminScopeMetadata); err != nil {
		writeAdminAuthError(ctx, err)
		return
	}
	id := ctx.Params().Get("id")
	if !validJournalUUID(id) {
		writeAdminLifecycleError(ctx, errAdminLifecycleNotFound)
		return
	}
	if lifecycle.retention == nil {
		writeAdminLifecycleError(ctx, errAdminLifecycleUnavailable)
		return
	}
	if err := lifecycle.retention.DeleteConversationAsAdmin(ctx.Request().Context(), id, principal); err != nil {
		writeAdminLifecycleError(ctx, err)
		return
	}
	_ = writeJSON(ctx, http.StatusOK, struct {
		ID      string `json:"id"`
		Deleted bool   `json:"deleted"`
	}{ID: id, Deleted: true})
}

func exportRequestAdmin(ctx iris.Context, store *AdminTokenStore, lifecycle adminLifecycleDependencies) {
	setAdminExportHeaders(ctx, "request")
	principal, ok := authenticateAdminRequest(ctx, store)
	if !ok {
		return
	}
	if err := authorizeAdminScope(ctx, store, principal, AdminScopeContent); err != nil {
		writeAdminAuthError(ctx, err)
		return
	}
	id := ctx.Params().Get("id")
	if !validJournalUUID(id) {
		writeAdminLifecycleError(ctx, errAdminLifecycleNotFound)
		return
	}
	if lifecycle.db == nil {
		writeAdminLifecycleError(ctx, errAdminLifecycleUnavailable)
		return
	}
	metadata, err := loadRequestMetadata(ctx, lifecycle.db, id)
	if err != nil {
		writeAdminLifecycleError(ctx, err)
		return
	}
	if metadata.State == "deleting" {
		writeAdminLifecycleError(ctx, errAdminLifecycleConflict)
		return
	}
	if err := recordStandaloneAdminAction(ctx.Request().Context(), lifecycle.db, principal, "request.content_export", id); err != nil {
		writeAdminLifecycleError(ctx, err)
		return
	}
	plan, err := loadRequestExportPlanData(ctx, lifecycle.db, id, metadata)
	if err != nil {
		writeAdminLifecycleError(ctx, err)
		return
	}
	result, err := materializeRequestExport(ctx.Request().Context(), lifecycle, plan)
	if err != nil {
		writeAdminLifecycleError(ctx, err)
		return
	}
	writeAdminExport(ctx, result, id)
}

func exportConversationAdmin(ctx iris.Context, store *AdminTokenStore, lifecycle adminLifecycleDependencies) {
	setAdminExportHeaders(ctx, "conversation")
	principal, ok := authenticateAdminRequest(ctx, store)
	if !ok {
		return
	}
	if err := authorizeAdminScope(ctx, store, principal, AdminScopeContent); err != nil {
		writeAdminAuthError(ctx, err)
		return
	}
	id := ctx.Params().Get("id")
	if !validJournalUUID(id) {
		writeAdminLifecycleError(ctx, errAdminLifecycleNotFound)
		return
	}
	if lifecycle.db == nil {
		writeAdminLifecycleError(ctx, errAdminLifecycleUnavailable)
		return
	}
	conversation, err := loadConversationMetadata(ctx, lifecycle.db, id, true)
	if err != nil {
		writeAdminLifecycleError(ctx, err)
		return
	}
	if conversation.State == "deleting" {
		writeAdminLifecycleError(ctx, errAdminLifecycleConflict)
		return
	}
	if err := recordStandaloneAdminAction(ctx.Request().Context(), lifecycle.db, principal, "conversation.content_export", id); err != nil {
		writeAdminLifecycleError(ctx, err)
		return
	}
	conversation, plans, err := loadConversationExportPlansData(ctx, lifecycle.db, id, conversation)
	if err != nil {
		writeAdminLifecycleError(ctx, err)
		return
	}
	result, err := materializeConversationExport(ctx.Request().Context(), lifecycle, conversation, plans)
	if err != nil {
		writeAdminLifecycleError(ctx, err)
		return
	}
	writeAdminExport(ctx, result, id)
}

func parseAdminLifecycleListFilter(ctx iris.Context) (adminLifecycleListFilter, error) {
	values := ctx.Request().URL.Query()
	allowed := map[string]bool{"limit": true, "cursor": true, "key_id": true, "endpoint": true, "state": true, "from": true, "to": true, "created_after": true, "created_before": true}
	for key, raw := range values {
		if !allowed[key] || len(raw) != 1 || raw[0] == "" {
			return adminLifecycleListFilter{}, fmt.Errorf("%w: invalid list parameter", errAdminLifecycleRequest)
		}
	}
	filter := adminLifecycleListFilter{Limit: adminLifecycleListLimit}
	if value := values.Get("limit"); value != "" {
		limit, err := strconv.Atoi(value)
		if err != nil || limit < 1 || limit > adminLifecycleMaxLimit {
			return adminLifecycleListFilter{}, fmt.Errorf("%w: invalid limit", errAdminLifecycleRequest)
		}
		filter.Limit = limit
	}
	if value := values.Get("cursor"); value != "" {
		cursor, err := decodeAdminLifecycleCursor(value)
		if err != nil {
			return adminLifecycleListFilter{}, fmt.Errorf("%w: invalid cursor", errAdminLifecycleRequest)
		}
		filter.Cursor, filter.HasCursor = cursor, true
	}
	for name, destination := range map[string]*string{"key_id": &filter.KeyID, "endpoint": &filter.Endpoint, "state": &filter.State} {
		if value := values.Get(name); value != "" {
			if len(value) > artifactMaxOwnerFieldSize || strings.TrimSpace(value) == "" {
				return adminLifecycleListFilter{}, fmt.Errorf("%w: invalid %s", errAdminLifecycleRequest, name)
			}
			*destination = value
		}
	}
	if filter.State != "" {
		switch filter.State {
		case requestStatusRunning, requestStatusSucceeded, requestStatusFailed, requestStatusCanceled, "active", "deleting":
		default:
			return adminLifecycleListFilter{}, fmt.Errorf("%w: invalid state", errAdminLifecycleRequest)
		}
	}
	from, err := lifecycleTimeParam(values, "from", "created_after")
	if err != nil {
		return adminLifecycleListFilter{}, err
	}
	to, err := lifecycleTimeParam(values, "to", "created_before")
	if err != nil {
		return adminLifecycleListFilter{}, err
	}
	if from != nil && to != nil {
		if !from.Before(*to) && !from.Equal(*to) {
			return adminLifecycleListFilter{}, fmt.Errorf("%w: invalid time range", errAdminLifecycleRequest)
		}
		if to.Sub(*from) > adminLifecycleMaxTimeRange {
			return adminLifecycleListFilter{}, fmt.Errorf("%w: time range is too large", errAdminLifecycleRequest)
		}
	}
	filter.From, filter.To = from, to
	return filter, nil
}

func lifecycleTimeParam(values map[string][]string, first, second string) (*time.Time, error) {
	firstValue := ""
	if raw := values[first]; len(raw) == 1 {
		firstValue = raw[0]
	}
	secondValue := ""
	if raw := values[second]; len(raw) == 1 {
		secondValue = raw[0]
	}
	if firstValue != "" && secondValue != "" {
		return nil, fmt.Errorf("%w: duplicate time filter", errAdminLifecycleRequest)
	}
	value := firstValue
	if value == "" {
		value = secondValue
	}
	if value == "" {
		return nil, nil
	}
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil || parsed.Location() != time.UTC || parsed.Format(time.RFC3339Nano) != value {
		return nil, fmt.Errorf("%w: time must be canonical UTC", errAdminLifecycleRequest)
	}
	parsed = parsed.UTC()
	return &parsed, nil
}

func (filter adminLifecycleListFilter) auditFilters() []string {
	filters := make([]string, 0, 5)
	if filter.KeyID != "" {
		filters = append(filters, "key_id")
	}
	if filter.Endpoint != "" {
		filters = append(filters, "endpoint")
	}
	if filter.State != "" {
		filters = append(filters, "state")
	}
	if filter.From != nil {
		filters = append(filters, "from")
	}
	if filter.To != nil {
		filters = append(filters, "to")
	}
	return filters
}

func listAdminRequests(ctx iris.Context, db *gorm.DB, filter adminLifecycleListFilter) ([]RequestRecord, string, error) {
	query := db.WithContext(ctx.Request().Context()).Model(&RequestRecord{}).
		Select("request_id, accepted_replay_id, conversation_id, api_key_id, endpoint, model, journal_mode, status, accepted_at, started_at, updated_at, terminal_at, expires_at, terminal_replay_id, terminal_conflict, deleting_at").
		Order("accepted_at DESC, request_id DESC").Limit(filter.Limit + 1)
	if filter.HasCursor {
		query = query.Where("(accepted_at < ?) OR (accepted_at = ? AND request_id < ?)", filter.Cursor.CreatedAt, filter.Cursor.CreatedAt, filter.Cursor.ID)
	}
	if filter.KeyID != "" {
		query = query.Where("api_key_id = ?", filter.KeyID)
	}
	if filter.Endpoint != "" {
		query = query.Where("endpoint = ?", filter.Endpoint)
	}
	if filter.State != "" {
		switch filter.State {
		case "active":
			query = query.Where("deleting_at IS NULL")
		case "deleting":
			query = query.Where("deleting_at IS NOT NULL")
		case requestStatusRunning, requestStatusSucceeded, requestStatusFailed, requestStatusCanceled:
			query = query.Where("status = ? AND deleting_at IS NULL", filter.State)
		default:
			return nil, "", fmt.Errorf("%w: invalid request state", errAdminLifecycleRequest)
		}
	}
	if filter.From != nil {
		query = query.Where("accepted_at >= ?", *filter.From)
	}
	if filter.To != nil {
		query = query.Where("accepted_at <= ?", *filter.To)
	}
	var rows []RequestRecord
	if err := query.Find(&rows).Error; err != nil {
		return nil, "", fmt.Errorf("list requests: %w", err)
	}
	return trimRequestPage(rows, filter.Limit)
}

func trimRequestPage(rows []RequestRecord, limit int) ([]RequestRecord, string, error) {
	if len(rows) <= limit {
		return rows, "", nil
	}
	last := rows[limit-1]
	rows = rows[:limit]
	cursor, err := encodeAdminLifecycleCursor(adminLifecycleCursor{CreatedAt: last.AcceptedAt, ID: last.ID})
	if err != nil {
		return nil, "", err
	}
	return rows, cursor, nil
}

func listAdminConversations(ctx iris.Context, db *gorm.DB, filter adminLifecycleListFilter) ([]adminConversationListRow, string, error) {
	selectSQL := `conversations.id AS id, conversations.created_at AS created_at, conversations.updated_at AS updated_at, conversations.expires_at AS expires_at, conversations.deleting_at AS deleting_at,
(SELECT COUNT(*) FROM requests r WHERE r.conversation_id = conversations.id) AS request_count,
(SELECT COUNT(*) FROM requests r WHERE r.conversation_id = conversations.id AND r.terminal_at IS NULL) AS running_request_count,
(SELECT COUNT(*) FROM requests r WHERE r.conversation_id = conversations.id AND r.status = 'succeeded') AS succeeded_request_count,
(SELECT COUNT(*) FROM requests r WHERE r.conversation_id = conversations.id AND r.status = 'failed') AS failed_request_count,
(SELECT COUNT(*) FROM requests r WHERE r.conversation_id = conversations.id AND r.status = 'canceled') AS canceled_request_count,
(SELECT COALESCE(SUM(u.input_tokens), 0) FROM usage u JOIN requests r ON r.request_id = u.request_id WHERE r.conversation_id = conversations.id) AS input_tokens,
(SELECT COALESCE(SUM(u.output_tokens), 0) FROM usage u JOIN requests r ON r.request_id = u.request_id WHERE r.conversation_id = conversations.id) AS output_tokens,
(SELECT COALESCE(SUM(u.total_tokens), 0) FROM usage u JOIN requests r ON r.request_id = u.request_id WHERE r.conversation_id = conversations.id) AS total_tokens,
(SELECT COALESCE(SUM(u.image_count), 0) FROM usage u JOIN requests r ON r.request_id = u.request_id WHERE r.conversation_id = conversations.id) AS image_count`
	query := db.WithContext(ctx.Request().Context()).Table("conversations").Select(selectSQL).
		Order("conversations.created_at DESC, conversations.id DESC").Limit(filter.Limit + 1)
	if filter.HasCursor {
		query = query.Where("(conversations.created_at < ?) OR (conversations.created_at = ? AND conversations.id < ?)", filter.Cursor.CreatedAt, filter.Cursor.CreatedAt, filter.Cursor.ID)
	}
	needsRequestFilter := filter.KeyID != "" || filter.Endpoint != "" || filter.From != nil || filter.To != nil
	switch filter.State {
	case "":
	case "deleting":
		query = query.Where("conversations.deleting_at IS NOT NULL")
	case "active":
		query = query.Where("conversations.deleting_at IS NULL")
	case requestStatusRunning, requestStatusSucceeded, requestStatusFailed, requestStatusCanceled:
		needsRequestFilter = true
	default:
		return nil, "", fmt.Errorf("%w: invalid conversation state", errAdminLifecycleRequest)
	}
	if needsRequestFilter {
		existsSQL := "EXISTS (SELECT 1 FROM requests filtered_requests WHERE filtered_requests.conversation_id = conversations.id"
		args := make([]any, 0, 5)
		switch filter.State {
		case requestStatusRunning, requestStatusSucceeded, requestStatusFailed, requestStatusCanceled:
			existsSQL += " AND filtered_requests.status = ? AND filtered_requests.deleting_at IS NULL"
			args = append(args, filter.State)
		}
		if filter.KeyID != "" {
			existsSQL += " AND filtered_requests.api_key_id = ?"
			args = append(args, filter.KeyID)
		}
		if filter.Endpoint != "" {
			existsSQL += " AND filtered_requests.endpoint = ?"
			args = append(args, filter.Endpoint)
		}
		if filter.From != nil {
			existsSQL += " AND filtered_requests.accepted_at >= ?"
			args = append(args, *filter.From)
		}
		if filter.To != nil {
			existsSQL += " AND filtered_requests.accepted_at <= ?"
			args = append(args, *filter.To)
		}
		query = query.Where(existsSQL+" LIMIT 1)", args...)
	}
	var rows []adminConversationListRow
	if err := query.Scan(&rows).Error; err != nil {
		return nil, "", fmt.Errorf("list conversations: %w", err)
	}
	if len(rows) <= filter.Limit {
		return rows, "", nil
	}
	last := rows[filter.Limit-1]
	rows = rows[:filter.Limit]
	cursor, err := encodeAdminLifecycleCursor(adminLifecycleCursor{CreatedAt: last.CreatedAt, ID: last.ID})
	if err != nil {
		return nil, "", err
	}
	return rows, cursor, nil
}

func loadRequestMetadata(ctx iris.Context, db *gorm.DB, id string) (adminRequestMetadata, error) {
	var row RequestRecord
	if err := db.WithContext(ctx.Request().Context()).Select("request_id, accepted_replay_id, conversation_id, api_key_id, endpoint, model, journal_mode, status, accepted_at, started_at, updated_at, terminal_at, expires_at, terminal_replay_id, terminal_conflict, deleting_at").Where("request_id = ?", id).First(&row).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return adminRequestMetadata{}, errAdminLifecycleNotFound
		}
		return adminRequestMetadata{}, fmt.Errorf("load request metadata: %w", err)
	}
	metadata := requestMetadataFromRecord(row)
	var usage adminUsageMetadata
	if err := db.WithContext(ctx.Request().Context()).Model(&UsageRecord{}).Select("COALESCE(SUM(input_tokens), 0) AS input_tokens, COALESCE(SUM(output_tokens), 0) AS output_tokens, COALESCE(SUM(total_tokens), 0) AS total_tokens, COALESCE(SUM(image_count), 0) AS image_count").Where("request_id = ?", id).Scan(&usage).Error; err != nil {
		return adminRequestMetadata{}, fmt.Errorf("load request usage: %w", err)
	}
	metadata.Usage = usage
	if err := db.WithContext(ctx.Request().Context()).Model(&StreamEventRecord{}).Where("request_id = ?", id).Count(&metadata.EventCount).Error; err != nil {
		return adminRequestMetadata{}, fmt.Errorf("count request events: %w", err)
	}
	var events []adminLifecycleEventRow
	if err := db.WithContext(ctx.Request().Context()).Table("stream_events").Select("stream_events.event_type AS event_type, stream_events.created_at AS created_at, COALESCE(length(encrypted_payloads.encrypted_envelope), 0) AS size").Joins("LEFT JOIN encrypted_payloads ON encrypted_payloads.id = stream_events.payload_id").Where("stream_events.request_id = ?", id).Order("stream_events.sequence ASC, stream_events.replay_id ASC").Limit(adminLifecycleMaxEvents + 1).Scan(&events).Error; err != nil {
		return adminRequestMetadata{}, fmt.Errorf("load request events: %w", err)
	}
	if len(events) > adminLifecycleMaxEvents {
		metadata.EventsTruncated = true
		events = events[:adminLifecycleMaxEvents]
	}
	metadata.Events = make([]adminEventMetadata, 0, len(events))
	for _, event := range events {
		metadata.Events = append(metadata.Events, adminEventMetadata{Type: event.EventType, CreatedAt: event.CreatedAt, Size: event.Size})
	}
	if err := db.WithContext(ctx.Request().Context()).Model(&ArtifactRecord{}).Where("request_id = ?", id).Count(&metadata.ArtifactCount).Error; err != nil {
		return adminRequestMetadata{}, fmt.Errorf("count request artifacts: %w", err)
	}
	var artifacts []ArtifactRecord
	if err := db.WithContext(ctx.Request().Context()).Model(&ArtifactRecord{}).Select("id, mime, plaintext_size, expires_at, state, deleted_at").Where("request_id = ?", id).Order("created_at ASC, id ASC").Limit(adminLifecycleMaxArtifacts + 1).Find(&artifacts).Error; err != nil {
		return adminRequestMetadata{}, fmt.Errorf("load request artifacts: %w", err)
	}
	if len(artifacts) > adminLifecycleMaxArtifacts {
		metadata.ArtifactsTrunc = true
		artifacts = artifacts[:adminLifecycleMaxArtifacts]
	}
	metadata.Artifacts = make([]adminArtifactMetadata, 0, len(artifacts))
	for _, artifact := range artifacts {
		metadata.Artifacts = append(metadata.Artifacts, artifactMetadataFromRecord(artifact))
	}
	return metadata, nil
}

func loadConversationMetadata(ctx iris.Context, db *gorm.DB, id string, includeRequests bool) (adminConversationMetadata, error) {
	var row ConversationRecord
	if err := db.WithContext(ctx.Request().Context()).Select("id, created_at, updated_at, expires_at, request_count, deleting_at").Where("id = ?", id).First(&row).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return adminConversationMetadata{}, errAdminLifecycleNotFound
		}
		return adminConversationMetadata{}, fmt.Errorf("load conversation metadata: %w", err)
	}
	metadata := adminConversationMetadata{ID: row.ID, CreatedAt: row.CreatedAt, UpdatedAt: row.UpdatedAt, ExpiresAt: row.ExpiresAt, State: conversationState(row), RequestCount: row.RequestCount}
	var aggregate adminConversationAggregate
	if err := db.WithContext(ctx.Request().Context()).Table("requests").Select(`COUNT(*) AS request_count, COALESCE(SUM(CASE WHEN terminal_at IS NULL THEN 1 ELSE 0 END), 0) AS running_request_count, COALESCE(SUM(CASE WHEN status = 'succeeded' THEN 1 ELSE 0 END), 0) AS succeeded_request_count, COALESCE(SUM(CASE WHEN status = 'failed' THEN 1 ELSE 0 END), 0) AS failed_request_count, COALESCE(SUM(CASE WHEN status = 'canceled' THEN 1 ELSE 0 END), 0) AS canceled_request_count, COALESCE((SELECT SUM(u.input_tokens) FROM usage u JOIN requests ur ON ur.request_id = u.request_id WHERE ur.conversation_id = requests.conversation_id), 0) AS input_tokens, COALESCE((SELECT SUM(u.output_tokens) FROM usage u JOIN requests ur ON ur.request_id = u.request_id WHERE ur.conversation_id = requests.conversation_id), 0) AS output_tokens, COALESCE((SELECT SUM(u.total_tokens) FROM usage u JOIN requests ur ON ur.request_id = u.request_id WHERE ur.conversation_id = requests.conversation_id), 0) AS total_tokens, COALESCE((SELECT SUM(u.image_count) FROM usage u JOIN requests ur ON ur.request_id = u.request_id WHERE ur.conversation_id = requests.conversation_id), 0) AS image_count`).Where("conversation_id = ?", id).Scan(&aggregate).Error; err != nil {
		return adminConversationMetadata{}, fmt.Errorf("aggregate conversation metadata: %w", err)
	}
	metadata.RequestCount = aggregate.RequestCount
	metadata.RunningRequestCount = aggregate.RunningRequestCount
	metadata.SucceededRequestCount = aggregate.SucceededRequestCount
	metadata.FailedRequestCount = aggregate.FailedRequestCount
	metadata.CanceledRequestCount = aggregate.CanceledRequestCount
	metadata.Usage = adminUsageMetadata{InputTokens: aggregate.InputTokens, OutputTokens: aggregate.OutputTokens, TotalTokens: aggregate.TotalTokens, ImageCount: aggregate.ImageCount}
	firstAt, lastAt, err := conversationRequestBounds(ctx, db, id)
	if err != nil {
		return adminConversationMetadata{}, err
	}
	metadata.FirstRequestAt = firstAt
	metadata.LastRequestAt = lastAt
	if !includeRequests {
		return metadata, nil
	}
	var requests []RequestRecord
	if err := db.WithContext(ctx.Request().Context()).Select("request_id, accepted_replay_id, conversation_id, api_key_id, endpoint, model, journal_mode, status, accepted_at, started_at, updated_at, terminal_at, expires_at, terminal_replay_id, terminal_conflict, deleting_at").Where("conversation_id = ?", id).Order("accepted_at DESC, request_id DESC").Limit(adminLifecycleMaxRequests + 1).Find(&requests).Error; err != nil {
		return adminConversationMetadata{}, fmt.Errorf("load conversation requests: %w", err)
	}
	if len(requests) > adminLifecycleMaxRequests {
		metadata.RequestsTruncated = true
		requests = requests[:adminLifecycleMaxRequests]
	}
	metadata.Requests = make([]adminRequestMetadata, 0, len(requests))
	for _, request := range requests {
		metadata.Requests = append(metadata.Requests, requestMetadataFromRecord(request))
	}
	return metadata, nil
}

func requestMetadataFromRecord(row RequestRecord) adminRequestMetadata {
	return adminRequestMetadata{ID: row.ID, ConversationID: row.ConversationID, APIKeyID: row.APIKeyID, Endpoint: row.Endpoint, Model: row.Model, Mode: row.Mode, State: requestState(row), AcceptedAt: row.AcceptedAt, StartedAt: row.StartedAt, UpdatedAt: row.UpdatedAt, TerminalAt: row.TerminalAt, ExpiresAt: row.ExpiresAt, TerminalConflict: row.TerminalConflict}
}
func conversationRequestBounds(ctx iris.Context, db *gorm.DB, id string) (*time.Time, *time.Time, error) {
	var first []RequestRecord
	if err := db.WithContext(ctx.Request().Context()).Select("accepted_at").Where("conversation_id = ?", id).Order("accepted_at ASC, request_id ASC").Limit(1).Find(&first).Error; err != nil {
		return nil, nil, fmt.Errorf("load first conversation request time: %w", err)
	}
	if len(first) == 0 {
		return nil, nil, nil
	}
	var last []RequestRecord
	if err := db.WithContext(ctx.Request().Context()).Select("accepted_at").Where("conversation_id = ?", id).Order("accepted_at DESC, request_id DESC").Limit(1).Find(&last).Error; err != nil {
		return nil, nil, fmt.Errorf("load last conversation request time: %w", err)
	}
	firstAt := first[0].AcceptedAt.UTC()
	lastAt := last[0].AcceptedAt.UTC()
	return &firstAt, &lastAt, nil
}

func artifactMetadataFromRecord(row ArtifactRecord) adminArtifactMetadata {
	return adminArtifactMetadata{ID: row.ID, MIME: row.MIME, PlaintextSize: row.PlaintextSize, ExpiresAt: row.ExpiresAt}
}

func conversationMetadataFromListRow(row adminConversationListRow) adminConversationMetadata {
	return adminConversationMetadata{ID: row.ID, CreatedAt: row.CreatedAt, UpdatedAt: row.UpdatedAt, ExpiresAt: row.ExpiresAt, State: conversationStateFromDeletingAt(row.DeletingAt), RequestCount: row.RequestCount, RunningRequestCount: row.RunningRequestCount, SucceededRequestCount: row.SucceededRequestCount, FailedRequestCount: row.FailedRequestCount, CanceledRequestCount: row.CanceledRequestCount, Usage: adminUsageMetadata{InputTokens: row.InputTokens, OutputTokens: row.OutputTokens, TotalTokens: row.TotalTokens, ImageCount: row.ImageCount}}
}

func requestState(row RequestRecord) string {
	if row.DeletingAt != nil {
		return "deleting"
	}
	switch row.Status {
	case requestStatusRunning, requestStatusSucceeded, requestStatusFailed, requestStatusCanceled:
		return row.Status
	default:
		return "unknown"
	}
}

func conversationState(row ConversationRecord) string {
	return conversationStateFromDeletingAt(row.DeletingAt)
}

func conversationStateFromDeletingAt(deletingAt *time.Time) string {
	if deletingAt != nil {
		return "deleting"
	}
	return "active"
}

func loadRequestExportPlanData(ctx iris.Context, db *gorm.DB, id string, metadata adminRequestMetadata) (adminRequestExportPlan, error) {
	if metadata.State == "deleting" {
		return adminRequestExportPlan{}, errAdminLifecycleConflict
	}
	var journals []JournalRecord
	if err := db.WithContext(ctx.Request().Context()).
		Select("replay_id, request_id, sequence, mode, event_type, event_version, key_version, payload, checksum, created_at").
		Where("request_id = ?", id).
		Order("sequence ASC, replay_id ASC").
		Limit(adminLifecycleMaxEvents + 2).
		Find(&journals).Error; err != nil {
		return adminRequestExportPlan{}, fmt.Errorf("load request export events: %w", err)
	}
	if len(journals) > adminLifecycleMaxEvents+1 {
		return adminRequestExportPlan{}, errAdminLifecycleTooLarge
	}
	plans := make([]adminExportPayloadPlan, 0, len(journals))
	inputSeen := false
	for _, journal := range journals {
		if err := validateJournalRecord(journal); err != nil {
			return adminRequestExportPlan{}, fmt.Errorf("validate request export event: %w", err)
		}
		if journal.EventType == journalRequestEventType || journal.EventType == "request.running" {
			continue
		}
		if len(journal.Payload) == 0 {
			return adminRequestExportPlan{}, errors.New("stored request payload envelope is invalid")
		}
		if len(journal.Payload) > envelope.MaxEnvelopeSize {
			return adminRequestExportPlan{}, errAdminLifecycleTooLarge
		}
		if len(journal.Payload) <= adminPayloadEnvelopeOverhead {
			return adminRequestExportPlan{}, errors.New("stored request payload envelope is invalid")
		}
		plaintextSize := int64(len(journal.Payload) - adminPayloadEnvelopeOverhead)
		if plaintextSize > envelope.MaxPlaintextSize {
			return adminRequestExportPlan{}, errAdminLifecycleTooLarge
		}
		plan := adminExportPayloadPlan{
			Type: journal.EventType, Sequence: journal.Sequence, CreatedAt: journal.CreatedAt,
			Envelope: append([]byte(nil), journal.Payload...), Input: journal.EventType == "request.input", PlaintextSize: plaintextSize,
		}
		if plan.Input {
			if inputSeen {
				return adminRequestExportPlan{}, errors.New("request input payload is duplicated")
			}
			inputSeen = true
		}
		plans = append(plans, plan)
	}
	if len(plans) > adminLifecycleMaxEvents {
		return adminRequestExportPlan{}, errAdminLifecycleTooLarge
	}
	var artifacts []ArtifactRecord
	if err := db.WithContext(ctx.Request().Context()).
		Select("id, request_id, conversation_id, api_key_id, result_index, mime, plaintext_size, expires_at, state, deleted_at, created_at").
		Where("request_id = ?", id).
		Order("created_at ASC, id ASC").
		Limit(adminLifecycleMaxArtifacts + 1).
		Find(&artifacts).Error; err != nil {
		return adminRequestExportPlan{}, fmt.Errorf("load request export artifacts: %w", err)
	}
	if len(artifacts) > adminLifecycleMaxArtifacts {
		return adminRequestExportPlan{}, errAdminLifecycleTooLarge
	}
	plan := adminRequestExportPlan{Metadata: metadata, Payloads: plans, Artifacts: artifacts}
	if err := preflightRequestExport(plan); err != nil {
		return adminRequestExportPlan{}, err
	}
	return plan, nil
}

func loadConversationExportPlansData(ctx iris.Context, db *gorm.DB, id string, metadata adminConversationMetadata) (adminConversationMetadata, []adminRequestExportPlan, error) {
	if metadata.State == "deleting" {
		return adminConversationMetadata{}, nil, errAdminLifecycleConflict
	}
	var requests []RequestRecord
	if err := db.WithContext(ctx.Request().Context()).
		Select("request_id, accepted_replay_id, conversation_id, api_key_id, endpoint, model, journal_mode, status, accepted_at, started_at, updated_at, terminal_at, expires_at, terminal_replay_id, terminal_conflict, deleting_at").
		Where("conversation_id = ?", id).
		Order("accepted_at ASC, request_id ASC").
		Limit(adminLifecycleMaxRequests + 1).
		Find(&requests).Error; err != nil {
		return adminConversationMetadata{}, nil, fmt.Errorf("load conversation export requests: %w", err)
	}
	if len(requests) > adminLifecycleMaxRequests {
		return adminConversationMetadata{}, nil, errAdminLifecycleTooLarge
	}
	plans := make([]adminRequestExportPlan, 0, len(requests))
	for _, request := range requests {
		requestMetadata, err := loadRequestMetadata(ctx, db, request.ID)
		if err != nil {
			return adminConversationMetadata{}, nil, err
		}
		plan, err := loadRequestExportPlanData(ctx, db, request.ID, requestMetadata)
		if err != nil {
			return adminConversationMetadata{}, nil, err
		}
		plans = append(plans, plan)
	}
	if err := preflightConversationExport(metadata, plans); err != nil {
		return adminConversationMetadata{}, nil, err
	}
	return metadata, plans, nil
}

func preflightRequestExport(plan adminRequestExportPlan) error {
	metadata, err := json.Marshal(plan.Metadata)
	if err != nil {
		return fmt.Errorf("encode request export metadata: %w", err)
	}
	total := int64(len(metadata))
	if err := addExportSize(&total, 2048); err != nil {
		return err
	}
	for _, payload := range plan.Payloads {
		if payload.PlaintextSize <= 0 {
			return errors.New("stored request payload size is invalid")
		}
		if payload.PlaintextSize > envelope.MaxPlaintextSize {
			return errAdminLifecycleTooLarge
		}
		if err := addExportSize(&total, int64(base64.StdEncoding.EncodedLen(int(payload.PlaintextSize)))+1024); err != nil {
			return err
		}
	}
	for _, artifact := range plan.Artifacts {
		if artifact.PlaintextSize <= 0 {
			return errors.New("stored artifact size is invalid")
		}
		if artifact.PlaintextSize > artifactMaxPlaintextSize {
			return errAdminLifecycleTooLarge
		}
		if err := addExportSize(&total, int64(base64.StdEncoding.EncodedLen(int(artifact.PlaintextSize)))+1024); err != nil {
			return err
		}
	}
	return nil
}

func preflightConversationExport(metadata adminConversationMetadata, plans []adminRequestExportPlan) error {
	encoded, err := json.Marshal(metadata)
	if err != nil {
		return fmt.Errorf("encode conversation export metadata: %w", err)
	}
	total := int64(len(encoded))
	if err := addExportSize(&total, 4096); err != nil {
		return err
	}
	for _, plan := range plans {
		if err := preflightRequestExport(plan); err != nil {
			return err
		}
		requestEncoded, marshalErr := json.Marshal(plan.Metadata)
		if marshalErr != nil {
			return fmt.Errorf("encode conversation request metadata: %w", marshalErr)
		}
		if err := addExportSize(&total, int64(len(requestEncoded))+1024); err != nil {
			return err
		}
		for _, payload := range plan.Payloads {
			if payload.PlaintextSize <= 0 {
				return errors.New("stored request payload size is invalid")
			}
			if payload.PlaintextSize > envelope.MaxPlaintextSize {
				return errAdminLifecycleTooLarge
			}
			if err := addExportSize(&total, int64(base64.StdEncoding.EncodedLen(int(payload.PlaintextSize)))+512); err != nil {
				return err
			}
		}
		for _, artifact := range plan.Artifacts {
			if err := addExportSize(&total, int64(base64.StdEncoding.EncodedLen(int(artifact.PlaintextSize)))+512); err != nil {
				return err
			}
		}
	}
	return nil
}

func addExportSize(total *int64, amount int64) error {
	if amount < 0 || *total > adminLifecycleExportCap-amount {
		return errAdminLifecycleTooLarge
	}
	*total += amount
	return nil
}

func materializeRequestExport(ctx context.Context, lifecycle adminLifecycleDependencies, plan adminRequestExportPlan) (adminContentExport, error) {
	content := adminRequestExport{Metadata: plan.Metadata, Events: make([]adminExportEvent, 0, len(plan.Payloads)), Artifacts: make([]adminExportArtifact, 0, len(plan.Artifacts))}
	for _, payload := range plan.Payloads {
		plain, err := envelope.Decrypt(payload.Envelope, envelope.PayloadDomain, lifecycle.keys)
		if err != nil {
			return adminContentExport{}, fmt.Errorf("decrypt request export payload: %w", err)
		}
		value, err := exportValueFromPlaintext(plain, payload.Input)
		if err != nil {
			return adminContentExport{}, err
		}
		if payload.Input {
			content.Input = &value
			continue
		}
		content.Events = append(content.Events, adminExportEvent{Type: payload.Type, Sequence: payload.Sequence, CreatedAt: payload.CreatedAt, Payload: value})
	}
	for _, artifact := range plan.Artifacts {
		if lifecycle.artifacts == nil {
			return adminContentExport{}, errAdminLifecycleUnavailable
		}
		plain, err := lifecycle.artifacts.Read(ctx, artifact.ID)
		if err != nil {
			return adminContentExport{}, fmt.Errorf("read request export artifact: %w", err)
		}
		if int64(len(plain)) != artifact.PlaintextSize {
			return adminContentExport{}, errors.New("artifact plaintext size changed")
		}
		content.Artifacts = append(content.Artifacts, adminExportArtifact{ID: artifact.ID, MIME: artifact.MIME, PlaintextSize: artifact.PlaintextSize, ExpiresAt: artifact.ExpiresAt, Data: base64.StdEncoding.EncodeToString(plain)})
	}
	return adminContentExport{Type: "request", Metadata: exportMetadataFromRequest(plan.Metadata), Requests: []adminRequestExport{content}}, nil
}

func materializeConversationExport(ctx context.Context, lifecycle adminLifecycleDependencies, metadata adminConversationMetadata, plans []adminRequestExportPlan) (adminContentExport, error) {
	requests := make([]adminRequestExport, 0, len(plans))
	for _, plan := range plans {
		content, err := materializeRequestExport(ctx, lifecycle, plan)
		if err != nil {
			return adminContentExport{}, err
		}
		if len(content.Requests) != 1 {
			return adminContentExport{}, errors.New("request export shape is invalid")
		}
		requests = append(requests, content.Requests[0])
	}
	return adminContentExport{Type: "conversation", Metadata: exportMetadataFromConversation(metadata), Requests: requests}, nil
}

func exportValueFromPlaintext(plain []byte, input bool) (adminExportValue, error) {
	if len(plain) == 0 || len(plain) > envelope.MaxPlaintextSize {
		return adminExportValue{}, errors.New("decrypted export payload size is invalid")
	}
	if json.Valid(plain) {
		return adminExportValue{jsonValue: append(json.RawMessage(nil), plain...)}, nil
	}
	if input {
		return adminExportValue{}, errors.New("request input is not valid JSON")
	}
	return adminExportValue{base64: base64.StdEncoding.EncodeToString(plain)}, nil
}

func exportMetadataFromRequest(metadata adminRequestMetadata) adminExportMetadata {
	return adminExportMetadata{ID: metadata.ID, ConversationID: metadata.ConversationID, APIKeyID: metadata.APIKeyID, Endpoint: metadata.Endpoint, Model: metadata.Model, State: metadata.State, CreatedAt: metadata.AcceptedAt, UpdatedAt: metadata.UpdatedAt, ExpiresAt: metadata.ExpiresAt, Usage: metadata.Usage}
}

func exportMetadataFromConversation(metadata adminConversationMetadata) adminExportMetadata {
	return adminExportMetadata{ID: metadata.ID, State: metadata.State, CreatedAt: metadata.CreatedAt, UpdatedAt: metadata.UpdatedAt, ExpiresAt: metadata.ExpiresAt, RequestCount: metadata.RequestCount, Usage: metadata.Usage}
}

func encodeAdminLifecycleCursor(cursor adminLifecycleCursor) (string, error) {
	if cursor.CreatedAt.IsZero() || !validLifecycleCursorID(cursor.ID) {
		return "", errAdminLifecycleRequest
	}
	value := cursor.CreatedAt.UTC().Format(time.RFC3339Nano) + "\x00" + cursor.ID
	encoded := base64.RawURLEncoding.EncodeToString([]byte(value))
	if len(encoded) > adminLifecycleMaxCursor {
		return "", errAdminLifecycleRequest
	}
	return encoded, nil
}

func decodeAdminLifecycleCursor(value string) (adminLifecycleCursor, error) {
	if value == "" || len(value) > adminLifecycleMaxCursor {
		return adminLifecycleCursor{}, errAdminLifecycleRequest
	}
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(decoded) > adminLifecycleMaxCursor {
		return adminLifecycleCursor{}, errAdminLifecycleRequest
	}
	parts := bytes.Split(decoded, []byte{0})
	if len(parts) != 2 || !validLifecycleCursorID(string(parts[1])) {
		return adminLifecycleCursor{}, errAdminLifecycleRequest
	}
	createdAt, err := time.Parse(time.RFC3339Nano, string(parts[0]))
	if err != nil || createdAt.Location() != time.UTC || createdAt.Format(time.RFC3339Nano) != string(parts[0]) {
		return adminLifecycleCursor{}, errAdminLifecycleRequest
	}
	canonical, err := encodeAdminLifecycleCursor(adminLifecycleCursor{CreatedAt: createdAt, ID: string(parts[1])})
	if err != nil || canonical != value {
		return adminLifecycleCursor{}, errAdminLifecycleRequest
	}
	return adminLifecycleCursor{CreatedAt: createdAt.UTC(), ID: string(parts[1])}, nil
}

func validLifecycleCursorID(value string) bool {
	return validJournalUUID(value)
}

func recordLifecycleAudit(ctx iris.Context, db *gorm.DB, principal AdminPrincipal, action, target string, filters []string) error {
	return db.WithContext(ctx.Request().Context()).Transaction(func(tx *gorm.DB) error {
		return writeAdminAudit(tx, principal, action, target, adminAuditMetadata{Fields: []string{"metadata"}, Filters: filters}, time.Now().UTC())
	})
}

func recordStandaloneAdminAction(ctx context.Context, db *gorm.DB, principal AdminPrincipal, action, target string) error {
	if ctx == nil || db == nil {
		return errAdminLifecycleUnavailable
	}
	return db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		return writeAdminAudit(tx, principal, action, target, adminAuditMetadata{Fields: []string{"metadata"}}, time.Now().UTC())
	})
}

func setAdminExportHeaders(ctx iris.Context, kind string) {
	ctx.Header("Cache-Control", "no-store")
	ctx.Header("Pragma", "no-cache")
	ctx.Header("X-Content-Type-Options", "nosniff")
	ctx.Header("Content-Disposition", `attachment; filename="`+kind+`-export.json"`)
}

type adminExportBuffer struct {
	buffer bytes.Buffer
	limit  int64
}

func (writer *adminExportBuffer) Write(data []byte) (int, error) {
	if int64(len(data)) > writer.limit-int64(writer.buffer.Len()) {
		return 0, errAdminLifecycleTooLarge
	}
	return writer.buffer.Write(data)
}

func writeAdminExport(ctx iris.Context, value adminContentExport, target string) {
	writer := &adminExportBuffer{limit: adminLifecycleExportCap}
	encoder := json.NewEncoder(writer)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		writeAdminLifecycleError(ctx, err)
		return
	}
	ctx.Header("Content-Type", "application/json")
	ctx.StatusCode(http.StatusOK)
	if _, err := ctx.ResponseWriter().Write(writer.buffer.Bytes()); err != nil {
		return
	}
}

func writeAdminLifecycleError(ctx iris.Context, err error) {
	switch {
	case errors.Is(err, errAdminLifecycleNotFound):
		writeAdminError(ctx, http.StatusNotFound, "Lifecycle record not found.")
	case errors.Is(err, errAdminLifecycleConflict), errors.Is(err, errRequestHasRunningRequest), errors.Is(err, errConversationHasRunningRequest):
		writeAdminError(ctx, http.StatusConflict, "Lifecycle record cannot be changed now.")
	case errors.Is(err, errAdminLifecycleTooLarge):
		writeAdminErrorCode(ctx, http.StatusRequestEntityTooLarge, "The export is too large.", "export_too_large")
	case errors.Is(err, errAdminLifecycleRequest):
		writeAdminError(ctx, http.StatusBadRequest, "Invalid lifecycle request.")
	case errors.Is(err, errAdminLifecycleUnavailable):
		writeAdminError(ctx, http.StatusServiceUnavailable, "Lifecycle storage is unavailable.")
	case errors.Is(err, ErrAdminTokenForbidden):
		writeAdminAuthError(ctx, err)
	default:
		writeAdminError(ctx, http.StatusInternalServerError, "Internal server error.")
	}
}
