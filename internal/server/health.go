package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sync"

	"github.com/catgirl-systems/codex-sub-proxy/internal/apikey"
	"github.com/kataras/iris/v12"
)

type CredentialSnapshot struct {
	Available bool
	State     string
}

type Readiness struct {
	mu                 sync.RWMutex
	storage            bool
	keys               bool
	credentialSnapshot func() CredentialSnapshot
}

type ReadinessSnapshot struct {
	Storage         bool   `json:"storage"`
	Keys            bool   `json:"keys"`
	UpstreamAuth    bool   `json:"upstream_auth"`
	CredentialState string `json:"credential_state,omitempty"`
}

func NewReadiness() *Readiness {
	return &Readiness{}
}

// Set records fixed checks and one coherent credential observation callback.
func (r *Readiness) Set(storage, keys bool, credential func() CredentialSnapshot) {
	r.mu.Lock()
	r.storage = storage
	r.keys = keys
	r.credentialSnapshot = credential
	r.mu.Unlock()
}

func (r *Readiness) Snapshot() ReadinessSnapshot {
	r.mu.RLock()
	snapshot := ReadinessSnapshot{
		Storage: r.storage,
		Keys:    r.keys,
	}
	credential := r.credentialSnapshot
	r.mu.RUnlock()
	if credential != nil {
		current := credential()
		snapshot.UpstreamAuth = current.Available
		snapshot.CredentialState = current.State
	}
	return snapshot
}

func (s ReadinessSnapshot) Ready() bool {
	return s.Storage && s.Keys && s.UpstreamAuth
}

func newHealthApplication(readiness *Readiness) (*iris.Application, error) {
	app := buildHealthApplication(readiness)
	if err := app.Build(); err != nil {
		return nil, fmt.Errorf("build health application: %w", err)
	}
	return app, nil
}

func buildHealthApplication(readiness *Readiness) *iris.Application {
	app := iris.New()
	app.Any("/healthz", func(ctx iris.Context) {
		if ctx.Method() != http.MethodGet {
			ctx.Header("Allow", http.MethodGet)
			http.Error(ctx.ResponseWriter(), "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		writeJSON(ctx, http.StatusOK, struct {
			Status string `json:"status"`
		}{Status: "live"})
	})
	app.Any("/readyz", func(ctx iris.Context) {
		if ctx.Method() != http.MethodGet {
			ctx.Header("Allow", http.MethodGet)
			http.Error(ctx.ResponseWriter(), "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		snapshot := ReadinessSnapshot{}
		if readiness != nil {
			snapshot = readiness.Snapshot()
		}
		status := http.StatusServiceUnavailable
		name := "unavailable"
		if snapshot.Ready() {
			status = http.StatusOK
			name = "ready"
		}
		writeJSON(ctx, status, struct {
			Status string            `json:"status"`
			Checks ReadinessSnapshot `json:"checks"`
		}{Status: name, Checks: snapshot})
	})
	return app
}

const journalRequestValueKey = "csp-journal-request"
const journalAuditValueKey = "csp-journal-audit"

type journalRequestValue struct {
	journal *Journal
	request JournalRequest
	context context.Context
}

type journalAuditValue struct {
	journal  *Journal
	endpoint string
	apiKeyID string
	recorded bool
}

func setJournalAuditContext(ctx iris.Context, journal *Journal, endpoint string) {
	if journal == nil {
		return
	}
	ctx.Values().Set(journalAuditValueKey, &journalAuditValue{journal: journal, endpoint: endpoint})
}

func setJournalAuditPrincipal(ctx iris.Context, apiKeyID string) {
	value, ok := ctx.Values().Get(journalAuditValueKey).(*journalAuditValue)
	if !ok || value == nil {
		return
	}
	value.apiKeyID = apiKeyID
}

func recordJournalRejection(ctx iris.Context, status int, eventType string) {
	value, ok := ctx.Values().Get(journalAuditValueKey).(*journalAuditValue)
	if !ok || value == nil || value.journal == nil || value.recorded {
		return
	}
	value.recorded = true
	detail := []byte(`{"version":1}`)
	if err := value.journal.RecordAudit(ctx.Request().Context(), JournalAuditMetadata{
		APIKeyID:  value.apiKeyID,
		Endpoint:  value.endpoint,
		EventType: eventType,
		Status:    status,
	}, detail); err != nil {
		value.journal.recordWorkerError(err)
	}
}

func startJournalRequestWithMetadata(ctx iris.Context, journal *Journal, metadata JournalRequestMetadata, input []byte) (JournalRequest, error) {
	if journal == nil {
		return JournalRequest{}, nil
	}
	request, err := journal.BeginRequestWithMetadata(ctx.Request().Context(), metadata, input)
	if err != nil {
		return JournalRequest{}, err
	}
	ctx.Values().Set(journalRequestValueKey, &journalRequestValue{journal: journal, request: request, context: ctx.Request().Context()})
	return request, nil
}

func markJournalTerminal(ctx iris.Context, state, detail string) {
	value, ok := ctx.Values().Get(journalRequestValueKey).(*journalRequestValue)
	if !ok || value == nil || value.journal == nil {
		return
	}
	markJournalTerminalValue(value, state, detail)
}

func markJournalTerminalValue(value *journalRequestValue, state, detail string) {
	if value == nil || value.journal == nil {
		return
	}
	requestState := value.journal.requestState(value.request)
	if requestState == nil {
		return
	}
	requestState.mu.Lock()
	if requestState.terminalRecord {
		requestState.mu.Unlock()
		return
	}
	requestState.mu.Unlock()
	if err := value.journal.RecordTerminal(context.WithoutCancel(value.context), value.request, state, []byte(detail)); err != nil {
		value.journal.recordError(err)
	}
}

func finishJournalRequest(ctx iris.Context, journal *Journal, request JournalRequest) {
	if journal == nil {
		return
	}
	state := requestStatusSucceeded
	if ctx.Request().Context().Err() != nil {
		state = requestStatusCanceled
	} else if status := ctx.ResponseWriter().StatusCode(); status >= http.StatusBadRequest {
		state = requestStatusFailed
	}
	if err := journal.CompleteRequestWithState(context.WithoutCancel(ctx.Request().Context()), request, state); err != nil {
		journal.recordError(err)
	}
}

func recordJournalUsage(ctx iris.Context, usage apikey.QuotaUsage) {
	value, ok := ctx.Values().Get(journalRequestValueKey).(*journalRequestValue)
	if !ok || value == nil || value.journal == nil {
		return
	}
	if err := value.journal.RecordUsage(ctx.Request().Context(), value.request, 0, usage.Tokens, usage.Tokens, usage.Images); err != nil {
		value.journal.recordError(err)
	}
}
func writeJournalJSON(ctx iris.Context, status int, eventType string, payload []byte) error {
	value, ok := ctx.Values().Get(journalRequestValueKey).(*journalRequestValue)
	if !ok || value == nil || value.journal == nil {
		ctx.Header("Content-Type", "application/json")
		ctx.StatusCode(status)
		written, err := ctx.ResponseWriter().Write(payload)
		if err == nil && written != len(payload) {
			return errors.New("short JSON response write")
		}
		return err
	}
	err := value.journal.Forward(ctx.Request().Context(), value.request, eventType, payload, func(_ context.Context, _ string) error {
		ctx.Header("Content-Type", "application/json")
		ctx.StatusCode(status)
		written, err := ctx.ResponseWriter().Write(payload)
		if err == nil && written != len(payload) {
			return errors.New("short JSON response write")
		}
		return err
	})
	if err != nil {
		markJournalTerminal(ctx, requestStatusFailed, "")
	}
	if err == nil {
		if status >= 200 && status < 300 {
			markJournalTerminal(ctx, requestStatusSucceeded, "")
		} else if status >= 400 {
			markJournalTerminal(ctx, requestStatusFailed, "")
		}
	}
	return err
}

func writeJSON(ctx iris.Context, status int, value any) error {
	payload, err := json.Marshal(value)
	if err != nil {
		writeSafeInternalError(ctx)
		return err
	}
	payload = append(payload, '\n')
	if err := writeJournalJSON(ctx, status, "response.json", payload); err != nil {
		handleJournalResponseError(ctx, err)
		return err
	}
	return nil
}

func handleJournalResponseError(ctx iris.Context, err error) {
	value, ok := ctx.Values().Get(journalRequestValueKey).(*journalRequestValue)
	if ok && value != nil && value.journal != nil {
		markJournalTerminal(ctx, requestStatusFailed, err.Error())
		value.journal.recordError(err)
		if value.journal.mode == journalModeDurable && ctx.ResponseWriter().Written() < 0 {
			writeSafeInternalError(ctx)
		}
		return
	}
	if ctx.ResponseWriter().Written() < 0 {
		writeSafeInternalError(ctx)
	}
}

func writeSafeInternalError(ctx iris.Context) {
	ctx.Header("Content-Type", "application/json")
	ctx.StatusCode(http.StatusInternalServerError)
	_, _ = ctx.ResponseWriter().Write([]byte(`{"error":{"message":"Internal server error.","type":"server_error","code":"internal_error"}}` + "\n"))
}
