package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sync"

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

type journalRequestValue struct {
	journal *Journal
	request JournalRequest
}

func startJournalRequest(ctx iris.Context, journal *Journal) (JournalRequest, error) {
	if journal == nil {
		return JournalRequest{}, nil
	}
	request, err := journal.BeginRequest(ctx.Request().Context())
	if err != nil {
		return JournalRequest{}, err
	}
	ctx.Values().Set(journalRequestValueKey, &journalRequestValue{journal: journal, request: request})
	return request, nil
}

func finishJournalRequest(ctx iris.Context, journal *Journal, request JournalRequest) {
	if journal == nil {
		return
	}
	if err := journal.CompleteRequest(ctx.Request().Context(), request); err != nil {
		journal.recordError(err)
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
	return value.journal.Forward(ctx.Request().Context(), value.request, eventType, payload, func(_ context.Context, _ string) error {
		ctx.Header("Content-Type", "application/json")
		ctx.StatusCode(status)
		written, err := ctx.ResponseWriter().Write(payload)
		if err == nil && written != len(payload) {
			return errors.New("short JSON response write")
		}
		return err
	})
}

func writeJSON(ctx iris.Context, status int, value any) {
	payload, err := json.Marshal(value)
	if err != nil {
		writeSafeInternalError(ctx)
		return
	}
	payload = append(payload, '\n')
	if err := writeJournalJSON(ctx, status, "response.json", payload); err != nil {
		handleJournalResponseError(ctx, err)
	}
}

func handleJournalResponseError(ctx iris.Context, err error) {
	value, ok := ctx.Values().Get(journalRequestValueKey).(*journalRequestValue)
	if ok && value != nil && value.journal != nil {
		if value.journal.mode == journalModeDurable && ctx.ResponseWriter().Written() < 0 {
			value.journal.recordError(err)
			writeSafeInternalError(ctx)
			return
		}
		value.journal.recordError(err)
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
