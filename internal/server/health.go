package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync"

	"github.com/kataras/iris/v12"
)

type Readiness struct {
	mu                  sync.RWMutex
	storage             bool
	keys                bool
	credentialAvailable func() bool
}

type ReadinessSnapshot struct {
	Storage      bool `json:"storage"`
	Keys         bool `json:"keys"`
	UpstreamAuth bool `json:"upstream_auth"`
}

func NewReadiness() *Readiness {
	return &Readiness{}
}

func (r *Readiness) Set(storage, keys bool, credentialAvailable func() bool) {
	r.mu.Lock()
	r.storage = storage
	r.keys = keys
	r.credentialAvailable = credentialAvailable
	r.mu.Unlock()
}

func (r *Readiness) Snapshot() ReadinessSnapshot {
	r.mu.RLock()
	snapshot := ReadinessSnapshot{
		Storage: r.storage,
		Keys:    r.keys,
	}
	credentialAvailable := r.credentialAvailable
	r.mu.RUnlock()
	if credentialAvailable != nil {
		snapshot.UpstreamAuth = credentialAvailable()
	}
	return snapshot
}

func (s ReadinessSnapshot) Ready() bool {
	return s.Storage && s.Keys && s.UpstreamAuth
}

func newHealthApplication(readiness *Readiness) (*iris.Application, error) {
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
	if err := app.Build(); err != nil {
		return nil, fmt.Errorf("build health application: %w", err)
	}
	return app, nil
}

func writeJSON(ctx iris.Context, status int, value any) {
	ctx.Header("Content-Type", "application/json")
	ctx.StatusCode(status)
	_ = json.NewEncoder(ctx.ResponseWriter()).Encode(value)
}
