package server

import (
	"encoding/json"
	"net/http"
	"sync"
)

type Readiness struct {
	mu           sync.RWMutex
	storage      bool
	keys         bool
	upstreamAuth bool
}

type ReadinessSnapshot struct {
	Storage      bool `json:"storage"`
	Keys         bool `json:"keys"`
	UpstreamAuth bool `json:"upstream_auth"`
}

func NewReadiness() *Readiness {
	return &Readiness{}
}

func (r *Readiness) Set(storage, keys, upstreamAuth bool) {
	r.mu.Lock()
	r.storage = storage
	r.keys = keys
	r.upstreamAuth = upstreamAuth
	r.mu.Unlock()
}

func (r *Readiness) Snapshot() ReadinessSnapshot {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return ReadinessSnapshot{
		Storage:      r.storage,
		Keys:         r.keys,
		UpstreamAuth: r.upstreamAuth,
	}
}

func (s ReadinessSnapshot) Ready() bool {
	return s.Storage && s.Keys && s.UpstreamAuth
}

func NewHealthHandler(readiness *Readiness) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		writeJSON(w, http.StatusOK, struct {
			Status string `json:"status"`
		}{Status: "live"})
	})
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
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
		writeJSON(w, status, struct {
			Status string            `json:"status"`
			Checks ReadinessSnapshot `json:"checks"`
		}{Status: name, Checks: snapshot})
	})
	return mux
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
