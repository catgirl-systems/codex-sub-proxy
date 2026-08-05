package server

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/catgirl-systems/codex-sub-proxy/internal/config"
)

func TestTelemetryOTLPHTTPExporterCapture(t *testing.T) {
	var requests atomic.Int32
	var payload atomic.Value
	exporterServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		body, _ := io.ReadAll(r.Body)
		payload.Store(string(body))
		w.WriteHeader(http.StatusOK)
	}))
	defer exporterServer.Close()

	telemetryConfig := config.TelemetryConfig{
		Enabled:         true,
		Endpoint:        exporterServer.URL,
		Insecure:        true,
		ExportInterval:  25 * time.Millisecond,
		ShutdownTimeout: time.Second,
	}
	telemetry, err := NewTelemetry(context.Background(), telemetryConfig, nil, "test")
	if err != nil {
		t.Fatalf("new telemetry: %v", err)
	}
	telemetry.RecordTokens(context.Background(), "/v1/responses", "input", 3)
	if err := telemetry.Shutdown(context.Background()); err != nil {
		t.Fatalf("shutdown telemetry: %v", err)
	}
	if requests.Load() == 0 {
		t.Fatal("OTLP exporter did not send a capture request")
	}
	captured, _ := payload.Load().(string)
	if strings.Contains(captured, "Bearer") || strings.Contains(captured, "secret") {
		t.Fatalf("captured metrics body contains secret material: %q", captured)
	}
}
