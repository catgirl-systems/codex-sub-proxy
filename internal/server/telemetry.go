package server

import (
	"context"
	"errors"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/catgirl-systems/codex-sub-proxy/internal/config"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	otelmetric "go.opentelemetry.io/otel/metric"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
)

const telemetryServiceName = "codex-sub-proxy"

type Telemetry struct {
	provider    *sdkmetric.MeterProvider
	ready       bool
	mu          sync.Mutex
	closed      bool
	shutdownErr error
	shutdown    sync.Once

	requests      otelmetric.Int64Counter
	requestActive otelmetric.Int64UpDownCounter
	requestTime   otelmetric.Float64Histogram
	status        otelmetric.Int64Counter
	tokens        otelmetric.Int64Counter
	images        otelmetric.Int64Counter
	quotaReject   otelmetric.Int64Counter
	transport     otelmetric.Int64Counter
	fallback      otelmetric.Int64Counter
	journal       otelmetric.Int64Counter
}

// NewTelemetry builds one process-wide meter provider.
func NewTelemetry(ctx context.Context, cfg config.TelemetryConfig, headers map[string]string, buildVersion string) (*Telemetry, error) {
	return newTelemetry(ctx, cfg, headers, buildVersion)
}

func newTelemetry(ctx context.Context, cfg config.TelemetryConfig, headers map[string]string, buildVersion string) (*Telemetry, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if buildVersion == "" {
		buildVersion = "dev"
	}
	telemetry := &Telemetry{}
	resourceValue, err := resource.New(ctx, resource.WithAttributes(
		attribute.String("service.name", telemetryServiceName),
		attribute.String("service.version", buildVersion),
	))
	if err != nil {
		telemetry.provider = sdkmetric.NewMeterProvider()
		return telemetry, err
	}
	var providerOptions []sdkmetric.Option
	if !cfg.Enabled {
		telemetry.provider = sdkmetric.NewMeterProvider(sdkmetric.WithResource(resourceValue))
		telemetry.ready = true
		telemetry.createInstruments()
		return telemetry, nil
	}
	if err := validateTelemetryEndpoint(cfg); err != nil {
		telemetry.provider = sdkmetric.NewMeterProvider(sdkmetric.WithResource(resourceValue))
		telemetry.createInstruments()
		return telemetry, err
	}
	parsedEndpoint, _ := url.Parse(cfg.Endpoint)
	exporterOptions := []otlpmetrichttp.Option{
		otlpmetrichttp.WithEndpoint(parsedEndpoint.Host),
		otlpmetrichttp.WithHeaders(headers),
		otlpmetrichttp.WithTimeout(cfg.ShutdownTimeout),
	}
	if cfg.Insecure {
		exporterOptions = append(exporterOptions, otlpmetrichttp.WithInsecure())
	}
	exporter, err := otlpmetrichttp.New(ctx, exporterOptions...)
	if err != nil {
		telemetry.provider = sdkmetric.NewMeterProvider(sdkmetric.WithResource(resourceValue))
		telemetry.createInstruments()
		return telemetry, err
	}
	reader := sdkmetric.NewPeriodicReader(exporter, sdkmetric.WithInterval(cfg.ExportInterval))
	providerOptions = append(providerOptions, sdkmetric.WithReader(reader), sdkmetric.WithResource(resourceValue))
	telemetry.provider = sdkmetric.NewMeterProvider(providerOptions...)
	telemetry.ready = true
	telemetry.createInstruments()
	return telemetry, nil
}

func validateTelemetryEndpoint(cfg config.TelemetryConfig) error {
	parsed, err := url.Parse(cfg.Endpoint)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.User != nil {
		return errors.New("telemetry endpoint is invalid")
	}
	if parsed.Scheme == "https" {
		if cfg.Insecure {
			return errors.New("insecure telemetry transport is invalid for HTTPS")
		}
		return nil
	}
	if parsed.Scheme != "http" || !cfg.Insecure {
		return errors.New("telemetry endpoint requires HTTPS")
	}
	host := strings.ToLower(parsed.Hostname())
	if host == "localhost" {
		return nil
	}
	ip, err := netip.ParseAddr(host)
	if err != nil || !ip.IsLoopback() {
		return errors.New("insecure telemetry endpoint must use loopback")
	}
	return nil
}

func (t *Telemetry) createInstruments() {
	if t == nil || t.provider == nil {
		return
	}
	meter := t.provider.Meter(telemetryServiceName)
	t.requests, _ = meter.Int64Counter("csp.server.requests")
	t.requestActive, _ = meter.Int64UpDownCounter("csp.server.active_requests")
	t.requestTime, _ = meter.Float64Histogram("csp.server.request_duration_ms")
	t.status, _ = meter.Int64Counter("csp.server.responses")
	t.tokens, _ = meter.Int64Counter("csp.server.tokens")
	t.images, _ = meter.Int64Counter("csp.server.images")
	t.quotaReject, _ = meter.Int64Counter("csp.server.quota_rejections")
	t.transport, _ = meter.Int64Counter("csp.server.upstream_transport")
	t.fallback, _ = meter.Int64Counter("csp.server.fallbacks")
	t.journal, _ = meter.Int64Counter("csp.server.journal_events")
}

func (t *Telemetry) Ready() bool {
	return t != nil && t.ready
}

func (t *Telemetry) beginRequest(ctx context.Context, listener, route, method string) {
	if t == nil || t.requestActive == nil {
		return
	}
	t.requestActive.Add(ctx, 1, otelmetric.WithAttributes(
		attribute.String("listener", boundedEnum(listener, "data", "admin")),
		attribute.String("route", telemetryRoute(route)),
		attribute.String("method", telemetryMethod(method)),
	))
}

func (t *Telemetry) observeRequest(ctx context.Context, listener, route, method string, status int, duration time.Duration, responseBytes int, transport string) {
	if t == nil || t.requests == nil {
		return
	}
	activeAttrs := otelmetric.WithAttributes(
		attribute.String("listener", boundedEnum(listener, "data", "admin")),
		attribute.String("route", telemetryRoute(route)),
		attribute.String("method", telemetryMethod(method)),
	)
	attrs := otelmetric.WithAttributes(
		attribute.String("listener", boundedEnum(listener, "data", "admin")),
		attribute.String("route", telemetryRoute(route)),
		attribute.String("method", telemetryMethod(method)),
		attribute.String("status_class", statusClass(status)),
	)
	t.requests.Add(ctx, 1, attrs)
	t.status.Add(ctx, 1, attrs)
	t.requestTime.Record(ctx, float64(duration)/float64(time.Millisecond), attrs)
	if t.requestActive != nil {
		t.requestActive.Add(ctx, -1, activeAttrs)
	}
	if transport != "" && transport != "none" && t.transport != nil {
		t.transport.Add(ctx, 1, otelmetric.WithAttributes(attribute.String("transport", boundedEnum(transport, "http", "websocket", "sse", "none"))))
	}
	_ = responseBytes
}
func (t *Telemetry) RecordTokens(ctx context.Context, route, kind string, count int64) {
	if t == nil || t.tokens == nil || count < 0 {
		return
	}
	t.tokens.Add(ctx, count, otelmetric.WithAttributes(attribute.String("route", telemetryRoute(route)), attribute.String("kind", boundedEnum(kind, "input", "output", "cached", "reasoning"))))
}

func (t *Telemetry) RecordImages(ctx context.Context, route string, count int64) {
	if t == nil || t.images == nil || count < 0 {
		return
	}
	t.images.Add(ctx, count, otelmetric.WithAttributes(attribute.String("route", telemetryRoute(route))))
}

func (t *Telemetry) RecordQuotaRejection(ctx context.Context, route string) {
	if t == nil || t.quotaReject == nil {
		return
	}
	t.quotaReject.Add(ctx, 1, otelmetric.WithAttributes(attribute.String("route", telemetryRoute(route))))
}

func (t *Telemetry) RecordFallback(ctx context.Context, route string) {
	if t == nil || t.fallback == nil {
		return
	}
	t.fallback.Add(ctx, 1, otelmetric.WithAttributes(attribute.String("route", telemetryRoute(route))))
}

func (t *Telemetry) RecordJournal(ctx context.Context, event string) {
	if t == nil || t.journal == nil {
		return
	}
	t.journal.Add(ctx, 1, otelmetric.WithAttributes(attribute.String("event", boundedEnum(event, "pending", "sweep_failure"))))
}

func (t *Telemetry) Shutdown(ctx context.Context) error {
	if t == nil || t.provider == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	t.shutdown.Do(func() {
		t.mu.Lock()
		t.closed = true
		t.mu.Unlock()
		err := t.provider.Shutdown(ctx)
		t.mu.Lock()
		t.shutdownErr = err
		t.mu.Unlock()
	})
	t.mu.Lock()
	err := t.shutdownErr
	t.mu.Unlock()
	return err
}

func telemetryRoute(route string) string {
	switch route {
	case "/healthz", "/readyz", "/v1/models", "/v1/chat/completions", "/v1/responses", "/v1/images/generations", "/v1/images/edits":
		return route
	default:
		return "admin_operation"
	}
}

func telemetryMethod(method string) string {
	return safeMethod(method)
}

func boundedEnum(value string, allowed ...string) string {
	for _, item := range allowed {
		if value == item {
			return value
		}
	}
	return "other"
}
