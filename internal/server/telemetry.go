package server

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net/http"
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
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	"go.opentelemetry.io/otel/sdk/resource"
)

const (
	telemetryServiceName     = "codex-sub-proxy"
	telemetryResponseBodyCap = 64 << 10
	telemetryHTTPTimeout     = time.Minute
)

var (
	errTelemetrySetup    = errors.New("telemetry setup failed")
	errTelemetryExport   = errors.New("telemetry export failed")
	errTelemetryFlush    = errors.New("telemetry flush failed")
	errTelemetryShutdown = errors.New("telemetry shutdown failed")
)

type Telemetry struct {
	provider    *sdkmetric.MeterProvider
	shutdownErr error
	shutdown    sync.Once

	requests      otelmetric.Int64Counter
	requestActive otelmetric.Int64UpDownCounter
	requestTime   otelmetric.Float64Histogram
	status        otelmetric.Int64Counter
	transport     otelmetric.Int64Counter
}

// NewTelemetry builds one process-wide meter provider.
func NewTelemetry(ctx context.Context, cfg config.TelemetryConfig, headers map[string]string) (*Telemetry, error) {
	return newTelemetry(ctx, cfg, headers)
}

func newTelemetry(ctx context.Context, cfg config.TelemetryConfig, headers map[string]string) (*Telemetry, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	telemetry := &Telemetry{}
	resourceValue, err := resource.New(ctx, resource.WithAttributes(
		attribute.String("service.name", telemetryServiceName),
	))
	if err != nil {
		telemetry.provider = sdkmetric.NewMeterProvider()
		return telemetry, errTelemetrySetup
	}
	if !cfg.Enabled {
		telemetry.provider = sdkmetric.NewMeterProvider(sdkmetric.WithResource(resourceValue))
		telemetry.createInstruments()
		return telemetry, nil
	}
	if err := validateTelemetryEndpoint(cfg); err != nil {
		telemetry.provider = sdkmetric.NewMeterProvider(sdkmetric.WithResource(resourceValue))
		telemetry.createInstruments()
		return telemetry, err
	}
	parsedEndpoint, _ := url.Parse(cfg.Endpoint)
	transport := telemetryHTTPTransport()
	timeout := cfg.ShutdownTimeout
	if timeout <= 0 || timeout > telemetryHTTPTimeout {
		timeout = telemetryHTTPTimeout
	}
	httpClient := &http.Client{
		Transport: transport,
		Timeout:   timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	exporterOptions := []otlpmetrichttp.Option{
		otlpmetrichttp.WithEndpoint(parsedEndpoint.Host),
		otlpmetrichttp.WithHeaders(headers),
		otlpmetrichttp.WithHTTPClient(httpClient),
	}
	if cfg.Insecure {
		exporterOptions = append(exporterOptions, otlpmetrichttp.WithInsecure())
	}
	exporter, err := otlpmetrichttp.New(ctx, exporterOptions...)
	if err != nil {
		telemetry.provider = sdkmetric.NewMeterProvider(sdkmetric.WithResource(resourceValue))
		telemetry.createInstruments()
		return telemetry, errTelemetrySetup
	}
	reader := sdkmetric.NewPeriodicReader(&redactingMetricExporter{inner: exporter}, sdkmetric.WithInterval(cfg.ExportInterval))
	telemetry.provider = sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader), sdkmetric.WithResource(resourceValue))
	telemetry.createInstruments()
	return telemetry, nil
}

func telemetryHTTPTransport() http.RoundTripper {
	if transport, ok := http.DefaultTransport.(*http.Transport); ok {
		clone := transport.Clone()
		if clone.TLSClientConfig == nil {
			clone.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
		} else {
			clone.TLSClientConfig = clone.TLSClientConfig.Clone()
			if clone.TLSClientConfig.MinVersion == 0 {
				clone.TLSClientConfig.MinVersion = tls.VersionTLS12
			}
		}
		return &telemetryResponseTransport{base: clone}
	}
	return &telemetryResponseTransport{base: http.DefaultTransport}
}

type telemetryResponseTransport struct {
	base http.RoundTripper
}

func (transport *telemetryResponseTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	response, err := transport.base.RoundTrip(request)
	if err != nil || response == nil || response.Body == nil {
		return response, err
	}
	response.Body = &telemetryResponseBody{
		reader: io.LimitReader(response.Body, telemetryResponseBodyCap),
		closer: response.Body,
	}
	return response, nil
}

type telemetryResponseBody struct {
	reader io.Reader
	closer io.Closer
}

func (body *telemetryResponseBody) Read(p []byte) (int, error) {
	return body.reader.Read(p)
}

func (body *telemetryResponseBody) Close() error {
	return body.closer.Close()
}

type redactingMetricExporter struct {
	inner sdkmetric.Exporter
}

func (exporter *redactingMetricExporter) Temporality(kind sdkmetric.InstrumentKind) metricdata.Temporality {
	return exporter.inner.Temporality(kind)
}

func (exporter *redactingMetricExporter) Aggregation(kind sdkmetric.InstrumentKind) sdkmetric.Aggregation {
	return exporter.inner.Aggregation(kind)
}

func (exporter *redactingMetricExporter) Export(ctx context.Context, data *metricdata.ResourceMetrics) error {
	if err := exporter.inner.Export(ctx, data); err != nil {
		return errTelemetryExport
	}
	return nil
}

func (exporter *redactingMetricExporter) ForceFlush(ctx context.Context) error {
	if err := exporter.inner.ForceFlush(ctx); err != nil {
		return errTelemetryFlush
	}
	return nil
}

func (exporter *redactingMetricExporter) Shutdown(ctx context.Context) error {
	if err := exporter.inner.Shutdown(ctx); err != nil {
		return errTelemetryShutdown
	}
	return nil
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
	t.transport, _ = meter.Int64Counter("csp.server.upstream_transport")
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

func (t *Telemetry) observeRequest(ctx context.Context, listener, route, method string, status int, duration time.Duration, transport string) {
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
}

func (t *Telemetry) Shutdown(ctx context.Context) error {
	if t == nil || t.provider == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	t.shutdown.Do(func() {
		t.shutdownErr = t.provider.Shutdown(ctx)
	})
	return t.shutdownErr
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
