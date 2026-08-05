package server

import (
	"context"
	"github.com/catgirl-systems/codex-sub-proxy/internal/config"
	"github.com/kataras/iris/v12"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/textproto"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestForwardingParsersAcceptIPv6AndRejectAmbiguousValues(t *testing.T) {
	xff, err := parseXForwardedFor("2001:db8::1, 192.0.2.1")
	if err != nil || len(xff) != 2 || !xff[0].Is6() || !xff[1].Is4() {
		t.Fatalf("IPv6 X-Forwarded-For = %#v, err=%v", xff, err)
	}
	forwarded, err := parseForwardedChain(`for=192.0.2.1,for="[2001:db8::1]"`)
	if err != nil || len(forwarded) != 2 || !forwarded[0].Is4() || !forwarded[1].Is6() {
		t.Fatalf("dual-stack Forwarded = %#v, err=%v", forwarded, err)
	}
	for _, value := range []string{"[2001:db8::1]", "2001:db8::1%en0", "192.0.2.1:443", ""} {
		if _, err := parseXForwardedFor(value); err == nil {
			t.Fatalf("accepted invalid X-Forwarded-For %q", value)
		}
	}
	for _, value := range []string{`for=unknown`, `for="[2001:db8::1]:443"`, `for="[2001:db8::1]\\"`, `for=192.0.2.1;proto=https`} {
		if _, err := parseForwardedChain(value); err == nil {
			t.Fatalf("accepted invalid Forwarded %q", value)
		}
	}
	trusted := []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}
	request := httptest.NewRequest(http.MethodGet, "http://proxy.example/v1/models", nil)
	request.RemoteAddr = "192.0.2.10:443"
	request.Header.Set("X-Forwarded-For", "2001:db8::1")
	client, present, err := resolveTrustedClient(request, trusted)
	if err != nil || !present || !client.Is6() {
		t.Fatalf("trusted IPv6 client = %v/%v, err=%v", client, present, err)
	}
}

func TestCORSPreflightMergesVary(t *testing.T) {
	app := iris.New()
	app.Options("/v1/models", func(ctx iris.Context) {
		ctx.Header("Vary", "Accept-Encoding")
		handled, allowed := handleCORS(ctx, boundaryConfig{
			listener:       "data",
			allowedOrigins: map[string]struct{}{"https://client.example": {}},
			corsMaxAge:     time.Minute,
		}, ctx.Request(), "/v1/models")
		if !handled || !allowed {
			t.Fatal("valid preflight was rejected")
		}
	})
	request := httptest.NewRequest(http.MethodOptions, "http://proxy.example/v1/models", nil)
	if err := app.Build(); err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Origin", "https://client.example")
	request.Header.Set("Access-Control-Request-Method", http.MethodGet)
	request.Header.Set("Access-Control-Request-Headers", "Authorization, Content-Type")
	response := httptest.NewRecorder()
	app.ServeHTTP(response, request)
	if response.Code != http.StatusNoContent {
		t.Fatalf("preflight status = %d", response.Code)
	}
	vary := response.Header().Get("Vary")
	for _, value := range []string{"Accept-Encoding", "Origin", "Access-Control-Request-Method", "Access-Control-Request-Headers"} {
		if !strings.Contains(vary, value) {
			t.Fatalf("Vary %q does not contain %q", vary, value)
		}
	}
}

func TestImagePartMIMERequiresDeclarationAndDetectorAgreement(t *testing.T) {
	png := []byte("\x89PNG\r\n\x1a\n")
	for _, test := range []struct {
		name   string
		header string
		data   []byte
		want   bool
	}{
		{name: "valid", header: "image/png", data: png, want: true},
		{name: "missing", data: png},
		{name: "generic", header: "application/octet-stream", data: png},
		{name: "mismatch", header: "image/jpeg", data: png},
		{name: "html", header: "image/png", data: []byte("<html><svg></svg></html>")},
	} {
		t.Run(test.name, func(t *testing.T) {
			header := &multipart.FileHeader{Header: make(textproto.MIMEHeader)}
			if test.header != "" {
				header.Header.Set("Content-Type", test.header)
			}
			actual, ok := imageMIME(test.data)
			matched := ok && imageDeclaredMIMEMatches(header, actual)
			if matched != test.want {
				t.Fatalf("MIME match = %v, actual=%q detected=%v", matched, actual, ok)
			}
		})
	}
}

type securityRoundTripper func(*http.Request) (*http.Response, error)

func (roundTripper securityRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	return roundTripper(request)
}

func TestTelemetryResponseBodyIsBoundedAndClosable(t *testing.T) {
	closed := &atomic.Bool{}
	transport := telemetryResponseTransport{base: securityRoundTripper(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusInternalServerError, Body: closeTrackingBody{Reader: strings.NewReader(strings.Repeat("secret", telemetryResponseBodyCap)), closed: closed}}, nil
	})}
	response, err := transport.RoundTrip(httptest.NewRequest(http.MethodGet, "http://collector", nil))
	if err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(response.Body)
	if err != nil || len(data) != telemetryResponseBodyCap {
		t.Fatalf("bounded response length = %d, err=%v", len(data), err)
	}
	if err := response.Body.Close(); err != nil {
		t.Fatal(err)
	}
	if !closed.Load() {
		t.Fatal("response body was not closed")
	}
}

type closeTrackingBody struct {
	*strings.Reader
	closed *atomic.Bool
}

func (body closeTrackingBody) Close() error {
	body.closed.Store(true)
	return nil
}

func TestTelemetryExporterDoesNotFollowRedirectOrExposeResponse(t *testing.T) {
	const secret = "collector-response-secret"
	var redirected atomic.Bool
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		redirected.Store(true)
	}))
	defer target.Close()
	collector := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Location", target.URL)
		writer.WriteHeader(http.StatusFound)
		_, _ = io.WriteString(writer, strings.Repeat(secret, 10000))
	}))
	defer collector.Close()
	telemetry, err := NewTelemetry(context.Background(), config.TelemetryConfig{
		Enabled:         true,
		Endpoint:        collector.URL,
		Insecure:        true,
		ExportInterval:  10 * time.Millisecond,
		ShutdownTimeout: 200 * time.Millisecond,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	telemetry.requests.Add(context.Background(), 1)
	err = telemetry.Shutdown(context.Background())
	if redirected.Load() {
		t.Fatal("OTel exporter followed redirect")
	}
	if strings.Contains(errString(err), secret) {
		t.Fatalf("OTel error exposed collector response: %q", err)
	}
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func TestTLSFileChecksRejectSymlinkAndBroadKey(t *testing.T) {
	certificate, privateKey := testCertificate(t)
	directory := t.TempDir()
	certificatePath := directory + "/server.crt"
	keyPath := directory + "/server.key"
	if err := os.WriteFile(certificatePath, certificate, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, privateKey, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readTLSFile(certificatePath, false); err != nil {
		t.Fatalf("normal certificate read failed: %v", err)
	}
	if err := os.Chmod(keyPath, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := readTLSFile(keyPath, true); err == nil {
		t.Fatal("broad private-key permissions accepted")
	}
	linkPath := directory + "/link.crt"
	if err := os.Symlink(certificatePath, linkPath); err != nil {
		t.Fatal(err)
	}
	if _, err := readTLSFile(linkPath, false); err == nil {
		t.Fatal("TLS symlink accepted")
	}
}
