package codex

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

func TestResponsesTransportWebSocketSuccessPreservesEvents(t *testing.T) {
	var sseRequests atomic.Int32
	server := newTransportServer(t, func(writer http.ResponseWriter, request *http.Request) {
		if request.Method == http.MethodPost {
			sseRequests.Add(1)
			http.Error(writer, "unexpected SSE fallback", http.StatusInternalServerError)
			return
		}
		connection, err := transportUpgrader.Upgrade(writer, request, nil)
		if err != nil {
			return
		}
		defer connection.Close()
		if _, _, err := connection.ReadMessage(); err != nil {
			return
		}
		for _, frame := range transportWebSocketFixture(t) {
			if err := connection.WriteMessage(websocket.TextMessage, frame); err != nil {
				return
			}
		}
		_ = connection.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""), time.Now().Add(time.Second))
	})
	defer server.Close()

	transport := newTestResponsesTransport(t, server, ResponsesTransportWebSocketPreferred)
	result, err := transport.Do(context.Background(), CodexResponseRequest{Model: "gpt-5.6-sol", Stream: true})
	if err != nil {
		t.Fatalf("transport.Do: %v", err)
	}
	if len(result.Events) != 6 || result.TerminalType != CodexEventResponseDone || result.Response == nil {
		t.Fatalf("result = %#v", result)
	}
	if sseRequests.Load() != 0 {
		t.Fatalf("SSE requests = %d, want 0", sseRequests.Load())
	}
}

func TestResponsesTransportWebSocketWireContract(t *testing.T) {
	messageReceived := make(chan string, 1)
	betaReceived := make(chan string, 1)
	server := newTransportServer(t, func(writer http.ResponseWriter, request *http.Request) {
		betaReceived <- request.Header.Get(BetaHeader)
		connection, err := transportUpgrader.Upgrade(writer, request, nil)
		if err != nil {
			return
		}
		defer connection.Close()
		_, message, err := connection.ReadMessage()
		if err != nil {
			return
		}
		messageReceived <- string(message)
		_ = connection.WriteMessage(websocket.TextMessage, []byte(`{"type":"response.done","response":{"status":"completed"}}`))
	})
	defer server.Close()

	transport := newTestResponsesTransport(t, server, ResponsesTransportWebSocketPreferred)
	request := CodexResponseRequest{Model: "gpt-5.6-sol", Stream: true}
	if _, err := transport.Do(context.Background(), request); err != nil {
		t.Fatalf("transport.Do: %v", err)
	}
	select {
	case got := <-betaReceived:
		if got != responsesWebSocketBeta {
			t.Fatalf("OpenAI-Beta = %q, want %q", got, responsesWebSocketBeta)
		}
	case <-time.After(time.Second):
		t.Fatal("WebSocket handshake was not received")
	}
	select {
	case got := <-messageReceived:
		want := `{"type":"response.create","model":"gpt-5.6-sol","stream":true}`
		if got != want {
			t.Fatalf("WebSocket request = %s, want %s", got, want)
		}
	case <-time.After(time.Second):
		t.Fatal("WebSocket request was not received")
	}
}

func TestResponsesTransportFallsBackOnUnsupportedWebSocket(t *testing.T) {
	var sseRequests atomic.Int32
	server := newTransportServer(t, func(writer http.ResponseWriter, request *http.Request) {
		if request.Method == http.MethodGet {
			writer.Header().Set("Content-Type", "application/json")
			writer.WriteHeader(http.StatusUpgradeRequired)
			_, _ = writer.Write([]byte(`{"error":{"code":"websocket_not_supported"}}`))
			return
		}
		sseRequests.Add(1)
		writer.Header().Set("Content-Type", "text/event-stream")
		writer.WriteHeader(http.StatusOK)
		_, _ = writer.Write(transportSSEFixture(t))
	})
	defer server.Close()

	transport := newTestResponsesTransport(t, server, ResponsesTransportWebSocketPreferred)
	result, err := transport.Do(context.Background(), CodexResponseRequest{Model: "gpt-5.6-sol", Stream: true})
	if err != nil {
		t.Fatalf("transport.Do: %v", err)
	}
	if result.TerminalType != CodexEventResponseCompleted || sseRequests.Load() != 1 {
		t.Fatalf("result = %#v, SSE requests = %d", result, sseRequests.Load())
	}
}

func TestResponsesTransportFallsBackAfterReplaySafeWebSocketEvents(t *testing.T) {
	var sseRequests atomic.Int32
	sseBodyReceived := make(chan []byte, 1)
	server := newTransportServer(t, func(writer http.ResponseWriter, request *http.Request) {
		if request.Method == http.MethodGet {
			connection, err := transportUpgrader.Upgrade(writer, request, nil)
			if err != nil {
				return
			}
			defer connection.Close()
			if _, _, err := connection.ReadMessage(); err != nil {
				return
			}
			frames := [][]byte{
				[]byte(`{"type":"response.created","response":{"status":"in_progress"}}`),
				[]byte(`{"type":"response.metadata","metadata":{"state":"ready"}}`),
			}
			for _, frame := range frames {
				if err := connection.WriteMessage(websocket.TextMessage, frame); err != nil {
					return
				}
			}
			_ = connection.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""), time.Now().Add(time.Second))
			return
		}
		sseRequests.Add(1)
		body, err := io.ReadAll(request.Body)
		if err == nil {
			sseBodyReceived <- body
		}
		writer.Header().Set("Content-Type", "text/event-stream")
		writer.WriteHeader(http.StatusOK)
		_, _ = writer.Write(transportSSEFixture(t))
	})
	defer server.Close()

	transport := newTestResponsesTransport(t, server, ResponsesTransportWebSocketPreferred)
	request := CodexResponseRequest{Model: "gpt-5.6-sol", Stream: true}
	result, err := transport.Do(context.Background(), request)
	if err != nil {
		t.Fatalf("transport.Do: %v", err)
	}
	if result.TerminalType != CodexEventResponseCompleted || sseRequests.Load() != 1 {
		t.Fatalf("result = %#v, SSE requests = %d", result, sseRequests.Load())
	}
	select {
	case got := <-sseBodyReceived:
		want, err := json.Marshal(request)
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != string(want) {
			t.Fatalf("SSE request = %s, want %s", got, want)
		}
	case <-time.After(time.Second):
		t.Fatal("SSE request was not received")
	}
}

func TestResponsesTransportDoesNotReplayAfterPartialWebSocketOutput(t *testing.T) {
	var sseRequests atomic.Int32
	server := newTransportServer(t, func(writer http.ResponseWriter, request *http.Request) {
		if request.Method == http.MethodPost {
			sseRequests.Add(1)
			writer.Header().Set("Content-Type", "text/event-stream")
			writer.WriteHeader(http.StatusOK)
			_, _ = writer.Write(transportSSEFixture(t))
			return
		}
		connection, err := transportUpgrader.Upgrade(writer, request, nil)
		if err != nil {
			return
		}
		if _, _, err := connection.ReadMessage(); err == nil {
			frame := []byte(`{"type":"response.output_text.delta","sequence_number":1,"delta":"partial"}`)
			_ = connection.WriteMessage(websocket.TextMessage, frame)
		}
		_ = connection.Close()
	})
	defer server.Close()

	transport := newTestResponsesTransport(t, server, ResponsesTransportWebSocketPreferred)
	_, err := transport.Do(context.Background(), CodexResponseRequest{Model: "gpt-5.6-sol", Stream: true})
	if err == nil || !errors.Is(err, ErrCodexStreamAbruptClose) {
		t.Fatalf("error = %v, want abrupt close", err)
	}
	if sseRequests.Load() != 0 {
		t.Fatalf("SSE requests = %d, want 0", sseRequests.Load())
	}
}

func TestResponsesTransportDoesNotReplayAfterWebSocketToolOutput(t *testing.T) {
	var sseRequests atomic.Int32
	server := newTransportServer(t, func(writer http.ResponseWriter, request *http.Request) {
		if request.Method == http.MethodPost {
			sseRequests.Add(1)
			writer.Header().Set("Content-Type", "text/event-stream")
			writer.WriteHeader(http.StatusOK)
			_, _ = writer.Write(transportSSEFixture(t))
			return
		}
		connection, err := transportUpgrader.Upgrade(writer, request, nil)
		if err != nil {
			return
		}
		defer connection.Close()
		if _, _, err := connection.ReadMessage(); err != nil {
			return
		}
		frame := []byte(`{"type":"response.output_item.added","item":{"type":"function_call","name":"lookup","arguments":"{}"}}`)
		if err := connection.WriteMessage(websocket.TextMessage, frame); err != nil {
			return
		}
		_ = connection.Close()
	})
	defer server.Close()

	transport := newTestResponsesTransport(t, server, ResponsesTransportWebSocketPreferred)
	_, err := transport.Do(context.Background(), CodexResponseRequest{Model: "gpt-5.6-sol", Stream: true})
	if err == nil || !errors.Is(err, ErrCodexStreamAbruptClose) {
		t.Fatalf("error = %v, want abrupt close", err)
	}
	if sseRequests.Load() != 0 {
		t.Fatalf("SSE requests = %d, want 0", sseRequests.Load())
	}
}

func TestResponsesTransportCancellationClosesWebSocket(t *testing.T) {
	requestReceived := make(chan struct{})
	server := newTransportServer(t, func(writer http.ResponseWriter, request *http.Request) {
		connection, err := transportUpgrader.Upgrade(writer, request, nil)
		if err != nil {
			return
		}
		defer connection.Close()
		if _, _, err := connection.ReadMessage(); err != nil {
			return
		}
		close(requestReceived)
		_, _, _ = connection.ReadMessage()
	})
	defer server.Close()

	transport := newTestResponsesTransport(t, server, ResponsesTransportWebSocketPreferred)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errorsReturned := make(chan error, 1)
	go func() {
		_, err := transport.Do(ctx, CodexResponseRequest{Model: "gpt-5.6-sol", Stream: true})
		errorsReturned <- err
	}()
	select {
	case <-requestReceived:
	case <-time.After(time.Second):
		t.Fatal("WebSocket request was not received")
	}
	cancel()
	select {
	case err := <-errorsReturned:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("error = %v, want context cancellation", err)
		}
	case <-time.After(time.Second):
		t.Fatal("transport did not stop after cancellation")
	}
}

func TestResponsesTransportRejectsOversizeWebSocketMessage(t *testing.T) {
	var sseRequests atomic.Int32
	server := newTransportServer(t, func(writer http.ResponseWriter, request *http.Request) {
		if request.Method == http.MethodPost {
			sseRequests.Add(1)
			return
		}
		connection, err := transportUpgrader.Upgrade(writer, request, nil)
		if err != nil {
			return
		}
		defer connection.Close()
		if _, _, err := connection.ReadMessage(); err != nil {
			return
		}
		_ = connection.WriteMessage(websocket.TextMessage, []byte(strings.Repeat("x", maxCodexStreamLineBytes+1)))
	})
	defer server.Close()

	transport := newTestResponsesTransport(t, server, ResponsesTransportWebSocketPreferred)
	_, err := transport.Do(context.Background(), CodexResponseRequest{Model: "gpt-5.6-sol", Stream: true})
	if !errors.Is(err, ErrCodexStreamMalformed) {
		t.Fatalf("error = %v, want malformed stream", err)
	}
	if sseRequests.Load() != 0 {
		t.Fatalf("SSE requests = %d, want 0", sseRequests.Load())
	}
}

func TestResponsesTransportCloseCodeFallbackPolicy(t *testing.T) {
	for _, test := range []struct {
		name        string
		code        int
		wantSSE     bool
		wantSuccess bool
	}{
		{name: "unsupported data", code: websocket.CloseUnsupportedData, wantSSE: true, wantSuccess: true},
		{name: "policy violation", code: websocket.ClosePolicyViolation, wantSSE: false, wantSuccess: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			var sseRequests atomic.Int32
			server := newTransportServer(t, func(writer http.ResponseWriter, request *http.Request) {
				if request.Method == http.MethodPost {
					sseRequests.Add(1)
					writer.Header().Set("Content-Type", "text/event-stream")
					writer.WriteHeader(http.StatusOK)
					_, _ = writer.Write(transportSSEFixture(t))
					return
				}
				connection, err := transportUpgrader.Upgrade(writer, request, nil)
				if err != nil {
					return
				}
				defer connection.Close()
				if _, _, err := connection.ReadMessage(); err != nil {
					return
				}
				_ = connection.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(test.code, ""), time.Now().Add(time.Second))
			})
			defer server.Close()

			transport := newTestResponsesTransport(t, server, ResponsesTransportWebSocketPreferred)
			result, err := transport.Do(context.Background(), CodexResponseRequest{Model: "gpt-5.6-sol", Stream: true})
			if test.wantSuccess {
				if err != nil || result.TerminalType != CodexEventResponseCompleted {
					t.Fatalf("result = %#v, error = %v", result, err)
				}
			} else if err == nil {
				t.Fatal("policy close unexpectedly succeeded")
			}
			wantRequests := int32(0)
			if test.wantSSE {
				wantRequests = 1
			}
			if sseRequests.Load() != wantRequests {
				t.Fatalf("SSE requests = %d, want %d", sseRequests.Load(), wantRequests)
			}
		})
	}
}

func TestResponsesTransportErrorsDoNotExposeSecrets(t *testing.T) {
	secret := "transport-secret-value"
	server := newTransportServer(t, func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		writer.WriteHeader(http.StatusBadRequest)
		_, _ = writer.Write([]byte(`{"error":{"message":"` + secret + `"}}`))
	})
	defer server.Close()

	transport := newTestResponsesTransport(t, server, ResponsesTransportWebSocketPreferred)
	_, err := transport.Do(context.Background(), CodexResponseRequest{Model: "gpt-5.6-sol", Stream: true})
	if err == nil {
		t.Fatal("transport returned no error")
	}
	if strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), "transport-token") {
		t.Fatalf("error exposes secret: %v", err)
	}
}

func TestResponsesTransportUsesHTTPTransportProxy(t *testing.T) {
	var proxyRequests atomic.Int32
	proxy := newTransportConnectProxy(t, &proxyRequests)
	defer proxy.Close()
	proxyURL, err := url.Parse(proxy.URL)
	if err != nil {
		t.Fatal(err)
	}

	server := newTransportServer(t, func(writer http.ResponseWriter, request *http.Request) {
		connection, err := transportUpgrader.Upgrade(writer, request, nil)
		if err != nil {
			return
		}
		defer connection.Close()
		if _, _, err := connection.ReadMessage(); err != nil {
			return
		}
		_ = connection.WriteMessage(websocket.TextMessage, []byte(`{"type":"response.done","response":{"status":"completed"}}`))
	})
	defer server.Close()

	httpTransport := server.Client().Transport.(*http.Transport).Clone()
	httpTransport.Proxy = http.ProxyURL(proxyURL)
	client := &http.Client{Transport: httpTransport}
	transport := newTestResponsesTransportWithClient(t, server, ResponsesTransportWebSocketPreferred, client)
	if _, err := transport.Do(context.Background(), CodexResponseRequest{Model: "gpt-5.6-sol", Stream: true}); err != nil {
		t.Fatalf("transport.Do: %v", err)
	}
	if proxyRequests.Load() == 0 {
		t.Fatal("WebSocket did not use the configured HTTP proxy")
	}
}

func TestResponsesTransportUsesCustomTLSRoots(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		connection, err := transportUpgrader.Upgrade(writer, request, nil)
		if err != nil {
			return
		}
		defer connection.Close()
		if _, _, err := connection.ReadMessage(); err != nil {
			return
		}
		_ = connection.WriteMessage(websocket.TextMessage, []byte(`{"type":"response.done","response":{"status":"completed"}}`))
	}))
	defer server.Close()

	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	httpTransport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots}}
	client := &http.Client{Transport: httpTransport}
	transport := newTestResponsesTransportWithClient(t, server, ResponsesTransportWebSocketPreferred, client)
	if _, err := transport.Do(context.Background(), CodexResponseRequest{Model: "gpt-5.6-sol", Stream: true}); err != nil {
		t.Fatalf("transport.Do with custom TLS roots: %v", err)
	}
}

func TestResponsesTransportConditionalProxyBypassUsesCustomTLS(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		connection, err := transportUpgrader.Upgrade(writer, request, nil)
		if err != nil {
			return
		}
		defer connection.Close()
		if _, _, err := connection.ReadMessage(); err != nil {
			return
		}
		_ = connection.WriteMessage(websocket.TextMessage, []byte(`{"type":"response.done","response":{"status":"completed"}}`))
	}))
	defer server.Close()

	httpTransport := server.Client().Transport.(*http.Transport).Clone()
	var proxyCalls atomic.Int32
	var tlsCalls atomic.Int32
	var wrongScheme atomic.Bool
	httpTransport.Proxy = func(request *http.Request) (*url.URL, error) {
		proxyCalls.Add(1)
		if request.URL == nil || request.URL.Scheme != "https" {
			wrongScheme.Store(true)
		}
		return nil, nil
	}
	tlsConfig := httpTransport.TLSClientConfig.Clone()
	httpTransport.DialTLSContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		tlsCalls.Add(1)
		return (&tls.Dialer{NetDialer: &net.Dialer{}, Config: tlsConfig}).DialContext(ctx, network, address)
	}
	client := &http.Client{Transport: httpTransport}
	transport := newTestResponsesTransportWithClient(t, server, ResponsesTransportWebSocketPreferred, client)

	if _, err := transport.Do(context.Background(), CodexResponseRequest{Model: "gpt-5.6-sol", Stream: true}); err != nil {
		t.Fatalf("transport.Do with conditional proxy bypass: %v", err)
	}
	if proxyCalls.Load() != 1 {
		t.Fatalf("proxy callback calls = %d, want 1", proxyCalls.Load())
	}
	if wrongScheme.Load() {
		t.Fatal("proxy callback received a non-HTTP request scheme")
	}
	if tlsCalls.Load() != 1 {
		t.Fatalf("custom TLS dialer calls = %d, want 1", tlsCalls.Load())
	}
}

func TestResponsesTransportConditionalProxyUsesProxyRoute(t *testing.T) {
	var proxyRequests atomic.Int32
	proxy := newTransportConnectProxy(t, &proxyRequests)
	defer proxy.Close()
	proxyURL, err := url.Parse(proxy.URL)
	if err != nil {
		t.Fatal(err)
	}

	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		connection, err := transportUpgrader.Upgrade(writer, request, nil)
		if err != nil {
			return
		}
		defer connection.Close()
		if _, _, err := connection.ReadMessage(); err != nil {
			return
		}
		_ = connection.WriteMessage(websocket.TextMessage, []byte(`{"type":"response.done","response":{"status":"completed"}}`))
	}))
	defer server.Close()

	httpTransport := server.Client().Transport.(*http.Transport).Clone()
	var proxyCalls atomic.Int32
	var tlsCalls atomic.Int32
	httpTransport.Proxy = func(request *http.Request) (*url.URL, error) {
		proxyCalls.Add(1)
		return proxyURL, nil
	}
	httpTransport.DialTLSContext = func(context.Context, string, string) (net.Conn, error) {
		tlsCalls.Add(1)
		return nil, errors.New("origin TLS dialer must not be used for a proxy route")
	}
	client := &http.Client{Transport: httpTransport}
	transport := newTestResponsesTransportWithClient(t, server, ResponsesTransportWebSocketPreferred, client)

	if _, err := transport.Do(context.Background(), CodexResponseRequest{Model: "gpt-5.6-sol", Stream: true}); err != nil {
		t.Fatalf("transport.Do with conditional proxy route: %v", err)
	}
	if proxyCalls.Load() != 1 {
		t.Fatalf("proxy callback calls = %d, want 1", proxyCalls.Load())
	}
	if proxyRequests.Load() == 0 {
		t.Fatal("WebSocket did not use the configured proxy")
	}
	if tlsCalls.Load() != 0 {
		t.Fatalf("custom TLS dialer calls = %d, want 0 for a proxy route", tlsCalls.Load())
	}
}

func TestResponsesTransportConditionalProxyError(t *testing.T) {
	var requests atomic.Int32
	server := newTransportServer(t, func(writer http.ResponseWriter, request *http.Request) {
		requests.Add(1)
		http.Error(writer, "unexpected request", http.StatusInternalServerError)
	})
	defer server.Close()

	proxyErr := errors.New("conditional proxy failure")
	httpTransport := server.Client().Transport.(*http.Transport).Clone()
	var proxyCalls atomic.Int32
	httpTransport.Proxy = func(*http.Request) (*url.URL, error) {
		proxyCalls.Add(1)
		return nil, proxyErr
	}
	client := &http.Client{Transport: httpTransport}
	transport := newTestResponsesTransportWithClient(t, server, ResponsesTransportWebSocketPreferred, client)

	_, err := transport.Do(context.Background(), CodexResponseRequest{Model: "gpt-5.6-sol", Stream: true})
	if !errors.Is(err, proxyErr) {
		t.Fatalf("transport.Do error = %v, want proxy callback error", err)
	}
	if !strings.Contains(err.Error(), "codex proxy callback") {
		t.Fatalf("transport.Do error = %v, want proxy callback context", err)
	}
	if proxyCalls.Load() != 1 {
		t.Fatalf("proxy callback calls = %d, want 1", proxyCalls.Load())
	}
	if requests.Load() != 0 {
		t.Fatalf("fallback requests = %d, want 0", requests.Load())
	}
}

func TestResponsesTransportUsesEnvironmentProxy(t *testing.T) {
	var proxyRequests atomic.Int32
	proxy := newTransportConnectProxy(t, &proxyRequests)
	defer proxy.Close()
	t.Setenv("HTTP_PROXY", proxy.URL)
	t.Setenv("HTTPS_PROXY", proxy.URL)
	t.Setenv("NO_PROXY", "")

	server := newTransportServer(t, func(writer http.ResponseWriter, request *http.Request) {
		connection, err := transportUpgrader.Upgrade(writer, request, nil)
		if err != nil {
			return
		}
		defer connection.Close()
		if _, _, err := connection.ReadMessage(); err != nil {
			return
		}
		_ = connection.WriteMessage(websocket.TextMessage, []byte(`{"type":"response.done","response":{"status":"completed"}}`))
	})
	defer server.Close()

	httpTransport := server.Client().Transport.(*http.Transport).Clone()
	httpTransport.Proxy = func(*http.Request) (*url.URL, error) {
		return url.Parse(os.Getenv("HTTP_PROXY"))
	}
	client := &http.Client{Transport: httpTransport}
	transport := newTestResponsesTransportWithClient(t, server, ResponsesTransportWebSocketPreferred, client)
	if _, err := transport.Do(context.Background(), CodexResponseRequest{Model: "gpt-5.6-sol", Stream: true}); err != nil {
		t.Fatalf("transport.Do: %v", err)
	}
	if proxyRequests.Load() == 0 {
		t.Fatal("WebSocket did not use the proxy from the environment")
	}
}

func newTransportConnectProxy(t *testing.T, requests *atomic.Int32) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodConnect {
			http.Error(writer, "CONNECT required", http.StatusMethodNotAllowed)
			return
		}
		target, err := net.Dial("tcp", request.Host)
		if err != nil {
			http.Error(writer, "proxy dial failed", http.StatusBadGateway)
			return
		}
		hijacker, ok := writer.(http.Hijacker)
		if !ok {
			_ = target.Close()
			http.Error(writer, "hijacking is not supported", http.StatusInternalServerError)
			return
		}
		client, buffered, err := hijacker.Hijack()
		if err != nil {
			_ = target.Close()
			return
		}
		requests.Add(1)
		defer client.Close()
		defer target.Close()
		if _, err := buffered.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
			return
		}
		if err := buffered.Flush(); err != nil {
			return
		}
		go func() {
			_, _ = io.Copy(target, client)
			_ = target.Close()
		}()
		_, _ = io.Copy(client, target)
	}))
}

var transportUpgrader = websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}

func newTransportServer(t *testing.T, handler http.HandlerFunc) *httptest.Server {
	t.Helper()
	return httptest.NewServer(handler)
}

func newTestResponsesTransport(t *testing.T, server *httptest.Server, policy ResponsesTransportPolicy) *ResponsesTransport {
	t.Helper()
	return newTestResponsesTransportWithClient(t, server, policy, server.Client())
}

func newTestResponsesTransportWithClient(t *testing.T, server *httptest.Server, policy ResponsesTransportPolicy, client *http.Client) *ResponsesTransport {
	t.Helper()
	keys := testCredentialKeys(t)
	credentialPath := t.TempDir() + "/credential.enc"
	if err := SaveCredential(credentialPath, Credential{
		AccessToken:  "transport-token",
		RefreshToken: "transport-refresh",
		AccountID:    "transport-account",
		ExpiresAt:    time.Now().Add(time.Hour),
	}, keys); err != nil {
		t.Fatal(err)
	}
	refresher, err := NewRefresher(credentialPath, keys, RefresherOptions{})
	if err != nil {
		t.Fatal(err)
	}
	webSocketURL := "ws" + strings.TrimPrefix(server.URL, "http")
	transport, err := NewResponsesTransport(ResponsesTransportOptions{
		Policy:       policy,
		ResponsesURL: server.URL,
		WebSocketURL: webSocketURL,
		HTTPClient:   client,
		Refresher:    refresher,
	})
	if err != nil {
		t.Fatal(err)
	}
	return transport
}

func transportWebSocketFixture(t *testing.T) [][]byte {
	t.Helper()
	raw, err := os.ReadFile("testdata/responses_websocket.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	frames := make([][]byte, 0, len(lines))
	for _, line := range lines {
		frames = append(frames, []byte(line))
	}
	return frames
}

func transportSSEFixture(t *testing.T) []byte {
	t.Helper()
	raw, err := os.ReadFile("testdata/responses_terminal.sse")
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
