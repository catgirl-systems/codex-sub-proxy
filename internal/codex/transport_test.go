package codex

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
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

var transportUpgrader = websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}

func newTransportServer(t *testing.T, handler http.HandlerFunc) *httptest.Server {
	t.Helper()
	return httptest.NewServer(handler)
}

func newTestResponsesTransport(t *testing.T, server *httptest.Server, policy ResponsesTransportPolicy) *ResponsesTransport {
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
		HTTPClient:   server.Client(),
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
