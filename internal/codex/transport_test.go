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
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	coderwebsocket "github.com/coder/websocket"
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
		defer connection.CloseNow()
		if _, _, err := connection.Read(context.Background()); err != nil {
			return
		}
		for _, frame := range transportWebSocketFixture(t) {
			if err := connection.Write(context.Background(), coderwebsocket.MessageText, frame); err != nil {
				return
			}
		}
		_ = connection.Close(coderwebsocket.StatusNormalClosure, "")
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
	liteReceived := make(chan string, 1)
	server := newTransportServer(t, func(writer http.ResponseWriter, request *http.Request) {
		betaReceived <- request.Header.Get(BetaHeader)
		liteReceived <- request.Header.Get(ResponsesLiteHeader)
		connection, err := transportUpgrader.Upgrade(writer, request, nil)
		if err != nil {
			return
		}
		defer connection.CloseNow()
		_, message, err := connection.Read(context.Background())
		if err != nil {
			return
		}
		messageReceived <- string(message)
		_ = connection.Write(context.Background(), coderwebsocket.MessageText, []byte(`{"type":"response.done","response":{"status":"completed"}}`))
	})
	defer server.Close()

	transport := newTestResponsesTransport(t, server, ResponsesTransportWebSocketPreferred)
	request := CodexResponseRequest{Model: "gpt-5.6-sol", Stream: true, ResponsesLite: true}
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
	case got := <-liteReceived:
		if got != "true" {
			t.Fatalf("Responses Lite header = %q, want true", got)
		}
	case <-time.After(time.Second):
		t.Fatal("WebSocket Lite header was not received")
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

func TestResponsesTransportCompactPostsTypedRequestAndHeaders(t *testing.T) {
	server := newTransportServer(t, func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost || request.URL.Path != "/compact" {
			t.Errorf("compact request = %s %s", request.Method, request.URL.Path)
		}
		if got := request.Header.Get(AuthorizationHeader); got != "Bearer transport-token" {
			t.Errorf("authorization = %q", got)
		}
		if got := request.Header.Get(AccountIDHeader); got != "transport-account" {
			t.Errorf("account ID = %q", got)
		}
		if got := request.Header.Get(ResponsesLiteHeader); got != "true" {
			t.Errorf("Responses Lite = %q", got)
		}
		var compact CodexCompactRequest
		if err := json.NewDecoder(request.Body).Decode(&compact); err != nil {
			t.Errorf("decode compact request: %v", err)
		}
		if compact.Model != "gpt-5.6-sol" || compact.Input == nil || compact.Input.String == nil || *compact.Input.String != "hello" {
			t.Errorf("compact request = %#v", compact)
		}
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{"id":"cmp_1","object":"response.compaction","output":[{"type":"compaction","id":"item_1","encrypted_content":"encrypted","created_by":"codex"}]}`))
	})
	defer server.Close()

	transport := newTestResponsesTransport(t, server, ResponsesTransportSSE)
	input := "hello"
	result, err := transport.Compact(context.Background(), CodexCompactRequest{
		Model:         "gpt-5.6-sol",
		Input:         &CodexInput{String: &input},
		ResponsesLite: true,
	})
	if err != nil {
		t.Fatalf("transport.Compact: %v", err)
	}
	if result.ID != "cmp_1" || len(result.Output) != 1 || result.Output[0].Type != "compaction" ||
		result.Output[0].EncryptedContent != "encrypted" {
		t.Fatalf("compact result = %#v", result)
	}
}

func TestResponsesTransportCompactMergesHeaderConfig(t *testing.T) {
	var mu sync.Mutex
	var seen [][2]string
	server := newTransportServer(t, func(writer http.ResponseWriter, request *http.Request) {
		mu.Lock()
		seen = append(seen, [2]string{request.Header.Get(SessionIDHeader), request.Header.Get(ThreadIDHeader)})
		mu.Unlock()
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{"id":"cmp_1","object":"response.compaction","output":[{"type":"compaction","id":"item_1","encrypted_content":"encrypted","created_by":"codex"}]}`))
	})
	defer server.Close()
	transport := newTestResponsesTransport(t, server, ResponsesTransportSSE)
	transport.headers = HeaderConfig{SessionID: "base-session", ThreadID: "base-thread"}
	input := "hello"
	request := CodexCompactRequest{Model: "gpt-5.6-sol", Input: &CodexInput{String: &input}}
	if _, err := transport.Compact(context.Background(), request); err != nil {
		t.Fatalf("compact with base headers: %v", err)
	}
	if _, err := transport.CompactWithHeaders(context.Background(), request, RequestHeaderConfig{
		SessionID: "call-session", ThreadID: "call-thread",
	}); err != nil {
		t.Fatalf("compact with per-call headers: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	want := [][2]string{{"base-session", "base-thread"}, {"call-session", "call-thread"}}
	if !reflect.DeepEqual(seen, want) {
		t.Fatalf("compact request headers = %v, want %v", seen, want)
	}
}

func TestResponsesTransportPerCallHeadersDoNotMutateBaseConcurrently(t *testing.T) {
	fixture := transportSSEFixture(t)
	var mu sync.Mutex
	seen := make(map[[2]string]int)
	server := newTransportServer(t, func(writer http.ResponseWriter, request *http.Request) {
		key := [2]string{request.Header.Get(SessionIDHeader), request.Header.Get(ThreadIDHeader)}
		mu.Lock()
		seen[key]++
		mu.Unlock()
		writer.Header().Set("Content-Type", "text/event-stream")
		_, _ = writer.Write(fixture)
	})
	defer server.Close()
	transport := newTestResponsesTransport(t, server, ResponsesTransportSSE)
	transport.headers = HeaderConfig{SessionID: "base-session", ThreadID: "base-thread"}
	requests := []RequestHeaderConfig{
		{},
		{SessionID: "call-session", ThreadID: "call-thread"},
	}
	errs := make(chan error, len(requests))
	var waitGroup sync.WaitGroup
	for _, requestHeaders := range requests {
		waitGroup.Add(1)
		go func(requestHeaders RequestHeaderConfig) {
			defer waitGroup.Done()
			_, err := transport.DoWithHeaders(context.Background(), CodexResponseRequest{
				Model: "gpt-5.6-sol", Stream: true,
			}, requestHeaders)
			errs <- err
		}(requestHeaders)
	}
	waitGroup.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent Responses request: %v", err)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if seen[[2]string{"base-session", "base-thread"}] != 1 ||
		seen[[2]string{"call-session", "call-thread"}] != 1 ||
		len(seen) != 2 {
		t.Fatalf("concurrent request headers = %v", seen)
	}
}

func TestResponsesTransportDoPreservesAggregateFailures(t *testing.T) {
	tests := []struct {
		name         string
		fixture      string
		wantError    bool
		wantCategory string
		wantStatus   string
		wantTerminal string
	}{
		{
			name:         "completed",
			fixture:      "data: {\"type\":\"response.completed\",\"sequence_number\":1,\"response\":{\"status\":\"completed\"}}\n\ndata: [DONE]\n\n",
			wantStatus:   CodexResponseStatusCompleted,
			wantTerminal: CodexEventResponseCompleted,
		},
		{
			name:         "embedded error before completed",
			fixture:      "data: {\"type\":\"response.output_text.delta\",\"sequence_number\":1,\"delta\":\"visible\",\"error\":{\"code\":\"provider-code\",\"type\":\"provider_error\",\"message\":\"private provider message\"}}\n\ndata: {\"type\":\"response.completed\",\"sequence_number\":2,\"response\":{\"status\":\"completed\"}}\n\ndata: [DONE]\n\n",
			wantError:    true,
			wantCategory: "failed",
			wantStatus:   CodexResponseStatusCompleted,
			wantTerminal: CodexEventResponseCompleted,
		},
		{
			name:         "response failed",
			fixture:      "data: {\"type\":\"response.failed\",\"sequence_number\":1,\"response\":{\"status\":\"failed\",\"error\":{\"code\":\"server_error\",\"message\":\"private response failure\"}}}\n\ndata: [DONE]\n\n",
			wantError:    true,
			wantCategory: "response_failed",
			wantStatus:   CodexResponseStatusFailed,
			wantTerminal: CodexEventResponseFailed,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := newTransportServer(t, func(writer http.ResponseWriter, request *http.Request) {
				writer.Header().Set("Content-Type", "text/event-stream")
				_, _ = io.WriteString(writer, test.fixture)
			})
			defer server.Close()

			transport := newTestResponsesTransport(t, server, ResponsesTransportSSE)
			result, err := transport.Do(context.Background(), CodexResponseRequest{Model: "gpt-5.6-sol", Stream: true})
			if test.wantError {
				var failure *CodexStreamFailureError
				if err == nil || !errors.As(err, &failure) || !errors.Is(err, ErrCodexStreamFailed) {
					t.Fatalf("transport.Do error = %v, want typed stream failure", err)
				}
				if failure.Category != test.wantCategory || failure.Status != test.wantStatus {
					t.Fatalf("stream failure = %#v, want category %q and status %q", failure, test.wantCategory, test.wantStatus)
				}
				if strings.Contains(err.Error(), "provider-code") || strings.Contains(err.Error(), "private") {
					t.Fatalf("private provider error reached transport error: %v", err)
				}
			} else if err != nil {
				t.Fatalf("transport.Do: %v", err)
			}
			if result.TerminalType != test.wantTerminal || result.Response == nil || result.Response.Status != test.wantStatus {
				t.Fatalf("result = %#v, want terminal %q and status %q", result, test.wantTerminal, test.wantStatus)
			}
		})
	}
}

func TestResponsesTransportStreamDeliversIncrementally(t *testing.T) {
	firstEvent := []byte("data: {\"type\":\"response.output_text.delta\",\"sequence_number\":0,\"delta\":\"first\"}\n\n")
	terminalEvent := []byte("data: {\"type\":\"response.completed\",\"sequence_number\":1,\"response\":{\"status\":\"completed\"}}\n\ndata: [DONE]\n\n")
	firstReceived := make(chan struct{})
	release := make(chan struct{})
	server := newTransportServer(t, func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "text/event-stream")
		writer.WriteHeader(http.StatusOK)
		flusher, ok := writer.(http.Flusher)
		if !ok {
			return
		}
		_, _ = writer.Write(firstEvent)
		flusher.Flush()
		close(firstReceived)
		<-release
		_, _ = writer.Write(terminalEvent)
		flusher.Flush()
	})
	defer server.Close()

	transport := newTestResponsesTransport(t, server, ResponsesTransportSSE)
	events := make(chan CodexResponseStreamEvent, 2)
	errorsReturned := make(chan error, 1)
	go func() {
		errorsReturned <- transport.Stream(context.Background(), CodexResponseRequest{Model: "gpt-5.6-sol", Stream: true}, func(event CodexResponseStreamEvent) error {
			events <- event
			return nil
		})
	}()
	select {
	case <-firstReceived:
	case <-time.After(time.Second):
		t.Fatal("upstream did not flush first event")
	}
	select {
	case event := <-events:
		if event.Type != CodexEventResponseOutputTextDelta || event.Delta != "first" {
			t.Fatalf("first event = %#v", event)
		}
	case <-time.After(time.Second):
		t.Fatal("first event was not delivered incrementally")
	}
	select {
	case event := <-events:
		t.Fatalf("terminal event arrived before release: %#v", event)
	default:
	}
	close(release)
	select {
	case event := <-events:
		if event.Type != CodexEventResponseCompleted {
			t.Fatalf("terminal event = %#v", event)
		}
	case <-time.After(time.Second):
		t.Fatal("terminal event was not delivered")
	}
	select {
	case err := <-errorsReturned:
		if err != nil {
			t.Fatalf("transport.Stream: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("transport.Stream did not finish")
	}
}
func TestResponsesTransportSSEDeliversPreambleBeforeAbruptClose(t *testing.T) {
	firstEvent := []byte("data: {\"type\":\"response.created\",\"sequence_number\":0,\"response\":{\"status\":\"in_progress\"}}\n\n")
	firstReceived := make(chan struct{})
	release := make(chan struct{})
	server := newTransportServer(t, func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "text/event-stream")
		writer.WriteHeader(http.StatusOK)
		flusher, ok := writer.(http.Flusher)
		if !ok {
			return
		}
		_, _ = writer.Write(firstEvent)
		flusher.Flush()
		close(firstReceived)
		<-release
	})
	defer server.Close()

	transport := newTestResponsesTransport(t, server, ResponsesTransportSSE)
	events := make(chan CodexResponseStreamEvent, 1)
	errorsReturned := make(chan error, 1)
	go func() {
		errorsReturned <- transport.Stream(context.Background(), CodexResponseRequest{Model: "gpt-5.6-sol", Stream: true}, func(event CodexResponseStreamEvent) error {
			events <- event
			return nil
		})
	}()
	select {
	case <-firstReceived:
	case <-time.After(time.Second):
		t.Fatal("upstream did not flush response.created")
	}
	select {
	case event := <-events:
		if event.Type != CodexEventResponseCreated {
			t.Fatalf("first event = %#v", event)
		}
	case <-time.After(time.Second):
		t.Fatal("response.created was not delivered before upstream close")
	}
	close(release)
	select {
	case err := <-errorsReturned:
		if !errors.Is(err, ErrCodexStreamAbruptClose) {
			t.Fatalf("transport.Stream error = %v, want abrupt close", err)
		}
	case <-time.After(time.Second):
		t.Fatal("transport.Stream did not finish")
	}
}
func TestResponsesTransportStreamFallbackDiscardsReplayPreamble(t *testing.T) {
	var sseRequests atomic.Int32
	server := newTransportServer(t, func(writer http.ResponseWriter, request *http.Request) {
		if request.Method == http.MethodGet {
			connection, err := transportUpgrader.Upgrade(writer, request, nil)
			if err != nil {
				return
			}
			defer connection.CloseNow()
			if _, _, err := connection.Read(context.Background()); err != nil {
				return
			}
			_ = connection.Write(context.Background(), coderwebsocket.MessageText, []byte(`{"type":"response.created","sequence_number":0,"response":{"status":"in_progress"}}`))
			_ = connection.Close(coderwebsocket.StatusNormalClosure, "")
			return
		}
		sseRequests.Add(1)
		writer.Header().Set("Content-Type", "text/event-stream")
		writer.WriteHeader(http.StatusOK)
		_, _ = writer.Write(transportSSEFixture(t))
	})
	defer server.Close()

	transport := newTestResponsesTransport(t, server, ResponsesTransportWebSocketPreferred)
	events := make(chan CodexResponseStreamEvent, maxCodexStreamEvents)
	err := transport.Stream(context.Background(), CodexResponseRequest{Model: "gpt-5.6-sol", Stream: true}, func(event CodexResponseStreamEvent) error {
		events <- event
		return nil
	})
	if err != nil {
		t.Fatalf("transport.Stream: %v", err)
	}
	if sseRequests.Load() != 1 {
		t.Fatalf("SSE requests = %d, want 1", sseRequests.Load())
	}
	createdCount := 0
	terminalCount := 0
	for {
		select {
		case event := <-events:
			if event.Type == CodexEventResponseCreated {
				createdCount++
			}
			if isCodexTerminalEvent(event.Type) {
				terminalCount++
			}
		default:
			if createdCount != 1 || terminalCount != 1 {
				t.Fatalf("created = %d, terminal = %d", createdCount, terminalCount)
			}
			return
		}
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
			defer connection.CloseNow()
			if _, _, err := connection.Read(context.Background()); err != nil {
				return
			}
			frames := [][]byte{
				[]byte(`{"type":"response.created","response":{"status":"in_progress"}}`),
				[]byte(`{"type":"response.metadata","metadata":{"state":"ready"}}`),
			}
			for _, frame := range frames {
				if err := connection.Write(context.Background(), coderwebsocket.MessageText, frame); err != nil {
					return
				}
			}
			_ = connection.Close(coderwebsocket.StatusNormalClosure, "")
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

func TestResponsesTransportFallsBackAfterBareWebSocketDrop(t *testing.T) {
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
		if _, _, err := connection.Read(context.Background()); err == nil {
			_ = connection.CloseNow()
		}
	})
	defer server.Close()

	transport := newTestResponsesTransport(t, server, ResponsesTransportWebSocketPreferred)
	result, err := transport.Do(context.Background(), CodexResponseRequest{Model: "gpt-5.6-sol", Stream: true})
	if err != nil {
		t.Fatalf("transport.Do: %v", err)
	}
	if result.TerminalType != CodexEventResponseCompleted {
		t.Fatalf("terminal type = %q, want %q", result.TerminalType, CodexEventResponseCompleted)
	}
	if sseRequests.Load() != 1 {
		t.Fatalf("SSE requests = %d, want 1", sseRequests.Load())
	}
}

func TestResponsesTransportDoesNotFallbackAfterMalformedWebSocketFrame(t *testing.T) {
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
		defer connection.CloseNow()
		if _, _, err := connection.Read(context.Background()); err != nil {
			return
		}
		_ = connection.Write(context.Background(), coderwebsocket.MessageText, []byte(`{"type":"response.created"`))
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
		if _, _, err := connection.Read(context.Background()); err == nil {
			frame := []byte(`{"type":"response.output_text.delta","sequence_number":1,"delta":"partial"}`)
			_ = connection.Write(context.Background(), coderwebsocket.MessageText, frame)
		}
		_ = connection.CloseNow()
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
		defer connection.CloseNow()
		if _, _, err := connection.Read(context.Background()); err != nil {
			return
		}
		frame := []byte(`{"type":"response.output_item.added","item":{"type":"function_call","name":"lookup","arguments":"{}"}}`)
		if err := connection.Write(context.Background(), coderwebsocket.MessageText, frame); err != nil {
			return
		}
		_ = connection.CloseNow()
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
		defer connection.CloseNow()
		if _, _, err := connection.Read(context.Background()); err != nil {
			return
		}
		close(requestReceived)
		_, _, _ = connection.Read(context.Background())
	})
	defer server.Close()

	transport := newTestResponsesTransport(t, server, ResponsesTransportWebSocketPreferred)
	ctx, cancel := context.WithCancelCause(context.Background())
	defer cancel(nil)
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
	cause := errors.New("caller cancellation cause")
	cancel(cause)
	select {
	case err := <-errorsReturned:
		if !errors.Is(err, cause) {
			t.Fatalf("error = %v, want caller cancellation cause", err)
		}
	case <-time.After(time.Second):
		t.Fatal("transport did not stop after cancellation")
	}
}

func TestWebSocketReadFallbackStatuslessNetworkErrors(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{name: "EOF", err: io.EOF, want: true},
		{name: "unexpected EOF", err: io.ErrUnexpectedEOF, want: true},
		{name: "timeout", err: context.DeadlineExceeded, want: true},
		{name: "protocol", err: errors.New("unexpected reserved bits"), want: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := webSocketReadFallback(test.err); got != test.want {
				t.Fatalf("fallback = %v, want %v", got, test.want)
			}
		})
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
		defer connection.CloseNow()
		if _, _, err := connection.Read(context.Background()); err != nil {
			return
		}
		_ = connection.Write(context.Background(), coderwebsocket.MessageText, []byte(strings.Repeat("x", maxCodexStreamLineBytes+1)))
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
		{name: "unsupported data", code: int(coderwebsocket.StatusUnsupportedData), wantSSE: true, wantSuccess: true},
		{name: "policy violation", code: int(coderwebsocket.StatusPolicyViolation), wantSSE: false, wantSuccess: false},
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
				defer connection.CloseNow()
				if _, _, err := connection.Read(context.Background()); err != nil {
					return
				}
				_ = connection.Close(coderwebsocket.StatusCode(test.code), "")
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

func TestResponsesTransportMapsWrappedWebSocketErrors(t *testing.T) {
	tests := []struct {
		name       string
		frame      string
		category   ErrorCategory
		statusCode int
		retryAfter time.Duration
	}{
		{
			name:       "usage limit",
			frame:      `{"type":"error","status":429,"retry_after":7.5,"error":{"type":"usage_limit_reached","message":"private usage details"},"headers":{"x-codex-primary-used-percent":100}}`,
			category:   CategoryUsageLimit,
			statusCode: http.StatusTooManyRequests,
			retryAfter: 7500 * time.Millisecond,
		},
		{
			name:       "policy",
			frame:      `{"type":"error","status":400,"error":{"type":"cyber_policy","message":"private policy details"}}`,
			category:   CategoryPolicy,
			statusCode: http.StatusBadRequest,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := newTransportServer(t, func(writer http.ResponseWriter, request *http.Request) {
				connection, err := transportUpgrader.Upgrade(writer, request, nil)
				if err != nil {
					return
				}
				defer connection.CloseNow()
				if _, _, err := connection.Read(context.Background()); err != nil {
					return
				}
				_ = connection.Write(context.Background(), coderwebsocket.MessageText, []byte(test.frame))
			})
			defer server.Close()

			transport := newTestResponsesTransport(t, server, ResponsesTransportWebSocketPreferred)
			_, err := transport.Do(context.Background(), CodexResponseRequest{Model: "gpt-5.6-sol", Stream: true})
			var safeErr *SafeError
			if !errors.As(err, &safeErr) {
				t.Fatalf("error = %v, want SafeError", err)
			}
			if safeErr.Category != test.category || safeErr.StatusCode != test.statusCode {
				t.Fatalf("safe error = %#v, want category %q status %d", safeErr, test.category, test.statusCode)
			}
			if safeErr.RetryAfter != test.retryAfter {
				t.Fatalf("retry after = %s, want %s", safeErr.RetryAfter, test.retryAfter)
			}
			if strings.Contains(err.Error(), "private") {
				t.Fatalf("error exposes private detail: %v", err)
			}
		})
	}
}

func TestDecodeCodexWebSocketMessageConvertsScalarHeaders(t *testing.T) {
	frame := []byte(`{"type":"error","status":429,"headers":{
		"x-codex-primary-used-percent":"100.0",
		"x-codex-primary-window-minutes":15,
		"retry-after":7,
		"x-request-id":true,
		"x-visible":"value",
		"invalid name":"skip",
		"x-array":[1],
		"x-object":{"value":1},
		"x-null":null
	}}`)
	_, response, err := decodeCodexWebSocketMessage(frame)
	if err != nil {
		t.Fatalf("decode error: %v", err)
	}
	if response == nil || response.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("response = %#v, want status 429", response)
	}
	for name, want := range map[string]string{
		"X-Codex-Primary-Used-Percent":   "100.0",
		"X-Codex-Primary-Window-Minutes": "15",
		"Retry-After":                    "7",
		"X-Request-Id":                   "true",
		"X-Visible":                      "value",
	} {
		if got := response.Header.Get(name); got != want {
			t.Errorf("header %q = %q, want %q", name, got, want)
		}
	}
	for _, name := range []string{"invalid name", "X-Array", "X-Object", "X-Null"} {
		if got := response.Header.Get(name); got != "" {
			t.Errorf("header %q = %q, want skipped", name, got)
		}
	}
	mapped := MapUpstreamError(response.StatusCode, response.Header, frame)
	if mapped.RetryAfter != 7*time.Second || mapped.RequestID != "true" {
		t.Fatalf("mapped error = %#v, want retry-after 7s and bool request id", mapped)
	}
	closeHTTPResponse(response)
}

func TestDecodeCodexWebSocketMessagePreservesRetryMetadataScalars(t *testing.T) {
	tests := []struct {
		name       string
		retryAfter string
		requestID  string
		wantRetry  time.Duration
		wantID     string
	}{
		{name: "numeric retry and string request", retryAfter: "17", requestID: `"request-string"`, wantRetry: 17 * time.Second, wantID: "request-string"},
		{name: "string retry and numeric request", retryAfter: `"18"`, requestID: "123", wantRetry: 18 * time.Second, wantID: "123"},
		{name: "boolean retry and boolean request", retryAfter: "true", requestID: "false", wantID: "false"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			frame := []byte(`{"type":"error","status":429,"headers":{"retry-after":` + test.retryAfter + `,"x-request-id":` + test.requestID + `}}`)
			_, response, err := decodeCodexWebSocketMessage(frame)
			if err != nil {
				t.Fatalf("decode error: %v", err)
			}
			mapped := MapUpstreamError(response.StatusCode, response.Header, frame)
			if mapped.RetryAfter != test.wantRetry || mapped.RequestID != test.wantID {
				t.Fatalf("mapped error = %#v, want retry-after %s and request id %q", mapped, test.wantRetry, test.wantID)
			}
			closeHTTPResponse(response)
		})
	}
}

func TestDecodeCodexWebSocketMessagePreservesNonHTTPErrorEvents(t *testing.T) {
	tests := []struct {
		name  string
		frame string
	}{
		{name: "statusless", frame: `{"type":"error","message":"stream failed"}`},
		{name: "success status", frame: `{"type":"error","status":200,"message":"stream failed"}`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			event, response, err := decodeCodexWebSocketMessage([]byte(test.frame))
			if err != nil {
				t.Fatalf("decode error: %v", err)
			}
			if response != nil {
				t.Fatalf("response = %#v, want no synthetic response", response)
			}
			if event.Type != CodexEventError {
				t.Fatalf("event type = %q, want %q", event.Type, CodexEventError)
			}
			_, err = ParseCodexWebSocketFrames([][]byte{[]byte(test.frame)})
			if !errors.Is(err, ErrCodexStreamFailed) {
				t.Fatalf("stream error = %v, want failed stream", err)
			}
		})
	}
}

func TestDecodeCodexWebSocketMessageRejectsConflictingStatuses(t *testing.T) {
	frame := []byte(`{"type":"error","status":401,"status_code":403}`)
	_, _, err := decodeCodexWebSocketMessage(frame)
	if !errors.Is(err, ErrCodexStreamMalformed) {
		t.Fatalf("error = %v, want malformed conflicting statuses", err)
	}
}

func TestResponsesTransportWrapped401RefreshesOnce(t *testing.T) {
	keys := testCredentialKeys(t)
	credentialPath := t.TempDir() + "/credential.enc"
	if err := SaveCredential(credentialPath, Credential{
		AccessToken:  "old-access",
		RefreshToken: "old-refresh",
		AccountID:    "transport-account",
		ExpiresAt:    time.Now().Add(time.Hour),
	}, keys); err != nil {
		t.Fatal(err)
	}
	var websocketRequests atomic.Int32
	var refreshRequests atomic.Int32
	var wrongToken atomic.Bool
	server := newTransportServer(t, func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/oauth/token" {
			refreshRequests.Add(1)
			writer.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(writer, `{"access_token":"new-access","refresh_token":"new-refresh","expires_in":3600}`)
			return
		}
		connection, err := transportUpgrader.Upgrade(writer, request, nil)
		if err != nil {
			return
		}
		defer connection.CloseNow()
		if _, _, err := connection.Read(context.Background()); err != nil {
			return
		}
		if websocketRequests.Add(1) == 1 {
			_ = connection.Write(context.Background(), coderwebsocket.MessageText, []byte(`{"type":"error","status_code":401,"error":{"code":"token_expired","message":"private auth detail"}}`))
			return
		}
		if request.Header.Get(AuthorizationHeader) != "Bearer new-access" {
			wrongToken.Store(true)
		}
		_ = connection.Write(context.Background(), coderwebsocket.MessageText, []byte(`{"type":"response.done","response":{"status":"completed"}}`))
	})
	defer server.Close()
	refresher, err := NewRefresher(credentialPath, keys, RefresherOptions{Issuer: server.URL, ClientID: "client", HTTPClient: server.Client()})
	if err != nil {
		t.Fatal(err)
	}
	transport, err := NewResponsesTransport(ResponsesTransportOptions{
		Policy:       ResponsesTransportWebSocketPreferred,
		ResponsesURL: server.URL,
		WebSocketURL: "ws" + strings.TrimPrefix(server.URL, "http"),
		HTTPClient:   server.Client(),
		Refresher:    refresher,
	})
	if err != nil {
		t.Fatal(err)
	}
	result, err := transport.Do(context.Background(), CodexResponseRequest{Model: "gpt-5.6-sol", Stream: true})
	if err != nil {
		t.Fatalf("transport.Do: %v", err)
	}
	if result.TerminalType != CodexEventResponseDone {
		t.Fatalf("terminal type = %q, want %q", result.TerminalType, CodexEventResponseDone)
	}
	if websocketRequests.Load() != 2 {
		t.Fatalf("WebSocket requests = %d, want 2", websocketRequests.Load())
	}
	if refreshRequests.Load() != 1 {
		t.Fatalf("refresh requests = %d, want 1", refreshRequests.Load())
	}
	if wrongToken.Load() {
		t.Fatal("refreshed access token was not used")
	}
}

func TestResponsesTransportDoesNotRefreshWrapped401AfterOutput(t *testing.T) {
	keys := testCredentialKeys(t)
	credentialPath := t.TempDir() + "/credential.enc"
	if err := SaveCredential(credentialPath, Credential{
		AccessToken:  "old-access",
		RefreshToken: "old-refresh",
		AccountID:    "transport-account",
		ExpiresAt:    time.Now().Add(time.Hour),
	}, keys); err != nil {
		t.Fatal(err)
	}
	var refreshRequests atomic.Int32
	server := newTransportServer(t, func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/oauth/token" {
			refreshRequests.Add(1)
			writer.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(writer, `{"access_token":"unexpected","refresh_token":"unexpected","expires_in":3600}`)
			return
		}
		connection, err := transportUpgrader.Upgrade(writer, request, nil)
		if err != nil {
			return
		}
		defer connection.CloseNow()
		if _, _, err := connection.Read(context.Background()); err != nil {
			return
		}
		_ = connection.Write(context.Background(), coderwebsocket.MessageText, []byte(`{"type":"response.output_text.delta","delta":"visible output"}`))
		_ = connection.Write(context.Background(), coderwebsocket.MessageText, []byte(`{"type":"error","status":401,"error":{"code":"token_expired","message":"private auth detail"}}`))
	})
	defer server.Close()
	refresher, err := NewRefresher(credentialPath, keys, RefresherOptions{Issuer: server.URL, ClientID: "client", HTTPClient: server.Client()})
	if err != nil {
		t.Fatal(err)
	}
	transport, err := NewResponsesTransport(ResponsesTransportOptions{
		Policy:       ResponsesTransportWebSocketPreferred,
		ResponsesURL: server.URL,
		WebSocketURL: "ws" + strings.TrimPrefix(server.URL, "http"),
		HTTPClient:   server.Client(),
		Refresher:    refresher,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = transport.Do(context.Background(), CodexResponseRequest{Model: "gpt-5.6-sol", Stream: true})
	var safeErr *SafeError
	if !errors.As(err, &safeErr) || safeErr.Category != CategoryAuthentication || safeErr.StatusCode != http.StatusUnauthorized {
		t.Fatalf("error = %#v, want authentication SafeError", err)
	}
	if strings.Contains(err.Error(), "private") {
		t.Fatalf("error exposes private detail: %v", err)
	}
	if refreshRequests.Load() != 0 {
		t.Fatalf("refresh requests = %d, want 0", refreshRequests.Load())
	}
}

func TestResponsesTransportHTTPClientTimeoutBoundsWebSocketAttempt(t *testing.T) {
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
		defer connection.CloseNow()
		if _, _, err := connection.Read(context.Background()); err != nil {
			return
		}
		frame := []byte(`{"type":"response.metadata","metadata":{"state":"still-running"}}`)
		for {
			if err := connection.Write(context.Background(), coderwebsocket.MessageText, frame); err != nil {
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
	})
	defer server.Close()
	client := &http.Client{
		Transport: server.Client().Transport,
		Timeout:   120 * time.Millisecond,
	}
	transport := newTestResponsesTransportWithClient(t, server, ResponsesTransportWebSocketPreferred, client)
	start := time.Now()
	_, err := transport.Do(context.Background(), CodexResponseRequest{Model: "gpt-5.6-sol", Stream: true})
	elapsed := time.Since(start)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("error = %v, want client timeout", err)
	}
	if elapsed > time.Second {
		t.Fatalf("timeout elapsed = %s, want under 1s", elapsed)
	}
	if sseRequests.Load() != 0 {
		t.Fatalf("SSE requests = %d, want 0 after client timeout", sseRequests.Load())
	}
}
func TestCodexSSEContextUsesSmallerTimeout(t *testing.T) {
	ctx := context.Background()
	requestContext, cancel := codexSSEContext(ctx, codexHTTPTimeout*2)
	defer cancel()
	deadline, ok := requestContext.Deadline()
	if !ok {
		t.Fatal("SSE context has no deadline")
	}
	if remaining := time.Until(deadline); remaining > codexHTTPTimeout || remaining <= 0 {
		t.Fatalf("SSE deadline remaining = %s, want at most %s", remaining, codexHTTPTimeout)
	}

	requestContext, cancel = codexSSEContext(ctx, 10*time.Millisecond)
	defer cancel()
	deadline, ok = requestContext.Deadline()
	if !ok {
		t.Fatal("client-limited SSE context has no deadline")
	}
	if remaining := time.Until(deadline); remaining > 10*time.Millisecond || remaining <= 0 {
		t.Fatalf("client-limited deadline remaining = %s, want at most 10ms", remaining)
	}
}

func TestResponsesTransportSSEHTTPClientTimeoutReturnsDeadline(t *testing.T) {
	headersSent := make(chan struct{})
	server := newTransportServer(t, func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "text/event-stream")
		writer.WriteHeader(http.StatusOK)
		if flusher, ok := writer.(http.Flusher); ok {
			flusher.Flush()
		}
		close(headersSent)
		<-request.Context().Done()
	})
	defer server.Close()
	client := &http.Client{
		Transport: server.Client().Transport,
		Timeout:   80 * time.Millisecond,
	}
	transport := newTestResponsesTransportWithClient(t, server, ResponsesTransportSSE, client)
	errChannel := make(chan error, 1)
	go func() {
		_, err := transport.Do(context.Background(), CodexResponseRequest{Model: "gpt-5.6-sol", Stream: true})
		errChannel <- err
	}()
	select {
	case <-headersSent:
	case <-time.After(time.Second):
		t.Fatal("SSE response headers were not sent")
	}
	select {
	case err := <-errChannel:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("SSE timeout error = %v, want deadline exceeded", err)
		}
		if strings.Contains(err.Error(), server.URL) {
			t.Fatalf("SSE timeout error exposes URL: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("SSE timeout did not return")
	}
}

func TestResponsesTransportSSECallerCancellationCause(t *testing.T) {
	headersSent := make(chan struct{})
	server := newTransportServer(t, func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "text/event-stream")
		writer.WriteHeader(http.StatusOK)
		if flusher, ok := writer.(http.Flusher); ok {
			flusher.Flush()
		}
		close(headersSent)
		<-request.Context().Done()
	})
	defer server.Close()
	transport := newTestResponsesTransport(t, server, ResponsesTransportSSE)
	ctx, cancel := context.WithCancelCause(context.Background())
	defer cancel(nil)
	errChannel := make(chan error, 1)
	go func() {
		_, err := transport.Do(ctx, CodexResponseRequest{Model: "gpt-5.6-sol", Stream: true})
		errChannel <- err
	}()
	select {
	case <-headersSent:
	case <-time.After(time.Second):
		t.Fatal("SSE response headers were not sent")
	}
	cause := errors.New("caller cancellation cause")
	cancel(cause)
	select {
	case err := <-errChannel:
		if !errors.Is(err, cause) {
			t.Fatalf("SSE cancellation error = %v, want cause", err)
		}
	case <-time.After(time.Second):
		t.Fatal("SSE cancellation did not return")
	}
}

func TestResponsesTransportZeroHTTPClientTimeoutStillReadsWebSocket(t *testing.T) {
	server := newTransportServer(t, func(writer http.ResponseWriter, request *http.Request) {
		connection, err := transportUpgrader.Upgrade(writer, request, nil)
		if err != nil {
			return
		}
		defer connection.CloseNow()
		if _, _, err := connection.Read(context.Background()); err != nil {
			return
		}
		time.Sleep(100 * time.Millisecond)
		_ = connection.Write(context.Background(), coderwebsocket.MessageText, []byte(`{"type":"response.done","response":{"status":"completed"}}`))
	})
	defer server.Close()
	client := &http.Client{Transport: server.Client().Transport}
	transport := newTestResponsesTransportWithClient(t, server, ResponsesTransportWebSocketPreferred, client)
	result, err := transport.Do(context.Background(), CodexResponseRequest{Model: "gpt-5.6-sol", Stream: true})
	if err != nil {
		t.Fatalf("transport.Do: %v", err)
	}
	if result.TerminalType != CodexEventResponseDone {
		t.Fatalf("terminal type = %q, want %q", result.TerminalType, CodexEventResponseDone)
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
		defer connection.CloseNow()
		if _, _, err := connection.Read(context.Background()); err != nil {
			return
		}
		_ = connection.Write(context.Background(), coderwebsocket.MessageText, []byte(`{"type":"response.done","response":{"status":"completed"}}`))
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

func TestResponsesTransportUsesHTTPSProxy(t *testing.T) {
	var proxyRequests atomic.Int32
	proxy := newTransportTLSConnectProxy(t, &proxyRequests)
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
		defer connection.CloseNow()
		if _, _, err := connection.Read(context.Background()); err != nil {
			return
		}
		_ = connection.Write(context.Background(), coderwebsocket.MessageText, []byte(`{"type":"response.done","response":{"status":"completed"}}`))
	}))
	defer server.Close()

	roots := x509.NewCertPool()
	roots.AddCert(proxy.Certificate())
	roots.AddCert(server.Certificate())
	httpTransport := &http.Transport{
		Proxy: http.ProxyURL(proxyURL),
		TLSClientConfig: &tls.Config{
			RootCAs: roots,
		},
	}
	client := &http.Client{Transport: httpTransport}
	transport := newTestResponsesTransportWithClient(t, server, ResponsesTransportWebSocketPreferred, client)
	if _, err := transport.Do(context.Background(), CodexResponseRequest{Model: "gpt-5.6-sol", Stream: true}); err != nil {
		t.Fatalf("transport.Do through HTTPS proxy: %v", err)
	}
	if proxyRequests.Load() != 1 {
		t.Fatalf("HTTPS proxy requests = %d, want 1", proxyRequests.Load())
	}
}

func TestResponsesTransportConcurrentCalls(t *testing.T) {
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
		defer connection.CloseNow()
		if _, _, err := connection.Read(context.Background()); err != nil {
			return
		}
		_ = connection.Write(context.Background(), coderwebsocket.MessageText, []byte(`{"type":"response.done","response":{"status":"completed"}}`))
	})
	defer server.Close()

	httpTransport := server.Client().Transport.(*http.Transport).Clone()
	httpTransport.Proxy = http.ProxyURL(proxyURL)
	client := &http.Client{Transport: httpTransport}
	transport := newTestResponsesTransportWithClient(t, server, ResponsesTransportWebSocketPreferred, client)

	const calls = 8
	errs := make(chan error, calls)
	var group sync.WaitGroup
	group.Add(calls)
	for range calls {
		go func() {
			defer group.Done()
			_, err := transport.Do(context.Background(), CodexResponseRequest{Model: "gpt-5.6-sol", Stream: true})
			errs <- err
		}()
	}
	group.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Errorf("transport.Do: %v", err)
		}
	}
	if proxyRequests.Load() != calls {
		t.Fatalf("proxy requests = %d, want %d", proxyRequests.Load(), calls)
	}
}

func TestResponsesTransportUsesCustomTLSRoots(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		connection, err := transportUpgrader.Upgrade(writer, request, nil)
		if err != nil {
			return
		}
		defer connection.CloseNow()
		if _, _, err := connection.Read(context.Background()); err != nil {
			return
		}
		_ = connection.Write(context.Background(), coderwebsocket.MessageText, []byte(`{"type":"response.done","response":{"status":"completed"}}`))
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
		defer connection.CloseNow()
		if _, _, err := connection.Read(context.Background()); err != nil {
			return
		}
		_ = connection.Write(context.Background(), coderwebsocket.MessageText, []byte(`{"type":"response.done","response":{"status":"completed"}}`))
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
		defer connection.CloseNow()
		if _, _, err := connection.Read(context.Background()); err != nil {
			return
		}
		_ = connection.Write(context.Background(), coderwebsocket.MessageText, []byte(`{"type":"response.done","response":{"status":"completed"}}`))
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
		defer connection.CloseNow()
		if _, _, err := connection.Read(context.Background()); err != nil {
			return
		}
		_ = connection.Write(context.Background(), coderwebsocket.MessageText, []byte(`{"type":"response.done","response":{"status":"completed"}}`))
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
	return httptest.NewServer(transportConnectProxyHandler(requests))
}

func newTransportTLSConnectProxy(t *testing.T, requests *atomic.Int32) *httptest.Server {
	t.Helper()
	return httptest.NewTLSServer(transportConnectProxyHandler(requests))
}

func transportConnectProxyHandler(requests *atomic.Int32) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		targetAddress := request.Host
		if request.Method != http.MethodConnect {
			if request.URL == nil || request.URL.Host == "" {
				http.Error(writer, "proxy target is missing", http.StatusBadRequest)
				return
			}
			targetAddress = request.URL.Host
		}
		target, err := net.Dial("tcp", targetAddress)
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
		if request.Method == http.MethodConnect {
			if _, err := buffered.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
				return
			}
			if err := buffered.Flush(); err != nil {
				return
			}
		} else {
			request.URL.Scheme = ""
			request.URL.Host = ""
			request.RequestURI = request.URL.RequestURI()
			if err := request.Write(target); err != nil {
				return
			}
		}
		go func() {
			_, _ = io.Copy(target, client)
			_ = target.Close()
		}()
		_, _ = io.Copy(client, target)
	})
}

var transportUpgrader transportWebSocketUpgrader

type transportWebSocketUpgrader struct{}

func (transportWebSocketUpgrader) Upgrade(writer http.ResponseWriter, request *http.Request, _ http.Header) (*coderwebsocket.Conn, error) {
	return coderwebsocket.Accept(writer, request, &coderwebsocket.AcceptOptions{InsecureSkipVerify: true})
}

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
	refresher, err := NewRefresher(credentialPath, keys, RefresherOptions{Issuer: server.URL, ClientID: "client"})
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
