package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/catgirl-systems/codex-sub-proxy/internal/apikey"
	"github.com/catgirl-systems/codex-sub-proxy/internal/codex"
	"github.com/catgirl-systems/codex-sub-proxy/internal/envelope"
	coderwebsocket "github.com/coder/websocket"
)

type responsesWebSocketTestBroker struct {
	waitForCancel          bool
	connectionLimit        bool
	previousNotFoundOnCall int32
	responseType           string
	responseStatus         string
	started                chan struct{}
	canceled               chan struct{}
	forcedIDs              chan string
	startedOnce            sync.Once
	canceledOnce           sync.Once
	calls                  atomic.Int32
	selections             chan codex.SelectionRequest
	privates               chan codex.CodexResponseRequest
}

func (broker *responsesWebSocketTestBroker) StreamResponses(ctx context.Context, request codex.SelectionRequest, private codex.CodexResponseRequest, forcedAccountID string, bind func(codex.Account) error, onEvent func(codex.CodexResponseStreamEvent) error) (BrokerResponsesResult, error) {
	account := codex.Account{ID: "ws-account", Enabled: true, Available: true}
	result := BrokerResponsesResult{Account: account}
	if bind != nil {
		if err := bind(account); err != nil {
			return result, err
		}
	}
	call := broker.calls.Add(1)
	if broker.forcedIDs != nil {
		broker.forcedIDs <- forcedAccountID
	}
	if broker.selections != nil {
		broker.selections <- request
	}
	if broker.privates != nil {
		broker.privates <- private
	}
	if broker.connectionLimit && call == 1 {
		return result, onEvent(codex.CodexResponseStreamEvent{
			Type:           codex.CodexEventError,
			Code:           "websocket_connection_limit_reached",
			SequenceNumber: 0,
		})
	}
	if broker.started != nil {
		broker.startedOnce.Do(func() { close(broker.started) })
	}
	if broker.waitForCancel {
		select {
		case <-ctx.Done():
			if broker.canceled != nil {
				broker.canceledOnce.Do(func() { close(broker.canceled) })
			}
			return result, ctx.Err()
		}
	}
	if broker.previousNotFoundOnCall == call {
		return result, onEvent(codex.CodexResponseStreamEvent{
			Type:           codex.CodexEventError,
			Code:           "previous_response_not_found",
			SequenceNumber: 0,
		})
	}
	responseStatus := broker.responseStatus
	if responseStatus == "" {
		responseStatus = codex.CodexResponseStatusCompleted
	}
	responseType := broker.responseType
	if responseType == "" {
		responseType = codex.CodexEventResponseCompleted
	}
	response := codex.CodexResponse{ID: fmt.Sprintf("ws-response-%d", call), Model: request.Model, Status: responseStatus}
	if err := onEvent(codex.CodexResponseStreamEvent{Type: responseType, SequenceNumber: 0, Response: &response}); err != nil {
		return result, err
	}
	return result, nil
}

func (broker *responsesWebSocketTestBroker) DoResponses(context.Context, codex.SelectionRequest, codex.CodexResponseRequest, string, func(codex.Account) error) (BrokerResponsesResult, error) {
	return BrokerResponsesResult{}, errors.New("unused DoResponses")
}

func (broker *responsesWebSocketTestBroker) Compact(context.Context, codex.SelectionRequest, codex.CodexCompactRequest, string, func(codex.Account) error) (BrokerCompactResult, error) {
	return BrokerCompactResult{}, errors.New("unused Compact")
}

func (broker *responsesWebSocketTestBroker) GenerateImage(context.Context, codex.SelectionRequest, codex.CodexImageGenerationRequest, string, func(codex.Account) error) (BrokerImageResult, error) {
	return BrokerImageResult{}, errors.New("unused GenerateImage")
}

func (broker *responsesWebSocketTestBroker) EditImage(context.Context, codex.SelectionRequest, codex.CodexImageEditRequest, string, func(codex.Account) error) (BrokerImageResult, error) {
	return BrokerImageResult{}, errors.New("unused EditImage")
}

func dialResponsesWebSocket(t *testing.T, address, rawKey string, headers http.Header) (*coderwebsocket.Conn, *http.Response, error) {
	t.Helper()
	if headers == nil {
		headers = make(http.Header)
	}
	if rawKey != "" {
		headers.Set("Authorization", "Bearer "+rawKey)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	return coderwebsocket.Dial(ctx, "ws://"+address+responsesEndpoint, &coderwebsocket.DialOptions{
		HTTPHeader:      headers,
		CompressionMode: coderwebsocket.CompressionDisabled,
	})
}

func writeResponsesWebSocketCreate(t *testing.T, connection *coderwebsocket.Conn, model string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := connection.Write(ctx, coderwebsocket.MessageText, []byte(`{"type":"response.create","model":"`+model+`","input":"hello"}`)); err != nil {
		t.Fatal(err)
	}
}

func readResponsesWebSocketEvent(t *testing.T, connection *coderwebsocket.Conn) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	messageType, payload, err := connection.Read(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if messageType != coderwebsocket.MessageText {
		t.Fatalf("message type = %v, want text", messageType)
	}
	var event struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(payload, &event); err != nil {
		t.Fatal(err)
	}
	if event.Type == "error" {
		t.Logf("websocket error payload = %s", payload)
	}
	return event.Type
}

func TestResponsesWebSocketAuthAndOrigin(t *testing.T) {
	broker := &responsesWebSocketTestBroker{}
	servers, rawKey := newResponsesTestServerWithBroker(t, "", nil, broker)
	defer shutdownResponsesTestServer(t, servers)

	_, response, err := dialResponsesWebSocket(t, servers.DataAddr(), "", nil)
	if err == nil || response == nil || response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated websocket response = %#v, err = %v", response, err)
	}

	connection, response, err := dialResponsesWebSocket(t, servers.DataAddr(), rawKey, nil)
	if err != nil || response == nil {
		t.Fatalf("same-origin websocket dial: response=%#v err=%v", response, err)
	}
	_ = connection.Close(coderwebsocket.StatusNormalClosure, "")

	origin := make(http.Header)
	origin.Set("Origin", "https://cross-origin.example")
	_, response, err = dialResponsesWebSocket(t, servers.DataAddr(), rawKey, origin)
	if err == nil || response == nil || response.StatusCode != http.StatusForbidden {
		t.Fatalf("cross-origin websocket response = %#v, err = %v", response, err)
	}
}
func TestResponsesWebSocketRejectsInvalidUnknownAndOversizedMessages(t *testing.T) {
	tests := []struct {
		name      string
		frame     []byte
		wantError bool
		wantClose coderwebsocket.StatusCode
	}{
		{name: "invalid JSON", frame: []byte("not-json"), wantError: true, wantClose: coderwebsocket.StatusPolicyViolation},
		{name: "unknown type", frame: []byte(`{"type":"response.unknown"}`), wantError: true, wantClose: coderwebsocket.StatusPolicyViolation},
		{name: "unknown field", frame: []byte(`{"type":"response.create","model":"gpt-5.6-sol","unknown":true}`), wantError: true, wantClose: coderwebsocket.StatusPolicyViolation},
		{name: "read limit", frame: []byte(`{"type":"response.create","model":"gpt-5.6-sol","input":"` + strings.Repeat("x", maxResponsesBodyBytes) + `"}`), wantClose: coderwebsocket.StatusMessageTooBig},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			broker := &responsesWebSocketTestBroker{}
			servers, rawKey := newResponsesTestServerWithBroker(t, "", nil, broker)
			defer shutdownResponsesTestServer(t, servers)
			connection, response, err := dialResponsesWebSocket(t, servers.DataAddr(), rawKey, nil)
			if err != nil || response == nil {
				t.Fatalf("websocket dial: response=%#v err=%v", response, err)
			}
			defer connection.Close(coderwebsocket.StatusNormalClosure, "")
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			err = connection.Write(ctx, coderwebsocket.MessageText, test.frame)
			cancel()
			if err != nil {
				t.Fatal(err)
			}
			if test.wantError {
				if eventType := readResponsesWebSocketEvent(t, connection); eventType != "error" {
					t.Fatalf("event type = %q, want error", eventType)
				}
			}
			ctx, cancel = context.WithTimeout(context.Background(), 3*time.Second)
			_, _, readErr := connection.Read(ctx)
			cancel()
			if status := coderwebsocket.CloseStatus(readErr); status != test.wantClose {
				t.Fatalf("close status = %v, want %v (err=%v)", status, test.wantClose, readErr)
			}
		})
	}
}
func TestResponsesWebSocketClientDisconnectCancelsUpstream(t *testing.T) {
	broker := &responsesWebSocketTestBroker{waitForCancel: true, started: make(chan struct{}), canceled: make(chan struct{})}
	servers, rawKey := newResponsesTestServerWithBroker(t, "", nil, broker)
	defer shutdownResponsesTestServer(t, servers)
	connection, response, err := dialResponsesWebSocket(t, servers.DataAddr(), rawKey, nil)
	if err != nil || response == nil {
		t.Fatalf("websocket dial: response=%#v err=%v", response, err)
	}
	writeResponsesWebSocketCreate(t, connection, "gpt-5.6-sol")
	select {
	case <-broker.started:
	case <-time.After(3 * time.Second):
		t.Fatal("active turn did not start")
	}
	_ = connection.Close(coderwebsocket.StatusNormalClosure, "")
	select {
	case <-broker.canceled:
	case <-time.After(3 * time.Second):
		t.Fatal("client disconnect did not cancel upstream")
	}
}

func TestResponsesWebSocketAdmissionFailureMarksJournalFailed(t *testing.T) {
	policy := &apikey.Policy{
		Name:                    "ws-admission-failure",
		Owner:                   "ws-admission-failure",
		AllowedEndpoints:        []string{responsesEndpoint},
		AllowedModels:           []string{"gpt-5.6-sol"},
		PeriodDuration:          time.Hour,
		PeriodTokenLimit:        1,
		TokenReservationDefault: 2,
	}
	servers, rawKey := newResponsesTestServerWithBroker(t, "", policy, &responsesWebSocketTestBroker{})
	defer shutdownResponsesTestServer(t, servers)
	connection, response, err := dialResponsesWebSocket(t, servers.DataAddr(), rawKey, nil)
	if err != nil || response == nil {
		t.Fatalf("websocket dial: response=%#v err=%v", response, err)
	}
	defer connection.Close(coderwebsocket.StatusNormalClosure, "")
	writeResponsesWebSocketCreate(t, connection, "gpt-5.6-sol")
	if eventType := readResponsesWebSocketEvent(t, connection); eventType != "error" {
		t.Fatalf("admission error event type = %q", eventType)
	}
	deadline := time.Now().Add(2 * time.Second)
	var record RequestRecord
	for {
		err := servers.journal.db.Order("accepted_at DESC").First(&record).Error
		if err == nil && record.TerminalAt != nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("admission request did not reach terminal state: %v", err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	if record.Status != requestStatusFailed {
		t.Fatalf("admission request status = %q, want %q", record.Status, requestStatusFailed)
	}
}
func TestResponseEventTurnStateIsReplacementOnly(t *testing.T) {
	state := responseEventTurnState(codex.CodexResponseStreamEvent{
		Type:    codex.CodexEventResponseMetadata,
		Headers: map[string]string{codex.TurnStateHeader: "replace-state"},
	})
	if state != "replace-state" {
		t.Fatalf("metadata turn state = %q", state)
	}
	if next := responseEventTurnState(codex.CodexResponseStreamEvent{
		Type:    codex.CodexEventResponseCompleted,
		Headers: map[string]string{codex.TurnStateHeader: "must-not-carry"},
	}); next != "" {
		t.Fatalf("non-metadata turn state = %q, want empty", next)
	}
}

func TestNilQuotaLeaseIsSuccessfulNoop(t *testing.T) {
	var lease *quotaLease
	if err := lease.reconcile(apikey.QuotaUsage{Tokens: 1}); err != nil {
		t.Fatalf("nil lease reconcile: %v", err)
	}
	if err := lease.release("test"); err != nil {
		t.Fatalf("nil lease release: %v", err)
	}
}

func TestResponsesWebSocketDisablesCompression(t *testing.T) {
	servers, rawKey := newResponsesTestServerWithBroker(t, "", nil, &responsesWebSocketTestBroker{})
	defer shutdownResponsesTestServer(t, servers)
	headers := make(http.Header)
	headers.Set("Authorization", "Bearer "+rawKey)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	connection, response, err := coderwebsocket.Dial(ctx, "ws://"+servers.DataAddr()+responsesEndpoint, &coderwebsocket.DialOptions{
		HTTPHeader:      headers,
		CompressionMode: coderwebsocket.CompressionContextTakeover,
	})
	if err != nil || response == nil {
		t.Fatalf("compressed websocket dial: response=%#v err=%v", response, err)
	}
	defer connection.Close(coderwebsocket.StatusNormalClosure, "")
	if extension := response.Header.Get("Sec-WebSocket-Extensions"); extension != "" {
		t.Fatalf("compression negotiated unexpectedly: %q", extension)
	}
}

func TestResponsesWebSocketSequentialTurnsAndMetadata(t *testing.T) {
	broker := &responsesWebSocketTestBroker{
		selections: make(chan codex.SelectionRequest, 2),
		privates:   make(chan codex.CodexResponseRequest, 2),
	}
	servers, rawKey := newResponsesTestServerWithBroker(t, "", nil, broker)
	defer shutdownResponsesTestServer(t, servers)
	headers := make(http.Header)
	headers.Set(codex.ResponsesLiteHeader, "true")
	headers.Set(codex.TurnMetadataHeader, `{"session_id":"ws-session","thread_id":"ws-thread"}`)
	connection, response, err := dialResponsesWebSocket(t, servers.DataAddr(), rawKey, headers)
	if err != nil || response == nil {
		t.Fatalf("websocket dial: response=%#v err=%v", response, err)
	}
	defer connection.Close(coderwebsocket.StatusNormalClosure, "")

	writeResponsesWebSocketCreate(t, connection, "gpt-5.6-sol")
	if eventType := readResponsesWebSocketEvent(t, connection); eventType != codex.CodexEventResponseCompleted {
		t.Fatalf("first event type = %q", eventType)
	}
	writeResponsesWebSocketCreate(t, connection, "gpt-5.6-sol")
	if eventType := readResponsesWebSocketEvent(t, connection); eventType != codex.CodexEventResponseCompleted {
		t.Fatalf("second event type = %q", eventType)
	}
	if got := broker.calls.Load(); got != 2 {
		t.Fatalf("broker calls = %d, want 2", got)
	}
	selection := <-broker.selections
	private := <-broker.privates
	if selection.Headers.SessionID != "ws-session" || selection.Headers.ThreadID != "ws-thread" || !selection.Headers.ResponsesLiteRequested {
		t.Fatalf("selection headers = %#v", selection.Headers)
	}
	if !private.ResponsesLite {
		t.Fatalf("private Responses Lite = false, want true")
	}
}
func TestResponsesConnectionLimitRetryKeepsSelectedAccount(t *testing.T) {
	t.Run("sse", func(t *testing.T) {
		broker := &responsesWebSocketTestBroker{connectionLimit: true, forcedIDs: make(chan string, 2)}
		servers, rawKey := newResponsesTestServerWithBroker(t, "", nil, broker)
		defer shutdownResponsesTestServer(t, servers)
		response := doResponsesRequest(t, servers.DataAddr(), rawKey, `{"model":"gpt-5.6-sol","stream":true}`, "application/json")
		body, err := io.ReadAll(response.Body)
		_ = response.Body.Close()
		if err != nil {
			t.Fatal(err)
		}
		if response.StatusCode != http.StatusOK || !strings.Contains(string(body), `"type":"response.completed"`) {
			t.Fatalf("status=%d body=%s", response.StatusCode, body)
		}
		firstForced, secondForced := <-broker.forcedIDs, <-broker.forcedIDs
		if firstForced != "" || secondForced != "ws-account" {
			t.Fatalf("forced account IDs = %q, %q", firstForced, secondForced)
		}
	})
	t.Run("websocket", func(t *testing.T) {
		broker := &responsesWebSocketTestBroker{connectionLimit: true, forcedIDs: make(chan string, 2)}
		servers, rawKey := newResponsesTestServerWithBroker(t, "", nil, broker)
		defer shutdownResponsesTestServer(t, servers)
		connection, response, err := dialResponsesWebSocket(t, servers.DataAddr(), rawKey, nil)
		if err != nil || response == nil {
			t.Fatalf("websocket dial: response=%#v err=%v", response, err)
		}
		defer connection.Close(coderwebsocket.StatusNormalClosure, "")
		writeResponsesWebSocketCreate(t, connection, "gpt-5.6-sol")
		if eventType := readResponsesWebSocketEvent(t, connection); eventType != codex.CodexEventResponseCompleted {
			t.Fatalf("event type = %q", eventType)
		}
		firstForced, secondForced := <-broker.forcedIDs, <-broker.forcedIDs
		if firstForced != "" || secondForced != "ws-account" {
			t.Fatalf("forced account IDs = %q, %q", firstForced, secondForced)
		}
	})
}

func TestResponsesFailedDoneMarksJournalFailedWithoutLink(t *testing.T) {
	assertFailed := func(t *testing.T, servers *Servers) {
		t.Helper()
		deadline := time.Now().Add(2 * time.Second)
		var record RequestRecord
		for {
			err := servers.journal.db.Order("accepted_at DESC").First(&record).Error
			if err == nil && record.TerminalAt != nil {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("request did not reach terminal state: %v", err)
			}
			time.Sleep(10 * time.Millisecond)
		}
		if record.Status != requestStatusFailed {
			t.Fatalf("request status = %q, want %q", record.Status, requestStatusFailed)
		}
		var links int64
		if err := servers.journal.db.Model(&ResponseLinkRecord{}).Where("response_id LIKE ?", "ws-response-%").Count(&links).Error; err != nil {
			t.Fatal(err)
		}
		if links != 0 {
			t.Fatalf("response links = %d, want 0", links)
		}
	}
	t.Run("sse", func(t *testing.T) {
		broker := &responsesWebSocketTestBroker{responseType: codex.CodexEventResponseDone, responseStatus: codex.CodexResponseStatusFailed}
		servers, rawKey := newResponsesTestServerWithBroker(t, "", nil, broker)
		defer shutdownResponsesTestServer(t, servers)
		response := doResponsesRequest(t, servers.DataAddr(), rawKey, `{"model":"gpt-5.6-sol","stream":true}`, "application/json")
		body, err := io.ReadAll(response.Body)
		_ = response.Body.Close()
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(body), `"type":"response.failed"`) || strings.Contains(string(body), `"type":"response.completed"`) {
			t.Fatalf("failed stream body = %s", body)
		}
		assertFailed(t, servers)
	})
	t.Run("websocket", func(t *testing.T) {
		broker := &responsesWebSocketTestBroker{responseType: codex.CodexEventResponseDone, responseStatus: codex.CodexResponseStatusFailed}
		servers, rawKey := newResponsesTestServerWithBroker(t, "", nil, broker)
		defer shutdownResponsesTestServer(t, servers)
		connection, response, err := dialResponsesWebSocket(t, servers.DataAddr(), rawKey, nil)
		if err != nil || response == nil {
			t.Fatalf("websocket dial: response=%#v err=%v", response, err)
		}
		defer connection.Close(coderwebsocket.StatusNormalClosure, "")
		writeResponsesWebSocketCreate(t, connection, "gpt-5.6-sol")
		if eventType := readResponsesWebSocketEvent(t, connection); eventType != codex.CodexEventResponseFailed {
			t.Fatalf("event type = %q", eventType)
		}
		assertFailed(t, servers)
	})
}

func TestResponsesWebSocketTerminalPersistsResponseLinkBeforeDelivery(t *testing.T) {
	broker := &responsesWebSocketTestBroker{}
	servers, rawKey := newResponsesTestServerWithBroker(t, "", nil, broker)
	defer shutdownResponsesTestServer(t, servers)
	connection, response, err := dialResponsesWebSocket(t, servers.DataAddr(), rawKey, nil)
	if err != nil || response == nil {
		t.Fatalf("websocket dial: response=%#v err=%v", response, err)
	}
	defer connection.Close(coderwebsocket.StatusNormalClosure, "")
	writeResponsesWebSocketCreate(t, connection, "gpt-5.6-sol")
	if eventType := readResponsesWebSocketEvent(t, connection); eventType != codex.CodexEventResponseCompleted {
		t.Fatalf("event type = %q", eventType)
	}
	var link ResponseLinkRecord
	if err := servers.journal.db.Where("response_id = ?", "ws-response-1").First(&link).Error; err != nil {
		t.Fatalf("response link before client delivery: %v", err)
	}
	if link.AccountID != "ws-account" || link.APIKeyID == "" || link.RequestID == "" || link.ConversationID == "" {
		t.Fatalf("response link = %+v", link)
	}
	resolved, err := servers.journal.ResolvePreviousResponse(context.Background(), "ws-response-1", link.APIKeyID)
	if err != nil {
		t.Fatalf("resolve persisted response link: %v", err)
	}
	if resolved.SourceRequestID != link.RequestID || resolved.ConversationID != link.ConversationID || resolved.AccountID != "ws-account" {
		t.Fatalf("resolved metadata = %+v, link = %+v", resolved, link)
	}
}

func TestResponsesWebSocketTurnStateOnlyRetriesSameTurn(t *testing.T) {
	turnStates := make(chan string, 3)
	var upstreamCalls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		call := upstreamCalls.Add(1)
		turnStates <- request.Header.Get(codex.TurnStateHeader)
		writer.Header().Set("Content-Type", "text/event-stream")
		if call == 1 {
			_, _ = io.WriteString(writer, "data: {\"type\":\"response.metadata\",\"sequence_number\":0,\"headers\":{\"x-codex-turn-state\":\"replacement-state\"}}\n\ndata: {\"type\":\"error\",\"sequence_number\":1,\"code\":\"websocket_connection_limit_reached\",\"message\":\"limit\"}\n\ndata: [DONE]\n\n")
			return
		}
		_, _ = io.WriteString(writer, fmt.Sprintf("data: {\"type\":\"response.completed\",\"sequence_number\":0,\"response\":{\"id\":\"turn-response-%d\",\"model\":\"gpt-5.6-sol\",\"status\":\"completed\"}}\n\ndata: [DONE]\n\n", call))
	}))
	defer upstream.Close()
	activeKey, err := envelope.NewKey(1, make([]byte, envelope.KeySize))
	if err != nil {
		t.Fatal(err)
	}
	keys, err := envelope.NewKeySet(activeKey)
	if err != nil {
		t.Fatal(err)
	}
	credentialPath := t.TempDir() + "/credential.enc"
	if err := codex.SaveCredential(credentialPath, codex.Credential{
		AccessToken: "access", RefreshToken: "refresh", AccountID: "ws-account", ExpiresAt: time.Now().Add(time.Hour),
	}, keys); err != nil {
		t.Fatal(err)
	}
	refresher, err := codex.NewRefresher(credentialPath, keys, codex.RefresherOptions{Issuer: upstream.URL, ClientID: "client"})
	if err != nil {
		t.Fatal(err)
	}
	transport, err := codex.NewResponsesTransport(codex.ResponsesTransportOptions{
		Policy: codex.ResponsesTransportSSE, ResponsesURL: upstream.URL, Refresher: refresher,
	})
	if err != nil {
		t.Fatal(err)
	}
	broker, err := NewProfileBroker(codex.SingleSelector{}, []BrokerProfile{{
		Account:   codex.Account{ID: "ws-account", IsDefault: true, Enabled: true, Available: true},
		Responses: transport,
	}})
	if err != nil {
		t.Fatal(err)
	}
	servers, rawKey := newResponsesTestServerWithBroker(t, "", nil, broker)
	defer shutdownResponsesTestServer(t, servers)
	connection, response, err := dialResponsesWebSocket(t, servers.DataAddr(), rawKey, nil)
	if err != nil || response == nil {
		t.Fatalf("websocket dial: response=%#v err=%v", response, err)
	}
	defer connection.Close(coderwebsocket.StatusNormalClosure, "")
	writeResponsesWebSocketCreate(t, connection, "gpt-5.6-sol")
	if eventType := readResponsesWebSocketEvent(t, connection); eventType != codex.CodexEventResponseCompleted {
		t.Fatalf("replacement event type = %q", eventType)
	}
	writeResponsesWebSocketCreate(t, connection, "gpt-5.6-sol")
	if eventType := readResponsesWebSocketEvent(t, connection); eventType != codex.CodexEventResponseCompleted {
		t.Fatalf("sequential event type = %q", eventType)
	}
	if got := upstreamCalls.Load(); got != 3 {
		t.Fatalf("upstream calls = %d, want 3", got)
	}
	firstState, replacementState, secondTurnState := <-turnStates, <-turnStates, <-turnStates
	if firstState != "" || replacementState != "replacement-state" || secondTurnState != "" {
		t.Fatalf("turn states = %q, %q, %q", firstState, replacementState, secondTurnState)
	}
}

func TestResponsesContinuationRetryRebuildsFullTranscriptOnce(t *testing.T) {
	broker := &responsesWebSocketTestBroker{
		previousNotFoundOnCall: 2,
		privates:               make(chan codex.CodexResponseRequest, 3),
	}
	servers, rawKey := newResponsesTestServerWithBroker(t, "", nil, broker)
	defer shutdownResponsesTestServer(t, servers)
	first := doResponsesRequest(t, servers.DataAddr(), rawKey, `{"model":"gpt-5.6-sol","stream":true,"input":"first"}`, "application/json")
	firstBody, err := io.ReadAll(first.Body)
	_ = first.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if first.StatusCode != http.StatusOK || !strings.Contains(string(firstBody), `"id":"ws-response-1"`) {
		t.Fatalf("first response status=%d body=%s", first.StatusCode, firstBody)
	}
	second := doResponsesRequest(t, servers.DataAddr(), rawKey, `{"model":"gpt-5.6-sol","stream":true,"previous_response_id":"ws-response-1","input":"second"}`, "application/json")
	secondBody, err := io.ReadAll(second.Body)
	_ = second.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if second.StatusCode != http.StatusOK || !strings.Contains(string(secondBody), `"id":"ws-response-3"`) {
		t.Fatalf("continuation response status=%d body=%s", second.StatusCode, secondBody)
	}
	if broker.calls.Load() != 3 {
		t.Fatalf("broker calls = %d, want 3", broker.calls.Load())
	}
	privateBodies := make([]string, 0, 3)
	for range 3 {
		private, ok := <-broker.privates
		if !ok {
			t.Fatal("private request channel closed")
		}
		payload, err := json.Marshal(private)
		if err != nil {
			t.Fatal(err)
		}
		privateBodies = append(privateBodies, string(payload))
	}
	if !strings.Contains(privateBodies[2], "first") || !strings.Contains(privateBodies[2], "second") {
		t.Fatalf("fallback private request omitted transcript: %s", privateBodies[2])
	}
}

func TestResponsesWebSocketContinuationRetryRebuildsFullTranscript(t *testing.T) {
	broker := &responsesWebSocketTestBroker{
		previousNotFoundOnCall: 2,
		privates:               make(chan codex.CodexResponseRequest, 3),
	}
	servers, rawKey := newResponsesTestServerWithBroker(t, "", nil, broker)
	defer shutdownResponsesTestServer(t, servers)
	connection, response, err := dialResponsesWebSocket(t, servers.DataAddr(), rawKey, nil)
	if err != nil || response == nil {
		t.Fatalf("websocket dial: response=%#v err=%v", response, err)
	}
	defer connection.Close(coderwebsocket.StatusNormalClosure, "")
	writeCreate := func(input, previousResponseID string) {
		t.Helper()
		payload := `{"type":"response.create","model":"gpt-5.6-sol","input":` + strconv.Quote(input)
		if previousResponseID != "" {
			payload += `,"previous_response_id":` + strconv.Quote(previousResponseID)
		}
		payload += `}`
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := connection.Write(ctx, coderwebsocket.MessageText, []byte(payload)); err != nil {
			t.Fatal(err)
		}
	}
	readCompleted := func() string {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		for {
			messageType, payload, err := connection.Read(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if messageType != coderwebsocket.MessageText {
				t.Fatalf("message type = %v, want text", messageType)
			}
			var event struct {
				Type     string `json:"type"`
				Response struct {
					ID string `json:"id"`
				} `json:"response"`
			}
			if err := json.Unmarshal(payload, &event); err != nil {
				t.Fatal(err)
			}
			if event.Type == codex.CodexEventResponseCompleted {
				return event.Response.ID
			}
		}
	}
	writeCreate("first", "")
	firstResponseID := readCompleted()
	if firstResponseID != "ws-response-1" {
		t.Fatalf("first response ID = %q", firstResponseID)
	}
	var firstLink ResponseLinkRecord
	if err := servers.journal.db.Where("response_id = ?", firstResponseID).First(&firstLink).Error; err != nil {
		t.Fatalf("first response link: %v", err)
	}
	var firstRequest RequestRecord
	if err := servers.journal.db.Where("request_id = ?", firstLink.RequestID).First(&firstRequest).Error; err != nil {
		t.Fatalf("first request: %v", err)
	}
	var apiKeyRecord apikey.Record
	if err := servers.journal.db.Where("id = ?", firstLink.APIKeyID).First(&apiKeyRecord).Error; err != nil {
		t.Fatalf("API key owner: %v", err)
	}
	if apiKeyRecord.Owner != "test" || firstLink.APIKeyID != firstRequest.APIKeyID ||
		firstLink.AccountID != firstRequest.AccountID || firstLink.AccountID != "ws-account" ||
		firstLink.ConversationID != firstRequest.ConversationID {
		t.Fatalf("first owner/link/request mismatch: owner=%q link=%+v request=%+v", apiKeyRecord.Owner, firstLink, firstRequest)
	}
	writeCreate("second", firstResponseID)
	secondResponseID := readCompleted()
	if secondResponseID != "ws-response-3" {
		t.Fatalf("second response ID = %q", secondResponseID)
	}
	var secondLink ResponseLinkRecord
	if err := servers.journal.db.Where("response_id = ?", secondResponseID).First(&secondLink).Error; err != nil {
		t.Fatalf("second response link: %v", err)
	}
	if secondLink.APIKeyID != firstLink.APIKeyID || secondLink.AccountID != firstLink.AccountID ||
		secondLink.ConversationID != firstLink.ConversationID || secondLink.RequestID == firstLink.RequestID {
		t.Fatalf("continuation link mismatch: first=%+v second=%+v", firstLink, secondLink)
	}
	if got := broker.calls.Load(); got != 3 {
		t.Fatalf("broker calls = %d, want 3", got)
	}
	privateBodies := make([]string, 0, 3)
	for range 3 {
		private, ok := <-broker.privates
		if !ok {
			t.Fatal("private request channel closed")
		}
		payload, err := json.Marshal(private)
		if err != nil {
			t.Fatal(err)
		}
		privateBodies = append(privateBodies, string(payload))
	}
	if !strings.Contains(privateBodies[0], "first") || !strings.Contains(privateBodies[1], "second") ||
		!strings.Contains(privateBodies[2], "first") || !strings.Contains(privateBodies[2], "second") {
		t.Fatalf("private transcript requests = %s", privateBodies)
	}
}

func TestResponsesWebSocketConcurrentFrameCancelsTurn(t *testing.T) {
	for _, test := range []struct {
		name        string
		messageType coderwebsocket.MessageType
		frame       []byte
		wantStatus  coderwebsocket.StatusCode
	}{
		{name: "text", messageType: coderwebsocket.MessageText, frame: []byte(`{"type":"response.create","model":"gpt-5.6-sol"}`), wantStatus: coderwebsocket.StatusPolicyViolation},
		{name: "binary", messageType: coderwebsocket.MessageBinary, frame: []byte("binary"), wantStatus: coderwebsocket.StatusUnsupportedData},
	} {
		t.Run(test.name, func(t *testing.T) {
			broker := &responsesWebSocketTestBroker{waitForCancel: true, started: make(chan struct{}), canceled: make(chan struct{})}
			servers, rawKey := newResponsesTestServerWithBroker(t, "", nil, broker)
			defer shutdownResponsesTestServer(t, servers)
			connection, response, err := dialResponsesWebSocket(t, servers.DataAddr(), rawKey, nil)
			if err != nil || response == nil {
				t.Fatalf("websocket dial: response=%#v err=%v", response, err)
			}
			defer connection.Close(coderwebsocket.StatusNormalClosure, "")
			writeResponsesWebSocketCreate(t, connection, "gpt-5.6-sol")
			select {
			case <-broker.started:
			case <-time.After(3 * time.Second):
				t.Fatal("broker turn did not start")
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			if err := connection.Write(ctx, test.messageType, test.frame); err != nil {
				cancel()
				t.Fatal(err)
			}
			cancel()
			select {
			case <-broker.canceled:
			case <-time.After(3 * time.Second):
				t.Fatal("active turn was not canceled")
			}
			for {
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				_, _, readErr := connection.Read(ctx)
				cancel()
				if status := coderwebsocket.CloseStatus(readErr); status != -1 {
					if status != test.wantStatus {
						t.Fatalf("close status = %v, want %v (err=%v)", status, test.wantStatus, readErr)
					}
					break
				}
				if readErr != nil && !errors.Is(readErr, context.DeadlineExceeded) {
					continue
				}
			}
		})
	}
}

func TestPublicEventPayloadResponseDoneStatus(t *testing.T) {
	for _, test := range []struct {
		status string
		want   string
	}{
		{status: codex.CodexResponseStatusCompleted, want: codex.CodexEventResponseCompleted},
		{status: codex.CodexResponseStatusIncomplete, want: codex.CodexEventResponseIncomplete},
		{status: codex.CodexResponseStatusFailed, want: codex.CodexEventResponseFailed},
	} {
		t.Run(test.status, func(t *testing.T) {
			payload, keep, err := publicEventPayload(codex.CodexResponseStreamEvent{
				Type:     codex.CodexEventResponseDone,
				Response: &codex.CodexResponse{Status: test.status},
			})
			if err != nil || !keep {
				t.Fatalf("payload keep=%v err=%v", keep, err)
			}
			var event struct {
				Type string `json:"type"`
			}
			if err := json.Unmarshal(payload, &event); err != nil {
				t.Fatal(err)
			}
			if event.Type != test.want {
				t.Fatalf("event type = %q, want %q", event.Type, test.want)
			}
		})
	}
}
