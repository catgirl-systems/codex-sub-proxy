package codex

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"syscall"
	"time"

	coderwebsocket "github.com/coder/websocket"
	"golang.org/x/net/http/httpguts"
)

const (
	defaultResponsesURL = "https://chatgpt.com/backend-api/codex/responses"

	responsesWebSocketBeta = "responses_websockets=2026-02-06"

	codexDialTimeout     = 10 * time.Second
	codexReadTimeout     = 2 * time.Minute
	codexWriteTimeout    = 10 * time.Second
	codexHTTPTimeout     = 5 * time.Minute
	maxCodexRequestBytes = maxCodexStreamPayloadBytes
)

// ResponsesTransportPolicy selects the private Responses transport.
type ResponsesTransportPolicy string

const (
	ResponsesTransportWebSocketPreferred ResponsesTransportPolicy = "websocket_preferred"
	ResponsesTransportSSE                ResponsesTransportPolicy = "sse"
)

// ResponsesTransportOptions contains the private Responses endpoints and auth.
type ResponsesTransportOptions struct {
	Policy       ResponsesTransportPolicy
	ResponsesURL string
	WebSocketURL string
	HTTPClient   *http.Client
	Refresher    *Refresher
	Headers      HeaderConfig
}

// ResponsesTransport sends one private Responses request.
type ResponsesTransport struct {
	policy       ResponsesTransportPolicy
	responsesURL string
	webSocketURL string
	httpClient   *http.Client
	refresher    *Refresher
	headers      HeaderConfig
}

type codexWebSocketRequest struct {
	Type string `json:"type"`
	CodexResponseRequest
}

// ErrCodexTransport means that the upstream transport failed before a result.
var ErrCodexTransport = errors.New("codex transport failed")

var errCodexAggregateLimit = errors.New("codex stream aggregate size exceeds limit")

// NewResponsesTransport validates and creates a private Responses transport.
func NewResponsesTransport(options ResponsesTransportOptions) (*ResponsesTransport, error) {
	policy := options.Policy
	if policy == "" {
		policy = ResponsesTransportWebSocketPreferred
	}
	if policy != ResponsesTransportWebSocketPreferred && policy != ResponsesTransportSSE {
		return nil, fmt.Errorf("responses transport policy %q is not supported", policy)
	}
	responsesURL := strings.TrimSpace(options.ResponsesURL)
	if responsesURL == "" {
		responsesURL = defaultResponsesURL
	}
	if err := validateHTTPURL(responsesURL); err != nil {
		return nil, fmt.Errorf("responses URL: %w", err)
	}
	webSocketURL := strings.TrimSpace(options.WebSocketURL)
	if webSocketURL == "" {
		webSocketURL, _ = websocketURL(responsesURL)
	}
	if err := validateWebSocketURL(webSocketURL); err != nil {
		return nil, fmt.Errorf("websocket URL: %w", err)
	}
	if options.Refresher == nil {
		return nil, errors.New("codex credential refresher is required")
	}
	client := options.HTTPClient
	if client == nil {
		client = http.DefaultClient
	}
	return &ResponsesTransport{
		policy:       policy,
		responsesURL: responsesURL,
		webSocketURL: webSocketURL,
		httpClient:   client,
		refresher:    options.Refresher,
		headers:      options.Headers,
	}, nil
}

// Do sends one private Responses request and returns all validated stream events.
func (transport *ResponsesTransport) Do(ctx context.Context, request CodexResponseRequest) (CodexStreamResult, error) {
	return transport.DoWithHeaders(ctx, request, RequestHeaderConfig{})
}

// DoWithHeaders sends one request with bounded per-call header variations.
func (transport *ResponsesTransport) DoWithHeaders(ctx context.Context, request CodexResponseRequest, requestHeaders RequestHeaderConfig) (CodexStreamResult, error) {
	if ctx == nil {
		return CodexStreamResult{}, errors.New("codex transport context is nil")
	}
	if err := requestHeaders.Validate(); err != nil {
		return CodexStreamResult{}, err
	}
	body, err := json.Marshal(request)
	if err != nil {
		return CodexStreamResult{}, fmt.Errorf("encode codex Responses request: %w", err)
	}
	if len(body) == 0 || len(body) > maxCodexRequestBytes {
		return CodexStreamResult{}, fmt.Errorf("%w: request message exceeds limit", ErrCodexStreamMalformed)
	}
	var webSocketBody []byte
	if transport.policy != ResponsesTransportSSE {
		webSocketBody, err = json.Marshal(codexWebSocketRequest{
			Type:                 "response.create",
			CodexResponseRequest: request,
		})
		if err != nil {
			return CodexStreamResult{}, fmt.Errorf("encode Codex WebSocket request: %w", err)
		}
		if len(webSocketBody) == 0 || len(webSocketBody) > maxCodexRequestBytes {
			return CodexStreamResult{}, fmt.Errorf("%w: WebSocket request message exceeds limit", ErrCodexStreamMalformed)
		}
	}

	var state transportResultState
	response, err := transport.refresher.Do(ctx, true, func(attemptContext context.Context, credential Credential) (*http.Response, error) {
		headers := transport.headers
		headers = mergeRequestHeaders(headers, requestHeaders)
		headers.AccessToken = credential.AccessToken
		headers.AccountID = credential.AccountID
		headers.ResponsesLite = headers.ResponsesLite || requestHeaders.ResponsesLiteRequested || request.ResponsesLite
		headers.TurnState = turnStateFromContext(attemptContext)
		if credential.AccountIsFedRAMP {
			headers.FedRAMP = true
		}
		result, authResponse, attemptErr := transport.attempt(attemptContext, body, webSocketBody, headers)
		if authResponse != nil {
			return authResponse, nil
		}
		if attemptErr != nil {
			if len(result.Events) != 0 || result.Response != nil {
				state.result = result
			}
			return nil, attemptErr
		}
		state.result = result
		state.ready = true
		return &http.Response{StatusCode: http.StatusOK, Body: http.NoBody}, nil
	})
	if err != nil {
		if response != nil {
			closeHTTPResponse(response)
		}
		if contextErr := context.Cause(ctx); contextErr != nil {
			return state.result, contextErr
		}
		return state.result, err
	}
	if !state.ready {
		if response != nil {
			return CodexStreamResult{}, mapHTTPResponseError(response)
		}
		return CodexStreamResult{}, errors.New("codex transport returned no result")
	}

	if response != nil {
		closeHTTPResponse(response)
	}
	return state.result, nil
}

// Compact sends one private Responses compaction request.
func (transport *ResponsesTransport) Compact(ctx context.Context, request CodexCompactRequest) (CodexCompactResult, error) {
	return transport.CompactWithHeaders(ctx, request, RequestHeaderConfig{})
}

// CompactWithHeaders sends one compaction request with bounded per-call header variations.
func (transport *ResponsesTransport) CompactWithHeaders(ctx context.Context, request CodexCompactRequest, requestHeaders RequestHeaderConfig) (CodexCompactResult, error) {
	if ctx == nil {
		return CodexCompactResult{}, errors.New("codex transport context is nil")
	}
	if err := requestHeaders.Validate(); err != nil {
		return CodexCompactResult{}, err
	}
	if err := request.validate(); err != nil {
		return CodexCompactResult{}, err
	}
	body, err := json.Marshal(request)
	if err != nil {
		return CodexCompactResult{}, fmt.Errorf("encode codex compact request: %w", err)
	}
	if len(body) == 0 || len(body) > maxCodexRequestBytes {
		return CodexCompactResult{}, fmt.Errorf("%w: compact request message exceeds limit", ErrCodexStreamMalformed)
	}
	compactURL, err := appendURLPath(transport.responsesURL, "compact")
	if err != nil {
		return CodexCompactResult{}, fmt.Errorf("build compact URL: %w", err)
	}

	operationContext, cancel := codexSSEContext(ctx, transport.httpClient.Timeout)
	defer cancel()
	response, err := transport.refresher.Do(operationContext, true, func(attemptContext context.Context, credential Credential) (*http.Response, error) {
		headers := mergeRequestHeaders(transport.headers, requestHeaders)
		headers.AccessToken = credential.AccessToken
		headers.AccountID = credential.AccountID
		headers.ResponsesLite = headers.ResponsesLite || requestHeaders.ResponsesLiteRequested || request.ResponsesLite
		if credential.AccountIsFedRAMP {
			headers.FedRAMP = true
		}
		request, requestErr := NewRequest(
			attemptContext,
			http.MethodPost,
			compactURL,
			bytes.NewReader(body),
			headers,
		)
		if requestErr != nil {
			return nil, requestErr
		}
		request.Header.Set("Accept", "application/json")
		request.Header.Set("Content-Type", "application/json")
		response, requestErr := transport.httpClient.Do(request)
		if requestErr != nil {
			if contextErr := context.Cause(ctx); contextErr != nil {
				return nil, contextErr
			}
			if contextErr := context.Cause(attemptContext); contextErr != nil {
				return nil, contextErr
			}
			return nil, fmt.Errorf("%w: compact request failed", ErrCodexTransport)
		}
		return response, nil
	})
	if err != nil {
		if response != nil {
			closeHTTPResponse(response)
		}
		if contextErr := context.Cause(ctx); contextErr != nil {
			return CodexCompactResult{}, contextErr
		}
		if contextErr := context.Cause(operationContext); contextErr != nil {
			return CodexCompactResult{}, contextErr
		}
		return CodexCompactResult{}, err
	}
	if response == nil {
		return CodexCompactResult{}, fmt.Errorf("%w: compact response is nil", ErrCodexTransport)
	}
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return CodexCompactResult{}, mapHTTPResponseError(response)
	}
	defer closeHTTPResponse(response)
	if response.Body == nil {
		return CodexCompactResult{}, fmt.Errorf("%w: compact response body is nil", ErrCodexTransport)
	}
	reader := &codexContextReader{ctx: operationContext, reader: io.LimitReader(response.Body, maxCodexContractBytes+1)}
	resultBody, readErr := io.ReadAll(reader)
	if contextErr := context.Cause(ctx); contextErr != nil {
		return CodexCompactResult{}, contextErr
	}
	if contextErr := context.Cause(operationContext); contextErr != nil {
		return CodexCompactResult{}, contextErr
	}
	if readErr != nil {
		return CodexCompactResult{}, fmt.Errorf("%w: read compact response: %w", ErrCodexTransport, readErr)
	}
	if len(resultBody) == 0 || len(resultBody) > maxCodexContractBytes {
		return CodexCompactResult{}, fmt.Errorf("%w: compact response body exceeds limit", ErrCodexStreamMalformed)
	}
	var result CodexCompactResult
	if err := json.Unmarshal(resultBody, &result); err != nil {
		return CodexCompactResult{}, fmt.Errorf("%w: decode compact response: %w", ErrCodexStreamMalformed, err)
	}
	return result, nil
}

// Stream sends one request and delivers validated events in arrival order.
func (transport *ResponsesTransport) Stream(ctx context.Context, request CodexResponseRequest, onEvent func(CodexResponseStreamEvent) error) error {
	return transport.StreamWithHeaders(ctx, request, RequestHeaderConfig{}, onEvent)
}

// StreamWithHeaders streams one request with bounded per-call header variations.
func (transport *ResponsesTransport) StreamWithHeaders(ctx context.Context, request CodexResponseRequest, requestHeaders RequestHeaderConfig, onEvent func(CodexResponseStreamEvent) error) error {
	if ctx == nil {
		return errors.New("codex transport context is nil")
	}
	if err := requestHeaders.Validate(); err != nil {
		return err
	}
	if onEvent == nil {
		return errors.New("codex transport stream callback is nil")
	}
	body, err := json.Marshal(request)
	if err != nil {
		return fmt.Errorf("encode codex Responses request: %w", err)
	}
	if len(body) == 0 || len(body) > maxCodexRequestBytes {
		return fmt.Errorf("%w: request message exceeds limit", ErrCodexStreamMalformed)
	}
	var webSocketBody []byte
	if transport.policy != ResponsesTransportSSE {
		webSocketBody, err = json.Marshal(codexWebSocketRequest{
			Type:                 "response.create",
			CodexResponseRequest: request,
		})
		if err != nil {
			return fmt.Errorf("encode Codex WebSocket request: %w", err)
		}
		if len(webSocketBody) == 0 || len(webSocketBody) > maxCodexRequestBytes {
			return fmt.Errorf("%w: WebSocket request message exceeds limit", ErrCodexStreamMalformed)
		}
	}

	var state struct {
		result CodexStreamResult
		err    error
		ready  bool
	}
	response, err := transport.refresher.Do(ctx, true, func(attemptContext context.Context, credential Credential) (*http.Response, error) {
		headers := transport.headers
		headers = mergeRequestHeaders(headers, requestHeaders)
		headers.AccessToken = credential.AccessToken
		headers.AccountID = credential.AccountID
		headers.ResponsesLite = headers.ResponsesLite || requestHeaders.ResponsesLiteRequested || request.ResponsesLite
		headers.TurnState = turnStateFromContext(attemptContext)
		if credential.AccountIsFedRAMP {
			headers.FedRAMP = true
		}
		result, authResponse, attemptErr := transport.streamAttempt(attemptContext, body, webSocketBody, headers, onEvent)
		if authResponse != nil {
			return authResponse, nil
		}
		state.result = result
		if attemptErr != nil {
			state.err = attemptErr
			if context.Cause(ctx) != nil {
				return nil, attemptErr
			}
			return &http.Response{StatusCode: http.StatusOK, Body: http.NoBody}, nil
		}
		state.ready = true
		return &http.Response{StatusCode: http.StatusOK, Body: http.NoBody}, nil
	})
	if err != nil {
		if response != nil {
			closeHTTPResponse(response)
		}
		if contextErr := context.Cause(ctx); contextErr != nil {
			return contextErr
		}
		return err
	}
	if response != nil {
		closeHTTPResponse(response)
	}
	if state.err != nil {
		return state.err
	}
	if !state.ready {
		return errors.New("codex transport returned no stream")
	}
	return nil
}

func (transport *ResponsesTransport) streamAttempt(ctx context.Context, body, webSocketBody []byte, headers HeaderConfig, onEvent func(CodexResponseStreamEvent) error) (CodexStreamResult, *http.Response, error) {
	if transport.policy == ResponsesTransportSSE {
		return transport.trySSE(ctx, body, headers, onEvent)
	}
	buffer := &codexReplayBuffer{onEvent: onEvent}
	result, authResponse, err, fallback := transport.tryWebSocket(ctx, webSocketBody, headers, buffer.emit)
	if authResponse != nil && authResponse.StatusCode != http.StatusUnauthorized {
		err = mapHTTPResponseError(authResponse)
		authResponse = nil
		fallback = false
	}
	if err != nil && authResponse == nil && !buffer.emitted &&
		isSafeErrorCode(err, "websocket_connection_limit_reached") {
		// The failed connection is closed by tryWebSocket. Retry once before
		// replaying any event or allowing account-level error handling.
		buffer.discard()
		result, authResponse, err, fallback = transport.tryWebSocket(ctx, webSocketBody, headers, buffer.emit)
		if authResponse != nil && authResponse.StatusCode != http.StatusUnauthorized {
			err = mapHTTPResponseError(authResponse)
			authResponse = nil
			fallback = false
		}
	}
	if authResponse != nil || err == nil {
		return result, authResponse, err
	}
	if contextErr := context.Cause(ctx); contextErr != nil {
		return CodexStreamResult{}, nil, contextErr
	}
	if !fallback || buffer.emitted {
		return result, nil, err
	}
	buffer.discard()
	return transport.trySSE(ctx, body, headers, onEvent)
}

type codexReplayBuffer struct {
	pending []CodexResponseStreamEvent
	onEvent func(CodexResponseStreamEvent) error
	emitted bool
}

func (buffer *codexReplayBuffer) emit(event CodexResponseStreamEvent) error {
	if !buffer.emitted && codexWebSocketEventReplaySafe(event) {
		buffer.pending = append(buffer.pending, event)
		return nil
	}
	for _, pending := range buffer.pending {
		buffer.emitted = true
		if err := buffer.onEvent(pending); err != nil {
			buffer.pending = nil
			return err
		}
	}
	buffer.pending = nil
	buffer.emitted = true
	return buffer.onEvent(event)
}

func (buffer *codexReplayBuffer) discard() {
	buffer.pending = nil
}

type transportResultState struct {
	result CodexStreamResult
	ready  bool
}

func (transport *ResponsesTransport) attempt(ctx context.Context, body, webSocketBody []byte, headers HeaderConfig) (CodexStreamResult, *http.Response, error) {
	if transport.policy == ResponsesTransportSSE {
		return transport.trySSE(ctx, body, headers, nil)
	}
	result, authResponse, err, fallback := transport.tryWebSocket(ctx, webSocketBody, headers, nil)
	if authResponse != nil && authResponse.StatusCode != http.StatusUnauthorized {
		err = mapHTTPResponseError(authResponse)
		authResponse = nil
		fallback = false
	}
	if err != nil && authResponse == nil && isSafeErrorCode(err, "websocket_connection_limit_reached") {
		result, authResponse, err, fallback = transport.tryWebSocket(ctx, webSocketBody, headers, nil)
		if authResponse != nil && authResponse.StatusCode != http.StatusUnauthorized {
			err = mapHTTPResponseError(authResponse)
			authResponse = nil
			fallback = false
		}
	}
	if authResponse != nil || err == nil {
		return result, authResponse, err
	}
	if contextErr := context.Cause(ctx); contextErr != nil {
		return CodexStreamResult{}, nil, contextErr
	}
	if !fallback {
		return CodexStreamResult{}, nil, err
	}
	return transport.trySSE(ctx, body, headers, nil)
}

func (transport *ResponsesTransport) tryWebSocket(ctx context.Context, body []byte, headers HeaderConfig, onEvent func(CodexResponseStreamEvent) error) (CodexStreamResult, *http.Response, error, bool) {
	attemptContext := ctx
	cancelAttempt := func() {}
	if timeout := transport.httpClient.Timeout; timeout > 0 {
		attemptContext, cancelAttempt = context.WithTimeout(ctx, timeout)
	}
	defer cancelAttempt()

	dialContext, cancelDial := context.WithTimeout(attemptContext, codexDialTimeout)
	defer cancelDial()
	wsHeaders := headers
	wsHeaders.Beta = responsesWebSocketBeta
	httpHeaders, err := BuildHeaders(wsHeaders)
	if err != nil {
		return CodexStreamResult{}, nil, err, false
	}
	httpHeaders.Set("Accept", "application/json")
	connection, response, err := coderwebsocket.Dial(dialContext, transport.webSocketURL, &coderwebsocket.DialOptions{
		HTTPClient:      transport.httpClient,
		HTTPHeader:      httpHeaders,
		CompressionMode: coderwebsocket.CompressionDisabled,
	})
	if err != nil {
		if contextErr := context.Cause(ctx); contextErr != nil {
			return CodexStreamResult{}, nil, contextErr, false
		}
		if contextErr := context.Cause(attemptContext); contextErr != nil {
			return CodexStreamResult{}, nil, contextErr, false
		}
		if contextErr := context.Cause(dialContext); contextErr != nil {
			return CodexStreamResult{}, nil, contextErr, false
		}
		if response != nil {
			return transport.webSocketHandshakeFailure(response)
		}
		dialErr, fallback := webSocketDialFailure(transport.httpClient, err)
		return CodexStreamResult{}, nil, dialErr, fallback
	}
	return readCodexWebSocketStream(ctx, attemptContext, connection, body, onEvent)
}

func (transport *ResponsesTransport) webSocketHandshakeFailure(response *http.Response) (CodexStreamResult, *http.Response, error, bool) {
	body, _ := readHTTPErrorBody(response.Body)
	closeHTTPResponse(response)
	if response.StatusCode == http.StatusUnauthorized {
		response.Body = http.NoBody
		return CodexStreamResult{}, response, nil, false
	}
	fallback := webSocketFallbackStatus(response.StatusCode) || webSocketUnsupportedBody(body)
	return CodexStreamResult{}, nil, MapUpstreamError(response.StatusCode, response.Header, body), fallback
}

func readCodexWebSocketStream(callerContext, attemptContext context.Context, connection *coderwebsocket.Conn, body []byte, onEvent func(CodexResponseStreamEvent) error) (CodexStreamResult, *http.Response, error, bool) {
	if connection == nil {
		return CodexStreamResult{}, nil, fmt.Errorf("%w: WebSocket connection is nil", ErrCodexTransport), true
	}
	defer closeCodexWebSocket(attemptContext, connection)

	writeContext, cancel := context.WithTimeout(attemptContext, codexWriteTimeout)
	err := connection.Write(writeContext, coderwebsocket.MessageText, body)
	cancel()
	if err != nil {
		if contextErr := context.Cause(callerContext); contextErr != nil {
			return CodexStreamResult{}, nil, contextErr, false
		}
		if contextErr := context.Cause(attemptContext); contextErr != nil {
			return CodexStreamResult{}, nil, contextErr, false
		}
		return CodexStreamResult{}, nil, fmt.Errorf("%w: write WebSocket request", ErrCodexTransport), true
	}
	connection.SetReadLimit(maxCodexStreamLineBytes)

	var decoder codexStreamDecoder
	replayUnsafe := false
	snapshot := func() CodexStreamResult {
		return CodexStreamResult{
			Events:       decoder.events,
			TerminalType: decoder.terminalType,
			Response:     decoder.response,
		}
	}
	for {
		readContext, cancel := context.WithTimeout(attemptContext, codexReadTimeout)
		messageType, frame, err := connection.Read(readContext)
		cancel()
		if err != nil {
			if contextErr := context.Cause(callerContext); contextErr != nil {
				return snapshot(), nil, contextErr, false
			}
			if contextErr := context.Cause(attemptContext); contextErr != nil {
				return snapshot(), nil, contextErr, false
			}
			if errors.Is(err, coderwebsocket.ErrMessageTooBig) {
				return snapshot(), nil, fmt.Errorf("%w: WebSocket message exceeds limit", ErrCodexStreamMalformed), false
			}
			return snapshot(), nil, webSocketReadFailure(err), !replayUnsafe && webSocketReadFallback(err)
		}
		if messageType != coderwebsocket.MessageText && messageType != coderwebsocket.MessageBinary {
			return snapshot(), nil, fmt.Errorf("%w: WebSocket message type is invalid", ErrCodexStreamMalformed), false
		}
		if len(frame) == 0 || len(frame) > maxCodexStreamLineBytes {
			return snapshot(), nil, fmt.Errorf("%w: WebSocket message size is invalid", ErrCodexStreamMalformed), false
		}
		if err := decoder.reservePayload(len(frame)); err != nil {
			return snapshot(), nil, err, false
		}
		event, errorResponse, err := decodeCodexWebSocketMessage(frame)
		if err != nil {
			return snapshot(), nil, err, false
		}
		if errorResponse != nil {
			if errorResponse.StatusCode == http.StatusUnauthorized && !replayUnsafe {
				return snapshot(), errorResponse, nil, false
			}
			if replayUnsafe {
				return snapshot(), nil, mapHTTPResponseError(errorResponse), false
			}
			return snapshot(), errorResponse, nil, false
		}
		if !codexWebSocketEventReplaySafe(event) {
			replayUnsafe = true
		}
		if err := decoder.add(event); err != nil {
			return snapshot(), nil, err, false
		}
		if onEvent != nil {
			if err := onEvent(event); err != nil {
				return snapshot(), nil, err, false
			}
		}
		if isCodexTerminalEvent(event.Type) {
			result, finishErr := decoder.finish()
			return result, nil, finishErr, false
		}
	}
}

func decodeCodexWebSocketMessage(frame []byte) (CodexResponseStreamEvent, *http.Response, error) {
	var header struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(frame, &header); err != nil {
		return CodexResponseStreamEvent{}, nil, fmt.Errorf("%w: decode WebSocket frame: %v", ErrCodexStreamMalformed, err)
	}
	if strings.TrimSpace(header.Type) == "" {
		return CodexResponseStreamEvent{}, nil, fmt.Errorf("%w: event type is empty", ErrCodexStreamMalformed)
	}
	if header.Type == CodexEventError {
		var envelope CodexErrorEnvelope
		if err := json.Unmarshal(frame, &envelope); err != nil {
			return CodexResponseStreamEvent{}, nil, fmt.Errorf("%w: decode WebSocket error: %v", ErrCodexStreamMalformed, err)
		}
		status := envelope.Status
		present := status != 0
		if envelope.Status != 0 && envelope.StatusCode != 0 && envelope.Status != envelope.StatusCode {
			return CodexResponseStreamEvent{}, nil, fmt.Errorf("%w: error frame has conflicting status fields", ErrCodexStreamMalformed)
		}
		if !present {
			status = envelope.StatusCode
			present = status != 0
		}
		event, err := decodeCodexErrorEvent(frame)
		if err != nil {
			return CodexResponseStreamEvent{}, nil, err
		}
		if present && status >= 300 && status <= 599 {
			return CodexResponseStreamEvent{}, codexErrorResponse(frame, envelope, status), nil
		}
		return event, nil, nil
	}
	event, err := DecodeCodexWebSocketFrame(frame)
	if err != nil {
		return CodexResponseStreamEvent{}, nil, err
	}
	return event, nil, nil
}

func decodeCodexErrorEvent(frame []byte) (CodexResponseStreamEvent, error) {
	var wire struct {
		Type           string                     `json:"type"`
		SequenceNumber int                        `json:"sequence_number"`
		Error          *CodexError                `json:"error,omitempty"`
		Code           string                     `json:"code,omitempty"`
		Message        string                     `json:"message,omitempty"`
		Param          string                     `json:"param,omitempty"`
		Headers        map[string]json.RawMessage `json:"headers,omitempty"`
	}
	if err := json.Unmarshal(frame, &wire); err != nil {
		return CodexResponseStreamEvent{}, fmt.Errorf("%w: decode WebSocket error event: %v", ErrCodexStreamMalformed, err)
	}
	event := CodexResponseStreamEvent{
		Type:           wire.Type,
		SequenceNumber: wire.SequenceNumber,
		Error:          wire.Error,
		Code:           wire.Code,
		Message:        wire.Message,
		Param:          wire.Param,
		Raw:            append([]byte(nil), frame...),
	}
	if len(wire.Headers) != 0 {
		event.Headers = make(map[string]string, len(wire.Headers))
		for name, rawValue := range wire.Headers {
			rawValue = bytes.TrimSpace(rawValue)
			if len(rawValue) == 0 || bytes.Equal(rawValue, []byte("null")) {
				continue
			}
			var value string
			switch rawValue[0] {
			case '"':
				if err := json.Unmarshal(rawValue, &value); err != nil {
					continue
				}
			case 't', 'f':
				var boolean bool
				if err := json.Unmarshal(rawValue, &boolean); err != nil {
					continue
				}
				value = strconv.FormatBool(boolean)
			case '[', '{':
				continue
			default:
				var number json.Number
				if err := json.Unmarshal(rawValue, &number); err != nil {
					continue
				}
				value = number.String()
			}
			event.Headers[name] = value
		}
	}
	return event, nil
}

func codexErrorResponse(frame []byte, envelope CodexErrorEnvelope, status int) *http.Response {
	headers := codexErrorHeaders(envelope.Headers)
	return &http.Response{
		StatusCode: status,
		Header:     headers,
		Body:       io.NopCloser(bytes.NewReader(frame)),
	}
}

func codexErrorHeaders(rawHeaders map[string]json.RawMessage) http.Header {
	headers := make(http.Header)
	for name, rawValue := range rawHeaders {
		if !httpguts.ValidHeaderFieldName(name) {
			continue
		}
		rawValue = bytes.TrimSpace(rawValue)
		if len(rawValue) == 0 || bytes.Equal(rawValue, []byte("null")) {
			continue
		}
		var value string
		switch rawValue[0] {
		case '"':
			if err := json.Unmarshal(rawValue, &value); err != nil {
				continue
			}
		case 't', 'f':
			var boolean bool
			if err := json.Unmarshal(rawValue, &boolean); err != nil {
				continue
			}
			value = strconv.FormatBool(boolean)
		case '[', '{':
			continue
		default:
			var number json.Number
			if err := json.Unmarshal(rawValue, &number); err != nil {
				continue
			}
			value = number.String()
		}
		headers.Add(name, value)
	}
	return headers
}

func codexWebSocketEventReplaySafe(event CodexResponseStreamEvent) bool {
	switch event.Type {
	case CodexEventResponseCreated, "response.queued", "response.in_progress":
		if len(event.Headers) != 0 || event.Metadata != nil {
			return false
		}
	case CodexEventResponseMetadata, "response.rate_limits.updated":
	default:
		return false
	}
	if event.Item != nil || event.Part != nil || event.Error != nil ||
		event.Delta != "" || event.Arguments != "" || event.Text != "" ||
		len(event.Logprobs) != 0 || event.Code != "" || event.Message != "" ||
		event.ItemID != "" || event.PartialImageB64 != "" || event.PartialImageIndex != 0 {
		return false
	}
	if event.Response != nil &&
		(event.Response.OutputText != "" || len(event.Response.Output) != 0 || event.Response.Error != nil) {
		return false
	}
	return true
}

func webSocketReadFailure(err error) error {
	if code := coderwebsocket.CloseStatus(err); code != -1 {
		return fmt.Errorf("%w: WebSocket close code %d", ErrCodexStreamAbruptClose, code)
	}
	return fmt.Errorf("%w: WebSocket read failed", ErrCodexStreamAbruptClose)
}

func closeCodexWebSocket(ctx context.Context, connection *coderwebsocket.Conn) {
	done := make(chan struct{})
	go func() {
		_ = connection.CloseNow()
		close(done)
	}()
	select {
	case <-done:
	case <-ctx.Done():
	}
}

func webSocketReadFallback(err error) bool {
	switch coderwebsocket.CloseStatus(err) {
	case coderwebsocket.StatusNormalClosure, coderwebsocket.StatusGoingAway, coderwebsocket.StatusNoStatusRcvd,
		coderwebsocket.StatusAbnormalClosure, coderwebsocket.StatusUnsupportedData, coderwebsocket.StatusInternalError,
		coderwebsocket.StatusServiceRestart, coderwebsocket.StatusTryAgainLater:
		return true
	case -1:
		return webSocketNetworkReadFailure(err)
	default:
		return false
	}
}

func webSocketNetworkReadFailure(err error) bool {
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) ||
		errors.Is(err, context.DeadlineExceeded) ||
		errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.ECONNABORTED) ||
		errors.Is(err, syscall.EPIPE) || errors.Is(err, syscall.ETIMEDOUT) {
		return true
	}
	var networkError net.Error
	return errors.As(err, &networkError) && networkError.Timeout()
}

func webSocketDialFailure(client *http.Client, err error) (error, bool) {
	httpTransport, ok := client.Transport.(*http.Transport)
	if !ok || httpTransport == nil {
		if client.Transport == nil {
			httpTransport, ok = http.DefaultTransport.(*http.Transport)
		}
	}
	var networkError *net.OpError
	if ok && httpTransport.Proxy != nil && !errors.As(err, &networkError) {
		return fmt.Errorf("codex proxy callback: %w", err), false
	}
	return fmt.Errorf("%w: WebSocket dial failed", ErrCodexTransport), true
}

func (transport *ResponsesTransport) trySSE(ctx context.Context, body []byte, headers HeaderConfig, onEvent func(CodexResponseStreamEvent) error) (CodexStreamResult, *http.Response, error) {
	requestContext, cancel := codexSSEContext(ctx, transport.httpClient.Timeout)
	defer cancel()
	request, err := NewRequest(requestContext, http.MethodPost, transport.responsesURL, bytes.NewReader(body), headers)
	if err != nil {
		return CodexStreamResult{}, nil, err
	}
	request.Header.Set("Accept", "text/event-stream")
	request.Header.Set("Content-Type", "application/json")
	response, err := transport.httpClient.Do(request)
	if err != nil {
		return CodexStreamResult{}, nil, codexSSERequestError(ctx, requestContext, err)
	}
	if response == nil {
		return CodexStreamResult{}, nil, fmt.Errorf("%w: SSE response is nil", ErrCodexTransport)
	}
	if response.StatusCode == http.StatusUnauthorized {
		return CodexStreamResult{}, response, nil
	}
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		var errorBody []byte
		var readErr error
		if response.Body != nil {
			errorReader := &codexContextReader{ctx: requestContext, reader: response.Body}
			errorBody, readErr = readHTTPErrorBody(errorReader)
		}
		closeHTTPResponse(response)
		if contextErr := context.Cause(ctx); contextErr != nil {
			return CodexStreamResult{}, nil, contextErr
		}
		if contextErr := context.Cause(requestContext); contextErr != nil {
			return CodexStreamResult{}, nil, contextErr
		}
		if readErr != nil && codexSSETimeoutError(readErr) {
			return CodexStreamResult{}, nil, context.DeadlineExceeded
		}
		return CodexStreamResult{}, nil, MapUpstreamError(response.StatusCode, response.Header, errorBody)
	}
	defer closeHTTPResponse(response)
	bounded := &codexAggregateReader{
		reader:    &codexContextReader{ctx: requestContext, reader: response.Body},
		remaining: maxCodexStreamPayloadBytes + 1,
	}
	result, err := parseCodexResponsesSSE(bounded, onEvent)
	if err != nil {
		if errors.Is(err, errCodexAggregateLimit) {
			return CodexStreamResult{}, nil, fmt.Errorf("%w: SSE aggregate limit exceeded", ErrCodexStreamMalformed)
		}
		if contextErr := context.Cause(ctx); contextErr != nil {
			return CodexStreamResult{}, nil, contextErr
		}
		if contextErr := context.Cause(requestContext); contextErr != nil {
			return CodexStreamResult{}, nil, contextErr
		}
		if codexSSETimeoutError(err) {
			return CodexStreamResult{}, nil, context.DeadlineExceeded
		}
		return result, nil, err
	}
	if bounded.total > maxCodexStreamPayloadBytes || bounded.exceeded {
		return CodexStreamResult{}, nil, fmt.Errorf("%w: SSE aggregate limit exceeded", ErrCodexStreamMalformed)
	}
	return result, nil, nil
}

func codexSSEContext(ctx context.Context, clientTimeout time.Duration) (context.Context, context.CancelFunc) {
	timeout := codexHTTPTimeout
	if clientTimeout > 0 && clientTimeout < timeout {
		timeout = clientTimeout
	}
	return context.WithTimeout(ctx, timeout)
}

func codexSSERequestError(callerContext, requestContext context.Context, err error) error {
	if contextErr := context.Cause(callerContext); contextErr != nil {
		return contextErr
	}
	if contextErr := context.Cause(requestContext); contextErr != nil {
		return contextErr
	}
	if codexSSETimeoutError(err) {
		return context.DeadlineExceeded
	}
	return fmt.Errorf("%w: SSE request failed", ErrCodexTransport)
}

func codexSSETimeoutError(err error) bool {
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var networkError net.Error
	return errors.As(err, &networkError) && networkError.Timeout()
}

type codexContextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (reader *codexContextReader) Read(target []byte) (int, error) {
	if contextErr := context.Cause(reader.ctx); contextErr != nil {
		return 0, contextErr
	}
	if reader.reader == nil {
		return 0, io.EOF
	}
	count, err := reader.reader.Read(target)
	if contextErr := context.Cause(reader.ctx); contextErr != nil && err != nil {
		return count, contextErr
	}
	return count, err
}

type codexAggregateReader struct {
	reader    io.Reader
	remaining int64
	total     int64
	exceeded  bool
}

func (reader *codexAggregateReader) Read(target []byte) (int, error) {
	if reader.remaining == 0 {
		reader.exceeded = true
		return 0, errCodexAggregateLimit
	}
	if int64(len(target)) > reader.remaining {
		target = target[:reader.remaining]
	}
	count, err := reader.reader.Read(target)
	reader.remaining -= int64(count)
	reader.total += int64(count)
	return count, err
}

func readHTTPErrorBody(body io.Reader) ([]byte, error) {
	if body == nil {
		return nil, nil
	}
	limited := io.LimitReader(body, maxErrorBodyBytes+1)
	data, err := io.ReadAll(limited)
	if len(data) > maxErrorBodyBytes {
		data = data[:maxErrorBodyBytes]
	}
	return data, err
}
func mapHTTPResponseError(response *http.Response) *SafeError {
	if response == nil {
		return MapUpstreamError(0, nil, nil)
	}
	body, _ := readHTTPErrorBody(response.Body)
	closeHTTPResponse(response)
	return MapUpstreamError(response.StatusCode, response.Header, body)
}

func closeHTTPResponse(response *http.Response) {
	if response != nil && response.Body != nil {
		_ = response.Body.Close()
	}
}

func appendURLPath(raw, suffix string) (string, error) {
	parsed, err := url.Parse(raw)
	if err != nil {
		return "", err
	}
	if parsed.Host == "" || strings.TrimSpace(suffix) == "" {
		return "", errors.New("URL path cannot be appended")
	}
	parsed.Path = strings.TrimRight(parsed.Path, "/") + "/" + strings.TrimLeft(suffix, "/")
	parsed.RawPath = ""
	return parsed.String(), nil
}

func validateHTTPURL(raw string) error {
	parsed, err := url.ParseRequestURI(raw)
	if err != nil || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.User != nil {
		return errors.New("url must use http or https without user info")
	}
	return nil
}

func validateWebSocketURL(raw string) error {
	parsed, err := url.ParseRequestURI(raw)
	if err != nil || parsed.Host == "" || (parsed.Scheme != "ws" && parsed.Scheme != "wss") || parsed.User != nil {
		return errors.New("url must use ws or wss without user info")
	}
	return nil
}

func websocketURL(raw string) (string, error) {
	parsed, err := url.Parse(raw)
	if err != nil {
		return "", err
	}
	switch parsed.Scheme {
	case "http":
		parsed.Scheme = "ws"
	case "https":
		parsed.Scheme = "wss"
	default:
		return "", errors.New("responses URL must use http or https")
	}
	return parsed.String(), nil
}

func webSocketFallbackStatus(status int) bool {
	switch status {
	case http.StatusNotFound, http.StatusMethodNotAllowed, http.StatusUpgradeRequired, http.StatusNotImplemented,
		http.StatusRequestTimeout, http.StatusInternalServerError, http.StatusBadGateway, http.StatusServiceUnavailable,
		http.StatusGatewayTimeout:
		return true
	default:
		return false
	}
}

func webSocketUnsupportedBody(body []byte) bool {
	text := strings.ToLower(string(body))
	for _, marker := range []string{
		"websocket_not_supported",
		"websocket unsupported",
		"transport_not_supported",
		"unsupported transport",
		"not supported",
	} {
		if strings.Contains(text, marker) {
			return true
		}
	}
	return false
}
