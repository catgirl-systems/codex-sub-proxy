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

// Do sends one request and returns all validated stream events.
func (transport *ResponsesTransport) Do(ctx context.Context, request CodexResponseRequest) (CodexStreamResult, error) {
	if ctx == nil {
		return CodexStreamResult{}, errors.New("codex transport context is nil")
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
		headers.AccessToken = credential.AccessToken
		headers.AccountID = credential.AccountID
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

type transportResultState struct {
	result CodexStreamResult
	ready  bool
}

func (transport *ResponsesTransport) attempt(ctx context.Context, body, webSocketBody []byte, headers HeaderConfig) (CodexStreamResult, *http.Response, error) {
	if transport.policy == ResponsesTransportSSE {
		return transport.trySSE(ctx, body, headers)
	}
	result, authResponse, err, fallback := transport.tryWebSocket(ctx, webSocketBody, headers)
	if authResponse != nil || err == nil {
		return result, authResponse, err
	}
	if contextErr := context.Cause(ctx); contextErr != nil {
		return CodexStreamResult{}, nil, contextErr
	}
	if !fallback {
		return CodexStreamResult{}, nil, err
	}
	return transport.trySSE(ctx, body, headers)
}

func (transport *ResponsesTransport) tryWebSocket(ctx context.Context, body []byte, headers HeaderConfig) (CodexStreamResult, *http.Response, error, bool) {
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
	return readCodexWebSocket(ctx, attemptContext, connection, body)
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

func readCodexWebSocket(callerContext, attemptContext context.Context, connection *coderwebsocket.Conn, body []byte) (CodexStreamResult, *http.Response, error, bool) {
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

	frames := make([][]byte, 0, 16)
	aggregateBytes := 0
	replayUnsafe := false
	for {
		readContext, cancel := context.WithTimeout(attemptContext, codexReadTimeout)
		messageType, frame, err := connection.Read(readContext)
		cancel()
		if err != nil {
			if contextErr := context.Cause(callerContext); contextErr != nil {
				return CodexStreamResult{}, nil, contextErr, false
			}
			if contextErr := context.Cause(attemptContext); contextErr != nil {
				return CodexStreamResult{}, nil, contextErr, false
			}
			if errors.Is(err, coderwebsocket.ErrMessageTooBig) {
				return CodexStreamResult{}, nil, fmt.Errorf("%w: WebSocket message exceeds limit", ErrCodexStreamMalformed), false
			}
			return CodexStreamResult{}, nil, webSocketReadFailure(err), !replayUnsafe && webSocketReadFallback(err)
		}
		if messageType != coderwebsocket.MessageText && messageType != coderwebsocket.MessageBinary {
			return CodexStreamResult{}, nil, fmt.Errorf("%w: WebSocket message type is invalid", ErrCodexStreamMalformed), false
		}
		if len(frame) == 0 || len(frame) > maxCodexStreamLineBytes {
			return CodexStreamResult{}, nil, fmt.Errorf("%w: WebSocket message size is invalid", ErrCodexStreamMalformed), false
		}
		if len(frames) >= maxCodexStreamEvents || aggregateBytes > maxCodexStreamPayloadBytes-len(frame) {
			return CodexStreamResult{}, nil, fmt.Errorf("%w: WebSocket aggregate limit exceeded", ErrCodexStreamMalformed), false
		}
		event, errorResponse, err := decodeCodexWebSocketMessage(frame)
		if err != nil {
			return CodexStreamResult{}, nil, err, false
		}
		if errorResponse != nil {
			if errorResponse.StatusCode == http.StatusUnauthorized && !replayUnsafe {
				return CodexStreamResult{}, errorResponse, nil, false
			}
			if replayUnsafe {
				return CodexStreamResult{}, nil, mapHTTPResponseError(errorResponse), false
			}
			return CodexStreamResult{}, errorResponse, nil, false
		}
		frames = append(frames, frame)
		aggregateBytes += len(frame)
		if !codexWebSocketEventReplaySafe(event) {
			replayUnsafe = true
		}
		if isCodexTerminalEvent(event.Type) {
			result, parseErr := ParseCodexWebSocketFrames(frames)
			if parseErr != nil {
				return result, nil, parseErr, false
			}
			return result, nil, nil, false
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

func (transport *ResponsesTransport) trySSE(ctx context.Context, body []byte, headers HeaderConfig) (CodexStreamResult, *http.Response, error) {
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
	result, err := ParseCodexResponsesSSE(bounded)
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
