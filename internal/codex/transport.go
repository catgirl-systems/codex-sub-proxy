package codex

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gorilla/websocket"
)

const (
	defaultResponsesURL = "https://chatgpt.com/backend-api/codex/responses"

	responsesWebSocketBeta = "responses_websockets=2026-02-06"

	codexDialTimeout      = 10 * time.Second
	codexHandshakeTimeout = 10 * time.Second
	codexReadTimeout      = 2 * time.Minute
	codexWriteTimeout     = 10 * time.Second
	codexHTTPTimeout      = 5 * time.Minute
	maxCodexRequestBytes  = maxCodexStreamPayloadBytes
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
	dialer       websocket.Dialer
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
		dialer:       newResponsesWebSocketDialer(client),
	}, nil
}

func newResponsesWebSocketDialer(client *http.Client) websocket.Dialer {
	dialer := *websocket.DefaultDialer
	dialer.HandshakeTimeout = codexHandshakeTimeout
	dialer.EnableCompression = false

	if client == nil {
		return dialer
	}
	httpTransport, ok := client.Transport.(*http.Transport)
	if !ok || httpTransport == nil {
		return dialer
	}
	dialer.Proxy = httpTransport.Proxy
	dialer.NetDialContext = httpTransport.DialContext
	if httpTransport.Proxy == nil {
		dialer.NetDialTLSContext = httpTransport.DialTLSContext
	}
	if httpTransport.TLSClientConfig != nil {
		dialer.TLSClientConfig = httpTransport.TLSClientConfig.Clone()
	}
	return dialer
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
			return nil, attemptErr
		}
		state.result = result
		state.ready = true
		return &http.Response{StatusCode: http.StatusOK, Body: http.NoBody}, nil
	})
	if response != nil {
		closeHTTPResponse(response)
	}
	if err != nil {
		return CodexStreamResult{}, err
	}
	if !state.ready {
		if response != nil && response.StatusCode == http.StatusUnauthorized {
			return CodexStreamResult{}, MapUpstreamError(response.StatusCode, response.Header, nil)
		}
		return CodexStreamResult{}, errors.New("codex transport returned no result")
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
	if ctx.Err() != nil || !fallback {
		return CodexStreamResult{}, nil, err
	}
	return transport.trySSE(ctx, body, headers)
}

func (transport *ResponsesTransport) tryWebSocket(ctx context.Context, body []byte, headers HeaderConfig) (CodexStreamResult, *http.Response, error, bool) {
	dialContext, cancel := context.WithTimeout(ctx, codexDialTimeout)
	defer cancel()
	wsHeaders := headers
	wsHeaders.Beta = responsesWebSocketBeta
	handshakeRequest, err := NewRequest(dialContext, http.MethodGet, transport.webSocketURL, nil, wsHeaders)
	if err != nil {
		return CodexStreamResult{}, nil, err, false
	}
	handshakeRequest.Header.Set("Accept", "application/json")
	connection, response, err := transport.dialer.DialContext(dialContext, transport.webSocketURL, handshakeRequest.Header)
	if err != nil {
		if dialContext.Err() != nil {
			return CodexStreamResult{}, nil, dialContext.Err(), false
		}
		if response != nil {
			return transport.webSocketHandshakeFailure(response)
		}
		return CodexStreamResult{}, nil, fmt.Errorf("%w: WebSocket dial failed", ErrCodexTransport), true
	}
	return readCodexWebSocket(ctx, connection, body)
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

func readCodexWebSocket(ctx context.Context, connection *websocket.Conn, body []byte) (CodexStreamResult, *http.Response, error, bool) {
	if connection == nil {
		return CodexStreamResult{}, nil, fmt.Errorf("%w: WebSocket connection is nil", ErrCodexTransport), true
	}
	defer connection.Close()
	if err := connection.SetWriteDeadline(time.Now().Add(codexWriteTimeout)); err != nil {
		return CodexStreamResult{}, nil, fmt.Errorf("%w: set WebSocket write limit", ErrCodexTransport), true
	}
	if err := connection.WriteMessage(websocket.TextMessage, body); err != nil {
		if ctx.Err() != nil {
			return CodexStreamResult{}, nil, ctx.Err(), false
		}
		return CodexStreamResult{}, nil, fmt.Errorf("%w: write WebSocket request", ErrCodexTransport), true
	}
	connection.SetReadLimit(maxCodexStreamLineBytes)
	stopContext := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = connection.Close()
		case <-stopContext:
		}
	}()
	defer close(stopContext)

	frames := make([][]byte, 0, 16)
	aggregateBytes := 0
	replayUnsafe := false
	for {
		if err := connection.SetReadDeadline(time.Now().Add(codexReadTimeout)); err != nil {
			return CodexStreamResult{}, nil, fmt.Errorf("%w: set WebSocket read limit", ErrCodexTransport), !replayUnsafe
		}
		messageType, frame, err := connection.ReadMessage()
		if err != nil {
			if ctx.Err() != nil {
				return CodexStreamResult{}, nil, ctx.Err(), false
			}
			if errors.Is(err, websocket.ErrReadLimit) {
				return CodexStreamResult{}, nil, fmt.Errorf("%w: WebSocket message exceeds limit", ErrCodexStreamMalformed), false
			}
			return CodexStreamResult{}, nil, webSocketReadFailure(err), !replayUnsafe && webSocketReadFallback(err)
		}
		if messageType != websocket.TextMessage && messageType != websocket.BinaryMessage {
			return CodexStreamResult{}, nil, fmt.Errorf("%w: WebSocket message type is invalid", ErrCodexStreamMalformed), false
		}
		if len(frame) == 0 || len(frame) > maxCodexStreamLineBytes {
			return CodexStreamResult{}, nil, fmt.Errorf("%w: WebSocket message size is invalid", ErrCodexStreamMalformed), false
		}
		if len(frames) >= maxCodexStreamEvents || aggregateBytes > maxCodexStreamPayloadBytes-len(frame) {
			return CodexStreamResult{}, nil, fmt.Errorf("%w: WebSocket aggregate limit exceeded", ErrCodexStreamMalformed), false
		}
		event, err := DecodeCodexWebSocketFrame(frame)
		if err != nil {
			return CodexStreamResult{}, nil, err, false
		}
		frames = append(frames, frame)
		aggregateBytes += len(frame)
		if !codexWebSocketEventReplaySafe(event) {
			replayUnsafe = true
		}
		if isCodexTerminalEvent(event.Type) {
			result, parseErr := ParseCodexWebSocketFrames(frames)
			if parseErr != nil {
				return CodexStreamResult{}, nil, parseErr, false
			}
			return result, nil, nil, false
		}
	}
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
	var closeError *websocket.CloseError
	if errors.As(err, &closeError) {
		return fmt.Errorf("%w: WebSocket close code %d", ErrCodexStreamAbruptClose, closeError.Code)
	}
	return fmt.Errorf("%w: WebSocket read failed", ErrCodexStreamAbruptClose)
}

func webSocketReadFallback(err error) bool {
	var closeError *websocket.CloseError
	if errors.As(err, &closeError) {
		switch closeError.Code {
		case websocket.CloseNormalClosure, websocket.CloseGoingAway, websocket.CloseNoStatusReceived,
			websocket.CloseAbnormalClosure, websocket.CloseUnsupportedData, websocket.CloseInternalServerErr,
			websocket.CloseServiceRestart, websocket.CloseTryAgainLater:
			return true
		default:
			return false
		}
	}
	return true
}

func (transport *ResponsesTransport) trySSE(ctx context.Context, body []byte, headers HeaderConfig) (CodexStreamResult, *http.Response, error) {
	requestContext, cancel := context.WithTimeout(ctx, codexHTTPTimeout)
	defer cancel()
	request, err := NewRequest(requestContext, http.MethodPost, transport.responsesURL, bytes.NewReader(body), headers)
	if err != nil {
		return CodexStreamResult{}, nil, err
	}
	request.Header.Set("Accept", "text/event-stream")
	request.Header.Set("Content-Type", "application/json")
	response, err := transport.httpClient.Do(request)
	if err != nil {
		if ctx.Err() != nil {
			return CodexStreamResult{}, nil, ctx.Err()
		}
		return CodexStreamResult{}, nil, fmt.Errorf("%w: SSE request failed", ErrCodexTransport)
	}
	if response == nil {
		return CodexStreamResult{}, nil, fmt.Errorf("%w: SSE response is nil", ErrCodexTransport)
	}
	if response.StatusCode == http.StatusUnauthorized {
		return CodexStreamResult{}, response, nil
	}
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		body, _ := readHTTPErrorBody(response.Body)
		closeHTTPResponse(response)
		return CodexStreamResult{}, nil, MapUpstreamError(response.StatusCode, response.Header, body)
	}
	defer closeHTTPResponse(response)
	bounded := &codexAggregateReader{reader: response.Body, remaining: maxCodexStreamPayloadBytes + 1}
	result, err := ParseCodexResponsesSSE(bounded)
	if err != nil {
		if errors.Is(err, errCodexAggregateLimit) {
			return CodexStreamResult{}, nil, fmt.Errorf("%w: SSE aggregate limit exceeded", ErrCodexStreamMalformed)
		}
		return CodexStreamResult{}, nil, err
	}
	if bounded.total > maxCodexStreamPayloadBytes || bounded.exceeded {
		return CodexStreamResult{}, nil, fmt.Errorf("%w: SSE aggregate limit exceeded", ErrCodexStreamMalformed)
	}
	return result, nil, nil
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
