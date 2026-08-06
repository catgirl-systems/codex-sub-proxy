package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"github.com/catgirl-systems/codex-sub-proxy/internal/apikey"
	"github.com/catgirl-systems/codex-sub-proxy/internal/codex"
	"github.com/catgirl-systems/codex-sub-proxy/internal/openai"
	coderwebsocket "github.com/coder/websocket"
	"github.com/go-playground/validator/v10"
	"github.com/kataras/iris/v12"
)

const (
	responsesWebSocketWriteTimeout = 10 * time.Second
	responsesWebSocketCloseInvalid = "invalid Responses request"
	responsesWebSocketClosePolicy  = "Responses request policy violation"
)

// newResponsesWebSocketHandler serves GET /v1/responses after the API key has
// been authenticated. Each text response.create message is one sequential
// Responses turn; no concurrent readers or concurrent turns are started.
func websocketHeaderContainsToken(headers http.Header, name, token string) bool {
	for _, value := range headers.Values(name) {
		for _, candidate := range strings.Split(value, ",") {
			if strings.EqualFold(strings.TrimSpace(candidate), token) {
				return true
			}
		}
	}
	return false
}

func newResponsesWebSocketHandler(
	authorizer *apikey.Authorizer,
	broker UpstreamBroker,
	journal *Journal,
	quota *apikey.QuotaStore,
	artifacts *ArtifactStore,
	artifactRequired bool,
	allowedOrigins map[string]struct{},
) iris.Handler {
	originPatterns := make([]string, 0, len(allowedOrigins))
	for origin := range allowedOrigins {
		originPatterns = append(originPatterns, origin)
	}
	sort.Strings(originPatterns)
	return func(ctx iris.Context) {
		setJournalAuditContext(ctx, journal, responsesEndpoint)
		request := ctx.Request()
		if request.Method != http.MethodGet {
			ctx.Header("Allow", http.MethodGet)
			writeResponsesError(ctx, http.StatusMethodNotAllowed, responsesErrorType, "method_not_allowed", "Only GET is allowed for a WebSocket endpoint.")
			return
		}
		if !websocketHeaderContainsToken(request.Header, "Connection", "Upgrade") ||
			!websocketHeaderContainsToken(request.Header, "Upgrade", "websocket") {
			ctx.Header("Allow", http.MethodPost)
			writeResponsesError(ctx, http.StatusMethodNotAllowed, responsesErrorType, "method_not_allowed", "Only POST is allowed without a WebSocket upgrade.")
			return
		}
		principal, err := authenticateResponsesPrincipal(ctx, authorizer)
		if err != nil {
			writeResponsesRequestError(ctx, err)
			return
		}
		connection, err := coderwebsocket.Accept(ctx.ResponseWriter().Naive(), request, &coderwebsocket.AcceptOptions{
			OriginPatterns:  originPatterns,
			CompressionMode: coderwebsocket.CompressionDisabled,
		})
		if err != nil {
			return
		}
		defer connection.Close(coderwebsocket.StatusNormalClosure, "")
		connection.SetReadLimit(maxResponsesBodyBytes)
		serveResponsesWebSocket(ctx, connection, principal, authorizer, broker, journal, quota, artifacts, artifactRequired)
	}
}

type responsesWebSocketRead struct {
	messageType coderwebsocket.MessageType
	frame       []byte
	err         error
	concurrent  bool
}

func serveResponsesWebSocket(
	ctx iris.Context,
	connection *coderwebsocket.Conn,
	principal apikey.Principal,
	authorizer *apikey.Authorizer,
	broker UpstreamBroker,
	journal *Journal,
	quota *apikey.QuotaStore,
	artifacts *ArtifactStore,
	artifactRequired bool,
) {
	if ctx == nil || connection == nil {
		return
	}
	requestContext := ctx.Request().Context()
	connectionContext, cancelConnection := context.WithCancel(requestContext)
	defer cancelConnection()
	requestValidation := validator.New()

	readResults := make(chan responsesWebSocketRead, 1)
	violations := make(chan responsesWebSocketRead)
	nextRead := make(chan struct{}, 1)
	var turnActive atomic.Bool
	var violationPending atomic.Bool
	var activeTurnCancel atomic.Pointer[context.CancelFunc]
	go func() {
		defer close(readResults)
		first := true
		for {
			if !first {
				select {
				case <-nextRead:
				case <-connectionContext.Done():
					return
				}
			}
			messageType, frame, err := connection.Read(connectionContext)
			result := responsesWebSocketRead{
				messageType: messageType,
				frame:       frame,
				err:         err,
				concurrent:  turnActive.Load(),
			}
			if err != nil {
				select {
				case readResults <- result:
				case <-connectionContext.Done():
				}
				cancelConnection()
				return
			}
			if result.concurrent {
				violationPending.Store(true)
				if cancel := activeTurnCancel.Load(); cancel != nil {
					(*cancel)()
				}
				select {
				case violations <- result:
				case <-connectionContext.Done():
				}
				return
			}
			select {
			case readResults <- result:
			case <-connectionContext.Done():
				return
			}
			first = false
		}
	}()
	releaseReader := func() bool {
		select {
		case nextRead <- struct{}{}:
			return true
		case <-connectionContext.Done():
			return false
		}
	}
	finishWebSocketJournal := func(request JournalRequest, operationContext context.Context) {
		if journal == nil {
			return
		}
		if operationContext != nil && operationContext.Err() != nil {
			if err := journal.CompleteRequestWithState(context.WithoutCancel(connectionContext), request, requestStatusCanceled); err != nil {
				journal.recordError(err)
			}
			return
		}
		finishJournalRequest(ctx, journal, request)
	}
	closeViolation := func(violation responsesWebSocketRead) {
		if violation.messageType != coderwebsocket.MessageText {
			closeResponsesWebSocket(connection, coderwebsocket.StatusUnsupportedData, responsesWebSocketCloseInvalid)
			return
		}
		_ = writeResponsesWebSocketError(connectionContext, connection, "invalid_request", "The request is invalid.")
		closeResponsesWebSocket(connection, coderwebsocket.StatusPolicyViolation, responsesWebSocketClosePolicy)
	}
	takeViolation := func() (responsesWebSocketRead, bool) {
		if violationPending.Load() {
			select {
			case violation := <-violations:
				violationPending.Store(false)
				return violation, true
			case <-connectionContext.Done():
				return responsesWebSocketRead{}, false
			}
		}
		select {
		case violation := <-violations:
			violationPending.Store(false)
			return violation, true
		default:
			return responsesWebSocketRead{}, false
		}
	}
	var pendingRead *responsesWebSocketRead
	for {
		var result responsesWebSocketRead
		var ok bool
		if pendingRead != nil {
			result, ok = *pendingRead, true
			pendingRead = nil
		} else {
			result, ok = <-readResults
		}
		if !ok {
			return
		}
		if result.err != nil {
			status := coderwebsocket.CloseStatus(result.err)
			switch status {
			case -1:
				status = coderwebsocket.StatusInternalError
			case coderwebsocket.StatusNormalClosure:
				return
			}
			closeResponsesWebSocket(connection, status, responsesWebSocketCloseInvalid)
			return
		}
		if result.messageType != coderwebsocket.MessageText {
			closeResponsesWebSocket(connection, coderwebsocket.StatusUnsupportedData, responsesWebSocketCloseInvalid)
			return
		}
		publicRequest, err := decodeResponsesWebSocketCreate(result.frame)
		if err != nil {
			_ = writeResponsesWebSocketError(connectionContext, connection, "invalid_request", "The request is invalid.")
			closeResponsesWebSocket(connection, coderwebsocket.StatusPolicyViolation, responsesWebSocketClosePolicy)
			return
		}
		publicRequest.Stream = true
		if err := requestValidation.Struct(publicRequest); err != nil {
			_ = writeResponsesWebSocketError(connectionContext, connection, "invalid_request", "The request is invalid.")
			closeResponsesWebSocket(connection, coderwebsocket.StatusPolicyViolation, responsesWebSocketClosePolicy)
			return
		}
		setJournalAuditContext(ctx, journal, responsesEndpoint)
		turnContext, cancelTurn := context.WithCancel(connectionContext)
		turnActive.Store(true)
		activeTurnCancel.Store(&cancelTurn)
		if !releaseReader() {
			turnActive.Store(false)
			activeTurnCancel.Store(nil)
			cancelTurn()
			return
		}
		admission, err := prepareResponsesAdmissionForPrincipal(ctx, turnContext, authorizer, broker, journal, quota, publicRequest, principal)
		if err != nil {
			clientCanceled := connectionContext.Err() != nil
			turnActive.Store(false)
			activeTurnCancel.Store(nil)
			if admission != nil {
				if clientCanceled {
					cancelTurn()
				} else {
					markJournalTerminal(ctx, requestStatusFailed, "")
				}
				finishWebSocketJournal(admission.journalRequest, turnContext)
				ctx.Values().Set(journalRequestValueKey, nil)
			}
			if !clientCanceled {
				cancelTurn()
			}
			if violation, ok := takeViolation(); ok {
				closeViolation(violation)
				return
			}
			if connectionContext.Err() != nil {
				return
			}
			if errors.Is(err, apikey.ErrInvalidKey) || errors.Is(err, apikey.ErrForbidden) {
				_ = writeResponsesWebSocketError(connectionContext, connection, "invalid_api_key", "The API key is not authorized.")
				closeResponsesWebSocket(connection, coderwebsocket.StatusPolicyViolation, responsesWebSocketClosePolicy)
				return
			}
			if status, _, code, message, ok := responsesRequestErrorFields(err); ok {
				_ = writeResponsesWebSocketError(connectionContext, connection, code, message)
				if status == http.StatusBadRequest || status == http.StatusForbidden {
					closeResponsesWebSocket(connection, coderwebsocket.StatusPolicyViolation, responsesWebSocketClosePolicy)
					return
				}
				continue
			}
			var quotaErr *apikey.QuotaError
			if errors.As(err, &quotaErr) {
				_ = writeResponsesWebSocketError(connectionContext, connection, "rate_limit_exceeded", "The request quota was exceeded.")
				continue
			}
			_ = writeResponsesWebSocketError(connectionContext, connection, "internal_error", "Internal server error.")
			continue
		}
		turnDone := make(chan struct{})
		go func() {
			serveResponsesWebSocketTurn(ctx, turnContext, connection, broker, admission, journal, artifacts, artifactRequired, &turnActive)
			finishWebSocketJournal(admission.journalRequest, turnContext)
			close(turnDone)
		}()
		select {
		case readResult, readOK := <-readResults:
			if !readOK {
				cancelTurn()
				<-turnDone
				turnActive.Store(false)
				activeTurnCancel.Store(nil)
				ctx.Values().Set(journalRequestValueKey, nil)
				return
			}
			if readResult.err == nil {
				pendingRead = &readResult
				continue
			}
			cancelTurn()
			<-turnDone
			turnActive.Store(false)
			activeTurnCancel.Store(nil)
			ctx.Values().Set(journalRequestValueKey, nil)
			status := coderwebsocket.CloseStatus(readResult.err)
			switch status {
			case -1:
				status = coderwebsocket.StatusInternalError
			case coderwebsocket.StatusNormalClosure:
				return
			}
			closeResponsesWebSocket(connection, status, responsesWebSocketCloseInvalid)
			return
		case violation := <-violations:
			<-turnDone
			turnActive.Store(false)
			activeTurnCancel.Store(nil)
			ctx.Values().Set(journalRequestValueKey, nil)
			cancelTurn()
			closeViolation(violation)
			return
		case <-turnDone:
			turnActive.Store(false)
			activeTurnCancel.Store(nil)
			cancelTurn()
			if violation, ok := takeViolation(); ok {
				closeViolation(violation)
				return
			}
		}
	}
}

func decodeResponsesWebSocketCreate(frame []byte) (openai.ResponseRequest, error) {
	if len(frame) == 0 || len(frame) > maxResponsesBodyBytes {
		return openai.ResponseRequest{}, errors.New("Responses WebSocket request exceeds limit")
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(frame, &fields); err != nil || fields == nil {
		return openai.ResponseRequest{}, errors.New("Responses WebSocket request is not a JSON object")
	}
	var messageType string
	rawType, ok := fields["type"]
	if !ok || json.Unmarshal(rawType, &messageType) != nil || messageType != "response.create" {
		return openai.ResponseRequest{}, errors.New("Responses WebSocket message type is invalid")
	}
	delete(fields, "type")
	requestBody, err := json.Marshal(fields)
	if err != nil {
		return openai.ResponseRequest{}, fmt.Errorf("encode Responses WebSocket request: %w", err)
	}
	var request openai.ResponseRequest
	decoder := json.NewDecoder(bytes.NewReader(requestBody))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		return openai.ResponseRequest{}, fmt.Errorf("decode Responses WebSocket request: %w", err)
	}
	return request, nil
}
func serveResponsesWebSocketTurn(
	ctx iris.Context,
	requestContext context.Context,
	connection *coderwebsocket.Conn,
	broker UpstreamBroker,
	admission *responsesAdmission,
	journal *Journal,
	artifacts *ArtifactStore,
	artifactRequired bool,
	turnActive *atomic.Bool,
) {
	if admission == nil {
		_ = writeResponsesWebSocketError(requestContext, connection, "internal_error", "Internal server error.")
		return
	}
	defer func() { _ = admission.lease.release("request ended") }()
	setTransportOutcome(ctx, "websocket")
	forcedAccountID := admission.continuationAccountID
	retriedAffinity := false
	retriedContinuation := false
	retriedConnectionLimit := false
	wroteOutput := false
	terminalWritten := false
	turnState := ""
	privateRequest := admission.privateRequest
	selection := admission.selection
	var streamErr error
	for {
		attemptContext, cancel := context.WithCancel(codex.WithTurnState(requestContext, turnState))
		var attemptResult BrokerResponsesResult
		attemptResult, streamErr = broker.StreamResponses(attemptContext, selection, privateRequest, forcedAccountID, admission.bindAccount, func(event codex.CodexResponseStreamEvent) error {
			if requestContext.Err() != nil {
				return requestContext.Err()
			}
			if state := responseEventTurnState(event); state != "" {
				turnState = state
			}
			code := responseEventErrorCode(event)
			if !wroteOutput && (strings.EqualFold(code, "previous_response_not_found") ||
				strings.EqualFold(code, "websocket_connection_limit_reached")) {
				return &upstreamEventError{code: code, err: errors.New("upstream error event terminated before output")}
			}
			if event.SequenceNumber < 0 {
				return fmt.Errorf("invalid upstream sequence number %d", event.SequenceNumber)
			}
			if isCodexTerminal(event.Type) && event.Response != nil {
				if err := persistResponseImageArtifacts(requestContext, artifacts, artifactRequired, imageArtifactOwner(ctx), codex.CodexStreamResult{Response: event.Response}); err != nil {
					return err
				}
			}
			payload, keep, err := publicEventPayload(event)
			if err != nil {
				return err
			}
			if !keep {
				return nil
			}
			failedTerminal := isFailedCodexResponseEvent(event)
			successTerminal := isCodexTerminal(event.Type) && !failedTerminal && event.Response != nil
			if successTerminal {
				if err := validateQuotaUsageFromCodex(event.Response.Usage); err != nil {
					return fmt.Errorf("%w: %v", codex.ErrCodexStreamMalformed, err)
				}
				if err := admission.lease.reconcile(quotaUsageFromCodex(event.Response.Usage, 0)); err != nil {
					return err
				}
				journalUsage := journalUsageFromCodex(event.Response.Usage, 0)
				journalUsage.ResolvedModel = event.Response.Model
				recordJournalUsageDetails(ctx, journalUsage)
			}
			if isCodexTerminal(event.Type) || event.Error != nil {
				if turnActive != nil {
					turnActive.Store(false)
				}
			}
			if err := writeResponsesWebSocketJournalEvent(ctx, requestContext, connection, payload); err != nil {
				return err
			}
			wroteOutput = true
			if isCodexTerminal(event.Type) || event.Error != nil {
				terminalWritten = true
				if failedTerminal {
					markJournalTerminal(ctx, requestStatusFailed, "")
				}
			}
			if event.Error != nil || event.Type == codex.CodexEventError {
				return &upstreamEventError{code: responseEventErrorCode(event), err: errors.New("upstream error event terminated public stream")}
			}
			return nil
		})
		cancel()
		if requestContext.Err() != nil {
			break
		}
		if !retriedContinuation && !wroteOutput && isPreviousResponseNotFoundError(streamErr) {
			fallbackRequest, fallbackErr := rebuildContinuationRequest(requestContext, journal, admission.continuationSourceRequestID, admission.journalRequest.ConversationID, privateRequest)
			if fallbackErr == nil {
				privateRequest = fallbackRequest
				selection.PreviousResponseID = ""
				retriedContinuation = true
				continue
			}
			streamErr = fallbackErr
			break
		}
		if !retriedConnectionLimit && !wroteOutput &&
			strings.EqualFold(upstreamErrorCode(streamErr), "websocket_connection_limit_reached") {
			if attemptResult.Account.ID != "" {
				forcedAccountID = attemptResult.Account.ID
			}
			retriedConnectionLimit = true
			continue
		}
		retry := !retriedAffinity && canRetrySessionAffinity(streamErr, admission.sessionHash, forcedAccountID, wroteOutput) && journal != nil
		if !retry {
			break
		}
		retriedAffinity = true
		winner, resolveErr := journal.ResolveSessionAffinity(requestContext, admission.principal.ID, admission.sessionHash)
		if resolveErr != nil {
			streamErr = resolveErr
			break
		}
		forcedAccountID = winner
		turnState = ""
		selection.AffinityAccountID = ""
	}
	if requestContext.Err() != nil {
		return
	}
	if !terminalWritten {
		_, responseError := responsesError(streamErr)
		if errors.Is(streamErr, errQuotaFinalization) {
			responseError = openai.Error{Type: responsesServerErrorType, Code: "internal_error", Message: "Internal server error."}
		}
		if err := writeResponsesWebSocketJournalError(ctx, requestContext, connection, responseError.Code, responseError.Message); err != nil {
			markJournalFailure(ctx)
			markJournalTerminal(ctx, requestStatusFailed, "")
			return
		}
		markJournalTerminal(ctx, requestStatusFailed, "")
	}
}

func writeResponsesWebSocketEvent(ctx context.Context, connection *coderwebsocket.Conn, payload []byte) error {
	payload = bytes.TrimSpace(payload)
	if len(payload) == 0 || len(payload) > maxResponsesEventBytes || !json.Valid(payload) {
		return errors.New("Responses WebSocket event is invalid")
	}
	writeContext, cancel := context.WithTimeout(ctx, responsesWebSocketWriteTimeout)
	defer cancel()
	return connection.Write(writeContext, coderwebsocket.MessageText, payload)
}
func writeResponsesWebSocketJournalEvent(ctx iris.Context, requestContext context.Context, connection *coderwebsocket.Conn, payload []byte) error {
	payload = bytes.TrimSpace(payload)
	if len(payload) == 0 || len(payload) > maxResponsesEventBytes || !json.Valid(payload) {
		return errors.New("Responses WebSocket event is invalid")
	}
	eventType := "json.event"
	var event struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(payload, &event); err == nil && event.Type != "" {
		eventType = event.Type
	}
	value, ok := ctx.Values().Get(journalRequestValueKey).(*journalRequestValue)
	if !ok || value == nil || value.journal == nil {
		return writeResponsesWebSocketEvent(requestContext, connection, payload)
	}
	err := value.journal.Forward(requestContext, value.request, eventType, payload, func(writeContext context.Context, _ string) error {
		return writeResponsesWebSocketEvent(writeContext, connection, payload)
	})
	if err != nil {
		return err
	}
	if eventType == "error" || strings.HasPrefix(eventType, "response.failed") {
		markJournalTerminalValue(value, requestStatusFailed, "")
	}
	return nil
}

func writeResponsesWebSocketJournalError(ctx iris.Context, requestContext context.Context, connection *coderwebsocket.Conn, code, message string) error {
	if code == "" {
		code = "internal_error"
	}
	if message == "" || strings.ContainsAny(message, "\r\n") {
		message = "The request could not be completed."
	}
	payload, err := json.Marshal(openai.ResponseErrorEvent{Type: openai.EventError, Code: code, Message: message})
	if err != nil {
		return err
	}
	return writeResponsesWebSocketJournalEvent(ctx, requestContext, connection, payload)
}

func writeResponsesWebSocketError(ctx context.Context, connection *coderwebsocket.Conn, code, message string) error {
	if code == "" {
		code = "internal_error"
	}
	if message == "" || strings.ContainsAny(message, "\r\n") {
		message = "The request could not be completed."
	}
	payload, err := json.Marshal(openai.ResponseErrorEvent{Type: openai.EventError, Code: code, Message: message})
	if err != nil {
		return err
	}
	return writeResponsesWebSocketEvent(ctx, connection, payload)
}

func closeResponsesWebSocket(connection *coderwebsocket.Conn, status coderwebsocket.StatusCode, reason string) {
	if connection != nil {
		_ = connection.Close(status, reason)
	}
}
