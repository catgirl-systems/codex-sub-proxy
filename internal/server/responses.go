package server

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"mime"
	"net/http"
	"strings"
	"time"

	"github.com/catgirl-systems/codex-sub-proxy/internal/apikey"
	"github.com/catgirl-systems/codex-sub-proxy/internal/codex"
	"github.com/catgirl-systems/codex-sub-proxy/internal/openai"
	"github.com/go-playground/validator/v10"
	"github.com/kataras/iris/v12"
)

const (
	responsesEndpoint        = "/v1/responses"
	maxResponsesBodyBytes    = 4 * 1024 * 1024
	maxResponsesEventBytes   = 256 * 1024
	maxResponsesJSONBytes    = 4 * 1024 * 1024
	maxTurnMetadataBytes     = 4096
	responsesErrorType       = "invalid_request_error"
	responsesServerErrorType = "server_error"

	responsesLiteClientMetadataKey = "ws_request_header_x_openai_internal_codex_responses_lite"
)

func newResponsesHandler(authorizer *apikey.Authorizer, broker UpstreamBroker, journal *Journal, quota *apikey.QuotaStore, artifacts *ArtifactStore, artifactRequired bool) iris.Handler {
	requestValidation := validator.New()
	return func(ctx iris.Context) {
		setJournalAuditContext(ctx, journal, responsesEndpoint)
		request := ctx.Request()
		requestContext := request.Context()
		if request.Method != http.MethodPost {
			ctx.Header("Allow", http.MethodPost)
			writeResponsesError(ctx, http.StatusMethodNotAllowed, responsesErrorType, "method_not_allowed", "Only POST is allowed for this endpoint.")
			return
		}

		headers := request.Header.Values("Authorization")
		if len(headers) != 1 {
			writeAPIKeyError(ctx, apikey.ErrInvalidKey)
			return
		}
		principal, err := authorizer.AuthenticateHeader(requestContext, headers[0])
		setJournalAuditPrincipal(ctx, principal.ID)
		if err != nil {
			writeAPIKeyError(ctx, err)
			return
		}

		mediaType, _, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
		if err != nil || mediaType != "application/json" {
			writeResponsesError(ctx, http.StatusUnsupportedMediaType, responsesErrorType, "invalid_media_type", "Content-Type must be application/json.")
			return
		}
		if request.ContentLength > maxResponsesBodyBytes {
			writeResponsesError(ctx, http.StatusRequestEntityTooLarge, responsesErrorType, "request_too_large", "Request body is too large.")
			return
		}

		request.Body = http.MaxBytesReader(ctx.ResponseWriter(), request.Body, maxResponsesBodyBytes)
		defer request.Body.Close()
		var publicRequest openai.ResponseRequest
		decoder := json.NewDecoder(request.Body)
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&publicRequest); err != nil {
			writeResponsesDecodeError(ctx, err, "Request body is not valid JSON.")
			return
		}
		var extra json.RawMessage
		if err := decoder.Decode(&extra); err != io.EOF {
			if err == nil {
				writeResponsesError(ctx, http.StatusBadRequest, responsesErrorType, "invalid_json", "Request body must contain one JSON object.")
			} else {
				writeResponsesDecodeError(ctx, err, "Request body must contain one JSON object.")
			}
			return
		}
		if err := requestValidation.Struct(publicRequest); err != nil {
			writeResponsesError(ctx, http.StatusBadRequest, responsesErrorType, "invalid_request", "The request is invalid.")
			return
		}
		requestHeaders, err := requestHeaderConfig(request.Header)
		if err != nil {
			writeResponsesError(ctx, http.StatusBadRequest, responsesErrorType, "invalid_request", "The request is invalid.")
			return
		}
		responsesLiteHeader := requestHeaders.ResponsesLiteRequested
		principal, err = authorizer.AuthorizePrincipal(requestContext, principal, responsesEndpoint, publicRequest.Model)
		if err != nil {
			writeAPIKeyError(ctx, err)
			return
		}
		if broker == nil {
			writeResponsesError(ctx, http.StatusServiceUnavailable, responsesServerErrorType, "upstream_unavailable", "The upstream service is unavailable.")
			return
		}
		journalInput, err := json.Marshal(publicRequest)
		if err != nil {
			writeResponsesError(ctx, http.StatusInternalServerError, responsesServerErrorType, "internal_error", "Internal server error.")
			return
		}
		journalMetadata := JournalRequestMetadata{
			Endpoint: responsesEndpoint, Model: publicRequest.Model, APIKeyID: principal.ID,
		}
		var sessionHash, affinityAccountID string
		if publicRequest.PreviousResponseID != "" {
			if journal == nil {
				writeResponsesError(ctx, http.StatusBadRequest, responsesErrorType, "previous_response_not_found", "The previous response was not found.")
				return
			}
			resolved, resolveErr := journal.ResolvePreviousResponse(requestContext, publicRequest.PreviousResponseID, principal.ID)
			if resolveErr != nil {
				if errors.Is(resolveErr, ErrPreviousResponseNotFound) {
					writeResponsesError(ctx, http.StatusBadRequest, responsesErrorType, "previous_response_not_found", "The previous response was not found.")
				} else {
					writeResponsesError(ctx, http.StatusInternalServerError, responsesServerErrorType, "internal_error", "Internal server error.")
				}
				return
			}
			journalMetadata.ConversationID = resolved.ConversationID
			journalMetadata.AccountID = resolved.AccountID
			journalMetadata.PreviousResponseID = publicRequest.PreviousResponseID
		} else {
			var affinityErr error
			sessionHash, affinityAccountID, affinityErr = resolveSessionAffinity(requestContext, journal, principal.ID, requestHeaders)
			if affinityErr != nil {
				writeResponsesError(ctx, http.StatusInternalServerError, responsesServerErrorType, "internal_error", "Internal server error.")
				return
			}
		}
		journalRequestID, err := startJournalRequestWithMetadata(ctx, journal, journalMetadata, journalInput)
		if err != nil {
			if errors.Is(err, ErrPreviousResponseNotFound) {
				writeResponsesError(ctx, http.StatusBadRequest, responsesErrorType, "previous_response_not_found", "The previous response was not found.")
			} else {
				writeResponsesError(ctx, http.StatusInternalServerError, responsesServerErrorType, "internal_error", "Internal server error.")
			}
			return
		}
		defer finishJournalRequest(ctx, journal, journalRequestID)
		privateRequest, err := privateResponseRequest(publicRequest)
		if err != nil {
			writeResponsesError(ctx, http.StatusBadRequest, responsesErrorType, "invalid_request", "The request is invalid.")
			return
		}
		if responsesLiteHeader && privateRequest.ResponsesLite {
			writeResponsesError(ctx, http.StatusBadRequest, responsesErrorType, "invalid_request", "The request is invalid.")
			return
		}
		privateRequest.ResponsesLite = responsesLiteHeader || privateRequest.ResponsesLite
		selection := codex.SelectionRequest{
			Endpoint: responsesEndpoint, Model: publicRequest.Model, APIKeyID: principal.ID,
			PreviousResponseID: publicRequest.PreviousResponseID,
			Headers:            requestHeaders,
			AffinityAccountID:  affinityAccountID,
		}
		bindAccount := func(account codex.Account) error {
			if journal == nil {
				return nil
			}
			return journal.BindAccount(requestContext, journalRequestID.ID, account.ID, sessionAffinityHashForAccount(sessionHash, affinityAccountID, account.ID))
		}

		continuationAccountID := ""
		if publicRequest.PreviousResponseID != "" {
			continuationAccountID = journalRequestID.AccountID
		}
		if publicRequest.Stream {
			lease, err := admitRequestQuota(requestContext, quota, principal, responseQuotaRequest(principal.Policy, publicRequest.MaxOutputTokens))
			if err != nil {
				var quotaErr *apikey.QuotaError
				if errors.As(err, &quotaErr) {
					writeQuotaResponsesError(ctx, err)
				} else {
					writeResponsesError(ctx, http.StatusInternalServerError, responsesServerErrorType, "internal_error", "Internal server error.")
				}
				return
			}
			defer func() { _ = lease.release("request ended") }()
			serveResponsesStream(ctx, requestContext, broker, selection, privateRequest, continuationAccountID, sessionHash, principal.ID, journal, bindAccount, lease, artifacts, artifactRequired)
			return
		}
		lease, err := admitRequestQuota(requestContext, quota, principal, responseQuotaRequest(principal.Policy, publicRequest.MaxOutputTokens))
		if err != nil {
			var quotaErr *apikey.QuotaError
			if errors.As(err, &quotaErr) {
				writeQuotaResponsesError(ctx, err)
			} else {
				writeResponsesError(ctx, http.StatusInternalServerError, responsesServerErrorType, "internal_error", "Internal server error.")
			}
			return
		}
		defer func() { _ = lease.release("request ended") }()
		if err := http.NewResponseController(ctx.ResponseWriter().Naive()).SetWriteDeadline(time.Now().Add(imagesWriteTimeout)); err != nil {
			writeResponsesError(ctx, http.StatusInternalServerError, responsesServerErrorType, "internal_error", "Internal server error.")
			return
		}

		setTransportOutcome(ctx, "http")
		forcedAccountID := continuationAccountID
		retriedAffinity := false
		var brokerResult BrokerResponsesResult
		for {
			attemptContext, cancel := context.WithCancel(requestContext)
			brokerResult, err = broker.DoResponses(attemptContext, selection, privateRequest, forcedAccountID, bindAccount)
			retry := !retriedAffinity && canRetrySessionAffinity(err, sessionHash, forcedAccountID, false) && journal != nil
			cancel()
			if !retry {
				break
			}
			retriedAffinity = true
			winner, resolveErr := journal.ResolveSessionAffinity(requestContext, principal.ID, sessionHash)
			if resolveErr != nil {
				err = resolveErr
				break
			}
			forcedAccountID = winner
		}
		result := brokerResult.Result
		if err != nil && (result.Response == nil || result.Response.Status != codex.CodexResponseStatusFailed) {
			if requestContext.Err() != nil {
				return
			}
			status, responseError := responsesError(err)
			writeResponsesError(ctx, status, responseError.Type, responseError.Code, responseError.Message)
			return
		}
		if requestContext.Err() != nil {
			return
		}
		if err := persistResponseImageArtifacts(requestContext, artifacts, artifactRequired, imageArtifactOwner(ctx), result); err != nil {
			markJournalTerminal(ctx, requestStatusFailed, "")
			writeResponsesError(ctx, http.StatusInternalServerError, responsesServerErrorType, "internal_error", "Internal server error.")
			return
		}
		payload, err := publicResponsePayload(result)
		if err != nil {
			writeResponsesError(ctx, http.StatusBadGateway, responsesServerErrorType, "invalid_upstream_response", "The upstream response was invalid.")
			return
		}
		if len(payload) > maxResponsesJSONBytes {
			writeResponsesError(ctx, http.StatusBadGateway, responsesServerErrorType, "upstream_response_too_large", "The upstream response is too large.")
			return
		}
		if err := validateQuotaUsageFromCodex(result.Response.Usage); err != nil {
			writeResponsesError(ctx, http.StatusBadGateway, responsesServerErrorType, "invalid_upstream_response", "The upstream response was invalid.")
			return
		}
		usage := quotaUsageFromCodex(result.Response.Usage, 0)
		if err := lease.reconcile(usage); err != nil {
			writeResponsesError(ctx, http.StatusInternalServerError, responsesServerErrorType, "internal_error", "Internal server error.")
			return
		}
		journalUsage := journalUsageFromCodex(result.Response.Usage, 0)
		journalUsage.ResolvedModel = result.Response.Model
		recordJournalUsageDetails(ctx, journalUsage)
		if err := writeJournalJSON(ctx, http.StatusOK, "response.json", payload); err != nil {
			handleJournalResponseError(ctx, err)
			return
		}
	}
}
func writeResponsesDecodeError(ctx iris.Context, err error, message string) {
	var tooLarge *http.MaxBytesError
	if errors.As(err, &tooLarge) {
		writeResponsesError(ctx, http.StatusRequestEntityTooLarge, responsesErrorType, "request_too_large", "Request body is too large.")
		return
	}
	if errors.Is(err, openai.ErrUnsupportedParameter) {
		writeResponsesError(ctx, http.StatusBadRequest, responsesErrorType, "unsupported_parameter", "The request uses an unsupported parameter.")
		return
	}
	writeResponsesError(ctx, http.StatusBadRequest, responsesErrorType, "invalid_json", message)
}

func privateResponseRequest(publicRequest openai.ResponseRequest) (codex.CodexResponseRequest, error) {
	if publicRequest.Metadata != nil && publicRequest.ClientMetadata != nil {
		return codex.CodexResponseRequest{}, errors.New("public Responses request cannot contain both metadata and client_metadata")
	}
	clientMetadata := publicRequest.Metadata
	if publicRequest.ClientMetadata != nil {
		clientMetadata = publicRequest.ClientMetadata
	}
	responsesLite, err := responsesLiteClientMetadataValue(publicRequest.ClientMetadata)
	if err != nil {
		return codex.CodexResponseRequest{}, err
	}
	privateRequest := codex.CodexResponseRequest{
		Model:                publicRequest.Model,
		Instructions:         publicRequest.Instructions,
		Store:                publicRequest.Store,
		Stream:               true,
		ParallelToolCalls:    publicRequest.ParallelToolCalls,
		ClientMetadata:       clientMetadata,
		Generate:             publicRequest.Generate,
		Include:              publicRequest.Include,
		PreviousResponseID:   publicRequest.PreviousResponseID,
		PromptCacheKey:       publicRequest.PromptCacheKey,
		PromptCacheRetention: publicRequest.PromptCacheRetention,
		ServiceTier:          publicRequest.ServiceTier,
		ResponsesLite:        responsesLite,
	}
	if publicRequest.StreamOptions != nil {
		privateRequest.StreamOptions = &codex.CodexStreamOptions{
			ReasoningSummaryDelivery: publicRequest.StreamOptions.ReasoningSummaryDelivery,
		}
	}
	if publicRequest.MaxOutputTokens != nil {
		privateRequest.MaxOutputTokens = *publicRequest.MaxOutputTokens
	}
	privateRequest.Input, err = privateInput(publicRequest.Input)
	if err != nil {
		return codex.CodexResponseRequest{}, err
	}
	privateRequest.Tools, err = privateTools(publicRequest.Tools)
	if err != nil {
		return codex.CodexResponseRequest{}, err
	}
	privateRequest.ToolChoice, err = privateToolChoice(publicRequest.ToolChoice)
	if err != nil {
		return codex.CodexResponseRequest{}, err
	}
	privateRequest.Reasoning = privateReasoning(publicRequest.Reasoning)
	privateRequest.Text = privateText(publicRequest.Text)
	return privateRequest, nil
}

func responsesLiteHeaderValue(values []string) (bool, error) {
	if len(values) == 0 {
		return false, nil
	}
	if len(values) != 1 || values[0] != "true" {
		return false, errors.New("Responses Lite header must contain one true value")
	}
	return true, nil
}

type turnMetadataIdentity struct {
	SessionID string `json:"session_id"`
	ThreadID  string `json:"thread_id"`
}

func decodeTurnMetadataIdentity(raw string) (turnMetadataIdentity, error) {
	decoder := json.NewDecoder(strings.NewReader(raw))
	token, err := decoder.Token()
	if err != nil {
		return turnMetadataIdentity{}, err
	}
	delimiter, ok := token.(json.Delim)
	if !ok || delimiter != '{' {
		return turnMetadataIdentity{}, errors.New("turn metadata is not an object")
	}
	seen := make(map[string]struct{}, 4)
	var metadata turnMetadataIdentity
	for decoder.More() {
		keyToken, err := decoder.Token()
		if err != nil {
			return turnMetadataIdentity{}, err
		}
		key, ok := keyToken.(string)
		if !ok {
			return turnMetadataIdentity{}, errors.New("turn metadata key is invalid")
		}
		normalizedKey := strings.ToLower(key)
		if _, exists := seen[normalizedKey]; exists {
			return turnMetadataIdentity{}, errors.New("turn metadata contains duplicate keys")
		}
		seen[normalizedKey] = struct{}{}
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return turnMetadataIdentity{}, err
		}
		switch normalizedKey {
		case "session_id":
			if len(value) == 0 || bytes.Equal(bytes.TrimSpace(value), []byte("null")) || json.Unmarshal(value, &metadata.SessionID) != nil {
				return turnMetadataIdentity{}, errors.New("turn metadata session_id is invalid")
			}
		case "thread_id":
			if len(value) == 0 || bytes.Equal(bytes.TrimSpace(value), []byte("null")) || json.Unmarshal(value, &metadata.ThreadID) != nil {
				return turnMetadataIdentity{}, errors.New("turn metadata thread_id is invalid")
			}
		}
	}
	token, err = decoder.Token()
	if err != nil {
		return turnMetadataIdentity{}, err
	}
	delimiter, ok = token.(json.Delim)
	if !ok || delimiter != '}' {
		return turnMetadataIdentity{}, errors.New("turn metadata object is invalid")
	}
	var extra json.RawMessage
	if err := decoder.Decode(&extra); err != io.EOF {
		return turnMetadataIdentity{}, errors.New("turn metadata has trailing data")
	}
	return metadata, nil
}

func requestHeaderConfig(headers http.Header) (codex.RequestHeaderConfig, error) {
	lite, err := responsesLiteHeaderValue(headerValuesEqualFold(headers, codex.ResponsesLiteHeader))
	if err != nil {
		return codex.RequestHeaderConfig{}, err
	}
	sessionID, err := boundedRequestHeader(headers, codex.SessionIDHeader)
	if err != nil {
		return codex.RequestHeaderConfig{}, err
	}
	threadID, err := boundedRequestHeader(headers, codex.ThreadIDHeader)
	if err != nil {
		return codex.RequestHeaderConfig{}, err
	}
	metadataValues := headerValuesEqualFold(headers, codex.TurnMetadataHeader)
	if len(metadataValues) > 1 {
		return codex.RequestHeaderConfig{}, errors.New("turn metadata header must contain one value")
	}
	if len(metadataValues) == 1 {
		rawMetadata := strings.TrimSpace(metadataValues[0])
		if len(rawMetadata) == 0 || len(rawMetadata) > maxTurnMetadataBytes || rawMetadata[0] != '{' {
			return codex.RequestHeaderConfig{}, errors.New("turn metadata header is invalid")
		}
		metadata, err := decodeTurnMetadataIdentity(rawMetadata)
		if err != nil {
			return codex.RequestHeaderConfig{}, errors.New("turn metadata header is invalid")
		}
		if metadata.SessionID, err = boundedIdentityValue("session_id", metadata.SessionID); err != nil {
			return codex.RequestHeaderConfig{}, err
		}
		if metadata.ThreadID, err = boundedIdentityValue("thread-id", metadata.ThreadID); err != nil {
			return codex.RequestHeaderConfig{}, err
		}
		if sessionID != "" && metadata.SessionID != "" && sessionID != metadata.SessionID {
			return codex.RequestHeaderConfig{}, errors.New("session_id and turn metadata disagree")
		}
		if threadID != "" && metadata.ThreadID != "" && threadID != metadata.ThreadID {
			return codex.RequestHeaderConfig{}, errors.New("thread-id and turn metadata disagree")
		}
		if sessionID == "" {
			sessionID = metadata.SessionID
		}
		if threadID == "" {
			threadID = metadata.ThreadID
		}
	}
	return codex.RequestHeaderConfig{SessionID: sessionID, ThreadID: threadID, ResponsesLiteRequested: lite}, nil
}

func boundedIdentityValue(name, value string) (string, error) {
	if len(value) > 256 || strings.ContainsAny(value, "\x00\r\n") {
		return "", fmt.Errorf("%s header is invalid", name)
	}
	return value, nil
}

func boundedRequestHeader(headers http.Header, name string) (string, error) {
	values := headerValuesEqualFold(headers, name)
	if len(values) == 0 {
		return "", nil
	}
	if len(values) != 1 || len(values[0]) > 256 || strings.ContainsAny(values[0], "\x00\r\n") {
		return "", fmt.Errorf("%s header is invalid", name)
	}
	return values[0], nil
}

func headerValuesEqualFold(headers http.Header, name string) []string {
	var values []string
	for key, entries := range headers {
		if strings.EqualFold(key, name) {
			values = append(values, entries...)
		}
	}
	return values
}

func responsesLiteClientMetadataValue(metadata map[string]string) (bool, error) {
	value, ok := metadata[responsesLiteClientMetadataKey]
	if !ok {
		return false, nil
	}
	if value != "true" {
		return false, errors.New("Responses Lite client metadata must be true")
	}
	return true, nil
}

func privateInput(input *openai.Input) (*codex.CodexInput, error) {
	if input == nil {
		return nil, nil
	}
	switch {
	case input.String != nil && input.Items == nil:
		value := *input.String
		return &codex.CodexInput{String: &value}, nil
	case input.String == nil && input.Items != nil:
		items := make([]codex.CodexInputItem, 0, len(input.Items))
		for _, item := range input.Items {
			var arguments json.RawMessage
			if item.Arguments != "" {
				var err error
				arguments, err = json.Marshal(item.Arguments)
				if err != nil {
					return nil, fmt.Errorf("encode private input arguments: %w", err)
				}
			}
			tools, err := privateTools(item.Tools)
			if err != nil {
				return nil, fmt.Errorf("encode private input tools: %w", err)
			}
			var pendingSafetyChecks []codex.CodexSafetyCheck
			if item.PendingSafetyChecks != nil {
				pendingSafetyChecks = make([]codex.CodexSafetyCheck, len(item.PendingSafetyChecks))
				for index, check := range item.PendingSafetyChecks {
					pendingSafetyChecks[index] = codex.CodexSafetyCheck{
						ID:      check.ID,
						Code:    check.Code,
						Message: check.Message,
					}
				}
			}
			var acknowledgedSafetyChecks []codex.CodexSafetyCheck
			if item.AcknowledgedSafetyChecks != nil {
				acknowledgedSafetyChecks = make([]codex.CodexSafetyCheck, len(item.AcknowledgedSafetyChecks))
				for index, check := range item.AcknowledgedSafetyChecks {
					acknowledgedSafetyChecks[index] = codex.CodexSafetyCheck{
						ID:      check.ID,
						Code:    check.Code,
						Message: check.Message,
					}
				}
			}
			items = append(items, codex.CodexInputItem{
				Type:                     item.Type,
				Role:                     item.Role,
				Status:                   item.Status,
				Content:                  item.Content,
				ID:                       item.ID,
				CallID:                   item.CallID,
				Name:                     item.Name,
				Arguments:                arguments,
				Output:                   item.Output,
				Action:                   item.Action,
				Actions:                  item.Actions,
				PendingSafetyChecks:      pendingSafetyChecks,
				AcknowledgedSafetyChecks: acknowledgedSafetyChecks,
				Tools:                    tools,
			})
		}
		return &codex.CodexInput{Items: items}, nil
	default:
		return nil, errors.New("public input must contain exactly one variant")
	}
}

func privateTools(tools []openai.Tool) ([]codex.CodexTool, error) {
	return privateToolsAtDepth(tools, 0)
}

func privateToolsAtDepth(tools []openai.Tool, depth int) ([]codex.CodexTool, error) {
	if tools == nil {
		return nil, nil
	}
	if depth > 1 {
		return nil, errors.New("public namespace tool nesting exceeds one level")
	}
	result := make([]codex.CodexTool, 0, len(tools))
	for _, tool := range tools {
		var mask *codex.CodexInputImageMask
		if tool.InputImageMask != nil {
			mask = &codex.CodexInputImageMask{FileID: tool.InputImageMask.FileID, ImageURL: tool.InputImageMask.ImageURL}
		}
		nested, err := privateToolsAtDepth(tool.Tools, depth+1)
		if err != nil {
			return nil, err
		}
		if len(tool.Tools) != 0 && tool.Type != "namespace" {
			return nil, errors.New("public tool tools is only valid for namespace tools")
		}
		result = append(result, codex.CodexTool{
			Type:              tool.Type,
			Name:              tool.Name,
			Description:       tool.Description,
			Strict:            tool.Strict,
			Parameters:        tool.Parameters,
			Action:            tool.Action,
			Background:        tool.Background,
			InputFidelity:     tool.InputFidelity,
			InputImageMask:    mask,
			Model:             tool.Model,
			Moderation:        tool.Moderation,
			OutputCompression: tool.OutputCompression,
			OutputFormat:      tool.OutputFormat,
			PartialImages:     tool.PartialImages,
			Quality:           tool.Quality,
			Size:              tool.Size,
			Tools:             nested,
		})
	}
	return result, nil
}

func privateToolChoice(choice *openai.ToolChoice) (*codex.CodexToolChoice, error) {
	if choice == nil {
		return nil, nil
	}
	switch {
	case choice.String != nil && choice.Type == "" && choice.Name == "":
		value := *choice.String
		return &codex.CodexToolChoice{String: &value}, nil
	case choice.String == nil && choice.Type != "":
		return &codex.CodexToolChoice{Type: choice.Type, Name: choice.Name}, nil
	default:
		return nil, errors.New("public tool choice contains exactly one variant")
	}
}

func privateReasoning(reasoning *openai.ReasoningConfig) *codex.CodexReasoningConfig {
	if reasoning == nil {
		return nil
	}
	return &codex.CodexReasoningConfig{Effort: reasoning.Effort, Summary: reasoning.Summary, Context: reasoning.Context}
}

func privateText(text *openai.TextConfig) *codex.CodexTextConfig {
	if text == nil {
		return nil
	}
	privateText := &codex.CodexTextConfig{Verbosity: text.Verbosity}
	if text.Format != nil {
		privateText.Format = &codex.CodexTextFormat{
			Type:        text.Format.Type,
			Name:        text.Format.Name,
			Description: text.Format.Description,
			Schema:      text.Format.Schema,
			Strict:      text.Format.Strict,
		}
	}
	return privateText
}

func serveResponsesStream(ctx iris.Context, requestContext context.Context, broker UpstreamBroker, selection codex.SelectionRequest, privateRequest codex.CodexResponseRequest, forcedAccountID, sessionHash, apiKeyID string, journal *Journal, bindAccount func(codex.Account) error, lease *quotaLease, artifacts *ArtifactStore, artifactRequired bool) {
	var writer http.ResponseWriter = ctx.ResponseWriter()
	baseWriter := writer
	baseFlusher, ok := writer.(http.Flusher)
	if !ok {
		markJournalTerminal(ctx, requestStatusFailed, "")
		return
	}
	deferredWriter, ok := newDeferredSSEWriter(writer)
	if !ok {
		markJournalTerminal(ctx, requestStatusFailed, "")
		return
	}
	if err := http.NewResponseController(ctx.ResponseWriter().Naive()).SetWriteDeadline(time.Time{}); err != nil && !errors.Is(err, http.ErrNotSupported) {
		markJournalTerminal(ctx, requestStatusFailed, "")
		return
	}
	writer.Header().Set("Content-Type", "text/event-stream")
	writer.Header().Set("Cache-Control", "no-cache, no-store")
	writer.Header().Set("Connection", "keep-alive")
	writer.Header().Set("X-Accel-Buffering", "no")
	writer = deferredWriter
	var flusher http.Flusher = deferredWriter
	var journalWriter *journalSSEWriter
	if wrapped, journalFlusher := newJournalSSEWriter(ctx, writer); wrapped != nil {
		journalWriter = wrapped
		writer = wrapped
		flusher = journalFlusher
	}
	bindForStream := func(account codex.Account) error {
		if bindAccount != nil {
			if err := bindAccount(account); err != nil {
				return err
			}
		}
		if !deferredWriter.committed {
			if err := deferredWriter.commit(http.StatusOK); err != nil {
				return err
			}
			flusher.Flush()
		}
		return nil
	}

	terminalWritten := false
	lastSequence := -1
	wroteOutput := false
	retriedAffinity := false
	setTransportOutcome(ctx, "websocket")
	var streamErr error
	for {
		terminalWritten = false
		lastSequence = -1
		attemptContext, cancel := context.WithCancel(requestContext)
		_, streamErr = broker.StreamResponses(attemptContext, selection, privateRequest, forcedAccountID, bindForStream, func(event codex.CodexResponseStreamEvent) error {
			if requestContext.Err() != nil {
				return requestContext.Err()
			}
			if event.SequenceNumber < 0 || event.SequenceNumber == math.MaxInt {
				return fmt.Errorf("invalid upstream sequence number %d", event.SequenceNumber)
			}
			if event.SequenceNumber > lastSequence {
				lastSequence = event.SequenceNumber
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
			successTerminal := isCodexTerminal(event.Type) && event.Type != codex.CodexEventError &&
				event.Response != nil && event.Response.Error == nil &&
				event.Response.Status != codex.CodexResponseStatusFailed
			if successTerminal {
				if err := validateQuotaUsageFromCodex(event.Response.Usage); err != nil {
					return fmt.Errorf("%w: %v", codex.ErrCodexStreamMalformed, err)
				}
				usage := quotaUsageFromCodex(event.Response.Usage, 0)
				if err := lease.reconcile(usage); err != nil {
					return err
				}
				journalUsage := journalUsageFromCodex(event.Response.Usage, 0)
				journalUsage.ResolvedModel = event.Response.Model
				recordJournalUsageDetails(ctx, journalUsage)
			}
			if err := writeResponsesSSERecord(writer, flusher, payload); err != nil {
				return err
			}
			wroteOutput = true
			if isCodexTerminal(event.Type) || event.Error != nil {
				terminalWritten = true
			}
			if event.Error != nil || event.Type == codex.CodexEventError {
				return errors.New("upstream error event terminated public stream")
			}
			return nil
		})
		retry := !retriedAffinity && canRetrySessionAffinity(streamErr, sessionHash, forcedAccountID, wroteOutput) && journal != nil
		cancel()
		if !retry {
			break
		}
		retriedAffinity = true
		winner, resolveErr := journal.ResolveSessionAffinity(requestContext, apiKeyID, sessionHash)
		if resolveErr != nil {
			streamErr = resolveErr
			break
		}
		forcedAccountID = winner
		selection.AffinityAccountID = ""
	}
	if requestContext.Err() != nil {
		return
	}
	if journalWriter != nil && journalWriter.failed != nil {
		markJournalTerminalValue(journalWriter.value, requestStatusFailed, "")
		journalWriter.value.journal.recordError(journalWriter.failed)
		writeJournalSSEFailure(baseWriter, baseFlusher, []byte(`{"type":"error","code":"internal_error","message":"Internal server error."}`))
		return
	}
	if !deferredWriter.committed && !terminalWritten && streamErr != nil {
		status, responseError := responsesError(streamErr)
		writeResponsesError(ctx, status, responseError.Type, responseError.Code, responseError.Message)
		return
	}
	if !terminalWritten {
		var responseError openai.Error
		if errors.Is(streamErr, errQuotaFinalization) {
			responseError = openai.Error{Type: responsesServerErrorType, Code: "internal_error", Message: "Internal server error."}
		} else {
			_, responseError = responsesError(streamErr)
		}
		errorEvent := openai.ResponseErrorEvent{
			Type:           openai.EventError,
			Code:           responseError.Code,
			Message:        responseError.Message,
			SequenceNumber: lastSequence + 1,
		}
		payload, err := json.Marshal(errorEvent)
		if err != nil || len(payload) > maxResponsesEventBytes {
			return
		}
		if err := writeResponsesSSERecord(writer, flusher, payload); err != nil {
			if journalWriter != nil && journalWriter.failed != nil {
				markJournalTerminalValue(journalWriter.value, requestStatusFailed, "")
				journalWriter.value.journal.recordError(journalWriter.failed)
				writeJournalSSEFailure(baseWriter, baseFlusher, []byte(`{"type":"error","code":"internal_error","message":"Internal server error."}`))
			}
			return
		}
		terminalWritten = true
	}
	if requestContext.Err() != nil {
		return
	}
	if err := writeResponsesSSERecord(writer, flusher, []byte("[DONE]")); err != nil {
		if journalWriter != nil && journalWriter.failed != nil {
			markJournalTerminalValue(journalWriter.value, requestStatusFailed, "")
			journalWriter.value.journal.recordError(journalWriter.failed)
			writeJournalSSEFailure(baseWriter, baseFlusher, []byte(`{"type":"error","code":"internal_error","message":"Internal server error."}`))
		}
		return
	}
}

type deferredSSEWriter struct {
	writer    http.ResponseWriter
	flusher   http.Flusher
	committed bool
}

func newDeferredSSEWriter(writer http.ResponseWriter) (*deferredSSEWriter, bool) {
	flusher, ok := writer.(http.Flusher)
	if !ok {
		return nil, false
	}
	return &deferredSSEWriter{writer: writer, flusher: flusher}, true
}

func (writer *deferredSSEWriter) Header() http.Header {
	return writer.writer.Header()
}

func (writer *deferredSSEWriter) WriteHeader(statusCode int) {
	if !writer.committed {
		if err := writer.commit(statusCode); err != nil {
			return
		}
		return
	}
	writer.writer.WriteHeader(statusCode)
}

func (writer *deferredSSEWriter) Write(payload []byte) (int, error) {
	if !writer.committed {
		if err := writer.commit(http.StatusOK); err != nil {
			return 0, err
		}
	}
	return writer.writer.Write(payload)
}

func (writer *deferredSSEWriter) Flush() {
	if writer.committed {
		writer.flusher.Flush()
	}
}

func (writer *deferredSSEWriter) commit(statusCode int) error {
	if writer.committed {
		return nil
	}
	writer.writer.WriteHeader(statusCode)
	writer.committed = true
	return nil
}

func writeResponsesSSERecord(writer http.ResponseWriter, flusher http.Flusher, payload []byte) error {
	payload = bytes.TrimSpace(payload)
	if len(payload) == 0 || len(payload) > maxResponsesEventBytes || bytes.ContainsAny(payload, "\r\n") {
		return errors.New("responses SSE payload is invalid")
	}
	if _, err := writer.Write([]byte("data: ")); err != nil {
		return err
	}
	if _, err := writer.Write(payload); err != nil {
		return err
	}
	if _, err := writer.Write([]byte("\n\n")); err != nil {
		return err
	}
	flusher.Flush()
	return nil
}

func isCodexTerminal(eventType string) bool {
	switch eventType {
	case codex.CodexEventResponseCompleted, codex.CodexEventResponseDone,
		codex.CodexEventResponseIncomplete, codex.CodexEventResponseFailed,
		codex.CodexEventError:
		return true
	default:
		return false
	}
}

func publicEventPayload(event codex.CodexResponseStreamEvent) ([]byte, bool, error) {
	if event.Error != nil || event.Type == codex.CodexEventError {
		code := event.Code
		if event.Error != nil && event.Error.Code != "" {
			code = event.Error.Code
		}
		if code == "" {
			code = "upstream_error"
		}
		payload, err := json.Marshal(openai.ResponseErrorEvent{
			Type:           openai.EventError,
			Code:           code,
			Message:        "The upstream service returned an error.",
			Param:          event.Param,
			SequenceNumber: event.SequenceNumber,
		})
		if err != nil {
			return nil, false, fmt.Errorf("encode public Responses error event: %w", err)
		}
		if len(payload) > maxResponsesEventBytes {
			return nil, false, errors.New("public Responses error event exceeds limit")
		}
		return payload, true, nil
	}
	if event.Type == codex.CodexEventResponseMetadata {
		return nil, false, nil
	}
	if isCodexTerminal(event.Type) && event.Type != codex.CodexEventError && event.Response == nil {
		return nil, false, fmt.Errorf("%w: terminal event response is missing", codex.ErrCodexStreamMalformed)
	}
	if event.Type == codex.CodexEventResponseDone {
		event.Type = codex.CodexEventResponseCompleted
		event.Raw = nil
	}
	eventCode, eventMessage := event.Code, event.Message
	if event.Type == codex.CodexEventResponseFailed {
		eventCode, eventMessage = "", ""
	}

	if len(event.Raw) != 0 && rawPublicEvent(event.Raw, event.Type) {
		payload := bytes.TrimSpace(event.Raw)
		if json.Valid(payload) && !bytes.ContainsAny(payload, "\r\n") && len(payload) <= maxResponsesEventBytes {
			return payload, true, nil
		}
	}
	var item *openai.OutputItem
	if event.Item != nil {
		outputItem := publicOutputItem(event.Item)
		item = &outputItem
	}
	publicEvent := openai.ResponseStreamEvent{
		Type:              event.Type,
		SequenceNumber:    event.SequenceNumber,
		Response:          publicResponse(event.Response),
		Item:              item,
		Part:              publicContentPart(event.Part),
		Delta:             event.Delta,
		Arguments:         event.Arguments,
		Annotation:        event.Annotation,
		Text:              event.Text,
		Logprobs:          publicLogprobs(event.Logprobs),
		Code:              eventCode,
		Message:           eventMessage,
		ItemID:            event.ItemID,
		OutputIndex:       event.OutputIndex,
		ContentIndex:      event.ContentIndex,
		SummaryIndex:      event.SummaryIndex,
		PartialImageB64:   event.PartialImageB64,
		PartialImageIndex: event.PartialImageIndex,
	}
	payload, err := json.Marshal(publicEvent)
	if err != nil {
		return nil, false, fmt.Errorf("encode public Responses event: %w", err)
	}
	if len(payload) > maxResponsesEventBytes {
		return nil, false, errors.New("public Responses event exceeds limit")
	}
	return payload, true, nil
}

func rawPublicEvent(raw []byte, eventType string) bool {
	if eventType == codex.CodexEventResponseMetadata || eventType == codex.CodexEventError || eventType == codex.CodexEventResponseFailed {
		return false
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return false
	}
	if errorValue, found := fields["error"]; found && !bytes.Equal(bytes.TrimSpace(errorValue), []byte("null")) {
		return false
	}
	if _, found := fields["headers"]; found {
		return false
	}
	if _, found := fields["metadata"]; found {
		return false
	}
	if response, found := fields["response"]; found && privateResponseJSON(response) {
		return false
	}
	if item, found := fields["item"]; found && privateOutputJSON(item) {
		return false
	}
	return true
}

func privateResponseJSON(raw []byte) bool {
	var response map[string]json.RawMessage
	if err := json.Unmarshal(raw, &response); err != nil {
		return true
	}
	if _, found := response["end_turn"]; found {
		return true
	}
	if _, found := response["error"]; found {
		return true
	}
	if output, found := response["output"]; found {
		var items []json.RawMessage
		if err := json.Unmarshal(output, &items); err != nil {
			return true
		}
		for _, item := range items {
			if privateOutputJSON(item) {
				return true
			}
		}
	}
	if usage, found := response["usage"]; found {
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(usage, &fields); err != nil {
			return true
		}
		if _, found := fields["prompt_cache_hit_tokens"]; found {
			return true
		}
		for _, name := range []string{"input_tokens_details", "output_tokens_details"} {
			if details, found := fields[name]; found {
				var detail map[string]json.RawMessage
				if err := json.Unmarshal(details, &detail); err != nil {
					return true
				}
				for _, key := range []string{"cache_write_tokens", "orchestration_input_tokens", "orchestration_input_cached_tokens", "image_tokens", "text_tokens", "orchestration_output_tokens"} {
					if _, found := detail[key]; found {
						return true
					}
				}
			}
		}
	}
	return false
}

func privateOutputJSON(raw []byte) bool {
	var item map[string]json.RawMessage
	if err := json.Unmarshal(raw, &item); err != nil {
		return true
	}
	for _, key := range []string{"output", "actions", "phase"} {
		if _, found := item[key]; found {
			return true
		}
	}
	if _, found := item["created_by"]; found {
		var itemType string
		if err := json.Unmarshal(item["type"], &itemType); err != nil || itemType != "compaction" {
			return true
		}
	}
	if _, found := item["encrypted_content"]; found {
		var itemType string
		if err := json.Unmarshal(item["type"], &itemType); err != nil || itemType != "compaction" {
			return true
		}
	}
	return false
}

func publicResponsePayload(result codex.CodexStreamResult) ([]byte, error) {
	if result.Response == nil {
		return nil, errors.New("upstream response is missing")
	}
	if raw := rawResponsePayload(result.Events); len(raw) != 0 && !privateResponseJSON(raw) && result.Response.Status != codex.CodexResponseStatusFailed {
		return raw, nil
	}
	payload, err := json.Marshal(publicResponse(result.Response))
	if err != nil {
		return nil, fmt.Errorf("encode public Responses response: %w", err)
	}
	return payload, nil
}

func rawResponsePayload(events []codex.CodexResponseStreamEvent) []byte {
	for index := len(events) - 1; index >= 0; index-- {
		if !isCodexTerminal(events[index].Type) || len(events[index].Raw) == 0 {
			continue
		}
		var envelope struct {
			Response json.RawMessage `json:"response"`
		}
		if err := json.Unmarshal(events[index].Raw, &envelope); err == nil && json.Valid(envelope.Response) {
			return bytes.TrimSpace(envelope.Response)
		}
	}
	return nil
}

func publicResponse(response *codex.CodexResponse) *openai.Response {
	if response == nil {
		return nil
	}
	return &openai.Response{
		ID:                 response.ID,
		Object:             response.Object,
		CreatedAt:          response.CreatedAt,
		CompletedAt:        response.CompletedAt,
		Model:              response.Model,
		Status:             response.Status,
		OutputText:         response.OutputText,
		Output:             publicOutputItems(response.Output),
		Usage:              publicUsage(response.Usage),
		Error:              publicErrorFromCodex(response.Error),
		IncompleteDetails:  publicIncompleteDetails(response.IncompleteDetails),
		ServiceTier:        response.ServiceTier,
		PreviousResponseID: response.PreviousResponseID,
	}
}

func publicOutputItems(items []codex.CodexOutputItem) []openai.OutputItem {
	if items == nil {
		return nil
	}
	output := make([]openai.OutputItem, 0, len(items))
	for _, item := range items {
		output = append(output, publicOutputItem(&item))
	}
	return output
}

func publicOutputItem(item *codex.CodexOutputItem) openai.OutputItem {
	if item == nil {
		return openai.OutputItem{}
	}
	output := openai.OutputItem{
		ID:                       item.ID,
		Type:                     item.Type,
		Role:                     item.Role,
		Status:                   item.Status,
		Content:                  publicContentParts(item.Content),
		CallID:                   item.CallID,
		Name:                     item.Name,
		Arguments:                item.Arguments,
		Input:                    item.Input,
		Result:                   item.Result,
		RevisedPrompt:            item.RevisedPrompt,
		Action:                   item.Action,
		PendingSafetyChecks:      publicSafetyChecks(item.PendingSafetyChecks),
		AcknowledgedSafetyChecks: publicSafetyChecks(item.AcknowledgedSafetyChecks),
	}
	if item.Type == "compaction" {
		output.EncryptedContent = item.EncryptedContent
		output.CreatedBy = item.CreatedBy
	}
	return output
}
func publicSafetyChecks(checks []codex.CodexSafetyCheck) []openai.SafetyCheck {
	if checks == nil {
		return nil
	}
	safetyChecks := make([]openai.SafetyCheck, 0, len(checks))
	for _, check := range checks {
		safetyChecks = append(safetyChecks, openai.SafetyCheck{
			ID:      check.ID,
			Code:    check.Code,
			Message: check.Message,
		})
	}
	return safetyChecks
}

func publicContentParts(parts []codex.CodexContentPart) []openai.ContentPart {
	if parts == nil {
		return nil
	}
	content := make([]openai.ContentPart, 0, len(parts))
	for _, part := range parts {
		contentPart := publicContentPart(&part)
		if contentPart != nil {
			content = append(content, *contentPart)
		}
	}
	return content
}

func publicContentPart(part *codex.CodexContentPart) *openai.ContentPart {
	if part == nil {
		return nil
	}
	return &openai.ContentPart{
		Type:        part.Type,
		Text:        part.Text,
		Refusal:     part.Refusal,
		ImageURL:    part.ImageURL,
		Detail:      part.Detail,
		Annotations: part.Annotations,
		Logprobs:    publicLogprobs(part.Logprobs),
	}
}

func publicLogprobs(logprobs []codex.CodexTextLogprob) []openai.TextLogprob {
	if logprobs == nil {
		return nil
	}
	values := make([]openai.TextLogprob, 0, len(logprobs))
	for _, logprob := range logprobs {
		values = append(values, openai.TextLogprob{
			Token:       logprob.Token,
			Bytes:       logprob.Bytes,
			Logprob:     logprob.Logprob,
			TopLogprobs: publicTopLogprobs(logprob.TopLogprobs),
		})
	}
	return values
}

func publicTopLogprobs(logprobs []codex.CodexTopLogprob) []openai.TopLogprob {
	if logprobs == nil {
		return nil
	}
	values := make([]openai.TopLogprob, 0, len(logprobs))
	for _, logprob := range logprobs {
		values = append(values, openai.TopLogprob{Token: logprob.Token, Bytes: logprob.Bytes, Logprob: logprob.Logprob})
	}
	return values
}

func publicUsage(usage *codex.CodexUsage) *openai.Usage {
	if usage == nil {
		return nil
	}
	result := &openai.Usage{
		InputTokens:  usage.InputTokens,
		OutputTokens: usage.OutputTokens,
		TotalTokens:  usage.TotalTokens,
	}
	if usage.InputTokensDetails != nil {
		result.InputTokensDetails = &openai.InputTokenDetails{CachedTokens: usage.InputTokensDetails.CachedTokens}
	}
	if usage.OutputTokensDetails != nil {
		result.OutputTokensDetails = &openai.OutputTokenDetails{ReasoningTokens: usage.OutputTokensDetails.ReasoningTokens}
	}
	return result
}

func publicIncompleteDetails(details *codex.CodexIncompleteDetails) *openai.IncompleteDetails {
	if details == nil {
		return nil
	}
	return &openai.IncompleteDetails{Reason: details.Reason}
}

func publicErrorFromCodex(providerError *codex.CodexError) *openai.Error {
	if providerError == nil {
		return nil
	}
	code := providerError.Code
	if code == "" {
		code = "upstream_error"
	}
	return &openai.Error{Type: responsesServerErrorType, Code: code, Message: "The upstream service returned an error."}
}

func responsesError(err error) (int, openai.Error) {
	if err == nil {
		return http.StatusBadGateway, openai.Error{Type: responsesServerErrorType, Code: "upstream_error", Message: "The upstream service returned an error."}
	}
	if errors.Is(err, codex.ErrInvalidImageRequest) {
		return http.StatusBadRequest, openai.Error{Type: responsesErrorType, Code: "invalid_request", Message: "The request is invalid."}
	}
	var safeError *codex.SafeError
	if errors.Is(err, ErrBrokerUnavailable) || errors.Is(err, codex.ErrNoAvailableAccount) {
		return http.StatusServiceUnavailable, openai.Error{Type: responsesServerErrorType, Code: "upstream_unavailable", Message: "The upstream service is unavailable."}
	}
	if errors.Is(err, ErrBrokerBind) {
		return http.StatusInternalServerError, openai.Error{Type: responsesServerErrorType, Code: "internal_error", Message: "Internal server error."}
	}
	if errors.As(err, &safeError) {
		status := safeError.StatusCode
		if status < 400 || status > 599 {
			status = http.StatusBadGateway
		}
		return status, openai.Error{Type: responsesErrorTypeForCategory(safeError.Category), Code: string(safeError.Category), Message: safeError.Message}
	}
	if errors.Is(err, codex.ErrRefreshRequiresLogin) {
		return http.StatusUnauthorized, openai.Error{Type: "authentication_error", Code: "upstream_authentication_error", Message: "The upstream credential is not valid."}
	}
	if errors.Is(err, codex.ErrRefreshTemporary) {
		return http.StatusServiceUnavailable, openai.Error{Type: responsesServerErrorType, Code: "upstream_unavailable", Message: "The upstream service is temporarily unavailable."}
	}
	if errors.Is(err, codex.ErrCodexStreamMalformed) || errors.Is(err, codex.ErrCodexStreamAbruptClose) || errors.Is(err, codex.ErrCodexStreamFailed) {
		return http.StatusBadGateway, openai.Error{Type: responsesServerErrorType, Code: "upstream_protocol_error", Message: "The upstream service returned an invalid response."}
	}
	return http.StatusBadGateway, openai.Error{Type: responsesServerErrorType, Code: "upstream_error", Message: "The upstream service is unavailable."}
}

func responsesErrorTypeForCategory(category codex.ErrorCategory) string {
	switch category {
	case codex.CategoryAuthentication:
		return "authentication_error"
	case codex.CategoryInvalidRequest, codex.CategoryContextWindow:
		return responsesErrorType
	case codex.CategoryRateLimit, codex.CategoryUsageLimit:
		return "rate_limit_error"
	case codex.CategoryPolicy:
		return "permission_error"
	default:
		return responsesServerErrorType
	}
}

func writeResponsesError(ctx iris.Context, status int, typ, code, message string) {
	setRequestError(ctx, errorClassForStatus(status), code)
	if _, ok := ctx.Values().Get(journalRequestValueKey).(*journalRequestValue); !ok {
		recordJournalRejection(ctx, status, "audit.rejected."+code)
	}
	writeJSON(ctx, status, openai.ErrorResponse{Error: openai.Error{Type: typ, Code: code, Message: message}})
}
func persistResponseImageArtifacts(ctx context.Context, store *ArtifactStore, required bool, owner ArtifactOwner, result codex.CodexStreamResult) error {
	if result.Response == nil {
		return nil
	}
	var candidates []struct {
		index int
		mime  string
		data  []byte
	}
	for index, item := range result.Response.Output {
		if item.Type != codex.CodexImageGenerationCall || item.Result == "" {
			continue
		}
		if len(item.Result) > 8<<20 {
			return errors.New("response image artifact is too large")
		}
		data, err := base64.StdEncoding.DecodeString(item.Result)
		if err != nil {
			return errors.New("response image artifact is invalid")
		}
		if len(data) == 0 || len(data) > maxImageFileBytes {
			return errors.New("response image artifact size is invalid")
		}
		mimeType, ok := artifactImageMIME(data)
		if !ok {
			return errors.New("response image artifact MIME is unsupported")
		}
		candidates = append(candidates, struct {
			index int
			mime  string
			data  []byte
		}{index: index, mime: mimeType, data: data})
	}
	if len(candidates) == 0 {
		return nil
	}
	if store == nil {
		if required {
			return errors.New("encrypted artifact storage is unavailable")
		}
		return nil
	}
	if err := validateArtifactOwner(owner); err != nil {
		return err
	}
	saved := make([]ArtifactRecord, 0, len(candidates))
	for _, candidate := range candidates {
		record, err := store.Save(ctx, owner, candidate.index, candidate.mime, candidate.data)
		if err != nil {
			cleanupImageArtifacts(ctx, store, saved)
			return fmt.Errorf("persist response image artifact %d: %w", candidate.index, err)
		}
		if record.persisted {
			saved = append(saved, record)
		}
	}
	return nil
}
