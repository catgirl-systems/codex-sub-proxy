package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"

	"github.com/catgirl-systems/codex-sub-proxy/internal/apikey"
	"github.com/catgirl-systems/codex-sub-proxy/internal/codex"
	"github.com/catgirl-systems/codex-sub-proxy/internal/openai"
	"github.com/go-playground/validator/v10"
	"github.com/kataras/iris/v12"
)

const (
	responsesEndpoint        = "/v1/responses"
	maxResponsesBodyBytes    = 4 * 1024 * 1024
	maxResponsesJSONBytes    = 4 * 1024 * 1024
	maxResponsesEventBytes   = 256 * 1024
	responsesErrorType       = "invalid_request_error"
	responsesServerErrorType = "server_error"
)

func newResponsesHandler(authorizer *apikey.Authorizer, transport *codex.ResponsesTransport) iris.Handler {
	requestValidation := validator.New()
	return func(ctx iris.Context) {
		request := ctx.Request()
		if request.Method != http.MethodPost {
			ctx.Header("Allow", http.MethodPost)
			writeResponsesError(ctx, http.StatusMethodNotAllowed, responsesErrorType, "method_not_allowed", "Only POST is allowed for this endpoint.")
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

		requestContext := request.Context()
		headers := request.Header.Values("Authorization")
		if len(headers) != 1 {
			writeAPIKeyError(ctx, apikey.ErrInvalidKey)
			return
		}
		if _, err := authorizer.AuthorizeHeader(requestContext, headers[0], responsesEndpoint, publicRequest.Model); err != nil {
			writeAPIKeyError(ctx, err)
			return
		}
		if transport == nil {
			writeResponsesError(ctx, http.StatusServiceUnavailable, responsesServerErrorType, "upstream_unavailable", "The upstream service is unavailable.")
			return
		}
		privateRequest, err := privateResponseRequest(publicRequest)
		if err != nil {
			writeResponsesError(ctx, http.StatusBadRequest, responsesErrorType, "invalid_request", "The request is invalid.")
			return
		}

		result, err := transport.Do(requestContext, privateRequest)
		if publicRequest.Stream {
			if err != nil && len(result.Events) == 0 && result.Response == nil {
				if requestContext.Err() != nil {
					return
				}
				status, responseError := responsesError(err)
				writeResponsesError(ctx, status, responseError.Type, responseError.Code, responseError.Message)
				return
			}
			serveResponsesStream(ctx, requestContext, result, err)
			return
		}
		if err != nil {
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
		payload, err := publicResponsePayload(result)
		if err != nil {
			writeResponsesError(ctx, http.StatusBadGateway, responsesServerErrorType, "invalid_upstream_response", "The upstream response was invalid.")
			return
		}
		if len(payload) > maxResponsesJSONBytes {

			writeResponsesError(ctx, http.StatusBadGateway, responsesServerErrorType, "upstream_response_too_large", "The upstream response is too large.")
			return
		}
		ctx.Header("Content-Type", "application/json")
		ctx.StatusCode(http.StatusOK)
		if _, err := ctx.ResponseWriter().Write(payload); err != nil {
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
	writeResponsesError(ctx, http.StatusBadRequest, responsesErrorType, "invalid_json", message)
}

func privateResponseRequest(publicRequest openai.ResponseRequest) (codex.CodexResponseRequest, error) {
	encoded, err := json.Marshal(publicRequest)
	if err != nil {
		return codex.CodexResponseRequest{}, fmt.Errorf("encode public Responses request: %w", err)
	}
	if len(encoded) == 0 || len(encoded) > maxResponsesBodyBytes {
		return codex.CodexResponseRequest{}, errors.New("public Responses request exceeds limit")
	}
	var privateRequest codex.CodexResponseRequest
	if err := json.Unmarshal(encoded, &privateRequest); err != nil {
		return codex.CodexResponseRequest{}, fmt.Errorf("decode private Responses request: %w", err)
	}
	privateRequest.Stream = true
	return privateRequest, nil
}

func serveResponsesStream(ctx iris.Context, requestContext context.Context, result codex.CodexStreamResult, streamErr error) {
	writer := ctx.ResponseWriter()
	writer.Header().Set("Content-Type", "text/event-stream")
	writer.Header().Set("Cache-Control", "no-cache")
	writer.Header().Set("Connection", "keep-alive")
	writer.Header().Set("X-Accel-Buffering", "no")
	writer.WriteHeader(http.StatusOK)

	flusher, ok := writer.(http.Flusher)
	if !ok {
		return
	}
	terminalWritten := false
	for _, event := range result.Events {
		if requestContext.Err() != nil {
			return
		}
		terminalEvent := isCodexTerminal(event.Type)
		if terminalEvent && terminalWritten {
			return
		}
		payload, keep, err := publicEventPayload(event)
		if err != nil {
			streamErr = err
			break
		}
		if !keep {
			continue
		}
		if err := writeResponsesSSERecord(writer, flusher, payload); err != nil {
			return
		}
		if terminalEvent {
			terminalWritten = true
		}
	}

	if !terminalWritten {
		if requestContext.Err() != nil {
			return
		}
		sequenceNumber := nextSequenceNumber(result.Events)
		errorEvent := openai.ResponseStreamEvent{
			Type:           openai.EventError,
			SequenceNumber: sequenceNumber,
			Error:          responsesErrorValue(streamErr),
		}
		payload, err := json.Marshal(errorEvent)
		if err != nil || len(payload) > maxResponsesEventBytes {
			return
		}
		if err := writeResponsesSSERecord(writer, flusher, payload); err != nil {
			return
		}
		terminalWritten = true
	}
	if requestContext.Err() != nil {
		return
	}
	_ = writeResponsesSSERecord(writer, flusher, []byte("[DONE]"))
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

func nextSequenceNumber(events []codex.CodexResponseStreamEvent) int {
	if len(events) == 0 {
		return 0
	}
	return events[len(events)-1].SequenceNumber + 1
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
	if event.Type == codex.CodexEventResponseMetadata {
		return nil, false, nil
	}
	if len(event.Raw) != 0 && rawPublicEvent(event.Raw, event.Type) {
		payload := bytes.TrimSpace(event.Raw)
		if json.Valid(payload) && !bytes.ContainsAny(payload, "\r\n") && len(payload) <= maxResponsesEventBytes {
			return append([]byte(nil), payload...), true, nil
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
		Annotation:        append([]byte(nil), event.Annotation...),
		Text:              event.Text,
		Logprobs:          publicLogprobs(event.Logprobs),
		Code:              event.Code,
		Message:           event.Message,
		ItemID:            event.ItemID,
		OutputIndex:       event.OutputIndex,
		ContentIndex:      event.ContentIndex,
		SummaryIndex:      event.SummaryIndex,
		PartialImageB64:   event.PartialImageB64,
		PartialImageIndex: event.PartialImageIndex,
	}
	if event.Error != nil {
		publicEvent.Error = publicErrorFromCodex(event.Error)
	}
	if publicEvent.Type == openai.EventError && publicEvent.Error == nil {
		publicEvent.Error = &openai.Error{Type: responsesServerErrorType, Code: "upstream_error", Message: "The upstream service returned an error."}
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
	for _, key := range []string{"output", "actions", "pending_safety_checks", "acknowledged_safety_checks", "created_by", "phase"} {
		if _, found := item[key]; found {
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
		return append([]byte(nil), raw...), nil
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
		ID:            item.ID,
		Type:          item.Type,
		Role:          item.Role,
		Status:        item.Status,
		Content:       publicContentParts(item.Content),
		CallID:        item.CallID,
		Name:          item.Name,
		Arguments:     item.Arguments,
		Input:         item.Input,
		Result:        item.Result,
		RevisedPrompt: item.RevisedPrompt,
	}
	if len(item.Action) != 0 {
		var action string
		if json.Unmarshal(item.Action, &action) == nil {
			output.Action = action
		}
	}
	return output
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
		Annotations: append([]json.RawMessage(nil), part.Annotations...),
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
			Bytes:       append([]int(nil), logprob.Bytes...),
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
		values = append(values, openai.TopLogprob{Token: logprob.Token, Bytes: append([]int(nil), logprob.Bytes...), Logprob: logprob.Logprob})
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
	var safeError *codex.SafeError
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

func responsesErrorValue(err error) *openai.Error {
	_, value := responsesError(err)
	return &value
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
	writeJSON(ctx, status, openai.ErrorResponse{Error: openai.Error{Type: typ, Code: code, Message: message}})
}
