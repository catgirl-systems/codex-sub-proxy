package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"mime"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/catgirl-systems/codex-sub-proxy/internal/apikey"
	"github.com/catgirl-systems/codex-sub-proxy/internal/codex"
	"github.com/catgirl-systems/codex-sub-proxy/internal/openai"
	"github.com/go-playground/validator/v10"
	"github.com/kataras/iris/v12"
)

const (
	chatCompletionsEndpoint = "/v1/chat/completions"
	maxChatBodyBytes        = 4 * 1024 * 1024
	maxChatMessages         = 256
	maxChatContentParts     = 256
	maxChatTools            = 128
	maxChatToolCalls        = 128
	maxChatStringBytes      = 1 * 1024 * 1024
	maxChatArgumentsBytes   = 1 * 1024 * 1024
	maxChatSchemaBytes      = 256 * 1024
	maxChatJSONDepth        = 32
	maxChatJSONMembers      = 4096
)

var (
	errChatUnsupported = errors.New("chat parameter is unsupported")
	errChatStreamAbort = errors.New("chat stream translation aborted")
)

type chatCompletionRequest struct {
	Model               string             `json:"model" validate:"required,max=128"`
	Messages            []chatMessage      `json:"messages" validate:"required,min=1,max=256"`
	Stream              bool               `json:"stream"`
	StreamOptions       *chatStreamOptions `json:"stream_options"`
	MaxCompletionTokens *int               `json:"max_completion_tokens" validate:"omitempty,min=1,max=1000000"`
	Temperature         *float64           `json:"temperature"`
	TopP                *float64           `json:"top_p"`
	N                   *int               `json:"n" validate:"omitempty,min=1,max=1"`
	Tools               []chatTool         `json:"tools" validate:"max=128"`
	ToolChoice          json.RawMessage    `json:"tool_choice"`
	ResponseFormat      json.RawMessage    `json:"response_format"`
	Stop                json.RawMessage    `json:"stop"`
	Logprobs            json.RawMessage    `json:"logprobs"`
	Modalities          json.RawMessage    `json:"modalities"`
	Audio               json.RawMessage    `json:"audio"`
	Prediction          json.RawMessage    `json:"prediction"`
	FunctionCall        json.RawMessage    `json:"function_call"`
	Functions           json.RawMessage    `json:"functions"`
}

type chatStreamOptions struct {
	IncludeUsage *bool `json:"include_usage"`
}

type chatMessage struct {
	Role         string          `json:"role" validate:"required"`
	Content      json.RawMessage `json:"content"`
	Refusal      json.RawMessage `json:"refusal"`
	Name         string          `json:"name"`
	ToolCallID   string          `json:"tool_call_id"`
	ToolCalls    []chatToolCall  `json:"tool_calls" validate:"max=128"`
	Audio        json.RawMessage `json:"audio"`
	FunctionCall json.RawMessage `json:"function_call"`
}

type chatToolCall struct {
	ID       string               `json:"id" validate:"required,max=256"`
	Type     string               `json:"type" validate:"required"`
	Function chatToolCallFunction `json:"function"`
}

type chatToolCallFunction struct {
	Name      string `json:"name" validate:"required,max=64"`
	Arguments string `json:"arguments" validate:"max=1048576"`
}

type chatTool struct {
	Type     string                 `json:"type" validate:"required"`
	Function chatFunctionDefinition `json:"function"`
}

type chatFunctionDefinition struct {
	Name        string          `json:"name" validate:"required,max=64"`
	Description string          `json:"description" validate:"max=1048576"`
	Parameters  json.RawMessage `json:"parameters"`
	Strict      *bool           `json:"strict"`
}

type chatTextPart struct {
	Type string `json:"type" validate:"required"`
	Text string `json:"text" validate:"max=1048576"`
}

type chatResponseFormat struct {
	Type       string          `json:"type" validate:"required"`
	JSONSchema *chatJSONSchema `json:"json_schema"`
}

type chatJSONSchema struct {
	Name        string          `json:"name" validate:"required,max=64"`
	Description string          `json:"description" validate:"max=1048576"`
	Schema      json.RawMessage `json:"schema"`
	Strict      *bool           `json:"strict"`
}

type chatNamedToolChoice struct {
	Type     string                `json:"type" validate:"required"`
	Function chatNamedToolFunction `json:"function"`
}

type chatNamedToolFunction struct {
	Name string `json:"name" validate:"required,max=64"`
}

func newChatCompletionsHandler(authorizer *apikey.Authorizer, transport *codex.ResponsesTransport, journal *Journal, quota *apikey.QuotaStore) iris.Handler {
	requestValidation := validator.New()
	return func(ctx iris.Context) {
		setJournalAuditContext(ctx, journal, chatCompletionsEndpoint)
		request := ctx.Request()
		requestContext := request.Context()
		if request.Method != http.MethodPost {
			ctx.Header("Allow", http.MethodPost)
			writeChatError(ctx, http.StatusMethodNotAllowed, responsesErrorType, "method_not_allowed", "Only POST is allowed for this endpoint.")
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
			writeChatError(ctx, http.StatusUnsupportedMediaType, responsesErrorType, "invalid_media_type", "Content-Type must be application/json.")
			return
		}
		if request.ContentLength > maxChatBodyBytes {
			writeChatError(ctx, http.StatusRequestEntityTooLarge, responsesErrorType, "request_too_large", "Request body is too large.")
			return
		}

		request.Body = http.MaxBytesReader(ctx.ResponseWriter(), request.Body, maxChatBodyBytes)
		defer request.Body.Close()
		var publicRequest chatCompletionRequest
		decoder := json.NewDecoder(request.Body)
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&publicRequest); err != nil {
			writeChatDecodeError(ctx, err)
			return
		}
		var extra json.RawMessage
		if err := decoder.Decode(&extra); err != io.EOF {
			if err == nil {
				writeChatError(ctx, http.StatusBadRequest, responsesErrorType, "invalid_json", "Request body must contain one JSON object.")
			} else {
				writeChatDecodeError(ctx, err)
			}
			return
		}
		if err := requestValidation.Struct(publicRequest); err != nil {
			writeChatError(ctx, http.StatusBadRequest, responsesErrorType, "invalid_request", "The request is invalid.")
			return
		}
		includeUsage, err := validateChatRequest(publicRequest)
		if err != nil {
			if errors.Is(err, errChatUnsupported) {
				writeChatError(ctx, http.StatusBadRequest, responsesErrorType, "unsupported_parameter", "The request uses an unsupported parameter.")
			} else {
				writeChatError(ctx, http.StatusBadRequest, responsesErrorType, "invalid_request", "The request is invalid.")
			}
			return
		}
		principal, err = authorizer.AuthorizePrincipal(requestContext, principal, chatCompletionsEndpoint, publicRequest.Model)
		if err != nil {
			writeAPIKeyError(ctx, err)
			return
		}
		journalInput, err := json.Marshal(publicRequest)
		if err != nil {
			writeChatError(ctx, http.StatusInternalServerError, responsesServerErrorType, "internal_error", "Internal server error.")
			return
		}
		journalRequestID, err := startJournalRequestWithMetadata(ctx, journal, JournalRequestMetadata{
			Endpoint: chatCompletionsEndpoint, Model: publicRequest.Model, APIKeyID: principal.ID,
		}, journalInput)
		if err != nil {
			writeChatError(ctx, http.StatusInternalServerError, responsesServerErrorType, "internal_error", "Internal server error.")
			return
		}
		if journal != nil {
			defer finishJournalRequest(ctx, journal, journalRequestID)
		}
		if transport == nil {
			writeChatError(ctx, http.StatusServiceUnavailable, responsesServerErrorType, "upstream_unavailable", "The upstream service is unavailable.")
			return
		}
		privateRequest, err := privateChatRequest(publicRequest)
		if err != nil {
			if errors.Is(err, errChatUnsupported) {
				writeChatError(ctx, http.StatusBadRequest, responsesErrorType, "unsupported_parameter", "The request uses an unsupported parameter.")
			} else {
				writeChatError(ctx, http.StatusBadRequest, responsesErrorType, "invalid_request", "The request is invalid.")
			}
			return
		}
		lease, err := admitRequestQuota(requestContext, quota, principal, responseQuotaRequest(principal.Policy, publicRequest.MaxCompletionTokens))
		if err != nil {
			var quotaErr *apikey.QuotaError
			if errors.As(err, &quotaErr) {
				writeQuotaChatError(ctx, err)
			} else {
				writeChatError(ctx, http.StatusInternalServerError, responsesServerErrorType, "internal_error", "Internal server error.")
			}
			return
		}
		if lease != nil {
			defer func() { _ = lease.release("request ended") }()
		}
		if publicRequest.Stream {
			serveChatStream(ctx, requestContext, transport, privateRequest, publicRequest.Model, includeUsage, lease)
			return
		}

		if err := http.NewResponseController(ctx.ResponseWriter().Naive()).SetWriteDeadline(time.Now().Add(imagesWriteTimeout)); err != nil {
			writeChatError(ctx, http.StatusInternalServerError, responsesServerErrorType, "internal_error", "Internal server error.")
			return
		}
		result, err := transport.Do(requestContext, privateRequest)
		if err != nil && (result.Response == nil || result.Response.Status != codex.CodexResponseStatusFailed) {
			if requestContext.Err() != nil {
				return
			}
			status, responseError := responsesError(err)
			writeChatError(ctx, status, responseError.Type, responseError.Code, responseError.Message)
			return
		}
		if requestContext.Err() != nil {
			return
		}
		if result.Response == nil {
			writeChatError(ctx, http.StatusBadGateway, responsesServerErrorType, "invalid_upstream_response", "The upstream response was invalid.")
			return
		}
		payload, err := chatCompletionPayload(result.Response, publicRequest.Model)
		if err != nil {
			writeChatError(ctx, http.StatusBadGateway, responsesServerErrorType, "invalid_upstream_response", "The upstream response was invalid.")
			return
		}
		if len(payload) > maxResponsesJSONBytes {
			writeChatError(ctx, http.StatusBadGateway, responsesServerErrorType, "upstream_response_too_large", "The upstream response is too large.")
			return
		}
		if err := validateQuotaUsageFromCodex(result.Response.Usage); err != nil {
			writeChatError(ctx, http.StatusBadGateway, responsesServerErrorType, "invalid_upstream_response", "The upstream response was invalid.")
			return
		}
		usage := quotaUsageFromCodex(result.Response.Usage, 0)
		if err := lease.reconcile(usage); err != nil {
			writeChatError(ctx, http.StatusInternalServerError, responsesServerErrorType, "internal_error", "Internal server error.")
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

func writeChatDecodeError(ctx iris.Context, err error) {
	var tooLarge *http.MaxBytesError
	if errors.As(err, &tooLarge) {
		writeChatError(ctx, http.StatusRequestEntityTooLarge, responsesErrorType, "request_too_large", "Request body is too large.")
		return
	}
	writeChatError(ctx, http.StatusBadRequest, responsesErrorType, "invalid_json", "Request body is not valid JSON.")
}

func writeChatError(ctx iris.Context, status int, typ, code, message string) {
	if _, ok := ctx.Values().Get(journalRequestValueKey).(*journalRequestValue); !ok {
		recordJournalRejection(ctx, status, "audit.rejected."+code)
	}
	writeJSON(ctx, status, openai.ErrorResponse{Error: openai.Error{Type: typ, Code: code, Message: message}})
}

func validateChatRequest(request chatCompletionRequest) (bool, error) {
	if request.N != nil && *request.N != 1 {
		return false, fmt.Errorf("n must be one")
	}
	if request.Temperature != nil {
		return false, fmt.Errorf("%w: temperature", errChatUnsupported)
	}
	if request.TopP != nil {
		return false, fmt.Errorf("%w: top_p", errChatUnsupported)
	}
	unsupported := []struct {
		field string
		value json.RawMessage
	}{
		{"stop", request.Stop},
		{"logprobs", request.Logprobs},
		{"modalities", request.Modalities},
		{"audio", request.Audio},
		{"prediction", request.Prediction},
		{"function_call", request.FunctionCall},
		{"functions", request.Functions},
	}
	for _, item := range unsupported {
		if len(item.value) != 0 {
			return false, fmt.Errorf("%w: %s", errChatUnsupported, item.field)
		}
	}
	if request.StreamOptions != nil && request.StreamOptions.IncludeUsage != nil && !request.Stream {
		return false, fmt.Errorf("%w: stream_options", errChatUnsupported)
	}
	if err := validateChatResponseFormat(request.ResponseFormat); err != nil {
		return false, err
	}
	if len(request.Tools) > maxChatTools {
		return false, errors.New("too many tools")
	}
	for index := range request.Tools {
		if err := validateChatTool(request.Tools[index]); err != nil {
			return false, fmt.Errorf("tool %d: %w", index, err)
		}
	}
	if err := validateChatToolChoice(request.ToolChoice); err != nil {
		return false, err
	}
	for index := range request.Messages {
		if err := validateChatMessage(request.Messages[index]); err != nil {
			return false, fmt.Errorf("message %d: %w", index, err)
		}
	}
	return request.StreamOptions != nil && request.StreamOptions.IncludeUsage != nil && *request.StreamOptions.IncludeUsage, nil
}

func validateChatResponseFormat(raw json.RawMessage) error {
	if len(raw) == 0 {
		return nil
	}
	var format chatResponseFormat
	if err := decodeStrictJSON(raw, &format); err != nil {
		return fmt.Errorf("decode response_format: %w", err)
	}
	switch format.Type {
	case "text":
		if format.JSONSchema != nil {
			return errors.New("response_format text contains json_schema")
		}
		return nil
	case "json_object":
		if format.JSONSchema != nil {
			return errors.New("response_format json_object contains json_schema")
		}
		return nil
	case "json_schema":
		if format.JSONSchema == nil || len(format.JSONSchema.Schema) == 0 {
			return errors.New("response_format json_schema is incomplete")
		}
		if err := validateChatIdentifier(format.JSONSchema.Name, 64); err != nil {
			return errors.New("response_format json_schema name is invalid")
		}
		if err := validateBoundedString(format.JSONSchema.Description, maxChatStringBytes); err != nil {
			return errors.New("response_format json_schema description is invalid")
		}
		if err := validateJSONObject(format.JSONSchema.Schema, maxChatSchemaBytes); err != nil {
			return fmt.Errorf("response_format json_schema schema is invalid: %w", err)
		}
		return nil
	default:
		return errors.New("response_format type is invalid")
	}
}

func validateChatTool(tool chatTool) error {
	if tool.Type != "function" {
		return fmt.Errorf("%w: tool type", errChatUnsupported)
	}
	if err := validateChatIdentifier(tool.Function.Name, 64); err != nil {
		return errors.New("tool function name is invalid")
	}
	if err := validateBoundedString(tool.Function.Description, maxChatStringBytes); err != nil {
		return errors.New("tool description is invalid")
	}
	if len(tool.Function.Parameters) != 0 {
		if err := validateJSONObject(tool.Function.Parameters, maxChatSchemaBytes); err != nil {
			return fmt.Errorf("tool parameters are invalid: %w", err)
		}
	}
	return nil
}

func validateChatToolChoice(raw json.RawMessage) error {
	if len(raw) == 0 {
		return nil
	}
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return errors.New("tool_choice is invalid")
	}
	if trimmed[0] == '"' {
		var choice string
		if err := json.Unmarshal(trimmed, &choice); err != nil {
			return errors.New("tool_choice is invalid")
		}
		switch choice {
		case "none", "auto", "required":
			return nil
		default:
			return errors.New("tool_choice is invalid")
		}
	}
	var choice chatNamedToolChoice
	if err := decodeStrictJSON(trimmed, &choice); err != nil {
		return fmt.Errorf("decode tool_choice: %w", err)
	}
	if choice.Type != "function" || validateChatIdentifier(choice.Function.Name, 64) != nil {
		return errors.New("tool_choice is invalid")
	}
	return nil
}

func validateChatMessage(message chatMessage) error {
	if len(message.Refusal) != 0 || len(message.Audio) != 0 || len(message.FunctionCall) != 0 {
		return fmt.Errorf("%w: assistant message field", errChatUnsupported)
	}
	if err := validateBoundedString(message.Name, maxChatStringBytes); err != nil {
		return errors.New("message name is invalid")
	}
	if len(message.ToolCalls) > maxChatToolCalls {
		return errors.New("too many tool calls")
	}
	for index := range message.ToolCalls {
		call := message.ToolCalls[index]
		if call.Type != "function" {
			return fmt.Errorf("%w: tool call type", errChatUnsupported)
		}
		if err := validateBoundedString(call.ID, 256); err != nil {
			return errors.New("tool call identity is invalid")
		}
		if err := validateChatIdentifier(call.Function.Name, 64); err != nil {
			return errors.New("tool call identity is invalid")
		}
		if err := validateBoundedString(call.Function.Arguments, maxChatArgumentsBytes); err != nil || validateChatJSONValue([]byte(call.Function.Arguments), maxChatArgumentsBytes) != nil {
			return errors.New("tool call arguments are invalid")
		}
	}
	_, present, err := parseChatTextContent(message.Content)
	if err != nil {
		return err
	}
	switch message.Role {
	case "developer", "system", "user":
		if message.ToolCallID != "" {
			return errors.New("tool call id is only valid on tool messages")
		}
		if !present {
			return errors.New("message content is required")
		}
		if len(message.ToolCalls) != 0 {
			return errors.New("tool calls are only valid on assistant messages")
		}
	case "assistant":
		if message.ToolCallID != "" {
			return errors.New("tool call id is only valid on tool messages")
		}
		if !present && len(message.ToolCalls) == 0 {
			return errors.New("assistant message must contain content or tool calls")
		}
	case "tool":
		if !present || len(message.ToolCalls) != 0 || message.ToolCallID == "" {
			return errors.New("tool message is invalid")
		}
		if err := validateBoundedString(message.ToolCallID, 256); err != nil {
			return errors.New("tool call id is invalid")
		}
	default:
		return fmt.Errorf("message role %q is unsupported", message.Role)
	}
	return nil
}

func privateChatRequest(request chatCompletionRequest) (codex.CodexResponseRequest, error) {
	privateRequest := codex.CodexResponseRequest{Model: request.Model, Stream: true}
	if request.MaxCompletionTokens != nil {
		privateRequest.MaxCompletionTokens = *request.MaxCompletionTokens
	}
	privateRequest.Input = &codex.CodexInput{Items: make([]codex.CodexInputItem, 0, len(request.Messages))}
	for index := range request.Messages {
		items, err := privateChatMessageItems(request.Messages[index])
		if err != nil {
			return codex.CodexResponseRequest{}, fmt.Errorf("message %d: %w", index, err)
		}
		privateRequest.Input.Items = append(privateRequest.Input.Items, items...)
	}
	var err error
	privateRequest.Tools, err = privateChatTools(request.Tools)
	if err != nil {
		return codex.CodexResponseRequest{}, err
	}
	privateRequest.ToolChoice, err = privateChatToolChoice(request.ToolChoice)
	if err != nil {
		return codex.CodexResponseRequest{}, err
	}
	privateRequest.Text, err = privateChatText(request.ResponseFormat)
	if err != nil {
		return codex.CodexResponseRequest{}, err
	}
	return privateRequest, nil
}

func privateChatMessageItems(message chatMessage) ([]codex.CodexInputItem, error) {
	texts, present, err := parseChatTextContent(message.Content)
	if err != nil {
		return nil, err
	}
	if message.Name != "" {
		return nil, fmt.Errorf("%w: message name", errChatUnsupported)
	}
	items := make([]codex.CodexInputItem, 0, 1+len(message.ToolCalls))
	switch message.Role {
	case "developer", "system", "user", "assistant":
		if present {
			content, err := json.Marshal(chatInputContent(texts))
			if err != nil {
				return nil, fmt.Errorf("encode message content: %w", err)
			}
			items = append(items, codex.CodexInputItem{Type: "message", Role: message.Role, Content: content})
		}
	case "tool":
		output, err := json.Marshal(strings.Join(texts, ""))
		if err != nil {
			return nil, fmt.Errorf("encode tool output: %w", err)
		}
		items = append(items, codex.CodexInputItem{Type: "function_call_output", CallID: message.ToolCallID, Output: output})
	default:
		return nil, errors.New("message role is invalid")
	}
	if message.Role == "assistant" {
		for _, call := range message.ToolCalls {
			arguments, err := json.Marshal(call.Function.Arguments)
			if err != nil {
				return nil, fmt.Errorf("encode tool call arguments: %w", err)
			}
			items = append(items, codex.CodexInputItem{Type: "function_call", CallID: call.ID, Name: call.Function.Name, Arguments: arguments})
		}
	}
	return items, nil
}

func chatInputContent(texts []string) []codex.CodexInputContent {
	content := make([]codex.CodexInputContent, 0, len(texts))
	for _, text := range texts {
		content = append(content, codex.CodexInputContent{Type: "input_text", Text: text})
	}
	return content
}

func privateChatTools(tools []chatTool) ([]codex.CodexTool, error) {
	if tools == nil {
		return nil, nil
	}
	result := make([]codex.CodexTool, 0, len(tools))
	for index, tool := range tools {
		if err := validateChatTool(tool); err != nil {
			return nil, fmt.Errorf("tool %d: %w", index, err)
		}
		result = append(result, codex.CodexTool{Type: "function", Name: tool.Function.Name, Description: tool.Function.Description, Strict: tool.Function.Strict, Parameters: tool.Function.Parameters})
	}
	return result, nil
}

func privateChatToolChoice(raw json.RawMessage) (*codex.CodexToolChoice, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	trimmed := bytes.TrimSpace(raw)
	if trimmed[0] == '"' {
		var value string
		if err := json.Unmarshal(trimmed, &value); err != nil {
			return nil, errors.New("tool_choice is invalid")
		}
		return &codex.CodexToolChoice{String: &value}, nil
	}
	var named chatNamedToolChoice
	if err := decodeStrictJSON(trimmed, &named); err != nil {
		return nil, fmt.Errorf("decode tool_choice: %w", err)
	}
	return &codex.CodexToolChoice{Type: named.Type, Name: named.Function.Name}, nil
}
func privateChatText(raw json.RawMessage) (*codex.CodexTextConfig, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	var format chatResponseFormat
	if err := decodeStrictJSON(raw, &format); err != nil {
		return nil, fmt.Errorf("decode response_format: %w", err)
	}
	result := &codex.CodexTextConfig{Format: &codex.CodexTextFormat{Type: format.Type}}
	if format.Type == "json_schema" {
		if format.JSONSchema == nil {
			return nil, errors.New("response_format json_schema is incomplete")
		}
		result.Format.Name = format.JSONSchema.Name
		result.Format.Description = format.JSONSchema.Description
		result.Format.Schema = format.JSONSchema.Schema
		result.Format.Strict = format.JSONSchema.Strict
	}
	return result, nil
}

func parseChatTextContent(raw json.RawMessage) ([]string, bool, error) {
	if len(raw) == 0 {
		return nil, false, nil
	}
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return nil, false, errors.New("message content is invalid")
	}
	if bytes.Equal(trimmed, []byte("null")) {
		return nil, false, nil
	}
	if trimmed[0] == '"' {
		var text string
		if err := json.Unmarshal(trimmed, &text); err != nil {
			return nil, false, errors.New("message content is invalid")
		}
		if err := validateBoundedString(text, maxChatStringBytes); err != nil {
			return nil, false, errors.New("message content is too large")
		}
		return []string{text}, true, nil
	}
	if trimmed[0] != '[' {
		return nil, false, errors.New("message content must be a string or text array")
	}
	decoder := json.NewDecoder(bytes.NewReader(trimmed))
	decoder.DisallowUnknownFields()
	token, err := decoder.Token()
	if err != nil || token != json.Delim('[') {
		return nil, false, errors.New("message content is invalid")
	}
	texts := make([]string, 0)
	for decoder.More() {
		if len(texts) >= maxChatContentParts {
			return nil, false, errors.New("message content has too many parts")
		}
		var part chatTextPart
		if err := decoder.Decode(&part); err != nil {
			return nil, false, errors.New("message content part is invalid")
		}
		if part.Type != "text" {
			return nil, false, fmt.Errorf("%w: content type", errChatUnsupported)
		}
		if err := validateBoundedString(part.Text, maxChatStringBytes); err != nil {
			return nil, false, errors.New("message content part is too large")
		}
		texts = append(texts, part.Text)
	}
	if _, err := decoder.Token(); err != nil {
		return nil, false, errors.New("message content is invalid")
	}
	var extra json.RawMessage
	if err := decoder.Decode(&extra); err != io.EOF {
		return nil, false, errors.New("message content has multiple values")
	}
	return texts, true, nil
}

func decodeStrictJSON(data []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var extra json.RawMessage
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return errors.New("multiple JSON values")
		}
		return err
	}
	return nil
}

func validateBoundedString(value string, maxBytes int) error {
	if len(value) > maxBytes || !utf8.ValidString(value) {
		return errors.New("string is invalid")
	}
	return nil
}
func validateChatIdentifier(value string, maxBytes int) error {
	if err := validateBoundedString(value, maxBytes); err != nil || value == "" {
		return errors.New("identifier is invalid")
	}
	for index := range value {
		character := value[index]
		if (character < 'a' || character > 'z') &&
			(character < 'A' || character > 'Z') &&
			(character < '0' || character > '9') &&
			character != '_' && character != '-' {
			return errors.New("identifier is invalid")
		}
	}
	return nil
}

func validateChatJSONValue(raw []byte, maxBytes int) error {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || len(trimmed) > maxBytes || !json.Valid(trimmed) {
		return errors.New("invalid JSON value")
	}
	decoder := json.NewDecoder(bytes.NewReader(trimmed))
	members := 0
	if err := walkChatJSON(decoder, 0, &members); err != nil {
		return err
	}
	var extra json.RawMessage
	if err := decoder.Decode(&extra); err != io.EOF {
		return errors.New("multiple JSON values")
	}
	return nil
}

func validateJSONObject(raw []byte, maxBytes int) error {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || len(trimmed) > maxBytes || trimmed[0] != '{' {
		return errors.New("expected a JSON object")
	}
	if err := validateChatJSONValue(trimmed, maxBytes); err != nil {
		return err
	}
	return nil
}

func walkChatJSON(decoder *json.Decoder, depth int, members *int) error {
	if depth > maxChatJSONDepth {
		return errors.New("JSON nesting is too deep")
	}
	token, err := decoder.Token()
	if err != nil {
		return errors.New("invalid JSON value")
	}
	switch value := token.(type) {
	case json.Delim:
		switch value {
		case '{':
			for decoder.More() {
				if _, err := decoder.Token(); err != nil {
					return errors.New("invalid JSON object")
				}
				(*members)++
				if *members > maxChatJSONMembers {
					return errors.New("JSON object has too many members")
				}
				if err := walkChatJSON(decoder, depth+1, members); err != nil {
					return err
				}
			}
			if _, err := decoder.Token(); err != nil {
				return errors.New("invalid JSON object")
			}
		case '[':
			for decoder.More() {
				if err := walkChatJSON(decoder, depth+1, members); err != nil {
					return err
				}
			}
			if _, err := decoder.Token(); err != nil {
				return errors.New("invalid JSON array")
			}
		default:
			return errors.New("invalid JSON delimiter")
		}
	}
	return nil
}

type chatIdentity struct {
	id      string
	model   string
	created int64
}

func newChatIdentity(response *codex.CodexResponse, model string) chatIdentity {
	identity := chatIdentity{id: fmt.Sprintf("chatcmpl-%d", time.Now().UnixNano()), model: model, created: time.Now().Unix()}
	if response != nil {
		if response.ID != "" {
			identity.id = response.ID
		}
		if response.Model != "" {
			identity.model = response.Model
		}
		if response.CreatedAt > 0 {
			identity.created = response.CreatedAt
		}
	}
	return identity
}

type chatCompletionResponse struct {
	ID      string                 `json:"id"`
	Object  string                 `json:"object"`
	Created int64                  `json:"created"`
	Model   string                 `json:"model"`
	Choices []chatCompletionChoice `json:"choices"`
	Usage   chatCompletionUsage    `json:"usage"`
}

type chatCompletionChoice struct {
	Index        int64                 `json:"index"`
	Message      chatCompletionMessage `json:"message"`
	FinishReason string                `json:"finish_reason"`
	Logprobs     any                   `json:"logprobs"`
}

type chatCompletionMessage struct {
	Role      string            `json:"role"`
	Content   *string           `json:"content"`
	ToolCalls []chatToolCallOut `json:"tool_calls,omitempty"`
}

type chatToolCallOut struct {
	ID       string                  `json:"id"`
	Type     string                  `json:"type"`
	Function chatToolCallFunctionOut `json:"function"`
}

type chatToolCallFunctionOut struct {
	Name      string `json:"name"`
	Arguments string `json:"arguments"`
}

type chatCompletionUsage struct {
	PromptTokens            int64                       `json:"prompt_tokens"`
	CompletionTokens        int64                       `json:"completion_tokens"`
	TotalTokens             int64                       `json:"total_tokens"`
	PromptTokensDetails     chatPromptTokensDetails     `json:"prompt_tokens_details"`
	CompletionTokensDetails chatCompletionTokensDetails `json:"completion_tokens_details"`
	CachedTokensKnown       bool                        `json:"-"`
	ReasoningTokensKnown    bool                        `json:"-"`
}

type chatPromptTokensDetails struct {
	CachedTokens int64 `json:"cached_tokens"`
	AudioTokens  int64 `json:"audio_tokens"`
}

type chatCompletionTokensDetails struct {
	ReasoningTokens          int64 `json:"reasoning_tokens"`
	AudioTokens              int64 `json:"audio_tokens"`
	AcceptedPredictionTokens int64 `json:"accepted_prediction_tokens"`
	RejectedPredictionTokens int64 `json:"rejected_prediction_tokens"`
}

type chatCompletionChunk struct {
	ID      string               `json:"id"`
	Object  string               `json:"object"`
	Created int64                `json:"created"`
	Model   string               `json:"model"`
	Choices []chatChunkChoice    `json:"choices"`
	Usage   *chatCompletionUsage `json:"usage"`
}

type chatChunkChoice struct {
	Index        int64          `json:"index"`
	Delta        chatChunkDelta `json:"delta"`
	FinishReason *string        `json:"finish_reason"`
	Logprobs     any            `json:"logprobs"`
}

type chatChunkDelta struct {
	Role      string          `json:"role,omitempty"`
	Content   *string         `json:"content"`
	ToolCalls []chatToolDelta `json:"tool_calls,omitempty"`
}

type chatToolDelta struct {
	Index    int64                 `json:"index"`
	ID       string                `json:"id,omitempty"`
	Type     string                `json:"type,omitempty"`
	Function chatToolDeltaFunction `json:"function"`
}

type chatToolDeltaFunction struct {
	Name      string `json:"name,omitempty"`
	Arguments string `json:"arguments,omitempty"`
}

func chatCompletionPayload(response *codex.CodexResponse, model string) ([]byte, error) {
	if response == nil || response.Status == codex.CodexResponseStatusFailed || response.Error != nil {
		return nil, errors.New("upstream response failed")
	}
	text, tools, err := chatResponseOutput(response)
	if err != nil {
		return nil, err
	}
	content := text
	usage, err := chatResponseUsage(response.Usage)
	if err != nil {
		return nil, err
	}
	identity := newChatIdentity(response, model)
	message := chatCompletionMessage{Role: "assistant", Content: &content}
	if text == "" && len(tools) > 0 {
		message.Content = nil
	}
	if len(tools) > 0 {
		message.ToolCalls = tools
	}
	result := chatCompletionResponse{
		ID: identity.id, Object: "chat.completion", Created: identity.created, Model: identity.model,
		Choices: []chatCompletionChoice{{Index: 0, Message: message, FinishReason: chatFinishReason(response, len(tools)), Logprobs: nil}},
		Usage:   usage,
	}
	return json.Marshal(result)
}

func chatResponseOutput(response *codex.CodexResponse) (string, []chatToolCallOut, error) {
	var text string
	tools := make([]chatToolCallOut, 0)
	for _, item := range response.Output {
		switch item.Type {
		case "message":
			if item.Role != "" && item.Role != "assistant" {
				return "", nil, errors.New("upstream message role is invalid")
			}
			for _, part := range item.Content {
				switch part.Type {
				case "output_text":
					if len(part.Annotations) != 0 {
						return "", nil, errors.New("upstream output annotations are not representable")
					}
					if err := appendBoundedChatText(&text, part.Text); err != nil {
						return "", nil, err
					}
				case "refusal":
					return "", nil, errors.New("upstream refusal is not representable")
				default:
					return "", nil, errors.New("upstream output content is not representable")
				}
			}
		case "reasoning":
			continue
		case "function_call":
			tool, err := chatOutputTool(item)
			if err != nil {
				return "", nil, err
			}
			tools = append(tools, tool)
		default:
			return "", nil, errors.New("upstream output item is not representable")
		}
	}
	if text == "" && response.OutputText != "" {
		text = response.OutputText
	}
	if err := validateBoundedString(text, maxChatStringBytes); err != nil {
		return "", nil, errors.New("upstream text is too large")
	}
	return text, tools, nil
}

func appendBoundedChatText(target *string, value string) error {
	if len(value) > maxChatStringBytes || len(*target) > maxChatStringBytes-len(value) {
		return errors.New("upstream text is too large")
	}
	*target += value
	return nil
}

func chatOutputTool(item codex.CodexOutputItem) (chatToolCallOut, error) {
	id := item.CallID
	if id == "" {
		id = item.ID
	}
	if id == "" || validateChatIdentifier(item.Name, 64) != nil || len(item.Arguments) > maxChatArgumentsBytes || validateChatJSONValue([]byte(item.Arguments), maxChatArgumentsBytes) != nil {
		return chatToolCallOut{}, errors.New("upstream tool call is invalid")
	}
	return chatToolCallOut{ID: id, Type: "function", Function: chatToolCallFunctionOut{Name: item.Name, Arguments: item.Arguments}}, nil
}

func chatFinishReason(response *codex.CodexResponse, toolCount int) string {
	if response != nil && response.Status == codex.CodexResponseStatusIncomplete && response.IncompleteDetails != nil {
		switch response.IncompleteDetails.Reason {
		case codex.CodexIncompleteReasonMaxOutputTokens:
			return "length"
		case codex.CodexIncompleteReasonContentFilter:
			return "content_filter"
		}
	}
	if toolCount > 0 {
		return "tool_calls"
	}
	return "stop"
}

func journalUsageFromChatUsage(usage chatCompletionUsage) JournalUsage {
	result := JournalUsage{
		InputTokens:            usage.PromptTokens,
		CachedInputTokens:      usage.PromptTokensDetails.CachedTokens,
		CachedInputTokensKnown: usage.CachedTokensKnown,
		OutputTokens:           usage.CompletionTokens,
		ReasoningTokens:        usage.CompletionTokensDetails.ReasoningTokens,
		ReasoningTokensKnown:   usage.ReasoningTokensKnown,
		TotalTokens:            usage.TotalTokens,
	}
	return result
}

func chatResponseUsage(usage *codex.CodexUsage) (chatCompletionUsage, error) {
	result := chatCompletionUsage{}
	if usage == nil {
		return result, nil
	}
	if usage.InputTokens < 0 || usage.OutputTokens < 0 || usage.TotalTokens < 0 || usage.PromptCacheHitTokens < 0 {
		return result, errors.New("upstream usage is invalid")
	}
	result.PromptTokens = int64(usage.InputTokens)
	result.CompletionTokens = int64(usage.OutputTokens)
	result.TotalTokens = int64(usage.TotalTokens)
	if result.TotalTokens == 0 {
		if result.PromptTokens > math.MaxInt64-result.CompletionTokens {
			return result, errors.New("upstream usage is invalid")
		}
		result.TotalTokens = result.PromptTokens + result.CompletionTokens
	}
	result.PromptTokensDetails.CachedTokens = int64(usage.PromptCacheHitTokens)
	result.CachedTokensKnown = usage.PromptCacheHitTokens > 0
	if usage.InputTokensDetails != nil {
		if usage.InputTokensDetails.CachedTokens < 0 || usage.InputTokensDetails.ImageTokens < 0 || usage.InputTokensDetails.TextTokens < 0 {
			return result, errors.New("upstream usage is invalid")
		}
		result.PromptTokensDetails.CachedTokens = int64(usage.InputTokensDetails.CachedTokens)
		result.CachedTokensKnown = true
	}
	if usage.OutputTokensDetails != nil {
		if usage.OutputTokensDetails.ReasoningTokens < 0 || usage.OutputTokensDetails.ImageTokens < 0 || usage.OutputTokensDetails.TextTokens < 0 {
			return result, errors.New("upstream usage is invalid")
		}
		result.CompletionTokensDetails.ReasoningTokens = int64(usage.OutputTokensDetails.ReasoningTokens)
		result.ReasoningTokensKnown = true
	}
	return result, nil
}

func serveChatStream(ctx iris.Context, requestContext context.Context, transport *codex.ResponsesTransport, privateRequest codex.CodexResponseRequest, model string, includeUsage bool, lease *quotaLease) {
	var writer http.ResponseWriter = ctx.ResponseWriter()
	baseWriter := writer
	writer.Header().Set("Content-Type", "text/event-stream")
	writer.Header().Set("Cache-Control", "no-cache")
	writer.Header().Set("Connection", "keep-alive")
	writer.Header().Set("X-Accel-Buffering", "no")
	flusher, ok := writer.(http.Flusher)
	if !ok {
		markJournalTerminal(ctx, requestStatusFailed, "")
		return
	}
	baseFlusher := flusher
	writer.WriteHeader(http.StatusOK)
	flusher.Flush()
	if err := http.NewResponseController(ctx.ResponseWriter().Naive()).SetWriteDeadline(time.Time{}); err != nil {
		markJournalTerminal(ctx, requestStatusFailed, "")
		return
	}
	var journalWriter *journalSSEWriter
	if wrapped, journalFlusher := newJournalSSEWriter(ctx, writer); wrapped != nil {
		journalWriter = wrapped
		writer = wrapped
		flusher = journalFlusher
	}
	reportJournalFailure := func() bool {
		if journalWriter == nil || journalWriter.failed == nil {
			return false
		}
		markJournalTerminalValue(journalWriter.value, requestStatusFailed, "")
		journalWriter.value.journal.recordError(journalWriter.failed)
		payload, err := json.Marshal(openai.ErrorResponse{Error: openai.Error{Type: responsesServerErrorType, Code: "internal_error", Message: "Internal server error."}})
		if err == nil {
			writeJournalSSEFailure(baseWriter, baseFlusher, payload)
		}
		return true
	}

	state := newChatStreamState(model, includeUsage, writer, flusher)
	state.lease = lease
	streamErr := transport.Stream(requestContext, privateRequest, state.event)
	if requestContext.Err() != nil {
		return
	}
	if reportJournalFailure() {
		return
	}
	if state.writeErr != nil {
		return
	}
	if state.failure != nil || streamErr != nil || !state.finishSent {
		err := state.failure
		if err == nil {
			err = streamErr
		}
		if err == nil {
			err = errors.New("upstream stream ended without a terminal event")
		}
		if writeErr := state.writeError(err); writeErr != nil && reportJournalFailure() {
			return
		}
		if writeErr := writeResponsesSSERecord(writer, flusher, []byte("[DONE]")); writeErr != nil && reportJournalFailure() {
			return
		}
		return
	}
	if state.mappedUsage != nil {
		journalUsage := journalUsageFromChatUsage(*state.mappedUsage)
		if state.response != nil {
			journalUsage.ResolvedModel = state.response.Model
		}
		recordJournalUsageDetails(ctx, journalUsage)
	}
	if includeUsage {
		usage := *state.mappedUsage
		if err := state.writeChunk(chatCompletionChunk{ID: state.identity.id, Object: "chat.completion.chunk", Created: state.identity.created, Model: state.identity.model, Choices: []chatChunkChoice{}, Usage: &usage}); err != nil {
			reportJournalFailure()
			return
		}
	}
	if err := writeResponsesSSERecord(writer, flusher, []byte("[DONE]")); err != nil {
		reportJournalFailure()
		return
	}
}

type chatToolStreamState struct {
	index        int
	id           string
	name         string
	arguments    strings.Builder
	emittedBytes int
	metadataSent bool
	final        bool
}

type chatStreamState struct {
	identity     chatIdentity
	includeUsage bool
	writer       http.ResponseWriter
	flusher      http.Flusher
	lease        *quotaLease
	quotaFailure bool
	roleSent     bool
	finishSent   bool
	text         string
	mappedUsage  *chatCompletionUsage
	response     *codex.CodexResponse
	failure      error
	writeErr     error
	tools        []*chatToolStreamState
	aliases      map[string]*chatToolStreamState
}

func newChatStreamState(model string, includeUsage bool, writer http.ResponseWriter, flusher http.Flusher) *chatStreamState {
	return &chatStreamState{
		identity:     newChatIdentity(nil, model),
		includeUsage: includeUsage,
		writer:       writer,
		flusher:      flusher,
		aliases:      make(map[string]*chatToolStreamState),
	}
}

func (state *chatStreamState) fail(err error) error {
	if err == nil {
		err = errors.New("upstream stream event is invalid")
	}
	state.failure = fmt.Errorf("%w: %v", errChatStreamAbort, err)
	return errChatStreamAbort
}

func (state *chatStreamState) event(event codex.CodexResponseStreamEvent) error {
	if state.failure != nil {
		return errChatStreamAbort
	}
	if event.Response != nil {
		state.response = event.Response
		if !state.roleSent {
			if event.Response.ID != "" {
				state.identity.id = event.Response.ID
			}
			if event.Response.Model != "" {
				state.identity.model = event.Response.Model
			}
			if event.Response.CreatedAt > 0 {
				state.identity.created = event.Response.CreatedAt
			}
		}
	}
	if event.Error != nil || event.Type == codex.CodexEventError ||
		event.Type == codex.CodexEventResponseFailed ||
		(event.Response != nil && (event.Response.Error != nil || event.Response.Status == codex.CodexResponseStatusFailed)) {
		state.failure = errors.New("upstream stream failed")
		return nil
	}
	if isCodexTerminal(event.Type) {
		if event.Response == nil && event.Type != codex.CodexEventError {
			return state.fail(errors.New("terminal response is missing"))
		}
		if event.Response == nil {
			return state.fail(errors.New("terminal response is missing"))
		}
		if err := state.validateResponse(event.Response); err != nil {
			return state.fail(err)
		}
		if state.includeUsage {
			if state.lease == nil && event.Response.Usage == nil {
				return state.fail(errors.New("upstream usage is missing"))
			}
			usage, err := chatResponseUsage(event.Response.Usage)
			if err != nil {
				return state.fail(err)
			}
			state.mappedUsage = &usage
		}
		if err := validateQuotaUsageFromCodex(event.Response.Usage); err != nil {
			return state.fail(err)
		}
		usage := quotaUsageFromCodex(event.Response.Usage, 0)
		if err := state.lease.reconcile(usage); err != nil {
			state.quotaFailure = true
			return state.fail(errQuotaFinalization)
		}
		if err := state.writeRole(); err != nil {
			state.writeErr = err
			return err
		}
		if err := state.reconcileResponse(event.Response); err != nil {
			return state.fail(err)
		}
		if err := state.finish(event.Response); err != nil {
			return state.fail(err)
		}
		return nil
	}

	switch event.Type {
	case codex.CodexEventResponseCreated, "response.queued", "response.in_progress",
		codex.CodexEventResponseMetadata, "response.rate_limits.updated",
		"response.reasoning_summary_part.added", "response.reasoning_summary_part.done",
		"response.reasoning_summary_text.delta", "response.reasoning_summary_text.done":
		return nil
	case codex.CodexEventResponseOutputTextDelta:
		if event.Annotation != nil {
			return state.fail(errors.New("upstream output annotations are not representable"))
		}
		if event.Part != nil {
			if _, err := chatStreamPartText(event.Part); err != nil {
				return state.fail(err)
			}
		}
		if err := state.writeRole(); err != nil {
			state.writeErr = err
			return err
		}
		if event.Delta != "" {
			if err := state.writeText(event.Delta); err != nil {
				state.writeErr = err
				return err
			}
		}
	case "response.output_text.done":
		if event.Annotation != nil {
			return state.fail(errors.New("upstream output annotations are not representable"))
		}
		if err := state.writeRole(); err != nil {
			state.writeErr = err
			return err
		}
		if event.Text != "" {
			if err := state.reconcileText(event.Text); err != nil {
				return state.fail(err)
			}
		}
	case codex.CodexEventResponseContentPartAdded, "response.content_part.done":
		text, err := chatStreamPartText(event.Part)
		if err != nil {
			return state.fail(err)
		}
		if err := state.writeRole(); err != nil {
			state.writeErr = err
			return err
		}
		if text != "" {
			if err := state.reconcileText(text); err != nil {
				return state.fail(err)
			}
		}
	case codex.CodexEventResponseOutputItemAdded, codex.CodexEventResponseOutputItemDone:
		if event.Item == nil {
			return state.fail(errors.New("upstream output item is missing"))
		}
		switch event.Item.Type {
		case "reasoning":
			return nil
		case "message":
			text, err := chatStreamMessageText(event.Item)
			if err != nil {
				return state.fail(err)
			}
			if err := state.writeRole(); err != nil {
				state.writeErr = err
				return err
			}
			if text != "" {
				if err := state.reconcileText(text); err != nil {
					return state.fail(err)
				}
			}
		case "function_call":
			if err := state.writeRole(); err != nil {
				state.writeErr = err
				return err
			}
			tool := state.tool(event.Item.ID, event.Item.CallID, event.Item.Name)
			if err := state.writeToolMetadata(tool); err != nil {
				state.writeErr = err
				return err
			}
			if event.Item.Arguments != "" {
				if err := state.addToolArguments(tool, event.Item.Arguments, true); err != nil {
					return state.fail(err)
				}
			}
		default:
			return state.fail(errors.New("upstream output item is not representable"))
		}
	case codex.CodexEventResponseFunctionArgsDelta:
		if err := state.writeRole(); err != nil {
			state.writeErr = err
			return err
		}
		fragment := event.Delta
		if fragment == "" {
			fragment = event.Arguments
		}
		tool := state.tool(event.ItemID, "", "")
		if err := state.addToolArguments(tool, fragment, false); err != nil {
			return state.fail(err)
		}
	case codex.CodexEventResponseFunctionArgsDone:
		if err := state.writeRole(); err != nil {
			state.writeErr = err
			return err
		}
		tool := state.tool(event.ItemID, "", "")
		if err := state.addToolArguments(tool, event.Arguments, true); err != nil {
			return state.fail(err)
		}
	default:
		return state.fail(fmt.Errorf("upstream stream event %q is not representable", event.Type))
	}
	return nil
}

func chatStreamPartText(part *codex.CodexContentPart) (string, error) {
	if part == nil {
		return "", errors.New("upstream content part is missing")
	}
	if part.Type != "output_text" {
		return "", errors.New("upstream output content is not representable")
	}
	if len(part.Annotations) != 0 {
		return "", errors.New("upstream output annotations are not representable")
	}
	if err := validateBoundedString(part.Text, maxChatStringBytes); err != nil {
		return "", errors.New("upstream text is too large")
	}
	return part.Text, nil
}

func chatStreamMessageText(item *codex.CodexOutputItem) (string, error) {
	if item.Role != "" && item.Role != "assistant" {
		return "", errors.New("upstream message role is invalid")
	}
	var text string
	for index := range item.Content {
		partText, err := chatStreamPartText(&item.Content[index])
		if err != nil {
			return "", err
		}
		if err := appendBoundedChatText(&text, partText); err != nil {
			return "", err
		}
	}
	return text, nil
}
func (state *chatStreamState) writeRole() error {
	if state.roleSent {
		return nil
	}
	state.roleSent = true
	return state.writeChunk(chatCompletionChunk{ID: state.identity.id, Object: "chat.completion.chunk", Created: state.identity.created, Model: state.identity.model, Choices: []chatChunkChoice{{Index: 0, Delta: chatChunkDelta{Role: "assistant", Content: nil}, FinishReason: nil, Logprobs: nil}}, Usage: nil})
}

func (state *chatStreamState) writeText(text string) error {
	if text == "" {
		return nil
	}
	if len(text) > maxChatStringBytes || len(state.text) > maxChatStringBytes-len(text) {
		return errors.New("upstream text is too large")
	}
	value := text
	if err := state.writeChunk(chatCompletionChunk{ID: state.identity.id, Object: "chat.completion.chunk", Created: state.identity.created, Model: state.identity.model, Choices: []chatChunkChoice{{Index: 0, Delta: chatChunkDelta{Content: &value}, FinishReason: nil, Logprobs: nil}}, Usage: nil}); err != nil {
		return err
	}
	state.text += text
	return nil
}

func (state *chatStreamState) tool(itemID, callID, name string) *chatToolStreamState {
	if itemID != "" {
		if tool := state.aliases[itemID]; tool != nil {
			if callID != "" {
				state.aliases[callID] = tool
			}
			if name != "" {
				tool.name = name
			}
			if tool.id == "" {
				if callID != "" {
					tool.id = callID
				} else {
					tool.id = itemID
				}
			}
			return tool
		}
	}
	if callID != "" {
		if tool := state.aliases[callID]; tool != nil {
			if itemID != "" {
				state.aliases[itemID] = tool
			}
			if name != "" {
				tool.name = name
			}
			return tool
		}
	}
	if itemID == "" && callID == "" && len(state.tools) == 1 {
		tool := state.tools[0]
		if name != "" {
			tool.name = name
		}
		return tool
	}
	id := callID
	if id == "" {
		id = itemID
	}
	tool := &chatToolStreamState{index: len(state.tools), id: id, name: name}
	state.tools = append(state.tools, tool)
	if itemID != "" {
		state.aliases[itemID] = tool
	}
	if callID != "" {
		state.aliases[callID] = tool
	}
	return tool
}
func (state *chatStreamState) outputTool(id, name string) *chatToolStreamState {
	for _, tool := range state.tools {
		if id != "" && tool.id == id {
			return tool
		}
	}
	if name != "" {
		for _, tool := range state.tools {
			if tool.name == name && !tool.final {
				return tool
			}
		}
	}
	return state.tool(id, id, name)
}

func (state *chatStreamState) writeToolMetadata(tool *chatToolStreamState) error {
	if tool.metadataSent {
		return nil
	}
	if tool.id == "" || tool.name == "" {
		return nil
	}
	if validateChatIdentifier(tool.name, 64) != nil {
		return errors.New("upstream tool name is invalid")
	}
	tool.metadataSent = true
	chunk := chatCompletionChunk{ID: state.identity.id, Object: "chat.completion.chunk", Created: state.identity.created, Model: state.identity.model, Choices: []chatChunkChoice{{Index: 0, Delta: chatChunkDelta{ToolCalls: []chatToolDelta{{Index: int64(tool.index), ID: tool.id, Type: "function", Function: chatToolDeltaFunction{Name: tool.name}}}}, FinishReason: nil, Logprobs: nil}}, Usage: nil}
	if err := state.writeChunk(chunk); err != nil {
		return err
	}
	return state.writeToolArgumentSuffix(tool)
}

func (state *chatStreamState) writeToolArgumentSuffix(tool *chatToolStreamState) error {
	arguments := tool.arguments.String()
	if len(arguments) <= tool.emittedBytes {
		return nil
	}
	fragment := arguments[tool.emittedBytes:]
	tool.emittedBytes = len(arguments)
	return state.writeChunk(chatCompletionChunk{ID: state.identity.id, Object: "chat.completion.chunk", Created: state.identity.created, Model: state.identity.model, Choices: []chatChunkChoice{{Index: 0, Delta: chatChunkDelta{ToolCalls: []chatToolDelta{{Index: int64(tool.index), Function: chatToolDeltaFunction{Arguments: fragment}}}}, FinishReason: nil, Logprobs: nil}}, Usage: nil})
}

func (state *chatStreamState) addToolArguments(tool *chatToolStreamState, fragment string, final bool) error {
	if tool.final {
		if fragment == "" || tool.arguments.String() == fragment {
			return nil
		}
		return errors.New("upstream tool arguments were duplicated")
	}
	if len(fragment) > maxChatArgumentsBytes || tool.arguments.Len() > maxChatArgumentsBytes-len(fragment) {
		return errors.New("upstream tool arguments are too large")
	}
	if final && fragment != "" {
		current := tool.arguments.String()
		switch {
		case current == "":
			tool.arguments.WriteString(fragment)
		case current == fragment:
		case strings.HasPrefix(fragment, current):
			tool.arguments.WriteString(fragment[len(current):])
		default:
			return errors.New("upstream tool arguments were inconsistent")
		}
	} else if fragment != "" {
		tool.arguments.WriteString(fragment)
	}
	if tool.metadataSent {
		if err := state.writeToolArgumentSuffix(tool); err != nil {
			return err
		}
	}
	if final {
		tool.final = true
		if tool.arguments.Len() == 0 || validateChatJSONValue([]byte(tool.arguments.String()), maxChatArgumentsBytes) != nil {
			return errors.New("upstream tool arguments are invalid")
		}
	}
	return nil
}

func (state *chatStreamState) reconcileText(text string) error {
	if len(text) > maxChatStringBytes || !strings.HasPrefix(text, state.text) {
		return errors.New("upstream text was inconsistent with emitted text")
	}
	return state.writeText(text[len(state.text):])
}

func (state *chatStreamState) validateResponse(response *codex.CodexResponse) error {
	if response == nil {
		return errors.New("terminal response is missing")
	}
	text, _, err := chatResponseOutput(response)
	if err != nil {
		return err
	}
	if len(text) > maxChatStringBytes || !strings.HasPrefix(text, state.text) {
		return errors.New("upstream text was inconsistent with emitted text")
	}
	return nil
}

func (state *chatStreamState) reconcileResponse(response *codex.CodexResponse) error {
	if response == nil {
		return errors.New("terminal response is missing")
	}
	text, tools, err := chatResponseOutput(response)
	if err != nil {
		return err
	}
	if err := state.reconcileText(text); err != nil {
		return err
	}
	for _, output := range tools {
		tool := state.outputTool(output.ID, output.Function.Name)
		if err := state.writeToolMetadata(tool); err != nil {
			return err
		}
		if err := state.addToolArguments(tool, output.Function.Arguments, true); err != nil {
			return err
		}
	}
	return nil
}

func (state *chatStreamState) finish(response *codex.CodexResponse) error {
	if state.finishSent {
		return errors.New("upstream stream sent duplicate terminal event")
	}
	if response == nil {
		return errors.New("terminal response is missing")
	}
	if state.includeUsage && state.mappedUsage == nil {
		return errors.New("upstream usage is missing")
	}
	for _, tool := range state.tools {
		if tool.id == "" || tool.name == "" || tool.arguments.Len() == 0 || validateChatJSONValue([]byte(tool.arguments.String()), maxChatArgumentsBytes) != nil {
			return errors.New("upstream tool call is incomplete")
		}
		if err := state.writeToolMetadata(tool); err != nil {
			return err
		}
	}
	reason := chatFinishReason(response, len(state.tools))
	if err := state.writeChunk(chatCompletionChunk{ID: state.identity.id, Object: "chat.completion.chunk", Created: state.identity.created, Model: state.identity.model, Choices: []chatChunkChoice{{Index: 0, Delta: chatChunkDelta{Content: nil}, FinishReason: &reason, Logprobs: nil}}, Usage: nil}); err != nil {
		return err
	}
	state.finishSent = true
	return nil
}

func (state *chatStreamState) writeChunk(chunk chatCompletionChunk) error {
	payload, err := json.Marshal(chunk)
	if err != nil {
		return err
	}
	if len(payload) > maxResponsesEventBytes {
		return errors.New("chat stream payload is too large")
	}
	return writeResponsesSSERecord(state.writer, state.flusher, payload)
}

func (state *chatStreamState) writeError(err error) error {
	if err == nil {
		return nil
	}
	var responseError openai.Error
	if state.quotaFailure {
		responseError = openai.Error{Type: responsesServerErrorType, Code: "internal_error", Message: "Internal server error."}
	} else if errors.Is(err, errChatStreamAbort) {
		responseError = openai.Error{Type: responsesServerErrorType, Code: "invalid_upstream_response", Message: "The upstream response was invalid."}
	} else {
		_, responseError = responsesError(err)
	}
	payload, marshalErr := json.Marshal(openai.ErrorResponse{Error: responseError})
	if marshalErr != nil {
		return marshalErr
	}
	return writeResponsesSSERecord(state.writer, state.flusher, payload)
}
