package openai

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

const (
	// Responses event names used by the public wire contract.
	EventResponseCreated                 = "response.created"
	EventResponseOutputItemAdded         = "response.output_item.added"
	EventResponseOutputItemDone          = "response.output_item.done"
	EventContentPartAdded                = "response.content_part.added"
	EventOutputTextDelta                 = "response.output_text.delta"
	EventOutputTextAnnotationAdded       = "response.output_text.annotation.added"
	EventFunctionArgsDelta               = "response.function_call_arguments.delta"
	EventFunctionArgsDone                = "response.function_call_arguments.done"
	EventCompleted                       = "response.completed"
	EventDone                            = "response.done"
	EventIncomplete                      = "response.incomplete"
	EventFailed                          = "response.failed"
	EventError                           = "error"
	ImageGenerationCall                  = "image_generation_call"
	ToolChoiceImageGeneration            = "image_generation"
	EventImageGenerationCallInProgress   = "response.image_generation_call.in_progress"
	EventImageGenerationCallGenerating   = "response.image_generation_call.generating"
	EventImageGenerationCallCompleted    = "response.image_generation_call.completed"
	EventImageGenerationCallPartialImage = "response.image_generation_call.partial_image"

	ResponseStatusCompleted  = "completed"
	ResponseStatusFailed     = "failed"
	ResponseStatusIncomplete = "incomplete"
)
const (
	maxResponsesInputItems    = 1024
	maxResponsesContentParts  = 1024
	maxResponsesItemTools     = 128
	maxResponsesInclude       = 64
	maxResponsesMetadata      = 16
	maxResponsesSafetyChecks  = maxResponsesItemTools
	maxResponsesContractBytes = 4 * 1024 * 1024
)

// ErrUnsupportedParameter marks a public Responses field that this Codex adapter cannot represent.
var ErrUnsupportedParameter = errors.New("Responses parameter is unsupported")

type ResponseRequest struct {
	Model                string            `json:"model" validate:"required,max=256"`
	Input                *Input            `json:"input,omitempty"`
	Instructions         string            `json:"instructions,omitempty" validate:"max=65536"`
	Tools                []Tool            `json:"tools,omitempty" validate:"max=128"`
	ToolChoice           *ToolChoice       `json:"tool_choice,omitempty"`
	Store                *bool             `json:"store,omitempty"`
	Stream               bool              `json:"stream,omitempty"`
	ParallelToolCalls    *bool             `json:"parallel_tool_calls,omitempty"`
	ClientMetadata       map[string]string `json:"client_metadata,omitempty" validate:"max=16,dive,keys,max=64,endkeys,max=512"`
	Generate             *bool             `json:"generate,omitempty"`
	PreviousResponseID   string            `json:"previous_response_id,omitempty" validate:"max=256"`
	Reasoning            *ReasoningConfig  `json:"reasoning,omitempty"`
	Text                 *TextConfig       `json:"text,omitempty"`
	StreamOptions        *StreamOptions    `json:"stream_options,omitempty"`
	MaxOutputTokens      *int              `json:"max_output_tokens,omitempty" validate:"omitempty,min=1"`
	Include              []string          `json:"include,omitempty" validate:"max=64,dive,max=128"`
	Metadata             map[string]string `json:"metadata,omitempty" validate:"max=16,dive,keys,max=64,endkeys,max=512"`
	PromptCacheKey       string            `json:"prompt_cache_key,omitempty" validate:"max=512"`
	PromptCacheRetention string            `json:"prompt_cache_retention,omitempty" validate:"omitempty,oneof=in_memory 24h"`
	ServiceTier          string            `json:"service_tier,omitempty" validate:"omitempty,oneof=auto default flex scale priority"`
}

func (request *ResponseRequest) UnmarshalJSON(data []byte) error {
	if len(data) > maxResponsesContractBytes {
		return fmt.Errorf("decode public Responses request: body exceeds %d bytes", maxResponsesContractBytes)
	}
	*request = ResponseRequest{}
	type responseRequest ResponseRequest
	wire := struct {
		*responseRequest
		Input              json.RawMessage `json:"input"`
		ToolChoice         json.RawMessage `json:"tool_choice"`
		Tools              json.RawMessage `json:"tools"`
		Include            json.RawMessage `json:"include"`
		Metadata           json.RawMessage `json:"metadata"`
		ClientMetadata     json.RawMessage `json:"client_metadata"`
		Background         json.RawMessage `json:"background"`
		Conversation       json.RawMessage `json:"conversation"`
		ContextManagement  json.RawMessage `json:"context_management"`
		MaxToolCalls       json.RawMessage `json:"max_tool_calls"`
		Moderation         json.RawMessage `json:"moderation"`
		Prompt             json.RawMessage `json:"prompt"`
		PromptCacheOptions json.RawMessage `json:"prompt_cache_options"`
		SafetyIdentifier   json.RawMessage `json:"safety_identifier"`
		Temperature        json.RawMessage `json:"temperature"`
		TopLogprobs        json.RawMessage `json:"top_logprobs"`
		TopP               json.RawMessage `json:"top_p"`
		Truncation         json.RawMessage `json:"truncation"`
		User               json.RawMessage `json:"user"`
	}{
		responseRequest: (*responseRequest)(request),
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&wire); err != nil {
		return err
	}
	var extra json.RawMessage
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return fmt.Errorf("decode public Responses request: multiple JSON values")
		}
		return fmt.Errorf("decode public Responses request: %w", err)
	}
	if wire.Metadata != nil && wire.ClientMetadata != nil {
		return fmt.Errorf("public Responses request cannot contain both metadata and client_metadata")
	}
	unsupported := []struct {
		field string
		value json.RawMessage
	}{
		{"background", wire.Background},
		{"conversation", wire.Conversation},
		{"context_management", wire.ContextManagement},
		{"max_tool_calls", wire.MaxToolCalls},
		{"moderation", wire.Moderation},
		{"prompt", wire.Prompt},
		{"prompt_cache_options", wire.PromptCacheOptions},
		{"safety_identifier", wire.SafetyIdentifier},
		{"temperature", wire.Temperature},
		{"top_logprobs", wire.TopLogprobs},
		{"top_p", wire.TopP},
		{"truncation", wire.Truncation},
		{"user", wire.User},
	}
	for _, parameter := range unsupported {
		if parameter.value != nil {
			return fmt.Errorf("%w: %s", ErrUnsupportedParameter, parameter.field)
		}
	}
	if request.StreamOptions != nil && request.StreamOptions.IncludeObfuscation != nil {
		return fmt.Errorf("%w: stream_options.include_obfuscation", ErrUnsupportedParameter)
	}
	if wire.Input != nil {
		if bytes.Equal(bytes.TrimSpace(wire.Input), []byte("null")) {
			return fmt.Errorf("public input must be a string or array")
		}
		var input Input
		if err := json.Unmarshal(wire.Input, &input); err != nil {
			return err
		}
		request.Input = &input
	}
	if wire.ToolChoice != nil {
		if bytes.Equal(bytes.TrimSpace(wire.ToolChoice), []byte("null")) {
			return fmt.Errorf("public tool choice must be a string or object")
		}
		var choice ToolChoice
		if err := json.Unmarshal(wire.ToolChoice, &choice); err != nil {
			return err
		}
		request.ToolChoice = &choice
	}
	if wire.Tools != nil {
		if bytes.Equal(bytes.TrimSpace(wire.Tools), []byte("null")) {
			request.Tools = nil
		} else {
			tools, err := decodeResponsesTools(wire.Tools, "decode public request tools")
			if err != nil {
				return err
			}
			request.Tools = tools
		}
	}
	if wire.Include != nil {
		if bytes.Equal(bytes.TrimSpace(wire.Include), []byte("null")) {
			request.Include = nil
		} else {
			include, err := decodeResponsesInclude(wire.Include, "decode public request include")
			if err != nil {
				return err
			}
			request.Include = include
		}
	}
	if wire.Metadata != nil {
		metadata, err := decodeResponsesMetadata(wire.Metadata, "decode public request metadata")
		if err != nil {
			return err
		}
		request.Metadata = metadata
	}
	if wire.ClientMetadata != nil {
		clientMetadata, err := decodeResponsesMetadata(wire.ClientMetadata, "decode public request client_metadata")
		if err != nil {
			return err
		}
		request.ClientMetadata = clientMetadata
	}
	return nil
}

// Input is the public Responses input string-or-array union.
type Input struct {
	String *string     `json:"-"`
	Items  []InputItem `json:"-" validate:"max=1024,dive"`
}

func (input Input) MarshalJSON() ([]byte, error) {
	switch {
	case input.String != nil && input.Items == nil:
		return json.Marshal(*input.String)
	case input.String == nil && input.Items != nil:
		return json.Marshal(input.Items)
	default:
		return nil, fmt.Errorf("public input must contain exactly one variant")
	}
}

func (input *Input) UnmarshalJSON(data []byte) error {
	value := bytes.TrimSpace(data)
	if len(value) == 0 || bytes.Equal(value, []byte("null")) {
		return fmt.Errorf("public input must be a string or array")
	}
	switch value[0] {
	case '"':
		var text string
		if err := json.Unmarshal(value, &text); err != nil {
			return fmt.Errorf("decode public input string: %w", err)
		}
		*input = Input{String: &text}
		return nil
	case '[':
		items := make([]InputItem, 0)
		err := decodeResponsesArray(value, "decode public input array", "input items", maxResponsesInputItems,
			func(decoder *json.Decoder, index int) error {
				var item InputItem
				if err := decoder.Decode(&item); err != nil {
					return err
				}
				items = append(items, item)
				return nil
			})
		if err != nil {
			return err
		}
		*input = Input{Items: items}
		return nil
	default:
		return fmt.Errorf("public input must be a string or array")
	}
}

func decodeResponsesArray(data []byte, field, itemName string, limit int, decode func(*json.Decoder, int) error) error {
	value := bytes.TrimSpace(data)
	if len(value) == 0 || bytes.Equal(value, []byte("null")) {
		return nil
	}
	decoder := json.NewDecoder(bytes.NewReader(value))
	decoder.DisallowUnknownFields()
	token, err := decoder.Token()
	if err != nil {
		return fmt.Errorf("%s: %w", field, err)
	}
	if delimiter, ok := token.(json.Delim); !ok || delimiter != '[' {
		return fmt.Errorf("%s: must be an array", field)
	}
	for index := 0; decoder.More(); index++ {
		if index >= limit {
			return fmt.Errorf("%s: too many %s (maximum %d)", field, itemName, limit)
		}
		if err := decode(decoder, index); err != nil {
			return fmt.Errorf("%s %d: %w", field, index, err)
		}
	}
	if _, err := decoder.Token(); err != nil {
		return fmt.Errorf("%s: %w", field, err)
	}
	var extra json.RawMessage
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return fmt.Errorf("%s: multiple JSON values", field)
		}
		return fmt.Errorf("%s: %w", field, err)
	}
	return nil
}

func decodeResponsesJSONValue(data []byte, target any, field string) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("%s: %w", field, err)
	}
	var extra json.RawMessage
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return fmt.Errorf("%s: multiple JSON values", field)
		}
		return fmt.Errorf("%s: %w", field, err)
	}
	return nil
}

func decodeResponsesInputContentParts(data []byte, field string) ([]InputContent, error) {
	parts := make([]InputContent, 0)
	err := decodeResponsesArray(data, field, "content parts", maxResponsesContentParts,
		func(decoder *json.Decoder, index int) error {
			var part InputContent
			if err := decoder.Decode(&part); err != nil {
				return err
			}
			parts = append(parts, part)
			return nil
		})
	if err != nil {
		return nil, err
	}
	return parts, nil
}

func decodeResponsesInputItemField(data []byte, field string, allowObject bool) error {
	value := bytes.TrimSpace(data)
	if len(value) == 0 || bytes.Equal(value, []byte("null")) {
		return nil
	}
	switch value[0] {
	case '"':
		var text string
		return decodeResponsesJSONValue(value, &text, field)
	case '[':
		_, err := decodeResponsesInputContentParts(value, field)
		return err
	case '{':
		if !allowObject {
			return fmt.Errorf("%s: must be a string or array", field)
		}
		var content InputContent
		return decodeResponsesJSONValue(value, &content, field)
	default:
		if allowObject {
			return fmt.Errorf("%s: must be a string, object, or array", field)
		}
		return fmt.Errorf("%s: must be a string or array", field)
	}
}

func decodeResponsesTools(data []byte, field string) ([]Tool, error) {
	return decodeResponsesToolsAtDepth(data, field, 0)
}

func decodeResponsesToolsAtDepth(data []byte, field string, depth int) ([]Tool, error) {
	tools := make([]Tool, 0)
	err := decodeResponsesArray(data, field, "tools", maxResponsesItemTools,
		func(decoder *json.Decoder, index int) error {
			var raw json.RawMessage
			if err := decoder.Decode(&raw); err != nil {
				return err
			}
			var tool Tool
			if err := decodePublicTool(raw, &tool, depth); err != nil {
				return err
			}
			tools = append(tools, tool)
			return nil
		})
	if err != nil {
		return nil, err
	}
	return tools, nil
}

func decodeResponsesInclude(data []byte, field string) ([]string, error) {
	include := make([]string, 0)
	err := decodeResponsesArray(data, field, "include entries", maxResponsesInclude,
		func(decoder *json.Decoder, index int) error {
			var entry string
			if err := decoder.Decode(&entry); err != nil {
				return err
			}
			include = append(include, entry)
			return nil
		})
	if err != nil {
		return nil, err
	}
	return include, nil
}

func decodeResponsesMetadata(data []byte, field string) (map[string]string, error) {
	value := bytes.TrimSpace(data)
	if len(value) == 0 {
		return nil, fmt.Errorf("%s: empty JSON value", field)
	}
	if bytes.Equal(value, []byte("null")) {
		return nil, nil
	}
	decoder := json.NewDecoder(bytes.NewReader(value))
	token, err := decoder.Token()
	if err != nil {
		return nil, fmt.Errorf("%s: %w", field, err)
	}
	delimiter, ok := token.(json.Delim)
	if !ok || delimiter != '{' {
		return nil, fmt.Errorf("%s: must be a JSON object", field)
	}
	metadata := make(map[string]string)
	for index := 0; decoder.More(); index++ {
		if index >= maxResponsesMetadata {
			return nil, fmt.Errorf("%s: too many metadata entries (maximum %d)", field, maxResponsesMetadata)
		}
		keyToken, err := decoder.Token()
		if err != nil {
			return nil, fmt.Errorf("%s: %w", field, err)
		}
		key, ok := keyToken.(string)
		if !ok {
			return nil, fmt.Errorf("%s: metadata key must be a string", field)
		}
		if _, exists := metadata[key]; exists {
			return nil, fmt.Errorf("%s: duplicate metadata key %q", field, key)
		}
		valueToken, err := decoder.Token()
		if err != nil {
			return nil, fmt.Errorf("%s %q: %w", field, key, err)
		}
		metadataValue, ok := valueToken.(string)
		if !ok {
			return nil, fmt.Errorf("%s %q: metadata value must be a string", field, key)
		}
		metadata[key] = metadataValue
	}
	token, err = decoder.Token()
	if err != nil {
		return nil, fmt.Errorf("%s: %w", field, err)
	}
	delimiter, ok = token.(json.Delim)
	if !ok || delimiter != '}' {
		return nil, fmt.Errorf("%s: must end with a JSON object", field)
	}
	var extra json.RawMessage
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return nil, fmt.Errorf("%s: multiple JSON values", field)
		}
		return nil, fmt.Errorf("%s: %w", field, err)
	}
	return metadata, nil
}

func decodeResponsesSafetyChecks(data []byte, field string) ([]SafetyCheck, error) {
	checks := make([]SafetyCheck, 0)
	err := decodeResponsesArray(data, field, "safety checks", maxResponsesSafetyChecks,
		func(decoder *json.Decoder, index int) error {
			var check SafetyCheck
			if err := decoder.Decode(&check); err != nil {
				return err
			}
			checks = append(checks, check)
			return nil
		})
	if err != nil {
		return nil, err
	}
	return checks, nil
}

// InputItem is one public Responses input item. Content and output are
// polymorphic in the wire contract (a string or a typed content list).
type InputItem struct {
	Type                     string          `json:"type,omitempty"`
	Role                     string          `json:"role,omitempty"`
	Status                   string          `json:"status,omitempty"`
	Content                  json.RawMessage `json:"content,omitempty"`
	ID                       string          `json:"id,omitempty"`
	CallID                   string          `json:"call_id,omitempty"`
	Name                     string          `json:"name,omitempty"`
	Arguments                string          `json:"arguments,omitempty"`
	Output                   json.RawMessage `json:"output,omitempty"`
	Action                   json.RawMessage `json:"action,omitempty"`
	Actions                  json.RawMessage `json:"actions,omitempty"`
	PendingSafetyChecks      []SafetyCheck   `json:"pending_safety_checks,omitempty" validate:"max=128,dive"`
	AcknowledgedSafetyChecks []SafetyCheck   `json:"acknowledged_safety_checks,omitempty" validate:"max=128,dive"`
	Tools                    []Tool          `json:"tools,omitempty" validate:"max=128,dive"`
}

func (item *InputItem) UnmarshalJSON(data []byte) error {
	*item = InputItem{}
	value := bytes.TrimSpace(data)
	if len(value) == 0 || value[0] != '{' {
		return fmt.Errorf("public input item must be a JSON object")
	}
	type inputItem InputItem
	wire := struct {
		*inputItem
		PendingSafetyChecks      json.RawMessage `json:"pending_safety_checks"`
		AcknowledgedSafetyChecks json.RawMessage `json:"acknowledged_safety_checks"`
		Tools                    json.RawMessage `json:"tools"`
	}{
		inputItem: (*inputItem)(item),
	}
	decoder := json.NewDecoder(bytes.NewReader(value))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&wire); err != nil {
		return err
	}
	var extra json.RawMessage
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return fmt.Errorf("decode public input item: multiple JSON values")
		}
		return fmt.Errorf("decode public input item: %w", err)
	}
	if wire.PendingSafetyChecks != nil {
		checks, err := decodeResponsesSafetyChecks(wire.PendingSafetyChecks, "decode public input item pending_safety_checks")
		if err != nil {
			return err
		}
		item.PendingSafetyChecks = checks
	}
	if wire.AcknowledgedSafetyChecks != nil {
		checks, err := decodeResponsesSafetyChecks(wire.AcknowledgedSafetyChecks, "decode public input item acknowledged_safety_checks")
		if err != nil {
			return err
		}
		item.AcknowledgedSafetyChecks = checks
	}
	if wire.Tools != nil {
		tools, err := decodeResponsesTools(wire.Tools, "decode public input item tools")
		if err != nil {
			return err
		}
		item.Tools = tools
	}
	if err := decodeResponsesInputItemField(item.Content, "decode public input item content", false); err != nil {
		return err
	}
	if err := decodeResponsesInputItemField(item.Output, "decode public input item output", true); err != nil {
		return err
	}
	return nil
}

// SafetyCheck is one computer-call safety check.
type SafetyCheck struct {
	ID      string `json:"id"`
	Code    string `json:"code,omitempty"`
	Message string `json:"message,omitempty"`
}

// InputContent is one public input content part.
type InputContent struct {
	Type     string `json:"type"`
	Text     string `json:"text,omitempty"`
	ImageURL string `json:"image_url,omitempty"`
	FileID   string `json:"file_id,omitempty"`
	FileData string `json:"file_data,omitempty"`
	FileURL  string `json:"file_url,omitempty"`
	Filename string `json:"filename,omitempty"`
	Detail   string `json:"detail,omitempty"`
}

// InputImageMask is an optional hosted-image inpainting mask.
type InputImageMask struct {
	FileID   string `json:"file_id,omitempty"`
	ImageURL string `json:"image_url,omitempty"`
}

// TextLogprob is the log probability for one output token.
type TextLogprob struct {
	Token       string       `json:"token"`
	Bytes       []int        `json:"bytes,omitempty"`
	Logprob     float64      `json:"logprob"`
	TopLogprobs []TopLogprob `json:"top_logprobs,omitempty"`
}

// TopLogprob is one alternative token log probability.
type TopLogprob struct {
	Token   string  `json:"token"`
	Bytes   []int   `json:"bytes,omitempty"`
	Logprob float64 `json:"logprob"`
}

// Tool describes a public Responses tool.
type Tool struct {
	Type              string          `json:"type"`
	Name              string          `json:"name,omitempty"`
	Parameters        json.RawMessage `json:"parameters,omitempty"`
	Strict            *bool           `json:"strict,omitempty"`
	Description       string          `json:"description,omitempty"`
	Action            string          `json:"action,omitempty"`
	Background        string          `json:"background,omitempty"`
	InputFidelity     string          `json:"input_fidelity,omitempty"`
	InputImageMask    *InputImageMask `json:"input_image_mask,omitempty"`
	Model             string          `json:"model,omitempty"`
	Moderation        string          `json:"moderation,omitempty"`
	OutputCompression int             `json:"output_compression,omitempty"`
	OutputFormat      string          `json:"output_format,omitempty"`
	PartialImages     int             `json:"partial_images,omitempty"`
	Quality           string          `json:"quality,omitempty"`
	Size              string          `json:"size,omitempty"`
	Tools             []Tool          `json:"tools,omitempty" validate:"max=128,dive"`
}

func (tool *Tool) UnmarshalJSON(data []byte) error {
	return decodePublicTool(data, tool, 0)
}

func decodePublicTool(data []byte, tool *Tool, depth int) error {
	if depth > 1 {
		return fmt.Errorf("public namespace tool nesting exceeds one level")
	}
	*tool = Tool{}
	type toolFields Tool
	wire := struct {
		*toolFields
		Tools json.RawMessage `json:"tools"`
	}{
		toolFields: (*toolFields)(tool),
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&wire); err != nil {
		return err
	}
	var extra json.RawMessage
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return fmt.Errorf("decode public tool: multiple JSON values")
		}
		return fmt.Errorf("decode public tool: %w", err)
	}
	if wire.Tools != nil {
		if tool.Type != "namespace" {
			return fmt.Errorf("public tool tools is only valid for namespace tools")
		}
		if depth >= 1 {
			return fmt.Errorf("public namespace tool nesting exceeds one level")
		}
		tools, err := decodeResponsesToolsAtDepth(wire.Tools, "decode public namespace tools", depth+1)
		if err != nil {
			return err
		}
		tool.Tools = tools
	}
	return nil
}

// ToolChoice selects a public Responses tool as a string or object.
type ToolChoice struct {
	String *string `json:"-"`
	Type   string  `json:"type"`
	Name   string  `json:"name,omitempty"`
}

func (choice ToolChoice) MarshalJSON() ([]byte, error) {
	if choice.String != nil {
		if choice.Type != "" || choice.Name != "" {
			return nil, fmt.Errorf("public tool choice contains multiple variants")
		}
		return json.Marshal(*choice.String)
	}
	if choice.Type == "" {
		return nil, fmt.Errorf("public tool choice object requires type")
	}
	return json.Marshal(struct {
		Type string `json:"type"`
		Name string `json:"name,omitempty"`
	}{
		Type: choice.Type,
		Name: choice.Name,
	})
}

func (choice *ToolChoice) UnmarshalJSON(data []byte) error {
	value := bytes.TrimSpace(data)
	if len(value) == 0 || bytes.Equal(value, []byte("null")) {
		return fmt.Errorf("public tool choice must be a string or object")
	}
	switch value[0] {
	case '"':
		var text string
		if err := json.Unmarshal(value, &text); err != nil {
			return fmt.Errorf("decode public tool choice string: %w", err)
		}
		*choice = ToolChoice{String: &text}
		return nil
	case '{':
		var object struct {
			Type string `json:"type"`
			Name string `json:"name,omitempty"`
		}
		decoder := json.NewDecoder(bytes.NewReader(value))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&object); err != nil {
			return fmt.Errorf("decode public tool choice object: %w", err)
		}
		var extra json.RawMessage
		if err := decoder.Decode(&extra); err != io.EOF {
			if err == nil {
				return fmt.Errorf("decode public tool choice object: multiple JSON values")
			}
			return fmt.Errorf("decode public tool choice object: %w", err)
		}
		if object.Type == "" {
			return fmt.Errorf("decode public tool choice object: type is required")
		}
		*choice = ToolChoice{Type: object.Type, Name: object.Name}
		return nil
	default:
		return fmt.Errorf("public tool choice must be a string or object")
	}
}

// ReasoningConfig carries public reasoning options.
type ReasoningConfig struct {
	Effort  string `json:"effort,omitempty"`
	Summary string `json:"summary,omitempty"`
	Context string `json:"context,omitempty"`
}

// StreamOptions carries provider-specific streaming options accepted by Codex.
type StreamOptions struct {
	ReasoningSummaryDelivery string `json:"reasoning_summary_delivery,omitempty"`
	IncludeObfuscation       *bool  `json:"include_obfuscation,omitempty"`
}

// TextConfig carries public text output options.
type TextConfig struct {
	Verbosity string      `json:"verbosity,omitempty"`
	Format    *TextFormat `json:"format,omitempty"`
}

// TextFormat is the structured-output format accepted by Responses.
type TextFormat struct {
	Type        string          `json:"type"`
	Name        string          `json:"name,omitempty"`
	Description string          `json:"description,omitempty"`
	Schema      json.RawMessage `json:"schema,omitempty"`
	Strict      *bool           `json:"strict,omitempty"`
}

// Response is the public OpenAI Responses result.
type Response struct {
	ID                 string             `json:"id,omitempty"`
	Object             string             `json:"object,omitempty"`
	CreatedAt          int64              `json:"created_at,omitempty"`
	CompletedAt        int64              `json:"completed_at,omitempty"`
	Model              string             `json:"model,omitempty"`
	Status             string             `json:"status,omitempty"`
	OutputText         string             `json:"output_text,omitempty"`
	Output             []OutputItem       `json:"output,omitempty"`
	Usage              *Usage             `json:"usage,omitempty"`
	Error              *Error             `json:"error,omitempty"`
	IncompleteDetails  *IncompleteDetails `json:"incomplete_details,omitempty"`
	ServiceTier        string             `json:"service_tier,omitempty"`
	PreviousResponseID string             `json:"previous_response_id,omitempty"`
}

// OutputItem is one public Responses output item.
type OutputItem struct {
	ID                       string          `json:"id,omitempty"`
	Type                     string          `json:"type"`
	Role                     string          `json:"role,omitempty"`
	Status                   string          `json:"status,omitempty"`
	Content                  []ContentPart   `json:"content,omitempty"`
	CallID                   string          `json:"call_id,omitempty"`
	Name                     string          `json:"name,omitempty"`
	Arguments                string          `json:"arguments,omitempty"`
	Input                    string          `json:"input,omitempty"`
	Result                   string          `json:"result,omitempty"`
	RevisedPrompt            string          `json:"revised_prompt,omitempty"`
	Action                   json.RawMessage `json:"action,omitempty"`
	PendingSafetyChecks      []SafetyCheck   `json:"pending_safety_checks,omitempty"`
	AcknowledgedSafetyChecks []SafetyCheck   `json:"acknowledged_safety_checks,omitempty"`
	EncryptedContent         string          `json:"encrypted_content,omitempty"`
	CreatedBy                string          `json:"created_by,omitempty"`
}

// ContentPart is one public output content part.
type ContentPart struct {
	Type        string            `json:"type"`
	Text        string            `json:"text,omitempty"`
	Refusal     string            `json:"refusal,omitempty"`
	ImageURL    string            `json:"image_url,omitempty"`
	Detail      string            `json:"detail,omitempty"`
	Annotations []json.RawMessage `json:"annotations,omitempty"`
	Logprobs    []TextLogprob     `json:"logprobs,omitempty"`
}

// IncompleteDetails explains why a response stopped early.
type IncompleteDetails struct {
	Reason string `json:"reason,omitempty"`
}

// ResponseStreamEvent is one public Responses SSE event.
type ResponseStreamEvent struct {
	Type              string          `json:"type"`
	SequenceNumber    int             `json:"sequence_number"`
	Response          *Response       `json:"response,omitempty"`
	Item              *OutputItem     `json:"item,omitempty"`
	Part              *ContentPart    `json:"part,omitempty"`
	Error             *Error          `json:"error,omitempty"`
	Delta             string          `json:"delta,omitempty"`
	Arguments         string          `json:"arguments,omitempty"`
	Annotation        json.RawMessage `json:"annotation,omitempty"`
	Text              string          `json:"text,omitempty"`
	Logprobs          []TextLogprob   `json:"logprobs,omitempty"`
	Code              string          `json:"code,omitempty"`
	Message           string          `json:"message,omitempty"`
	ItemID            string          `json:"item_id,omitempty"`
	OutputIndex       int             `json:"output_index"`
	ContentIndex      int             `json:"content_index"`
	SummaryIndex      int             `json:"summary_index"`
	PartialImageB64   string          `json:"partial_image_b64,omitempty"`
	PartialImageIndex int             `json:"partial_image_index"`
}

// ResponseErrorEvent is the safe public stream error event shape.
type ResponseErrorEvent struct {
	Type           string `json:"type"`
	Code           string `json:"code"`
	Message        string `json:"message"`
	Param          string `json:"param"`
	SequenceNumber int    `json:"sequence_number"`
}

// Usage records public token counts.
type Usage struct {
	InputTokens         int                 `json:"input_tokens,omitempty"`
	OutputTokens        int                 `json:"output_tokens,omitempty"`
	TotalTokens         int                 `json:"total_tokens,omitempty"`
	InputTokensDetails  *InputTokenDetails  `json:"input_tokens_details,omitempty"`
	OutputTokensDetails *OutputTokenDetails `json:"output_tokens_details,omitempty"`
}

// InputTokenDetails gives the public input token breakdown.
type InputTokenDetails struct {
	CachedTokens int `json:"cached_tokens,omitempty"`
	ImageTokens  int `json:"image_tokens,omitempty"`
	TextTokens   int `json:"text_tokens,omitempty"`
}

// OutputTokenDetails gives the public output token breakdown.
type OutputTokenDetails struct {
	ReasoningTokens int `json:"reasoning_tokens,omitempty"`
	ImageTokens     int `json:"image_tokens,omitempty"`
	TextTokens      int `json:"text_tokens,omitempty"`
}

// Error is one public OpenAI error object.
type Error struct {
	Message string `json:"message"`
	Type    string `json:"type,omitempty"`
	Param   string `json:"param,omitempty"`
	Code    string `json:"code,omitempty"`
}

// ErrorResponse is a public OpenAI error envelope.
type ErrorResponse struct {
	Error Error `json:"error"`
}

// ImageGenerationRequest is a public Images generation request.
type ImageGenerationRequest struct {
	Model             string `json:"model" validate:"required,eq=gpt-image-2,max=64"`
	Prompt            string `json:"prompt" validate:"required,max=65536"`
	N                 *int   `json:"n,omitempty" validate:"omitempty,min=1,max=5"`
	Size              string `json:"size,omitempty" validate:"omitempty,max=32"`
	Quality           string `json:"quality,omitempty" validate:"omitempty,oneof=low medium high auto"`
	Background        string `json:"background,omitempty" validate:"omitempty,oneof=auto opaque transparent"`
	OutputCompression *int   `json:"output_compression,omitempty" validate:"omitempty,min=0,max=100"`
	OutputFormat      string `json:"output_format,omitempty" validate:"omitempty,oneof=png jpeg webp"`
	Moderation        string `json:"moderation,omitempty" validate:"omitempty,oneof=low auto"`
	ResponseFormat    string `json:"response_format,omitempty" validate:"omitempty,oneof=b64_json"`
	User              string `json:"user,omitempty" validate:"max=65536"`
}

// ImageEditRequest is the typed request assembled from an Images multipart form.
type ImageEditRequest struct {
	Model             string   `json:"model" validate:"required,eq=gpt-image-2,max=64"`
	Prompt            string   `json:"prompt" validate:"required,max=65536"`
	Images            []string `json:"images" validate:"-"`
	N                 *int     `json:"n,omitempty" validate:"omitempty,min=1,max=5"`
	Size              string   `json:"size,omitempty" validate:"omitempty,max=32"`
	Quality           string   `json:"quality,omitempty" validate:"omitempty,oneof=low medium high auto"`
	Background        string   `json:"background,omitempty" validate:"omitempty,oneof=auto opaque transparent"`
	OutputCompression *int     `json:"output_compression,omitempty" validate:"omitempty,min=0,max=100"`
	OutputFormat      string   `json:"output_format,omitempty" validate:"omitempty,oneof=png jpeg webp"`
	ResponseFormat    string   `json:"response_format,omitempty" validate:"omitempty,oneof=b64_json"`
	User              string   `json:"user,omitempty" validate:"max=65536"`
}

// ImageResponse is a public Images result.
type ImageResponse struct {
	Created      int64       `json:"created"`
	Background   string      `json:"background,omitempty"`
	Data         []ImageData `json:"data"`
	OutputFormat string      `json:"output_format,omitempty"`
	Quality      string      `json:"quality,omitempty"`
	Size         string      `json:"size,omitempty"`
	Usage        *Usage      `json:"usage,omitempty"`
}

// ImageData is one public Images result.
type ImageData struct {
	B64JSON       string `json:"b64_json,omitempty"`
	URL           string `json:"url,omitempty"`
	RevisedPrompt string `json:"revised_prompt,omitempty"`
}
