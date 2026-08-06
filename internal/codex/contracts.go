package codex

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
)

const (
	// Codex responses event names.
	CodexEventResponseCreated                     = "response.created"
	CodexEventResponseOutputItemAdded             = "response.output_item.added"
	CodexEventResponseOutputItemDone              = "response.output_item.done"
	CodexEventResponseContentPartAdded            = "response.content_part.added"
	CodexEventResponseOutputTextDelta             = "response.output_text.delta"
	CodexEventResponseFunctionArgsDelta           = "response.function_call_arguments.delta"
	CodexEventResponseFunctionArgsDone            = "response.function_call_arguments.done"
	CodexEventResponseCompleted                   = "response.completed"
	CodexEventResponseDone                        = "response.done"
	CodexEventResponseIncomplete                  = "response.incomplete"
	CodexEventResponseFailed                      = "response.failed"
	CodexEventError                               = "error"
	CodexEventResponseMetadata                    = "response.metadata"
	CodexResponseStatusCompleted                  = "completed"
	CodexResponseStatusFailed                     = "failed"
	CodexResponseStatusIncomplete                 = "incomplete"
	CodexResponseStatusInProgress                 = "in_progress"
	CodexIncompleteReasonMaxOutputTokens          = "max_output_tokens"
	CodexIncompleteReasonContentFilter            = "content_filter"
	CodexImageGenerationCall                      = "image_generation_call"
	CodexEventResponseImageGenerationInProgress   = "response.image_generation_call.in_progress"
	CodexEventResponseImageGenerationGenerating   = "response.image_generation_call.generating"
	CodexEventResponseImageGenerationCompleted    = "response.image_generation_call.completed"
	CodexEventResponseImageGenerationPartialImage = "response.image_generation_call.partial_image"
)

const (
	maxCodexStreamLineBytes    = 256 * 1024
	maxCodexStreamEvents       = 8192
	maxCodexStreamPayloadBytes = 4 * 1024 * 1024

	maxCodexInputItems    = 1024
	maxCodexContentParts  = 1024
	maxCodexItemTools     = 128
	maxCodexInclude       = 64
	maxCodexMetadata      = 16
	maxCodexSafetyChecks  = maxCodexItemTools
	maxCodexContractBytes = 4 * 1024 * 1024
)

// CodexStreamOptions controls provider-specific stream behavior.
type CodexStreamOptions struct {
	ReasoningSummaryDelivery string `json:"reasoning_summary_delivery"`
}

// CodexInputImageMask is an optional image-generation inpainting mask.
type CodexInputImageMask struct {
	FileID   string `json:"file_id,omitempty"`
	ImageURL string `json:"image_url,omitempty"`
}

// CodexSafetyCheck is a provider safety check attached to computer calls.
type CodexSafetyCheck struct {
	ID      string `json:"id"`
	Code    string `json:"code,omitempty"`
	Message string `json:"message,omitempty"`
}

// CodexTextLogprob is one output token log probability.
type CodexTextLogprob struct {
	Token       string            `json:"token"`
	Bytes       []int             `json:"bytes,omitempty"`
	Logprob     float64           `json:"logprob"`
	TopLogprobs []CodexTopLogprob `json:"top_logprobs,omitempty"`
}

// CodexTopLogprob is one alternative token log probability.
type CodexTopLogprob struct {
	Token   string  `json:"token"`
	Bytes   []int   `json:"bytes,omitempty"`
	Logprob float64 `json:"logprob"`
}

// CodexResponseRequest is the private request body for the Responses endpoint.
type CodexResponseRequest struct {
	Model                string                `json:"model"`
	Input                *CodexInput           `json:"input,omitempty"`
	Instructions         string                `json:"instructions,omitempty"`
	Tools                []CodexTool           `json:"tools,omitempty"`
	ToolChoice           *CodexToolChoice      `json:"tool_choice,omitempty"`
	Store                *bool                 `json:"store,omitempty"`
	Stream               bool                  `json:"stream,omitempty"`
	ParallelToolCalls    *bool                 `json:"parallel_tool_calls,omitempty"`
	ClientMetadata       map[string]string     `json:"client_metadata,omitempty"`
	Generate             *bool                 `json:"generate,omitempty"`
	Include              []string              `json:"include,omitempty"`
	PreviousResponseID   string                `json:"previous_response_id,omitempty"`
	Reasoning            *CodexReasoningConfig `json:"reasoning,omitempty"`
	Text                 *CodexTextConfig      `json:"text,omitempty"`
	StreamOptions        *CodexStreamOptions   `json:"stream_options,omitempty"`
	PromptCacheKey       string                `json:"prompt_cache_key,omitempty"`
	PromptCacheRetention string                `json:"prompt_cache_retention,omitempty"`
	MaxOutputTokens      int                   `json:"max_output_tokens,omitempty"`
	MaxCompletionTokens  int                   `json:"max_completion_tokens,omitempty"`
	ServiceTier          string                `json:"service_tier,omitempty"`

	// ResponsesLite requests the private Lite transport marker and is never
	// serialized into the private request body.
	ResponsesLite bool `json:"-"`
}

// CodexCompactRequest is the private request body for the Responses compact endpoint.
type CodexCompactRequest struct {
	Model                string                `json:"model"`
	Input                *CodexInput           `json:"input,omitempty"`
	Instructions         string                `json:"instructions,omitempty"`
	Tools                []CodexTool           `json:"tools,omitempty"`
	ParallelToolCalls    *bool                 `json:"parallel_tool_calls,omitempty"`
	Reasoning            *CodexReasoningConfig `json:"reasoning,omitempty"`
	Text                 *CodexTextConfig      `json:"text,omitempty"`
	PromptCacheKey       string                `json:"prompt_cache_key,omitempty"`
	PromptCacheRetention string                `json:"prompt_cache_retention,omitempty"`
	ServiceTier          string                `json:"service_tier,omitempty"`

	// ResponsesLite requests the private Lite transport marker and is never
	// serialized into the private request body.
	ResponsesLite bool `json:"-"`
}

func (request *CodexCompactRequest) UnmarshalJSON(data []byte) error {
	if len(data) > maxCodexContractBytes {
		return fmt.Errorf("decode private compact request: body exceeds %d bytes", maxCodexContractBytes)
	}
	*request = CodexCompactRequest{}
	type compactRequest CodexCompactRequest
	wire := struct {
		*compactRequest
		Tools json.RawMessage `json:"tools"`
	}{
		compactRequest: (*compactRequest)(request),
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&wire); err != nil {
		return fmt.Errorf("decode private compact request: %w", err)
	}
	if wire.Tools != nil {
		if bytes.Equal(bytes.TrimSpace(wire.Tools), []byte("null")) {
			request.Tools = nil
		} else {
			tools, err := decodeCodexTools(wire.Tools, "decode private compact request tools")
			if err != nil {
				return err
			}
			request.Tools = tools
		}
	}
	var extra json.RawMessage
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return errors.New("decode private compact request: multiple JSON values")
		}
		return fmt.Errorf("decode private compact request: %w", err)
	}
	return nil
}

func (request CodexCompactRequest) validate() error {
	if strings.TrimSpace(request.Model) == "" {
		return errors.New("compact request model is required")
	}
	if request.Input == nil {
		return errors.New("compact request input is required")
	}
	if (request.Input.String == nil) == (request.Input.Items == nil) {
		return errors.New("compact request input must contain exactly one variant")
	}
	if len(request.Tools) > maxCodexItemTools {
		return fmt.Errorf("compact request tools exceed %d items", maxCodexItemTools)
	}
	return nil
}

func (request *CodexResponseRequest) UnmarshalJSON(data []byte) error {
	if len(data) > maxCodexContractBytes {
		return fmt.Errorf("decode private Responses request: body exceeds %d bytes", maxCodexContractBytes)
	}
	*request = CodexResponseRequest{}
	type codexResponseRequest CodexResponseRequest
	wire := struct {
		*codexResponseRequest
		Input          json.RawMessage `json:"input"`
		ToolChoice     json.RawMessage `json:"tool_choice"`
		Tools          json.RawMessage `json:"tools"`
		Include        json.RawMessage `json:"include"`
		ClientMetadata json.RawMessage `json:"client_metadata"`
		Metadata       json.RawMessage `json:"metadata"`
	}{
		codexResponseRequest: (*codexResponseRequest)(request),
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&wire); err != nil {
		return err
	}
	var extra json.RawMessage
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return fmt.Errorf("decode private Responses request: multiple JSON values")
		}
		return fmt.Errorf("decode private Responses request: %w", err)
	}
	if wire.Metadata != nil && wire.ClientMetadata != nil {
		return fmt.Errorf("private Responses request cannot contain both metadata and client_metadata")
	}
	if wire.Metadata != nil {
		return fmt.Errorf("private Responses request does not support metadata")
	}
	if wire.Input != nil {
		if bytes.Equal(bytes.TrimSpace(wire.Input), []byte("null")) {
			return fmt.Errorf("private input must be a string or array")
		}
		var input CodexInput
		if err := json.Unmarshal(wire.Input, &input); err != nil {
			return err
		}
		request.Input = &input
	}
	if wire.ToolChoice != nil {
		if bytes.Equal(bytes.TrimSpace(wire.ToolChoice), []byte("null")) {
			return fmt.Errorf("private tool choice must be a string or object")
		}
		var choice CodexToolChoice
		if err := json.Unmarshal(wire.ToolChoice, &choice); err != nil {
			return err
		}
		request.ToolChoice = &choice
	}
	if wire.Tools != nil {
		if bytes.Equal(bytes.TrimSpace(wire.Tools), []byte("null")) {
			request.Tools = nil
		} else {
			tools, err := decodeCodexTools(wire.Tools, "decode private request tools")
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
			include, err := decodeCodexInclude(wire.Include, "decode private request include")
			if err != nil {
				return err
			}
			request.Include = include
		}
	}
	if wire.ClientMetadata != nil {
		metadata, err := decodeCodexMetadata(wire.ClientMetadata, "decode private request client_metadata")
		if err != nil {
			return err
		}
		request.ClientMetadata = metadata
	}
	return nil
}

// CodexInput is the private Responses input string-or-array union.
type CodexInput struct {
	String *string          `json:"-"`
	Items  []CodexInputItem `json:"-"`
}

func (input CodexInput) MarshalJSON() ([]byte, error) {
	switch {
	case input.String != nil && input.Items == nil:
		return json.Marshal(*input.String)
	case input.String == nil && input.Items != nil:
		return json.Marshal(input.Items)
	default:
		return nil, fmt.Errorf("private input must contain exactly one variant")
	}
}

func (input *CodexInput) UnmarshalJSON(data []byte) error {
	value := bytes.TrimSpace(data)
	if len(value) == 0 || bytes.Equal(value, []byte("null")) {
		return fmt.Errorf("private input must be a string or array")
	}
	switch value[0] {
	case '"':
		var text string
		if err := json.Unmarshal(value, &text); err != nil {
			return fmt.Errorf("decode private input string: %w", err)
		}
		*input = CodexInput{String: &text}
		return nil
	case '[':
		items := make([]CodexInputItem, 0)
		err := decodeCodexArray(value, "decode private input array", "input items", maxCodexInputItems,
			func(decoder *json.Decoder, index int) error {
				var item CodexInputItem
				if err := decoder.Decode(&item); err != nil {
					return err
				}
				items = append(items, item)
				return nil
			})
		if err != nil {
			return err
		}
		*input = CodexInput{Items: items}
		return nil
	default:
		return fmt.Errorf("private input must be a string or array")
	}
}

func decodeCodexArray(data []byte, field, itemName string, limit int, decode func(*json.Decoder, int) error) error {
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
	delimiter, ok := token.(json.Delim)
	if !ok || delimiter != '[' {
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

// CodexInputItem is one private Responses input item. Content and output are
// polymorphic in the provider contract, so they remain raw JSON values.
type CodexInputItem struct {
	Type                     string             `json:"type,omitempty"`
	Role                     string             `json:"role,omitempty"`
	Status                   string             `json:"status,omitempty"`
	Content                  json.RawMessage    `json:"content,omitempty"`
	ID                       string             `json:"id,omitempty"`
	Input                    string             `json:"input,omitempty"`
	CallID                   string             `json:"call_id,omitempty"`
	Name                     string             `json:"name,omitempty"`
	Arguments                json.RawMessage    `json:"arguments,omitempty"`
	Output                   json.RawMessage    `json:"output,omitempty"`
	Action                   json.RawMessage    `json:"action,omitempty"`
	Actions                  json.RawMessage    `json:"actions,omitempty"`
	PendingSafetyChecks      []CodexSafetyCheck `json:"pending_safety_checks,omitempty"`
	AcknowledgedSafetyChecks []CodexSafetyCheck `json:"acknowledged_safety_checks,omitempty"`
	EncryptedContent         string             `json:"encrypted_content,omitempty"`
	Result                   string             `json:"result,omitempty"`
	RevisedPrompt            string             `json:"revised_prompt,omitempty"`
	Phase                    string             `json:"phase,omitempty"`
	CreatedBy                string             `json:"created_by,omitempty"`
	Tools                    []CodexTool        `json:"tools,omitempty"`
}

func (item *CodexInputItem) UnmarshalJSON(data []byte) error {
	*item = CodexInputItem{}
	value := bytes.TrimSpace(data)
	if len(value) == 0 || value[0] != '{' {
		return fmt.Errorf("private input item must be a JSON object")
	}
	type inputItem CodexInputItem
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
			return fmt.Errorf("decode private input item: multiple JSON values")
		}
		return fmt.Errorf("decode private input item: %w", err)
	}
	if wire.PendingSafetyChecks != nil {
		checks, err := decodeCodexSafetyChecks(wire.PendingSafetyChecks, "decode private input item pending_safety_checks")
		if err != nil {
			return err
		}
		item.PendingSafetyChecks = checks
	}
	if wire.AcknowledgedSafetyChecks != nil {
		checks, err := decodeCodexSafetyChecks(wire.AcknowledgedSafetyChecks, "decode private input item acknowledged_safety_checks")
		if err != nil {
			return err
		}
		item.AcknowledgedSafetyChecks = checks
	}
	if wire.Tools != nil {
		tools, err := decodeCodexTools(wire.Tools, "decode private input item tools")
		if err != nil {
			return err
		}
		item.Tools = tools
	}
	if err := decodeCodexInputItemField(item.Content, "decode private input item content", false); err != nil {
		return err
	}
	if err := decodeCodexInputItemField(item.Output, "decode private input item output", true); err != nil {
		return err
	}
	return nil
}

func decodeCodexInputContentParts(data []byte, field string) ([]CodexInputContent, error) {
	parts := make([]CodexInputContent, 0)
	err := decodeCodexArray(data, field, "content parts", maxCodexContentParts,
		func(decoder *json.Decoder, index int) error {
			var part CodexInputContent
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

func decodeCodexInputItemField(data []byte, field string, allowObject bool) error {
	value := bytes.TrimSpace(data)
	if len(value) == 0 || bytes.Equal(value, []byte("null")) {
		return nil
	}
	switch value[0] {
	case '"':
		var text string
		return decodeCodexJSONValue(value, &text, field)
	case '[':
		_, err := decodeCodexInputContentParts(value, field)
		return err
	case '{':
		if !allowObject {
			return fmt.Errorf("%s: must be a string or array", field)
		}
		var content CodexInputContent
		return decodeCodexJSONValue(value, &content, field)
	default:
		if allowObject {
			return fmt.Errorf("%s: must be a string, object, or array", field)
		}
		return fmt.Errorf("%s: must be a string or array", field)
	}
}

func decodeCodexJSONValue(data []byte, target any, field string) error {
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

// CodexInputContent is one private Responses input content part.
type CodexInputContent struct {
	Type        string             `json:"type"`
	Text        string             `json:"text,omitempty"`
	Refusal     string             `json:"refusal,omitempty"`
	ImageURL    string             `json:"image_url,omitempty"`
	FileID      string             `json:"file_id,omitempty"`
	FileData    string             `json:"file_data,omitempty"`
	FileURL     string             `json:"file_url,omitempty"`
	Filename    string             `json:"filename,omitempty"`
	Detail      string             `json:"detail,omitempty"`
	Annotations []json.RawMessage  `json:"annotations,omitempty"`
	Logprobs    []CodexTextLogprob `json:"logprobs,omitempty"`
}

// CodexTool describes a private Responses tool.
type CodexTool struct {
	Type              string               `json:"type"`
	Name              string               `json:"name,omitempty"`
	Description       string               `json:"description,omitempty"`
	Strict            *bool                `json:"strict,omitempty"`
	Parameters        json.RawMessage      `json:"parameters,omitempty"`
	Action            string               `json:"action,omitempty"`
	Background        string               `json:"background,omitempty"`
	InputFidelity     string               `json:"input_fidelity,omitempty"`
	InputImageMask    *CodexInputImageMask `json:"input_image_mask,omitempty"`
	Model             string               `json:"model,omitempty"`
	Moderation        string               `json:"moderation,omitempty"`
	OutputCompression int                  `json:"output_compression,omitempty"`
	OutputFormat      string               `json:"output_format,omitempty"`
	PartialImages     int                  `json:"partial_images,omitempty"`
	Quality           string               `json:"quality,omitempty"`
	Size              string               `json:"size,omitempty"`
	Tools             []CodexTool          `json:"tools,omitempty"`
}

func (tool *CodexTool) UnmarshalJSON(data []byte) error {
	return decodeCodexTool(data, tool, 0)
}

func decodeCodexTool(data []byte, tool *CodexTool, depth int) error {
	if depth > 1 {
		return fmt.Errorf("private namespace tool nesting exceeds one level")
	}
	*tool = CodexTool{}
	type toolFields CodexTool
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
			return fmt.Errorf("decode private tool: multiple JSON values")
		}
		return fmt.Errorf("decode private tool: %w", err)
	}
	if wire.Tools != nil {
		if tool.Type != "namespace" {
			return fmt.Errorf("private tool tools is only valid for namespace tools")
		}
		if depth >= 1 {
			return fmt.Errorf("private namespace tool nesting exceeds one level")
		}
		tools, err := decodeCodexToolsAtDepth(wire.Tools, "decode private namespace tools", depth+1)
		if err != nil {
			return err
		}
		tool.Tools = tools
	}
	return nil
}
func decodeCodexTools(data []byte, field string) ([]CodexTool, error) {
	return decodeCodexToolsAtDepth(data, field, 0)
}

func decodeCodexToolsAtDepth(data []byte, field string, depth int) ([]CodexTool, error) {
	tools := make([]CodexTool, 0)
	err := decodeCodexArray(data, field, "tools", maxCodexItemTools,
		func(decoder *json.Decoder, index int) error {
			var raw json.RawMessage
			if err := decoder.Decode(&raw); err != nil {
				return err
			}
			var tool CodexTool
			if err := decodeCodexTool(raw, &tool, depth); err != nil {
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

func decodeCodexSafetyChecks(data []byte, field string) ([]CodexSafetyCheck, error) {
	checks := make([]CodexSafetyCheck, 0)
	err := decodeCodexArray(data, field, "safety checks", maxCodexSafetyChecks,
		func(decoder *json.Decoder, index int) error {
			var check CodexSafetyCheck
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

func decodeCodexInclude(data []byte, field string) ([]string, error) {
	include := make([]string, 0)
	err := decodeCodexArray(data, field, "include entries", maxCodexInclude,
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

func decodeCodexMetadata(data []byte, field string) (map[string]string, error) {
	value := bytes.TrimSpace(data)
	if len(value) == 0 {
		return nil, fmt.Errorf("%s: empty JSON value", field)
	}
	if bytes.Equal(value, []byte("null")) {
		return nil, nil
	}
	decoder := json.NewDecoder(bytes.NewReader(value))
	decoder.DisallowUnknownFields()
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
		if index >= maxCodexMetadata {
			return nil, fmt.Errorf("%s: too many metadata entries (maximum %d)", field, maxCodexMetadata)
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

// CodexToolChoice selects a private Responses tool as a string or object.
type CodexToolChoice struct {
	String *string `json:"-"`
	Type   string  `json:"type"`
	Name   string  `json:"name,omitempty"`
}

func (choice CodexToolChoice) MarshalJSON() ([]byte, error) {
	if choice.String != nil {
		if choice.Type != "" || choice.Name != "" {
			return nil, fmt.Errorf("private tool choice contains multiple variants")
		}
		return json.Marshal(*choice.String)
	}
	if choice.Type == "" {
		return nil, fmt.Errorf("private tool choice object requires type")
	}
	return json.Marshal(struct {
		Type string `json:"type"`
		Name string `json:"name,omitempty"`
	}{Type: choice.Type, Name: choice.Name})
}

func (choice *CodexToolChoice) UnmarshalJSON(data []byte) error {
	value := bytes.TrimSpace(data)
	if len(value) == 0 || bytes.Equal(value, []byte("null")) {
		return fmt.Errorf("private tool choice must be a string or object")
	}
	switch value[0] {
	case '"':
		var text string
		if err := json.Unmarshal(value, &text); err != nil {
			return fmt.Errorf("decode private tool choice string: %w", err)
		}
		*choice = CodexToolChoice{String: &text}
		return nil
	case '{':
		var object struct {
			Type string `json:"type"`
			Name string `json:"name,omitempty"`
		}
		decoder := json.NewDecoder(bytes.NewReader(value))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&object); err != nil {
			return fmt.Errorf("decode private tool choice object: %w", err)
		}
		var extra json.RawMessage
		if err := decoder.Decode(&extra); err != io.EOF {
			if err == nil {
				return fmt.Errorf("decode private tool choice object: multiple JSON values")
			}
			return fmt.Errorf("decode private tool choice object: %w", err)
		}
		if object.Type == "" {
			return fmt.Errorf("decode private tool choice object: type is required")
		}
		*choice = CodexToolChoice{Type: object.Type, Name: object.Name}
		return nil
	default:
		return fmt.Errorf("private tool choice must be a string or object")
	}
}

// CodexReasoningConfig carries the private reasoning options used by Codex.
type CodexReasoningConfig struct {
	Effort  string `json:"effort,omitempty"`
	Summary string `json:"summary,omitempty"`
	Context string `json:"context,omitempty"`
}

// CodexTextConfig carries private text output options.
type CodexTextConfig struct {
	Verbosity string           `json:"verbosity,omitempty"`
	Format    *CodexTextFormat `json:"format,omitempty"`
}

// CodexTextFormat is the flattened Responses text.format object.
type CodexTextFormat struct {
	Type        string          `json:"type"`
	Name        string          `json:"name,omitempty"`
	Description string          `json:"description,omitempty"`
	Schema      json.RawMessage `json:"schema,omitempty"`
	Strict      *bool           `json:"strict,omitempty"`
}

// CodexResponse is a private Responses result.
type CodexResponse struct {
	ID                 string                  `json:"id,omitempty"`
	Object             string                  `json:"object,omitempty"`
	CreatedAt          int64                   `json:"created_at,omitempty"`
	CompletedAt        int64                   `json:"completed_at,omitempty"`
	Model              string                  `json:"model,omitempty"`
	Status             string                  `json:"status,omitempty"`
	OutputText         string                  `json:"output_text,omitempty"`
	Output             []CodexOutputItem       `json:"output,omitempty"`
	Usage              *CodexUsage             `json:"usage,omitempty"`
	Error              *CodexError             `json:"error,omitempty"`
	IncompleteDetails  *CodexIncompleteDetails `json:"incomplete_details,omitempty"`
	ServiceTier        string                  `json:"service_tier,omitempty"`
	PreviousResponseID string                  `json:"previous_response_id,omitempty"`
	EndTurn            *bool                   `json:"end_turn,omitempty"`
}

// CodexCompactResult is the typed private Responses compact result.
type CodexCompactResult CodexResponse

func (result *CodexCompactResult) UnmarshalJSON(data []byte) error {
	if len(data) > maxCodexContractBytes {
		return fmt.Errorf("decode private compact result: body exceeds %d bytes", maxCodexContractBytes)
	}
	*result = CodexCompactResult{}
	type compactResult CodexResponse
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode((*compactResult)(result)); err != nil {
		return fmt.Errorf("decode private compact result: %w", err)
	}
	if result.Output == nil {
		return errors.New("decode private compact result: output is required")
	}
	if len(result.Output) > maxCodexInputItems {
		return fmt.Errorf("decode private compact result: output exceeds %d items", maxCodexInputItems)
	}
	var extra json.RawMessage
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return errors.New("decode private compact result: multiple JSON values")
		}
		return fmt.Errorf("decode private compact result: %w", err)
	}
	return nil
}

// CodexOutputItem is a typed private output item.
type CodexOutputItem struct {
	ID                       string             `json:"id,omitempty"`
	Type                     string             `json:"type"`
	Role                     string             `json:"role,omitempty"`
	Status                   string             `json:"status,omitempty"`
	Content                  []CodexContentPart `json:"content,omitempty"`
	CallID                   string             `json:"call_id,omitempty"`
	Name                     string             `json:"name,omitempty"`
	Arguments                string             `json:"arguments,omitempty"`
	Input                    string             `json:"input,omitempty"`
	Output                   json.RawMessage    `json:"output,omitempty"`
	Result                   string             `json:"result,omitempty"`
	RevisedPrompt            string             `json:"revised_prompt,omitempty"`
	Action                   json.RawMessage    `json:"action,omitempty"`
	Actions                  json.RawMessage    `json:"actions,omitempty"`
	PendingSafetyChecks      []CodexSafetyCheck `json:"pending_safety_checks,omitempty"`
	AcknowledgedSafetyChecks []CodexSafetyCheck `json:"acknowledged_safety_checks,omitempty"`
	EncryptedContent         string             `json:"encrypted_content,omitempty"`
	CreatedBy                string             `json:"created_by,omitempty"`
	Phase                    string             `json:"phase,omitempty"`
}

// CodexContentPart is one private Responses message content part.
type CodexContentPart struct {
	Type        string             `json:"type"`
	Text        string             `json:"text,omitempty"`
	Refusal     string             `json:"refusal,omitempty"`
	ImageURL    string             `json:"image_url,omitempty"`
	FileID      string             `json:"file_id,omitempty"`
	FileData    string             `json:"file_data,omitempty"`
	FileURL     string             `json:"file_url,omitempty"`
	Filename    string             `json:"filename,omitempty"`
	Detail      string             `json:"detail,omitempty"`
	Annotations []json.RawMessage  `json:"annotations,omitempty"`
	Logprobs    []CodexTextLogprob `json:"logprobs,omitempty"`
}

func (part *CodexContentPart) UnmarshalJSON(data []byte) error {
	*part = CodexContentPart{}
	value := bytes.TrimSpace(data)
	if len(value) == 0 || value[0] != '{' {
		return errors.New("private output content part must be a JSON object")
	}
	type contentPart CodexContentPart
	decoder := json.NewDecoder(bytes.NewReader(value))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode((*contentPart)(part)); err != nil {
		return fmt.Errorf("decode private output content part: %w", err)
	}
	var extra json.RawMessage
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return errors.New("decode private output content part: multiple JSON values")
		}
		return fmt.Errorf("decode private output content part: %w", err)
	}
	return nil
}

// CodexIncompleteDetails explains why a response stopped early.
type CodexIncompleteDetails struct {
	Reason string `json:"reason,omitempty"`
}

// CodexResponseStreamEvent is one private SSE or WebSocket event.
type CodexResponseStreamEvent struct {
	Type              string             `json:"type"`
	SequenceNumber    int                `json:"sequence_number"`
	Response          *CodexResponse     `json:"response,omitempty"`
	Item              *CodexOutputItem   `json:"item,omitempty"`
	Part              *CodexContentPart  `json:"part,omitempty"`
	Error             *CodexError        `json:"error,omitempty"`
	Delta             string             `json:"delta,omitempty"`
	Arguments         string             `json:"arguments,omitempty"`
	Text              string             `json:"text,omitempty"`
	Logprobs          []CodexTextLogprob `json:"logprobs,omitempty"`
	Code              string             `json:"code,omitempty"`
	Message           string             `json:"message,omitempty"`
	Param             string             `json:"param,omitempty"`
	ItemID            string             `json:"item_id,omitempty"`
	OutputIndex       int                `json:"output_index"`
	ContentIndex      int                `json:"content_index"`
	SummaryIndex      int                `json:"summary_index"`
	PartialImageB64   string             `json:"partial_image_b64,omitempty"`
	PartialImageIndex int                `json:"partial_image_index"`
	Headers           map[string]string  `json:"headers,omitempty"`
	Metadata          json.RawMessage    `json:"metadata,omitempty"`
	Annotation        json.RawMessage    `json:"annotation,omitempty"`
	Raw               json.RawMessage    `json:"-"`
}

// CodexUsage records token counts reported by Codex.
type CodexUsage struct {
	InputTokens          int                      `json:"input_tokens,omitempty"`
	OutputTokens         int                      `json:"output_tokens,omitempty"`
	TotalTokens          int                      `json:"total_tokens,omitempty"`
	PromptCacheHitTokens int                      `json:"prompt_cache_hit_tokens,omitempty"`
	InputTokensDetails   *CodexInputTokenDetails  `json:"input_tokens_details,omitempty"`
	OutputTokensDetails  *CodexOutputTokenDetails `json:"output_tokens_details,omitempty"`
}

// CodexInputTokenDetails gives the private input token breakdown.
type CodexInputTokenDetails struct {
	CachedTokens                   int `json:"cached_tokens,omitempty"`
	CacheWriteTokens               int `json:"cache_write_tokens,omitempty"`
	OrchestrationInputTokens       int `json:"orchestration_input_tokens,omitempty"`
	OrchestrationInputCachedTokens int `json:"orchestration_input_cached_tokens,omitempty"`
	ImageTokens                    int `json:"image_tokens,omitempty"`
	TextTokens                     int `json:"text_tokens,omitempty"`
}

// CodexOutputTokenDetails gives the private output token breakdown.
type CodexOutputTokenDetails struct {
	ReasoningTokens           int `json:"reasoning_tokens,omitempty"`
	OrchestrationOutputTokens int `json:"orchestration_output_tokens,omitempty"`
	ImageTokens               int `json:"image_tokens,omitempty"`
	TextTokens                int `json:"text_tokens,omitempty"`
}

// CodexError is a private provider error object.
type CodexError struct {
	Code       string  `json:"code,omitempty"`
	Type       string  `json:"type,omitempty"`
	Message    string  `json:"message,omitempty"`
	PlanType   string  `json:"plan_type,omitempty"`
	RetryAfter float64 `json:"retry_after,omitempty"`
	ResetsAt   int64   `json:"resets_at,omitempty"`
}

// CodexErrorEnvelope is a private HTTP or WebSocket error response.
type CodexErrorEnvelope struct {
	Type       string                     `json:"type,omitempty"`
	Status     int                        `json:"status,omitempty"`
	StatusCode int                        `json:"status_code,omitempty"`
	Code       string                     `json:"code,omitempty"`
	Message    string                     `json:"message,omitempty"`
	RetryAfter float64                    `json:"retry_after,omitempty"`
	ResetsAt   int64                      `json:"resets_at,omitempty"`
	Error      *CodexError                `json:"error,omitempty"`
	Headers    map[string]json.RawMessage `json:"headers,omitempty"`
}

// CodexImageGenerationRequest is the exact private generation request body.
type CodexImageGenerationRequest struct {
	Model             string `json:"model"`
	Prompt            string `json:"prompt"`
	N                 *int   `json:"n,omitempty"`
	Size              string `json:"size,omitempty"`
	Quality           string `json:"quality,omitempty"`
	Background        string `json:"background,omitempty"`
	OutputCompression *int   `json:"output_compression,omitempty"`
	OutputFormat      string `json:"output_format,omitempty"`
	Moderation        string `json:"moderation,omitempty"`
	User              string `json:"user,omitempty"`
}

// CodexImageEditRequest is the exact private edit request body.
type CodexImageEditRequest struct {
	Model             string                `json:"model"`
	Prompt            string                `json:"prompt"`
	Images            []CodexImageEditInput `json:"images"`
	N                 *int                  `json:"n,omitempty"`
	Size              string                `json:"size,omitempty"`
	Quality           string                `json:"quality,omitempty"`
	Background        string                `json:"background,omitempty"`
	OutputCompression *int                  `json:"output_compression,omitempty"`
	OutputFormat      string                `json:"output_format,omitempty"`
	User              string                `json:"user,omitempty"`
}

// CodexImageEditInput is one image_url object in a private edit request.
type CodexImageEditInput struct {
	ImageURL string `json:"image_url"`
}

// CodexImageResponse is a private direct Images result.
type CodexImageResponse struct {
	Created      *uint64          `json:"created"`
	Background   string           `json:"background,omitempty"`
	Data         []CodexImageData `json:"data"`
	OutputFormat string           `json:"output_format,omitempty"`
	Quality      string           `json:"quality,omitempty"`
	Size         string           `json:"size,omitempty"`
	Usage        *CodexUsage      `json:"usage,omitempty"`
}

// CodexImageData is one private image result.
type CodexImageData struct {
	B64JSON       string `json:"b64_json,omitempty"`
	URL           string `json:"url,omitempty"`
	RevisedPrompt string `json:"revised_prompt,omitempty"`
}

// CodexRefreshFailure is the typed permanent refresh response.
type CodexRefreshFailure struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description,omitempty"`
	ErrorURI         string `json:"error_uri,omitempty"`
	Status           int    `json:"status,omitempty"`
}

// IsPermanent reports whether a structured refresh error requires a new login.
func (failure CodexRefreshFailure) IsPermanent() bool {
	switch strings.ToLower(strings.TrimSpace(failure.Error)) {
	case "invalid_client", "invalid_grant", "invalid_token", "unauthorized_client",
		"refresh_token_expired", "refresh_token_reused", "refresh_token_invalidated":
		return true
	default:
		return false
	}
}

// CodexStreamResult is the validated result of one private stream.
type CodexStreamResult struct {
	Events       []CodexResponseStreamEvent
	TerminalType string
	Response     *CodexResponse
}

// ErrCodexStreamAbruptClose means that a stream ended without a terminal event.
var ErrCodexStreamAbruptClose = errors.New("codex stream ended before terminal event")

// ErrCodexStreamDuplicateTerminal means that a stream sent two terminal events.
var ErrCodexStreamDuplicateTerminal = errors.New("codex stream sent duplicate terminal event")

// ErrCodexStreamMalformed means that a stream event or line is invalid or exceeds a stream bound.
var ErrCodexStreamMalformed = errors.New("codex stream event is malformed")

// ErrCodexStreamFailed means that Codex sent a failed terminal event.
var ErrCodexStreamFailed = errors.New("codex stream failed")

// CodexStreamFailureError keeps only safe failure classification fields.
type CodexStreamFailureError struct {
	Category string
	Status   string
	Code     string
}

func (e *CodexStreamFailureError) Error() string {
	return "codex stream failed"
}

func (e *CodexStreamFailureError) Unwrap() error {
	return ErrCodexStreamFailed
}

// ParseCodexResponsesSSE parses one Responses SSE body and requires one terminal event.
func ParseCodexResponsesSSE(reader io.Reader) (CodexStreamResult, error) {
	return parseCodexResponsesSSE(reader, nil)
}

func parseCodexResponsesSSE(reader io.Reader, onEvent func(CodexResponseStreamEvent) error) (CodexStreamResult, error) {
	if reader == nil {
		return CodexStreamResult{}, fmt.Errorf("parse Codex SSE: reader is nil")
	}

	var decoder codexStreamDecoder
	stream := bufio.NewReaderSize(reader, maxCodexStreamLineBytes+1)
	var data bytes.Buffer
	snapshot := func() CodexStreamResult {
		return CodexStreamResult{
			Events:       decoder.events,
			TerminalType: decoder.terminalType,
			Response:     decoder.response,
		}
	}
	flush := func() error {
		if data.Len() == 0 {
			return nil
		}
		payload := bytes.TrimSpace(data.Bytes())
		if bytes.Equal(payload, []byte("[DONE]")) {
			data.Reset()
			if decoder.doneSeen {
				return ErrCodexStreamDuplicateTerminal
			}
			if decoder.terminalType == "" {
				return fmt.Errorf("%w: upstream [DONE] arrived before terminal event", ErrCodexStreamMalformed)
			}
			decoder.doneSeen = true
			return nil
		}
		if decoder.doneSeen {
			return ErrCodexStreamDuplicateTerminal
		}
		var event CodexResponseStreamEvent
		if err := json.Unmarshal(payload, &event); err != nil {
			return fmt.Errorf("%w: decode SSE event: %v", ErrCodexStreamMalformed, err)
		}
		if err := decoder.reservePayload(len(payload)); err != nil {
			return err
		}
		event.Raw = append(event.Raw[:0], payload...)
		if err := decoder.add(event); err != nil {
			return err
		}
		data.Reset()
		if onEvent != nil {
			if err := onEvent(event); err != nil {
				return err
			}
		}
		return nil
	}
	consumeLine := func(line []byte) error {
		if decoder.doneSeen && len(line) > 0 && !bytes.HasPrefix(line, []byte(":")) {
			return ErrCodexStreamDuplicateTerminal
		}
		switch {
		case len(line) == 0:
			return flush()
		case bytes.HasPrefix(line, []byte("data:")):
			value := bytes.TrimPrefix(line, []byte("data:"))
			value = bytes.TrimPrefix(value, []byte(" "))
			additional := len(value)
			if data.Len() > 0 {
				additional++
			}
			if additional > maxCodexStreamLineBytes || data.Len() > maxCodexStreamLineBytes-additional {
				return fmt.Errorf("%w: data field is too large", ErrCodexStreamMalformed)
			}
			if data.Len() > 0 {
				data.WriteByte('\n')
			}
			data.Write(value)
		}
		return nil
	}

	for {
		line, isPrefix, err := stream.ReadLine()
		if isPrefix || len(line) > maxCodexStreamLineBytes {
			return snapshot(), fmt.Errorf("%w: SSE line is too large", ErrCodexStreamMalformed)
		}
		if err != nil && !errors.Is(err, io.EOF) {
			return snapshot(), fmt.Errorf("read Codex SSE: %w", err)
		}
		if len(line) > 0 || err == nil {
			if consumeErr := consumeLine(line); consumeErr != nil {
				return snapshot(), consumeErr
			}
		}
		if errors.Is(err, io.EOF) {
			break
		}
	}
	if err := flush(); err != nil {
		return snapshot(), err
	}
	return decoder.finish()
}

// DecodeCodexWebSocketFrame decodes one JSON WebSocket frame.
func DecodeCodexWebSocketFrame(frame []byte) (CodexResponseStreamEvent, error) {
	if len(frame) == 0 || len(frame) > maxCodexStreamLineBytes {
		return CodexResponseStreamEvent{}, fmt.Errorf("%w: WebSocket frame size is invalid", ErrCodexStreamMalformed)
	}
	var header struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(frame, &header); err != nil {
		return CodexResponseStreamEvent{}, fmt.Errorf("%w: decode WebSocket frame: %v", ErrCodexStreamMalformed, err)
	}
	if strings.TrimSpace(header.Type) == "" {
		return CodexResponseStreamEvent{}, fmt.Errorf("%w: event type is empty", ErrCodexStreamMalformed)
	}
	if header.Type == CodexEventError {
		return decodeCodexErrorEvent(frame)
	}
	var event CodexResponseStreamEvent
	if err := json.Unmarshal(frame, &event); err != nil {
		return CodexResponseStreamEvent{}, fmt.Errorf("%w: decode WebSocket frame: %v", ErrCodexStreamMalformed, err)
	}
	event.Raw = append(event.Raw[:0], frame...)
	return event, nil
}

// ParseCodexWebSocketFrames validates one sequence of JSON WebSocket frames.
func ParseCodexWebSocketFrames(frames [][]byte) (CodexStreamResult, error) {
	var decoder codexStreamDecoder
	for index, frame := range frames {
		if len(frame) == 0 || len(frame) > maxCodexStreamLineBytes {
			return CodexStreamResult{}, fmt.Errorf(
				"decode Codex WebSocket frame %d: %w: WebSocket frame size is invalid",
				index,
				ErrCodexStreamMalformed,
			)
		}
		if err := decoder.reservePayload(len(frame)); err != nil {
			return CodexStreamResult{}, fmt.Errorf("decode Codex WebSocket frame %d: %w", index, err)
		}
		event, err := DecodeCodexWebSocketFrame(frame)
		if err != nil {
			return CodexStreamResult{}, fmt.Errorf("decode Codex WebSocket frame %d: %w", index, err)
		}
		if err := decoder.add(event); err != nil {
			return CodexStreamResult{}, fmt.Errorf("process Codex WebSocket frame %d: %w", index, err)
		}
	}
	return decoder.finish()
}

type codexStreamDecoder struct {
	events       []CodexResponseStreamEvent
	terminalType string
	response     *CodexResponse
	failed       bool
	code         string
	doneSeen     bool
	payloadBytes int
}

func (decoder *codexStreamDecoder) reservePayload(payloadBytes int) error {
	if payloadBytes < 0 || decoder.payloadBytes > maxCodexStreamPayloadBytes-payloadBytes {
		return fmt.Errorf("%w: decoded payload exceeds limit", ErrCodexStreamMalformed)
	}
	decoder.payloadBytes += payloadBytes
	return nil
}

func (decoder *codexStreamDecoder) add(event CodexResponseStreamEvent) error {
	if strings.TrimSpace(event.Type) == "" {
		return fmt.Errorf("%w: event type is empty", ErrCodexStreamMalformed)
	}
	if decoder.terminalType != "" {
		return ErrCodexStreamDuplicateTerminal
	}
	if len(decoder.events) >= maxCodexStreamEvents {
		return fmt.Errorf("%w: event count exceeds limit", ErrCodexStreamMalformed)
	}
	if isCodexResponseTerminalEvent(event.Type) && event.Response == nil {
		return fmt.Errorf("%w: terminal event response is missing", ErrCodexStreamMalformed)
	}
	decoder.events = append(decoder.events, event)
	decoder.failed = decoder.failed || event.Error != nil ||
		(event.Response != nil && event.Response.Error != nil)
	if isCodexTerminalEvent(event.Type) {
		if event.Code != "" {
			decoder.code = event.Code
		} else if event.Error != nil {
			decoder.code = event.Error.Code
		} else if event.Response != nil && event.Response.Error != nil {
			decoder.code = event.Response.Error.Code
		}
	}
	if !isCodexTerminalEvent(event.Type) {
		return nil
	}
	decoder.terminalType = event.Type
	decoder.response = event.Response
	decoder.failed = decoder.failed || event.Type == CodexEventResponseFailed || event.Type == CodexEventError ||
		(event.Response != nil && event.Response.Status == CodexResponseStatusFailed)
	return nil
}

func (decoder *codexStreamDecoder) finish() (CodexStreamResult, error) {
	result := CodexStreamResult{
		Events:       decoder.events,
		TerminalType: decoder.terminalType,
		Response:     decoder.response,
	}
	if decoder.terminalType == "" {
		return result, ErrCodexStreamAbruptClose
	}
	if decoder.failed {
		category := "failed"
		switch decoder.terminalType {
		case CodexEventResponseFailed:
			category = "response_failed"
		case CodexEventError:
			category = "error"
		}
		status := ""
		if decoder.response != nil {
			switch decoder.response.Status {
			case CodexResponseStatusCompleted, CodexResponseStatusFailed, CodexResponseStatusIncomplete,
				CodexResponseStatusInProgress:
				status = decoder.response.Status
			}
		}
		return result, &CodexStreamFailureError{Category: category, Status: status, Code: decoder.code}
	}
	return result, nil
}

func isCodexResponseTerminalEvent(eventType string) bool {
	switch eventType {
	case CodexEventResponseCompleted, CodexEventResponseDone, CodexEventResponseIncomplete, CodexEventResponseFailed:
		return true
	default:
		return false
	}
}

func isCodexTerminalEvent(eventType string) bool {
	switch eventType {
	case CodexEventResponseCompleted, CodexEventResponseDone, CodexEventResponseIncomplete,
		CodexEventResponseFailed, CodexEventError:
		return true
	default:
		return false
	}
}
