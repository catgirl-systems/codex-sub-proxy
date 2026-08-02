package openai

import (
	"bytes"
	"encoding/json"
	"fmt"
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

// ResponseRequest is the public OpenAI Responses request body.
type ResponseRequest struct {
	Model              string            `json:"model" validate:"required,max=256"`
	Input              *Input            `json:"input,omitempty"`
	Instructions       string            `json:"instructions,omitempty" validate:"max=65536"`
	Tools              []Tool            `json:"tools,omitempty" validate:"max=128"`
	ToolChoice         *ToolChoice       `json:"tool_choice,omitempty"`
	Store              *bool             `json:"store,omitempty"`
	Stream             bool              `json:"stream,omitempty"`
	ParallelToolCalls  *bool             `json:"parallel_tool_calls,omitempty"`
	PreviousResponseID string            `json:"previous_response_id,omitempty" validate:"max=256"`
	Reasoning          *ReasoningConfig  `json:"reasoning,omitempty"`
	Text               *TextConfig       `json:"text,omitempty"`
	MaxOutputTokens    *int              `json:"max_output_tokens,omitempty" validate:"omitempty,min=1"`
	Include            []string          `json:"include,omitempty" validate:"max=64,dive,max=128"`
	Metadata           map[string]string `json:"metadata,omitempty" validate:"max=16,dive,keys,max=64,endkeys,max=512"`
	PromptCacheKey     string            `json:"prompt_cache_key,omitempty" validate:"max=512"`
	ServiceTier        string            `json:"service_tier,omitempty" validate:"omitempty,oneof=auto default flex scale priority"`
}

func (request *ResponseRequest) UnmarshalJSON(data []byte) error {
	*request = ResponseRequest{}
	type responseRequest ResponseRequest
	wire := struct {
		*responseRequest
		Input      json.RawMessage `json:"input"`
		ToolChoice json.RawMessage `json:"tool_choice"`
	}{
		responseRequest: (*responseRequest)(request),
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&wire); err != nil {
		return err
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
	return nil
}

// Input is the public Responses input string-or-array union.
type Input struct {
	String *string     `json:"-"`
	Items  []InputItem `json:"-"`
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
		var items []InputItem
		if err := json.Unmarshal(value, &items); err != nil {
			return fmt.Errorf("decode public input array: %w", err)
		}
		*input = Input{Items: items}
		return nil
	default:
		return fmt.Errorf("public input must be a string or array")
	}
}

// InputItem is one public Responses input item. Content and output are
// polymorphic in the wire contract (a string or a typed content list).
type InputItem struct {
	Type      string          `json:"type,omitempty"`
	Role      string          `json:"role,omitempty"`
	Content   json.RawMessage `json:"content,omitempty"`
	ID        string          `json:"id,omitempty"`
	CallID    string          `json:"call_id,omitempty"`
	Name      string          `json:"name,omitempty"`
	Arguments string          `json:"arguments,omitempty"`
	Output    json.RawMessage `json:"output,omitempty"`
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
		if err := json.Unmarshal(value, &object); err != nil {
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
}

// TextConfig carries public text output options.
type TextConfig struct {
	Verbosity string `json:"verbosity,omitempty"`
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
	ID            string        `json:"id,omitempty"`
	Type          string        `json:"type"`
	Role          string        `json:"role,omitempty"`
	Status        string        `json:"status,omitempty"`
	Content       []ContentPart `json:"content,omitempty"`
	CallID        string        `json:"call_id,omitempty"`
	Name          string        `json:"name,omitempty"`
	Arguments     string        `json:"arguments,omitempty"`
	Input         string        `json:"input,omitempty"`
	Result        string        `json:"result,omitempty"`
	RevisedPrompt string        `json:"revised_prompt,omitempty"`
	Action        string        `json:"action,omitempty"`
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
}

// OutputTokenDetails gives the public output token breakdown.
type OutputTokenDetails struct {
	ReasoningTokens int `json:"reasoning_tokens,omitempty"`
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
	Model          string `json:"model"`
	Prompt         string `json:"prompt"`
	N              int    `json:"n,omitempty"`
	Size           string `json:"size,omitempty"`
	Quality        string `json:"quality,omitempty"`
	ResponseFormat string `json:"response_format,omitempty"`
	User           string `json:"user,omitempty"`
}

// ImageEditRequest is the JSON form used by the private image adapter after multipart decoding.
type ImageEditRequest struct {
	Model          string   `json:"model"`
	Prompt         string   `json:"prompt"`
	Images         []string `json:"images"`
	N              int      `json:"n,omitempty"`
	Size           string   `json:"size,omitempty"`
	Quality        string   `json:"quality,omitempty"`
	ResponseFormat string   `json:"response_format,omitempty"`
	User           string   `json:"user,omitempty"`
}

// ImageResponse is a public Images result.
type ImageResponse struct {
	Created int64       `json:"created"`
	Data    []ImageData `json:"data"`
}

// ImageData is one public image result.
type ImageData struct {
	B64JSON       string `json:"b64_json,omitempty"`
	URL           string `json:"url,omitempty"`
	RevisedPrompt string `json:"revised_prompt,omitempty"`
}
