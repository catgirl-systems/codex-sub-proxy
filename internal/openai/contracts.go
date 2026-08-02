package openai

import "encoding/json"

const (
	// Responses event names used by the public wire contract.
	EventResponseCreated         = "response.created"
	EventResponseOutputItemAdded = "response.output_item.added"
	EventResponseOutputItemDone  = "response.output_item.done"
	EventContentPartAdded        = "response.content_part.added"
	EventOutputTextDelta         = "response.output_text.delta"
	EventCompleted               = "response.completed"
	EventDone                    = "response.done"
	EventIncomplete              = "response.incomplete"
	EventFailed                  = "response.failed"
	EventError                   = "error"
	ImageGenerationCall          = "image_generation_call"
	ToolChoiceImageGeneration    = "image_generation"

	ResponseStatusCompleted  = "completed"
	ResponseStatusFailed     = "failed"
	ResponseStatusIncomplete = "incomplete"
)

// ResponseRequest is the public OpenAI Responses request body.
type ResponseRequest struct {
	Model              string           `json:"model"`
	Input              []InputItem      `json:"input,omitempty"`
	Instructions       string           `json:"instructions,omitempty"`
	Tools              []Tool           `json:"tools,omitempty"`
	ToolChoice         *ToolChoice      `json:"tool_choice,omitempty"`
	Store              bool             `json:"store,omitempty"`
	Stream             bool             `json:"stream,omitempty"`
	ParallelToolCalls  bool             `json:"parallel_tool_calls,omitempty"`
	PreviousResponseID string           `json:"previous_response_id,omitempty"`
	Reasoning          *ReasoningConfig `json:"reasoning,omitempty"`
	Text               *TextConfig      `json:"text,omitempty"`
}

// InputItem is one public Responses input item.
type InputItem struct {
	Type      string         `json:"type,omitempty"`
	Role      string         `json:"role,omitempty"`
	Content   []InputContent `json:"content,omitempty"`
	ID        string         `json:"id,omitempty"`
	CallID    string         `json:"call_id,omitempty"`
	Name      string         `json:"name,omitempty"`
	Arguments string         `json:"arguments,omitempty"`
	Output    string         `json:"output,omitempty"`
}

// InputContent is one public input content part.
type InputContent struct {
	Type     string `json:"type"`
	Text     string `json:"text,omitempty"`
	ImageURL string `json:"image_url,omitempty"`
	Detail   string `json:"detail,omitempty"`
}

// Tool describes a public Responses tool.
type Tool struct {
	Type         string          `json:"type"`
	Parameters   json.RawMessage `json:"parameters,omitempty"`
	Description  string          `json:"description,omitempty"`
	Action       string          `json:"action,omitempty"`
	OutputFormat string          `json:"output_format,omitempty"`
	Size         string          `json:"size,omitempty"`
}

// ToolChoice selects a public Responses tool.
type ToolChoice struct {
	Type string `json:"type"`
	Name string `json:"name,omitempty"`
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
	Type     string `json:"type"`
	Text     string `json:"text,omitempty"`
	Refusal  string `json:"refusal,omitempty"`
	ImageURL string `json:"image_url,omitempty"`
	Detail   string `json:"detail,omitempty"`
}

// IncompleteDetails explains why a response stopped early.
type IncompleteDetails struct {
	Reason string `json:"reason,omitempty"`
}

// ResponseStreamEvent is one public Responses SSE event.
type ResponseStreamEvent struct {
	Type           string       `json:"type"`
	SequenceNumber int          `json:"sequence_number"`
	Response       *Response    `json:"response,omitempty"`
	Item           *OutputItem  `json:"item,omitempty"`
	Part           *ContentPart `json:"part,omitempty"`
	Error          *Error       `json:"error,omitempty"`
	Delta          string       `json:"delta,omitempty"`
	Text           string       `json:"text,omitempty"`
	Code           string       `json:"code,omitempty"`
	Message        string       `json:"message,omitempty"`
	ItemID         string       `json:"item_id,omitempty"`
	OutputIndex    int          `json:"output_index"`
	ContentIndex   int          `json:"content_index"`
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
