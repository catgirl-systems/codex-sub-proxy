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
	CodexEventResponseCreated            = "response.created"
	CodexEventResponseOutputItemAdded    = "response.output_item.added"
	CodexEventResponseOutputItemDone     = "response.output_item.done"
	CodexEventResponseContentPartAdded   = "response.content_part.added"
	CodexEventResponseOutputTextDelta    = "response.output_text.delta"
	CodexEventResponseFunctionArgsDelta  = "response.function_call_arguments.delta"
	CodexEventResponseFunctionArgsDone   = "response.function_call_arguments.done"
	CodexEventResponseCompleted          = "response.completed"
	CodexEventResponseDone               = "response.done"
	CodexEventResponseIncomplete         = "response.incomplete"
	CodexEventResponseFailed             = "response.failed"
	CodexEventError                      = "error"
	CodexEventResponseMetadata           = "response.metadata"
	CodexResponseStatusCompleted         = "completed"
	CodexResponseStatusFailed            = "failed"
	CodexResponseStatusIncomplete        = "incomplete"
	CodexResponseStatusInProgress        = "in_progress"
	CodexIncompleteReasonMaxOutputTokens = "max_output_tokens"
	CodexIncompleteReasonContentFilter   = "content_filter"
	CodexImageGenerationCall             = "image_generation_call"
)

const maxCodexStreamLineBytes = 256 * 1024
const maxCodexStreamEvents = 8192

// CodexResponseRequest is the private request body for the Responses endpoint.
type CodexResponseRequest struct {
	Model              string                `json:"model"`
	Input              []CodexInputItem      `json:"input,omitempty"`
	Instructions       string                `json:"instructions,omitempty"`
	Tools              []CodexTool           `json:"tools,omitempty"`
	ToolChoice         *CodexToolChoice      `json:"tool_choice,omitempty"`
	Store              bool                  `json:"store,omitempty"`
	Stream             bool                  `json:"stream,omitempty"`
	ParallelToolCalls  bool                  `json:"parallel_tool_calls,omitempty"`
	ClientMetadata     map[string]string     `json:"client_metadata,omitempty"`
	PreviousResponseID string                `json:"previous_response_id,omitempty"`
	Reasoning          *CodexReasoningConfig `json:"reasoning,omitempty"`
	Text               *CodexTextConfig      `json:"text,omitempty"`
}

// CodexInputItem is one private Responses input item.
type CodexInputItem struct {
	Type      string              `json:"type,omitempty"`
	Role      string              `json:"role,omitempty"`
	Content   []CodexInputContent `json:"content,omitempty"`
	ID        string              `json:"id,omitempty"`
	CallID    string              `json:"call_id,omitempty"`
	Name      string              `json:"name,omitempty"`
	Arguments string              `json:"arguments,omitempty"`
	Output    string              `json:"output,omitempty"`
}

// CodexInputContent is one private input content part.
type CodexInputContent struct {
	Type     string `json:"type"`
	Text     string `json:"text,omitempty"`
	ImageURL string `json:"image_url,omitempty"`
	Detail   string `json:"detail,omitempty"`
}

// CodexTool describes a private Responses tool.
type CodexTool struct {
	Type         string          `json:"type"`
	Action       string          `json:"action,omitempty"`
	OutputFormat string          `json:"output_format,omitempty"`
	Size         string          `json:"size,omitempty"`
	Parameters   json.RawMessage `json:"parameters,omitempty"`
}

// CodexToolChoice selects a private Responses tool.
type CodexToolChoice struct {
	Type string `json:"type"`
}

// CodexReasoningConfig carries the private reasoning options used by Codex.
type CodexReasoningConfig struct {
	Effort  string `json:"effort,omitempty"`
	Summary string `json:"summary,omitempty"`
	Context string `json:"context,omitempty"`
}

// CodexTextConfig carries private text output options.
type CodexTextConfig struct {
	Verbosity string `json:"verbosity,omitempty"`
}

// CodexResponse is a private Responses result.
type CodexResponse struct {
	ID                string                  `json:"id,omitempty"`
	Object            string                  `json:"object,omitempty"`
	CreatedAt         int64                   `json:"created_at,omitempty"`
	Model             string                  `json:"model,omitempty"`
	Status            string                  `json:"status,omitempty"`
	OutputText        string                  `json:"output_text,omitempty"`
	Output            []CodexOutputItem       `json:"output,omitempty"`
	Usage             *CodexUsage             `json:"usage,omitempty"`
	Error             *CodexError             `json:"error,omitempty"`
	IncompleteDetails *CodexIncompleteDetails `json:"incomplete_details,omitempty"`
	ServiceTier       string                  `json:"service_tier,omitempty"`
	EndTurn           *bool                   `json:"end_turn,omitempty"`
}

// CodexOutputItem is a typed private output item.
type CodexOutputItem struct {
	ID            string             `json:"id,omitempty"`
	Type          string             `json:"type"`
	Role          string             `json:"role,omitempty"`
	Status        string             `json:"status,omitempty"`
	Content       []CodexContentPart `json:"content,omitempty"`
	CallID        string             `json:"call_id,omitempty"`
	Name          string             `json:"name,omitempty"`
	Arguments     string             `json:"arguments,omitempty"`
	Input         string             `json:"input,omitempty"`
	Result        string             `json:"result,omitempty"`
	RevisedPrompt string             `json:"revised_prompt,omitempty"`
	Action        string             `json:"action,omitempty"`
}

// CodexContentPart is a typed private output content part.
type CodexContentPart struct {
	Type     string `json:"type"`
	Text     string `json:"text,omitempty"`
	Refusal  string `json:"refusal,omitempty"`
	ImageURL string `json:"image_url,omitempty"`
	Detail   string `json:"detail,omitempty"`
}

// CodexIncompleteDetails explains why a response stopped early.
type CodexIncompleteDetails struct {
	Reason string `json:"reason,omitempty"`
}

// CodexResponseStreamEvent is one private SSE or WebSocket event.
type CodexResponseStreamEvent struct {
	Type         string            `json:"type"`
	Response     *CodexResponse    `json:"response,omitempty"`
	Item         *CodexOutputItem  `json:"item,omitempty"`
	Part         *CodexContentPart `json:"part,omitempty"`
	Error        *CodexError       `json:"error,omitempty"`
	Delta        string            `json:"delta,omitempty"`
	Text         string            `json:"text,omitempty"`
	Code         string            `json:"code,omitempty"`
	Message      string            `json:"message,omitempty"`
	ItemID       string            `json:"item_id,omitempty"`
	OutputIndex  int               `json:"output_index,omitempty"`
	SummaryIndex int               `json:"summary_index,omitempty"`
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
}

// CodexOutputTokenDetails gives the private output token breakdown.
type CodexOutputTokenDetails struct {
	ReasoningTokens           int `json:"reasoning_tokens,omitempty"`
	OrchestrationOutputTokens int `json:"orchestration_output_tokens,omitempty"`
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
	Type       string               `json:"type,omitempty"`
	Status     int                  `json:"status,omitempty"`
	Code       string               `json:"code,omitempty"`
	Message    string               `json:"message,omitempty"`
	RetryAfter float64              `json:"retry_after,omitempty"`
	ResetsAt   int64                `json:"resets_at,omitempty"`
	Error      *CodexError          `json:"error,omitempty"`
	Headers    *CodexRateLimitHeads `json:"headers,omitempty"`
}

// CodexRateLimitHeads contains the rate data in a wrapped WebSocket error.
type CodexRateLimitHeads struct {
	PrimaryUsedPercent     float64 `json:"x-codex-primary-used-percent,omitempty"`
	PrimaryWindowMinutes   int     `json:"x-codex-primary-window-minutes,omitempty"`
	PrimaryResetAt         int64   `json:"x-codex-primary-reset-at,omitempty"`
	SecondaryUsedPercent   float64 `json:"x-codex-secondary-used-percent,omitempty"`
	SecondaryWindowMinutes int     `json:"x-codex-secondary-window-minutes,omitempty"`
	SecondaryResetAt       int64   `json:"x-codex-secondary-reset-at,omitempty"`
}

// CodexImageRequest is a private direct Images request.
type CodexImageRequest struct {
	Model          string   `json:"model"`
	Prompt         string   `json:"prompt,omitempty"`
	N              int      `json:"n,omitempty"`
	Size           string   `json:"size,omitempty"`
	Quality        string   `json:"quality,omitempty"`
	ResponseFormat string   `json:"response_format,omitempty"`
	Image          string   `json:"image,omitempty"`
	Images         []string `json:"images,omitempty"`
}

// CodexImageResponse is a private direct Images result.
type CodexImageResponse struct {
	Created int64            `json:"created,omitempty"`
	Data    []CodexImageData `json:"data"`
	Usage   *CodexUsage      `json:"usage,omitempty"`
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

// IsPermanent reports whether a refresh failure requires a new login.
func (failure CodexRefreshFailure) IsPermanent() bool {
	switch strings.ToLower(strings.TrimSpace(failure.Error)) {
	case "invalid_grant", "invalid_token", "unauthorized_client", "refresh_token_expired", "refresh_token_reused", "refresh_token_invalidated":
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

// ErrCodexStreamMalformed means that a stream event is not valid JSON or has no type.
var ErrCodexStreamMalformed = errors.New("codex stream event is malformed")

// ErrCodexStreamFailed means that Codex sent a failed terminal event.
var ErrCodexStreamFailed = errors.New("codex stream failed")

// CodexStreamFailureError keeps a failed terminal event without exposing its message.
type CodexStreamFailureError struct {
	Event CodexResponseStreamEvent
}

func (e *CodexStreamFailureError) Error() string {
	return "codex stream failed"
}

func (e *CodexStreamFailureError) Unwrap() error {
	return ErrCodexStreamFailed
}

// ParseCodexResponsesSSE parses one Responses SSE body and requires one terminal event.
func ParseCodexResponsesSSE(reader io.Reader) (CodexStreamResult, error) {
	if reader == nil {
		return CodexStreamResult{}, fmt.Errorf("parse Codex SSE: reader is nil")
	}

	var decoder codexStreamDecoder
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 64*1024), maxCodexStreamLineBytes)
	var data bytes.Buffer
	flush := func() error {
		if data.Len() == 0 {
			return nil
		}
		payload := bytes.TrimSpace(data.Bytes())
		if bytes.Equal(payload, []byte("[DONE]")) {
			data.Reset()
			return nil
		}
		var event CodexResponseStreamEvent
		if err := json.Unmarshal(payload, &event); err != nil {
			return fmt.Errorf("%w: decode SSE event: %v", ErrCodexStreamMalformed, err)
		}
		if err := decoder.add(event); err != nil {
			return err
		}
		data.Reset()
		return nil
	}

	for scanner.Scan() {
		line := scanner.Bytes()
		switch {
		case len(line) == 0:
			if err := flush(); err != nil {
				return CodexStreamResult{}, err
			}
		case bytes.HasPrefix(line, []byte("data:")):
			value := bytes.TrimPrefix(line, []byte("data:"))
			value = bytes.TrimPrefix(value, []byte(" "))
			if data.Len() > 0 {
				data.WriteByte('\n')
			}
			if data.Len()+len(value) > maxCodexStreamLineBytes {
				return CodexStreamResult{}, fmt.Errorf("%w: data field is too large", ErrCodexStreamMalformed)
			}
			data.Write(value)
		}
	}
	if err := scanner.Err(); err != nil {
		return CodexStreamResult{}, fmt.Errorf("read Codex SSE: %w", err)
	}
	if err := flush(); err != nil {
		return CodexStreamResult{}, err
	}
	return decoder.finish()
}

// DecodeCodexWebSocketFrame decodes one JSON WebSocket frame.
func DecodeCodexWebSocketFrame(frame []byte) (CodexResponseStreamEvent, error) {
	if len(frame) == 0 || len(frame) > maxCodexStreamLineBytes {
		return CodexResponseStreamEvent{}, fmt.Errorf("%w: WebSocket frame size is invalid", ErrCodexStreamMalformed)
	}
	var event CodexResponseStreamEvent
	if err := json.Unmarshal(frame, &event); err != nil {
		return CodexResponseStreamEvent{}, fmt.Errorf("%w: decode WebSocket frame: %v", ErrCodexStreamMalformed, err)
	}
	if strings.TrimSpace(event.Type) == "" {
		return CodexResponseStreamEvent{}, fmt.Errorf("%w: event type is empty", ErrCodexStreamMalformed)
	}
	return event, nil
}

// ParseCodexWebSocketFrames validates one sequence of JSON WebSocket frames.
func ParseCodexWebSocketFrames(frames [][]byte) (CodexStreamResult, error) {
	var decoder codexStreamDecoder
	for index, frame := range frames {
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
	decoder.events = append(decoder.events, event)
	if !isCodexTerminalEvent(event.Type) {
		return nil
	}
	decoder.terminalType = event.Type
	decoder.response = event.Response
	decoder.failed = event.Type == CodexEventResponseFailed || event.Type == CodexEventError ||
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
		return result, &CodexStreamFailureError{Event: decoder.events[len(decoder.events)-1]}
	}
	return result, nil
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
