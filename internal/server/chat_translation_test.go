package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/catgirl-systems/codex-sub-proxy/internal/apikey"
	"github.com/catgirl-systems/codex-sub-proxy/internal/codex"
	"github.com/go-playground/validator/v10"
	sdk "github.com/openai/openai-go"
	"github.com/openai/openai-go/option"
	"github.com/openai/openai-go/packages/param"
	"github.com/openai/openai-go/shared"
)

func TestPrivateChatResponseFormatMapping(t *testing.T) {
	tests := []struct {
		name     string
		format   string
		wantType string
		wantName string
		wantDesc string
		wantRaw  string
	}{
		{name: "text", format: `{"type":"text"}`, wantType: "text"},
		{name: "json object", format: `{"type":"json_object"}`, wantType: "json_object"},
		{name: "json schema", format: `{"type":"json_schema","json_schema":{"name":"answer","description":"answer format","schema":{"type":"object","properties":{"answer":{"type":"string"}}},"strict":true}}`, wantType: "json_schema", wantName: "answer", wantDesc: "answer format", wantRaw: `{"type":"object","properties":{"answer":{"type":"string"}}}`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := chatCompletionRequest{
				Model:          "gpt-5.6-sol",
				Messages:       []chatMessage{{Role: "user", Content: json.RawMessage(`"return JSON"`)}},
				ResponseFormat: json.RawMessage(test.format),
			}
			if err := validateChatRequestOnly(request); err != nil {
				t.Fatalf("validate request: %v", err)
			}
			private, err := privateChatRequest(request)
			if err != nil {
				t.Fatalf("translate request: %v", err)
			}
			payload, err := json.Marshal(private)
			if err != nil {
				t.Fatalf("marshal private request: %v", err)
			}
			var wire struct {
				Text *struct {
					Format *struct {
						Type        string          `json:"type"`
						Name        string          `json:"name"`
						Description string          `json:"description"`
						Schema      json.RawMessage `json:"schema"`
						Strict      *bool           `json:"strict"`
					} `json:"format"`
				} `json:"text"`
			}
			if err := json.Unmarshal(payload, &wire); err != nil {
				t.Fatalf("decode private request: %v", err)
			}
			if wire.Text == nil || wire.Text.Format == nil {
				t.Fatal("private text.format missing")
			}
			format := wire.Text.Format
			if format.Type != test.wantType || format.Name != test.wantName || format.Description != test.wantDesc {
				t.Fatalf("private format = %+v", format)
			}
			if test.wantRaw != "" && string(format.Schema) != test.wantRaw {
				t.Fatalf("private schema = %s", format.Schema)
			}
		})
	}
}

func TestPinnedSDKChatResponseFormatsDecodeIntoPublicRequest(t *testing.T) {
	schema := shared.ResponseFormatJSONSchemaJSONSchemaParam{
		Name:   "answer",
		Schema: map[string]any{"type": "object", "properties": map[string]any{"answer": map[string]any{"type": "string"}}},
	}
	request := sdk.ChatCompletionNewParams{
		Model:    "gpt-5.6-sol",
		Messages: []sdk.ChatCompletionMessageParamUnion{sdk.UserMessage("return JSON")},
		ResponseFormat: sdk.ChatCompletionNewParamsResponseFormatUnion{
			OfJSONSchema: &shared.ResponseFormatJSONSchemaParam{JSONSchema: schema},
		},
	}
	payload, err := json.Marshal(request)
	if err != nil {
		t.Fatalf("marshal SDK request: %v", err)
	}
	var public chatCompletionRequest
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&public); err != nil {
		t.Fatalf("decode SDK request: %v; payload=%s", err, payload)
	}
	if err := validateChatRequestOnly(public); err != nil {
		t.Fatalf("validate SDK request: %v; payload=%s", err, payload)
	}
	private, err := privateChatRequest(public)
	if err != nil {
		t.Fatalf("translate SDK request: %v", err)
	}
	if private.Text == nil || private.Text.Format == nil || private.Text.Format.Type != "json_schema" {
		t.Fatalf("private format = %+v", private.Text)
	}
}

func TestPrivateChatFunctionCallUsesCallIDOnly(t *testing.T) {
	request := chatCompletionRequest{
		Model: "gpt-5.6-sol",
		Messages: []chatMessage{{
			Role:      "assistant",
			ToolCalls: []chatToolCall{{Type: "function", ID: "call-weather", Function: chatToolCallFunction{Name: "weather", Arguments: `{}`}}},
		}},
	}
	private, err := privateChatRequest(request)
	if err != nil {
		t.Fatalf("translate Chat function call: %v", err)
	}
	if private.Input == nil || len(private.Input.Items) != 1 {
		t.Fatalf("private input = %#v", private.Input)
	}
	item := private.Input.Items[0]
	if item.CallID != "call-weather" || item.ID != "" {
		t.Fatalf("private function call identity = %#v", item)
	}
}

func TestPinnedSDKChatNewAndStreaming(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		body, err := io.ReadAll(request.Body)
		if err != nil {
			http.Error(writer, "read request", http.StatusBadRequest)
			return
		}
		var private struct {
			Text *struct {
				Format *struct {
					Type   string          `json:"type"`
					Name   string          `json:"name"`
					Schema json.RawMessage `json:"schema"`
				} `json:"format"`
			} `json:"text"`
		}
		if err := json.Unmarshal(body, &private); err != nil {
			http.Error(writer, "invalid private request", http.StatusBadRequest)
			return
		}
		if private.Text == nil || private.Text.Format == nil || private.Text.Format.Type != "json_schema" || private.Text.Format.Name != "answer" {
			http.Error(writer, "response format was not flattened", http.StatusBadRequest)
			return
		}
		writer.Header().Set("Content-Type", "text/event-stream")
		writer.WriteHeader(http.StatusOK)
		for _, event := range chatSmokeEvents() {
			payload, _ := json.Marshal(event)
			_, _ = fmt.Fprintf(writer, "data: %s\n\n", payload)
		}
	}))
	defer upstream.Close()

	policy := &apikey.Policy{Name: "chat-test", Owner: "chat-test", AllowedEndpoints: []string{chatCompletionsEndpoint}, AllowedModels: []string{"gpt-5.6-sol"}}
	servers, rawKey := newResponsesTestServer(t, upstream.URL, policy)
	defer shutdownResponsesTestServer(t, servers)
	client := sdk.NewClient(option.WithBaseURL("http://"+servers.DataAddr()+"/v1/"), option.WithAPIKey(rawKey))
	schema := shared.ResponseFormatJSONSchemaJSONSchemaParam{
		Name:   "answer",
		Schema: map[string]any{"type": "object", "properties": map[string]any{"answer": map[string]any{"type": "string"}}},
	}
	params := sdk.ChatCompletionNewParams{
		Model:    "gpt-5.6-sol",
		Messages: []sdk.ChatCompletionMessageParamUnion{sdk.UserMessage("hello")},
		ResponseFormat: sdk.ChatCompletionNewParamsResponseFormatUnion{
			OfJSONSchema: &shared.ResponseFormatJSONSchemaParam{JSONSchema: schema},
		},
	}
	completion, err := client.Chat.Completions.New(context.Background(), params)
	if err != nil {
		t.Fatalf("SDK Chat.New: %v", err)
	}
	if completion.ID != "resp-chat-1" || completion.Choices[0].Message.Content != "hi" || completion.Choices[0].FinishReason != "stop" {
		t.Fatalf("completion = %+v", completion)
	}

	params.StreamOptions.IncludeUsage = param.NewOpt(true)
	stream := client.Chat.Completions.NewStreaming(context.Background(), params)
	var text string
	var roleChunks, finishChunks, usageChunks int
	for stream.Next() {
		chunk := stream.Current()
		if len(chunk.Choices) == 0 {
			usageChunks++
			continue
		}
		choice := chunk.Choices[0]
		if choice.Delta.Role == "assistant" {
			roleChunks++
		}
		text += choice.Delta.Content
		if choice.FinishReason != "" {
			finishChunks++
		}
	}
	if err := stream.Err(); err != nil {
		t.Fatalf("SDK Chat.NewStreaming: %v", err)
	}
	if text != "hi" || roleChunks != 1 || finishChunks != 1 || usageChunks != 1 {
		t.Fatalf("stream text=%q role=%d finish=%d usage=%d", text, roleChunks, finishChunks, usageChunks)
	}
}

func chatSmokeEvents() []map[string]any {
	response := map[string]any{
		"id": "resp-chat-1", "model": "gpt-5.6-sol", "created_at": int64(1710000000), "status": "completed",
		"output": []any{map[string]any{"type": "message", "role": "assistant", "content": []any{map[string]any{"type": "output_text", "text": "hi"}}}},
		"usage":  map[string]any{"input_tokens": 3, "output_tokens": 2, "total_tokens": 5},
	}
	return []map[string]any{
		{"type": "response.created", "sequence_number": 0, "response": map[string]any{"id": "resp-chat-1", "model": "gpt-5.6-sol", "created_at": int64(1710000000), "status": "in_progress"}},
		{"type": "response.output_text.delta", "sequence_number": 1, "delta": "h"},
		{"type": "response.output_text.delta", "sequence_number": 2, "delta": "i"},
		{"type": "response.completed", "sequence_number": 3, "response": response},
	}
}

func TestChatStreamInterleavedToolCallsPreserveOrderAndUniqueness(t *testing.T) {
	recorder := httptest.NewRecorder()
	state := newChatStreamState("gpt-5.6-sol", false, recorder, recorder)
	events := []codex.CodexResponseStreamEvent{
		{Type: codex.CodexEventResponseCreated, SequenceNumber: 0, Response: &codex.CodexResponse{ID: "resp-tools", Model: "gpt-5.6-sol", CreatedAt: 1710000000, Status: codex.CodexResponseStatusInProgress}},
		{Type: codex.CodexEventResponseOutputItemAdded, SequenceNumber: 1, Item: &codex.CodexOutputItem{Type: "function_call", ID: "fc-1", CallID: "call-1", Name: "first"}},
		{Type: codex.CodexEventResponseOutputItemAdded, SequenceNumber: 2, Item: &codex.CodexOutputItem{Type: "function_call", ID: "fc-2", CallID: "call-2", Name: "second"}},
		{Type: codex.CodexEventResponseFunctionArgsDelta, SequenceNumber: 3, ItemID: "fc-1", Delta: `{"a":`},
		{Type: codex.CodexEventResponseFunctionArgsDelta, SequenceNumber: 4, ItemID: "fc-2", Delta: `{"b":`},
		{Type: codex.CodexEventResponseFunctionArgsDelta, SequenceNumber: 5, ItemID: "fc-1", Delta: `1}`},
		{Type: codex.CodexEventResponseFunctionArgsDelta, SequenceNumber: 6, ItemID: "fc-2", Delta: `2}`},
		{Type: codex.CodexEventResponseFunctionArgsDone, SequenceNumber: 7, ItemID: "fc-1", Arguments: `{"a":1}`},
		{Type: codex.CodexEventResponseFunctionArgsDone, SequenceNumber: 8, ItemID: "fc-2", Arguments: `{"b":2}`},
		{Type: codex.CodexEventResponseCompleted, SequenceNumber: 9, Response: &codex.CodexResponse{
			ID: "resp-tools", Model: "gpt-5.6-sol", CreatedAt: 1710000000, Status: codex.CodexResponseStatusCompleted,
			Output: []codex.CodexOutputItem{
				{Type: "function_call", ID: "fc-1", CallID: "call-1", Name: "first", Arguments: `{"a":1}`},
				{Type: "function_call", ID: "fc-2", CallID: "call-2", Name: "second", Arguments: `{"b":2}`},
			},
		}},
	}
	for _, event := range events {
		if err := state.event(event); err != nil {
			t.Fatalf("translate event %s: %v", event.Type, err)
		}
	}
	if !state.finishSent {
		t.Fatal("stream did not finish")
	}
	chunks := decodeChatChunks(t, recorder.Body.String())
	var roleCount, finishCount int
	arguments := map[int64]string{}
	metadata := map[int64]int{}
	for _, chunk := range chunks {
		for _, choice := range chunk.Choices {
			if choice.Delta.Role == "assistant" {
				roleCount++
			}
			if choice.FinishReason != nil {
				finishCount++
			}
			for _, tool := range choice.Delta.ToolCalls {
				if tool.ID != "" || tool.Type != "" || tool.Function.Name != "" {
					metadata[tool.Index]++
				}
				arguments[tool.Index] += tool.Function.Arguments
			}
		}
	}
	if roleCount != 1 || finishCount != 1 {
		t.Fatalf("role chunks=%d finish chunks=%d", roleCount, finishCount)
	}
	if metadata[0] != 1 || metadata[1] != 1 || arguments[0] != `{"a":1}` || arguments[1] != `{"b":2}` {
		t.Fatalf("metadata=%v arguments=%v", metadata, arguments)
	}
}

func TestChatStreamRejectsIncompleteToolArguments(t *testing.T) {
	recorder := httptest.NewRecorder()
	state := newChatStreamState("gpt-5.6-sol", false, recorder, recorder)
	events := []codex.CodexResponseStreamEvent{
		{Type: codex.CodexEventResponseCreated, SequenceNumber: 0, Response: &codex.CodexResponse{ID: "resp-invalid", Model: "gpt-5.6-sol", CreatedAt: 1710000000, Status: codex.CodexResponseStatusInProgress}},
		{Type: codex.CodexEventResponseOutputItemAdded, SequenceNumber: 1, Item: &codex.CodexOutputItem{Type: "function_call", ID: "fc-invalid", CallID: "call-invalid", Name: "lookup"}},
		{Type: codex.CodexEventResponseFunctionArgsDelta, SequenceNumber: 2, ItemID: "fc-invalid", Delta: `{"query":`},
		{Type: codex.CodexEventResponseCompleted, SequenceNumber: 3, Response: &codex.CodexResponse{
			ID: "resp-invalid", Model: "gpt-5.6-sol", CreatedAt: 1710000000, Status: codex.CodexResponseStatusCompleted,
			Output: []codex.CodexOutputItem{{Type: "function_call", ID: "fc-invalid", CallID: "call-invalid", Name: "lookup", Arguments: `{"query":`}},
		}},
	}
	for index, event := range events {
		err := state.event(event)
		if index < len(events)-1 && err != nil {
			t.Fatalf("event %s: %v", event.Type, err)
		}
		if index == len(events)-1 && err == nil {
			t.Fatal("incomplete arguments were accepted")
		}
	}
	if state.finishSent {
		t.Fatal("invalid stream emitted a finish chunk")
	}
}

func TestChatCompletionMixedTextAndToolsRetainsContent(t *testing.T) {
	response := &codex.CodexResponse{
		Status: codex.CodexResponseStatusCompleted,
		Output: []codex.CodexOutputItem{
			{Type: "message", Role: "assistant", Content: []codex.CodexContentPart{{Type: "output_text", Text: "answer"}}},
			{Type: "function_call", ID: "fc-1", CallID: "call-1", Name: "lookup", Arguments: `{}`},
		},
	}
	payload, err := chatCompletionPayload(response, "gpt-5.6-sol")
	if err != nil {
		t.Fatalf("encode mixed completion: %v", err)
	}
	var completion chatCompletionResponse
	if err := json.Unmarshal(payload, &completion); err != nil {
		t.Fatalf("decode mixed completion: %v", err)
	}
	message := completion.Choices[0].Message
	if message.Content == nil || *message.Content != "answer" || len(message.ToolCalls) != 1 {
		t.Fatalf("mixed message = %#v", message)
	}
}

func TestChatRequestRejectsToolCallIDOnNonToolRoles(t *testing.T) {
	for _, role := range []string{"developer", "system", "user", "assistant"} {
		t.Run(role, func(t *testing.T) {
			request := chatCompletionRequest{
				Model:    "gpt-5.6-sol",
				Messages: []chatMessage{{Role: role, Content: json.RawMessage(`"hello"`), ToolCallID: "call-1"}},
			}
			if err := validateChatRequestOnly(request); err == nil {
				t.Fatal("nonempty tool_call_id was accepted")
			}
		})
	}
}

func TestChatStreamReconcilesTerminalText(t *testing.T) {
	tests := []struct {
		name       string
		terminal   string
		wantText   string
		wantFinish bool
	}{
		{name: "suffix", terminal: "hello", wantText: "hello", wantFinish: true},
		{name: "mismatch", terminal: "heXlo", wantFinish: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			state := newChatStreamState("gpt-5.6-sol", false, recorder, recorder)
			if err := state.event(codex.CodexResponseStreamEvent{
				Type: codex.CodexEventResponseOutputTextDelta, Delta: "hel",
			}); err != nil {
				t.Fatalf("delta: %v", err)
			}
			err := state.event(codex.CodexResponseStreamEvent{
				Type: codex.CodexEventResponseCompleted,
				Response: &codex.CodexResponse{
					Status: codex.CodexResponseStatusCompleted,
					Output: []codex.CodexOutputItem{{Type: "message", Role: "assistant", Content: []codex.CodexContentPart{{Type: "output_text", Text: test.terminal}}}},
				},
			})
			if test.wantFinish && err != nil {
				t.Fatalf("terminal: %v", err)
			}
			if !test.wantFinish && err == nil {
				t.Fatal("mismatched terminal text was accepted")
			}
			if state.finishSent != test.wantFinish {
				t.Fatalf("finish sent = %t, want %t", state.finishSent, test.wantFinish)
			}
			if test.wantFinish {
				var got string
				for _, chunk := range decodeChatChunks(t, recorder.Body.String()) {
					for _, choice := range chunk.Choices {
						if choice.Delta.Content != nil {
							got += *choice.Delta.Content
						}
					}
				}
				if got != test.wantText {
					t.Fatalf("stream text = %q, want %q", got, test.wantText)
				}
			}
		})
	}
}

func TestChatStreamRejectsMissingOrInvalidRequestedUsage(t *testing.T) {
	tests := []struct {
		name  string
		usage *codex.CodexUsage
	}{
		{name: "missing"},
		{name: "negative", usage: &codex.CodexUsage{InputTokens: -1}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			state := newChatStreamState("gpt-5.6-sol", true, recorder, recorder)
			err := state.event(codex.CodexResponseStreamEvent{
				Type: codex.CodexEventResponseCompleted,
				Response: &codex.CodexResponse{
					Status: codex.CodexResponseStatusCompleted, Usage: test.usage,
				},
			})
			if err == nil || state.finishSent {
				t.Fatalf("usage error = %v, finish sent = %t", err, state.finishSent)
			}
			if recorder.Body.Len() != 0 {
				t.Fatalf("invalid usage emitted success chunks: %s", recorder.Body.String())
			}
		})
	}
}

func TestChatStreamRejectsMissingResponseAndResponseError(t *testing.T) {
	recorder := httptest.NewRecorder()
	state := newChatStreamState("gpt-5.6-sol", false, recorder, recorder)
	if err := state.event(codex.CodexResponseStreamEvent{Type: codex.CodexEventResponseDone}); err == nil {
		t.Fatal("terminal without response was accepted")
	}
	recorder = httptest.NewRecorder()
	state = newChatStreamState("gpt-5.6-sol", false, recorder, recorder)
	if err := state.event(codex.CodexResponseStreamEvent{
		Type:     codex.CodexEventResponseCreated,
		Response: &codex.CodexResponse{Error: &codex.CodexError{Code: "provider_error"}},
	}); err != nil {
		t.Fatalf("response error event: %v", err)
	}
	if state.failure == nil || state.finishSent || recorder.Body.Len() != 0 {
		t.Fatalf("response error state = %#v, body=%s", state, recorder.Body.String())
	}
}

func TestChatStreamRejectsAnnotationsAndUnknownSemanticValues(t *testing.T) {
	annotated := &codex.CodexResponse{
		Status: codex.CodexResponseStatusCompleted,
		Output: []codex.CodexOutputItem{{Type: "message", Content: []codex.CodexContentPart{
			{Type: "output_text", Text: "text", Annotations: []json.RawMessage{json.RawMessage(`{"type":"url_citation"}`)}},
		}}},
	}
	if _, err := chatCompletionPayload(annotated, "gpt-5.6-sol"); err == nil {
		t.Fatal("annotated output was accepted")
	}
	tests := []codex.CodexResponseStreamEvent{
		{Type: "response.output_text.annotation.added", Annotation: json.RawMessage(`{"type":"url_citation"}`)},
		{Type: codex.CodexEventResponseContentPartAdded, Part: &codex.CodexContentPart{Type: "output_text", Annotations: []json.RawMessage{json.RawMessage(`{}`)}}},
		{Type: codex.CodexEventResponseOutputItemAdded, Item: &codex.CodexOutputItem{Type: "image_generation_call"}},
		{Type: codex.CodexEventResponseContentPartAdded, Part: &codex.CodexContentPart{Type: "image"}},
		{Type: "response.unknown.semantic"},
	}
	for _, event := range tests {
		t.Run(event.Type, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			state := newChatStreamState("gpt-5.6-sol", false, recorder, recorder)
			if err := state.event(event); err == nil {
				t.Fatalf("event %q was accepted", event.Type)
			}
			if state.finishSent || recorder.Body.Len() != 0 {
				t.Fatalf("event %q emitted success output: %s", event.Type, recorder.Body.String())
			}
		})
	}
}

func decodeChatChunks(t *testing.T, body string) []chatCompletionChunk {
	t.Helper()
	var chunks []chatCompletionChunk
	for _, record := range strings.Split(body, "\n\n") {
		if !strings.HasPrefix(record, "data: ") || strings.TrimSpace(strings.TrimPrefix(record, "data: ")) == "[DONE]" {
			continue
		}
		var chunk chatCompletionChunk
		if err := json.Unmarshal([]byte(strings.TrimPrefix(record, "data: ")), &chunk); err != nil {
			t.Fatalf("decode chunk: %v", err)
		}
		chunks = append(chunks, chunk)
	}
	return chunks
}
func validateChatRequestOnly(request chatCompletionRequest) error {
	if err := validator.New().Struct(request); err != nil {
		return err
	}
	_, err := validateChatRequest(request)
	return err
}
