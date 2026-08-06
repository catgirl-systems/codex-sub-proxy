package codex

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"os"
	"regexp"
	"strings"
	"testing"
)

type codexErrorReader struct {
	err error
}

func (reader codexErrorReader) Read([]byte) (int, error) {
	return 0, reader.err
}

type codexChunkErrorReader struct {
	data []byte
	err  error
}

func (reader *codexChunkErrorReader) Read(target []byte) (int, error) {
	if len(reader.data) == 0 {
		return 0, reader.err
	}
	count := copy(target, reader.data)
	reader.data = reader.data[count:]
	return count, reader.err
}

func TestCodexResponseRequestFixtureRoundTrips(t *testing.T) {
	raw, err := os.ReadFile("testdata/responses_request.json")
	if err != nil {
		t.Fatal(err)
	}
	var request CodexResponseRequest
	if err := json.Unmarshal(raw, &request); err != nil {
		t.Fatalf("decode request: %v", err)
	}
	if request.Model != "gpt-5.6-sol" || !request.Stream || request.ToolChoice == nil {
		t.Fatalf("request = %#v", request)
	}
	if request.Input == nil || len(request.Input.Items) != 6 || len(request.Tools) != 1 || request.Tools[0].Type != "image_generation" {
		t.Fatalf("request shape = %#v", request)
	}
	if request.Store == nil || *request.Store ||
		request.ParallelToolCalls == nil || *request.ParallelToolCalls {
		t.Fatalf("presence-preserving request flags = %#v", request)
	}
	if request.Tools[0].PartialImages != 2 || request.Tools[0].InputImageMask == nil ||
		request.Tools[0].InputImageMask.FileID != "fixture-file-mask" {
		t.Fatalf("hosted image tool = %#v", request.Tools[0])
	}
	if len(request.Include) != 1 || request.StreamOptions == nil ||
		request.StreamOptions.ReasoningSummaryDelivery != "sequential_cutoff" ||
		request.PromptCacheKey != "fixture-cache-key" ||
		request.PromptCacheRetention != "24h" ||
		request.MaxOutputTokens != 123 || request.MaxCompletionTokens != 456 ||
		request.ServiceTier != "priority" {
		t.Fatalf("request options = %#v", request)
	}
	if request.Input.Items[0].Content == nil || !bytes.Contains(request.Input.Items[0].Content, []byte(`fixture-file-image`)) ||
		!bytes.Contains(request.Input.Items[1].Arguments, []byte(`value`)) {
		t.Fatalf("input content/arguments = %s / %s", request.Input.Items[0].Content, request.Input.Items[1].Arguments)
	}
	if request.Input.Items[3].Action == nil || request.Input.Items[3].Actions == nil ||
		len(request.Input.Items[3].PendingSafetyChecks) != 1 ||
		request.Input.Items[3].PendingSafetyChecks[0].ID != "fixture-safety" ||
		request.Input.Items[3].Status != "completed" {
		t.Fatalf("computer input = %#v", request.Input.Items[3])
	}
	if request.Input.Items[4].Output == nil || len(request.Input.Items[4].AcknowledgedSafetyChecks) != 1 {
		t.Fatalf("computer output = %#v", request.Input.Items[4])
	}
	encoded, err := json.Marshal(request)
	if err != nil {
		t.Fatalf("encode request: %v", err)
	}
	var roundTrip CodexResponseRequest
	if err := json.Unmarshal(encoded, &roundTrip); err != nil {
		t.Fatalf("decode encoded request: %v", err)
	}
	if roundTrip.Model != request.Model || roundTrip.Tools[0].Action != request.Tools[0].Action ||
		roundTrip.Tools[0].PartialImages != 2 || roundTrip.StreamOptions == nil ||
		roundTrip.Store == nil || *roundTrip.Store ||
		roundTrip.ParallelToolCalls == nil || *roundTrip.ParallelToolCalls ||
		roundTrip.Input == nil ||
		roundTrip.Input.Items[3].PendingSafetyChecks[0].ID != "fixture-safety" ||
		roundTrip.Input.Items[3].Status != "completed" ||
		!bytes.Contains(roundTrip.Input.Items[0].Content, []byte(`fixture-file-image`)) {
		t.Fatalf("round-trip request = %#v", roundTrip)
	}
}
func TestCodexRequestUnionsRoundTripAndRejectInvalidForms(t *testing.T) {
	tests := []struct {
		name string
		raw  string
	}{
		{
			name: "string input and string tool choice",
			raw:  `{"model":"gpt-5.6-sol","input":"fixture input","tool_choice":"auto"}`,
		},
		{
			name: "array input and object tool choice",
			raw:  `{"model":"gpt-5.6-sol","input":[{"type":"message","role":"user"}],"tool_choice":{"type":"function"}}`,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var request CodexResponseRequest
			if err := json.Unmarshal([]byte(test.raw), &request); err != nil {
				t.Fatalf("decode request: %v", err)
			}
			if request.Input == nil || request.ToolChoice == nil {
				t.Fatalf("decoded unions = %#v", request)
			}
			encoded, err := json.Marshal(request)
			if err != nil {
				t.Fatalf("encode request: %v", err)
			}
			var wantFields, gotFields map[string]json.RawMessage
			if err := json.Unmarshal([]byte(test.raw), &wantFields); err != nil {
				t.Fatalf("decode source request: %v", err)
			}
			if err := json.Unmarshal(encoded, &gotFields); err != nil {
				t.Fatalf("decode encoded request: %v", err)
			}
			if string(gotFields["input"]) != string(wantFields["input"]) ||
				string(gotFields["tool_choice"]) != string(wantFields["tool_choice"]) {
				t.Fatalf("union round-trip = %s", encoded)
			}
		})
	}

	for _, raw := range []string{
		`{"model":"gpt-5.6-sol","input":null}`,
		`{"model":"gpt-5.6-sol","input":{}}`,
		`{"model":"gpt-5.6-sol","input":1}`,
		`{"model":"gpt-5.6-sol","tool_choice":null}`,
		`{"model":"gpt-5.6-sol","tool_choice":{}}`,
		`{"model":"gpt-5.6-sol","tool_choice":[]}`,
		`{"model":"gpt-5.6-sol","tool_choice":false}`,
	} {
		var request CodexResponseRequest
		if err := json.Unmarshal([]byte(raw), &request); err == nil {
			t.Fatalf("invalid union accepted: %s", raw)
		}
	}
	text := ""
	if _, err := json.Marshal(CodexInput{}); err == nil {
		t.Fatal("empty input union encoded")
	}
	if _, err := json.Marshal(CodexInput{String: &text, Items: []CodexInputItem{}}); err == nil {
		t.Fatal("mixed input union encoded")
	}
	if _, err := json.Marshal(CodexToolChoice{}); err == nil {
		t.Fatal("empty tool choice union encoded")
	}
	if _, err := json.Marshal(CodexToolChoice{String: &text, Type: "function"}); err == nil {
		t.Fatal("mixed tool choice union encoded")
	}
}

func TestResponsesCompatibilityMatrix(t *testing.T) {
	raw := `{"model":"gpt-5.6-sol","input":[{"type":"message","role":"developer","content":[{"type":"input_text","text":"fixture instructions"}]},{"type":"additional_tools","tools":[{"type":"namespace","name":"shell","tools":[{"type":"function","name":"exec"}]}]},{"type":"message","content":[{"type":"input_image","image_url":"data:image/png;base64,AAAA"}]}],"client_metadata":{"trace":"fixture","ws_request_header_x_openai_internal_codex_responses_lite":"true"},"generate":false,"reasoning":{"effort":"high","context":"fixture-context"},"text":{"format":{"type":"json_schema","name":"fixture","schema":{"type":"object"},"strict":true}},"stream_options":{"reasoning_summary_delivery":"sequential_cutoff"}}`
	var request CodexResponseRequest
	if err := json.Unmarshal([]byte(raw), &request); err != nil {
		t.Fatalf("decode private compatibility matrix request: %v", err)
	}
	if request.ClientMetadata["trace"] != "fixture" ||
		request.ClientMetadata["ws_request_header_x_openai_internal_codex_responses_lite"] != "true" ||
		request.Generate == nil || *request.Generate ||
		request.Input == nil || len(request.Input.Items) != 3 ||
		request.Input.Items[0].Role != "developer" ||
		len(request.Input.Items[1].Tools) != 1 ||
		request.Input.Items[1].Tools[0].Type != "namespace" ||
		len(request.Input.Items[1].Tools[0].Tools) != 1 ||
		request.Input.Items[1].Tools[0].Tools[0].Name != "exec" ||
		!bytes.Contains(request.Input.Items[2].Content, []byte("data:image/png;base64,AAAA")) ||
		request.Reasoning == nil || request.Reasoning.Context != "fixture-context" ||
		request.Text == nil || request.Text.Format == nil || request.Text.Format.Name != "fixture" ||
		request.StreamOptions == nil || request.StreamOptions.ReasoningSummaryDelivery != "sequential_cutoff" {
		t.Fatalf("private compatibility matrix request = %#v", request)
	}

	encoded, err := json.Marshal(request)
	if err != nil {
		t.Fatalf("encode private compatibility matrix request: %v", err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &fields); err != nil {
		t.Fatalf("decode encoded private request: %v", err)
	}
	if string(fields["client_metadata"]) != `{"trace":"fixture","ws_request_header_x_openai_internal_codex_responses_lite":"true"}` ||
		string(fields["generate"]) != "false" {
		t.Fatalf("private request fields = %s", encoded)
	}

	var response CodexResponse
	if err := json.Unmarshal([]byte(`{"output":[{"type":"compaction","id":"cmp_1","encrypted_content":"fixture","created_by":"codex"}]}`), &response); err != nil {
		t.Fatalf("decode private compaction output: %v", err)
	}
	if len(response.Output) != 1 || response.Output[0].Type != "compaction" ||
		response.Output[0].EncryptedContent != "fixture" || response.Output[0].CreatedBy != "codex" {
		t.Fatalf("private compaction output = %#v", response.Output)
	}

	for _, invalid := range []string{
		`{"model":"gpt-5.6-sol","unknown":true}`,
		`{"model":"gpt-5.6-sol","input":[{"type":"additional_tools","tools":[{"type":"namespace","tools":[{"type":"namespace","tools":[{"type":"function"}]}]}]}]}`,
	} {
		var invalidRequest CodexResponseRequest
		if err := json.Unmarshal([]byte(invalid), &invalidRequest); err == nil {
			t.Fatalf("accepted invalid private matrix request: %s", invalid)
		}
	}
}

func TestCodexCompactRequestRejectsOversizedToolsDuringDecode(t *testing.T) {
	tools := make([]string, maxCodexItemTools+1)
	for index := range tools {
		tools[index] = `{"type":"function","name":"fixture"}`
	}
	raw := `{"model":"gpt-5.6-sol","input":"fixture","tools":[` + strings.Join(tools, ",") + `]}`
	var request CodexCompactRequest
	err := json.Unmarshal([]byte(raw), &request)
	if err == nil || !strings.Contains(err.Error(), "too many tools") {
		t.Fatalf("oversized compact tools error = %v", err)
	}
}

func TestCodexCompactRequestPreservesPrivateControlsAndServiceTier(t *testing.T) {
	raw := `{"model":"gpt-5.6-sol","input":"fixture","tools":[{"type":"function","name":"fixture"}],"parallel_tool_calls":true,"reasoning":{"effort":"high"},"text":{"format":{"type":"text"}},"service_tier":"scale"}`
	var request CodexCompactRequest
	if err := json.Unmarshal([]byte(raw), &request); err != nil {
		t.Fatalf("decode private compact request: %v", err)
	}
	if err := request.validate(); err != nil {
		t.Fatalf("validate private compact request: %v", err)
	}
	if len(request.Tools) != 1 || request.ParallelToolCalls == nil || !*request.ParallelToolCalls ||
		request.Reasoning == nil || request.Text == nil || request.ServiceTier != "scale" {
		t.Fatalf("private compact request = %#v", request)
	}
}

func TestCodexStreamEventArgumentsRoundTrip(t *testing.T) {
	raw := []byte(`{"type":"response.function_call_arguments.done","sequence_number":4,"item_id":"fixture-call","output_index":0,"arguments":"{\"value\":1}"}`)
	var event CodexResponseStreamEvent
	if err := json.Unmarshal(raw, &event); err != nil {
		t.Fatalf("decode event: %v", err)
	}
	if event.Type != CodexEventResponseFunctionArgsDone || event.Arguments != `{"value":1}` {
		t.Fatalf("decoded event = %#v", event)
	}
	encoded, err := json.Marshal(event)
	if err != nil {
		t.Fatalf("encode event: %v", err)
	}
	var roundTrip CodexResponseStreamEvent
	if err := json.Unmarshal(encoded, &roundTrip); err != nil {
		t.Fatalf("decode encoded event: %v", err)
	}
	if roundTrip.Type != event.Type || roundTrip.Arguments != event.Arguments {
		t.Fatalf("event round-trip = %#v", roundTrip)
	}
}

func TestCodexResponsesTerminalFixtureIncludesHostedImage(t *testing.T) {
	raw, err := os.ReadFile("testdata/responses_terminal.sse")
	if err != nil {
		t.Fatal(err)
	}
	result, err := ParseCodexResponsesSSE(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("parse terminal fixture: %v", err)
	}
	if result.TerminalType != CodexEventResponseCompleted || result.Response == nil {
		t.Fatalf("terminal result = %#v", result)
	}
	if result.Response.Status != CodexResponseStatusCompleted || len(result.Response.Output) != 1 {
		t.Fatalf("response = %#v", result.Response)
	}
	image := result.Response.Output[0]
	if image.Type != CodexImageGenerationCall || image.Status != CodexResponseStatusCompleted {
		t.Fatalf("image output = %#v", image)
	}
	if _, err := base64.StdEncoding.DecodeString(image.Result); err != nil {
		t.Fatalf("decode hosted image: %v", err)
	}
	if result.Response.Usage == nil || result.Response.Usage.TotalTokens != 20 {
		t.Fatalf("usage = %#v", result.Response.Usage)
	}
	var sawMetadata, sawPartial bool
	for _, event := range result.Events {
		switch event.Type {
		case CodexEventResponseMetadata:
			sawMetadata = len(event.Headers) == 1 &&
				event.Headers["x-codex-turn-state"] == "fixture-turn-state" &&
				bytes.Contains(event.Metadata, []byte(`"decision":"allow"`))
		case CodexEventResponseImageGenerationPartialImage:
			sawPartial = event.PartialImageB64 != "" && event.PartialImageIndex == 0
		}
	}
	if !sawMetadata || !sawPartial {
		t.Fatalf("stream metadata/partial image missing: %#v", result.Events)
	}
}

func TestCodexResponsesIncompleteFixtureIsTerminal(t *testing.T) {
	raw, err := os.ReadFile("testdata/responses_incomplete.sse")
	if err != nil {
		t.Fatal(err)
	}
	result, err := ParseCodexResponsesSSE(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("parse incomplete fixture: %v", err)
	}
	if result.TerminalType != CodexEventResponseIncomplete || result.Response == nil {
		t.Fatalf("terminal result = %#v", result)
	}
	if result.Response.IncompleteDetails == nil || result.Response.IncompleteDetails.Reason != CodexIncompleteReasonMaxOutputTokens {
		t.Fatalf("incomplete details = %#v", result.Response.IncompleteDetails)
	}
}

func TestCodexResponsesFailedFixtureReturnsTypedFailure(t *testing.T) {
	raw, err := os.ReadFile("testdata/responses_failed.sse")
	if err != nil {
		t.Fatal(err)
	}
	result, err := ParseCodexResponsesSSE(bytes.NewReader(raw))
	if err == nil {
		t.Fatal("failed fixture returned no error")
	}
	var failure *CodexStreamFailureError
	if !errors.As(err, &failure) || !errors.Is(err, ErrCodexStreamFailed) {
		t.Fatalf("error = %v", err)
	}
	if failure.Category != "response_failed" || failure.Status != CodexResponseStatusFailed {
		t.Fatalf("safe failure = %#v", failure)
	}
	if encoded, marshalErr := json.Marshal(failure); marshalErr != nil {
		t.Fatalf("encode safe failure: %v", marshalErr)
	} else if strings.Contains(string(encoded), "synthetic upstream failure") {
		t.Fatal("errors.As exposed private provider message")
	}
	if result.TerminalType != CodexEventResponseFailed || result.Response == nil || result.Response.Error == nil {
		t.Fatalf("failed result = %#v", result)
	}
	if result.Response.Error.Code != "server_error" {
		t.Fatalf("failure = %#v", result.Response.Error)
	}
	if strings.Contains(err.Error(), "synthetic upstream failure") {
		t.Fatal("private provider message reached parser error")
	}
}

func TestCodexResponsesMalformedFixtureFailsClosed(t *testing.T) {
	raw, err := os.ReadFile("testdata/responses_malformed.sse")
	if err != nil {
		t.Fatal(err)
	}
	_, err = ParseCodexResponsesSSE(bytes.NewReader(raw))
	if !errors.Is(err, ErrCodexStreamMalformed) {
		t.Fatalf("error = %v", err)
	}
}

func TestCodexResponsesAbruptFixtureFailsWithoutTerminal(t *testing.T) {
	raw, err := os.ReadFile("testdata/responses_abrupt_close.sse")
	if err != nil {
		t.Fatal(err)
	}
	_, err = ParseCodexResponsesSSE(bytes.NewReader(raw))
	if !errors.Is(err, ErrCodexStreamAbruptClose) {
		t.Fatalf("error = %v", err)
	}
}

func TestCodexResponsesSSERejectsOverlongCommentAndData(t *testing.T) {
	tests := []struct {
		name string
		line string
	}{
		{
			name: "comment",
			line: ":" + strings.Repeat("x", maxCodexStreamLineBytes+1),
		},
		{
			name: "data",
			line: "data: " + strings.Repeat("x", maxCodexStreamLineBytes+1),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := ParseCodexResponsesSSE(strings.NewReader(test.line + "\n"))
			if !errors.Is(err, ErrCodexStreamMalformed) {
				t.Fatalf("error = %v", err)
			}
		})
	}
}

func TestCodexResponsesSSEWrapsReadCause(t *testing.T) {
	for _, cause := range []error{context.Canceled, io.ErrUnexpectedEOF} {
		_, err := ParseCodexResponsesSSE(codexErrorReader{err: cause})
		if !errors.Is(err, cause) {
			t.Fatalf("error = %v, want cause %v", err, cause)
		}
		if errors.Is(err, ErrCodexStreamMalformed) {
			t.Fatalf("read cause classified malformed: %v", err)
		}
	}
	partial := &codexChunkErrorReader{
		data: []byte("data: {\"type\":\"response.created\"}\n"),
		err:  context.Canceled,
	}
	_, err := ParseCodexResponsesSSE(partial)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("partial read error = %v", err)
	}
}

func TestCodexWebSocketFixtureRoundTrips(t *testing.T) {
	raw, err := os.ReadFile("testdata/responses_websocket.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	frames := bytes.Split(bytes.TrimSpace(raw), []byte("\n"))
	result, err := ParseCodexWebSocketFrames(frames)
	if err != nil {
		t.Fatalf("parse WebSocket fixture: %v", err)
	}
	if result.TerminalType != CodexEventResponseDone || result.Response == nil {
		t.Fatalf("WebSocket result = %#v", result)
	}
	if result.Response.Status != CodexResponseStatusCompleted || len(result.Events) != 6 {
		t.Fatalf("WebSocket events = %#v", result.Events)
	}
	if result.Events[0].SequenceNumber != 0 || result.Events[1].OutputIndex != 0 ||
		result.Events[2].ContentIndex != 0 {
		t.Fatalf("WebSocket coordinates = %#v", result.Events[:3])
	}
	encoded, err := json.Marshal(result.Events[len(result.Events)-1])
	if err != nil {
		t.Fatalf("encode WebSocket event: %v", err)
	}
	if _, err := DecodeCodexWebSocketFrame(encoded); err != nil {
		t.Fatalf("decode encoded WebSocket event: %v", err)
	}
}
func TestCodexStreamPayloadBudgetAppliesToSSEAndWebSocket(t *testing.T) {
	event := `{"type":"response.output_text.delta","delta":"` + strings.Repeat("x", 200*1024) + `"}`
	frame := []byte(event)
	if len(frame) >= maxCodexStreamLineBytes {
		t.Fatalf("test frame is too large: %d", len(frame))
	}
	frameCount := maxCodexStreamPayloadBytes/len(frame) + 1
	frames := make([][]byte, frameCount)
	for index := range frames {
		frames[index] = frame
	}
	if _, err := ParseCodexWebSocketFrames(frames); !errors.Is(err, ErrCodexStreamMalformed) {
		t.Fatalf("WebSocket aggregate limit error = %v", err)
	}

	var sse strings.Builder
	for range frames {
		sse.WriteString("data: ")
		sse.WriteString(event)
		sse.WriteString("\n\n")
	}
	if _, err := ParseCodexResponsesSSE(strings.NewReader(sse.String())); !errors.Is(err, ErrCodexStreamMalformed) {
		t.Fatalf("SSE aggregate limit error = %v", err)
	}
}

func TestCodexWebSocketRejectsDuplicateTerminal(t *testing.T) {
	raw, err := os.ReadFile("testdata/responses_websocket.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	frames := bytes.Split(bytes.TrimSpace(raw), []byte("\n"))
	frames = append(frames, []byte(`{"type":"response.completed","response":{"status":"completed"}}`))
	_, err = ParseCodexWebSocketFrames(frames)
	if !errors.Is(err, ErrCodexStreamDuplicateTerminal) {
		t.Fatalf("error = %v", err)
	}
}

func TestCodexResponsesSSEDoneOrdering(t *testing.T) {
	terminal := `data: {"type":"response.completed","response":{"status":"completed"}}` + "\n\n"
	tests := []struct {
		name      string
		raw       string
		wantError error
	}{
		{name: "early", raw: "data: [DONE]\n\n", wantError: ErrCodexStreamMalformed},
		{name: "duplicate", raw: terminal + "data: [DONE]\n\ndata: [DONE]\n\n", wantError: ErrCodexStreamDuplicateTerminal},
		{name: "post done data", raw: terminal + "data: [DONE]\n\ndata: {\"type\":\"response.created\"}\n\n", wantError: ErrCodexStreamDuplicateTerminal},
		{name: "post done event field", raw: terminal + "data: [DONE]\n\nevent: response.completed\n\n", wantError: ErrCodexStreamDuplicateTerminal},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := ParseCodexResponsesSSE(strings.NewReader(test.raw))
			if !errors.Is(err, test.wantError) {
				t.Fatalf("error = %v, want %v", err, test.wantError)
			}
		})
	}
	if _, err := ParseCodexResponsesSSE(strings.NewReader(terminal + "data: [DONE]\n\n")); err != nil {
		t.Fatalf("valid terminal then DONE: %v", err)
	}
}

func TestCodexResponsesSSERequiresTerminalResponse(t *testing.T) {
	for _, eventType := range []string{CodexEventResponseCompleted, CodexEventResponseDone, CodexEventResponseIncomplete, CodexEventResponseFailed} {
		t.Run(eventType, func(t *testing.T) {
			raw := `data: {"type":"` + eventType + `"}` + "\n\n"
			_, err := ParseCodexResponsesSSE(strings.NewReader(raw))
			if !errors.Is(err, ErrCodexStreamMalformed) {
				t.Fatalf("error = %v", err)
			}
		})
	}
}

func TestCodexResponsesSSEResponseErrorFailsStream(t *testing.T) {
	raw := `data: {"type":"response.created","response":{"status":"in_progress","error":{"code":"provider_error"}}}` + "\n\n" +
		`data: {"type":"response.completed","response":{"status":"completed"}}` + "\n\n" +
		"data: [DONE]\n\n"
	result, err := ParseCodexResponsesSSE(strings.NewReader(raw))
	if err == nil || !errors.Is(err, ErrCodexStreamFailed) {
		t.Fatalf("error = %v, result = %#v", err, result)
	}
}

func TestCodexImageFixturesDecodeAndEncode(t *testing.T) {
	for _, name := range []string{"images_generation.json", "images_edit.json"} {
		raw, err := os.ReadFile("testdata/" + name)
		if err != nil {
			t.Fatal(err)
		}
		var response CodexImageResponse
		if err := json.Unmarshal(raw, &response); err != nil {
			t.Fatalf("decode %s: %v", name, err)
		}
		if response.Created == nil || len(response.Data) != 1 || response.Data[0].B64JSON == "" {
			t.Fatalf("image response %s = %#v", name, response)
		}
		if response.Usage == nil || response.Usage.InputTokensDetails == nil ||
			response.Usage.OutputTokensDetails == nil ||
			response.Usage.InputTokensDetails.ImageTokens == 0 ||
			response.Usage.InputTokensDetails.TextTokens == 0 {
			t.Fatalf("image usage %s = %#v", name, response.Usage)
		}
		if _, err := base64.StdEncoding.DecodeString(response.Data[0].B64JSON); err != nil {
			t.Fatalf("decode image data %s: %v", name, err)
		}
		encoded, err := json.Marshal(response)
		if err != nil {
			t.Fatalf("encode %s: %v", name, err)
		}
		var roundTrip CodexImageResponse
		if err := json.Unmarshal(encoded, &roundTrip); err != nil {
			t.Fatalf("decode encoded %s: %v", name, err)
		}
	}
}

func TestCodexImageRequestFixturesDecode(t *testing.T) {
	for _, name := range []string{"images_generation_request.json", "images_edit_request.json"} {
		raw, err := os.ReadFile("testdata/" + name)
		if err != nil {
			t.Fatal(err)
		}
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(raw, &fields); err != nil {
			t.Fatalf("decode %s: %v", name, err)
		}
		wantKeys := []string{"model", "prompt", "n", "size", "quality"}
		if strings.Contains(name, "edit") {
			wantKeys = append(wantKeys, "images")
		}
		assertExactImageJSONKeys(t, fields, wantKeys...)
		if string(fields["model"]) != `"gpt-image-2"` || string(fields["quality"]) != `"auto"` {
			t.Fatalf("request %s has wrong model or quality: %s", name, raw)
		}
		if strings.Contains(string(fields["prompt"]), "real") {
			t.Fatalf("request %s contains non-synthetic prompt", name)
		}
		if strings.Contains(name, "edit") {
			var images []map[string]json.RawMessage
			if err := json.Unmarshal(fields["images"], &images); err != nil || len(images) != 1 {
				t.Fatalf("edit images %s = %s, err = %v", name, fields["images"], err)
			}
			assertExactImageJSONKeys(t, images[0], "image_url")
		}
	}
}

func TestCodexUsageFixtureDecodesAllBreakdowns(t *testing.T) {
	raw, err := os.ReadFile("testdata/usage.json")
	if err != nil {
		t.Fatal(err)
	}
	var usage CodexUsage
	if err := json.Unmarshal(raw, &usage); err != nil {
		t.Fatalf("decode usage: %v", err)
	}
	if usage.TotalTokens != 59 || usage.InputTokensDetails == nil || usage.OutputTokensDetails == nil {
		t.Fatalf("usage = %#v", usage)
	}
	if usage.InputTokensDetails.OrchestrationInputCachedTokens != 2 ||
		usage.InputTokensDetails.ImageTokens != 7 ||
		usage.InputTokensDetails.TextTokens != 35 ||
		usage.OutputTokensDetails.ReasoningTokens != 5 ||
		usage.OutputTokensDetails.ImageTokens != 2 ||
		usage.OutputTokensDetails.TextTokens != 15 {
		t.Fatalf("usage details = %#v", usage)
	}
}

func TestCodexErrorFixtureDecodesRateLimitData(t *testing.T) {
	raw, err := os.ReadFile("testdata/error_usage_limit.json")
	if err != nil {
		t.Fatal(err)
	}
	var response CodexErrorEnvelope
	if err := json.Unmarshal(raw, &response); err != nil {
		t.Fatalf("decode error: %v", err)
	}
	if response.Status != 429 || response.Error == nil || response.Error.Code != "usage_limit_reached" {
		t.Fatalf("error response = %#v", response)
	}
	if response.Headers == nil || string(response.Headers["x-codex-primary-used-percent"]) != "100" {
		t.Fatalf("rate headers = %#v", response.Headers)
	}
	mapped := MapUpstreamError(response.Status, nil, raw)
	if mapped.Category != CategoryUsageLimit || mapped.IsRetryable() {
		t.Fatalf("mapped error = %#v", mapped)
	}
}

func TestCodexErrorHeadersDecodeAndRoundTrip(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want map[string]string
	}{
		{
			name: "wrapped WebSocket fixture",
			raw:  wrappedWebSocketUsageLimitFixture,
			want: map[string]string{
				"x-codex-primary-used-percent":   `"100.0"`,
				"x-codex-primary-window-minutes": "15",
			},
		},
		{
			name: "string scalars",
			raw: `{"headers":{
				"x-codex-primary-used-percent":"100.0",
				"x-codex-primary-window-minutes":"15",
				"x-codex-primary-reset-at":"1738888888",
				"x-codex-secondary-used-percent":"25.5",
				"x-codex-secondary-window-minutes":"30",
				"x-codex-secondary-reset-at":"1738889999"
			}}`,
			want: map[string]string{
				"x-codex-primary-used-percent":     `"100.0"`,
				"x-codex-primary-window-minutes":   `"15"`,
				"x-codex-primary-reset-at":         `"1738888888"`,
				"x-codex-secondary-used-percent":   `"25.5"`,
				"x-codex-secondary-window-minutes": `"30"`,
				"x-codex-secondary-reset-at":       `"1738889999"`,
			},
		},
		{
			name: "numeric and boolean scalars",
			raw: `{"headers":{
				"x-codex-primary-used-percent":100.0,
				"x-codex-primary-window-minutes":15,
				"x-codex-primary-reset-at":1738888888,
				"x-codex-secondary-used-percent":25.5,
				"x-codex-secondary-window-minutes":30,
				"x-codex-secondary-reset-at":1738889999,
				"x-codex-bool":true
			}}`,
			want: map[string]string{
				"x-codex-primary-used-percent":     "100.0",
				"x-codex-primary-window-minutes":   "15",
				"x-codex-primary-reset-at":         "1738888888",
				"x-codex-secondary-used-percent":   "25.5",
				"x-codex-secondary-window-minutes": "30",
				"x-codex-secondary-reset-at":       "1738889999",
				"x-codex-bool":                     "true",
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var envelope CodexErrorEnvelope
			if err := json.Unmarshal([]byte(test.raw), &envelope); err != nil {
				t.Fatalf("decode headers: %v", err)
			}
			if len(envelope.Headers) != len(test.want) {
				t.Fatalf("decoded headers = %#v, want %#v", envelope.Headers, test.want)
			}
			for name, want := range test.want {
				if got := string(envelope.Headers[name]); got != want {
					t.Errorf("header %q = %q, want raw %q", name, got, want)
				}
			}

			encoded, err := json.Marshal(envelope)
			if err != nil {
				t.Fatalf("encode headers: %v", err)
			}
			var roundTrip CodexErrorEnvelope
			if err := json.Unmarshal(encoded, &roundTrip); err != nil {
				t.Fatalf("decode round-trip headers: %v", err)
			}
			if len(roundTrip.Headers) != len(test.want) {
				t.Fatalf("round-trip headers = %#v, want %#v", roundTrip.Headers, test.want)
			}
			for name, want := range test.want {
				if got := string(roundTrip.Headers[name]); got != want {
					t.Errorf("round-trip header %q = %q, want raw %q", name, got, want)
				}
			}
		})
	}
}
func TestCodexErrorEnvelopeDecodesStatusAliases(t *testing.T) {
	tests := []struct {
		name           string
		raw            string
		wantStatus     int
		wantStatusCode int
		wantErr        bool
	}{
		{name: "status", raw: `{"status":401}`, wantStatus: 401},
		{name: "status code alias", raw: `{"status_code":401}`, wantStatusCode: 401},
		{name: "matching aliases", raw: `{"status":401,"status_code":401}`, wantStatus: 401, wantStatusCode: 401},
		{name: "statusless", raw: `{}`},
		{name: "invalid alias", raw: `{"status_code":"unknown"}`, wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var envelope CodexErrorEnvelope
			err := json.Unmarshal([]byte(test.raw), &envelope)
			if (err != nil) != test.wantErr {
				t.Fatalf("decode error = %v, want error = %t", err, test.wantErr)
			}
			if test.wantErr {
				return
			}
			if envelope.Status != test.wantStatus || envelope.StatusCode != test.wantStatusCode {
				t.Fatalf("decoded status = %d/%d, want %d/%d", envelope.Status, envelope.StatusCode, test.wantStatus, test.wantStatusCode)
			}
		})
	}
}

func TestCodexPermanentRefreshFixture(t *testing.T) {
	raw, err := os.ReadFile("testdata/refresh_failure_permanent.json")
	if err != nil {
		t.Fatal(err)
	}
	var failure CodexRefreshFailure
	if err := json.Unmarshal(raw, &failure); err != nil {
		t.Fatalf("decode refresh failure: %v", err)
	}
	if !failure.IsPermanent() {
		t.Fatalf("refresh failure is not permanent: %#v", failure)
	}
}

func TestCodexTransientRefreshFixtureIsNotPermanent(t *testing.T) {
	raw, err := os.ReadFile("testdata/refresh_failure_transient.json")
	if err != nil {
		t.Fatal(err)
	}
	var failure CodexRefreshFailure
	if err := json.Unmarshal(raw, &failure); err != nil {
		t.Fatalf("decode refresh failure: %v", err)
	}
	if failure.IsPermanent() {
		t.Fatalf("transient refresh failure is permanent: %#v", failure)
	}
}
func TestCodexRefreshFailureUsesStructuredCodes(t *testing.T) {
	tests := []struct {
		name      string
		failure   CodexRefreshFailure
		permanent bool
	}{
		{name: "invalid grant", failure: CodexRefreshFailure{Error: "invalid_grant", Status: 400}, permanent: true},
		{name: "invalid token", failure: CodexRefreshFailure{Error: "invalid_token", Status: 400}, permanent: true},
		{name: "unauthorized client", failure: CodexRefreshFailure{Error: "unauthorized_client", Status: 400}, permanent: true},
		{name: "unstructured revoked token", failure: CodexRefreshFailure{ErrorDescription: "Refresh token revoked", Status: 400}, permanent: false},
		{name: "unstructured expired token", failure: CodexRefreshFailure{ErrorDescription: "Refresh token expired", Status: 400}, permanent: false},
		{name: "bare unauthorized", failure: CodexRefreshFailure{Status: 401}, permanent: false},
		{name: "temporary unavailable", failure: CodexRefreshFailure{Error: "temporarily_unavailable", Status: 503}, permanent: false},
		{name: "service unavailable", failure: CodexRefreshFailure{ErrorDescription: "refresh service is unavailable", Status: 503}, permanent: false},
		{name: "rate limited unauthorized", failure: CodexRefreshFailure{ErrorDescription: "401 unauthorized: too many requests", Status: 401}, permanent: false},
		{name: "network timeout unauthorized", failure: CodexRefreshFailure{ErrorDescription: "network timeout", Status: 401}, permanent: false},
		{name: "forbidden", failure: CodexRefreshFailure{ErrorDescription: "403 forbidden", Status: 403}, permanent: false},
		{name: "gateway", failure: CodexRefreshFailure{ErrorDescription: "502 bad gateway", Status: 502}, permanent: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := test.failure.IsPermanent(); got != test.permanent {
				t.Fatalf("IsPermanent() = %t, want %t for %#v", got, test.permanent, test.failure)
			}
		})
	}
}

func TestCodexFixtureCredentialPatternsCatchCommonSentinels(t *testing.T) {
	patterns := []*regexp.Regexp{
		regexp.MustCompile(`(?i)[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}`),
		regexp.MustCompile(`(?i)\bbearer\s+[a-z0-9._\-]{8,}`),
		regexp.MustCompile(`(?i)\b(?:sk|rk|pk|gh[pousr]|github_pat|xox[baprs])[-_][a-z0-9_-]{8,}`),
		regexp.MustCompile(`(?i)\bAKIA[0-9A-Z]{16}\b`),
		regexp.MustCompile(`eyJ[a-zA-Z0-9_-]{8,}\.[a-zA-Z0-9_-]{8,}\.[a-zA-Z0-9_-]{8,}`),
		regexp.MustCompile(`(?i)"(?:access|refresh|api)[_-]?token"\s*:\s*"[^"]{12,}"`),
		regexp.MustCompile(`(?i)"(?:client[_-]?secret|(?:api|access|refresh)[_-]?(?:key|token)|private[_-]?key|credentials?|password|passwd|secret|token)"\s*:\s*"[^"]{8,}"`),
		regexp.MustCompile(`(?i)(?:"(?:cookie|set[_-]?cookie|session(?:[_-]?id)?)"\s*:\s*"[^"]{8,}"|\b(?:cookie|set-cookie|session(?:[-_ ]?id)?)\s*[:=]\s*[^\s"';,]{8,})`),
	}
	sentinels := []string{
		`"client_secret":"synthetic-client-secret-value"`,
		`"credential":"synthetic-credential-value"`,
		`Cookie: session=synthetic-session-value`,
		`"cookie":"synthetic-cookie-value"`,
		"AKIA1234567890ABCDEF",
		"ghp_syntheticgithubtokenvalue",
		"github_pat_syntheticgithubtokenvalue",
	}
	for _, sentinel := range sentinels {
		matched := false
		for _, pattern := range patterns {
			if pattern.MatchString(sentinel) {
				matched = true
				break
			}
		}
		if !matched {
			t.Fatalf("credential sentinel was not detected: %q", sentinel)
		}
	}
}

func TestCodexFixturesContainNoCredentialPatterns(t *testing.T) {
	fixtureNames := []string{
		"responses_request.json",
		"responses_terminal.sse",
		"responses_incomplete.sse",
		"responses_failed.sse",
		"responses_malformed.sse",
		"responses_abrupt_close.sse",
		"responses_websocket.jsonl",
		"images_generation_request.json",
		"images_edit_request.json",
		"images_generation.json",
		"images_edit.json",
		"usage.json",
		"refresh_failure_transient.json",
		"error_usage_limit.json",
		"error_policy.json",
		"refresh_failure_permanent.json",
	}
	patterns := []*regexp.Regexp{
		regexp.MustCompile(`(?i)[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}`),
		regexp.MustCompile(`(?i)\bbearer\s+[a-z0-9._\-]{8,}`),
		regexp.MustCompile(`(?i)\b(?:sk|rk|pk|gh[pousr]|github_pat|xox[baprs])[-_][a-z0-9_-]{8,}`),
		regexp.MustCompile(`(?i)\bAKIA[0-9A-Z]{16}\b`),
		regexp.MustCompile(`eyJ[a-zA-Z0-9_-]{8,}\.[a-zA-Z0-9_-]{8,}\.[a-zA-Z0-9_-]{8,}`),
		regexp.MustCompile(`(?i)"(?:access|refresh|api)[_-]?token"\s*:\s*"[^"]{12,}"`),
		regexp.MustCompile(`(?i)"(?:client[_-]?secret|(?:api|access|refresh)[_-]?(?:key|token)|private[_-]?key|credentials?|password|passwd|secret|token)"\s*:\s*"[^"]{8,}"`),
		regexp.MustCompile(`(?i)(?:"(?:cookie|set[_-]?cookie|session(?:[_-]?id)?)"\s*:\s*"[^"]{8,}"|\b(?:cookie|set-cookie|session(?:[-_ ]?id)?)\s*[:=]\s*[^\s"';,]{8,})`),
	}
	for _, name := range fixtureNames {
		raw, err := os.ReadFile("testdata/" + name)
		if err != nil {
			t.Fatal(err)
		}
		for _, pattern := range patterns {
			if match := pattern.Find(raw); match != nil {
				t.Fatalf("fixture %s matches forbidden pattern %q", name, match)
			}
		}
	}
}

func TestCodexContentPartDecoderRejectsUnknownFields(t *testing.T) {
	var part CodexContentPart
	if err := json.Unmarshal([]byte(`{"type":"input_file","file_id":"file-123","unexpected":"value"}`), &part); err == nil {
		t.Fatal("unknown private output content field accepted")
	}
}
