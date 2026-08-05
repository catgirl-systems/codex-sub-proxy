package openai

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/go-playground/validator/v10"
)

type requestFixtures struct {
	Responses ResponseRequest        `json:"responses"`
	Images    ImageGenerationRequest `json:"images"`
	Edits     ImageEditRequest       `json:"edits"`
}

func TestResponsesRequestFixtureRoundTrips(t *testing.T) {
	raw, err := os.ReadFile("testdata/requests.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixtures requestFixtures
	if err := json.Unmarshal(raw, &fixtures); err != nil {
		t.Fatalf("decode requests: %v", err)
	}
	if fixtures.Responses.Model != "gpt-5.6-sol" || !fixtures.Responses.Stream {
		t.Fatalf("Responses request = %#v", fixtures.Responses)
	}
	if fixtures.Responses.Input == nil || len(fixtures.Responses.Input.Items) != 4 || len(fixtures.Responses.Tools) != 2 {
		t.Fatalf("Responses input = %#v", fixtures.Responses)
	}
	if !strings.Contains(string(fixtures.Responses.Input.Items[0].Content), "fixture-public-file-image") {
		t.Fatalf("input image = %s", fixtures.Responses.Input.Items[0].Content)
	}
	computerCall := fixtures.Responses.Input.Items[1]
	if computerCall.Status != "completed" || len(computerCall.Action) == 0 || len(computerCall.Actions) == 0 ||
		len(computerCall.PendingSafetyChecks) != 1 || computerCall.PendingSafetyChecks[0].Message != "fixture safety check" {
		t.Fatalf("computer call input = %#v", computerCall)
	}
	computerOutput := fixtures.Responses.Input.Items[2]
	if computerOutput.Status != "completed" || len(computerOutput.Output) == 0 ||
		len(computerOutput.AcknowledgedSafetyChecks) != 1 || computerOutput.AcknowledgedSafetyChecks[0].ID != "fixture-public-safety" {
		t.Fatalf("computer call output = %#v", computerOutput)
	}
	additionalTools := fixtures.Responses.Input.Items[3]
	if len(additionalTools.Tools) != 1 || additionalTools.Tools[0].Name != "fixture_function" {
		t.Fatalf("additional tools = %#v", additionalTools)
	}
	if fixtures.Responses.ToolChoice == nil || fixtures.Responses.ToolChoice.Type != ToolChoiceImageGeneration {
		t.Fatalf("tool choice = %#v", fixtures.Responses.ToolChoice)
	}
	if fixtures.Responses.Store == nil || *fixtures.Responses.Store ||
		fixtures.Responses.ParallelToolCalls == nil || *fixtures.Responses.ParallelToolCalls {
		t.Fatalf("presence-preserving request flags = %#v", fixtures.Responses)
	}
	imageTool := fixtures.Responses.Tools[0]
	if imageTool.PartialImages != 2 || imageTool.InputImageMask == nil ||
		imageTool.InputImageMask.FileID != "fixture-public-file-mask" {
		t.Fatalf("hosted image tool = %#v", imageTool)
	}
	functionTool := fixtures.Responses.Tools[1]
	if functionTool.Name != "fixture_function" || functionTool.Strict == nil || *functionTool.Strict {
		t.Fatalf("function tool = %#v", functionTool)
	}
	if fixtures.Images.Model != "gpt-image-2" || fixtures.Images.ResponseFormat != "b64_json" {
		t.Fatalf("Images request = %#v", fixtures.Images)
	}
	if len(fixtures.Edits.Images) != 1 || fixtures.Edits.Images[0][:len("data:image/png;base64,")] != "data:image/png;base64," {
		t.Fatalf("edit request = %#v", fixtures.Edits)
	}
	encoded, err := json.Marshal(fixtures.Responses)
	if err != nil {
		t.Fatalf("encode Responses request: %v", err)
	}
	var roundTrip ResponseRequest
	if err := json.Unmarshal(encoded, &roundTrip); err != nil {
		t.Fatalf("decode encoded Responses request: %v", err)
	}
	if roundTrip.Tools[0].PartialImages != 2 || roundTrip.Tools[1].Name != "fixture_function" ||
		roundTrip.Tools[1].Strict == nil || *roundTrip.Tools[1].Strict ||
		roundTrip.Store == nil || *roundTrip.Store ||
		roundTrip.ParallelToolCalls == nil || *roundTrip.ParallelToolCalls ||
		roundTrip.Input == nil || len(roundTrip.Input.Items) != 4 ||
		!strings.Contains(string(roundTrip.Input.Items[0].Content), "fixture-public-file-image") ||
		roundTrip.Input.Items[1].Status != "completed" || len(roundTrip.Input.Items[1].Action) == 0 ||
		len(roundTrip.Input.Items[1].Actions) == 0 || len(roundTrip.Input.Items[1].PendingSafetyChecks) != 1 ||
		roundTrip.Input.Items[2].Status != "completed" || len(roundTrip.Input.Items[2].Output) == 0 ||
		len(roundTrip.Input.Items[2].AcknowledgedSafetyChecks) != 1 ||
		len(roundTrip.Input.Items[3].Tools) != 1 {
		t.Fatalf("round-trip Responses request = %#v", roundTrip)
	}
}
func TestPublicRequestUnionsRoundTripAndRejectInvalidForms(t *testing.T) {
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
			raw:  `{"model":"gpt-5.6-sol","input":[{"type":"message","role":"user"}],"tool_choice":{"type":"function","name":"fixture_function"}}`,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var request ResponseRequest
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
		var request ResponseRequest
		if err := json.Unmarshal([]byte(raw), &request); err == nil {
			t.Fatalf("invalid union accepted: %s", raw)
		}
	}
	text := ""
	if _, err := json.Marshal(Input{}); err == nil {
		t.Fatal("empty input union encoded")
	}
	if _, err := json.Marshal(Input{String: &text, Items: []InputItem{}}); err == nil {
		t.Fatal("mixed input union encoded")
	}
	if _, err := json.Marshal(ToolChoice{}); err == nil {
		t.Fatal("empty tool choice union encoded")
	}
	if _, err := json.Marshal(ToolChoice{String: &text, Type: "function"}); err == nil {
		t.Fatal("mixed tool choice union encoded")
	}
}

func TestResponsesCompatibilityMatrix(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		check   func(*ResponseRequest) error
		wantErr error
	}{
		{
			name: "client metadata and generate",
			raw:  `{"model":"gpt-5.6-sol","client_metadata":{"trace":"fixture"},"generate":false}`,
			check: func(request *ResponseRequest) error {
				if request.ClientMetadata["trace"] != "fixture" || request.Generate == nil || *request.Generate {
					return errors.New("public client metadata/generate mapping changed")
				}
				return nil
			},
		},
		{
			name: "developer message and data image",
			raw:  `{"model":"gpt-5.6-sol","input":[{"type":"message","role":"developer","content":[{"type":"input_text","text":"fixture instructions"}]},{"type":"message","role":"user","content":[{"type":"input_image","image_url":"data:image/png;base64,AAAA"}]}]}`,
			check: func(request *ResponseRequest) error {
				if request.Input == nil || len(request.Input.Items) != 2 ||
					request.Input.Items[0].Role != "developer" ||
					!strings.Contains(string(request.Input.Items[1].Content), "data:image/png;base64,AAAA") {
					return errors.New("developer/image input mapping changed")
				}
				return nil
			},
		},
		{
			name: "additional tools namespace",
			raw:  `{"model":"gpt-5.6-sol","input":[{"type":"additional_tools","tools":[{"type":"namespace","name":"shell","tools":[{"type":"function","name":"exec"}]}]}]}`,
			check: func(request *ResponseRequest) error {
				if request.Input == nil || len(request.Input.Items) != 1 || len(request.Input.Items[0].Tools) != 1 ||
					request.Input.Items[0].Tools[0].Type != "namespace" ||
					len(request.Input.Items[0].Tools[0].Tools) != 1 ||
					request.Input.Items[0].Tools[0].Tools[0].Name != "exec" {
					return errors.New("additional namespace tools mapping changed")
				}
				return nil
			},
		},
		{
			name: "reasoning context and text format",
			raw:  `{"model":"gpt-5.6-sol","reasoning":{"effort":"high","context":"fixture-context"},"text":{"format":{"type":"json_schema","name":"fixture","schema":{"type":"object"},"strict":true}},"stream_options":{"reasoning_summary_delivery":"sequential_cutoff"}}`,
			check: func(request *ResponseRequest) error {
				if request.Reasoning == nil || request.Reasoning.Context != "fixture-context" ||
					request.Text == nil || request.Text.Format == nil || request.Text.Format.Name != "fixture" ||
					request.StreamOptions == nil || request.StreamOptions.ReasoningSummaryDelivery != "sequential_cutoff" {
					return errors.New("reasoning/text/stream options mapping changed")
				}
				return nil
			},
		},
		{
			name:    "metadata and client metadata conflict",
			raw:     `{"model":"gpt-5.6-sol","metadata":{"trace":"public"},"client_metadata":{"trace":"private"}}`,
			wantErr: errors.New("both metadata and client_metadata"),
		},
		{
			name:    "unsupported public parameter",
			raw:     `{"model":"gpt-5.6-sol","background":true}`,
			wantErr: ErrUnsupportedParameter,
		},
		{
			name:    "unsupported stream obfuscation",
			raw:     `{"model":"gpt-5.6-sol","stream_options":{"include_obfuscation":false}}`,
			wantErr: ErrUnsupportedParameter,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var request ResponseRequest
			err := json.Unmarshal([]byte(test.raw), &request)
			if test.wantErr != nil {
				if err == nil || (!errors.Is(test.wantErr, ErrUnsupportedParameter) && !strings.Contains(err.Error(), test.wantErr.Error())) ||
					(errors.Is(test.wantErr, ErrUnsupportedParameter) && !errors.Is(err, ErrUnsupportedParameter)) {
					t.Fatalf("error = %v, want %v", err, test.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("decode request: %v", err)
			}
			if err := test.check(&request); err != nil {
				t.Fatal(err)
			}
		})
	}

	var response Response
	if err := json.Unmarshal([]byte(`{"output":[{"type":"compaction","id":"cmp_1","encrypted_content":"fixture","created_by":"codex"}]}`), &response); err != nil {
		t.Fatalf("decode compaction output: %v", err)
	}
	if len(response.Output) != 1 || response.Output[0].Type != "compaction" ||
		response.Output[0].EncryptedContent != "fixture" || response.Output[0].CreatedBy != "codex" {
		t.Fatalf("compaction output = %#v", response.Output)
	}
}

func TestToolChoiceStrictDecoding(t *testing.T) {
	tests := []struct {
		name      string
		raw       string
		wantType  string
		wantName  string
		wantText  string
		wantError string
	}{
		{
			name:     "valid string",
			raw:      `"auto"`,
			wantText: "auto",
		},
		{
			name:     "valid object",
			raw:      `{"type":"function","name":"fixture_function"}`,
			wantType: "function",
			wantName: "fixture_function",
		},
		{
			name:      "unknown member",
			raw:       `{"type":"function","unknown":true}`,
			wantError: `decode public tool choice object: json: unknown field "unknown"`,
		},
		{
			name:      "trailing JSON",
			raw:       `{"type":"function"}{"type":"other"}`,
			wantError: "decode public tool choice object: multiple JSON values",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var choice ToolChoice
			err := choice.UnmarshalJSON([]byte(test.raw))
			if test.wantError != "" {
				if err == nil || !strings.Contains(err.Error(), test.wantError) {
					t.Fatalf("error = %v, want %q", err, test.wantError)
				}
				return
			}
			if err != nil {
				t.Fatalf("decode tool choice: %v", err)
			}
			if test.wantText != "" {
				if choice.String == nil || *choice.String != test.wantText {
					t.Fatalf("decoded string = %#v, want %q", choice.String, test.wantText)
				}
				return
			}
			if choice.String != nil || choice.Type != test.wantType || choice.Name != test.wantName {
				t.Fatalf("decoded object = %#v", choice)
			}
		})
	}
}

func TestPublicInputStrictDecodingRejectsUnknownNestedFields(t *testing.T) {
	tests := []string{
		`[{"typo":"message"}]`,
		`[{"type":"message","content":[{"type":"input_text","txet":"fixture"}]}]`,
		`[{"type":"computer_call_output","output":{"type":"computer_screenshot","file_id":"fixture","filed_id":"typo"}}]`,
		`[{"type":"computer_call","pending_safety_checks":[{"id":"fixture","idd":"typo"}]}]`,
		`[{"type":"additional_tools","tools":[{"type":"function","nam":"fixture"}]}]`,
		`[null]`,
		`[1]`,
	}
	for _, raw := range tests {
		var input Input
		if err := json.Unmarshal([]byte(raw), &input); err == nil {
			t.Fatalf("invalid input accepted: %s", raw)
		}
	}
}

func TestPublicResponsesCollectionBoundaries(t *testing.T) {
	tests := []struct {
		name  string
		limit int
		raw   func(int) string
	}{
		{
			name:  "input items",
			limit: maxResponsesInputItems,
			raw: func(count int) string {
				return responsesJSONList(count, `{"type":"message"}`)
			},
		},
		{
			name:  "content parts",
			limit: maxResponsesContentParts,
			raw: func(count int) string {
				return `[{"type":"message","content":` + responsesJSONList(count, `{"type":"input_text","text":"x"}`) + `}]`
			},
		},
		{
			name:  "output parts",
			limit: maxResponsesContentParts,
			raw: func(count int) string {
				return `[{"type":"computer_call_output","output":` + responsesJSONList(count, `{"type":"computer_screenshot","file_id":"x"}`) + `}]`
			},
		},
		{
			name:  "per-item tools",
			limit: maxResponsesItemTools,
			raw: func(count int) string {
				return `[{"type":"additional_tools","tools":` + responsesJSONList(count, `{"type":"function","name":"f"}`) + `}]`
			},
		},
		{
			name:  "pending safety checks",
			limit: maxResponsesSafetyChecks,
			raw: func(count int) string {
				return `[{"type":"computer_call","pending_safety_checks":` + responsesJSONList(count, `{"id":"check"}`) + `}]`
			},
		},
		{
			name:  "acknowledged safety checks",
			limit: maxResponsesSafetyChecks,
			raw: func(count int) string {
				return `[{"type":"computer_call_output","acknowledged_safety_checks":` + responsesJSONList(count, `{"id":"check"}`) + `}]`
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			for _, count := range []int{test.limit, test.limit + 1} {
				var input Input
				err := json.Unmarshal([]byte(test.raw(count)), &input)
				if count == test.limit {
					if err != nil {
						t.Fatalf("decode exact limit: %v", err)
					}
					if test.name == "input items" {
						if input.Items == nil || len(input.Items) != count {
							t.Fatalf("decoded input boundary = %#v", input)
						}
					} else if input.Items == nil || len(input.Items) != 1 {
						t.Fatalf("decoded nested boundary = %#v", input)
					}
					continue
				}
				if err == nil {
					t.Fatalf("accepted limit+1 collection")
				}
			}
		})
	}
}

func TestPublicResponsesTopLevelCollectionBoundaries(t *testing.T) {
	tests := []struct {
		name  string
		limit int
		body  func(int) string
		check func(*ResponseRequest, int) bool
	}{
		{
			name:  "tools",
			limit: maxResponsesItemTools,
			body: func(count int) string {
				return `{"model":"gpt-5.6-sol","tools":` + responsesJSONList(count, `{"type":"function","name":"f"}`) + `}`
			},
			check: func(request *ResponseRequest, count int) bool {
				return len(request.Tools) == count
			},
		},
		{
			name:  "include",
			limit: maxResponsesInclude,
			body: func(count int) string {
				return `{"model":"gpt-5.6-sol","include":` + responsesJSONList(count, `"reasoning.encrypted_content"`) + `}`
			},
			check: func(request *ResponseRequest, count int) bool {
				return len(request.Include) == count
			},
		},
		{
			name:  "metadata",
			limit: maxResponsesMetadata,
			body: func(count int) string {
				return `{"model":"gpt-5.6-sol","metadata":` + responsesJSONMetadata(count) + `}`
			},
			check: func(request *ResponseRequest, count int) bool {
				return len(request.Metadata) == count
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var request ResponseRequest
			if err := json.Unmarshal([]byte(test.body(test.limit)), &request); err != nil {
				t.Fatalf("decode exact limit: %v", err)
			}
			if !test.check(&request, test.limit) {
				t.Fatalf("decoded exact boundary = %#v", request)
			}
			if err := json.Unmarshal([]byte(test.body(test.limit+1)), &request); err == nil {
				t.Fatal("accepted limit+1 collection")
			}
		})
	}
}

func TestPublicResponsesTopLevelCollectionPresenceAndStrictness(t *testing.T) {
	tests := []struct {
		name            string
		raw             string
		wantToolsNil    bool
		wantIncludeNil  bool
		wantMetadataNil bool
		wantEmpty       string
	}{
		{
			name:            "omitted",
			raw:             `{"model":"gpt-5.6-sol"}`,
			wantToolsNil:    true,
			wantIncludeNil:  true,
			wantMetadataNil: true,
		},
		{
			name:            "null",
			raw:             `{"model":"gpt-5.6-sol","tools":null,"include":null,"metadata":null}`,
			wantToolsNil:    true,
			wantIncludeNil:  true,
			wantMetadataNil: true,
		},
		{
			name:      "empty",
			raw:       `{"model":"gpt-5.6-sol","tools":[],"include":[],"metadata":{}}`,
			wantEmpty: "all",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var request ResponseRequest
			if err := json.Unmarshal([]byte(test.raw), &request); err != nil {
				t.Fatalf("decode request: %v", err)
			}
			if (request.Tools == nil) != test.wantToolsNil ||
				(request.Include == nil) != test.wantIncludeNil ||
				(request.Metadata == nil) != test.wantMetadataNil {
				t.Fatalf("presence semantics = %#v", request)
			}
			if test.wantEmpty == "all" &&
				(len(request.Tools) != 0 || len(request.Include) != 0 || len(request.Metadata) != 0) {
				t.Fatalf("empty collection semantics = %#v", request)
			}
		})
	}

	for _, raw := range []string{
		`{"model":"gpt-5.6-sol","unknown":true}`,
		`{"model":"gpt-5.6-sol","metadata":{"trace":null}}`,
		`{"model":"gpt-5.6-sol","metadata":{"trace":1}}`,
		`{"model":"gpt-5.6-sol","metadata":{"trace":[]}}`,
		`{"model":"gpt-5.6-sol","metadata":{"trace":"first","trace":"second"}}`,
		`{"model":"gpt-5.6-sol","include":[1]}`,
		`{"model":"gpt-5.6-sol","tools":[]}[{"extra":true}]`,
	} {
		var request ResponseRequest
		if err := json.Unmarshal([]byte(raw), &request); err == nil {
			t.Fatalf("accepted invalid top-level request: %s", raw)
		}
	}
}

func TestPublicResponsesTopLevelCollectionsAcceptedControls(t *testing.T) {
	raw := `{"model":"gpt-5.6-sol","tools":[{"type":"function","name":"fixture"}],"include":["reasoning.encrypted_content"],"metadata":{"trace":"fixture","request":"accepted"}}`
	var request ResponseRequest
	if err := json.Unmarshal([]byte(raw), &request); err != nil {
		t.Fatalf("decode accepted controls: %v", err)
	}
	if len(request.Tools) != 1 || request.Tools[0].Name != "fixture" ||
		len(request.Include) != 1 || request.Include[0] != "reasoning.encrypted_content" ||
		len(request.Metadata) != 2 || request.Metadata["trace"] != "fixture" {
		t.Fatalf("accepted controls = %#v", request)
	}
}

func TestPublicInputRejectsTinyItemAmplification(t *testing.T) {
	raw := responsesJSONList(maxResponsesInputItems*192, `{"type":"message"}`)
	if len(raw) < 3*1024*1024 {
		t.Fatalf("stress input size = %d, want at least 3 MiB", len(raw))
	}
	var input Input
	if err := json.Unmarshal([]byte(raw), &input); err == nil {
		t.Fatal("accepted oversized tiny-item input")
	}
}

func responsesJSONList(count int, value string) string {
	var builder strings.Builder
	builder.Grow(count * (len(value) + 1))
	builder.WriteByte('[')
	for index := range count {
		if index > 0 {
			builder.WriteByte(',')
		}
		builder.WriteString(value)
	}
	builder.WriteByte(']')
	return builder.String()
}

func responsesJSONMetadata(count int) string {
	var builder strings.Builder
	builder.Grow(count * 8)
	builder.WriteByte('{')
	for index := range count {
		if index > 0 {
			builder.WriteByte(',')
		}
		builder.WriteByte('"')
		builder.WriteByte(byte('a' + index))
		builder.WriteString(`":"v"`)
	}
	builder.WriteByte('}')
	return builder.String()
}

func TestPublicInputValidationTraversesBoundedCollections(t *testing.T) {
	tests := []struct {
		name  string
		input Input
	}{
		{
			name:  "input items",
			input: Input{Items: make([]InputItem, maxResponsesInputItems+1)},
		},
		{
			name:  "per-item tools",
			input: Input{Items: []InputItem{{Tools: make([]Tool, maxResponsesItemTools+1)}}},
		},
		{
			name:  "pending safety checks",
			input: Input{Items: []InputItem{{PendingSafetyChecks: make([]SafetyCheck, maxResponsesSafetyChecks+1)}}},
		},
		{
			name:  "acknowledged safety checks",
			input: Input{Items: []InputItem{{AcknowledgedSafetyChecks: make([]SafetyCheck, maxResponsesSafetyChecks+1)}}},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := validator.New().Struct(ResponseRequest{Model: "gpt-5.6-sol", Input: &test.input}); err == nil {
				t.Fatal("nested collection exceeded its validation limit")
			}
		})
	}
}
func TestPublicStreamEventArgumentsAndAnnotationRoundTrip(t *testing.T) {

	raw := []byte(`{"type":"response.function_call_arguments.done","sequence_number":4,"item_id":"fixture-call","output_index":0,"arguments":"{\"value\":1}","annotation":{"type":"url_citation","url":"https://example.test"}}`)
	var event ResponseStreamEvent
	if err := json.Unmarshal(raw, &event); err != nil {
		t.Fatalf("decode event: %v", err)
	}
	if event.Type != EventFunctionArgsDone || event.Arguments != `{"value":1}` ||
		len(event.Annotation) == 0 || string(event.Annotation) != `{"type":"url_citation","url":"https://example.test"}` {
		t.Fatalf("decoded event = %#v", event)
	}
	encoded, err := json.Marshal(event)
	if err != nil {
		t.Fatalf("encode event: %v", err)
	}
	var roundTrip ResponseStreamEvent
	if err := json.Unmarshal(encoded, &roundTrip); err != nil {
		t.Fatalf("decode encoded event: %v", err)
	}
	if roundTrip.Type != event.Type || roundTrip.Arguments != event.Arguments ||
		string(roundTrip.Annotation) != string(event.Annotation) {
		t.Fatalf("event round-trip = %#v", roundTrip)
	}
}

func TestPublicResponsesSSEFixtureDecodesTypedEvents(t *testing.T) {
	raw, err := os.ReadFile("testdata/responses_terminal.sse")
	if err != nil {
		t.Fatal(err)
	}
	var events []ResponseStreamEvent
	for _, line := range strings.Split(string(raw), "\n") {
		if !strings.HasPrefix(line, "data:") {
			continue
		}
		payload := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
		if payload == "[DONE]" {
			continue
		}
		var event ResponseStreamEvent
		if err := json.Unmarshal([]byte(payload), &event); err != nil {
			t.Fatalf("decode SSE event: %v", err)
		}
		events = append(events, event)
	}
	if len(events) != 5 || events[len(events)-1].Type != EventCompleted {
		t.Fatalf("SSE events = %#v", events)
	}
	if events[0].SequenceNumber != 0 || events[1].SequenceNumber != 1 || events[2].SequenceNumber != 2 ||
		events[2].OutputIndex != 0 || events[2].PartialImageIndex != 0 || events[3].SequenceNumber != 3 ||
		events[4].SequenceNumber != 4 {
		t.Fatalf("SSE coordinates = %#v", events)
	}
	if events[2].Type != EventImageGenerationCallPartialImage || events[2].PartialImageB64 == "" {
		t.Fatalf("partial image event = %#v", events[2])
	}
	if events[3].Item == nil || events[3].Item.Type != ImageGenerationCall {
		t.Fatalf("image event = %#v", events[3])
	}
	for _, event := range events {
		encoded, err := json.Marshal(event)
		if err != nil {
			t.Fatalf("encode SSE event: %v", err)
		}
		var roundTrip ResponseStreamEvent
		if err := json.Unmarshal(encoded, &roundTrip); err != nil {
			t.Fatalf("decode encoded SSE event: %v", err)
		}
		if roundTrip.SequenceNumber != event.SequenceNumber || roundTrip.OutputIndex != event.OutputIndex ||
			roundTrip.ContentIndex != event.ContentIndex || roundTrip.SummaryIndex != event.SummaryIndex ||
			roundTrip.PartialImageIndex != event.PartialImageIndex ||
			roundTrip.PartialImageB64 != event.PartialImageB64 {
			t.Fatalf("round-trip SSE coordinates = %#v", roundTrip)
		}
	}
}

func TestPublicStreamCoordinatesRoundTripIncludingZero(t *testing.T) {
	raw := []byte(`{"type":"response.output_text.delta","sequence_number":0,"item_id":"synthetic-item","output_index":0,"content_index":0,"delta":"synthetic output"}`)
	var event ResponseStreamEvent
	if err := json.Unmarshal(raw, &event); err != nil {
		t.Fatalf("decode stream event: %v", err)
	}
	if event.SequenceNumber != 0 || event.OutputIndex != 0 || event.ContentIndex != 0 {
		t.Fatalf("stream coordinates = %#v", event)
	}
	encoded, err := json.Marshal(event)
	if err != nil {
		t.Fatalf("encode stream event: %v", err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &fields); err != nil {
		t.Fatalf("decode encoded stream event: %v", err)
	}
	for _, name := range []string{"sequence_number", "output_index", "content_index"} {
		if string(fields[name]) != "0" {
			t.Fatalf("encoded %s = %s", name, fields[name])
		}
	}
}

func TestPublicReasoningSummaryIndexRoundTripsZero(t *testing.T) {
	raw := []byte(`{"type":"response.reasoning_summary_text.delta","sequence_number":0,"item_id":"synthetic-reasoning","output_index":0,"summary_index":0,"delta":"synthetic summary"}`)
	var event ResponseStreamEvent
	if err := json.Unmarshal(raw, &event); err != nil {
		t.Fatalf("decode reasoning event: %v", err)
	}
	if event.SummaryIndex != 0 {
		t.Fatalf("reasoning summary index = %#v", event)
	}
	encoded, err := json.Marshal(event)
	if err != nil {
		t.Fatalf("encode reasoning event: %v", err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &fields); err != nil {
		t.Fatalf("decode encoded reasoning event: %v", err)
	}
	if string(fields["summary_index"]) != "0" {
		t.Fatalf("encoded summary index = %s", fields["summary_index"])
	}
}

func TestPublicResponsesTerminalFixtureIncludesHostedImage(t *testing.T) {
	raw, err := os.ReadFile("testdata/responses_terminal.json")
	if err != nil {
		t.Fatal(err)
	}
	var response Response
	if err := json.Unmarshal(raw, &response); err != nil {
		t.Fatalf("decode terminal response: %v", err)
	}
	if response.Status != ResponseStatusCompleted || len(response.Output) != 1 {
		t.Fatalf("response = %#v", response)
	}
	image := response.Output[0]
	if image.Type != ImageGenerationCall || image.Status != ResponseStatusCompleted || image.Result == "" {
		t.Fatalf("image output = %#v", image)
	}
	if _, err := base64.StdEncoding.DecodeString(image.Result); err != nil {
		t.Fatalf("decode hosted image: %v", err)
	}
	if response.Usage == nil || response.Usage.TotalTokens != 11 {
		t.Fatalf("usage = %#v", response.Usage)
	}
	encoded, err := json.Marshal(response)
	if err != nil {
		t.Fatalf("encode terminal response: %v", err)
	}
	var roundTrip Response
	if err := json.Unmarshal(encoded, &roundTrip); err != nil {
		t.Fatalf("decode encoded terminal response: %v", err)
	}
	if roundTrip.Output[0].RevisedPrompt != "a synthetic public icon" {
		t.Fatalf("round-trip output = %#v", roundTrip.Output[0])
	}
}

func TestPublicResponsesTextFixtureRoundTripsAnnotationsAndLogprobs(t *testing.T) {
	raw, err := os.ReadFile("testdata/responses_text.json")
	if err != nil {
		t.Fatal(err)
	}
	var response Response
	if err := json.Unmarshal(raw, &response); err != nil {
		t.Fatalf("decode text response: %v", err)
	}
	text := response.Output[0].Content[0]
	if len(text.Annotations) != 1 || len(text.Logprobs) != 1 ||
		text.Logprobs[0].Token != "fixture" || text.Logprobs[0].TopLogprobs[0].Logprob != -0.25 {
		t.Fatalf("text output = %#v", text)
	}
	encoded, err := json.Marshal(response)
	if err != nil {
		t.Fatalf("encode text response: %v", err)
	}
	var roundTrip Response
	if err := json.Unmarshal(encoded, &roundTrip); err != nil {
		t.Fatalf("decode encoded text response: %v", err)
	}
	roundText := roundTrip.Output[0].Content[0]
	if len(roundText.Annotations) != 1 || !strings.Contains(string(roundText.Annotations[0]), `"url_citation"`) ||
		roundText.Logprobs[0].Bytes[0] != 102 {
		t.Fatalf("round-trip text output = %#v", roundText)
	}
}

func TestPublicResponsesIncompleteFixture(t *testing.T) {
	raw, err := os.ReadFile("testdata/responses_incomplete.json")
	if err != nil {
		t.Fatal(err)
	}
	var response Response
	if err := json.Unmarshal(raw, &response); err != nil {
		t.Fatalf("decode incomplete response: %v", err)
	}
	if response.Status != ResponseStatusIncomplete || response.IncompleteDetails == nil {
		t.Fatalf("response = %#v", response)
	}
	if response.IncompleteDetails.Reason != "max_output_tokens" {
		t.Fatalf("incomplete details = %#v", response.IncompleteDetails)
	}
}

func TestPublicResponsesFailedFixture(t *testing.T) {
	raw, err := os.ReadFile("testdata/responses_failed.json")
	if err != nil {
		t.Fatal(err)
	}
	var response Response
	if err := json.Unmarshal(raw, &response); err != nil {
		t.Fatalf("decode failed response: %v", err)
	}
	if response.Status != ResponseStatusFailed || response.Error == nil {
		t.Fatalf("response = %#v", response)
	}
	if response.Error.Code != "server_error" || response.Error.Type != "server_error" {
		t.Fatalf("error = %#v", response.Error)
	}
}

func TestPublicImageFixturesDecode(t *testing.T) {
	for _, name := range []string{"images_generation.json", "images_edit.json"} {
		raw, err := os.ReadFile("testdata/" + name)
		if err != nil {
			t.Fatal(err)
		}
		var response ImageResponse
		if err := json.Unmarshal(raw, &response); err != nil {
			t.Fatalf("decode %s: %v", name, err)
		}
		if len(response.Data) != 1 || response.Data[0].B64JSON == "" {
			t.Fatalf("image response %s = %#v", name, response)
		}
		if _, err := base64.StdEncoding.DecodeString(response.Data[0].B64JSON); err != nil {
			t.Fatalf("decode image data %s: %v", name, err)
		}
	}
}
func TestPublicFixtureCredentialPatternsCatchCommonSentinels(t *testing.T) {
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

func TestPublicUsageAndErrorFixturesDecode(t *testing.T) {
	raw, err := os.ReadFile("testdata/usage.json")
	if err != nil {
		t.Fatal(err)
	}
	var usage Usage
	if err := json.Unmarshal(raw, &usage); err != nil {
		t.Fatalf("decode usage: %v", err)
	}
	if usage.TotalTokens != 44 || usage.InputTokensDetails == nil || usage.OutputTokensDetails == nil {
		t.Fatalf("usage = %#v", usage)
	}

	raw, err = os.ReadFile("testdata/error.json")
	if err != nil {
		t.Fatal(err)
	}
	var response ErrorResponse
	if err := json.Unmarshal(raw, &response); err != nil {
		t.Fatalf("decode error: %v", err)
	}
	if response.Error.Code != "model_not_available" || response.Error.Param != "model" {
		t.Fatalf("error = %#v", response.Error)
	}
}

func TestPublicFixturesContainNoCredentialPatterns(t *testing.T) {
	fixtureNames := []string{
		"requests.json",
		"responses_terminal.json",
		"responses_terminal.sse",
		"responses_text.json",
		"responses_incomplete.json",
		"responses_failed.json",
		"images_generation.json",
		"images_edit.json",
		"usage.json",
		"error.json",
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
