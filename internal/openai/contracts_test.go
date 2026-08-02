package openai

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"regexp"
	"strings"
	"testing"
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
	if fixtures.Responses.Input == nil || len(fixtures.Responses.Input.Items) != 1 || len(fixtures.Responses.Tools) != 2 {
		t.Fatalf("Responses input = %#v", fixtures.Responses)
	}
	if !strings.Contains(string(fixtures.Responses.Input.Items[0].Content), "fixture-public-file-image") {
		t.Fatalf("input image = %s", fixtures.Responses.Input.Items[0].Content)
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
		roundTrip.Input == nil ||
		!strings.Contains(string(roundTrip.Input.Items[0].Content), "fixture-public-file-image") {
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
