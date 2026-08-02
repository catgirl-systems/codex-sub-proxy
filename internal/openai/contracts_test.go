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
	if len(fixtures.Responses.Input) != 1 || len(fixtures.Responses.Tools) != 1 {
		t.Fatalf("Responses input = %#v", fixtures.Responses)
	}
	if fixtures.Responses.ToolChoice == nil || fixtures.Responses.ToolChoice.Type != ToolChoiceImageGeneration {
		t.Fatalf("tool choice = %#v", fixtures.Responses.ToolChoice)
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
	if roundTrip.Tools[0].Action != "generate" || roundTrip.ToolChoice.Type != ToolChoiceImageGeneration {
		t.Fatalf("round-trip Responses request = %#v", roundTrip)
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
	if len(events) != 4 || events[len(events)-1].Type != EventCompleted {
		t.Fatalf("SSE events = %#v", events)
	}
	if events[2].Item == nil || events[2].Item.Type != ImageGenerationCall {
		t.Fatalf("image event = %#v", events[2])
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
		regexp.MustCompile(`(?i)\b(?:sk|rk|pk|ghp|github_pat|xox[baprs])[-_][a-z0-9_-]{8,}`),
		regexp.MustCompile(`eyJ[a-zA-Z0-9_-]{8,}\.[a-zA-Z0-9_-]{8,}\.[a-zA-Z0-9_-]{8,}`),
		regexp.MustCompile(`(?i)"(?:access|refresh|api)[_-]?token"\s*:\s*"[^"]{12,}"`),
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
