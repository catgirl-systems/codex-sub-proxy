package codex

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"regexp"
	"strings"
	"testing"
)

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
	if len(request.Input) != 1 || len(request.Tools) != 1 || request.Tools[0].Type != "image_generation" {
		t.Fatalf("request shape = %#v", request)
	}
	encoded, err := json.Marshal(request)
	if err != nil {
		t.Fatalf("encode request: %v", err)
	}
	var roundTrip CodexResponseRequest
	if err := json.Unmarshal(encoded, &roundTrip); err != nil {
		t.Fatalf("decode encoded request: %v", err)
	}
	if roundTrip.Model != request.Model || roundTrip.Tools[0].Action != request.Tools[0].Action {
		t.Fatalf("round-trip request = %#v", roundTrip)
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
	encoded, err := json.Marshal(result.Events[len(result.Events)-1])
	if err != nil {
		t.Fatalf("encode WebSocket event: %v", err)
	}
	if _, err := DecodeCodexWebSocketFrame(encoded); err != nil {
		t.Fatalf("decode encoded WebSocket event: %v", err)
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
		if len(response.Data) != 1 || response.Data[0].B64JSON == "" {
			t.Fatalf("image response %s = %#v", name, response)
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
		var request CodexImageRequest
		if err := json.Unmarshal(raw, &request); err != nil {
			t.Fatalf("decode %s: %v", name, err)
		}
		if request.Model != "gpt-image-2" || request.ResponseFormat != "b64_json" {
			t.Fatalf("request %s = %#v", name, request)
		}
		if strings.Contains(request.Prompt, "real") {
			t.Fatalf("request %s contains non-synthetic prompt", name)
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
	if usage.InputTokensDetails.OrchestrationInputCachedTokens != 2 || usage.OutputTokensDetails.ReasoningTokens != 5 {
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
	if response.Headers == nil || response.Headers.PrimaryUsedPercent != 100 {
		t.Fatalf("rate headers = %#v", response.Headers)
	}
	mapped := MapUpstreamError(response.Status, nil, raw)
	if mapped.Category != CategoryUsageLimit || mapped.IsRetryable() {
		t.Fatalf("mapped error = %#v", mapped)
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
