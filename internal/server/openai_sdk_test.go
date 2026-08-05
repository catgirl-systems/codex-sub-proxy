package server

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/catgirl-systems/codex-sub-proxy/internal/codex"
	sdk "github.com/openai/openai-go/v3"
	"github.com/openai/openai-go/v3/option"
	"github.com/openai/openai-go/v3/packages/param"
	"github.com/openai/openai-go/v3/responses"
	"github.com/openai/openai-go/v3/shared"
)

func TestOfficialOpenAISDKUsesOnlyBaseURLAndAPIKey(t *testing.T) {
	fixture, err := os.ReadFile(filepath.Join("..", "codex", "testdata", "responses_terminal.sse"))
	if err != nil {
		t.Fatal(err)
	}
	upstream := newResponseFixtureUpstream(t, fixture)
	defer upstream.Close()
	servers, rawKey := newResponsesTestServer(t, upstream.URL, nil)
	defer shutdownResponsesTestServer(t, servers)

	client := sdk.NewClient(
		option.WithBaseURL("http://"+servers.DataAddr()+"/v1/"),
		option.WithAPIKey(rawKey),
	)
	params := responses.ResponseNewParams{
		Model: shared.ResponsesModel("gpt-5.6-sol"),
		Input: responses.ResponseNewParamsInputUnion{OfString: sdk.String("fixture input")},
	}
	result, err := client.Responses.New(context.Background(), params)
	if err != nil {
		t.Fatalf("official SDK JSON call: %v", err)
	}
	if result == nil || result.Status != "completed" || len(result.Output) == 0 || result.Output[0].Type != "image_generation_call" {
		t.Fatalf("official SDK JSON result = %#v", result)
	}
	if _, ok := result.Output[0].AsAny().(responses.ResponseOutputItemImageGenerationCall); !ok {
		t.Fatalf("official SDK image output union = %T", result.Output[0].AsAny())
	}

	stream := client.Responses.NewStreaming(context.Background(), params)
	eventCount := 0
	terminalCount := 0
	sawTypedCompleted := false
	for stream.Next() {
		eventCount++
		event := stream.Current()
		switch event.Type {
		case "response.completed", "response.done", "response.incomplete", "response.failed", "error":
			terminalCount++
		}
		if event.Type == "response.completed" {
			if _, ok := event.AsAny().(responses.ResponseCompletedEvent); !ok {
				t.Fatalf("official SDK completed union = %T", event.AsAny())
			}
			sawTypedCompleted = true
		}
	}
	if err := stream.Err(); err != nil {
		t.Fatalf("official SDK streaming call: %v", err)
	}
	if eventCount == 0 || terminalCount != 1 || !sawTypedCompleted {
		t.Fatalf("official SDK stream events = %d, terminals = %d, typed completed = %t", eventCount, terminalCount, sawTypedCompleted)
	}
}

func TestOfficialOpenAISDKNonstreamSurvivesWriteTimeout(t *testing.T) {
	fixture, err := os.ReadFile(filepath.Join("..", "codex", "testdata", "responses_terminal.sse"))
	if err != nil {
		t.Fatal(err)
	}
	upstreamStarted := make(chan struct{})
	releaseUpstream := make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "text/event-stream")
		writer.WriteHeader(http.StatusOK)
		close(upstreamStarted)
		<-releaseUpstream
		_, _ = writer.Write(fixture)
	}))
	defer upstream.Close()
	testWriteTimeout := 100 * time.Millisecond
	servers, rawKey := newResponsesTestServer(t, upstream.URL, nil, testWriteTimeout)
	defer shutdownResponsesTestServer(t, servers)

	client := sdk.NewClient(
		option.WithBaseURL("http://"+servers.DataAddr()+"/v1/"),
		option.WithAPIKey(rawKey),
	)
	params := responses.ResponseNewParams{
		Model: shared.ResponsesModel("gpt-5.6-sol"),
		Input: responses.ResponseNewParamsInputUnion{OfString: sdk.String("fixture input")},
	}
	type responseResult struct {
		value *responses.Response
		err   error
	}
	resultCh := make(chan responseResult, 1)
	requestContext, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	go func() {
		value, requestErr := client.Responses.New(requestContext, params)
		resultCh <- responseResult{value: value, err: requestErr}
	}()
	select {
	case <-upstreamStarted:
	case <-time.After(time.Second):
		t.Fatal("upstream request did not start")
	}
	releaseTimer := time.NewTimer(testWriteTimeout + 100*time.Millisecond)
	defer releaseTimer.Stop()
	select {
	case result := <-resultCh:
		t.Fatalf("nonstream response completed before upstream release: value=%#v err=%v", result.value, result.err)
	case <-releaseTimer.C:
	}
	close(releaseUpstream)

	select {
	case result := <-resultCh:
		if result.err != nil {
			t.Fatalf("official SDK delayed JSON call: %v", result.err)
		}
		if result.value == nil || result.value.Status != "completed" || len(result.value.Output) == 0 {
			t.Fatalf("official SDK delayed JSON result = %#v", result.value)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("official SDK delayed JSON response did not arrive")
	}
}

func TestOfficialOpenAISDKReceivesTypedStreamError(t *testing.T) {
	fixture := []byte("data: {\"type\":\"response.output_text.delta\",\"sequence_number\":1,\"delta\":\"visible\",\"error\":{\"code\":\"provider-code\",\"type\":\"provider_error\",\"message\":\"private provider message\"}}\n\ndata: {\"type\":\"response.completed\",\"sequence_number\":2,\"response\":{\"status\":\"completed\"}}\n\ndata: [DONE]\n\n")
	upstream := newResponseFixtureUpstream(t, fixture)
	defer upstream.Close()
	servers, rawKey := newResponsesTestServer(t, upstream.URL, nil)
	defer shutdownResponsesTestServer(t, servers)

	client := sdk.NewClient(
		option.WithBaseURL("http://"+servers.DataAddr()+"/v1/"),
		option.WithAPIKey(rawKey),
	)
	stream := client.Responses.NewStreaming(context.Background(), responses.ResponseNewParams{
		Model: shared.ResponsesModel("gpt-5.6-sol"),
		Input: responses.ResponseNewParamsInputUnion{OfString: sdk.String("fixture input")},
	})
	errorCount := 0
	var errorEvent responses.ResponseErrorEvent
	for stream.Next() {
		event := stream.Current()
		if event.Type != "error" {
			continue
		}
		var ok bool
		errorEvent, ok = event.AsAny().(responses.ResponseErrorEvent)
		if !ok {
			t.Fatalf("official SDK error union = %T", event.AsAny())
		}
		errorCount++
	}
	if err := stream.Err(); err != nil {
		t.Fatalf("official SDK stream error event: %v", err)
	}
	if errorCount != 1 || errorEvent.Code != "provider-code" ||
		errorEvent.Message != "The upstream service returned an error." {
		t.Fatalf("official SDK error events = %d, event = %#v", errorCount, errorEvent)
	}
}
func TestOfficialOpenAISDKComputerCallRoundTrip(t *testing.T) {
	fixture := []byte("data: {\"type\":\"response.created\",\"sequence_number\":0,\"response\":{\"id\":\"computer-response\",\"object\":\"response\",\"model\":\"gpt-5.6-sol\",\"status\":\"in_progress\"}}\n\ndata: {\"type\":\"response.output_item.added\",\"sequence_number\":1,\"output_index\":0,\"item\":{\"id\":\"computer-item\",\"type\":\"computer_call\",\"call_id\":\"computer-call\",\"status\":\"completed\",\"action\":{\"type\":\"click\",\"button\":\"left\",\"x\":4,\"y\":5},\"pending_safety_checks\":[{\"id\":\"safety-check\",\"code\":\"confirm\",\"message\":\"confirm action\"}],\"acknowledged_safety_checks\":[{\"id\":\"safety-check\",\"code\":\"confirm\",\"message\":\"confirm action\"}]}}\n\ndata: {\"type\":\"response.output_item.done\",\"sequence_number\":2,\"output_index\":0,\"item\":{\"id\":\"computer-item\",\"type\":\"computer_call\",\"call_id\":\"computer-call\",\"status\":\"completed\",\"action\":{\"type\":\"click\",\"button\":\"left\",\"x\":4,\"y\":5},\"pending_safety_checks\":[{\"id\":\"safety-check\",\"code\":\"confirm\",\"message\":\"confirm action\"}],\"acknowledged_safety_checks\":[{\"id\":\"safety-check\",\"code\":\"confirm\",\"message\":\"confirm action\"}]}}\n\ndata: {\"type\":\"response.completed\",\"sequence_number\":3,\"response\":{\"id\":\"computer-response\",\"object\":\"response\",\"model\":\"gpt-5.6-sol\",\"status\":\"completed\",\"output\":[{\"id\":\"computer-item\",\"type\":\"computer_call\",\"call_id\":\"computer-call\",\"status\":\"completed\",\"action\":{\"type\":\"click\",\"button\":\"left\",\"x\":4,\"y\":5},\"pending_safety_checks\":[{\"id\":\"safety-check\",\"code\":\"confirm\",\"message\":\"confirm action\"}],\"acknowledged_safety_checks\":[{\"id\":\"safety-check\",\"code\":\"confirm\",\"message\":\"confirm action\"}]}]}}\n\ndata: [DONE]\n\n")
	upstream := newResponseFixtureUpstream(t, fixture)
	defer upstream.Close()
	servers, rawKey := newResponsesTestServer(t, upstream.URL, nil)
	defer shutdownResponsesTestServer(t, servers)

	client := sdk.NewClient(
		option.WithBaseURL("http://"+servers.DataAddr()+"/v1/"),
		option.WithAPIKey(rawKey),
	)
	params := responses.ResponseNewParams{
		Model: shared.ResponsesModel("gpt-5.6-sol"),
		Input: responses.ResponseNewParamsInputUnion{OfString: sdk.String("fixture input")},
	}
	result, err := client.Responses.New(context.Background(), params)
	if err != nil {
		t.Fatalf("official SDK computer-call response: %v", err)
	}
	if result == nil || len(result.Output) != 1 {
		t.Fatalf("official SDK computer-call output = %#v", result)
	}
	computerCall, ok := result.Output[0].AsAny().(responses.ResponseComputerToolCall)
	if !ok || computerCall.CallID != "computer-call" || computerCall.Action.Type != "click" ||
		computerCall.Action.X != 4 || computerCall.Action.Y != 5 ||
		len(computerCall.PendingSafetyChecks) != 1 ||
		computerCall.PendingSafetyChecks[0].Message != "confirm action" ||
		!bytes.Contains([]byte(result.Output[0].RawJSON()), []byte(`"acknowledged_safety_checks"`)) {
		t.Fatalf("official SDK computer-call output = %#v", result.Output[0])
	}

	stream := client.Responses.NewStreaming(context.Background(), params)
	var added responses.ResponseOutputItemAddedEvent
	for stream.Next() {
		event := stream.Current()
		if event.Type != "response.output_item.added" {
			continue
		}
		var eventOK bool
		added, eventOK = event.AsAny().(responses.ResponseOutputItemAddedEvent)
		if !eventOK {
			t.Fatalf("official SDK computer-call stream union = %T", event.AsAny())
		}
	}
	if err := stream.Err(); err != nil {
		t.Fatalf("official SDK computer-call stream: %v", err)
	}
	streamComputerCall, ok := added.Item.AsAny().(responses.ResponseComputerToolCall)
	if !ok || streamComputerCall.Action.Type != "click" ||
		len(streamComputerCall.PendingSafetyChecks) != 1 ||
		!bytes.Contains([]byte(added.Item.RawJSON()), []byte(`"acknowledged_safety_checks"`)) {
		t.Fatalf("official SDK computer-call stream output = %#v", added.Item)
	}
}
func TestOfficialOpenAISDKComputerCallRequestReachesCodex(t *testing.T) {
	fixture, err := os.ReadFile(filepath.Join("..", "codex", "testdata", "responses_terminal.sse"))
	if err != nil {
		t.Fatal(err)
	}
	var upstreamBody atomic.Value
	upstream := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		body, readErr := io.ReadAll(request.Body)
		if readErr != nil {
			t.Errorf("read upstream request: %v", readErr)
		}
		upstreamBody.Store(body)
		writer.Header().Set("Content-Type", "text/event-stream")
		_, _ = writer.Write(fixture)
	}))
	defer upstream.Close()
	servers, rawKey := newResponsesTestServer(t, upstream.URL, nil)
	defer shutdownResponsesTestServer(t, servers)

	computerCall := responses.ResponseComputerToolCallParam{
		ID: "sdk-computer",
		Action: responses.ResponseComputerToolCallActionUnionParam{
			OfClick: &responses.ResponseComputerToolCallActionClickParam{
				Button: "left",
				X:      4,
				Y:      5,
			},
		},
		CallID: "sdk-computer-call",
		PendingSafetyChecks: []responses.ResponseComputerToolCallPendingSafetyCheckParam{{
			ID:      "sdk-safety",
			Code:    param.NewOpt("confirm"),
			Message: param.NewOpt("sdk safety"),
		}},
		Status: "completed",
		Type:   "computer_call",
	}
	computerOutput := responses.ResponseInputItemComputerCallOutputParam{
		CallID: "sdk-computer-call",
		Output: responses.ResponseComputerToolCallOutputScreenshotParam{
			FileID: param.NewOpt("sdk-screen"),
			Type:   "computer_screenshot",
		},
		AcknowledgedSafetyChecks: []responses.ResponseInputItemComputerCallOutputAcknowledgedSafetyCheckParam{{
			ID:      "sdk-safety",
			Code:    param.NewOpt("confirm"),
			Message: param.NewOpt("sdk safety"),
		}},
		Status: "completed",
		Type:   "computer_call_output",
	}
	params := responses.ResponseNewParams{
		Model: shared.ResponsesModel("gpt-5.6-sol"),
		Input: responses.ResponseNewParamsInputUnion{
			OfInputItemList: responses.ResponseInputParam{
				{OfComputerCall: &computerCall},
				{OfComputerCallOutput: &computerOutput},
			},
		},
	}
	client := sdk.NewClient(
		option.WithBaseURL("http://"+servers.DataAddr()+"/v1/"),
		option.WithAPIKey(rawKey),
	)
	if _, err := client.Responses.New(context.Background(), params); err != nil {
		t.Fatalf("official SDK computer-call request: %v", err)
	}
	body, ok := upstreamBody.Load().([]byte)
	if !ok {
		t.Fatal("upstream computer-call request was not captured")
	}
	var privateRequest codex.CodexResponseRequest
	if err := json.Unmarshal(body, &privateRequest); err != nil {
		t.Fatalf("decode upstream computer-call request: %v", err)
	}
	if privateRequest.Input == nil || len(privateRequest.Input.Items) != 2 {
		t.Fatalf("private SDK computer-call input = %#v", privateRequest.Input)
	}
	call := privateRequest.Input.Items[0]
	var action struct {
		Type   string `json:"type"`
		Button string `json:"button"`
		X      int    `json:"x"`
		Y      int    `json:"y"`
	}
	if err := json.Unmarshal(call.Action, &action); err != nil {
		t.Fatalf("decode private SDK computer action: %v", err)
	}
	if call.Status != "completed" || action.Type != "click" || action.Button != "left" ||
		action.X != 4 || action.Y != 5 || len(call.PendingSafetyChecks) != 1 ||
		call.PendingSafetyChecks[0].Message != "sdk safety" {
		t.Fatalf("private SDK computer call = %#v", call)
	}
	output := privateRequest.Input.Items[1]
	if output.Status != "completed" || string(output.Output) != `{"file_id":"sdk-screen","type":"computer_screenshot"}` ||
		len(output.AcknowledgedSafetyChecks) != 1 || output.AcknowledgedSafetyChecks[0].ID != "sdk-safety" {
		t.Fatalf("private SDK computer output = %#v", output)
	}
}
func TestOfficialOpenAISDKNormalizesResponseDone(t *testing.T) {
	fixture := []byte("data: {\"type\":\"response.done\",\"sequence_number\":1,\"response\":{\"id\":\"resp_done\",\"object\":\"response\",\"model\":\"gpt-5.6-sol\",\"status\":\"completed\"}}\n\ndata: [DONE]\n\n")
	upstream := newResponseFixtureUpstream(t, fixture)
	defer upstream.Close()
	servers, rawKey := newResponsesTestServer(t, upstream.URL, nil)
	defer shutdownResponsesTestServer(t, servers)

	client := sdk.NewClient(
		option.WithBaseURL("http://"+servers.DataAddr()+"/v1/"),
		option.WithAPIKey(rawKey),
	)
	stream := client.Responses.NewStreaming(context.Background(), responses.ResponseNewParams{
		Model: shared.ResponsesModel("gpt-5.6-sol"),
		Input: responses.ResponseNewParamsInputUnion{OfString: sdk.String("fixture input")},
	})
	var completed responses.ResponseCompletedEvent
	for stream.Next() {
		event := stream.Current()
		if event.Type == "response.completed" {
			var ok bool
			completed, ok = event.AsAny().(responses.ResponseCompletedEvent)
			if !ok {
				t.Fatalf("response.done normalized union = %T", event.AsAny())
			}
		}
	}
	if err := stream.Err(); err != nil {
		t.Fatalf("official SDK normalized stream: %v", err)
	}
	if completed.Response.ID != "resp_done" || completed.Response.Status != "completed" {
		t.Fatalf("normalized completed response = %#v", completed.Response)
	}
}
func TestOfficialOpenAISDKReceivesTypedFailedResponse(t *testing.T) {
	fixture, err := os.ReadFile(filepath.Join("..", "codex", "testdata", "responses_failed.sse"))
	if err != nil {
		t.Fatal(err)
	}
	upstream := newResponseFixtureUpstream(t, fixture)
	defer upstream.Close()
	servers, rawKey := newResponsesTestServer(t, upstream.URL, nil)
	defer shutdownResponsesTestServer(t, servers)

	client := sdk.NewClient(
		option.WithBaseURL("http://"+servers.DataAddr()+"/v1/"),
		option.WithAPIKey(rawKey),
	)
	stream := client.Responses.NewStreaming(context.Background(), responses.ResponseNewParams{
		Model: shared.ResponsesModel("gpt-5.6-sol"),
		Input: responses.ResponseNewParamsInputUnion{OfString: sdk.String("fixture input")},
	})
	var failed responses.ResponseFailedEvent
	for stream.Next() {
		event := stream.Current()
		if event.Type != "response.failed" {
			continue
		}
		var ok bool
		failed, ok = event.AsAny().(responses.ResponseFailedEvent)
		if !ok {
			t.Fatalf("official SDK failed union = %T", event.AsAny())
		}
	}
	if err := stream.Err(); err != nil {
		t.Fatalf("official SDK failed stream: %v", err)
	}
	if string(failed.Response.Status) != "failed" || string(failed.Response.Error.Code) != "server_error" ||
		failed.Response.Error.Message != "The upstream service returned an error." {
		t.Fatalf("official SDK failed response = %#v", failed.Response)
	}
	if bytes.Contains([]byte(failed.RawJSON()), []byte("synthetic upstream failure")) {
		t.Fatal("private provider failure message leaked through SDK failed event")
	}
}

func TestOfficialOpenAISDKReceivesTypedSafeError(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.WriteHeader(http.StatusInternalServerError)
		_, _ = io.WriteString(writer, `{"error":{"message":"private provider message"}}`)
	}))
	defer upstream.Close()
	servers, rawKey := newResponsesTestServer(t, upstream.URL, nil)
	defer shutdownResponsesTestServer(t, servers)

	client := sdk.NewClient(
		option.WithBaseURL("http://"+servers.DataAddr()+"/v1/"),
		option.WithAPIKey(rawKey),
	)
	stream := client.Responses.NewStreaming(context.Background(), responses.ResponseNewParams{
		Model: shared.ResponsesModel("gpt-5.6-sol"),
		Input: responses.ResponseNewParamsInputUnion{OfString: sdk.String("fixture input")},
	})
	var safeError responses.ResponseErrorEvent
	for stream.Next() {
		event := stream.Current()
		if event.Type == "error" {
			var ok bool
			safeError, ok = event.AsAny().(responses.ResponseErrorEvent)
			if !ok {
				t.Fatalf("official SDK error union = %T", event.AsAny())
			}
		}
	}
	if err := stream.Err(); err != nil {
		t.Fatalf("official SDK error stream: %v", err)
	}
	if safeError.Type != "error" || safeError.Code == "" || safeError.Message == "" || safeError.Param != "" || safeError.SequenceNumber != 0 {
		t.Fatalf("official SDK safe error = %#v", safeError)
	}
	if bytes.Contains([]byte(safeError.RawJSON()), []byte("private provider message")) {
		t.Fatal("private provider message leaked through SDK error")
	}
}

func TestOfficialOpenAISDKReceivesTypedPrivateEventError(t *testing.T) {
	fixture := []byte("data: {\"type\":\"response.output_text.delta\",\"sequence_number\":1,\"delta\":\"visible\",\"param\":\"prompt\",\"error\":{\"code\":\"server_error\",\"type\":\"provider_error\",\"message\":\"private provider message\",\"plan_type\":\"pro\",\"retry_after\":4.5,\"resets_at\":1738888890}}\n\ndata: {\"type\":\"response.completed\",\"sequence_number\":2,\"response\":{\"status\":\"completed\"}}\n\ndata: [DONE]\n\n")
	upstream := newResponseFixtureUpstream(t, fixture)
	defer upstream.Close()
	servers, rawKey := newResponsesTestServer(t, upstream.URL, nil)
	defer shutdownResponsesTestServer(t, servers)

	client := sdk.NewClient(
		option.WithBaseURL("http://"+servers.DataAddr()+"/v1/"),
		option.WithAPIKey(rawKey),
	)
	stream := client.Responses.NewStreaming(context.Background(), responses.ResponseNewParams{
		Model: shared.ResponsesModel("gpt-5.6-sol"),
		Input: responses.ResponseNewParamsInputUnion{OfString: sdk.String("fixture input")},
	})
	var safeError responses.ResponseErrorEvent
	for stream.Next() {
		event := stream.Current()
		if event.Type != "error" {
			continue
		}
		var ok bool
		safeError, ok = event.AsAny().(responses.ResponseErrorEvent)
		if !ok {
			t.Fatalf("official SDK private error union = %T", event.AsAny())
		}
	}
	if err := stream.Err(); err != nil {
		t.Fatalf("official SDK private error stream: %v", err)
	}
	if safeError.Code != "server_error" || safeError.Message != "The upstream service returned an error." ||
		safeError.Param != "prompt" || safeError.SequenceNumber != 1 {
		t.Fatalf("official SDK private error = %#v", safeError)
	}
	if bytes.Contains([]byte(safeError.RawJSON()), []byte("private provider message")) {
		t.Fatal("private provider message leaked through SDK private error")
	}
}

func newResponseFixtureUpstream(t *testing.T, fixture []byte) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost || request.URL.Path != "/" {
			t.Errorf("upstream request = %s %s, want POST /", request.Method, request.URL.Path)
		}
		if request.Header.Get("Authorization") != "Bearer access" {
			t.Errorf("upstream authorization = %q", request.Header.Get("Authorization"))
		}
		if request.Header.Get("Content-Type") != "application/json" || request.Header.Get("Accept") != "text/event-stream" {
			t.Errorf("upstream headers = %#v", request.Header)
		}
		body, err := io.ReadAll(request.Body)
		if err != nil {
			t.Errorf("read upstream body: %v", err)
		}
		if !bytes.Contains(body, []byte(`"model":"gpt-5.6-sol"`)) ||
			!bytes.Contains(body, []byte(`"stream":true`)) ||
			bytes.Contains(body, []byte(`"response.create"`)) {
			t.Errorf("upstream body = %s", body)
		}
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(body, &fields); err != nil {
			t.Errorf("decode upstream body: %v", err)
		}
		if _, ok := fields["model"]; !ok {
			t.Error("upstream body omitted model")
		}
		writer.Header().Set("Content-Type", "text/event-stream")
		_, _ = writer.Write(fixture)
	}))
}
