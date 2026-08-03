package server

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/catgirl-systems/codex-sub-proxy/internal/apikey"
	"github.com/catgirl-systems/codex-sub-proxy/internal/codex"
	"github.com/catgirl-systems/codex-sub-proxy/internal/envelope"
	"github.com/catgirl-systems/codex-sub-proxy/internal/storage"
)

func TestResponsesJSONPreservesImageAndUsage(t *testing.T) {
	var upstreamCalls atomic.Int32
	fixture, err := os.ReadFile(filepath.Join("..", "codex", "testdata", "responses_terminal.sse"))
	if err != nil {
		t.Fatal(err)
	}
	upstream := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		upstreamCalls.Add(1)
		writer.Header().Set("Content-Type", "text/event-stream")
		_, _ = writer.Write(fixture)
	}))
	defer upstream.Close()

	servers, rawKey := newResponsesTestServer(t, upstream.URL, nil)
	defer shutdownResponsesTestServer(t, servers)

	requestBody := `{"model":"gpt-5.6-sol","stream":false,"tools":[{"type":"image_generation"}]}`
	response := doResponsesRequest(t, servers.DataAddr(), rawKey, requestBody, "application/json")
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(response.Body)
		t.Fatalf("status = %d, body = %s", response.StatusCode, body)
	}
	var value struct {
		Status string `json:"status"`
		Output []struct {
			Type   string `json:"type"`
			Result string `json:"result"`
		} `json:"output"`
		Usage struct {
			InputTokens int `json:"input_tokens"`
			TotalTokens int `json:"total_tokens"`
		} `json:"usage"`
	}
	if err := json.NewDecoder(response.Body).Decode(&value); err != nil {
		t.Fatal(err)
	}
	if value.Status != "completed" || len(value.Output) != 1 || value.Output[0].Type != "image_generation_call" || value.Output[0].Result == "" {
		t.Fatalf("response = %#v", value)
	}
	if value.Usage.InputTokens != 12 || value.Usage.TotalTokens != 20 {
		t.Fatalf("usage = %#v", value.Usage)
	}
	if upstreamCalls.Load() != 1 {
		t.Fatalf("upstream calls = %d, want 1", upstreamCalls.Load())
	}
}
func TestResponsesComputerCallFieldsReachCodex(t *testing.T) {
	fixture, err := os.ReadFile(filepath.Join("..", "codex", "testdata", "responses_terminal.sse"))
	if err != nil {
		t.Fatal(err)
	}
	var upstreamBody atomic.Value
	upstream := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		body, readErr := io.ReadAll(request.Body)
		if readErr != nil {
			t.Errorf("read upstream body: %v", readErr)
		}
		upstreamBody.Store(body)
		writer.Header().Set("Content-Type", "text/event-stream")
		_, _ = writer.Write(fixture)
	}))
	defer upstream.Close()
	servers, rawKey := newResponsesTestServer(t, upstream.URL, nil)
	defer shutdownResponsesTestServer(t, servers)

	requestBody := `{"model":"gpt-5.6-sol","input":[{"type":"computer_call","id":"public-computer","call_id":"public-call","action":{"type":"click","button":"left","x":4,"y":5},"actions":[{"type":"screenshot"}],"pending_safety_checks":[{"id":"public-safety","code":"confirm","message":"public safety"}],"status":"completed"},{"type":"computer_call_output","call_id":"public-call","output":{"type":"computer_screenshot","file_id":"public-screen"},"acknowledged_safety_checks":[{"id":"public-safety","code":"confirm","message":"public safety"}],"status":"completed"},{"type":"additional_tools","role":"developer","tools":[{"type":"function","name":"public-function","parameters":{"type":"object"},"strict":false}]},{"type":"function_call","call_id":"public-function-call","name":"public-function","arguments":"{\"value\":1}"}]}`
	response := doResponsesRequest(t, servers.DataAddr(), rawKey, requestBody, "application/json")
	response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("computer-call request status = %d", response.StatusCode)
	}
	body, ok := upstreamBody.Load().([]byte)
	if !ok {
		t.Fatal("upstream request body was not captured")
	}
	var privateRequest codex.CodexResponseRequest
	if err := json.Unmarshal(body, &privateRequest); err != nil {
		t.Fatalf("decode private computer-call request: %v", err)
	}
	if privateRequest.Input == nil || len(privateRequest.Input.Items) != 4 {
		t.Fatalf("private computer-call input = %#v", privateRequest.Input)
	}
	computerCall := privateRequest.Input.Items[0]
	if computerCall.Status != "completed" || string(computerCall.Action) != `{"type":"click","button":"left","x":4,"y":5}` ||
		string(computerCall.Actions) != `[{"type":"screenshot"}]` || len(computerCall.PendingSafetyChecks) != 1 ||
		computerCall.PendingSafetyChecks[0].Message != "public safety" {
		t.Fatalf("private computer call = %#v", computerCall)
	}
	computerOutput := privateRequest.Input.Items[1]
	if computerOutput.Status != "completed" || string(computerOutput.Output) != `{"type":"computer_screenshot","file_id":"public-screen"}` ||
		len(computerOutput.AcknowledgedSafetyChecks) != 1 ||
		computerOutput.AcknowledgedSafetyChecks[0].ID != "public-safety" {
		t.Fatalf("private computer output = %#v", computerOutput)
	}
	functionCall := privateRequest.Input.Items[3]
	if functionCall.Arguments == nil || string(functionCall.Arguments) != `"{\"value\":1}"` {
		t.Fatalf("private function call arguments = %s", functionCall.Arguments)
	}
	for index, item := range privateRequest.Input.Items[:3] {
		var fields map[string]json.RawMessage
		encoded, err := json.Marshal(item)
		if err != nil {
			t.Fatalf("encode private input item %d: %v", index, err)
		}
		if err := json.Unmarshal(encoded, &fields); err != nil {
			t.Fatalf("decode private input item %d: %v", index, err)
		}
		if _, found := fields["arguments"]; found {
			t.Fatalf("private input item %d has unsupported empty arguments: %s", index, encoded)
		}
	}
}
func TestPublicComputerOutputMappingPreservesSafetyChecks(t *testing.T) {
	item := codex.CodexOutputItem{
		ID:      "computer-item",
		Type:    "computer_call",
		Status:  "completed",
		Action:  json.RawMessage(`{"type":"click","button":"left","x":4,"y":5}`),
		Actions: json.RawMessage(`[{"type":"screenshot"}]`),
		PendingSafetyChecks: []codex.CodexSafetyCheck{{
			ID:      "pending",
			Code:    "confirm",
			Message: "pending safety",
		}},
		AcknowledgedSafetyChecks: []codex.CodexSafetyCheck{{
			ID:      "acknowledged",
			Code:    "confirm",
			Message: "acknowledged safety",
		}},
		CreatedBy: "private",
		Phase:     "private",
	}
	output := publicOutputItem(&item)
	encoded, err := json.Marshal(output)
	if err != nil {
		t.Fatalf("encode public computer output: %v", err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &fields); err != nil {
		t.Fatalf("decode public computer output: %v", err)
	}
	if string(fields["action"]) != string(item.Action) ||
		!bytes.Contains(fields["pending_safety_checks"], []byte(`"pending"`)) ||
		!bytes.Contains(fields["acknowledged_safety_checks"], []byte(`"acknowledged"`)) {
		t.Fatalf("public computer output fields = %s", encoded)
	}
	for _, privateField := range []string{"actions", "created_by", "phase"} {
		if _, found := fields[privateField]; found {
			t.Fatalf("private output field %q reached public output: %s", privateField, encoded)
		}
	}
}
func TestResponsesSupportedFieldsReachCodexAndUnknownFieldsReject(t *testing.T) {
	fixture, err := os.ReadFile(filepath.Join("..", "codex", "testdata", "responses_terminal.sse"))
	if err != nil {
		t.Fatal(err)
	}
	var upstreamCalls atomic.Int32
	var upstreamBody atomic.Value
	upstream := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		upstreamCalls.Add(1)
		body, readErr := io.ReadAll(request.Body)
		if readErr != nil {
			t.Errorf("read upstream body: %v", readErr)
		}
		upstreamBody.Store(append([]byte(nil), body...))
		writer.Header().Set("Content-Type", "text/event-stream")
		_, _ = writer.Write(fixture)
	}))
	defer upstream.Close()
	servers, rawKey := newResponsesTestServer(t, upstream.URL, nil)
	defer shutdownResponsesTestServer(t, servers)

	requestBody := `{"model":"gpt-5.6-sol","stream":false,"max_output_tokens":123,"include":["reasoning.encrypted_content"],"metadata":{"trace":"fixture"},"prompt_cache_key":"fixture-cache","service_tier":"priority"}`
	response := doResponsesRequest(t, servers.DataAddr(), rawKey, requestBody, "application/json")
	response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("supported fields status = %d", response.StatusCode)
	}
	privateBody, ok := upstreamBody.Load().([]byte)
	if !ok {
		t.Fatal("upstream request body was not captured")
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(privateBody, &fields); err != nil {
		t.Fatalf("decode private request: %v", err)
	}
	for _, name := range []string{"max_output_tokens", "include", "client_metadata", "prompt_cache_key", "service_tier"} {
		if _, found := fields[name]; !found {
			t.Fatalf("private request omitted %s: %s", name, privateBody)
		}
	}
	if _, found := fields["metadata"]; found {
		t.Fatalf("private request used unsupported metadata field: %s", privateBody)
	}

	response = doResponsesRequest(t, servers.DataAddr(), rawKey, `{"model":"gpt-5.6-sol","unknown_field":true}`, "application/json")
	response.Body.Close()
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("unknown field status = %d", response.StatusCode)
	}
	for _, body := range []string{
		`{"model":"gpt-5.6-sol","input":[{"type":"message","content":[{"type":"input_text","txet":"fixture"}]}]}`,
		`{"model":"gpt-5.6-sol","input":[{"type":"computer_call_output","output":{"type":"computer_screenshot","file_id":"fixture","filed_id":"typo"}}]}`,
		`{"model":"gpt-5.6-sol","input":[{"type":"computer_call","pending_safety_checks":[{"id":"fixture","idd":"typo"}]}]}`,
		`{"model":"gpt-5.6-sol","input":[{"type":"additional_tools","tools":[{"type":"function","nam":"fixture"}]}]}`,
		`{"model":"gpt-5.6-sol","tool_choice":{"type":"function","unknown":true}}`,
	} {
		response = doResponsesRequest(t, servers.DataAddr(), rawKey, body, "application/json")
		response.Body.Close()
		if response.StatusCode != http.StatusBadRequest {
			t.Fatalf("nested unknown field status = %d, body = %s", response.StatusCode, body)
		}
	}
	if upstreamCalls.Load() != 1 {
		t.Fatalf("upstream calls after unknown field = %d", upstreamCalls.Load())
	}
}

func TestResponsesSSEFramesOnceAndOmitsPrivateMetadata(t *testing.T) {
	fixture, err := os.ReadFile(filepath.Join("..", "codex", "testdata", "responses_terminal.sse"))
	if err != nil {
		t.Fatal(err)
	}
	upstream := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "text/event-stream")
		_, _ = writer.Write(fixture)
	}))
	defer upstream.Close()

	servers, rawKey := newResponsesTestServer(t, upstream.URL, nil)
	defer shutdownResponsesTestServer(t, servers)

	response := doResponsesRequest(t, servers.DataAddr(), rawKey, `{"model":"gpt-5.6-sol","stream":true}`, "application/json")
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || response.Header.Get("Content-Type") != "text/event-stream" {
		t.Fatalf("status = %d, content type = %q", response.StatusCode, response.Header.Get("Content-Type"))
	}
	scanner := bufio.NewScanner(response.Body)
	var eventTypes []string
	doneCount := 0
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}
		if !strings.HasPrefix(line, "data: ") {
			t.Fatalf("invalid SSE line %q", line)
		}
		payload := strings.TrimPrefix(line, "data: ")
		if payload == "[DONE]" {
			doneCount++
			continue
		}
		var event struct {
			Type string `json:"type"`
		}
		if err := json.Unmarshal([]byte(payload), &event); err != nil {
			t.Fatalf("decode event %q: %v", payload, err)
		}
		if event.Type == codex.CodexEventResponseMetadata {
			t.Fatal("private metadata event reached public stream")
		}
		eventTypes = append(eventTypes, event.Type)
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	if doneCount != 1 {
		t.Fatalf("done count = %d, want 1", doneCount)
	}
	terminalCount := 0
	for _, eventType := range eventTypes {
		if eventType == codex.CodexEventResponseCompleted || eventType == codex.CodexEventResponseDone || eventType == codex.CodexEventResponseIncomplete || eventType == codex.CodexEventResponseFailed || eventType == codex.CodexEventError {
			terminalCount++
		}
	}
	if terminalCount != 1 {
		t.Fatalf("terminal count = %d, events = %v", terminalCount, eventTypes)
	}
}

func TestResponsesBoundaryAndAuthorizationRejectBeforeUpstream(t *testing.T) {
	var upstreamCalls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		upstreamCalls.Add(1)
	}))
	defer upstream.Close()

	servers, rawKey := newResponsesTestServer(t, upstream.URL, nil)
	defer shutdownResponsesTestServer(t, servers)
	base := "http://" + servers.DataAddr() + responsesEndpoint

	checks := []struct {
		name        string
		method      string
		contentType string
		body        string
		wantStatus  int
		key         string
	}{
		{name: "method", method: http.MethodGet, contentType: "", body: "", wantStatus: http.StatusMethodNotAllowed, key: rawKey},
		{name: "media type", method: http.MethodPost, contentType: "text/plain", body: `{ "model": "gpt-5.6-sol" }`, wantStatus: http.StatusUnsupportedMediaType, key: rawKey},
		{name: "malformed", method: http.MethodPost, contentType: "application/json", body: `{`, wantStatus: http.StatusBadRequest, key: rawKey},
		{name: "model denied", method: http.MethodPost, contentType: "application/json", body: `{"model":"gpt-denied"}`, wantStatus: http.StatusForbidden, key: rawKey},
	}
	for _, check := range checks {
		t.Run(check.name, func(t *testing.T) {
			request, err := http.NewRequest(check.method, base, strings.NewReader(check.body))
			if err != nil {
				t.Fatal(err)
			}
			if check.contentType != "" {
				request.Header.Set("Content-Type", check.contentType)
			}
			if check.key != "" {
				request.Header.Set("Authorization", "Bearer "+check.key)
			}
			response, err := http.DefaultClient.Do(request)
			if err != nil {
				t.Fatal(err)
			}
			response.Body.Close()
			if response.StatusCode != check.wantStatus {
				t.Fatalf("status = %d, want %d", response.StatusCode, check.wantStatus)
			}
		})
	}
	oversized := strings.NewReader(`{"model":"gpt-5.6-sol","input":"` + strings.Repeat("x", maxResponsesBodyBytes) + `"}`)
	request, err := http.NewRequest(http.MethodPost, base, oversized)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer "+rawKey)
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized status = %d", response.StatusCode)
	}
	if upstreamCalls.Load() != 0 {
		t.Fatalf("upstream calls = %d, want 0", upstreamCalls.Load())
	}
}

func TestResponsesCollectionLimitsRejectBeforeUpstream(t *testing.T) {
	fixture, err := os.ReadFile(filepath.Join("..", "codex", "testdata", "responses_terminal.sse"))
	if err != nil {
		t.Fatal(err)
	}
	var upstreamCalls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		upstreamCalls.Add(1)
		writer.Header().Set("Content-Type", "text/event-stream")
		_, _ = writer.Write(fixture)
	}))
	defer upstream.Close()

	servers, rawKey := newResponsesTestServer(t, upstream.URL, nil)
	defer shutdownResponsesTestServer(t, servers)

	tests := []struct {
		name  string
		limit int
		body  func(int) string
	}{
		{
			name:  "input items",
			limit: 1024,
			body: func(count int) string {
				return `{"model":"gpt-5.6-sol","input":` + responsesTestJSONList(count, `{"type":"message"}`) + `}`
			},
		},
		{
			name:  "content parts",
			limit: 1024,
			body: func(count int) string {
				return `{"model":"gpt-5.6-sol","input":[{"type":"message","content":` + responsesTestJSONList(count, `{"type":"input_text","text":"x"}`) + `}]}`
			},
		},
		{
			name:  "output parts",
			limit: 1024,
			body: func(count int) string {
				return `{"model":"gpt-5.6-sol","input":[{"type":"computer_call_output","output":` + responsesTestJSONList(count, `{"type":"computer_screenshot","file_id":"x"}`) + `}]}`
			},
		},
		{
			name:  "per-item tools",
			limit: 128,
			body: func(count int) string {
				return `{"model":"gpt-5.6-sol","input":[{"type":"additional_tools","tools":` + responsesTestJSONList(count, `{"type":"function","name":"f"}`) + `}]}`
			},
		},
		{
			name:  "pending safety checks",
			limit: 128,
			body: func(count int) string {
				return `{"model":"gpt-5.6-sol","input":[{"type":"computer_call","pending_safety_checks":` + responsesTestJSONList(count, `{"id":"check"}`) + `}]}`
			},
		},
		{
			name:  "acknowledged safety checks",
			limit: 128,
			body: func(count int) string {
				return `{"model":"gpt-5.6-sol","input":[{"type":"computer_call_output","acknowledged_safety_checks":` + responsesTestJSONList(count, `{"id":"check"}`) + `}]}`
			},
		},
		{
			name:  "top-level tools",
			limit: 128,
			body: func(count int) string {
				return `{"model":"gpt-5.6-sol","tools":` + responsesTestJSONList(count, `{"type":"function","name":"f"}`) + `}`
			},
		},
		{
			name:  "top-level include",
			limit: 64,
			body: func(count int) string {
				return `{"model":"gpt-5.6-sol","include":` + responsesTestJSONList(count, `"reasoning.encrypted_content"`) + `}`
			},
		},
		{
			name:  "top-level metadata",
			limit: 16,
			body: func(count int) string {
				return `{"model":"gpt-5.6-sol","metadata":` + responsesTestJSONMetadata(count) + `}`
			},
		},
	}
	accepted := 0
	for _, test := range tests {
		for _, count := range []int{test.limit, test.limit + 1} {
			response := doResponsesRequest(t, servers.DataAddr(), rawKey, test.body(count), "application/json")
			body, readErr := io.ReadAll(response.Body)
			response.Body.Close()
			if readErr != nil {
				t.Fatalf("%s count %d: read response: %v", test.name, count, readErr)
			}
			if count == test.limit {
				if response.StatusCode != http.StatusOK {
					t.Fatalf("%s exact limit status = %d, body = %s", test.name, response.StatusCode, body)
				}
				accepted++
				continue
			}
			if response.StatusCode != http.StatusBadRequest || !bytes.Contains(body, []byte(`"invalid_json"`)) {
				t.Fatalf("%s limit+1 status = %d, body = %s", test.name, response.StatusCode, body)
			}
		}
	}
	if upstreamCalls.Load() != int32(accepted) {
		t.Fatalf("upstream calls = %d, want %d", upstreamCalls.Load(), accepted)
	}
}

func TestResponsesTopLevelCollectionNearBodyLimitRejectBeforeUpstream(t *testing.T) {
	var upstreamCalls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		upstreamCalls.Add(1)
	}))
	defer upstream.Close()

	servers, rawKey := newResponsesTestServer(t, upstream.URL, nil)
	defer shutdownResponsesTestServer(t, servers)

	tests := []struct {
		name  string
		field string
		value string
	}{
		{
			name:  "tools",
			field: "tools",
			value: responsesTestJSONList(129, `{"type":"function","name":"f"}`),
		},
		{
			name:  "include",
			field: "include",
			value: responsesTestJSONList(65, `"reasoning.encrypted_content"`),
		},
		{
			name:  "metadata",
			field: "metadata",
			value: responsesTestJSONMetadata(17),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			prefix := `{"model":"gpt-5.6-sol","input":"`
			suffix := `","` + test.field + `":` + test.value + `}`
			padding := maxResponsesBodyBytes - len(prefix) - len(suffix) - 64
			body := prefix + strings.Repeat("x", padding) + suffix
			if len(body) < maxResponsesBodyBytes-1024 {
				t.Fatalf("body size = %d, want near %d", len(body), maxResponsesBodyBytes)
			}
			response := doResponsesRequest(t, servers.DataAddr(), rawKey, body, "application/json")
			responseBody, readErr := io.ReadAll(response.Body)
			response.Body.Close()
			if readErr != nil {
				t.Fatalf("read response: %v", readErr)
			}
			if response.StatusCode != http.StatusBadRequest || !bytes.Contains(responseBody, []byte(`"invalid_json"`)) {
				t.Fatalf("status = %d, body = %s", response.StatusCode, responseBody)
			}
		})
	}
	if upstreamCalls.Load() != 0 {
		t.Fatalf("upstream calls = %d, want 0", upstreamCalls.Load())
	}
}

func TestResponsesCancellationCancelsUpstream(t *testing.T) {
	started := make(chan struct{})
	cancelled := make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "text/event-stream")
		writer.WriteHeader(http.StatusOK)
		if flusher, ok := writer.(http.Flusher); ok {
			flusher.Flush()
		}
		close(started)
		<-request.Context().Done()
		close(cancelled)
	}))
	defer upstream.Close()
	servers, rawKey := newResponsesTestServer(t, upstream.URL, nil)
	defer shutdownResponsesTestServer(t, servers)

	requestContext, cancel := context.WithCancel(context.Background())
	request, err := http.NewRequestWithContext(requestContext, http.MethodPost, "http://"+servers.DataAddr()+responsesEndpoint, strings.NewReader(`{"model":"gpt-5.6-sol","stream":true}`))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer "+rawKey)
	client := &http.Client{Timeout: 5 * time.Second}
	type clientResult struct {
		response *http.Response
		err      error
	}
	resultCh := make(chan clientResult, 1)
	go func() {
		response, requestErr := client.Do(request)
		resultCh <- clientResult{response: response, err: requestErr}
	}()
	var response *http.Response
	select {
	case result := <-resultCh:
		if result.err != nil {
			t.Fatal(result.err)
		}
		response = result.response
	case <-time.After(time.Second):
		t.Fatal("downstream response headers were not flushed")
	}
	if response == nil {
		t.Fatal("downstream response is nil")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || response.Header.Get("Content-Type") != "text/event-stream" {
		t.Fatalf("status = %d, content type = %q", response.StatusCode, response.Header.Get("Content-Type"))
	}
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("upstream request did not start")
	}
	cancel()
	select {
	case <-cancelled:
	case <-time.After(time.Second):
		t.Fatal("upstream request was not cancelled")
	}
	body, _ := io.ReadAll(response.Body)
	if len(body) != 0 {
		t.Fatalf("downstream wrote after disconnect: %s", body)
	}
}
func TestResponsesSSEFirstEventSurvivesWriteTimeout(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "text/event-stream")
		writer.WriteHeader(http.StatusOK)
		flusher, ok := writer.(http.Flusher)
		if !ok {
			return
		}
		_, _ = io.WriteString(writer, "data: {\"type\":\"response.output_text.delta\",\"sequence_number\":0,\"delta\":\"first\"}\n\n")
		flusher.Flush()
		time.Sleep(11 * time.Second)
		_, _ = io.WriteString(writer, "data: {\"type\":\"response.completed\",\"sequence_number\":1,\"response\":{\"status\":\"completed\"}}\n\ndata: [DONE]\n\n")
		flusher.Flush()
	}))
	defer upstream.Close()
	servers, rawKey := newResponsesTestServer(t, upstream.URL, nil)
	defer shutdownResponsesTestServer(t, servers)

	request, err := http.NewRequest(http.MethodPost, "http://"+servers.DataAddr()+responsesEndpoint, strings.NewReader(`{"model":"gpt-5.6-sol","stream":true}`))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+rawKey)
	request.Header.Set("Content-Type", "application/json")
	response, err := (&http.Client{Timeout: 15 * time.Second}).Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", response.StatusCode)
	}
	firstLine := make(chan string, 1)
	streamDone := make(chan error, 1)
	go func() {
		scanner := bufio.NewScanner(response.Body)
		sentFirst := false
		for scanner.Scan() {
			if !sentFirst && strings.HasPrefix(scanner.Text(), "data: ") {
				firstLine <- scanner.Text()
				sentFirst = true
			}
			if scanner.Text() == "data: [DONE]" {
				streamDone <- nil
				return
			}
		}
		streamDone <- scanner.Err()
	}()
	select {
	case line := <-firstLine:
		if !strings.Contains(line, `"delta":"first"`) {
			t.Fatalf("first SSE line = %s", line)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("first SSE event did not arrive promptly")
	}
	select {
	case err := <-streamDone:
		if err != nil {
			t.Fatalf("read SSE stream: %v", err)
		}
	case <-time.After(13 * time.Second):
		t.Fatal("SSE stream did not survive write timeout")
	}
}

func responsesTestJSONList(count int, value string) string {
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

func responsesTestJSONMetadata(count int) string {
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

func newResponsesTestServer(t *testing.T, upstreamURL string, policy *apikey.Policy, serverWriteTimeout ...time.Duration) (*Servers, string) {
	t.Helper()
	timeout := writeTimeout
	if len(serverWriteTimeout) == 1 {
		timeout = serverWriteTimeout[0]
	}
	databasePath := filepath.Join(t.TempDir(), "test.sqlite3")
	database, err := storage.Open(context.Background(), databasePath, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	sqlDatabase, err := database.DB()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sqlDatabase.Close() })
	if err := apikey.Migrate(database); err != nil {
		t.Fatal(err)
	}
	hmacKey := []byte("test-api-key-hmac-key")
	if policy == nil {
		policy = &apikey.Policy{Name: "test", Owner: "test", AllowedEndpoints: []string{responsesEndpoint}, AllowedModels: []string{"gpt-5.6-sol"}}
	}
	rawKey, _, err := apikey.Create(context.Background(), database, hmacKey, *policy)
	if err != nil {
		t.Fatal(err)
	}
	activeKey, err := envelope.NewKey(1, bytes.Repeat([]byte{7}, envelope.KeySize))
	if err != nil {
		t.Fatal(err)
	}
	credentialKeys, err := envelope.NewKeySet(activeKey)
	if err != nil {
		t.Fatal(err)
	}
	credentialPath := filepath.Join(t.TempDir(), "credential.enc")
	if err := codex.SaveCredential(credentialPath, codex.Credential{AccessToken: "access", RefreshToken: "refresh", ExpiresAt: time.Now().Add(time.Hour), AccountID: "account"}, credentialKeys); err != nil {
		t.Fatal(err)
	}
	refresher, err := codex.NewRefresher(credentialPath, credentialKeys, codex.RefresherOptions{Issuer: "https://auth.openai.com", ClientID: "client"})
	if err != nil {
		t.Fatal(err)
	}
	transport, err := codex.NewResponsesTransport(codex.ResponsesTransportOptions{Policy: codex.ResponsesTransportSSE, ResponsesURL: upstreamURL, Refresher: refresher})
	if err != nil {
		t.Fatal(err)
	}
	servers, err := startWithWriteTimeout(Config{Listen: "127.0.0.1:0", AdminListen: "127.0.0.1:0", Database: database, APIKeyHMACKey: hmacKey, ResponsesTransport: transport}, NewReadiness(), timeout)
	if err != nil {
		t.Fatal(err)
	}
	return servers, rawKey
}

func shutdownResponsesTestServer(t *testing.T, servers *Servers) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := servers.Shutdown(ctx); err != nil {
		t.Fatal(err)
	}
}

func doResponsesRequest(t *testing.T, address, rawKey, body, contentType string) *http.Response {
	t.Helper()
	request, err := http.NewRequest(http.MethodPost, "http://"+address+responsesEndpoint, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+rawKey)
	request.Header.Set("Content-Type", contentType)
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	return response
}

func TestBusyRetentionDoesNotInterruptActiveSSE(t *testing.T) {
	fixture, err := os.ReadFile(filepath.Join("..", "codex", "testdata", "responses_terminal.sse"))
	if err != nil {
		t.Fatal(err)
	}
	separator := bytes.Index(fixture, []byte("\n\n"))
	if separator < 0 {
		t.Fatal("response fixture has no event separator")
	}
	firstEvent := fixture[:separator+2]
	remainingEvents := fixture[separator+2:]
	releaseUpstream := make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "text/event-stream")
		writer.WriteHeader(http.StatusOK)
		flusher, ok := writer.(http.Flusher)
		if !ok {
			t.Fatal("upstream writer is not flushable")
		}
		if _, err := writer.Write(firstEvent); err != nil {
			return
		}
		flusher.Flush()
		<-releaseUpstream
		_, _ = writer.Write(remainingEvents)
		flusher.Flush()
	}))
	defer upstream.Close()
	servers, rawKey := newResponsesTestServer(t, upstream.URL, nil)
	defer shutdownResponsesTestServer(t, servers)
	response := doResponsesRequest(t, servers.DataAddr(), rawKey, `{"model":"gpt-5.6-sol","stream":true}`, "application/json")
	defer response.Body.Close()
	reader := bufio.NewReader(response.Body)
	firstLine, err := reader.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(firstLine, `"response.created"`) {
		t.Fatalf("first SSE line = %q", firstLine)
	}

	now := time.Now().UTC()
	database := servers.journal.db
	if err := database.Create(&ConversationRecord{ID: "retention-lock", CreatedAt: now, UpdatedAt: now, ExpiresAt: now.Add(time.Hour)}).Error; err != nil {
		t.Fatal(err)
	}
	if err := database.Create(&EncryptedPayloadRecord{ID: "retention-lock-payload", ReplayID: "retention-lock-payload", KeyVersion: 1, Envelope: []byte("expired"), CreatedAt: now.Add(-time.Hour), ExpiresAt: now.Add(-time.Minute)}).Error; err != nil {
		t.Fatal(err)
	}
	lock := database.Begin()
	if lock.Error != nil {
		t.Fatal(lock.Error)
	}
	if err := lock.Model(&ConversationRecord{}).Where("id = ?", "retention-lock").Update("updated_at", now).Error; err != nil {
		_ = lock.Rollback()
		t.Fatal(err)
	}
	retentionDone := make(chan error, 1)
	go func() {
		retentionDone <- servers.retention.RunOnce(context.Background(), now)
	}()
	time.Sleep(1100 * time.Millisecond)
	if err := lock.Rollback().Error; err != nil {
		t.Fatal(err)
	}
	var retentionErr error
	select {
	case retentionErr = <-retentionDone:
	case <-time.After(2 * time.Second):
		t.Fatal("busy retention sweep did not finish")
	}
	if retentionErr == nil {
		t.Fatal("busy retention sweep unexpectedly succeeded")
	}
	close(releaseUpstream)
	body, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	stream := firstLine + string(body)
	if response.StatusCode != http.StatusOK || !strings.Contains(stream, `"response.completed"`) || !strings.Contains(stream, "[DONE]") {
		t.Fatalf("active SSE after busy retention = status %d body %s", response.StatusCode, stream)
	}
}
