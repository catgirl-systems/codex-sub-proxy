package server

import (
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

func TestResponsesProviderErrorAfterStreamHeadersIsSafeSSE(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.WriteHeader(http.StatusInternalServerError)
		_, _ = io.WriteString(writer, `{"error":{"message":"private provider body"}}`)
	}))
	defer upstream.Close()
	servers, rawKey := newResponsesTestServer(t, upstream.URL, nil)
	defer shutdownResponsesTestServer(t, servers)

	response := doResponsesRequest(t, servers.DataAddr(), rawKey, `{"model":"gpt-5.6-sol","stream":true}`, "application/json")
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK || response.Header.Get("Content-Type") != "text/event-stream" {
		t.Fatalf("status = %d, content type = %q, body = %s", response.StatusCode, response.Header.Get("Content-Type"), body)
	}
	if strings.Count(string(body), `"type":"error"`) != 1 || strings.Count(string(body), "[DONE]") != 1 {
		t.Fatalf("stream body = %s", body)
	}
	if strings.Contains(string(body), `"error":`) || strings.Contains(string(body), "private provider body") {
		t.Fatalf("unsafe provider error reached public stream: %s", body)
	}
}
func TestResponsesAbruptSSEPublishesPreambleBeforeSafeError(t *testing.T) {
	var upstreamCalls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		upstreamCalls.Add(1)
		writer.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(writer, "data: {\"type\":\"response.created\",\"sequence_number\":0,\"response\":{\"status\":\"in_progress\"}}\n\n")
	}))
	defer upstream.Close()
	servers, rawKey := newResponsesTestServer(t, upstream.URL, nil)
	defer shutdownResponsesTestServer(t, servers)

	response := doResponsesRequest(t, servers.DataAddr(), rawKey, `{"model":"gpt-5.6-sol","stream":true}`, "application/json")
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	stream := string(body)
	if response.StatusCode != http.StatusOK ||
		strings.Count(stream, `"type":"response.created"`) != 1 ||
		strings.Count(stream, `"type":"error"`) != 1 ||
		strings.Count(stream, "[DONE]") != 1 {
		t.Fatalf("status = %d, body = %s", response.StatusCode, body)
	}
	if strings.Index(stream, `"type":"response.created"`) > strings.Index(stream, `"type":"error"`) {
		t.Fatalf("safe error preceded response.created: %s", body)
	}
	if upstreamCalls.Load() != 1 {
		t.Fatalf("upstream calls = %d, want 1", upstreamCalls.Load())
	}
}
func TestResponsesInvalidSequenceProducesBoundedSafeTerminal(t *testing.T) {
	tests := []struct {
		name              string
		fixture           string
		wantErrorSequence int
		wantPreamble      bool
	}{
		{
			name:              "negative",
			fixture:           `data: {"type":"response.created","sequence_number":-1,"response":{"status":"in_progress"}}` + "\n\n",
			wantErrorSequence: 0,
		},
		{
			name:              "max int",
			fixture:           fmt.Sprintf("data: {\"type\":\"response.created\",\"sequence_number\":%d,\"response\":{\"status\":\"in_progress\"}}\n\n", math.MaxInt),
			wantErrorSequence: 0,
		},
		{
			name:              "boundary before max int",
			fixture:           fmt.Sprintf("data: {\"type\":\"response.created\",\"sequence_number\":%d,\"response\":{\"status\":\"in_progress\"}}\n\n", math.MaxInt-1),
			wantErrorSequence: math.MaxInt,
			wantPreamble:      true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			upstream := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				writer.Header().Set("Content-Type", "text/event-stream")
				_, _ = io.WriteString(writer, test.fixture)
			}))
			defer upstream.Close()
			servers, rawKey := newResponsesTestServer(t, upstream.URL, nil)
			defer shutdownResponsesTestServer(t, servers)

			response := doResponsesRequest(t, servers.DataAddr(), rawKey, `{"model":"gpt-5.6-sol","stream":true}`, "application/json")
			defer response.Body.Close()
			body, err := io.ReadAll(response.Body)
			if err != nil {
				t.Fatal(err)
			}
			if response.StatusCode != http.StatusOK || strings.Count(string(body), `"type":"error"`) != 1 ||
				strings.Count(string(body), "[DONE]") != 1 {
				t.Fatalf("status = %d, body = %s", response.StatusCode, body)
			}
			if test.wantPreamble != strings.Contains(string(body), `"type":"response.created"`) {
				t.Fatalf("preamble presence = %t, body = %s", strings.Contains(string(body), `"type":"response.created"`), body)
			}
			var errorSequence int
			for _, record := range strings.Split(string(body), "\n") {
				if !strings.HasPrefix(record, "data: ") || strings.TrimPrefix(record, "data: ") == "[DONE]" {
					continue
				}
				var event struct {
					Type           string `json:"type"`
					SequenceNumber int    `json:"sequence_number"`
				}
				if err := json.Unmarshal([]byte(strings.TrimPrefix(record, "data: ")), &event); err != nil {
					t.Fatalf("decode public event: %v", err)
				}
				if event.SequenceNumber < 0 {
					t.Fatalf("negative public sequence = %d", event.SequenceNumber)
				}
				if event.Type == "error" {
					errorSequence = event.SequenceNumber
				}
			}
			if errorSequence != test.wantErrorSequence {
				t.Fatalf("safe error sequence = %d, want %d; body = %s", errorSequence, test.wantErrorSequence, body)
			}
		})
	}
}

func TestResponsesPrivateTopLevelErrorIsSafeSSE(t *testing.T) {
	fixture := []byte("data: {\"type\":\"response.output_text.delta\",\"sequence_number\":1,\"delta\":\"visible\",\"code\":\"provider-code\",\"message\":\"provider message\",\"param\":\"prompt\",\"error\":{\"code\":\"server_error\",\"type\":\"provider_error\",\"message\":\"nested provider message\",\"plan_type\":\"pro\",\"retry_after\":4.5,\"resets_at\":1738888890}}\n\ndata: {\"type\":\"response.completed\",\"sequence_number\":2,\"response\":{\"status\":\"completed\"}}\n\ndata: [DONE]\n\n")
	upstream := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "text/event-stream")
		_, _ = writer.Write(fixture)
	}))
	defer upstream.Close()
	servers, rawKey := newResponsesTestServer(t, upstream.URL, nil)
	defer shutdownResponsesTestServer(t, servers)

	response := doResponsesRequest(t, servers.DataAddr(), rawKey, `{"model":"gpt-5.6-sol","stream":true}`, "application/json")
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	stream := string(body)
	for _, private := range []string{"provider-code", "provider message", "nested provider message", "plan_type", "retry_after", "resets_at"} {
		if strings.Contains(stream, private) {
			t.Fatalf("private error field %q leaked: %s", private, body)
		}
	}
	if strings.Count(stream, `"type":"error"`) != 1 || strings.Count(stream, "[DONE]") != 1 {
		t.Fatalf("stream = %s", body)
	}
	for _, record := range strings.Split(stream, "\n") {
		if !strings.HasPrefix(record, "data: ") || strings.TrimPrefix(record, "data: ") == "[DONE]" {
			continue
		}
		var fields map[string]json.RawMessage
		if err := json.Unmarshal([]byte(strings.TrimPrefix(record, "data: ")), &fields); err != nil {
			t.Fatalf("decode public event: %v", err)
		}
		if string(fields["type"]) != `"error"` {
			continue
		}
		for name := range fields {
			switch name {
			case "type", "code", "message", "param", "sequence_number":
			default:
				t.Fatalf("public error field %q is not official: %s", name, record)
			}
		}
		var code, message, param string
		if err := json.Unmarshal(fields["code"], &code); err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(fields["message"], &message); err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(fields["param"], &param); err != nil {
			t.Fatal(err)
		}
		if code != "server_error" || message != "The upstream service returned an error." || param != "prompt" {
			t.Fatalf("public error fields = code %q message %q param %q", code, message, param)
		}
	}
}

func TestResponsesFailedStreamHasOneSafeTerminal(t *testing.T) {
	fixture, err := os.ReadFile(filepath.Join("..", "codex", "testdata", "responses_failed.sse"))
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
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK || strings.Count(string(body), `"type":"response.failed"`) != 1 || strings.Count(string(body), "[DONE]") != 1 {
		t.Fatalf("status = %d, body = %s", response.StatusCode, body)
	}
	if strings.Contains(string(body), "synthetic upstream failure") {
		t.Fatal("provider failure body leaked")
	}
}

func TestResponsesFailedJSONHasTypedResponse(t *testing.T) {
	fixture, err := os.ReadFile(filepath.Join("..", "codex", "testdata", "responses_failed.sse"))
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

	response := doResponsesRequest(t, servers.DataAddr(), rawKey, `{"model":"gpt-5.6-sol","stream":false}`, "application/json")
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || response.Header.Get("Content-Type") != "application/json" {
		body, _ := io.ReadAll(response.Body)
		t.Fatalf("status = %d, content type = %q, body = %s", response.StatusCode, response.Header.Get("Content-Type"), body)
	}
	var value struct {
		Status string `json:"status"`
		Error  *struct {
			Type    string `json:"type"`
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.NewDecoder(response.Body).Decode(&value); err != nil {
		t.Fatal(err)
	}
	if value.Status != "failed" || value.Error == nil || value.Error.Type != "server_error" || value.Error.Code != "server_error" {
		t.Fatalf("failed response = %#v", value)
	}
	if value.Error.Message != "The upstream service returned an error." {
		t.Fatalf("failed response message = %q", value.Error.Message)
	}
}
