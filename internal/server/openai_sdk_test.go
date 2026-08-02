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
	"testing"

	sdk "github.com/openai/openai-go"
	"github.com/openai/openai-go/option"
	"github.com/openai/openai-go/responses"
	"github.com/openai/openai-go/shared"
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
