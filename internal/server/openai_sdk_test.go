package server

import (
	"context"
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

	stream := client.Responses.NewStreaming(context.Background(), params)
	eventCount := 0
	terminalCount := 0
	for stream.Next() {
		eventCount++
		event := stream.Current()
		switch event.Type {
		case "response.completed", "response.done", "response.incomplete", "response.failed", "error":
			terminalCount++
		}
	}
	if err := stream.Err(); err != nil {
		t.Fatalf("official SDK streaming call: %v", err)
	}
	if eventCount == 0 || terminalCount != 1 {
		t.Fatalf("official SDK stream events = %d, terminals = %d", eventCount, terminalCount)
	}
}
func newResponseFixtureUpstream(t *testing.T, fixture []byte) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "text/event-stream")
		_, _ = writer.Write(fixture)
	}))
}
