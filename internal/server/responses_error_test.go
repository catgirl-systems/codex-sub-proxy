package server

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestResponsesProviderErrorBeforeStreamHeadersIsSafeJSON(t *testing.T) {
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
	if response.StatusCode != http.StatusInternalServerError || response.Header.Get("Content-Type") != "application/json" {
		t.Fatalf("status = %d, content type = %q, body = %s", response.StatusCode, response.Header.Get("Content-Type"), body)
	}
	if strings.Contains(string(body), "private provider body") {
		t.Fatal("provider body leaked")
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
