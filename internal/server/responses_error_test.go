package server

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
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
