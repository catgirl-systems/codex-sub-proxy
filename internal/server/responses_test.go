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
	client := &http.Client{Timeout: time.Second}
	done := make(chan error, 1)
	go func() {
		response, requestErr := client.Do(request)
		if response != nil {
			response.Body.Close()
		}
		done <- requestErr
	}()
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
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("downstream request did not finish")
	}
}

func newResponsesTestServer(t *testing.T, upstreamURL string, policy *apikey.Policy) (*Servers, string) {
	t.Helper()
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
	servers, err := Start(Config{Listen: "127.0.0.1:0", AdminListen: "127.0.0.1:0", Database: database, APIKeyHMACKey: hmacKey, ResponsesTransport: transport}, NewReadiness())
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
