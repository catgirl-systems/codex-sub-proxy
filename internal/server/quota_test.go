package server

import (
	"context"
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
)

func TestResponsesQuotaRejectsBeforeUpstreamAndChargesTerminalUsage(t *testing.T) {
	fixture, err := os.ReadFile(filepath.Join("..", "codex", "testdata", "responses_terminal.sse"))
	if err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		calls.Add(1)
		writer.Header().Set("Content-Type", "text/event-stream")
		_, _ = writer.Write(fixture)
	}))
	defer upstream.Close()
	policy := &apikey.Policy{
		Name:                    "quota",
		Owner:                   "quota",
		AllowedEndpoints:        []string{responsesEndpoint},
		TokenReservationDefault: 20,
		AllowedModels:           []string{"gpt-5.6-sol"},
		PeriodDuration:          24 * time.Hour,
		PeriodTokenLimit:        20,
		MaxConcurrentRequests:   1,
	}
	servers, rawKey := newResponsesTestServer(t, upstream.URL, policy)
	defer shutdownResponsesTestServer(t, servers)
	first := doResponsesRequest(t, servers.DataAddr(), rawKey, `{"model":"gpt-5.6-sol","stream":false}`, "application/json")
	firstBody, err := io.ReadAll(first.Body)
	first.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if first.StatusCode != http.StatusOK {
		t.Fatalf("first status = %d, body = %s", first.StatusCode, firstBody)
	}
	second := doResponsesRequest(t, servers.DataAddr(), rawKey, `{"model":"gpt-5.6-sol","stream":false}`, "application/json")
	secondBody, err := io.ReadAll(second.Body)
	second.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if second.StatusCode != http.StatusTooManyRequests || len(secondBody) == 0 {
		t.Fatalf("second status = %d, body = %s", second.StatusCode, secondBody)
	}
	if second.Header.Get("Retry-After") == "" || second.Header.Get("X-RateLimit-Reset") == "" {
		t.Fatalf("quota headers = %#v", second.Header)
	}
	if calls.Load() != 1 {
		t.Fatalf("upstream calls = %d, want 1", calls.Load())
	}
}

func TestQuotaReleaseOnCanceledResponsesRequest(t *testing.T) {
	fixture, err := os.ReadFile(filepath.Join("..", "codex", "testdata", "responses_terminal.sse"))
	if err != nil {
		t.Fatal(err)
	}
	started := make(chan struct{})
	release := make(chan struct{})
	var calls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if calls.Add(1) == 1 {
			close(started)
			<-release
		}
		writer.Header().Set("Content-Type", "text/event-stream")
		_, _ = writer.Write(fixture)
	}))
	defer upstream.Close()
	policy := &apikey.Policy{
		Name:                  "cancel-quota",
		Owner:                 "cancel-quota",
		AllowedEndpoints:      []string{responsesEndpoint},
		AllowedModels:         []string{"gpt-5.6-sol"},
		MaxConcurrentRequests: 1,
	}
	servers, rawKey := newResponsesTestServer(t, upstream.URL, policy)
	defer shutdownResponsesTestServer(t, servers)
	requestContext, cancel := context.WithCancel(context.Background())
	request, err := http.NewRequestWithContext(requestContext, http.MethodPost, "http://"+servers.DataAddr()+responsesEndpoint, strings.NewReader(`{"model":"gpt-5.6-sol","stream":false}`))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+rawKey)
	request.Header.Set("Content-Type", "application/json")
	responseDone := make(chan error, 1)
	go func() {
		response, err := http.DefaultClient.Do(request)
		if response != nil {
			_ = response.Body.Close()
		}
		responseDone <- err
	}()
	<-started
	cancel()
	if err := <-responseDone; err == nil {
		t.Fatal("canceled request returned no error")
	}
	close(release)
	second := doResponsesRequest(t, servers.DataAddr(), rawKey, `{"model":"gpt-5.6-sol","stream":false}`, "application/json")
	defer second.Body.Close()
	if second.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(second.Body)
		t.Fatalf("request after cancellation status = %d, body = %s", second.StatusCode, body)
	}
}
