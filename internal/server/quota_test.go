package server

import (
	"bytes"
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
	"github.com/catgirl-systems/codex-sub-proxy/internal/codex"
	"github.com/catgirl-systems/codex-sub-proxy/internal/storage"
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
		Name:                            "quota",
		Owner:                           "quota",
		AllowedEndpoints:                []string{responsesEndpoint},
		TokenReservationDefault:         20,
		CostMicrounitReservationDefault: 5,
		AllowedModels:                   []string{"gpt-5.6-sol"},
		PeriodDuration:                  24 * time.Hour,
		PeriodTokenLimit:                20,
		PeriodCostMicrounitLimit:        5,
		MaxConcurrentRequests:           1,
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
func TestQuotaLeaseKeepsSuccessAfterWriteFailure(t *testing.T) {
	database, err := storage.Open(context.Background(), filepath.Join(t.TempDir(), "quota.sqlite3"), time.Second)
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
	store, err := apikey.NewQuotaStore(database)
	if err != nil {
		t.Fatal(err)
	}
	admission, err := store.Admit(context.Background(), "key", apikey.Policy{MaxConcurrentRequests: 1}, apikey.QuotaRequest{Requests: 1})
	if err != nil {
		t.Fatal(err)
	}
	lease := &quotaLease{store: store, id: admission.ID}
	if err := lease.reconcile(apikey.QuotaUsage{}); err != nil {
		t.Fatal(err)
	}
	if err := lease.release("downstream write failed"); err != nil {
		t.Fatal(err)
	}
	var reservation apikey.QuotaReservation
	if err := database.First(&reservation, "id = ?", admission.ID).Error; err != nil {
		t.Fatal(err)
	}
	if reservation.Status != "closed" {
		t.Fatalf("reservation status = %q", reservation.Status)
	}
}

func TestChatStreamReconcilesBeforeFinishChunk(t *testing.T) {
	database, err := storage.Open(context.Background(), filepath.Join(t.TempDir(), "quota.sqlite3"), time.Second)
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
	store, err := apikey.NewQuotaStore(database)
	if err != nil {
		t.Fatal(err)
	}
	admission, err := store.Admit(context.Background(), "key", apikey.Policy{MaxConcurrentRequests: 1}, apikey.QuotaRequest{Requests: 1})
	if err != nil {
		t.Fatal(err)
	}
	writer := &quotaFinishWriter{
		status: func() string {
			var reservation apikey.QuotaReservation
			if err := database.First(&reservation, "id = ?", admission.ID).Error; err != nil {
				return ""
			}
			return reservation.Status
		},
	}
	state := newChatStreamState("gpt-5.6-sol", false, writer, writer)
	state.lease = &quotaLease{store: store, id: admission.ID}
	err = state.event(codex.CodexResponseStreamEvent{
		Type: codex.CodexEventResponseCompleted,
		Response: &codex.CodexResponse{
			ID:     "response",
			Model:  "gpt-5.6-sol",
			Status: codex.CodexResponseStatusCompleted,
			Output: []codex.CodexOutputItem{{
				Type:    "message",
				Role:    "assistant",
				Content: []codex.CodexContentPart{{Type: "output_text", Text: "ok"}},
			}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !writer.finishCharged {
		t.Fatal("finish chunk was written before quota reconciliation")
	}
}

type quotaFinishWriter struct {
	header        http.Header
	body          bytes.Buffer
	status        func() string
	finishCharged bool
}

func (writer *quotaFinishWriter) Header() http.Header {
	if writer.header == nil {
		writer.header = make(http.Header)
	}
	return writer.header
}

func (writer *quotaFinishWriter) WriteHeader(status int) {}

func (writer *quotaFinishWriter) Write(payload []byte) (int, error) {
	if bytes.Contains(payload, []byte(`"finish_reason"`)) && writer.status() == "closed" {
		writer.finishCharged = true
	}
	return writer.body.Write(payload)
}

func (writer *quotaFinishWriter) Flush() {}
