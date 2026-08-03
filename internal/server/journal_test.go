package server

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/catgirl-systems/codex-sub-proxy/internal/apikey"
	"github.com/catgirl-systems/codex-sub-proxy/internal/storage"
	"gorm.io/gorm"
)

func openTestJournal(t *testing.T, mode string, queueCapacity int) (*Journal, *gorm.DB) {
	t.Helper()
	databasePath := filepath.Join(t.TempDir(), "journal.sqlite3")
	db, err := storage.Open(context.Background(), databasePath, time.Second)
	if err != nil {
		t.Fatalf("open database: %v", err)
	}
	if err := MigrateJournal(db); err != nil {
		t.Fatalf("migrate journal: %v", err)
	}
	journal, err := newJournal(db, mode, queueCapacity, time.Second)
	if err != nil {
		t.Fatalf("new journal: %v", err)
	}
	return journal, db
}

func closeTestJournal(t *testing.T, journal *Journal, db *gorm.DB) {
	t.Helper()
	if err := journal.Close(context.Background()); err != nil {
		t.Fatalf("close journal: %v", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("get database: %v", err)
	}
	if err := sqlDB.Close(); err != nil {
		t.Fatalf("close database: %v", err)
	}
}

func TestJournalDurableCommitsBeforeForward(t *testing.T) {
	journal, db := openTestJournal(t, journalModeDurable, 1)
	defer closeTestJournal(t, journal, db)

	request, err := journal.BeginRequest(context.Background())
	if err != nil {
		t.Fatalf("begin request: %v", err)
	}
	var callbackRecords []JournalRecord
	if err := journal.Forward(context.Background(), request, "response.json", []byte(`{"ok":true}`), func(_ context.Context, _ string) error {
		return db.Find(&callbackRecords).Error
	}); err != nil {
		t.Fatalf("forward event: %v", err)
	}
	if len(callbackRecords) != 2 {
		t.Fatalf("callback record count = %d, want 2", len(callbackRecords))
	}
	var event JournalRecord
	if err := db.Where("event_type = ?", "response.json").First(&event).Error; err != nil {
		t.Fatalf("load event: %v", err)
	}
	if !event.Applied || event.Sequence != 1 {
		t.Fatalf("event = %+v, want applied sequence 1", event)
	}
	if err := journal.CompleteRequest(context.Background(), request); err != nil {
		t.Fatalf("complete request: %v", err)
	}
}

func TestJournalBestEffortForwardsBeforeQueueWrite(t *testing.T) {
	journal, db := openTestJournal(t, journalModeBestEffort, 1)
	if err := journal.Start(); err != nil {
		t.Fatalf("start journal: %v", err)
	}
	request, err := journal.BeginRequest(context.Background())
	if err != nil {
		t.Fatalf("begin request: %v", err)
	}
	var callbackCount int
	if err := journal.Forward(context.Background(), request, "response.json", []byte(`{"ok":true}`), func(_ context.Context, _ string) error {
		var count int64
		if err := db.Model(&JournalRecord{}).Count(&count).Error; err != nil {
			return err
		}
		if count != 0 {
			return errors.New("journal row was visible before best-effort callback")
		}
		callbackCount++
		return nil
	}); err != nil {
		t.Fatalf("forward event: %v", err)
	}
	if callbackCount != 1 {
		t.Fatalf("callback count = %d, want 1", callbackCount)
	}
	if err := journal.CompleteRequest(context.Background(), request); err != nil {
		t.Fatalf("complete request: %v", err)
	}
	if err := journal.Close(context.Background()); err != nil {
		t.Fatalf("drain journal: %v", err)
	}
	var count int64
	if err := db.Model(&JournalRecord{}).Count(&count).Error; err != nil {
		t.Fatalf("count journal records: %v", err)
	}
	if count != 2 {
		t.Fatalf("journal record count = %d, want 2", count)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("get database: %v", err)
	}
	if err := sqlDB.Close(); err != nil {
		t.Fatalf("close database: %v", err)
	}
}
func TestBestEffortRequestWithoutOutputStoresMode(t *testing.T) {
	journal, db := openTestJournal(t, journalModeBestEffort, 1)
	if err := journal.Start(); err != nil {
		t.Fatalf("start journal: %v", err)
	}
	request, err := journal.BeginRequest(context.Background())
	if err != nil {
		t.Fatalf("begin request: %v", err)
	}
	if err := journal.CompleteRequest(context.Background(), request); err != nil {
		t.Fatalf("complete request: %v", err)
	}
	if err := journal.Close(context.Background()); err != nil {
		t.Fatalf("close journal: %v", err)
	}
	var record JournalRecord
	if err := db.Where("request_id = ?", request.ID).First(&record).Error; err != nil {
		t.Fatalf("load request record: %v", err)
	}
	if record.EventType != journalRequestEventType || record.Mode != journalModeBestEffort || record.Sequence != 0 {
		t.Fatalf("request record = %+v", record)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("get database: %v", err)
	}
	if err := sqlDB.Close(); err != nil {
		t.Fatalf("close database: %v", err)
	}
}

func TestJournalQueueBackpressureHonorsCancellation(t *testing.T) {
	journal, db := openTestJournal(t, journalModeBestEffort, 1)
	request, err := journal.BeginRequest(context.Background())
	if err != nil {
		t.Fatalf("begin request: %v", err)
	}
	if err := journal.Forward(context.Background(), request, "first", []byte("one"), func(context.Context, string) error { return nil }); err != nil {
		t.Fatalf("fill queue: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := journal.Forward(ctx, request, "second", []byte("two"), func(context.Context, string) error { return nil }); err == nil {
		t.Fatal("full queue accepted a canceled context")
	}
	if len(journal.queue) != 1 {
		t.Fatalf("queue length = %d, want 1", len(journal.queue))
	}
	if err := journal.Close(context.Background()); err == nil {
		t.Fatal("close silently dropped queued work")
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("get database: %v", err)
	}
	if err := sqlDB.Close(); err != nil {
		t.Fatalf("close database: %v", err)
	}
}

func TestJournalReplayRejectsChecksumCorruption(t *testing.T) {
	journal, db := openTestJournal(t, journalModeDurable, 1)
	request, err := journal.BeginRequest(context.Background())
	if err != nil {
		t.Fatalf("begin request: %v", err)
	}
	if err := journal.Forward(context.Background(), request, "response.json", []byte("payload"), func(context.Context, string) error {
		return errors.New("leave pending")
	}); err == nil {
		t.Fatal("forward unexpectedly succeeded")
	}
	if err := db.Model(&JournalRecord{}).Where("event_type = ?", "response.json").Update("checksum", []byte("corrupt")).Error; err != nil {
		t.Fatalf("corrupt checksum: %v", err)
	}
	if err := journal.Close(context.Background()); err != nil {
		t.Fatalf("close journal: %v", err)
	}
	journal, err = newJournal(db, journalModeDurable, 1, time.Second)
	if err != nil {
		t.Fatalf("reopen journal: %v", err)
	}
	called := false
	if err := journal.Replay(context.Background(), func(context.Context, string, string, []byte) error {
		called = true
		return nil
	}); err == nil {
		t.Fatal("corrupt journal replay succeeded")
	}
	if called {
		t.Fatal("corrupt record reached receiver")
	}
	closeTestJournal(t, journal, db)
}

func TestJournalReplayUsesReplayIDForIdempotence(t *testing.T) {
	journal, db := openTestJournal(t, journalModeDurable, 1)
	seen := make(map[string]struct{})
	request, err := journal.BeginRequest(context.Background())
	if err != nil {
		t.Fatalf("begin request: %v", err)
	}
	if err := journal.Forward(context.Background(), request, "response.json", []byte("payload"), func(_ context.Context, replayID string) error {
		seen[replayID] = struct{}{}
		return errors.New("crash after receiver apply")
	}); err == nil {
		t.Fatal("forward unexpectedly succeeded")
	}
	if len(seen) != 1 {
		t.Fatalf("receiver calls before reopen = %d, want 1", len(seen))
	}
	if err := journal.Close(context.Background()); err != nil {
		t.Fatalf("close journal: %v", err)
	}
	journal, err = newJournal(db, journalModeDurable, 1, time.Second)
	if err != nil {
		t.Fatalf("reopen journal: %v", err)
	}
	apply := func(_ context.Context, replayID, _ string, _ []byte) error {
		if _, exists := seen[replayID]; exists {
			return nil
		}
		seen[replayID] = struct{}{}
		return errors.New("forced crash")
	}
	if err := journal.Replay(context.Background(), apply); err != nil {
		t.Fatalf("replay after receiver apply: %v", err)
	}
	if len(seen) != 1 {
		t.Fatalf("receiver calls after reopen = %d, want 1", len(seen))
	}
	var pending int64
	if err := db.Model(&JournalRecord{}).Where("applied = ?", false).Count(&pending).Error; err != nil {
		t.Fatalf("count pending records: %v", err)
	}
	if pending != 0 {
		t.Fatalf("pending records after replay = %d, want 0", pending)
	}
}

func TestJournalSequencesAndReplayIDsAreUniqueUnderConcurrency(t *testing.T) {
	journal, db := openTestJournal(t, journalModeDurable, 1)
	defer closeTestJournal(t, journal, db)
	request, err := journal.BeginRequest(context.Background())
	if err != nil {
		t.Fatalf("begin request: %v", err)
	}
	const eventCount = 32
	var waitGroup sync.WaitGroup
	errorsSeen := make(chan error, eventCount)
	for index := range eventCount {
		waitGroup.Add(1)
		go func(index int) {
			defer waitGroup.Done()
			err := journal.Forward(context.Background(), request, "event", []byte{byte(index)}, func(context.Context, string) error { return nil })
			errorsSeen <- err
		}(index)
	}
	waitGroup.Wait()
	close(errorsSeen)
	for err := range errorsSeen {
		if err != nil {
			t.Fatalf("concurrent forward: %v", err)
		}
	}
	var records []JournalRecord
	if err := db.Where("request_id = ?", request.ID).Order("sequence asc").Find(&records).Error; err != nil {
		t.Fatalf("load records: %v", err)
	}
	if len(records) != eventCount+1 {
		t.Fatalf("record count = %d, want %d", len(records), eventCount+1)
	}
	for index, record := range records {
		if record.Sequence != uint64(index) || !record.Applied {
			t.Fatalf("record %d = %+v", index, record)
		}
	}
	if err := journal.CompleteRequest(context.Background(), request); err != nil {
		t.Fatalf("complete request: %v", err)
	}
}
func TestResponsesStreamWritesEachJournaledFrameOnce(t *testing.T) {
	fixture, err := os.ReadFile(filepath.Join("..", "codex", "testdata", "responses_terminal.sse"))
	if err != nil {
		t.Fatal(err)
	}
	upstream := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "text/event-stream")
		_, _ = writer.Write(fixture)
	}))
	defer upstream.Close()

	servers, rawKey := newResponsesTestServer(t, upstream.URL, nil)
	defer shutdownResponsesTestServer(t, servers)
	response := doResponsesRequest(t, servers.DataAddr(), rawKey, `{"model":"gpt-5.6-sol","stream":true}`, "application/json")
	body, err := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if err != nil {
		t.Fatalf("read Responses stream: %v", err)
	}
	if response.StatusCode != http.StatusOK {
		t.Fatalf("Responses status = %d, body = %s", response.StatusCode, body)
	}

	var records []JournalRecord
	if err := servers.journal.db.Order("sequence asc").Find(&records).Error; err != nil {
		t.Fatalf("load journal records: %v", err)
	}
	if len(records) < 2 || records[0].EventType != journalRequestEventType {
		t.Fatalf("journal records = %+v", records)
	}
	for _, record := range records[1:] {
		if !record.Applied {
			t.Fatalf("journal record %q is not applied", record.ReplayID)
		}
		if count := bytes.Count(body, record.Payload); count != 1 {
			t.Fatalf("journal payload %q appears %d times in response", record.EventType, count)
		}
	}
}
func TestChatRequestStoresJournalMode(t *testing.T) {
	fixture, err := os.ReadFile(filepath.Join("..", "codex", "testdata", "responses_terminal.sse"))
	if err != nil {
		t.Fatal(err)
	}
	upstream := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "text/event-stream")
		_, _ = writer.Write(fixture)
	}))
	defer upstream.Close()
	policy := &apikey.Policy{
		Name:             "chat-journal-test",
		Owner:            "chat-journal-test",
		AllowedEndpoints: []string{chatCompletionsEndpoint},
		AllowedModels:    []string{"gpt-5.6-sol"},
	}
	servers, rawKey := newResponsesTestServer(t, upstream.URL, policy)
	defer shutdownResponsesTestServer(t, servers)
	request, err := http.NewRequest(http.MethodPost, "http://"+servers.DataAddr()+chatCompletionsEndpoint, strings.NewReader(`{"model":"gpt-5.6-sol","messages":[{"role":"user","content":"hello"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+rawKey)
	request.Header.Set("Content-Type", "application/json")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatalf("send Chat request: %v", err)
	}
	_, _ = io.ReadAll(response.Body)
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK && response.StatusCode != http.StatusBadGateway {
		t.Fatalf("Chat status = %d", response.StatusCode)
	}
	assertRequestJournalMode(t, servers)
}

func TestImageRequestStoresJournalModeWithoutUpstream(t *testing.T) {
	upstream := httptest.NewServer(http.NotFoundHandler())
	defer upstream.Close()
	policy := &apikey.Policy{
		Name:             "image-journal-test",
		Owner:            "image-journal-test",
		AllowedEndpoints: []string{imagesGenerationsEndpoint},
		AllowedModels:    []string{"gpt-image-2"},
	}
	servers, rawKey := newResponsesTestServer(t, upstream.URL, policy)
	defer shutdownResponsesTestServer(t, servers)
	request, err := http.NewRequest(http.MethodPost, "http://"+servers.DataAddr()+imagesGenerationsEndpoint, strings.NewReader(`{"model":"gpt-image-2","prompt":"hello"}`))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+rawKey)
	request.Header.Set("Content-Type", "application/json")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatalf("send Images request: %v", err)
	}
	_, _ = io.ReadAll(response.Body)
	_ = response.Body.Close()
	if response.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("Images status = %d, want %d", response.StatusCode, http.StatusServiceUnavailable)
	}
	assertRequestJournalMode(t, servers)
}

func assertRequestJournalMode(t *testing.T, servers *Servers) {
	t.Helper()
	var records []JournalRecord
	if err := servers.journal.db.Order("created_at asc").Find(&records).Error; err != nil {
		t.Fatalf("load journal records: %v", err)
	}
	for _, record := range records {
		if record.EventType == journalRequestEventType {
			if record.Mode != journalModeDurable {
				t.Fatalf("request journal mode = %q, want %q", record.Mode, journalModeDurable)
			}
			return
		}
	}
	t.Fatalf("request mode record missing from %+v", records)
}
