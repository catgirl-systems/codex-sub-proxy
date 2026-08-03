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
	"github.com/catgirl-systems/codex-sub-proxy/internal/envelope"
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
		if count != 2 {
			return errors.New("journal records were not durable before callback")
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
	if count != 3 {
		t.Fatalf("journal record count = %d, want 3", count)
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
	if err := db.Where("request_id = ? AND event_type = ?", request.ID, "request.terminal").First(&record).Error; err != nil {
		t.Fatalf("load request record: %v", err)
	}
	if record.EventType != "request.terminal" || record.Mode != journalModeBestEffort || record.Sequence == 0 {
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
	if err := journal.Forward(context.Background(), request, "response.first", []byte(`{"first":true}`), func(context.Context, string) error { return nil }); err != nil {
		t.Fatalf("fill queue: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := journal.Forward(ctx, request, "second", []byte("two"), func(context.Context, string) error { return nil }); err == nil {
		t.Fatal("full queue accepted a canceled context")
	}
	if len(journal.queue) != 0 {
		t.Fatalf("legacy queue length = %d, want 0", len(journal.queue))
	}
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

func TestBestEffortFailedForwardDoesNotQueueOutput(t *testing.T) {
	journal, db := openTestJournal(t, journalModeBestEffort, 1)
	request, err := journal.BeginRequest(context.Background())
	if err != nil {
		t.Fatalf("begin request: %v", err)
	}
	if err := journal.Forward(context.Background(), request, "response.json", []byte(`{"never_delivered":true}`), func(context.Context, string) error {
		return errors.New("forward failed")
	}); err == nil {
		t.Fatal("failed forward succeeded")
	}
	var outputCount int64
	if err := db.Model(&JournalRecord{}).Where("event_type = ?", "response.json").Count(&outputCount).Error; err != nil {
		t.Fatalf("count output records: %v", err)
	}
	if outputCount != 1 || len(journal.queue) != 0 {
		t.Fatalf("failed output durable spool = rows:%d queue:%d", outputCount, len(journal.queue))
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := journal.CompleteRequest(ctx, request); err == nil {
		t.Fatal("canceled completion succeeded")
	}
	if journal.requestState(request) == nil {
		t.Fatal("request state was removed after failed completion")
	}
	if err := journal.RecordTerminal(context.Background(), request, requestStatusFailed, nil); err != nil {
		t.Fatalf("record later terminal: %v", err)
	}
	if err := journal.CompleteRequest(context.Background(), request); err != nil {
		t.Fatalf("complete after later terminal: %v", err)
	}
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
func TestJournalConcurrentTerminalClaimsAppendOneRecord(t *testing.T) {
	journal, db := openTestJournal(t, journalModeDurable, 8)
	defer closeTestJournal(t, journal, db)
	request, err := journal.BeginRequest(context.Background())
	if err != nil {
		t.Fatalf("begin request: %v", err)
	}
	const callers = 32
	start := make(chan struct{})
	errs := make(chan error, callers)
	var waitGroup sync.WaitGroup
	for index := range callers {
		waitGroup.Add(1)
		go func(index int) {
			defer waitGroup.Done()
			<-start
			if index%2 == 0 {
				errs <- journal.RecordTerminal(context.Background(), request, requestStatusSucceeded, nil)
				return
			}
			errs <- journal.CompleteRequestWithState(context.Background(), request, requestStatusFailed)
		}(index)
	}
	close(start)
	waitGroup.Wait()
	close(errs)
	for err := range errs {
		if err != nil && !strings.Contains(err.Error(), "unknown") {
			t.Fatalf("concurrent terminal claim: %v", err)
		}
	}
	var terminalCount int64
	if err := db.Model(&JournalRecord{}).Where("request_id = ? AND event_type = ?", request.ID, "request.terminal").Count(&terminalCount).Error; err != nil {
		t.Fatalf("count terminal records: %v", err)
	}
	if terminalCount != 1 {
		t.Fatalf("terminal record count = %d, want 1", terminalCount)
	}
}

func TestJournalTerminalClaimReleasesAfterAppendFailure(t *testing.T) {
	journal, db := openTestJournal(t, journalModeDurable, 2)
	defer closeTestJournal(t, journal, db)
	request, err := journal.BeginRequest(context.Background())
	if err != nil {
		t.Fatalf("begin request: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := journal.RecordTerminal(ctx, request, requestStatusFailed, nil); err == nil {
		t.Fatal("canceled terminal append succeeded")
	}
	state := journal.requestState(request)
	if state == nil {
		t.Fatal("request state was removed after failed append")
	}
	state.mu.Lock()
	claimed, appended := state.terminalClaimed, state.terminalRecord
	state.mu.Unlock()
	if claimed || appended {
		t.Fatalf("terminal state after failed append = claimed:%t appended:%t", claimed, appended)
	}
	if err := journal.RecordTerminal(context.Background(), request, requestStatusFailed, nil); err != nil {
		t.Fatalf("later terminal append: %v", err)
	}
	var terminalCount int64
	if err := db.Model(&JournalRecord{}).Where("request_id = ? AND event_type = ?", request.ID, "request.terminal").Count(&terminalCount).Error; err != nil {
		t.Fatalf("count terminal records: %v", err)
	}
	if terminalCount != 1 {
		t.Fatalf("terminal record count = %d, want 1", terminalCount)
	}
}

func TestJournalPlaintextBoundsAllowExactAndRejectOversize(t *testing.T) {
	payload := []byte(`"` + strings.Repeat("x", envelope.MaxPlaintextSize-2) + `"`)
	if len(payload) != envelope.MaxPlaintextSize {
		t.Fatalf("exact payload length = %d, want %d", len(payload), envelope.MaxPlaintextSize)
	}
	for _, mode := range []string{journalModeDurable, journalModeBestEffort} {
		t.Run(mode, func(t *testing.T) {
			journal, db := openTestJournal(t, mode, 4)
			defer closeTestJournal(t, journal, db)
			request, err := journal.BeginRequest(context.Background())
			if err != nil {
				t.Fatalf("begin request: %v", err)
			}
			if err := journal.Forward(context.Background(), request, "response.json", payload, func(context.Context, string) error { return nil }); err != nil {
				t.Fatalf("exact payload append: %v", err)
			}
			if err := journal.Forward(context.Background(), request, "response.json", append(append([]byte(nil), payload...), 'x'), func(context.Context, string) error { return nil }); err == nil {
				t.Fatal("oversized payload append succeeded")
			}
			var record JournalRecord
			if err := db.Where("request_id = ? AND event_type = ?", request.ID, "response.json").First(&record).Error; err != nil {
				t.Fatalf("load exact payload record: %v", err)
			}
			if len(record.Payload) != envelope.MaxEnvelopeSize {
				t.Fatalf("stored envelope length = %d, want %d", len(record.Payload), envelope.MaxEnvelopeSize)
			}
			if err := journal.Replay(context.Background()); err != nil {
				t.Fatalf("materialize exact payload: %v", err)
			}
		})
	}
}

func TestJournalCloseDeadlineUnblocksAdmittedEnqueue(t *testing.T) {
	journal, db := openTestJournal(t, journalModeBestEffort, 1)
	journal.queue <- journalWork{records: []JournalRecord{{ReplayID: "filled"}}}
	if err := journal.beginOperation(); err != nil {
		t.Fatalf("admit enqueue: %v", err)
	}
	forwardDone := make(chan error, 1)
	go func() {
		defer journal.endOperation()
		forwardDone <- journal.enqueue(context.Background(), journalWork{records: []JournalRecord{{ReplayID: "blocked"}}})
	}()
	closeContext, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := journal.Close(closeContext); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("close error = %v, want deadline", err)
	}
	select {
	case err := <-forwardDone:
		if !errors.Is(err, ErrJournalClosed) && !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("admitted enqueue error = %v, want close or deadline", err)
		}
	case <-time.After(time.Second):
		t.Fatal("admitted enqueue remained blocked")
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
	if err := journal.Close(context.Background()); err == nil {
		t.Fatal("close corrupt journal succeeded")
	}
	journal, err = newJournal(db, journalModeDurable, 1, time.Second)
	if err != nil {
		t.Fatalf("reopen journal: %v", err)
	}
	if err := journal.Replay(context.Background()); err == nil {
		t.Fatal("corrupt journal replay succeeded")
	}
	var receipts int64
	if err := db.Model(&JournalReceipt{}).Count(&receipts).Error; err != nil {
		t.Fatalf("count receipts: %v", err)
	}
	if receipts != 1 {
		t.Fatalf("receipt count = %d, want 1 accepted receipt", receipts)
	}
	_ = journal.Close(context.Background())
}

func TestJournalReplayUsesReplayIDForIdempotence(t *testing.T) {
	journal, db := openTestJournal(t, journalModeDurable, 1)
	request, err := journal.BeginRequest(context.Background())
	if err != nil {
		t.Fatalf("begin request: %v", err)
	}
	if err := journal.Forward(context.Background(), request, "response.json", []byte(`{"payload":true}`), func(context.Context, string) error {
		return errors.New("leave pending")
	}); err == nil {
		t.Fatal("forward unexpectedly succeeded")
	}
	if err := journal.Close(context.Background()); err != nil {
		t.Fatalf("close journal: %v", err)
	}

	journal, err = newJournal(db, journalModeDurable, 1, time.Second)
	if err != nil {
		t.Fatalf("reopen journal: %v", err)
	}
	if err := journal.Replay(context.Background()); err != nil {
		t.Fatalf("replay after reopen: %v", err)
	}
	var receipts []JournalReceipt
	if err := db.Find(&receipts).Error; err != nil {
		t.Fatalf("load receipts: %v", err)
	}
	if len(receipts) != 2 {
		t.Fatalf("receipt count after replay = %d, want 2", len(receipts))
	}
	var pending int64
	if err := db.Model(&JournalRecord{}).Where("applied = ?", false).Count(&pending).Error; err != nil {
		t.Fatalf("count pending records: %v", err)
	}
	if pending != 0 {
		t.Fatalf("pending records after replay = %d, want 0", pending)
	}
	if err := db.Model(&JournalRecord{}).Where("replay_id = ?", receipts[0].ReplayID).Update("applied", false).Error; err != nil {
		t.Fatalf("reset source state: %v", err)
	}
	if err := journal.Replay(context.Background()); err != nil {
		t.Fatalf("replay duplicate receipt: %v", err)
	}
	if err := db.Model(&JournalReceipt{}).Count(&pending).Error; err != nil {
		t.Fatalf("count duplicate receipts: %v", err)
	}
	if pending != 2 {
		t.Fatalf("receipt count after duplicate replay = %d, want 2", pending)
	}
	closeTestJournal(t, journal, db)
}
func TestJournalReplayRejectsImmutableFieldTampering(t *testing.T) {
	tamperers := []struct {
		name string
		edit func(*JournalRecord)
	}{
		{name: "replay id", edit: func(record *JournalRecord) {
			record.ReplayID = "11111111-1111-4111-8111-111111111111"
		}},
		{name: "request id", edit: func(record *JournalRecord) {
			record.RequestID = "22222222-2222-4222-8222-222222222222"
		}},
		{name: "sequence", edit: func(record *JournalRecord) {
			record.Sequence++
		}},
		{name: "mode", edit: func(record *JournalRecord) {
			record.Mode = journalModeBestEffort
		}},
		{name: "event type", edit: func(record *JournalRecord) {
			record.EventType = "tampered.event"
		}},
		{name: "payload", edit: func(record *JournalRecord) {
			record.Payload = []byte("tampered payload")
		}},
	}
	for _, test := range tamperers {
		t.Run(test.name, func(t *testing.T) {
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
			var record JournalRecord
			if err := db.Where("event_type = ?", "response.json").First(&record).Error; err != nil {
				t.Fatalf("load record: %v", err)
			}
			originalReplayID := record.ReplayID
			test.edit(&record)
			if err := db.Model(&JournalRecord{}).Where("replay_id = ?", originalReplayID).Updates(map[string]any{
				"replay_id":  record.ReplayID,
				"request_id": record.RequestID,
				"sequence":   record.Sequence,
				"mode":       record.Mode,
				"event_type": record.EventType,
				"payload":    record.Payload,
			}).Error; err != nil {
				t.Fatalf("save tampered record: %v", err)
			}
			if err := journal.Close(context.Background()); err == nil {
				t.Fatal("close tampered journal succeeded")
			}
			journal, err = newJournal(db, journalModeDurable, 1, time.Second)
			if err != nil {
				t.Fatalf("reopen journal: %v", err)
			}
			if err := journal.Replay(context.Background()); err == nil {
				t.Fatal("tampered replay succeeded")
			}
			var receipts int64
			if err := db.Model(&JournalReceipt{}).Count(&receipts).Error; err != nil {
				t.Fatalf("count receipts: %v", err)
			}
			if receipts != 1 {
				t.Fatalf("receipt count = %d, want 1 accepted receipt", receipts)
			}
			_ = journal.Close(context.Background())
		})
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
			err := journal.Forward(context.Background(), request, "response.event", []byte(`{"type":"response.event"}`), func(context.Context, string) error { return nil })
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
func TestServerStartupReplaysPendingJournalReceipt(t *testing.T) {
	journal, db := openTestJournal(t, journalModeDurable, 1)
	request, err := journal.BeginRequest(context.Background())
	if err != nil {
		t.Fatalf("begin request: %v", err)
	}
	if err := journal.Forward(context.Background(), request, "response.json", []byte(`{"recovered":true}`), func(context.Context, string) error {
		return errors.New("forced interruption")
	}); err == nil {
		t.Fatal("forward unexpectedly succeeded")
	}
	if err := journal.Close(context.Background()); err != nil {
		t.Fatalf("close seed journal: %v", err)
	}

	start := func() *Servers {
		servers, err := startWithWriteTimeout(Config{
			Listen:      "127.0.0.1:0",
			AdminListen: "127.0.0.1:0",
			Database:    db,
		}, NewReadiness(), time.Second)
		if err != nil {
			t.Fatalf("start server: %v", err)
		}
		return servers
	}
	servers := start()
	var receipts int64
	if err := db.Model(&JournalReceipt{}).Count(&receipts).Error; err != nil {
		t.Fatalf("count startup receipts: %v", err)
	}
	if receipts != 2 {
		t.Fatalf("startup receipt count = %d, want 2", receipts)
	}
	if err := servers.Shutdown(context.Background()); err != nil {
		t.Fatalf("shutdown first server: %v", err)
	}
	servers = start()
	if err := db.Model(&JournalReceipt{}).Count(&receipts).Error; err != nil {
		t.Fatalf("count repeated receipts: %v", err)
	}
	if receipts != 2 {
		t.Fatalf("repeated receipt count = %d, want 2", receipts)
	}
	if err := servers.Shutdown(context.Background()); err != nil {
		t.Fatalf("shutdown second server: %v", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("get database: %v", err)
	}
	if err := sqlDB.Close(); err != nil {
		t.Fatalf("close database: %v", err)
	}
}

func TestServerStartupRejectsCorruptPendingJournal(t *testing.T) {
	journal, db := openTestJournal(t, journalModeDurable, 1)
	request, err := journal.BeginRequest(context.Background())
	if err != nil {
		t.Fatalf("begin request: %v", err)
	}
	if err := journal.Forward(context.Background(), request, "response.json", []byte("corrupt me"), func(context.Context, string) error {
		return errors.New("forced interruption")
	}); err == nil {
		t.Fatal("forward unexpectedly succeeded")
	}
	if err := db.Model(&JournalRecord{}).Where("event_type = ?", "response.json").Update("event_type", "tampered").Error; err != nil {
		t.Fatalf("tamper journal event: %v", err)
	}
	if err := journal.Close(context.Background()); err == nil {
		t.Fatal("close corrupt journal succeeded")
	}
	_, err = startWithWriteTimeout(Config{
		Listen:      "127.0.0.1:0",
		AdminListen: "127.0.0.1:0",
		Database:    db,
	}, NewReadiness(), time.Second)
	if err == nil {
		t.Fatal("corrupt journal allowed server startup")
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("get database: %v", err)
	}
	if err := sqlDB.Close(); err != nil {
		t.Fatalf("close database: %v", err)
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
		if !knownStreamEvent(record.EventType) {
			continue
		}
		plain, err := servers.journal.decryptJournalPayload(record)
		if err != nil {
			t.Fatalf("decrypt journal record: %v", err)
		}
		if count := bytes.Count(body, plain); count != 1 {
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
func TestJournalDatabaseNeverStoresPlaintextPayload(t *testing.T) {
	journal, db := openTestJournal(t, journalModeDurable, 2)
	request, err := journal.BeginRequestWithMetadata(context.Background(), JournalRequestMetadata{
		Endpoint: responsesEndpoint,
		Model:    "gpt-5.6-sol",
		APIKeyID: "key-id-safe",
	}, []byte(`{"prompt":"prompt-secret","tool":"tool-secret","image":"data:image/png;base64,base64-secret"}`))
	if err != nil {
		t.Fatalf("begin request: %v", err)
	}
	event := []byte(`{"type":"response.output_text.delta","delta":"event-secret"}`)
	if err := journal.Forward(context.Background(), request, "response.output_text.delta", event, func(context.Context, string) error { return nil }); err != nil {
		t.Fatalf("forward event: %v", err)
	}
	if err := journal.RecordTerminal(context.Background(), request, requestStatusSucceeded, []byte("terminal-secret")); err != nil {
		t.Fatalf("record terminal: %v", err)
	}
	if err := journal.Close(context.Background()); err != nil {
		t.Fatalf("close journal: %v", err)
	}
	var records []JournalRecord
	if err := db.Find(&records).Error; err != nil {
		t.Fatalf("load records: %v", err)
	}
	for _, record := range records {
		if bytes.Contains(record.Payload, []byte("prompt-secret")) ||
			bytes.Contains(record.Payload, []byte("tool-secret")) ||
			bytes.Contains(record.Payload, []byte("base64-secret")) ||
			bytes.Contains(record.Payload, []byte("event-secret")) ||
			bytes.Contains(record.Payload, []byte("terminal-secret")) {
		}
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("get database: %v", err)
	}
	if err := sqlDB.Close(); err != nil {
		t.Fatalf("close database: %v", err)
	}
}

func TestJournalTerminalConflictKeepsFirstState(t *testing.T) {
	journal, db := openTestJournal(t, journalModeDurable, 2)
	request, err := journal.BeginRequest(context.Background())
	if err != nil {
		t.Fatalf("begin request: %v", err)
	}
	if err := journal.RecordTerminal(context.Background(), request, requestStatusSucceeded, nil); err != nil {
		t.Fatalf("record success: %v", err)
	}
	var firstTerminal JournalRecord
	if err := db.Where("request_id = ? AND event_type = ?", request.ID, "request.terminal").First(&firstTerminal).Error; err != nil {
		t.Fatalf("load first terminal: %v", err)
	}
	terminalPayload, err := lifecycleTerminalBytes(requestStatusSucceeded, []byte("conflict-detail"))
	if err != nil {
		t.Fatalf("encode conflict terminal: %v", err)
	}
	conflictReplayID, err := newJournalUUID()
	if err != nil {
		t.Fatalf("generate conflict replay ID: %v", err)
	}
	conflict, err := journal.newEncryptedRecord(conflictReplayID, request.ID, 0, request.Mode, "request.terminal", terminalPayload, true)
	if err != nil {
		t.Fatalf("build conflict record: %v", err)
	}
	conflict.CreatedAt = firstTerminal.CreatedAt.Add(time.Nanosecond)
	requestState := journal.requestState(request)
	if requestState == nil {
		t.Fatal("request state missing")
	}
	requestState.mu.Lock()
	if err := journal.appendRecord(context.Background(), requestState, conflict); err != nil {
		requestState.mu.Unlock()
		t.Fatalf("append conflict record: %v", err)
	}
	requestState.nextSequence++
	requestState.mu.Unlock()
	if err := journal.Close(context.Background()); err != nil {
		t.Fatalf("close journal: %v", err)
	}
	var conflictRecord JournalRecord
	if err := db.Where("replay_id = ?", conflictReplayID).First(&conflictRecord).Error; err != nil {
		t.Fatalf("load conflict record: %v", err)
	}
	materializeRequest := JournalRequest{
		ID: request.ID, Mode: request.Mode, ConversationID: request.ConversationID,
		Endpoint: request.Endpoint, Model: request.Model, APIKeyID: request.APIKeyID,
	}
	for range 2 {
		if err := db.Transaction(func(tx *gorm.DB) error {
			return journal.materializeRecord(tx, conflictRecord, materializeRequest)
		}); err != nil {
			t.Fatalf("repeat conflict materialization: %v", err)
		}
	}
	var requestRow RequestRecord
	if err := db.Where("request_id = ?", request.ID).First(&requestRow).Error; err != nil {
		t.Fatalf("load request projection: %v", err)
	}
	if requestRow.Status != requestStatusSucceeded || requestRow.TerminalAt == nil || !requestRow.TerminalConflict {
		t.Fatalf("request projection = %+v", requestRow)
	}
	var conflicts int64
	if err := db.Model(&AuditRecord{}).Where("request_id = ? AND event_type = ?", request.ID, "terminal.conflict").Count(&conflicts).Error; err != nil {
		t.Fatalf("count terminal conflicts: %v", err)
	}
	if conflicts != 1 {
		t.Fatalf("terminal conflict count = %d, want 1", conflicts)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("get database: %v", err)
	}
	if err := sqlDB.Close(); err != nil {
		t.Fatalf("close database: %v", err)
	}
}
func TestJournalKeyRotationAndWrongKeyFailClosed(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "rotation.sqlite3")
	db, err := storage.Open(context.Background(), dbPath, time.Second)
	if err != nil {
		t.Fatalf("open database: %v", err)
	}
	if err := MigrateJournal(db); err != nil {
		t.Fatalf("migrate journal: %v", err)
	}
	keyOne, err := envelope.NewKey(1, bytes.Repeat([]byte{1}, envelope.KeySize))
	if err != nil {
		t.Fatalf("key one: %v", err)
	}
	keyTwo, err := envelope.NewKey(2, bytes.Repeat([]byte{2}, envelope.KeySize))
	if err != nil {
		t.Fatalf("key two: %v", err)
	}
	keysOne, err := envelope.NewKeySet(keyOne)
	if err != nil {
		t.Fatalf("key set one: %v", err)
	}
	journal, err := newJournalWithKeys(db, journalModeDurable, 2, time.Second, keysOne)
	if err != nil {
		t.Fatalf("new journal one: %v", err)
	}
	request, err := journal.BeginRequestWithMetadata(context.Background(), JournalRequestMetadata{Endpoint: responsesEndpoint, Model: "gpt-5.6-sol"}, []byte(`{"prompt":"rotation-secret"}`))
	if err != nil {
		t.Fatalf("begin request: %v", err)
	}
	if err := journal.RecordTerminal(context.Background(), request, requestStatusSucceeded, nil); err != nil {
		t.Fatalf("record terminal: %v", err)
	}
	if err := journal.Close(context.Background()); err != nil {
		t.Fatalf("close journal one: %v", err)
	}
	rotated, err := envelope.NewKeySet(keyTwo, keyOne)
	if err != nil {
		t.Fatalf("rotated keys: %v", err)
	}
	journal, err = newJournalWithKeys(db, journalModeDurable, 2, time.Second, rotated)
	if err != nil {
		t.Fatalf("new rotated journal: %v", err)
	}
	if err := journal.Replay(context.Background()); err != nil {
		t.Fatalf("replay old key: %v", err)
	}
	var oldRecord JournalRecord
	if err := db.Where("event_type = ?", "request.input").First(&oldRecord).Error; err != nil {
		t.Fatalf("load old record: %v", err)
	}
	if _, err := journal.decryptJournalPayload(oldRecord); err != nil {
		t.Fatalf("decrypt old record with previous key: %v", err)
	}
	newRequest, err := journal.BeginRequest(context.Background())
	if err != nil {
		t.Fatalf("begin rotated request: %v", err)
	}
	if err := journal.Forward(context.Background(), newRequest, "response.json", []byte(`{"rotated":true}`), func(context.Context, string) error { return nil }); err != nil {
		t.Fatalf("forward rotated event: %v", err)
	}
	var newest JournalRecord
	if err := db.Order("created_at desc").First(&newest).Error; err != nil {
		t.Fatalf("load newest record: %v", err)
	}
	if newest.KeyVersion != keyTwo.Version {
		t.Fatalf("new record key version = %d, want %d", newest.KeyVersion, keyTwo.Version)
	}
	if err := journal.Close(context.Background()); err != nil {
		t.Fatalf("close rotated journal: %v", err)
	}
	if err := db.Model(&JournalRecord{}).Where("event_type = ?", "request.input").Update("applied", false).Error; err != nil {
		t.Fatalf("leave old record pending: %v", err)
	}
	var pendingRecord JournalRecord
	if err := db.Where("event_type = ?", "request.input").First(&pendingRecord).Error; err != nil {
		t.Fatalf("load old record: %v", err)
	}
	if err := db.Where("replay_id = ?", pendingRecord.ReplayID).Delete(&JournalReceipt{}).Error; err != nil {
		t.Fatalf("remove old receipt: %v", err)
	}
	wrongKey, err := envelope.NewKey(3, bytes.Repeat([]byte{3}, envelope.KeySize))
	if err != nil {
		t.Fatalf("wrong key: %v", err)
	}
	wrongKeys, err := envelope.NewKeySet(wrongKey)
	if err != nil {
		t.Fatalf("wrong key set: %v", err)
	}
	wrongJournal, err := newJournalWithKeys(db, journalModeDurable, 1, time.Second, wrongKeys)
	if err != nil {
		t.Fatalf("new wrong-key journal: %v", err)
	}
	if err := wrongJournal.Replay(context.Background()); err == nil {
		t.Fatal("wrong-key replay succeeded")
	}
	_ = wrongJournal.Close(context.Background())
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("get database: %v", err)
	}
	if err := sqlDB.Close(); err != nil {
		t.Fatalf("close database: %v", err)
	}
}
func TestJournalReplayQueueSaturationDoesNotBlockForward(t *testing.T) {
	journal, db := openTestJournal(t, journalModeDurable, 1)
	request, err := journal.BeginRequestWithMetadata(context.Background(), JournalRequestMetadata{Endpoint: responsesEndpoint, Model: "gpt-5.6-sol"}, []byte(`{"prompt":"bounded"}`))
	if err != nil {
		t.Fatalf("begin request: %v", err)
	}
	callbackDone := make(chan struct{})
	if err := journal.Forward(context.Background(), request, "response.output_text.delta", []byte(`{"type":"response.output_text.delta","delta":"ok"}`), func(context.Context, string) error {
		close(callbackDone)
		return nil
	}); err != nil {
		t.Fatalf("forward saturated queue: %v", err)
	}
	select {
	case <-callbackDone:
	case <-time.After(time.Second):
		t.Fatal("forward callback blocked on replay queue")
	}
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

func TestJournalCrashReopenDrainsPendingOnce(t *testing.T) {
	journal, db := openTestJournal(t, journalModeDurable, 1)
	request, err := journal.BeginRequest(context.Background())
	if err != nil {
		t.Fatalf("begin request: %v", err)
	}
	if err := journal.Forward(context.Background(), request, "response.json", []byte(`{"reopen":true}`), func(context.Context, string) error {
		return errors.New("simulated crash")
	}); err == nil {
		t.Fatal("forward unexpectedly succeeded")
	}
	reopened, err := newJournal(db, journalModeDurable, 1, time.Second)
	if err != nil {
		t.Fatalf("reopen journal: %v", err)
	}
	if err := reopened.Replay(context.Background()); err != nil {
		t.Fatalf("replay pending record: %v", err)
	}
	var events int64
	if err := db.Model(&StreamEventRecord{}).Where("event_type = ?", "response.json").Count(&events).Error; err != nil {
		t.Fatalf("count replayed events: %v", err)
	}
	if events != 1 {
		t.Fatalf("replayed event count = %d, want 1", events)
	}
	if err := reopened.Replay(context.Background()); err != nil {
		t.Fatalf("replay after reopen: %v", err)
	}
	if err := db.Model(&StreamEventRecord{}).Where("event_type = ?", "response.json").Count(&events).Error; err != nil {
		t.Fatalf("count repeated events: %v", err)
	}
	if events != 1 {
		t.Fatalf("repeated event count = %d, want 1", events)
	}
	_ = journal.Close(context.Background())
	_ = reopened.Close(context.Background())
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("get database: %v", err)
	}
	if err := sqlDB.Close(); err != nil {
		t.Fatalf("close database: %v", err)
	}
}
