package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
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
	if err := journal.appendRecord(context.Background(), requestState, conflict, ""); err != nil {
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

func TestJournalResponseLinksResolveAndExpire(t *testing.T) {
	journal, db := openTestJournal(t, journalModeDurable, 4)
	defer closeTestJournal(t, journal, db)

	request, err := journal.BeginRequestWithMetadata(context.Background(), JournalRequestMetadata{
		Endpoint: responsesEndpoint, Model: "gpt-5.6-sol", APIKeyID: "key-1",
	}, nil)
	if err != nil {
		t.Fatalf("begin request: %v", err)
	}
	if err := journal.Forward(context.Background(), request, "response.json", []byte(`{"id":"resp-json","status":"completed","output":[]}`), func(context.Context, string) error {
		var count int64
		if err := db.Model(&ResponseLinkRecord{}).Where("response_id = ?", "resp-json").Count(&count).Error; err != nil {
			return err
		}
		if count != 1 {
			return fmt.Errorf("response link count before output = %d", count)
		}
		return nil
	}); err != nil {
		t.Fatalf("forward JSON terminal: %v", err)
	}
	var link ResponseLinkRecord
	if err := db.Where("response_id = ?", "resp-json").First(&link).Error; err != nil {
		t.Fatalf("load JSON response link: %v", err)
	}
	if link.RequestID != request.ID || link.ConversationID != request.ConversationID || link.APIKeyID != "key-1" {
		t.Fatalf("response link = %+v", link)
	}
	resolved, err := journal.ResolvePreviousResponse(context.Background(), "resp-json", "key-1")
	if err != nil {
		t.Fatalf("resolve response link: %v", err)
	}
	if resolved.ConversationID != request.ConversationID || resolved.APIKeyID != "key-1" {
		t.Fatalf("resolved metadata = %+v", resolved)
	}
	if _, err := journal.ResolvePreviousResponse(context.Background(), "resp-json", "other-key"); !errors.Is(err, ErrPreviousResponseNotFound) {
		t.Fatalf("cross-key resolution error = %v", err)
	}
	if err := db.Model(&ResponseLinkRecord{}).Where("response_id = ?", "resp-json").Update("expires_at", time.Now().UTC().Add(-time.Second)).Error; err != nil {
		t.Fatalf("expire response link: %v", err)
	}
	if _, err := journal.ResolvePreviousResponse(context.Background(), "resp-json", "key-1"); !errors.Is(err, ErrPreviousResponseNotFound) {
		t.Fatalf("expired resolution error = %v", err)
	}

	request, err = journal.BeginRequestWithMetadata(context.Background(), JournalRequestMetadata{
		Endpoint: responsesEndpoint, Model: "gpt-5.6-sol", APIKeyID: "key-1",
	}, nil)
	if err != nil {
		t.Fatalf("begin SSE request: %v", err)
	}
	if err := journal.Forward(context.Background(), request, "response.completed", []byte("data: {\"type\":\"response.completed\",\"response\":{\"id\":\"resp-sse\",\"status\":\"completed\"}}\n\n"), func(context.Context, string) error {
		return nil
	}); err != nil {
		t.Fatalf("forward SSE terminal: %v", err)
	}
	if err := db.Where("response_id = ?", "resp-sse").First(&ResponseLinkRecord{}).Error; err != nil {
		t.Fatalf("load SSE response link: %v", err)
	}

	request, err = journal.BeginRequestWithMetadata(context.Background(), JournalRequestMetadata{
		Endpoint: responsesEndpoint, Model: "gpt-5.6-sol", APIKeyID: "key-1",
	}, nil)
	if err != nil {
		t.Fatalf("begin failed request: %v", err)
	}
	if err := journal.Forward(context.Background(), request, "response.failed", []byte(`data: {"type":"response.failed","response":{"id":"resp-failed","status":"failed"}}`), func(context.Context, string) error {
		return nil
	}); err != nil {
		t.Fatalf("forward failed terminal: %v", err)
	}
	var failedLinks int64
	if err := db.Model(&ResponseLinkRecord{}).Where("response_id = ?", "resp-failed").Count(&failedLinks).Error; err != nil {
		t.Fatalf("count failed response links: %v", err)
	}
	if failedLinks != 0 {
		t.Fatalf("failed response link count = %d, want 0", failedLinks)
	}
}

func TestJournalResolvePreviousResponseRejectsDeletingOwners(t *testing.T) {
	journal, db := openTestJournal(t, journalModeDurable, 4)
	defer closeTestJournal(t, journal, db)

	request, err := journal.BeginRequestWithMetadata(context.Background(), JournalRequestMetadata{
		Endpoint: responsesEndpoint, Model: "gpt-5.6-sol", APIKeyID: "key-1",
	}, nil)
	if err != nil {
		t.Fatalf("begin request: %v", err)
	}
	if err := journal.Forward(context.Background(), request, "response.json", []byte(`{"id":"deleting-owner-response","status":"completed","output":[]}`), func(context.Context, string) error {
		return nil
	}); err != nil {
		t.Fatalf("forward response: %v", err)
	}
	if err := journal.Replay(context.Background()); err != nil {
		t.Fatalf("materialize response: %v", err)
	}
	deletingAt := time.Now().UTC()
	if err := db.Model(&RequestRecord{}).Where("request_id = ?", request.ID).Update("deleting_at", deletingAt).Error; err != nil {
		t.Fatalf("mark request deleting: %v", err)
	}
	if _, err := journal.ResolvePreviousResponse(context.Background(), "deleting-owner-response", "key-1"); !errors.Is(err, ErrPreviousResponseNotFound) {
		t.Fatalf("deleting request resolution error = %v", err)
	}
	if err := db.Model(&RequestRecord{}).Where("request_id = ?", request.ID).Update("deleting_at", nil).Error; err != nil {
		t.Fatalf("clear request deletion: %v", err)
	}
	if err := db.Model(&ConversationRecord{}).Where("id = ?", request.ConversationID).Update("deleting_at", deletingAt).Error; err != nil {
		t.Fatalf("mark conversation deleting: %v", err)
	}
	if _, err := journal.ResolvePreviousResponse(context.Background(), "deleting-owner-response", "key-1"); !errors.Is(err, ErrPreviousResponseNotFound) {
		t.Fatalf("deleting conversation resolution error = %v", err)
	}
	if _, err := journal.BeginRequestWithMetadata(context.Background(), JournalRequestMetadata{
		Endpoint: responsesEndpoint, Model: "gpt-5.6-sol", APIKeyID: "key-1", ConversationID: request.ConversationID,
	}, nil); !errors.Is(err, ErrPreviousResponseNotFound) {
		t.Fatalf("begin deleting conversation error = %v", err)
	}
}

func TestJournalBeginRejectsConversationTombstoneAfterResolution(t *testing.T) {
	journal, db := openTestJournal(t, journalModeDurable, 4)
	defer closeTestJournal(t, journal, db)

	now := time.Now().UTC()
	conversationID := "tombstone-race-conversation"
	requestID := "tombstone-race-request"
	if err := db.Create(&ConversationRecord{
		ID: conversationID, CreatedAt: now, UpdatedAt: now, ExpiresAt: now.Add(time.Hour), RequestCount: 1,
	}).Error; err != nil {
		t.Fatalf("create tombstone conversation: %v", err)
	}
	if err := db.Create(&RequestRecord{
		ID: requestID, ReplayID: "tombstone-accepted-replay", ConversationID: conversationID,
		APIKeyID: "key-1", Endpoint: responsesEndpoint, Model: "gpt-5.6-sol", Mode: journalModeDurable,
		Status: requestStatusSucceeded, CreatedAt: now, AcceptedAt: now, StartedAt: now, UpdatedAt: now,
		TerminalAt: &now, ExpiresAt: now.Add(time.Hour),
	}).Error; err != nil {
		t.Fatalf("create tombstone request: %v", err)
	}
	if err := db.Create(&ResponseLinkRecord{
		ResponseID: "tombstone-race-response", RequestID: requestID, ConversationID: conversationID,
		APIKeyID: "key-1", CreatedAt: now, ExpiresAt: now.Add(time.Hour),
	}).Error; err != nil {
		t.Fatalf("create tombstone response link: %v", err)
	}
	if _, err := journal.ResolvePreviousResponse(context.Background(), "tombstone-race-response", "key-1"); err != nil {
		t.Fatalf("resolve response before deletion: %v", err)
	}
	retention, err := NewRetentionRunner(db, nil, RetentionConfig{})
	if err != nil {
		t.Fatalf("new retention runner: %v", err)
	}
	type requestDeletionResult struct {
		marked bool
		err    error
	}
	requestDeletionResults := make(chan requestDeletionResult, 1)
	go func() {
		marked, markErr := retention.markRequestDeleting(context.Background(), requestID, AdminPrincipal{})
		requestDeletionResults <- requestDeletionResult{marked: marked, err: markErr}
	}()
	requestDeadline := time.Now().Add(time.Second)
	for {
		var request RequestRecord
		if err := db.Where("request_id = ?", requestID).First(&request).Error; err != nil {
			t.Fatalf("load deleting request: %v", err)
		}
		if request.DeletingAt != nil {
			break
		}
		if !time.Now().Before(requestDeadline) {
			t.Fatal("request deletion did not commit")
		}
		time.Sleep(time.Millisecond)
	}
	requestDeletion := <-requestDeletionResults
	if requestDeletion.err != nil || !requestDeletion.marked {
		t.Fatalf("mark request deleting: marked=%t err=%v", requestDeletion.marked, requestDeletion.err)
	}
	if _, err := journal.BeginRequestWithMetadata(context.Background(), JournalRequestMetadata{
		Endpoint: responsesEndpoint, Model: "gpt-5.6-sol", APIKeyID: "key-1",
		ConversationID: conversationID, PreviousResponseID: "tombstone-race-response",
	}, nil); !errors.Is(err, ErrPreviousResponseNotFound) {
		t.Fatalf("begin request-tombstoned continuation error = %v", err)
	}
	type deletionResult struct {
		marked bool
		err    error
	}
	deletionResults := make(chan deletionResult, 1)
	go func() {
		marked, markErr := retention.markConversationDeleting(context.Background(), conversationID, AdminPrincipal{})
		deletionResults <- deletionResult{marked: marked, err: markErr}
	}()
	deadline := time.Now().Add(time.Second)
	for {
		var conversation ConversationRecord
		if err := db.Where("id = ?", conversationID).First(&conversation).Error; err != nil {
			t.Fatalf("load deleting conversation: %v", err)
		}
		if conversation.DeletingAt != nil {
			break
		}
		if !time.Now().Before(deadline) {
			t.Fatal("conversation deletion did not commit")
		}
		time.Sleep(time.Millisecond)
	}
	deletion := <-deletionResults
	if deletion.err != nil || !deletion.marked {
		t.Fatalf("mark conversation deleting: marked=%t err=%v", deletion.marked, deletion.err)
	}
	if _, err := journal.BeginRequestWithMetadata(context.Background(), JournalRequestMetadata{
		Endpoint: responsesEndpoint, Model: "gpt-5.6-sol", APIKeyID: "key-1", ConversationID: conversationID,
	}, nil); !errors.Is(err, ErrPreviousResponseNotFound) {
		t.Fatalf("begin tombstoned continuation error = %v", err)
	}
}

func TestJournalResponseLinkCollisionAndTerminalExpiry(t *testing.T) {
	journal, db := openTestJournal(t, journalModeDurable, 4)
	defer closeTestJournal(t, journal, db)

	request, err := journal.BeginRequestWithMetadata(context.Background(), JournalRequestMetadata{
		Endpoint: responsesEndpoint, Model: "gpt-5.6-sol", APIKeyID: "key-1",
	}, nil)
	if err != nil {
		t.Fatalf("begin request: %v", err)
	}
	if err := db.Model(&RequestRecord{}).Where("request_id = ?", request.ID).Update("expires_at", time.Now().UTC().Add(-time.Hour)).Error; err != nil {
		t.Fatalf("expire request metadata: %v", err)
	}
	before := time.Now().UTC()
	if err := journal.Forward(context.Background(), request, "response.json", []byte(`{"id":"collision-response","status":"completed","output":[]}`), func(context.Context, string) error {
		return nil
	}); err != nil {
		t.Fatalf("forward terminal response: %v", err)
	}
	var link ResponseLinkRecord
	if err := db.Where("response_id = ?", "collision-response").First(&link).Error; err != nil {
		t.Fatalf("load response link: %v", err)
	}
	if !link.ExpiresAt.After(before.Add(journal.metadataTTL / 2)) {
		t.Fatalf("response link expiry = %s, want terminal-relative expiry after %s", link.ExpiresAt, before.Add(journal.metadataTTL/2))
	}

	other, err := journal.BeginRequestWithMetadata(context.Background(), JournalRequestMetadata{
		Endpoint: responsesEndpoint, Model: "gpt-5.6-sol", APIKeyID: "key-1",
	}, nil)
	if err != nil {
		t.Fatalf("begin colliding request: %v", err)
	}
	if err := journal.Forward(context.Background(), other, "response.json", []byte(`{"id":"collision-response","status":"completed","output":[]}`), func(context.Context, string) error {
		return nil
	}); err == nil || !strings.Contains(err.Error(), "response link identity conflicts") {
		t.Fatalf("response link collision error = %v", err)
	}
	if err := journal.Replay(context.Background()); err != nil {
		t.Fatalf("replay after response link collision: %v", err)
	}
	oversizedID := strings.Repeat("x", 257)
	if err := journal.Forward(context.Background(), other, "response.json", []byte(`{"id":"`+oversizedID+`","status":"completed","output":[]}`), func(context.Context, string) error {
		return nil
	}); err == nil || !strings.Contains(err.Error(), "response link ID is too long") {
		t.Fatalf("oversized response link error = %v", err)
	}
	if err := journal.Forward(context.Background(), other, "response.json", []byte(`{"id":"collision-response-next","status":"completed","output":[]}`), func(context.Context, string) error {
		return nil
	}); err != nil {
		t.Fatalf("forward after response link collision: %v", err)
	}
	if err := journal.Replay(context.Background()); err != nil {
		t.Fatalf("replay after valid later response: %v", err)
	}
}

func TestJournalLoadConversationInputUsesTerminalOutputsAndBounds(t *testing.T) {
	journal, db := openTestJournal(t, journalModeDurable, 4)
	defer closeTestJournal(t, journal, db)

	input := []byte(`{"input":[{"type":"message","role":"user","content":[{"type":"input_text","text":"hello"}]}]}`)
	request, err := journal.BeginRequestWithMetadata(context.Background(), JournalRequestMetadata{
		Endpoint: responsesEndpoint, Model: "gpt-5.6-sol", APIKeyID: "key-1", ConversationHint: "history",
	}, input)
	if err != nil {
		t.Fatalf("begin request: %v", err)
	}
	if err := journal.Forward(context.Background(), request, "response.json", []byte(`{"id":"history-response","status":"completed","output":[{"type":"message","role":"assistant","content":[{"type":"output_text","text":"world"}]}]}`), func(context.Context, string) error {
		return nil
	}); err != nil {
		t.Fatalf("forward response: %v", err)
	}
	if err := journal.Replay(context.Background()); err != nil {
		t.Fatalf("replay conversation: %v", err)
	}
	items, err := journal.LoadConversationInput(context.Background(), request.ConversationID)
	if err != nil {
		t.Fatalf("load conversation input: %v", err)
	}
	if len(items) != 2 || !strings.Contains(string(items[0]), `"hello"`) || !strings.Contains(string(items[1]), `"world"`) {
		t.Fatalf("conversation items = %s", items)
	}
}

func TestJournalLoadConversationInputUsesOrderedStreamItems(t *testing.T) {
	journal, db := openTestJournal(t, journalModeDurable, 4)
	defer closeTestJournal(t, journal, db)

	request, err := journal.BeginRequestWithMetadata(context.Background(), JournalRequestMetadata{
		Endpoint: responsesEndpoint, Model: "gpt-5.6-sol", APIKeyID: "key-1",
	}, []byte(`{"input":[{"type":"message","role":"user","content":[{"type":"input_text","text":"stream input"}]}]}`))
	if err != nil {
		t.Fatalf("begin request: %v", err)
	}
	for _, item := range []string{
		`{"type":"message","role":"assistant","content":[{"type":"output_text","text":"first"}]}`,
		`{"type":"message","role":"assistant","content":[{"type":"output_text","text":"second"}]}`,
	} {
		payload := []byte(fmt.Sprintf(`{"type":"response.output_item.done","item":%s}`, item))
		if err := journal.Forward(context.Background(), request, "response.output_item.done", payload, func(context.Context, string) error {
			return nil
		}); err != nil {
			t.Fatalf("forward stream item: %v", err)
		}
	}
	if err := journal.RecordTerminal(context.Background(), request, requestStatusSucceeded, nil); err != nil {
		t.Fatalf("record terminal: %v", err)
	}
	if err := journal.Replay(context.Background()); err != nil {
		t.Fatalf("replay journal: %v", err)
	}
	items, err := journal.LoadConversationInput(context.Background(), request.ConversationID)
	if err != nil {
		t.Fatalf("load conversation input: %v", err)
	}
	if len(items) != 3 || !bytes.Contains(items[0], []byte("stream input")) ||
		!bytes.Contains(items[1], []byte("first")) || !bytes.Contains(items[2], []byte("second")) {
		t.Fatalf("stream conversation items = %s", items)
	}
}

func TestJournalLoadConversationInputPrefersTerminalOutputOverStreamItems(t *testing.T) {
	journal, db := openTestJournal(t, journalModeDurable, 4)
	defer closeTestJournal(t, journal, db)

	request, err := journal.BeginRequestWithMetadata(context.Background(), JournalRequestMetadata{
		Endpoint: responsesEndpoint, Model: "gpt-5.6-sol", APIKeyID: "key-1",
	}, []byte(`{"input":[{"type":"message","role":"user","content":[{"type":"input_text","text":"json input"}]}]}`))
	if err != nil {
		t.Fatalf("begin request: %v", err)
	}
	donePayload := []byte(`{"type":"response.output_item.done","item":{"type":"message","role":"assistant","content":[{"type":"output_text","text":"stream duplicate"}]}}`)
	if err := journal.Forward(context.Background(), request, "response.output_item.done", donePayload, func(context.Context, string) error {
		return nil
	}); err != nil {
		t.Fatalf("forward stream item: %v", err)
	}
	terminalPayload := []byte(`{"id":"json-response","object":"response","status":"completed","output":[{"type":"message","role":"assistant","content":[{"type":"output_text","text":"json output"}]}]}`)
	if err := journal.Forward(context.Background(), request, "response.json", terminalPayload, func(context.Context, string) error {
		return nil
	}); err != nil {
		t.Fatalf("forward terminal response: %v", err)
	}
	if err := journal.RecordTerminal(context.Background(), request, requestStatusSucceeded, nil); err != nil {
		t.Fatalf("record terminal: %v", err)
	}
	if err := journal.Replay(context.Background()); err != nil {
		t.Fatalf("replay journal: %v", err)
	}
	items, err := journal.LoadConversationInput(context.Background(), request.ConversationID)
	if err != nil {
		t.Fatalf("load conversation input: %v", err)
	}
	if len(items) != 2 || !bytes.Contains(items[0], []byte("json input")) ||
		!bytes.Contains(items[1], []byte("json output")) || bytes.Contains(items[1], []byte("stream duplicate")) {
		t.Fatalf("terminal conversation items = %s", items)
	}
}

func TestJournalLoadConversationInputIgnoresStaleSucceededProjection(t *testing.T) {
	journal, db := openTestJournal(t, journalModeDurable, 4)
	defer closeTestJournal(t, journal, db)

	request, err := journal.BeginRequestWithMetadata(context.Background(), JournalRequestMetadata{
		Endpoint: responsesEndpoint, Model: "gpt-5.6-sol", APIKeyID: "key-1",
	}, []byte(`{"input":[{"type":"message","role":"user","content":[{"type":"input_text","text":"stale input"}]}]}`))
	if err != nil {
		t.Fatalf("begin request: %v", err)
	}
	donePayload := []byte(`{"type":"response.output_item.done","item":{"type":"message","role":"assistant","content":[{"type":"output_text","text":"stale output"}]}}`)
	if err := journal.Forward(context.Background(), request, "response.output_item.done", donePayload, func(context.Context, string) error {
		return nil
	}); err != nil {
		t.Fatalf("forward stream item: %v", err)
	}
	if err := journal.Replay(context.Background()); err != nil {
		t.Fatalf("replay journal: %v", err)
	}
	if err := db.Model(&RequestRecord{}).Where("request_id = ?", request.ID).Updates(map[string]any{
		"status": requestStatusSucceeded, "terminal_at": time.Now().UTC(),
	}).Error; err != nil {
		t.Fatalf("set stale succeeded projection: %v", err)
	}
	items, err := journal.LoadConversationInput(context.Background(), request.ConversationID)
	if err != nil {
		t.Fatalf("load conversation input: %v", err)
	}
	if len(items) != 1 || !bytes.Contains(items[0], []byte("stale input")) {
		t.Fatalf("stale projection history = %s", items)
	}
}

func TestJournalLoadConversationInputStopsAtPreviousResponseRequest(t *testing.T) {
	journal, db := openTestJournal(t, journalModeDurable, 8)
	defer closeTestJournal(t, journal, db)

	begin := func(metadata JournalRequestMetadata, input, responseID, output string) JournalRequest {
		t.Helper()
		request, err := journal.BeginRequestWithMetadata(context.Background(), metadata, []byte(fmt.Sprintf(`{"input":[{"type":"message","role":"user","content":[{"type":"input_text","text":"%s"}]}]}`, input)))
		if err != nil {
			t.Fatalf("begin request %s: %v", input, err)
		}
		payload := []byte(fmt.Sprintf(`{"id":"%s","object":"response","status":"completed","output":[{"type":"message","role":"assistant","content":[{"type":"output_text","text":"%s"}]}]}`, responseID, output))
		if err := journal.Forward(context.Background(), request, "response.json", payload, func(context.Context, string) error {
			return nil
		}); err != nil {
			t.Fatalf("forward response %s: %v", responseID, err)
		}
		if err := journal.RecordTerminal(context.Background(), request, requestStatusSucceeded, nil); err != nil {
			t.Fatalf("record terminal %s: %v", responseID, err)
		}
		if err := journal.Replay(context.Background()); err != nil {
			t.Fatalf("replay response %s: %v", responseID, err)
		}
		return request
	}
	first := begin(JournalRequestMetadata{Endpoint: responsesEndpoint, Model: "gpt-5.6-sol", APIKeyID: "key-1"}, "first", "branch-first", "first-output")
	second := begin(JournalRequestMetadata{Endpoint: responsesEndpoint, Model: "gpt-5.6-sol", APIKeyID: "key-1", ConversationID: first.ConversationID}, "second", "branch-second", "second-output")
	_ = begin(JournalRequestMetadata{Endpoint: responsesEndpoint, Model: "gpt-5.6-sol", APIKeyID: "key-1", ConversationID: first.ConversationID}, "later", "branch-later", "later-output")

	items, err := journal.LoadConversationInputThrough(context.Background(), first.ConversationID, second.ID)
	if err != nil {
		t.Fatalf("load branch history: %v", err)
	}
	var history strings.Builder
	for _, item := range items {
		history.Write(item)
		history.WriteByte('\n')
	}
	historyText := history.String()
	if !strings.Contains(historyText, "first") || !strings.Contains(historyText, "second") ||
		strings.Contains(historyText, "later") || strings.Contains(historyText, "later-output") {
		t.Fatalf("branch history = %s", historyText)
	}
}

func TestJournalLoadConversationInputCutoffIgnoresLaterRequestBounds(t *testing.T) {
	journal, db := openTestJournal(t, journalModeDurable, 4)
	defer closeTestJournal(t, journal, db)

	first, err := journal.BeginRequestWithMetadata(context.Background(), JournalRequestMetadata{
		Endpoint: responsesEndpoint, Model: "gpt-5.6-sol", APIKeyID: "key-1",
	}, []byte(`{"input":[{"type":"message","role":"user","content":[{"type":"input_text","text":"branch root"}]}]}`))
	if err != nil {
		t.Fatalf("begin branch root: %v", err)
	}
	if err := journal.Replay(context.Background()); err != nil {
		t.Fatalf("materialize branch root: %v", err)
	}
	var root RequestRecord
	if err := db.Where("request_id = ?", first.ID).First(&root).Error; err != nil {
		t.Fatalf("load branch root: %v", err)
	}
	for index := 0; index <= maxConversationInputItems; index++ {
		requestID, err := newJournalUUID()
		if err != nil {
			t.Fatalf("generate later request ID: %v", err)
		}
		replayID, err := newJournalUUID()
		if err != nil {
			t.Fatalf("generate later replay ID: %v", err)
		}
		acceptedAt := root.AcceptedAt.Add(time.Duration(index+1) * time.Second)
		if err := db.Create(&JournalRequestRecord{
			RequestID: requestID, Mode: journalModeDurable, NextSequence: 1,
			ConversationID: first.ConversationID, Endpoint: responsesEndpoint,
			Model: "gpt-5.6-sol", APIKeyID: "key-1", CreatedAt: acceptedAt,
		}).Error; err != nil {
			t.Fatalf("create later journal request %d: %v", index, err)
		}
		if err := db.Create(&RequestRecord{
			ID: requestID, ReplayID: replayID, ConversationID: first.ConversationID,
			APIKeyID: "key-1", Endpoint: responsesEndpoint, Model: "gpt-5.6-sol",
			RequestedModel: "gpt-5.6-sol", Mode: journalModeDurable, Status: requestStatusSucceeded,
			CreatedAt: acceptedAt, AcceptedAt: acceptedAt, StartedAt: acceptedAt,
			UpdatedAt: acceptedAt, TerminalAt: &acceptedAt, ExpiresAt: acceptedAt.Add(time.Hour),
		}).Error; err != nil {
			t.Fatalf("create later request %d: %v", index, err)
		}
	}
	items, err := journal.LoadConversationInputThrough(context.Background(), first.ConversationID, first.ID)
	if err != nil {
		t.Fatalf("load early branch history: %v", err)
	}
	if len(items) != 1 || !bytes.Contains(items[0], []byte("branch root")) {
		t.Fatalf("early branch history = %s", items)
	}
}

func TestJournalLoadConversationInputCapsJournalRows(t *testing.T) {
	journal, db := openTestJournal(t, journalModeDurable, 4)
	defer closeTestJournal(t, journal, db)

	request, err := journal.BeginRequestWithMetadata(context.Background(), JournalRequestMetadata{
		Endpoint: responsesEndpoint, Model: "gpt-5.6-sol", APIKeyID: "key-1",
	}, nil)
	if err != nil {
		t.Fatalf("begin request: %v", err)
	}
	if err := journal.Close(context.Background()); err != nil {
		t.Fatalf("stop journal worker: %v", err)
	}
	for index := 0; index <= maxConversationJournalEvents; index++ {
		replayID, err := newJournalUUID()
		if err != nil {
			t.Fatalf("generate journal replay ID: %v", err)
		}
		record, err := journal.newEncryptedRecord(replayID, request.ID, uint64(index+100), journalModeDurable, "response.json", []byte(`{"status":"in_progress"}`), true)
		if err != nil {
			t.Fatalf("encrypt journal event %d: %v", index, err)
		}
		if err := db.Create(&record).Error; err != nil {
			t.Fatalf("store journal event %d: %v", index, err)
		}
	}
	if err := journal.Replay(context.Background()); err != nil {
		t.Fatalf("materialize bounded journal rows: %v", err)
	}
	if _, err := journal.LoadConversationInput(context.Background(), request.ConversationID); err == nil || !strings.Contains(err.Error(), "conversation journal bounds exceeded") {
		t.Fatalf("conversation journal bounds error = %v", err)
	}
}

func TestJournalBindAccountCapsInMemoryConversationStates(t *testing.T) {
	journal, db := openTestJournal(t, journalModeDurable, 4)
	defer closeTestJournal(t, journal, db)

	target, err := journal.BeginRequestWithMetadata(context.Background(), JournalRequestMetadata{
		Endpoint: responsesEndpoint, Model: "gpt-5.6-sol", APIKeyID: "key-1",
	}, nil)
	if err != nil {
		t.Fatalf("begin target request: %v", err)
	}
	journal.requestsMu.Lock()
	for index := range maxConversationInputItems {
		id := fmt.Sprintf("synthetic-request-%04d", index)
		journal.requests[id] = &journalRequestState{
			request: JournalRequest{ID: id, Mode: journalModeDurable, ConversationID: target.ConversationID},
		}
	}
	journal.requestsMu.Unlock()
	if err := journal.BindAccount(context.Background(), target.ID, "account-1", ""); err == nil ||
		!strings.Contains(err.Error(), "journal conversation request limit exceeded") {
		t.Fatalf("in-memory conversation state limit error = %v", err)
	}
}

func TestJournalLoadConversationInputRejectsTamperedRecord(t *testing.T) {
	journal, db := openTestJournal(t, journalModeDurable, 4)
	defer closeTestJournal(t, journal, db)

	request, err := journal.BeginRequestWithMetadata(context.Background(), JournalRequestMetadata{
		Endpoint: responsesEndpoint, Model: "gpt-5.6-sol", APIKeyID: "key-1",
	}, nil)
	if err != nil {
		t.Fatalf("begin request: %v", err)
	}
	if err := journal.Forward(context.Background(), request, "response.json", []byte(`{"id":"tampered-response","status":"completed","output":[]}`), func(context.Context, string) error {
		return nil
	}); err != nil {
		t.Fatalf("forward response: %v", err)
	}
	if err := journal.Close(context.Background()); err != nil {
		t.Fatalf("stop journal worker: %v", err)
	}
	if err := db.Model(&JournalRecord{}).Where("request_id = ? AND event_type = ?", request.ID, "response.json").Update("sequence", 999999).Error; err != nil {
		t.Fatalf("tamper journal sequence: %v", err)
	}
	if _, err := journal.LoadConversationInput(context.Background(), request.ConversationID); err == nil || !strings.Contains(err.Error(), "validate conversation journal event") {
		t.Fatalf("tampered journal validation error = %v", err)
	}
}

func TestJournalBindAccountBindsConversationAndSessionAffinity(t *testing.T) {
	journal, db := openTestJournal(t, journalModeDurable, 4)
	defer closeTestJournal(t, journal, db)

	sessionDigest := sha256.Sum256([]byte("session-1"))
	sessionHash := hex.EncodeToString(sessionDigest[:])
	request, err := journal.BeginRequestWithMetadata(context.Background(), JournalRequestMetadata{
		Endpoint: responsesEndpoint, Model: "gpt-5.6-sol", APIKeyID: "key-1",
	}, nil)
	if err != nil {
		t.Fatalf("begin request: %v", err)
	}
	if err := journal.Forward(context.Background(), request, "response.json", []byte(`{"id":"unbound-response","status":"completed","output":[]}`), func(context.Context, string) error {
		return nil
	}); err != nil {
		t.Fatalf("forward unbound response: %v", err)
	}
	sibling, err := journal.BeginRequestWithMetadata(context.Background(), JournalRequestMetadata{
		Endpoint: responsesEndpoint, Model: "gpt-5.6-sol", APIKeyID: "key-1", ConversationID: request.ConversationID,
	}, nil)
	if err != nil {
		t.Fatalf("begin sibling request: %v", err)
	}
	if err := journal.Forward(context.Background(), sibling, "response.json", []byte(`{"id":"sibling-response","status":"completed","output":[]}`), func(context.Context, string) error {
		return nil
	}); err != nil {
		t.Fatalf("forward sibling response: %v", err)
	}
	if err := journal.BindAccount(context.Background(), request.ID, "account-1", sessionHash); err != nil {
		t.Fatalf("bind account: %v", err)
	}
	if err := journal.Forward(context.Background(), request, "response.output_text.delta", []byte(`{"type":"response.output_text.delta","delta":"after"}`), func(context.Context, string) error {
		return nil
	}); err != nil {
		t.Fatalf("forward bound response: %v", err)
	}
	resolved, err := journal.ResolvePreviousResponse(context.Background(), "unbound-response", "key-1")
	if err != nil {
		t.Fatalf("resolve bound response link: %v", err)
	}
	if resolved.AccountID != "account-1" {
		t.Fatalf("resolved response account = %q", resolved.AccountID)
	}
	siblingResolved, err := journal.ResolvePreviousResponse(context.Background(), "sibling-response", "key-1")
	if err != nil {
		t.Fatalf("resolve sibling response link: %v", err)
	}
	if siblingResolved.AccountID != "account-1" {
		t.Fatalf("resolved sibling response account = %q", siblingResolved.AccountID)
	}
	var siblingJournal JournalRequestRecord
	if err := db.Where("request_id = ?", sibling.ID).First(&siblingJournal).Error; err != nil {
		t.Fatalf("load bound sibling journal request: %v", err)
	}
	if siblingJournal.AccountID != "account-1" {
		t.Fatalf("sibling journal account = %q", siblingJournal.AccountID)
	}
	if err := journal.Replay(context.Background()); err != nil {
		t.Fatalf("replay conversation account binding: %v", err)
	}
	var siblingLifecycle RequestRecord
	if err := db.Where("request_id = ?", sibling.ID).First(&siblingLifecycle).Error; err != nil {
		t.Fatalf("load replayed sibling request: %v", err)
	}
	if siblingLifecycle.AccountID != "account-1" {
		t.Fatalf("replayed sibling account = %q", siblingLifecycle.AccountID)
	}
	var lifecycle RequestRecord
	if err := db.Where("request_id = ?", request.ID).First(&lifecycle).Error; err != nil {
		t.Fatalf("load bound lifecycle request: %v", err)
	}
	if lifecycle.AccountID != "account-1" {
		t.Fatalf("lifecycle account = %q", lifecycle.AccountID)
	}
	var conversation ConversationRecord
	if err := db.Where("id = ?", request.ConversationID).First(&conversation).Error; err != nil {
		t.Fatalf("load bound conversation: %v", err)
	}
	if conversation.AccountID != "account-1" {
		t.Fatalf("conversation account = %q", conversation.AccountID)
	}
	var affinity SessionAffinityRecord
	if err := db.Where("api_key_id = ? AND session_hash = ?", "key-1", sessionHash).First(&affinity).Error; err != nil {
		t.Fatalf("load session affinity: %v", err)
	}
	if affinity.AccountID != "account-1" || affinity.ExpiresAt.IsZero() {
		t.Fatalf("session affinity = %+v", affinity)
	}
	var bound JournalRecord
	if err := db.Where("request_id = ? AND event_type = ?", request.ID, "lifecycle.account_bound").First(&bound).Error; err != nil {
		t.Fatalf("load account bound event: %v", err)
	}
	if bound.EventVersion != lifecycleEventVersion {
		t.Fatalf("account bound event version = %d, want %d", bound.EventVersion, lifecycleEventVersion)
	}
	if err := journal.BindAccount(context.Background(), request.ID, "account-2", ""); err == nil {
		t.Fatal("conflicting account binding succeeded")
	}

	other, err := journal.BeginRequestWithMetadata(context.Background(), JournalRequestMetadata{
		Endpoint: responsesEndpoint, Model: "gpt-5.6-sol", APIKeyID: "key-1",
	}, nil)
	if err != nil {
		t.Fatalf("begin competing request: %v", err)
	}
	if err := journal.BindAccount(context.Background(), other.ID, "account-2", sessionHash); err == nil {
		t.Fatal("conflicting session affinity binding succeeded")
	}
}

func TestJournalBindAccountRepairsPartialProjectionWhenAlreadyBound(t *testing.T) {
	journal, db := openTestJournal(t, journalModeDurable, 4)
	defer closeTestJournal(t, journal, db)

	first, err := journal.BeginRequestWithMetadata(context.Background(), JournalRequestMetadata{
		Endpoint: responsesEndpoint, Model: "gpt-5.6-sol", APIKeyID: "key-1", AccountID: "account-1",
	}, nil)
	if err != nil {
		t.Fatalf("begin account-bound request: %v", err)
	}
	sibling, err := journal.BeginRequestWithMetadata(context.Background(), JournalRequestMetadata{
		Endpoint: responsesEndpoint, Model: "gpt-5.6-sol", APIKeyID: "key-1", ConversationID: first.ConversationID,
	}, nil)
	if err != nil {
		t.Fatalf("begin partial sibling request: %v", err)
	}
	if err := journal.Forward(context.Background(), sibling, "response.json", []byte(`{"id":"partial-response","status":"completed","output":[]}`), func(context.Context, string) error {
		return nil
	}); err != nil {
		t.Fatalf("forward partial sibling response: %v", err)
	}
	if err := journal.BindAccount(context.Background(), first.ID, "account-1", ""); err != nil {
		t.Fatalf("repair account-bound projections: %v", err)
	}
	var siblingJournal JournalRequestRecord
	if err := db.Where("request_id = ?", sibling.ID).First(&siblingJournal).Error; err != nil {
		t.Fatalf("load repaired sibling journal request: %v", err)
	}
	if siblingJournal.AccountID != "account-1" {
		t.Fatalf("repaired sibling journal account = %q", siblingJournal.AccountID)
	}
	var link ResponseLinkRecord
	if err := db.Where("response_id = ?", "partial-response").First(&link).Error; err != nil {
		t.Fatalf("load repaired sibling response link: %v", err)
	}
	if link.AccountID != "account-1" {
		t.Fatalf("repaired sibling response account = %q", link.AccountID)
	}
	resolved, err := journal.ResolvePreviousResponse(context.Background(), "partial-response", "key-1")
	if err != nil {
		t.Fatalf("resolve repaired sibling response: %v", err)
	}
	if resolved.AccountID != "account-1" {
		t.Fatalf("resolved repaired sibling account = %q", resolved.AccountID)
	}
}

func TestJournalBindAccountRebindsExpiredSessionAffinity(t *testing.T) {
	journal, db := openTestJournal(t, journalModeDurable, 4)
	defer closeTestJournal(t, journal, db)

	sessionDigest := sha256.Sum256([]byte("expired-session"))
	sessionHash := hex.EncodeToString(sessionDigest[:])
	first, err := journal.BeginRequestWithMetadata(context.Background(), JournalRequestMetadata{
		Endpoint: responsesEndpoint, Model: "gpt-5.6-sol", APIKeyID: "key-1",
	}, nil)
	if err != nil {
		t.Fatalf("begin first request: %v", err)
	}
	if err := journal.BindAccount(context.Background(), first.ID, "account-1", sessionHash); err != nil {
		t.Fatalf("bind first account: %v", err)
	}
	if err := journal.Replay(context.Background()); err != nil {
		t.Fatalf("replay first account binding: %v", err)
	}
	if err := db.Model(&SessionAffinityRecord{}).Where("api_key_id = ? AND session_hash = ?", "key-1", sessionHash).
		Update("expires_at", time.Now().UTC().Add(-time.Minute)).Error; err != nil {
		t.Fatalf("expire session affinity: %v", err)
	}
	second, err := journal.BeginRequestWithMetadata(context.Background(), JournalRequestMetadata{
		Endpoint: responsesEndpoint, Model: "gpt-5.6-sol", APIKeyID: "key-1",
	}, nil)
	if err != nil {
		t.Fatalf("begin second request: %v", err)
	}
	if err := journal.BindAccount(context.Background(), second.ID, "account-2", sessionHash); err != nil {
		t.Fatalf("rebind expired session affinity: %v", err)
	}
	var affinity SessionAffinityRecord
	if err := db.Where("api_key_id = ? AND session_hash = ?", "key-1", sessionHash).First(&affinity).Error; err != nil {
		t.Fatalf("load rebound session affinity: %v", err)
	}
	if affinity.AccountID != "account-2" || !affinity.ExpiresAt.After(time.Now().UTC()) {
		t.Fatalf("rebound session affinity = %+v", affinity)
	}
}

func TestJournalBeginRegistrationSynchronizedWithBind(t *testing.T) {
	journal, db := openTestJournal(t, journalModeDurable, 4)
	defer closeTestJournal(t, journal, db)

	target, err := journal.BeginRequestWithMetadata(context.Background(), JournalRequestMetadata{
		Endpoint: responsesEndpoint, Model: "gpt-5.6-sol", APIKeyID: "key-1",
	}, nil)
	if err != nil {
		t.Fatalf("begin target request: %v", err)
	}
	journal.requestsMu.Lock()
	beginStarted := make(chan struct{})
	beginResult := make(chan struct {
		request JournalRequest
		err     error
	}, 1)
	go func() {
		close(beginStarted)
		request, beginErr := journal.BeginRequestWithMetadata(context.Background(), JournalRequestMetadata{
			Endpoint: responsesEndpoint, Model: "gpt-5.6-sol", APIKeyID: "key-1", ConversationID: target.ConversationID,
		}, nil)
		beginResult <- struct {
			request JournalRequest
			err     error
		}{request, beginErr}
	}()
	<-beginStarted
	deadline := time.Now().Add(200 * time.Millisecond)
	for time.Now().Before(deadline) {
		var count int64
		if err := db.Model(&JournalRequestRecord{}).Where("conversation_id = ?", target.ConversationID).Count(&count).Error; err != nil {
			journal.requestsMu.Unlock()
			t.Fatalf("count concurrent begin rows: %v", err)
		}
		if count != 1 {
			journal.requestsMu.Unlock()
			t.Fatalf("begin registered a row while binding lock held: count=%d", count)
		}
		time.Sleep(time.Millisecond)
	}
	journal.requestsMu.Unlock()
	var sibling JournalRequest
	select {
	case result := <-beginResult:
		if result.err != nil {
			t.Fatalf("begin synchronized sibling request: %v", result.err)
		}
		sibling = result.request
	case <-time.After(time.Second):
		t.Fatal("synchronized sibling begin timed out")
	}
	if err := journal.BindAccount(context.Background(), target.ID, "account-1", ""); err != nil {
		t.Fatalf("bind synchronized conversation: %v", err)
	}
	var siblingRow JournalRequestRecord
	if err := db.Where("request_id = ?", sibling.ID).First(&siblingRow).Error; err != nil {
		t.Fatalf("load synchronized sibling row: %v", err)
	}
	if siblingRow.AccountID != "account-1" {
		t.Fatalf("synchronized sibling account = %q", siblingRow.AccountID)
	}
}
func TestJournalBindAccountConcurrentSameConversation(t *testing.T) {
	journal, db := openTestJournal(t, journalModeDurable, 4)
	defer closeTestJournal(t, journal, db)

	first, err := journal.BeginRequestWithMetadata(context.Background(), JournalRequestMetadata{
		Endpoint: responsesEndpoint, Model: "gpt-5.6-sol", APIKeyID: "key-1",
	}, nil)
	if err != nil {
		t.Fatalf("begin first request: %v", err)
	}
	second, err := journal.BeginRequestWithMetadata(context.Background(), JournalRequestMetadata{
		Endpoint: responsesEndpoint, Model: "gpt-5.6-sol", APIKeyID: "key-1", ConversationID: first.ConversationID,
	}, nil)
	if err != nil {
		t.Fatalf("begin second request: %v", err)
	}
	hashFor := func(value string) string {
		digest := sha256.Sum256([]byte(value))
		return hex.EncodeToString(digest[:])
	}
	start := make(chan struct{})
	errs := make(chan error, 2)
	go func() {
		<-start
		errs <- journal.BindAccount(context.Background(), first.ID, "account-1", hashFor("first"))
	}()
	go func() {
		<-start
		errs <- journal.BindAccount(context.Background(), second.ID, "account-1", hashFor("second"))
	}()
	close(start)
	timeout := time.NewTimer(5 * time.Second)
	defer timeout.Stop()
	for range 2 {
		select {
		case err := <-errs:
			if err != nil {
				t.Fatalf("concurrent account bind: %v", err)
			}
		case <-timeout.C:
			t.Fatal("concurrent account bind timed out")
		}
	}
}

func TestJournalBindAccountHandlesLegacyNullAccounts(t *testing.T) {
	journal, db := openTestJournal(t, journalModeDurable, 4)
	defer closeTestJournal(t, journal, db)

	request, err := journal.BeginRequestWithMetadata(context.Background(), JournalRequestMetadata{
		Endpoint: responsesEndpoint, Model: "gpt-5.6-sol", APIKeyID: "key-1",
	}, nil)
	if err != nil {
		t.Fatalf("begin request: %v", err)
	}
	if err := journal.Forward(context.Background(), request, "response.json", []byte(`{"id":"legacy-null-response","status":"completed","output":[]}`), func(context.Context, string) error {
		return nil
	}); err != nil {
		t.Fatalf("forward response: %v", err)
	}
	if err := journal.Replay(context.Background()); err != nil {
		t.Fatalf("materialize response: %v", err)
	}
	for _, table := range []string{"journal_requests", "requests", "response_links"} {
		if err := db.Exec("UPDATE "+table+" SET account_id = NULL WHERE "+map[string]string{
			"journal_requests": "request_id = ?",
			"requests":         "request_id = ?",
			"response_links":   "response_id = ?",
		}[table], map[string]string{
			"journal_requests": request.ID,
			"requests":         request.ID,
			"response_links":   "legacy-null-response",
		}[table]).Error; err != nil {
			t.Fatalf("clear legacy %s account: %v", table, err)
		}
	}
	if err := db.Exec("UPDATE conversations SET account_id = NULL WHERE id = ?", request.ConversationID).Error; err != nil {
		t.Fatalf("clear legacy conversation account: %v", err)
	}
	if err := journal.BindAccount(context.Background(), request.ID, "account-legacy", ""); err != nil {
		t.Fatalf("bind legacy null account: %v", err)
	}
	var link ResponseLinkRecord
	if err := db.Where("response_id = ?", "legacy-null-response").First(&link).Error; err != nil {
		t.Fatalf("load legacy response link: %v", err)
	}
	if link.AccountID != "account-legacy" {
		t.Fatalf("legacy response link account = %q", link.AccountID)
	}
	if _, err := journal.ResolvePreviousResponse(context.Background(), "legacy-null-response", "key-1"); err != nil {
		t.Fatalf("resolve legacy response link: %v", err)
	}
}

func TestJournalReplayAcceptsUnmaterializedV1AcceptedRecord(t *testing.T) {
	journal, db := openTestJournal(t, journalModeDurable, 4)
	defer closeTestJournal(t, journal, db)

	request, err := journal.BeginRequestWithMetadata(context.Background(), JournalRequestMetadata{
		Endpoint: responsesEndpoint, Model: "gpt-5.6-sol", APIKeyID: "key-1",
	}, nil)
	if err != nil {
		t.Fatalf("begin request: %v", err)
	}
	var accepted JournalRecord
	if err := db.Where("request_id = ? AND event_type = ?", request.ID, journalRequestEventType).First(&accepted).Error; err != nil {
		t.Fatalf("load accepted record: %v", err)
	}
	payload, err := json.Marshal(map[string]any{
		"version": 1, "request_id": request.ID, "conversation_id": request.ConversationID,
		"endpoint": request.Endpoint, "model": request.Model, "api_key_id": request.APIKeyID, "mode": request.Mode,
	})
	if err != nil {
		t.Fatalf("encode v1 accepted payload: %v", err)
	}
	encrypted, err := envelope.Encrypt(payload, envelope.PayloadDomain, journal.keys)
	if err != nil {
		t.Fatalf("encrypt v1 accepted payload: %v", err)
	}
	accepted.EventVersion = 1
	accepted.Payload = encrypted
	accepted.Checksum = journalChecksum(accepted)
	if err := db.Model(&JournalRecord{}).Where("replay_id = ?", accepted.ReplayID).Updates(map[string]any{
		"event_version": accepted.EventVersion, "payload": accepted.Payload, "checksum": accepted.Checksum,
	}).Error; err != nil {
		t.Fatalf("replace accepted record: %v", err)
	}
	if err := journal.Replay(context.Background()); err != nil {
		t.Fatalf("replay v1 accepted record: %v", err)
	}
	var lifecycle RequestRecord
	if err := db.Where("request_id = ?", request.ID).First(&lifecycle).Error; err != nil {
		t.Fatalf("load replayed lifecycle request: %v", err)
	}
	if lifecycle.AccountID != "" {
		t.Fatalf("v1 lifecycle account = %q, want empty", lifecycle.AccountID)
	}
}

func TestSchemaMigratesLegacyAccountsAndContinuationTables(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "schema.sqlite3")
	db, err := storage.Open(context.Background(), databasePath, time.Second)
	if err != nil {
		t.Fatalf("open database: %v", err)
	}
	defer func() {
		sqlDB, closeErr := db.DB()
		if closeErr == nil {
			_ = sqlDB.Close()
		}
	}()
	if err := db.Exec(`CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, name TEXT NOT NULL)`).Error; err != nil {
		t.Fatalf("create schema migrations: %v", err)
	}
	if err := db.Exec(`INSERT INTO schema_migrations(version, name) VALUES (1, 'initial')`).Error; err != nil {
		t.Fatalf("insert schema version: %v", err)
	}
	if err := db.Exec(`
		CREATE TABLE accounts (
			id TEXT PRIMARY KEY NOT NULL,
			provider TEXT NOT NULL,
			account_id TEXT NOT NULL,
			created_at DATETIME NOT NULL,
			updated_at DATETIME NOT NULL,
			expires_at DATETIME NOT NULL
		)`).Error; err != nil {
		t.Fatalf("create legacy accounts: %v", err)
	}
	now := time.Now().UTC()
	if err := db.Exec(`INSERT INTO accounts(id, provider, account_id, created_at, updated_at, expires_at) VALUES (?, ?, ?, ?, ?, ?)`, "profile-1", "codex", "provider-1", now, now, now.Add(time.Hour)).Error; err != nil {
		t.Fatalf("insert legacy account: %v", err)
	}
	for _, legacy := range []struct {
		id        string
		accountID string
		createdAt time.Time
	}{
		{id: "profile-later", accountID: "provider-duplicate", createdAt: now.Add(time.Hour)},
		{id: "profile-earlier", accountID: "provider-duplicate", createdAt: now.Add(-time.Hour)},
		{id: "profile-tie-z", accountID: "provider-tie", createdAt: now},
		{id: "profile-tie-a", accountID: "provider-tie", createdAt: now},
	} {
		if err := db.Exec(`INSERT INTO accounts(id, provider, account_id, created_at, updated_at, expires_at) VALUES (?, ?, ?, ?, ?, ?)`,
			legacy.id, "codex", legacy.accountID, legacy.createdAt, legacy.createdAt, now.Add(time.Hour)).Error; err != nil {
			t.Fatalf("insert duplicate legacy account %q: %v", legacy.id, err)
		}
	}
	if err := MigrateSchema(db); err != nil {
		t.Fatalf("migrate schema: %v", err)
	}
	var beforeSecondMigration []struct {
		ID                string `gorm:"column:id"`
		ProviderAccountID string `gorm:"column:provider_account_id"`
	}
	if err := db.Model(&AccountRecord{}).Select("id, provider_account_id").Order("id ASC").Scan(&beforeSecondMigration).Error; err != nil {
		t.Fatalf("snapshot migrated account identities: %v", err)
	}
	if err := MigrateSchema(db); err != nil {
		t.Fatalf("repeat schema migration: %v", err)
	}
	var afterSecondMigration []struct {
		ID                string `gorm:"column:id"`
		ProviderAccountID string `gorm:"column:provider_account_id"`
	}
	if err := db.Model(&AccountRecord{}).Select("id, provider_account_id").Order("id ASC").Scan(&afterSecondMigration).Error; err != nil {
		t.Fatalf("load repeated migrated account identities: %v", err)
	}
	if !reflect.DeepEqual(afterSecondMigration, beforeSecondMigration) {
		t.Fatalf("repeated schema migration changed account identities: before=%v after=%v", beforeSecondMigration, afterSecondMigration)
	}
	var duplicateAccounts []struct {
		ID                string `gorm:"column:id"`
		ProviderAccountID string `gorm:"column:provider_account_id"`
	}
	if err := db.Model(&AccountRecord{}).Select("id, provider_account_id").Where("provider_account_id IN ?", []string{"provider-duplicate", "provider-tie"}).Order("provider_account_id ASC").Find(&duplicateAccounts).Error; err != nil {
		t.Fatalf("load deduplicated account identities: %v", err)
	}
	wantDuplicateAccounts := []struct {
		ID                string `gorm:"column:id"`
		ProviderAccountID string `gorm:"column:provider_account_id"`
	}{
		{ID: "profile-earlier", ProviderAccountID: "provider-duplicate"},
		{ID: "profile-tie-a", ProviderAccountID: "provider-tie"},
	}
	if !reflect.DeepEqual(duplicateAccounts, wantDuplicateAccounts) {
		t.Fatalf("deduplicated account identities = %v, want %v", duplicateAccounts, wantDuplicateAccounts)
	}
	var account AccountRecord
	if err := db.Where("id = ?", "profile-1").First(&account).Error; err != nil {
		t.Fatalf("load migrated account: %v", err)
	}
	if account.Provider != "codex" || account.ProviderAccountID != "provider-1" || account.CredentialPath != "" || account.Enabled {
		t.Fatalf("migrated account = %+v", account)
	}
	var accountColumns []struct {
		Name string `gorm:"column:name"`
	}
	if err := db.Raw("PRAGMA table_info(accounts)").Scan(&accountColumns).Error; err != nil {
		t.Fatalf("inspect migrated accounts: %v", err)
	}
	for _, column := range accountColumns {
		if column.Name == "account_id" || column.Name == "expires_at" {
			t.Fatalf("legacy account column %q remains", column.Name)
		}
	}
	if !db.Migrator().HasTable(&ResponseLinkRecord{}) || !db.Migrator().HasTable(&SessionAffinityRecord{}) {
		t.Fatal("continuation tables were not migrated")
	}
	var migration schemaMigration
	if err := db.Order("version DESC").First(&migration).Error; err != nil {
		t.Fatalf("load schema migration: %v", err)
	}
	if migration.Version != currentSchemaVersion || migration.Name != "accounts_and_continuations" {
		t.Fatalf("schema migration = %+v", migration)
	}
}

func TestRetentionSweepsExpiredSessionAffinities(t *testing.T) {
	journal, db := openTestJournal(t, journalModeDurable, 4)
	defer closeTestJournal(t, journal, db)
	now := time.Now().UTC()
	affinity := SessionAffinityRecord{
		APIKeyID: "key-1", SessionHash: strings.Repeat("a", sha256.Size*2), AccountID: "account-1",
		CreatedAt: now.Add(-time.Hour), UpdatedAt: now.Add(-time.Hour), ExpiresAt: now.Add(-time.Minute),
	}
	if err := db.Create(&affinity).Error; err != nil {
		t.Fatalf("create expired session affinity: %v", err)
	}
	runner, err := NewRetentionRunner(db, nil, RetentionConfig{PayloadTTL: time.Hour, MetadataTTL: time.Hour, SweepInterval: time.Hour, BatchSize: 8, DrainDeadline: time.Second})
	if err != nil {
		t.Fatalf("new retention runner: %v", err)
	}
	if err := runner.RunOnce(context.Background(), now); err != nil {
		t.Fatalf("run retention sweep: %v", err)
	}
	var count int64
	if err := db.Model(&SessionAffinityRecord{}).Where("api_key_id = ? AND session_hash = ?", affinity.APIKeyID, affinity.SessionHash).Count(&count).Error; err != nil {
		t.Fatalf("count expired session affinity: %v", err)
	}
	if count != 0 {
		t.Fatalf("expired session affinity count = %d, want 0", count)
	}
}
func TestJournalLoadConversationInputUsesResponsesTerminalEvents(t *testing.T) {
	journal, db := openTestJournal(t, journalModeDurable, 4)
	defer closeTestJournal(t, journal, db)

	request, err := journal.BeginRequestWithMetadata(context.Background(), JournalRequestMetadata{
		Endpoint: responsesEndpoint, Model: "gpt-5.6-sol", APIKeyID: "key-1",
	}, []byte(`{"input":[{"type":"message","role":"user","content":[{"type":"input_text","text":"hello"}]}]}`))
	if err != nil {
		t.Fatalf("begin request: %v", err)
	}
	payload := []byte("data: {\"type\":\"response.completed\",\"response\":{\"id\":\"response-stream\",\"status\":\"completed\",\"output\":[{\"type\":\"message\",\"role\":\"assistant\",\"content\":[{\"type\":\"output_text\",\"text\":\"world\"}]}]}}\n\n")
	if err := journal.Forward(context.Background(), request, "response.completed", payload, func(context.Context, string) error {
		return nil
	}); err != nil {
		t.Fatalf("forward response: %v", err)
	}
	items, err := journal.LoadConversationInput(context.Background(), request.ConversationID)
	if err != nil {
		t.Fatalf("load conversation input: %v", err)
	}
	if len(items) != 2 || !bytes.Contains(items[0], []byte("hello")) || !bytes.Contains(items[1], []byte("world")) {
		t.Fatalf("conversation items = %s", items)
	}
}
