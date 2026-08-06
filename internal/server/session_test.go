package server

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/catgirl-systems/codex-sub-proxy/internal/codex"
)

func TestRequestHeaderConfigTurnMetadataIsStrictAndConsistent(t *testing.T) {
	config, err := requestHeaderConfig(http.Header{
		codex.SessionIDHeader:    {"session"},
		codex.ThreadIDHeader:     {"thread"},
		codex.TurnMetadataHeader: {`{"session_id":"session","thread_id":"thread","turn_id":"turn"}`},
	})
	if err != nil {
		t.Fatalf("consistent turn metadata rejected: %v", err)
	}
	if config.SessionID != "session" || config.ThreadID != "thread" {
		t.Fatalf("request identity = %#v", config)
	}

	tests := []http.Header{
		{"SESSION_ID": {"one"}, "session_id": {"one"}},
		{codex.SessionIDHeader: {"header"}, codex.TurnMetadataHeader: {`{"session_id":"metadata"}`}},
		{codex.TurnMetadataHeader: {`{"session_id":"one","SESSION_ID":"two"}`}},
		{codex.TurnMetadataHeader: {`{"session_id":null}`}},
		{codex.TurnMetadataHeader: {`{"session_id":"one"} trailing`}},
		{codex.SessionIDHeader: {"session\x00id"}},
		{codex.TurnMetadataHeader: {`{"session_id":"session\u0000id"}`}},
	}
	for index, headers := range tests {
		if _, err := requestHeaderConfig(headers); err == nil {
			t.Fatalf("header case %d was accepted: %#v", index, headers)
		}
	}

	metadataOnly, err := requestHeaderConfig(http.Header{
		codex.TurnMetadataHeader: {`{"turn_id":"turn-only"}`},
	})
	if err != nil {
		t.Fatalf("metadata without identity rejected: %v", err)
	}
	if metadataOnly.SessionID != "" || metadataOnly.ThreadID != "" {
		t.Fatalf("metadata fabricated identity: %#v", metadataOnly)
	}

	if _, err := requestHeaderConfig(http.Header{
		codex.SessionIDHeader: {strings.Repeat("s", 257)},
	}); err == nil {
		t.Fatal("oversized session identity accepted")
	}
}

func TestSessionAffinityHashIsSaltedAndStable(t *testing.T) {
	headers := codex.RequestHeaderConfig{SessionID: "session", ThreadID: "thread"}
	first := sessionAffinityHash("key", headers)
	second := sessionAffinityHash("key", headers)
	if first == "" || first != second || len(first) != 64 {
		t.Fatalf("session hash = %q, %q", first, second)
	}
	if strings.Contains(first, "session") || strings.Contains(first, "thread") {
		t.Fatalf("session hash contains identity: %q", first)
	}
	if first == sessionAffinityHash("other-key", headers) {
		t.Fatal("session hash is not bound to API key")
	}
	if got := sessionAffinityHash("key", codex.RequestHeaderConfig{}); got != "" {
		t.Fatalf("empty identity hash = %q", got)
	}
	collision := codex.RequestHeaderConfig{SessionID: "a\x00thread_id\x00b"}
	if got := sessionAffinityHash("key", collision); got != "" {
		t.Fatalf("invalid NUL identity received an affinity hash: %q", got)
	}
	distinct := sessionAffinityHash("key", codex.RequestHeaderConfig{SessionID: "a", ThreadID: "b"})
	if distinct == "" {
		t.Fatal("valid identity did not receive an affinity hash")
	}
}

func TestProfileBrokerAffinityFallsBackForUnavailableAccount(t *testing.T) {
	broker, err := NewProfileBroker(&codex.RoundRobinSelector{}, []BrokerProfile{
		{Account: codex.Account{ID: "disabled", Enabled: false, Available: true}, Responses: &codex.ResponsesTransport{}},
		{Account: codex.Account{ID: "active", Enabled: true, Available: true}, Responses: &codex.ResponsesTransport{}},
	})
	if err != nil {
		t.Fatal(err)
	}
	selected, err := broker.profile(context.Background(), codex.SelectionRequest{
		Model:             "gpt-5.6-sol",
		AffinityAccountID: "disabled",
	}, "")
	if err != nil {
		t.Fatalf("select after disabled affinity: %v", err)
	}
	if selected.Account.ID != "active" {
		t.Fatalf("selected account = %q, want active", selected.Account.ID)
	}
}

func TestResolveSessionAffinityIgnoresExpiredRows(t *testing.T) {
	journal, db := openTestJournal(t, journalModeDurable, 4)
	defer closeTestJournal(t, journal, db)

	hash := sessionAffinityHash("key", codex.RequestHeaderConfig{SessionID: "session"})
	if err := db.Create(&SessionAffinityRecord{
		APIKeyID: "key", SessionHash: hash, AccountID: "account",
		CreatedAt: time.Now().UTC().Add(-time.Minute), UpdatedAt: time.Now().UTC().Add(-time.Minute),
		ExpiresAt: time.Now().UTC().Add(time.Minute),
	}).Error; err != nil {
		t.Fatal(err)
	}
	account, err := journal.ResolveSessionAffinity(context.Background(), "key", hash)
	if err != nil || account != "account" {
		t.Fatalf("resolve active affinity = %q, %v", account, err)
	}
	if err := db.Model(&SessionAffinityRecord{}).Where("api_key_id = ? AND session_hash = ?", "key", hash).
		Update("expires_at", time.Now().UTC().Add(-time.Second)).Error; err != nil {
		t.Fatal(err)
	}
	if _, err := journal.ResolveSessionAffinity(context.Background(), "key", hash); !errors.Is(err, ErrSessionAffinityNotFound) {
		t.Fatalf("resolve expired affinity = %v, want ErrSessionAffinityNotFound", err)
	}
}

func TestSessionAffinityBindConflictCanBeResolvedForRetry(t *testing.T) {
	journal, db := openTestJournal(t, journalModeDurable, 4)
	defer closeTestJournal(t, journal, db)

	hash := sessionAffinityHash("key", codex.RequestHeaderConfig{ThreadID: "thread"})
	first, err := journal.BeginRequestWithMetadata(context.Background(), JournalRequestMetadata{
		Endpoint: responsesEndpoint, Model: "gpt-5.6-sol", APIKeyID: "key",
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := journal.BindAccount(context.Background(), first.ID, "first", hash); err != nil {
		t.Fatal(err)
	}
	second, err := journal.BeginRequestWithMetadata(context.Background(), JournalRequestMetadata{
		Endpoint: responsesEndpoint, Model: "gpt-5.6-sol", APIKeyID: "key",
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	err = journal.BindAccount(context.Background(), second.ID, "second", hash)
	if !errors.Is(err, ErrSessionAffinityConflict) {
		t.Fatalf("binding conflict = %v, want ErrSessionAffinityConflict", err)
	}
	winner, err := journal.ResolveSessionAffinity(context.Background(), "key", hash)
	if err != nil || winner != "first" {
		t.Fatalf("resolved winner = %q, %v", winner, err)
	}
}

func TestEnsureSessionAffinityInsertFailureIsNotRetryableConflict(t *testing.T) {
	triggerName := "session_affinity_insert_failure"
	journal, db := openTestJournal(t, journalModeDurable, 4)
	defer func() {
		_ = db.Exec(`DROP TRIGGER ` + triggerName).Error
		closeTestJournal(t, journal, db)
	}()
	if err := db.Exec(`CREATE TRIGGER ` + triggerName + ` BEFORE INSERT ON session_affinities BEGIN SELECT RAISE(ABORT, 'injected session affinity failure'); END`).Error; err != nil {
		t.Fatal(err)
	}

	err := ensureSessionAffinity(db, "key", strings.Repeat("a", 64), "account", time.Now().UTC(), time.Now().UTC().Add(time.Hour))
	if err == nil {
		t.Fatal("injected session affinity insert failure was ignored")
	}
	if errors.Is(err, ErrSessionAffinityConflict) {
		t.Fatalf("injected insert failure became retryable conflict: %v", err)
	}
}
