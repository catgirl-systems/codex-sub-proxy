package storage

import (
	"context"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestOpenSetsBusyTimeoutAndConnectionBounds(t *testing.T) {
	path := filepath.Join(t.TempDir(), "data", "csp.sqlite3")
	db, err := Open(context.Background(), path, 2500*time.Millisecond)
	if err != nil {
		t.Fatalf("open database: %v", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("get sql database: %v", err)
	}
	defer sqlDB.Close()

	if got := sqlDB.Stats().MaxOpenConnections; got != 1 {
		t.Fatalf("max open connections = %d, want 1", got)
	}
	var timeout struct {
		Value int `gorm:"column:timeout"`
	}
	if err := db.Raw("PRAGMA busy_timeout").Scan(&timeout).Error; err != nil {
		t.Fatalf("read busy timeout: %v", err)
	}
	if timeout.Value != 2500 {
		t.Fatalf("busy timeout = %d, want 2500", timeout.Value)
	}
	var value struct {
		Value int `gorm:"column:value"`
	}
	if err := db.Raw("SELECT 1 AS value").Scan(&value).Error; err != nil {
		t.Fatalf("query database: %v", err)
	}
	if value.Value != 1 {
		t.Fatalf("query value = %d, want 1", value.Value)
	}
}

func TestSQLiteDSNMergesBusyTimeout(t *testing.T) {
	for name, test := range map[string]struct {
		path       string
		base       string
		parameters url.Values
	}{
		"plain path": {
			path: "/tmp/codex-sub-proxy.sqlite3",
			base: "/tmp/codex-sub-proxy.sqlite3",
		},
		"file URI": {
			path: "file:/tmp/codex-sub-proxy.sqlite3?mode=rwc&cache=shared",
			base: "file:/tmp/codex-sub-proxy.sqlite3",
			parameters: url.Values{
				"mode":  {"rwc"},
				"cache": {"shared"},
			},
		},
		"replace existing timeout": {
			path: "file:/tmp/codex-sub-proxy.sqlite3?_busy_timeout=999&_timeout=1000&mode=rwc",
			base: "file:/tmp/codex-sub-proxy.sqlite3",
			parameters: url.Values{
				"mode": {"rwc"},
			},
		},
	} {
		t.Run(name, func(t *testing.T) {
			dsn, err := sqliteDSN(test.path, 2500*time.Millisecond)
			if err != nil {
				t.Fatalf("build dsn: %v", err)
			}
			queryIndex := strings.IndexByte(dsn, '?')
			if queryIndex < 0 {
				t.Fatalf("dsn %q has no query", dsn)
			}
			if got := dsn[:queryIndex]; got != test.base {
				t.Fatalf("dsn base = %q, want %q", got, test.base)
			}
			query, err := url.ParseQuery(dsn[queryIndex+1:])
			if err != nil {
				t.Fatalf("parse dsn query: %v", err)
			}
			if got := query.Get("_busy_timeout"); got != "2500" {
				t.Fatalf("busy timeout = %q, want 2500", got)
			}
			if _, ok := query["_timeout"]; ok {
				t.Fatalf("dsn retained _timeout alias: %q", dsn)
			}
			for key, want := range test.parameters {
				if got := query[key]; len(got) != len(want) || got[0] != want[0] {
					t.Errorf("query[%q] = %v, want %v", key, got, want)
				}
			}
		})
	}
}

func TestOpenAppliesBusyTimeoutToReplacementConnection(t *testing.T) {
	db, err := Open(context.Background(), filepath.Join(t.TempDir(), "data.sqlite3"), 2500*time.Millisecond)
	if err != nil {
		t.Fatalf("open database: %v", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("get sql database: %v", err)
	}
	defer sqlDB.Close()
	sqlDB.SetConnMaxLifetime(10 * time.Millisecond)

	var timeout struct {
		Value int `gorm:"column:timeout"`
	}
	if err := db.Raw("PRAGMA busy_timeout").Scan(&timeout).Error; err != nil {
		t.Fatalf("read initial busy timeout: %v", err)
	}
	if timeout.Value != 2500 {
		t.Fatalf("initial busy timeout = %d, want 2500", timeout.Value)
	}
	time.Sleep(20 * time.Millisecond)

	timeout.Value = 0
	if err := db.Raw("PRAGMA busy_timeout").Scan(&timeout).Error; err != nil {
		t.Fatalf("read replacement busy timeout: %v", err)
	}
	if timeout.Value != 2500 {
		t.Fatalf("replacement busy timeout = %d, want 2500", timeout.Value)
	}
}

func TestOpenRejectsInvalidArguments(t *testing.T) {
	for name, test := range map[string]struct {
		path    string
		timeout time.Duration
	}{
		"empty path":   {path: "", timeout: time.Second},
		"zero timeout": {path: ":memory:", timeout: 0},
	} {
		t.Run(name, func(t *testing.T) {
			if db, err := Open(context.Background(), test.path, test.timeout); err == nil || db != nil {
				t.Fatal("open accepted invalid arguments")
			}
		})
	}
}
