package storage

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func TestOpenSetsBusyTimeoutAndCreatesDatabase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "data", "csp.sqlite3")
	db, err := Open(context.Background(), path, 2500*time.Millisecond)
	if err != nil {
		t.Fatalf("open database: %v", err)
	}
	defer db.Close()

	var timeout int
	if err := db.QueryRowContext(context.Background(), "PRAGMA busy_timeout").Scan(&timeout); err != nil {
		t.Fatalf("read busy timeout: %v", err)
	}
	if timeout != 2500 {
		t.Fatalf("busy timeout = %d, want 2500", timeout)
	}
	var value int
	if err := db.QueryRowContext(context.Background(), "SELECT 1").Scan(&value); err != nil {
		t.Fatalf("query database: %v", err)
	}
	if value != 1 {
		t.Fatalf("query value = %d", value)
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
