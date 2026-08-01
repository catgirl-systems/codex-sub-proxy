package storage

import (
	"context"
	"path/filepath"
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
