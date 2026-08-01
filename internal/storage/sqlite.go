package storage

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

func Open(ctx context.Context, path string, busyTimeout time.Duration) (*sql.DB, error) {
	if path == "" {
		return nil, fmt.Errorf("sqlite path is empty")
	}
	if busyTimeout <= 0 {
		return nil, fmt.Errorf("sqlite busy timeout must be positive")
	}
	if err := makeParentDirectory(path); err != nil {
		return nil, err
	}

	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open sqlite database: %w", err)
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)

	milliseconds := busyTimeout / time.Millisecond
	if milliseconds < 1 {
		milliseconds = 1
	}
	pragma := "PRAGMA busy_timeout = " + strconv.FormatInt(int64(milliseconds), 10)
	if _, err := db.ExecContext(ctx, pragma); err != nil {
		db.Close()
		return nil, fmt.Errorf("set sqlite busy timeout: %w", err)
	}
	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("ping sqlite database: %w", err)
	}
	return db, nil
}

func makeParentDirectory(path string) error {
	if path == ":memory:" || strings.HasPrefix(path, "file:") {
		return nil
	}
	parent := filepath.Dir(path)
	if parent == "." || parent == "" {
		return nil
	}
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return fmt.Errorf("create sqlite directory %q: %w", parent, err)
	}
	return nil
}
