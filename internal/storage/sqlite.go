package storage

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func Open(ctx context.Context, path string, busyTimeout time.Duration) (*gorm.DB, error) {
	if path == "" {
		return nil, fmt.Errorf("sqlite path is empty")
	}
	if busyTimeout <= 0 {
		return nil, fmt.Errorf("sqlite busy timeout must be positive")
	}
	if err := makeParentDirectory(path); err != nil {
		return nil, err
	}

	db, err := gorm.Open(sqlite.Open(path), &gorm.Config{})
	if err != nil {
		return nil, fmt.Errorf("open sqlite database: %w", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		return nil, fmt.Errorf("get sqlite database: %w", err)
	}
	sqlDB.SetMaxOpenConns(1)
	sqlDB.SetMaxIdleConns(1)

	milliseconds := busyTimeout / time.Millisecond
	if milliseconds < 1 {
		milliseconds = 1
	}
	pragma := "PRAGMA busy_timeout = " + strconv.FormatInt(int64(milliseconds), 10)
	if _, err := sqlDB.ExecContext(ctx, pragma); err != nil {
		_ = sqlDB.Close()
		return nil, fmt.Errorf("set sqlite busy timeout: %w", err)
	}
	if err := sqlDB.PingContext(ctx); err != nil {
		_ = sqlDB.Close()
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
