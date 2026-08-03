package storage

import (
	"context"
	"fmt"
	"net/url"
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
	dsn, err := sqliteDSN(path, busyTimeout)
	if err != nil {
		return nil, fmt.Errorf("build sqlite DSN: %w", err)
	}

	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
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
	if _, err := sqlDB.ExecContext(ctx, "PRAGMA foreign_keys = ON"); err != nil {
		_ = sqlDB.Close()
		return nil, fmt.Errorf("enable sqlite foreign keys: %w", err)
	}
	if err := sqlDB.PingContext(ctx); err != nil {
		_ = sqlDB.Close()
		return nil, fmt.Errorf("ping sqlite database: %w", err)
	}
	return db, nil
}

func sqliteDSN(path string, busyTimeout time.Duration) (string, error) {
	milliseconds := busyTimeout / time.Millisecond
	if milliseconds < 1 {
		milliseconds = 1
	}

	busyTimeoutValue := strconv.FormatInt(int64(milliseconds), 10)
	queryIndex := strings.IndexByte(path, '?')
	if queryIndex < 0 {
		return path + "?_busy_timeout=" + busyTimeoutValue, nil
	}

	query, err := url.ParseQuery(path[queryIndex+1:])
	if err != nil {
		return "", fmt.Errorf("parse query parameters: %w", err)
	}
	query.Del("_busy_timeout")
	query.Del("_timeout")
	query.Set("_busy_timeout", busyTimeoutValue)
	return path[:queryIndex] + "?" + query.Encode(), nil
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
