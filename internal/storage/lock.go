package storage

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// ApplicationLock prevents a live service from being replaced by restore.
type ApplicationLock struct {
	file *os.File
}

func LockPath(databasePath string) string {
	return databasePath + ".service.lock"
}

func AcquireApplicationLock(ctx context.Context, databasePath string) (*ApplicationLock, error) {
	if ctx == nil {
		return nil, errors.New("application lock context is nil")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if databasePath == "" || databasePath == ":memory:" || strings.HasPrefix(databasePath, "file:") {
		return nil, errors.New("application lock database path is invalid")
	}
	databasePath, err := filepath.Abs(databasePath)
	if err != nil {
		return nil, fmt.Errorf("resolve application lock database path: %w", err)
	}
	if filepath.Clean(databasePath) != databasePath {
		return nil, errors.New("application lock database path is invalid")
	}
	parent := filepath.Dir(databasePath)
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return nil, fmt.Errorf("create application lock parent: %w", err)
	}
	file, err := os.OpenFile(LockPath(databasePath), os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open application lock: %w", err)
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = file.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
			return nil, errors.New("service is running")
		}
		return nil, fmt.Errorf("acquire application lock: %w", err)
	}
	return &ApplicationLock{file: file}, nil
}

func (lock *ApplicationLock) Close() error {
	if lock == nil || lock.file == nil {
		return nil
	}
	file := lock.file
	lock.file = nil
	unlockErr := syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
	closeErr := file.Close()
	return errors.Join(unlockErr, closeErr)
}
