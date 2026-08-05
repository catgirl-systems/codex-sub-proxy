package storage

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
)

// ApplicationLock serializes process ownership of one database.
type ApplicationLock struct {
	file *os.File
	mode ApplicationLockMode
	mu   sync.Mutex
}

// ApplicationLockMode selects shared or exclusive ownership.
type ApplicationLockMode int

const (
	ApplicationLockShared ApplicationLockMode = iota + 1
	ApplicationLockExclusive
)

func LockPath(databasePath string) string {
	return databasePath + ".service.lock"
}

// AcquireApplicationLock takes an exclusive lock when no mode is supplied.
func AcquireApplicationLock(ctx context.Context, databasePath string, modes ...ApplicationLockMode) (*ApplicationLock, error) {
	mode := ApplicationLockExclusive
	if len(modes) > 1 {
		return nil, errors.New("application lock mode is specified more than once")
	}
	if len(modes) == 1 {
		mode = modes[0]
	}
	if mode != ApplicationLockShared && mode != ApplicationLockExclusive {
		return nil, errors.New("application lock mode is invalid")
	}
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
	flags := syscall.LOCK_NB
	if mode == ApplicationLockShared {
		flags |= syscall.LOCK_SH
	} else {
		flags |= syscall.LOCK_EX
	}
	if err := syscall.Flock(int(file.Fd()), flags); err != nil {
		_ = file.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
			return nil, errors.New("service is running")
		}
		return nil, fmt.Errorf("acquire application lock: %w", err)
	}
	return &ApplicationLock{file: file, mode: mode}, nil
}

func (lock *ApplicationLock) DowngradeShared() error {
	if lock == nil {
		return errors.New("application lock is nil")
	}
	lock.mu.Lock()
	defer lock.mu.Unlock()
	if lock.file == nil {
		return errors.New("application lock is closed")
	}
	if lock.mode == ApplicationLockShared {
		return nil
	}
	if err := syscall.Flock(int(lock.file.Fd()), syscall.LOCK_SH|syscall.LOCK_NB); err != nil {
		return fmt.Errorf("downgrade application lock: %w", err)
	}
	lock.mode = ApplicationLockShared
	return nil
}

func (lock *ApplicationLock) Mode() ApplicationLockMode {
	if lock == nil {
		return 0
	}
	lock.mu.Lock()
	defer lock.mu.Unlock()
	return lock.mode
}

func (lock *ApplicationLock) Close() error {
	if lock == nil {
		return nil
	}
	lock.mu.Lock()
	defer lock.mu.Unlock()
	if lock.file == nil {
		return nil
	}
	file := lock.file
	lock.file = nil
	unlockErr := syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
	closeErr := file.Close()
	return errors.Join(unlockErr, closeErr)
}
