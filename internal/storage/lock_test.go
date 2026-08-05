package storage

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestApplicationLockSharedExclusiveModesAndDowngrade(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "service.sqlite3")
	exclusive, err := AcquireApplicationLock(context.Background(), databasePath, ApplicationLockExclusive)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := AcquireApplicationLock(context.Background(), databasePath, ApplicationLockShared); err == nil {
		t.Fatal("shared writer acquired an exclusive application lock")
	} else if err.Error() != "service is running" {
		t.Fatalf("shared writer error = %v", err)
	}
	if err := exclusive.DowngradeShared(); err != nil {
		t.Fatal(err)
	}
	shared, err := AcquireApplicationLock(context.Background(), databasePath, ApplicationLockShared)
	if err != nil {
		t.Fatalf("shared writer after downgrade: %v", err)
	}
	if exclusive.Mode() != ApplicationLockShared {
		t.Fatalf("downgraded mode = %v", exclusive.Mode())
	}
	if _, err := AcquireApplicationLock(context.Background(), databasePath, ApplicationLockExclusive); err == nil {
		t.Fatal("restore acquired an exclusive lock while shared writers were active")
	}
	if err := shared.Close(); err != nil {
		t.Fatal(err)
	}
	if err := exclusive.Close(); err != nil {
		t.Fatal(err)
	}
	restored, err := AcquireApplicationLock(context.Background(), databasePath, ApplicationLockExclusive)
	if err != nil {
		t.Fatalf("exclusive lock after shared writers closed: %v", err)
	}
	if err := restored.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestApplicationLockRejectsCanceledAcquisition(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := AcquireApplicationLock(ctx, filepath.Join(t.TempDir(), "service.sqlite3"), ApplicationLockShared); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled lock error = %v", err)
	}
}

func TestApplicationLockCrossProcessExclusion(t *testing.T) {
	if os.Getenv("CSP_LOCK_HELPER") == "1" {
		lock, err := AcquireApplicationLock(context.Background(), os.Getenv("CSP_LOCK_DATABASE"), ApplicationLockExclusive)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		defer lock.Close()
		fmt.Fprintln(os.Stdout, "ready")
		_, _ = io.ReadAll(os.Stdin)
		return
	}
	databasePath := filepath.Join(t.TempDir(), "service.sqlite3")
	command := exec.Command(os.Args[0], "-test.run=TestApplicationLockCrossProcessExclusion", "--")
	command.Env = append(os.Environ(), "CSP_LOCK_HELPER=1", "CSP_LOCK_DATABASE="+databasePath)
	stdout, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdin, err := command.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	command.Stderr = os.Stderr
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(stdout)
	ready, err := reader.ReadString('\n')
	if err != nil {
		_ = command.Process.Kill()
		_ = command.Wait()
		t.Fatalf("helper readiness: %v", err)
	}
	if ready != "ready\n" {
		_ = command.Process.Kill()
		_ = command.Wait()
		t.Fatalf("helper readiness = %q", ready)
	}
	if _, err := AcquireApplicationLock(context.Background(), databasePath, ApplicationLockShared); err == nil {
		_ = command.Process.Kill()
		_ = command.Wait()
		t.Fatal("shared application lock crossed process exclusive owner")
	}
	_ = stdin.Close()
	if err := command.Wait(); err != nil {
		t.Fatalf("helper exit: %v", err)
	}
}
