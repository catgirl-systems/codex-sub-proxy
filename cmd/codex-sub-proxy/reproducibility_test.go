package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestBuildReproducibleAcrossWorkdirs(t *testing.T) {
	if testing.Short() {
		t.Skip("reproducibility build is skipped in short mode")
	}
	root := repositoryRoot(t)
	workspace := t.TempDir()
	first := filepath.Join(workspace, "first", "source")
	second := filepath.Join(workspace, "second", "source")
	copyRepository(t, root, first)
	copyRepository(t, root, second)
	firstBinary := filepath.Join(workspace, "first", "codex-sub-proxy")
	secondBinary := filepath.Join(workspace, "second", "codex-sub-proxy")
	buildReproducibleBinary(t, first, firstBinary)
	buildReproducibleBinary(t, second, secondBinary)
	firstHash := hashFile(t, firstBinary)
	secondHash := hashFile(t, secondBinary)
	if firstHash != secondHash {
		t.Fatalf("reproducible build hashes differ: %s != %s", firstHash, secondHash)
	}
}

func repositoryRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("find test source")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "../.."))
}

func copyRepository(t *testing.T, source, destination string) {
	t.Helper()
	if err := filepath.WalkDir(source, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relative, err := filepath.Rel(source, path)
		if err != nil {
			return err
		}
		if relative == ".git" || filepath.Base(relative) == ".git" || relative == "dist" {
			if entry.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		target := filepath.Join(destination, relative)
		if entry.IsDir() {
			return os.MkdirAll(target, 0o700)
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("source contains symlink %q", relative)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
			return err
		}
		return os.WriteFile(target, data, info.Mode().Perm())
	}); err != nil {
		t.Fatal(err)
	}
}

func buildReproducibleBinary(t *testing.T, directory, output string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "go", "build", "-trimpath", "-buildvcs=false", "-mod=readonly", "-ldflags", "-s -w -X github.com/catgirl-systems/codex-sub-proxy/internal/version.Version=v0.0.0 -X github.com/catgirl-systems/codex-sub-proxy/internal/version.Commit=reproducible -X github.com/catgirl-systems/codex-sub-proxy/internal/version.BuildTime=1700000000", "-o", output, "./cmd/codex-sub-proxy")
	cmd.Dir = directory
	cmd.Env = append(os.Environ(), "GOFLAGS=-trimpath -buildvcs=false -mod=readonly", "CGO_ENABLED=1", "GOOS="+runtime.GOOS, "GOARCH="+runtime.GOARCH)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("reproducible build failed: %v\n%s", err, output)
	}
}

func hashFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}
