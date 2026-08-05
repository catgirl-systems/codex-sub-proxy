package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRemoveContentsDoesNotFollowSymlinkVictim(t *testing.T) {
	output := filepath.Join(t.TempDir(), "output")
	if err := os.Mkdir(output, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := writeSentinel(output); err != nil {
		t.Fatal(err)
	}
	victim := filepath.Join(t.TempDir(), "victim")
	if err := os.WriteFile(victim, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victim, filepath.Join(output, "victim-link")); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(output)
	if err != nil {
		t.Fatal(err)
	}
	if err := removeContents(root, "."); err != nil {
		_ = root.Close()
		t.Fatal(err)
	}
	if err := root.Close(); err != nil {
		t.Fatal(err)
	}
	if got, err := os.ReadFile(victim); err != nil || string(got) != "secret" {
		t.Fatalf("victim = %q, %v", got, err)
	}
	if _, err := os.Lstat(filepath.Join(output, "victim-link")); !os.IsNotExist(err) {
		t.Fatalf("symlink remains: %v", err)
	}
}

func TestCleanAbsolutePathCanonicalizesSystemTemporaryRoot(t *testing.T) {
	resolved, err := filepath.EvalSymlinks("/tmp")
	if err != nil {
		t.Fatal(err)
	}
	path, err := cleanAbsolutePath("/tmp/csp-release-canonical/path")
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(resolved, "csp-release-canonical/path")
	if path != want {
		t.Fatalf("canonical path = %q, want %q", path, want)
	}
}

func TestValidateAncestorsRejectsUserSymlink(t *testing.T) {
	root := t.TempDir()
	victim := filepath.Join(t.TempDir(), "victim")
	if err := os.Mkdir(victim, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(victim, link); err != nil {
		t.Fatal(err)
	}
	if err := validateAncestors(filepath.Join(link, "release")); err == nil {
		t.Fatal("user-controlled symlink ancestor was accepted")
	}
}
