package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestOpenArchiveEntryRejectsReplacementAndSymlink(t *testing.T) {
	rootPath := t.TempDir()
	entryPath := filepath.Join(rootPath, "payload")
	if err := os.WriteFile(entryPath, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	entries, err := enumerateRoot(root, ".")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("entries = %d, want one", len(entries))
	}
	replacement := filepath.Join(rootPath, "replacement")
	if err := os.WriteFile(replacement, []byte("replacement"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(replacement, entryPath); err != nil {
		t.Fatal(err)
	}
	if file, _, err := openArchiveEntry(root, entries[0]); err == nil {
		_ = file.Close()
		t.Fatal("replacement file was accepted")
	}
	if err := os.Remove(entryPath); err != nil {
		t.Fatal(err)
	}
	victim := filepath.Join(t.TempDir(), "victim")
	if err := os.WriteFile(victim, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victim, entryPath); err != nil {
		t.Fatal(err)
	}
	if file, _, err := openArchiveEntry(root, entries[0]); err == nil {
		_ = file.Close()
		t.Fatal("symlink replacement was accepted")
	}
	if got, err := os.ReadFile(victim); err != nil || string(got) != "secret" {
		t.Fatalf("victim = %q, %v", got, err)
	}
}
