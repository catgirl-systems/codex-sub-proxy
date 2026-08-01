package main

import (
	"errors"
	"testing"
)

func TestServerStoppedErrorPreservesShutdownFailure(t *testing.T) {
	serveErr := errors.New("serve failed")
	shutdownErr := errors.New("shutdown failed")

	err := serverStoppedError(serveErr, shutdownErr)
	if !errors.Is(err, serveErr) {
		t.Fatalf("server error = %v, want %v", err, serveErr)
	}
	if !errors.Is(err, shutdownErr) {
		t.Fatalf("shutdown error = %v, want %v", err, shutdownErr)
	}
}

func TestRunRejectsSecretCommandLineFlagsAndArguments(t *testing.T) {
	for name, args := range map[string][]string{
		"secret flag":     {"--bootstrap-admin-token", "secret"},
		"secret argument": {"secret"},
	} {
		t.Run(name, func(t *testing.T) {
			if err := run(args); err == nil {
				t.Fatal("secret command-line input was accepted")
			}
		})
	}
}
