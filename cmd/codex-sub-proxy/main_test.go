package main

import "testing"

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
