package main

import (
	"strings"
	"testing"
)

func TestFakeResponseIDIsFreshAndSupportsAlternateConfiguredID(t *testing.T) {
	t.Setenv("CSP_FAKE_RESPONSE_ID", "")
	first, err := fakeResponseID()
	if err != nil {
		t.Fatal(err)
	}
	second, err := fakeResponseID()
	if err != nil {
		t.Fatal(err)
	}
	if first == second || !strings.HasPrefix(first, "resp_") || !strings.HasPrefix(second, "resp_") {
		t.Fatalf("response IDs = %q, %q", first, second)
	}
	t.Setenv("CSP_FAKE_RESPONSE_ID", "resp_alternate")
	configured, err := fakeResponseID()
	if err != nil {
		t.Fatal(err)
	}
	if configured != "resp_alternate" {
		t.Fatalf("configured response ID = %q", configured)
	}
}
