package codex

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func TestAccountSelectorsRespectAvailabilityAndOrdering(t *testing.T) {
	accounts := []Account{
		{ID: "zeta", Enabled: true, Available: true},
		{ID: "alpha", Enabled: true, Available: true},
		{ID: "cooldown", Enabled: true, Available: true, CooldownUntil: time.Now().Add(time.Hour)},
		{ID: "disabled", Enabled: false, Available: true},
	}
	selector := &RoundRobinSelector{}
	first, err := selector.Select(context.Background(), SelectionRequest{}, accounts)
	if err != nil {
		t.Fatal(err)
	}
	second, err := selector.Select(context.Background(), SelectionRequest{}, accounts)
	if err != nil {
		t.Fatal(err)
	}
	if first.ID != "alpha" || second.ID != "zeta" {
		t.Fatalf("round robin order = %q, %q", first.ID, second.ID)
	}
	single, err := (SingleSelector{}).Select(context.Background(), SelectionRequest{}, accounts)
	if err == nil || !errors.Is(err, ErrNoAvailableAccount) || single.ID != "" {
		t.Fatalf("single selector = %#v, %v", single, err)
	}
}

func TestQuotaAwareSelectorUsesUnknownQuotaAsZeroAndRotatesTies(t *testing.T) {
	accounts := []Account{
		{ID: "known", Enabled: true, Available: true, Quota: &QuotaSnapshot{Known: true, UsedPercent: 50}},
		{ID: "unknown", Enabled: true, Available: true},
		{ID: "also-unknown", Enabled: true, Available: true, Quota: &QuotaSnapshot{Known: false, UsedPercent: 99}},
	}
	selector := &QuotaAwareSelector{}
	first, err := selector.Select(context.Background(), SelectionRequest{}, accounts)
	if err != nil {
		t.Fatal(err)
	}
	second, err := selector.Select(context.Background(), SelectionRequest{}, accounts)
	if err != nil {
		t.Fatal(err)
	}
	if first.ID != "also-unknown" || second.ID != "unknown" {
		t.Fatalf("quota-aware tie order = %q, %q", first.ID, second.ID)
	}
}

func TestProfileCredentialPath(t *testing.T) {
	base := filepath.Join(t.TempDir(), "credential.enc")
	defaultPath, err := ProfileCredentialPath(base, "default")
	if err != nil {
		t.Fatal(err)
	}
	if defaultPath != base {
		t.Fatalf("default path = %q, want %q", defaultPath, base)
	}
	profilePath, err := ProfileCredentialPath(base, "work")
	if err != nil {
		t.Fatal(err)
	}
	if profilePath == base || filepath.Dir(profilePath) != base+".d" {
		t.Fatalf("profile path = %q", profilePath)
	}
	if _, err := ProfileCredentialPath(base, "../escape"); err == nil {
		t.Fatal("path traversal profile accepted")
	}
}

func TestRequestHeaderConfigBounds(t *testing.T) {
	if err := (RequestHeaderConfig{SessionID: string(make([]byte, 257))}).Validate(); err == nil {
		t.Fatal("oversized session header accepted")
	}
	if err := (RequestHeaderConfig{ThreadID: "line\nbreak"}).Validate(); err == nil {
		t.Fatal("line-break thread header accepted")
	}
}

func TestMergeRequestHeadersPreservesBaseAndAllowsPerCallOverride(t *testing.T) {
	base := HeaderConfig{
		SessionID: "base-session", ThreadID: "base-thread", ResponsesLite: true,
	}
	if got := mergeRequestHeaders(base, RequestHeaderConfig{}); got != base {
		t.Fatalf("empty per-call headers changed base = %+v, want %+v", got, base)
	}
	override := mergeRequestHeaders(base, RequestHeaderConfig{
		SessionID: "call-session", ThreadID: "call-thread",
	})
	if override.SessionID != "call-session" || override.ThreadID != "call-thread" || !override.ResponsesLite {
		t.Fatalf("per-call header override = %+v", override)
	}
}
