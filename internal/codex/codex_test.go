package codex

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestBuildHeadersMatchesCodexFixture(t *testing.T) {
	headers, err := BuildHeaders(HeaderConfig{
		AccessToken:         "access-token",
		AccountID:           "account-123",
		InstallationID:      "installation-123",
		SessionID:           "session-123",
		ThreadID:            "thread-123",
		WindowID:            "window-123",
		TurnID:              "turn-123",
		TurnStartedAtUnixMs: 1738888888123,
		RequestKind:         "turn",
		ImageTurnID:         "image-turn-123",
		Attestation:         `{"v":1,"s":0,"t":"opaque"}`,
		FedRAMP:             true,
	})
	if err != nil {
		t.Fatalf("BuildHeaders returned error: %v", err)
	}

	want := map[string]string{
		AuthorizationHeader:   "Bearer access-token",
		AccountIDHeader:       "account-123",
		BetaHeader:            DefaultBeta,
		OriginatorHeader:      DefaultOriginator,
		VersionHeader:         DefaultVersion,
		SessionIDHeader:       "session-123",
		ConversationIDHeader:  "session-123",
		ScopedSessionIDHeader: "session-123",
		"x-client-request-id": "thread-123",
		ThreadIDHeader:        "thread-123",
		WindowIDHeader:        "window-123",
		TurnMetadataHeader:    `{"installation_id":"installation-123","session_id":"session-123","thread_id":"thread-123","turn_id":"turn-123","window_id":"window-123","request_kind":"turn","turn_started_at_unix_ms":1738888888123}`,
		ImageTurnIDHeader:     "image-turn-123",
		AttestationHeader:     `{"v":1,"s":0,"t":"opaque"}`,
		FedRAMPHeader:         "true",
	}
	for name, expected := range want {
		if got := headers.Get(name); got != expected {
			t.Errorf("header %q = %q, want %q", name, got, expected)
		}
	}
	if got := headers.Get("turn_id"); got != "" {
		t.Fatalf("legacy turn id header = %q, want empty", got)
	}
}

func TestBuildHeadersUsesThreadThenSessionClientIdentity(t *testing.T) {
	tests := []struct {
		name   string
		config HeaderConfig
		want   string
	}{
		{
			name:   "thread identity",
			config: HeaderConfig{ThreadID: "thread-123", SessionID: "session-123"},
			want:   "thread-123",
		},
		{
			name:   "session fallback",
			config: HeaderConfig{SessionID: "session-123"},
			want:   "session-123",
		},
		{
			name: "no identity",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			headers, err := BuildHeaders(HeaderConfig{
				AccessToken: "access-token",
				AccountID:   "account-123",
				SessionID:   test.config.SessionID,
				ThreadID:    test.config.ThreadID,
			})
			if err != nil {
				t.Fatalf("BuildHeaders returned error: %v", err)
			}
			if got := headers.Get("x-client-request-id"); got != test.want {
				t.Fatalf("x-client-request-id = %q, want %q", got, test.want)
			}
		})
	}
}

func TestNewRequestDoesNotForwardDownstreamAuthorization(t *testing.T) {
	req, err := NewRequest(
		context.Background(),
		http.MethodPost,
		"https://chatgpt.com/backend-api/codex/responses",
		strings.NewReader(`{"input":[]}`),
		HeaderConfig{AccessToken: "upstream-token", AccountID: "account-123"},
	)
	if err != nil {
		t.Fatalf("NewRequest returned error: %v", err)
	}
	if got := req.Header.Get(AuthorizationHeader); got != "Bearer upstream-token" {
		t.Fatalf("upstream authorization = %q", got)
	}
	if strings.Contains(req.Header.Get(AuthorizationHeader), "downstream-token") {
		t.Fatal("downstream authorization reached upstream request")
	}
	if got := req.Header.Get("X-Downstream-Authorization"); got != "" {
		t.Fatalf("unexpected downstream header forwarded: %q", got)
	}
}

func TestBuildHeadersPreservesConfiguredValues(t *testing.T) {
	config := HeaderConfig{
		AccessToken: " access-token\t",
		AccountID:   "\taccount-123 ",
		Beta:        "\tbeta value ",
		Originator:  " originator\t",
		Version:     "\tversion ",
		SessionID:   " session\tid ",
	}

	headers, err := BuildHeaders(config)
	if err != nil {
		t.Fatalf("BuildHeaders returned error: %v", err)
	}
	want := map[string]string{
		AuthorizationHeader:   "Bearer  access-token\t",
		AccountIDHeader:       "\taccount-123 ",
		BetaHeader:            "\tbeta value ",
		OriginatorHeader:      " originator\t",
		VersionHeader:         "\tversion ",
		SessionIDHeader:       " session\tid ",
		ScopedSessionIDHeader: " session\tid ",
		"x-client-request-id": " session\tid ",
		ConversationIDHeader:  " session\tid ",
	}
	for name, expected := range want {
		if got := headers.Get(name); got != expected {
			t.Errorf("header %q = %q, want %q", name, got, expected)
		}
	}
}

func TestMapUpstreamErrorPreservesSafeRetryAndStatusData(t *testing.T) {
	headers := http.Header{
		"Retry-After":  []string{"17"},
		"X-Request-Id": []string{"req-123"},
	}
	body := []byte(`{"status":"rate_limited","error":{"code":"rate_limit_exceeded","message":"secret conversation"}}`)

	err := MapUpstreamError(http.StatusTooManyRequests, headers, body)
	if err.Category != CategoryRateLimit {
		t.Fatalf("category = %q, want %q", err.Category, CategoryRateLimit)
	}
	if err.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want %d", err.StatusCode, http.StatusTooManyRequests)
	}
	if err.ProviderStatus != "rate_limited" {
		t.Fatalf("provider status = %q, want rate_limited", err.ProviderStatus)
	}
	if err.RetryAfter != 17*time.Second {
		t.Fatalf("retry after = %s, want 17s", err.RetryAfter)
	}
	if err.RequestID != "req-123" {
		t.Fatalf("request id = %q, want req-123", err.RequestID)
	}
	if !err.IsRetryable() {
		t.Fatal("rate limit error is not retryable")
	}
	if strings.Contains(err.Error(), "secret conversation") {
		t.Fatal("private provider message reached safe error")
	}
}

const (
	wrappedWebSocketUsageLimitFixture = `{
		"type": "error",
		"status": 429,
		"error": {
			"type": "usage_limit_reached",
			"message": "The usage limit has been reached",
			"plan_type": "pro",
			"resets_at": 1738888888
		},
		"headers": {
			"x-codex-primary-used-percent": "100.0",
			"x-codex-primary-window-minutes": 15
		}
	}`
	wrappedWebSocketPolicyFixture = `{
		"type": "error",
		"status": 400,
		"error": {
			"type": "cyber_policy",
			"message": "This content was flagged for possible cybersecurity risk."
		}
	}`
	wrappedWebSocketNullOuterRetryFixture = `{
		"type": "error",
		"status": 429,
		"retry_after": null,
		"resets_at": null,
		"error": {
			"type": "rate_limit_exceeded",
			"retry_after": 17
		}
	}`
	wrappedWebSocketOuterRetryFixture = `{
		"type": "error",
		"status": 429,
		"retry_after": 5,
		"error": {
			"type": "rate_limit_exceeded",
			"retry_after": 17
		}
	}`
)

func TestMapUpstreamErrorParsesWrappedWebSocketCategories(t *testing.T) {
	tests := []struct {
		name     string
		body     string
		status   int
		category ErrorCategory
		message  string
	}{
		{"usage limit", wrappedWebSocketUsageLimitFixture, http.StatusTooManyRequests, CategoryUsageLimit, "The usage limit has been reached"},
		{"policy", wrappedWebSocketPolicyFixture, http.StatusBadRequest, CategoryPolicy, "This content was flagged for possible cybersecurity risk."},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := MapUpstreamError(test.status, nil, []byte(test.body))
			if err.Category != test.category {
				t.Fatalf("category = %q, want %q", err.Category, test.category)
			}
			if err.IsRetryable() {
				t.Fatal("wrapped error is retryable")
			}
			if strings.Contains(err.Error(), test.message) {
				t.Fatal("private provider message reached safe error")
			}
		})
	}
}

func TestMapUpstreamErrorMergesNestedRetryDataByOuterPrecedence(t *testing.T) {
	tests := []struct {
		name string
		body string
		want time.Duration
	}{
		{"nested retry after when outer is null", wrappedWebSocketNullOuterRetryFixture, 17 * time.Second},
		{"outer retry after takes precedence", wrappedWebSocketOuterRetryFixture, 5 * time.Second},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := MapUpstreamError(http.StatusTooManyRequests, nil, []byte(test.body))
			if err.RetryAfter != test.want {
				t.Fatalf("retry after = %s, want %s", err.RetryAfter, test.want)
			}
		})
	}
}

func TestMapUpstreamErrorPrefersNestedCodeOverOuterMachineValue(t *testing.T) {
	body := []byte(`{
		"type": "error",
		"code": "rate_limit_exceeded",
		"error": {
			"code": "usage_limit_reached",
			"message": "private usage limit details"
		}
	}`)

	err := MapUpstreamError(http.StatusTooManyRequests, nil, body)
	if err.Category != CategoryUsageLimit {
		t.Fatalf("category = %q, want %q", err.Category, CategoryUsageLimit)
	}
	if err.IsRetryable() {
		t.Fatal("nested usage-limit error is retryable")
	}
}

func TestMapUpstreamErrorUsesTypedCategories(t *testing.T) {
	cases := []struct {
		name     string
		status   int
		body     string
		headers  http.Header
		category ErrorCategory
		retry    bool
	}{
		{"authentication", http.StatusUnauthorized, `{"error":{"code":"token_expired"}}`, nil, CategoryAuthentication, false},
		{"generic forbidden", http.StatusForbidden, `{}`, nil, CategoryUnknown, false},
		{"forbidden auth code", http.StatusForbidden, `{"error":{"code":"invalid_api_key"}}`, nil, CategoryAuthentication, false},
		{"context", http.StatusBadRequest, `{"error":{"code":"context_length_exceeded"}}`, nil, CategoryContextWindow, false},
		{"generic entity too large", http.StatusRequestEntityTooLarge, `{}`, nil, CategoryUnknown, false},
		{"entity too large context code", http.StatusRequestEntityTooLarge, `{"error":{"code":"context_length_exceeded"}}`, nil, CategoryContextWindow, false},
		{"policy", http.StatusBadRequest, `{"error":{"code":"cyber_policy"}}`, http.Header{"Retry-After": []string{"17"}}, CategoryPolicy, false},
		{"usage limit", http.StatusTooManyRequests, `{"error":{"code":"usage_limit_reached"}}`, http.Header{"Retry-After": []string{"17"}}, CategoryUsageLimit, false},
		{"insufficient quota", http.StatusTooManyRequests, `{"error":{"code":"insufficient_quota"}}`, http.Header{"Retry-After": []string{"17"}}, CategoryUsageLimit, false},
		{"overloaded", http.StatusServiceUnavailable, `{"error":{"code":"server_is_overloaded"}}`, nil, CategoryOverloaded, true},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			err := MapUpstreamError(test.status, test.headers, []byte(test.body))
			if err.Category != test.category {
				t.Fatalf("category = %q, want %q", err.Category, test.category)
			}
			if err.IsRetryable() != test.retry {
				t.Fatalf("retryable = %t, want %t", err.IsRetryable(), test.retry)
			}
		})
	}
}

func TestMapUpstreamErrorRejectsInvalidRetryAfter(t *testing.T) {
	tests := []struct {
		name   string
		header string
		value  string
	}{
		{"negative seconds", "Retry-After", "-1"},
		{"not a number", "Retry-After", "NaN"},
		{"infinite milliseconds", "Retry-After-Ms", "Inf"},
		{"seconds overflow", "Retry-After", "1e308"},
		{"milliseconds overflow", "Retry-After-Ms", "1e308"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := MapUpstreamError(
				http.StatusTooManyRequests,
				http.Header{test.header: []string{test.value}},
				nil,
			)
			if err.RetryAfter != 0 {
				t.Fatalf("retry after = %s, want zero", err.RetryAfter)
			}
		})
	}
}
