package codex

import (
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// ErrorCategory is the safe category exposed to callers for a Codex failure.
type ErrorCategory string

const (
	CategoryAuthentication ErrorCategory = "authentication"
	CategoryInvalidRequest ErrorCategory = "invalid_request"
	CategoryContextWindow  ErrorCategory = "context_window"
	CategoryUsageLimit     ErrorCategory = "usage_limit"
	CategoryRateLimit      ErrorCategory = "rate_limit"
	CategoryPolicy         ErrorCategory = "policy"
	CategoryOverloaded     ErrorCategory = "server_overloaded"
	CategoryServer         ErrorCategory = "server"
	CategoryTransport      ErrorCategory = "transport"
	CategoryUnknown        ErrorCategory = "unknown"
)

// SafeError contains provider status and retry data without exposing the private error body.
type SafeError struct {
	Category       ErrorCategory
	StatusCode     int
	ProviderStatus string
	Message        string
	RetryAfter     time.Duration
	RequestID      string
	Retryable      bool
}

func (e *SafeError) Error() string {
	if e == nil {
		return "codex error"
	}
	if e.StatusCode > 0 {
		return fmt.Sprintf("%s (status %d)", e.Message, e.StatusCode)
	}
	return e.Message
}

// IsRetryable reports whether the upstream failure can be retried.
func (e *SafeError) IsRetryable() bool {
	return e != nil && e.Retryable
}

// MapUpstreamError maps a private Codex response to a safe typed error.
// The body is parsed only for a machine code, provider status, and retry data.
func MapUpstreamError(status int, headers http.Header, body []byte) *SafeError {
	if len(body) > maxErrorBodyBytes {
		body = body[:maxErrorBodyBytes]
	}
	detail := parseErrorDetail(body)
	category := classifyError(status, detail.Code)

	message := "upstream request failed"
	switch category {
	case CategoryAuthentication:
		message = "upstream authentication failed"
	case CategoryInvalidRequest:
		message = "upstream rejected the request"
	case CategoryContextWindow:
		message = "upstream context window exceeded"
	case CategoryUsageLimit:
		message = "upstream usage limit reached"
	case CategoryRateLimit:
		message = "upstream rate limit reached"
	case CategoryPolicy:
		message = "upstream request blocked by policy"
	case CategoryOverloaded:
		message = "upstream server is overloaded"
	case CategoryServer:
		message = "upstream server error"
	case CategoryTransport:
		message = "upstream transport failed"
	}

	retryAfter := retryAfter(headers, detail)
	requestID := strings.TrimSpace(headers.Get("X-Request-Id"))
	if requestID == "" {
		requestID = strings.TrimSpace(headers.Get("X-Oai-Request-Id"))
	}
	if requestID == "" {
		requestID = strings.TrimSpace(headers.Get("Request-Id"))
	}

	return &SafeError{
		Category:       category,
		StatusCode:     status,
		ProviderStatus: detail.Status,
		Message:        message,
		RetryAfter:     retryAfter,
		RequestID:      requestID,
		Retryable:      retryable(status, category, retryAfter),
	}
}

const maxErrorBodyBytes = 64 * 1024

type errorDetail struct {
	Code       string
	Status     string
	RetryAfter time.Duration
	RetryAt    time.Time
}

func parseErrorDetail(body []byte) errorDetail {
	var envelope struct {
		Code       string          `json:"code"`
		Type       string          `json:"type"`
		Status     json.RawMessage `json:"status"`
		RetryAfter json.RawMessage `json:"retry_after"`
		ResetsAt   json.RawMessage `json:"resets_at"`
		Error      json.RawMessage `json:"error"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		return errorDetail{}
	}

	detail := errorDetail{}
	var status string
	if json.Unmarshal(envelope.Status, &status) == nil {
		detail.Status = strings.TrimSpace(status)
	}

	if len(envelope.Error) > 0 && string(envelope.Error) != "null" {
		var nested struct {
			Code       string          `json:"code"`
			Type       string          `json:"type"`
			Status     json.RawMessage `json:"status"`
			RetryAfter json.RawMessage `json:"retry_after"`
			ResetsAt   json.RawMessage `json:"resets_at"`
		}
		if json.Unmarshal(envelope.Error, &nested) == nil {
			detail.Code = firstErrorCode(nested.Code, nested.Type)
			if detail.Status == "" {
				var nestedStatus string
				if json.Unmarshal(nested.Status, &nestedStatus) == nil {
					detail.Status = strings.TrimSpace(nestedStatus)
				}
			}
			if len(envelope.RetryAfter) == 0 {
				envelope.RetryAfter = nested.RetryAfter
			}
			if len(envelope.ResetsAt) == 0 {
				envelope.ResetsAt = nested.ResetsAt
			}
		}
	}
	if detail.Code == "" {
		detail.Code = firstErrorCode(envelope.Code, envelope.Type)
	}

	if len(envelope.RetryAfter) > 0 && string(envelope.RetryAfter) != "null" {
		var seconds float64
		if json.Unmarshal(envelope.RetryAfter, &seconds) == nil &&
			!math.IsNaN(seconds) &&
			!math.IsInf(seconds, 0) &&
			seconds >= 0 {
			nanoseconds := seconds * float64(time.Second)
			if nanoseconds < float64(math.MaxInt64) {
				detail.RetryAfter = time.Duration(nanoseconds)
				return detail
			}
		}
	}
	if len(envelope.ResetsAt) > 0 && string(envelope.ResetsAt) != "null" {
		var seconds int64
		if json.Unmarshal(envelope.ResetsAt, &seconds) == nil && seconds > 0 {
			detail.RetryAt = time.Unix(seconds, 0)
			if delay := time.Until(detail.RetryAt); delay > 0 {
				detail.RetryAfter = delay
			}
		}
	}
	return detail
}

func firstErrorCode(code, typ string) string {
	if code = strings.TrimSpace(code); code != "" {
		return code
	}
	if typ = strings.TrimSpace(typ); typ != "" && !strings.EqualFold(typ, "error") {
		return typ
	}
	return ""
}

func classifyError(status int, code string) ErrorCategory {
	code = strings.ToLower(strings.TrimSpace(code))
	switch {
	case status == http.StatusUnauthorized:
		return CategoryAuthentication
	case code == "token_expired" || code == "invalid_api_key" || code == "unauthorized" ||
		code == "authentication_error" || code == "missing_authorization_header":
		return CategoryAuthentication
	case code == "context_length_exceeded" || code == "context_window_exceeded":
		return CategoryContextWindow
	case code == "cyber_policy":
		return CategoryPolicy
	case code == "usage_limit_reached" || code == "usage_not_included" ||
		code == "insufficient_quota":
		return CategoryUsageLimit
	case code == "rate_limit_exceeded" || status == http.StatusTooManyRequests:
		return CategoryRateLimit
	case code == "server_is_overloaded" || code == "slow_down":
		return CategoryOverloaded
	case status == http.StatusBadRequest || status == http.StatusUnprocessableEntity:
		return CategoryInvalidRequest
	case status >= 500 && status <= 599:
		return CategoryServer
	case status >= 400 && status <= 499:
		return CategoryUnknown
	default:
		return CategoryUnknown
	}
}

func retryAfter(headers http.Header, detail errorDetail) time.Duration {
	if value := strings.TrimSpace(headers.Get("Retry-After-Ms")); value != "" {
		if milliseconds, err := strconv.ParseFloat(value, 64); err == nil &&
			!math.IsNaN(milliseconds) &&
			!math.IsInf(milliseconds, 0) &&
			milliseconds >= 0 {
			nanoseconds := milliseconds * float64(time.Millisecond)
			if nanoseconds < float64(math.MaxInt64) {
				return time.Duration(nanoseconds)
			}
		}
	}
	if value := strings.TrimSpace(headers.Get("Retry-After")); value != "" {
		if seconds, err := strconv.ParseFloat(value, 64); err == nil &&
			!math.IsNaN(seconds) &&
			!math.IsInf(seconds, 0) &&
			seconds >= 0 {
			nanoseconds := seconds * float64(time.Second)
			if nanoseconds < float64(math.MaxInt64) {
				return time.Duration(nanoseconds)
			}
		}
		if retryAt, err := http.ParseTime(value); err == nil {
			if delay := time.Until(retryAt); delay > 0 {
				return delay
			}
		}
	}
	if detail.RetryAfter > 0 {
		return detail.RetryAfter
	}
	if !detail.RetryAt.IsZero() {
		if delay := time.Until(detail.RetryAt); delay > 0 {
			return delay
		}
	}
	return 0
}

func retryable(status int, category ErrorCategory, _ time.Duration) bool {
	switch category {
	case CategoryAuthentication, CategoryInvalidRequest, CategoryContextWindow,
		CategoryUsageLimit, CategoryPolicy:
		return false
	case CategoryRateLimit, CategoryOverloaded, CategoryTransport:
		return true
	}
	return status == http.StatusRequestTimeout || status == http.StatusTooManyRequests ||
		(status >= 500 && status <= 599)
}
