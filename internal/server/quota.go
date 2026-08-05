package server

import (
	"context"
	"errors"
	"math"
	"net/http"
	"strconv"

	"github.com/catgirl-systems/codex-sub-proxy/internal/apikey"
	"github.com/catgirl-systems/codex-sub-proxy/internal/codex"
	"github.com/kataras/iris/v12"
)

type quotaLease struct {
	store        *apikey.QuotaStore
	id           string
	closed       bool
	successKnown bool
}

var errQuotaFinalization = errors.New("quota success finalization failed")

func admitRequestQuota(ctx context.Context, store *apikey.QuotaStore, principal apikey.Principal, request apikey.QuotaRequest) (*quotaLease, error) {
	admission, err := store.Admit(ctx, principal.ID, principal.Policy, request)
	if err != nil {
		return nil, err
	}
	if admission == nil {
		return nil, nil
	}
	return &quotaLease{store: store, id: admission.ID}, nil
}

func (lease *quotaLease) reconcile(usage apikey.QuotaUsage) error {
	if lease == nil || lease.closed {
		return nil
	}
	lease.successKnown = true
	err := lease.store.Reconcile(context.Background(), lease.id, usage)
	lease.closed = true
	if err != nil {
		return errors.Join(errQuotaFinalization, err)
	}
	return nil
}

func (lease *quotaLease) release(reason string) error {
	if lease == nil || lease.closed || lease.successKnown {
		return nil
	}
	if err := lease.store.Release(context.Background(), lease.id, reason); err != nil {
		return err
	}
	lease.closed = true
	return nil
}

func setQuotaResponseHeaders(ctx iris.Context, err error) {
	var quotaErr *apikey.QuotaError
	if !errors.As(err, &quotaErr) {
		return
	}
	seconds := int64(math.Ceil(quotaErr.RetryAfter.Seconds()))
	if seconds < 1 {
		seconds = 1
	}
	ctx.Header("Retry-After", strconv.FormatInt(seconds, 10))
	if !quotaErr.ResetAt.IsZero() {
		ctx.Header("X-RateLimit-Reset", strconv.FormatInt(quotaErr.ResetAt.Unix(), 10))
	}
}

func quotaResponseCode(err error) string {
	var quotaErr *apikey.QuotaError
	if !errors.As(err, &quotaErr) {
		return "rate_limit_exceeded"
	}
	if quotaErr.Kind == "concurrency" {
		return "concurrency_limit_exceeded"
	}
	if quotaErr.Kind == "requests" || quotaErr.Kind == "tokens" || quotaErr.Kind == "images" || quotaErr.Kind == "cost" {
		return "quota_exceeded"
	}
	return "rate_limit_exceeded"
}

func writeQuotaResponsesError(ctx iris.Context, err error) {
	setQuotaResponseHeaders(ctx, err)
	writeResponsesError(ctx, http.StatusTooManyRequests, "rate_limit_error", quotaResponseCode(err), "The API key quota or rate limit has been exceeded.")
}

func writeQuotaChatError(ctx iris.Context, err error) {
	setQuotaResponseHeaders(ctx, err)
	writeChatError(ctx, http.StatusTooManyRequests, "rate_limit_error", quotaResponseCode(err), "The API key quota or rate limit has been exceeded.")
}

func writeQuotaImagesError(ctx iris.Context, err error) {
	setQuotaResponseHeaders(ctx, err)
	writeImagesError(ctx, http.StatusTooManyRequests, quotaResponseCode(err), "The API key quota or rate limit has been exceeded.")
}

func responseQuotaRequest(policy apikey.Policy, maxOutputTokens *int) apikey.QuotaRequest {
	tokens := policy.TokenReservationDefault
	if maxOutputTokens != nil {
		tokens = int64(*maxOutputTokens)
	}
	return apikey.QuotaRequest{
		Requests:       1,
		Tokens:         tokens,
		CostMicrounits: policy.CostMicrounitReservationDefault,
	}
}

func imageQuotaRequest(policy apikey.Policy, count *int) apikey.QuotaRequest {
	images := policy.ImageReservationDefault
	if images == 0 {
		images = 1
	}
	if count != nil {
		images = int64(*count)
	}
	return apikey.QuotaRequest{
		Requests:       1,
		Images:         images,
		CostMicrounits: policy.CostMicrounitReservationDefault,
	}
}

func quotaUsageFromCodex(usage *codex.CodexUsage, images int) apikey.QuotaUsage {
	result := apikey.QuotaUsage{Requests: 1, Images: int64(images)}
	if usage != nil {
		result.Tokens = int64(usage.TotalTokens)
	}
	return result
}

func journalUsageFromCodex(usage *codex.CodexUsage, images int) JournalUsage {
	result := JournalUsage{ImageCount: int64(images)}
	if usage == nil {
		return result
	}
	result.InputTokens = int64(usage.InputTokens)
	result.OutputTokens = int64(usage.OutputTokens)
	result.TotalTokens = int64(usage.TotalTokens)
	result.CachedInputTokens = int64(usage.PromptCacheHitTokens)
	result.CachedInputTokensKnown = usage.PromptCacheHitTokens > 0
	if usage.InputTokensDetails != nil {
		result.CachedInputTokens = int64(usage.InputTokensDetails.CachedTokens)
		result.CachedInputTokensKnown = true
	}
	if usage.OutputTokensDetails != nil {
		result.ReasoningTokens = int64(usage.OutputTokensDetails.ReasoningTokens)
		result.ReasoningTokensKnown = true
	}
	return result
}

func validateQuotaUsageFromCodex(usage *codex.CodexUsage) error {
	if usage == nil {
		return nil
	}
	if usage.InputTokens < 0 || usage.OutputTokens < 0 || usage.TotalTokens < 0 || usage.PromptCacheHitTokens < 0 {
		return errors.New("upstream usage is invalid")
	}
	if usage.InputTokensDetails != nil {
		values := []int{
			usage.InputTokensDetails.CachedTokens,
			usage.InputTokensDetails.CacheWriteTokens,
			usage.InputTokensDetails.OrchestrationInputTokens,
			usage.InputTokensDetails.OrchestrationInputCachedTokens,
			usage.InputTokensDetails.ImageTokens,
			usage.InputTokensDetails.TextTokens,
		}
		for _, value := range values {
			if value < 0 {
				return errors.New("upstream usage is invalid")
			}
		}
	}
	if usage.OutputTokensDetails != nil {
		values := []int{
			usage.OutputTokensDetails.ReasoningTokens,
			usage.OutputTokensDetails.OrchestrationOutputTokens,
			usage.OutputTokensDetails.ImageTokens,
			usage.OutputTokensDetails.TextTokens,
		}
		for _, value := range values {
			if value < 0 {
				return errors.New("upstream usage is invalid")
			}
		}
	}
	return nil
}
