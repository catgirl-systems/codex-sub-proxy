package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/catgirl-systems/codex-sub-proxy/internal/apikey"
	"github.com/catgirl-systems/codex-sub-proxy/internal/codex"
	"github.com/catgirl-systems/codex-sub-proxy/internal/openai"
	"github.com/kataras/iris/v12"
)

// responsesAdmission contains the request state shared by HTTP and WebSocket
// Responses turns. It is created only after authentication and policy checks.
type responsesAdmission struct {
	principal                   apikey.Principal
	publicRequest               openai.ResponseRequest
	privateRequest              codex.CodexResponseRequest
	selection                   codex.SelectionRequest
	journalRequest              JournalRequest
	continuationAccountID       string
	continuationSourceRequestID string
	sessionHash                 string
	bindAccount                 func(codex.Account) error
	lease                       *quotaLease
}

// responsesRequestError is a safe, transport-neutral request rejection. The
// caller chooses the HTTP or WebSocket representation after this point.
type responsesRequestError struct {
	status   int
	typeName string
	code     string
	message  string
	err      error
}

func (e *responsesRequestError) Error() string {
	if e == nil {
		return ""
	}
	return e.message
}

func (e *responsesRequestError) Unwrap() error { return e.err }

func newResponsesRequestError(status int, typeName, code, message string, err error) error {
	return &responsesRequestError{status: status, typeName: typeName, code: code, message: message, err: err}
}

func responsesRequestErrorFields(err error) (int, string, string, string, bool) {
	var requestErr *responsesRequestError
	if !errors.As(err, &requestErr) || requestErr == nil {
		return 0, "", "", "", false
	}
	return requestErr.status, requestErr.typeName, requestErr.code, requestErr.message, true
}

// authenticateResponsesPrincipal performs the one authentication step that
// must happen before a WebSocket handshake is accepted.
func authenticateResponsesPrincipal(ctx iris.Context, authorizer *apikey.Authorizer) (apikey.Principal, error) {
	if ctx == nil {
		return apikey.Principal{}, newResponsesRequestError(http.StatusInternalServerError, responsesServerErrorType, "internal_error", "Internal server error.", errors.New("Responses context is nil"))
	}
	if authorizer == nil {
		return apikey.Principal{}, newResponsesRequestError(http.StatusServiceUnavailable, responsesServerErrorType, "service_unavailable", "The service is unavailable.", errors.New("Responses API-key authorizer is unavailable"))
	}
	request := ctx.Request()
	headers := request.Header.Values("Authorization")
	if len(headers) != 1 {
		return apikey.Principal{}, apikey.ErrInvalidKey
	}
	principal, err := authorizer.AuthenticateHeader(request.Context(), headers[0])
	setJournalAuditPrincipal(ctx, principal.ID)
	return principal, err
}

// prepareResponsesAdmission performs current policy loading,
// continuation/affinity resolution, journal admission, and quota reservation.
// HTTP and WebSocket handlers must use this function rather than reimplementing
// those policy decisions.
func prepareResponsesAdmission(
	ctx iris.Context,
	operationContext context.Context,
	authorizer *apikey.Authorizer,
	broker UpstreamBroker,
	journal *Journal,
	quota *apikey.QuotaStore,
	publicRequest openai.ResponseRequest,
) (*responsesAdmission, error) {
	principal, err := authenticateResponsesPrincipal(ctx, authorizer)
	if err != nil {
		return nil, err
	}
	return prepareResponsesAdmissionForPrincipal(ctx, operationContext, authorizer, broker, journal, quota, publicRequest, principal)
}

func prepareResponsesAdmissionForPrincipal(
	ctx iris.Context,
	operationContext context.Context,
	authorizer *apikey.Authorizer,
	broker UpstreamBroker,
	journal *Journal,
	quota *apikey.QuotaStore,
	publicRequest openai.ResponseRequest,
	principal apikey.Principal,
) (*responsesAdmission, error) {
	if ctx == nil {
		return nil, newResponsesRequestError(http.StatusInternalServerError, responsesServerErrorType, "internal_error", "Internal server error.", errors.New("Responses context is nil"))
	}
	if operationContext == nil {
		return nil, newResponsesRequestError(http.StatusInternalServerError, responsesServerErrorType, "internal_error", "Responses operation context is nil.", errors.New("Responses operation context is nil"))
	}
	request := ctx.Request()
	requestContext := operationContext
	if authorizer == nil {
		return nil, newResponsesRequestError(http.StatusServiceUnavailable, responsesServerErrorType, "service_unavailable", "The service is unavailable.", errors.New("Responses API-key authorizer is unavailable"))
	}
	requestHeaders, err := requestHeaderConfig(request.Header)
	if err != nil {
		return nil, newResponsesRequestError(http.StatusBadRequest, responsesErrorType, "invalid_request", "The request is invalid.", err)
	}
	responsesLiteHeader := requestHeaders.ResponsesLiteRequested
	principal, err = authorizer.AuthorizePrincipal(requestContext, principal, responsesEndpoint, publicRequest.Model)
	if err != nil {
		return nil, err
	}
	if broker == nil {
		return nil, newResponsesRequestError(http.StatusServiceUnavailable, responsesServerErrorType, "upstream_unavailable", "The upstream service is unavailable.", ErrBrokerUnavailable)
	}

	journalMetadata := JournalRequestMetadata{
		Endpoint: responsesEndpoint,
		Model:    publicRequest.Model,
		APIKeyID: principal.ID,
	}
	var sessionHash, affinityAccountID, continuationSourceRequestID string
	if publicRequest.PreviousResponseID != "" {
		if journal == nil {
			return nil, newResponsesRequestError(http.StatusBadRequest, responsesErrorType, "previous_response_not_found", "The previous response was not found.", ErrPreviousResponseNotFound)
		}
		resolved, resolveErr := journal.ResolvePreviousResponse(requestContext, publicRequest.PreviousResponseID, principal.ID)
		if resolveErr != nil {
			if errors.Is(resolveErr, ErrPreviousResponseNotFound) {
				return nil, newResponsesRequestError(http.StatusBadRequest, responsesErrorType, "previous_response_not_found", "The previous response was not found.", resolveErr)
			}
			return nil, newResponsesRequestError(http.StatusInternalServerError, responsesServerErrorType, "internal_error", "Internal server error.", resolveErr)
		}
		journalMetadata.ConversationID = resolved.ConversationID
		journalMetadata.AccountID = resolved.AccountID
		journalMetadata.PreviousResponseID = publicRequest.PreviousResponseID
		continuationSourceRequestID = resolved.SourceRequestID
	} else {
		sessionHash, affinityAccountID, err = resolveSessionAffinity(requestContext, journal, principal.ID, requestHeaders)
		if err != nil {
			return nil, newResponsesRequestError(http.StatusInternalServerError, responsesServerErrorType, "internal_error", "Internal server error.", err)
		}
	}
	privateRequest, err := privateResponseRequest(publicRequest)
	if err != nil {
		return nil, newResponsesRequestError(http.StatusBadRequest, responsesErrorType, "invalid_request", "The request is invalid.", err)
	}
	if responsesLiteHeader && privateRequest.ResponsesLite {
		return nil, newResponsesRequestError(http.StatusBadRequest, responsesErrorType, "invalid_request", "The request is invalid.", errors.New("Responses Lite was requested twice"))
	}
	privateRequest.ResponsesLite = responsesLiteHeader || privateRequest.ResponsesLite
	journalInput, err := json.Marshal(publicRequest)
	if err != nil {
		return nil, newResponsesRequestError(http.StatusInternalServerError, responsesServerErrorType, "internal_error", "Internal server error.", err)
	}
	journalRequest, err := startJournalRequestWithContext(ctx, requestContext, journal, journalMetadata, journalInput)
	if err != nil {
		if errors.Is(err, ErrPreviousResponseNotFound) {
			return nil, newResponsesRequestError(http.StatusBadRequest, responsesErrorType, "previous_response_not_found", "The previous response was not found.", err)
		}
		return nil, newResponsesRequestError(http.StatusInternalServerError, responsesServerErrorType, "internal_error", "Internal server error.", err)
	}
	admission := &responsesAdmission{
		principal:                   principal,
		publicRequest:               publicRequest,
		privateRequest:              privateRequest,
		journalRequest:              journalRequest,
		sessionHash:                 sessionHash,
		continuationSourceRequestID: continuationSourceRequestID,
	}
	admission.selection = codex.SelectionRequest{
		Endpoint:           responsesEndpoint,
		Model:              publicRequest.Model,
		APIKeyID:           principal.ID,
		PreviousResponseID: publicRequest.PreviousResponseID,
		Headers:            requestHeaders,
		AffinityAccountID:  affinityAccountID,
	}
	if publicRequest.PreviousResponseID != "" {
		admission.continuationAccountID = journalRequest.AccountID
	}
	admission.bindAccount = func(account codex.Account) error {
		if journal == nil {
			return nil
		}
		return journal.BindAccount(requestContext, journalRequest.ID, account.ID, sessionAffinityHashForAccount(sessionHash, affinityAccountID, account.ID))
	}
	admission.lease, err = admitRequestQuota(requestContext, quota, principal, responseQuotaRequest(principal.Policy, publicRequest.MaxOutputTokens))
	if err != nil {
		return admission, err
	}
	return admission, nil
}

func writeResponsesRequestError(ctx iris.Context, err error) {
	if err == nil {
		return
	}
	if errors.Is(err, apikey.ErrInvalidKey) || errors.Is(err, apikey.ErrForbidden) {
		writeAPIKeyError(ctx, err)
		return
	}
	var quotaErr *apikey.QuotaError
	if errors.As(err, &quotaErr) {
		writeQuotaResponsesError(ctx, err)
		return
	}
	if status, typeName, code, message, ok := responsesRequestErrorFields(err); ok {
		writeResponsesError(ctx, status, typeName, code, message)
		return
	}
	writeResponsesError(ctx, http.StatusInternalServerError, responsesServerErrorType, "internal_error", "Internal server error.")
}
