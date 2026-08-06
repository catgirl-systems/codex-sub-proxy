package server

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/catgirl-systems/codex-sub-proxy/internal/apikey"
	"github.com/catgirl-systems/codex-sub-proxy/internal/codex"
	"github.com/catgirl-systems/codex-sub-proxy/internal/openai"
	"github.com/kataras/iris/v12"
	"gorm.io/gorm"
)

const modelsEndpoint = "/v1/models"

type modelObject struct {
	ID            string                  `json:"id"`
	Object        string                  `json:"object"`
	Created       int64                   `json:"created"`
	OwnedBy       string                  `json:"owned_by"`
	DisplayName   string                  `json:"display_name,omitempty"`
	Description   string                  `json:"description,omitempty"`
	ContextWindow int64                   `json:"context_window,omitempty"`
	MaxOutput     int64                   `json:"max_output_tokens,omitempty"`
	Capabilities  codex.ModelCapabilities `json:"capabilities,omitempty"`
	ModelMessages json.RawMessage         `json:"model_messages,omitempty"`
}

type modelsResponse struct {
	Object string            `json:"object"`
	Data   []modelObject     `json:"data"`
	Models []codex.ModelInfo `json:"models"`
}

func newDataApplication(readiness *Readiness, db *gorm.DB, hmacKey []byte, broker UpstreamBroker, journal *Journal, quota *apikey.QuotaStore, artifacts *ArtifactStore, artifactRequired bool, policy applicationPolicy) (*iris.Application, error) {
	app := buildHealthApplication(readiness)
	authorizer := apikey.NewAuthorizer(db, hmacKey)
	unavailable := func(ctx iris.Context) {
		writeJSON(ctx, http.StatusServiceUnavailable, openai.ErrorResponse{Error: openai.Error{
			Type: "server_error", Code: "service_unavailable", Message: "The service is unavailable.",
		}})
	}
	var catalog *ModelCatalogManager
	if provider, ok := broker.(interface{ ModelCatalog() *ModelCatalogManager }); ok {
		catalog = provider.ModelCatalog()
	}
	if authorizer != nil {
		app.Get(modelsEndpoint, func(ctx iris.Context) {
			setJournalAuditContext(ctx, journal, modelsEndpoint)
			headers := ctx.Request().Header.Values("Authorization")
			if len(headers) != 1 {
				writeAPIKeyError(ctx, apikey.ErrInvalidKey)
				return
			}
			principal, err := authorizer.AuthenticateHeader(ctx.Request().Context(), headers[0])
			if err == nil {
				setJournalAuditPrincipal(ctx, principal.ID)
				principal, err = authorizer.AuthorizePrincipal(ctx.Request().Context(), principal, modelsEndpoint, "")
			}
			if err != nil {
				writeAPIKeyError(ctx, err)
				return
			}
			if catalog == nil {
				unavailable(ctx)
				return
			}
			models, fullModels, ready := catalog.PublicModels(principal.AllowedModels)
			if !ready {
				unavailable(ctx)
				return
			}
			etag := modelCatalogETag(fullModels)
			ctx.Header("ETag", etag)
			if modelETagMatches(ctx.Request().Header.Get("If-None-Match"), etag) {
				ctx.StatusCode(http.StatusNotModified)
				return
			}
			writeJSON(ctx, http.StatusOK, modelsResponse{Object: "list", Data: models, Models: fullModels})
		})
	} else {
		app.Any(modelsEndpoint, unavailable)
	}
	if authorizer != nil && broker != nil && quota != nil {
		app.Any(chatCompletionsEndpoint, newChatCompletionsHandler(authorizer, broker, journal, quota))
	} else {
		app.Any(chatCompletionsEndpoint, unavailable)
	}
	if authorizer != nil && broker != nil && quota != nil {
		app.Post(responsesEndpoint, newResponsesHandler(authorizer, broker, journal, quota, artifacts, artifactRequired))
		app.Get(responsesEndpoint, newResponsesWebSocketHandler(authorizer, broker, journal, quota, artifacts, artifactRequired, policy.allowedOrigins))
	} else {
		app.Any(responsesEndpoint, unavailable)
	}
	if authorizer != nil && broker != nil && quota != nil {
		app.Any(responsesCompactEndpoint, newResponsesCompactHandler(authorizer, broker, journal, quota))
	} else {
		app.Any(responsesCompactEndpoint, unavailable)
	}
	if authorizer != nil && quota != nil {
		app.Any(imagesGenerationsEndpoint, newImagesGenerationHandler(authorizer, broker, journal, quota, artifacts, artifactRequired))
		app.Any(imagesEditsEndpoint, newImagesEditHandler(authorizer, broker, journal, quota, artifacts, artifactRequired))
	} else {
		app.Any(imagesGenerationsEndpoint, unavailable)
		app.Any(imagesEditsEndpoint, unavailable)
	}
	if err := installApplicationMiddleware(app, policy); err != nil {
		return nil, err
	}
	if err := app.Build(); err != nil {
		return nil, err
	}
	return app, nil
}

func writeAPIKeyError(ctx iris.Context, err error) {
	recordJournalRejection(ctx, http.StatusUnauthorized, "audit.rejected.auth")
	status := http.StatusInternalServerError
	message := "Internal server error."
	typeName := "server_error"
	code := "internal_error"
	if errors.Is(err, apikey.ErrInvalidKey) {
		status = http.StatusUnauthorized
		message = "Incorrect API key provided."
		typeName = "invalid_request_error"
		code = "invalid_api_key"
		ctx.Header("WWW-Authenticate", "Bearer")
	} else if errors.Is(err, apikey.ErrForbidden) {
		status = http.StatusForbidden
		message = "The API key does not have permission to access this resource."
		typeName = "permission_error"
		code = "insufficient_permissions"
	}
	setRequestError(ctx, errorClassForStatus(status), code)
	writeJSON(ctx, status, struct {
		Error struct {
			Message string  `json:"message"`
			Type    string  `json:"type"`
			Param   *string `json:"param"`
			Code    string  `json:"code"`
		} `json:"error"`
	}{Error: struct {
		Message string  `json:"message"`
		Type    string  `json:"type"`
		Param   *string `json:"param"`
		Code    string  `json:"code"`
	}{Message: message, Type: typeName, Code: code}})
}
