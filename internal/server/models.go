package server

import (
	"errors"
	"net/http"

	"github.com/catgirl-systems/codex-sub-proxy/internal/apikey"
	"github.com/catgirl-systems/codex-sub-proxy/internal/codex"
	"github.com/kataras/iris/v12"
	"gorm.io/gorm"
)

const modelsEndpoint = "/v1/models"

type modelObject struct {
	ID      string `json:"id"`
	Object  string `json:"object"`
	Created int64  `json:"created"`
	OwnedBy string `json:"owned_by"`
}

type modelsResponse struct {
	Object string        `json:"object"`
	Data   []modelObject `json:"data"`
}

func newDataApplication(readiness *Readiness, db *gorm.DB, hmacKey []byte, transport *codex.ResponsesTransport, imageClients ...*codex.ImagesClient) (*iris.Application, error) {
	app := buildHealthApplication(readiness)
	authorizer := apikey.NewAuthorizer(db, hmacKey)
	app.Get(modelsEndpoint, func(ctx iris.Context) {
		headers := ctx.Request().Header.Values("Authorization")
		if len(headers) != 1 {
			writeAPIKeyError(ctx, apikey.ErrInvalidKey)
			return
		}
		principal, err := authorizer.AuthenticateHeader(ctx.Request().Context(), headers[0])
		if err == nil {
			err = authorizer.AuthorizePrincipal(ctx.Request().Context(), principal, modelsEndpoint, "")
		}
		if err != nil {
			writeAPIKeyError(ctx, err)
			return
		}
		models := make([]modelObject, 0, len(principal.AllowedModels))
		for _, id := range principal.AllowedModels {
			models = append(models, modelObject{
				ID:      id,
				Object:  "model",
				Created: 0,
				OwnedBy: apikey.ModelOwner,
			})
		}
		writeJSON(ctx, http.StatusOK, modelsResponse{Object: "list", Data: models})
	})
	app.Any(responsesEndpoint, newResponsesHandler(authorizer, transport))
	var imagesClient *codex.ImagesClient
	if len(imageClients) > 0 {
		imagesClient = imageClients[0]
	}
	app.Any(imagesGenerationsEndpoint, newImagesGenerationHandler(authorizer, imagesClient))
	app.Any(imagesEditsEndpoint, newImagesEditHandler(authorizer, imagesClient))
	if err := app.Build(); err != nil {
		return nil, err
	}
	return app, nil
}

func writeAPIKeyError(ctx iris.Context, err error) {
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
