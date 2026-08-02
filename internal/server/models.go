package server

import (
	"errors"
	"net/http"
	"sort"

	"github.com/catgirl-systems/codex-sub-proxy/internal/apikey"
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

func newDataApplication(readiness *Readiness, db *gorm.DB, hmacKey []byte) (*iris.Application, error) {
	app := buildHealthApplication(readiness)
	authorizer := apikey.NewAuthorizer(db, hmacKey)
	app.Get(modelsEndpoint, func(ctx iris.Context) {
		headers := ctx.Request().Header.Values("Authorization")
		if len(headers) != 1 {
			writeAPIKeyError(ctx, apikey.ErrInvalidKey)
			return
		}
		principal, err := authorizer.AuthorizeHeader(ctx.Request().Context(), headers[0], modelsEndpoint, "")
		if err != nil {
			writeAPIKeyError(ctx, err)
			return
		}
		modelIDs := uniqueSorted(principal.AllowedModels)
		models := make([]modelObject, 0, len(modelIDs))
		for _, id := range modelIDs {
			models = append(models, modelObject{
				ID:      id,
				Object:  "model",
				Created: 0,
				OwnedBy: apikey.ModelOwner,
			})
		}
		writeJSON(ctx, http.StatusOK, modelsResponse{Object: "list", Data: models})
	})
	if err := app.Build(); err != nil {
		return nil, err
	}
	return app, nil
}

func uniqueSorted(values []string) []string {
	result := append([]string(nil), values...)
	sort.Strings(result)
	if len(result) < 2 {
		return result
	}
	write := 1
	for read := 1; read < len(result); read++ {
		if result[read] == result[write-1] {
			continue
		}
		result[write] = result[read]
		write++
	}
	return result[:write]
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
