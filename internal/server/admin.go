package server

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/catgirl-systems/codex-sub-proxy/internal/apikey"
	"github.com/kataras/iris/v12"
	"gorm.io/gorm"
)

const (
	adminTokensEndpoint = "/admin/v1/admin-tokens"
	adminBodyLimit      = 16 * 1024
	adminPrincipalKey   = "csp-admin-principal"
)

// RequireAdminMetadata checks the principal stored after admin authentication.
func RequireAdminMetadata(ctx iris.Context) error {
	principal, ok := adminPrincipalFromContext(ctx)
	if !ok {
		return ErrAdminTokenInvalid
	}
	if !principal.HasScope(AdminScopeMetadata) {
		return ErrAdminTokenForbidden
	}
	return nil
}

// RequireAdminContent checks the content scope before a handler loads or decrypts content.
func RequireAdminContent(ctx iris.Context) error {
	principal, ok := adminPrincipalFromContext(ctx)
	if !ok {
		return ErrAdminTokenInvalid
	}
	if !principal.HasScope(AdminScopeContent) {
		return ErrAdminTokenForbidden
	}
	return nil
}

func adminPrincipalFromContext(ctx iris.Context) (AdminPrincipal, bool) {
	if ctx == nil {
		return AdminPrincipal{}, false
	}
	principal, ok := ctx.Values().Get(adminPrincipalKey).(AdminPrincipal)
	return principal, ok && principal.ID != ""
}

func setAdminPrincipal(ctx iris.Context, principal AdminPrincipal) {
	if ctx != nil {
		ctx.Values().Set(adminPrincipalKey, principal)
	}
}

func newAdminApplication(readiness *Readiness, store *AdminTokenStore, apiKeyStore *apikey.Store) (*iris.Application, error) {
	var db *gorm.DB
	if store != nil {
		db = store.db
	}
	var retention *RetentionRunner
	if db != nil {
		var err error
		retention, err = NewRetentionRunner(db, nil, RetentionConfig{})
		if err != nil {
			return nil, err
		}
	}
	return newAdminApplicationWithLifecycle(readiness, store, apiKeyStore, adminLifecycleDependencies{db: db, retention: retention})
}

func newAdminApplicationWithLifecycle(readiness *Readiness, store *AdminTokenStore, apiKeyStore *apikey.Store, lifecycle adminLifecycleDependencies) (*iris.Application, error) {
	app := buildAdminHealthApplication(readiness)
	app.Post(adminTokensEndpoint, func(ctx iris.Context) {
		principal, ok := authenticateAdminRequest(ctx, store)
		if !ok {
			return
		}
		if err := authorizeAdminScope(ctx, store, principal, AdminScopeMetadata); err != nil {
			writeAdminAuthError(ctx, err)
			return
		}
		request, err := decodeAdminTokenCreateRequest(ctx)
		if err != nil {
			writeAdminDecodeError(ctx, err, "Invalid admin token request.")
			return
		}
		raw, record, err := store.Create(ctx.Request().Context(), request, principal)
		if err != nil {
			writeAdminOperationError(ctx, err)
			return
		}
		writeJSON(ctx, http.StatusCreated, adminTokenCreateResponse{adminTokenMetadata: safeAdminTokenMetadata(record), Token: raw})
	})
	app.Get(adminTokensEndpoint, func(ctx iris.Context) {
		principal, ok := authenticateAdminRequest(ctx, store)
		if !ok {
			return
		}
		if err := authorizeAdminScope(ctx, store, principal, AdminScopeMetadata); err != nil {
			writeAdminAuthError(ctx, err)
			return
		}
		limit, offset, err := parseAdminListBounds(ctx)
		if err != nil {
			writeAdminError(ctx, http.StatusBadRequest, "Invalid admin token list bounds.")
			return
		}
		records, err := store.List(ctx.Request().Context(), limit, offset)
		if err != nil {
			writeAdminOperationError(ctx, err)
			return
		}
		if err := store.RecordListAudit(ctx.Request().Context(), principal, len(records)); err != nil {
			writeAdminOperationError(ctx, err)
			return
		}
		response := make([]adminTokenMetadata, 0, len(records))
		for _, record := range records {
			response = append(response, safeAdminTokenMetadata(record))
		}
		writeJSON(ctx, http.StatusOK, struct {
			Data []adminTokenMetadata `json:"data"`
		}{Data: response})
	})
	app.Delete(adminTokensEndpoint+"/{id:string}", func(ctx iris.Context) {
		principal, ok := authenticateAdminRequest(ctx, store)
		if !ok {
			return
		}
		if err := authorizeAdminScope(ctx, store, principal, AdminScopeMetadata); err != nil {
			writeAdminAuthError(ctx, err)
			return
		}
		record, err := store.Revoke(ctx.Request().Context(), ctx.Params().Get("id"), principal)
		if err != nil {
			writeAdminOperationError(ctx, err)
			return
		}
		writeJSON(ctx, http.StatusOK, safeAdminTokenMetadata(record))
	})
	registerAdminAPIKeyRoutes(app, store, apiKeyStore)
	registerAdminLifecycleRoutes(app, store, lifecycle)
	if err := app.Build(); err != nil {
		return nil, err
	}
	return app, nil
}

func authenticateAdminRequest(ctx iris.Context, store *AdminTokenStore) (AdminPrincipal, bool) {
	if store == nil {
		writeAdminError(ctx, http.StatusServiceUnavailable, "Administrative authentication is unavailable.")
		return AdminPrincipal{}, false
	}
	principal, err := store.AuthenticateHeaders(ctx.Request().Context(), ctx.Request().Header.Values("Authorization"))
	if err != nil {
		writeAdminAuthError(ctx, err)
		return AdminPrincipal{}, false
	}
	setAdminPrincipal(ctx, principal)
	return principal, true
}

func authorizeAdminScope(ctx iris.Context, store *AdminTokenStore, principal AdminPrincipal, scope AdminTokenScope) error {
	var err error
	if scope == AdminScopeMetadata {
		err = RequireAdminMetadata(ctx)
	} else {
		err = RequireAdminContent(ctx)
	}
	if err != nil {
		return err
	}
	if store == nil {
		return ErrAdminUnavailable
	}
	return store.Authorize(ctx.Request().Context(), principal, scope)
}

type adminTokenCreateBody struct {
	Name      string           `json:"name"`
	Scopes    AdminTokenScopes `json:"scopes"`
	ExpiresAt *time.Time       `json:"expires_at"`
}

func decodeAdminTokenCreateRequest(ctx iris.Context) (AdminTokenCreateRequest, error) {
	if ctx == nil || ctx.Request().Body == nil {
		return AdminTokenCreateRequest{}, errors.New("admin token request body is missing")
	}
	ctx.Request().Body = http.MaxBytesReader(ctx.ResponseWriter(), ctx.Request().Body, adminBodyLimit)
	decoder := json.NewDecoder(ctx.Request().Body)
	decoder.DisallowUnknownFields()
	var body adminTokenCreateBody
	if err := decoder.Decode(&body); err != nil {
		return AdminTokenCreateRequest{}, err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return AdminTokenCreateRequest{}, errors.New("admin token request has trailing JSON")
		}
		return AdminTokenCreateRequest{}, err
	}
	return AdminTokenCreateRequest(body), nil
}

func parseAdminListBounds(ctx iris.Context) (int, int, error) {
	limit := 100
	offset := 0
	for key, destination := range map[string]*int{"limit": &limit, "offset": &offset} {
		value := ctx.URLParam(key)
		if value == "" {
			continue
		}
		parsed, err := strconv.Atoi(value)
		if err != nil {
			return 0, 0, err
		}
		*destination = parsed
	}
	if limit <= 0 || limit > maxAdminListLimit || offset < 0 || offset > maxAdminListOffset {
		return 0, 0, errors.New("admin token list bounds are invalid")
	}
	return limit, offset, nil
}

type adminTokenMetadata struct {
	ID         string           `json:"id"`
	Name       string           `json:"name"`
	Prefix     string           `json:"prefix"`
	Scopes     AdminTokenScopes `json:"scopes"`
	CreatedAt  time.Time        `json:"created_at"`
	ExpiresAt  *time.Time       `json:"expires_at,omitempty"`
	RevokedAt  *time.Time       `json:"revoked_at,omitempty"`
	LastUsedAt *time.Time       `json:"last_used_at,omitempty"`
	CreatedBy  string           `json:"created_by"`
	RevokedBy  string           `json:"revoked_by,omitempty"`
	Bootstrap  bool             `json:"bootstrap"`
}

type adminTokenCreateResponse struct {
	adminTokenMetadata
	Token string `json:"token"`
}

func safeAdminTokenMetadata(record AdminToken) adminTokenMetadata {
	return adminTokenMetadata{
		ID:         record.ID,
		Name:       record.Name,
		Prefix:     record.Prefix,
		Scopes:     append(AdminTokenScopes(nil), record.Scopes...),
		CreatedAt:  record.CreatedAt,
		ExpiresAt:  record.ExpiresAt,
		RevokedAt:  record.RevokedAt,
		LastUsedAt: record.LastUsedAt,
		CreatedBy:  record.CreatedBy,
		RevokedBy:  record.RevokedBy,
		Bootstrap:  record.Bootstrap,
	}
}

func writeAdminDecodeError(ctx iris.Context, err error, invalidMessage string) {
	var maxBytesError *http.MaxBytesError
	if errors.As(err, &maxBytesError) {
		writeAdminErrorCode(ctx, http.StatusRequestEntityTooLarge, "Request body is too large.", "request_too_large")
		return
	}
	writeAdminError(ctx, http.StatusBadRequest, invalidMessage)
}

func writeAdminAuthError(ctx iris.Context, err error) {
	if errors.Is(err, ErrAdminUnavailable) {
		writeAdminError(ctx, http.StatusServiceUnavailable, "Administrative authentication is unavailable.")
		return
	}
	if errors.Is(err, ErrAdminTokenForbidden) {
		writeAdminError(ctx, http.StatusForbidden, "The admin token does not have the required scope.")
		return
	}
	if !errors.Is(err, ErrAdminTokenInvalid) {
		writeAdminError(ctx, http.StatusInternalServerError, "Internal server error.")
		return
	}
	ctx.Header("WWW-Authenticate", "Bearer")
	writeAdminError(ctx, http.StatusUnauthorized, "Incorrect admin token provided.")
}
func writeAdminOperationError(ctx iris.Context, err error) {
	switch {
	case errors.Is(err, apikey.ErrUnavailable):
		writeAdminError(ctx, http.StatusServiceUnavailable, "API-key management is unavailable.")
	case errors.Is(err, apikey.ErrInvalidExpiry):
		writeAdminError(ctx, http.StatusBadRequest, "Invalid API key request.")
	case errors.Is(err, errAdminAPIKeyNotFound):
		writeAdminError(ctx, http.StatusNotFound, "API key not found.")
	case errors.Is(err, errAdminAPIKeyRequest):
		writeAdminError(ctx, http.StatusBadRequest, "Invalid API key request.")
	case errors.Is(err, ErrAdminUnavailable):
		writeAdminError(ctx, http.StatusServiceUnavailable, "Administrative authentication is unavailable.")
	case errors.Is(err, ErrAdminTokenNotFound):
		writeAdminError(ctx, http.StatusNotFound, "Admin token not found.")
	case errors.Is(err, ErrAdminTokenNameTaken):
		writeAdminError(ctx, http.StatusConflict, "An admin token with that name already exists.")
	case errors.Is(err, ErrAdminTokenForbidden):
		writeAdminError(ctx, http.StatusForbidden, "The admin token does not have the required scope.")
	case errors.Is(err, ErrAdminTokenRequest):
		writeAdminError(ctx, http.StatusBadRequest, "Invalid admin token request.")
	default:
		writeAdminError(ctx, http.StatusInternalServerError, "Internal server error.")
	}
}

func writeAdminError(ctx iris.Context, status int, message string) {
	writeAdminErrorCode(ctx, status, message, "admin_request_failed")
}

func writeAdminErrorCode(ctx iris.Context, status int, message, code string) {
	writeJSON(ctx, status, struct {
		Error struct {
			Message string `json:"message"`
			Type    string `json:"type"`
			Code    string `json:"code"`
		} `json:"error"`
	}{Error: struct {
		Message string `json:"message"`
		Type    string `json:"type"`
		Code    string `json:"code"`
	}{Message: message, Type: "admin_error", Code: code}})
}
