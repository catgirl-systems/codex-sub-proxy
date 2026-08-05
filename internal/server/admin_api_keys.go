package server

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/catgirl-systems/codex-sub-proxy/internal/apikey"
	"github.com/kataras/iris/v12"
	"gorm.io/gorm"
)

const (
	adminAPIKeysEndpoint = "/admin/v1/api-keys"
	adminAPIKeyListLimit = 50
	adminAPIKeyMaxLimit  = 100
	adminAPIKeyMaxCursor = 256
)

var (
	errAdminAPIKeyRequest  = errors.New("invalid API key request")
	errAdminAPIKeyNotFound = errors.New("API key not found")
)

type adminAPIKeyPolicy struct {
	AllowedEndpoints                []string      `json:"allowed_endpoints"`
	AllowedModels                   []string      `json:"allowed_models"`
	ExpiresAt                       *time.Time    `json:"expires_at,omitempty"`
	MaxConcurrentRequests           int64         `json:"max_concurrent_requests"`
	RollingRequestCount             int64         `json:"rolling_request_count"`
	RollingRequestWindow            time.Duration `json:"rolling_request_window"`
	PeriodRequestLimit              int64         `json:"period_request_limit"`
	PeriodTokenLimit                int64         `json:"period_token_limit"`
	PeriodImageLimit                int64         `json:"period_image_limit"`
	PeriodCostMicrounitLimit        int64         `json:"period_cost_microunit_limit"`
	PeriodDuration                  time.Duration `json:"period_duration"`
	TokenReservationDefault         int64         `json:"token_reservation_default"`
	TokenReservationCeiling         int64         `json:"token_reservation_ceiling"`
	ImageReservationDefault         int64         `json:"image_reservation_default"`
	ImageReservationCeiling         int64         `json:"image_reservation_ceiling"`
	CostMicrounitReservationDefault int64         `json:"cost_microunit_reservation_default"`
	CostMicrounitReservationCeiling int64         `json:"cost_microunit_reservation_ceiling"`
}

func (policy *adminAPIKeyPolicy) UnmarshalJSON(data []byte) error {
	if policy == nil {
		return errors.New("API key policy destination is nil")
	}
	if bytes.Equal(bytes.TrimSpace(data), []byte("null")) {
		return errors.New("API key policy is null")
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return err
	}
	for _, name := range []string{
		"allowed_endpoints", "allowed_models",
		"max_concurrent_requests", "rolling_request_count", "rolling_request_window",
		"period_request_limit", "period_token_limit", "period_image_limit", "period_cost_microunit_limit",
		"period_duration", "token_reservation_default", "token_reservation_ceiling",
		"image_reservation_default", "image_reservation_ceiling",
		"cost_microunit_reservation_default", "cost_microunit_reservation_ceiling",
	} {
		if value, ok := fields[name]; ok && bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return fmt.Errorf("API key policy field %q is null", name)
		}
	}
	type policyAlias adminAPIKeyPolicy
	var decoded policyAlias
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&decoded); err != nil {
		return err
	}
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); err != io.EOF {
		return errors.New("API key policy has trailing JSON")
	}
	*policy = adminAPIKeyPolicy(decoded)
	return nil
}

func (policy adminAPIKeyPolicy) toPolicy(name, owner string) (apikey.Policy, error) {
	if strings.TrimSpace(name) == "" || strings.TrimSpace(owner) == "" {
		return apikey.Policy{}, fmt.Errorf("%w: name and owner are required", errAdminAPIKeyRequest)
	}
	if len(policy.AllowedEndpoints) == 0 {
		return apikey.Policy{}, fmt.Errorf("%w: endpoint allowlist is required", errAdminAPIKeyRequest)
	}
	converted := apikey.Policy{
		Name:                            name,
		Owner:                           owner,
		AllowedEndpoints:                append([]string{}, policy.AllowedEndpoints...),
		AllowedModels:                   append([]string{}, policy.AllowedModels...),
		ExpiresAt:                       policy.ExpiresAt,
		MaxConcurrentRequests:           policy.MaxConcurrentRequests,
		RollingRequestCount:             policy.RollingRequestCount,
		RollingRequestWindow:            policy.RollingRequestWindow,
		PeriodRequestLimit:              policy.PeriodRequestLimit,
		PeriodTokenLimit:                policy.PeriodTokenLimit,
		PeriodImageLimit:                policy.PeriodImageLimit,
		PeriodCostMicrounitLimit:        policy.PeriodCostMicrounitLimit,
		PeriodDuration:                  policy.PeriodDuration,
		TokenReservationDefault:         policy.TokenReservationDefault,
		TokenReservationCeiling:         policy.TokenReservationCeiling,
		ImageReservationDefault:         policy.ImageReservationDefault,
		ImageReservationCeiling:         policy.ImageReservationCeiling,
		CostMicrounitReservationDefault: policy.CostMicrounitReservationDefault,
		CostMicrounitReservationCeiling: policy.CostMicrounitReservationCeiling,
	}
	if err := apikey.ValidatePolicy(converted); err != nil {
		return apikey.Policy{}, fmt.Errorf("%w: %v", errAdminAPIKeyRequest, err)
	}
	return converted, nil
}

func adminAPIKeyPolicyFromRecord(record apikey.Record) (adminAPIKeyPolicy, error) {
	policy, err := record.Policy()
	if err != nil {
		return adminAPIKeyPolicy{}, err
	}
	return adminAPIKeyPolicyFromPolicy(policy), nil
}

func adminAPIKeyPolicyFromPolicy(policy apikey.Policy) adminAPIKeyPolicy {
	return adminAPIKeyPolicy{
		AllowedEndpoints:                append([]string{}, policy.AllowedEndpoints...),
		AllowedModels:                   append([]string{}, policy.AllowedModels...),
		ExpiresAt:                       policy.ExpiresAt,
		MaxConcurrentRequests:           policy.MaxConcurrentRequests,
		RollingRequestCount:             policy.RollingRequestCount,
		RollingRequestWindow:            policy.RollingRequestWindow,
		PeriodRequestLimit:              policy.PeriodRequestLimit,
		PeriodTokenLimit:                policy.PeriodTokenLimit,
		PeriodImageLimit:                policy.PeriodImageLimit,
		PeriodCostMicrounitLimit:        policy.PeriodCostMicrounitLimit,
		PeriodDuration:                  policy.PeriodDuration,
		TokenReservationDefault:         policy.TokenReservationDefault,
		TokenReservationCeiling:         policy.TokenReservationCeiling,
		ImageReservationDefault:         policy.ImageReservationDefault,
		ImageReservationCeiling:         policy.ImageReservationCeiling,
		CostMicrounitReservationDefault: policy.CostMicrounitReservationDefault,
		CostMicrounitReservationCeiling: policy.CostMicrounitReservationCeiling,
	}
}

func adminAPIKeyPolicyUpdates(policy apikey.Policy) map[string]any {
	return map[string]any{
		"allowed_endpoints":                  apikey.StringList(append([]string{}, policy.AllowedEndpoints...)),
		"allowed_models":                     apikey.StringList(append([]string{}, policy.AllowedModels...)),
		"expires_at":                         policy.ExpiresAt,
		"max_concurrent_requests":            policy.MaxConcurrentRequests,
		"rolling_request_count":              policy.RollingRequestCount,
		"rolling_request_window":             int64(policy.RollingRequestWindow),
		"period_request_limit":               policy.PeriodRequestLimit,
		"period_token_limit":                 policy.PeriodTokenLimit,
		"period_image_limit":                 policy.PeriodImageLimit,
		"period_cost_microunit_limit":        policy.PeriodCostMicrounitLimit,
		"period_duration":                    int64(policy.PeriodDuration),
		"token_reservation_default":          policy.TokenReservationDefault,
		"token_reservation_ceiling":          policy.TokenReservationCeiling,
		"image_reservation_default":          policy.ImageReservationDefault,
		"image_reservation_ceiling":          policy.ImageReservationCeiling,
		"cost_microunit_reservation_default": policy.CostMicrounitReservationDefault,
		"cost_microunit_reservation_ceiling": policy.CostMicrounitReservationCeiling,
	}
}

type adminAPIKeyMetadata struct {
	ID         string            `json:"id"`
	Name       string            `json:"name"`
	Owner      string            `json:"owner"`
	Prefix     string            `json:"prefix"`
	Policy     adminAPIKeyPolicy `json:"policy"`
	CreatedAt  time.Time         `json:"created_at"`
	Disabled   bool              `json:"disabled"`
	DisabledAt *time.Time        `json:"disabled_at,omitempty"`
	RevokedAt  *time.Time        `json:"revoked_at,omitempty"`
	RevokedBy  string            `json:"revoked_by,omitempty"`
	LastUsedAt *time.Time        `json:"last_used_at,omitempty"`
}

type adminAPIKeyIssueResponse struct {
	adminAPIKeyMetadata
	Key string `json:"key"`
}

func safeAdminAPIKeyMetadata(record apikey.Record) (adminAPIKeyMetadata, error) {
	policy, err := adminAPIKeyPolicyFromRecord(record)
	if err != nil {
		return adminAPIKeyMetadata{}, err
	}
	return adminAPIKeyMetadata{
		ID:         record.ID,
		Name:       record.Name,
		Owner:      record.Owner,
		Prefix:     record.Prefix,
		Policy:     policy,
		CreatedAt:  record.CreatedAt,
		Disabled:   record.DisabledAt != nil,
		DisabledAt: record.DisabledAt,
		RevokedAt:  record.RevokedAt,
		RevokedBy:  record.RevokedBy,
		LastUsedAt: record.LastUsedAt,
	}, nil
}

type adminAPIKeyIssueBody struct {
	Name   string            `json:"name"`
	Owner  string            `json:"owner"`
	Policy adminAPIKeyPolicy `json:"policy"`
}

type adminAPIKeyPatchBody struct {
	Name     json.RawMessage `json:"name"`
	Owner    json.RawMessage `json:"owner"`
	Disabled json.RawMessage `json:"disabled"`
	Policy   json.RawMessage `json:"policy"`
}

func (body adminAPIKeyPatchBody) empty() bool {
	return len(body.Name) == 0 && len(body.Owner) == 0 && len(body.Disabled) == 0 && len(body.Policy) == 0
}

func decodeAdminAPIKeyBody(ctx iris.Context, destination any) error {
	if ctx == nil || ctx.Request().Body == nil {
		return errors.New("API key request body is missing")
	}
	if ctx.Request().ContentLength > adminBodyLimit {
		return &http.MaxBytesError{Limit: adminBodyLimit}
	}
	ctx.Request().Body = http.MaxBytesReader(ctx.ResponseWriter(), ctx.Request().Body, adminBodyLimit)
	decoder := json.NewDecoder(ctx.Request().Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return errors.New("API key request has trailing JSON")
		}
		return err
	}
	return nil
}

func parseAdminAPIKeyString(raw json.RawMessage, field string) (string, error) {
	if len(raw) == 0 || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return "", fmt.Errorf("%w: %s is required", errAdminAPIKeyRequest, field)
	}
	var value string
	if err := json.Unmarshal(raw, &value); err != nil {
		return "", fmt.Errorf("%w: %s is invalid", errAdminAPIKeyRequest, field)
	}
	if strings.TrimSpace(value) == "" || len(value) > 255 {
		return "", fmt.Errorf("%w: %s is outside the supported range", errAdminAPIKeyRequest, field)
	}
	return value, nil
}

func parseAdminAPIKeyBool(raw json.RawMessage, field string) (bool, error) {
	if len(raw) == 0 || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return false, fmt.Errorf("%w: %s is required", errAdminAPIKeyRequest, field)
	}
	var value bool
	if err := json.Unmarshal(raw, &value); err != nil {
		return false, fmt.Errorf("%w: %s is invalid", errAdminAPIKeyRequest, field)
	}
	return value, nil
}

func decodeAdminAPIKeyPolicy(raw json.RawMessage, name, owner string) (apikey.Policy, error) {
	if len(raw) == 0 || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return apikey.Policy{}, fmt.Errorf("%w: policy is required", errAdminAPIKeyRequest)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var policy adminAPIKeyPolicy
	if err := decoder.Decode(&policy); err != nil {
		return apikey.Policy{}, fmt.Errorf("%w: policy is invalid", errAdminAPIKeyRequest)
	}
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); err != io.EOF {
		return apikey.Policy{}, fmt.Errorf("%w: policy is invalid", errAdminAPIKeyRequest)
	}
	return policy.toPolicy(name, owner)
}

func registerAdminAPIKeyRoutes(app *iris.Application, adminStore *AdminTokenStore, store *apikey.Store) {
	app.Post(adminAPIKeysEndpoint, func(ctx iris.Context) {
		principal, ok := authenticateAdminRequest(ctx, adminStore)
		if !ok {
			return
		}
		if err := authorizeAdminScope(ctx, adminStore, principal, AdminScopeMetadata); err != nil {
			writeAdminAuthError(ctx, err)
			return
		}
		var body adminAPIKeyIssueBody
		if err := decodeAdminAPIKeyBody(ctx, &body); err != nil {
			writeAdminDecodeError(ctx, err, "Invalid API key request.")
			return
		}
		if err := validateAdminAPIKeyText(body.Name, "name"); err != nil {
			writeAdminOperationError(ctx, err)
			return
		}
		if err := validateAdminAPIKeyText(body.Owner, "owner"); err != nil {
			writeAdminOperationError(ctx, err)
			return
		}
		policy, err := body.Policy.toPolicy(body.Name, body.Owner)
		if err != nil {
			writeAdminOperationError(ctx, err)
			return
		}
		if store == nil {
			writeAdminOperationError(ctx, apikey.ErrUnavailable)
			return
		}
		var raw string
		var record apikey.Record
		err = store.Transaction(ctx.Request().Context(), func(tx *gorm.DB) error {
			var createErr error
			raw, record, createErr = store.CreateTx(tx, policy)
			if createErr != nil {
				return createErr
			}
			return writeAdminAudit(tx, principal, "api_key.issue", record.ID, adminAuditMetadata{Fields: []string{"name", "owner", "policy"}}, record.CreatedAt)
		})
		if err != nil {
			raw = ""
			writeAdminOperationError(ctx, err)
			return
		}
		metadata, err := safeAdminAPIKeyMetadata(record)
		if err != nil {
			writeAdminOperationError(ctx, err)
			return
		}
		writeJSON(ctx, http.StatusCreated, adminAPIKeyIssueResponse{adminAPIKeyMetadata: metadata, Key: raw})
	})

	app.Get(adminAPIKeysEndpoint, func(ctx iris.Context) {
		principal, ok := authenticateAdminRequest(ctx, adminStore)
		if !ok {
			return
		}
		if err := authorizeAdminScope(ctx, adminStore, principal, AdminScopeMetadata); err != nil {
			writeAdminAuthError(ctx, err)
			return
		}
		if store == nil {
			writeAdminOperationError(ctx, apikey.ErrUnavailable)
			return
		}
		filter, err := parseAdminAPIKeyListFilter(ctx)
		if err != nil {
			writeAdminError(ctx, http.StatusBadRequest, "Invalid API key list bounds.")
			return
		}
		records, nextCursor, err := listAdminAPIKeys(ctx, store.DB(), filter)
		if err != nil {
			writeAdminOperationError(ctx, err)
			return
		}
		if err := storeAdminAPIKeyReadAudit(ctx, store.DB(), principal, "api_key.list", "api_keys", adminAuditMetadata{Filters: filter.auditFilters()}); err != nil {
			writeAdminOperationError(ctx, err)
			return
		}
		response := make([]adminAPIKeyMetadata, 0, len(records))
		for _, record := range records {
			metadata, metadataErr := safeAdminAPIKeyMetadata(record)
			if metadataErr != nil {
				writeAdminOperationError(ctx, metadataErr)
				return
			}
			response = append(response, metadata)
		}
		writeJSON(ctx, http.StatusOK, struct {
			Data       []adminAPIKeyMetadata `json:"data"`
			NextCursor string                `json:"next_cursor,omitempty"`
		}{Data: response, NextCursor: nextCursor})
	})

	app.Get(adminAPIKeysEndpoint+"/{id:string}/usage", func(ctx iris.Context) {
		principal, ok := authenticateAdminRequest(ctx, adminStore)
		if !ok {
			return
		}
		if err := authorizeAdminScope(ctx, adminStore, principal, AdminScopeMetadata); err != nil {
			writeAdminAuthError(ctx, err)
			return
		}
		id := ctx.Params().Get("id")
		if !validAPIKeyID(id) {
			writeAdminOperationError(ctx, errAdminAPIKeyNotFound)
			return
		}
		if store == nil {
			writeAdminOperationError(ctx, apikey.ErrUnavailable)
			return
		}
		usage, err := readAdminAPIKeyUsage(ctx, store.DB(), id)
		if err != nil {
			writeAdminOperationError(ctx, err)
			return
		}
		if err := storeAdminAPIKeyReadAudit(ctx, store.DB(), principal, "api_key.usage", id, adminAuditMetadata{Fields: []string{"policy", "period", "rolling", "pending"}}); err != nil {
			writeAdminOperationError(ctx, err)
			return
		}
		writeJSON(ctx, http.StatusOK, usage)
	})

	app.Get(adminAPIKeysEndpoint+"/{id:string}", func(ctx iris.Context) {
		principal, ok := authenticateAdminRequest(ctx, adminStore)
		if !ok {
			return
		}
		if err := authorizeAdminScope(ctx, adminStore, principal, AdminScopeMetadata); err != nil {
			writeAdminAuthError(ctx, err)
			return
		}
		id := ctx.Params().Get("id")
		if !validAPIKeyID(id) {
			writeAdminOperationError(ctx, errAdminAPIKeyNotFound)
			return
		}
		if store == nil {
			writeAdminOperationError(ctx, apikey.ErrUnavailable)
			return
		}
		record, err := loadAdminAPIKey(ctx, store.DB(), id)
		if err != nil {
			writeAdminOperationError(ctx, err)
			return
		}
		if err := storeAdminAPIKeyReadAudit(ctx, store.DB(), principal, "api_key.get", id, adminAuditMetadata{Fields: []string{"metadata", "policy"}}); err != nil {
			writeAdminOperationError(ctx, err)
			return
		}
		metadata, err := safeAdminAPIKeyMetadata(record)
		if err != nil {
			writeAdminOperationError(ctx, err)
			return
		}
		writeJSON(ctx, http.StatusOK, metadata)
	})

	app.Patch(adminAPIKeysEndpoint+"/{id:string}", func(ctx iris.Context) {
		principal, ok := authenticateAdminRequest(ctx, adminStore)
		if !ok {
			return
		}
		if err := authorizeAdminScope(ctx, adminStore, principal, AdminScopeMetadata); err != nil {
			writeAdminAuthError(ctx, err)
			return
		}
		var body adminAPIKeyPatchBody
		if err := decodeAdminAPIKeyBody(ctx, &body); err != nil {
			writeAdminDecodeError(ctx, err, "Invalid API key request.")
			return
		}
		if body.empty() {
			writeAdminOperationError(ctx, fmt.Errorf("%w: patch is empty", errAdminAPIKeyRequest))
			return
		}
		id := ctx.Params().Get("id")
		if !validAPIKeyID(id) {
			writeAdminOperationError(ctx, errAdminAPIKeyNotFound)
			return
		}
		if store == nil {
			writeAdminOperationError(ctx, apikey.ErrUnavailable)
			return
		}
		var updated apikey.Record
		err := store.Transaction(ctx.Request().Context(), func(tx *gorm.DB) error {
			record, loadErr := loadAdminAPIKeyTx(tx, id)
			if loadErr != nil {
				return loadErr
			}
			name, owner := record.Name, record.Owner
			updates := make(map[string]any)
			fields := make([]string, 0, 4)
			if len(body.Name) != 0 {
				nameValue, parseErr := parseAdminAPIKeyString(body.Name, "name")
				if parseErr != nil {
					return parseErr
				}
				name = nameValue
				updates["name"] = nameValue
				fields = append(fields, "name")
			}
			if len(body.Owner) != 0 {
				ownerValue, parseErr := parseAdminAPIKeyString(body.Owner, "owner")
				if parseErr != nil {
					return parseErr
				}
				owner = ownerValue
				updates["owner"] = ownerValue
				fields = append(fields, "owner")
			}
			if len(body.Policy) != 0 {
				policy, parseErr := decodeAdminAPIKeyPolicy(body.Policy, name, owner)
				if parseErr != nil {
					return parseErr
				}
				for key, value := range adminAPIKeyPolicyUpdates(policy) {
					updates[key] = value
				}
				fields = append(fields, "policy")
			}
			if len(body.Disabled) != 0 {
				disabled, parseErr := parseAdminAPIKeyBool(body.Disabled, "disabled")
				if parseErr != nil {
					return parseErr
				}
				if disabled {
					updates["disabled_at"] = time.Now().UTC()
				} else {
					updates["disabled_at"] = nil
				}
				fields = append(fields, "disabled")
			}
			if len(updates) == 0 {
				return fmt.Errorf("%w: patch is empty", errAdminAPIKeyRequest)
			}
			result := tx.Model(&apikey.Record{}).Where("id = ?", id).Updates(updates)
			if result.Error != nil {
				return fmt.Errorf("update API key: %w", result.Error)
			}
			if result.RowsAffected != 1 {
				return errAdminAPIKeyNotFound
			}
			updated, loadErr = loadAdminAPIKeyTx(tx, id)
			if loadErr != nil {
				return loadErr
			}
			sort.Strings(fields)
			return writeAdminAudit(tx, principal, "api_key.update", id, adminAuditMetadata{Fields: fields}, time.Now().UTC())
		})
		if err != nil {
			writeAdminOperationError(ctx, err)
			return
		}
		metadata, metadataErr := safeAdminAPIKeyMetadata(updated)
		if metadataErr != nil {
			writeAdminOperationError(ctx, metadataErr)
			return
		}
		writeJSON(ctx, http.StatusOK, metadata)
	})

	app.Delete(adminAPIKeysEndpoint+"/{id:string}", func(ctx iris.Context) {
		principal, ok := authenticateAdminRequest(ctx, adminStore)
		if !ok {
			return
		}
		if err := authorizeAdminScope(ctx, adminStore, principal, AdminScopeMetadata); err != nil {
			writeAdminAuthError(ctx, err)
			return
		}
		id := ctx.Params().Get("id")
		if !validAPIKeyID(id) {
			writeAdminOperationError(ctx, errAdminAPIKeyNotFound)
			return
		}
		if store == nil {
			writeAdminOperationError(ctx, apikey.ErrUnavailable)
			return
		}
		var record apikey.Record
		err := store.Transaction(ctx.Request().Context(), func(tx *gorm.DB) error {
			var loadErr error
			record, loadErr = loadAdminAPIKeyTx(tx, id)
			if loadErr != nil {
				return loadErr
			}
			if record.RevokedAt == nil {
				revokedAt := time.Now().UTC()
				result := tx.Model(&apikey.Record{}).Where("id = ? AND revoked_at IS NULL", id).Updates(map[string]any{"revoked_at": revokedAt, "revoked_by": principal.ID})
				if result.Error != nil {
					return fmt.Errorf("revoke API key: %w", result.Error)
				}
				if result.RowsAffected != 1 {
					current, loadErr := loadAdminAPIKeyTx(tx, id)
					if loadErr != nil {
						return loadErr
					}
					if current.RevokedAt == nil {
						return errAdminAPIKeyNotFound
					}
					record = current
				} else {
					record.RevokedAt = &revokedAt
					record.RevokedBy = principal.ID
				}
			}
			return writeAdminAudit(tx, principal, "api_key.revoke", id, adminAuditMetadata{Fields: []string{"revoked_at", "revoked_by"}}, time.Now().UTC())
		})
		if err != nil {
			writeAdminOperationError(ctx, err)
			return
		}
		metadata, metadataErr := safeAdminAPIKeyMetadata(record)
		if metadataErr != nil {
			writeAdminOperationError(ctx, metadataErr)
			return
		}
		writeJSON(ctx, http.StatusOK, metadata)
	})
}

func validateAdminAPIKeyText(value, field string) error {
	if strings.TrimSpace(value) == "" || len(value) > 255 {
		return fmt.Errorf("%w: %s is outside the supported range", errAdminAPIKeyRequest, field)
	}
	return nil
}

const adminAPIKeySelect = "id, name, owner, prefix, allowed_endpoints, allowed_models, created_at, expires_at, disabled_at, revoked_at, revoked_by, last_used_at, max_concurrent_requests, rolling_request_count, rolling_request_window, period_request_limit, period_token_limit, period_image_limit, period_cost_microunit_limit, period_duration, token_reservation_default, token_reservation_ceiling, image_reservation_default, image_reservation_ceiling, cost_microunit_reservation_default, cost_microunit_reservation_ceiling"

func loadAdminAPIKey(ctx iris.Context, db *gorm.DB, id string) (apikey.Record, error) {
	return loadAdminAPIKeyTx(db.WithContext(ctx.Request().Context()), id)
}

func loadAdminAPIKeyTx(db *gorm.DB, id string) (apikey.Record, error) {
	var record apikey.Record
	result := db.Select(adminAPIKeySelect).Where("id = ?", id).First(&record)
	if errors.Is(result.Error, gorm.ErrRecordNotFound) {
		return apikey.Record{}, errAdminAPIKeyNotFound
	}
	if result.Error != nil {
		return apikey.Record{}, fmt.Errorf("load API key: %w", result.Error)
	}
	return record, nil
}

type adminAPIKeyListFilter struct {
	Limit     int
	Cursor    adminAPIKeyCursor
	HasCursor bool
	Name      string
	Owner     string
	Disabled  *bool
	Revoked   *bool
}

func (filter adminAPIKeyListFilter) auditFilters() []string {
	filters := make([]string, 0, 4)
	if filter.Name != "" {
		filters = append(filters, "name")
	}
	if filter.Owner != "" {
		filters = append(filters, "owner")
	}
	if filter.Disabled != nil {
		filters = append(filters, "disabled")
	}
	if filter.Revoked != nil {
		filters = append(filters, "revoked")
	}
	return filters
}

type adminAPIKeyCursor struct {
	CreatedAt time.Time
	ID        string
}

func parseAdminAPIKeyListFilter(ctx iris.Context) (adminAPIKeyListFilter, error) {
	values := ctx.Request().URL.Query()
	for key := range values {
		switch key {
		case "limit", "cursor", "name", "owner", "disabled", "revoked":
		default:
			return adminAPIKeyListFilter{}, errors.New("unknown API key list parameter")
		}
		if len(values[key]) != 1 {
			return adminAPIKeyListFilter{}, errors.New("duplicate API key list parameter")
		}
	}
	filter := adminAPIKeyListFilter{Limit: adminAPIKeyListLimit}
	if rawValues, ok := values["limit"]; ok {
		if len(rawValues) != 1 || rawValues[0] == "" {
			return adminAPIKeyListFilter{}, errors.New("invalid API key list limit")
		}
		limit, err := strconv.Atoi(rawValues[0])
		if err != nil || limit <= 0 || limit > adminAPIKeyMaxLimit {
			return adminAPIKeyListFilter{}, errors.New("invalid API key list limit")
		}
		filter.Limit = limit
	}
	for field, destination := range map[string]*string{"name": &filter.Name, "owner": &filter.Owner} {
		if rawValues, ok := values[field]; ok {
			if len(rawValues) != 1 || len(rawValues[0]) > 255 || strings.TrimSpace(rawValues[0]) == "" {
				return adminAPIKeyListFilter{}, errors.New("invalid API key list filter")
			}
			*destination = rawValues[0]
		}
	}
	for field, destination := range map[string]**bool{"disabled": &filter.Disabled, "revoked": &filter.Revoked} {
		if rawValues, ok := values[field]; ok {
			if len(rawValues) != 1 || rawValues[0] == "" {
				return adminAPIKeyListFilter{}, errors.New("invalid API key list filter")
			}
			parsed, err := strconv.ParseBool(rawValues[0])
			if err != nil {
				return adminAPIKeyListFilter{}, errors.New("invalid API key list filter")
			}
			*destination = &parsed
		}
	}
	if rawValues, ok := values["cursor"]; ok {
		if len(rawValues) != 1 || rawValues[0] == "" {
			return adminAPIKeyListFilter{}, errors.New("invalid API key cursor")
		}
		cursor, err := decodeAdminAPIKeyCursor(rawValues[0])
		if err != nil {
			return adminAPIKeyListFilter{}, err
		}
		filter.Cursor = cursor
		filter.HasCursor = true
	}
	return filter, nil
}

func listAdminAPIKeys(ctx iris.Context, db *gorm.DB, filter adminAPIKeyListFilter) ([]apikey.Record, string, error) {
	query := db.WithContext(ctx.Request().Context()).Select(adminAPIKeySelect).Order("created_at DESC, id DESC").Limit(filter.Limit + 1)
	if filter.HasCursor {
		query = query.Where("(created_at < ?) OR (created_at = ? AND id < ?)", filter.Cursor.CreatedAt, filter.Cursor.CreatedAt, filter.Cursor.ID)
	}
	if filter.Name != "" {
		query = query.Where("name = ?", filter.Name)
	}
	if filter.Owner != "" {
		query = query.Where("owner = ?", filter.Owner)
	}
	if filter.Disabled != nil {
		if *filter.Disabled {
			query = query.Where("disabled_at IS NOT NULL")
		} else {
			query = query.Where("disabled_at IS NULL")
		}
	}
	if filter.Revoked != nil {
		if *filter.Revoked {
			query = query.Where("revoked_at IS NOT NULL")
		} else {
			query = query.Where("revoked_at IS NULL")
		}
	}
	var records []apikey.Record
	if err := query.Find(&records).Error; err != nil {
		return nil, "", fmt.Errorf("list API keys: %w", err)
	}
	if len(records) <= filter.Limit {
		return records, "", nil
	}
	last := records[filter.Limit-1]
	records = records[:filter.Limit]
	cursor, err := encodeAdminAPIKeyCursor(adminAPIKeyCursor{CreatedAt: last.CreatedAt, ID: last.ID})
	if err != nil {
		return nil, "", err
	}
	return records, cursor, nil
}

func encodeAdminAPIKeyCursor(cursor adminAPIKeyCursor) (string, error) {
	if cursor.CreatedAt.IsZero() || !validAPIKeyID(cursor.ID) {
		return "", errors.New("invalid API key cursor")
	}
	value := cursor.CreatedAt.UTC().Format(time.RFC3339Nano) + "\x00" + cursor.ID
	encoded := base64.RawURLEncoding.EncodeToString([]byte(value))
	if len(encoded) > adminAPIKeyMaxCursor {
		return "", errors.New("API key cursor is too large")
	}
	return encoded, nil
}

func decodeAdminAPIKeyCursor(value string) (adminAPIKeyCursor, error) {
	if value == "" || len(value) > adminAPIKeyMaxCursor {
		return adminAPIKeyCursor{}, errors.New("invalid API key cursor")
	}
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(decoded) > adminAPIKeyMaxCursor {
		return adminAPIKeyCursor{}, errors.New("invalid API key cursor")
	}
	parts := bytes.Split(decoded, []byte{0})
	if len(parts) != 2 || !validAPIKeyID(string(parts[1])) {
		return adminAPIKeyCursor{}, errors.New("invalid API key cursor")
	}
	createdAt, err := time.Parse(time.RFC3339Nano, string(parts[0]))
	if err != nil || createdAt.IsZero() {
		return adminAPIKeyCursor{}, errors.New("invalid API key cursor")
	}
	return adminAPIKeyCursor{CreatedAt: createdAt.UTC(), ID: string(parts[1])}, nil
}

func storeAdminAPIKeyReadAudit(ctx iris.Context, db *gorm.DB, principal AdminPrincipal, action, target string, metadata adminAuditMetadata) error {
	return db.WithContext(ctx.Request().Context()).Transaction(func(tx *gorm.DB) error {
		return writeAdminAudit(tx, principal, action, target, metadata, time.Now().UTC())
	})
}

func validAPIKeyID(id string) bool {
	if len(id) != 32 {
		return false
	}
	_, err := hex.DecodeString(id)
	return err == nil
}

type adminAPIKeyPeriodUsage struct {
	Start                  *time.Time `json:"start,omitempty"`
	End                    *time.Time `json:"end,omitempty"`
	RequestLimit           int64      `json:"request_limit"`
	TokenLimit             int64      `json:"token_limit"`
	ImageLimit             int64      `json:"image_limit"`
	CostMicrounitLimit     int64      `json:"cost_microunit_limit"`
	ReservedRequests       int64      `json:"reserved_requests"`
	ActualRequests         int64      `json:"actual_requests"`
	ReservedTokens         int64      `json:"reserved_tokens"`
	ActualTokens           int64      `json:"actual_tokens"`
	ReservedImages         int64      `json:"reserved_images"`
	ActualImages           int64      `json:"actual_images"`
	ReservedCostMicrounits int64      `json:"reserved_cost_microunits"`
	ActualCostMicrounits   int64      `json:"actual_cost_microunits"`
}

type adminAPIKeyRollingUsage struct {
	Count   int64         `json:"count"`
	Limit   int64         `json:"limit"`
	Window  time.Duration `json:"window"`
	ResetAt *time.Time    `json:"reset_at,omitempty"`
}

type adminAPIKeyConcurrencyUsage struct {
	Active int64 `json:"active"`
	Limit  int64 `json:"limit"`
}

type adminAPIKeyPendingUsage struct {
	Count int64 `json:"count"`
}

type adminAPIKeyUsageResponse struct {
	ID          string                      `json:"id"`
	Policy      adminAPIKeyPolicy           `json:"policy"`
	Period      adminAPIKeyPeriodUsage      `json:"period"`
	Rolling     adminAPIKeyRollingUsage     `json:"rolling"`
	Concurrency adminAPIKeyConcurrencyUsage `json:"concurrency"`
	Pending     adminAPIKeyPendingUsage     `json:"pending"`
}

func readAdminAPIKeyUsage(ctx iris.Context, db *gorm.DB, id string) (adminAPIKeyUsageResponse, error) {
	var response adminAPIKeyUsageResponse
	err := db.WithContext(ctx.Request().Context()).Transaction(func(tx *gorm.DB) error {
		record, err := loadAdminAPIKeyTx(tx, id)
		if err != nil {
			return err
		}
		policy, err := record.Policy()
		if err != nil {
			return err
		}
		response.ID = record.ID
		response.Policy = adminAPIKeyPolicyFromPolicy(policy)
		var state apikey.QuotaState
		if err := tx.Where("key_id = ?", id).First(&state).Error; err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
			return fmt.Errorf("load API key quota state: %w", err)
		}
		response.Concurrency = adminAPIKeyConcurrencyUsage{Active: state.ActiveRequests, Limit: policy.MaxConcurrentRequests}

		now := time.Now().UTC()
		var pending int64
		if err := tx.Model(&apikey.QuotaReservation{}).Where("key_id = ? AND status = ?", id, "pending").Count(&pending).Error; err != nil {
			return fmt.Errorf("count pending API key reservations: %w", err)
		}
		response.Pending = adminAPIKeyPendingUsage{Count: pending}

		if policy.RollingRequestCount > 0 && policy.RollingRequestWindow > 0 {
			var count int64
			if err := tx.Model(&apikey.QuotaRollingAdmission{}).Where("key_id = ? AND expires_at > ?", id, now).Count(&count).Error; err != nil {
				return fmt.Errorf("count rolling API key admissions: %w", err)
			}
			response.Rolling.Count = count
			response.Rolling.Limit = policy.RollingRequestCount
			response.Rolling.Window = policy.RollingRequestWindow
			var next apikey.QuotaRollingAdmission
			result := tx.Select("expires_at").Where("key_id = ? AND expires_at > ?", id, now).Order("expires_at ASC").Limit(1).First(&next)
			if result.Error == nil {
				reset := next.ExpiresAt.UTC()
				response.Rolling.ResetAt = &reset
			} else if !errors.Is(result.Error, gorm.ErrRecordNotFound) {
				return fmt.Errorf("load rolling API key reset: %w", result.Error)
			}
		}

		if policy.PeriodRequestLimit > 0 || policy.PeriodTokenLimit > 0 || policy.PeriodImageLimit > 0 || policy.PeriodCostMicrounitLimit > 0 {
			start := now.Truncate(policy.PeriodDuration)
			end := start.Add(policy.PeriodDuration)
			response.Period.Start = &start
			response.Period.End = &end
			response.Period.RequestLimit = policy.PeriodRequestLimit
			response.Period.TokenLimit = policy.PeriodTokenLimit
			response.Period.ImageLimit = policy.PeriodImageLimit
			response.Period.CostMicrounitLimit = policy.PeriodCostMicrounitLimit
			var bucket apikey.QuotaBucket
			result := tx.Select("reserved_requests, actual_requests, reserved_tokens, actual_tokens, reserved_images, actual_images, reserved_cost_microunits, actual_cost_microunits").Where("key_id = ? AND period_start = ?", id, start).First(&bucket)
			if result.Error == nil {
				response.Period.ReservedRequests = bucket.ReservedRequests
				response.Period.ActualRequests = bucket.ActualRequests
				response.Period.ReservedTokens = bucket.ReservedTokens
				response.Period.ActualTokens = bucket.ActualTokens
				response.Period.ReservedImages = bucket.ReservedImages
				response.Period.ActualImages = bucket.ActualImages
				response.Period.ReservedCostMicrounits = bucket.ReservedCostMicrounits
				response.Period.ActualCostMicrounits = bucket.ActualCostMicrounits
			} else if !errors.Is(result.Error, gorm.ErrRecordNotFound) {
				return fmt.Errorf("load current API key quota bucket: %w", result.Error)
			}
		}
		return nil
	})
	if err != nil {
		return adminAPIKeyUsageResponse{}, err
	}
	return response, nil
}
