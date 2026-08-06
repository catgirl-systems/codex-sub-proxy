package codex

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

const (
	defaultModelsURL       = "https://chatgpt.com/backend-api/codex/models"
	MaxModelCatalogBytes   = 16 << 20
	maxModelCatalogEntries = 4096
)

const maxModelsETagBytes = 512

func normalizeModelsETag(value string) string {
	value = strings.TrimSpace(value)
	if len(value) > maxModelsETagBytes || strings.ContainsAny(value, "\r\n") {
		return ""
	}
	return value
}

// ModelCapabilities is the extensible capability set returned by the Codex
// models endpoint. Typed fields on ModelInfo preserve the pinned contract;
// this map retains provider additions not yet known by the proxy.
type ModelCapabilities map[string]any

type ModelReasoningLevel struct {
	Effort      string `json:"effort,omitempty"`
	Description string `json:"description,omitempty"`
}

type ModelServiceTier struct {
	ID          string `json:"id,omitempty"`
	Name        string `json:"name,omitempty"`
	Description string `json:"description,omitempty"`
}

type ModelTruncationPolicy struct {
	Mode  string `json:"mode,omitempty"`
	Limit int64  `json:"limit,omitempty"`
}

// ModelInfo is the provider model description used by both Codex and the
// public OpenAI-compatible models endpoint.
type ModelInfo struct {
	ID                             string                `json:"id,omitempty"`
	Slug                           string                `json:"slug,omitempty"`
	Object                         string                `json:"object,omitempty"`
	Created                        int64                 `json:"created,omitempty"`
	OwnedBy                        string                `json:"owned_by,omitempty"`
	Source                         string                `json:"source,omitempty"`
	DisplayName                    string                `json:"display_name,omitempty"`
	Description                    string                `json:"description,omitempty"`
	Visibility                     string                `json:"visibility,omitempty"`
	SupportedInAPI                 bool                  `json:"supported_in_api,omitempty"`
	Priority                       int                   `json:"priority,omitempty"`
	ShellType                      string                `json:"shell_type,omitempty"`
	DefaultReasoningLevel          string                `json:"default_reasoning_level,omitempty"`
	ReasoningEfforts               []string              `json:"reasoning_efforts,omitempty"`
	DefaultReasoningEffort         string                `json:"default_reasoning_effort,omitempty"`
	SupportedReasoningLevels       []ModelReasoningLevel `json:"supported_reasoning_levels,omitempty"`
	AdditionalSpeedTiers           []string              `json:"additional_speed_tiers,omitempty"`
	ServiceTiers                   []ModelServiceTier    `json:"service_tiers,omitempty"`
	DefaultServiceTier             string                `json:"default_service_tier,omitempty"`
	AvailabilityNUX                json.RawMessage       `json:"availability_nux,omitempty"`
	Upgrade                        json.RawMessage       `json:"upgrade,omitempty"`
	ContextWindow                  int64                 `json:"context_window,omitempty"`
	MaxContextWindow               int64                 `json:"max_context_window,omitempty"`
	MaxOutputTokens                int64                 `json:"max_output_tokens,omitempty"`
	AutoCompactTokenLimit          int64                 `json:"auto_compact_token_limit,omitempty"`
	CompHash                       string                `json:"comp_hash,omitempty"`
	EffectiveContextWindowPercent  int64                 `json:"effective_context_window_percent,omitempty"`
	TruncationPolicy               ModelTruncationPolicy `json:"truncation_policy,omitempty"`
	InputModalities                []string              `json:"input_modalities,omitempty"`
	ExperimentalSupportedTools     []string              `json:"experimental_supported_tools,omitempty"`
	ModelMessages                  json.RawMessage       `json:"model_messages,omitempty"`
	IncludeSkillsUsageInstructions bool                  `json:"include_skills_usage_instructions,omitempty"`
	IncludePluginUsageInstructions bool                  `json:"include_plugin_usage_instructions,omitempty"`
	IncludeAppsUsageInstructions   bool                  `json:"include_apps_usage_instructions,omitempty"`
	SupportsReasoningSummary       bool                  `json:"supports_reasoning_summary_parameter,omitempty"`
	DefaultReasoningSummary        string                `json:"default_reasoning_summary,omitempty"`
	SupportsVerbosity              bool                  `json:"support_verbosity,omitempty"`
	DefaultVerbosity               string                `json:"default_verbosity,omitempty"`
	SupportsParallelToolCalls      bool                  `json:"supports_parallel_tool_calls,omitempty"`
	SupportsImageDetailOriginal    bool                  `json:"supports_image_detail_original,omitempty"`
	SupportsSearchTool             bool                  `json:"supports_search_tool,omitempty"`
	WebSearchToolType              string                `json:"web_search_tool_type,omitempty"`
	ApplyPatchToolType             string                `json:"apply_patch_tool_type,omitempty"`
	UseResponsesLite               bool                  `json:"use_responses_lite,omitempty"`
	AutoReviewModelOverride        string                `json:"auto_review_model_override,omitempty"`
	ModelSpecialty                 string                `json:"model_specialty,omitempty"`
	ToolMode                       string                `json:"tool_mode,omitempty"`
	MultiAgentVersion              string                `json:"multi_agent_version,omitempty"`
	Capabilities                   ModelCapabilities     `json:"capabilities,omitempty"`

	catalogMetadata bool
}

// ModelCatalogEnvelope accepts the standard OpenAI data envelope and the
// Codex models envelope. Codex's models field is preferred when both are
// present because it carries provider capabilities.
type ModelCatalogEnvelope struct {
	Data   []ModelInfo `json:"data,omitempty"`
	Models []ModelInfo `json:"models,omitempty"`
}

// ModelCatalogResult is one authenticated provider catalog response.
type ModelCatalogResult struct {
	Models      []ModelInfo
	ETag        string
	NotModified bool
	Provider    bool
}

// ModelsClientOptions contains one account's authenticated models endpoint.
type ModelsClientOptions struct {
	ModelsURL     string
	ClientVersion string
	HTTPClient    *http.Client
	Refresher     *Refresher
	Headers       HeaderConfig
}

// ModelsClient fetches one account's model catalog.
type ModelsClient struct {
	modelsURL     string
	clientVersion string
	httpClient    *http.Client
	refresher     *Refresher
	headers       HeaderConfig
}

// ModelCatalogHTTPError preserves the provider status for stale-cache policy.
type ModelCatalogHTTPError struct {
	StatusCode int
	Err        error
}

func (e *ModelCatalogHTTPError) Error() string {
	if e == nil {
		return "model catalog request failed"
	}
	if e.Err == nil {
		return fmt.Sprintf("model catalog request returned HTTP %d", e.StatusCode)
	}
	return fmt.Sprintf("model catalog request returned HTTP %d: %v", e.StatusCode, e.Err)
}

func (e *ModelCatalogHTTPError) Unwrap() error { return e.Err }

// NewModelsClient validates and creates an authenticated Codex models client.
func NewModelsClient(options ModelsClientOptions) (*ModelsClient, error) {
	modelsURL := strings.TrimSpace(options.ModelsURL)
	if modelsURL == "" {
		modelsURL = defaultModelsURL
	}
	if err := validateHTTPURL(modelsURL); err != nil {
		return nil, fmt.Errorf("models URL: %w", err)
	}
	clientVersion := strings.TrimSpace(options.ClientVersion)
	if clientVersion == "" {
		clientVersion = DefaultVersion
	}
	if strings.ContainsAny(clientVersion, "\r\n") || len(clientVersion) > 128 {
		return nil, errors.New("models client version is invalid")
	}
	if options.Refresher == nil {
		return nil, errors.New("Codex models credential refresher is required")
	}
	client := options.HTTPClient
	if client == nil {
		client = http.DefaultClient
	}
	return &ModelsClient{
		modelsURL: modelsURL, clientVersion: clientVersion, httpClient: client,
		refresher: options.Refresher, headers: options.Headers,
	}, nil
}

// List fetches the account catalog. A conditional request returns
// NotModified=true and never decodes or replaces the cached catalog.
func (client *ModelsClient) List(ctx context.Context, etag string) (ModelCatalogResult, error) {
	if ctx == nil {
		return ModelCatalogResult{}, errors.New("Codex models context is nil")
	}
	if client == nil || client.refresher == nil {
		return ModelCatalogResult{}, errors.New("Codex models client is unavailable")
	}
	operationContext := ctx
	response, err := client.refresher.Do(operationContext, true, func(attemptContext context.Context, credential Credential) (*http.Response, error) {
		endpoint, parseErr := url.Parse(client.modelsURL)
		if parseErr != nil {
			return nil, fmt.Errorf("parse models URL: %w", parseErr)
		}
		query := endpoint.Query()
		query.Set("client_version", client.clientVersion)
		endpoint.RawQuery = query.Encode()
		headers := client.headers
		headers.AccessToken = credential.AccessToken
		headers.AccountID = credential.AccountID
		if credential.AccountIsFedRAMP {
			headers.FedRAMP = true
		}
		request, requestErr := NewRequest(attemptContext, http.MethodGet, endpoint.String(), nil, headers)
		if requestErr != nil {
			return nil, requestErr
		}
		etag = normalizeModelsETag(etag)
		if etag != "" {
			request.Header.Set("If-None-Match", etag)
		}
		response, requestErr := client.httpClient.Do(request)
		if requestErr != nil {
			if contextErr := context.Cause(ctx); contextErr != nil {
				return nil, contextErr
			}
			return nil, fmt.Errorf("send Codex models request: %w", requestErr)
		}
		if response == nil {
			return nil, errors.New("Codex models request returned no response")
		}
		return response, nil
	})
	if err != nil {
		if contextErr := context.Cause(ctx); contextErr != nil {
			return ModelCatalogResult{}, contextErr
		}
		return ModelCatalogResult{}, err
	}
	if response == nil {
		return ModelCatalogResult{}, errors.New("Codex models request returned no response")
	}
	defer closeHTTPResponse(response)
	if response.StatusCode == http.StatusNotModified {
		return ModelCatalogResult{ETag: normalizeModelsETag(response.Header.Get("ETag")), NotModified: true}, nil
	}
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, MaxModelCatalogBytes))
		return ModelCatalogResult{}, &ModelCatalogHTTPError{StatusCode: response.StatusCode}
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, MaxModelCatalogBytes+1))
	if err != nil {
		return ModelCatalogResult{}, fmt.Errorf("read Codex models response: %w", err)
	}
	if len(body) == 0 || len(body) > MaxModelCatalogBytes {
		return ModelCatalogResult{}, errors.New("Codex models response is malformed")
	}
	models, err := DecodeModelCatalog(body)
	if err != nil {
		return ModelCatalogResult{}, err
	}
	return ModelCatalogResult{Models: models, ETag: normalizeModelsETag(response.Header.Get("ETag")), Provider: catalogUsesProviderEnvelope(body)}, nil
}

// DecodeModelCatalog validates a Codex or standard OpenAI model envelope.
func DecodeModelCatalog(data []byte) ([]ModelInfo, error) {
	if len(data) == 0 || len(data) > MaxModelCatalogBytes {
		return nil, errors.New("decode Codex models response: body exceeds limit")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	var envelope ModelCatalogEnvelope
	if err := decoder.Decode(&envelope); err != nil {
		return nil, fmt.Errorf("decode Codex models response: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return nil, errors.New("decode Codex models response: trailing JSON value")
		}
		return nil, fmt.Errorf("decode Codex models response: %w", err)
	}
	provider := envelope.Models != nil
	models := envelope.Models
	if models == nil {
		models = envelope.Data
	}
	if envelope.Models == nil && envelope.Data == nil {
		return nil, errors.New("decode Codex models response: missing data or models")
	}
	if len(models) > maxModelCatalogEntries {
		return nil, errors.New("decode Codex models response: too many models")
	}
	result := make([]ModelInfo, 0, len(models))
	seen := make(map[string]struct{}, len(models))
	for index := range models {
		model := models[index]
		model.ID = strings.TrimSpace(model.ID)
		model.Slug = strings.TrimSpace(model.Slug)
		if model.ID == "" {
			model.ID = model.Slug
		}
		if model.ID == "" || len(model.ID) > 256 || strings.ContainsAny(model.ID, "\r\n") {
			return nil, fmt.Errorf("decode Codex models response: model %d has invalid id", index)
		}
		if _, exists := seen[model.ID]; exists {
			return nil, fmt.Errorf("decode Codex models response: duplicate model %q", model.ID)
		}
		seen[model.ID] = struct{}{}
		if provider {
			model.catalogMetadata = true
			if !model.CatalogUsable() {
				continue
			}
		}
		if model.Capabilities == nil {
			model.Capabilities = ModelCapabilities{}
		}
		result = append(result, model)
	}
	return result, nil
}

func catalogUsesProviderEnvelope(data []byte) bool {
	var envelope struct {
		Models json.RawMessage `json:"models"`
	}
	if err := json.Unmarshal(data, &envelope); err != nil {
		return false
	}
	return len(envelope.Models) > 0 && string(envelope.Models) != "null"
}

// CatalogUsable reports whether a provider catalog entry may be exposed to
// API clients and selected for a request.
func (model ModelInfo) CatalogUsable() bool {
	if !model.catalogMetadata {
		return true
	}
	return model.SupportedInAPI && strings.TrimSpace(model.Visibility) == "list"
}

// SupportsResponsesLite reports the account-specific transport capability.
func (model ModelInfo) SupportsResponsesLite() bool {
	if model.UseResponsesLite {
		return true
	}
	for _, key := range []string{"use_responses_lite", "supports_responses_lite", "responses_lite"} {
		if value, ok := model.Capabilities[key].(bool); ok && value {
			return true
		}
	}
	return false
}
