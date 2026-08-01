package codex

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

const (
	AuthorizationHeader   = "Authorization"
	AccountIDHeader       = "ChatGPT-Account-ID"
	BetaHeader            = "OpenAI-Beta"
	OriginatorHeader      = "originator"
	VersionHeader         = "version"
	SessionIDHeader       = "session_id"
	ConversationIDHeader  = "conversation_id"
	ScopedSessionIDHeader = "session-id"
	ThreadIDHeader        = "thread-id"
	WindowIDHeader        = "x-codex-window-id"
	TurnMetadataHeader    = "x-codex-turn-metadata"
	ImageTurnIDHeader     = "x-codex-image-turn-id"
	AttestationHeader     = "x-oai-attestation"
	FedRAMPHeader         = "X-OpenAI-Fedramp"
)

const (
	DefaultBeta        = "responses=experimental"
	DefaultOriginator  = "pi"
	DefaultVersion     = "0.144.1"
	DefaultRequestKind = "turn"
)

// HeaderConfig contains only upstream Codex identity and request metadata.
// Downstream request headers are not accepted by this type.
type HeaderConfig struct {
	AccessToken string
	AccountID   string

	Beta       string
	Originator string
	Version    string

	InstallationID string
	SessionID      string
	ConversationID string
	ThreadID       string
	WindowID       string
	TurnID         string
	RequestKind    string
	ImageTurnID    string

	Attestation string
	FedRAMP     bool
}

// BuildHeaders creates the headers required by a Codex upstream request.
// It does not copy headers from a downstream request.
func BuildHeaders(config HeaderConfig) (http.Header, error) {
	originator := config.Originator
	if originator == "" {
		originator = DefaultOriginator
	}
	version := config.Version
	if version == "" {
		version = DefaultVersion
	}
	beta := config.Beta
	if beta == "" {
		beta = DefaultBeta
	}

	values := []struct {
		name  string
		value string
	}{
		{AuthorizationHeader, "Bearer " + config.AccessToken},
		{AccountIDHeader, config.AccountID},
		{BetaHeader, beta},
		{OriginatorHeader, originator},
		{VersionHeader, version},
	}

	headers := make(http.Header, 15)
	for _, value := range values {
		headers.Set(value.name, value.value)
	}

	if config.SessionID != "" {
		headers.Set(SessionIDHeader, config.SessionID)
		headers.Set(ScopedSessionIDHeader, config.SessionID)
	}
	if config.ThreadID != "" {
		headers.Set(ThreadIDHeader, config.ThreadID)
	}
	clientRequestID := config.ThreadID
	if clientRequestID == "" {
		clientRequestID = config.SessionID
	}
	if clientRequestID != "" {
		headers.Set("x-client-request-id", clientRequestID)
	}
	conversationID := config.ConversationID
	if conversationID == "" {
		conversationID = config.SessionID
	}
	if conversationID != "" {
		headers.Set(ConversationIDHeader, conversationID)
	}
	if config.WindowID != "" {
		headers.Set(WindowIDHeader, config.WindowID)
	}
	turnMetadata, err := buildTurnMetadata(config)
	if err != nil {
		return nil, err
	}
	if turnMetadata != "" {
		headers.Set(TurnMetadataHeader, turnMetadata)
	}
	if config.ImageTurnID != "" {
		headers.Set(ImageTurnIDHeader, config.ImageTurnID)
	}
	if config.Attestation != "" {
		headers.Set(AttestationHeader, config.Attestation)
	}
	if config.FedRAMP {
		headers.Set(FedRAMPHeader, "true")
	}
	return headers, nil
}

// NewRequest creates an upstream request with centrally generated Codex headers.
// The request has no way to inherit downstream authorization headers.
func NewRequest(
	ctx context.Context,
	method string,
	url string,
	body io.Reader,
	config HeaderConfig,
) (*http.Request, error) {
	if ctx == nil {
		return nil, fmt.Errorf("upstream request context is nil")
	}
	headers, err := BuildHeaders(config)
	if err != nil {
		return nil, err
	}
	request, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return nil, fmt.Errorf("build upstream request: %w", err)
	}
	request.Header = headers
	return request, nil
}

func buildTurnMetadata(config HeaderConfig) (string, error) {
	if config.InstallationID == "" && config.SessionID == "" && config.ThreadID == "" &&
		config.WindowID == "" && config.TurnID == "" && config.RequestKind == "" {
		return "", nil
	}
	requestKind := config.RequestKind
	if requestKind == "" {
		requestKind = DefaultRequestKind
	}
	metadata, err := json.Marshal(struct {
		InstallationID string `json:"installation_id,omitempty"`
		SessionID      string `json:"session_id,omitempty"`
		ThreadID       string `json:"thread_id,omitempty"`
		TurnID         string `json:"turn_id,omitempty"`
		WindowID       string `json:"window_id,omitempty"`
		RequestKind    string `json:"request_kind,omitempty"`
	}{
		InstallationID: config.InstallationID,
		SessionID:      config.SessionID,
		ThreadID:       config.ThreadID,
		TurnID:         config.TurnID,
		WindowID:       config.WindowID,
		RequestKind:    requestKind,
	})
	if err != nil {
		return "", fmt.Errorf("encode turn metadata: %w", err)
	}
	return string(metadata), nil
}
