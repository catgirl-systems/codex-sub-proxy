package server

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/catgirl-systems/codex-sub-proxy/internal/config"
	"github.com/kataras/iris/v12"
)

func canonicalAllowedOrigins(origins []string) (map[string]struct{}, error) {
	allowed := make(map[string]struct{}, len(origins))
	for _, raw := range origins {
		origin, err := config.CanonicalOrigin(raw)
		if err != nil {
			return nil, err
		}
		if _, exists := allowed[origin]; exists {
			return nil, errors.New("CORS origins must be unique")
		}
		allowed[origin] = struct{}{}
	}
	return allowed, nil
}

const (
	maxRequestTargetBytes = 8 << 10
	maxRequestPathBytes   = 4 << 10
	maxRequestQueryBytes  = 4 << 10
	maxHeaderCount        = 96
	maxHeaderValueBytes   = 8 << 10
	maxHeaderTotalBytes   = 48 << 10
	maxRequestIDBytes     = 64
	maxForwardedHops      = 8
)

type requestContextKey struct{}
type resolvedClientContextKey struct{}

type boundaryConfig struct {
	listener       string
	admin          bool
	allowedOrigins map[string]struct{}
	corsMaxAge     time.Duration
	trustedProxies []netip.Prefix
}

func requestIDFromContext(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	value, _ := ctx.Value(requestContextKey{}).(string)
	return value
}

func newBoundaryMiddleware(cfg boundaryConfig) (iris.Handler, error) {
	if cfg.listener != "data" && cfg.listener != "admin" {
		return nil, errors.New("listener name is invalid")
	}
	if cfg.corsMaxAge <= 0 || cfg.corsMaxAge > 24*time.Hour {
		return nil, errors.New("CORS max age is out of bounds")
	}
	return func(ctx iris.Context) {
		request := ctx.Request()
		requestID := safeRequestID(request.Header.Values("X-Request-ID"))
		request.Header.Set("X-Request-ID", requestID)
		ctx.Header("X-Request-ID", requestID)
		setSecurityHeaders(ctx, cfg.listener, request)
		corsHandled, corsAllowed := handleCORS(ctx, cfg, request)
		if !corsAllowed {
			writeBoundaryError(ctx, http.StatusForbidden, "cors_forbidden", "Cross-origin request is not allowed.")
			return
		}
		if corsHandled {
			return
		}

		if err := validateRequestShape(request); err != nil {
			writeBoundaryError(ctx, http.StatusBadRequest, "invalid_request", "The request is invalid.")
			return
		}
		if err := validateRequestHeaders(request); err != nil {
			writeBoundaryError(ctx, http.StatusBadRequest, "invalid_headers", "The request headers are invalid.")
			return
		}
		if err := validateContentEncoding(request); err != nil {
			writeBoundaryError(ctx, http.StatusUnsupportedMediaType, "unsupported_encoding", "Content-Encoding is not supported.")
			return
		}
		if err := validateRouteBoundary(request); err != nil {
			status := http.StatusBadRequest
			code := "invalid_request"
			if errors.Is(err, errBoundaryMethodNotAllowed) {
				status = http.StatusMethodNotAllowed
				code = "method_not_allowed"
			} else if errors.Is(err, errBoundaryMediaType) {
				status = http.StatusUnsupportedMediaType
				code = "invalid_media_type"
			}
			if errors.Is(err, errBoundaryRequestTooLarge) {
				status = http.StatusRequestEntityTooLarge
				code = "request_too_large"
			}
			writeBoundaryError(ctx, status, code, boundaryMessage(status, code))
			return
		}

		resolved, present, err := resolveTrustedClient(request, cfg.trustedProxies)
		if err != nil {
			writeBoundaryError(ctx, http.StatusBadRequest, "invalid_forwarding", "The forwarding headers are invalid.")
			return
		}
		requestContext := request.Context()
		requestContext = context.WithValue(requestContext, requestContextKey{}, requestID)
		if present {
			requestContext = context.WithValue(requestContext, resolvedClientContextKey{}, resolved)
		}
		*request = *request.WithContext(requestContext)
		ctx.Next()
	}, nil
}

var (
	errBoundaryMediaType        = errors.New("invalid media type")
	errBoundaryRequestTooLarge  = errors.New("request is too large")
	errBoundaryMethodNotAllowed = errors.New("method is not allowed")
)

func setSecurityHeaders(ctx iris.Context, listener string, request *http.Request) {
	ctx.Header("X-Content-Type-Options", "nosniff")
	if listener == "data" && isAPIPath(request.URL.Path) {
		ctx.Header("Cache-Control", "no-store")
	}
	if request.TLS != nil {
		ctx.Header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
	}
}

func isAPIPath(path string) bool {
	return strings.HasPrefix(path, "/v1/") || path == "/healthz" || path == "/readyz"
}

func safeRequestID(values []string) string {
	if len(values) == 1 && validRequestID(values[0]) {
		return values[0]
	}
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "00000000000000000000000000000000"
	}
	return hex.EncodeToString(raw[:])
}

func validRequestID(value string) bool {
	if len(value) == 0 || len(value) > maxRequestIDBytes {
		return false
	}
	for index := 0; index < len(value); index++ {
		char := value[index]
		if char < 0x21 || char > 0x7e || char == '"' || char == '\\' || char == ',' {
			return false
		}
	}
	return true
}

func validateRequestShape(request *http.Request) error {
	if request == nil || request.URL == nil {
		return errors.New("request target is invalid")
	}
	if len(request.RequestURI) > maxRequestTargetBytes || len(request.URL.Path) > maxRequestPathBytes || len(request.URL.RawQuery) > maxRequestQueryBytes {
		return errBoundaryRequestTooLarge
	}
	if request.Method == http.MethodConnect || request.Method == http.MethodTrace || request.Method == http.MethodPatch && request.URL.Path == "/v1/" {
		return errors.New("request method is unsafe")
	}
	return nil
}

func validateRequestHeaders(request *http.Request) error {
	if len(request.Header) > maxHeaderCount {
		return errors.New("too many headers")
	}
	total := 0
	for name, values := range request.Header {
		if len(name) > maxHeaderValueBytes {
			return errors.New("header name is too large")
		}
		total += len(name)
		for _, value := range values {
			if len(value) > maxHeaderValueBytes {
				return errors.New("header value is too large")
			}
			total += len(value)
			if total > maxHeaderTotalBytes {
				return errors.New("headers are too large")
			}
		}
	}
	return nil
}

func validateContentEncoding(request *http.Request) error {
	values := request.Header.Values("Content-Encoding")
	for _, value := range values {
		for _, encoding := range strings.Split(value, ",") {
			encoding = strings.ToLower(strings.TrimSpace(encoding))
			if encoding != "" && encoding != "identity" {
				return errors.New("content encoding is unsupported")
			}
		}
	}
	return nil
}

func validateRouteBoundary(request *http.Request) error {
	path := request.URL.Path
	if request.Method == http.MethodOptions {
		return nil
	}
	if request.Method == http.MethodGet && (path == "/v1/models" || path == "/healthz" || path == "/readyz") {
		if len(request.Header.Values("Content-Type")) != 0 {
			if len(request.Header.Values("Content-Type")) != 1 || strings.TrimSpace(request.Header.Get("Content-Type")) != "" {
				return errBoundaryMediaType
			}
		}
		if request.ContentLength != 0 {
			return errors.New("GET request has a body")
		}
		return nil
	}
	if path == "/v1/chat/completions" || path == "/v1/responses" || path == "/v1/images/generations" {
		if request.Method != http.MethodPost {
			return errBoundaryMethodNotAllowed
		}
		if err := requireMediaType(request, "application/json"); err != nil {
			return err
		}
		return nil
	}
	if path == "/v1/images/edits" {
		if request.Method != http.MethodPost {
			return errBoundaryMethodNotAllowed
		}
		mediaType, params, err := parseRequestMediaType(request)
		if err != nil || mediaType != "multipart/form-data" || params["boundary"] == "" || len(params["boundary"]) > 70 {
			return errBoundaryMediaType
		}
		if request.ContentLength > maxImagesMultipartBodyBytes {
			return errBoundaryRequestTooLarge
		}
		return nil
	}
	return nil
}

func parseRequestMediaType(request *http.Request) (string, map[string]string, error) {
	values := request.Header.Values("Content-Type")
	if len(values) != 1 || strings.TrimSpace(values[0]) == "" {
		return "", nil, errBoundaryMediaType
	}
	value := values[0]
	mediaType, params, err := mime.ParseMediaType(value)
	if err != nil || strings.Contains(strings.TrimSpace(value), ",") {
		return "", nil, errBoundaryMediaType
	}
	return strings.ToLower(mediaType), params, nil
}

func requireMediaType(request *http.Request, expected string) error {
	mediaType, _, err := parseRequestMediaType(request)
	if err != nil || mediaType != expected {
		return errBoundaryMediaType
	}
	return nil
}

func boundaryMessage(status int, code string) string {
	switch {
	case status == http.StatusUnsupportedMediaType:
		return "Content-Type is not supported."
	case status == http.StatusRequestEntityTooLarge:
		return "Request body is too large."
	case code == "invalid_forwarding":
		return "The forwarding headers are invalid."
	default:
		return "The request is invalid."
	}
}

func writeBoundaryError(ctx iris.Context, status int, code, message string) {
	setRequestError(ctx, errorClassForStatus(status), code)
	ctx.Header("Content-Type", "application/json")
	ctx.StatusCode(status)
	payload, err := json.Marshal(struct {
		Error struct {
			Message string `json:"message"`
			Type    string `json:"type"`
			Code    string `json:"code"`
		} `json:"error"`
	}{Error: struct {
		Message string `json:"message"`
		Type    string `json:"type"`
		Code    string `json:"code"`
	}{Message: message, Type: "invalid_request_error", Code: code}})
	if err == nil {
		payload = append(payload, '\n')
		_, _ = ctx.ResponseWriter().Write(payload)
	}
}

func handleCORS(ctx iris.Context, cfg boundaryConfig, request *http.Request) (bool, bool) {
	origins := request.Header.Values("Origin")
	if len(origins) == 0 {
		return false, true
	}
	if len(origins) != 1 {
		return true, false
	}
	origin, err := config.CanonicalOrigin(origins[0])
	if err != nil {
		return true, false
	}
	if cfg.admin {
		if origin != requestOrigin(request) {
			return true, false
		}
		return false, true
	}
	if origin == requestOrigin(request) {
		return false, true
	}
	if _, ok := cfg.allowedOrigins[origin]; !ok {
		return true, false
	}
	if request.Method == http.MethodOptions {
		requestedMethod := strings.ToUpper(strings.TrimSpace(request.Header.Get("Access-Control-Request-Method")))
		if !corsMethodAllowed(request.URL.Path, requestedMethod) {
			return true, false
		}
		if !corsHeadersAllowed(request.Header.Get("Access-Control-Request-Headers")) {
			return true, false
		}
		ctx.Header("Access-Control-Allow-Origin", origin)
		ctx.Header("Access-Control-Allow-Methods", requestedMethod)
		if headers := strings.TrimSpace(request.Header.Get("Access-Control-Request-Headers")); headers != "" {
			ctx.Header("Access-Control-Allow-Headers", strings.ToLower(headers))
		}
		ctx.Header("Access-Control-Max-Age", fmt.Sprintf("%d", int(cfg.corsMaxAge/time.Second)))
		ctx.Header("Vary", "Origin")
		ctx.StatusCode(http.StatusNoContent)
		return true, true
	}
	ctx.Header("Access-Control-Allow-Origin", origin)
	ctx.Header("Vary", "Origin")
	return false, true
}

func requestOrigin(request *http.Request) string {
	scheme := "http"
	if request.TLS != nil {
		scheme = "https"
	}
	candidate := scheme + "://" + request.Host
	origin, err := config.CanonicalOrigin(candidate)
	if err != nil {
		return ""
	}
	return origin
}

func corsMethodAllowed(path, method string) bool {
	switch path {
	case "/v1/models":
		return method == http.MethodGet
	case "/v1/chat/completions", "/v1/responses", "/v1/images/generations", "/v1/images/edits":
		return method == http.MethodPost
	default:
		return false
	}
}

var allowedCORSHeaders = map[string]struct{}{
	"authorization":       {},
	"content-type":        {},
	"idempotency-key":     {},
	"openai-beta":         {},
	"openai-organization": {},
	"openai-project":      {},
}

func corsHeadersAllowed(raw string) bool {
	if strings.TrimSpace(raw) == "" {
		return true
	}
	seen := make(map[string]struct{}, 6)
	for _, value := range strings.Split(raw, ",") {
		name := strings.ToLower(strings.TrimSpace(value))
		if name == "" {
			return false
		}
		if _, ok := allowedCORSHeaders[name]; !ok {
			return false
		}
		if _, duplicate := seen[name]; duplicate {
			return false
		}
		seen[name] = struct{}{}
	}
	return true
}

func resolveTrustedClient(request *http.Request, trusted []netip.Prefix) (netip.Addr, bool, error) {
	forwarded := request.Header.Values("Forwarded")
	xff := request.Header.Values("X-Forwarded-For")
	if len(forwarded) == 0 && len(xff) == 0 {
		return netip.Addr{}, false, nil
	}
	peer, err := parseImmediatePeer(request.RemoteAddr)
	if err != nil {
		return netip.Addr{}, false, errors.New("immediate peer is invalid")
	}
	if !prefixContains(trusted, peer) {
		return netip.Addr{}, false, nil
	}
	if len(forwarded) > 0 && len(xff) > 0 {
		return netip.Addr{}, false, errors.New("conflicting forwarding headers")
	}
	var chain []netip.Addr
	if len(forwarded) > 0 {
		if len(forwarded) != 1 {
			return netip.Addr{}, false, errors.New("forwarded header is repeated")
		}
		chain, err = parseForwardedChain(forwarded[0])
	} else {
		if len(xff) != 1 {
			return netip.Addr{}, false, errors.New("x-forwarded-for header is repeated")
		}
		chain, err = parseXForwardedFor(xff[0])
	}
	if err != nil {
		return netip.Addr{}, false, err
	}
	if len(chain) > maxForwardedHops {
		return netip.Addr{}, false, errors.New("forwarding chain is too long")
	}
	current := peer
	for index := len(chain) - 1; index >= 0 && prefixContains(trusted, current); index-- {
		current = chain[index]
	}
	if prefixContains(trusted, current) {
		return netip.Addr{}, false, errors.New("forwarding chain has no client")
	}
	return current, true, nil
}

func parseImmediatePeer(raw string) (netip.Addr, error) {
	if raw == "" || strings.Contains(raw, "%") {
		return netip.Addr{}, errors.New("peer is invalid")
	}
	if host, _, err := net.SplitHostPort(raw); err == nil {
		return netip.ParseAddr(host)
	}
	return netip.ParseAddr(raw)
}

func parseXForwardedFor(raw string) ([]netip.Addr, error) {
	parts := strings.Split(raw, ",")
	if len(parts) == 0 || len(parts) > maxForwardedHops {
		return nil, errors.New("x-forwarded-for hop count is invalid")
	}
	chain := make([]netip.Addr, 0, len(parts))
	for _, part := range parts {
		value := strings.TrimSpace(part)
		if value == "" || strings.ContainsAny(value, "[]:%") {
			return nil, errors.New("x-forwarded-for address is invalid")
		}
		addr, err := netip.ParseAddr(value)
		if err != nil {
			return nil, errors.New("x-forwarded-for address is invalid")
		}
		chain = append(chain, addr)
	}
	return chain, nil
}

func parseForwardedChain(raw string) ([]netip.Addr, error) {
	parts := strings.Split(raw, ",")
	if len(parts) == 0 || len(parts) > maxForwardedHops {
		return nil, errors.New("forwarded hop count is invalid")
	}
	chain := make([]netip.Addr, 0, len(parts))
	for _, part := range parts {
		pairs := strings.Split(part, ";")
		var value string
		for _, pair := range pairs {
			name, candidate, ok := strings.Cut(strings.TrimSpace(pair), "=")
			if !ok || !strings.EqualFold(name, "for") || value != "" {
				return nil, errors.New("forwarded element is invalid")
			}
			value = strings.TrimSpace(candidate)
		}
		if value == "" || strings.ContainsAny(value, "[]:%\"") {
			return nil, errors.New("forwarded address is invalid")
		}
		addr, err := netip.ParseAddr(value)
		if err != nil {
			return nil, errors.New("forwarded address is invalid")
		}
		chain = append(chain, addr)
	}
	return chain, nil
}

func prefixContains(prefixes []netip.Prefix, address netip.Addr) bool {
	for _, prefix := range prefixes {
		if prefix.Contains(address) {
			return true
		}
	}
	return false
}
