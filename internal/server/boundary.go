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
type boundaryRouteKey struct {
	listener string
	route    string
	method   string
}

type boundaryRoutePolicy struct {
	contentType  string
	multipart    bool
	maxBodyBytes int64
}

var boundaryRoutePolicies = map[boundaryRouteKey]boundaryRoutePolicy{
	{listener: "data", route: "/healthz", method: http.MethodGet}:                                          {},
	{listener: "data", route: "/readyz", method: http.MethodGet}:                                           {},
	{listener: "data", route: modelsEndpoint, method: http.MethodGet}:                                      {},
	{listener: "data", route: chatCompletionsEndpoint, method: http.MethodPost}:                            {contentType: "application/json", maxBodyBytes: maxChatBodyBytes},
	{listener: "data", route: responsesEndpoint, method: http.MethodPost}:                                  {contentType: "application/json", maxBodyBytes: maxResponsesBodyBytes},
	{listener: "data", route: responsesCompactEndpoint, method: http.MethodPost}:                           {contentType: "application/json", maxBodyBytes: maxResponsesBodyBytes},
	{listener: "data", route: imagesGenerationsEndpoint, method: http.MethodPost}:                          {contentType: "application/json", maxBodyBytes: maxImagesJSONBodyBytes},
	{listener: "data", route: imagesEditsEndpoint, method: http.MethodPost}:                                {contentType: "multipart/form-data", multipart: true, maxBodyBytes: maxImagesMultipartBodyBytes},
	{listener: "admin", route: "/healthz", method: http.MethodGet}:                                         {},
	{listener: "admin", route: "/readyz", method: http.MethodGet}:                                          {},
	{listener: "admin", route: "/admin/assets/app.js", method: http.MethodGet}:                             {},
	{listener: "admin", route: "/admin/assets/app.css", method: http.MethodGet}:                            {},
	{listener: "admin", route: adminLoginEndpoint, method: http.MethodGet}:                                 {},
	{listener: "admin", route: adminLoginEndpoint, method: http.MethodPost}:                                {contentType: "application/x-www-form-urlencoded", maxBodyBytes: adminFormLimit},
	{listener: "admin", route: adminDashboardEndpoint, method: http.MethodGet}:                             {},
	{listener: "admin", route: adminLogoutEndpoint, method: http.MethodGet}:                                {},
	{listener: "admin", route: adminLogoutEndpoint, method: http.MethodPost}:                               {contentType: "application/x-www-form-urlencoded", maxBodyBytes: adminFormLimit},
	{listener: "admin", route: adminTokensEndpoint, method: http.MethodGet}:                                {},
	{listener: "admin", route: adminTokensEndpoint, method: http.MethodPost}:                               {contentType: "application/json", maxBodyBytes: adminBodyLimit},
	{listener: "admin", route: adminTokensEndpoint + "/{id:string}", method: http.MethodDelete}:            {},
	{listener: "admin", route: adminAPIKeysEndpoint, method: http.MethodGet}:                               {},
	{listener: "admin", route: adminAPIKeysEndpoint, method: http.MethodPost}:                              {contentType: "application/json", maxBodyBytes: adminBodyLimit},
	{listener: "admin", route: adminAPIKeysEndpoint + "/{id:string}", method: http.MethodGet}:              {},
	{listener: "admin", route: adminAPIKeysEndpoint + "/{id:string}", method: http.MethodPatch}:            {contentType: "application/json", maxBodyBytes: adminBodyLimit},
	{listener: "admin", route: adminAPIKeysEndpoint + "/{id:string}", method: http.MethodDelete}:           {},
	{listener: "admin", route: adminAPIKeysEndpoint + "/{id:string}/usage", method: http.MethodGet}:        {},
	{listener: "admin", route: adminRequestsEndpoint, method: http.MethodGet}:                              {},
	{listener: "admin", route: adminRequestsEndpoint + "/{id:string}", method: http.MethodGet}:             {},
	{listener: "admin", route: adminRequestsEndpoint + "/{id:string}", method: http.MethodDelete}:          {},
	{listener: "admin", route: adminRequestsEndpoint + "/{id:string}/export", method: http.MethodGet}:      {},
	{listener: "admin", route: adminConversationsEndpoint, method: http.MethodGet}:                         {},
	{listener: "admin", route: adminConversationsEndpoint + "/{id:string}", method: http.MethodGet}:        {},
	{listener: "admin", route: adminConversationsEndpoint + "/{id:string}", method: http.MethodDelete}:     {},
	{listener: "admin", route: adminConversationsEndpoint + "/{id:string}/export", method: http.MethodGet}: {},
	{listener: "admin", route: adminAnalyticsEndpoint + "/overview", method: http.MethodGet}:               {},
	{listener: "admin", route: adminAnalyticsEndpoint + "/models", method: http.MethodGet}:                 {},
	{listener: "admin", route: adminAnalyticsEndpoint + "/keys", method: http.MethodGet}:                   {},
	{listener: "admin", route: adminAnalyticsEndpoint + "/errors", method: http.MethodGet}:                 {},
	{listener: "admin", route: adminAnalyticsEndpoint + "/quotas", method: http.MethodGet}:                 {},
	{listener: "admin", route: adminAnalyticsEndpoint + "/latency", method: http.MethodGet}:                {},
	{listener: "admin", route: adminAnalyticsEndpoint + "/usage", method: http.MethodGet}:                  {},
	{listener: "admin", route: adminAnalyticsEndpoint + "/costs", method: http.MethodGet}:                  {},
	{listener: "admin", route: "/{path:path}", method: http.MethodOptions}:                                 {},
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
		route := matchedRouteTemplate(ctx, request)
		requestID := safeRequestID(request.Header.Values("X-Request-ID"))
		request.Header.Set("X-Request-ID", requestID)
		ctx.Header("X-Request-ID", requestID)
		setSecurityHeaders(ctx, cfg.listener, request)

		if err := validateRequestShape(request); err != nil {
			status, code := boundaryErrorStatus(err)
			writeBoundaryError(ctx, status, code, boundaryMessage(status, code))
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
		if request.Method == http.MethodOptions {
			if err := validatePreflightBody(request); err != nil {
				status, code := boundaryErrorStatus(err)
				writeBoundaryError(ctx, status, code, boundaryMessage(status, code))
				return
			}
		}
		corsHandled, corsAllowed := handleCORS(ctx, cfg, request, route)
		if !corsAllowed {
			writeBoundaryError(ctx, http.StatusForbidden, "cors_forbidden", "Cross-origin request is not allowed.")
			return
		}
		if corsHandled {
			return
		}

		if err := validateRouteBoundary(request, cfg.listener, route); err != nil {
			status, code := boundaryErrorStatus(err)
			writeBoundaryError(ctx, status, code, boundaryMessage(status, code))
			return
		}
		if policy, ok := boundaryRoutePolicyFor(cfg.listener, route, request.Method); ok && policy.maxBodyBytes > 0 && request.Body != nil {
			request.Body = http.MaxBytesReader(ctx.ResponseWriter(), request.Body, policy.maxBodyBytes)
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
		enforceBoundaryCache(ctx, cfg.listener, request.URL.Path, route)
	}, nil
}

var (
	errBoundaryMediaType        = errors.New("invalid media type")
	errBoundaryRequestTooLarge  = errors.New("request is too large")
	errBoundaryMethodNotAllowed = errors.New("method is not allowed")
	errBoundaryBodyNotAllowed   = errors.New("request body is not allowed")
)

func matchedRouteTemplate(ctx iris.Context, request *http.Request) string {
	if ctx != nil {
		if route := ctx.GetCurrentRoute(); route != nil && route.Path() != "" {
			return route.Path()
		}
	}
	if request == nil || request.URL == nil {
		return ""
	}
	return request.URL.Path
}

func boundaryRoutePolicyFor(listener, route, method string) (boundaryRoutePolicy, bool) {
	policy, ok := boundaryRoutePolicies[boundaryRouteKey{listener: listener, route: route, method: method}]
	return policy, ok
}

func boundaryRouteExists(listener, route string) bool {
	for key := range boundaryRoutePolicies {
		if key.listener == listener && key.route == route {
			return true
		}
	}
	return false
}

func boundaryErrorStatus(err error) (int, string) {
	switch {
	case errors.Is(err, errBoundaryMethodNotAllowed):
		return http.StatusMethodNotAllowed, "method_not_allowed"
	case errors.Is(err, errBoundaryMediaType):
		return http.StatusUnsupportedMediaType, "invalid_media_type"
	case errors.Is(err, errBoundaryRequestTooLarge):
		return http.StatusRequestEntityTooLarge, "request_too_large"
	default:
		return http.StatusBadRequest, "invalid_request"
	}
}

func setSecurityHeaders(ctx iris.Context, listener string, request *http.Request) {
	ctx.Header("X-Content-Type-Options", "nosniff")
	if listener == "admin" || (listener == "data" && isAPIPath(request.URL.Path)) {
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

func enforceBoundaryCache(ctx iris.Context, listener, path, route string) {
	asset := path == "/admin/assets/app.js" || path == "/admin/assets/app.css" || route == "/admin/assets/app.js" || route == "/admin/assets/app.css"
	if listener == "admin" && !asset {
		ensureNoStore(ctx)
	}
	if listener == "data" && isAPIPath(path) {
		ensureNoStore(ctx)
	}
}

func ensureNoStore(ctx iris.Context) {
	value := ctx.GetHeader("Cache-Control")
	for _, directive := range strings.Split(value, ",") {
		if strings.EqualFold(strings.TrimSpace(directive), "no-store") {
			return
		}
	}
	if value == "" {
		ctx.Header("Cache-Control", "no-store")
		return
	}
	ctx.Header("Cache-Control", value+", no-store")
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
	if len(values) > 1 {
		return errors.New("content encoding is repeated")
	}
	if len(values) == 1 {
		encoding := strings.TrimSpace(values[0])
		if encoding != "" && !strings.EqualFold(encoding, "identity") {
			return errors.New("content encoding is unsupported")
		}
	}
	return nil
}

func validatePreflightBody(request *http.Request) error {
	if request.ContentLength != 0 {
		return errBoundaryBodyNotAllowed
	}
	if values := request.Header.Values("Content-Type"); len(values) > 1 || len(values) == 1 && strings.TrimSpace(values[0]) != "" {
		return errBoundaryMediaType
	}
	return nil
}

func validateRouteBoundary(request *http.Request, listener, route string) error {
	if request == nil || request.URL == nil {
		return errors.New("request target is invalid")
	}
	if request.Method == http.MethodOptions {
		return nil
	}
	policy, ok := boundaryRoutePolicyFor(listener, route, request.Method)
	if !ok {
		if boundaryRouteExists(listener, route) {
			if (route == "/healthz" || route == "/readyz") && request.ContentLength == 0 && (len(request.Header.Values("Content-Type")) == 0 || len(request.Header.Values("Content-Type")) == 1 && strings.TrimSpace(request.Header.Get("Content-Type")) == "") {
				return nil
			}
			return errBoundaryMethodNotAllowed
		}
		return nil
	}
	if policy.maxBodyBytes > 0 {
		if policy.multipart {
			mediaType, params, err := parseRequestMediaType(request)
			if err != nil || mediaType != policy.contentType || len(params) != 1 || params["boundary"] == "" || len(params["boundary"]) > 70 {
				return errBoundaryMediaType
			}
		} else if err := requireMediaType(request, policy.contentType); err != nil {
			return err
		}
		if request.ContentLength > policy.maxBodyBytes {
			return errBoundaryRequestTooLarge
		}
		return nil
	}
	if values := request.Header.Values("Content-Type"); len(values) > 1 || len(values) == 1 && strings.TrimSpace(values[0]) != "" {
		return errBoundaryMediaType
	}
	if request.ContentLength != 0 {
		return errBoundaryBodyNotAllowed
	}
	return nil
}

func parseRequestMediaType(request *http.Request) (string, map[string]string, error) {
	values := request.Header.Values("Content-Type")
	if len(values) != 1 || strings.TrimSpace(values[0]) == "" {
		return "", nil, errBoundaryMediaType
	}
	value := values[0]
	if strings.Contains(value, ",") {
		return "", nil, errBoundaryMediaType
	}
	mediaType, params, err := mime.ParseMediaType(value)
	if err != nil {
		return "", nil, errBoundaryMediaType
	}
	return strings.ToLower(mediaType), params, nil
}

func requireMediaType(request *http.Request, expected string) error {
	mediaType, params, err := parseRequestMediaType(request)
	if err != nil || mediaType != expected || len(params) != 0 {
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

func handleCORS(ctx iris.Context, cfg boundaryConfig, request *http.Request, route string) (bool, bool) {
	origins := request.Header.Values("Origin")
	if len(origins) == 0 {
		if request.Method == http.MethodOptions {
			return true, false
		}
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
		requestedMethods := request.Header.Values("Access-Control-Request-Method")
		if len(requestedMethods) != 1 {
			return true, false
		}
		requestedMethod := strings.TrimSpace(requestedMethods[0])
		if requestedMethod == "" {
			return true, false
		}
		if _, ok := boundaryRoutePolicyFor(cfg.listener, route, requestedMethod); !ok {
			return true, false
		}
		headers, ok := corsHeadersAllowed(request.Header.Get("Access-Control-Request-Headers"))
		if !ok {
			return true, false
		}
		ctx.Header("Access-Control-Allow-Origin", origin)
		ctx.Header("Access-Control-Allow-Methods", requestedMethod)
		if headers != "" {
			ctx.Header("Access-Control-Allow-Headers", headers)
		}
		ctx.Header("Access-Control-Max-Age", fmt.Sprintf("%d", int(cfg.corsMaxAge/time.Second)))
		appendVary(ctx, "Origin", "Access-Control-Request-Method", "Access-Control-Request-Headers")
		ctx.StatusCode(http.StatusNoContent)
		return true, true
	}
	ctx.Header("Access-Control-Allow-Origin", origin)
	appendVary(ctx, "Origin")
	return false, true
}

func appendVary(ctx iris.Context, values ...string) {
	header := ctx.ResponseWriter().Header()
	seen := make(map[string]struct{}, len(values))
	var merged []string
	for _, line := range header.Values("Vary") {
		for _, value := range strings.Split(line, ",") {
			value = strings.TrimSpace(value)
			if value == "" {
				continue
			}
			if value == "*" {
				return
			}
			key := strings.ToLower(value)
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			merged = append(merged, value)
		}
	}
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		key := strings.ToLower(value)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		merged = append(merged, value)
	}
	if len(merged) > 0 {
		header.Set("Vary", strings.Join(merged, ", "))
	}
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

var allowedCORSHeaders = map[string]struct{}{
	"authorization":       {},
	"content-type":        {},
	"idempotency-key":     {},
	"openai-beta":         {},
	"openai-organization": {},
	"openai-project":      {},
}

func corsHeadersAllowed(raw string) (string, bool) {
	if strings.TrimSpace(raw) == "" {
		return "", true
	}
	seen := make(map[string]struct{}, 6)
	headers := make([]string, 0, 6)
	for _, value := range strings.Split(raw, ",") {
		name := strings.ToLower(strings.TrimSpace(value))
		if name == "" || !validHeaderToken(name) {
			return "", false
		}
		if _, ok := allowedCORSHeaders[name]; !ok {
			return "", false
		}
		if _, duplicate := seen[name]; duplicate {
			return "", false
		}
		seen[name] = struct{}{}
		headers = append(headers, name)
	}
	return strings.Join(headers, ", "), true
}

func validHeaderToken(value string) bool {
	if value == "" {
		return false
	}
	for index := 0; index < len(value); index++ {
		char := value[index]
		if (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') || (char >= '0' && char <= '9') {
			continue
		}
		switch char {
		case '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~':
		default:
			return false
		}
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
	var host string
	if parsedHost, _, err := net.SplitHostPort(raw); err == nil {
		host = parsedHost
	} else {
		host = raw
	}
	addr, err := netip.ParseAddr(host)
	if err != nil || addr.Zone() != "" {
		return netip.Addr{}, errors.New("peer is invalid")
	}
	return addr.Unmap(), nil
}

func parseXForwardedFor(raw string) ([]netip.Addr, error) {
	parts := strings.Split(raw, ",")
	if len(parts) == 0 || len(parts) > maxForwardedHops {
		return nil, errors.New("x-forwarded-for hop count is invalid")
	}
	chain := make([]netip.Addr, 0, len(parts))
	for _, part := range parts {
		value := strings.TrimSpace(part)
		if value == "" || strings.ContainsAny(value, "[]%") {
			return nil, errors.New("x-forwarded-for address is invalid")
		}
		addr, err := netip.ParseAddr(value)
		if err != nil || addr.Zone() != "" {
			return nil, errors.New("x-forwarded-for address is invalid")
		}
		chain = append(chain, addr.Unmap())
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
		pairs := strings.Split(strings.TrimSpace(part), ";")
		if len(pairs) != 1 {
			return nil, errors.New("forwarded element is invalid")
		}
		name, candidate, ok := strings.Cut(pairs[0], "=")
		if !ok || name != strings.TrimSpace(name) || !strings.EqualFold(name, "for") {
			return nil, errors.New("forwarded element is invalid")
		}
		candidate = strings.TrimSpace(candidate)
		if candidate == "" {
			return nil, errors.New("forwarded address is invalid")
		}
		var addr netip.Addr
		quoted := strings.HasPrefix(candidate, `"`)
		if quoted {
			if len(candidate) < 4 || candidate[len(candidate)-1] != '"' {
				return nil, errors.New("forwarded address is invalid")
			}
			candidate = candidate[1 : len(candidate)-1]
			if strings.ContainsAny(candidate, `\"`) {
				return nil, errors.New("forwarded address is invalid")
			}
		}
		if strings.HasPrefix(candidate, "[") {
			if !quoted || len(candidate) < 3 || candidate[len(candidate)-1] != ']' || strings.ContainsAny(candidate[1:len(candidate)-1], "[]%") {
				return nil, errors.New("forwarded address is invalid")
			}
			addr, ok = parseForwardedIPv6(candidate[1 : len(candidate)-1])
		} else {
			addr, ok = parseForwardedIPv4(candidate)
		}
		if !ok {
			return nil, errors.New("forwarded address is invalid")
		}
		chain = append(chain, addr.Unmap())
	}
	return chain, nil
}

func parseForwardedIPv4(value string) (netip.Addr, bool) {
	addr, err := netip.ParseAddr(value)
	return addr, err == nil && addr.Is4()
}

func parseForwardedIPv6(value string) (netip.Addr, bool) {
	addr, err := netip.ParseAddr(value)
	return addr, err == nil && addr.Is6() && addr.Zone() == ""
}

func prefixContains(prefixes []netip.Prefix, address netip.Addr) bool {
	for _, prefix := range prefixes {
		if prefix.Contains(address) {
			return true
		}
	}
	return false
}
