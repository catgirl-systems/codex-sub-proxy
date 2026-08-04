package server

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"html/template"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/kataras/iris/v12"
)

//go:embed admin_assets/app.js admin_assets/app.css
var adminAssets embed.FS

const (
	adminDashboardEndpoint        = "/admin/"
	adminLoginEndpoint            = "/admin/login"
	adminLogoutEndpoint           = "/admin/logout"
	adminFormLimit                = 16 * 1024
	adminCSRFHeader               = "X-CSRF-Token"
	adminCSRFTokenCookie          = "__Host-csp_admin_csrf"
	adminSessionFallbackCookie    = "csp_admin_session"
	adminLoginNonceFallbackCookie = "csp_admin_login_nonce"
	adminCSRFFallbackCookie       = "csp_admin_csrf"
	adminCSP                      = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
)

var (
	adminDashboardTemplate = template.Must(template.New("admin-dashboard").Parse(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="csrf-token" content="{{.CSRFToken}}">
<title>Iris operations</title>
<link rel="stylesheet" href="/admin/assets/app.css">
</head>
<body data-scopes="{{.Scopes}}">
<main class="shell">
<header class="header">
<div><h1>Iris operations</h1><p class="principal">Signed in as <strong>{{.PrincipalName}}</strong></p></div>
</header>
<nav id="navigation" aria-label="Dashboard sections"></nav>
<p id="status" class="status" role="status" aria-live="polite"></p>
<div id="view"></div>
</main>
<script src="/admin/assets/app.js" defer></script>
</body>
</html>`))
	adminLoginTemplate = template.Must(template.New("admin-login").Parse(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Admin login</title>
<link rel="stylesheet" href="/admin/assets/app.css">
</head>
<body>
<main class="shell">
<section class="card">
<h1>Admin login</h1>
<p>Enter an administrative token.</p>
<form method="post" action="/admin/login">
<input type="hidden" name="login_nonce" value="{{.Nonce}}">
<div class="field"><label for="admin-token">Admin token</label><input id="admin-token" name="token" type="password" autocomplete="off" required></div>
<button class="button primary" type="submit">Sign in</button>
</form>
</section>
</main>
</body>
</html>`))
)

var (
	adminJSHash  = assetETag(adminAssets, "admin_assets/app.js")
	adminCSSHash = assetETag(adminAssets, "admin_assets/app.css")
)

type adminDashboardPage struct {
	PrincipalName string
	Scopes        string
	CSRFToken     string
}

type adminLoginPage struct {
	Nonce string
}

func registerAdminDashboardRoutes(app *iris.Application, store *AdminTokenStore, secure bool) {
	app.Get("/admin/assets/app.js", func(ctx iris.Context) {
		serveAdminAsset(ctx, "admin_assets/app.js", "text/javascript; charset=utf-8", adminJSHash)
	})
	app.Get("/admin/assets/app.css", func(ctx iris.Context) {
		serveAdminAsset(ctx, "admin_assets/app.css", "text/css; charset=utf-8", adminCSSHash)
	})
	app.Get(adminLoginEndpoint, func(ctx iris.Context) {
		setAdminPageHeaders(ctx, true)
		if store == nil {
			writeAdminError(ctx, http.StatusServiceUnavailable, "Administrative authentication is unavailable.")
			return
		}
		nonce, err := store.CreateLoginNonce(ctx.Request().Context())
		if err != nil {
			writeAdminError(ctx, http.StatusServiceUnavailable, "Administrative authentication is unavailable.")
			return
		}
		setAdminNonceCookie(ctx, nonce, secure)
		if err := adminLoginTemplate.Execute(ctx.ResponseWriter(), adminLoginPage{Nonce: nonce}); err != nil {
			return
		}
	})
	app.Post(adminLoginEndpoint, func(ctx iris.Context) {
		if !validateAdminRequestOrigin(ctx.Request(), secure) {
			writeAdminLoginFailure(ctx)
			return
		}
		if store == nil {
			writeAdminLoginFailure(ctx)
			return
		}
		nonceCookie, err := requestAdminCookie(ctx.Request(), adminLoginNonceCookieName, adminLoginNonceFallbackCookie, secure)
		if err != nil || nonceCookie.Value == "" {
			writeAdminLoginFailure(ctx)
			return
		}
		ctx.Request().Body = http.MaxBytesReader(ctx.ResponseWriter(), ctx.Request().Body, adminFormLimit)
		if err := ctx.Request().ParseForm(); err != nil {
			clearAdminNonceCookie(ctx, secure)
			writeAdminLoginFailure(ctx)
			return
		}
		nonceValues := ctx.Request().PostForm["login_nonce"]
		tokenValues := ctx.Request().PostForm["token"]
		if len(nonceValues) != 1 || len(tokenValues) != 1 || tokenValues[0] == "" || len(tokenValues[0]) > maxAdminTokenSize {
			clearAdminNonceCookie(ctx, secure)
			writeAdminLoginFailure(ctx)
			return
		}
		if err := store.ConsumeLoginNonce(ctx.Request().Context(), nonceCookie.Value, nonceValues[0]); err != nil {
			clearAdminNonceCookie(ctx, secure)
			writeAdminLoginFailure(ctx)
			return
		}
		principal, err := store.Authenticate(ctx.Request().Context(), []byte(tokenValues[0]))
		if err != nil {
			clearAdminNonceCookie(ctx, secure)
			writeAdminLoginFailure(ctx)
			return
		}
		if oldCookie, cookieErr := requestAdminCookie(ctx.Request(), adminSessionCookieName, adminSessionFallbackCookie, secure); cookieErr == nil && oldCookie.Value != "" {
			if _, oldAuth, oldErr := store.AuthenticateSession(ctx.Request().Context(), oldCookie.Value); oldErr == nil {
				if oldErr := store.RevokeSession(ctx.Request().Context(), oldAuth); oldErr != nil {
					clearAdminNonceCookie(ctx, secure)
					writeAdminLoginFailure(ctx)
					return
				}
			}
		}
		sessionCookie, csrfToken, _, err := store.CreateSession(ctx.Request().Context(), principal)
		if err != nil {
			clearAdminNonceCookie(ctx, secure)
			writeAdminLoginFailure(ctx)
			return
		}
		setAdminSessionCookie(ctx, sessionCookie, secure)
		setAdminCSRFTokenCookie(ctx, csrfToken, secure)
		clearAdminNonceCookie(ctx, secure)
		ctx.Redirect(adminDashboardEndpoint, http.StatusSeeOther)
	})
	app.Get(adminDashboardEndpoint, func(ctx iris.Context) {
		if store == nil {
			redirectAdminLogin(ctx, secure)
			return
		}
		principal, auth, err := authenticateAdminSession(ctx, store, secure)
		if err != nil {
			clearAdminSessionCookie(ctx, secure)
			clearAdminCSRFTokenCookie(ctx, secure)
			redirectAdminLogin(ctx, secure)
			return
		}
		setAdminPageHeaders(ctx, true)
		page := adminDashboardPage{PrincipalName: principal.Name, Scopes: adminScopesCSV(principal.Scopes), CSRFToken: auth.csrfToken}
		if err := adminDashboardTemplate.Execute(ctx.ResponseWriter(), page); err != nil {
			return
		}
	})
	app.Get(adminLogoutEndpoint, func(ctx iris.Context) {
		ctx.Header("Allow", http.MethodPost)
		writeAdminError(ctx, http.StatusMethodNotAllowed, "Use POST to log out.")
	})
	app.Post(adminLogoutEndpoint, func(ctx iris.Context) {
		if store == nil {
			writeAdminError(ctx, http.StatusServiceUnavailable, "Administrative authentication is unavailable.")
			return
		}
		principal, ok := authenticateAdminRequest(ctx, store)
		if !ok {
			return
		}
		auth, ok := adminSessionFromContext(ctx)
		if !ok {
			writeAdminError(ctx, http.StatusBadRequest, "A browser session is required.")
			return
		}
		if err := store.LogoutSession(ctx.Request().Context(), auth.auth, principal); err != nil {
			writeAdminAuthError(ctx, err)
			return
		}
		clearAdminSessionCookie(ctx, secure)
		clearAdminCSRFTokenCookie(ctx, secure)
		ctx.Redirect(adminLoginEndpoint, http.StatusSeeOther)
	})
	app.Options("/{path:path}", func(ctx iris.Context) {
		ctx.Header("Allow", "GET, HEAD, POST, PATCH, DELETE, OPTIONS")
		ctx.StatusCode(http.StatusNoContent)
	})
}

type adminSessionContext struct {
	auth      adminSessionAuth
	csrfToken string
}

const adminSessionContextKey = "csp-admin-session"

func authenticateAdminSession(ctx iris.Context, store *AdminTokenStore, secure bool) (AdminPrincipal, adminSessionContext, error) {
	cookie, err := requestAdminCookie(ctx.Request(), adminSessionCookieName, adminSessionFallbackCookie, secure)
	if err != nil || cookie.Value == "" {
		return AdminPrincipal{}, adminSessionContext{}, ErrAdminTokenInvalid
	}
	principal, auth, err := store.AuthenticateSession(ctx.Request().Context(), cookie.Value)
	if err != nil {
		return AdminPrincipal{}, adminSessionContext{}, err
	}
	csrfCookie, err := requestAdminCookie(ctx.Request(), adminCSRFTokenCookie, adminCSRFFallbackCookie, secure)
	if err != nil || !store.ValidateSessionCSRF(csrfCookie.Value, auth) {
		return AdminPrincipal{}, adminSessionContext{}, ErrAdminTokenInvalid
	}
	return principal, adminSessionContext{auth: auth, csrfToken: csrfCookie.Value}, nil
}

func setAdminSessionContext(ctx iris.Context, auth adminSessionAuth, csrfToken string) {
	ctx.Values().Set(adminSessionContextKey, adminSessionContext{auth: auth, csrfToken: csrfToken})
}
func adminScopesCSV(scopes AdminTokenScopes) string {
	values := make([]string, 0, len(scopes))
	for _, scope := range scopes {
		values = append(values, string(scope))
	}
	return strings.Join(values, ",")
}

func adminSessionFromContext(ctx iris.Context) (adminSessionContext, bool) {
	value, ok := ctx.Values().Get(adminSessionContextKey).(adminSessionContext)
	return value, ok && value.auth.ID != ""
}

func validateAdminSameOrigin(request *http.Request) bool {
	if request == nil {
		return false
	}
	values := request.Header.Values("Origin")
	if len(values) > 1 {
		return false
	}
	if len(values) == 1 && values[0] != "" {
		return sameAdminOrigin(values[0], request, false)
	}
	referers := request.Header.Values("Referer")
	if len(referers) != 1 || referers[0] == "" {
		return false
	}
	return sameAdminOrigin(referers[0], request, true)
}

func validateAdminRequestOrigin(request *http.Request, secure bool) bool {
	if validateAdminSameOrigin(request) {
		return true
	}
	if secure || request == nil {
		return false
	}
	origins := request.Header.Values("Origin")
	referers := request.Header.Values("Referer")
	if len(referers) != 0 {
		return false
	}
	return len(origins) == 0 || (len(origins) == 1 && origins[0] == "null")
}

func sameAdminOrigin(raw string, request *http.Request, allowPath bool) bool {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.User != nil || parsed.Scheme == "" || parsed.Host == "" {
		return false
	}
	scheme := "http"
	if request.TLS != nil {
		scheme = "https"
	}
	if parsed.Scheme != scheme || parsed.Host != request.Host || parsed.RawQuery != "" || parsed.Fragment != "" {
		return false
	}
	if !allowPath && parsed.Path != "" {
		return false
	}
	return true
}

func writeAdminLoginFailure(ctx iris.Context) {
	writeAdminErrorCode(ctx, http.StatusUnauthorized, "Unable to sign in.", "admin_login_failed")
}

func setAdminPageHeaders(ctx iris.Context, noStore bool) {
	ctx.Header("Content-Security-Policy", adminCSP)
	ctx.Header("X-Content-Type-Options", "nosniff")
	ctx.Header("Referrer-Policy", "no-referrer")
	ctx.Header("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=(), fullscreen=()")
	if noStore {
		ctx.Header("Cache-Control", "no-store")
	}
}

func serveAdminAsset(ctx iris.Context, name, contentType, etag string) {
	setAdminPageHeaders(ctx, false)
	ctx.Header("Cache-Control", "public, max-age=31536000, immutable")
	ctx.Header("ETag", etag)
	if ctx.GetHeader("If-None-Match") == etag {
		ctx.StatusCode(http.StatusNotModified)
		return
	}
	file, err := adminAssets.Open(name)
	if err != nil {
		ctx.StatusCode(http.StatusNotFound)
		return
	}
	defer file.Close()
	ctx.ContentType(contentType)
	ctx.StatusCode(http.StatusOK)
	_, _ = io.Copy(ctx.ResponseWriter(), file)
}

func assetETag(files fs.FS, name string) string {
	file, err := files.Open(name)
	if err != nil {
		return ""
	}
	defer file.Close()
	contents, err := io.ReadAll(file)
	if err != nil {
		return ""
	}
	digest := sha256.Sum256(contents)
	return `"` + hex.EncodeToString(digest[:]) + `"`
}

func requestAdminCookie(request *http.Request, primary, fallback string, secure bool) (*http.Cookie, error) {
	cookie, err := request.Cookie(primary)
	if err == nil || secure {
		return cookie, err
	}
	return request.Cookie(fallback)
}

func setAdminSessionCookie(ctx iris.Context, value string, secure bool) {
	setAdminCookie(ctx, adminSessionCookieName, value, true, secure, adminSessionTTL)
	if !secure {
		setAdminCookie(ctx, adminSessionFallbackCookie, value, true, secure, adminSessionTTL)
	}
}

func clearAdminSessionCookie(ctx iris.Context, secure bool) {
	clearAdminCookie(ctx, adminSessionCookieName, true, secure)
	if !secure {
		clearAdminCookie(ctx, adminSessionFallbackCookie, true, secure)
	}
}

func setAdminCSRFTokenCookie(ctx iris.Context, value string, secure bool) {
	setAdminCookie(ctx, adminCSRFTokenCookie, value, false, secure, adminSessionTTL)
	if !secure {
		setAdminCookie(ctx, adminCSRFFallbackCookie, value, false, secure, adminSessionTTL)
	}
}

func clearAdminCSRFTokenCookie(ctx iris.Context, secure bool) {
	clearAdminCookie(ctx, adminCSRFTokenCookie, false, secure)
	if !secure {
		clearAdminCookie(ctx, adminCSRFFallbackCookie, false, secure)
	}
}

func setAdminCookie(ctx iris.Context, name, value string, httpOnly, secure bool, maxAge time.Duration) {
	http.SetCookie(ctx.ResponseWriter(), &http.Cookie{Name: name, Value: value, Path: "/", HttpOnly: httpOnly, Secure: secure, SameSite: http.SameSiteStrictMode, MaxAge: int(maxAge / time.Second)})
}

func clearAdminCookie(ctx iris.Context, name string, httpOnly, secure bool) {
	http.SetCookie(ctx.ResponseWriter(), &http.Cookie{Name: name, Value: "", Path: "/", HttpOnly: httpOnly, Secure: secure, SameSite: http.SameSiteStrictMode, MaxAge: -1, Expires: time.Unix(1, 0).UTC()})
}

func setAdminNonceCookie(ctx iris.Context, value string, secure bool) {
	setAdminCookie(ctx, adminLoginNonceCookieName, value, true, secure, adminLoginNonceTTL)
	if !secure {
		setAdminCookie(ctx, adminLoginNonceFallbackCookie, value, true, secure, adminLoginNonceTTL)
	}
}

func clearAdminNonceCookie(ctx iris.Context, secure bool) {
	clearAdminCookie(ctx, adminLoginNonceCookieName, true, secure)
	if !secure {
		clearAdminCookie(ctx, adminLoginNonceFallbackCookie, true, secure)
	}
}

func redirectAdminLogin(ctx iris.Context, secure bool) {
	clearAdminSessionCookie(ctx, secure)
	clearAdminCSRFTokenCookie(ctx, secure)
	ctx.Redirect(adminLoginEndpoint, http.StatusSeeOther)
}

func csrfTokenFromRequest(ctx iris.Context) string {
	values := ctx.Request().Header.Values(adminCSRFHeader)
	if len(values) == 1 && values[0] != "" {
		return values[0]
	}
	if len(values) > 1 {
		return ""
	}
	if strings.HasPrefix(strings.ToLower(ctx.GetHeader("Content-Type")), "application/x-www-form-urlencoded") && ctx.Request().Body != nil {
		ctx.Request().Body = http.MaxBytesReader(ctx.ResponseWriter(), ctx.Request().Body, adminFormLimit)
		if err := ctx.Request().ParseForm(); err == nil {
			values := ctx.Request().PostForm["csrf_token"]
			if len(values) == 1 {
				return values[0]
			}
		}
	}
	return ""
}
