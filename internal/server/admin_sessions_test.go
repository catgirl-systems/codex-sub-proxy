package server

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestAdminSessionLifecycleAndTokenChanges(t *testing.T) {
	now := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
	store, closeStore := openAdminTestStore(t, []byte("admin-hmac-exact"), &now)
	defer closeStore()
	raw := adminTestToken()
	if _, err := store.MaterializeBootstrap(context.Background(), []byte(raw)); err != nil {
		t.Fatal(err)
	}
	principal, err := store.Authenticate(context.Background(), []byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	cookie, csrf, record, err := store.CreateSession(context.Background(), principal)
	if err != nil {
		t.Fatal(err)
	}
	if cookie == "" || csrf == "" || record.ID == "" {
		t.Fatal("session response is incomplete")
	}
	var stored AdminSession
	if err := store.db.First(&stored, "id = ?", record.ID).Error; err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{cookie, csrf, raw} {
		if strings.Contains(string(stored.Digest), secret) || strings.Contains(string(stored.CSRFDigest), secret) {
			t.Fatalf("secret stored in session record: %q", secret)
		}
	}
	authPrincipal, auth, err := store.AuthenticateSession(context.Background(), cookie)
	if err != nil || authPrincipal.ID != principal.ID {
		t.Fatalf("authenticate session = %v, %v", authPrincipal, err)
	}
	if !store.ValidateSessionCSRF(csrf, auth) || store.ValidateSessionCSRF(strings.Repeat("a", 64), auth) {
		t.Fatal("CSRF validation result is incorrect")
	}
	updatedScopes := AdminTokenScopes{AdminScopeMetadata}
	if err := store.db.Model(&AdminToken{}).Where("id = ?", principal.ID).Update("scopes", updatedScopes).Error; err != nil {
		t.Fatal(err)
	}
	changedPrincipal, _, err := store.AuthenticateSession(context.Background(), cookie)
	if err != nil || changedPrincipal.HasScope(AdminScopeContent) {
		t.Fatalf("session scope did not follow token: %+v, %v", changedPrincipal, err)
	}
	if _, err := store.Revoke(context.Background(), principal.ID, principal); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.AuthenticateSession(context.Background(), cookie); err == nil {
		t.Fatal("revoked backing token kept session alive")
	}
}

func TestAdminSessionExpiryAndIdleBoundary(t *testing.T) {
	now := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
	store, closeStore := openAdminTestStore(t, []byte("admin-hmac"), &now)
	defer closeStore()
	raw := adminTestToken()
	if _, err := store.MaterializeBootstrap(context.Background(), []byte(raw)); err != nil {
		t.Fatal(err)
	}
	principal, err := store.Authenticate(context.Background(), []byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	cookie, _, record, err := store.CreateSession(context.Background(), principal)
	if err != nil {
		t.Fatal(err)
	}
	now = record.CreatedAt.Add(adminSessionIdleTTL)
	if _, _, err := store.AuthenticateSession(context.Background(), cookie); err == nil {
		t.Fatal("session remained valid at idle expiry")
	}
	now = record.ExpiresAt
	if _, _, err := store.AuthenticateSession(context.Background(), cookie); err == nil {
		t.Fatal("session remained valid at fixed expiry")
	}
}

func TestAdminLoginNonceIsOneUseAndSameOriginIsExact(t *testing.T) {
	now := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
	store, closeStore := openAdminTestStore(t, []byte("admin-hmac"), &now)
	defer closeStore()
	nonce, err := store.CreateLoginNonce(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := store.ConsumeLoginNonce(context.Background(), nonce, nonce); err != nil {
		t.Fatal(err)
	}
	if err := store.ConsumeLoginNonce(context.Background(), nonce, nonce); err == nil {
		t.Fatal("login nonce replay succeeded")
	}
	if err := store.ConsumeLoginNonce(context.Background(), nonce, nonce+"x"); err == nil {
		t.Fatal("mismatched nonce succeeded")
	}
	request := httptest.NewRequest(http.MethodPost, "http://admin.example/admin/login", nil)
	request.Host = "admin.example"
	request.Header.Set("Origin", "http://admin.example")
	if !validateAdminSameOrigin(request) {
		t.Fatal("same origin rejected")
	}
	request.Header.Set("Origin", "https://admin.example")
	if validateAdminSameOrigin(request) {
		t.Fatal("cross-scheme origin accepted")
	}
	request.Header.Set("Origin", "http://admin.example.evil")
	if validateAdminSameOrigin(request) {
		t.Fatal("cross-host origin accepted")
	}
	request.Header.Del("Origin")
	request.Header.Set("Referer", "http://admin.example/admin/login")
	if !validateAdminSameOrigin(request) {
		t.Fatal("same-origin referer rejected")
	}
}

func TestAdminDashboardLoginAndCSRFBoundary(t *testing.T) {
	now := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
	store, closeStore := openAdminTestStore(t, []byte("admin-hmac"), &now)
	defer closeStore()
	raw := adminTestToken()
	if _, err := store.MaterializeBootstrap(context.Background(), []byte(raw)); err != nil {
		t.Fatal(err)
	}
	app, err := newAdminApplication(NewReadiness(), store, nil)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(app)
	defer server.Close()
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

	loginResponse, err := client.Get(server.URL + adminLoginEndpoint)
	if err != nil {
		t.Fatal(err)
	}
	loginBody, _ := io.ReadAll(loginResponse.Body)
	loginResponse.Body.Close()
	nonce := between(string(loginBody), `name="login_nonce" value="`, `"`)
	if loginResponse.StatusCode != http.StatusOK || nonce == "" {
		t.Fatalf("login page status=%d nonce=%q", loginResponse.StatusCode, nonce)
	}
	var nonceCookie *http.Cookie
	for _, cookie := range loginResponse.Cookies() {
		if cookie.Name == adminLoginNonceCookieName {
			nonceCookie = cookie
		}
	}
	if nonceCookie == nil || !nonceCookie.HttpOnly || nonceCookie.SameSite != http.SameSiteStrictMode || nonceCookie.Path != "/" {
		t.Fatalf("login nonce cookie = %+v", nonceCookie)
	}
	form := url.Values{"login_nonce": {nonce}, "token": {raw}}
	loginRequest, _ := http.NewRequest(http.MethodPost, server.URL+adminLoginEndpoint, strings.NewReader(form.Encode()))
	loginRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	loginRequest.Header.Set("Origin", server.URL)
	loginRequest.AddCookie(nonceCookie)
	loginResponse, err = client.Do(loginRequest)
	if err != nil {
		t.Fatal(err)
	}
	loginResponse.Body.Close()
	var sessionCookie, csrfCookie *http.Cookie
	for _, cookie := range loginResponse.Cookies() {
		switch cookie.Name {
		case adminSessionCookieName:
			sessionCookie = cookie
		case adminCSRFTokenCookie:
			csrfCookie = cookie
		}
	}
	if loginResponse.StatusCode != http.StatusSeeOther || sessionCookie == nil || csrfCookie == nil || sessionCookie.Value == "" || csrfCookie.Value == "" {
		t.Fatalf("login status=%d session=%+v csrf=%+v", loginResponse.StatusCode, sessionCookie, csrfCookie)
	}
	if !sessionCookie.HttpOnly || sessionCookie.SameSite != http.SameSiteStrictMode || sessionCookie.Path != "/" || sessionCookie.Domain != "" {
		t.Fatalf("session cookie flags = %+v", sessionCookie)
	}
	pageRequest, _ := http.NewRequest(http.MethodGet, server.URL+adminDashboardEndpoint, nil)
	pageRequest.AddCookie(sessionCookie)
	pageRequest.AddCookie(csrfCookie)
	pageResponse, err := client.Do(pageRequest)
	if err != nil {
		t.Fatal(err)
	}
	pageBody, _ := io.ReadAll(pageResponse.Body)
	pageResponse.Body.Close()
	if pageResponse.StatusCode != http.StatusOK || !strings.Contains(string(pageBody), "Iris operations") || !strings.Contains(pageResponse.Header.Get("Content-Security-Policy"), "script-src 'self'") || pageResponse.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("dashboard status=%d headers=%v", pageResponse.StatusCode, pageResponse.Header)
	}
	apiRequest, _ := http.NewRequest(http.MethodPost, server.URL+adminTokensEndpoint, strings.NewReader(`not-json`))
	apiRequest.Header.Set("Content-Type", "application/json")
	apiRequest.Header.Set("Origin", server.URL)
	apiRequest.AddCookie(sessionCookie)
	apiRequest.AddCookie(csrfCookie)
	apiResponse, err := client.Do(apiRequest)
	if err != nil {
		t.Fatal(err)
	}
	apiResponse.Body.Close()
	if apiResponse.StatusCode != http.StatusForbidden {
		t.Fatalf("missing CSRF status=%d", apiResponse.StatusCode)
	}
	apiRequest, _ = http.NewRequest(http.MethodPost, server.URL+adminTokensEndpoint, strings.NewReader(`{"name":"metadata","scopes":["metadata"]}`))
	apiRequest.Header.Set("Content-Type", "application/json")
	apiRequest.Header.Set("Origin", server.URL)
	apiRequest.Header.Set(adminCSRFHeader, csrfCookie.Value)
	apiRequest.AddCookie(sessionCookie)
	apiRequest.AddCookie(csrfCookie)
	apiResponse, err = client.Do(apiRequest)
	if err != nil {
		t.Fatal(err)
	}
	apiResponse.Body.Close()
	if apiResponse.StatusCode != http.StatusCreated {
		t.Fatalf("valid CSRF status=%d", apiResponse.StatusCode)
	}
	logoutGet, _ := http.NewRequest(http.MethodGet, server.URL+adminLogoutEndpoint, nil)
	logoutGet.AddCookie(sessionCookie)
	logoutGet.AddCookie(csrfCookie)
	logoutResponse, err := client.Do(logoutGet)
	if err != nil {
		t.Fatal(err)
	}
	logoutResponse.Body.Close()
	if logoutResponse.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("logout GET status=%d", logoutResponse.StatusCode)
	}
	logoutForm := url.Values{"csrf_token": {csrfCookie.Value}}
	logoutRequest, _ := http.NewRequest(http.MethodPost, server.URL+adminLogoutEndpoint, strings.NewReader(logoutForm.Encode()))
	logoutRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	logoutRequest.Header.Set("Origin", server.URL)
	logoutRequest.AddCookie(sessionCookie)
	logoutRequest.AddCookie(csrfCookie)
	logoutResponse, err = client.Do(logoutRequest)
	if err != nil {
		t.Fatal(err)
	}
	logoutResponse.Body.Close()
	if logoutResponse.StatusCode != http.StatusSeeOther {
		t.Fatalf("logout POST status=%d", logoutResponse.StatusCode)
	}
	pageRequest, _ = http.NewRequest(http.MethodGet, server.URL+adminDashboardEndpoint, nil)
	pageRequest.AddCookie(sessionCookie)
	pageRequest.AddCookie(csrfCookie)
	pageResponse, err = client.Do(pageRequest)
	if err != nil {
		t.Fatal(err)
	}
	pageResponse.Body.Close()
	if pageResponse.StatusCode != http.StatusSeeOther {
		t.Fatalf("dashboard after logout status=%d", pageResponse.StatusCode)
	}
}

func between(value, start, end string) string {
	begin := strings.Index(value, start)
	if begin < 0 {
		return ""
	}
	begin += len(start)
	finish := strings.Index(value[begin:], end)
	if finish < 0 {
		return ""
	}
	return value[begin : begin+finish]
}
