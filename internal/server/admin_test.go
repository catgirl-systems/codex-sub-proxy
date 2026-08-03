package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/catgirl-systems/codex-sub-proxy/internal/storage"
	"github.com/kataras/iris/v12"
)

func openAdminTestStore(t *testing.T, key []byte, now *time.Time) (*AdminTokenStore, func()) {
	t.Helper()
	db, err := storage.Open(context.Background(), t.TempDir()+"/admin.sqlite3", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if err := MigrateAdminTokens(db); err != nil {
		t.Fatal(err)
	}
	store := newAdminTokenStoreWithClock(db, key, func() time.Time { return *now })
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatal(err)
	}
	return store, func() { _ = sqlDB.Close() }
}

func adminTestToken() string {
	return AdminTokenPrefix + strings.Repeat("a", adminTokenPrefixBytes*2) + "_" + strings.Repeat("b", adminTokenSecretBytes*2)
}

func TestAdminTokenStoreScopesUseAndRevoke(t *testing.T) {
	now := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
	store, closeStore := openAdminTestStore(t, []byte("admin-hmac"), &now)
	defer closeStore()
	bootstrapRaw := adminTestToken()
	materialized, err := store.MaterializeBootstrap(context.Background(), []byte(bootstrapRaw))
	if err != nil || !materialized {
		t.Fatalf("materialize bootstrap = %t, %v", materialized, err)
	}
	principal, err := store.AuthenticateHeaders(context.Background(), []string{"Bearer " + bootstrapRaw})
	if err != nil {
		t.Fatalf("authenticate bootstrap: %v", err)
	}
	if err := store.Authorize(context.Background(), principal, AdminScopeMetadata); err != nil {
		t.Fatalf("authorize metadata: %v", err)
	}
	var stored AdminToken
	if err := store.db.First(&stored, "id = ?", principal.ID).Error; err != nil {
		t.Fatal(err)
	}
	if stored.LastUsedAt == nil || !stored.LastUsedAt.Equal(now) {
		t.Fatalf("last used = %v, want %v", stored.LastUsedAt, now)
	}
	previousUse := *stored.LastUsedAt
	now = now.Add(-time.Minute)
	if err := store.Authorize(context.Background(), principal, AdminScopeContent); err != nil {
		t.Fatalf("authorize content: %v", err)
	}
	if err := store.db.First(&stored, "id = ?", principal.ID).Error; err != nil {
		t.Fatal(err)
	}
	if !stored.LastUsedAt.Equal(previousUse) {
		t.Fatalf("last used moved backwards to %v", stored.LastUsedAt)
	}

	metadataRaw, metadataRecord, err := store.Create(context.Background(), AdminTokenCreateRequest{Name: "metadata-only", Scopes: AdminTokenScopes{AdminScopeMetadata}}, principal)
	if err != nil {
		t.Fatalf("create metadata token: %v", err)
	}
	metadataPrincipal, err := store.Authenticate(context.Background(), []byte(metadataRaw))
	if err != nil {
		t.Fatalf("authenticate metadata token: %v", err)
	}
	if metadataPrincipal.HasScope(AdminScopeContent) {
		t.Fatal("metadata token has content scope")
	}
	if err := store.Authorize(context.Background(), metadataPrincipal, AdminScopeContent); err == nil {
		t.Fatal("metadata token passed content authorization")
	}
	if _, err := store.Revoke(context.Background(), principal.ID, principal); err != nil {
		t.Fatalf("revoke bootstrap: %v", err)
	}
	if _, err := store.Authenticate(context.Background(), []byte(bootstrapRaw)); err == nil {
		t.Fatal("revoked bootstrap token authenticated")
	}
	if _, err := store.Revoke(context.Background(), principal.ID, metadataPrincipal); err != nil {
		t.Fatalf("repeat revoke: %v", err)
	}
	if metadataRecord.ID == principal.ID {
		t.Fatal("generated token reused bootstrap ID")
	}
	var audits []AuditRecord
	if err := store.db.Order("created_at asc").Find(&audits).Error; err != nil {
		t.Fatal(err)
	}
	if len(audits) != 4 {
		t.Fatalf("audit count = %d, want 4", len(audits))
	}
	for _, audit := range audits {
		if audit.PrincipalID == "" || audit.PrincipalName == "" || audit.Action == "" || audit.TargetID == "" || audit.CreatedAt.IsZero() {
			t.Fatalf("incomplete audit = %+v", audit)
		}
		if strings.Contains(audit.Metadata, bootstrapRaw) || strings.Contains(audit.Metadata, "digest") {
			t.Fatalf("secret in audit metadata = %q", audit.Metadata)
		}
	}
	if bytes.Contains(stored.Digest, []byte(bootstrapRaw)) {
		t.Fatal("raw bootstrap token stored in digest")
	}
}

func TestAdminRoutesReturnTokenOnceAndGuardContent(t *testing.T) {
	now := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
	store, closeStore := openAdminTestStore(t, []byte("admin-hmac"), &now)
	defer closeStore()
	bootstrapRaw := adminTestToken()
	if _, err := store.MaterializeBootstrap(context.Background(), []byte(bootstrapRaw)); err != nil {
		t.Fatal(err)
	}
	app, err := newAdminApplication(NewReadiness(), store)
	if err != nil {
		t.Fatal(err)
	}
	httpServer := httptest.NewServer(app)
	defer httpServer.Close()

	requestBody := strings.NewReader(`{"name":"metadata-route","scopes":["metadata"]}`)
	request, err := http.NewRequest(http.MethodPost, httpServer.URL+adminTokensEndpoint, requestBody)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+bootstrapRaw)
	request.Header.Set("Content-Type", "application/json")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	var created struct {
		ID    string `json:"id"`
		Token string `json:"token"`
	}
	if err := json.NewDecoder(response.Body).Decode(&created); err != nil {
		response.Body.Close()
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusCreated || created.Token == "" {
		t.Fatalf("create status=%d token=%q", response.StatusCode, created.Token)
	}
	listRequest, _ := http.NewRequest(http.MethodGet, httpServer.URL+adminTokensEndpoint, nil)
	listRequest.Header.Set("Authorization", "Bearer "+bootstrapRaw)
	listResponse, err := http.DefaultClient.Do(listRequest)
	if err != nil {
		t.Fatal(err)
	}
	listBytes := make([]byte, 16*1024)
	n, readErr := listResponse.Body.Read(listBytes)
	listResponse.Body.Close()
	if readErr != nil && n == 0 {
		t.Fatal(readErr)
	}
	listBytes = listBytes[:n]
	if bytes.Contains(listBytes, []byte(created.Token)) || bytes.Contains(listBytes, []byte("digest")) {
		t.Fatalf("list exposed secret: %s", listBytes)
	}
	if listResponse.StatusCode != http.StatusOK {
		t.Fatalf("list status = %d", listResponse.StatusCode)
	}

	contentApp := httptest.NewServer(buildAdminContentTestApplication(store))
	defer contentApp.Close()
	contentRequest, _ := http.NewRequest(http.MethodGet, contentApp.URL+"/test-decrypt", nil)
	contentRequest.Header.Set("Authorization", "Bearer "+created.Token)
	contentResponse, err := http.DefaultClient.Do(contentRequest)
	if err != nil {
		t.Fatal(err)
	}
	contentResponse.Body.Close()
	if contentResponse.StatusCode != http.StatusForbidden {
		t.Fatalf("metadata content status = %d, want 403", contentResponse.StatusCode)
	}
	contentRequest, _ = http.NewRequest(http.MethodGet, contentApp.URL+"/test-decrypt", nil)
	contentRequest.Header.Set("Authorization", "Bearer "+bootstrapRaw)
	contentResponse, err = http.DefaultClient.Do(contentRequest)
	if err != nil {
		t.Fatal(err)
	}
	contentResponse.Body.Close()
	if contentResponse.StatusCode != http.StatusOK {
		t.Fatalf("content scope status = %d, want 200", contentResponse.StatusCode)
	}

	revokeRequest, _ := http.NewRequest(http.MethodDelete, httpServer.URL+adminTokensEndpoint+"/"+created.ID, nil)
	revokeRequest.Header.Set("Authorization", "Bearer "+bootstrapRaw)
	revokeResponse, err := http.DefaultClient.Do(revokeRequest)
	if err != nil {
		t.Fatal(err)
	}
	revokeResponse.Body.Close()
	if revokeResponse.StatusCode != http.StatusOK {
		t.Fatalf("revoke status = %d", revokeResponse.StatusCode)
	}
	authRequest, _ := http.NewRequest(http.MethodGet, httpServer.URL+adminTokensEndpoint, nil)
	authRequest.Header.Set("Authorization", "Bearer "+created.Token)
	authResponse, err := http.DefaultClient.Do(authRequest)
	if err != nil {
		t.Fatal(err)
	}
	authResponse.Body.Close()
	if authResponse.StatusCode != http.StatusUnauthorized {
		t.Fatalf("revoked token status = %d", authResponse.StatusCode)
	}
}

func buildAdminContentTestApplication(store *AdminTokenStore) *iris.Application {
	app := iris.New()
	app.Get("/test-decrypt", func(ctx iris.Context) {
		principal, err := store.AuthenticateHeaders(ctx.Request().Context(), ctx.Request().Header.Values("Authorization"))
		if err != nil {
			writeAdminAuthError(ctx, err)
			return
		}
		setAdminPrincipal(ctx, principal)
		if err := RequireAdminContent(ctx); err != nil {
			writeAdminAuthError(ctx, err)
			return
		}
		writeJSON(ctx, http.StatusOK, struct {
			Content string `json:"content"`
		}{Content: "decrypted"})
	})
	_ = app.Build()
	return app
}
func TestAdminBootstrapAndRevokeConcurrency(t *testing.T) {
	now := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
	store, closeStore := openAdminTestStore(t, []byte("admin-hmac"), &now)
	defer closeStore()
	raw := adminTestToken()
	const workers = 16
	results := make(chan error, workers)
	for range workers {
		go func() {
			_, err := store.MaterializeBootstrap(context.Background(), []byte(raw))
			results <- err
		}()
	}
	for range workers {
		if err := <-results; err != nil {
			t.Fatalf("concurrent bootstrap: %v", err)
		}
	}
	var tokenCount, auditCount int64
	if err := store.db.Model(&AdminToken{}).Count(&tokenCount).Error; err != nil {
		t.Fatal(err)
	}
	if err := store.db.Model(&AuditRecord{}).Where("action = ?", "admin_token.bootstrap").Count(&auditCount).Error; err != nil {
		t.Fatal(err)
	}
	if tokenCount != 1 || auditCount != 1 {
		t.Fatalf("bootstrap token/audit count = %d/%d, want 1/1", tokenCount, auditCount)
	}
	principal, err := store.Authenticate(context.Background(), []byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	revokeDone := make(chan error, 1)
	go func() {
		_, revokeErr := store.Revoke(context.Background(), principal.ID, principal)
		revokeDone <- revokeErr
	}()
	authResults := make(chan error, workers)
	for range workers {
		go func() {
			authPrincipal, authErr := store.Authenticate(context.Background(), []byte(raw))
			if authErr == nil {
				authErr = store.Authorize(context.Background(), authPrincipal, AdminScopeMetadata)
			}
			authResults <- authErr
		}()
	}
	if err := <-revokeDone; err != nil {
		t.Fatalf("concurrent revoke: %v", err)
	}
	for range workers {
		<-authResults
	}
	if _, err := store.Authenticate(context.Background(), []byte(raw)); err == nil {
		t.Fatal("token authenticated after concurrent revoke")
	}
	secondStore := NewAdminTokenStore(store.db, []byte("admin-hmac"))
	otherRaw := AdminTokenPrefix + strings.Repeat("c", adminTokenPrefixBytes*2) + "_" + strings.Repeat("d", adminTokenSecretBytes*2)
	materialized, err := secondStore.MaterializeBootstrap(context.Background(), []byte(otherRaw))
	if err != nil {
		t.Fatal(err)
	}
	if materialized {
		t.Fatal("bootstrap reset existing token")
	}
}

func TestAdminExpiryBoundaryAndAuditRollback(t *testing.T) {
	now := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
	store, closeStore := openAdminTestStore(t, []byte("admin-hmac"), &now)
	defer closeStore()
	raw := adminTestToken()
	if _, err := store.MaterializeBootstrap(context.Background(), []byte(raw)); err != nil {
		t.Fatal(err)
	}
	actor, err := store.Authenticate(context.Background(), []byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	expires := now.Add(time.Second)
	futureRaw, record, err := store.Create(context.Background(), AdminTokenCreateRequest{Name: "expires", Scopes: AdminTokenScopes{AdminScopeMetadata}, ExpiresAt: &expires}, actor)
	if err != nil {
		t.Fatal(err)
	}
	now = expires.Add(-time.Nanosecond)
	if principal, err := store.Authenticate(context.Background(), []byte(futureRaw)); err != nil {
		t.Fatalf("authenticate before expiry: %v", err)
	} else if err := store.Authorize(context.Background(), principal, AdminScopeMetadata); err != nil {
		t.Fatalf("authorize before expiry: %v", err)
	}
	now = expires
	if _, err := store.Authenticate(context.Background(), []byte(futureRaw)); err == nil {
		t.Fatal("token authenticated at expiry boundary")
	}
	if err := store.db.Migrator().DropTable(&AuditRecord{}); err != nil {
		t.Fatal(err)
	}
	_, _, err = store.Create(context.Background(), AdminTokenCreateRequest{Name: "rollback", Scopes: AdminTokenScopes{AdminScopeMetadata}}, actor)
	if err == nil {
		t.Fatal("create succeeded without audit table")
	}
	var count int64
	if err := store.db.Model(&AdminToken{}).Where("name = ?", "rollback").Count(&count).Error; err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("rolled back token count = %d", count)
	}
	if record.ID == "" {
		t.Fatal("created token has no ID")
	}
}
func TestAdminRoutesUseRealAdminListener(t *testing.T) {
	db, err := storage.Open(context.Background(), t.TempDir()+"/listener.sqlite3", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatal(err)
	}
	defer sqlDB.Close()
	raw := adminTestToken()
	readiness := NewReadiness()
	readiness.Set(true, true, func() CredentialSnapshot { return CredentialSnapshot{Available: true} })
	servers, err := Start(Config{
		Listen:              "127.0.0.1:0",
		AdminListen:         "127.0.0.1:0",
		Database:            db,
		AdminTokenHMACKey:   []byte("admin-hmac"),
		AdminBootstrapToken: []byte(raw),
	}, readiness)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := servers.Shutdown(ctx); err != nil {
			t.Fatal(err)
		}
	}()
	client := &http.Client{Timeout: time.Second}
	for _, endpoint := range []string{"http://" + servers.AdminAddr() + "/readyz", "http://" + servers.DataAddr() + "/readyz"} {
		response, err := client.Get(endpoint)
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		if response.StatusCode != http.StatusOK {
			t.Fatalf("readiness status for %s = %d", endpoint, response.StatusCode)
		}
	}
	request, err := http.NewRequest(http.MethodGet, "http://"+servers.AdminAddr()+adminTokensEndpoint, nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+raw)
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("admin list status = %d", response.StatusCode)
	}
	dataRequest, err := http.NewRequest(http.MethodGet, "http://"+servers.DataAddr()+adminTokensEndpoint, nil)
	if err != nil {
		t.Fatal(err)
	}
	dataResponse, err := client.Do(dataRequest)
	if err != nil {
		t.Fatal(err)
	}
	dataResponse.Body.Close()
	if dataResponse.StatusCode != http.StatusNotFound {
		t.Fatalf("data admin route status = %d, want 404", dataResponse.StatusCode)
	}
}
func TestAdminReadinessDoesNotChangeDataReadiness(t *testing.T) {
	db, err := storage.Open(context.Background(), t.TempDir()+"/unavailable.sqlite3", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatal(err)
	}
	defer sqlDB.Close()
	readiness := NewReadiness()
	readiness.Set(true, true, func() CredentialSnapshot { return CredentialSnapshot{Available: true} })
	servers, err := Start(Config{Listen: "127.0.0.1:0", AdminListen: "127.0.0.1:0", Database: db}, readiness)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = servers.Shutdown(ctx)
	}()
	client := &http.Client{Timeout: time.Second}
	dataResponse, err := client.Get("http://" + servers.DataAddr() + "/readyz")
	if err != nil {
		t.Fatal(err)
	}
	dataResponse.Body.Close()
	adminResponse, err := client.Get("http://" + servers.AdminAddr() + "/readyz")
	if err != nil {
		t.Fatal(err)
	}
	adminResponse.Body.Close()
	if dataResponse.StatusCode != http.StatusOK || adminResponse.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("data/admin readiness = %d/%d, want 200/503", dataResponse.StatusCode, adminResponse.StatusCode)
	}
	request, err := http.NewRequest(http.MethodGet, "http://"+servers.AdminAddr()+adminTokensEndpoint, nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("admin unavailable route status = %d, want 503", response.StatusCode)
	}
}
