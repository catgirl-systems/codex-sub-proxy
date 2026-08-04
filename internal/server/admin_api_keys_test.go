package server

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/catgirl-systems/codex-sub-proxy/internal/apikey"
	"github.com/catgirl-systems/codex-sub-proxy/internal/storage"
)

func TestAdminAPIKeyIssuePatchRevokeAndDataAuth(t *testing.T) {
	db, err := storage.Open(context.Background(), t.TempDir()+"/api-keys.sqlite3", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sqlDB.Close() })
	adminRaw := adminTestToken()
	apiHMAC := []byte("api-key-hmac-key-for-test-012345678901")
	readiness := NewReadiness()
	readiness.Set(true, true, func() CredentialSnapshot { return CredentialSnapshot{Available: true} })
	servers, err := Start(Config{
		Listen:              "127.0.0.1:0",
		AdminListen:         "127.0.0.1:0",
		Database:            db,
		APIKeyHMACKey:       apiHMAC,
		AdminTokenHMACKey:   []byte("admin-hmac"),
		AdminBootstrapToken: []byte(adminRaw),
	}, readiness)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = servers.Shutdown(ctx)
	})
	client := &http.Client{Timeout: 3 * time.Second}
	adminURL := "http://" + servers.AdminAddr() + adminAPIKeysEndpoint
	dataURL := "http://" + servers.DataAddr() + modelsEndpoint
	policy := adminAPIKeyPolicy{AllowedEndpoints: []string{modelsEndpoint}, AllowedModels: []string{"gpt-a"}}
	body, err := json.Marshal(adminAPIKeyIssueBody{Name: "listener-key", Owner: "test-owner", Policy: policy})
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequest(http.MethodPost, adminURL, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+adminRaw)
	request.Header.Set("Content-Type", "application/json")
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	var issued adminAPIKeyIssueResponse
	if err := json.NewDecoder(response.Body).Decode(&issued); err != nil {
		response.Body.Close()
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusCreated || issued.Key == "" || issued.ID == "" {
		t.Fatalf("issue status/key/id = %d/%q/%q", response.StatusCode, issued.Key, issued.ID)
	}
	if !strings.HasPrefix(issued.Key, apikey.KeyPrefix) {
		t.Fatalf("issued key prefix = %q", issued.Key)
	}

	listRequest, err := http.NewRequest(http.MethodGet, adminURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	listRequest.Header.Set("Authorization", "Bearer "+adminRaw)
	listResponse, err := client.Do(listRequest)
	if err != nil {
		t.Fatal(err)
	}
	listBytes, err := io.ReadAll(listResponse.Body)
	listResponse.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if listResponse.StatusCode != http.StatusOK || bytes.Contains(listBytes, []byte(issued.Key)) || bytes.Contains(listBytes, []byte("digest")) || bytes.Contains(listBytes, []byte(`"key"`)) {
		t.Fatalf("list status/body = %d/%s", listResponse.StatusCode, listBytes)
	}
	detailRequest, err := http.NewRequest(http.MethodGet, adminURL+"/"+issued.ID, nil)
	if err != nil {
		t.Fatal(err)
	}
	detailRequest.Header.Set("Authorization", "Bearer "+adminRaw)
	detailResponse, err := client.Do(detailRequest)
	if err != nil {
		t.Fatal(err)
	}
	detailBytes, err := io.ReadAll(detailResponse.Body)
	detailResponse.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if detailResponse.StatusCode != http.StatusOK || bytes.Contains(detailBytes, []byte(issued.Key)) || bytes.Contains(detailBytes, []byte("digest")) || bytes.Contains(detailBytes, []byte(`"key"`)) {
		t.Fatalf("detail status/body = %d/%s", detailResponse.StatusCode, detailBytes)
	}
	usageRequest, err := http.NewRequest(http.MethodGet, adminURL+"/"+issued.ID+"/usage", nil)
	if err != nil {
		t.Fatal(err)
	}
	usageRequest.Header.Set("Authorization", "Bearer "+adminRaw)
	usageResponse, err := client.Do(usageRequest)
	if err != nil {
		t.Fatal(err)
	}
	usageBytes, err := io.ReadAll(usageResponse.Body)
	usageResponse.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if usageResponse.StatusCode != http.StatusOK || bytes.Contains(usageBytes, []byte(issued.Key)) || bytes.Contains(usageBytes, []byte("reservation_id")) || bytes.Contains(usageBytes, []byte("request_id")) {
		t.Fatalf("usage status/body = %d/%s", usageResponse.StatusCode, usageBytes)
	}
	dataRequest, err := http.NewRequest(http.MethodGet, dataURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	dataRequest.Header.Set("Authorization", "Bearer "+issued.Key)
	dataResponse, err := client.Do(dataRequest)
	if err != nil {
		t.Fatal(err)
	}
	dataResponse.Body.Close()
	if dataResponse.StatusCode != http.StatusOK {
		t.Fatalf("issued key data status = %d", dataResponse.StatusCode)
	}

	const patchWorkers = 16
	patchStatuses := make(chan int, patchWorkers)
	for worker := range patchWorkers {
		go func(worker int) {
			body := `{"name":"listener-key-` + strconv.Itoa(worker) + `"}`
			request, requestErr := http.NewRequest(http.MethodPatch, adminURL+"/"+issued.ID, strings.NewReader(body))
			if requestErr != nil {
				patchStatuses <- 0
				return
			}
			request.Header.Set("Authorization", "Bearer "+adminRaw)
			request.Header.Set("Content-Type", "application/json")
			response, requestErr := client.Do(request)
			if requestErr != nil {
				patchStatuses <- 0
				return
			}
			response.Body.Close()
			patchStatuses <- response.StatusCode
		}(worker)
	}
	for range patchWorkers {
		if status := <-patchStatuses; status != http.StatusOK {
			t.Fatalf("concurrent patch status = %d", status)
		}
	}
	patchBody := `{"disabled":true}`
	patchRequest, err := http.NewRequest(http.MethodPatch, adminURL+"/"+issued.ID, strings.NewReader(patchBody))
	if err != nil {
		t.Fatal(err)
	}
	patchRequest.Header.Set("Authorization", "Bearer "+adminRaw)
	patchRequest.Header.Set("Content-Type", "application/json")
	patchResponse, err := client.Do(patchRequest)
	if err != nil {
		t.Fatal(err)
	}
	patchResponse.Body.Close()
	if patchResponse.StatusCode != http.StatusOK {
		t.Fatalf("disable status = %d", patchResponse.StatusCode)
	}
	dataRequest, _ = http.NewRequest(http.MethodGet, dataURL, nil)
	dataRequest.Header.Set("Authorization", "Bearer "+issued.Key)
	dataResponse, err = client.Do(dataRequest)
	if err != nil {
		t.Fatal(err)
	}
	dataResponse.Body.Close()
	if dataResponse.StatusCode != http.StatusUnauthorized {
		t.Fatalf("disabled key data status = %d", dataResponse.StatusCode)
	}

	revokeRequest, err := http.NewRequest(http.MethodDelete, adminURL+"/"+issued.ID, nil)
	if err != nil {
		t.Fatal(err)
	}
	revokeRequest.Header.Set("Authorization", "Bearer "+adminRaw)
	revokeResponse, err := client.Do(revokeRequest)
	if err != nil {
		t.Fatal(err)
	}
	revokeResponse.Body.Close()
	if revokeResponse.StatusCode != http.StatusOK {
		t.Fatalf("revoke status = %d", revokeResponse.StatusCode)
	}
	const revokeWorkers = 32
	revokeStatuses := make(chan int, revokeWorkers)
	for range revokeWorkers {
		go func() {
			request, requestErr := http.NewRequest(http.MethodDelete, adminURL+"/"+issued.ID, nil)
			if requestErr != nil {
				revokeStatuses <- 0
				return
			}
			request.Header.Set("Authorization", "Bearer "+adminRaw)
			response, requestErr := client.Do(request)
			if requestErr != nil {
				revokeStatuses <- 0
				return
			}
			response.Body.Close()
			revokeStatuses <- response.StatusCode
		}()
	}
	for range revokeWorkers {
		if status := <-revokeStatuses; status != http.StatusOK {
			t.Fatalf("concurrent revoke status = %d", status)
		}
	}
	var stored apikey.Record
	if err := db.Select("id", "digest", "revoked_at", "revoked_by").First(&stored, "id = ?", issued.ID).Error; err != nil {
		t.Fatal(err)
	}
	if len(stored.Digest) != 32 || stored.RevokedAt == nil || stored.RevokedBy == "" {
		t.Fatalf("stored revoke metadata = %+v", stored)
	}
}

func TestAdminAPIKeyRoutesRequireMetadataBeforeBodyOrTarget(t *testing.T) {
	now := time.Now().UTC()
	store, closeStore := openAdminTestStore(t, []byte("admin-hmac"), &now)
	defer closeStore()
	raw := adminTestToken()
	if _, err := store.MaterializeBootstrap(context.Background(), []byte(raw)); err != nil {
		t.Fatal(err)
	}
	metadataRaw, _, err := store.Create(context.Background(), AdminTokenCreateRequest{Name: "metadata-only-api", Scopes: AdminTokenScopes{AdminScopeMetadata}}, AdminPrincipal{ID: "bootstrap", Name: "bootstrap", Scopes: AdminTokenScopes{AdminScopeMetadata, AdminScopeContent}})
	if err != nil {
		t.Fatal(err)
	}
	contentRaw, _, err := store.Create(context.Background(), AdminTokenCreateRequest{Name: "content-only-api", Scopes: AdminTokenScopes{AdminScopeContent}}, AdminPrincipal{ID: "bootstrap", Name: "bootstrap", Scopes: AdminTokenScopes{AdminScopeMetadata, AdminScopeContent}})
	if err != nil {
		t.Fatal(err)
	}
	app, err := newAdminApplication(NewReadiness(), store, apikey.NewStore(store.db, []byte("api-key-hmac")))
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(app)
	defer server.Close()
	request, err := http.NewRequest(http.MethodPatch, server.URL+adminAPIKeysEndpoint+"/not-an-id", strings.NewReader(strings.Repeat("x", adminBodyLimit*2)))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+metadataRaw)
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("metadata oversized patch status = %d, want 413", response.StatusCode)
	}
	request, err = http.NewRequest(http.MethodPatch, server.URL+adminAPIKeysEndpoint+"/not-an-id", strings.NewReader(strings.Repeat("x", adminBodyLimit*2)))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+contentRaw)
	response, err = http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("content-only oversized patch status = %d, want 403", response.StatusCode)
	}
}
