package server

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/catgirl-systems/codex-sub-proxy/internal/apikey"
	"github.com/catgirl-systems/codex-sub-proxy/internal/codex"
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

func TestAdminAPIKeyResponsesRoundTripEmptyModels(t *testing.T) {
	db, err := storage.Open(context.Background(), t.TempDir()+"/empty-models.sqlite3", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if err := apikey.Migrate(db); err != nil {
		t.Fatal(err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sqlDB.Close() })
	adminStore := NewAdminTokenStore(db, []byte("admin-hmac"))
	if err := MigrateAdminTokens(db); err != nil {
		t.Fatal(err)
	}
	adminRaw := adminTestToken()
	if _, err := adminStore.MaterializeBootstrap(context.Background(), []byte(adminRaw)); err != nil {
		t.Fatal(err)
	}
	app, err := newAdminApplication(NewReadiness(), adminStore, apikey.NewStore(db, []byte("api-key-hmac")))
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(app)
	defer server.Close()

	doRequest := func(method, path, body string) *http.Response {
		t.Helper()
		request, err := http.NewRequest(method, server.URL+path, strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Authorization", "Bearer "+adminRaw)
		if body != "" {
			request.Header.Set("Content-Type", "application/json")
		}
		response, err := http.DefaultClient.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		return response
	}
	decodeStrict := func(response *http.Response, destination any) {
		t.Helper()
		defer response.Body.Close()
		decoder := json.NewDecoder(response.Body)
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(destination); err != nil {
			t.Fatal(err)
		}
		var extra any
		if err := decoder.Decode(&extra); err != io.EOF {
			t.Fatalf("trailing response JSON: %v", err)
		}
	}

	issueResponse := doRequest(http.MethodPost, adminAPIKeysEndpoint, `{"name":"empty-models","owner":"owner","policy":{"allowed_endpoints":["`+modelsEndpoint+`"],"allowed_models":[]}}`)
	if issueResponse.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(issueResponse.Body)
		issueResponse.Body.Close()
		t.Fatalf("issue status = %d, body = %s", issueResponse.StatusCode, body)
	}
	var issued adminAPIKeyIssueResponse
	decodeStrict(issueResponse, &issued)
	if issued.ID == "" || issued.Key == "" || issued.Policy.AllowedModels == nil || len(issued.Policy.AllowedModels) != 0 {
		t.Fatalf("issued empty models = %#v", issued.Policy.AllowedModels)
	}

	listResponse := doRequest(http.MethodGet, adminAPIKeysEndpoint, "")
	if listResponse.StatusCode != http.StatusOK {
		listResponse.Body.Close()
		t.Fatalf("list status = %d", listResponse.StatusCode)
	}
	var listed struct {
		Data       []adminAPIKeyMetadata `json:"data"`
		NextCursor string                `json:"next_cursor,omitempty"`
	}
	decodeStrict(listResponse, &listed)
	if len(listed.Data) != 1 || listed.Data[0].Policy.AllowedModels == nil {
		t.Fatalf("listed empty models = %#v", listed.Data)
	}

	getResponse := doRequest(http.MethodGet, adminAPIKeysEndpoint+"/"+issued.ID, "")
	if getResponse.StatusCode != http.StatusOK {
		getResponse.Body.Close()
		t.Fatalf("get status = %d", getResponse.StatusCode)
	}
	var got adminAPIKeyMetadata
	decodeStrict(getResponse, &got)
	if got.Policy.AllowedModels == nil || len(got.Policy.AllowedModels) != 0 {
		t.Fatalf("got empty models = %#v", got.Policy.AllowedModels)
	}

	usageResponse := doRequest(http.MethodGet, adminAPIKeysEndpoint+"/"+issued.ID+"/usage", "")
	if usageResponse.StatusCode != http.StatusOK {
		usageResponse.Body.Close()
		t.Fatalf("usage status = %d", usageResponse.StatusCode)
	}
	var usage adminAPIKeyUsageResponse
	decodeStrict(usageResponse, &usage)
	if usage.Policy.AllowedModels == nil || len(usage.Policy.AllowedModels) != 0 {
		t.Fatalf("usage empty models = %#v", usage.Policy.AllowedModels)
	}

	patchResponse := doRequest(http.MethodPatch, adminAPIKeysEndpoint+"/"+issued.ID, `{"policy":{"allowed_endpoints":["`+modelsEndpoint+`"],"allowed_models":[]}}`)
	if patchResponse.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(patchResponse.Body)
		patchResponse.Body.Close()
		t.Fatalf("patch status = %d, body = %s", patchResponse.StatusCode, body)
	}
	var patched adminAPIKeyMetadata
	decodeStrict(patchResponse, &patched)
	if patched.Policy.AllowedModels == nil || len(patched.Policy.AllowedModels) != 0 {
		t.Fatalf("patched empty models = %#v", patched.Policy.AllowedModels)
	}
}

func TestAdminAPIKeyDecodeErrorsUseAPIKeyMessage(t *testing.T) {
	db, err := storage.Open(context.Background(), t.TempDir()+"/decode-errors.sqlite3", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if err := apikey.Migrate(db); err != nil {
		t.Fatal(err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sqlDB.Close() })
	adminStore := NewAdminTokenStore(db, []byte("admin-hmac"))
	if err := MigrateAdminTokens(db); err != nil {
		t.Fatal(err)
	}
	adminRaw := adminTestToken()
	if _, err := adminStore.MaterializeBootstrap(context.Background(), []byte(adminRaw)); err != nil {
		t.Fatal(err)
	}
	app, err := newAdminApplication(NewReadiness(), adminStore, apikey.NewStore(db, []byte("api-key-hmac")))
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(app)
	defer server.Close()
	doRequest := func(method, path, body string) *http.Response {
		t.Helper()
		request, err := http.NewRequest(method, server.URL+path, strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Authorization", "Bearer "+adminRaw)
		request.Header.Set("Content-Type", "application/json")
		response, err := http.DefaultClient.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		return response
	}
	assertAPIKeyError := func(response *http.Response) {
		t.Helper()
		defer response.Body.Close()
		var payload struct {
			Error struct {
				Message string `json:"message"`
			} `json:"error"`
		}
		if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
			t.Fatal(err)
		}
		if response.StatusCode != http.StatusBadRequest || payload.Error.Message != "Invalid API key request." {
			t.Fatalf("API-key decode response = %d/%q", response.StatusCode, payload.Error.Message)
		}
	}
	for _, body := range []string{
		`{`,
		`{"name":"bad","owner":"owner","policy":{"allowed_endpoints":["/v1/models"],"unknown":true}}`,
		`{"name":"bad","owner":"owner","policy":{"allowed_endpoints":["/v1/models"]}}{}`,
		`{"name":"bad","owner":"owner","policy":null}`,
	} {
		assertAPIKeyError(doRequest(http.MethodPost, adminAPIKeysEndpoint, body))
	}

	issueResponse := doRequest(http.MethodPost, adminAPIKeysEndpoint, `{"name":"valid","owner":"owner","policy":{"allowed_endpoints":["/v1/models"],"allowed_models":[]}}`)
	if issueResponse.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(issueResponse.Body)
		issueResponse.Body.Close()
		t.Fatalf("valid issue status = %d, body = %s", issueResponse.StatusCode, body)
	}
	var issued adminAPIKeyIssueResponse
	if err := json.NewDecoder(issueResponse.Body).Decode(&issued); err != nil {
		issueResponse.Body.Close()
		t.Fatal(err)
	}
	issueResponse.Body.Close()
	for _, body := range []string{
		`{"policy":null}`,
		`{"policy":{"allowed_endpoints":["/v1/models"],"unknown":true}}`,
		`{"policy":{"allowed_endpoints":["/v1/models"]}}{}`,
	} {
		assertAPIKeyError(doRequest(http.MethodPatch, adminAPIKeysEndpoint+"/"+issued.ID, body))
	}
}

type gatedAPIKeyBody struct {
	prefix      []byte
	suffix      []byte
	started     chan struct{}
	release     chan struct{}
	startedOnce sync.Once
	releaseOnce sync.Once
}

func newGatedAPIKeyBody(prefix, suffix []byte) *gatedAPIKeyBody {
	body := &gatedAPIKeyBody{
		prefix:  append([]byte(nil), prefix...),
		suffix:  append([]byte(nil), suffix...),
		started: make(chan struct{}),
		release: make(chan struct{}),
	}
	if len(body.prefix) == 0 {
		body.startedOnce.Do(func() { close(body.started) })
	}
	return body
}

func (body *gatedAPIKeyBody) Read(destination []byte) (int, error) {
	if len(body.prefix) > 0 {
		count := copy(destination, body.prefix)
		body.prefix = body.prefix[count:]
		if len(body.prefix) == 0 {
			body.startedOnce.Do(func() { close(body.started) })
		}
		return count, nil
	}
	<-body.release
	if len(body.suffix) == 0 {
		return 0, io.EOF
	}
	count := copy(destination, body.suffix)
	body.suffix = body.suffix[count:]
	return count, nil
}

func (body *gatedAPIKeyBody) Close() error {
	body.releaseOnce.Do(func() { close(body.release) })
	return nil
}

func (body *gatedAPIKeyBody) releaseBody() {
	body.releaseOnce.Do(func() { close(body.release) })
}

func TestAPIKeyFinalAuthorizationReloadsAfterAdminPatch(t *testing.T) {
	db, err := storage.Open(context.Background(), t.TempDir()+"/slow-auth.sqlite3", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if err := apikey.Migrate(db); err != nil {
		t.Fatal(err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sqlDB.Close() })
	apiHMAC := []byte("api-key-hmac-for-slow-auth-0123456789")
	adminStore := NewAdminTokenStore(db, []byte("admin-hmac"))
	if err := MigrateAdminTokens(db); err != nil {
		t.Fatal(err)
	}
	adminRaw := adminTestToken()
	if _, err := adminStore.MaterializeBootstrap(context.Background(), []byte(adminRaw)); err != nil {
		t.Fatal(err)
	}
	quota, err := apikey.NewQuotaStore(db)
	if err != nil {
		t.Fatal(err)
	}
	adminApp, err := newAdminApplication(NewReadiness(), adminStore, apikey.NewStore(db, apiHMAC))
	if err != nil {
		t.Fatal(err)
	}
	dataApp, err := newDataApplication(NewReadiness(), db, apiHMAC, &codex.ResponsesTransport{}, &codex.ImagesClient{}, nil, quota, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	adminServer := httptest.NewServer(adminApp)
	defer adminServer.Close()
	dataServer := httptest.NewServer(dataApp)
	defer dataServer.Close()
	client := &http.Client{Timeout: 10 * time.Second}

	doAdminRequest := func(method, path string, body []byte) *http.Response {
		t.Helper()
		request, err := http.NewRequest(method, adminServer.URL+path, bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Authorization", "Bearer "+adminRaw)
		if len(body) > 0 {
			request.Header.Set("Content-Type", "application/json")
		}
		response, err := client.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		return response
	}
	issue := func(name string, policy adminAPIKeyPolicy) (string, string) {
		t.Helper()
		body, err := json.Marshal(adminAPIKeyIssueBody{Name: name, Owner: "owner", Policy: policy})
		if err != nil {
			t.Fatal(err)
		}
		response := doAdminRequest(http.MethodPost, adminAPIKeysEndpoint, body)
		defer response.Body.Close()
		if response.StatusCode != http.StatusCreated {
			payload, _ := io.ReadAll(response.Body)
			t.Fatalf("issue %q status = %d, body = %s", name, response.StatusCode, payload)
		}
		var issued adminAPIKeyIssueResponse
		if err := json.NewDecoder(response.Body).Decode(&issued); err != nil {
			t.Fatal(err)
		}
		if issued.ID == "" || issued.Key == "" {
			t.Fatalf("issue %q returned empty key metadata", name)
		}
		return issued.ID, issued.Key
	}
	patch := func(id string, policy adminAPIKeyPolicy) {
		t.Helper()
		body, err := json.Marshal(struct {
			Policy adminAPIKeyPolicy `json:"policy"`
		}{Policy: policy})
		if err != nil {
			t.Fatal(err)
		}
		response := doAdminRequest(http.MethodPatch, adminAPIKeysEndpoint+"/"+id, body)
		defer response.Body.Close()
		if response.StatusCode != http.StatusOK {
			payload, _ := io.ReadAll(response.Body)
			t.Fatalf("patch %q status = %d, body = %s", id, response.StatusCode, payload)
		}
	}
	sendSlow := func(method, path, contentType, rawKey string, prefix, suffix []byte, id string, policy adminAPIKeyPolicy) int {
		t.Helper()
		body := newGatedAPIKeyBody(prefix, suffix)
		request, err := http.NewRequest(method, dataServer.URL+path, body)
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Authorization", "Bearer "+rawKey)
		if contentType != "" {
			request.Header.Set("Content-Type", contentType)
		}
		type result struct {
			response *http.Response
			err      error
		}
		results := make(chan result, 1)
		go func() {
			response, requestErr := client.Do(request)
			results <- result{response: response, err: requestErr}
		}()
		select {
		case <-body.started:
		case <-time.After(5 * time.Second):
			body.Close()
			t.Fatal("slow request body was not read")
		}
		patch(id, policy)
		body.releaseBody()
		requestResult := <-results
		if requestResult.err != nil {
			t.Fatal(requestResult.err)
		}
		defer requestResult.response.Body.Close()
		return requestResult.response.StatusCode
	}

	denyPolicy := func(endpoint, model string) adminAPIKeyPolicy {
		return adminAPIKeyPolicy{
			AllowedEndpoints: []string{endpoint},
			AllowedModels:    []string{model},
		}
	}
	tests := []struct {
		name        string
		endpoint    string
		model       string
		contentType string
		prefix      []byte
		suffix      []byte
	}{
		{
			name:        "responses",
			endpoint:    responsesEndpoint,
			model:       "gpt-a",
			contentType: "application/json",
			prefix:      []byte(`{"model":"gpt-a"`),
			suffix:      []byte(`}`),
		},
		{
			name:        "chat",
			endpoint:    chatCompletionsEndpoint,
			model:       "gpt-a",
			contentType: "application/json",
			prefix:      []byte(`{"model":"gpt-a","messages":[{"role":"user","content":"x"}`),
			suffix:      []byte(`]}`),
		},
		{
			name:        "image generations",
			endpoint:    imagesGenerationsEndpoint,
			model:       "gpt-image-2",
			contentType: "application/json",
			prefix:      []byte(`{"model":"gpt-image-2","prompt":"x"`),
			suffix:      []byte(`}`),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			id, rawKey := issue(test.name, adminAPIKeyPolicy{
				AllowedEndpoints: []string{test.endpoint},
				AllowedModels:    []string{test.model},
			})
			if status := sendSlow(http.MethodPost, test.endpoint, test.contentType, rawKey, test.prefix, test.suffix, id, denyPolicy(modelsEndpoint, "gpt-denied")); status != http.StatusForbidden {
				t.Fatalf("stale %s authorization status = %d, want 403", test.name, status)
			}
		})
	}
	t.Run("image edits", func(t *testing.T) {
		var requestBody bytes.Buffer
		writer := multipart.NewWriter(&requestBody)
		if err := writer.WriteField("model", "gpt-image-2"); err != nil {
			t.Fatal(err)
		}
		if err := writer.WriteField("prompt", "x"); err != nil {
			t.Fatal(err)
		}
		if err := writer.Close(); err != nil {
			t.Fatal(err)
		}
		split := requestBody.Len() / 2
		id, rawKey := issue("image-edits", adminAPIKeyPolicy{
			AllowedEndpoints: []string{imagesEditsEndpoint},
			AllowedModels:    []string{"gpt-image-2"},
		})
		if status := sendSlow(http.MethodPost, imagesEditsEndpoint, writer.FormDataContentType(), rawKey, requestBody.Bytes()[:split], requestBody.Bytes()[split:], id, denyPolicy(modelsEndpoint, "gpt-denied")); status != http.StatusForbidden {
			t.Fatalf("stale image edits authorization status = %d, want 403", status)
		}
	})
	t.Run("models", func(t *testing.T) {
		id, rawKey := issue("models", adminAPIKeyPolicy{
			AllowedEndpoints: []string{modelsEndpoint},
			AllowedModels:    []string{},
		})
		patch(id, denyPolicy(responsesEndpoint, "gpt-denied"))
		request, err := http.NewRequest(http.MethodGet, dataServer.URL+modelsEndpoint, nil)
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Authorization", "Bearer "+rawKey)
		response, err := client.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		if response.StatusCode != http.StatusForbidden {
			t.Fatalf("stale models authorization status = %d, want 403", response.StatusCode)
		}
	})
	t.Run("quota", func(t *testing.T) {
		id, rawKey := issue("quota", adminAPIKeyPolicy{
			AllowedEndpoints:      []string{responsesEndpoint},
			AllowedModels:         []string{"gpt-a"},
			MaxConcurrentRequests: 10,
		})
		authorizer := apikey.NewAuthorizer(db, apiHMAC)
		principal, err := authorizer.Authenticate(context.Background(), rawKey)
		if err != nil {
			t.Fatal(err)
		}
		admission, err := quota.Admit(context.Background(), principal.ID, principal.Policy, apikey.QuotaRequest{Requests: 1})
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = quota.Release(context.Background(), admission.ID, "test ended") }()
		if status := sendSlow(http.MethodPost, responsesEndpoint, "application/json", rawKey, []byte(`{"model":"gpt-a"`), []byte(`}`), id, adminAPIKeyPolicy{
			AllowedEndpoints:      []string{responsesEndpoint},
			AllowedModels:         []string{"gpt-a"},
			MaxConcurrentRequests: 1,
		}); status != http.StatusTooManyRequests {
			t.Fatalf("stale quota authorization status = %d, want 429", status)
		}
	})
}
