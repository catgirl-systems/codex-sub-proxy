package codex

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"testing"
	"time"
)

func TestModelsClientDecodesDualEnvelopeAndRenewsWithETag(t *testing.T) {
	keys := testCredentialKeys(t)
	credentialPath := filepath.Join(t.TempDir(), "credential.enc")
	if err := SaveCredential(credentialPath, Credential{
		AccessToken: "models-access", RefreshToken: "models-refresh", AccountID: "account-a", ExpiresAt: time.Now().Add(time.Hour),
	}, keys); err != nil {
		t.Fatal(err)
	}
	var requests int
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requests++
		if request.URL.Query().Get("client_version") != "client-test" {
			t.Fatalf("client_version = %q", request.URL.Query().Get("client_version"))
		}
		if request.Header.Get(AuthorizationHeader) != "Bearer models-access" || request.Header.Get(AccountIDHeader) != "account-a" {
			t.Fatalf("auth headers = %q/%q", request.Header.Get(AuthorizationHeader), request.Header.Get(AccountIDHeader))
		}
		writer.Header().Set("ETag", `"models-a"`)
		if request.Header.Get("If-None-Match") == `"models-a"` {
			writer.WriteHeader(http.StatusNotModified)
			return
		}
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{"data":[{"id":"openai-model","object":"model","created":7,"owned_by":"openai"}],"models":[{"slug":"codex-model","display_name":"Codex","supported_in_api":true,"visibility":"list","capabilities":{"supports_reasoning":true},"model_messages":{"a":"same"},"use_responses_lite":true}]}`))
	}))
	defer server.Close()
	refresher, err := NewRefresher(credentialPath, keys, RefresherOptions{Issuer: server.URL, ClientID: "client", HTTPClient: server.Client()})
	if err != nil {
		t.Fatal(err)
	}
	client, err := NewModelsClient(ModelsClientOptions{ModelsURL: server.URL + "/backend-api/models", ClientVersion: "client-test", HTTPClient: server.Client(), Refresher: refresher})
	if err != nil {
		t.Fatal(err)
	}
	result, err := client.List(context.Background(), "")
	if err != nil {
		t.Fatalf("first models request: %v", err)
	}
	if result.NotModified || len(result.Models) != 1 || result.Models[0].ID != "codex-model" || !result.Models[0].SupportsResponsesLite() {
		t.Fatalf("first result = %#v", result)
	}
	if result.Models[0].Capabilities["supports_reasoning"] != true {
		t.Fatalf("capabilities were not retained: %#v", result.Models[0].Capabilities)
	}
	if _, err := url.Parse(server.URL); err != nil {
		t.Fatal(err)
	}
	result, err = client.List(context.Background(), result.ETag)
	if err != nil {
		t.Fatalf("conditional models request: %v", err)
	}
	if !result.NotModified || requests != 2 {
		t.Fatalf("conditional result = %#v, requests = %d", result, requests)
	}
}

func TestDecodeModelCatalogRejectsMalformedSuccessAndAcceptsOpenAIData(t *testing.T) {
	if _, err := DecodeModelCatalog([]byte(`{"object":"list"}`)); err == nil {
		t.Fatal("missing model envelope accepted")
	}
	if _, err := DecodeModelCatalog([]byte(`{"models":[{"slug":"same"},{"slug":"same"}]}`)); err == nil {
		t.Fatal("duplicate model IDs accepted")
	}
	models, err := DecodeModelCatalog([]byte(`{"object":"list","data":[{"id":"openai-model","created":9,"owned_by":"openai"}]}`))
	if err != nil || len(models) != 1 || models[0].ID != "openai-model" {
		t.Fatalf("OpenAI data decode = %#v, %v", models, err)
	}
	var standard struct {
		Data []struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := json.Unmarshal([]byte(`{"object":"list","data":[{"id":"openai-model"}],"models":[{"slug":"codex-model"}]}`), &standard); err != nil {
		t.Fatal(err)
	}
	if len(standard.Data) != 1 || standard.Data[0].ID != "openai-model" {
		t.Fatalf("standard envelope = %#v", standard)
	}
}

func TestModelsClientDefaultURLUsesCodexPath(t *testing.T) {
	client, err := NewModelsClient(ModelsClientOptions{Refresher: &Refresher{}})
	if err != nil {
		t.Fatal(err)
	}
	if client.modelsURL != defaultModelsURL {
		t.Fatalf("default models URL = %q", client.modelsURL)
	}
}

func TestDecodeModelCatalogFiltersHiddenAndUnsupportedModels(t *testing.T) {
	models, err := DecodeModelCatalog([]byte(`{"models":[
		{"slug":"visible","supported_in_api":true,"visibility":"list","source":"codex","supports_parallel_tool_calls":true},
		{"slug":"hidden","supported_in_api":true,"visibility":"hide"},
		{"slug":"unsupported","supported_in_api":false,"visibility":"list"}
	]}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(models) != 1 || models[0].ID != "visible" || models[0].Source != "codex" || !models[0].SupportsParallelToolCalls {
		t.Fatalf("filtered provider models = %#v", models)
	}
}

func TestDecodeModelCatalogBoundsInput(t *testing.T) {
	if _, err := DecodeModelCatalog(make([]byte, MaxModelCatalogBytes+1)); err == nil {
		t.Fatal("oversized catalog accepted")
	}
}
