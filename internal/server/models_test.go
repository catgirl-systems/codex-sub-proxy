package server

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/catgirl-systems/codex-sub-proxy/internal/apikey"
	"github.com/catgirl-systems/codex-sub-proxy/internal/storage"
)

func TestModelsWithoutCatalogAreUnavailable(t *testing.T) {
	db, err := storage.Open(context.Background(), ":memory:", time.Second)
	if err != nil {
		t.Fatalf("open database: %v", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("get SQL database: %v", err)
	}
	defer sqlDB.Close()
	if err := apikey.Migrate(db); err != nil {
		t.Fatalf("migrate API keys: %v", err)
	}
	hmacKey := []byte("01234567890123456789012345678901")
	rawKey, _, err := apikey.Create(context.Background(), db, hmacKey, apikey.Policy{
		Name: "models", Owner: "owner", AllowedEndpoints: []string{modelsEndpoint},
		AllowedModels: []string{"gpt-z", "gpt-a"},
	})
	if err != nil {
		t.Fatalf("create API key: %v", err)
	}
	servers, err := Start(Config{Listen: "127.0.0.1:0", AdminListen: "127.0.0.1:0", Database: db, APIKeyHMACKey: hmacKey}, NewReadiness())
	if err != nil {
		t.Fatalf("start server: %v", err)
	}
	defer shutdownServerTest(t, servers)
	req, err := http.NewRequest(http.MethodGet, "http://"+servers.DataAddr()+modelsEndpoint, nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+rawKey)
	response, err := (&http.Client{Timeout: time.Second}).Do(req)
	if err != nil {
		t.Fatalf("request models: %v", err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("models status = %d, want unavailable", response.StatusCode)
	}
}

func TestModelsRejectsMalformedOversizeAndDeniedRequests(t *testing.T) {
	db, err := storage.Open(context.Background(), ":memory:", time.Second)
	if err != nil {
		t.Fatalf("open database: %v", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("get SQL database: %v", err)
	}
	defer sqlDB.Close()
	if err := apikey.Migrate(db); err != nil {
		t.Fatalf("migrate API keys: %v", err)
	}
	hmacKey := []byte("01234567890123456789012345678901")
	rawKey, _, err := apikey.Create(context.Background(), db, hmacKey, apikey.Policy{
		Name:             "denied",
		Owner:            "owner",
		AllowedEndpoints: []string{"/v1/responses"},
		AllowedModels:    []string{"gpt-a"},
	})
	if err != nil {
		t.Fatalf("create API key: %v", err)
	}
	servers, err := Start(Config{Listen: "127.0.0.1:0", AdminListen: "127.0.0.1:0", Database: db, APIKeyHMACKey: hmacKey}, NewReadiness())
	if err != nil {
		t.Fatalf("start server: %v", err)
	}
	defer shutdownServerTest(t, servers)
	client := &http.Client{Timeout: time.Second}
	cases := []struct {
		name   string
		header string
		status int
	}{
		{name: "missing", status: http.StatusUnauthorized},
		{name: "malformed", header: "Bearer bad", status: http.StatusUnauthorized},
		{name: "oversize", header: "Bearer " + strings.Repeat("x", apikey.MaxAuthorizationHeaderSize), status: http.StatusUnauthorized},
		{name: "endpoint denied", header: "Bearer " + rawKey, status: http.StatusForbidden},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodGet, "http://"+servers.DataAddr()+modelsEndpoint, nil)
			if err != nil {
				t.Fatalf("build request: %v", err)
			}
			if testCase.header != "" {
				req.Header.Set("Authorization", testCase.header)
			}
			response, err := client.Do(req)
			if err != nil {
				t.Fatalf("request models: %v", err)
			}
			response.Body.Close()
			if response.StatusCode != testCase.status {
				t.Fatalf("status = %d, want %d", response.StatusCode, testCase.status)
			}
		})
	}
}

func shutdownServerTest(t *testing.T, servers *Servers) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := servers.Shutdown(ctx); err != nil {
		t.Fatalf("shutdown server: %v", err)
	}
}
