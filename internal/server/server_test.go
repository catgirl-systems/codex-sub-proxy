package server

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"
)

func TestStartServesHealthAndReadinessOnBothListeners(t *testing.T) {
	readiness := NewReadiness()
	servers, err := Start(Config{
		Listen:      "127.0.0.1:0",
		AdminListen: "127.0.0.1:0",
	}, readiness)
	if err != nil {
		t.Fatalf("start servers: %v", err)
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := servers.Shutdown(ctx); err != nil {
			t.Fatalf("shutdown servers: %v", err)
		}
	}()

	client := &http.Client{Timeout: time.Second}
	checkHealth(t, client, "http://"+servers.DataAddr()+"/healthz")
	checkHealth(t, client, "http://"+servers.AdminAddr()+"/healthz")
	checkReadiness(t, client, "http://"+servers.DataAddr()+"/readyz", http.StatusServiceUnavailable, "unavailable")

	readiness.Set(true, true, true)
	checkReadiness(t, client, "http://"+servers.AdminAddr()+"/readyz", http.StatusOK, "ready")
}

func checkHealth(t *testing.T, client *http.Client, url string) {
	t.Helper()
	response, err := client.Get(url)
	if err != nil {
		t.Fatalf("get health: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("health status = %d", response.StatusCode)
	}
	var body struct {
		Status string `json:"status"`
	}
	if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
		t.Fatalf("decode health response: %v", err)
	}
	if body.Status != "live" {
		t.Fatalf("health body status = %q", body.Status)
	}
}

func checkReadiness(t *testing.T, client *http.Client, url string, wantCode int, wantStatus string) {
	t.Helper()
	response, err := client.Get(url)
	if err != nil {
		t.Fatalf("get readiness: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode != wantCode {
		t.Fatalf("readiness status = %d, want %d", response.StatusCode, wantCode)
	}
	var body struct {
		Status string `json:"status"`
	}
	if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
		t.Fatalf("decode readiness response: %v", err)
	}
	if body.Status != wantStatus {
		t.Fatalf("readiness body status = %q, want %q", body.Status, wantStatus)
	}
}
