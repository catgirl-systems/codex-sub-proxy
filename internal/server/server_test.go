package server

import (
	"context"
	"encoding/json"
	"io"
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
	checkReadiness(t, client, "http://"+servers.DataAddr()+"/readyz", http.StatusServiceUnavailable, "unavailable", ReadinessSnapshot{})
	checkReadiness(t, client, "http://"+servers.AdminAddr()+"/readyz", http.StatusServiceUnavailable, "unavailable", ReadinessSnapshot{})

	readiness.Set(true, true, true)
	checkReadiness(t, client, "http://"+servers.DataAddr()+"/readyz", http.StatusOK, "ready", ReadinessSnapshot{
		Storage:      true,
		Keys:         true,
		UpstreamAuth: true,
	})
	checkReadiness(t, client, "http://"+servers.AdminAddr()+"/readyz", http.StatusOK, "ready", ReadinessSnapshot{
		Storage:      true,
		Keys:         true,
		UpstreamAuth: true,
	})
}

func TestStartBoundsHeaderAndIdleConnections(t *testing.T) {
	servers, err := Start(Config{
		Listen:      "127.0.0.1:0",
		AdminListen: "127.0.0.1:0",
	}, NewReadiness())
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

	for name, server := range map[string]*http.Server{
		"data":  servers.dataServer,
		"admin": servers.adminServer,
	} {
		if server.ReadHeaderTimeout != readHeaderTimeout {
			t.Errorf("%s ReadHeaderTimeout = %s, want %s", name, server.ReadHeaderTimeout, readHeaderTimeout)
		}
		if server.WriteTimeout != writeTimeout {
			t.Errorf("%s WriteTimeout = %s, want %s", name, server.WriteTimeout, writeTimeout)
		}
		if server.IdleTimeout != idleTimeout {
			t.Errorf("%s IdleTimeout = %s, want %s", name, server.IdleTimeout, idleTimeout)
		}
	}
}

func TestHealthEndpointsRejectNonGet(t *testing.T) {
	servers, err := Start(Config{
		Listen:      "127.0.0.1:0",
		AdminListen: "127.0.0.1:0",
	}, NewReadiness())
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
	for _, address := range []string{servers.DataAddr(), servers.AdminAddr()} {
		request, err := http.NewRequest(http.MethodPost, "http://"+address+"/healthz", nil)
		if err != nil {
			t.Fatalf("new request: %v", err)
		}
		response, err := client.Do(request)
		if err != nil {
			t.Fatalf("post health: %v", err)
		}
		body, err := io.ReadAll(response.Body)
		response.Body.Close()
		if err != nil {
			t.Fatalf("read method error: %v", err)
		}
		if response.StatusCode != http.StatusMethodNotAllowed {
			t.Errorf("method status = %d, want %d", response.StatusCode, http.StatusMethodNotAllowed)
		}
		if response.Header.Get("Allow") != http.MethodGet {
			t.Errorf("allow header = %q, want %q", response.Header.Get("Allow"), http.MethodGet)
		}
		if response.Header.Get("Content-Type") != "text/plain; charset=utf-8" {
			t.Errorf("content type = %q, want text/plain; charset=utf-8", response.Header.Get("Content-Type"))
		}
		if string(body) != "method not allowed\n" {
			t.Errorf("method body = %q, want method not allowed newline", body)
		}
	}
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
	if response.Header.Get("Content-Type") != "application/json" {
		t.Fatalf("health content type = %q, want application/json", response.Header.Get("Content-Type"))
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

func checkReadiness(t *testing.T, client *http.Client, url string, wantCode int, wantStatus string, wantChecks ReadinessSnapshot) {
	t.Helper()
	response, err := client.Get(url)
	if err != nil {
		t.Fatalf("get readiness: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode != wantCode {
		t.Fatalf("readiness status = %d, want %d", response.StatusCode, wantCode)
	}
	if response.Header.Get("Content-Type") != "application/json" {
		t.Fatalf("readiness content type = %q, want application/json", response.Header.Get("Content-Type"))
	}
	var body struct {
		Status string            `json:"status"`
		Checks ReadinessSnapshot `json:"checks"`
	}
	if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
		t.Fatalf("decode readiness response: %v", err)
	}
	if body.Status != wantStatus {
		t.Fatalf("readiness body status = %q, want %q", body.Status, wantStatus)
	}
	if body.Checks != wantChecks {
		t.Fatalf("readiness checks = %+v, want %+v", body.Checks, wantChecks)
	}
}
