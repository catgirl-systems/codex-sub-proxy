package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/catgirl-systems/codex-sub-proxy/internal/codex"
	"github.com/catgirl-systems/codex-sub-proxy/internal/envelope"
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

	readiness.Set(true, true, func() bool { return true })
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

func TestReadinessReflectsCredentialChanges(t *testing.T) {
	credentialPath := filepath.Join(t.TempDir(), "credential.enc")
	credentialKey := testCredentialKey(t)
	credential := codex.Credential{
		AccessToken:  "access-token",
		RefreshToken: "refresh-token",
		ExpiresAt:    time.Now().Add(time.Hour),
		AccountID:    "account",
	}
	if err := codex.SaveCredential(credentialPath, credential, credentialKey); err != nil {
		t.Fatalf("save credential: %v", err)
	}

	readiness := NewReadiness()
	readiness.Set(true, true, func() bool {
		return codex.CredentialAvailable(credentialPath, credentialKey)
	})
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
	url := "http://" + servers.DataAddr() + "/readyz"
	checkReadiness(t, client, url, http.StatusOK, "ready", ReadinessSnapshot{
		Storage:      true,
		Keys:         true,
		UpstreamAuth: true,
	})

	if err := os.Remove(credentialPath); err != nil {
		t.Fatalf("remove credential: %v", err)
	}
	checkReadiness(t, client, url, http.StatusServiceUnavailable, "unavailable", ReadinessSnapshot{
		Storage: true,
		Keys:    true,
	})

	credential.ExpiresAt = time.Now().Add(-time.Second)
	if err := codex.SaveCredential(credentialPath, credential, credentialKey); err != nil {
		t.Fatalf("save expired credential: %v", err)
	}
	checkReadiness(t, client, url, http.StatusServiceUnavailable, "unavailable", ReadinessSnapshot{
		Storage: true,
		Keys:    true,
	})

	credential.ExpiresAt = time.Now().Add(time.Hour)
	if err := codex.SaveCredential(credentialPath, credential, credentialKey); err != nil {
		t.Fatalf("restore credential: %v", err)
	}
	checkReadiness(t, client, url, http.StatusOK, "ready", ReadinessSnapshot{
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

func TestShutdownStartsBothServersAndBoundsListenerWait(t *testing.T) {
	dataListener := newShutdownTestListener()
	adminListener := newShutdownTestListener()
	servers := &Servers{
		dataServer:    &http.Server{},
		adminServer:   &http.Server{},
		dataListener:  dataListener,
		adminListener: adminListener,
		errors:        make(chan error, 2),
	}
	servers.waitGroup.Add(2)
	go servers.serve(servers.dataServer, dataListener)
	go servers.serve(servers.adminServer, adminListener)
	for name, listener := range map[string]*shutdownTestListener{
		"data":  dataListener,
		"admin": adminListener,
	} {
		select {
		case <-listener.started:
		case <-time.After(time.Second):
			t.Fatalf("%s listener did not start", name)
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	shutdownDone := make(chan error, 1)
	startedAt := time.Now()
	go func() {
		shutdownDone <- servers.Shutdown(ctx)
	}()
	for name, listener := range map[string]*shutdownTestListener{
		"data":  dataListener,
		"admin": adminListener,
	} {
		select {
		case <-listener.firstClose:
		case <-time.After(200 * time.Millisecond):
			t.Fatalf("%s server shutdown did not start", name)
		}
	}

	var shutdownErr error
	select {
	case shutdownErr = <-shutdownDone:
	case <-time.After(time.Second):
		t.Fatal("shutdown did not return")
	}
	if !errors.Is(shutdownErr, context.DeadlineExceeded) {
		t.Fatalf("shutdown error = %v, want deadline exceeded", shutdownErr)
	}
	if elapsed := time.Since(startedAt); elapsed > 500*time.Millisecond {
		t.Fatalf("shutdown took %s after deadline", elapsed)
	}

	serveDone := make(chan struct{})
	go func() {
		servers.waitGroup.Wait()
		close(serveDone)
	}()
	select {
	case <-serveDone:
	case <-time.After(time.Second):
		t.Fatal("listener goroutines did not stop after force close")
	}
}

type shutdownTestListener struct {
	addr           net.Addr
	started        chan struct{}
	firstClose     chan struct{}
	unblock        chan struct{}
	startOnce      sync.Once
	firstCloseOnce sync.Once
	closeOnce      sync.Once
	closeMu        sync.Mutex
	closeCalls     int
}

func newShutdownTestListener() *shutdownTestListener {
	return &shutdownTestListener{
		addr:       &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)},
		started:    make(chan struct{}),
		firstClose: make(chan struct{}),
		unblock:    make(chan struct{}),
	}
}

func (l *shutdownTestListener) Accept() (net.Conn, error) {
	l.startOnce.Do(func() {
		close(l.started)
	})
	<-l.unblock
	return nil, net.ErrClosed
}

func (l *shutdownTestListener) Close() error {
	l.closeMu.Lock()
	l.closeCalls++
	call := l.closeCalls
	l.closeMu.Unlock()
	if call == 1 {
		l.firstCloseOnce.Do(func() {
			close(l.firstClose)
		})
		return nil
	}
	l.closeOnce.Do(func() {
		close(l.unblock)
	})
	return nil
}

func (l *shutdownTestListener) Addr() net.Addr {
	return l.addr
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

func testCredentialKey(t *testing.T) envelope.KeySet {
	t.Helper()
	key, err := envelope.NewKey(1, bytes.Repeat([]byte{0x44}, envelope.KeySize))
	if err != nil {
		t.Fatal(err)
	}
	keys, err := envelope.NewKeySet(key)
	if err != nil {
		t.Fatal(err)
	}
	return keys
}
