package codex

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestRefresherSingleFlightPersistsRotatedCredential(t *testing.T) {
	path := filepath.Join(t.TempDir(), "credential.enc")
	keys := testCredentialKeys(t)
	original := Credential{
		AccessToken:  "old-access",
		IDToken:      "old-id",
		RefreshToken: "old-refresh",
		ExpiresAt:    time.Now().Add(-time.Minute),
		AccountID:    "account",
	}
	if err := SaveCredential(path, original, keys); err != nil {
		t.Fatal(err)
	}

	started := make(chan struct{})
	release := make(chan struct{})
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/oauth/token" {
			http.NotFound(writer, request)
			return
		}
		if requests.Add(1) != 1 {
			http.Error(writer, "unexpected extra refresh", http.StatusInternalServerError)
			return
		}
		form, err := url.ParseQuery(readBody(t, request))
		if err != nil || form.Get("refresh_token") != original.RefreshToken {
			http.Error(writer, "invalid refresh request", http.StatusBadRequest)
			return
		}
		close(started)
		<-release
		writer.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(writer, `{"access_token":"new-access","refresh_token":"new-refresh","id_token":"new-id","expires_in":3600}`)
	}))
	defer server.Close()

	refresher, err := NewRefresher(path, keys, RefresherOptions{Issuer: server.URL, ClientID: "client", HTTPClient: server.Client()})
	if err != nil {
		t.Fatal(err)
	}
	const callers = 8
	start := make(chan struct{})
	results := make(chan Credential, callers)
	errorsCh := make(chan error, callers)
	var group sync.WaitGroup
	group.Add(callers)
	for range callers {
		go func() {
			defer group.Done()
			<-start
			credential, callErr := refresher.Credential(context.Background())
			results <- credential
			errorsCh <- callErr
		}()
	}
	close(start)
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("refresh did not start")
	}
	if got := refresher.Status(); got != CredentialStatusRefreshing {
		t.Fatalf("status while refreshing = %q", got)
	}
	close(release)
	group.Wait()
	close(results)
	close(errorsCh)
	for callErr := range errorsCh {
		if callErr != nil {
			t.Fatalf("refresh error: %v", callErr)
		}
	}
	for credential := range results {
		if credential.AccessToken != "new-access" || credential.RefreshToken != "new-refresh" || credential.IDToken != "new-id" {
			t.Fatalf("credential = %#v", credential)
		}
	}
	if requests.Load() != 1 {
		t.Fatalf("refresh requests = %d, want 1", requests.Load())
	}
	stored, err := LoadCredential(path, keys)
	if err != nil {
		t.Fatal(err)
	}
	if stored.AccessToken != "new-access" || stored.RefreshToken != "new-refresh" || stored.IDToken != "new-id" {
		t.Fatalf("stored credential = %#v", stored)
	}
	stored.ExpiresAt = time.Now().Add(4 * time.Minute)
	if err := SaveCredential(path, stored, keys); err != nil {
		t.Fatal(err)
	}
	if got := refresher.Status(); got != CredentialStatusRefreshable {
		t.Fatalf("refreshable status = %q", got)
	}
	stored.ExpiresAt = time.Now().Add(-time.Minute)
	if err := SaveCredential(path, stored, keys); err != nil {
		t.Fatal(err)
	}
	if got := refresher.Status(); got != CredentialStatusExpired {
		t.Fatalf("expired status = %q", got)
	}
	encoded, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encoded, []byte("new-access")) || bytes.Contains(encoded, []byte("new-refresh")) || bytes.Contains(encoded, []byte("new-id")) {
		t.Fatal("rotated token reached credential file")
	}
	if got := binary.BigEndian.Uint32(encoded[5:9]); got != keys.Active.Version {
		t.Fatalf("credential key version = %d, want %d", got, keys.Active.Version)
	}
}

func TestRefresherSnapshotDoesNotWaitForActiveRefresh(t *testing.T) {
	path := filepath.Join(t.TempDir(), "credential.enc")
	keys := testCredentialKeys(t)
	if err := SaveCredential(path, Credential{
		AccessToken:  "old-access",
		RefreshToken: "old-refresh",
		ExpiresAt:    time.Now().Add(-time.Minute),
		AccountID:    "account",
	}, keys); err != nil {
		t.Fatal(err)
	}
	started := make(chan struct{})
	release := make(chan struct{})
	var releaseOnce sync.Once
	defer releaseOnce.Do(func() { close(release) })
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		close(started)
		<-release
		writer.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(writer, `{"access_token":"new-access","refresh_token":"new-refresh","expires_in":3600}`)
	}))
	defer server.Close()
	refresher, err := NewRefresher(path, keys, RefresherOptions{Issuer: server.URL, ClientID: "client", HTTPClient: server.Client()})
	if err != nil {
		t.Fatal(err)
	}
	refreshDone := make(chan error, 1)
	go func() {
		_, refreshErr := refresher.Credential(context.Background())
		refreshDone <- refreshErr
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("refresh did not start")
	}
	snapshotDone := make(chan CredentialSnapshot, 1)
	go func() {
		snapshotDone <- refresher.Snapshot()
	}()
	select {
	case snapshot := <-snapshotDone:
		if snapshot.State != CredentialStatusRefreshing {
			t.Fatalf("snapshot = %+v, want refreshing", snapshot)
		}
	case <-time.After(time.Second):
		t.Fatal("snapshot waited for active refresh")
	}
	releaseOnce.Do(func() { close(release) })
	if refreshErr := <-refreshDone; refreshErr != nil {
		t.Fatalf("refresh error: %v", refreshErr)
	}
}

func TestRefresherCanceledWaiterDoesNotCancelRefresh(t *testing.T) {
	path := filepath.Join(t.TempDir(), "credential.enc")
	keys := testCredentialKeys(t)
	if err := SaveCredential(path, Credential{
		AccessToken:  "old-access",
		RefreshToken: "old-refresh",
		ExpiresAt:    time.Now().Add(-time.Minute),
		AccountID:    "account",
	}, keys); err != nil {
		t.Fatal(err)
	}
	started := make(chan struct{})
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		close(started)
		<-release
		writer.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(writer, `{"access_token":"new-access","refresh_token":"new-refresh","expires_in":3600}`)
	}))
	defer server.Close()
	refresher, err := NewRefresher(path, keys, RefresherOptions{Issuer: server.URL, ClientID: "client", HTTPClient: server.Client()})
	if err != nil {
		t.Fatal(err)
	}
	leaderDone := make(chan error, 1)
	go func() {
		_, leaderErr := refresher.Credential(context.Background())
		leaderDone <- leaderErr
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("refresh did not start")
	}
	waiterContext, cancel := context.WithCancel(context.Background())
	waiterDone := make(chan error, 1)
	go func() {
		_, waiterErr := refresher.Credential(waiterContext)
		waiterDone <- waiterErr
	}()
	cancel()
	select {
	case waiterErr := <-waiterDone:
		if !errors.Is(waiterErr, context.Canceled) {
			t.Fatalf("waiter error = %v", waiterErr)
		}
	case <-time.After(time.Second):
		t.Fatal("canceled waiter did not return")
	}
	close(release)
	if leaderErr := <-leaderDone; leaderErr != nil {
		t.Fatalf("leader error: %v", leaderErr)
	}
}

func TestRefresherLeaderCancellationDoesNotCancelLiveWaiter(t *testing.T) {
	path := filepath.Join(t.TempDir(), "credential.enc")
	keys := testCredentialKeys(t)
	original := Credential{
		AccessToken:  "old-access",
		RefreshToken: "old-refresh",
		ExpiresAt:    time.Now().Add(-time.Minute),
		AccountID:    "account",
	}
	if err := SaveCredential(path, original, keys); err != nil {
		t.Fatal(err)
	}
	started := make(chan struct{})
	release := make(chan struct{})
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if requests.Add(1) != 1 {
			http.Error(writer, "unexpected extra refresh", http.StatusInternalServerError)
			return
		}
		close(started)
		<-release
		writer.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(writer, `{"access_token":"new-access","refresh_token":"new-refresh","expires_in":3600}`)
	}))
	defer server.Close()
	refresher, err := NewRefresher(path, keys, RefresherOptions{Issuer: server.URL, ClientID: "client", HTTPClient: server.Client()})
	if err != nil {
		t.Fatal(err)
	}
	leaderContext, cancel := context.WithCancel(context.Background())
	defer cancel()
	leaderDone := make(chan error, 1)
	go func() {
		_, leaderErr := refresher.Credential(leaderContext)
		leaderDone <- leaderErr
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("refresh did not start")
	}
	waiterDone := make(chan struct {
		credential Credential
		err        error
	}, 1)
	go func() {
		credential, waiterErr := refresher.Credential(context.Background())
		waiterDone <- struct {
			credential Credential
			err        error
		}{credential: credential, err: waiterErr}
	}()
	cancel()
	select {
	case leaderErr := <-leaderDone:
		if !errors.Is(leaderErr, context.Canceled) {
			t.Fatalf("leader error = %v", leaderErr)
		}
	case <-time.After(time.Second):
		t.Fatal("canceled leader did not return")
	}
	close(release)
	select {
	case result := <-waiterDone:
		if result.err != nil || result.credential.AccessToken != "new-access" {
			t.Fatalf("waiter result = %#v, %v", result.credential, result.err)
		}
	case <-time.After(time.Second):
		t.Fatal("live waiter did not return")
	}
	if requests.Load() != 1 {
		t.Fatalf("refresh requests = %d, want 1", requests.Load())
	}
}

func TestRefresherConcurrentCredentialReplacementWins(t *testing.T) {
	path := filepath.Join(t.TempDir(), "credential.enc")
	keys := testCredentialKeys(t)
	if err := SaveCredential(path, Credential{
		AccessToken:  "old-access",
		RefreshToken: "old-refresh",
		ExpiresAt:    time.Now().Add(-time.Minute),
		AccountID:    "account",
	}, keys); err != nil {
		t.Fatal(err)
	}
	started := make(chan struct{})
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		close(started)
		<-release
		writer.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(writer, `{"access_token":"refresh-access","refresh_token":"refresh-token","expires_in":3600}`)
	}))
	defer server.Close()
	refresher, err := NewRefresher(path, keys, RefresherOptions{Issuer: server.URL, ClientID: "client", HTTPClient: server.Client()})
	if err != nil {
		t.Fatal(err)
	}
	resultDone := make(chan struct {
		credential Credential
		err        error
	}, 1)
	go func() {
		credential, refreshErr := refresher.Credential(context.Background())
		resultDone <- struct {
			credential Credential
			err        error
		}{credential: credential, err: refreshErr}
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("refresh did not start")
	}
	replacement := Credential{
		AccessToken:  "replacement-access",
		RefreshToken: "replacement-refresh",
		ExpiresAt:    time.Now().Add(time.Hour),
		AccountID:    "account",
	}
	replacementDone := make(chan error, 1)
	go func() {
		replacementDone <- SaveCredential(path, replacement, keys)
	}()
	if replacementErr := <-replacementDone; replacementErr != nil {
		t.Fatalf("replace credential: %v", replacementErr)
	}
	close(release)
	select {
	case result := <-resultDone:
		if result.err != nil || !sameCredential(result.credential, replacement) {
			t.Fatalf("refresh result = %#v, %v", result.credential, result.err)
		}
	case <-time.After(time.Second):
		t.Fatal("refresh did not return")
	}
	stored, err := LoadCredential(path, keys)
	if err != nil {
		t.Fatal(err)
	}
	if !sameCredential(stored, replacement) {
		t.Fatalf("stored credential = %#v, want replacement", stored)
	}
}

func TestRefresherRejectsMissingRotatedRefreshToken(t *testing.T) {
	path := filepath.Join(t.TempDir(), "credential.enc")
	keys := testCredentialKeys(t)
	original := Credential{
		AccessToken:  "old-access",
		RefreshToken: "old-refresh",
		ExpiresAt:    time.Now().Add(-time.Minute),
		AccountID:    "account",
	}
	if err := SaveCredential(path, original, keys); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(writer, `{"access_token":"new-access","expires_in":3600}`)
	}))
	defer server.Close()
	refresher, err := NewRefresher(path, keys, RefresherOptions{Issuer: server.URL, ClientID: "client", HTTPClient: server.Client()})
	if err != nil {
		t.Fatal(err)
	}
	_, err = refresher.Credential(context.Background())
	var refreshErr *RefreshError
	if !errors.Is(err, ErrRefreshTemporary) || !errors.As(err, &refreshErr) || refreshErr.Permanent() {
		t.Fatalf("missing rotated token error = %v", err)
	}
	stored, err := LoadCredential(path, keys)
	if err != nil {
		t.Fatal(err)
	}
	if !sameCredential(stored, original) {
		t.Fatalf("stored credential = %#v, want original", stored)
	}
}

func TestRefresherPlainTextUnauthorizedClassification(t *testing.T) {
	t.Run("transient", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "credential.enc")
		keys := testCredentialKeys(t)
		if err := SaveCredential(path, Credential{
			AccessToken:  "old-access",
			RefreshToken: "old-refresh",
			ExpiresAt:    time.Now().Add(-time.Minute),
			AccountID:    "account",
		}, keys); err != nil {
			t.Fatal(err)
		}
		var requests atomic.Int32
		secret := "plain-text-secret"
		server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			if requests.Add(1) == 1 {
				http.Error(writer, "upstream timeout "+secret, http.StatusUnauthorized)
				return
			}
			writer.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(writer, `{"access_token":"new-access","refresh_token":"new-refresh","expires_in":3600}`)
		}))
		defer server.Close()
		refresher, err := NewRefresher(path, keys, RefresherOptions{Issuer: server.URL, ClientID: "client", HTTPClient: server.Client()})
		if err != nil {
			t.Fatal(err)
		}
		_, err = refresher.Credential(context.Background())
		if !errors.Is(err, ErrRefreshTemporary) || strings.Contains(err.Error(), secret) {
			t.Fatalf("transient plain-text error = %v", err)
		}
		if got := refresher.Status(); got != CredentialStatusTransientFailure {
			t.Fatalf("transient plain-text status = %q", got)
		}
		if credential, retryErr := refresher.Credential(context.Background()); retryErr != nil || credential.AccessToken != "new-access" {
			t.Fatalf("transient plain-text retry = %#v, %v", credential, retryErr)
		}
		if requests.Load() != 2 {
			t.Fatalf("transient plain-text requests = %d, want 2", requests.Load())
		}
	})

	t.Run("unstructured", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "credential.enc")
		keys := testCredentialKeys(t)
		if err := SaveCredential(path, Credential{
			AccessToken:  "old-access",
			RefreshToken: "old-refresh",
			ExpiresAt:    time.Now().Add(-time.Minute),
			AccountID:    "account",
		}, keys); err != nil {
			t.Fatal(err)
		}
		var requests atomic.Int32
		secret := "plain-text-secret"
		server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			requests.Add(1)
			http.Error(writer, "invalid grant "+secret, http.StatusUnauthorized)
		}))
		defer server.Close()
		refresher, err := NewRefresher(path, keys, RefresherOptions{Issuer: server.URL, ClientID: "client", HTTPClient: server.Client()})
		if err != nil {
			t.Fatal(err)
		}
		_, err = refresher.Credential(context.Background())
		var refreshErr *RefreshError
		if !errors.Is(err, ErrRefreshTemporary) || !errors.As(err, &refreshErr) || refreshErr.Permanent() || strings.Contains(err.Error(), secret) {
			t.Fatalf("unstructured plain-text error = %v", err)
		}
		if got := refresher.Status(); got != CredentialStatusTransientFailure {
			t.Fatalf("unstructured plain-text status = %q", got)
		}
		_, err = refresher.Credential(context.Background())
		if !errors.Is(err, ErrRefreshTemporary) || requests.Load() != 2 {
			t.Fatalf("unstructured plain-text retry = %v, requests = %d", err, requests.Load())
		}
	})
}

func TestRefresherSnapshotTransitions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "credential.enc")
	keys := testCredentialKeys(t)
	refresher, err := NewRefresher(path, keys, RefresherOptions{Issuer: "http://127.0.0.1", ClientID: "client"})
	if err != nil {
		t.Fatal(err)
	}
	credential := Credential{
		AccessToken:  "access",
		RefreshToken: "refresh",
		ExpiresAt:    time.Now().Add(time.Hour),
		AccountID:    "account",
	}
	if err := SaveCredential(path, credential, keys); err != nil {
		t.Fatal(err)
	}
	snapshot := refresher.Snapshot()
	if !snapshot.Available || snapshot.State != CredentialStatusCurrent {
		t.Fatalf("current snapshot = %+v", snapshot)
	}
	credential.ExpiresAt = time.Now().Add(time.Minute)
	if err := SaveCredential(path, credential, keys); err != nil {
		t.Fatal(err)
	}
	snapshot = refresher.Snapshot()
	if !snapshot.Available || snapshot.State != CredentialStatusRefreshable {
		t.Fatalf("refreshable snapshot = %+v", snapshot)
	}
	credential.ExpiresAt = time.Now().Add(-time.Minute)
	if err := SaveCredential(path, credential, keys); err != nil {
		t.Fatal(err)
	}
	snapshot = refresher.Snapshot()
	if snapshot.Available || snapshot.State != CredentialStatusExpired {
		t.Fatalf("expired snapshot = %+v", snapshot)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	snapshot = refresher.Snapshot()
	if snapshot.Available || snapshot.State != CredentialStatusMissing {
		t.Fatalf("missing snapshot = %+v", snapshot)
	}
}

func TestRefresherPermanentAndTransientFailures(t *testing.T) {
	t.Run("permanent", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "credential.enc")
		keys := testCredentialKeys(t)
		if err := SaveCredential(path, Credential{
			AccessToken:  "old-access",
			RefreshToken: "old-refresh",
			ExpiresAt:    time.Now().Add(-time.Minute),
			AccountID:    "account",
		}, keys); err != nil {
			t.Fatal(err)
		}
		var requests atomic.Int32
		secret := "refresh-secret-value"
		server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			requests.Add(1)
			http.Error(writer, `{"error":"invalid_grant","error_description":"`+secret+`"}`, http.StatusBadRequest)
		}))
		defer server.Close()
		refresher, err := NewRefresher(path, keys, RefresherOptions{Issuer: server.URL, ClientID: "client", HTTPClient: server.Client()})
		if err != nil {
			t.Fatal(err)
		}
		_, err = refresher.Credential(context.Background())
		var refreshErr *RefreshError
		if !errors.Is(err, ErrRefreshRequiresLogin) || !errors.As(err, &refreshErr) || !refreshErr.Permanent() {
			t.Fatalf("permanent error = %v", err)
		}
		if strings.Contains(err.Error(), secret) {
			t.Fatal("refresh secret reached error")
		}
		if got := refresher.Status(); got != CredentialStatusPermanentFailure {
			t.Fatalf("status = %q", got)
		}
		if refresher.Available() {
			t.Fatal("permanent credential reported available")
		}
		_, err = refresher.Credential(context.Background())
		if !errors.Is(err, ErrRefreshRequiresLogin) || requests.Load() != 1 {
			t.Fatalf("second permanent error = %v, requests = %d", err, requests.Load())
		}
	})

	t.Run("transient", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "credential.enc")
		keys := testCredentialKeys(t)
		original := Credential{
			AccessToken:  "old-access",
			RefreshToken: "old-refresh",
			ExpiresAt:    time.Now().Add(-time.Minute),
			AccountID:    "account",
		}
		if err := SaveCredential(path, original, keys); err != nil {
			t.Fatal(err)
		}
		var requests atomic.Int32
		server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			if requests.Add(1) == 1 {
				http.Error(writer, `{"error":"temporarily_unavailable","error_description":"`+"refresh-secret-value"+`"}`, http.StatusServiceUnavailable)
				return
			}
			writer.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(writer, `{"access_token":"new-access","refresh_token":"new-refresh","expires_in":3600}`)
		}))
		defer server.Close()
		refresher, err := NewRefresher(path, keys, RefresherOptions{Issuer: server.URL, ClientID: "client", HTTPClient: server.Client()})
		if err != nil {
			t.Fatal(err)
		}
		_, err = refresher.Credential(context.Background())
		if !errors.Is(err, ErrRefreshTemporary) {
			t.Fatalf("transient error = %v", err)
		}
		if got := refresher.Status(); got != CredentialStatusTransientFailure {
			t.Fatalf("status = %q", got)
		}
		stored, loadErr := LoadCredential(path, keys)
		if loadErr != nil || stored.AccessToken != original.AccessToken || stored.RefreshToken != original.RefreshToken {
			t.Fatalf("stored after transient = %#v, %v", stored, loadErr)
		}
		credential, err := refresher.Credential(context.Background())
		if err != nil || credential.AccessToken != "new-access" {
			t.Fatalf("retry credential = %#v, %v", credential, err)
		}
		if requests.Load() != 2 {
			t.Fatalf("refresh requests = %d, want 2", requests.Load())
		}
	})
}

func TestRefresherRetriesOnlyReplaySafe401Once(t *testing.T) {
	path := filepath.Join(t.TempDir(), "credential.enc")
	keys := testCredentialKeys(t)
	if err := SaveCredential(path, Credential{
		AccessToken:  "old-access",
		RefreshToken: "old-refresh",
		ExpiresAt:    time.Now().Add(time.Hour),
		AccountID:    "account",
	}, keys); err != nil {
		t.Fatal(err)
	}
	var refreshRequests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		refreshRequests.Add(1)
		writer.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(writer, `{"access_token":"new-access","refresh_token":"new-refresh","expires_in":3600}`)
	}))
	defer server.Close()
	refresher, err := NewRefresher(path, keys, RefresherOptions{Issuer: server.URL, ClientID: "client", HTTPClient: server.Client()})
	if err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	response, err := refresher.Do(context.Background(), true, func(_ context.Context, credential Credential) (*http.Response, error) {
		if calls.Add(1) == 1 {
			return &http.Response{StatusCode: http.StatusUnauthorized, Body: io.NopCloser(bytes.NewReader(nil))}, nil
		}
		if credential.AccessToken != "new-access" {
			t.Errorf("retry access token = %q", credential.AccessToken)
		}
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewReader(nil))}, nil
	})
	if err != nil || response == nil || response.StatusCode != http.StatusOK || calls.Load() != 2 || refreshRequests.Load() != 1 {
		t.Fatalf("replay-safe result = %#v, %v, calls = %d, refreshes = %d", response, err, calls.Load(), refreshRequests.Load())
	}

	calls.Store(0)
	response, err = refresher.Do(context.Background(), false, func(context.Context, Credential) (*http.Response, error) {
		calls.Add(1)
		return &http.Response{StatusCode: http.StatusUnauthorized, Body: io.NopCloser(bytes.NewReader(nil))}, nil
	})
	if err != nil || response == nil || response.StatusCode != http.StatusUnauthorized || calls.Load() != 1 || refreshRequests.Load() != 1 {
		t.Fatalf("non-replay-safe result = %#v, %v, calls = %d, refreshes = %d", response, err, calls.Load(), refreshRequests.Load())
	}
}

func readBody(t *testing.T, request *http.Request) string {
	t.Helper()
	body, err := io.ReadAll(request.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}
