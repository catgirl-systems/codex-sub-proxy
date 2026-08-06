package server

import (
	"context"
	"errors"
	"github.com/catgirl-systems/codex-sub-proxy/internal/codex"
	"github.com/catgirl-systems/codex-sub-proxy/internal/envelope"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func TestProfileBrokerRequiresUsableProfiles(t *testing.T) {
	if _, err := NewProfileBroker(codex.SingleSelector{}, nil); err == nil {
		t.Fatal("empty broker profiles accepted")
	}
	if _, err := NewProfileBroker(codex.SingleSelector{}, []BrokerProfile{{Account: codex.Account{ID: "empty"}}}); err == nil {
		t.Fatal("profile without clients accepted")
	}
}

func TestProfileBrokerUnavailableTransportDoesNotBind(t *testing.T) {
	broker, err := NewProfileBroker(codex.SingleSelector{}, []BrokerProfile{{
		Account: codex.Account{ID: "default", IsDefault: true, Enabled: true, Available: true},
		Images:  &codex.ImagesClient{},
	}})
	if err != nil {
		t.Fatal(err)
	}
	var bound codex.Account
	result, err := broker.Compact(context.Background(), codex.SelectionRequest{}, codex.CodexCompactRequest{}, "", func(account codex.Account) error {
		bound = account
		return nil
	})
	if !errors.Is(err, ErrBrokerUnavailable) {
		t.Fatalf("error = %v, want ErrBrokerUnavailable", err)
	}
	if result.Account.ID != "default" || bound.ID != "" {
		t.Fatalf("compact account = %#v, bound = %#v", result.Account, bound)
	}
}

func TestProfileBrokerStreamUnavailableDoesNotBind(t *testing.T) {
	broker, err := NewProfileBroker(codex.SingleSelector{}, []BrokerProfile{{
		Account: codex.Account{ID: "default", IsDefault: true, Enabled: true, Available: true},
		Images:  &codex.ImagesClient{},
	}})
	if err != nil {
		t.Fatal(err)
	}
	var bound codex.Account
	result, err := broker.StreamResponses(context.Background(), codex.SelectionRequest{}, codex.CodexResponseRequest{}, "", func(account codex.Account) error {
		bound = account
		return nil
	}, func(codex.CodexResponseStreamEvent) error {
		t.Fatal("unavailable stream emitted an event")
		return nil
	})
	if !errors.Is(err, ErrBrokerUnavailable) {
		t.Fatalf("error = %v, want ErrBrokerUnavailable", err)
	}
	if result.Account.ID != "default" || bound.ID != "" {
		t.Fatalf("stream account = %#v, bound = %#v", result.Account, bound)
	}
}

func TestProfileBrokerWrapsBindFailureBeforeDispatch(t *testing.T) {
	broker, err := NewProfileBroker(codex.SingleSelector{}, []BrokerProfile{{
		Account:   codex.Account{ID: "default", IsDefault: true, Enabled: true, Available: true},
		Responses: &codex.ResponsesTransport{},
	}})
	if err != nil {
		t.Fatal(err)
	}
	bindErr := errors.New("journal request account conflicts")
	result, err := broker.DoResponses(context.Background(), codex.SelectionRequest{}, codex.CodexResponseRequest{}, "", func(codex.Account) error {
		return bindErr
	})
	if !errors.Is(err, ErrBrokerBind) || !errors.Is(err, bindErr) {
		t.Fatalf("bind error = %v, want broker bind and source errors", err)
	}
	if result.Account.ID != "default" {
		t.Fatalf("bind failure account = %#v", result.Account)
	}
}

func TestProfileBrokerForcesContinuationAccount(t *testing.T) {
	broker, err := NewProfileBroker(&codex.RoundRobinSelector{}, []BrokerProfile{
		{
			Account:   codex.Account{ID: "first", IsDefault: true, Enabled: true, Available: true},
			Responses: &codex.ResponsesTransport{},
		},
		{
			Account:   codex.Account{ID: "second", Enabled: true, Available: true},
			Responses: &codex.ResponsesTransport{},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	selected, err := broker.profile(context.Background(), codex.SelectionRequest{}, "second")
	if err != nil {
		t.Fatalf("forced continuation selection: %v", err)
	}
	if selected.Account.ID != "second" {
		t.Fatalf("forced continuation account = %q, want second", selected.Account.ID)
	}

	unavailableBroker, err := NewProfileBroker(&codex.RoundRobinSelector{}, []BrokerProfile{
		{
			Account:   codex.Account{ID: "first", IsDefault: true, Enabled: true, Available: true},
			Responses: &codex.ResponsesTransport{},
		},
		{
			Account:   codex.Account{ID: "second", Enabled: true, Available: false},
			Responses: &codex.ResponsesTransport{},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := unavailableBroker.profile(context.Background(), codex.SelectionRequest{}, "second"); !errors.Is(err, codex.ErrNoAvailableAccount) {
		t.Fatalf("unavailable forced continuation error = %v, want ErrNoAvailableAccount", err)
	}
}

func TestProfileBrokerRefreshesAvailabilityForSelection(t *testing.T) {
	activeKey, err := envelope.NewKey(1, make([]byte, envelope.KeySize))
	if err != nil {
		t.Fatal(err)
	}
	keys, err := envelope.NewKeySet(activeKey)
	if err != nil {
		t.Fatal(err)
	}
	credentialPath := filepath.Join(t.TempDir(), "credential.enc")
	credential := codex.Credential{
		AccessToken:  "access",
		RefreshToken: "refresh",
		AccountID:    "account",
		ExpiresAt:    time.Now().Add(time.Hour),
	}
	if err := codex.SaveCredential(credentialPath, credential, keys); err != nil {
		t.Fatal(err)
	}
	refresher, err := codex.NewRefresher(credentialPath, keys, codex.RefresherOptions{
		Issuer: "https://auth.openai.com", ClientID: "client",
	})
	if err != nil {
		t.Fatal(err)
	}
	broker, err := NewProfileBroker(codex.SingleSelector{}, []BrokerProfile{{
		Account:   codex.Account{ID: "default", IsDefault: true, Enabled: true, Available: true},
		Refresher: refresher,
		Images:    &codex.ImagesClient{},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if selected, err := broker.profile(context.Background(), codex.SelectionRequest{}, ""); err != nil || selected.Account.ID != "default" {
		t.Fatalf("initial selection = %#v, %v", selected.Account, err)
	}
	credential.ExpiresAt = time.Now().Add(-time.Minute)
	if err := codex.SaveCredential(credentialPath, credential, keys); err != nil {
		t.Fatal(err)
	}
	if selected, err := broker.profile(context.Background(), codex.SelectionRequest{}, ""); err != nil || selected.Account.ID != "default" {
		t.Fatalf("expired-but-refreshable selection = %#v, %v", selected.Account, err)
	}
	credential.ExpiresAt = time.Now().Add(time.Hour)
	if err := codex.SaveCredential(credentialPath, credential, keys); err != nil {
		t.Fatal(err)
	}

	if selected, err := broker.profile(context.Background(), codex.SelectionRequest{}, ""); err != nil || selected.Account.ID != "default" {
		t.Fatalf("recovered selection = %#v, %v", selected.Account, err)
	}
}

func TestProfileBrokerRefreshesExpiredCredentialOnRequest(t *testing.T) {
	activeKey, err := envelope.NewKey(1, make([]byte, envelope.KeySize))
	if err != nil {
		t.Fatal(err)
	}
	keys, err := envelope.NewKeySet(activeKey)
	if err != nil {
		t.Fatal(err)
	}
	credentialPath := filepath.Join(t.TempDir(), "credential.enc")
	if err := codex.SaveCredential(credentialPath, codex.Credential{
		AccessToken:  "expired-access",
		RefreshToken: "refresh-token",
		AccountID:    "account",
		ExpiresAt:    time.Now().Add(-time.Minute),
	}, keys); err != nil {
		t.Fatal(err)
	}
	var refreshRequests atomic.Int32
	var responseRequests atomic.Int32
	var wrongToken atomic.Bool
	upstream := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/oauth/token":
			refreshRequests.Add(1)
			writer.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(writer, `{"access_token":"refreshed-access","refresh_token":"refresh-token","expires_in":3600}`)
		case "/responses":
			responseRequests.Add(1)
			if request.Header.Get("Authorization") != "Bearer refreshed-access" {
				wrongToken.Store(true)
			}
			writer.Header().Set("Content-Type", "text/event-stream")
			_, _ = io.WriteString(writer, `data: {"type":"response.completed","sequence_number":0,"response":{"status":"completed"}}

data: [DONE]

`)
		default:
			http.NotFound(writer, request)
		}
	}))
	defer upstream.Close()
	refresher, err := codex.NewRefresher(credentialPath, keys, codex.RefresherOptions{
		Issuer: upstream.URL, ClientID: "client", HTTPClient: upstream.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}
	transport, err := codex.NewResponsesTransport(codex.ResponsesTransportOptions{
		Policy: codex.ResponsesTransportSSE, ResponsesURL: upstream.URL + "/responses",
		HTTPClient: upstream.Client(), Refresher: refresher,
	})
	if err != nil {
		t.Fatal(err)
	}
	broker, err := NewProfileBroker(codex.SingleSelector{}, []BrokerProfile{{
		Account:   codex.Account{ID: "default", IsDefault: true, Enabled: true},
		Refresher: refresher, Responses: transport,
	}})
	if err != nil {
		t.Fatal(err)
	}
	result, err := broker.DoResponses(context.Background(), codex.SelectionRequest{Model: "gpt-5.6-sol"}, codex.CodexResponseRequest{Model: "gpt-5.6-sol"}, "", func(codex.Account) error {
		return nil
	})
	if err != nil {
		t.Fatalf("broker response: %v", err)
	}
	if result.Result.Response == nil || result.Result.Response.Status != codex.CodexResponseStatusCompleted {
		t.Fatalf("response result = %#v", result.Result.Response)
	}
	if refreshRequests.Load() != 1 || responseRequests.Load() != 1 {
		t.Fatalf("refresh requests = %d, response requests = %d, want one each", refreshRequests.Load(), responseRequests.Load())
	}
	if wrongToken.Load() {
		t.Fatal("refreshed access token was not sent")
	}
}

func TestProfileBrokerAccountsAreCloned(t *testing.T) {
	broker, err := NewProfileBroker(codex.SingleSelector{}, []BrokerProfile{{
		Account:   codex.Account{ID: "default", IsDefault: true, Enabled: true, Available: true, Models: []string{"gpt-5.6-sol"}},
		Responses: &codex.ResponsesTransport{},
	}})
	if err != nil {
		t.Fatal(err)
	}
	accounts := broker.Accounts()
	if len(accounts) != 1 || accounts[0].ID != "default" {
		t.Fatalf("accounts = %#v", accounts)
	}
	accounts[0].Models[0] = "mutated"
	again := broker.Accounts()
	if again[0].Models[0] != "gpt-5.6-sol" {
		t.Fatalf("broker account model mutated through clone: %#v", again)
	}
	selected, err := (codex.SingleSelector{}).Select(context.Background(), codex.SelectionRequest{Model: "gpt-5.6-sol"}, again)
	if err != nil || selected.ID != "default" {
		t.Fatalf("selected account = %#v, %v", selected, err)
	}
}
