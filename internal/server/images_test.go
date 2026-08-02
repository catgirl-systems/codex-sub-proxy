package server

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/catgirl-systems/codex-sub-proxy/internal/apikey"
	"github.com/catgirl-systems/codex-sub-proxy/internal/codex"
	"github.com/catgirl-systems/codex-sub-proxy/internal/envelope"
	"github.com/catgirl-systems/codex-sub-proxy/internal/storage"
	sdk "github.com/openai/openai-go"
	"github.com/openai/openai-go/option"
)

func TestImagesOfficialSDKGenerationAndEdit(t *testing.T) {
	generationResponse, err := os.ReadFile(filepath.Join("..", "codex", "testdata", "images_generation.json"))
	if err != nil {
		t.Fatal(err)
	}
	editResponse, err := os.ReadFile(filepath.Join("..", "codex", "testdata", "images_edit.json"))
	if err != nil {
		t.Fatal(err)
	}
	imageBytes := []byte("\x89PNG\r\n\x1a\n\x00")

	var generationRequests, editRequests atomic.Int32
	var generationTurnID, editTurnID string
	upstream := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/generations":
			generationTurnID = request.Header.Get(codex.ImageTurnIDHeader)
			if len(generationTurnID) != 36 || generationTurnID[8] != '-' || generationTurnID[13] != '-' || generationTurnID[18] != '-' || generationTurnID[23] != '-' {
				t.Errorf("generation image turn id = %q", generationTurnID)
			}
			generationRequests.Add(1)
			if request.Method != http.MethodPost || request.Header.Get("Content-Type") != "application/json" {
				t.Errorf("generation request = %s %s content-type=%q", request.Method, request.URL.Path, request.Header.Get("Content-Type"))
			}
			var body map[string]json.RawMessage
			if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
				t.Errorf("generation body: %v", err)
			}
			if string(body["model"]) != `"gpt-image-2"` || string(body["prompt"]) != `"generate"` {
				t.Errorf("generation body = %s", body)
			}
			writer.Header().Set("Content-Type", "application/json")
			_, _ = writer.Write(generationResponse)
		case "/edits":
			editTurnID = request.Header.Get(codex.ImageTurnIDHeader)
			if len(editTurnID) != 36 || editTurnID[8] != '-' || editTurnID[13] != '-' || editTurnID[18] != '-' || editTurnID[23] != '-' {
				t.Errorf("edit image turn id = %q", editTurnID)
			}
			editRequests.Add(1)
			if request.Method != http.MethodPost || request.Header.Get("Content-Type") != "application/json" {
				t.Errorf("edit request = %s %s content-type=%q", request.Method, request.URL.Path, request.Header.Get("Content-Type"))
			}
			var body struct {
				Model  string                      `json:"model"`
				Prompt string                      `json:"prompt"`
				Images []codex.CodexImageEditInput `json:"images"`
			}
			if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
				t.Errorf("edit body: %v", err)
			}
			if body.Model != "gpt-image-2" || body.Prompt != "edit" || len(body.Images) != 2 || len(body.Images[0].ImageURL) < len("data:image/png;base64,") {
				t.Errorf("edit body = %#v", body)
			}
			writer.Header().Set("Content-Type", "application/json")
			_, _ = writer.Write(editResponse)
		default:
			writer.WriteHeader(http.StatusNotFound)
		}
	}))
	defer upstream.Close()

	databasePath := filepath.Join(t.TempDir(), "images.sqlite3")
	database, err := storage.Open(context.Background(), databasePath, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	sqlDatabase, err := database.DB()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sqlDatabase.Close() })
	if err := apikey.Migrate(database); err != nil {
		t.Fatal(err)
	}
	hmacKey := []byte("test-api-key-hmac-key")
	policy := apikey.Policy{
		Name:             "images",
		Owner:            "test",
		AllowedEndpoints: []string{imagesGenerationsEndpoint, imagesEditsEndpoint},
		AllowedModels:    []string{"gpt-image-2"},
	}
	rawKey, _, err := apikey.Create(context.Background(), database, hmacKey, policy)
	if err != nil {
		t.Fatal(err)
	}
	activeKey, err := envelope.NewKey(1, bytes.Repeat([]byte{7}, envelope.KeySize))
	if err != nil {
		t.Fatal(err)
	}
	credentialKeys, err := envelope.NewKeySet(activeKey)
	if err != nil {
		t.Fatal(err)
	}
	credentialPath := filepath.Join(t.TempDir(), "credential.enc")
	if err := codex.SaveCredential(credentialPath, codex.Credential{AccessToken: "access", RefreshToken: "refresh", ExpiresAt: time.Now().Add(time.Hour), AccountID: "account"}, credentialKeys); err != nil {
		t.Fatal(err)
	}
	refresher, err := codex.NewRefresher(credentialPath, credentialKeys, codex.RefresherOptions{Issuer: "https://auth.openai.com", ClientID: "client"})
	if err != nil {
		t.Fatal(err)
	}
	imagesClient, err := codex.NewImagesClient(codex.ImagesClientOptions{
		GenerationsURL: upstream.URL + "/generations",
		EditsURL:       upstream.URL + "/edits",
		Refresher:      refresher,
		Headers:        codex.HeaderConfig{},
	})
	if err != nil {
		t.Fatal(err)
	}
	servers, err := Start(Config{
		Listen:        "127.0.0.1:0",
		AdminListen:   "127.0.0.1:0",
		Database:      database,
		APIKeyHMACKey: hmacKey,
		ImagesClient:  imagesClient,
	}, NewReadiness())
	if err != nil {
		t.Fatal(err)
	}
	defer shutdownResponsesTestServer(t, servers)

	client := sdk.NewClient(
		option.WithBaseURL("http://"+servers.DataAddr()+"/v1/"),
		option.WithAPIKey(rawKey),
	)
	generated, err := client.Images.Generate(context.Background(), sdk.ImageGenerateParams{
		Model:          sdk.ImageModel("gpt-image-2"),
		Prompt:         "generate",
		ResponseFormat: sdk.ImageGenerateParamsResponseFormatB64JSON,
	})
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if generated == nil || len(generated.Data) != 1 || generated.Data[0].B64JSON == "" {
		t.Fatalf("generated = %#v", generated)
	}
	edited, err := client.Images.Edit(context.Background(), sdk.ImageEditParams{
		Image: sdk.ImageEditParamsImageUnion{OfFileArray: []io.Reader{bytes.NewReader(imageBytes), bytes.NewReader(imageBytes)}},
		Model: sdk.ImageModel("gpt-image-2"), Prompt: "edit",
		ResponseFormat: sdk.ImageEditParamsResponseFormatB64JSON,
	})
	if err != nil {
		t.Fatalf("edit: %v", err)
	}
	if edited == nil || len(edited.Data) != 1 || edited.Data[0].B64JSON == "" {
		t.Fatalf("edited = %#v", edited)
	}
	request, err := http.NewRequest(http.MethodPost, "http://"+servers.DataAddr()+imagesGenerationsEndpoint, bytes.NewBufferString(`{"model":"gpt-image-2","prompt":"generate","response_format":"url"}`))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+rawKey)
	request.Header.Set("Content-Type", "application/json")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var errorBody map[string]map[string]string
	if err := json.NewDecoder(response.Body).Decode(&errorBody); err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusBadRequest || errorBody["error"]["code"] != "unsupported_response_format" {
		t.Fatalf("url response = %d %#v", response.StatusCode, errorBody)
	}

	if generationRequests.Load() != 1 || editRequests.Load() != 1 || generationTurnID == "" || editTurnID == "" || generationTurnID == editTurnID {
		t.Fatalf("upstream requests = generation %d edit %d turn IDs = %q/%q", generationRequests.Load(), editRequests.Load(), generationTurnID, editTurnID)
	}
}
