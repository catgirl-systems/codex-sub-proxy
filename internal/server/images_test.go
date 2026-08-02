package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/catgirl-systems/codex-sub-proxy/internal/apikey"
	"github.com/catgirl-systems/codex-sub-proxy/internal/codex"
	"github.com/catgirl-systems/codex-sub-proxy/internal/envelope"
	"github.com/catgirl-systems/codex-sub-proxy/internal/openai"
	"github.com/catgirl-systems/codex-sub-proxy/internal/storage"
	"github.com/go-playground/validator/v10"
	sdk "github.com/openai/openai-go"
	"github.com/openai/openai-go/option"
	"github.com/openai/openai-go/packages/param"
)

func TestImagesPublicValidationAndJSONLimits(t *testing.T) {
	validation := validator.New()
	zero := 0
	for _, request := range []openai.ImageGenerationRequest{
		{Model: "gpt-image-1", Prompt: "prompt"},
		{Model: "gpt-image-2", Prompt: "   "},
		{Model: "gpt-image-2", Prompt: "prompt", N: &zero},
		{Model: "gpt-image-2", Prompt: "prompt", OutputCompression: &zero},
		{Model: "gpt-image-2", Prompt: "prompt", OutputCompression: &zero, OutputFormat: "png"},
	} {
		if err := validateImagesRequest(validation, request); err == nil {
			t.Fatalf("invalid request %#v was accepted", request)
		}
	}
	valid := openai.ImageGenerationRequest{Model: "gpt-image-2", Prompt: "prompt"}
	body := `{"model":"gpt-image-2","prompt":"prompt"}` + strings.Repeat(" ", maxImagesJSONBodyBytes)
	recorder := httptest.NewRecorder()
	err := decodeImagesJSON(http.MaxBytesReader(recorder, io.NopCloser(strings.NewReader(body)), maxImagesJSONBodyBytes), &valid)
	if !errors.Is(err, errImagesBodyTooLarge) {
		t.Fatalf("trailing oversized JSON error = %v", err)
	}
	omittedForm, _, err := decodeImageEditForm(map[string][]string{
		"model": {"gpt-image-2"}, "prompt": {"prompt"},
	})
	if err != nil || omittedForm.N != nil || omittedForm.OutputCompression != nil {
		t.Fatalf("omitted multipart integers = %#v, err = %v", omittedForm, err)
	}
	zeroForm, _, err := decodeImageEditForm(map[string][]string{
		"model": {"gpt-image-2"}, "prompt": {"prompt"}, "n": {"0"},
		"output_compression": {"0"}, "output_format": {"jpeg"},
	})
	if err != nil || zeroForm.N == nil || *zeroForm.N != 0 ||
		zeroForm.OutputCompression == nil || *zeroForm.OutputCompression != 0 {
		t.Fatalf("explicit zero multipart integers = %#v, err = %v", zeroForm, err)
	}
}

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
	var slowGeneration atomic.Bool
	generationStarted := make(chan struct{}, 1)
	releaseGeneration := make(chan struct{})
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
			if string(body["model"]) != `"gpt-image-2"` || string(body["prompt"]) != `"generate"` ||
				string(body["n"]) != "1" || string(body["output_compression"]) != "0" ||
				string(body["output_format"]) != `"webp"` || string(body["background"]) != `"transparent"` ||
				string(body["quality"]) != `"auto"` || string(body["size"]) != `"1024x1024"` {
				t.Errorf("generation body = %s", body)
			}
			if slowGeneration.Load() {
				generationStarted <- struct{}{}
				<-releaseGeneration
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
				Model             string                      `json:"model"`
				Prompt            string                      `json:"prompt"`
				Images            []codex.CodexImageEditInput `json:"images"`
				N                 *int                        `json:"n"`
				OutputCompression *int                        `json:"output_compression"`
				OutputFormat      string                      `json:"output_format"`
				Background        string                      `json:"background"`
				Quality           string                      `json:"quality"`
				Size              string                      `json:"size"`
			}
			if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
				t.Errorf("edit body: %v", err)
			}
			if body.Model != "gpt-image-2" || body.Prompt != "edit" || len(body.Images) != 2 ||
				len(body.Images[0].ImageURL) < len("data:image/png;base64,") ||
				body.N == nil || *body.N != 1 || body.OutputCompression == nil || *body.OutputCompression != 0 ||
				body.OutputFormat != "jpeg" || body.Background != "opaque" ||
				body.Quality != "medium" || body.Size != "1024x1536" {
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
		Model:             sdk.ImageModel("gpt-image-2"),
		Prompt:            "generate",
		N:                 param.NewOpt[int64](1),
		OutputCompression: param.NewOpt[int64](0),
		OutputFormat:      sdk.ImageGenerateParamsOutputFormatWebP,
		Background:        sdk.ImageGenerateParamsBackgroundTransparent,
		Quality:           sdk.ImageGenerateParamsQualityAuto,
		Size:              sdk.ImageGenerateParamsSize1024x1024,
		ResponseFormat:    sdk.ImageGenerateParamsResponseFormatB64JSON,
	})
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	slowGeneration.Store(true)
	slowDone := make(chan error, 1)
	go func() {
		_, err := client.Images.Generate(context.Background(), sdk.ImageGenerateParams{
			Model:             sdk.ImageModel("gpt-image-2"),
			Prompt:            "generate",
			N:                 param.NewOpt[int64](1),
			OutputCompression: param.NewOpt[int64](0),
			OutputFormat:      sdk.ImageGenerateParamsOutputFormatWebP,
			Background:        sdk.ImageGenerateParamsBackgroundTransparent,
			Quality:           sdk.ImageGenerateParamsQualityAuto,
			Size:              sdk.ImageGenerateParamsSize1024x1024,
			ResponseFormat:    sdk.ImageGenerateParamsResponseFormatB64JSON,
		})
		slowDone <- err
	}()
	select {
	case <-generationStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("slow generation did not reach upstream")
	}
	time.Sleep(writeTimeout + 500*time.Millisecond)
	close(releaseGeneration)
	if err := <-slowDone; err != nil {
		t.Fatalf("generation beyond server WriteTimeout: %v", err)
	}
	slowGeneration.Store(false)
	if generated.Background != sdk.ImagesResponseBackgroundTransparent ||
		generated.Quality != sdk.ImagesResponseQualityHigh ||
		generated.Size != sdk.ImagesResponseSize1024x1024 ||
		generated.OutputFormat != sdk.ImagesResponseOutputFormatWebP {
		t.Fatalf("generated metadata = %#v", generated)
	}
	edited, err := client.Images.Edit(context.Background(), sdk.ImageEditParams{
		Image:             sdk.ImageEditParamsImageUnion{OfFileArray: []io.Reader{bytes.NewReader(imageBytes), bytes.NewReader(imageBytes)}},
		Model:             sdk.ImageModel("gpt-image-2"),
		Prompt:            "edit",
		N:                 param.NewOpt[int64](1),
		OutputCompression: param.NewOpt[int64](0),
		OutputFormat:      sdk.ImageEditParamsOutputFormatJPEG,
		Background:        sdk.ImageEditParamsBackgroundOpaque,
		Quality:           sdk.ImageEditParamsQualityMedium,
		Size:              sdk.ImageEditParamsSize1024x1536,
		ResponseFormat:    sdk.ImageEditParamsResponseFormatB64JSON,
	})
	if err != nil {
		t.Fatalf("edit: %v", err)
	}
	if edited == nil || len(edited.Data) != 1 || edited.Data[0].B64JSON == "" {
		t.Fatalf("edited = %#v", edited)
	}
	if edited.Background != sdk.ImagesResponseBackgroundOpaque ||
		edited.Quality != sdk.ImagesResponseQualityMedium ||
		edited.Size != sdk.ImagesResponseSize1024x1536 ||
		edited.OutputFormat != sdk.ImagesResponseOutputFormatJPEG {
		t.Fatalf("edited metadata = %#v", edited)
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

	for _, payload := range []string{
		`{"model":"gpt-image-1","prompt":"generate"}`,
		`{"model":"gpt-image-2","prompt":"generate","size":"512x1024"}`,
	} {
		request, err := http.NewRequest(http.MethodPost, "http://"+servers.DataAddr()+imagesGenerationsEndpoint, bytes.NewBufferString(payload))
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Authorization", "Bearer "+rawKey)
		request.Header.Set("Content-Type", "application/json")
		response, err := http.DefaultClient.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		var body map[string]map[string]string
		if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
			_ = response.Body.Close()
			t.Fatal(err)
		}
		_ = response.Body.Close()
		if response.StatusCode != http.StatusBadRequest || body["error"]["type"] != "invalid_request_error" ||
			body["error"]["code"] != "invalid_request" {
			t.Fatalf("invalid image request = %d %#v", response.StatusCode, body)
		}
	}

	if generationRequests.Load() != 2 || editRequests.Load() != 1 || generationTurnID == "" || editTurnID == "" || generationTurnID == editTurnID {
		t.Fatalf("upstream requests = generation %d edit %d turn IDs = %q/%q", generationRequests.Load(), editRequests.Load(), generationTurnID, editTurnID)
	}
}
