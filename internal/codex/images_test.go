package codex

import (
	"context"
	"encoding/base64"
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

	"github.com/catgirl-systems/codex-sub-proxy/internal/envelope"
)

const testCodexImageDataURL = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII="

func codexImageInt(value int) *int {
	return &value
}

func TestImagesClientGenerateWireAndDecode(t *testing.T) {
	responseBody := readImageFixture(t, "images_generation.json")
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requests.Add(1)
		if request.Method != http.MethodPost || request.URL.Path != "/backend-api/codex/images/generations" {
			t.Errorf("request = %s %s", request.Method, request.URL.Path)
		}
		assertImageHeaders(t, request, "access-token", "account-123", "image-turn-123")
		if got := request.Header.Get("Content-Type"); got != "application/json" {
			t.Errorf("content type = %q", got)
		}
		var body map[string]json.RawMessage
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			t.Errorf("decode request: %v", err)
		}
		assertExactImageJSONKeys(t, body, "model", "prompt", "n", "size", "quality", "output_compression", "output_format", "moderation", "user")
		for key, want := range map[string]string{
			"model": `"gpt-image-2"`, "prompt": `"fixture generated icon"`,
			"n": "1", "size": `"1024x1024"`, "quality": `"auto"`,
			"output_compression": "75", "output_format": `"webp"`, "moderation": `"low"`, "user": `"fixture-user"`,
		} {
			if got := string(body[key]); got != want {
				t.Errorf("body[%q] = %s, want %s", key, got, want)
			}
		}
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write(responseBody)
	}))
	defer server.Close()
	client := newTestImagesClient(t, server, "access-token", "account-123")
	result, err := client.Generate(context.Background(), CodexImageGenerationRequest{
		Model: "gpt-image-2", Prompt: "fixture generated icon", N: codexImageInt(1),
		Size: "1024x1024", Quality: "auto", OutputCompression: codexImageInt(75),
		OutputFormat: "webp", Moderation: "low", User: "fixture-user",
	})
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if requests.Load() != 1 || result.Created != 1738888894 || len(result.Images) != 1 {
		t.Fatalf("result = %#v, requests = %d", result, requests.Load())
	}
	if result.Background != "transparent" || result.Quality != "high" ||
		result.Size != "1024x1024" || result.OutputFormat != "webp" {
		t.Fatalf("result metadata = %#v", result)
	}
	if result.Images[0].MIMEType != "image/png" || len(result.Images[0].Bytes) == 0 ||
		result.Images[0].RevisedPrompt != "a synthetic generated icon" {
		t.Fatalf("image = %#v", result.Images[0])
	}
	if result.Usage == nil || result.Usage.TotalTokens != 11 || result.Usage.InputTokensDetails == nil ||
		result.Usage.OutputTokensDetails == nil ||
		result.Usage.InputTokensDetails.ImageTokens != 3 ||
		result.Usage.InputTokensDetails.TextTokens != 6 ||
		result.Usage.OutputTokensDetails.ImageTokens != 1 ||
		result.Usage.OutputTokensDetails.TextTokens != 1 {
		t.Fatalf("usage = %#v", result.Usage)
	}
}

func TestImagesClientOptionalIntegerPresence(t *testing.T) {
	responseBody := readImageFixture(t, "images_generation.json")
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		index := int(requests.Add(1))
		var body map[string]json.RawMessage
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			t.Errorf("decode request %d: %v", index, err)
			writer.WriteHeader(http.StatusBadRequest)
			return
		}
		switch index {
		case 1:
			assertExactImageJSONKeys(t, body, "model", "prompt")
		case 2:
			assertExactImageJSONKeys(t, body, "model", "prompt", "output_compression", "output_format")
			if string(body["output_compression"]) != "0" {
				t.Errorf("output_compression = %s, want 0", body["output_compression"])
			}
		default:
			t.Errorf("unexpected request %d", index)
		}
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write(responseBody)
	}))
	defer server.Close()
	client := newTestImagesClient(t, server, "access-token", "account-123")
	if _, err := client.Generate(context.Background(), CodexImageGenerationRequest{
		Model: "gpt-image-2", Prompt: "omitted",
	}); err != nil {
		t.Fatalf("omitted option request: %v", err)
	}
	if _, err := client.Generate(context.Background(), CodexImageGenerationRequest{
		Model: "gpt-image-2", Prompt: "zero compression",
		OutputCompression: codexImageInt(0), OutputFormat: "jpeg",
	}); err != nil {
		t.Fatalf("zero compression request: %v", err)
	}
	if _, err := client.Generate(context.Background(), CodexImageGenerationRequest{
		Model: "gpt-image-2", Prompt: "zero count", N: codexImageInt(0),
	}); err == nil {
		t.Fatal("explicit n=0 was accepted")
	}
	for _, outputFormat := range []string{"", "png"} {
		if _, err := client.Generate(context.Background(), CodexImageGenerationRequest{
			Model: "gpt-image-2", Prompt: "invalid compression format",
			OutputCompression: codexImageInt(0), OutputFormat: outputFormat,
		}); err == nil {
			t.Fatalf("compression with output_format %q was accepted", outputFormat)
		}
	}
	if requests.Load() != 2 {
		t.Fatalf("requests = %d, want 2", requests.Load())
	}
}

func TestCodexImageSizeMinimumPixels(t *testing.T) {
	if err := validateCodexImageSize("640x1024"); err != nil {
		t.Fatalf("exact minimum size rejected: %v", err)
	}
	if err := validateCodexImageSize("624x1024"); err == nil {
		t.Fatal("below-minimum size was accepted")
	}
	if err := validateCodexImageSize("512x1024"); err == nil {
		t.Fatal("below-minimum size was accepted")
	}
}

func TestCodexImageBase64ExactBoundaries(t *testing.T) {
	image := make([]byte, maxCodexImageBytes)
	copy(image, []byte{0x89, 'P', 'N', 'G', '\r', '\n', 0x1a, '\n'})
	encoded := base64.StdEncoding.EncodeToString(image)
	if decodedSize, ok := codexBase64DecodedSize(encoded); !ok || decodedSize != maxCodexImageBytes {
		t.Fatalf("exact maximum decoded size = %d, %t", decodedSize, ok)
	}
	if err := validateCodexImageDataURL("data:image/png;base64," + encoded); err != nil {
		t.Fatalf("exact maximum input rejected: %v", err)
	}
	created := uint64(1)
	result, err := decodeCodexImageResponse(nil, CodexImageResponse{
		Created: &created,
		Data:    []CodexImageData{{B64JSON: encoded}},
	})
	if err != nil {
		t.Fatalf("exact maximum response rejected: %v", err)
	}
	if len(result.Images) != 1 || len(result.Images[0].Bytes) != maxCodexImageBytes {
		t.Fatalf("decoded exact maximum response = %d bytes", len(result.Images[0].Bytes))
	}
	oversized := append(append([]byte(nil), image...), 0)
	oversizedEncoded := base64.StdEncoding.EncodeToString(oversized)
	if decodedSize, ok := codexBase64DecodedSize(oversizedEncoded); ok && decodedSize <= maxCodexImageBytes {
		t.Fatalf("oversized decoded size = %d, %t", decodedSize, ok)
	}
	if err := validateCodexImageDataURL("data:image/png;base64," + oversizedEncoded); err == nil {
		t.Fatal("oversized input was accepted")
	}
	if _, err := decodeCodexImageResponse(nil, CodexImageResponse{
		Created: &created,
		Data:    []CodexImageData{{B64JSON: oversizedEncoded}},
	}); err == nil {
		t.Fatal("oversized response was accepted")
	}
	for _, malformed := range []string{"not-base64", "AAAAA", "AA=A", "AAAA="} {
		if _, ok := codexBase64DecodedSize(malformed); ok {
			t.Fatalf("malformed base64 %q was accepted", malformed)
		}
	}
}
func TestImagesClientEditWireAndDecode(t *testing.T) {
	responseBody := readImageFixture(t, "images_edit.json")
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/backend-api/codex/images/edits" {
			t.Errorf("path = %q", request.URL.Path)
		}
		assertImageHeaders(t, request, "access-token", "account-123", "image-turn-123")
		var body map[string]json.RawMessage
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			t.Errorf("decode request: %v", err)
		}
		assertExactImageJSONKeys(t, body, "model", "prompt", "images", "n", "size", "quality", "output_compression", "output_format", "user")
		for key, want := range map[string]string{
			"model": `"gpt-image-2"`, "prompt": `"fixture edited icon"`,
			"n": "1", "size": `"1024x1024"`, "quality": `"auto"`,
			"output_compression": "80", "output_format": `"jpeg"`, "user": `"fixture-user"`,
		} {
			if got := string(body[key]); got != want {
				t.Errorf("body[%q] = %s, want %s", key, got, want)
			}
		}
		var images []map[string]json.RawMessage
		if err := json.Unmarshal(body["images"], &images); err != nil || len(images) != 1 {
			t.Fatalf("images = %s, err = %v", body["images"], err)
		}
		assertExactImageJSONKeys(t, images[0], "image_url")
		if got := string(images[0]["image_url"]); got != `"`+testCodexImageDataURL+`"` {
			t.Errorf("images[0].image_url = %s", got)
		}
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write(responseBody)
	}))
	defer server.Close()
	client := newTestImagesClient(t, server, "access-token", "account-123")
	result, err := client.Edit(context.Background(), CodexImageEditRequest{
		Model: "gpt-image-2", Prompt: "fixture edited icon", N: codexImageInt(1),
		Size: "1024x1024", Quality: "auto", OutputCompression: codexImageInt(80),
		OutputFormat: "jpeg", User: "fixture-user",
		Images: []CodexImageEditInput{{ImageURL: testCodexImageDataURL}},
	})
	if err != nil {
		t.Fatalf("edit: %v", err)
	}
	if len(result.Images) != 1 || result.Images[0].MIMEType != "image/png" || len(result.Images[0].Bytes) == 0 {
		t.Fatalf("result = %#v", result)
	}
	if result.Background != "opaque" || result.Quality != "medium" ||
		result.Size != "1024x1536" || result.OutputFormat != "jpeg" {
		t.Fatalf("result metadata = %#v", result)
	}
	if result.Usage == nil || result.Usage.InputTokensDetails == nil ||
		result.Usage.InputTokensDetails.ImageTokens != 8 ||
		result.Usage.InputTokensDetails.TextTokens != 8 {
		t.Fatalf("usage = %#v", result.Usage)
	}
}

func TestImagesClientBackgroundValuesWire(t *testing.T) {
	backgrounds := []string{"auto", "opaque", "transparent"}
	for _, operation := range []struct {
		name string
		edit bool
		path string
	}{
		{name: "generate", path: "/backend-api/codex/images/generations"},
		{name: "edit", edit: true, path: "/backend-api/codex/images/edits"},
	} {
		t.Run(operation.name, func(t *testing.T) {
			responseBody := readImageFixture(t, "images_generation.json")
			if operation.edit {
				responseBody = readImageFixture(t, "images_edit.json")
			}
			var requests atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				index := int(requests.Add(1)) - 1
				if index >= len(backgrounds) {
					t.Errorf("unexpected request %d", index+1)
					writer.WriteHeader(http.StatusInternalServerError)
					return
				}
				if request.URL.Path != operation.path {
					t.Errorf("path = %q, want %q", request.URL.Path, operation.path)
				}
				var body map[string]json.RawMessage
				if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
					t.Errorf("decode request: %v", err)
					writer.WriteHeader(http.StatusBadRequest)
					return
				}
				wantKeys := []string{"model", "prompt", "n", "size", "quality", "background"}
				if operation.edit {
					wantKeys = append(wantKeys, "images")
				}
				assertExactImageJSONKeys(t, body, wantKeys...)
				if got, want := string(body["background"]), `"`+backgrounds[index]+`"`; got != want {
					t.Errorf("background = %s, want %s", got, want)
				}
				writer.Header().Set("Content-Type", "application/json")
				_, _ = writer.Write(responseBody)
			}))
			defer server.Close()
			client := newTestImagesClient(t, server, "access-token", "account-123")
			for _, background := range backgrounds {
				var (
					result CodexImageResult
					err    error
				)
				if operation.edit {
					result, err = client.Edit(context.Background(), CodexImageEditRequest{
						Model: "gpt-image-2", Prompt: "fixture edited icon", N: codexImageInt(1),
						Size: "1024x1024", Quality: "auto", Background: background,
						Images: []CodexImageEditInput{{ImageURL: testCodexImageDataURL}},
					})
				} else {
					result, err = client.Generate(context.Background(), CodexImageGenerationRequest{
						Model: "gpt-image-2", Prompt: "fixture generated icon", N: codexImageInt(1),
						Size: "1024x1024", Quality: "auto", Background: background,
					})
				}
				if err != nil {
					t.Fatalf("%s background %q: %v", operation.name, background, err)
				}
				if len(result.Images) != 1 {
					t.Fatalf("%s background %q result = %#v", operation.name, background, result)
				}
			}
			if got := requests.Load(); got != int32(len(backgrounds)) {
				t.Fatalf("requests = %d, want %d", got, len(backgrounds))
			}
		})
	}
}

func TestImagesClientRefreshesOnceAfterUnauthorized(t *testing.T) {
	responseBody := readImageFixture(t, "images_generation.json")
	var imageRequests, refreshRequests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/backend-api/codex/images/generations":
			imageRequests.Add(1)
			if request.Header.Get(AuthorizationHeader) == "Bearer old-access" {
				writer.WriteHeader(http.StatusUnauthorized)
				_, _ = io.WriteString(writer, `{"error":{"code":"unauthorized","message":"private image secret"}}`)
				return
			}
			if request.Header.Get(AuthorizationHeader) != "Bearer new-access" {
				t.Errorf("authorization = %q", request.Header.Get(AuthorizationHeader))
			}
			writer.Header().Set("Content-Type", "application/json")
			_, _ = writer.Write(responseBody)
		case "/oauth/token":
			refreshRequests.Add(1)
			if err := request.ParseForm(); err != nil || request.Form.Get("refresh_token") != "old-refresh" {
				t.Errorf("refresh form = %v", request.Form)
			}
			writer.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(writer, `{"access_token":"new-access","refresh_token":"new-refresh","expires_in":3600,"account_id":"account-123"}`)
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()
	path := filepath.Join(t.TempDir(), "credential.enc")
	keys := testCredentialKeys(t)
	if err := SaveCredential(path, Credential{
		AccessToken: "old-access", RefreshToken: "old-refresh", ExpiresAt: time.Now().Add(time.Hour), AccountID: "account-123",
	}, keys); err != nil {
		t.Fatal(err)
	}
	refresher, err := NewRefresher(path, keys, RefresherOptions{Issuer: server.URL, ClientID: "client", HTTPClient: server.Client()})
	if err != nil {
		t.Fatal(err)
	}
	client, err := NewImagesClient(ImagesClientOptions{
		GenerationsURL: server.URL + "/backend-api/codex/images/generations",
		EditsURL:       server.URL + "/backend-api/codex/images/edits",
		HTTPClient:     server.Client(), Refresher: refresher,
		Headers: HeaderConfig{ImageTurnID: "image-turn-123"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Generate(context.Background(), CodexImageGenerationRequest{Model: "gpt-image-2", Prompt: "rotate"}); err != nil {
		t.Fatalf("generate after refresh: %v", err)
	}
	if imageRequests.Load() != 2 || refreshRequests.Load() != 1 {
		t.Fatalf("image requests = %d, refresh requests = %d", imageRequests.Load(), refreshRequests.Load())
	}
}

func TestImagesClientRejectsInvalidInputBeforeDispatch(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requests.Add(1)
		writer.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()
	client := newTestImagesClient(t, server, "access-token", "account-123")
	tooManyImages := make([]CodexImageEditInput, maxCodexImageCount+1)
	for index := range tooManyImages {
		tooManyImages[index].ImageURL = testCodexImageDataURL
	}
	tests := []struct {
		name        string
		edit        bool
		generation  CodexImageGenerationRequest
		editRequest CodexImageEditRequest
	}{
		{name: "model", generation: CodexImageGenerationRequest{Model: "gpt-image-1", Prompt: "x"}},
		{name: "prompt", generation: CodexImageGenerationRequest{Model: "gpt-image-2"}},
		{name: "count", generation: CodexImageGenerationRequest{Model: "gpt-image-2", Prompt: "x", N: codexImageInt(maxCodexImageCount + 1)}},
		{name: "quality standard", generation: CodexImageGenerationRequest{Model: "gpt-image-2", Prompt: "x", Quality: "standard"}},
		{name: "quality unknown", generation: CodexImageGenerationRequest{Model: "gpt-image-2", Prompt: "x", Quality: "extreme"}},
		{name: "size", generation: CodexImageGenerationRequest{Model: "gpt-image-2", Prompt: "x", Size: "17x17"}},
		{name: "size below minimum", generation: CodexImageGenerationRequest{Model: "gpt-image-2", Prompt: "x", Size: "624x1024"}},
		{name: "background", generation: CodexImageGenerationRequest{Model: "gpt-image-2", Prompt: "x", Background: "invalid"}},
		{name: "edit background", edit: true, editRequest: CodexImageEditRequest{Model: "gpt-image-2", Prompt: "x", Background: "invalid", Images: []CodexImageEditInput{{ImageURL: testCodexImageDataURL}}}},
		{name: "edit no image", edit: true, editRequest: CodexImageEditRequest{Model: "gpt-image-2", Prompt: "x"}},
		{name: "edit too many", edit: true, editRequest: CodexImageEditRequest{Model: "gpt-image-2", Prompt: "x", Images: tooManyImages}},
		{name: "edit bad base64", edit: true, editRequest: CodexImageEditRequest{Model: "gpt-image-2", Prompt: "x", Images: []CodexImageEditInput{{ImageURL: "data:image/png;base64,not-base64"}}}},
		{name: "edit empty image URL", edit: true, editRequest: CodexImageEditRequest{Model: "gpt-image-2", Prompt: "x", Images: []CodexImageEditInput{{}}}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var err error
			if test.edit {
				_, err = client.Edit(context.Background(), test.editRequest)
			} else {
				_, err = client.Generate(context.Background(), test.generation)
			}
			if err == nil {
				t.Fatal("invalid request returned no error")
			}
		})
	}
	if requests.Load() != 0 {
		t.Fatalf("invalid requests reached upstream: %d", requests.Load())
	}
}

func TestImagesClientRejectsMalformedAndOversizedOutput(t *testing.T) {
	imageB64 := testCodexImageDataURL[len("data:image/png;base64,"):]
	tests := []struct {
		name string
		body string
	}{
		{name: "malformed JSON", body: "{"},
		{name: "bad base64", body: `{"created":1,"data":[{"b64_json":"not-base64"}]}`},
		{name: "non-image base64", body: `{"created":1,"data":[{"b64_json":"aGVsbG8="}]}`},
		{name: "too many images", body: `{"created":1,"data":[{"b64_json":"` + imageB64 + `"},{"b64_json":"` + imageB64 + `"},{"b64_json":"` + imageB64 + `"},{"b64_json":"` + imageB64 + `"},{"b64_json":"` + imageB64 + `"},{"b64_json":"` + imageB64 + `"}]}`},
		{name: "oversized body", body: strings.Repeat("x", maxCodexImageResponseBytes+1)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				_, _ = io.WriteString(writer, test.body)
			}))
			defer server.Close()
			client := newTestImagesClient(t, server, "access-token", "account-123")
			_, err := client.Generate(context.Background(), CodexImageGenerationRequest{Model: "gpt-image-2", Prompt: "x"})
			if err == nil {
				t.Fatal("invalid response returned no error")
			}
		})
	}
}

func TestImagesClientRejectsMissingNegativeAndOverflowCreated(t *testing.T) {
	imageB64 := testCodexImageDataURL[len("data:image/png;base64,"):]
	tests := []struct {
		name string
		body string
	}{
		{name: "missing", body: `{"data":[{"b64_json":"` + imageB64 + `"}]}`},
		{name: "negative", body: `{"created":-1,"data":[{"b64_json":"` + imageB64 + `"}]}`},
		{name: "overflow", body: `{"created":18446744073709551616,"data":[{"b64_json":"` + imageB64 + `"}]}`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				_, _ = io.WriteString(writer, test.body)
			}))
			defer server.Close()
			client := newTestImagesClient(t, server, "access-token", "account-123")
			_, err := client.Generate(context.Background(), CodexImageGenerationRequest{Model: "gpt-image-2", Prompt: "x"})
			if err == nil {
				t.Fatal("invalid created value returned no error")
			}
		})
	}
}

func TestImagesClientMapsProviderErrorWithoutBodyLeak(t *testing.T) {
	secret := "private-image-provider-secret"
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("X-Request-ID", "request-123")
		writer.WriteHeader(http.StatusTooManyRequests)
		_, _ = io.WriteString(writer, `{"error":{"code":"rate_limit_exceeded","message":"`+secret+`"}}`)
	}))
	defer server.Close()
	client := newTestImagesClient(t, server, "access-token", "account-123")
	_, err := client.Generate(context.Background(), CodexImageGenerationRequest{Model: "gpt-image-2", Prompt: "x"})
	var safeError *SafeError
	if err == nil || !errors.As(err, &safeError) || safeError.Category != CategoryRateLimit ||
		strings.Contains(err.Error(), secret) {
		t.Fatalf("error = %v", err)
	}
}

func TestImagesClientCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		select {
		case <-request.Context().Done():
		case <-time.After(100 * time.Millisecond):
		}
		writer.WriteHeader(http.StatusRequestTimeout)
	}))
	defer server.Close()
	client := newTestImagesClient(t, server, "access-token", "account-123")
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	_, err := client.Generate(ctx, CodexImageGenerationRequest{Model: "gpt-image-2", Prompt: "x"})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("error = %v", err)
	}
}

func TestImagesClientBoundsStalledHeaders(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		select {
		case <-request.Context().Done():
		case <-time.After(100 * time.Millisecond):
		}
	}))
	defer server.Close()
	client := newTestImagesClient(t, server, "access-token", "account-123")
	client.httpClient.Timeout = 40 * time.Millisecond
	started := time.Now()
	_, err := client.Generate(context.Background(), CodexImageGenerationRequest{Model: "gpt-image-2", Prompt: "x"})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("stalled headers error = %v, want deadline exceeded", err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("stalled headers elapsed = %s", elapsed)
	}
}

func TestImagesClientBoundsStalledBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		writer.WriteHeader(http.StatusOK)
		if flusher, ok := writer.(http.Flusher); ok {
			flusher.Flush()
		}
		_, _ = io.WriteString(writer, `{"created":1,"data":[`)
		if flusher, ok := writer.(http.Flusher); ok {
			flusher.Flush()
		}
		select {
		case <-request.Context().Done():
		case <-time.After(100 * time.Millisecond):
		}
	}))
	defer server.Close()
	client := newTestImagesClient(t, server, "access-token", "account-123")
	client.httpClient.Timeout = 40 * time.Millisecond
	started := time.Now()
	_, err := client.Generate(context.Background(), CodexImageGenerationRequest{Model: "gpt-image-2", Prompt: "x"})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("stalled body error = %v, want deadline exceeded", err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("stalled body elapsed = %s", elapsed)
	}
}

func TestImagesClientPreservesCallerCancellationCause(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		select {
		case <-request.Context().Done():
		case <-time.After(100 * time.Millisecond):
		}
	}))
	defer server.Close()
	client := newTestImagesClient(t, server, "access-token", "account-123")
	cause := errors.New("caller stopped image request")
	ctx, cancel := context.WithCancelCause(context.Background())
	cancel(cause)
	_, err := client.Generate(ctx, CodexImageGenerationRequest{Model: "gpt-image-2", Prompt: "x"})
	if !errors.Is(err, cause) {
		t.Fatalf("canceled image error = %v, want cause %v", err, cause)
	}
}

func TestImagesClientLiveOptIn(t *testing.T) {
	if os.Getenv("CSP_LIVE_CODEX_IMAGES") != "1" {
		t.Skip("set CSP_LIVE_CODEX_IMAGES=1 to run the live Codex Images check")
	}
	credentialPath := strings.TrimSpace(os.Getenv("CSP_CODEX_CREDENTIAL_FILE"))
	keyValue := os.Getenv("CSP_CREDENTIAL_ENCRYPTION_KEY")
	if credentialPath == "" || keyValue == "" {
		t.Skip("set CSP_CODEX_CREDENTIAL_FILE and CSP_CREDENTIAL_ENCRYPTION_KEY for the live check")
	}
	keys, err := newLiveCredentialKeys(keyValue)
	if err != nil {
		t.Skip("CSP_CREDENTIAL_ENCRYPTION_KEY is not a usable credential key")
	}
	refresher, err := NewRefresher(credentialPath, keys, RefresherOptions{Issuer: "https://auth.openai.com", ClientID: "client"})
	if err != nil {
		t.Fatal(err)
	}
	client, err := NewImagesClient(ImagesClientOptions{
		Refresher: refresher,
		Headers:   HeaderConfig{ImageTurnID: "csp-live-image-turn"},
	})
	if err != nil {
		t.Fatal(err)
	}
	generation, err := client.Generate(context.Background(), CodexImageGenerationRequest{
		Model: "gpt-image-2", Prompt: "a small synthetic blue square", N: codexImageInt(1),
		Size: "1024x1024", Quality: "auto",
	})
	if err != nil {
		t.Fatalf("live generation: %v", err)
	}
	if len(generation.Images) != 1 || generation.Images[0].MIMEType == "" || len(generation.Images[0].Bytes) == 0 {
		t.Fatalf("live generation result has no detected image")
	}
	edit, err := client.Edit(context.Background(), CodexImageEditRequest{
		Model: "gpt-image-2", Prompt: "add one small white dot", N: codexImageInt(1),
		Size: "1024x1024", Quality: "auto",
		Images: []CodexImageEditInput{{ImageURL: "data:" + generation.Images[0].MIMEType + ";base64," + encodeLiveImage(generation.Images[0].Bytes)}},
	})
	if err != nil {
		t.Fatalf("live edit: %v", err)
	}
	if len(edit.Images) != 1 || edit.Images[0].MIMEType == "" || len(edit.Images[0].Bytes) == 0 {
		t.Fatalf("live edit result has no detected image")
	}
}

func assertExactImageJSONKeys(t *testing.T, fields map[string]json.RawMessage, want ...string) {
	t.Helper()
	expected := make(map[string]struct{}, len(want))
	for _, key := range want {
		expected[key] = struct{}{}
	}
	if len(fields) != len(expected) {
		t.Fatalf("JSON keys = %v, want exactly %v", fields, want)
	}
	for key := range fields {
		if _, ok := expected[key]; !ok {
			t.Errorf("unexpected JSON key %q", key)
		}
	}
}

func assertImageHeaders(t *testing.T, request *http.Request, accessToken, accountID, imageTurnID string) {
	t.Helper()
	for name, want := range map[string]string{
		AuthorizationHeader: "Bearer " + accessToken,
		AccountIDHeader:     accountID,
		BetaHeader:          DefaultBeta,
		OriginatorHeader:    DefaultOriginator,
		VersionHeader:       DefaultVersion,
		ImageTurnIDHeader:   imageTurnID,
	} {
		if got := request.Header.Get(name); got != want {
			t.Errorf("header %s = %q, want %q", name, got, want)
		}
	}
}

func newTestImagesClient(t *testing.T, server *httptest.Server, accessToken, accountID string) *ImagesClient {
	t.Helper()
	path := filepath.Join(t.TempDir(), "credential.enc")
	keys := testCredentialKeys(t)
	if err := SaveCredential(path, Credential{
		AccessToken: accessToken, RefreshToken: "refresh-token", ExpiresAt: time.Now().Add(time.Hour), AccountID: accountID,
	}, keys); err != nil {
		t.Fatal(err)
	}
	refresher, err := NewRefresher(path, keys, RefresherOptions{Issuer: server.URL, ClientID: "client", HTTPClient: server.Client()})

	if err != nil {
		t.Fatal(err)
	}
	client, err := NewImagesClient(ImagesClientOptions{
		GenerationsURL: server.URL + "/backend-api/codex/images/generations",
		EditsURL:       server.URL + "/backend-api/codex/images/edits",
		HTTPClient:     server.Client(), Refresher: refresher,
		Headers: HeaderConfig{
			ImageTurnID: "image-turn-123",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func readImageFixture(t *testing.T, name string) []byte {
	t.Helper()
	body, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func newLiveCredentialKeys(value string) (envelope.KeySet, error) {
	key, err := envelope.NewKey(1, []byte(value))
	if err != nil {
		return envelope.KeySet{}, err
	}
	return envelope.NewKeySet(key)
}

func encodeLiveImage(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}
