package codex

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
)

const (
	defaultImagesGenerationsURL = "https://chatgpt.com/backend-api/codex/images/generations"
	defaultImagesEditsURL       = "https://chatgpt.com/backend-api/codex/images/edits"

	maxCodexImageCount         = 5
	maxCodexImagePromptBytes   = 64 << 10
	maxCodexImageBytes         = 4 << 20
	maxCodexImageRequestBytes  = maxCodexRequestBytes
	maxCodexImageResponseBytes = maxCodexStreamPayloadBytes
	maxCodexImageDimension     = 3840
	maxCodexImagePixels        = 3840 * 2160
)

// ImagesClientOptions contains the private Codex Images endpoints and auth.
type ImagesClientOptions struct {
	GenerationsURL string
	EditsURL       string
	HTTPClient     *http.Client
	Refresher      *Refresher
	Headers        HeaderConfig
}

// ImagesClient sends direct private Codex Images requests.
type ImagesClient struct {
	generationsURL string
	editsURL       string
	httpClient     *http.Client
	refresher      *Refresher
	headers        HeaderConfig
}

// CodexImageResult is the decoded result of one private Images request.
type CodexImageResult struct {
	Created int64
	Images  []CodexImage
	Usage   *CodexUsage
}

// CodexImage is one decoded image and its provider metadata.
type CodexImage struct {
	Bytes         []byte
	MIMEType      string
	RevisedPrompt string
}

// NewImagesClient validates and creates a private Codex Images client.
func NewImagesClient(options ImagesClientOptions) (*ImagesClient, error) {
	generationsURL := strings.TrimSpace(options.GenerationsURL)
	if generationsURL == "" {
		generationsURL = defaultImagesGenerationsURL
	}
	if err := validateHTTPURL(generationsURL); err != nil {
		return nil, fmt.Errorf("Images generations URL: %w", err)
	}
	editsURL := strings.TrimSpace(options.EditsURL)
	if editsURL == "" {
		editsURL = defaultImagesEditsURL
	}
	if err := validateHTTPURL(editsURL); err != nil {
		return nil, fmt.Errorf("Images edits URL: %w", err)
	}
	if options.Refresher == nil {
		return nil, errors.New("Codex Images credential refresher is required")
	}
	if err := validateImageTurnID(options.Headers.ImageTurnID); err != nil {
		return nil, err
	}
	client := options.HTTPClient
	if client == nil {
		client = http.DefaultClient
	}
	return &ImagesClient{
		generationsURL: generationsURL,
		editsURL:       editsURL,
		httpClient:     client,
		refresher:      options.Refresher,
		headers:        options.Headers,
	}, nil
}

// Generate creates images from a text prompt.
func (client *ImagesClient) Generate(ctx context.Context, request CodexImageRequest) (CodexImageResult, error) {
	return client.do(ctx, false, request)
}

// Edit creates images from one or more source images.
func (client *ImagesClient) Edit(ctx context.Context, request CodexImageRequest) (CodexImageResult, error) {
	return client.do(ctx, true, request)
}

func (client *ImagesClient) do(ctx context.Context, edit bool, request CodexImageRequest) (CodexImageResult, error) {
	if ctx == nil {
		return CodexImageResult{}, errors.New("Codex Images context is nil")
	}
	if client == nil {
		return CodexImageResult{}, errors.New("Codex Images client is nil")
	}
	if err := validateImageTurnID(client.headers.ImageTurnID); err != nil {
		return CodexImageResult{}, err
	}
	if request.ResponseFormat == "" {
		request.ResponseFormat = "b64_json"
	}
	if err := validateCodexImageRequest(request, edit); err != nil {
		return CodexImageResult{}, err
	}
	body, err := json.Marshal(request)
	if err != nil {
		return CodexImageResult{}, fmt.Errorf("encode Codex Images request: %w", err)
	}
	if len(body) == 0 || len(body) > maxCodexImageRequestBytes {
		return CodexImageResult{}, errors.New("Codex Images request is too large")
	}
	endpoint := client.generationsURL
	if edit {
		endpoint = client.editsURL
	}
	response, err := client.refresher.Do(ctx, true, func(attemptContext context.Context, credential Credential) (*http.Response, error) {
		headers := client.headers
		headers.AccessToken = credential.AccessToken
		headers.AccountID = credential.AccountID
		if credential.AccountIsFedRAMP {
			headers.FedRAMP = true
		}
		request, requestErr := NewRequest(
			attemptContext,
			http.MethodPost,
			endpoint,
			bytes.NewReader(body),
			headers,
		)
		if requestErr != nil {
			return nil, requestErr
		}
		request.Header.Set("Content-Type", "application/json")
		response, requestErr := client.httpClient.Do(request)
		if requestErr != nil {
			if contextErr := contextError(ctx); contextErr != nil {
				return nil, contextErr
			}
			if contextErr := contextError(attemptContext); contextErr != nil {
				return nil, contextErr
			}
			return nil, fmt.Errorf("send Codex Images request: %w", requestErr)
		}
		if response == nil {
			return nil, errors.New("Codex Images request returned no response")
		}
		return response, nil
	})
	if err != nil {
		if contextErr := contextError(ctx); contextErr != nil {
			return CodexImageResult{}, contextErr
		}
		return CodexImageResult{}, err
	}
	if response == nil {
		return CodexImageResult{}, errors.New("Codex Images request returned no response")
	}
	defer closeHTTPResponse(response)
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		body, readErr := readCodexImageErrorBody(ctx, response.Body)
		if contextErr := contextError(ctx); contextErr != nil {
			return CodexImageResult{}, contextErr
		}
		if readErr != nil {
			return CodexImageResult{}, fmt.Errorf("read Codex Images error: %w", readErr)
		}
		return CodexImageResult{}, MapUpstreamError(response.StatusCode, response.Header, body)
	}
	if response.ContentLength > maxCodexImageResponseBytes {
		return CodexImageResult{}, errors.New("Codex Images response is too large")
	}
	responseBody, err := readCodexImageBody(ctx, response.Body)
	if err != nil {
		if contextErr := contextError(ctx); contextErr != nil {
			return CodexImageResult{}, contextErr
		}
		return CodexImageResult{}, err
	}
	var imageResponse CodexImageResponse
	if err := json.Unmarshal(responseBody, &imageResponse); err != nil {
		return CodexImageResult{}, errors.New("Codex Images response is malformed")
	}
	return decodeCodexImageResponse(request, imageResponse)
}

func validateImageTurnID(imageTurnID string) error {
	if strings.TrimSpace(imageTurnID) == "" {
		return errors.New("Codex Images image-turn identity is required")
	}
	if strings.ContainsAny(imageTurnID, "\r\n") {
		return errors.New("Codex Images image-turn identity is invalid")
	}
	return nil
}

func validateCodexImageRequest(request CodexImageRequest, edit bool) error {
	if request.Model != "gpt-image-2" {
		return errors.New("Codex Images model must be gpt-image-2")
	}
	if strings.TrimSpace(request.Prompt) == "" {
		return errors.New("Codex Images prompt is required")
	}
	if len(request.Prompt) > maxCodexImagePromptBytes {
		return errors.New("Codex Images prompt is too large")
	}
	if request.N < 0 || request.N > maxCodexImageCount {
		return errors.New("Codex Images image count is invalid")
	}
	if request.Size != "" {
		if err := validateCodexImageSize(request.Size); err != nil {
			return err
		}
	}
	if request.Quality != "" {
		switch request.Quality {
		case "low", "medium", "high", "auto", "standard":
		default:
			return errors.New("Codex Images quality is invalid")
		}
	}
	if request.Background != "" {
		switch request.Background {
		case "auto", "opaque":
		default:
			return errors.New("Codex Images background is invalid")
		}
	}
	if request.OutputFormat != "" {
		switch request.OutputFormat {
		case "png", "webp", "jpeg":
		default:
			return errors.New("Codex Images output format is invalid")
		}
	}
	if request.ResponseFormat != "b64_json" {
		return errors.New("Codex Images response format must be b64_json")
	}
	if !edit {
		if request.Image != "" || len(request.Images) != 0 || request.Mask != "" {
			return errors.New("Codex Images generation does not accept source images")
		}
		return nil
	}
	if request.Image != "" && len(request.Images) != 0 {
		return errors.New("Codex Images edit accepts image or images, not both")
	}
	if request.Image == "" && len(request.Images) == 0 {
		return errors.New("Codex Images edit requires source images")
	}
	if err := validateCodexImageInputSize(request); err != nil {
		return err
	}
	if request.Image != "" {
		if err := validateCodexImageDataURL(request.Image); err != nil {
			return fmt.Errorf("Codex Images edit image: %w", err)
		}
	}
	if len(request.Images) > maxCodexImageCount {
		return errors.New("Codex Images edit image count is invalid")
	}
	for index, image := range request.Images {
		if err := validateCodexImageDataURL(image); err != nil {
			return fmt.Errorf("Codex Images edit image %d: %w", index, err)
		}
	}
	if request.Mask != "" {
		if err := validateCodexImageDataURL(request.Mask); err != nil {
			return fmt.Errorf("Codex Images edit mask: %w", err)
		}
	}
	return nil
}

func validateCodexImageSize(size string) error {
	if size == "auto" {
		return nil
	}
	parts := strings.Split(size, "x")
	if len(parts) != 2 {
		return errors.New("Codex Images size is invalid")
	}
	width, err := strconv.Atoi(parts[0])
	if err != nil {
		return errors.New("Codex Images size is invalid")
	}
	height, err := strconv.Atoi(parts[1])
	if err != nil {
		return errors.New("Codex Images size is invalid")
	}
	if width <= 0 || height <= 0 || width > maxCodexImageDimension || height > maxCodexImageDimension ||
		width%16 != 0 || height%16 != 0 || width > maxCodexImagePixels/height || height > maxCodexImagePixels/width ||
		width > height*3 || height > width*3 {
		return errors.New("Codex Images size is invalid")
	}
	return nil
}

func validateCodexImageInputSize(request CodexImageRequest) error {
	total := 0
	add := func(value string) bool {
		if len(value) > maxCodexImageRequestBytes-total {
			return false
		}
		total += len(value)
		return true
	}
	if !add(request.Image) {
		return errors.New("Codex Images edit images are too large")
	}
	for _, image := range request.Images {
		if !add(image) {
			return errors.New("Codex Images edit images are too large")
		}
	}
	if !add(request.Mask) {
		return errors.New("Codex Images edit mask is too large")
	}
	return nil
}

func validateCodexImageDataURL(value string) error {
	const dataPrefix = "data:"
	if !strings.HasPrefix(value, dataPrefix) {
		return errors.New("image must be a base64 data URL")
	}
	if len(value) > maxCodexImageRequestBytes {
		return errors.New("image data URL is too large")
	}
	comma := strings.IndexByte(value, ',')
	if comma < len(dataPrefix)+1 {
		return errors.New("image data URL is invalid")
	}
	metadata := strings.Split(value[len(dataPrefix):comma], ";")
	if len(metadata) != 2 || !strings.EqualFold(metadata[1], "base64") {
		return errors.New("image data URL is invalid")
	}
	declaredMIME := strings.ToLower(strings.TrimSpace(metadata[0]))
	switch declaredMIME {
	case "image/png", "image/jpeg", "image/webp":
	default:
		return errors.New("image data URL MIME type is invalid")
	}
	encoded := value[comma+1:]
	decodedSize, ok := codexBase64DecodedSize(encoded)
	if !ok || decodedSize == 0 || decodedSize > maxCodexImageBytes {
		return errors.New("image data URL is too large or invalid")
	}
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return errors.New("image data URL base64 is invalid")
	}
	actualMIME, ok := detectCodexImageMIME(decoded)
	if !ok || actualMIME != declaredMIME {
		return errors.New("image data URL does not contain the declared image type")
	}
	return nil
}

func decodeCodexImageResponse(request CodexImageRequest, response CodexImageResponse) (CodexImageResult, error) {
	if len(response.Data) == 0 || len(response.Data) > maxCodexImageCount {
		return CodexImageResult{}, errors.New("Codex Images response image count is invalid")
	}
	if request.N > 0 && len(response.Data) > request.N {
		return CodexImageResult{}, errors.New("Codex Images response image count is invalid")
	}
	result := CodexImageResult{
		Created: response.Created,
		Images:  make([]CodexImage, len(response.Data)),
		Usage:   response.Usage,
	}
	for index, image := range response.Data {
		if image.B64JSON == "" || image.URL != "" {
			return CodexImageResult{}, fmt.Errorf("Codex Images response image %d is invalid", index)
		}
		decodedSize, ok := codexBase64DecodedSize(image.B64JSON)
		if !ok || decodedSize == 0 || decodedSize > maxCodexImageBytes {
			return CodexImageResult{}, fmt.Errorf("Codex Images response image %d is too large or invalid", index)
		}
		decoded, err := base64.StdEncoding.DecodeString(image.B64JSON)
		if err != nil {
			return CodexImageResult{}, fmt.Errorf("Codex Images response image %d is invalid", index)
		}
		mimeType, ok := detectCodexImageMIME(decoded)
		if !ok {
			return CodexImageResult{}, fmt.Errorf("Codex Images response image %d has an unsupported type", index)
		}
		if request.OutputFormat != "" && mimeType != codexImageMIME(request.OutputFormat) {
			return CodexImageResult{}, fmt.Errorf("Codex Images response image %d has an unexpected type", index)
		}
		if len(image.RevisedPrompt) > maxCodexImagePromptBytes {
			return CodexImageResult{}, fmt.Errorf("Codex Images response image %d metadata is too large", index)
		}
		result.Images[index] = CodexImage{
			Bytes:         decoded,
			MIMEType:      mimeType,
			RevisedPrompt: image.RevisedPrompt,
		}
	}
	return result, nil
}

func codexBase64DecodedSize(value string) (int, bool) {
	if value == "" || len(value)%4 == 1 {
		return 0, false
	}
	decoded := base64.StdEncoding.DecodedLen(len(value))
	if decoded < 0 || decoded > maxCodexImageBytes {
		return 0, false
	}
	return decoded, true
}

func detectCodexImageMIME(data []byte) (string, bool) {
	if len(data) >= 8 && bytes.Equal(data[:8], []byte{0x89, 'P', 'N', 'G', '\r', '\n', 0x1a, '\n'}) {
		return "image/png", true
	}
	if len(data) >= 3 && data[0] == 0xff && data[1] == 0xd8 && data[2] == 0xff {
		return "image/jpeg", true
	}
	if len(data) >= 12 && bytes.Equal(data[:4], []byte("RIFF")) && bytes.Equal(data[8:12], []byte("WEBP")) {
		return "image/webp", true
	}
	return "", false
}

func codexImageMIME(outputFormat string) string {
	switch outputFormat {
	case "png":
		return "image/png"
	case "webp":
		return "image/webp"
	case "jpeg":
		return "image/jpeg"
	default:
		return ""
	}
}

func readCodexImageBody(ctx context.Context, body io.Reader) ([]byte, error) {
	if body == nil {
		return nil, errors.New("Codex Images response body is empty")
	}
	limited := io.LimitReader(&codexContextReader{ctx: ctx, reader: body}, maxCodexImageResponseBytes+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return nil, fmt.Errorf("read Codex Images response: %w", err)
	}
	if len(data) > maxCodexImageResponseBytes {
		return nil, errors.New("Codex Images response is too large")
	}
	if len(data) == 0 {
		return nil, errors.New("Codex Images response body is empty")
	}
	return data, nil
}

func readCodexImageErrorBody(ctx context.Context, body io.Reader) ([]byte, error) {
	if body == nil {
		return nil, nil
	}
	return readHTTPErrorBody(&codexContextReader{ctx: ctx, reader: body})
}
