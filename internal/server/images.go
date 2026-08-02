package server

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"mime"
	"mime/multipart"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/catgirl-systems/codex-sub-proxy/internal/apikey"
	"github.com/catgirl-systems/codex-sub-proxy/internal/codex"
	"github.com/catgirl-systems/codex-sub-proxy/internal/openai"
	"github.com/go-playground/validator/v10"
	"github.com/kataras/iris/v12"
)

const (
	imagesGenerationsEndpoint = "/v1/images/generations"
	imagesEditsEndpoint       = "/v1/images/edits"

	maxImagesJSONBodyBytes      = 256 << 10
	maxImagesMultipartBodyBytes = 24 << 20
	maxImagesMultipartMemory    = 1 << 20
	maxImageFileBytes           = 4 << 20
	maxImageTotalBytes          = 20 << 20
	maxImagePromptBytes         = 64 << 10
	maxImageUserBytes           = 64 << 10
	maxImageResponseJSONBytes   = 32 << 20
	maxImageModelBytes          = 64
	maxImageOptionBytes         = 64
	maxImageResponsePromptBytes = 64 << 10
	imagesWriteTimeout          = 5*time.Minute + writeTimeout
)

var (
	errImagesUnsupportedMask = errors.New("mask is not supported")
	errImagesUnsupportedForm = errors.New("multipart field is not supported")
)

func newImagesGenerationHandler(authorizer *apikey.Authorizer, client *codex.ImagesClient) iris.Handler {
	requestValidation := validator.New()
	return func(ctx iris.Context) {
		setImagesWriteDeadline(ctx)
		request := ctx.Request()
		if request.Method != http.MethodPost {
			writeImagesMethodNotAllowed(ctx)
			return
		}
		principal, ok := authenticateImagesRequest(ctx, authorizer)
		if !ok {
			return
		}
		mediaType, _, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
		if err != nil || mediaType != "application/json" {
			writeImagesError(ctx, http.StatusUnsupportedMediaType, "invalid_media_type", "Content-Type must be application/json.")
			return
		}
		if request.ContentLength > maxImagesJSONBodyBytes {
			writeImagesError(ctx, http.StatusRequestEntityTooLarge, "request_too_large", "Request body is too large.")
			return
		}
		request.Body = http.MaxBytesReader(ctx.ResponseWriter(), request.Body, maxImagesJSONBodyBytes)
		defer request.Body.Close()
		var publicRequest openai.ImageGenerationRequest
		if err := decodeImagesJSON(request.Body, &publicRequest); err != nil {
			if errors.Is(err, errImagesBodyTooLarge) {
				writeImagesError(ctx, http.StatusRequestEntityTooLarge, "request_too_large", "Request body is too large.")
			} else {
				writeImagesError(ctx, http.StatusBadRequest, "invalid_json", "Request body is not valid JSON.")
			}
			return
		}
		if publicRequest.ResponseFormat == "url" {
			writeImagesError(ctx, http.StatusBadRequest, "unsupported_response_format", "Only b64_json response format is supported.")
			return
		}
		if err := validateImagesRequest(requestValidation, publicRequest); err != nil {
			writeImagesError(ctx, http.StatusBadRequest, "invalid_request", "The request is invalid.")
			return
		}
		if err := authorizer.AuthorizePrincipal(request.Context(), principal, imagesGenerationsEndpoint, publicRequest.Model); err != nil {
			writeAPIKeyError(ctx, err)
			return
		}
		if client == nil {
			writeImagesError(ctx, http.StatusServiceUnavailable, "upstream_unavailable", "The upstream service is unavailable.")
			return
		}
		result, err := client.Generate(request.Context(), codex.CodexImageGenerationRequest{
			Model:             publicRequest.Model,
			Prompt:            publicRequest.Prompt,
			N:                 publicRequest.N,
			Size:              publicRequest.Size,
			Quality:           publicRequest.Quality,
			Background:        publicRequest.Background,
			OutputCompression: publicRequest.OutputCompression,
			OutputFormat:      publicRequest.OutputFormat,
			Moderation:        publicRequest.Moderation,
			User:              publicRequest.User,
		})
		if err != nil {
			writeImagesDispatchError(ctx, err)
			return
		}
		if request.Context().Err() != nil {
			return
		}
		response, err := publicImageResponse(result)
		if err != nil {
			writeImagesError(ctx, http.StatusBadGateway, "invalid_upstream_response", "The upstream response was invalid.")
			return
		}
		writeJSON(ctx, http.StatusOK, response)
	}
}

func newImagesEditHandler(authorizer *apikey.Authorizer, client *codex.ImagesClient) iris.Handler {
	requestValidation := validator.New()
	return func(ctx iris.Context) {
		setImagesWriteDeadline(ctx)
		request := ctx.Request()
		if request.Method != http.MethodPost {
			writeImagesMethodNotAllowed(ctx)
			return
		}
		principal, ok := authenticateImagesRequest(ctx, authorizer)
		if !ok {
			return
		}
		mediaType, _, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
		if err != nil || mediaType != "multipart/form-data" {
			writeImagesError(ctx, http.StatusUnsupportedMediaType, "invalid_media_type", "Content-Type must be multipart/form-data.")
			return
		}
		if request.ContentLength > maxImagesMultipartBodyBytes {
			writeImagesError(ctx, http.StatusRequestEntityTooLarge, "request_too_large", "Request body is too large.")
			return
		}
		request.Body = http.MaxBytesReader(ctx.ResponseWriter(), request.Body, maxImagesMultipartBodyBytes)
		defer request.Body.Close()
		defer func() {
			if request.MultipartForm != nil {
				_ = request.MultipartForm.RemoveAll()
			}
		}()
		if err := request.ParseMultipartForm(maxImagesMultipartMemory); err != nil {
			var maxBytesError *http.MaxBytesError
			if errors.As(err, &maxBytesError) {
				writeImagesError(ctx, http.StatusRequestEntityTooLarge, "request_too_large", "Request body is too large.")
			} else {
				writeImagesError(ctx, http.StatusBadRequest, "invalid_multipart", "The multipart request is invalid.")
			}
			return
		}
		form := request.MultipartForm
		if form == nil {
			writeImagesError(ctx, http.StatusBadRequest, "invalid_multipart", "The multipart request is invalid.")
			return
		}
		if err := validateImageFormFields(form); err != nil {
			if errors.Is(err, errImagesUnsupportedMask) {
				writeImagesError(ctx, http.StatusBadRequest, "unsupported_parameter", "The mask parameter is not supported.")
			} else {
				writeImagesError(ctx, http.StatusBadRequest, "invalid_request", "The request is invalid.")
			}
			return
		}
		publicRequest, present, err := decodeImageEditForm(form.Value)
		if err != nil {
			writeImagesError(ctx, http.StatusBadRequest, "invalid_request", "The request is invalid.")
			return
		}
		if present.responseFormat == "url" {
			writeImagesError(ctx, http.StatusBadRequest, "unsupported_response_format", "Only b64_json response format is supported.")
			return
		}
		if err := validateImagesRequest(requestValidation, publicRequest); err != nil {
			writeImagesError(ctx, http.StatusBadRequest, "invalid_request", "The request is invalid.")
			return
		}
		if err := authorizer.AuthorizePrincipal(request.Context(), principal, imagesEditsEndpoint, publicRequest.Model); err != nil {
			writeAPIKeyError(ctx, err)
			return
		}
		if client == nil {
			writeImagesError(ctx, http.StatusServiceUnavailable, "upstream_unavailable", "The upstream service is unavailable.")
			return
		}
		files, err := imageFileHeaders(form)
		if err != nil {
			writeImagesError(ctx, http.StatusBadRequest, "invalid_image", "The image files are invalid.")
			return
		}
		dataURLs, err := encodeImageFiles(files)
		if err != nil {
			writeImagesError(ctx, http.StatusBadRequest, "invalid_image", "The image files are invalid.")
			return
		}
		publicRequest.Images = dataURLs
		result, err := client.Edit(request.Context(), codex.CodexImageEditRequest{
			Model:             publicRequest.Model,
			Prompt:            publicRequest.Prompt,
			Images:            imageEditInputs(dataURLs),
			N:                 publicRequest.N,
			Size:              publicRequest.Size,
			Quality:           publicRequest.Quality,
			Background:        publicRequest.Background,
			OutputCompression: publicRequest.OutputCompression,
			OutputFormat:      publicRequest.OutputFormat,
			User:              publicRequest.User,
		})
		if err != nil {
			writeImagesDispatchError(ctx, err)
			return
		}
		if request.Context().Err() != nil {
			return
		}
		response, err := publicImageResponse(result)
		if err != nil {
			writeImagesError(ctx, http.StatusBadGateway, "invalid_upstream_response", "The upstream response was invalid.")
			return
		}
		writeJSON(ctx, http.StatusOK, response)
	}
}

var errImagesBodyTooLarge = errors.New("image request body is too large")

type imageEditFormPresence struct {
	responseFormat string
}

func authenticateImagesRequest(ctx iris.Context, authorizer *apikey.Authorizer) (apikey.Principal, bool) {
	headers := ctx.Request().Header.Values("Authorization")
	if len(headers) != 1 {
		writeAPIKeyError(ctx, apikey.ErrInvalidKey)
		return apikey.Principal{}, false
	}
	principal, err := authorizer.AuthenticateHeader(ctx.Request().Context(), headers[0])
	if err != nil {
		writeAPIKeyError(ctx, err)
		return apikey.Principal{}, false
	}
	return principal, true
}

func setImagesWriteDeadline(ctx iris.Context) {
	_ = http.NewResponseController(ctx.ResponseWriter().Naive()).SetWriteDeadline(time.Now().Add(imagesWriteTimeout))
}

func writeImagesMethodNotAllowed(ctx iris.Context) {
	ctx.Header("Allow", http.MethodPost)
	writeImagesError(ctx, http.StatusMethodNotAllowed, "method_not_allowed", "Only POST is allowed for this endpoint.")
}

func writeImagesError(ctx iris.Context, status int, code, message string) {
	typeName := "invalid_request_error"
	if status >= http.StatusInternalServerError {
		typeName = "server_error"
	}
	writeResponsesError(ctx, status, typeName, code, message)
}

func writeImagesDispatchError(ctx iris.Context, err error) {
	if ctx.Request().Context().Err() != nil {
		return
	}
	status, responseError := responsesError(err)
	writeResponsesError(ctx, status, responseError.Type, responseError.Code, responseError.Message)
}

func decodeImagesJSON(reader io.Reader, destination any) error {
	decoder := json.NewDecoder(reader)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		var maxBytesError *http.MaxBytesError
		if errors.As(err, &maxBytesError) {
			return errImagesBodyTooLarge
		}
		return err
	}
	var extra json.RawMessage
	if err := decoder.Decode(&extra); err != io.EOF {
		var maxBytesError *http.MaxBytesError
		if errors.As(err, &maxBytesError) {
			return errImagesBodyTooLarge
		}
		if err == nil {
			return errors.New("multiple JSON values")
		}
		return err
	}
	return nil
}

func validateImagesRequest(requestValidation *validator.Validate, request any) error {
	if err := requestValidation.Struct(request); err != nil {
		return err
	}
	switch request := request.(type) {
	case openai.ImageGenerationRequest:
		return validateImageRequestFields(request.Model, request.Prompt, request.User, request.OutputCompression, request.OutputFormat)
	case openai.ImageEditRequest:
		return validateImageRequestFields(request.Model, request.Prompt, request.User, request.OutputCompression, request.OutputFormat)
	default:
		return errors.New("unsupported image request")
	}
}

func validateImageRequestFields(model, prompt, user string, outputCompression *int, outputFormat string) error {
	if model != "gpt-image-2" || strings.TrimSpace(prompt) == "" {
		return errors.New("image model or prompt is invalid")
	}
	if len(model) > maxImageModelBytes || len(prompt) > maxImagePromptBytes || len(user) > maxImageUserBytes {
		return errors.New("image request field is too large")
	}
	if outputCompression != nil && outputFormat != "jpeg" && outputFormat != "webp" {
		return errors.New("image output compression requires jpeg or webp output format")
	}
	return nil
}

func validateImageFormFields(form *multipart.Form) error {
	for field := range form.Value {
		switch field {
		case "model", "prompt", "n", "size", "quality", "background", "output_compression", "output_format", "response_format", "user":
		case "mask":
			return errImagesUnsupportedMask
		default:
			return fmt.Errorf("%w: %s", errImagesUnsupportedForm, field)
		}
	}
	for field := range form.File {
		if field != "image" && field != "image[]" {
			if field == "mask" {
				return errImagesUnsupportedMask
			}
			return fmt.Errorf("%w: %s", errImagesUnsupportedForm, field)
		}
	}
	if len(form.File["image"]) > 0 && len(form.File["image[]"]) > 0 {
		return errors.New("image field has multiple encodings")
	}
	return nil
}

func decodeImageEditForm(values map[string][]string) (openai.ImageEditRequest, imageEditFormPresence, error) {
	var request openai.ImageEditRequest
	var present imageEditFormPresence
	model, _, err := imageFormString(values, "model", maxImageModelBytes)
	if err != nil {
		return request, present, err
	}
	prompt, _, err := imageFormString(values, "prompt", maxImagePromptBytes)
	if err != nil {
		return request, present, err
	}
	request.Model = model
	request.Prompt = prompt
	if request.N, err = imageFormInt(values, "n"); err != nil {
		return request, present, err
	}
	if request.Size, _, err = imageFormString(values, "size", maxImageOptionBytes); err != nil {
		return request, present, err
	}
	if request.Quality, _, err = imageFormString(values, "quality", maxImageOptionBytes); err != nil {
		return request, present, err
	}
	if request.Background, _, err = imageFormString(values, "background", maxImageOptionBytes); err != nil {
		return request, present, err
	}
	if request.OutputCompression, err = imageFormInt(values, "output_compression"); err != nil {
		return request, present, err
	}
	if request.OutputFormat, _, err = imageFormString(values, "output_format", maxImageOptionBytes); err != nil {
		return request, present, err
	}
	if present.responseFormat, _, err = imageFormString(values, "response_format", maxImageOptionBytes); err != nil {
		return request, present, err
	}
	request.ResponseFormat = present.responseFormat
	if request.User, _, err = imageFormString(values, "user", maxImageUserBytes); err != nil {
		return request, present, err
	}
	return request, present, nil
}

func imageFormString(values map[string][]string, name string, maxBytes int) (string, bool, error) {
	items, ok := values[name]
	if !ok {
		return "", false, nil
	}
	if len(items) != 1 || len(items[0]) > maxBytes {
		return "", true, errors.New("multipart field is invalid")
	}
	return items[0], true, nil
}

func imageFormInt(values map[string][]string, name string) (*int, error) {
	value, present, err := imageFormString(values, name, maxImageOptionBytes)
	if err != nil {
		return nil, err
	}
	if !present {
		return nil, nil
	}
	parsed, err := strconv.ParseInt(value, 10, 32)
	if err != nil {
		return nil, errors.New("multipart integer field is invalid")
	}
	converted := int(parsed)
	return &converted, nil
}

func imageFileHeaders(form *multipart.Form) ([]*multipart.FileHeader, error) {
	files := form.File["image"]
	if len(files) == 0 {
		files = form.File["image[]"]
	}
	if len(files) == 0 || len(files) > 5 {
		return nil, errors.New("image count is invalid")
	}
	total := int64(0)
	for _, file := range files {
		if file == nil || file.Size == 0 || file.Size > maxImageFileBytes {
			return nil, errors.New("image size is invalid")
		}
		if file.Size > 0 {
			if total > maxImageTotalBytes-file.Size {
				return nil, errors.New("image total size is invalid")
			}
			total += file.Size
		}
	}
	return files, nil
}

func encodeImageFiles(files []*multipart.FileHeader) ([]string, error) {
	dataURLs := make([]string, 0, len(files))
	total := int64(0)
	for _, header := range files {
		file, err := header.Open()
		if err != nil {
			return nil, errors.New("open image file")
		}
		data, readErr := io.ReadAll(io.LimitReader(file, maxImageFileBytes+1))
		closeErr := file.Close()
		if readErr != nil || closeErr != nil {
			return nil, errors.New("read image file")
		}
		if len(data) == 0 || len(data) > maxImageFileBytes || (header.Size >= 0 && int64(len(data)) != header.Size) {
			return nil, errors.New("image file is truncated or too large")
		}
		if total > maxImageTotalBytes-int64(len(data)) {
			return nil, errors.New("image total size is invalid")
		}
		total += int64(len(data))
		imageMIME, ok := imageMIME(data)
		if !ok || !imageDeclaredMIMEMatches(header, imageMIME) {
			return nil, errors.New("image MIME type is invalid")
		}
		prefix := "data:" + imageMIME + ";base64,"
		encoded := make([]byte, len(prefix)+base64.StdEncoding.EncodedLen(len(data)))
		copy(encoded, prefix)
		base64.StdEncoding.Encode(encoded[len(prefix):], data)
		dataURLs = append(dataURLs, string(encoded))
	}
	return dataURLs, nil
}

func imageDeclaredMIMEMatches(header *multipart.FileHeader, actual string) bool {
	if header == nil {
		return false
	}
	declared := strings.TrimSpace(header.Header.Get("Content-Type"))
	if declared == "" {
		return true
	}
	mediaType, _, err := mime.ParseMediaType(declared)
	if err != nil {
		return false
	}
	mediaType = strings.ToLower(mediaType)
	return mediaType == "application/octet-stream" || mediaType == actual
}

func imageMIME(data []byte) (string, bool) {
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

func imageEditInputs(dataURLs []string) []codex.CodexImageEditInput {
	inputs := make([]codex.CodexImageEditInput, len(dataURLs))
	for index, dataURL := range dataURLs {
		inputs[index].ImageURL = dataURL
	}
	return inputs
}

func publicImageResponse(result codex.CodexImageResult) (openai.ImageResponse, error) {
	if result.Created > math.MaxInt64 || len(result.Images) == 0 || len(result.Images) > 5 {
		return openai.ImageResponse{}, errors.New("invalid image result")
	}
	response := openai.ImageResponse{
		Created:      int64(result.Created),
		Background:   result.Background,
		Data:         make([]openai.ImageData, len(result.Images)),
		OutputFormat: result.OutputFormat,
		Quality:      result.Quality,
		Size:         result.Size,
		Usage:        publicImageUsage(result.Usage),
	}
	responseBytes := 0
	for index, image := range result.Images {
		if len(image.Bytes) == 0 || len(image.Bytes) > maxImageFileBytes || len(image.RevisedPrompt) > maxImageResponsePromptBytes {
			return openai.ImageResponse{}, errors.New("invalid image result")
		}
		encodedSize := base64.StdEncoding.EncodedLen(len(image.Bytes))
		if encodedSize > maxImageResponseJSONBytes-responseBytes {
			return openai.ImageResponse{}, errors.New("image result is too large")
		}
		responseBytes += encodedSize
		response.Data[index] = openai.ImageData{
			B64JSON:       base64.StdEncoding.EncodeToString(image.Bytes),
			RevisedPrompt: image.RevisedPrompt,
		}
	}
	return response, nil
}

func publicImageUsage(usage *codex.CodexUsage) *openai.Usage {
	if usage == nil {
		return nil
	}
	public := &openai.Usage{
		InputTokens:  usage.InputTokens,
		OutputTokens: usage.OutputTokens,
		TotalTokens:  usage.TotalTokens,
	}
	if usage.InputTokensDetails != nil {
		public.InputTokensDetails = &openai.InputTokenDetails{
			CachedTokens: usage.InputTokensDetails.CachedTokens,
			ImageTokens:  usage.InputTokensDetails.ImageTokens,
			TextTokens:   usage.InputTokensDetails.TextTokens,
		}
	}
	return public
}
