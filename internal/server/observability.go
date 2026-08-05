package server

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/kataras/iris/v12"
)

const (
	requestErrorKey     = "csp-request-error"
	requestErrorCodeKey = "csp-request-error-code"
	requestTransportKey = "csp-request-transport"
)

type requestObservation struct {
	logger    *slog.Logger
	listener  string
	telemetry *Telemetry
}

func newJSONLogger(writer io.Writer) *slog.Logger {
	if writer == nil {
		writer = io.Discard
	}
	return slog.New(slog.NewJSONHandler(writer, &slog.HandlerOptions{Level: slog.LevelInfo}))
}

func requestLoggerMiddleware(observation requestObservation) iris.Handler {
	logger := observation.logger
	if logger == nil {
		logger = newJSONLogger(nil)
	}
	if observation.listener != "admin" {
		observation.listener = "data"
	}
	return func(ctx iris.Context) {
		started := time.Now()
		request := ctx.Request()
		requestID := requestIDFromContext(request.Context())
		if !validRequestID(requestID) {
			requestID = safeRequestID(request.Header.Values("X-Request-ID"))
			request.Header.Set("X-Request-ID", requestID)
			ctx.Header("X-Request-ID", requestID)
			*request = *request.WithContext(withRequestID(request.Context(), requestID))
		}
		if observation.telemetry != nil {
			observation.telemetry.beginRequest(request.Context(), observation.listener, request.URL.Path, request.Method)
		}
		defer func() {
			if recovered := recover(); recovered != nil {
				setRequestError(ctx, "panic", "panic")
				logger.Error("request_panic", "request_id", requestID, "listener", observation.listener, "error_class", "panic", "error_code", "panic")
				if ctx.ResponseWriter().Written() < 0 {
					writeSafeInternalError(ctx)
				}
			}
			status := ctx.ResponseWriter().StatusCode()
			if status < 100 || status > 599 {
				status = http.StatusOK
			}
			written := ctx.ResponseWriter().Written()
			if written < 0 {
				written = 0
			}
			route := "unmatched"
			routeName := "unmatched"
			if current := ctx.GetCurrentRoute(); current != nil {
				if path := current.Path(); path != "" {
					route = path
					routeName = path
				}
				if name := current.Name(); name != "" {
					routeName = name
				}
			}
			errorClass, _ := ctx.Values().Get(requestErrorKey).(string)
			errorCode, _ := ctx.Values().Get(requestErrorCodeKey).(string)
			transport, _ := ctx.Values().Get(requestTransportKey).(string)
			if transport == "" {
				transport = "none"
			}
			duration := time.Since(started)
			logger.Info("request_complete",
				"request_id", requestID,
				"listener", observation.listener,
				"method", safeMethod(request.Method),
				"route", route,
				"route_name", routeName,
				"status_class", statusClass(status),
				"status", status,
				"duration_ms", duration.Milliseconds(),
				"response_bytes", written,
				"error_class", safeLogValue(errorClass),
				"error_code", safeLogValue(errorCode),
				"transport_outcome", safeLogValue(transport),
			)
			if observation.telemetry != nil {
				observation.telemetry.observeRequest(request.Context(), observation.listener, route, safeMethod(request.Method), status, duration, transport)
			}
		}()
		ctx.Next()
	}
}

func withRequestID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, requestContextKey{}, id)
}

func setRequestError(ctx iris.Context, class, code string) {
	if class != "" {
		ctx.Values().Set(requestErrorKey, class)
	}
	if code != "" {
		ctx.Values().Set(requestErrorCodeKey, code)
	}
}

func setTransportOutcome(ctx iris.Context, outcome string) {
	if outcome == "" {
		return
	}
	ctx.Values().Set(requestTransportKey, outcome)
}

func statusClass(status int) string {
	if status < 100 || status > 599 {
		return "unknown"
	}
	return fmt.Sprintf("%dxx", status/100)
}

func errorClassForStatus(status int) string {
	switch {
	case status >= 400 && status < 500:
		return "client"
	case status >= 500:
		return "server"
	default:
		return ""
	}
}

func safeMethod(method string) string {
	method = strings.ToUpper(method)
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete, http.MethodOptions:
		return method
	default:
		return "OTHER"
	}
}

func safeLogValue(value string) string {
	if len(value) > 64 {
		return "invalid"
	}
	for index := 0; index < len(value); index++ {
		if value[index] < 'a' || value[index] > 'z' {
			if value[index] < '0' || value[index] > '9' {
				if value[index] != '_' && value[index] != '-' {
					return "invalid"
				}
			}
		}
	}
	return value
}
