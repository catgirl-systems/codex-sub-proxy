package server

import (
	"errors"
	"log/slog"
	"net/netip"
	"time"

	"github.com/kataras/iris/v12"
)

type applicationPolicy struct {
	listener       string
	admin          bool
	allowedOrigins map[string]struct{}
	corsMaxAge     time.Duration
	trustedProxies []netip.Prefix
	logger         *slog.Logger
	telemetry      *Telemetry
}

func installApplicationMiddleware(app *iris.Application, policy applicationPolicy) error {
	if app == nil {
		return errors.New("application is nil")
	}
	if policy.listener == "" {
		if policy.admin {
			policy.listener = "admin"
		} else {
			policy.listener = "data"
		}
	}
	if policy.corsMaxAge <= 0 {
		policy.corsMaxAge = 10 * time.Minute
	}
	boundary, err := newBoundaryMiddleware(boundaryConfig{
		listener:       policy.listener,
		admin:          policy.admin,
		allowedOrigins: policy.allowedOrigins,
		corsMaxAge:     policy.corsMaxAge,
		trustedProxies: policy.trustedProxies,
	})
	if err != nil {
		return err
	}
	app.UseRouter(requestLoggerMiddleware(requestObservation{logger: policy.logger, listener: policy.listener, telemetry: policy.telemetry}), boundary)
	return nil
}
