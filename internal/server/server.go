package server

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/catgirl-systems/codex-sub-proxy/internal/codex"
	"gorm.io/gorm"
)

const (
	readHeaderTimeout = 5 * time.Second
	writeTimeout      = 10 * time.Second
	idleTimeout       = 60 * time.Second
)

type Config struct {
	Listen             string
	AdminListen        string
	Database           *gorm.DB
	APIKeyHMACKey      []byte
	ResponsesTransport *codex.ResponsesTransport
	ImagesClient       *codex.ImagesClient
}

type Servers struct {
	dataServer    *http.Server
	adminServer   *http.Server
	dataListener  net.Listener
	adminListener net.Listener
	dataAddr      string
	adminAddr     string
	errors        chan error
	waitGroup     sync.WaitGroup
}

func Start(cfg Config, readiness *Readiness) (*Servers, error) {
	return startWithWriteTimeout(cfg, readiness, writeTimeout)
}

func startWithWriteTimeout(cfg Config, readiness *Readiness, serverWriteTimeout time.Duration) (*Servers, error) {
	if cfg.Listen == "" {
		return nil, fmt.Errorf("data listener address is empty")
	}
	if cfg.AdminListen == "" {
		return nil, fmt.Errorf("admin listener address is empty")
	}
	dataHandler, err := newDataApplication(readiness, cfg.Database, cfg.APIKeyHMACKey, cfg.ResponsesTransport, cfg.ImagesClient)
	if err != nil {
		return nil, fmt.Errorf("build data application: %w", err)
	}
	adminHandler, err := newHealthApplication(readiness)
	if err != nil {
		return nil, fmt.Errorf("build admin health application: %w", err)
	}

	dataListener, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return nil, fmt.Errorf("listen for data plane on %q: %w", cfg.Listen, err)
	}
	adminListener, err := net.Listen("tcp", cfg.AdminListen)
	if err != nil {
		_ = dataListener.Close()
		return nil, fmt.Errorf("listen for admin plane on %q: %w", cfg.AdminListen, err)
	}
	servers := &Servers{
		dataServer: &http.Server{
			Handler:           dataHandler,
			ReadHeaderTimeout: readHeaderTimeout,
			WriteTimeout:      serverWriteTimeout,
			IdleTimeout:       idleTimeout,
			MaxHeaderBytes:    64 * 1024,
		},
		adminServer: &http.Server{
			Handler:           adminHandler,
			ReadHeaderTimeout: readHeaderTimeout,
			WriteTimeout:      serverWriteTimeout,
			IdleTimeout:       idleTimeout,
			MaxHeaderBytes:    64 * 1024,
		},
		dataListener:  dataListener,
		adminListener: adminListener,
		dataAddr:      dataListener.Addr().String(),
		adminAddr:     adminListener.Addr().String(),
		errors:        make(chan error, 2),
	}
	servers.waitGroup.Add(2)
	go servers.serve(servers.dataServer, dataListener)
	go servers.serve(servers.adminServer, adminListener)
	return servers, nil
}

func (s *Servers) DataAddr() string {
	return s.dataAddr
}

func (s *Servers) AdminAddr() string {
	return s.adminAddr
}

func (s *Servers) Errors() <-chan error {
	return s.errors
}

func (s *Servers) Shutdown(ctx context.Context) error {
	shutdownErrors := make(chan error, 2)
	go func() {
		shutdownErrors <- s.dataServer.Shutdown(ctx)
	}()
	go func() {
		shutdownErrors <- s.adminServer.Shutdown(ctx)
	}()

	var errs []error
	for range 2 {
		select {
		case err := <-shutdownErrors:
			if err != nil {
				errs = append(errs, err)
			}
		case <-ctx.Done():
			s.forceClose()
			return errors.Join(append(errs, ctx.Err())...)
		}
	}
	if len(errs) > 0 {
		s.forceClose()
	}

	serveDone := make(chan struct{})
	go func() {
		s.waitGroup.Wait()
		close(serveDone)
	}()
	select {
	case <-serveDone:
		return errors.Join(errs...)
	case <-ctx.Done():
		s.forceClose()
		return errors.Join(append(errs, ctx.Err())...)
	}
}

func (s *Servers) forceClose() {
	if s.dataListener != nil {
		_ = s.dataListener.Close()
	}
	if s.adminListener != nil {
		_ = s.adminListener.Close()
	}
	_ = s.dataServer.Close()
	_ = s.adminServer.Close()
}

func (s *Servers) serve(server *http.Server, listener net.Listener) {
	defer s.waitGroup.Done()
	if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
		s.errors <- err
	}
}
