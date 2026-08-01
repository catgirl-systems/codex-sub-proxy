package server

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"
)

const (
	readHeaderTimeout = 5 * time.Second
	writeTimeout      = 10 * time.Second
	idleTimeout       = 60 * time.Second
)

type Config struct {
	Listen      string
	AdminListen string
}

type Servers struct {
	dataServer  *http.Server
	adminServer *http.Server
	dataAddr    string
	adminAddr   string
	errors      chan error
	waitGroup   sync.WaitGroup
}

func Start(cfg Config, readiness *Readiness) (*Servers, error) {
	if cfg.Listen == "" {
		return nil, fmt.Errorf("data listener address is empty")
	}
	if cfg.AdminListen == "" {
		return nil, fmt.Errorf("admin listener address is empty")
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
			Handler:           NewHealthHandler(readiness),
			ReadHeaderTimeout: readHeaderTimeout,
			WriteTimeout:      writeTimeout,
			IdleTimeout:       idleTimeout,
		},
		adminServer: &http.Server{
			Handler:           NewHealthHandler(readiness),
			ReadHeaderTimeout: readHeaderTimeout,
			WriteTimeout:      writeTimeout,
			IdleTimeout:       idleTimeout,
		},
		dataAddr:  dataListener.Addr().String(),
		adminAddr: adminListener.Addr().String(),
		errors:    make(chan error, 2),
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
	var first error
	if err := s.dataServer.Shutdown(ctx); err != nil {
		first = err
	}
	if err := s.adminServer.Shutdown(ctx); err != nil && first == nil {
		first = err
	}
	s.waitGroup.Wait()
	return first
}

func (s *Servers) serve(server *http.Server, listener net.Listener) {
	defer s.waitGroup.Done()
	if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
		s.errors <- err
	}
}
