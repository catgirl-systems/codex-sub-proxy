package server

import (
	"context"
	"errors"
	"fmt"
	"github.com/catgirl-systems/codex-sub-proxy/internal/apikey"
	"github.com/catgirl-systems/codex-sub-proxy/internal/codex"
	"github.com/catgirl-systems/codex-sub-proxy/internal/envelope"
	"gorm.io/gorm"
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
	Listen               string
	AdminListen          string
	Database             *gorm.DB
	APIKeyHMACKey        []byte
	PayloadKeys          envelope.KeySet
	ResponsesTransport   *codex.ResponsesTransport
	ImagesClient         *codex.ImagesClient
	ArtifactStore        *ArtifactStore
	ArtifactRequired     bool
	Retention            RetentionConfig
	JournalMode          string
	JournalQueueCapacity int
	JournalDrainDeadline time.Duration
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
	journal       *Journal
	retention     *RetentionRunner
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

	errorsChannel := make(chan error, 8)
	var journal *Journal
	var quota *apikey.QuotaStore
	var retention *RetentionRunner
	closeStarted := func() {
		if retention != nil {
			_ = retention.Close(context.Background())
		}
		if journal != nil {
			_ = journal.Close(context.Background())
		}
	}
	if cfg.Database != nil {
		if err := MigrateJournal(cfg.Database); err != nil {
			return nil, err
		}
		if err := apikey.MigrateQuota(cfg.Database); err != nil {
			return nil, err
		}
		var err error
		quota, err = apikey.NewQuotaStore(cfg.Database)
		if err != nil {
			return nil, err
		}
		if err := quota.RecoverPending(context.Background()); err != nil {
			return nil, fmt.Errorf("recover quota reservations: %w", err)
		}
		if cfg.PayloadKeys.Active.Version == 0 {
			journal, err = newJournal(cfg.Database, cfg.JournalMode, cfg.JournalQueueCapacity, cfg.JournalDrainDeadline)
		} else {
			journal, err = newJournalWithKeysAndTTLs(cfg.Database, cfg.JournalMode, cfg.JournalQueueCapacity, cfg.JournalDrainDeadline, cfg.Retention.PayloadTTL, cfg.Retention.MetadataTTL, cfg.PayloadKeys)
		}
		if err != nil {
			return nil, err
		}
		journal.setErrorSink(errorsChannel)
		if err := journal.Replay(context.Background()); err != nil {
			return nil, fmt.Errorf("replay journal: %w", err)
		}
		if err := journal.Start(); err != nil {
			return nil, fmt.Errorf("start journal: %w", err)
		}
		if cfg.ArtifactStore != nil || cfg.Retention.SweepInterval != 0 {
			retention, err = NewRetentionRunner(cfg.Database, cfg.ArtifactStore, cfg.Retention)
			if err != nil {
				closeStarted()
				return nil, err
			}
			if err := retention.Start(); err != nil {
				closeStarted()
				return nil, fmt.Errorf("start retention: %w", err)
			}
		}
	}
	dataHandler, err := newDataApplication(readiness, cfg.Database, cfg.APIKeyHMACKey, cfg.ResponsesTransport, cfg.ImagesClient, journal, quota, cfg.ArtifactStore, cfg.ArtifactRequired)
	if err != nil {
		closeStarted()
		return nil, fmt.Errorf("build data application: %w", err)
	}
	adminHandler, err := newHealthApplication(readiness)
	if err != nil {
		closeStarted()
		return nil, fmt.Errorf("build admin health application: %w", err)
	}

	dataListener, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		closeStarted()
		return nil, fmt.Errorf("listen for data plane on %q: %w", cfg.Listen, err)
	}
	adminListener, err := net.Listen("tcp", cfg.AdminListen)
	if err != nil {
		_ = dataListener.Close()
		closeStarted()
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
		errors:        errorsChannel,
		journal:       journal,
		retention:     retention,
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

// DeleteConversation removes all owned lifecycle content and metadata.
func (s *Servers) DeleteConversation(ctx context.Context, id string) error {
	if s == nil || s.retention == nil {
		return errors.New("retention is unavailable")
	}
	return s.retention.DeleteConversation(ctx, id)
}
func (s *Servers) Shutdown(ctx context.Context) error {
	if ctx == nil {
		return errors.New("shutdown context is nil")
	}
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
			if err := s.closeJournal(ctx); err != nil {
				errs = append(errs, err)
			}
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
		if err := s.closeJournal(ctx); err != nil {
			errs = append(errs, err)
		}
		return errors.Join(errs...)
	case <-ctx.Done():
		s.forceClose()
		if err := s.closeJournal(ctx); err != nil {
			errs = append(errs, err)
		}
		return errors.Join(append(errs, ctx.Err())...)
	}
}

func (s *Servers) closeJournal(ctx context.Context) error {
	var errs []error
	if s.retention != nil {
		if err := s.retention.Close(ctx); err != nil {
			errs = append(errs, err)
		}
	}
	if s.journal != nil {
		if err := s.journal.Close(ctx); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
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
