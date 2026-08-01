package main

import (
	"context"
	"database/sql"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/catgirl-systems/codex-sub-proxy/internal/config"
	"github.com/catgirl-systems/codex-sub-proxy/internal/server"
	"github.com/catgirl-systems/codex-sub-proxy/internal/storage"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		log.Print(err)
		os.Exit(1)
	}
}

func run(args []string) error {
	flags := flag.NewFlagSet("codex-sub-proxy", flag.ContinueOnError)
	configPath := flags.String("config", "config.toml", "path to the TOML configuration file")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected command-line argument")
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}

	readiness := server.NewReadiness()
	var db *sql.DB
	storageReady := false
	databasePath, err := config.ExpandPath(cfg.Storage.SQLitePath)
	if err != nil {
		log.Printf("storage is unavailable: %v", err)
	} else {
		db, err = storage.Open(context.Background(), databasePath, cfg.Storage.BusyTimeout)
		if err != nil {
			log.Printf("storage is unavailable: %v", err)
		} else {
			storageReady = true
		}
	}
	if db != nil {
		defer db.Close()
	}

	keysReady := cfg.Security.KeysAvailable(os.LookupEnv)
	upstreamAuthReady := config.CredentialFileAvailable(cfg.Codex.CredentialFile)
	readiness.Set(storageReady, keysReady, upstreamAuthReady)

	servers, err := server.Start(server.Config{
		Listen:      cfg.Server.Listen,
		AdminListen: cfg.Server.AdminListen,
	}, readiness)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	select {
	case err := <-servers.Errors():
		shutdownServers(servers)
		return fmt.Errorf("server stopped: %w", err)
	case <-ctx.Done():
		return shutdownServers(servers)
	}
}

func shutdownServers(servers *server.Servers) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return servers.Shutdown(ctx)
}
