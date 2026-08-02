package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/catgirl-systems/codex-sub-proxy/internal/codex"
	"github.com/catgirl-systems/codex-sub-proxy/internal/config"
	"github.com/catgirl-systems/codex-sub-proxy/internal/payload"
	"github.com/catgirl-systems/codex-sub-proxy/internal/server"
	"github.com/catgirl-systems/codex-sub-proxy/internal/storage"
	"gorm.io/gorm"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		log.Print(err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) > 0 {
		switch args[0] {
		case "import":
			return runImport(args[1:])
		case "login":
			return runLogin(args[1:])
		}
	}
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

	payloadKeys, payloadErr := cfg.Security.PayloadKeySet(os.LookupEnv)
	credentialKeys, credentialErr := cfg.Security.CredentialKeySet(os.LookupEnv)
	if payloadErr == nil && credentialErr == nil {
		if err := config.ValidateActiveKeyIndependence(payloadKeys, credentialKeys); err != nil {
			return err
		}
	}

	readiness := server.NewReadiness()
	var db *gorm.DB
	storageReady := false
	databasePath, err := config.ExpandPath(cfg.Storage.SQLitePath)
	if err != nil {
		log.Printf("storage is unavailable: %v", err)
	} else {
		db, err = storage.Open(context.Background(), databasePath, cfg.Storage.BusyTimeout)
		if err != nil {
			log.Printf("storage is unavailable: %v", err)
		} else if err := payload.Migrate(db); err != nil {
			log.Printf("storage is unavailable: %v", err)
		} else {
			storageReady = true
		}
	}
	if db != nil {
		sqlDB, dbErr := db.DB()
		if dbErr != nil {
			return fmt.Errorf("get sqlite database: %w", dbErr)
		}
		defer func() {
			_ = sqlDB.Close()
		}()
	}

	keysReady := cfg.Security.KeysAvailable(os.LookupEnv)
	keysReady = keysReady && payloadErr == nil && credentialErr == nil
	var credentialAvailable func() bool
	if credentialErr == nil {
		if credentialPath, expandErr := config.ExpandPath(cfg.Codex.CredentialFile); expandErr == nil {
			credentialAvailable = func() bool {
				return codex.CredentialAvailable(credentialPath, credentialKeys)
			}
		}
	}
	readiness.Set(storageReady, keysReady, credentialAvailable)

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
		return serverStoppedError(err, shutdownServers(servers))
	case <-ctx.Done():
		return shutdownServers(servers)
	}
}

func runImport(args []string) error {
	flags := flag.NewFlagSet("codex-sub-proxy import", flag.ContinueOnError)
	configPath := flags.String("config", "config.toml", "path to the TOML configuration file")
	sourcePath := flags.String("source", "", "path to Codex auth.json, Codex home, or OMP agent.db")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected command-line argument")
	}
	if *sourcePath == "" {
		return fmt.Errorf("credential source path is required")
	}
	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	credentialKeys, err := cfg.Security.CredentialKeySet(os.LookupEnv)
	if err != nil {
		return err
	}
	destinationPath, err := config.ExpandPath(cfg.Codex.CredentialFile)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	_, err = codex.ImportCredential(ctx, *sourcePath, destinationPath, credentialKeys)
	return err
}

func runLogin(args []string) error {
	flags := flag.NewFlagSet("codex-sub-proxy login", flag.ContinueOnError)
	configPath := flags.String("config", "config.toml", "path to the TOML configuration file")
	issuer := flags.String("issuer", "", "OAuth issuer URL")
	port := flags.Int("port", 0, "local OAuth callback port")
	device := flags.Bool("device", false, "use device-code login")
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
	credentialKeys, err := cfg.Security.CredentialKeySet(os.LookupEnv)
	if err != nil {
		return err
	}
	destinationPath, err := config.ExpandPath(cfg.Codex.CredentialFile)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	_, err = codex.LoginAndSave(ctx, codex.LoginOptions{
		Issuer:       *issuer,
		CallbackPort: *port,
		Device:       *device,
		OnAuthorizationURL: func(url string) {
			fmt.Fprintln(os.Stdout, url)
		},
		OnDeviceCode: func(url, code string) {
			fmt.Fprintf(os.Stdout, "Open %s and enter code %s.\n", url, code)
		},
	}, destinationPath, credentialKeys)
	return err
}

func serverStoppedError(serveErr, shutdownErr error) error {
	serverErr := fmt.Errorf("server stopped: %w", serveErr)
	if shutdownErr == nil {
		return serverErr
	}
	return errors.Join(serverErr, fmt.Errorf("shutdown servers: %w", shutdownErr))
}

func shutdownServers(servers *server.Servers) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return servers.Shutdown(ctx)
}
