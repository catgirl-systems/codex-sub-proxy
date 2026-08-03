package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/catgirl-systems/codex-sub-proxy/internal/apikey"
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
		case "api-key":
			return runAPIKey(args[1:])
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
	apiKeyHMACKey, apiKeyHMACErr := cfg.Security.APIKeyHMACKey(os.LookupEnv)
	if payloadErr == nil && credentialErr == nil {
		if err := config.RequireDistinctActiveKeys(payloadKeys, credentialKeys); err != nil {
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
		} else if err := apikey.Migrate(db); err != nil {
			log.Printf("storage is unavailable: %v", err)
		} else if err := server.MigrateJournal(db); err != nil {
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
	keysReady = keysReady && payloadErr == nil && credentialErr == nil && apiKeyHMACErr == nil
	var credentialSnapshot func() server.CredentialSnapshot
	var responsesTransport *codex.ResponsesTransport
	var imagesClient *codex.ImagesClient
	if credentialErr == nil {
		if credentialPath, expandErr := config.ExpandPath(cfg.Codex.CredentialFile); expandErr == nil {
			if refresher, refreshErr := codex.NewRefresher(credentialPath, credentialKeys, codex.RefresherOptions{
				Issuer:   "https://auth.openai.com",
				ClientID: "app_EMoamEEZ73f0CkXaXp7hrann",
			}); refreshErr == nil {
				credentialSnapshot = func() server.CredentialSnapshot {
					snapshot := refresher.Snapshot()
					return server.CredentialSnapshot{
						Available: snapshot.Available,
						State:     string(snapshot.State),
					}
				}
				responsesTransport, err = codex.NewResponsesTransport(codex.ResponsesTransportOptions{
					Policy:    codex.ResponsesTransportPolicy(cfg.Codex.ResponsesTransport),
					Refresher: refresher,
					Headers:   codex.HeaderConfig{},
				})
				if err != nil {
					return fmt.Errorf("build Responses transport: %w", err)
				}
				imagesClient, err = codex.NewImagesClient(codex.ImagesClientOptions{
					Refresher: refresher,
					Headers:   codex.HeaderConfig{},
				})
				if err != nil {
					return fmt.Errorf("build Images client: %w", err)
				}
			}
		}
	}

	readiness.Set(storageReady, keysReady, credentialSnapshot)
	servers, err := server.Start(server.Config{
		Listen:               cfg.Server.Listen,
		AdminListen:          cfg.Server.AdminListen,
		Database:             db,
		APIKeyHMACKey:        apiKeyHMACKey,
		ResponsesTransport:   responsesTransport,
		PayloadKeys:          payloadKeys,
		ImagesClient:         imagesClient,
		JournalMode:          string(cfg.Journal.Mode),
		JournalQueueCapacity: cfg.Journal.QueueCapacity,
		JournalDrainDeadline: cfg.Journal.DrainDeadline,
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

type listFlag []string

func (f *listFlag) String() string {
	return strings.Join(*f, ",")
}

func (f *listFlag) Set(value string) error {
	parts := strings.Split(value, ",")
	for _, part := range parts {
		if part == "" {
			return fmt.Errorf("list value is empty")
		}
		*f = append(*f, part)
	}
	return nil
}

func runAPIKey(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("API-key command is required")
	}
	switch args[0] {
	case "create":
		return runAPIKeyCreate(args[1:])
	default:
		return fmt.Errorf("unknown API-key command %q", args[0])
	}
}

func runAPIKeyCreate(args []string) error {
	flags := flag.NewFlagSet("codex-sub-proxy api-key create", flag.ContinueOnError)
	configPath := flags.String("config", "config.toml", "path to the TOML configuration file")
	name := flags.String("name", "", "API-key name")
	owner := flags.String("owner", "", "API-key owner")
	var endpoints listFlag
	var models listFlag
	flags.Var(&endpoints, "endpoint", "allowed endpoint; repeat or use a comma-separated list")
	flags.Var(&endpoints, "endpoints", "allowed endpoint; repeat or use a comma-separated list")
	flags.Var(&models, "model", "allowed model; repeat or use a comma-separated list")
	flags.Var(&endpoints, "allowed-endpoint", "allowed endpoint; repeat or use a comma-separated list")
	flags.Var(&endpoints, "allowed-endpoints", "allowed endpoint; repeat or use a comma-separated list")
	flags.Var(&models, "allowed-model", "allowed model; repeat or use a comma-separated list")
	flags.Var(&models, "allowed-models", "allowed model; repeat or use a comma-separated list")
	flags.Var(&models, "models", "allowed model; repeat or use a comma-separated list")
	expiresAt := flags.String("expires-at", "", "RFC3339 expiry time")
	expires := flags.String("expires", "", "RFC3339 expiry time or duration from now")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected command-line argument")
	}
	if strings.TrimSpace(*expiresAt) != "" && strings.TrimSpace(*expires) != "" {
		return fmt.Errorf("only one expiry option is allowed")
	}
	expiry, err := parseAPIKeyExpiry(*expiresAt, *expires, time.Now().UTC())
	if err != nil {
		return err
	}
	policy := apikey.Policy{
		Name:             *name,
		Owner:            *owner,
		AllowedEndpoints: endpoints,
		AllowedModels:    models,
		ExpiresAt:        expiry,
	}
	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	hmacKey, err := cfg.Security.APIKeyHMACKey(os.LookupEnv)
	if err != nil {
		return err
	}
	databasePath, err := config.ExpandPath(cfg.Storage.SQLitePath)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	db, err := storage.Open(ctx, databasePath, cfg.Storage.BusyTimeout)
	if err != nil {
		return err
	}
	sqlDB, err := db.DB()
	if err != nil {
		return fmt.Errorf("get sqlite database: %w", err)
	}
	defer func() {
		_ = sqlDB.Close()
	}()
	if err := apikey.Migrate(db); err != nil {
		return err
	}
	rawKey, _, err := apikey.Create(ctx, db, hmacKey, policy)
	if err != nil {
		return err
	}
	fmt.Fprintln(os.Stdout, rawKey)
	return nil
}

func parseAPIKeyExpiry(expiryAt, expiry string, now time.Time) (*time.Time, error) {
	value := strings.TrimSpace(expiryAt)
	if value == "" {
		value = strings.TrimSpace(expiry)
	}
	if value == "" {
		return nil, nil
	}
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil && strings.TrimSpace(expiryAt) == "" {
		duration, durationErr := time.ParseDuration(value)
		if durationErr != nil {
			return nil, fmt.Errorf("parse API-key expiry: %w", err)
		}
		if duration <= 0 {
			return nil, fmt.Errorf("API-key expiry duration must be positive")
		}
		parsed = now.Add(duration)
		err = nil
	}
	if err != nil {
		return nil, fmt.Errorf("parse API-key expiry: %w", err)
	}
	parsed = parsed.UTC()
	if !parsed.After(now) {
		return nil, fmt.Errorf("API-key expiry must be in the future")
	}
	return &parsed, nil
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
	payloadKeys, err := cfg.Security.PayloadKeySet(os.LookupEnv)
	if err != nil {
		return err
	}
	credentialKeys, err := cfg.Security.CredentialKeySet(os.LookupEnv)
	if err != nil {
		return err
	}
	if err := config.RequireDistinctActiveKeys(payloadKeys, credentialKeys); err != nil {
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
	clientID := flags.String("client-id", "", "OAuth client ID")
	port := flags.Int("port", 0, "local OAuth callback port")
	device := flags.Bool("device", false, "use device-code login")
	pollInterval := flags.Duration("poll-interval", 0, "device-code polling interval")
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
	payloadKeys, err := cfg.Security.PayloadKeySet(os.LookupEnv)
	if err != nil {
		return err
	}
	credentialKeys, err := cfg.Security.CredentialKeySet(os.LookupEnv)
	if err != nil {
		return err
	}
	if err := config.RequireDistinctActiveKeys(payloadKeys, credentialKeys); err != nil {
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
		ClientID:     *clientID,
		CallbackPort: *port,
		Device:       *device,
		PollInterval: *pollInterval,
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
