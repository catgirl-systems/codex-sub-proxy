package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"github.com/catgirl-systems/codex-sub-proxy/internal/apikey"
	"github.com/catgirl-systems/codex-sub-proxy/internal/codex"
	"github.com/catgirl-systems/codex-sub-proxy/internal/config"
	"github.com/catgirl-systems/codex-sub-proxy/internal/envelope"
	"github.com/catgirl-systems/codex-sub-proxy/internal/server"
	"github.com/catgirl-systems/codex-sub-proxy/internal/storage"
	"github.com/catgirl-systems/codex-sub-proxy/internal/version"
	"gorm.io/gorm"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

var processLogger = slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

func main() {
	if err := run(os.Args[1:]); err != nil {
		processLogger.Error("process_exit", "error_class", "startup", "error_code", "failed")
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
		case "backup":
			return runBackup(args[1:])
		case "restore":
			return runRestore(args[1:])
		case "version":
			fmt.Fprintln(os.Stdout, version.String())
			return nil
		}
		if args[0] == "--version" {
			fmt.Fprintln(os.Stdout, version.String())
			return nil
		}
	}
	flags := flag.NewFlagSet("codex-sub-proxy", flag.ContinueOnError)
	configPath := flags.String("config", "config.toml", "path to the TOML configuration file")
	showVersion := flags.Bool("version", false, "print version information")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *showVersion {
		fmt.Fprintln(os.Stdout, version.String())
		return nil
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected command-line argument")
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}

	var telemetry *server.Telemetry
	telemetryHeaders := map[string]string{}
	if cfg.Telemetry.Enabled {
		var telemetryErr error
		telemetryHeaders, telemetryErr = cfg.Telemetry.ResolveHeaders(os.LookupEnv)
		if telemetryErr != nil {
			processLogger.Warn("telemetry_unavailable", "error_class", "telemetry", "error_code", "headers_invalid")
		} else {
			telemetry, telemetryErr = server.NewTelemetry(context.Background(), cfg.Telemetry, telemetryHeaders)
			if telemetryErr != nil {
				processLogger.Warn("telemetry_unavailable", "error_class", "telemetry", "error_code", "exporter_unavailable")
				telemetry = nil
			}
		}
	} else {
		telemetry, _ = server.NewTelemetry(context.Background(), cfg.Telemetry, telemetryHeaders)
	}
	payloadKeys, payloadErr := cfg.Security.PayloadKeySet(os.LookupEnv)
	credentialKeys, credentialErr := cfg.Security.CredentialKeySet(os.LookupEnv)
	apiKeyHMACKey, apiKeyHMACErr := cfg.Security.APIKeyHMACKey(os.LookupEnv)
	adminHMACKey, _ := cfg.Security.AdminTokenHMACKey(os.LookupEnv)
	adminBootstrapToken, _ := cfg.Security.AdminBootstrapToken(os.LookupEnv)
	if payloadErr == nil && credentialErr == nil {
		if err := config.RequireDistinctActiveKeys(payloadKeys, credentialKeys); err != nil {
			return err
		}
	}

	readiness := server.NewReadiness()
	var db *gorm.DB
	var artifactStore *server.ArtifactStore
	var applicationLock *storage.ApplicationLock
	storageReady := false
	databasePath, err := config.ExpandPath(cfg.Storage.SQLitePath)
	if err != nil {
		processLogger.Error("storage_unavailable", "error_class", "storage", "error_code", "path_unavailable")
	} else {
		applicationLock, err = storage.AcquireApplicationLock(context.Background(), databasePath, storage.ApplicationLockExclusive)
		if err != nil {
			return err
		}
		defer func() {
			_ = applicationLock.Close()
		}()
		if err := server.RecoverRestoreWithLock(applicationLock, databasePath); err != nil {
			return err
		}
		db, err = storage.Open(context.Background(), databasePath, cfg.Storage.BusyTimeout)
		if err != nil {
			processLogger.Error("storage_unavailable", "error_class", "storage", "error_code", "open")
		} else if err := server.MigrateSchema(db); err != nil {
			processLogger.Error("storage_unavailable", "error_class", "storage", "error_code", "schema_migrate")
		} else if payloadErr != nil {
			processLogger.Error("artifact_unavailable", "error_class", "storage", "error_code", "payload_key")
		} else {
			artifactStore, err = server.NewArtifactStore(db, cfg.Storage.ArtifactRoot, payloadKeys, cfg.Retention.ArtifactTTL)
			if err != nil {
				processLogger.Error("artifact_unavailable", "error_class", "storage", "error_code", "open")
			} else {
				storageReady = true
			}
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

	keysReady := cfg.Security.DataKeysAvailable(os.LookupEnv)
	keysReady = keysReady && payloadErr == nil && credentialErr == nil && apiKeyHMACErr == nil
	var credentialSnapshot func() server.CredentialSnapshot
	var upstreamBroker server.UpstreamBroker
	if credentialErr == nil {
		upstreamBroker, credentialSnapshot, err = buildUpstreamBroker(context.Background(), cfg, db, credentialKeys)
		if err != nil {
			processLogger.Error("account_registry_unavailable", "error_class", "account_registry", "error_code", "startup", "error", err)
			upstreamBroker = nil
			credentialSnapshot = nil
		}
	}

	cleanupTimeout := cfg.Retention.DrainDeadline
	if cfg.Journal.DrainDeadline > cleanupTimeout {
		cleanupTimeout = cfg.Journal.DrainDeadline
	}
	if cfg.Telemetry.ShutdownTimeout > cleanupTimeout {
		cleanupTimeout = cfg.Telemetry.ShutdownTimeout
	}
	readiness.Set(storageReady, keysReady, credentialSnapshot)
	servers, err := server.Start(server.Config{
		Listen:              cfg.Server.Listen,
		AdminListen:         cfg.Server.AdminListen,
		StartupLock:         applicationLock,
		Database:            db,
		APIKeyHMACKey:       apiKeyHMACKey,
		AdminTokenHMACKey:   adminHMACKey,
		AdminBootstrapToken: adminBootstrapToken,
		AdminCookieSecure:   cfg.Security.AdminCookieSecure,
		UpstreamBroker:      upstreamBroker,
		PayloadKeys:         payloadKeys,
		ArtifactStore:       artifactStore,
		ArtifactRequired:    true,
		Retention: server.RetentionConfig{
			ArtifactTTL:   cfg.Retention.ArtifactTTL,
			PayloadTTL:    cfg.Retention.PayloadTTL,
			MetadataTTL:   cfg.Retention.MetadataTTL,
			SweepInterval: cfg.Retention.SweepInterval,
			BatchSize:     cfg.Retention.BatchSize,
			DrainDeadline: cfg.Retention.DrainDeadline,
		},
		JournalMode:          string(cfg.Journal.Mode),
		JournalQueueCapacity: cfg.Journal.QueueCapacity,
		JournalDrainDeadline: cfg.Journal.DrainDeadline,
		CleanupTimeout:       cleanupTimeout,
		Pricing:              cfg.Pricing,
		CORS:                 cfg.CORS,
		TrustedProxyCIDRs:    cfg.Server.TrustedProxyCIDRs,
		DataTLS:              cfg.Server.DataTLS,
		AdminTLS:             cfg.Server.AdminTLS,
		Logger:               processLogger,
		Telemetry:            telemetry,
	}, readiness)
	if err != nil {
		if telemetry != nil {
			_ = telemetry.Shutdown(context.Background())
		}
		processLogger.Error("server_start_failed", "error_class", "server", "error_code", "startup")
		return err
	}
	processLogger.Info("process_started", "service", "codex-sub-proxy")
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	select {
	case err := <-servers.Errors():
		return serverStoppedError(err, shutdownServers(servers))
	case <-ctx.Done():
		return shutdownServers(servers)
	}
}

func configuredAccountSelector(value config.AccountSelector) (codex.AccountSelector, error) {
	switch value {
	case config.AccountSelectorSingle:
		return codex.SingleSelector{}, nil
	case config.AccountSelectorRoundRobin:
		return &codex.RoundRobinSelector{}, nil
	case config.AccountSelectorQuotaAware:
		return &codex.QuotaAwareSelector{}, nil
	default:
		return nil, fmt.Errorf("unsupported Codex account selector %q", value)
	}
}

func buildUpstreamBroker(ctx context.Context, cfg config.Config, db *gorm.DB, credentialKeys envelope.KeySet) (server.UpstreamBroker, func() server.CredentialSnapshot, error) {
	if ctx == nil {
		return nil, nil, errors.New("upstream broker context is nil")
	}
	if db == nil {
		return nil, nil, nil
	}
	store, err := server.NewAccountStore(db)
	if err != nil {
		return nil, nil, err
	}
	records, err := store.List(ctx)
	if err != nil {
		return nil, nil, err
	}
	credentialPath, pathErr := config.ExpandPath(cfg.Codex.CredentialFile)
	if pathErr != nil {
		return nil, nil, pathErr
	}
	historicalCredential, historicalErr := codex.LoadCredential(credentialPath, credentialKeys)
	legacyPlaceholder := len(records) == 1 &&
		records[0].Provider == "codex" &&
		strings.TrimSpace(records[0].CredentialPath) == "" &&
		records[0].ProviderAccountID == historicalCredential.AccountID
	if historicalErr == nil && (len(records) == 0 || legacyPlaceholder) {
		if legacyPlaceholder {
			record := records[0]
			if record.ID == "default" {
				record.CredentialPath = credentialPath
				record.Enabled = true
				record.IsDefault = true
				if err := store.Upsert(ctx, record); err != nil {
					return nil, nil, fmt.Errorf("materialize default account: %w", err)
				}
			} else if err := store.MaterializeLegacyDefault(ctx, record.ID, credentialPath, historicalCredential); err != nil {
				return nil, nil, fmt.Errorf("materialize default account: %w", err)
			}
		} else {
			if err := store.MaterializeDefault(ctx, credentialPath, historicalCredential); err != nil {
				return nil, nil, fmt.Errorf("materialize default account: %w", err)
			}
		}
		records, err = store.List(ctx)
		if err != nil {
			return nil, nil, err
		}
	}
	selector, err := configuredAccountSelector(cfg.Codex.AccountSelector)
	if err != nil {
		return nil, nil, err
	}
	readinessSelector, err := configuredAccountSelector(cfg.Codex.AccountSelector)
	if err != nil {
		return nil, nil, err
	}
	profiles := make([]server.BrokerProfile, 0, len(records))
	refreshersByAccount := make(map[string]*codex.Refresher, len(records))
	for _, record := range records {
		if record.Provider != "codex" || strings.TrimSpace(record.CredentialPath) == "" {
			continue
		}
		credential, loadErr := codex.LoadCredential(record.CredentialPath, credentialKeys)
		if loadErr != nil || credential.AccountID != record.ProviderAccountID {
			continue
		}
		refresher, refreshErr := codex.NewRefresher(record.CredentialPath, credentialKeys, codex.RefresherOptions{
			Issuer: "https://auth.openai.com", ClientID: "app_EMoamEEZ73f0CkXaXp7hrann",
		})
		if refreshErr != nil {
			continue
		}
		responsesTransport, transportErr := codex.NewResponsesTransport(codex.ResponsesTransportOptions{
			Policy:       codex.ResponsesTransportPolicy(cfg.Codex.ResponsesTransport),
			ResponsesURL: cfg.Codex.ResponsesURL,
			Refresher:    refresher,
			Headers:      codex.HeaderConfig{},
		})
		if transportErr != nil {
			return nil, nil, fmt.Errorf("build Responses transport for account %q: %w", record.ID, transportErr)
		}
		imagesClient, imagesErr := codex.NewImagesClient(codex.ImagesClientOptions{
			Refresher: refresher,
			Headers:   codex.HeaderConfig{},
		})
		if imagesErr != nil {
			return nil, nil, fmt.Errorf("build Images client for account %q: %w", record.ID, imagesErr)
		}
		snapshot := refresher.Snapshot()
		profiles = append(profiles, server.BrokerProfile{
			Account: codex.Account{
				ID: record.ID, ProviderAccountID: record.ProviderAccountID, CredentialPath: record.CredentialPath,
				Enabled: record.Enabled, IsDefault: record.IsDefault, Available: snapshot.Available,
				CooldownUntil: accountRecordTime(record.CooldownUntil), PlanType: record.PlanType,
			},
			Refresher: refresher, Responses: responsesTransport, Images: imagesClient,
		})
		refreshersByAccount[record.ID] = refresher
	}
	if len(profiles) == 0 {
		return nil, nil, nil
	}
	broker, err := server.NewProfileBroker(selector, profiles)
	if err != nil {
		return nil, nil, err
	}
	credentialSnapshot := func() server.CredentialSnapshot {
		var result server.CredentialSnapshot
		snapshots := make(map[string]codex.CredentialSnapshot, len(refreshersByAccount))
		for accountID, refresher := range refreshersByAccount {
			snapshot := refresher.Snapshot()
			snapshots[accountID] = snapshot
			if result.State == "" || result.State == string(codex.CredentialStatusMissing) {
				result.State = string(snapshot.State)
			}
		}
		selected, err := readinessSelector.Select(context.Background(), codex.SelectionRequest{}, broker.Accounts())
		if err != nil {
			return result
		}
		snapshot, ok := snapshots[selected.ID]
		if !ok {
			return result
		}
		return server.CredentialSnapshot{Available: true, State: string(snapshot.State)}
	}
	return broker, credentialSnapshot, nil
}

func accountRecordTime(value *time.Time) time.Time {
	if value == nil {
		return time.Time{}
	}
	return value.UTC()
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
	if strings.TrimSpace(*name) == "" {
		return fmt.Errorf("API-key name is required")
	}
	if strings.TrimSpace(*owner) == "" {
		return fmt.Errorf("API-key owner is required")
	}
	endpointValues := []string(endpoints)
	modelValues := []string(models)
	if len(endpointValues) == 0 {
		return fmt.Errorf("at least one endpoint is required")
	}
	if len(modelValues) == 0 {
		return fmt.Errorf("at least one model is required")
	}
	expiry, err := parseAPIKeyExpiry(*expiresAt, *expires, time.Now().UTC())
	if err != nil {
		return err
	}
	policy := apikey.Policy{
		Name:             *name,
		Owner:            *owner,
		AllowedEndpoints: endpointValues,
		AllowedModels:    modelValues,
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
	lock, err := storage.AcquireApplicationLock(context.Background(), databasePath, storage.ApplicationLockShared)
	if err != nil {
		return err
	}
	defer lock.Close()
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
func runImport(args []string) error {
	flags := flag.NewFlagSet("codex-sub-proxy import", flag.ContinueOnError)
	configPath := flags.String("config", "config.toml", "path to the TOML configuration file")
	sourcePath := flags.String("source", "", "path to Codex auth.json, Codex home, or OMP agent.db")
	profile := flags.String("profile", "default", "credential profile name")
	makeDefault := flags.Bool("default", false, "make this profile the default account")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected command-line argument")
	}
	if strings.TrimSpace(*sourcePath) == "" {
		return errors.New("credential source path is required")
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
	basePath, err := config.ExpandPath(cfg.Codex.CredentialFile)
	if err != nil {
		return err
	}
	destinationPath, err := codex.ProfileCredentialPath(basePath, *profile)
	if err != nil {
		return err
	}
	if err := codex.ValidateImportDestination(*sourcePath, destinationPath); err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	credential, err := codex.ExtractCredential(ctx, *sourcePath, credentialKeys)
	if err != nil {
		return err
	}
	return saveProfileCredential(ctx, cfg, basePath, *profile, *makeDefault || strings.TrimSpace(*profile) == "default", credential, credentialKeys)
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

func runLogin(args []string) error {
	flags := flag.NewFlagSet("codex-sub-proxy login", flag.ContinueOnError)
	configPath := flags.String("config", "config.toml", "path to the TOML configuration file")
	issuer := flags.String("issuer", "", "OAuth issuer URL")
	clientID := flags.String("client-id", "", "OAuth client ID")
	profile := flags.String("profile", "default", "credential profile name")
	makeDefault := flags.Bool("default", false, "make this profile the default account")
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
	basePath, err := config.ExpandPath(cfg.Codex.CredentialFile)
	if err != nil {
		return err
	}
	if _, err := codex.ProfileCredentialPath(basePath, *profile); err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	credential, err := codex.Login(ctx, codex.LoginOptions{
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
	})
	if err != nil {
		return err
	}
	return saveProfileCredential(ctx, cfg, basePath, *profile, *makeDefault || strings.TrimSpace(*profile) == "default", credential, credentialKeys)
}
func saveProfileCredential(ctx context.Context, cfg config.Config, basePath, profile string, makeDefault bool, credential codex.Credential, keys envelope.KeySet) error {
	if ctx == nil {
		return errors.New("credential profile context is nil")
	}
	if strings.TrimSpace(credential.AccountID) == "" {
		return errors.New("credential account ID is empty")
	}
	if len(credential.AccountID) > 255 || strings.ContainsAny(credential.AccountID, "\r\n") {
		return errors.New("credential account ID is invalid")
	}
	destinationPath, err := codex.ProfileCredentialPath(basePath, profile)
	if err != nil {
		return err
	}
	databasePath, err := config.ExpandPath(cfg.Storage.SQLitePath)
	if err != nil {
		return err
	}
	lock, err := storage.AcquireApplicationLock(ctx, databasePath, storage.ApplicationLockExclusive)
	if err != nil {
		return err
	}
	defer lock.Close()
	db, err := storage.Open(ctx, databasePath, cfg.Storage.BusyTimeout)
	if err != nil {
		return err
	}
	sqlDB, err := db.DB()
	if err != nil {
		return fmt.Errorf("get sqlite database: %w", err)
	}
	defer func() { _ = sqlDB.Close() }()
	if err := server.MigrateSchema(db); err != nil {
		return err
	}
	store, err := server.NewAccountStore(db)
	if err != nil {
		return err
	}
	records, err := store.List(ctx)
	if err != nil {
		return err
	}
	profileID := strings.TrimSpace(profile)
	for _, record := range records {
		if record.ID != profileID && record.ProviderAccountID == credential.AccountID {
			return fmt.Errorf("provider account ID %q is already registered", credential.AccountID)
		}
	}
	isDefault := makeDefault || profileID == "default"
	if !isDefault {
		for _, record := range records {
			if record.ID == profileID {
				isDefault = record.IsDefault
				break
			}
		}
	}
	rollback, err := codex.SaveCredentialContextWithRollback(ctx, destinationPath, credential, keys)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	err = store.Upsert(ctx, server.AccountRecord{
		ID: profileID, Provider: "codex", ProviderAccountID: credential.AccountID,
		CredentialPath: destinationPath, Enabled: true, IsDefault: isDefault,
		PlanType: credential.PlanType, Email: credential.Email, CreatedAt: now, UpdatedAt: now, LastSeenAt: &now,
	})
	if err == nil {
		return nil
	}
	restoreErr := rollback.Restore(context.WithoutCancel(ctx))
	if restoreErr != nil {
		return credentialProfileRollbackError(err, restoreErr)
	}
	return fmt.Errorf("register credential profile: %w", err)
}

func credentialProfileRollbackError(registerErr, restoreErr error) error {
	return errors.Join(
		fmt.Errorf("register credential profile: %w", registerErr),
		fmt.Errorf("restore credential: %w", restoreErr),
	)
}

func runBackup(args []string) error {
	flags := flag.NewFlagSet("codex-sub-proxy backup", flag.ContinueOnError)
	configPath := flags.String("config", "config.toml", "path to the TOML configuration file")
	outputPath := flags.String("output", "", "new local backup archive path")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected command-line argument")
	}
	if strings.TrimSpace(*outputPath) == "" {
		return errors.New("backup output path is required")
	}
	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	databasePath, err := config.ExpandPath(cfg.Storage.SQLitePath)
	if err != nil {
		return err
	}
	artifactRoot, err := config.ExpandPath(cfg.Storage.ArtifactRoot)
	if err != nil {
		return err
	}
	payloadKeys, err := cfg.Security.PayloadKeySet(os.LookupEnv)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	applicationLock, err := storage.AcquireApplicationLock(ctx, databasePath, storage.ApplicationLockShared)
	if err != nil {
		return err
	}
	defer applicationLock.Close()
	artifactBarrier, err := server.AcquireArtifactBarrier(ctx, artifactRoot, server.ArtifactBarrierExclusive)
	if err != nil {
		return err
	}
	defer artifactBarrier.Close()
	db, err := storage.Open(ctx, databasePath, cfg.Storage.BusyTimeout)
	if err != nil {
		return err
	}
	sqlDB, err := db.DB()
	if err != nil {
		return fmt.Errorf("get sqlite database: %w", err)
	}
	defer sqlDB.Close()
	artifacts, err := server.NewArtifactStoreWithBarrier(db, artifactRoot, payloadKeys, cfg.Retention.ArtifactTTL, artifactBarrier)
	if err != nil {
		return err
	}
	defer artifacts.Close()
	principal := fmt.Sprintf("cli:%d", os.Getuid())
	return server.CreateBackupWithBarrier(ctx, db, artifacts, *outputPath, principal, artifactBarrier)
}

func runRestore(args []string) error {
	flags := flag.NewFlagSet("codex-sub-proxy restore", flag.ContinueOnError)
	configPath := flags.String("config", "config.toml", "path to the TOML configuration file")
	inputPath := flags.String("input", "", "local backup archive path")
	force := flags.Bool("force", false, "replace the current database and artifact root")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected command-line argument")
	}
	if strings.TrimSpace(*inputPath) == "" {
		return errors.New("restore input path is required")
	}
	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	databasePath, err := config.ExpandPath(cfg.Storage.SQLitePath)
	if err != nil {
		return err
	}
	artifactRoot, err := config.ExpandPath(cfg.Storage.ArtifactRoot)
	if err != nil {
		return err
	}
	payloadVersions := append([]uint32{cfg.Security.PayloadEncryptionKeyVersion}, cfg.Security.PayloadEncryptionPreviousKeyVersions...)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	return server.Restore(ctx, server.RestoreOptions{
		DatabasePath:       databasePath,
		ArtifactRoot:       artifactRoot,
		Input:              *inputPath,
		Force:              *force,
		PayloadKeyVersions: payloadVersions,
		BusyTimeout:        cfg.Storage.BusyTimeout,
	})
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
