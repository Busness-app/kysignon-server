package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/Yoshiofthewire/kysignon-server/internal/api"
	"github.com/Yoshiofthewire/kysignon-server/internal/audit"
	"github.com/Yoshiofthewire/kysignon-server/internal/auth"
	"github.com/Yoshiofthewire/kysignon-server/internal/backup"
	"github.com/Yoshiofthewire/kysignon-server/internal/config"
	"github.com/Yoshiofthewire/kysignon-server/internal/crypto"
	"github.com/Yoshiofthewire/kysignon-server/internal/mfa"
	"github.com/Yoshiofthewire/kysignon-server/internal/netguard"
	"github.com/Yoshiofthewire/kysignon-server/internal/oauth"
	"github.com/Yoshiofthewire/kysignon-server/internal/store"
	"github.com/Yoshiofthewire/kysignon-server/internal/sync"
	"github.com/Yoshiofthewire/kysignon-server/web"
	"github.com/google/uuid"
)

// auditRetention bounds how long audit events are kept. On SQLite this is the table that
// grows fastest and never stops.
const auditRetention = 180 * 24 * time.Hour

const appVersion = "1.0.0"

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "bootstrap-admin":
			bootstrapCmd := flag.NewFlagSet("bootstrap-admin", flag.ExitOnError)
			bootstrapUser := bootstrapCmd.String("username", "admin", "Admin username")
			bootstrapPass := bootstrapCmd.String("password", "", "Admin password (min 12 chars)")
			bootstrapEmail := bootstrapCmd.String("email", "admin@local.kysecurity", "Admin email")
			_ = bootstrapCmd.Parse(os.Args[2:])
			runBootstrap(*bootstrapUser, *bootstrapPass, *bootstrapEmail)
			return
		case "backup-drill":
			runBackupDrill()
			return
		case "export-recovery-kit":
			kitCmd := flag.NewFlagSet("export-recovery-kit", flag.ExitOnError)
			outPath := kitCmd.String("out", "kysignon-recovery-kit", "Directory to write the capsule and custodian shard files into")
			_ = kitCmd.Parse(os.Args[2:])
			runExportRecoveryKit(*outPath)
			return
		case "push-backup":
			pushCmd := flag.NewFlagSet("push-backup", flag.ExitOnError)
			recURL := pushCmd.String("recovery-url", "", "KyRecovery server base URL")
			apiToken := pushCmd.String("token", "", "KyRecovery API bearer token")
			_ = pushCmd.Parse(os.Args[2:])
			runPushBackup(*recURL, *apiToken)
			return
		}
	}

	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	dbStore, err := store.New(cfg.DBPath)
	if err != nil {
		log.Fatalf("Failed to initialize database store: %v", err)
	}
	defer dbStore.Close()

	keyManager, err := crypto.LoadOrCreateRSAKey(cfg.RSAKeyPath)
	if err != nil {
		log.Fatalf("Failed to initialize RSA key manager: %v", err)
	}

	// Paired systems on a shared container network need private callbacks; on a public
	// deployment allowing them turns an attacker-chosen callback into an SSRF primitive.
	netguard.AllowPrivate = cfg.AllowPrivateCallbacks
	if cfg.AllowPrivateCallbacks {
		log.Println("WARNING: KYSIGNON_ALLOW_PRIVATE_CALLBACKS is on; paired systems may register internal callback URLs")
	}

	auditLogger := audit.NewLogger(dbStore)
	syncEngine := sync.NewEngine(dbStore, cfg.EncryptionKey)
	mfaEngine := mfa.NewEngine(dbStore, cfg.EncryptionKey)
	relaySender, err := mfa.NewRelaySender(
		mfa.RelayConfig{
			URL:     cfg.PushRelayURL,
			Key:     cfg.PushRelayKey,
			KeyFile: filepath.Join(cfg.DataDir, "push-relay-fcm.key"),
			Label:   "kysignon-" + cfg.IssuerURL,
		},
		mfa.RelayConfig{
			URL:     cfg.APNSRelayURL,
			Key:     cfg.APNSRelayKey,
			KeyFile: filepath.Join(cfg.DataDir, "push-relay-apns.key"),
			Label:   "kysignon-" + cfg.IssuerURL,
		},
	)
	if err != nil {
		log.Fatalf("Failed to initialize push relay sender: %v", err)
	}
	mfaEngine.SetPushSender(relaySender)
	oauthEngine := oauth.NewEngine(dbStore, keyManager, cfg.IssuerURL)

	adminCount, err := dbStore.CountAdmins()
	if err != nil {
		log.Fatalf("Failed to count administrators: %v", err)
	}
	switch {
	case adminCount > 0:
		if cfg.BootstrapPass != "" {
			log.Println("BOOTSTRAP_ADMIN_PASS is set but an administrator already exists; ignoring it. " +
				"Use the admin UI to change a password.")
		}
	case cfg.BootstrapPass != "":
		if err := ensureBootstrapAdmin(dbStore, cfg.BootstrapUser, cfg.BootstrapPass); err != nil {
			log.Fatalf("Bootstrap failed: %v", err)
		}
		log.Printf("Bootstrap administrator %q created from BOOTSTRAP_ADMIN_PASS.", cfg.BootstrapUser)
	default:
		firstRunPass, err := crypto.GenerateRandomAlphanumeric(16)
		if err != nil {
			log.Fatalf("Failed to generate first-run admin password: %v", err)
		}
		if err := ensureBootstrapAdmin(dbStore, cfg.BootstrapUser, firstRunPass); err != nil {
			log.Fatalf("Bootstrap failed: %v", err)
		}
		passFile := filepath.Join(cfg.DataDir, "first-run-password.txt")
		if err := os.WriteFile(passFile, []byte(fmt.Sprintf("User: %s\nPassword: %s\n", cfg.BootstrapUser, firstRunPass)), 0600); err != nil {
			log.Fatalf("Created the bootstrap admin but could not write %s: %v", passFile, err)
		}
		log.Printf("Bootstrap admin created. Credentials written to %s (removed automatically after first sign-in).", passFile)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start background account sync dispatcher worker
	go syncEngine.StartWorker(ctx)

	// Background housekeeping. Every table below is written by unauthenticated or
	// per-request paths, so none of them may grow without bound.
	go func() {
		housekeep := func() {
			_ = dbStore.CleanupExpiredSessions()
			_ = dbStore.DeleteExpiredMFATokens()
			_ = dbStore.DeleteExpiredAuthorizationCodes()
			_ = dbStore.DeleteExpiredIssuedTokens()
			_ = dbStore.DeleteExpiredDevicePairingTokens()
			_ = dbStore.DeleteExpiredMFAChallenges()
			_ = dbStore.DeleteDeliveredSyncEvents(time.Now().UTC().Add(-7 * 24 * time.Hour))
			_ = dbStore.DeleteAuditEventsOlderThan(time.Now().UTC().Add(-auditRetention))
			if err := clearFirstRunPasswordFile(dbStore, cfg.DataDir); err != nil {
				log.Printf("Housekeeping: %v", err)
			}
		}
		housekeep()

		ticker := time.NewTicker(15 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				housekeep()
			}
		}
	}()

	staticFS, _ := web.FS()

	server := api.NewServer(
		cfg,
		dbStore,
		keyManager,
		syncEngine,
		mfaEngine,
		oauthEngine,
		auditLogger,
		staticFS,
	)

	go func() {
		log.Printf("KySignOn Server listening on :%s (Issuer: %s)", cfg.Port, cfg.IssuerURL)
		if err := server.Start(); err != nil && err.Error() != "http: Server closed" {
			log.Fatalf("Server error: %v", err)
		}
	}()

	// Graceful shutdown handling
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	<-sigChan

	log.Println("Shutting down KySignOn Server gracefully...")
	cancel()

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()

	if err := server.Shutdown(shutdownCtx); err != nil {
		log.Printf("Shutdown error: %v", err)
	}
	log.Println("KySignOn Server stopped.")
}

func runBootstrap(username, password, email string) {
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Config load error: %v", err)
	}

	dbStore, err := store.New(cfg.DBPath)
	if err != nil {
		log.Fatalf("Store error: %v", err)
	}
	defer dbStore.Close()

	if password == "" {
		password, err = crypto.GenerateRandomAlphanumeric(16)
		if err != nil {
			log.Fatalf("Failed to generate admin password: %v", err)
		}
		fmt.Printf("Generated admin password: %s\n", password)
	}

	if err := ensureBootstrapAdmin(dbStore, username, password); err != nil {
		log.Fatalf("Bootstrap failed: %v", err)
	}
	fmt.Printf("Admin user '%s' bootstrapped successfully.\n", username)
}

// ensureBootstrapAdmin creates the first administrator. It deliberately does NOT touch an
// existing account: BOOTSTRAP_ADMIN_PASS usually lives in an .env file that stays set, and
// re-applying it on every restart would silently revert any password rotation the admin
// performed, with nothing in the audit log to explain it.
func ensureBootstrapAdmin(dbStore *store.Store, username, password string) error {
	existing, err := dbStore.GetUserByUsername(username)
	if err != nil {
		return fmt.Errorf("failed to check for an existing %q account: %w", username, err)
	}
	if existing != nil {
		return nil
	}

	passHash, err := auth.HashPassword(password)
	if err != nil {
		return fmt.Errorf("bootstrap password rejected: %w", err)
	}

	admin := &store.User{
		ID:           uuid.New().String(),
		Username:     username,
		DisplayName:  "Administrator",
		Email:        username + "@local.kysecurity",
		PasswordHash: passHash,
		Role:         "admin",
		Status:       "active",
	}
	if err := dbStore.CreateUser(admin); err != nil {
		return fmt.Errorf("failed to create the bootstrap administrator: %w", err)
	}
	return nil
}

func adminSessionExpiry() time.Time {
	return time.Now().UTC().Add(24 * time.Hour)
}

// clearFirstRunPasswordFile removes the generated credentials file once any session has
// existed, meaning someone has logged in and no longer needs a plaintext password on disk.
func clearFirstRunPasswordFile(dbStore *store.Store, dataDir string) error {
	path := filepath.Join(dataDir, "first-run-password.txt")
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil
	}

	loggedIn, err := dbStore.HasAnySession()
	if err != nil {
		return err
	}
	if !loggedIn {
		return nil
	}

	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove %s: %w", path, err)
	}
	log.Printf("Removed %s; the first administrator has signed in.", path)
	return nil
}

// openStoreForBackup opens the live database so backups can take a consistent snapshot
// through it rather than copying the file out from under WAL.
//
// It also materializes the RSA signing key the same way the server does. The key is created
// lazily on first server start, so backing up a freshly bootstrapped install would otherwise
// fail on a missing file — and a capsule without the signing key cannot restore a working
// service, which is why its absence is fatal rather than skipped.
func openStoreForBackup(cfg *config.Config) *store.Store {
	if _, err := crypto.LoadOrCreateRSAKey(cfg.RSAKeyPath); err != nil {
		log.Fatalf("Failed to load the RSA signing key at %s: %v", cfg.RSAKeyPath, err)
	}
	dbStore, err := store.New(cfg.DBPath)
	if err != nil {
		log.Fatalf("Failed to open the database at %s: %v", cfg.DBPath, err)
	}
	return dbStore
}

func runBackupDrill() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}
	dbStore := openStoreForBackup(cfg)
	defer dbStore.Close()

	payload, err := backup.BuildLocalPayload(cfg, dbStore, appVersion)
	if err != nil {
		log.Fatalf("Failed to build local backup payload: %v", err)
	}
	files, err := backup.AsBackupFiles(payload)
	if err != nil {
		log.Fatalf("Failed to decode backup payload: %v", err)
	}

	capsule, key, err := backup.CreateCapsule("KySignOn", appVersion, files,
		payload.Dependencies, payload.VerificationRecipe, payload.Threshold, payload.TotalShares)
	if err != nil {
		log.Fatalf("Failed to create capsule: %v", err)
	}

	result, err := backup.RunRestoreDrill(context.Background(), capsule, key)
	if err != nil {
		log.Fatalf("Drill execution failed: %v", err)
	}

	fmt.Printf("\n=== KyBackup Restore Drill Summary ===\n")
	statusStr := "PASSED (OK)"
	if !result.Passed {
		statusStr = "FAILED"
	}
	fmt.Printf("Status:   %s\n", statusStr)
	fmt.Printf("Duration: %d ms\n", result.DurationMS)
	for _, check := range result.Checks {
		status := "\u2713"
		if !check.Passed {
			status = "\u2717"
		}
		fmt.Printf("  [%s] %s: %s\n", status, check.Name, check.Message)
	}
	fmt.Println("==================================================")
	if !result.Passed {
		os.Exit(1)
	}
}

// runExportRecoveryKit writes the encrypted capsule and one file per custodian into outDir.
// The shards are deliberately separate files: a single document holding a quorum reduces the
// advertised 2-of-3 custody model to 1-of-1.
func runExportRecoveryKit(outDir string) {
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}
	if outDir == "" || outDir == "-" {
		log.Fatalf("Error: -out must name a directory to write the kit into")
	}
	dbStore := openStoreForBackup(cfg)
	defer dbStore.Close()

	payload, err := backup.BuildLocalPayload(cfg, dbStore, appVersion)
	if err != nil {
		log.Fatalf("Failed to build payload: %v", err)
	}
	files, err := backup.AsBackupFiles(payload)
	if err != nil {
		log.Fatalf("Failed to decode backup payload: %v", err)
	}

	capsule, _, err := backup.CreateCapsule("KySignOn", appVersion, files,
		payload.Dependencies, payload.VerificationRecipe, payload.Threshold, payload.TotalShares)
	if err != nil {
		log.Fatalf("Failed to create capsule: %v", err)
	}
	capsuleBytes, err := backup.SerializeCapsule(capsule)
	if err != nil {
		log.Fatalf("Failed to serialize capsule: %v", err)
	}

	if err := os.MkdirAll(outDir, 0700); err != nil {
		log.Fatalf("Failed to create %s: %v", outDir, err)
	}

	capsulePath := filepath.Join(outDir, capsule.Manifest.CapsuleID+".kycap")
	if err := os.WriteFile(capsulePath, capsuleBytes, 0600); err != nil {
		log.Fatalf("Failed to write capsule: %v", err)
	}
	fmt.Printf("Encrypted capsule: %s (%d bytes)\n", capsulePath, len(capsuleBytes))

	for _, share := range capsule.Shares {
		card := backup.GenerateCustodianCardHTML(capsule.Manifest, share, "KySignOn", cfg.IssuerURL)
		cardPath := filepath.Join(outDir, fmt.Sprintf("custodian-shard-%d.html", share.Index))
		if err := os.WriteFile(cardPath, []byte(card), 0600); err != nil {
			log.Fatalf("Failed to write custodian card %d: %v", share.Index, err)
		}
		fmt.Printf("Custodian shard %d:  %s\n", share.Index, cardPath)
	}

	fmt.Printf("\nDistribute each custodian file to a different custodian, then delete it from\n"+
		"this host. Any %d of %d shards plus the capsule restores the service:\n"+
		"  kyrestore -capsule %s -shard 1:<hex> -shard 2:<hex> -out ./restored\n",
		capsule.Manifest.Threshold, capsule.Manifest.TotalShares, capsulePath)
}

func runPushBackup(recURL, apiToken string) {
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}
	dbStore := openStoreForBackup(cfg)
	defer dbStore.Close()

	if recURL == "" {
		recURL, _ = backup.LoadRecoveryURL(dbStore)
	}
	if apiToken == "" {
		// The stored credential is encrypted under the deployment key; this is the only path
		// that decrypts it, and it never prints the value.
		apiToken, err = backup.LoadRecoveryToken(dbStore, cfg.EncryptionKey)
		if err != nil {
			log.Fatalf("Failed to read the stored KyRecovery token: %v", err)
		}
	}
	if recURL == "" || apiToken == "" {
		log.Fatalf("Error: KyRecovery URL and API token are required (pass flags or pair via UI)")
	}

	payload, err := backup.BuildLocalPayload(cfg, dbStore, appVersion)
	if err != nil {
		log.Fatalf("Failed to build payload: %v", err)
	}

	client := backup.NewKyRecoveryClient()
	resp, err := client.PushBackup(context.Background(), recURL, apiToken, *payload)
	if err != nil {
		log.Fatalf("Failed to push backup to %s: %v", recURL, err)
	}

	fmt.Printf("Backup push successful! Capsule ID: %s (%d bytes)\n", resp.CapsuleID, resp.SizeBytes)
}
