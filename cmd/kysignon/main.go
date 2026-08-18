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
	"github.com/Yoshiofthewire/kysignon-server/internal/config"
	"github.com/Yoshiofthewire/kysignon-server/internal/crypto"
	"github.com/Yoshiofthewire/kysignon-server/internal/mfa"
	"github.com/Yoshiofthewire/kysignon-server/internal/oauth"
	"github.com/Yoshiofthewire/kysignon-server/internal/store"
	"github.com/Yoshiofthewire/kysignon-server/internal/sync"
	"github.com/Yoshiofthewire/kysignon-server/web"
	"github.com/google/uuid"
)

// auditRetention bounds how long audit events are kept. On SQLite this is the table that
// grows fastest and never stops.
const auditRetention = 180 * 24 * time.Hour

func main() {
	bootstrapCmd := flag.NewFlagSet("bootstrap-admin", flag.ExitOnError)
	bootstrapUser := bootstrapCmd.String("username", "admin", "Admin username")
	bootstrapPass := bootstrapCmd.String("password", "", "Admin password (min 12 chars)")
	bootstrapEmail := bootstrapCmd.String("email", "admin@local.kysecurity", "Admin email")

	if len(os.Args) > 1 && os.Args[1] == "bootstrap-admin" {
		_ = bootstrapCmd.Parse(os.Args[2:])
		runBootstrap(*bootstrapUser, *bootstrapPass, *bootstrapEmail)
		return
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
	sync.AllowPrivateCallbacks = cfg.AllowPrivateCallbacks
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
