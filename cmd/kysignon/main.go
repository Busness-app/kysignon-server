package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/google/uuid"
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
)

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

	auditLogger := audit.NewLogger(dbStore)
	syncEngine := sync.NewEngine(dbStore)
	mfaEngine := mfa.NewEngine(dbStore, cfg.EncryptionKey)
	oauthEngine := oauth.NewEngine(dbStore, keyManager, cfg.IssuerURL)

	// Check if initial admin bootstrap is requested via environment
	if cfg.BootstrapPass != "" {
		ensureBootstrapAdmin(dbStore, cfg.BootstrapUser, cfg.BootstrapPass)
	} else {
		// If no admin exists at all, generate a first-run password file
		adminCount, _ := dbStore.CountAdmins()
		if adminCount == 0 {
			firstRunPass := crypto.GenerateRandomAlphanumeric(16)
			passFile := cfg.DataDir + "/first-run-password.txt"
			if err := os.WriteFile(passFile, []byte(fmt.Sprintf("User: %s\nPassword: %s\n", cfg.BootstrapUser, firstRunPass)), 0600); err != nil {
				log.Printf("Warning: failed to write %s: %v", passFile, err)
			}
			ensureBootstrapAdmin(dbStore, cfg.BootstrapUser, firstRunPass)
			log.Printf("Bootstrap admin created. Credentials written to %s", passFile)
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start background account sync dispatcher worker
	go syncEngine.StartWorker(ctx)

	// Background session cleanup worker
	go func() {
		ticker := time.NewTicker(1 * time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				_ = dbStore.CleanupExpiredSessions()
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
		password = crypto.GenerateRandomAlphanumeric(16)
		fmt.Printf("Generated admin password: %s\n", password)
	}

	ensureBootstrapAdmin(dbStore, username, password)
	fmt.Printf("Admin user '%s' bootstrapped successfully.\n", username)
}

func ensureBootstrapAdmin(dbStore *store.Store, username, password string) {
	passHash, err := auth.HashPassword(password)
	if err != nil {
		log.Printf("Failed to hash bootstrap password: %v", err)
		return
	}

	existing, err := dbStore.GetUserByUsername(username)
	if err != nil {
		log.Printf("Failed to check existing user: %v", err)
		return
	}
	if existing != nil {
		_ = dbStore.UpdateUserPassword(existing.ID, passHash)
		return
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

	_ = dbStore.CreateUser(admin)
}
