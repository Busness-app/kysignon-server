package oauth

import (
	"crypto/sha256"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/uuid"
	"github.com/Yoshiofthewire/kysignon-server/internal/crypto"
	"github.com/Yoshiofthewire/kysignon-server/internal/store"
)

func setupTestOAuthEngine(t *testing.T) (*Engine, *store.Store, func()) {
	tmpDir, err := os.MkdirTemp("", "kysignon-oauth-test-*")
	if err != nil {
		t.Fatalf("MkdirTemp failed: %v", err)
	}

	dbPath := filepath.Join(tmpDir, "test.db")
	dbStore, err := store.New(dbPath)
	if err != nil {
		t.Fatalf("store.New failed: %v", err)
	}

	keyPath := filepath.Join(tmpDir, "test_jwt.key")
	km, err := crypto.LoadOrCreateRSAKey(keyPath)
	if err != nil {
		t.Fatalf("crypto.LoadOrCreateRSAKey failed: %v", err)
	}

	engine := NewEngine(dbStore, km, "http://localhost:5867")

	cleanup := func() {
		_ = dbStore.Close()
		_ = os.RemoveAll(tmpDir)
	}

	return engine, dbStore, cleanup
}

func TestPKCEValidation(t *testing.T) {
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	h := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(h[:])

	if !ValidatePKCE(verifier, challenge, "S256") {
		t.Fatal("S256 PKCE validation failed")
	}

	if ValidatePKCE("wrong_verifier_12345678901234567890", challenge, "S256") {
		t.Fatal("S256 PKCE validation should have failed for invalid verifier")
	}

	if !ValidatePKCE("plain_verifier", "plain_verifier", "plain") {
		t.Fatal("plain PKCE validation failed")
	}
}

func TestAuthorizationCodeExchangeWithPKCE(t *testing.T) {
	engine, dbStore, cleanup := setupTestOAuthEngine(t)
	defer cleanup()

	// Create user
	user := &store.User{
		ID:           uuid.New().String(),
		Username:     "alice",
		DisplayName:  "Alice",
		Email:        "alice@example.com",
		PasswordHash: "dummyhash",
		Role:         "user",
		Status:       "active",
	}
	if err := dbStore.CreateUser(user); err != nil {
		t.Fatalf("CreateUser failed: %v", err)
	}

	// Create public OAuth client (e.g. KyPost web client)
	client := &store.OAuthClient{
		ID:                uuid.New().String(),
		ClientName:        "KyPost",
		ClientType:        "public",
		RedirectURIsJSON:  `["https://kypost.local/callback"]`,
		AllowedScopesJSON: `["openid","profile","email"]`,
		Enabled:           true,
	}
	if err := dbStore.CreateOAuthClient(client); err != nil {
		t.Fatalf("CreateOAuthClient failed: %v", err)
	}

	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	h := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(h[:])

	// Create Auth Code
	code, err := engine.CreateAuthorizationCode(client.ID, user.ID, "https://kypost.local/callback", "openid profile", challenge, "S256")
	if err != nil {
		t.Fatalf("CreateAuthorizationCode failed: %v", err)
	}

	// Exchange Code for Tokens
	tokenResp, err := engine.ExchangeAuthorizationCode(code, client.ID, "", "https://kypost.local/callback", verifier)
	if err != nil {
		t.Fatalf("ExchangeAuthorizationCode failed: %v", err)
	}

	if tokenResp.AccessToken == "" || tokenResp.IDToken == "" {
		t.Fatalf("missing tokens in response: %+v", tokenResp)
	}

	// Verify ID Token
	idClaims, err := engine.keyManager.VerifyJWT(tokenResp.IDToken)
	if err != nil {
		t.Fatalf("ID token verification failed: %v", err)
	}
	if idClaims["sub"] != user.ID || idClaims["preferred_username"] != "alice" {
		t.Fatalf("unexpected id token claims: %+v", idClaims)
	}

	// Test Single-Use Replay Rejection
	_, err = engine.ExchangeAuthorizationCode(code, client.ID, "", "https://kypost.local/callback", verifier)
	if err == nil {
		t.Fatal("expected authorization code replay to be rejected")
	}
}
