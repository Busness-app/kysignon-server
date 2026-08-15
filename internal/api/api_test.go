package api

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/Yoshiofthewire/kysignon-server/internal/audit"
	"github.com/Yoshiofthewire/kysignon-server/internal/auth"
	"github.com/Yoshiofthewire/kysignon-server/internal/config"
	"github.com/Yoshiofthewire/kysignon-server/internal/crypto"
	"github.com/Yoshiofthewire/kysignon-server/internal/mfa"
	"github.com/Yoshiofthewire/kysignon-server/internal/oauth"
	"github.com/Yoshiofthewire/kysignon-server/internal/store"
	"github.com/Yoshiofthewire/kysignon-server/internal/sync"
)

func setupTestServer(t *testing.T) (*Server, *store.Store, *sync.Engine, *mfa.Engine, *oauth.Engine, func()) {
	tmpDir, err := os.MkdirTemp("", "kysignon-api-test-*")
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

	encKey, _ := crypto.GenerateRandomBytes(32)
	cfg := &config.Config{
		Port:          "5867",
		IssuerURL:     "http://localhost:5867",
		DBPath:        dbPath,
		DataDir:       tmpDir,
		EncryptionKey: encKey,
		SecretKey:     encKey,
	}

	auditLogger := audit.NewLogger(dbStore)
	syncEngine := sync.NewEngine(dbStore)
	mfaEngine := mfa.NewEngine(dbStore, encKey)
	oauthEngine := oauth.NewEngine(dbStore, km, cfg.IssuerURL)

	server := NewServer(
		cfg,
		dbStore,
		km,
		syncEngine,
		mfaEngine,
		oauthEngine,
		auditLogger,
		nil,
	)

	cleanup := func() {
		_ = dbStore.Close()
		_ = os.RemoveAll(tmpDir)
	}

	return server, dbStore, syncEngine, mfaEngine, oauthEngine, cleanup
}

func TestHealthAndOIDCDiscoveryEndpoints(t *testing.T) {
	server, _, _, _, _, cleanup := setupTestServer(t)
	defer cleanup()

	// 1. Healthz
	req := httptest.NewRequest("GET", "/healthz", nil)
	rec := httptest.NewRecorder()
	server.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 from /healthz, got %d", rec.Code)
	}

	// 2. OpenID Configuration
	req = httptest.NewRequest("GET", "/.well-known/openid-configuration", nil)
	rec = httptest.NewRecorder()
	server.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 from /.well-known/openid-configuration, got %d", rec.Code)
	}

	var oidcCfg oauth.OIDCConfiguration
	if err := json.NewDecoder(rec.Body).Decode(&oidcCfg); err != nil {
		t.Fatalf("failed to decode OIDC config: %v", err)
	}
	if oidcCfg.Issuer != "http://localhost:5867" || oidcCfg.JwksURI == "" {
		t.Fatalf("unexpected OIDC config: %+v", oidcCfg)
	}
}

func TestLoginAndCSRFAuthenticationFlow(t *testing.T) {
	server, dbStore, _, _, _, cleanup := setupTestServer(t)
	defer cleanup()

	// Create test user
	passHash, _ := auth.HashPassword("valid-secret-password-123")
	user := &store.User{
		ID:           uuid.New().String(),
		Username:     "alice",
		DisplayName:  "Alice",
		Email:        "alice@example.com",
		PasswordHash: passHash,
		Role:         "user",
		Status:       "active",
	}
	_ = dbStore.CreateUser(user)

	// 1. Fetch CSRF token
	req := httptest.NewRequest("GET", "/api/auth/csrf", nil)
	rec := httptest.NewRecorder()
	server.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 from /api/auth/csrf, got %d", rec.Code)
	}

	var csrfResp struct {
		CSRFToken string `json:"csrfToken"`
	}
	_ = json.NewDecoder(rec.Body).Decode(&csrfResp)
	csrfCookie := rec.Result().Cookies()[0]

	// 2. Login with password and CSRF token
	loginBody, _ := json.Marshal(map[string]string{
		"username": "alice",
		"password": "valid-secret-password-123",
	})
	loginReq := httptest.NewRequest("POST", "/api/auth/login", bytes.NewReader(loginBody))
	loginReq.Header.Set("Content-Type", "application/json")
	loginReq.Header.Set("X-CSRF-Token", csrfResp.CSRFToken)
	loginReq.AddCookie(csrfCookie)
	loginRec := httptest.NewRecorder()

	server.httpServer.Handler.ServeHTTP(loginRec, loginReq)

	if loginRec.Code != http.StatusOK {
		t.Fatalf("expected 200 from login, got %d: %s", loginRec.Code, loginRec.Body.String())
	}

	// 3. Verify session cookie issued
	var sessionCookie *http.Cookie
	for _, c := range loginRec.Result().Cookies() {
		if c.Name == "kysignon_session" {
			sessionCookie = c
			break
		}
	}
	if sessionCookie == nil || sessionCookie.Value == "" {
		t.Fatal("missing session cookie in login response")
	}

	// 4. Access /api/auth/me with session cookie
	meReq := httptest.NewRequest("GET", "/api/auth/me", nil)
	meReq.AddCookie(sessionCookie)
	meRec := httptest.NewRecorder()

	server.httpServer.Handler.ServeHTTP(meRec, meReq)
	if meRec.Code != http.StatusOK {
		t.Fatalf("expected 200 from /api/auth/me, got %d", meRec.Code)
	}

	var meResp struct {
		Username string `json:"username"`
		Role     string `json:"role"`
	}
	_ = json.NewDecoder(meRec.Body).Decode(&meResp)
	if meResp.Username != "alice" || meResp.Role != "user" {
		t.Fatalf("unexpected /api/auth/me response: %+v", meResp)
	}
}

func TestAdminSystemPairingHandshakeViaAPI(t *testing.T) {
	server, dbStore, _, _, _, cleanup := setupTestServer(t)
	defer cleanup()

	// 1. Create Admin
	adminPassHash, _ := auth.HashPassword("admin-secure-password-123")
	admin := &store.User{
		ID:           uuid.New().String(),
		Username:     "admin",
		DisplayName:  "System Administrator",
		Email:        "admin@example.com",
		PasswordHash: adminPassHash,
		Role:         "admin",
		Status:       "active",
	}
	_ = dbStore.CreateUser(admin)

	// Create session for admin
	adminSessionToken, _ := crypto.GenerateRandomHex(32)
	_ = dbStore.CreateSession(&store.Session{
		ID:               uuid.New().String(),
		UserID:           admin.ID,
		SessionTokenHash: crypto.HashSHA256(adminSessionToken),
		IPAddress:        "127.0.0.1",
		UserAgent:        "Go-Test",
		ExpiresAt:        timeNowUTC().Add(24 * timeHour),
	})
	adminCookie := &http.Cookie{Name: "kysignon_session", Value: adminSessionToken}

	// Fetch CSRF
	csrfToken, _ := crypto.GenerateRandomHex(32)
	csrfCookie := &http.Cookie{Name: "kysignon_csrf", Value: csrfToken}

	// 2. Admin calls POST /api/admin/systems/pairing-token
	pairingReqBody, _ := json.Marshal(map[string]string{
		"systemType": "kypost",
	})
	pairReq := httptest.NewRequest("POST", "/api/admin/systems/pairing-token", bytes.NewReader(pairingReqBody))
	pairReq.Header.Set("Content-Type", "application/json")
	pairReq.Header.Set("X-CSRF-Token", csrfToken)
	pairReq.AddCookie(adminCookie)
	pairReq.AddCookie(csrfCookie)
	pairRec := httptest.NewRecorder()

	server.httpServer.Handler.ServeHTTP(pairRec, pairReq)
	if pairRec.Code != http.StatusOK {
		t.Fatalf("expected 200 from pairing-token, got %d: %s", pairRec.Code, pairRec.Body.String())
	}

	var pairResp struct {
		PairingToken string `json:"pairingToken"`
		PINCode      string `json:"pinCode"`
		SystemType   string `json:"systemType"`
	}
	_ = json.NewDecoder(pairRec.Body).Decode(&pairResp)
	if pairResp.PairingToken == "" || pairResp.PINCode == "" {
		t.Fatalf("unexpected pairing token response: %+v", pairResp)
	}

	// 3. Downstream KyPost product registers via POST /api/systems/register (Unauthenticated with token)
	regBody, _ := json.Marshal(map[string]string{
		"pairingToken": pairResp.PairingToken,
		"systemName":   "Production KyPost Cluster",
		"systemType":   "kypost",
		"callbackUrl":  "https://kypost.example.com/api/sso/sync",
	})
	regReq := httptest.NewRequest("POST", "/api/systems/register", bytes.NewReader(regBody))
	regReq.Header.Set("Content-Type", "application/json")
	regRec := httptest.NewRecorder()

	server.httpServer.Handler.ServeHTTP(regRec, regReq)
	if regRec.Code != http.StatusOK {
		t.Fatalf("expected 200 from /api/systems/register, got %d: %s", regRec.Code, regRec.Body.String())
	}

	var regResp struct {
		SystemID   string `json:"systemId"`
		HMACSecret string `json:"hmacSecret"`
		Status     string `json:"status"`
	}
	_ = json.NewDecoder(regRec.Body).Decode(&regResp)
	if regResp.SystemID == "" || regResp.HMACSecret == "" || regResp.Status != "active" {
		t.Fatalf("unexpected system registration response: %+v", regResp)
	}

	// 4. Admin lists systems via GET /api/admin/systems
	listReq := httptest.NewRequest("GET", "/api/admin/systems", nil)
	listReq.AddCookie(adminCookie)
	listRec := httptest.NewRecorder()

	server.httpServer.Handler.ServeHTTP(listRec, listReq)
	if listRec.Code != http.StatusOK {
		t.Fatalf("expected 200 from GET /api/admin/systems, got %d", listRec.Code)
	}

	var listResp struct {
		Systems []store.PairedSystem `json:"systems"`
	}
	_ = json.NewDecoder(listRec.Body).Decode(&listResp)
	if len(listResp.Systems) != 1 || listResp.Systems[0].Name != "Production KyPost Cluster" {
		t.Fatalf("unexpected systems list: %+v", listResp)
	}
}

func TestOIDCAuthorizeAndPKCETokenFlowViaHTTP(t *testing.T) {
	server, dbStore, _, _, _, cleanup := setupTestServer(t)
	defer cleanup()

	// 1. Create User
	passHash, _ := auth.HashPassword("valid-secret-password-123")
	user := &store.User{
		ID:           uuid.New().String(),
		Username:     "carol",
		DisplayName:  "Carol Danvers",
		Email:        "carol@example.com",
		PasswordHash: passHash,
		Role:         "user",
		Status:       "active",
	}
	_ = dbStore.CreateUser(user)

	sessionToken, _ := crypto.GenerateRandomHex(32)
	_ = dbStore.CreateSession(&store.Session{
		ID:               uuid.New().String(),
		UserID:           user.ID,
		SessionTokenHash: crypto.HashSHA256(sessionToken),
		IPAddress:        "127.0.0.1",
		UserAgent:        "Go-Test",
		ExpiresAt:        timeNowUTC().Add(24 * timeHour),
	})
	userCookie := &http.Cookie{Name: "kysignon_session", Value: sessionToken}

	// 2. Create OIDC Client
	client := &store.OAuthClient{
		ID:                uuid.New().String(),
		ClientName:        "KyBookmarks Client",
		ClientType:        "public",
		RedirectURIsJSON:  `["https://bookmarks.local/callback"]`,
		AllowedScopesJSON: `["openid","profile","email"]`,
		Enabled:           true,
	}
	_ = dbStore.CreateOAuthClient(client)

	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	h := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(h[:])

	// 3. GET /oauth/authorize with active session
	authParams := url.Values{
		"client_id":             {client.ID},
		"redirect_uri":          {"https://bookmarks.local/callback"},
		"response_type":         {"code"},
		"scope":                 {"openid profile email"},
		"state":                 {"random-state-12345"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}

	authReq := httptest.NewRequest("GET", "/oauth/authorize?"+authParams.Encode(), nil)
	authReq.AddCookie(userCookie)
	authRec := httptest.NewRecorder()

	server.httpServer.Handler.ServeHTTP(authRec, authReq)
	if authRec.Code != http.StatusFound {
		t.Fatalf("expected 302 redirect from /oauth/authorize, got %d: %s", authRec.Code, authRec.Body.String())
	}

	redirectLocation := authRec.Header().Get("Location")
	targetURL, err := url.Parse(redirectLocation)
	if err != nil {
		t.Fatalf("invalid redirect location: %s", redirectLocation)
	}

	code := targetURL.Query().Get("code")
	state := targetURL.Query().Get("state")
	if code == "" || state != "random-state-12345" {
		t.Fatalf("unexpected redirect query params: %s", targetURL.RawQuery)
	}

	// 4. POST /oauth/token exchanging code and PKCE verifier
	tokenForm := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"client_id":     {client.ID},
		"redirect_uri":  {"https://bookmarks.local/callback"},
		"code_verifier": {verifier},
	}

	tokenReq := httptest.NewRequest("POST", "/oauth/token", strings.NewReader(tokenForm.Encode()))
	tokenReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tokenRec := httptest.NewRecorder()

	server.httpServer.Handler.ServeHTTP(tokenRec, tokenReq)
	if tokenRec.Code != http.StatusOK {
		t.Fatalf("expected 200 from /oauth/token, got %d: %s", tokenRec.Code, tokenRec.Body.String())
	}

	var tokenResp oauth.TokenResponse
	if err := json.NewDecoder(tokenRec.Body).Decode(&tokenResp); err != nil {
		t.Fatalf("failed to decode token response: %v", err)
	}

	if tokenResp.AccessToken == "" || tokenResp.IDToken == "" {
		t.Fatalf("missing tokens: %+v", tokenResp)
	}

	// 5. GET /oauth/userinfo with Access Token
	userinfoReq := httptest.NewRequest("GET", "/oauth/userinfo", nil)
	userinfoReq.Header.Set("Authorization", "Bearer "+tokenResp.AccessToken)
	userinfoRec := httptest.NewRecorder()

	server.httpServer.Handler.ServeHTTP(userinfoRec, userinfoReq)
	if userinfoRec.Code != http.StatusOK {
		t.Fatalf("expected 200 from /oauth/userinfo, got %d", userinfoRec.Code)
	}

	var userinfo map[string]any
	_ = json.NewDecoder(userinfoRec.Body).Decode(&userinfo)
	if userinfo["preferred_username"] != "carol" || userinfo["email"] != "carol@example.com" {
		t.Fatalf("unexpected userinfo: %+v", userinfo)
	}
}

// Helpers
var (
	timeNowUTC = func() time.Time { return time.Now().UTC() }
	timeHour   = 1 * time.Hour
)
