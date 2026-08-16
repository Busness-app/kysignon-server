package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/Yoshiofthewire/kysignon-server/internal/auth"
	"github.com/Yoshiofthewire/kysignon-server/internal/config"
	"github.com/Yoshiofthewire/kysignon-server/internal/crypto"
	"github.com/Yoshiofthewire/kysignon-server/internal/store"
	"github.com/google/uuid"
)

var testCSRFKey = []byte("0123456789abcdef0123456789abcdef")

func newUser(t *testing.T, db *store.Store, role string) *store.User {
	t.Helper()
	hash, err := auth.HashPassword("correct-horse-battery")
	if err != nil {
		t.Fatal(err)
	}
	u := &store.User{
		ID: uuid.New().String(), Username: "u" + uuid.New().String()[:8],
		DisplayName: "U", Email: uuid.New().String()[:8] + "@x.test",
		PasswordHash: hash, Role: role, Status: "active",
	}
	if err := db.CreateUser(u); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	return u
}

func newSession(t *testing.T, db *store.Store, u *store.User, expires time.Time) string {
	t.Helper()
	raw, err := crypto.GenerateRandomHex(32)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.CreateSession(&store.Session{
		ID: uuid.New().String(), UserID: u.ID, SessionTokenHash: crypto.HashSHA256(raw),
		IPAddress: "1.2.3.4", UserAgent: "test", ExpiresAt: expires,
	}); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	return raw
}

func newClient(t *testing.T, db *store.Store, id string, uris, scopes []string) {
	t.Helper()
	u, _ := json.Marshal(uris)
	s, _ := json.Marshal(scopes)
	if err := db.CreateOAuthClient(&store.OAuthClient{
		ID: id, ClientName: id, ClientType: "public",
		RedirectURIsJSON: string(u), AllowedScopesJSON: string(s), Enabled: true,
	}); err != nil {
		t.Fatalf("CreateOAuthClient: %v", err)
	}
}

// An expired session must not authorise anything, including SSO. Relying on a background
// cleanup goroutine to enforce expiry means expiry is not enforced.
func TestExpiredSessionCannotMintAuthorizationCode(t *testing.T) {
	srv, db, _, _, _, cleanup := setupTestServer(t)
	defer cleanup()

	u := newUser(t, db, "user")
	cookie := newSession(t, db, u, time.Now().UTC().Add(-30*24*time.Hour))
	newClient(t, db, "kypost", []string{"https://mail.urlxl.com/callback"}, []string{"openid"})

	req := httptest.NewRequest("GET",
		"/oauth/authorize?client_id=kypost&redirect_uri=https%3A%2F%2Fmail.urlxl.com%2Fcallback"+
			"&response_type=code&scope=openid&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256", nil)
	req.AddCookie(&http.Cookie{Name: "kysignon_session", Value: cookie})
	rr := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rr, req)

	if loc := rr.Header().Get("Location"); strings.Contains(loc, "code=") {
		t.Errorf("expired session minted an authorization code: %s", loc)
	}
}

func TestLiveSessionStillMintsAuthorizationCode(t *testing.T) {
	srv, db, _, _, _, cleanup := setupTestServer(t)
	defer cleanup()

	u := newUser(t, db, "user")
	cookie := newSession(t, db, u, time.Now().UTC().Add(24*time.Hour))
	newClient(t, db, "kypost", []string{"https://mail.urlxl.com/callback"}, []string{"openid"})

	req := httptest.NewRequest("GET",
		"/oauth/authorize?client_id=kypost&redirect_uri=https%3A%2F%2Fmail.urlxl.com%2Fcallback"+
			"&response_type=code&scope=openid&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256", nil)
	req.AddCookie(&http.Cookie{Name: "kysignon_session", Value: cookie})
	rr := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rr, req)

	if loc := rr.Header().Get("Location"); !strings.Contains(loc, "code=") {
		t.Errorf("a live session failed to get an authorization code: %d %s", rr.Code, loc)
	}
}

// The limiter keys on client IP. If a peer can name its own IP, the limiter is decorative.
func TestForwardedHeadersIgnoredFromUntrustedPeers(t *testing.T) {
	mm := NewMiddlewareManager(nil, nil, testCSRFKey) // no trusted proxies, the shipped default

	req := httptest.NewRequest("POST", "/api/auth/login", nil)
	req.RemoteAddr = "10.89.0.9:5555"
	req.Header.Set("CF-Connecting-IP", "203.0.113.7")
	req.Header.Set("X-Forwarded-For", "203.0.113.8")

	if got := mm.ClientIP(req); got != "10.89.0.9" {
		t.Errorf("ClientIP = %q, want the real peer 10.89.0.9; forwarding headers were believed", got)
	}
}

func TestForwardedHeadersHonouredFromTrustedProxy(t *testing.T) {
	mm := NewMiddlewareManager(nil, []string{"10.89.0.1/32"}, testCSRFKey)

	req := httptest.NewRequest("POST", "/api/auth/login", nil)
	req.RemoteAddr = "10.89.0.1:5555"
	req.Header.Set("X-Forwarded-For", "203.0.113.8")

	if got := mm.ClientIP(req); got != "203.0.113.8" {
		t.Errorf("ClientIP = %q, want 203.0.113.8 from the configured proxy", got)
	}
}

func TestRateLimiterCannotBeBypassedByHeaderRotation(t *testing.T) {
	mm := NewMiddlewareManager(nil, nil, testCSRFKey)
	passed := 0
	h := mm.RateLimit("login", 3, 0)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { passed++ }))

	for i := 0; i < 50; i++ {
		req := httptest.NewRequest("POST", "/api/auth/login", nil)
		req.RemoteAddr = "10.89.0.9:5555"
		req.Header.Set("CF-Connecting-IP", uuid.New().String())
		h.ServeHTTP(httptest.NewRecorder(), req)
	}
	if passed > 3 {
		t.Errorf("%d/50 requests passed a 3-token limiter by rotating a forwarded header", passed)
	}
}

// An unbounded limiter map is a memory-exhaustion primitive against the whole suite:
// each distinct client IP allocates a bucket that is never reclaimed.
func TestRateLimiterEvictsIdleEntries(t *testing.T) {
	mm := NewMiddlewareManager(nil, []string{"10.0.0.0/8"}, testCSRFKey)
	clock := time.Now()
	mm.now = func() time.Time { return clock }

	h := mm.RateLimit("login", 5, 1)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	hit := func() {
		req := httptest.NewRequest("POST", "/api/auth/login", nil)
		req.RemoteAddr = "10.0.0.1:5555"
		req.Header.Set("CF-Connecting-IP", uuid.New().String())
		h.ServeHTTP(httptest.NewRecorder(), req)
	}

	for i := 0; i < 500; i++ {
		hit()
	}
	if got := mm.TrackedLimiters(); got < 500 {
		t.Fatalf("expected 500 live buckets, got %d", got)
	}

	// Long after every bucket has refilled, they carry no state worth keeping.
	clock = clock.Add(30 * time.Minute)
	hit()

	if got := mm.TrackedLimiters(); got > 10 {
		t.Errorf("limiter map still holds %d entries 30 minutes after last use; it must be reclaimed", got)
	}
}

func TestRateLimiterIsHardCapped(t *testing.T) {
	mm := NewMiddlewareManager(nil, []string{"10.0.0.0/8"}, testCSRFKey)
	mm.maxLimiters = 50
	h := mm.RateLimit("login", 5, 0)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))

	for i := 0; i < 500; i++ {
		req := httptest.NewRequest("POST", "/api/auth/login", nil)
		req.RemoteAddr = "10.0.0.1:5555"
		req.Header.Set("CF-Connecting-IP", uuid.New().String())
		h.ServeHTTP(httptest.NewRecorder(), req)
	}
	if got := mm.TrackedLimiters(); got > 50 {
		t.Errorf("limiter map grew to %d entries past its %d cap", got, 50)
	}
}

func TestServerHasTimeouts(t *testing.T) {
	srv, _, _, _, _, cleanup := setupTestServer(t)
	defer cleanup()

	if srv.httpServer.ReadHeaderTimeout == 0 {
		t.Error("ReadHeaderTimeout is unset; the server is open to slowloris")
	}
	if srv.httpServer.ReadTimeout == 0 {
		t.Error("ReadTimeout is unset")
	}
	if srv.httpServer.WriteTimeout == 0 {
		t.Error("WriteTimeout is unset")
	}
	if srv.httpServer.IdleTimeout == 0 {
		t.Error("IdleTimeout is unset")
	}
}

// An unbounded body on an unauthenticated endpoint is a memory exhaustion primitive.
func TestOversizedRequestBodyIsRejected(t *testing.T) {
	srv, _, _, _, _, cleanup := setupTestServer(t)
	defer cleanup()

	huge := `{"username":"a","password":"` + strings.Repeat("x", 4<<20) + `"}`
	req := httptest.NewRequest("POST", "/api/auth/login", strings.NewReader(huge))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code == http.StatusOK {
		t.Error("a 4 MB login body was accepted")
	}
}

// Argon2 runs at 64 MB per verification. An unbounded password is a memory amplifier.
func TestAbsurdlyLongPasswordIsRejectedBeforeHashing(t *testing.T) {
	if _, err := auth.HashPassword(strings.Repeat("x", 100000)); err == nil {
		t.Error("HashPassword accepted a 100k-character password")
	}
}

// GET is exempt from CSRF validation by design, so no GET route may change state.
func TestAdminApplicationsGetIsARead(t *testing.T) {
	srv, db, _, _, _, cleanup := setupTestServer(t)
	defer cleanup()

	admin := newUser(t, db, "admin")
	cookie := newSession(t, db, admin, time.Now().UTC().Add(time.Hour))

	before, err := db.ListApplications()
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest("GET", "/api/admin/applications", nil)
	req.AddCookie(&http.Cookie{Name: "kysignon_session", Value: cookie})
	rr := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("GET /api/admin/applications returned %d; it should list applications", rr.Code)
	}
	after, err := db.ListApplications()
	if err != nil {
		t.Fatal(err)
	}
	if len(after) != len(before) {
		t.Errorf("a GET changed application count from %d to %d", len(before), len(after))
	}
}

// postLogin issues a login request that actually reaches the credential check: the CSRF
// middleware rejects a bare POST long before any password is verified.
func postLogin(t *testing.T, srv *Server, username, password, ip string) (int, time.Duration) {
	t.Helper()
	// Pre-login there is no session to bind to, which is exactly the case the server
	// issues an unbound token for.
	csrf := srv.middleware.IssueCSRFToken("")
	body := `{"username":"` + username + `","password":"` + password + `"}`
	req := httptest.NewRequest("POST", "/api/auth/login", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", csrf)
	req.AddCookie(&http.Cookie{Name: "kysignon_csrf", Value: csrf})
	req.RemoteAddr = ip + ":1"
	rr := httptest.NewRecorder()
	start := time.Now()
	srv.httpServer.Handler.ServeHTTP(rr, req)
	return rr.Code, time.Since(start)
}

// A missing username must cost the same as a wrong password, or usernames are enumerable.
func TestLoginDoesNotRevealWhetherAUserExists(t *testing.T) {
	srv, db, _, _, _, cleanup := setupTestServer(t)
	defer cleanup()
	existing := newUser(t, db, "user")

	realCode, realDur := postLogin(t, srv, existing.Username, "definitely-wrong-password", "198.51.100.10")
	fakeCode, fakeDur := postLogin(t, srv, "no-such-user-here", "definitely-wrong-password", "198.51.100.11")

	if realCode != http.StatusUnauthorized {
		t.Fatalf("a wrong password for a real user returned %d, want 401", realCode)
	}
	if fakeCode != realCode {
		t.Errorf("status differs by user existence: real=%d fake=%d", realCode, fakeCode)
	}
	// The known-user path pays for a full Argon2id verification. If the unknown-user path
	// skips it, the gap is orders of magnitude and identifies valid usernames.
	if fakeDur*4 < realDur {
		t.Errorf("unknown user answered in %v vs %v for a real user; timing reveals valid usernames",
			fakeDur, realDur)
	}
}

// Repeated failures must lock the account regardless of which IP they arrive from.
func TestRepeatedFailuresLockTheAccountAcrossIPs(t *testing.T) {
	srv, db, _, _, _, cleanup := setupTestServer(t)
	defer cleanup()
	u := newUser(t, db, "user")

	// Each guess from a fresh address, so only a per-account counter can stop this.
	for i := 0; i < store.MaxFailedLogins+2; i++ {
		postLogin(t, srv, u.Username, "wrong-password-guess", fmt.Sprintf("198.51.100.%d", 20+i))
	}

	code, _ := postLogin(t, srv, u.Username, "correct-horse-battery", "203.0.113.99")
	if code == http.StatusOK {
		t.Error("the correct password still succeeded after the account exceeded its failure budget")
	}
}

// Session cookies must carry Secure whenever the operator has said so, even if the proxy
// does not forward X-Forwarded-Proto.
func TestSessionCookieIsSecureWhenConfigured(t *testing.T) {
	srv, db, _, _, _, cleanup := setupTestServerWith(t, func(c *config.Config) { c.SecureCookies = true })
	defer cleanup()
	u := newUser(t, db, "user")

	csrf := srv.middleware.IssueCSRFToken("")
	body := `{"username":"` + u.Username + `","password":"correct-horse-battery"}`
	req := httptest.NewRequest("POST", "/api/auth/login", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", csrf)
	req.AddCookie(&http.Cookie{Name: "kysignon_csrf", Value: csrf})
	rr := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("login returned %d: %s", rr.Code, rr.Body.String())
	}
	found := false
	for _, c := range rr.Result().Cookies() {
		if c.Name == "kysignon_session" {
			found = true
			if !c.Secure {
				t.Error("session cookie was issued without the Secure flag despite KYSIGNON_SECURE_COOKIES")
			}
		}
	}
	if !found {
		t.Fatal("no session cookie was issued")
	}
}

// X-Forwarded-Proto from an untrusted peer must not decide cookie flags.
func TestUntrustedForwardedProtoDoesNotSetSecure(t *testing.T) {
	mm := NewMiddlewareManager(nil, nil, testCSRFKey)
	req := httptest.NewRequest("POST", "/api/auth/login", nil)
	req.RemoteAddr = "203.0.113.5:1"
	req.Header.Set("X-Forwarded-Proto", "https")

	if mm.IsHTTPS(req) {
		t.Error("X-Forwarded-Proto from an untrusted peer was believed")
	}
}

func TestRevokedTokenIsRejectedAtUserinfo(t *testing.T) {
	srv, db, _, _, oe, cleanup := setupTestServer(t)
	defer cleanup()

	u := newUser(t, db, "user")
	newClient(t, db, "kynotes", []string{"https://notes.urlxl.com/callback"}, []string{"openid"})

	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	challenge := "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
	code, err := oe.CreateAuthorizationCode("kynotes", u.ID, "https://notes.urlxl.com/callback", "openid", challenge, "S256")
	if err != nil {
		t.Fatal(err)
	}
	resp, err := oe.ExchangeAuthorizationCode(code, "kynotes", "", "https://notes.urlxl.com/callback", verifier)
	if err != nil {
		t.Fatal(err)
	}

	userinfo := func() int {
		req := httptest.NewRequest("GET", "/oauth/userinfo", nil)
		req.Header.Set("Authorization", "Bearer "+resp.AccessToken)
		rr := httptest.NewRecorder()
		srv.httpServer.Handler.ServeHTTP(rr, req)
		return rr.Code
	}

	if got := userinfo(); got != http.StatusOK {
		t.Fatalf("fresh access token rejected: %d", got)
	}

	form := url.Values{"token": {resp.AccessToken}, "client_id": {"kynotes"}}
	req := httptest.NewRequest("POST", "/oauth/revoke", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("revocation returned %d", rr.Code)
	}

	if got := userinfo(); got == http.StatusOK {
		t.Error("a revoked access token still worked at userinfo")
	}
}

// Disabling a user must cut off tokens already in the wild, not just new logins.
func TestDisablingUserRevokesOutstandingTokens(t *testing.T) {
	srv, db, _, _, oe, cleanup := setupTestServer(t)
	defer cleanup()

	admin := newUser(t, db, "admin")
	adminCookie := newSession(t, db, admin, time.Now().UTC().Add(time.Hour))
	victim := newUser(t, db, "user")
	newClient(t, db, "kynotes", []string{"https://notes.urlxl.com/callback"}, []string{"openid"})

	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	challenge := "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
	code, _ := oe.CreateAuthorizationCode("kynotes", victim.ID, "https://notes.urlxl.com/callback", "openid", challenge, "S256")
	resp, err := oe.ExchangeAuthorizationCode(code, "kynotes", "", "https://notes.urlxl.com/callback", verifier)
	if err != nil {
		t.Fatal(err)
	}

	csrf := srv.middleware.IssueCSRFToken(adminCookie)
	body := `{"status":"disabled"}`
	req := httptest.NewRequest("PUT", "/api/admin/users/"+victim.ID, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", csrf)
	req.AddCookie(&http.Cookie{Name: "kysignon_session", Value: adminCookie})
	req.AddCookie(&http.Cookie{Name: "kysignon_csrf", Value: csrf})
	rr := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("disabling the user returned %d: %s", rr.Code, rr.Body.String())
	}

	req = httptest.NewRequest("GET", "/oauth/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+resp.AccessToken)
	rr = httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rr, req)
	if rr.Code == http.StatusOK {
		t.Error("a disabled user's outstanding access token still worked")
	}
}

// A matching cookie/header pair proves only that the caller set both, which any party able
// to write a cookie for this domain can do. A token that was never issued to this session
// must not pass.
func TestForgedCSRFTokenIsRejected(t *testing.T) {
	srv, db, _, _, _, cleanup := setupTestServer(t)
	defer cleanup()

	admin := newUser(t, db, "admin")
	cookie := newSession(t, db, admin, time.Now().UTC().Add(time.Hour))

	forged, err := crypto.GenerateRandomHex(32)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("POST", "/api/admin/users", strings.NewReader(`{"username":"x"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", forged)
	req.AddCookie(&http.Cookie{Name: "kysignon_session", Value: cookie})
	req.AddCookie(&http.Cookie{Name: "kysignon_csrf", Value: forged})
	rr := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("a self-chosen CSRF token was accepted (status %d); double-submit alone is not a check", rr.Code)
	}
}

func TestIssuedCSRFTokenIsAccepted(t *testing.T) {
	srv, db, _, _, _, cleanup := setupTestServer(t)
	defer cleanup()

	admin := newUser(t, db, "admin")
	cookie := newSession(t, db, admin, time.Now().UTC().Add(time.Hour))
	csrf := srv.middleware.IssueCSRFToken(cookie)

	req := httptest.NewRequest("POST", "/api/admin/users/"+admin.ID+"/revoke-sessions", nil)
	req.Header.Set("X-CSRF-Token", csrf)
	req.AddCookie(&http.Cookie{Name: "kysignon_session", Value: cookie})
	req.AddCookie(&http.Cookie{Name: "kysignon_csrf", Value: csrf})
	rr := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code == http.StatusForbidden {
		t.Errorf("a correctly issued CSRF token was rejected: %s", rr.Body.String())
	}
}

// adminRequest performs an authenticated admin call with a correctly issued CSRF token.
func adminRequest(t *testing.T, srv *Server, method, path, cookie, body string) *httptest.ResponseRecorder {
	t.Helper()
	csrf := srv.middleware.IssueCSRFToken(cookie)
	var reader *strings.Reader
	if body == "" {
		reader = strings.NewReader("")
	} else {
		reader = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, path, reader)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", csrf)
	req.AddCookie(&http.Cookie{Name: "kysignon_session", Value: cookie})
	req.AddCookie(&http.Cookie{Name: "kysignon_csrf", Value: csrf})
	rr := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rr, req)
	return rr
}

// A server-side integration can hold a secret, so registration must give it one. Defaulting
// to a public client silently drops a whole authentication factor for every suite app.
func TestNewClientIsConfidentialByDefault(t *testing.T) {
	srv, db, _, _, _, cleanup := setupTestServer(t)
	defer cleanup()
	admin := newUser(t, db, "admin")
	cookie := newSession(t, db, admin, time.Now().UTC().Add(time.Hour))

	rr := adminRequest(t, srv, "POST", "/api/admin/clients", cookie,
		`{"clientId":"kypost","clientName":"KyPost","redirectUris":["https://mail.urlxl.com/callback"]}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("client creation returned %d: %s", rr.Code, rr.Body.String())
	}

	var resp struct {
		ClientSecret string `json:"clientSecret"`
		Client       struct {
			ClientType string `json:"clientType"`
		} `json:"client"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Client.ClientType != "confidential" {
		t.Errorf("clientType = %q, want confidential when unspecified", resp.Client.ClientType)
	}
	if resp.ClientSecret == "" {
		t.Error("no client secret was issued; the client cannot authenticate at the token endpoint")
	}

	stored, err := db.GetOAuthClientByID("kypost")
	if err != nil || stored == nil {
		t.Fatal(err)
	}
	if stored.ClientSecretHash == "" {
		t.Error("no secret hash was stored")
	}
}

// A genuinely public client (SPA, mobile) must still be registrable, explicitly.
func TestPublicClientStillRegistrableWhenAsked(t *testing.T) {
	srv, db, _, _, _, cleanup := setupTestServer(t)
	defer cleanup()
	admin := newUser(t, db, "admin")
	cookie := newSession(t, db, admin, time.Now().UTC().Add(time.Hour))

	rr := adminRequest(t, srv, "POST", "/api/admin/clients", cookie,
		`{"clientId":"mobile","clientName":"Mobile","clientType":"public","redirectUris":["https://m.urlxl.com/callback"]}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("public client creation returned %d: %s", rr.Code, rr.Body.String())
	}
	stored, _ := db.GetOAuthClientByID("mobile")
	if stored == nil || stored.ClientType != "public" {
		t.Errorf("explicit public client was not honoured: %+v", stored)
	}
}

// An existing client with no secret must be upgradeable in place. Without this the only
// route is delete-and-recreate, which breaks the integration it is meant to secure.
func TestClientSecretCanBeRotated(t *testing.T) {
	srv, db, _, _, oe, cleanup := setupTestServer(t)
	defer cleanup()
	admin := newUser(t, db, "admin")
	cookie := newSession(t, db, admin, time.Now().UTC().Add(time.Hour))
	user := newUser(t, db, "user")

	create := adminRequest(t, srv, "POST", "/api/admin/clients", cookie,
		`{"clientId":"kydns","clientName":"KyDNS","redirectUris":["https://dns.urlxl.com/callback"]}`)
	if create.Code != http.StatusOK {
		t.Fatalf("create returned %d: %s", create.Code, create.Body.String())
	}
	var created struct {
		ClientSecret string `json:"clientSecret"`
	}
	_ = json.Unmarshal(create.Body.Bytes(), &created)

	rotate := adminRequest(t, srv, "PUT", "/api/admin/clients/kydns", cookie, `{"rotateSecret":true}`)
	if rotate.Code != http.StatusOK {
		t.Fatalf("rotation returned %d: %s", rotate.Code, rotate.Body.String())
	}
	var rotated struct {
		ClientSecret string `json:"clientSecret"`
	}
	_ = json.Unmarshal(rotate.Body.Bytes(), &rotated)
	if rotated.ClientSecret == "" {
		t.Fatal("rotation returned no new secret")
	}
	if rotated.ClientSecret == created.ClientSecret {
		t.Error("rotation returned the same secret")
	}

	// The old secret must stop working, and the new one must work.
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	challenge := "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"

	code, err := oe.CreateAuthorizationCode("kydns", user.ID, "https://dns.urlxl.com/callback", "openid", challenge, "S256")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := oe.ExchangeAuthorizationCode(code, "kydns", created.ClientSecret, "https://dns.urlxl.com/callback", verifier); err == nil {
		t.Error("the superseded client secret still authenticated")
	}

	code, err = oe.CreateAuthorizationCode("kydns", user.ID, "https://dns.urlxl.com/callback", "openid", challenge, "S256")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := oe.ExchangeAuthorizationCode(code, "kydns", rotated.ClientSecret, "https://dns.urlxl.com/callback", verifier); err != nil {
		t.Errorf("the rotated client secret did not authenticate: %v", err)
	}
}

// A client registered as public can be corrected to confidential without deleting it,
// which is what makes the mistake recoverable rather than permanent.
func TestPublicClientCanBePromotedToConfidential(t *testing.T) {
	srv, db, _, _, _, cleanup := setupTestServer(t)
	defer cleanup()
	admin := newUser(t, db, "admin")
	cookie := newSession(t, db, admin, time.Now().UTC().Add(time.Hour))

	newClient(t, db, "kypasswords", []string{"https://passwords.urlxl.com/callback"}, []string{"openid"})

	rr := adminRequest(t, srv, "PUT", "/api/admin/clients/kypasswords", cookie,
		`{"clientType":"confidential"}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("promotion returned %d: %s", rr.Code, rr.Body.String())
	}
	var resp struct {
		ClientSecret string `json:"clientSecret"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp.ClientSecret == "" {
		t.Error("promoting to confidential issued no secret, leaving the client unable to authenticate")
	}

	stored, _ := db.GetOAuthClientByID("kypasswords")
	if stored == nil || stored.ClientType != "confidential" || stored.ClientSecretHash == "" {
		t.Errorf("client was not promoted: %+v", stored)
	}
}

// Redirect URIs are the control that decides who receives a code, so editing them must be
// possible without deleting the client, and must never widen silently.
func TestClientRedirectURIsCanBeUpdated(t *testing.T) {
	srv, db, _, _, _, cleanup := setupTestServer(t)
	defer cleanup()
	admin := newUser(t, db, "admin")
	cookie := newSession(t, db, admin, time.Now().UTC().Add(time.Hour))
	newClient(t, db, "kynotes", []string{"https://notes.urlxl.com/callback"}, []string{"openid"})

	rr := adminRequest(t, srv, "PUT", "/api/admin/clients/kynotes", cookie,
		`{"redirectUris":["https://notes.urlxl.com/callback","https://notes.urlxl.com/oauth/callback"]}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("update returned %d: %s", rr.Code, rr.Body.String())
	}

	stored, _ := db.GetOAuthClientByID("kynotes")
	if stored == nil || !strings.Contains(stored.RedirectURIsJSON, "/oauth/callback") {
		t.Errorf("redirect URIs were not updated: %+v", stored)
	}
}

// The suite services are all server-side backends. Registering one as a public client
// discards the client secret factor for an application that can plainly hold one, so the
// server refuses it rather than leaving it to whoever fills in the form.
func TestSuiteClientCannotBeRegisteredPublic(t *testing.T) {
	srv, db, _, _, _, cleanup := setupTestServer(t)
	defer cleanup()
	admin := newUser(t, db, "admin")
	cookie := newSession(t, db, admin, time.Now().UTC().Add(time.Hour))

	for _, id := range []string{"kypost", "kydns", "kypasswords", "kynotes", "kybookmarks", "KyPost"} {
		body := `{"clientId":"` + id + `","clientName":"x","clientType":"public",` +
			`"redirectUris":["https://x.urlxl.com/callback"]}`
		rr := adminRequest(t, srv, "POST", "/api/admin/clients", cookie, body)
		if rr.Code == http.StatusOK {
			t.Errorf("suite client %q was registered as public", id)
		}
		if stored, _ := db.GetOAuthClientByID(id); stored != nil {
			t.Errorf("suite client %q was persisted despite the rejection", id)
		}
	}
}

func TestSuiteClientRegistersAsConfidential(t *testing.T) {
	srv, db, _, _, _, cleanup := setupTestServer(t)
	defer cleanup()
	admin := newUser(t, db, "admin")
	cookie := newSession(t, db, admin, time.Now().UTC().Add(time.Hour))

	rr := adminRequest(t, srv, "POST", "/api/admin/clients", cookie,
		`{"clientId":"kypost","clientName":"KyPost","redirectUris":["https://mail.urlxl.com/callback"]}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("suite client registration returned %d: %s", rr.Code, rr.Body.String())
	}
	stored, _ := db.GetOAuthClientByID("kypost")
	if stored == nil || stored.ClientType != "confidential" || stored.ClientSecretHash == "" {
		t.Errorf("suite client did not get a secret: %+v", stored)
	}
}

// Nor may one be demoted later; the rule has to hold on the edit path too, or it is only
// a speed bump on the create form.
func TestSuiteClientCannotBeDemotedToPublic(t *testing.T) {
	srv, db, _, _, _, cleanup := setupTestServer(t)
	defer cleanup()
	admin := newUser(t, db, "admin")
	cookie := newSession(t, db, admin, time.Now().UTC().Add(time.Hour))

	create := adminRequest(t, srv, "POST", "/api/admin/clients", cookie,
		`{"clientId":"kydns","clientName":"KyDNS","redirectUris":["https://dns.urlxl.com/callback"]}`)
	if create.Code != http.StatusOK {
		t.Fatalf("setup failed: %s", create.Body.String())
	}

	rr := adminRequest(t, srv, "PUT", "/api/admin/clients/kydns", cookie, `{"clientType":"public"}`)
	if rr.Code == http.StatusOK {
		t.Error("a suite client was demoted to public")
	}
	stored, _ := db.GetOAuthClientByID("kydns")
	if stored == nil || stored.ClientType != "confidential" {
		t.Errorf("suite client type is now %v", stored)
	}
}

// A genuinely public client — an SPA or a native app — is still registrable. The rule is
// about the suite backends, not a ban on the public client type.
func TestNonSuiteClientMayStillBePublic(t *testing.T) {
	srv, db, _, _, _, cleanup := setupTestServer(t)
	defer cleanup()
	admin := newUser(t, db, "admin")
	cookie := newSession(t, db, admin, time.Now().UTC().Add(time.Hour))

	rr := adminRequest(t, srv, "POST", "/api/admin/clients", cookie,
		`{"clientId":"some-spa","clientName":"SPA","clientType":"public",`+
			`"redirectUris":["https://spa.example.com/callback"]}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("a non-suite public client was rejected: %s", rr.Body.String())
	}
	stored, _ := db.GetOAuthClientByID("some-spa")
	if stored == nil || stored.ClientType != "public" {
		t.Errorf("expected a public client, got %+v", stored)
	}
}
