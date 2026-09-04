package api

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

// destructiveAdminRoutes is every admin operation a stolen session must not be able to
// perform on its own. Each one either creates or resets an identity, rotates a secret, or
// exports recovery material.
var destructiveAdminRoutes = []struct{ method, path, body string }{
	{"POST", "/api/admin/users", `{"username":"newadmin","email":"n@x.test","password":"CorrectHorseBattery1","role":"admin"}`},
	{"PUT", "/api/admin/users/{victim}", `{"status":"disabled"}`},
	{"POST", "/api/admin/users/{victim}/reset-mfa", ``},
	{"DELETE", "/api/admin/users/{victim}", ``},
	{"POST", "/api/admin/clients", `{"clientId":"newapp","clientName":"New App","redirectUris":["https://app.test/cb"]}`},
	{"PUT", "/api/admin/clients/kynotes", `{"rotateSecret":true}`},
	{"DELETE", "/api/admin/clients/kynotes", ``},
	{"POST", "/api/admin/systems", `{"name":"S","systemType":"scim","callbackUrl":"https://s.test/scim/v2"}`},
	{"POST", "/api/admin/backup/recovery-kit", ``},
	{"POST", "/api/admin/backup/pair-remote", `{"recovery_url":"https://r.test","pairing_code":"123456"}`},
	{"POST", "/api/admin/backup/push", ``},
}

// A stolen admin cookie is the whole threat: it carries every privilege the real
// administrator has. Step-up costs the password plus, for accounts with TOTP enrolled, an
// existing factor the thief does not have (passkey-only accounts currently get the grant
// from the password alone; see stepup.go), so it is the boundary these operations must sit
// behind.
func TestDestructiveAdminRoutesRequireStepUp(t *testing.T) {
	srv, db, _, _, _, cleanup := setupTestServer(t)
	defer cleanup()

	admin := newUser(t, db, "admin")
	cookie := newSession(t, db, admin, time.Now().UTC().Add(time.Hour))
	victim := newUser(t, db, "user")
	newClient(t, db, "kynotes", []string{"https://notes.urlxl.com/callback"}, []string{"openid"})

	for _, route := range destructiveAdminRoutes {
		path := strings.ReplaceAll(route.path, "{victim}", victim.ID)
		t.Run(route.method+" "+route.path, func(t *testing.T) {
			rr := adminRequestNoStepUp(t, srv, route.method, path, cookie, route.body)
			if rr.Code != http.StatusForbidden {
				t.Fatalf("reached with a session alone: %d %s", rr.Code, rr.Body.String())
			}
			var body map[string]any
			_ = json.Unmarshal(rr.Body.Bytes(), &body)
			if body["error"] != "step_up_required" {
				t.Fatalf("expected step_up_required, got %v", body["error"])
			}
		})
	}
}

// The capsule and the shards are the recovery quorum. Fetching them over GET does not make
// them less secret than the POST that built them.
func TestRecoveryArtifactDownloadsRequireStepUp(t *testing.T) {
	srv, db, _, _, _, cleanup := setupTestServer(t)
	defer cleanup()

	admin := newUser(t, db, "admin")
	cookie := newSession(t, db, admin, time.Now().UTC().Add(time.Hour))

	rr := adminRequest(t, srv, "POST", "/api/admin/backup/recovery-kit", cookie, "")
	if rr.Code != http.StatusOK {
		t.Fatalf("kit creation failed: %d %s", rr.Code, rr.Body.String())
	}
	var kit struct {
		KitID string `json:"kit_id"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &kit); err != nil || kit.KitID == "" {
		t.Fatalf("no kit id: %v %s", err, rr.Body.String())
	}

	for _, path := range []string{
		"/api/admin/backup/recovery-kit/" + kit.KitID + "/capsule",
		"/api/admin/backup/recovery-kit/" + kit.KitID + "/shard/1",
	} {
		got := adminRequestNoStepUp(t, srv, "GET", path, cookie, "")
		if got.Code != http.StatusForbidden {
			t.Errorf("%s was served to a bare session: %d", path, got.Code)
		}
	}
}

// One re-authentication authorizes one change. A grant that survives its use is a second
// session token with a different name.
func TestStepUpGrantIsSingleUseAcrossAdminOperations(t *testing.T) {
	srv, db, _, _, _, cleanup := setupTestServer(t)
	defer cleanup()

	admin := newUser(t, db, "admin")
	cookie := newSession(t, db, admin, time.Now().UTC().Add(time.Hour))
	grant := mintStepUp(t, srv, cookie)

	first := adminRequestWithStepUp(t, srv, "POST", "/api/admin/clients", cookie,
		`{"clientId":"app-one","clientName":"One","redirectUris":["https://one.test/cb"]}`, grant)
	if first.Code != http.StatusOK {
		t.Fatalf("first use of the grant failed: %d %s", first.Code, first.Body.String())
	}

	second := adminRequestWithStepUp(t, srv, "POST", "/api/admin/clients", cookie,
		`{"clientId":"app-two","clientName":"Two","redirectUris":["https://two.test/cb"]}`, grant)
	if second.Code != http.StatusForbidden {
		t.Fatalf("the same grant authorized a second change: %d %s", second.Code, second.Body.String())
	}
}

// Read-only admin views and the emergency session revoke stay reachable with a session
// alone: gating the lock-down button behind a second factor is friction during an incident.
func TestNonDestructiveAdminRoutesStayReachable(t *testing.T) {
	srv, db, _, _, _, cleanup := setupTestServer(t)
	defer cleanup()

	admin := newUser(t, db, "admin")
	cookie := newSession(t, db, admin, time.Now().UTC().Add(time.Hour))

	for _, path := range []string{"/api/admin/users", "/api/admin/clients", "/api/admin/audit-events"} {
		if rr := adminRequestNoStepUp(t, srv, "GET", path, cookie, ""); rr.Code != http.StatusOK {
			t.Errorf("GET %s = %d, want 200", path, rr.Code)
		}
	}
	if rr := adminRequestNoStepUp(t, srv, "POST", "/api/admin/users/"+admin.ID+"/revoke-sessions", cookie, ""); rr.Code != http.StatusOK {
		t.Errorf("revoke-sessions = %d, want 200", rr.Code)
	}
}

// With two administrators, neither may walk away holding a reconstructable set.
func TestSecondAdminIsRequiredToCollectAQuorum(t *testing.T) {
	srv, db, _, _, _, cleanup := setupTestServer(t)
	defer cleanup()

	adminA := newUser(t, db, "admin")
	adminB := newUser(t, db, "admin")
	cookieA := newSession(t, db, adminA, time.Now().UTC().Add(time.Hour))
	cookieB := newSession(t, db, adminB, time.Now().UTC().Add(time.Hour))
	_ = adminB

	rr := adminRequest(t, srv, "POST", "/api/admin/backup/recovery-kit", cookieA, "")
	if rr.Code != http.StatusOK {
		t.Fatalf("kit creation failed: %d %s", rr.Code, rr.Body.String())
	}
	var kit struct {
		KitID           string `json:"kit_id"`
		Threshold       int    `json:"threshold"`
		MaxPerCustodian int    `json:"max_per_custodian"`
		SoleCustodian   bool   `json:"sole_custodian"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &kit); err != nil {
		t.Fatal(err)
	}
	if kit.SoleCustodian {
		t.Fatal("a two-administrator deployment reported itself as single-custodian")
	}
	if kit.MaxPerCustodian != kit.Threshold-1 {
		t.Fatalf("max_per_custodian = %d, want threshold-1 = %d", kit.MaxPerCustodian, kit.Threshold-1)
	}

	shard := func(cookie string, i int) *httptest.ResponseRecorder {
		return adminRequest(t, srv, "GET", fmt.Sprintf("/api/admin/backup/recovery-kit/%s/shard/%d", kit.KitID, i), cookie, "")
	}

	if got := shard(cookieA, 1); got.Code != http.StatusOK {
		t.Fatalf("the first shard was refused: %d %s", got.Code, got.Body.String())
	}
	if got := shard(cookieA, 2); got.Code != http.StatusForbidden {
		t.Fatalf("one administrator collected a quorum: %d %s", got.Code, got.Body.String())
	}
	if got := shard(cookieB, 2); got.Code != http.StatusOK {
		t.Fatalf("the second custodian was refused: %d %s", got.Code, got.Body.String())
	}
	// A shard belongs to the one custodian who collected it. Retrying is for its holder;
	// it is never a way for a second principal to accumulate a quorum.
	if got := shard(cookieB, 1); got.Code != http.StatusForbidden {
		t.Fatalf("a shard held by another administrator was served: %d %s", got.Code, got.Body.String())
	}
}

// A single-admin homelab still needs a recovery kit; the alternative is no backup at all.
// The relaxation is allowed, and recorded as the custody gap it is.
func TestSoleAdminMayCollectAllShardsAndItIsAudited(t *testing.T) {
	srv, db, _, _, _, cleanup := setupTestServer(t)
	defer cleanup()

	admin := newUser(t, db, "admin")
	cookie := newSession(t, db, admin, time.Now().UTC().Add(time.Hour))

	rr := adminRequest(t, srv, "POST", "/api/admin/backup/recovery-kit", cookie, "")
	var kit struct {
		KitID         string `json:"kit_id"`
		TotalShares   int    `json:"total_shares"`
		SoleCustodian bool   `json:"sole_custodian"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &kit); err != nil {
		t.Fatal(err)
	}
	if !kit.SoleCustodian {
		t.Fatal("a one-administrator deployment did not report itself as single-custodian")
	}
	for i := 1; i <= kit.TotalShares; i++ {
		got := adminRequest(t, srv, "GET", fmt.Sprintf("/api/admin/backup/recovery-kit/%s/shard/%d", kit.KitID, i), cookie, "")
		if got.Code != http.StatusOK {
			t.Fatalf("shard %d refused for the only administrator: %d %s", i, got.Code, got.Body.String())
		}
	}

	events, _, err := db.ListAuditEvents(200, 0)
	if err != nil {
		t.Fatal(err)
	}
	var warnings int
	for _, e := range events {
		if e.Action == "admin.backup_single_custodian_quorum" {
			warnings++
		}
	}
	if warnings != kit.TotalShares {
		t.Errorf("recorded %d single-custodian warnings for %d shards", warnings, kit.TotalShares)
	}
}

// Readiness must answer "can this instance authenticate someone", which /healthz never could.
func TestReadinessReflectsDatabaseHealth(t *testing.T) {
	srv, db, _, _, _, cleanup := setupTestServer(t)
	defer cleanup()

	rr := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rr, httptest.NewRequest("GET", "/readyz", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("a healthy server reported not ready: %d %s", rr.Code, rr.Body.String())
	}
	var body struct {
		Status string            `json:"status"`
		Checks map[string]string `json:"checks"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"database", "signing_key", "encryption_key", "audit"} {
		if body.Checks[name] != "ok" {
			t.Errorf("check %q = %q, want ok", name, body.Checks[name])
		}
	}

	// With the database gone, continuing to advertise readiness is how a load balancer keeps
	// feeding logins to an instance that cannot serve them.
	_ = db.Close()
	rr = httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rr, httptest.NewRequest("GET", "/readyz", nil))
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("readiness stayed green with no database: %d %s", rr.Code, rr.Body.String())
	}

	// Liveness is deliberately unaffected; the process is still running and restarting it
	// would not bring the volume back.
	rr = httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rr, httptest.NewRequest("GET", "/healthz", nil))
	if rr.Code != http.StatusOK {
		t.Errorf("liveness failed for a running process: %d", rr.Code)
	}
}

// An export whose durable record vanished is an unattributed disclosure of the recovery
// quorum. Refusing is the only outcome that keeps the trail meaning anything.
func TestSecretExportIsRefusedWhenTheAuditTrailCannotBeWritten(t *testing.T) {
	srv, db, _, _, _, cleanup := setupTestServer(t)
	defer cleanup()

	admin := newUser(t, db, "admin")
	cookie := newSession(t, db, admin, time.Now().UTC().Add(time.Hour))

	rr := adminRequest(t, srv, "POST", "/api/admin/backup/recovery-kit", cookie, "")
	if rr.Code != http.StatusOK {
		t.Fatalf("kit creation failed: %d %s", rr.Code, rr.Body.String())
	}
	var kit struct {
		KitID string `json:"kit_id"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &kit)

	// Break audit persistence the way a failing volume would: the write errors, everything
	// else still works.
	raw, err := sql.Open("sqlite", srv.cfg.DBPath)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	if _, err := raw.Exec(`DROP TABLE audit_events`); err != nil {
		t.Fatalf("could not break the audit table: %v", err)
	}

	got := adminRequest(t, srv, "GET", "/api/admin/backup/recovery-kit/"+kit.KitID+"/shard/1", cookie, "")
	if got.Code != http.StatusServiceUnavailable {
		t.Fatalf("a shard was exported with no audit record: %d %s", got.Code, got.Body.String())
	}
	if !strings.Contains(got.Body.String(), "audit_unavailable") {
		t.Errorf("the refusal did not name the cause: %s", got.Body.String())
	}

	// And readiness must say so rather than reporting a healthy identity authority.
	rr = httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rr, httptest.NewRequest("GET", "/readyz", nil))
	var body struct {
		Checks map[string]string `json:"checks"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &body)
	if body.Checks["audit"] != "degraded" {
		t.Errorf("readiness reported audit as %q while writes were failing", body.Checks["audit"])
	}
}
