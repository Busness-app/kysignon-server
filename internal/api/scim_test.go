package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/Busness-app/kysignon-server/internal/store"
)

func TestSCIMConnectionAdministration(t *testing.T) {
	srv, db, engine, _, _, cleanup := setupTestServer(t)
	defer cleanup()
	admin := newUser(t, db, "admin")
	cookie := newSession(t, db, admin, time.Now().UTC().Add(time.Hour))
	body := `{"name":"SCIM","systemType":"scim","callbackUrl":"https://example.com/scim/v2","bearerToken":"target-secret"}`
	if rr := adminRequestNoStepUp(t, srv, "POST", "/api/admin/systems", cookie, body); rr.Code != http.StatusForbidden {
		t.Fatalf("creation missing step-up: %d", rr.Code)
	}
	rr := adminRequest(t, srv, "POST", "/api/admin/systems", cookie, body)
	if rr.Code != 200 || strings.Contains(rr.Body.String(), "target-secret") {
		t.Fatalf("create: %d %s", rr.Code, rr.Body.String())
	}
	var response struct{ System store.PairedSystem }
	if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	id := response.System.ID
	path := "/api/admin/systems/" + id + "/connection"
	replacement := `{"systemType":"scim","bearerToken":"replacement-secret"}`
	if rr = adminRequestNoStepUp(t, srv, "PUT", path, cookie, replacement); rr.Code != http.StatusForbidden {
		t.Fatalf("rotation missing step-up: %d", rr.Code)
	}
	if rr = adminRequest(t, srv, "PUT", path, cookie, replacement); rr.Code != 200 {
		t.Fatalf("rotate: %d %s", rr.Code, rr.Body.String())
	}
	sys, err := db.GetPairedSystemByID(id)
	if err != nil {
		t.Fatal(err)
	}
	secret, err := engine.SigningSecret(sys)
	if err != nil || secret != "replacement-secret" {
		t.Fatal("replacement failed", err)
	}
	rr = adminRequest(t, srv, "GET", "/api/admin/systems", cookie, "")
	if strings.Contains(rr.Body.String(), secret) || strings.Contains(rr.Body.String(), sys.HMACSecretEncrypted) {
		t.Fatal("listing exposes credentials")
	}
	// A known protocol cannot be changed by reusing its credentials.
	rr = adminRequest(t, srv, "PUT", path, cookie, `{"systemType":"suite_webhook"}`)
	if rr.Code != 400 {
		t.Fatalf("protocol switch accepted: %d", rr.Code)
	}
	legacy := &store.PairedSystem{ID: "legacy-custom", Name: "legacy", SystemType: "custom", CallbackURL: "https://example.com/legacy", HMACSecretEncrypted: sys.HMACSecretEncrypted, Status: "active"}
	if err = db.CreatePairedSystem(legacy); err != nil {
		t.Fatal(err)
	}
	rr = adminRequest(t, srv, "PUT", "/api/admin/systems/legacy-custom/connection", cookie, `{"systemType":"suite_webhook"}`)
	if rr.Code != 200 {
		t.Fatalf("review failed: %d %s", rr.Code, rr.Body.String())
	}
	loaded, _ := db.GetPairedSystemByID(legacy.ID)
	if loaded.SystemType != "suite_webhook" || loaded.HMACSecretEncrypted != legacy.HMACSecretEncrypted {
		t.Fatal("review changed identity/secret")
	}
}
