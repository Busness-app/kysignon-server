package api

import (
	"strings"
	"testing"
	"time"

	"github.com/Busness-app/kysignon-server/internal/store"
)

func TestSyncDeliveryRecoveryRequiresStepUpAndConfirmation(t *testing.T) {
	srv, db, _, _, _, cleanup := setupTestServer(t)
	defer cleanup()
	admin := newUser(t, db, "admin")
	cookie := newSession(t, db, admin, time.Now().UTC().Add(time.Hour))
	sys := &store.PairedSystem{ID: "recovery-target", Name: "Recovery target", SystemType: "suite_webhook", CallbackURL: "https://example.com/hook", Status: "active"}
	if err := db.CreatePairedSystem(sys); err != nil {
		t.Fatal(err)
	}
	if err := db.CreateAccountSyncEvent(&store.AccountSyncEvent{ID: "attempt", UserID: admin.ID, SystemID: sys.ID, EventType: "user.updated", Status: "pending", PayloadJSON: `{}`}); err != nil {
		t.Fatal(err)
	}
	events, err := db.ClaimDueSyncEvents(50, time.Minute)
	if err != nil || len(events) != 1 {
		t.Fatal(events, err)
	}
	if ok, err := db.BeginSyncDelivery(events[0], -time.Second); err != nil || !ok {
		t.Fatal(ok, err)
	}
	base := "/api/admin/systems/" + sys.ID + "/deliveries"
	rr := adminRequest(t, srv, "GET", base, cookie, "")
	if rr.Code != 200 || !strings.Contains(rr.Body.String(), events[0].ClaimToken) {
		t.Fatal(rr.Code, rr.Body.String())
	}
	path := base + "/" + events[0].ClaimToken + "/resume"
	if rr := adminRequestNoStepUp(t, srv, "POST", path, cookie, `{"confirmedQuiescent":true}`); rr.Code != 403 {
		t.Fatal("no step-up", rr.Code)
	}
	for _, body := range []string{`{}`, `{"confirmedQuiescent":false}`, `{"confirmedQuiescent":"true"}`} {
		if rr := adminRequest(t, srv, "POST", path, cookie, body); rr.Code != 400 {
			t.Fatal(body, rr.Code)
		}
	}
	if rr := adminRequest(t, srv, "POST", path, cookie, `{"confirmedQuiescent":true,"allowCreateRetry":true}`); rr.Code != 409 {
		t.Fatal("suite create reset accepted", rr.Code)
	}
	rr = adminRequest(t, srv, "POST", path, cookie, `{"confirmedQuiescent":true}`)
	if rr.Code != 200 {
		t.Fatal(rr.Code, rr.Body.String())
	}
	if rr := adminRequest(t, srv, "POST", path, cookie, `{"confirmedQuiescent":true}`); rr.Code != 409 {
		t.Fatal("stale attempt replay", rr.Code)
	}
	audit, _, err := db.ListAuditEvents(100, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range audit {
		if a.Action == "admin.sync_delivery_resumed" && strings.Contains(a.DetailsJSON, sys.Name) {
			return
		}
	}
	t.Fatal("missing readable recovery audit")
}
