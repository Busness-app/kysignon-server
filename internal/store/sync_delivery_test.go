package store

import (
	"path/filepath"
	"testing"
	"time"
)

func TestSyncDeliveryOrderingAndCrashRecovery(t *testing.T) {
	path := filepath.Join(t.TempDir(), "delivery.db")
	s, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { s.Close() }()
	u := createTestUser(t, s)
	if err := s.CreatePairedSystem(&PairedSystem{ID: "target", Name: "Target", SystemType: "scim", CallbackURL: "https://example.com/scim", Status: "active"}); err != nil {
		t.Fatal(err)
	}
	enqueue := func(id, user string) {
		t.Helper()
		if err := s.CreateAccountSyncEvent(&AccountSyncEvent{ID: id, SystemID: "target", UserID: user, EventType: "user.updated", PayloadJSON: `{}`, Status: "pending"}); err != nil {
			t.Fatal(err)
		}
	}
	claim := func() []AccountSyncEvent {
		t.Helper()
		events, err := s.ClaimDueSyncEvents(50, time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		return events
	}
	enqueue("first", u.ID)
	enqueue("second", u.ID)
	enqueue("other", "other")
	events := claim()
	if len(events) != 2 || events[0].ID != "first" || events[1].ID != "other" {
		t.Fatalf("not one head per resource: %+v", events)
	}
	first := events[0]
	// A claimed-but-unsent worker cannot send after its claim was reassigned.
	if _, err := s.db.Exec(`UPDATE account_sync_events SET lease_until=? WHERE id='first'`, time.Now().UTC().Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}
	newer := claim()
	if len(newer) != 1 {
		t.Fatal(newer)
	}
	if ok, err := s.BeginSyncDelivery(first, time.Minute); err != nil || ok {
		t.Fatal("stale claim began", ok, err)
	}
	first = newer[0]
	if ok, err := s.BeginSyncDelivery(first, -time.Second); err != nil || !ok {
		t.Fatal("begin", ok, err)
	}
	// Expiration and process restart do not mean a remote write has stopped.
	s.Close()
	s, err = New(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := claim(); len(got) != 0 {
		t.Fatalf("expired in-flight attempt reclaimed: %+v", got)
	}
	// Local deletion removes the old event but not its in-flight resource fence.
	if _, err := s.db.Exec(`INSERT INTO sync_resource_state(system_id,resource_id,active,provisioned,revision) VALUES('target',?,1,1,1)`, u.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteUserWithSyncEvents(u.ID, nil); err != nil {
		t.Fatal(err)
	}
	if got := claim(); len(got) != 0 {
		t.Fatal("delete bypassed in-flight write", got)
	}
	if err := s.FinishSyncDelivery(first, "delivered", "", 1, nil); err != nil {
		t.Fatal(err)
	}
	got := claim()
	if len(got) != 1 || got[0].EventType != "user.deleted" || got[0].Revision != 2 {
		t.Fatal("delete not released", got)
	}
	if ok, err := s.BeginSyncDelivery(got[0], -time.Second); err != nil || !ok {
		t.Fatal(ok, err)
	}
	if _, err := s.StartSCIMCreate("target", "user", u.ID); err != nil {
		t.Fatal(err)
	}
	// Failed audit rolls recovery back along with fence and create-marker removal.
	if _, err := s.db.Exec(`CREATE TRIGGER reject_delivery_audit BEFORE INSERT ON audit_events BEGIN SELECT RAISE(ABORT,'audit failed'); END`); err != nil {
		t.Fatal(err)
	}
	audit := &AuditEvent{ID: "resume", Action: "admin.sync_delivery_resumed", Outcome: "success"}
	if err := s.ResumeSyncDelivery("target", got[0].ClaimToken, true, audit); err == nil {
		t.Fatal("recovery without audit")
	}
	if _, started, err := s.SCIMUserLink("target", u.ID); err != nil || !started {
		t.Fatal("audit rollback lost create marker", started, err)
	}
	attempts, err := s.ListSyncDeliveryAttempts("target")
	if err != nil || len(attempts) != 1 {
		t.Fatal(attempts, err)
	}
	if _, err := s.db.Exec(`DROP TRIGGER reject_delivery_audit`); err != nil {
		t.Fatal(err)
	}
	if err := s.ResumeSyncDelivery("target", got[0].ClaimToken, true, audit); err != nil {
		t.Fatal(err)
	}
	if _, started, err := s.SCIMUserLink("target", u.ID); err != nil || started {
		t.Fatal("confirmed create retry retained marker", started, err)
	}
	if err := s.FinishSyncDelivery(got[0], "delivered", "", 1, nil); err == nil {
		t.Fatal("old worker completed resumed attempt")
	}
	if len(claim()) != 1 {
		t.Fatal("recovered event not queued")
	}
}

func TestSyncDeliveryBackoffHoldsLaterEvents(t *testing.T) {
	s, cleanup := setupTestStore(t)
	defer cleanup()
	for _, id := range []string{"first", "second"} {
		if err := s.CreateAccountSyncEvent(&AccountSyncEvent{ID: id, UserID: "u", SystemID: "s", EventType: "user.updated", Status: "pending", PayloadJSON: `{}`}); err != nil {
			t.Fatal(err)
		}
	}
	next := time.Now().UTC().Add(time.Hour)
	if err := s.UpdateSyncEventStatus("first", "pending", "retry", 1, &next); err != nil {
		t.Fatal(err)
	}
	if got, err := s.ClaimDueSyncEvents(50, time.Minute); err != nil || len(got) != 0 {
		t.Fatal("backoff bypassed", got, err)
	}
	// Legacy rows exhausted by missing credentials used to remain pending at five.
	if err := s.UpdateSyncEventStatus("first", "pending", "exhausted", 5, nil); err != nil {
		t.Fatal(err)
	}
	if got, err := s.ClaimDueSyncEvents(50, time.Minute); err != nil || len(got) != 1 || got[0].ID != "second" {
		t.Fatal("exhausted legacy head starved queue", got, err)
	}
}
