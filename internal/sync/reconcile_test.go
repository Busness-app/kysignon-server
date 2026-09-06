package sync

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Busness-app/ky-primitives/scim"
	"github.com/Busness-app/kysignon-server/internal/store"
	"github.com/google/uuid"
)

func runJob(t *testing.T, e *Engine, s *store.Store, systemID, kind string) *store.DriftReport {
	t.Helper()
	if _, err := s.CreateReconcileJob(systemID, kind, "test", nil); err != nil {
		t.Fatal(err)
	}
	ran, err := e.RunReconcileJob(context.Background())
	if err != nil || !ran {
		t.Fatal("job did not run", ran, err)
	}
	jobs, err := s.ListReconcileJobs(systemID, 1)
	if err != nil || len(jobs) != 1 || jobs[0].Status != "done" {
		t.Fatalf("job outcome %+v %v", jobs, err)
	}
	var report store.DriftReport
	if err := json.Unmarshal(jobs[0].Result, &report); err != nil {
		t.Fatal(err)
	}
	return &report
}

func TestReconcileJobListsAndRepairsGenericSCIM(t *testing.T) {
	e, s, u, cleanup := setupTestSyncEngine(t)
	defer cleanup()
	remote := newFakeSCIM()
	srv := httptest.NewTLSServer(remote)
	defer srv.Close()
	e.httpClient = srv.Client()
	sys, _, err := e.CreateSystem(&CreateSystemRequest{Name: "target", SystemType: "scim", CallbackURL: srv.URL + "/scim/v2", BearerToken: "target-token"})
	if err != nil {
		t.Fatal(err)
	}
	app := appRecordFor(t, s, sys.ID)
	others := []*store.User{}
	for _, name := range []string{"second", "third", "fourth"} {
		o := &store.User{ID: uuid.NewString(), Username: name, DisplayName: name, Email: name + "@example.com", PasswordHash: "x", Role: "user", Status: "active"}
		if err := s.CreateUser(o); err != nil {
			t.Fatal(err)
		}
		others = append(others, o)
	}
	for _, x := range []*store.User{u, others[0], others[1], others[2]} {
		if err := s.SetAppAssignment(app.ID, "users", x.ID, true, nil); err != nil {
			t.Fatal(err)
		}
	}
	drain(t, e)
	// fourth loses access and is deactivated; the target later reactivates it by itself.
	if err := s.SetAppAssignment(app.ID, "users", others[2].ID, false, nil); err != nil {
		t.Fatal(err)
	}
	drain(t, e)
	// Drift introduced behind KySignOn's back: one account deleted, one renamed, one
	// revoked user reactivated, and an account nobody here manages.
	remote.mu.Lock()
	for id, r := range remote.users {
		switch r.ExternalID {
		case u.ID:
			delete(remote.users, id)
		case others[0].ID:
			r.DisplayName = "changed"
			remote.users[id] = r
		case others[2].ID:
			r.Active = true
			remote.users[id] = r
		}
	}
	remote.users["foreign"] = scim.User{ID: "foreign", ExternalID: "nobody", UserName: "foreign", Active: true}
	remote.mu.Unlock()

	preview := runJob(t, e, s, sys.ID, "preview")
	if !preview.Supported || !preview.Complete || preview.Repaired || preview.ListedUsers != 4 || preview.MissingCount != 1 || preview.StaleCount != 1 || preview.OrphanedCount != 1 || preview.Unrelated != 1 {
		t.Fatalf("preview %+v", preview)
	}
	if remote.pages < 2 {
		t.Fatal("listing did not paginate", remote.pages)
	}
	if pending, _ := s.GetPendingSyncEvents(10); len(pending) != 0 {
		t.Fatal("preview queued work", pending)
	}
	// A failed page makes the run incomplete: observations only, nothing deactivated.
	remote.mu.Lock()
	remote.pages, remote.failPage = 0, 2
	remote.mu.Unlock()
	partial := runJob(t, e, s, sys.ID, "repair")
	if partial.Complete || partial.Repaired || partial.OrphanedCount != 0 || partial.ListingError == "" {
		t.Fatalf("partial %+v", partial)
	}
	drain(t, e)
	if got, _ := remote.userByExternal(others[2].ID); !got.Active {
		t.Fatal("incomplete listing deactivated an account")
	}
	remote.mu.Lock()
	remote.pages, remote.failPage = 0, 0
	remote.mu.Unlock()
	repair := runJob(t, e, s, sys.ID, "repair")
	// The incomplete run already queued the safe attribute repair, so only the
	// destructive classes remain for the complete run.
	if !repair.Repaired || repair.MissingCount != 1 || repair.OrphanedCount != 1 {
		t.Fatalf("repair %+v", repair)
	}
	drain(t, e)
	if got, ok := remote.userByExternal(u.ID); !ok || !got.Active {
		t.Fatal("missing account not recreated", got, ok)
	}
	if got, _ := remote.userByExternal(others[0].ID); got.DisplayName != others[0].DisplayName {
		t.Fatal("stale attributes not repaired", got)
	}
	if got, _ := remote.userByExternal(others[2].ID); got.Active {
		t.Fatal("orphaned account still active")
	}
	if got, _ := remote.userByExternal("nobody"); !got.Active {
		t.Fatal("unrelated account touched")
	}
	rows, _, err := s.ListProvisioningState(sys.ID, "", 50, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rows {
		if r.Observed == "" || (r.Desired && r.Observed != "present_active" && r.Observed != "absent") {
			t.Fatalf("observation not recorded: %+v", r)
		}
	}
}

func TestReconcileJobDoesNotBlockDelivery(t *testing.T) {
	e, s, u, cleanup := setupTestSyncEngine(t)
	defer cleanup()
	remote := newFakeSCIM()
	srv := httptest.NewTLSServer(remote)
	defer srv.Close()
	e.httpClient = srv.Client()
	sys, _, err := e.CreateSystem(&CreateSystemRequest{Name: "target", SystemType: "scim", CallbackURL: srv.URL + "/scim/v2", BearerToken: "target-token"})
	if err != nil {
		t.Fatal(err)
	}
	app := appRecordFor(t, s, sys.ID)
	for i := 0; i < 6; i++ {
		o := &store.User{ID: uuid.NewString(), Username: "u" + uuid.NewString()[:6], DisplayName: "x", Email: uuid.NewString() + "@example.com", PasswordHash: "x", Role: "user", Status: "active"}
		if err := s.CreateUser(o); err != nil {
			t.Fatal(err)
		}
		if err := s.SetAppAssignment(app.ID, "users", o.ID, true, nil); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.SetAppAssignment(app.ID, "users", u.ID, true, nil); err != nil {
		t.Fatal(err)
	}
	drain(t, e)
	// The target answers each listing page slowly; a revocation must not wait for it.
	remote.mu.Lock()
	remote.pageDelay = 300 * time.Millisecond
	remote.mu.Unlock()
	if _, err := s.CreateReconcileJob(sys.ID, "repair", "test", nil); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { defer close(done); e.runReconcileJobs(context.Background()) }()
	if err := s.SetAppAssignment(app.ID, "users", u.ID, false, nil); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	drain(t, e)
	if got, _ := remote.userByExternal(u.ID); got.Active {
		t.Fatal("revocation not delivered while listing ran")
	}
	jobs, _ := s.ListReconcileJobs(sys.ID, 1)
	if time.Since(start) > 500*time.Millisecond || len(jobs) != 1 || jobs[0].Status != "running" {
		t.Fatalf("delivery waited for the listing: %v %+v", time.Since(start), jobs)
	}
	<-done
}

func TestReconcileJobUnsupportedForSuiteWebhook(t *testing.T) {
	e, s, u, cleanup := setupTestSyncEngine(t)
	defer cleanup()
	srv, _ := newSuiteReceiver(t, 0)
	defer srv.Close()
	sys, _, err := e.CreateSystem(&CreateSystemRequest{Name: "suite", SystemType: "suite_webhook", CallbackURL: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	grantAllUsers(t, s, sys.ID)
	drain(t, e)
	report := runJob(t, e, s, sys.ID, "repair")
	if report.Supported || report.Repaired {
		t.Fatalf("%+v", report)
	}
	rows, _, _ := s.ListProvisioningState(sys.ID, "", 50, 0)
	if len(rows) == 0 || rows[0].Observed != "unsupported" || rows[0].UserID != u.ID && len(rows) < 1 {
		t.Fatalf("%+v", rows)
	}
	if ran, err := e.RunReconcileJob(context.Background()); ran || err != nil {
		t.Fatal("ran without a queued job", ran, err)
	}
	if _, err := s.ClaimReconcileJob(time.Minute); err != nil {
		t.Fatal(err)
	}
}
