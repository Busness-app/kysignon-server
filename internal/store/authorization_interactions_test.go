package store

import (
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestAuthorizationInteractionAtomicity(t *testing.T) {
	s, u, a := appAccessFixture(t)
	if err := s.SetAppPolicy(a.ID, "all_active_users", true, a.Revision, nil); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	create := func(hash string) {
		t.Helper()
		if err := s.CreateAuthorizationInteraction(&AuthorizationInteraction{Hash: hash, BrowserHash: "browser", UserID: u.ID, OriginalSessionID: "session", CreatedAt: now, ExpiresAt: now.Add(time.Minute), Request: "client_id=client"}); err != nil {
			t.Fatal(err)
		}
	}
	session := func(id string) *Session {
		at := time.Now().UTC()
		return &Session{ID: id, UserID: u.ID, SessionTokenHash: id, ExpiresAt: now.Add(time.Hour), AuthenticationEvidence: AuthenticationEvidence{PrimaryAuthenticatedAt: &at}}
	}
	create("login")
	if err := s.CreateSessionForInteraction(session("wrong"), "login", "wrong-browser"); !errors.Is(err, ErrAuthorizationInteraction) {
		t.Fatal(err)
	}
	if got, _ := s.GetSessionByID("wrong"); got != nil {
		t.Fatal("failed binding left session")
	}
	// A failed session insertion rolls back the interaction's satisfied marker.
	duplicate := session("session")
	if err := s.CreateSessionForInteraction(duplicate, "login", "browser"); err == nil {
		t.Fatal("duplicate session accepted")
	}
	i, err := s.GetAuthorizationInteraction("login", "browser")
	if err != nil || i.SessionID != "" {
		t.Fatal("failed session burned interaction", err)
	}
	sess := session("new")
	if err := s.CreateSessionForInteraction(sess, "login", "browser"); err != nil {
		t.Fatal(err)
	}
	// Atomic code consumption permits only one concurrent resume.
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for n := range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			id := fmt.Sprint(n)
			results <- s.CreateAuthorizationCode(&AuthorizationCode{ID: id, CodeHash: id, ClientID: "client", UserID: u.ID, SessionID: sess.ID, InteractionHash: "login", ExpiresAt: now.Add(time.Minute), AuthenticationEvidence: sess.AuthenticationEvidence})
		}()
	}
	wg.Wait()
	close(results)
	wins := 0
	for err := range results {
		if err == nil {
			wins++
		} else if !errors.Is(err, ErrAuthorizationInteraction) {
			t.Fatal(err)
		}
	}
	if wins != 1 {
		t.Fatalf("%d resumes succeeded", wins)
	}
	create("expired")
	if _, err := s.db.Exec(`UPDATE authorization_interactions SET expires_at=? WHERE hash='expired'`, now.Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateSessionForInteraction(session("late"), "expired", "browser"); !errors.Is(err, ErrAuthorizationInteraction) {
		t.Fatal("expired interaction accepted", err)
	}
	create("revoked")
	if err := s.DeleteSession("session"); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateSessionForInteraction(session("after-logout"), "revoked", "browser"); !errors.Is(err, ErrAuthorizationInteraction) {
		t.Fatal("logout revived interaction", err)
	}
}

func TestAuthorizationCodeMaximumAgeAtRegistration(t *testing.T) {
	s, u, a := appAccessFixture(t)
	if err := s.SetAppPolicy(a.ID, "all_active_users", true, a.Revision, nil); err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		id   string
		ago  time.Duration
		want bool
	}{{"fresh", time.Second, true}, {"stale", time.Hour, false}} {
		at := time.Now().UTC().Add(-tt.ago)
		until := at.Add(time.Minute)
		if err := s.CreateAuthorizationCode(&AuthorizationCode{ID: tt.id, CodeHash: tt.id, ClientID: "client", UserID: u.ID, SessionID: "session", AuthenticationExpiresAt: &until, ExpiresAt: time.Now().UTC().Add(time.Minute), AuthenticationEvidence: AuthenticationEvidence{PrimaryAuthenticatedAt: &at}}); err != nil {
			t.Fatal(err)
		}
		if ok, err := s.ConsumeAuthorizationCode(tt.id); err != nil || !ok {
			t.Fatal(err)
		}
		err := s.RecordIssuedToken(accessToken(u, tt.id, tt.id))
		if tt.want && err != nil {
			t.Fatal(err)
		}
		if !tt.want && !errors.Is(err, ErrAppAccessDenied) {
			t.Fatal("stale proof registered", err)
		}
	}
}

func TestAuthorizationInteractionCapacityAndMigration(t *testing.T) {
	s, _, _ := appAccessFixture(t)
	now := time.Now().UTC()
	for n := range 11 {
		err := s.CreateAuthorizationInteraction(&AuthorizationInteraction{Hash: fmt.Sprint(n), BrowserHash: "browser", Request: "client_id=client", CreatedAt: now, ExpiresAt: now.Add(time.Minute)})
		if n < 10 && err != nil {
			t.Fatal(err)
		}
		if n == 10 && !errors.Is(err, ErrAuthorizationInteraction) {
			t.Fatal("browser capacity not enforced", err)
		}
	}
	if err := s.migrateAuthorizationInteractions(); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetAuthorizationInteraction("0", "browser"); err != nil {
		t.Fatal("migration lost pending interaction", err)
	}
	if _, err := s.db.Exec(`UPDATE authorization_interactions SET expires_at=?`, now.Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateAuthorizationInteraction(&AuthorizationInteraction{Hash: "new", BrowserHash: "browser", Request: "client_id=client", CreatedAt: now, ExpiresAt: now.Add(time.Minute)}); err != nil {
		t.Fatal("expired rows consumed capacity", err)
	}
}
