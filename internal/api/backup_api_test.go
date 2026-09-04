package api

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Busness-app/ky-primitives/capsule"
	"github.com/Busness-app/ky-primitives/recoverykey"
	"github.com/Busness-app/kysignon-server/internal/auth"
	"github.com/Busness-app/kysignon-server/internal/backup"
	"github.com/Busness-app/kysignon-server/internal/crypto"
	"github.com/Busness-app/kysignon-server/internal/store"
	"github.com/google/uuid"
)

// fakeRecovery stands in for KyRecovery: the real client refuses non-HTTPS and private hosts,
// so the handlers cannot be exercised against a test listener.
type fakeRecovery struct {
	result   backup.PairingResult
	claimErr error
	deposit  error
	got      []byte
}

func (f *fakeRecovery) ClaimPairing(context.Context, string, string, string, string) (backup.PairingResult, error) {
	return f.result, f.claimErr
}

func (f *fakeRecovery) Deposit(_ context.Context, _, _ string, container []byte) (backup.Receipt, error) {
	f.got = container
	if f.deposit != nil {
		return backup.Receipt{}, f.deposit
	}
	m, err := capsule.ReadUnverifiedManifest(container)
	if err != nil {
		return backup.Receipt{}, err
	}
	sum := sha256.Sum256(container)
	return backup.Receipt{CapsuleID: m.CapsuleID, Digest: hex.EncodeToString(sum[:]), SizeBytes: int64(len(container)), DepositedAt: time.Now().UTC()}, nil
}

func TestAdminBackupEndpoints(t *testing.T) {
	priv, err := recoverykey.Generate()
	if err != nil {
		t.Fatal(err)
	}
	fake := &fakeRecovery{result: backup.PairingResult{APIToken: "kyrec_live_t", Key: backup.RecoveryKey{Public: priv.Public(), Threshold: 2, TotalShares: 3}}}
	prev := newRecoveryClient
	newRecoveryClient = func() recoveryClient { return fake }
	t.Cleanup(func() { newRecoveryClient = prev })

	srv, dbStore, _, _, _, cleanup := setupTestServer(t)
	defer cleanup()

	adminPass := "AdminPassword123!"
	passHash, _ := auth.HashPassword(adminPass)
	adminUser := &store.User{
		ID: uuid.New().String(), Username: "admin_backup_test", DisplayName: "Admin Backup", Email: "admin@backup.test",
		PasswordHash: passHash, Role: "admin", Status: "active",
	}
	if err := dbStore.CreateUser(adminUser); err != nil {
		t.Fatalf("CreateUser failed: %v", err)
	}
	adminSessionToken, _ := crypto.GenerateRandomHex(32)
	_ = dbStore.CreateSession(&store.Session{
		ID: uuid.New().String(), UserID: adminUser.ID, SessionTokenHash: crypto.HashSHA256(adminSessionToken),
		IPAddress: "127.0.0.1", UserAgent: "Go-Test", ExpiresAt: time.Now().Add(24 * time.Hour),
	})
	csrfToken := srv.middleware.IssueCSRFToken(adminSessionToken)
	adminCookie := &http.Cookie{Name: "kysignon_session", Value: adminSessionToken}
	csrfCookie := &http.Cookie{Name: "kysignon_csrf", Value: csrfToken}
	stepUp := func() string { return mintStepUp(t, srv, adminSessionToken) }

	do := func(method, path string, body []byte, withStepUp bool) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, bytes.NewReader(body))
		req.AddCookie(adminCookie)
		req.AddCookie(csrfCookie)
		req.Header.Set("X-CSRF-Token", csrfToken)
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		if withStepUp {
			req.Header.Set(StepUpHeader, stepUp())
		}
		w := httptest.NewRecorder()
		srv.httpServer.Handler.ServeHTTP(w, req)
		return w
	}
	auditHas := func(action, outcome string) bool {
		events, _, err := dbStore.ListAuditEvents(100, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range events {
			if e.Action == action && e.Outcome == outcome && e.ActorID == adminUser.ID {
				return true
			}
		}
		return false
	}

	t.Run("status before pairing", func(t *testing.T) {
		w := do("GET", "/api/admin/backup/status", nil, false)
		if w.Code != http.StatusOK {
			t.Fatalf("got %d: %s", w.Code, w.Body.String())
		}
		var resp map[string]any
		_ = json.NewDecoder(w.Body).Decode(&resp)
		if resp["app_name"] != "KySignOn" || resp["paired"] != false {
			t.Errorf("status %v", resp)
		}
	})

	t.Run("drill runs unpaired and says so", func(t *testing.T) {
		w := do("POST", "/api/admin/backup/drill", nil, false)
		if w.Code != http.StatusOK {
			t.Fatalf("got %d: %s", w.Code, w.Body.String())
		}
		var result backup.DrillResult
		_ = json.NewDecoder(w.Body).Decode(&result)
		if result.Passed {
			t.Error("unpaired drill passed")
		}
	})

	t.Run("export and deposit refuse while unpaired", func(t *testing.T) {
		if w := do("GET", "/api/admin/backup/export-capsule", nil, true); w.Code != http.StatusPreconditionFailed {
			t.Errorf("export: got %d: %s", w.Code, w.Body.String())
		}
		if w := do("POST", "/api/admin/backup/deposit", nil, true); w.Code != http.StatusPreconditionFailed {
			t.Errorf("deposit: got %d: %s", w.Code, w.Body.String())
		}
		if fake.got != nil {
			t.Error("bytes were sent while unpaired")
		}
	})

	t.Run("pairing refuses internal and non-https recovery URLs", func(t *testing.T) {
		for _, target := range []string{"http://recovery.example.test", "https://127.0.0.1:8095", "https://10.0.0.5", "https://user:pw@recovery.example.test", "https://recovery.example.test/#frag", "https://recovery.example.test/?a=b"} {
			body, _ := json.Marshal(map[string]string{"recovery_url": target, "pairing_code": "123456"})
			if w := do("POST", "/api/admin/backup/pair-remote", body, true); w.Code != http.StatusBadRequest {
				t.Errorf("%s: got %d: %s", target, w.Code, w.Body.String())
			}
		}
		if auditHas("admin.backup_remote_pair", "success") {
			t.Error("a refused URL was audited as a pairing")
		}
	})

	t.Run("pairing pins the key and stores the sealed token", func(t *testing.T) {
		body, _ := json.Marshal(map[string]string{"recovery_url": "https://recovery.example.test", "pairing_code": "123456"})
		w := do("POST", "/api/admin/backup/pair-remote", body, true)
		if w.Code != http.StatusOK {
			t.Fatalf("got %d: %s", w.Code, w.Body.String())
		}
		var resp map[string]any
		_ = json.NewDecoder(w.Body).Decode(&resp)
		if resp["recovery_key_id"] != priv.Public().ID() {
			t.Errorf("pair response %v", resp)
		}
		if !auditHas("admin.backup_remote_pair", "success") {
			t.Error("pairing not audited")
		}
		if v, _ := dbStore.GetSetting("kyrecovery_token_enc"); v == "" || strings.Contains(v, "kyrec_live_t") {
			t.Errorf("token stored as %q", v)
		}
		// Re-pairing to a different key must not silently re-point the instance.
		other, _ := recoverykey.Generate()
		fake.result = backup.PairingResult{APIToken: "tok2", Key: backup.RecoveryKey{Public: other.Public(), Threshold: 2, TotalShares: 3}}
		if w := do("POST", "/api/admin/backup/pair-remote", body, true); w.Code != http.StatusConflict {
			t.Errorf("re-pair: got %d: %s", w.Code, w.Body.String())
		}
	})

	t.Run("deposit seals to the pinned key, records the receipt, audits", func(t *testing.T) {
		w := do("POST", "/api/admin/backup/deposit", nil, true)
		if w.Code != http.StatusOK {
			t.Fatalf("got %d: %s", w.Code, w.Body.String())
		}
		var rcpt backup.Receipt
		_ = json.NewDecoder(w.Body).Decode(&rcpt)
		if _, files, err := capsule.Open(fake.got, priv, t.TempDir()); err != nil || len(files) < 5 {
			t.Fatalf("what the store received does not open with the suite key: %v", err)
		}
		if last, ok, _ := backup.LastDeposit(dbStore); !ok || last.CapsuleID != rcpt.CapsuleID {
			t.Errorf("last deposit %+v %v", last, ok)
		}
		if !auditHas("admin.backup_deposit", "success") {
			t.Error("deposit not audited")
		}
		fake.deposit = errors.New(backup.ErrRemote.Error() + ": deposit rejected (429)")
		fake.deposit = errors.Join(backup.ErrRemote, fake.deposit)
		if w := do("POST", "/api/admin/backup/deposit", nil, true); w.Code != http.StatusBadGateway {
			t.Errorf("refused deposit: got %d: %s", w.Code, w.Body.String())
		}
		if again, _, _ := backup.LastDeposit(dbStore); again.CapsuleID != rcpt.CapsuleID {
			t.Error("a refused deposit replaced the last receipt")
		}
		fake.deposit = nil
	})

	t.Run("export is a sealed capsule and is audited", func(t *testing.T) {
		w := do("GET", "/api/admin/backup/export-capsule", nil, true)
		if w.Code != http.StatusOK {
			t.Fatalf("got %d: %s", w.Code, w.Body.String())
		}
		if _, _, err := capsule.Open(w.Body.Bytes(), priv, t.TempDir()); err != nil {
			t.Fatalf("export does not open with the suite key: %v", err)
		}
		if w.Header().Get("X-Recovery-Key-ID") != priv.Public().ID() {
			t.Errorf("header %q", w.Header().Get("X-Recovery-Key-ID"))
		}
		if !auditHas("admin.backup_capsule_export", "success") {
			t.Error("export not audited")
		}
	})

	t.Run("status after pairing", func(t *testing.T) {
		w := do("GET", "/api/admin/backup/status", nil, false)
		var resp map[string]any
		_ = json.NewDecoder(w.Body).Decode(&resp)
		if resp["paired"] != true || resp["recovery_key_id"] != priv.Public().ID() || resp["last_deposit"] == nil {
			t.Errorf("status %v", resp)
		}
	})

	t.Run("step-up is required on the secret-bearing routes", func(t *testing.T) {
		for _, tc := range []struct{ method, path string }{{"GET", "/api/admin/backup/export-capsule"}, {"POST", "/api/admin/backup/deposit"}, {"POST", "/api/admin/backup/pair-remote"}} {
			if w := do(tc.method, tc.path, []byte(`{}`), false); w.Code != http.StatusForbidden && w.Code != http.StatusUnauthorized {
				t.Errorf("%s %s without step-up: got %d", tc.method, tc.path, w.Code)
			}
		}
	})
}
