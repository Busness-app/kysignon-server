package sync

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Yoshiofthewire/kysignon-server/internal/crypto"
	"github.com/Yoshiofthewire/kysignon-server/internal/store"
	"github.com/google/uuid"
)

func setupSync(t *testing.T) (*Engine, *store.Store, *store.User, func()) {
	t.Helper()
	dir, err := os.MkdirTemp("", "kysignon-sync-sec-*")
	if err != nil {
		t.Fatal(err)
	}
	db, err := store.New(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	key, _ := crypto.GenerateRandomBytes(32)
	admin := &store.User{
		ID: uuid.New().String(), Username: "admin" + uuid.New().String()[:6],
		DisplayName: "A", Email: uuid.New().String()[:6] + "@x.test",
		PasswordHash: "x", Role: "admin", Status: "active",
	}
	if err := db.CreateUser(admin); err != nil {
		t.Fatal(err)
	}
	// These tests point callbacks at httptest servers on loopback.
	AllowPrivateCallbacks = true
	t.Cleanup(func() { AllowPrivateCallbacks = false })

	return NewEngine(db, key), db, admin, func() {
		_ = db.Close()
		_ = os.RemoveAll(dir)
	}
}

// The PIN shown to the admin must be part of redemption. Generating one and discarding it
// is security theatre: the token alone becomes the whole credential.
func TestSystemPairingRequiresThePIN(t *testing.T) {
	e, _, admin, cleanup := setupSync(t)
	defer cleanup()

	token, pin, _, err := e.GenerateSystemPairingToken("kypost", admin.ID)
	if err != nil {
		t.Fatal(err)
	}
	if pin == "" {
		t.Fatal("no PIN was issued")
	}

	if _, err := e.RegisterPairedSystem(&SystemRegistrationRequest{
		PairingToken: token, SystemName: "evil", SystemType: "kypost",
		CallbackURL: "https://attacker.example.com/collect",
	}); err == nil {
		t.Error("a system paired without presenting the PIN")
	}

	if _, err := e.RegisterPairedSystem(&SystemRegistrationRequest{
		PairingToken: token, PINCode: "WRONGPIN", SystemName: "evil", SystemType: "kypost",
		CallbackURL: "https://attacker.example.com/collect",
	}); err == nil {
		t.Error("a system paired with the wrong PIN")
	}
}

func TestSystemPairingSucceedsWithTokenAndPIN(t *testing.T) {
	e, _, admin, cleanup := setupSync(t)
	defer cleanup()

	token, pin, _, err := e.GenerateSystemPairingToken("kypost", admin.ID)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := e.RegisterPairedSystem(&SystemRegistrationRequest{
		PairingToken: token, PINCode: pin, SystemName: "mail", SystemType: "kypost",
		CallbackURL: "https://mail.urlxl.com/hooks/kysignon",
	})
	if err != nil {
		t.Fatalf("a correct token and PIN was rejected: %v", err)
	}
	if resp.HMACSecret == "" {
		t.Error("no HMAC secret was issued")
	}
}

// A wrong PIN must not be retryable until it is guessed.
func TestSystemPairingPINHasAnAttemptBudget(t *testing.T) {
	e, _, admin, cleanup := setupSync(t)
	defer cleanup()

	token, pin, _, err := e.GenerateSystemPairingToken("kypost", admin.ID)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		_, _ = e.RegisterPairedSystem(&SystemRegistrationRequest{
			PairingToken: token, PINCode: "BADGUESS", SystemName: "x", SystemType: "kypost",
			CallbackURL: "https://x.test/hook",
		})
	}
	if _, err := e.RegisterPairedSystem(&SystemRegistrationRequest{
		PairingToken: token, PINCode: pin, SystemName: "x", SystemType: "kypost",
		CallbackURL: "https://x.test/hook",
	}); err == nil {
		t.Error("the correct PIN still worked after repeated wrong guesses; the PIN is brute-forceable")
	}
}

// The callback URL is chosen by whoever redeems the token, and the server then POSTs the
// whole directory to it. It must not be able to name an internal address.
func TestCallbackURLIsValidated(t *testing.T) {
	e, _, admin, cleanup := setupSync(t)
	defer cleanup()
	AllowPrivateCallbacks = false // the production default

	rejected := []string{
		"http://169.254.169.254/latest/meta-data/",
		"http://127.0.0.1:5867/api/admin/users",
		"http://[::1]:8080/hook",
		"file:///etc/passwd",
		"gopher://evil.test/_x",
		"https://10.89.0.2/internal",
		"not a url at all",
		"",
	}
	for _, target := range rejected {
		token, pin, _, err := e.GenerateSystemPairingToken("kypost", admin.ID)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := e.RegisterPairedSystem(&SystemRegistrationRequest{
			PairingToken: token, PINCode: pin, SystemName: "x", SystemType: "kypost",
			CallbackURL: target,
		}); err == nil {
			t.Errorf("callback URL %q was accepted", target)
		}
	}
}

// Events must reach only the system they belong to. Fanning every user record out to every
// paired system means the least trusted integration receives the whole directory.
func TestEventsAreScopedToTheirSystem(t *testing.T) {
	e, db, admin, cleanup := setupSync(t)
	defer cleanup()

	var hitsA, hitsB int
	srvA := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hitsA++ }))
	defer srvA.Close()
	srvB := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hitsB++ }))
	defer srvB.Close()

	pair := func(name, url string) string {
		token, pin, _, err := e.GenerateSystemPairingToken("custom", admin.ID)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := e.RegisterPairedSystem(&SystemRegistrationRequest{
			PairingToken: token, PINCode: pin, SystemName: name, SystemType: "custom", CallbackURL: url,
		})
		if err != nil {
			t.Fatalf("pairing %s: %v", name, err)
		}
		return resp.SystemID
	}

	idA := pair("system-a", srvA.URL)
	pair("system-b", srvB.URL)

	if err := e.ResyncAllAccounts(idA); err != nil {
		t.Fatal(err)
	}
	if err := e.DispatchPendingEvents(context.Background()); err != nil {
		t.Fatal(err)
	}

	if hitsA == 0 {
		t.Error("the system that was resynced received nothing")
	}
	if hitsB != 0 {
		t.Errorf("resyncing system A delivered %d event(s) to system B", hitsB)
	}
	_ = db
}

// Delivery being impossible right now is not delivery. An event queued for a system that
// is temporarily disabled must wait for it, not be marked delivered and dropped, or a
// deprovision silently never reaches a downstream that still holds the account.
func TestUndeliverableEventStaysQueued(t *testing.T) {
	e, db, admin, cleanup := setupSync(t)
	defer cleanup()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()

	token, pin, _, _ := e.GenerateSystemPairingToken("custom", admin.ID)
	resp, err := e.RegisterPairedSystem(&SystemRegistrationRequest{
		PairingToken: token, PINCode: pin, SystemName: "mail", SystemType: "custom", CallbackURL: srv.URL,
	})
	if err != nil {
		t.Fatal(err)
	}

	u := &store.User{
		ID: uuid.New().String(), Username: "leaver", DisplayName: "L", Email: "l@x.test",
		PasswordHash: "x", Role: "user", Status: "active",
	}
	if err := db.CreateUser(u); err != nil {
		t.Fatal(err)
	}
	if err := e.QueueAccountSyncEvent(u.ID, "user.deleted", map[string]any{"id": u.ID}); err != nil {
		t.Fatal(err)
	}
	if err := db.UpdatePairedSystemStatus(resp.SystemID, "disabled"); err != nil {
		t.Fatal(err)
	}

	if err := e.DispatchPendingEvents(context.Background()); err != nil {
		t.Fatal(err)
	}

	pending, err := db.GetPendingSyncEvents(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) == 0 {
		t.Error("user.deleted was marked delivered while its target system was unreachable")
	}
}

// Retrying every 3 seconds with no backoff hammers a system that is already failing.
func TestFailedDeliveryBacksOff(t *testing.T) {
	e, db, admin, cleanup := setupSync(t)
	defer cleanup()

	var attempts int
	failing := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer failing.Close()

	token, pin, _, _ := e.GenerateSystemPairingToken("custom", admin.ID)
	resp, err := e.RegisterPairedSystem(&SystemRegistrationRequest{
		PairingToken: token, PINCode: pin, SystemName: "flaky", SystemType: "custom", CallbackURL: failing.URL,
	})
	if err != nil {
		t.Fatal(err)
	}

	u := &store.User{
		ID: uuid.New().String(), Username: "x", DisplayName: "X", Email: "x2@x.test",
		PasswordHash: "x", Role: "user", Status: "active",
	}
	if err := db.CreateUser(u); err != nil {
		t.Fatal(err)
	}
	if err := db.CreateAccountSyncEvent(&store.AccountSyncEvent{
		ID: uuid.New().String(), UserID: u.ID, SystemID: resp.SystemID,
		EventType: "user.created", PayloadJSON: `{"id":"x"}`, Status: "pending",
	}); err != nil {
		t.Fatal(err)
	}

	for i := 0; i < 5; i++ {
		if err := e.DispatchPendingEvents(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if attempts > 1 {
		t.Errorf("a failing endpoint was retried %d times back-to-back with no backoff", attempts)
	}
}

// A secret that signs every outbound webhook must not sit in the database in the clear.
func TestHMACSecretIsNotStoredInPlaintext(t *testing.T) {
	e, db, admin, cleanup := setupSync(t)
	defer cleanup()

	token, pin, _, _ := e.GenerateSystemPairingToken("kypost", admin.ID)
	resp, err := e.RegisterPairedSystem(&SystemRegistrationRequest{
		PairingToken: token, PINCode: pin, SystemName: "mail", SystemType: "kypost",
		CallbackURL: "https://mail.urlxl.com/hooks",
	})
	if err != nil {
		t.Fatal(err)
	}

	systems, err := db.ListAllPairedSystems()
	if err != nil || len(systems) != 1 {
		t.Fatalf("expected 1 system: %v", err)
	}
	for _, s := range systems {
		if strings.Contains(s.HMACSecretHash, resp.HMACSecret) || strings.Contains(s.HMACSecretEncrypted, resp.HMACSecret) {
			t.Error("the webhook signing secret is stored in plaintext")
		}
	}

	// It must still be usable for signing after the round trip.
	got, err := e.SigningSecret(&systems[0])
	if err != nil {
		t.Fatalf("could not recover the signing secret: %v", err)
	}
	if got != resp.HMACSecret {
		t.Error("the recovered signing secret does not match the one handed to the system")
	}
}

func TestPairingTokenIsSingleUse(t *testing.T) {
	e, _, admin, cleanup := setupSync(t)
	defer cleanup()

	token, pin, _, _ := e.GenerateSystemPairingToken("kypost", admin.ID)
	req := func() *SystemRegistrationRequest {
		return &SystemRegistrationRequest{
			PairingToken: token, PINCode: pin, SystemName: "mail", SystemType: "kypost",
			CallbackURL: "https://mail.urlxl.com/hooks",
		}
	}
	if _, err := e.RegisterPairedSystem(req()); err != nil {
		t.Fatal(err)
	}
	if _, err := e.RegisterPairedSystem(req()); err == nil {
		t.Error("a pairing token was redeemed twice")
	}
}

func TestExpiredPairingTokenIsRejected(t *testing.T) {
	e, db, admin, cleanup := setupSync(t)
	defer cleanup()

	token, pin, _, _ := e.GenerateSystemPairingToken("kypost", admin.ID)
	if err := db.ExpireSystemPairingTokens(time.Now().UTC().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := e.RegisterPairedSystem(&SystemRegistrationRequest{
		PairingToken: token, PINCode: pin, SystemName: "late", SystemType: "kypost",
		CallbackURL: "https://mail.urlxl.com/hooks",
	}); err == nil {
		t.Error("an expired pairing token was accepted")
	}
}
