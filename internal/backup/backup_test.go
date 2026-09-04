package backup_test

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Busness-app/ky-primitives/capsule"
	"github.com/Busness-app/ky-primitives/recoverykey"
	"github.com/Busness-app/kysignon-server/internal/backup"
	"github.com/Busness-app/kysignon-server/internal/config"
	"github.com/Busness-app/kysignon-server/internal/crypto"
	"github.com/Busness-app/kysignon-server/internal/store"
	"github.com/google/uuid"
)

// instance is a live kysignon data directory: a store with one active admin, a signing key,
// and 32-byte deployment keys, which is what the collector needs to produce a capsule.
func instance(t *testing.T) (*config.Config, *store.Store) {
	t.Helper()
	dir := t.TempDir()
	cfg := &config.Config{
		Port:          "5867",
		IssuerURL:     "https://sso.example.test",
		DBPath:        filepath.Join(dir, "kysignon.db"),
		DataDir:       dir,
		RSAKeyPath:    filepath.Join(dir, "jwt_rs256.key"),
		SecretKey:     make([]byte, config.KeyLength),
		EncryptionKey: make([]byte, config.KeyLength),
		AppName:       config.DefaultAppName,
		SessionTTL:    time.Hour,
	}
	if _, err := rand.Read(cfg.EncryptionKey); err != nil {
		t.Fatal(err)
	}
	if _, err := rand.Read(cfg.SecretKey); err != nil {
		t.Fatal(err)
	}
	if _, err := crypto.LoadOrCreateRSAKey(cfg.RSAKeyPath); err != nil {
		t.Fatal(err)
	}
	st, err := store.New(cfg.DBPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	if err := st.CreateUser(&store.User{ID: uuid.NewString(), Username: "admin", DisplayName: "Admin", Email: "admin@example.test",
		PasswordHash: "x", Role: "admin", Status: "active"}); err != nil {
		t.Fatal(err)
	}
	return cfg, st
}

func pair(t *testing.T, cfg *config.Config, st *store.Store) recoverykey.PrivateKey {
	t.Helper()
	priv, err := recoverykey.Generate()
	if err != nil {
		t.Fatal(err)
	}
	if err := backup.StoreRecoveryKey(cfg.DataDir, st, backup.RecoveryKey{Public: priv.Public(), Threshold: 2, TotalShares: 3}); err != nil {
		t.Fatal(err)
	}
	if err := backup.StorePairing(st, cfg.EncryptionKey, "https://recovery.example.test", "kyrec_live_t"); err != nil {
		t.Fatal(err)
	}
	return priv
}

// fakeStore is kyrecovery's side of a deposit: it answers with the receipt the real server
// would for the bytes it received.
type fakeStore struct {
	url, token string
	container  []byte
	err        error
}

func (f *fakeStore) Deposit(_ context.Context, serverURL, apiToken string, container []byte) (backup.Receipt, error) {
	f.url, f.token, f.container = serverURL, apiToken, container
	if f.err != nil {
		return backup.Receipt{}, f.err
	}
	m, err := capsule.ReadUnverifiedManifest(container)
	if err != nil {
		return backup.Receipt{}, err
	}
	sum := sha256.Sum256(container)
	return backup.Receipt{CapsuleID: m.CapsuleID, Digest: hex.EncodeToString(sum[:]), SizeBytes: int64(len(container)), DepositedAt: time.Now().UTC()}, nil
}

// The capsule must carry everything a restore needs, and the database inside it must be a
// consistent snapshot: the store runs in WAL mode, and a row committed moments ago lives only
// in the -wal until a checkpoint.
func TestCollectSealableCarriesEverythingARestoreNeeds(t *testing.T) {
	cfg, st := instance(t)
	if err := st.SetSetting("canary", "still-in-the-wal"); err != nil {
		t.Fatal(err)
	}
	payload, err := backup.CollectSealable(cfg, st, "1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	got := map[string][]byte{}
	for _, f := range payload.Files {
		got[f.Path] = f.Data
		if f.Mode != 0600 {
			t.Errorf("%s mode %o", f.Path, f.Mode)
		}
	}
	for _, want := range []string{"data/kysignon.db", "data/jwt_rs256.key", "data/encryption.key", "data/secret.key", "config/kysignon.json"} {
		if len(got[want]) == 0 {
			t.Errorf("missing %s", want)
		}
	}
	if string(got["data/encryption.key"]) != string(cfg.EncryptionKey) {
		t.Error("encryption key is not the loaded one byte for byte")
	}
	restored := filepath.Join(t.TempDir(), "restored.db")
	if err := os.WriteFile(restored, got["data/kysignon.db"], 0600); err != nil {
		t.Fatal(err)
	}
	copyStore, err := store.New(restored)
	if err != nil {
		t.Fatalf("snapshot does not open: %v", err)
	}
	defer copyStore.Close()
	if v, err := copyStore.GetSetting("canary"); err != nil || v != "still-in-the-wal" {
		t.Fatalf("snapshot lacks the uncheckpointed row: %q %v", v, err)
	}
	if entries, _ := os.ReadDir(cfg.DataDir); len(entries) > 0 {
		for _, e := range entries {
			if e.IsDir() && strings.HasPrefix(e.Name(), "snapshot-") {
				t.Error("snapshot scratch directory left behind")
			}
		}
	}
	if payload.ServiceName != "KySignOn" {
		t.Errorf("service name %q", payload.ServiceName)
	}
}

func TestDrillProvesARestoreIsUsable(t *testing.T) {
	cfg, st := instance(t)
	payload, err := backup.CollectSealable(cfg, st, "1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	result, err := backup.RunRestoreDrill(context.Background(), payload.ServiceName, payload.AppVersion, payload.Files, payload.Dependencies, payload.VerificationRecipe, backup.RecoveryKey{})
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{}
	for _, c := range result.Checks {
		names[c.Name] = c.Passed
	}
	// Unpaired: the only failing check is the recovery key; everything about the bytes passes.
	if names["Recovery Key"] {
		t.Error("unpaired drill claimed a recovery key")
	}
	for _, want := range []string{"Directory Unpack", "Required Files", "Token Signing", "Session Secret Restored"} {
		if !names[want] {
			t.Errorf("check %q did not pass: %+v", want, result.Checks)
		}
	}
	if result.Passed {
		t.Error("an unpaired drill passed")
	}

	priv := pair(t, cfg, st)
	pinned, err := backup.LoadRecoveryKey(cfg.DataDir, st)
	if err != nil {
		t.Fatal(err)
	}
	result, err = backup.RunRestoreDrill(context.Background(), payload.ServiceName, payload.AppVersion, payload.Files, payload.Dependencies, payload.VerificationRecipe, pinned)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Passed {
		t.Fatalf("paired drill failed: %+v", result.Checks)
	}
	_ = priv
}

func TestDepositSealsToThePinnedKeyAndRecordsTheReceipt(t *testing.T) {
	cfg, st := instance(t)
	priv := pair(t, cfg, st)
	fake := &fakeStore{}
	rcpt, m, err := backup.DepositBackup(context.Background(), cfg, st, st, fake, "1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	if fake.url != "https://recovery.example.test" || fake.token != "kyrec_live_t" {
		t.Errorf("sent to %s with %s", fake.url, fake.token)
	}
	if m.ServiceName != "KySignOn" || m.RecoveryKeyID != priv.Public().ID() || rcpt.CapsuleID != m.CapsuleID {
		t.Errorf("manifest %+v receipt %+v", m, rcpt)
	}
	if _, files, err := capsule.Open(fake.container, priv, t.TempDir()); err != nil || len(files) < 5 {
		t.Fatalf("what the store holds does not open with the suite key: %v (%d files)", err, len(files))
	}
	last, ok, err := backup.LastDeposit(st)
	if err != nil || !ok || last.CapsuleID != rcpt.CapsuleID {
		t.Errorf("last deposit %+v %v %v", last, ok, err)
	}
}

func TestDepositRequiresAFullPairing(t *testing.T) {
	cfg, st := instance(t)
	fake := &fakeStore{}
	if _, _, err := backup.DepositBackup(context.Background(), cfg, st, st, fake, "1.0.0"); !errors.Is(err, backup.ErrNotPaired) {
		t.Fatalf("unpaired: %v", err)
	}
	priv, _ := recoverykey.Generate()
	if err := backup.StoreRecoveryKey(cfg.DataDir, st, backup.RecoveryKey{Public: priv.Public(), Threshold: 2, TotalShares: 3}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := backup.DepositBackup(context.Background(), cfg, st, st, fake, "1.0.0"); !errors.Is(err, backup.ErrNotPaired) {
		t.Fatalf("key only: %v", err)
	}
	if fake.container != nil {
		t.Error("bytes were sent without a pairing")
	}
}

// The token is the standing credential to the service holding every identity backup. It must
// not sit in the settings table in the clear, and must not decrypt under another key.
func TestRecoveryTokenIsNeverStoredInTheClear(t *testing.T) {
	cfg, st := instance(t)
	pair(t, cfg, st)
	for _, key := range []string{"kyrecovery_token_enc", "kyrecovery_url", "kyrecovery_token"} {
		v, err := st.GetSetting(key)
		if err == nil && strings.Contains(v, "kyrec_live_t") {
			t.Errorf("%s holds the token in the clear", key)
		}
	}
	p, err := backup.LoadPairing(cfg.DataDir, st, cfg.EncryptionKey)
	if err != nil || p.Token != "kyrec_live_t" {
		t.Fatalf("load: %+v %v", p, err)
	}
	other := make([]byte, config.KeyLength)
	if _, err := backup.LoadPairing(cfg.DataDir, st, other); err == nil {
		t.Error("the token decrypted under a different deployment key")
	}
}

func TestStoreRecoveryKeyRefusesASecondKey(t *testing.T) {
	cfg, st := instance(t)
	pair(t, cfg, st)
	other, _ := recoverykey.Generate()
	err := backup.StoreRecoveryKey(cfg.DataDir, st, backup.RecoveryKey{Public: other.Public(), Threshold: 2, TotalShares: 3})
	if err == nil || !errors.Is(err, os.ErrExist) {
		t.Fatalf("re-pair to a different key: %v", err)
	}
}

// recorder answers every request with one canned response and keeps the last request seen.
type recorder struct {
	status int
	body   func(sent []byte) string
	last   *http.Request
	sent   []byte
}

func (r *recorder) RoundTrip(req *http.Request) (*http.Response, error) {
	r.last = req
	r.sent, _ = io.ReadAll(req.Body)
	return &http.Response{StatusCode: r.status, Body: io.NopCloser(strings.NewReader(r.body(r.sent))), Header: http.Header{}}, nil
}

func receiptFor(container []byte, id string) string {
	sum := sha256.Sum256(container)
	return fmt.Sprintf(`{"capsule_id":%q,"digest":%q,"size_bytes":%d,"deposited_at":"2026-09-04T10:00:00Z"}`, id, hex.EncodeToString(sum[:]), len(container))
}

// kyrecovery pins the service name the claim sends and refuses every later deposit whose
// manifest names another, so the claim must carry the same value Seal is given.
func TestClaimPairingSendsTheServiceName(t *testing.T) {
	priv, _ := recoverykey.Generate()
	pub := base64.StdEncoding.EncodeToString(priv.Public().Bytes())
	rec := &recorder{status: http.StatusOK, body: func([]byte) string {
		return fmt.Sprintf(`{"api_token":"tok","recovery_public_key":%q,"threshold":2,"total_shares":3}`, pub)
	}}
	client := backup.NewClientWithTransportForTest(rec)
	res, err := client.ClaimPairing(context.Background(), "https://recovery.example.test", " 123456 ", "KySignOn", "KySignOn")
	if err != nil {
		t.Fatal(err)
	}
	var sent map[string]string
	_ = json.Unmarshal(rec.sent, &sent)
	if sent["service_name"] != "KySignOn" || sent["pairing_code"] != "123456" {
		t.Errorf("claim body %v", sent)
	}
	if res.Key.Public.ID() != priv.Public().ID() || res.APIToken != "tok" {
		t.Errorf("result %+v", res)
	}
}

func TestDepositChecksTheReceiptAgainstTheBytesSent(t *testing.T) {
	container := []byte("kycap/3 bytes")
	ok := backup.NewClientWithTransportForTest(&recorder{status: http.StatusCreated, body: func(sent []byte) string { return receiptFor(sent, "cap-1") }})
	rcpt, err := ok.Deposit(context.Background(), "https://recovery.example.test", "tok", container)
	if err != nil || rcpt.CapsuleID != "cap-1" {
		t.Fatalf("%v %+v", err, rcpt)
	}
	for name, body := range map[string]func([]byte) string{
		"wrong digest":  func([]byte) string { return receiptFor([]byte("other"), "cap-1") },
		"no capsule id": func(sent []byte) string { return receiptFor(sent, "") },
	} {
		c := backup.NewClientWithTransportForTest(&recorder{status: http.StatusCreated, body: body})
		if _, err := c.Deposit(context.Background(), "https://recovery.example.test", "tok", container); !errors.Is(err, backup.ErrRemote) {
			t.Errorf("%s: %v", name, err)
		}
	}
	huge := "<html>" + strings.Repeat("x", 64<<10) + "\x00\x07"
	c := backup.NewClientWithTransportForTest(&recorder{status: http.StatusBadGateway, body: func([]byte) string { return huge }})
	_, err = c.Deposit(context.Background(), "https://recovery.example.test", "tok", container)
	if err == nil || len(err.Error()) > 400 || strings.ContainsAny(err.Error(), "\x00\x07") {
		t.Fatalf("error not bounded: %d bytes", len(fmt.Sprint(err)))
	}
	for _, u := range []string{"http://recovery.example.test", "https://127.0.0.1:8095", "https://10.0.0.5", "https://user:pw@recovery.example.test"} {
		if _, err := ok.Deposit(context.Background(), u, "tok", container); err == nil || errors.Is(err, backup.ErrRemote) {
			t.Errorf("%s: %v", u, err)
		}
	}
}

func TestOutcomeNamesADepositTheStoreHolds(t *testing.T) {
	rcpt := backup.Receipt{CapsuleID: "cap-1", Digest: "abc", SizeBytes: 3}
	m := capsule.Manifest{UnverifiedManifest: capsule.UnverifiedManifest{CapsuleID: "cap-1"}}
	action, outcome, details := backup.Outcome(rcpt, m, fmt.Errorf("%w: cap-1: disk full", backup.ErrReceiptUnrecorded))
	if action != "admin.backup_deposit" || outcome != "success" || !strings.Contains(fmt.Sprint(details["receipt_unrecorded"]), "disk full") {
		t.Errorf("%s %s %v", action, outcome, details)
	}
	_, outcome, details = backup.Outcome(backup.Receipt{}, m, errors.New("deposit rejected (503): "+strings.Repeat("x", 5000)))
	if outcome != "failure" || len(fmt.Sprint(details["error"])) > 300 {
		t.Errorf("%s %v", outcome, details)
	}
}
