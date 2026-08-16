package mfa

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"testing"
	"time"

	"github.com/Yoshiofthewire/kysignon-server/internal/crypto"
	"github.com/Yoshiofthewire/kysignon-server/internal/store"
	"github.com/google/uuid"
)

func mfaUser(t *testing.T, db *store.Store) *store.User {
	t.Helper()
	u := &store.User{
		ID: uuid.New().String(), Username: "u" + uuid.New().String()[:8],
		DisplayName: "U", Email: uuid.New().String()[:8] + "@x.test",
		PasswordHash: "x", Role: "user", Status: "active",
	}
	if err := db.CreateUser(u); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	return u
}

func signingKey(t *testing.T) (*ecdsa.PrivateKey, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub := elliptic.Marshal(elliptic.P256(), key.PublicKey.X, key.PublicKey.Y)
	return key, base64.StdEncoding.EncodeToString(pub)
}

// currentTOTPCode computes the code a correctly configured authenticator would show now.
func currentTOTPCode(t *testing.T, secretBase32 string) string {
	t.Helper()
	secret, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secretBase32)
	if err != nil {
		t.Fatal(err)
	}
	return calculateTOTPCode(secret, time.Now().Unix()/30)
}

func sign(t *testing.T, key *ecdsa.PrivateKey, msg []byte) string {
	t.Helper()
	digest := sha256.Sum256(msg)
	sig, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(sig)
}

// A device with no usable key cannot ever approve a push, but registering one still
// enrols push MFA. That combination locks the user out of every future login.
func TestDeviceWithoutPublicKeyIsRejected(t *testing.T) {
	e, db, _, cleanup := setupTestMFAEngine(t)
	defer cleanup()
	u := mfaUser(t, db)

	token, _, _, err := e.GenerateDevicePairingToken(u.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.RegisterNativeDevice(&NativeDeviceRegisterRequest{
		PairingToken: token, DeviceName: "no-key", DeviceIdentifier: "dev-1",
	}); err == nil {
		t.Error("a device with no public key was paired and made an MFA approver")
	}

	if methods, _ := db.ListUserMFAMethods(u.ID); len(methods) != 0 {
		t.Errorf("push MFA was enrolled for a device that cannot sign: %d method(s)", len(methods))
	}
}

func TestDeviceWithMalformedPublicKeyIsRejected(t *testing.T) {
	e, db, _, cleanup := setupTestMFAEngine(t)
	defer cleanup()
	u := mfaUser(t, db)

	token, _, _, err := e.GenerateDevicePairingToken(u.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.RegisterNativeDevice(&NativeDeviceRegisterRequest{
		PairingToken: token, DeviceName: "junk-key", DeviceIdentifier: "dev-2",
		PublicKey: "not-a-real-key",
	}); err == nil {
		t.Error("a device with an unparseable public key was paired")
	}
}

func TestDeviceWithValidKeyPairsAndCanApprove(t *testing.T) {
	e, db, _, cleanup := setupTestMFAEngine(t)
	defer cleanup()
	u := mfaUser(t, db)

	key, pub := signingKey(t)
	token, _, _, err := e.GenerateDevicePairingToken(u.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.RegisterNativeDevice(&NativeDeviceRegisterRequest{
		PairingToken: token, DeviceName: "phone", DeviceIdentifier: "dev-3", PublicKey: pub,
	}); err != nil {
		t.Fatalf("a device with a valid P-256 key was rejected: %v", err)
	}

	ch, err := e.CreatePushChallenge(u.ID)
	if err != nil {
		t.Fatal(err)
	}
	sig := sign(t, key, PushResponseMessage(ch.ID, true, ch.MatchDigits))
	approved, _, err := e.RespondPushChallenge(ch.ID, ch.MatchDigits, true, sig)
	if err != nil || !approved {
		t.Errorf("a correctly signed approval failed: approved=%v err=%v", approved, err)
	}
}

// Regenerating recovery codes is what a user does after a leak. It must revoke the old set.
func TestRegeneratingRecoveryCodesRevokesTheOldSet(t *testing.T) {
	e, db, _, cleanup := setupTestMFAEngine(t)
	defer cleanup()
	u := mfaUser(t, db)

	first, err := e.GenerateRecoveryCodes(u.ID)
	if err != nil {
		t.Fatal(err)
	}
	second, err := e.GenerateRecoveryCodes(u.ID)
	if err != nil {
		t.Fatal(err)
	}

	if ok, _ := e.VerifyAndConsumeRecoveryCode(u.ID, first[0]); ok {
		t.Error("a recovery code from the previous set still works after regeneration")
	}
	if ok, _ := e.VerifyAndConsumeRecoveryCode(u.ID, second[0]); !ok {
		t.Error("a freshly generated recovery code did not work")
	}
	if codes, _ := db.GetValidRecoveryCodes(u.ID); len(codes) != 7 {
		t.Errorf("expected 7 unused codes from the current set, got %d", len(codes))
	}
}

func TestRecoveryCodeIsSingleUse(t *testing.T) {
	e, db, _, cleanup := setupTestMFAEngine(t)
	defer cleanup()
	u := mfaUser(t, db)

	codes, err := e.GenerateRecoveryCodes(u.ID)
	if err != nil {
		t.Fatal(err)
	}
	if ok, _ := e.VerifyAndConsumeRecoveryCode(u.ID, codes[0]); !ok {
		t.Fatal("first use of a recovery code failed")
	}
	if ok, _ := e.VerifyAndConsumeRecoveryCode(u.ID, codes[0]); ok {
		t.Error("a recovery code was accepted twice")
	}
}

// RFC 6238 §5.2: a TOTP value must not be accepted twice.
func TestTOTPCodeCannotBeReplayed(t *testing.T) {
	e, db, _, cleanup := setupTestMFAEngine(t)
	defer cleanup()
	u := mfaUser(t, db)

	secret, _, err := e.GenerateTOTPSecret(u.Username, "KySignOn")
	if err != nil {
		t.Fatal(err)
	}
	if err := e.SaveUserTOTP(u.ID, secret); err != nil {
		t.Fatal(err)
	}

	code := currentTOTPCode(t, secret)
	ok, err := e.VerifyUserTOTP(u.ID, code)
	if err != nil || !ok {
		t.Fatalf("a valid TOTP code was rejected: ok=%v err=%v", ok, err)
	}
	if ok, _ := e.VerifyUserTOTP(u.ID, code); ok {
		t.Error("the same TOTP code was accepted a second time")
	}
}

// A pairing PIN is a 6-digit secret. Storing it in the clear means a database read is a
// pairing capability, and matching it across all users widens the search space to whoever
// happens to be pairing right now.
func TestPairingPINIsHashedAndScopedToItsUser(t *testing.T) {
	e, db, _, cleanup := setupTestMFAEngine(t)
	defer cleanup()
	alice := mfaUser(t, db)
	bob := mfaUser(t, db)

	_, alicePIN, _, err := e.GenerateDevicePairingToken(alice.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, bobPIN, _, err := e.GenerateDevicePairingToken(bob.ID); err != nil {
		t.Fatal(err)
	} else if bobPIN == alicePIN {
		t.Skip("PIN collision between the two users, rerun")
	}

	stored, err := db.GetDevicePairingTokenByUserPIN(alice.ID, crypto.HashSHA256(alicePIN))
	if err != nil || stored == nil {
		t.Fatalf("alice could not redeem her own PIN: %v", err)
	}
	if stored.UserID != alice.ID {
		t.Errorf("PIN resolved to user %s, want %s", stored.UserID, alice.ID)
	}
	if stored.PINHash == alicePIN {
		t.Error("the pairing PIN is stored in plaintext")
	}

	// Scoping is what stops any live PIN in the deployment matching any pairing attempt.
	if other, _ := db.GetDevicePairingTokenByUserPIN(bob.ID, crypto.HashSHA256(alicePIN)); other != nil {
		t.Error("alice's PIN was redeemable against bob's account")
	}
}

// One MFA token must not fund unlimited second-factor guesses.
func TestMFATokenIsSpentAfterTooManyFailures(t *testing.T) {
	e, db, _, cleanup := setupTestMFAEngine(t)
	defer cleanup()
	u := mfaUser(t, db)

	secret, _, _ := e.GenerateTOTPSecret(u.Username, "KySignOn")
	if err := e.SaveUserTOTP(u.ID, secret); err != nil {
		t.Fatal(err)
	}
	raw, err := e.IssueMFAToken(u.ID, "")
	if err != nil {
		t.Fatal(err)
	}

	for i := 0; i < MaxMFAAttempts+1; i++ {
		token, err := e.ValidateMFAToken(raw)
		if err != nil {
			break
		}
		if _, err := e.RegisterMFAFailure(token.ID); err != nil {
			t.Fatal(err)
		}
	}

	if _, err := e.ValidateMFAToken(raw); err == nil {
		t.Errorf("the MFA token survived %d failed attempts", MaxMFAAttempts+1)
	}
}

func TestMFATokenSurvivesAFewFailures(t *testing.T) {
	e, db, _, cleanup := setupTestMFAEngine(t)
	defer cleanup()
	u := mfaUser(t, db)

	raw, err := e.IssueMFAToken(u.ID, "")
	if err != nil {
		t.Fatal(err)
	}
	token, err := e.ValidateMFAToken(raw)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.RegisterMFAFailure(token.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := e.ValidateMFAToken(raw); err != nil {
		t.Errorf("a single mistyped code invalidated the login attempt: %v", err)
	}
}

func TestExpiredPairingTokenIsRejected(t *testing.T) {
	e, db, _, cleanup := setupTestMFAEngine(t)
	defer cleanup()
	u := mfaUser(t, db)

	_, pub := signingKey(t)
	token, _, _, err := e.GenerateDevicePairingToken(u.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.ExpireDevicePairingTokens(u.ID, time.Now().UTC().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := e.RegisterNativeDevice(&NativeDeviceRegisterRequest{
		PairingToken: token, DeviceName: "late", DeviceIdentifier: "dev-late", PublicKey: pub,
	}); err == nil {
		t.Error("an expired pairing token was accepted")
	}
}
