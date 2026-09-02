package webauthn

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"testing"
)

const testRPID = "auth.example.com"
const testOrigin = "https://auth.example.com"

// authData builds a 37-byte authenticator data header for rpID with the given flags and
// signature counter. Registration responses append attested credential data after it;
// nothing this package does reads past byte 37, so the tests do not synthesise it.
func authData(rpID string, flags byte, count uint32) []byte {
	h := sha256.Sum256([]byte(rpID))
	b := make([]byte, 37)
	copy(b, h[:])
	b[32] = flags
	binary.BigEndian.PutUint32(b[33:37], count)
	return b
}

func clientDataJSON(t *testing.T, typ, challenge, origin string) []byte {
	t.Helper()
	b, err := json.Marshal(map[string]any{
		"type":        typ,
		"challenge":   challenge,
		"origin":      origin,
		"crossOrigin": false,
	})
	if err != nil {
		t.Fatalf("marshal client data: %v", err)
	}
	return b
}

func testKey(t *testing.T) (*ecdsa.PrivateKey, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	spki, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey: %v", err)
	}
	return key, spki
}

// signAssertion produces the signature a real authenticator would: over the authenticator
// data concatenated with the SHA-256 of the client data JSON.
func signAssertion(t *testing.T, key *ecdsa.PrivateKey, ad, cdj []byte) []byte {
	t.Helper()
	cdHash := sha256.Sum256(cdj)
	digest := sha256.Sum256(append(append([]byte{}, ad...), cdHash[:]...))
	sig, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatalf("SignASN1: %v", err)
	}
	return sig
}

func TestParseAuthenticatorDataFlags(t *testing.T) {
	ad, err := ParseAuthenticatorData(authData(testRPID, FlagUserPresent|FlagUserVerified|FlagBackupEligible|FlagBackupState, 7))
	if err != nil {
		t.Fatalf("ParseAuthenticatorData: %v", err)
	}
	if !ad.UserPresent() || !ad.UserVerified() || !ad.BackupEligible() || !ad.BackupState() {
		t.Fatalf("expected all four flags set, got %#x", ad.Flags)
	}
	if ad.SignCount != 7 {
		t.Fatalf("SignCount = %d, want 7", ad.SignCount)
	}
}

func TestParseAuthenticatorDataRejectsShortInput(t *testing.T) {
	if _, err := ParseAuthenticatorData(make([]byte, 36)); err == nil {
		t.Fatal("expected an error for 36 bytes of authenticator data")
	}
}

func TestVerifyAssertionAcceptsGenuineSignature(t *testing.T) {
	key, spki := testKey(t)
	ad := authData(testRPID, FlagUserPresent|FlagUserVerified, 5)
	cdj := clientDataJSON(t, "webauthn.get", "Q0hBTExFTkdF", testOrigin)

	got, err := VerifyAssertion(AssertionInput{
		AuthenticatorData: ad,
		ClientDataJSON:    cdj,
		Signature:         signAssertion(t, key, ad, cdj),
		PublicKeySPKI:     spki,
		Challenge:         "Q0hBTExFTkdF",
		Origin:            testOrigin,
		RPID:              testRPID,
		StoredSignCount:   4,
	})
	if err != nil {
		t.Fatalf("VerifyAssertion: %v", err)
	}
	if got.SignCount != 5 {
		t.Fatalf("SignCount = %d, want 5", got.SignCount)
	}
}

func TestVerifyAssertionRejects(t *testing.T) {
	key, spki := testKey(t)
	otherKey, _ := testKey(t)

	base := func() AssertionInput {
		ad := authData(testRPID, FlagUserPresent, 5)
		cdj := clientDataJSON(t, "webauthn.get", "Q0hBTExFTkdF", testOrigin)
		return AssertionInput{
			AuthenticatorData: ad,
			ClientDataJSON:    cdj,
			Signature:         signAssertion(t, key, ad, cdj),
			PublicKeySPKI:     spki,
			Challenge:         "Q0hBTExFTkdF",
			Origin:            testOrigin,
			RPID:              testRPID,
			StoredSignCount:   4,
		}
	}

	cases := map[string]func(*AssertionInput){
		"wrong challenge": func(in *AssertionInput) { in.Challenge = "T1RIRVJT" },
		"wrong origin":    func(in *AssertionInput) { in.Origin = "https://evil.example.com" },
		"wrong rp id":     func(in *AssertionInput) { in.RPID = "evil.example.com" },
		"wrong key": func(in *AssertionInput) {
			spki, err := x509.MarshalPKIXPublicKey(&otherKey.PublicKey)
			if err != nil {
				t.Fatalf("MarshalPKIXPublicKey: %v", err)
			}
			in.PublicKeySPKI = spki
		},
		"tampered authenticator data": func(in *AssertionInput) {
			in.AuthenticatorData = authData(testRPID, FlagUserPresent|FlagUserVerified, 5)
		},
		"replayed sign count":  func(in *AssertionInput) { in.StoredSignCount = 5 },
		"regressed sign count": func(in *AssertionInput) { in.StoredSignCount = 9 },
		"user not present": func(in *AssertionInput) {
			ad := authData(testRPID, 0x00, 5)
			in.AuthenticatorData = ad
			in.Signature = signAssertion(t, key, ad, in.ClientDataJSON)
		},
		"wrong ceremony type": func(in *AssertionInput) {
			cdj := clientDataJSON(t, "webauthn.create", "Q0hBTExFTkdF", testOrigin)
			in.ClientDataJSON = cdj
			in.Signature = signAssertion(t, key, in.AuthenticatorData, cdj)
		},
	}

	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			in := base()
			mutate(&in)
			if _, err := VerifyAssertion(in); err == nil {
				t.Fatalf("expected VerifyAssertion to reject %s", name)
			}
		})
	}
}

func TestVerifyAssertionAcceptsBothCountersZero(t *testing.T) {
	key, spki := testKey(t)
	ad := authData(testRPID, FlagUserPresent, 0)
	cdj := clientDataJSON(t, "webauthn.get", "Q0hBTExFTkdF", testOrigin)

	if _, err := VerifyAssertion(AssertionInput{
		AuthenticatorData: ad,
		ClientDataJSON:    cdj,
		Signature:         signAssertion(t, key, ad, cdj),
		PublicKeySPKI:     spki,
		Challenge:         "Q0hBTExFTkdF",
		Origin:            testOrigin,
		RPID:              testRPID,
		StoredSignCount:   0,
	}); err != nil {
		t.Fatalf("an authenticator that never increments its counter must be accepted: %v", err)
	}
}

// TestVerifyAssertionBackupEligibleCounterExemption proves both halves of the fix: a
// backup-eligible (cloud-synced) credential must authenticate even when a sibling device's
// counter fails to advance past the stored value, while a device-bound credential must
// still be rejected in that same situation — that is where clone detection means something.
func TestVerifyAssertionBackupEligibleCounterExemption(t *testing.T) {
	key, spki := testKey(t)
	cdj := clientDataJSON(t, "webauthn.get", "Q0hBTExFTkdF", testOrigin)
	// A sibling device reports a lower counter than the one on record — the normal case
	// for a passkey synced across several devices that each keep their own counter.
	ad := authData(testRPID, FlagUserPresent, 2)

	base := AssertionInput{
		AuthenticatorData: ad,
		ClientDataJSON:    cdj,
		Signature:         signAssertion(t, key, ad, cdj),
		PublicKeySPKI:     spki,
		Challenge:         "Q0hBTExFTkdF",
		Origin:            testOrigin,
		RPID:              testRPID,
		StoredSignCount:   9,
	}

	backupEligible := base
	backupEligible.BackupEligible = true
	if _, err := VerifyAssertion(backupEligible); err != nil {
		t.Fatalf("a backup-eligible credential must authenticate despite a non-advancing counter: %v", err)
	}

	deviceBound := base
	deviceBound.BackupEligible = false
	if _, err := VerifyAssertion(deviceBound); err == nil {
		t.Fatal("a device-bound credential must still be rejected when its counter fails to advance")
	}
}

func TestVerifyRegistrationRequiresUserPresence(t *testing.T) {
	_, spki := testKey(t)
	cdj := clientDataJSON(t, "webauthn.create", "Q0hBTExFTkdF", testOrigin)

	in := RegistrationInput{
		AuthenticatorData: authData(testRPID, FlagUserPresent, 0),
		ClientDataJSON:    cdj,
		PublicKeySPKI:     spki,
		Challenge:         "Q0hBTExFTkdF",
		Origin:            testOrigin,
		RPID:              testRPID,
	}
	if _, err := VerifyRegistration(in); err != nil {
		t.Fatalf("VerifyRegistration: %v", err)
	}

	in.AuthenticatorData = authData(testRPID, 0x00, 0)
	if _, err := VerifyRegistration(in); err == nil {
		t.Fatal("expected registration without the user-present bit to be rejected")
	}
}

func TestVerifyRegistrationRejectsNonES256Key(t *testing.T) {
	cdj := clientDataJSON(t, "webauthn.create", "Q0hBTExFTkdF", testOrigin)
	if _, err := VerifyRegistration(RegistrationInput{
		AuthenticatorData: authData(testRPID, FlagUserPresent, 0),
		ClientDataJSON:    cdj,
		PublicKeySPKI:     []byte("not a key"),
		Challenge:         "Q0hBTExFTkdF",
		Origin:            testOrigin,
		RPID:              testRPID,
	}); err == nil {
		t.Fatal("expected an unparseable public key to be rejected")
	}
}

func TestRPIDFromIssuer(t *testing.T) {
	cases := []struct {
		issuer, rpID, origin string
	}{
		{"https://auth.example.com", "auth.example.com", "https://auth.example.com"},
		{"https://auth.example.com/", "auth.example.com", "https://auth.example.com"},
		{"http://localhost:5867", "localhost", "http://localhost:5867"},
	}
	for _, c := range cases {
		rpID, origin, err := RPIDFromIssuer(c.issuer)
		if err != nil {
			t.Fatalf("RPIDFromIssuer(%q): %v", c.issuer, err)
		}
		if rpID != c.rpID || origin != c.origin {
			t.Fatalf("RPIDFromIssuer(%q) = %q, %q; want %q, %q", c.issuer, rpID, origin, c.rpID, c.origin)
		}
	}

	if _, _, err := RPIDFromIssuer("not a url"); err == nil {
		t.Fatal("expected an error for an issuer URL with no host")
	}
}

func TestVerifyClientDataRejectsBase64Variants(t *testing.T) {
	// The challenge is compared as the exact base64url string the browser echoes. A
	// padded or standard-alphabet variant of the same bytes is a different string and
	// must not be accepted, or a lookup keyed on the challenge could miss.
	cdj := clientDataJSON(t, "webauthn.get", "Q0hBTExFTkdFUw", testOrigin)
	padded := base64.StdEncoding.EncodeToString([]byte("CHALLENGES"))
	if err := VerifyClientData(cdj, "webauthn.get", padded, testOrigin); err == nil {
		t.Fatal("expected a padded challenge encoding to be rejected")
	}
}
