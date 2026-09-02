package api

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
)

// testAuthenticator is a software authenticator good enough to exercise the endpoints.
type testAuthenticator struct {
	key       *ecdsa.PrivateKey
	credID    string
	signCount uint32
}

func newTestAuthenticator(t *testing.T, credID string) *testAuthenticator {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return &testAuthenticator{key: key, credID: credID}
}

func (a *testAuthenticator) spkiB64(t *testing.T) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(&a.key.PublicKey)
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey: %v", err)
	}
	return base64.RawURLEncoding.EncodeToString(der)
}

func (a *testAuthenticator) authData(rpID string, flags byte) []byte {
	h := sha256.Sum256([]byte(rpID))
	b := make([]byte, 37)
	copy(b, h[:])
	b[32] = flags
	binary.BigEndian.PutUint32(b[33:37], a.signCount)
	return b
}

func (a *testAuthenticator) clientData(t *testing.T, typ, challenge, origin string) []byte {
	t.Helper()
	b, err := json.Marshal(map[string]any{"type": typ, "challenge": challenge, "origin": origin, "crossOrigin": false})
	if err != nil {
		t.Fatalf("marshal client data: %v", err)
	}
	return b
}

func (a *testAuthenticator) sign(t *testing.T, ad, cdj []byte) string {
	t.Helper()
	cdHash := sha256.Sum256(cdj)
	digest := sha256.Sum256(append(append([]byte{}, ad...), cdHash[:]...))
	sig, err := ecdsa.SignASN1(rand.Reader, a.key, digest[:])
	if err != nil {
		t.Fatalf("SignASN1: %v", err)
	}
	return base64.RawURLEncoding.EncodeToString(sig)
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// do issues a GET or DELETE with the fixture's session and CSRF credentials.
// stepUpFixture.post already covers POST; the passkey routes also need these two verbs.
func (f *stepUpFixture) do(t *testing.T, method, path, stepUp string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, nil)
	req.AddCookie(f.cookie)
	req.AddCookie(f.csrfCk)
	req.Header.Set("X-CSRF-Token", f.csrf)
	if stepUp != "" {
		req.Header.Set(StepUpHeader, stepUp)
	}
	w := httptest.NewRecorder()
	f.srv.httpServer.Handler.ServeHTTP(w, req)
	return w
}

// anonPost issues an unauthenticated JSON POST with a self-consistent CSRF pair, which is
// all the double-submit check requires of a caller that holds no session.
func anonPost(t *testing.T, srv *Server, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	csrf := "test-csrf-" + uuid.New().String()
	req.AddCookie(&http.Cookie{Name: "kysignon_csrf", Value: csrf})
	req.Header.Set("X-CSRF-Token", csrf)
	w := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(w, req)
	return w
}

func TestPasskeyRegistrationRequiresStepUp(t *testing.T) {
	f, cleanup := newStepUpFixture(t)
	defer cleanup()

	rec := f.post(t, "/api/user/passkeys/register/begin", map[string]string{"name": "KyAuth"}, "")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("begin without a step-up grant returned %d, want 403: %s", rec.Code, rec.Body.String())
	}
}

func TestPasskeyRegistrationRoundTrip(t *testing.T) {
	f, cleanup := newStepUpFixture(t)
	defer cleanup()

	a := newTestAuthenticator(t, "Y3JlZC1vbmU")

	rec := f.post(t, "/api/user/passkeys/register/begin", map[string]string{"name": "KyAuth on Pixel"}, f.grant(t))
	if rec.Code != http.StatusOK {
		t.Fatalf("begin returned %d: %s", rec.Code, rec.Body.String())
	}

	var begun struct {
		Challenge string `json:"challenge"`
		RPID      string `json:"rpId"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &begun); err != nil {
		t.Fatalf("decode begin response: %v", err)
	}
	if begun.Challenge == "" || begun.RPID != "localhost" {
		t.Fatalf("unexpected begin response: %+v", begun)
	}

	ad := a.authData(begun.RPID, 0x01|0x04|0x40)
	cdj := a.clientData(t, "webauthn.create", begun.Challenge, "http://localhost:5867")
	rec = f.post(t, "/api/user/passkeys/register/finish", map[string]string{
		"credentialId":      a.credID,
		"authenticatorData": b64(ad),
		"clientDataJSON":    b64(cdj),
		"publicKey":         a.spkiB64(t),
		"name":              "KyAuth on Pixel",
	}, f.grant(t))
	if rec.Code != http.StatusOK {
		t.Fatalf("finish returned %d: %s", rec.Code, rec.Body.String())
	}

	creds, err := f.store.ListUserWebAuthnCredentials(f.user.ID)
	if err != nil || len(creds) != 1 {
		t.Fatalf("expected one stored credential, got %d (%v)", len(creds), err)
	}
	if creds[0].Name != "KyAuth on Pixel" {
		t.Fatalf("credential name = %q", creds[0].Name)
	}
}

func TestPasskeyRegistrationRejectsForeignOrigin(t *testing.T) {
	f, cleanup := newStepUpFixture(t)
	defer cleanup()

	a := newTestAuthenticator(t, "Y3JlZC1ldmls")

	rec := f.post(t, "/api/user/passkeys/register/begin", map[string]string{"name": "evil"}, f.grant(t))
	var begun struct {
		Challenge string `json:"challenge"`
		RPID      string `json:"rpId"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &begun); err != nil {
		t.Fatalf("decode begin response: %v", err)
	}

	ad := a.authData(begun.RPID, 0x01)
	cdj := a.clientData(t, "webauthn.create", begun.Challenge, "https://evil.example.com")
	rec = f.post(t, "/api/user/passkeys/register/finish", map[string]string{
		"credentialId":      a.credID,
		"authenticatorData": b64(ad),
		"clientDataJSON":    b64(cdj),
		"publicKey":         a.spkiB64(t),
		"name":              "evil",
	}, f.grant(t))

	if rec.Code == http.StatusOK {
		t.Fatal("a ceremony completed at another origin must not enrol a credential")
	}
}
