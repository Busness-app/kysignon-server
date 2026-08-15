package crypto

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestAESGCMEncryption(t *testing.T) {
	key, err := GenerateRandomBytes(32)
	if err != nil {
		t.Fatalf("GenerateRandomBytes failed: %v", err)
	}

	secretMessage := "my-super-secret-totp-seed-12345"
	encrypted, err := EncryptAESGCM(key, []byte(secretMessage))
	if err != nil {
		t.Fatalf("EncryptAESGCM failed: %v", err)
	}

	decrypted, err := DecryptAESGCM(key, encrypted)
	if err != nil {
		t.Fatalf("DecryptAESGCM failed: %v", err)
	}

	if string(decrypted) != secretMessage {
		t.Fatalf("decrypted mismatch: got %s, want %s", string(decrypted), secretMessage)
	}
}

func TestHMACSHA256(t *testing.T) {
	key := []byte("shared-sync-webhook-secret-key-32b")
	data := []byte(`{"event":"user.created","username":"alice"}`)

	sig := SignHMACSHA256(key, data)
	if !VerifyHMACSHA256(key, data, sig) {
		t.Fatal("HMAC verification failed")
	}

	if VerifyHMACSHA256(key, []byte(`{"tampered":true}`), sig) {
		t.Fatal("HMAC verification should have failed for tampered data")
	}
}

func TestRSAKeyAndJWTSigning(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "kysignon-key-test-*")
	if err != nil {
		t.Fatalf("MkdirTemp failed: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	keyPath := filepath.Join(tmpDir, "test_jwt.key")
	km, err := LoadOrCreateRSAKey(keyPath)
	if err != nil {
		t.Fatalf("LoadOrCreateRSAKey failed: %v", err)
	}

	jwks := km.GetJWKS()
	if len(jwks.Keys) != 1 || jwks.Keys[0].Alg != "RS256" {
		t.Fatalf("unexpected JWKS output: %+v", jwks)
	}

	claims := map[string]any{
		"sub": "user-uuid-123",
		"iss": "http://localhost:5867",
		"exp": time.Now().Add(1 * time.Hour).Unix(),
	}

	tokenStr, err := km.SignJWT(claims)
	if err != nil {
		t.Fatalf("SignJWT failed: %v", err)
	}

	parsedClaims, err := km.VerifyJWT(tokenStr)
	if err != nil {
		t.Fatalf("VerifyJWT failed: %v", err)
	}

	if parsedClaims["sub"] != "user-uuid-123" {
		t.Fatalf("claims sub mismatch: got %v", parsedClaims["sub"])
	}
}
