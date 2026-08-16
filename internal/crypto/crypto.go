package crypto

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"strings"
	"time"
)

// GenerateRandomBytes returns cryptographically secure random bytes.
func GenerateRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}

// GenerateRandomHex returns a hex-encoded random string.
func GenerateRandomHex(n int) (string, error) {
	b, err := GenerateRandomBytes(n)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// GenerateRandomAlphanumeric returns an alphanumeric code of specified length.
func GenerateRandomAlphanumeric(length int) string {
	const charset = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	b := make([]byte, length)
	_, _ = rand.Read(b)
	for i := range b {
		b[i] = charset[int(b[i])%len(charset)]
	}
	return string(b)
}

// GenerateRandomPIN returns a numeric PIN of specified digits.
func GenerateRandomPIN(digits int) string {
	const digitsCharset = "0123456789"
	b := make([]byte, digits)
	_, _ = rand.Read(b)
	for i := range b {
		b[i] = digitsCharset[int(b[i])%len(digitsCharset)]
	}
	return string(b)
}

// HashSHA256 returns hex encoded SHA-256 hash of the input.
func HashSHA256(input string) string {
	sum := sha256.Sum256([]byte(input))
	return hex.EncodeToString(sum[:])
}

// SignHMACSHA256 produces a hex-encoded HMAC-SHA256 signature.
func SignHMACSHA256(key []byte, data []byte) string {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return hex.EncodeToString(h.Sum(nil))
}

// VerifyHMACSHA256 verifies HMAC-SHA256 in constant time.
func VerifyHMACSHA256(key []byte, data []byte, expectedHex string) bool {
	sig, err := hex.DecodeString(expectedHex)
	if err != nil {
		return false
	}
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return hmac.Equal(h.Sum(nil), sig)
}

// EncryptAESGCM encrypts plaintext using AES-256-GCM with a prepended nonce.
func EncryptAESGCM(key []byte, plaintext []byte) (string, error) {
	if len(key) != 32 {
		return "", errors.New("AES-256 key must be exactly 32 bytes")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// DecryptAESGCM decrypts base64 encoded ciphertext using AES-256-GCM.
func DecryptAESGCM(key []byte, ciphertextBase64 string) ([]byte, error) {
	if len(key) != 32 {
		return nil, errors.New("AES-256 key must be exactly 32 bytes")
	}
	data, err := base64.StdEncoding.DecodeString(ciphertextBase64)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, errors.New("malformed ciphertext")
	}
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

// decodeBase64Any decodes standard, raw-standard, or raw-URL base64.
// Mobile SDKs disagree about padding and alphabet; the server should not care.
func decodeBase64Any(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	for _, enc := range []*base64.Encoding{
		base64.StdEncoding,
		base64.RawStdEncoding,
		base64.URLEncoding,
		base64.RawURLEncoding,
	} {
		if b, err := enc.DecodeString(s); err == nil {
			return b, nil
		}
	}
	return nil, errors.New("value is not valid base64")
}

// ParseP256PublicKey parses a base64 P-256 public key in either SPKI DER or uncompressed
// SEC1 point form. The point is validated as on-curve and non-identity; an invalid encoding
// is always an error and never a usable key.
func ParseP256PublicKey(encoded string) (*ecdsa.PublicKey, error) {
	raw, err := decodeBase64Any(encoded)
	if err != nil {
		return nil, err
	}

	if parsed, err := x509.ParsePKIXPublicKey(raw); err == nil {
		pub, ok := parsed.(*ecdsa.PublicKey)
		if !ok || pub.Curve != elliptic.P256() {
			return nil, errors.New("public key is not P-256")
		}
		return pub, nil
	}

	// crypto/ecdh rejects off-curve points, the identity, and wrong lengths.
	if _, err := ecdh.P256().NewPublicKey(raw); err != nil {
		return nil, fmt.Errorf("invalid P-256 public key: %w", err)
	}

	return &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     new(big.Int).SetBytes(raw[1:33]),
		Y:     new(big.Int).SetBytes(raw[33:65]),
	}, nil
}

// VerifyECDSAP256 verifies an ASN.1 DER ECDSA signature over SHA-256(message) against a
// base64-encoded P-256 public key. Any parse failure is a verification failure.
func VerifyECDSAP256(publicKey string, message []byte, signature string) bool {
	pub, err := ParseP256PublicKey(publicKey)
	if err != nil {
		return false
	}
	sig, err := decodeBase64Any(signature)
	if err != nil {
		return false
	}
	digest := sha256.Sum256(message)
	return ecdsa.VerifyASN1(pub, digest[:], sig)
}

// JWTKeyManager manages RSA keys for OIDC ID Token signing and JWKS.
type JWTKeyManager struct {
	PrivateKey *rsa.PrivateKey
	PublicKey  *rsa.PublicKey
	KeyID      string
}

// LoadOrCreateRSAKey loads an RSA private key from disk or creates a new 2048-bit key.
func LoadOrCreateRSAKey(keyPath string) (*JWTKeyManager, error) {
	var privKey *rsa.PrivateKey

	if data, err := os.ReadFile(keyPath); err == nil {
		block, _ := pem.Decode(data)
		if block != nil {
			var parsedKey any
			var parseErr error
			if block.Type == "RSA PRIVATE KEY" {
				parsedKey, parseErr = x509.ParsePKCS1PrivateKey(block.Bytes)
			} else {
				parsedKey, parseErr = x509.ParsePKCS8PrivateKey(block.Bytes)
			}
			if parseErr == nil {
				if k, ok := parsedKey.(*rsa.PrivateKey); ok {
					privKey = k
				}
			}
		}
	}

	if privKey == nil {
		var err error
		privKey, err = rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, fmt.Errorf("failed to generate RSA key: %w", err)
		}
		der := x509.MarshalPKCS1PrivateKey(privKey)
		pemData := pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: der,
		})
		_ = os.WriteFile(keyPath, pemData, 0600)
	}

	pubKey := &privKey.PublicKey
	pubDER, _ := x509.MarshalPKIXPublicKey(pubKey)
	kid := hex.EncodeToString(sha256.New().Sum(pubDER)[:8])

	return &JWTKeyManager{
		PrivateKey: privKey,
		PublicKey:  pubKey,
		KeyID:      kid,
	}, nil
}

// JWK represents an RFC 7517 JSON Web Key.
type JWK struct {
	Kty string `json:"kty"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
}

// JWKS represents a JSON Web Key Set.
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// GetJWKS returns the public keys in JWKS format.
func (m *JWTKeyManager) GetJWKS() JWKS {
	nBytes := m.PublicKey.N.Bytes()
	eBytes := big.NewInt(int64(m.PublicKey.E)).Bytes()

	return JWKS{
		Keys: []JWK{
			{
				Kty: "RSA",
				Use: "sig",
				Alg: "RS256",
				Kid: m.KeyID,
				N:   base64.RawURLEncoding.EncodeToString(nBytes),
				E:   base64.RawURLEncoding.EncodeToString(eBytes),
			},
		},
	}
}

// SignJWT creates an RS256 signed JWT string with the given claims.
func (m *JWTKeyManager) SignJWT(claims map[string]any) (string, error) {
	header := map[string]any{
		"typ": "JWT",
		"alg": "RS256",
		"kid": m.KeyID,
	}

	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}

	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	claimsB64 := base64.RawURLEncoding.EncodeToString(claimsJSON)

	signingInput := headerB64 + "." + claimsB64
	hashed := sha256.Sum256([]byte(signingInput))

	sig, err := rsa.SignPKCS1v15(rand.Reader, m.PrivateKey, crypto.SHA256, hashed[:])
	if err != nil {
		return "", fmt.Errorf("failed to sign JWT: %w", err)
	}

	sigB64 := base64.RawURLEncoding.EncodeToString(sig)
	return signingInput + "." + sigB64, nil
}

// VerifyJWT validates the signature and expiration of an RS256 signed JWT.
func (m *JWTKeyManager) VerifyJWT(tokenString string) (map[string]any, error) {
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return nil, errors.New("invalid token format")
	}

	signingInput := parts[0] + "." + parts[1]
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, errors.New("invalid signature encoding")
	}

	hashed := sha256.Sum256([]byte(signingInput))
	if err := rsa.VerifyPKCS1v15(m.PublicKey, crypto.SHA256, hashed[:], sig); err != nil {
		return nil, errors.New("invalid token signature")
	}

	claimsJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, errors.New("invalid claims encoding")
	}

	var claims map[string]any
	if err := json.Unmarshal(claimsJSON, &claims); err != nil {
		return nil, errors.New("invalid claims json")
	}

	if exp, ok := claims["exp"].(float64); ok {
		if time.Now().Unix() > int64(exp) {
			return nil, errors.New("token expired")
		}
	}

	return claims, nil
}
