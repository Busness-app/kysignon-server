package mfa

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/Yoshiofthewire/kysignon-server/internal/crypto"
	"github.com/Yoshiofthewire/kysignon-server/internal/store"
	"github.com/google/uuid"
)

type Engine struct {
	store         *store.Store
	encryptionKey []byte
}

func NewEngine(s *store.Store, encryptionKey []byte) *Engine {
	return &Engine{
		store:         s,
		encryptionKey: encryptionKey,
	}
}

// GenerateTOTPSecret generates a random 20-byte base32 TOTP secret and returns an otpauth URL.
func (e *Engine) GenerateTOTPSecret(username, issuer string) (secretBase32, otpAuthURL string, err error) {
	b, err := crypto.GenerateRandomBytes(20)
	if err != nil {
		return "", "", err
	}
	secretBase32 = base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b)
	if issuer == "" {
		issuer = "KySignOn"
	}

	uri := fmt.Sprintf("otpauth://totp/%s:%s?secret=%s&issuer=%s&algorithm=SHA1&digits=6&period=30",
		url.PathEscape(issuer),
		url.PathEscape(username),
		secretBase32,
		url.QueryEscape(issuer),
	)

	return secretBase32, uri, nil
}

// ValidateTOTP verifies a 6-digit TOTP code against a base32 secret with a +/- 1 step grace window.
func ValidateTOTP(secretBase32, code string) bool {
	secret, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(strings.TrimSpace(secretBase32)))
	if err != nil {
		return false
	}

	timeStep := int64(30)
	now := time.Now().Unix()
	currentCounter := now / timeStep

	for i := int64(-1); i <= 1; i++ {
		counter := currentCounter + i
		expected := calculateTOTPCode(secret, counter)
		if expected == strings.TrimSpace(code) {
			return true
		}
	}
	return false
}

func calculateTOTPCode(secret []byte, counter int64) string {
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, uint64(counter))

	h := hmac.New(sha1.New, secret)
	h.Write(buf)
	sum := h.Sum(nil)

	offset := sum[len(sum)-1] & 0x0F
	truncated := binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7FFFFFFF
	codeInt := truncated % 1000000

	return fmt.Sprintf("%06d", codeInt)
}

// SaveUserTOTP encrypts and saves a user's TOTP secret.
func (e *Engine) SaveUserTOTP(userID, secretBase32 string) error {
	encrypted, err := crypto.EncryptAESGCM(e.encryptionKey, []byte(secretBase32))
	if err != nil {
		return fmt.Errorf("failed to encrypt TOTP secret: %w", err)
	}

	method := &store.MFAMethod{
		ID:              uuid.New().String(),
		UserID:          userID,
		MethodType:      "totp",
		EncryptedSecret: encrypted,
		IsPrimary:       true,
	}

	return e.store.SetMFAMethod(method)
}

// VerifyUserTOTP verifies a TOTP code for an enrolled user.
func (e *Engine) VerifyUserTOTP(userID, code string) (bool, error) {
	method, err := e.store.GetMFAMethod(userID, "totp")
	if err != nil {
		return false, err
	}
	if method == nil || method.EncryptedSecret == "" {
		return false, errors.New("TOTP not enrolled for this user")
	}

	decrypted, err := crypto.DecryptAESGCM(e.encryptionKey, method.EncryptedSecret)
	if err != nil {
		return false, fmt.Errorf("failed to decrypt TOTP secret: %w", err)
	}

	return ValidateTOTP(string(decrypted), code), nil
}

// GenerateRecoveryCodes creates 8 one-time recovery codes for a user.
func (e *Engine) GenerateRecoveryCodes(userID string) ([]string, error) {
	var plainCodes []string
	var recoveryCodes []store.RecoveryCode

	for i := 0; i < 8; i++ {
		code := fmt.Sprintf("%s-%s", crypto.GenerateRandomAlphanumeric(4), crypto.GenerateRandomAlphanumeric(4))
		plainCodes = append(plainCodes, code)
		recoveryCodes = append(recoveryCodes, store.RecoveryCode{
			ID:       uuid.New().String(),
			UserID:   userID,
			CodeHash: crypto.HashSHA256(strings.ToUpper(strings.ReplaceAll(code, "-", ""))),
		})
	}

	if err := e.store.SaveRecoveryCodes(recoveryCodes); err != nil {
		return nil, err
	}

	return plainCodes, nil
}

// VerifyAndConsumeRecoveryCode validates and consumes a recovery code.
func (e *Engine) VerifyAndConsumeRecoveryCode(userID, code string) (bool, error) {
	normalized := strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(code), "-", ""))
	codeHash := crypto.HashSHA256(normalized)

	codes, err := e.store.GetValidRecoveryCodes(userID)
	if err != nil {
		return false, err
	}

	for _, c := range codes {
		if c.CodeHash == codeHash {
			_ = e.store.MarkRecoveryCodeUsed(c.ID)
			return true, nil
		}
	}
	return false, nil
}

// GenerateDevicePairingToken generates a 90s ephemeral PIN & token for registering a native mobile device.
func (e *Engine) GenerateDevicePairingToken(userID string) (token string, pin string, expiresAt time.Time, err error) {
	rawToken, err := crypto.GenerateRandomHex(24)
	if err != nil {
		return "", "", time.Time{}, err
	}

	pin = crypto.GenerateRandomPIN(6)
	tokenHash := crypto.HashSHA256(rawToken)
	expiresAt = time.Now().UTC().Add(90 * time.Second)

	item := &store.DevicePairingToken{
		ID:        uuid.New().String(),
		UserID:    userID,
		TokenHash: tokenHash,
		PINCode:   pin,
		ExpiresAt: expiresAt,
	}

	if err := e.store.CreateDevicePairingToken(item); err != nil {
		return "", "", time.Time{}, err
	}

	return rawToken, pin, expiresAt, nil
}

type NativeDeviceRegisterRequest struct {
	PairingToken     string `json:"pairingToken,omitempty"`
	PINCode          string `json:"pinCode,omitempty"`
	DeviceName       string `json:"deviceName"`
	DeviceIdentifier string `json:"deviceIdentifier"`
	PublicKey        string `json:"publicKey,omitempty"`
	PushToken        string `json:"pushToken,omitempty"`
}

// RegisterNativeDevice registers a device presented with a valid 90s pairing token or PIN.
func (e *Engine) RegisterNativeDevice(req *NativeDeviceRegisterRequest) (*store.NativeDevice, error) {
	var validToken *store.DevicePairingToken
	var err error

	if req.PairingToken != "" {
		tokenHash := crypto.HashSHA256(req.PairingToken)
		validToken, err = e.store.GetValidDevicePairingToken(tokenHash)
	} else if req.PINCode != "" {
		validToken, err = e.store.GetValidDevicePairingTokenByPIN(req.PINCode)
	} else {
		return nil, errors.New("pairingToken or pinCode is required")
	}

	if err != nil {
		return nil, err
	}
	if validToken == nil {
		return nil, errors.New("invalid or expired pairing token")
	}

	if err := e.store.MarkDevicePairingTokenUsed(validToken.ID); err != nil {
		return nil, err
	}

	name := req.DeviceName
	if name == "" {
		name = "KySecurity Authenticator Device"
	}

	device := &store.NativeDevice{
		ID:               uuid.New().String(),
		UserID:           validToken.UserID,
		DeviceName:       name,
		DeviceIdentifier: req.DeviceIdentifier,
		PublicKey:        req.PublicKey,
		PushToken:        req.PushToken,
		IsMFAApprover:    true, // Enrolled devices are default approvers
	}

	if err := e.store.UpsertNativeDevice(device); err != nil {
		return nil, err
	}

	// Also record push MFA method for user
	_ = e.store.SetMFAMethod(&store.MFAMethod{
		ID:         uuid.New().String(),
		UserID:     validToken.UserID,
		MethodType: "push",
		IsPrimary:  false,
	})

	return device, nil
}

// CreatePushChallenge creates a push challenge with a 2-digit match and 3 decoys.
func (e *Engine) CreatePushChallenge(userID string) (*store.MFAChallenge, error) {
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	matchNum := int(b[0]%90) + 10 // 10-99
	matchDigits := strconv.Itoa(matchNum)

	// Generate 3 unique decoys
	decoysMap := map[int]bool{matchNum: true}
	var decoys []string
	for idx := 1; len(decoys) < 3; idx++ {
		decoyNum := int(b[idx%4]%90) + 10
		if !decoysMap[decoyNum] {
			decoysMap[decoyNum] = true
			decoys = append(decoys, strconv.Itoa(decoyNum))
		}
		_, _ = rand.Read(b)
	}

	decoysJSON, _ := json.Marshal(decoys)

	challenge := &store.MFAChallenge{
		ID:              uuid.New().String(),
		UserID:          userID,
		MethodType:      "push",
		MatchDigits:     matchDigits,
		DecoyDigitsJSON: string(decoysJSON),
		Status:          "pending",
		ExpiresAt:       time.Now().UTC().Add(5 * time.Minute),
	}

	if err := e.store.CreateMFAChallenge(challenge); err != nil {
		return nil, err
	}

	return challenge, nil
}

// RespondPushChallenge processes the match number submitted by a paired mobile client.
func (e *Engine) RespondPushChallenge(challengeID, selectedDigits string, approve bool) (bool, error) {
	ch, err := e.store.GetMFAChallenge(challengeID)
	if err != nil {
		return false, err
	}
	if ch == nil {
		return false, errors.New("challenge not found")
	}

	if ch.Status != "pending" {
		return false, errors.New("challenge is no longer pending")
	}

	if time.Now().UTC().After(ch.ExpiresAt) {
		_ = e.store.UpdateMFAChallengeStatus(ch.ID, "expired")
		return false, errors.New("challenge expired")
	}

	if !approve || selectedDigits != ch.MatchDigits {
		_ = e.store.UpdateMFAChallengeStatus(ch.ID, "denied")
		return false, nil
	}

	_ = e.store.UpdateMFAChallengeStatus(ch.ID, "approved")
	return true, nil
}

// CheckPushChallenge checks the current status of a push challenge.
func (e *Engine) CheckPushChallenge(challengeID string) (status string, err error) {
	ch, err := e.store.GetMFAChallenge(challengeID)
	if err != nil {
		return "", err
	}
	if ch == nil {
		return "", errors.New("challenge not found")
	}

	if ch.Status == "pending" && time.Now().UTC().After(ch.ExpiresAt) {
		_ = e.store.UpdateMFAChallengeStatus(ch.ID, "expired")
		return "expired", nil
	}

	return ch.Status, nil
}
