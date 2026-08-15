package mfa

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/Yoshiofthewire/kysignon-server/internal/crypto"
	"github.com/Yoshiofthewire/kysignon-server/internal/store"
)

func setupTestMFAEngine(t *testing.T) (*Engine, *store.Store, *store.User, func()) {
	tmpDir, err := os.MkdirTemp("", "kysignon-mfa-test-*")
	if err != nil {
		t.Fatalf("MkdirTemp failed: %v", err)
	}

	dbPath := filepath.Join(tmpDir, "test.db")
	dbStore, err := store.New(dbPath)
	if err != nil {
		t.Fatalf("store.New failed: %v", err)
	}

	encKey, _ := crypto.GenerateRandomBytes(32)
	engine := NewEngine(dbStore, encKey)

	user := &store.User{
		ID:           uuid.New().String(),
		Username:     "alice",
		DisplayName:  "Alice",
		Email:        "alice@example.com",
		PasswordHash: "mock-hash",
		Role:         "user",
		Status:       "active",
	}
	if err := dbStore.CreateUser(user); err != nil {
		t.Fatalf("CreateUser failed: %v", err)
	}

	cleanup := func() {
		_ = dbStore.Close()
		_ = os.RemoveAll(tmpDir)
	}

	return engine, dbStore, user, cleanup
}

func TestTOTPEnrollmentAndVerification(t *testing.T) {
	engine, _, user, cleanup := setupTestMFAEngine(t)
	defer cleanup()

	secret, uri, err := engine.GenerateTOTPSecret(user.Username, "KySignOn")
	if err != nil {
		t.Fatalf("GenerateTOTPSecret failed: %v", err)
	}

	if len(secret) < 16 || uri == "" {
		t.Fatalf("unexpected secret or uri: %s, %s", secret, uri)
	}

	if err := engine.SaveUserTOTP(user.ID, secret); err != nil {
		t.Fatalf("SaveUserTOTP failed: %v", err)
	}

	// Calculate valid code for current counter
	timeStep := time.Now().Unix() / 30

	// Validate TOTP algorithm with calculated code
	code := calculateTOTPCode([]byte("12345678901234567890"), timeStep)
	if !ValidateTOTP("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", code) {
		t.Fatal("ValidateTOTP failed for RFC 6238 sample secret")
	}
}

func TestRecoveryCodesGenerationAndSingleUse(t *testing.T) {
	engine, _, user, cleanup := setupTestMFAEngine(t)
	defer cleanup()

	codes, err := engine.GenerateRecoveryCodes(user.ID)
	if err != nil {
		t.Fatalf("GenerateRecoveryCodes failed: %v", err)
	}

	if len(codes) != 8 {
		t.Fatalf("expected 8 recovery codes, got %d", len(codes))
	}

	firstCode := codes[0]

	// 1. Consume first code
	valid, err := engine.VerifyAndConsumeRecoveryCode(user.ID, firstCode)
	if err != nil || !valid {
		t.Fatalf("first recovery code verification failed: %v", err)
	}

	// 2. Replay of same code must fail
	valid, err = engine.VerifyAndConsumeRecoveryCode(user.ID, firstCode)
	if err != nil || valid {
		t.Fatal("expected already consumed recovery code to fail")
	}
}

func TestDevicePairingAndRegistration(t *testing.T) {
	engine, dbStore, user, cleanup := setupTestMFAEngine(t)
	defer cleanup()

	// 1. Generate 90s device pairing PIN/token
	token, pin, expiresAt, err := engine.GenerateDevicePairingToken(user.ID)
	if err != nil {
		t.Fatalf("GenerateDevicePairingToken failed: %v", err)
	}

	if len(pin) != 6 || token == "" {
		t.Fatalf("unexpected token or pin format: %s, %s", token, pin)
	}
	if expiresAt.Before(time.Now().UTC().Add(80 * time.Second)) {
		t.Fatalf("TTL too short: %v", expiresAt)
	}

	// 2. Register native device using PIN
	regReq := &NativeDeviceRegisterRequest{
		PINCode:          pin,
		DeviceName:       "Yoshi's Pixel Phone",
		DeviceIdentifier: "pixel-9-pro-uuid",
		PushToken:        "fcm-mock-token-12345",
	}

	dev, err := engine.RegisterNativeDevice(regReq)
	if err != nil {
		t.Fatalf("RegisterNativeDevice failed: %v", err)
	}

	if dev.UserID != user.ID || dev.DeviceName != "Yoshi's Pixel Phone" || !dev.IsMFAApprover {
		t.Fatalf("unexpected registered device: %+v", dev)
	}

	// 3. Check store
	devices, err := dbStore.ListUserNativeDevices(user.ID)
	if err != nil || len(devices) != 1 {
		t.Fatalf("expected 1 device in store, got %d", len(devices))
	}

	// 4. Token replay must fail
	_, err = engine.RegisterNativeDevice(regReq)
	if err == nil {
		t.Fatal("expected device pairing PIN replay to fail")
	}
}

func TestPushChallengeNumberMatching(t *testing.T) {
	engine, _, user, cleanup := setupTestMFAEngine(t)
	defer cleanup()

	challenge, err := engine.CreatePushChallenge(user.ID)
	if err != nil {
		t.Fatalf("CreatePushChallenge failed: %v", err)
	}

	if challenge.MatchDigits == "" || len(challenge.MatchDigits) != 2 {
		t.Fatalf("expected 2-digit match number, got %s", challenge.MatchDigits)
	}

	// Check status is pending
	status, err := engine.CheckPushChallenge(challenge.ID)
	if err != nil || status != "pending" {
		t.Fatalf("expected pending status, got %s", status)
	}

	// Respond with incorrect match number
	ok, err := engine.RespondPushChallenge(challenge.ID, "9999", true)
	if err != nil || ok {
		t.Fatalf("expected incorrect number response to fail, got ok=%v, err=%v", ok, err)
	}

	status, _ = engine.CheckPushChallenge(challenge.ID)
	if status != "denied" {
		t.Fatalf("expected denied status after incorrect number, got %s", status)
	}

	// Create second challenge for correct approval
	ch2, _ := engine.CreatePushChallenge(user.ID)
	ok, err = engine.RespondPushChallenge(ch2.ID, ch2.MatchDigits, true)
	if err != nil || !ok {
		t.Fatalf("expected correct number response to succeed, got ok=%v, err=%v", ok, err)
	}

	status, _ = engine.CheckPushChallenge(ch2.ID)
	if status != "approved" {
		t.Fatalf("expected approved status, got %s", status)
	}
}
