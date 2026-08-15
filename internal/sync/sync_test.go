package sync

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/Yoshiofthewire/kysignon-server/internal/store"
)

func setupTestSyncEngine(t *testing.T) (*Engine, *store.Store, *store.User, func()) {
	tmpDir, err := os.MkdirTemp("", "kysignon-sync-test-*")
	if err != nil {
		t.Fatalf("MkdirTemp failed: %v", err)
	}

	dbPath := filepath.Join(tmpDir, "test.db")
	dbStore, err := store.New(dbPath)
	if err != nil {
		t.Fatalf("store.New failed: %v", err)
	}

	adminUser := &store.User{
		ID:           uuid.New().String(),
		Username:     "admin",
		DisplayName:  "Administrator",
		Email:        "admin@example.com",
		PasswordHash: "mock-hash",
		Role:         "admin",
		Status:       "active",
	}
	if err := dbStore.CreateUser(adminUser); err != nil {
		t.Fatalf("CreateUser failed: %v", err)
	}

	engine := NewEngine(dbStore)

	cleanup := func() {
		_ = dbStore.Close()
		_ = os.RemoveAll(tmpDir)
	}

	return engine, dbStore, adminUser, cleanup
}

func TestSystemPairingHandshakeAndTokenExpiry(t *testing.T) {
	engine, dbStore, adminUser, cleanup := setupTestSyncEngine(t)
	defer cleanup()

	// 1. Generate 90s system pairing token
	token, pin, expiresAt, err := engine.GenerateSystemPairingToken("kypost", adminUser.ID)
	if err != nil {
		t.Fatalf("GenerateSystemPairingToken failed: %v", err)
	}

	if len(pin) != 8 || token == "" {
		t.Fatalf("unexpected token or pin format: %s, %s", token, pin)
	}
	if expiresAt.Before(time.Now().UTC().Add(80 * time.Second)) {
		t.Fatalf("token TTL too short: %v", expiresAt)
	}

	// 2. Register paired system using token
	regReq := &SystemRegistrationRequest{
		PairingToken: token,
		SystemName:   "Production KyPost",
		SystemType:   "kypost",
		CallbackURL:  "https://kypost.local/api/sync",
	}

	resp, err := engine.RegisterPairedSystem(regReq)
	if err != nil {
		t.Fatalf("RegisterPairedSystem failed: %v", err)
	}

	if resp.SystemID == "" || resp.HMACSecret == "" || resp.Status != "active" {
		t.Fatalf("unexpected registration response: %+v", resp)
	}

	// 3. Replay of same pairing token must be rejected
	_, err = engine.RegisterPairedSystem(regReq)
	if err == nil {
		t.Fatal("expected token replay to be rejected")
	}

	// 4. Check system persisted in store
	ps, err := dbStore.GetPairedSystemByID(resp.SystemID)
	if err != nil || ps == nil {
		t.Fatalf("paired system not found in store: %v", err)
	}
	if ps.Name != "Production KyPost" || ps.Status != "active" {
		t.Fatalf("unexpected paired system in store: %+v", ps)
	}
}

func TestAccountSyncWebhookDispatch(t *testing.T) {
	engine, dbStore, adminUser, cleanup := setupTestSyncEngine(t)
	defer cleanup()

	var receivedCount int32
	var lastReceivedEventType string
	var lastReceivedSignature string

	sharedSecret := "mock-hmac-secret-32-chars-long!"

	// Mock downstream KyPost sync receiver server
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&receivedCount, 1)
		lastReceivedSignature = r.Header.Get("X-KySignOn-Signature")
		lastReceivedEventType = r.Header.Get("X-KySignOn-Event-Type")

		var payload SyncWebhookPayload
		_ = json.NewDecoder(r.Body).Decode(&payload)

		w.WriteHeader(http.StatusOK)
	}))
	defer mockServer.Close()

	// Register paired system pointing to mock server
	ps := &store.PairedSystem{
		ID:             uuid.New().String(),
		Name:           "Mock KyPost",
		SystemType:     "kypost",
		CallbackURL:    mockServer.URL,
		HMACSecretHash: sharedSecret,
		Status:         "active",
	}
	if err := dbStore.CreatePairedSystem(ps); err != nil {
		t.Fatalf("CreatePairedSystem failed: %v", err)
	}

	// Create user & queue sync event
	userPayload := map[string]any{
		"id":          adminUser.ID,
		"username":    adminUser.Username,
		"displayName": adminUser.DisplayName,
		"email":       adminUser.Email,
		"role":        adminUser.Role,
		"status":      adminUser.Status,
	}

	if err := engine.QueueAccountSyncEvent(adminUser.ID, "user.created", userPayload); err != nil {
		t.Fatalf("QueueAccountSyncEvent failed: %v", err)
	}

	// Dispatch pending events
	if err := engine.DispatchPendingEvents(context.Background()); err != nil {
		t.Fatalf("DispatchPendingEvents failed: %v", err)
	}

	if atomic.LoadInt32(&receivedCount) != 1 {
		t.Fatalf("expected 1 webhook delivery, got %d", receivedCount)
	}
	if lastReceivedEventType != "user.created" {
		t.Fatalf("unexpected event type: %s", lastReceivedEventType)
	}
	if lastReceivedSignature == "" {
		t.Fatal("missing HMAC signature on outbound sync webhook")
	}
}
