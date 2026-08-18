package sync

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/Yoshiofthewire/kysignon-server/internal/crypto"
	"github.com/Yoshiofthewire/kysignon-server/internal/store"
	"github.com/google/uuid"
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

	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	engine := NewEngine(dbStore, key)

	// Pairing callbacks in these tests point at httptest servers on loopback.
	AllowPrivateCallbacks = true
	t.Cleanup(func() { AllowPrivateCallbacks = false })

	cleanup := func() {
		_ = dbStore.Close()
		_ = os.RemoveAll(tmpDir)
	}

	return engine, dbStore, adminUser, cleanup
}

func TestDirectSCIMSystemCreationAndRecovery(t *testing.T) {
	engine, dbStore, _, cleanup := setupTestSyncEngine(t)
	defer cleanup()

	// 1. Create SCIM system directly
	req := &CreateSystemRequest{
		Name:        "Production KyPost",
		SystemType:  "kypost",
		CallbackURL: "https://kypost.local/scim/v2",
	}

	ps, token, err := engine.CreateSystem(req)
	if err != nil {
		t.Fatalf("CreateSystem failed: %v", err)
	}

	if ps.ID == "" || ps.Status != "active" || len(token) < 32 {
		t.Fatalf("unexpected system created: %+v, token=%s", ps, token)
	}

	// 2. Recover secret
	secret, err := engine.SigningSecret(ps)
	if err != nil {
		t.Fatalf("SigningSecret failed: %v", err)
	}
	if secret != token {
		t.Fatalf("expected recovered secret '%s', got '%s'", token, secret)
	}

	// 3. Check system persisted in store
	loaded, err := dbStore.GetPairedSystemByID(ps.ID)
	if err != nil || loaded == nil {
		t.Fatalf("paired system not found in store: %v", err)
	}
	if loaded.Name != "Production KyPost" || loaded.Status != "active" {
		t.Fatalf("unexpected paired system in store: %+v", loaded)
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
		ID:                  uuid.New().String(),
		Name:                "Mock KyPost",
		SystemType:          "kypost",
		CallbackURL:         mockServer.URL,
		HMACSecretEncrypted: mustEncrypt(t, engine, sharedSecret),
		Status:              "active",
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

func TestAccountSyncSCIMPayloadAndHeaders(t *testing.T) {
	engine, dbStore, adminUser, cleanup := setupTestSyncEngine(t)
	defer cleanup()

	var receivedCount int32
	var receivedContentType string
	var receivedAuthHeader string
	var receivedSCIMUser SCIMUserResource

	sharedSecret := "mock-hmac-secret-32-chars-long!"

	mockSCIMServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&receivedCount, 1)
		receivedContentType = r.Header.Get("Content-Type")
		receivedAuthHeader = r.Header.Get("Authorization")

		_ = json.NewDecoder(r.Body).Decode(&receivedSCIMUser)
		w.WriteHeader(http.StatusCreated)
	}))
	defer mockSCIMServer.Close()

	ps := &store.PairedSystem{
		ID:                  uuid.New().String(),
		Name:                "SCIM Downstream",
		SystemType:          "custom",
		CallbackURL:         mockSCIMServer.URL,
		HMACSecretEncrypted: mustEncrypt(t, engine, sharedSecret),
		Status:              "active",
	}
	if err := dbStore.CreatePairedSystem(ps); err != nil {
		t.Fatalf("CreatePairedSystem failed: %v", err)
	}

	scimUser := UserToSCIMResource(adminUser)
	if err := engine.QueueAccountSyncEvent(adminUser.ID, "user.created", scimUser); err != nil {
		t.Fatalf("QueueAccountSyncEvent failed: %v", err)
	}

	if err := engine.DispatchPendingEvents(context.Background()); err != nil {
		t.Fatalf("DispatchPendingEvents failed: %v", err)
	}

	if atomic.LoadInt32(&receivedCount) != 1 {
		t.Fatalf("expected 1 SCIM delivery, got %d", receivedCount)
	}
	if receivedContentType != "application/scim+json" {
		t.Fatalf("expected application/scim+json content-type, got %s", receivedContentType)
	}
	if receivedAuthHeader != "Bearer "+sharedSecret {
		t.Fatalf("expected Bearer authorization header, got %s", receivedAuthHeader)
	}
	if len(receivedSCIMUser.Schemas) == 0 || receivedSCIMUser.Schemas[0] != SCIMUserSchema {
		t.Fatalf("expected SCIM schema %s, got %+v", SCIMUserSchema, receivedSCIMUser.Schemas)
	}
	if receivedSCIMUser.UserName != adminUser.Username {
		t.Fatalf("expected SCIM userName %s, got %s", adminUser.Username, receivedSCIMUser.UserName)
	}
	if len(receivedSCIMUser.Emails) == 0 || receivedSCIMUser.Emails[0].Value != adminUser.Email {
		t.Fatalf("expected SCIM email %s, got %+v", adminUser.Email, receivedSCIMUser.Emails)
	}
	if !receivedSCIMUser.Active {
		t.Fatal("expected SCIM active to be true")
	}
}

func TestRESTfulSCIMEndpointsCRUD(t *testing.T) {
	engine, dbStore, adminUser, cleanup := setupTestSyncEngine(t)
	defer cleanup()

	var receivedMethods []string
	var receivedPaths []string
	var receivedBodies [][]byte

	sharedSecret := "mock-hmac-secret-32-chars-long!"

	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedMethods = append(receivedMethods, r.Method)
		receivedPaths = append(receivedPaths, r.URL.Path)

		buf := new(bytes.Buffer)
		_, _ = buf.ReadFrom(r.Body)
		receivedBodies = append(receivedBodies, buf.Bytes())

		if r.Method == http.MethodPost {
			w.WriteHeader(http.StatusCreated)
		} else if r.Method == http.MethodPut {
			w.WriteHeader(http.StatusOK)
		} else if r.Method == http.MethodDelete {
			w.WriteHeader(http.StatusNoContent)
		}
	}))
	defer mockServer.Close()

	ps := &store.PairedSystem{
		ID:                  uuid.New().String(),
		Name:                "Standard SCIM Service",
		SystemType:          "scim",
		CallbackURL:         mockServer.URL + "/scim/v2",
		HMACSecretEncrypted: mustEncrypt(t, engine, sharedSecret),
		Status:              "active",
	}
	if err := dbStore.CreatePairedSystem(ps); err != nil {
		t.Fatalf("CreatePairedSystem failed: %v", err)
	}

	scimUser := UserToSCIMResource(adminUser)

	// 1. Create -> POST /scim/v2/Users
	if err := engine.QueueAccountSyncEvent(adminUser.ID, "user.created", scimUser); err != nil {
		t.Fatalf("Queue user.created failed: %v", err)
	}
	if err := engine.DispatchPendingEvents(context.Background()); err != nil {
		t.Fatalf("Dispatch user.created failed: %v", err)
	}

	// 2. Update -> PUT /scim/v2/Users/{id}
	if err := engine.QueueAccountSyncEvent(adminUser.ID, "user.updated", scimUser); err != nil {
		t.Fatalf("Queue user.updated failed: %v", err)
	}
	if err := engine.DispatchPendingEvents(context.Background()); err != nil {
		t.Fatalf("Dispatch user.updated failed: %v", err)
	}

	// 3. Delete -> DELETE /scim/v2/Users/{id}
	if err := engine.QueueAccountSyncEvent(adminUser.ID, "user.deleted", map[string]any{"id": adminUser.ID}); err != nil {
		t.Fatalf("Queue user.deleted failed: %v", err)
	}
	if err := engine.DispatchPendingEvents(context.Background()); err != nil {
		t.Fatalf("Dispatch user.deleted failed: %v", err)
	}

	if len(receivedMethods) != 3 {
		t.Fatalf("expected 3 requests, got %d", len(receivedMethods))
	}

	// Verify Create
	if receivedMethods[0] != http.MethodPost || receivedPaths[0] != "/scim/v2/Users" {
		t.Fatalf("expected POST /scim/v2/Users, got %s %s", receivedMethods[0], receivedPaths[0])
	}
	if len(receivedBodies[0]) == 0 {
		t.Fatal("expected non-empty body on POST /scim/v2/Users")
	}

	// Verify Update
	expectedResourcePath := "/scim/v2/Users/" + adminUser.ID
	if receivedMethods[1] != http.MethodPut || receivedPaths[1] != expectedResourcePath {
		t.Fatalf("expected PUT %s, got %s %s", expectedResourcePath, receivedMethods[1], receivedPaths[1])
	}
	if len(receivedBodies[1]) == 0 {
		t.Fatal("expected non-empty body on PUT /scim/v2/Users/{id}")
	}

	// Verify Delete
	if receivedMethods[2] != http.MethodDelete || receivedPaths[2] != expectedResourcePath {
		t.Fatalf("expected DELETE %s, got %s %s", expectedResourcePath, receivedMethods[2], receivedPaths[2])
	}
	if len(receivedBodies[2]) != 0 {
		t.Fatalf("expected empty body on DELETE /scim/v2/Users/{id}, got %d bytes", len(receivedBodies[2]))
	}
}

// mustEncrypt seals a webhook signing secret the way pairing does, so a hand-built
// PairedSystem in a test carries a secret the engine can actually recover.
func mustEncrypt(t *testing.T, e *Engine, secret string) string {
	t.Helper()
	sealed, err := crypto.EncryptAESGCM(e.encryptionKey, []byte(secret))
	if err != nil {
		t.Fatalf("EncryptAESGCM: %v", err)
	}
	return sealed
}


