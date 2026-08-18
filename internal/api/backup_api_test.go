package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Yoshiofthewire/kysignon-server/internal/auth"
	"github.com/Yoshiofthewire/kysignon-server/internal/backup"
	"github.com/Yoshiofthewire/kysignon-server/internal/crypto"
	"github.com/Yoshiofthewire/kysignon-server/internal/store"
	"github.com/google/uuid"
)

func TestAdminBackupEndpoints(t *testing.T) {
	srv, dbStore, _, _, _, cleanup := setupTestServer(t)
	defer cleanup()

	// Create admin user
	adminPass := "AdminPassword123!"
	passHash, _ := auth.HashPassword(adminPass)
	adminUser := &store.User{
		ID:           uuid.New().String(),
		Username:     "admin_backup_test",
		DisplayName:  "Admin Backup",
		Email:        "admin@backup.test",
		PasswordHash: passHash,
		Role:         "admin",
		Status:       "active",
	}
	if err := dbStore.CreateUser(adminUser); err != nil {
		t.Fatalf("CreateUser failed: %v", err)
	}

	adminSessionToken, _ := crypto.GenerateRandomHex(32)
	_ = dbStore.CreateSession(&store.Session{
		ID:               uuid.New().String(),
		UserID:           adminUser.ID,
		SessionTokenHash: crypto.HashSHA256(adminSessionToken),
		IPAddress:        "127.0.0.1",
		UserAgent:        "Go-Test",
		ExpiresAt:        time.Now().Add(24 * time.Hour),
	})

	csrfToken := srv.middleware.IssueCSRFToken(adminSessionToken)
	adminCookie := &http.Cookie{Name: "kysignon_session", Value: adminSessionToken}
	csrfCookie := &http.Cookie{Name: "kysignon_csrf", Value: csrfToken}

	t.Run("Status endpoint", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/admin/backup/status", nil)
		req.AddCookie(adminCookie)
		w := httptest.NewRecorder()

		srv.httpServer.Handler.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("expected status 200, got %d: %s", w.Code, w.Body.String())
		}

		var resp map[string]any
		_ = json.NewDecoder(w.Body).Decode(&resp)
		if resp["app_name"] != "KySignOn" {
			t.Errorf("expected app_name KySignOn, got %v", resp["app_name"])
		}
	})

	t.Run("Restore drill endpoint", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/api/admin/backup/drill", nil)
		req.AddCookie(adminCookie)
		req.AddCookie(csrfCookie)
		req.Header.Set("X-CSRF-Token", csrfToken)
		w := httptest.NewRecorder()

		srv.httpServer.Handler.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("expected status 200, got %d: %s", w.Code, w.Body.String())
		}

		var drillResult backup.DrillResult
		if err := json.NewDecoder(w.Body).Decode(&drillResult); err != nil {
			t.Fatalf("failed to decode drill result: %v", err)
		}
		if !drillResult.Passed {
			t.Errorf("expected drill to pass, got error: %s", drillResult.ErrorMessage)
		}
	})

	t.Run("Export recovery kit endpoint", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/admin/backup/recovery-kit", nil)
		req.AddCookie(adminCookie)
		w := httptest.NewRecorder()

		srv.httpServer.Handler.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("expected status 200, got %d: %s", w.Code, w.Body.String())
		}

		body := w.Body.String()
		if !strings.Contains(body, "Disaster Recovery Kit") || !strings.Contains(body, "KySignOn") {
			t.Errorf("expected recovery kit HTML, got: %s", body)
		}
	})

	t.Run("Pair remote validation", func(t *testing.T) {
		body, _ := json.Marshal(map[string]string{
			"recovery_url": "http://127.0.0.1:9999",
			"pairing_code": "123456",
		})
		req := httptest.NewRequest("POST", "/api/admin/backup/pair-remote", bytes.NewReader(body))
		req.AddCookie(adminCookie)
		req.AddCookie(csrfCookie)
		req.Header.Set("X-CSRF-Token", csrfToken)
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		srv.httpServer.Handler.ServeHTTP(w, req)
		// Should fail to connect to non-existent server 9999 with 400 Bad Request
		if w.Code != http.StatusBadRequest {
			t.Errorf("expected status 400 for invalid connection, got %d: %s", w.Code, w.Body.String())
		}
	})
}
