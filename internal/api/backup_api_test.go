package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Busness-app/kysignon-server/internal/auth"
	"github.com/Busness-app/kysignon-server/internal/backup"
	"github.com/Busness-app/kysignon-server/internal/crypto"
	"github.com/Busness-app/kysignon-server/internal/store"
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

	// Every secret-bearing backup route consumes a single-use step-up grant, so each request
	// below mints its own the way the UI prompts for one per action.
	stepUp := func() string { return mintStepUp(t, srv, adminSessionToken) }

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

	t.Run("Recovery kit separates the capsule from each shard", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/api/admin/backup/recovery-kit", nil)
		req.AddCookie(adminCookie)
		req.AddCookie(csrfCookie)
		req.Header.Set("X-CSRF-Token", csrfToken)
		req.Header.Set(StepUpHeader, stepUp())
		w := httptest.NewRecorder()
		srv.httpServer.Handler.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("expected status 200, got %d: %s", w.Code, w.Body.String())
		}

		var kit struct {
			KitID       string `json:"kit_id"`
			Threshold   int    `json:"threshold"`
			TotalShares int    `json:"total_shares"`
			CapsuleSize int    `json:"capsule_size"`
		}
		if err := json.NewDecoder(w.Body).Decode(&kit); err != nil {
			t.Fatalf("failed to decode kit: %v", err)
		}
		if kit.KitID == "" || kit.CapsuleSize == 0 {
			t.Fatalf("kit response carries no capsule: %+v", kit)
		}

		// The capsule download must contain real ciphertext. A kit whose container is
		// absent is the failure the whole feature was built to avoid.
		capReq := httptest.NewRequest("GET", "/api/admin/backup/recovery-kit/"+kit.KitID+"/capsule", nil)
		capReq.AddCookie(adminCookie)
		capReq.Header.Set(StepUpHeader, stepUp())
		capW := httptest.NewRecorder()
		srv.httpServer.Handler.ServeHTTP(capW, capReq)
		if capW.Code != http.StatusOK {
			t.Fatalf("capsule download failed: %d %s", capW.Code, capW.Body.String())
		}
		parsed, err := backup.ParseCapsule(capW.Body.Bytes())
		if err != nil {
			t.Fatalf("downloaded capsule is not readable: %v", err)
		}
		if len(parsed.Ciphertext) == 0 {
			t.Fatal("downloaded capsule has no ciphertext")
		}
		if len(parsed.Shares) != 0 {
			t.Fatalf("the capsule download also carried %d key shards", len(parsed.Shares))
		}

		// Each shard is its own download, bound to the custodian who collected it. A repeat
		// fetch by that same holder must succeed: a failed response — audit write, full
		// disk, dropped connection — cannot be allowed to destroy the only copy of a
		// recovery shard.
		var cards []string
		for i := 1; i <= kit.TotalShares; i++ {
			shardReq := httptest.NewRequest("GET", fmt.Sprintf("/api/admin/backup/recovery-kit/%s/shard/%d", kit.KitID, i), nil)
			shardReq.AddCookie(adminCookie)
			shardReq.Header.Set(StepUpHeader, stepUp())
			shardW := httptest.NewRecorder()
			srv.httpServer.Handler.ServeHTTP(shardW, shardReq)
			if shardW.Code != http.StatusOK {
				t.Fatalf("shard %d download failed: %d %s", i, shardW.Code, shardW.Body.String())
			}
			cards = append(cards, shardW.Body.String())

			replay := httptest.NewRequest("GET", fmt.Sprintf("/api/admin/backup/recovery-kit/%s/shard/%d", kit.KitID, i), nil)
			replay.AddCookie(adminCookie)
			replay.Header.Set(StepUpHeader, stepUp())
			replayW := httptest.NewRecorder()
			srv.httpServer.Handler.ServeHTTP(replayW, replay)
			if replayW.Code != http.StatusOK {
				t.Errorf("the holder of shard %d could not retry a failed download: %d %s", i, replayW.Code, replayW.Body.String())
			}
			if replayW.Body.String() != shardW.Body.String() {
				t.Errorf("the retry of shard %d returned different material", i)
			}
		}

		// No single artifact may contain a quorum.
		for i, card := range cards {
			shard := shardHexFromCard(t, card)
			for j, other := range cards {
				if i == j {
					continue
				}
				if strings.Contains(other, shard) {
					t.Fatalf("custodian document %d also contains shard %d", j+1, i+1)
				}
			}
			if strings.Contains(capW.Body.String(), shard) {
				t.Fatalf("the capsule download contains shard %d", i+1)
			}
		}
	})

	t.Run("Pairing refuses internal and non-https recovery URLs", func(t *testing.T) {
		// The recovery URL is admin-supplied, so it is a request forgery primitive unless
		// it is constrained. None of these may produce an outbound request.
		for _, target := range []string{
			"http://169.254.169.254/latest/meta-data/",
			"http://127.0.0.1:9999",
			"https://10.89.0.2/api",
			"file:///etc/passwd",
			"https://user:pass@recovery.example.test",
			"https://recovery.example.test#fragment",
			"not a url",
		} {
			body, _ := json.Marshal(map[string]string{"recovery_url": target, "pairing_code": "123456"})
			req := httptest.NewRequest("POST", "/api/admin/backup/pair-remote", bytes.NewReader(body))
			req.AddCookie(adminCookie)
			req.AddCookie(csrfCookie)
			req.Header.Set("X-CSRF-Token", csrfToken)
			req.Header.Set(StepUpHeader, stepUp())
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			srv.httpServer.Handler.ServeHTTP(w, req)
			if w.Code != http.StatusBadRequest {
				t.Errorf("recovery URL %q was not rejected (status %d)", target, w.Code)
			}
			if stored, _ := dbStore.GetSetting("kyrecovery_url"); stored != "" {
				t.Fatalf("recovery URL %q was persisted despite being rejected", target)
			}
		}
	})
}

// shardHexFromCard reads the shard off a custodian document the way a custodian would.
func shardHexFromCard(t *testing.T, card string) string {
	t.Helper()
	start := strings.Index(card, "<code>")
	if start < 0 {
		t.Fatal("custodian card contains no shard")
	}
	start += len("<code>")
	end := strings.Index(card[start:], "</code>")
	if end < 0 {
		t.Fatal("custodian card shard is unterminated")
	}
	shard := strings.TrimSpace(card[start : start+end])
	if len(shard) < 32 {
		t.Fatalf("custodian card shard %q looks too short to be a key share", shard)
	}
	return shard
}
