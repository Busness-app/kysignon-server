package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"

	"github.com/Yoshiofthewire/kysignon-server/internal/audit"
	"github.com/Yoshiofthewire/kysignon-server/internal/backup"
	"github.com/Yoshiofthewire/kysignon-server/internal/config"
	"github.com/Yoshiofthewire/kysignon-server/internal/store"
)

// appVersion is reported in capsule manifests and status responses.
const appVersion = "1.0.0"

type BackupHandler struct {
	cfg            *config.Config
	store          *store.Store
	audit          *audit.Logger
	middleware     *MiddlewareManager
	recoveryClient *backup.KyRecoveryClient
	kits           *backup.KitStore
}

func NewBackupHandler(cfg *config.Config, s *store.Store, audit *audit.Logger, mm *MiddlewareManager) *BackupHandler {
	return &BackupHandler{
		cfg:            cfg,
		store:          s,
		audit:          audit,
		middleware:     mm,
		recoveryClient: backup.NewKyRecoveryClient(),
		kits:           backup.NewKitStore(),
	}
}

func (h *BackupHandler) actor(r *http.Request) (string, string) {
	if admin := GetUserFromContext(r.Context()); admin != nil {
		return admin.ID, admin.Username
	}
	return "", ""
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// buildCapsule collects a consistent snapshot and encapsulates it.
func (h *BackupHandler) buildCapsule() (*backup.Capsule, []byte, error) {
	payload, err := backup.BuildLocalPayload(h.cfg, h.store, appVersion)
	if err != nil {
		return nil, nil, err
	}
	files, err := backup.AsBackupFiles(payload)
	if err != nil {
		return nil, nil, err
	}
	return backup.CreateCapsule("KySignOn", appVersion, files,
		payload.Dependencies, payload.VerificationRecipe, payload.Threshold, payload.TotalShares)
}

// RunDrill executes an automated live disaster recovery restore drill inside a temporary isolated sandbox.
func (h *BackupHandler) RunDrill(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method_not_allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	adminID, adminUsername := h.actor(r)

	capsule, key, err := h.buildCapsule()
	if err != nil {
		h.audit.Record("admin.backup_drill_run", adminID, adminUsername, "", "backup", h.middleware.ClientIP(r), r.UserAgent(), "failure", map[string]any{
			"error": err.Error(),
		})
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "Failed to build backup capsule: " + err.Error()})
		return
	}

	drillResult, err := backup.RunRestoreDrill(r.Context(), capsule, key)
	if err != nil {
		h.audit.Record("admin.backup_drill_run", adminID, adminUsername, "", "backup", h.middleware.ClientIP(r), r.UserAgent(), "failure", map[string]any{
			"error": err.Error(),
		})
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "Failed to execute restore drill: " + err.Error()})
		return
	}

	outcome := "success"
	if !drillResult.Passed {
		outcome = "failure"
	}
	h.audit.Record("admin.backup_drill_run", adminID, adminUsername, "", "backup", h.middleware.ClientIP(r), r.UserAgent(), outcome, map[string]any{
		"passed":      drillResult.Passed,
		"duration_ms": drillResult.DurationMS,
	})

	writeJSON(w, http.StatusOK, drillResult)
}

// CreateRecoveryKit builds the capsule and registers its artifacts for separate collection.
//
// It deliberately returns no secret material. The encrypted container and each custodian
// shard are fetched by their own authenticated requests, so no single response or file ever
// contains a reconstruction quorum.
func (h *BackupHandler) CreateRecoveryKit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method_not_allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	adminID, adminUsername := h.actor(r)

	capsule, _, err := h.buildCapsule()
	if err != nil {
		h.audit.Record("admin.backup_recovery_kit_create", adminID, adminUsername, "", "backup", h.middleware.ClientIP(r), r.UserAgent(), "failure", map[string]any{
			"error": err.Error(),
		})
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "Failed to build recovery kit: " + err.Error()})
		return
	}

	kit, err := h.kits.Create(capsule)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}

	h.audit.Record("admin.backup_recovery_kit_create", adminID, adminUsername, kit.Manifest.CapsuleID, "backup", h.middleware.ClientIP(r), r.UserAgent(), "success", map[string]any{
		"capsule_id": kit.Manifest.CapsuleID,
		"kit_id":     kit.ID,
	})

	writeJSON(w, http.StatusOK, map[string]any{
		"kit_id":       kit.ID,
		"capsule_id":   kit.Manifest.CapsuleID,
		"payload_hash": kit.Manifest.PayloadHash,
		"threshold":    kit.Manifest.Threshold,
		"total_shares": kit.Manifest.TotalShares,
		"capsule_size": len(kit.Capsule),
		"expires_at":   kit.ExpiresAt,
		"shards":       kit.Shards(),
	})
}

// DownloadCapsule serves the encrypted .kycap container. This is the artifact the previous
// "self-contained kit" never included, which made every exported key shard useless.
func (h *BackupHandler) DownloadCapsule(w http.ResponseWriter, r *http.Request) {
	adminID, adminUsername := h.actor(r)
	kit, err := h.kits.Get(r.PathValue("id"))
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": err.Error()})
		return
	}

	h.audit.Record("admin.backup_capsule_download", adminID, adminUsername, kit.Manifest.CapsuleID, "backup", h.middleware.ClientIP(r), r.UserAgent(), "success", map[string]any{
		"capsule_id": kit.Manifest.CapsuleID,
	})

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename=%q`, kit.Manifest.CapsuleID+".kycap"))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(kit.Capsule)
}

// DownloadShard serves exactly one custodian shard, once.
func (h *BackupHandler) DownloadShard(w http.ResponseWriter, r *http.Request) {
	adminID, adminUsername := h.actor(r)

	index, err := strconv.Atoi(r.PathValue("index"))
	if err != nil || index <= 0 {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "shard index must be a positive integer"})
		return
	}
	kitID := r.PathValue("id")
	kit, err := h.kits.Get(kitID)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": err.Error()})
		return
	}
	share, err := h.kits.TakeShard(kitID, index)
	if err != nil {
		h.audit.Record("admin.backup_shard_download", adminID, adminUsername, kit.Manifest.CapsuleID, "backup", h.middleware.ClientIP(r), r.UserAgent(), "failure", map[string]any{
			"shard_index": index,
			"error":       err.Error(),
		})
		writeJSON(w, http.StatusNotFound, map[string]any{"error": err.Error()})
		return
	}

	h.audit.Record("admin.backup_shard_download", adminID, adminUsername, kit.Manifest.CapsuleID, "backup", h.middleware.ClientIP(r), r.UserAgent(), "success", map[string]any{
		"capsule_id":  kit.Manifest.CapsuleID,
		"shard_index": index,
	})

	html := backup.GenerateCustodianCardHTML(kit.Manifest, share, "KySignOn", h.cfg.IssuerURL)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename=%q`,
		fmt.Sprintf("kysignon-custodian-shard-%d.html", index)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(html))
}

// DiscardRecoveryKit zeroizes any shards the operator did not collect.
func (h *BackupHandler) DiscardRecoveryKit(w http.ResponseWriter, r *http.Request) {
	adminID, adminUsername := h.actor(r)
	kitID := r.PathValue("id")
	h.kits.Discard(kitID)
	h.audit.Record("admin.backup_recovery_kit_discard", adminID, adminUsername, kitID, "backup", h.middleware.ClientIP(r), r.UserAgent(), "success", nil)
	writeJSON(w, http.StatusOK, map[string]any{"discarded": true})
}

type RemotePairRequest struct {
	RecoveryURL string `json:"recovery_url"`
	PairingCode string `json:"pairing_code"`
}

// PairRemote pairs KySignOn with a remote KyRecovery instance via ephemeral 6-digit PIN.
func (h *BackupHandler) PairRemote(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method_not_allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	admin := GetUserFromContext(r.Context())
	var adminID, adminUsername string
	if admin != nil {
		adminID = admin.ID
		adminUsername = admin.Username
	}

	var req RemotePairRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "Invalid JSON request body"})
		return
	}

	if req.RecoveryURL == "" || req.PairingCode == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Both recovery_url and pairing_code are required"})
		return
	}

	// Validated here as well as in the client so a bad URL is rejected before it is stored
	// or audited as a pairing attempt.
	if err := backup.ValidateRecoveryURL(req.RecoveryURL); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	token, err := h.recoveryClient.ClaimPairing(r.Context(), req.RecoveryURL, req.PairingCode, "KySignOn")
	if err != nil {
		h.audit.Record("admin.backup_remote_pair", adminID, adminUsername, "", "backup", h.middleware.ClientIP(r), r.UserAgent(), "failure", map[string]any{
			"recovery_url": req.RecoveryURL,
			"error":        err.Error(),
		})
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	// A pairing that cannot be persisted is not a pairing. Reporting success here would
	// leave the admin believing KyRecovery is configured when the next push has no token.
	if err := h.store.SetSetting("kyrecovery_url", req.RecoveryURL); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Failed to persist recovery URL: " + err.Error()})
		return
	}
	if err := h.store.SetSetting("kyrecovery_token", token); err != nil {
		_ = h.store.SetSetting("kyrecovery_url", "")
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Failed to persist recovery token: " + err.Error()})
		return
	}

	h.audit.Record("admin.backup_remote_pair", adminID, adminUsername, "", "backup", h.middleware.ClientIP(r), r.UserAgent(), "success", map[string]any{
		"recovery_url": req.RecoveryURL,
	})

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"paired":       true,
		"recovery_url": req.RecoveryURL,
	})
}

// PushBackup dispatches a backup capsule to the configured KyRecovery server.
func (h *BackupHandler) PushBackup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method_not_allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	admin := GetUserFromContext(r.Context())
	var adminID, adminUsername string
	if admin != nil {
		adminID = admin.ID
		adminUsername = admin.Username
	}

	recURL, _ := h.store.GetSetting("kyrecovery_url")
	recToken, _ := h.store.GetSetting("kyrecovery_token")
	if recURL == "" || recToken == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "KyRecovery is not paired"})
		return
	}

	payload, err := backup.BuildLocalPayload(h.cfg, h.store, appVersion)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Failed to collect backup payload: " + err.Error()})
		return
	}

	resp, err := h.recoveryClient.PushBackup(r.Context(), recURL, recToken, *payload)
	if err != nil {
		h.audit.Record("admin.backup_remote_push", adminID, adminUsername, "", "backup", h.middleware.ClientIP(r), r.UserAgent(), "failure", map[string]any{
			"recovery_url": recURL,
			"error":        err.Error(),
		})
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}

	h.audit.Record("admin.backup_remote_push", adminID, adminUsername, resp.CapsuleID, "backup", h.middleware.ClientIP(r), r.UserAgent(), "success", map[string]any{
		"capsule_id": resp.CapsuleID,
		"size_bytes": resp.SizeBytes,
	})

	writeJSON(w, http.StatusOK, resp)
}

// Status returns current disaster recovery readiness and pairing status.
func (h *BackupHandler) Status(w http.ResponseWriter, r *http.Request) {
	recURL, _ := h.store.GetSetting("kyrecovery_url")
	recToken, _ := h.store.GetSetting("kyrecovery_token")

	writeJSON(w, http.StatusOK, map[string]any{
		"paired":       recURL != "" && recToken != "",
		"recovery_url": recURL,
		"app_name":     "KySignOn",
		"app_version":  appVersion,
	})
}
