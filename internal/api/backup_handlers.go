package api

import (
	"encoding/base64"
	"encoding/json"
	"net/http"

	"github.com/Yoshiofthewire/kysignon-server/internal/audit"
	"github.com/Yoshiofthewire/kysignon-server/internal/backup"
	"github.com/Yoshiofthewire/kysignon-server/internal/config"
	"github.com/Yoshiofthewire/kysignon-server/internal/store"
)

type BackupHandler struct {
	cfg            *config.Config
	store          *store.Store
	audit          *audit.Logger
	middleware     *MiddlewareManager
	recoveryClient *backup.KyRecoveryClient
}

func NewBackupHandler(cfg *config.Config, s *store.Store, audit *audit.Logger, mm *MiddlewareManager) *BackupHandler {
	return &BackupHandler{
		cfg:            cfg,
		store:          s,
		audit:          audit,
		middleware:     mm,
		recoveryClient: backup.NewKyRecoveryClient(),
	}
}

// RunDrill executes an automated live disaster recovery restore drill inside a temporary isolated sandbox.
func (h *BackupHandler) RunDrill(w http.ResponseWriter, r *http.Request) {
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

	payload, err := backup.BuildLocalPayload(h.cfg, "1.0.0")
	if err != nil {
		h.audit.Record("admin.backup_drill_run", adminID, adminUsername, "", "backup", h.middleware.ClientIP(r), r.UserAgent(), "failure", map[string]any{
			"error": err.Error(),
		})
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]any{"error": "Failed to collect backup files: " + err.Error()})
		return
	}

	var files []backup.BackupFile
	for _, f := range payload.Files {
		data, err := base64.StdEncoding.DecodeString(f.DataBase64)
		if err != nil {
			continue
		}
		files = append(files, backup.BackupFile{
			Path: f.Path,
			Data: data,
			Mode: f.Mode,
		})
	}

	capsule, key, err := backup.CreateCapsule("KySignOn", "1.0.0", files, payload.Dependencies, payload.VerificationRecipe, 2, 3)
	if err != nil {
		h.audit.Record("admin.backup_drill_run", adminID, adminUsername, "", "backup", h.middleware.ClientIP(r), r.UserAgent(), "failure", map[string]any{
			"error": err.Error(),
		})
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]any{"error": "Failed to create backup capsule: " + err.Error()})
		return
	}

	drillResult, err := backup.RunRestoreDrill(r.Context(), capsule, key)
	if err != nil {
		h.audit.Record("admin.backup_drill_run", adminID, adminUsername, "", "backup", h.middleware.ClientIP(r), r.UserAgent(), "failure", map[string]any{
			"error": err.Error(),
		})
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]any{"error": "Failed to execute restore drill: " + err.Error()})
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

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(drillResult)
}

// ExportRecoveryKit generates a self-contained offline emergency Disaster Recovery Kit HTML document.
func (h *BackupHandler) ExportRecoveryKit(w http.ResponseWriter, r *http.Request) {
	admin := GetUserFromContext(r.Context())
	var adminID, adminUsername string
	if admin != nil {
		adminID = admin.ID
		adminUsername = admin.Username
	}

	payload, err := backup.BuildLocalPayload(h.cfg, "1.0.0")
	if err != nil {
		http.Error(w, "Failed to collect backup payload: "+err.Error(), http.StatusInternalServerError)
		return
	}

	var files []backup.BackupFile
	for _, f := range payload.Files {
		data, _ := base64.StdEncoding.DecodeString(f.DataBase64)
		files = append(files, backup.BackupFile{
			Path: f.Path,
			Data: data,
			Mode: f.Mode,
		})
	}

	capsule, _, err := backup.CreateCapsule("KySignOn", "1.0.0", files, payload.Dependencies, payload.VerificationRecipe, 2, 3)
	if err != nil {
		http.Error(w, "Failed to create capsule: "+err.Error(), http.StatusInternalServerError)
		return
	}

	html := backup.GenerateRecoveryKitHTML(capsule, "KySignOn", h.cfg.IssuerURL)

	h.audit.Record("admin.backup_recovery_kit_export", adminID, adminUsername, capsule.Manifest.CapsuleID, "backup", h.middleware.ClientIP(r), r.UserAgent(), "success", map[string]any{
		"capsule_id": capsule.Manifest.CapsuleID,
	})

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="kysignon-recovery-kit.html"`)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(html))
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
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "Both recovery_url and pairing_code are required"})
		return
	}

	token, err := h.recoveryClient.ClaimPairing(r.Context(), req.RecoveryURL, req.PairingCode, "KySignOn")
	if err != nil {
		h.audit.Record("admin.backup_remote_pair", adminID, adminUsername, "", "backup", h.middleware.ClientIP(r), r.UserAgent(), "failure", map[string]any{
			"recovery_url": req.RecoveryURL,
			"error":        err.Error(),
		})
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	_ = h.store.SetSetting("kyrecovery_url", req.RecoveryURL)
	_ = h.store.SetSetting("kyrecovery_token", token)

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
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "KyRecovery is not paired"})
		return
	}

	payload, err := backup.BuildLocalPayload(h.cfg, "1.0.0")
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "Failed to collect backup payload: " + err.Error()})
		return
	}

	resp, err := h.recoveryClient.PushBackup(r.Context(), recURL, recToken, *payload)
	if err != nil {
		h.audit.Record("admin.backup_remote_push", adminID, adminUsername, "", "backup", h.middleware.ClientIP(r), r.UserAgent(), "failure", map[string]any{
			"recovery_url": recURL,
			"error":        err.Error(),
		})
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadGateway)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	h.audit.Record("admin.backup_remote_push", adminID, adminUsername, resp.CapsuleID, "backup", h.middleware.ClientIP(r), r.UserAgent(), "success", map[string]any{
		"capsule_id": resp.CapsuleID,
		"size_bytes": resp.SizeBytes,
	})

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

// Status returns current disaster recovery readiness and pairing status.
func (h *BackupHandler) Status(w http.ResponseWriter, r *http.Request) {
	recURL, _ := h.store.GetSetting("kyrecovery_url")
	recToken, _ := h.store.GetSetting("kyrecovery_token")

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"paired":       recURL != "" && recToken != "",
		"recovery_url": recURL,
		"app_name":     "KySignOn",
		"app_version":  "1.0.0",
	})
}
