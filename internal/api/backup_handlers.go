package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"time"

	"github.com/Busness-app/ky-primitives/capsule"
	"github.com/Busness-app/kysignon-server/internal/audit"
	"github.com/Busness-app/kysignon-server/internal/backup"
	"github.com/Busness-app/kysignon-server/internal/config"
	"github.com/Busness-app/kysignon-server/internal/store"
)

// appVersion is reported in capsule manifests and status responses.
const appVersion = "1.0.0"

// depositWriteBudget is how long the admin's connection may stay open for the receipt: the
// upload budget plus room for sealing. The listener's write timeout is sized for JSON replies.
const depositWriteBudget = 16 * time.Minute

// recoveryClient is the KyRecovery client as the handlers use it, narrowed so tests can stand
// in a fake without reaching the network.
type recoveryClient interface {
	ClaimPairing(ctx context.Context, serverURL, pairingCode, serviceName, appName string) (backup.PairingResult, error)
	backup.Depositor
}

type BackupHandler struct {
	cfg        *config.Config
	store      *store.Store
	audit      *audit.Logger
	middleware *MiddlewareManager
	recovery   recoveryClient
}

// newRecoveryClient builds the KyRecovery client; tests swap in a fake, since the real one
// refuses loopback and plain HTTP by design.
var newRecoveryClient = func() recoveryClient { return backup.NewKyRecoveryClient() }

func NewBackupHandler(cfg *config.Config, s *store.Store, audit *audit.Logger, mm *MiddlewareManager) *BackupHandler {
	return &BackupHandler{
		cfg:        cfg,
		store:      s,
		audit:      audit,
		middleware: mm,
		recovery:   newRecoveryClient(),
	}
}

func (h *BackupHandler) actor(r *http.Request) (string, string) {
	if admin := GetUserFromContext(r.Context()); admin != nil {
		return admin.ID, admin.Username
	}
	return "", ""
}

func (h *BackupHandler) record(r *http.Request, action, actorID, actorName, targetID, outcome string, details map[string]any) error {
	return h.audit.Record(action, actorID, actorName, targetID, "backup", h.middleware.ClientIP(r), r.UserAgent(), outcome, details)
}

// recordCritical writes an audit event for an operation that must not proceed unrecorded.
// A capsule leaving this server with no durable record of who took it is not an export, it is
// an unattributed disclosure, so the caller aborts when this returns false.
func (h *BackupHandler) recordCritical(w http.ResponseWriter, r *http.Request, action, actorID, actorName, targetID, outcome string, details map[string]any) bool {
	if err := h.record(r, action, actorID, actorName, targetID, outcome, details); err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{
			"error": "audit_unavailable",
			"error_description": "The audit trail could not be written, so this operation was refused. " +
				"Check database health and retry.",
		})
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// RunDrill seals the live payload to a throwaway key, opens it in a sandbox and runs the
// verification recipe. It reports, not proves, whether the suite key is pinned.
func (h *BackupHandler) RunDrill(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed")
		return
	}
	adminID, adminUsername := h.actor(r)
	payload, err := backup.CollectSealable(h.cfg, h.store, appVersion)
	if err != nil {
		_ = h.record(r, "admin.backup_drill_run", adminID, adminUsername, "", "failure", map[string]any{"error": backup.AuditSafe(err.Error())})
		writeError(w, http.StatusInternalServerError, "Failed to collect backup payload: "+err.Error())
		return
	}
	pinned, err := backup.LoadRecoveryKey(h.cfg.DataDir, h.store)
	if err != nil && !errors.Is(err, backup.ErrNotPaired) {
		writeError(w, http.StatusInternalServerError, "Failed to load recovery key: "+err.Error())
		return
	}
	result, err := backup.RunRestoreDrill(r.Context(), payload.ServiceName, payload.AppVersion, payload.Files, payload.Dependencies, payload.VerificationRecipe, pinned)
	if err != nil {
		_ = h.record(r, "admin.backup_drill_run", adminID, adminUsername, "", "failure", map[string]any{"error": backup.AuditSafe(err.Error())})
		writeError(w, http.StatusInternalServerError, "Failed to execute restore drill: "+err.Error())
		return
	}
	outcome := "success"
	if !result.Passed {
		outcome = "failure"
	}
	_ = h.record(r, "admin.backup_drill_run", adminID, adminUsername, "", outcome, map[string]any{"passed": result.Passed, "duration_ms": result.DurationMS})
	writeJSON(w, http.StatusOK, result)
}

// ExportCapsule hands the operator the capsule sealed to the suite recovery key. Only the
// custodians' shares open it, so the download is safe to store anywhere; kyrecovery is where
// it belongs. The export is refused rather than served unrecorded.
func (h *BackupHandler) ExportCapsule(w http.ResponseWriter, r *http.Request) {
	adminID, adminUsername := h.actor(r)
	key, err := backup.LoadRecoveryKey(h.cfg.DataDir, h.store)
	if errors.Is(err, backup.ErrNotPaired) {
		writeError(w, http.StatusPreconditionFailed, "Not paired with KyRecovery; no recovery key to seal to")
		return
	}
	if errors.Is(err, backup.ErrRecoveryKeyMismatch) {
		writeError(w, http.StatusConflict, "Recovery key file does not match the pinned key ID; refusing to seal")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to load recovery key")
		return
	}
	payload, err := backup.CollectSealable(h.cfg, h.store, appVersion)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to collect backup payload: "+err.Error())
		return
	}
	raw, m, err := backup.Seal(payload.ServiceName, payload.AppVersion, payload.Files, payload.Dependencies, payload.VerificationRecipe, key)
	if err != nil {
		log.Printf("[BACKUP] export capsule: seal failed: %s", backup.AuditSafe(err.Error()))
		if errors.Is(err, capsule.ErrCapsuleTooLarge) {
			writeError(w, http.StatusRequestEntityTooLarge, backup.TooLargeMessage)
			return
		}
		writeError(w, http.StatusInternalServerError, "Failed to seal capsule")
		return
	}
	if !h.recordCritical(w, r, "admin.backup_capsule_export", adminID, adminUsername, m.CapsuleID, "success", map[string]any{
		"capsule_id": m.CapsuleID, "recovery_key_id": m.RecoveryKeyID, "size_bytes": len(raw),
	}) {
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s.kycap"`, backup.FilenameSafe(m.CapsuleID)))
	w.Header().Set("X-Recovery-Key-ID", m.RecoveryKeyID)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(raw)
}

type RemotePairRequest struct {
	RecoveryURL string `json:"recovery_url"`
	PairingCode string `json:"pairing_code"`
}

// PairRemote claims a 6-digit PIN with KyRecovery, pins the suite recovery public key it
// hands back, and stores the URL and the sealed bearer token.
func (h *BackupHandler) PairRemote(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed")
		return
	}
	adminID, adminUsername := h.actor(r)
	var req RemotePairRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid JSON request body")
		return
	}
	if req.RecoveryURL == "" || req.PairingCode == "" {
		writeError(w, http.StatusBadRequest, "Both recovery_url and pairing_code are required")
		return
	}
	// Validated here as well as in the client so a bad URL is rejected before it is stored
	// or audited as a pairing attempt.
	if err := backup.ValidateRecoveryURL(req.RecoveryURL); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	target := backup.AuditSafe(req.RecoveryURL)
	fail := func(status int, msg string) {
		_ = h.record(r, "admin.backup_remote_pair", adminID, adminUsername, target, "failure", map[string]any{"recovery_url": target, "error": backup.AuditSafe(msg)})
		writeError(w, status, msg)
	}

	// The service name sent here is what kyrecovery pins for the token and what every
	// capsule's manifest is checked against, so it is the same AppName the collector seals under.
	result, err := h.recovery.ClaimPairing(r.Context(), req.RecoveryURL, req.PairingCode, h.cfg.AppName, h.cfg.AppName)
	if err != nil {
		fail(http.StatusBadRequest, err.Error())
		return
	}
	if err := backup.StoreRecoveryKey(h.cfg.DataDir, h.store, result.Key); err != nil {
		if errors.Is(err, fs.ErrExist) {
			fail(http.StatusConflict, "Already paired to a different recovery key")
			return
		}
		fail(http.StatusInternalServerError, "Failed to save recovery key")
		return
	}
	// The pin is now on disk whatever happens next, so it is recorded whatever happens next:
	// a write-once pin that exists nowhere in the audit trail is the gap this closes.
	if err := backup.StorePairing(h.store, h.cfg.EncryptionKey, req.RecoveryURL, result.APIToken); err != nil {
		_ = h.record(r, "admin.backup_remote_pair", adminID, adminUsername, target, "failure", map[string]any{
			"recovery_url": target, "recovery_key_id": result.Key.Public.ID(), "error": "key pinned but the pairing was not stored: " + backup.AuditSafe(err.Error()),
		})
		writeError(w, http.StatusInternalServerError, "Failed to persist recovery pairing")
		return
	}
	_ = h.record(r, "admin.backup_remote_pair", adminID, adminUsername, target, "success", map[string]any{
		"recovery_url": target, "recovery_key_id": result.Key.Public.ID(), "threshold": result.Key.Threshold, "total_shares": result.Key.TotalShares,
	})
	writeJSON(w, http.StatusOK, map[string]any{
		"paired":          true,
		"recovery_url":    req.RecoveryURL,
		"recovery_key_id": result.Key.Public.ID(),
		"threshold":       result.Key.Threshold,
		"total_shares":    result.Key.TotalShares,
	})
}

// Deposit seals a capsule and deposits it with KyRecovery now, outside the schedule. The
// deposit runs on a context that outlives the request: once bytes are on their way, a closed
// tab must not leave KyRecovery holding a capsule this instance has no receipt for.
func (h *BackupHandler) Deposit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed")
		return
	}
	_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(depositWriteBudget))
	adminID, adminUsername := h.actor(r)
	ctx := context.WithoutCancel(r.Context())
	rcpt, m, err := backup.DepositBackup(ctx, h.cfg, h.store, h.store, h.recovery, appVersion)
	action, outcome, details := backup.Outcome(rcpt, m, err)
	_ = h.record(r, action, adminID, adminUsername, rcpt.CapsuleID, outcome, details)
	if errors.Is(err, backup.ErrReceiptUnrecorded) {
		log.Printf("[BACKUP] deposit %s: receipt not recorded: %s", rcpt.CapsuleID, backup.AuditSafe(err.Error()))
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("Capsule %s was deposited but the receipt could not be recorded locally", rcpt.CapsuleID))
		return
	}
	if err != nil {
		switch {
		case errors.Is(err, backup.ErrKeyPinMissing):
			writeError(w, http.StatusPreconditionFailed, "Paired with KyRecovery but the recovery public key is missing or does not match the pin; restore recovery.pub or re-pair")
		case errors.Is(err, backup.ErrNotPaired):
			writeError(w, http.StatusPreconditionFailed, "Not paired with KyRecovery")
		case errors.Is(err, backup.ErrRecoveryKeyMismatch):
			writeError(w, http.StatusConflict, "Recovery key file does not match the pinned key ID; refusing to seal")
		case errors.Is(err, backup.ErrDepositInProgress):
			writeError(w, http.StatusConflict, "A deposit is already in progress")
		case errors.Is(err, capsule.ErrCapsuleTooLarge):
			writeError(w, http.StatusRequestEntityTooLarge, backup.TooLargeMessage)
		case errors.Is(err, backup.ErrRemote):
			log.Printf("[BACKUP] deposit failed: %s", backup.AuditSafe(err.Error()))
			writeError(w, http.StatusBadGateway, "KyRecovery did not accept the deposit")
		default:
			log.Printf("[BACKUP] deposit failed (local): %s", backup.AuditSafe(err.Error()))
			writeError(w, http.StatusInternalServerError, "Deposit failed before reaching KyRecovery")
		}
		return
	}
	writeJSON(w, http.StatusOK, rcpt)
}

// Status reports pairing and the last receipt. It never decrypts or echoes the credential.
func (h *BackupHandler) Status(w http.ResponseWriter, r *http.Request) {
	out := map[string]any{
		"paired":      false,
		"app_name":    h.cfg.AppName,
		"app_version": appVersion,
	}
	if u, err := h.store.GetSetting("kyrecovery_url"); err == nil {
		out["recovery_url"] = u
	}
	if key, err := backup.LoadRecoveryKey(h.cfg.DataDir, h.store); err == nil {
		out["paired"] = backup.HasPairing(h.store)
		out["recovery_key_id"] = key.Public.ID()
		out["threshold"] = key.Threshold
		out["total_shares"] = key.TotalShares
	} else if errors.Is(err, backup.ErrRecoveryKeyMismatch) {
		out["recovery_key_error"] = "recovery.pub does not match the pinned key ID"
	}
	if last, ok, err := backup.LastDeposit(h.store); err == nil && ok {
		out["last_deposit"] = last
	}
	if h.cfg.BackupDepositInterval > 0 {
		out["deposit_interval_sec"] = int64(h.cfg.BackupDepositInterval / time.Second)
	}
	writeJSON(w, http.StatusOK, out)
}
