package api

import (
	"encoding/json"
	"net/http"

	"github.com/Yoshiofthewire/kysignon-server/internal/audit"
	"github.com/Yoshiofthewire/kysignon-server/internal/mfa"
	"github.com/Yoshiofthewire/kysignon-server/internal/store"
)

type DeviceHandler struct {
	store      *store.Store
	mfaEngine  *mfa.Engine
	audit      *audit.Logger
	middleware *MiddlewareManager
	issuerURL  string
}

func NewDeviceHandler(s *store.Store, mfaEngine *mfa.Engine, audit *audit.Logger, mm *MiddlewareManager, issuerURL string) *DeviceHandler {
	return &DeviceHandler{
		store:      s,
		mfaEngine:  mfaEngine,
		audit:      audit,
		middleware: mm,
		issuerURL:  issuerURL,
	}
}

// GenerateDevicePairingToken creates an ephemeral 90s PIN/QR pairing token.
func (h *DeviceHandler) GenerateDevicePairingToken(w http.ResponseWriter, r *http.Request) {
	user := GetUserFromContext(r.Context())
	if user == nil {
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		return
	}

	token, pin, expiresAt, err := h.mfaEngine.GenerateDevicePairingToken(user.ID)
	if err != nil {
		http.Error(w, `{"error":"internal_error"}`, http.StatusInternalServerError)
		return
	}

	qrPayload := map[string]any{
		"type":         "kysignon_device_pairing",
		"serverUrl":    h.issuerURL,
		"pairingToken": token,
		"pinCode":      pin,
		"username":     user.Username,
		"expiresAt":    expiresAt.Unix(),
	}
	qrBytes, _ := json.Marshal(qrPayload)

	h.audit.Record("device.pairing_token_generated", user.ID, user.Username, user.ID, "user", h.middleware.ClientIP(r), r.UserAgent(), "success", nil)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"pairingToken": token,
		"pinCode":      pin,
		"expiresAt":    expiresAt,
		"qrPayload":    string(qrBytes),
	})
}

// RegisterNativeDevice allows native mobile client to exchange 90s pairing token or PIN for registration.
func (h *DeviceHandler) RegisterNativeDevice(w http.ResponseWriter, r *http.Request) {
	var req mfa.NativeDeviceRegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid_request","error_description":"Malformed JSON body"}`, http.StatusBadRequest)
		return
	}

	dev, err := h.mfaEngine.RegisterNativeDevice(&req)
	if err != nil {
		http.Error(w, `{"error":"registration_failed","error_description":"`+err.Error()+`"}`, http.StatusBadRequest)
		return
	}

	h.audit.Record("device.registered", dev.UserID, "", dev.ID, "device", h.middleware.ClientIP(r), r.UserAgent(), "success", map[string]any{
		"deviceName": dev.DeviceName,
	})

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"success":  true,
		"deviceId": dev.ID,
		"device":   dev,
	})
}

// ListUserDevices lists registered devices for current user.
func (h *DeviceHandler) ListUserDevices(w http.ResponseWriter, r *http.Request) {
	user := GetUserFromContext(r.Context())
	if user == nil {
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		return
	}

	devices, err := h.store.ListUserNativeDevices(user.ID)
	if err != nil {
		http.Error(w, `{"error":"internal_error"}`, http.StatusInternalServerError)
		return
	}

	if devices == nil {
		devices = []store.NativeDevice{}
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"devices": devices})
}

// DeleteUserDevice deletes a device.
func (h *DeviceHandler) DeleteUserDevice(w http.ResponseWriter, r *http.Request) {
	user := GetUserFromContext(r.Context())
	if user == nil {
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		return
	}

	deviceID := r.PathValue("id")
	if deviceID == "" {
		http.Error(w, `{"error":"device_id_required"}`, http.StatusBadRequest)
		return
	}

	if err := h.store.DeleteNativeDevice(deviceID, user.ID); err != nil {
		http.Error(w, `{"error":"internal_error"}`, http.StatusInternalServerError)
		return
	}

	h.audit.Record("device.deleted", user.ID, user.Username, deviceID, "device", h.middleware.ClientIP(r), r.UserAgent(), "success", nil)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

// SetDeviceMFAApprover enables/disables a device as an MFA approver.
func (h *DeviceHandler) SetDeviceMFAApprover(w http.ResponseWriter, r *http.Request) {
	user := GetUserFromContext(r.Context())
	if user == nil {
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		return
	}

	deviceID := r.PathValue("id")
	var req struct {
		IsMFAApprover bool `json:"isMfaApprover"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid_request"}`, http.StatusBadRequest)
		return
	}

	if err := h.store.SetNativeDeviceMFAApprover(deviceID, user.ID, req.IsMFAApprover); err != nil {
		http.Error(w, `{"error":"internal_error"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

// SetupTOTP generates a new TOTP secret and QR/URI.
func (h *DeviceHandler) SetupTOTP(w http.ResponseWriter, r *http.Request) {
	user := GetUserFromContext(r.Context())
	if user == nil {
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		return
	}

	secret, uri, err := h.mfaEngine.GenerateTOTPSecret(user.Username, "KySignOn")
	if err != nil {
		http.Error(w, `{"error":"internal_error"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"secret": secret,
		"uri":    uri,
	})
}

type EnableTOTPRequest struct {
	Secret string `json:"secret"`
	Code   string `json:"code"`
}

// EnableTOTP validates the code and persists the TOTP secret.
func (h *DeviceHandler) EnableTOTP(w http.ResponseWriter, r *http.Request) {
	user := GetUserFromContext(r.Context())
	if user == nil {
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		return
	}

	var req EnableTOTPRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Secret == "" || req.Code == "" {
		http.Error(w, `{"error":"invalid_request"}`, http.StatusBadRequest)
		return
	}

	if !mfa.ValidateTOTP(req.Secret, req.Code) {
		http.Error(w, `{"error":"invalid_code","error_description":"TOTP code verification failed"}`, http.StatusBadRequest)
		return
	}

	if err := h.mfaEngine.SaveUserTOTP(user.ID, req.Secret); err != nil {
		http.Error(w, `{"error":"internal_error"}`, http.StatusInternalServerError)
		return
	}

	recoveryCodes, err := h.mfaEngine.GenerateRecoveryCodes(user.ID)
	if err != nil {
		http.Error(w, `{"error":"internal_error"}`, http.StatusInternalServerError)
		return
	}

	h.audit.Record("mfa.totp_enabled", user.ID, user.Username, user.ID, "user", h.middleware.ClientIP(r), r.UserAgent(), "success", nil)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"success":       true,
		"recoveryCodes": recoveryCodes,
	})
}

// GenerateRecoveryCodes generates 8 new recovery codes for user.
func (h *DeviceHandler) GenerateRecoveryCodes(w http.ResponseWriter, r *http.Request) {
	user := GetUserFromContext(r.Context())
	if user == nil {
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		return
	}

	codes, err := h.mfaEngine.GenerateRecoveryCodes(user.ID)
	if err != nil {
		http.Error(w, `{"error":"internal_error"}`, http.StatusInternalServerError)
		return
	}

	h.audit.Record("mfa.recovery_codes_generated", user.ID, user.Username, user.ID, "user", h.middleware.ClientIP(r), r.UserAgent(), "success", nil)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"recoveryCodes": codes,
	})
}

// ListApplications returns dashboard application links.
func (h *DeviceHandler) ListApplications(w http.ResponseWriter, r *http.Request) {
	apps, err := h.store.ListApplications()
	if err != nil {
		http.Error(w, `{"error":"internal_error"}`, http.StatusInternalServerError)
		return
	}

	if apps == nil {
		apps = []store.Application{}
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"applications": apps})
}
