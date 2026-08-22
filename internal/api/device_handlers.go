package api

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"sort"
	"strings"

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
		log.Printf("device pairing token creation failed for user %s: %v", user.ID, err)
		http.Error(w, `{"error":"internal_error"}`, http.StatusInternalServerError)
		return
	}

	qrPayload := map[string]any{
		"type":      "kysignon_device_pairing",
		"serverUrl": h.issuerURL,
		// The token is the credential. userId is carried so a device pairing by PIN can
		// scope its redemption to this account rather than matching any live PIN.
		"pairingToken": token,
		"pinCode":      pin,
		"userId":       user.ID,
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

	// Checked but not spent: this only mints a candidate secret, and failing here rather
	// than after the operator has scanned a QR code is the better experience.
	if err := requireStepUp(h.store, r); err != nil {
		writeStepUpError(w, err)
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

	// A code generated by this request's own secret proves nothing about the account holder,
	// so entitlement comes from the step-up grant, not from the code below.
	if err := consumeStepUp(h.store, r); err != nil {
		writeStepUpError(w, err)
		return
	}

	if !mfa.ValidateTOTP(req.Secret, req.Code) {
		http.Error(w, `{"error":"invalid_code","error_description":"TOTP code verification failed"}`, http.StatusBadRequest)
		return
	}

	// Enrolling a factor and the record of who enrolled it commit together. An account that
	// gained an authenticator with no durable trail of where it came from is exactly the
	// state an attacker who has borrowed a session wants to leave behind.
	enabled := h.audit.Prepare("mfa.totp_enabled", user.ID, user.Username, user.ID, "user", h.middleware.ClientIP(r), r.UserAgent(), "success", nil)
	if err := h.mfaEngine.SaveUserTOTP(user.ID, req.Secret, enabled.Row); err != nil {
		http.Error(w, `{"error":"internal_error"}`, http.StatusInternalServerError)
		return
	}
	enabled.Committed()

	issued := h.audit.Prepare("mfa.recovery_codes_generated", user.ID, user.Username, user.ID, "user", h.middleware.ClientIP(r), r.UserAgent(), "success", map[string]any{"reason": "totp_enrollment"})
	recoveryCodes, err := h.mfaEngine.GenerateRecoveryCodes(user.ID, issued.Row)
	if err != nil {
		http.Error(w, `{"error":"internal_error"}`, http.StatusInternalServerError)
		return
	}
	issued.Committed()

	// Replacing a factor logs out every other session. If this replacement was an attacker
	// with a stolen cookie, the legitimate user keeps nothing; if it was the legitimate
	// user, the stolen cookie is what gets cut.
	if sess := GetSessionFromContext(r.Context()); sess != nil {
		if err := h.store.DeleteOtherUserSessions(user.ID, sess.ID); err != nil {
			log.Printf("failed to revoke sibling sessions after TOTP replacement for %s: %v", user.ID, err)
		}
	}

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

	// Regenerating invalidates the codes the account holder is already storing offline, so
	// it is a factor change and gated the same way.
	if err := consumeStepUp(h.store, r); err != nil {
		writeStepUpError(w, err)
		return
	}

	regenerated := h.audit.Prepare("mfa.recovery_codes_generated", user.ID, user.Username, user.ID, "user", h.middleware.ClientIP(r), r.UserAgent(), "success", nil)
	codes, err := h.mfaEngine.GenerateRecoveryCodes(user.ID, regenerated.Row)
	if err != nil {
		http.Error(w, `{"error":"internal_error"}`, http.StatusInternalServerError)
		return
	}
	regenerated.Committed()

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"recoveryCodes": codes,
	})
}

// ListApplications returns dashboard application links, aggregating custom applications and registered OAuth clients.
func (h *DeviceHandler) ListApplications(w http.ResponseWriter, r *http.Request) {
	customApps, err := h.store.ListApplications()
	if err != nil {
		http.Error(w, `{"error":"internal_error"}`, http.StatusInternalServerError)
		return
	}

	oauthClients, err := h.store.ListOAuthClients()
	if err != nil {
		oauthClients = []store.OAuthClient{}
	}

	appMap := make(map[string]store.Application)
	for _, app := range customApps {
		if app.Enabled {
			appMap[app.ID] = app
		}
	}

	// Add OAuth clients as launchable applications
	for _, client := range oauthClients {
		if !client.Enabled {
			continue
		}
		if _, exists := appMap[client.ID]; exists {
			continue
		}

		launchURL := strings.TrimSpace(client.LaunchURL)
		if launchURL == "" {
			var uris []string
			_ = json.Unmarshal([]byte(client.RedirectURIsJSON), &uris)
			origin := ""
			for _, uStr := range uris {
				if parsed, err := url.Parse(uStr); err == nil && parsed.Scheme != "" && parsed.Host != "" {
					if origin == "" || (strings.Contains(origin, "localhost") && !strings.Contains(parsed.Host, "localhost")) {
						origin = fmt.Sprintf("%s://%s", parsed.Scheme, parsed.Host)
					}
				}
			}

			if origin != "" {
				switch strings.ToLower(client.ID) {
				case "kydns":
					launchURL = origin + "/auth/sso/login"
				case "kypost":
					launchURL = origin + "/api/auth/oidc/login"
				case "kypasswords":
					launchURL = origin + "/api/auth/oidc/login"
				case "kybookmarks":
					launchURL = origin + "/api/auth/oidc/login"
				case "kynotes":
					launchURL = origin + "/api/auth/oidc/login"
				default:
					launchURL = origin
				}
			} else if len(uris) > 0 {
				launchURL = uris[0]
			}
		}

		if launchURL != "" {
			iconName := "globe"
			switch strings.ToLower(client.ID) {
			case "kydns":
				iconName = "globe"
			case "kypost":
				iconName = "mail"
			case "kypasswords":
				iconName = "lock"
			case "kybookmarks":
				iconName = "bookmark"
			case "kynotes":
				iconName = "file-text"
			}

			appMap[client.ID] = store.Application{
				ID:          client.ID,
				Name:        client.ClientName,
				URL:         launchURL,
				IconName:    iconName,
				Description: fmt.Sprintf("OAuth 2.0 / OIDC SSO App (%s)", client.ClientType),
				Enabled:     true,
			}
		}
	}

	result := make([]store.Application, 0, len(appMap))
	for _, app := range appMap {
		result = append(result, app)
	}
	// Map iteration order is randomised, so without this the launcher reshuffles on every
	// page load despite sort_order existing.
	sort.Slice(result, func(i, j int) bool {
		if result[i].SortOrder != result[j].SortOrder {
			return result[i].SortOrder < result[j].SortOrder
		}
		return result[i].Name < result[j].Name
	})

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"applications": result})
}
