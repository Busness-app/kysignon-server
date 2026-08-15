package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/Yoshiofthewire/kysignon-server/internal/audit"
	"github.com/Yoshiofthewire/kysignon-server/internal/auth"
	"github.com/Yoshiofthewire/kysignon-server/internal/crypto"
	"github.com/Yoshiofthewire/kysignon-server/internal/mfa"
	"github.com/Yoshiofthewire/kysignon-server/internal/store"
	"github.com/google/uuid"
)

type AuthHandler struct {
	store      *store.Store
	mfaEngine  *mfa.Engine
	audit      *audit.Logger
	middleware *MiddlewareManager
}

func NewAuthHandler(s *store.Store, mfaEngine *mfa.Engine, audit *audit.Logger, mm *MiddlewareManager) *AuthHandler {
	return &AuthHandler{
		store:      s,
		mfaEngine:  mfaEngine,
		audit:      audit,
		middleware: mm,
	}
}

// GetCSRFToken issues a random CSRF token cookie and returns it.
func (h *AuthHandler) GetCSRFToken(w http.ResponseWriter, r *http.Request) {
	csrfToken, err := crypto.GenerateRandomHex(32)
	if err != nil {
		http.Error(w, `{"error":"internal_error"}`, http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "kysignon_csrf",
		Value:    csrfToken,
		Path:     "/",
		SameSite: http.SameSiteLaxMode,
		HttpOnly: false, // Accessible by frontend JavaScript for double-submit header
		Secure:   r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https",
	})

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"csrfToken": csrfToken})
}

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type LoginResponse struct {
	Success     bool     `json:"success"`
	MFARequired bool     `json:"mfaRequired,omitempty"`
	MFAToken    string   `json:"mfaToken,omitempty"`
	MFAMethods  []string `json:"mfaMethods,omitempty"`
	ChallengeID string   `json:"challengeId,omitempty"`
	MatchDigits string   `json:"matchDigits,omitempty"`
	DecoyDigits []string `json:"decoyDigits,omitempty"`
	User        any      `json:"user,omitempty"`
}

// Login handles primary username/password verification.
func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid_request","error_description":"Malformed JSON body"}`, http.StatusBadRequest)
		return
	}

	ip := h.middleware.ClientIP(r)
	ua := r.UserAgent()

	user, err := h.store.GetUserByUsername(req.Username)
	if err != nil || user == nil {
		h.audit.Record("auth.login", "", req.Username, "", "user", ip, ua, "failure", map[string]any{"reason": "user_not_found"})
		http.Error(w, `{"error":"invalid_credentials","error_description":"Invalid username or password"}`, http.StatusUnauthorized)
		return
	}

	if user.Status != "active" {
		h.audit.Record("auth.login", user.ID, user.Username, user.ID, "user", ip, ua, "denied", map[string]any{"reason": "user_disabled"})
		http.Error(w, `{"error":"account_disabled","error_description":"Account is disabled"}`, http.StatusForbidden)
		return
	}

	validPass, err := auth.VerifyPassword(req.Password, user.PasswordHash)
	if err != nil || !validPass {
		h.audit.Record("auth.login", user.ID, user.Username, user.ID, "user", ip, ua, "failure", map[string]any{"reason": "invalid_password"})
		http.Error(w, `{"error":"invalid_credentials","error_description":"Invalid username or password"}`, http.StatusUnauthorized)
		return
	}

	// Check if user has enrolled MFA methods
	mfaMethods, err := h.store.ListUserMFAMethods(user.ID)
	if err != nil {
		http.Error(w, `{"error":"internal_error"}`, http.StatusInternalServerError)
		return
	}

	var methodTypes []string
	hasPush := false
	for _, m := range mfaMethods {
		methodTypes = append(methodTypes, m.MethodType)
		if m.MethodType == "push" {
			hasPush = true
		}
	}

	if len(methodTypes) > 0 {
		mfaToken, err := crypto.GenerateRandomHex(32)
		if err != nil {
			http.Error(w, `{"error":"internal_error"}`, http.StatusInternalServerError)
			return
		}

		resp := LoginResponse{
			Success:     false,
			MFARequired: true,
			MFAToken:    mfaToken + ":" + user.ID, // ephemeral token for second-factor completion
			MFAMethods:  methodTypes,
		}

		if hasPush {
			challenge, err := h.mfaEngine.CreatePushChallenge(user.ID)
			if err == nil && challenge != nil {
				resp.ChallengeID = challenge.ID
				resp.MatchDigits = challenge.MatchDigits
				var decoys []string
				_ = json.Unmarshal([]byte(challenge.DecoyDigitsJSON), &decoys)
				resp.DecoyDigits = decoys
			}
		}

		h.audit.Record("auth.mfa_challenge", user.ID, user.Username, user.ID, "user", ip, ua, "success", map[string]any{"methods": methodTypes})
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
		return
	}

	// No MFA enrolled, issue session directly
	h.createSessionAndRespond(w, r, user)
}

func (h *AuthHandler) createSessionAndRespond(w http.ResponseWriter, r *http.Request, user *store.User) {
	rawToken, err := crypto.GenerateRandomHex(32)
	if err != nil {
		http.Error(w, `{"error":"internal_error"}`, http.StatusInternalServerError)
		return
	}

	tokenHash := crypto.HashSHA256(rawToken)
	ip := h.middleware.ClientIP(r)
	ua := r.UserAgent()
	expiresAt := time.Now().UTC().Add(24 * time.Hour)

	sess := &store.Session{
		ID:               uuid.New().String(),
		UserID:           user.ID,
		SessionTokenHash: tokenHash,
		IPAddress:        ip,
		UserAgent:        ua,
		ExpiresAt:        expiresAt,
	}

	if err := h.store.CreateSession(sess); err != nil {
		http.Error(w, `{"error":"internal_error"}`, http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "kysignon_session",
		Value:    rawToken,
		Path:     "/",
		Expires:  expiresAt,
		SameSite: http.SameSiteLaxMode,
		HttpOnly: true,
		Secure:   r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https",
	})

	h.audit.Record("auth.login_success", user.ID, user.Username, user.ID, "user", ip, ua, "success", nil)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(LoginResponse{
		Success: true,
		User: map[string]any{
			"id":          user.ID,
			"username":    user.Username,
			"displayName": user.DisplayName,
			"email":       user.Email,
			"role":        user.Role,
		},
	})
}

type MFAVerifyRequest struct {
	MFAToken string `json:"mfaToken"`
	Code     string `json:"code"`
}

// VerifyTOTP verifies a TOTP code and finishes login.
func (h *AuthHandler) VerifyTOTP(w http.ResponseWriter, r *http.Request) {
	var req MFAVerifyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.MFAToken == "" || req.Code == "" {
		http.Error(w, `{"error":"invalid_request"}`, http.StatusBadRequest)
		return
	}

	parts := strings.Split(req.MFAToken, ":")
	if len(parts) != 2 {
		http.Error(w, `{"error":"invalid_mfa_token"}`, http.StatusUnauthorized)
		return
	}
	userID := parts[1]

	user, err := h.store.GetUserByID(userID)
	if err != nil || user == nil || user.Status != "active" {
		http.Error(w, `{"error":"invalid_user"}`, http.StatusUnauthorized)
		return
	}

	valid, err := h.mfaEngine.VerifyUserTOTP(userID, req.Code)
	if err != nil || !valid {
		h.audit.Record("auth.mfa_totp", userID, user.Username, userID, "user", h.middleware.ClientIP(r), r.UserAgent(), "failure", nil)
		http.Error(w, `{"error":"invalid_totp_code","error_description":"Invalid 6-digit TOTP code"}`, http.StatusUnauthorized)
		return
	}

	h.createSessionAndRespond(w, r, user)
}

// VerifyRecoveryCode verifies a one-time recovery code and finishes login.
func (h *AuthHandler) VerifyRecoveryCode(w http.ResponseWriter, r *http.Request) {
	var req MFAVerifyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.MFAToken == "" || req.Code == "" {
		http.Error(w, `{"error":"invalid_request"}`, http.StatusBadRequest)
		return
	}

	parts := strings.Split(req.MFAToken, ":")
	if len(parts) != 2 {
		http.Error(w, `{"error":"invalid_mfa_token"}`, http.StatusUnauthorized)
		return
	}
	userID := parts[1]

	user, err := h.store.GetUserByID(userID)
	if err != nil || user == nil || user.Status != "active" {
		http.Error(w, `{"error":"invalid_user"}`, http.StatusUnauthorized)
		return
	}

	valid, err := h.mfaEngine.VerifyAndConsumeRecoveryCode(userID, req.Code)
	if err != nil || !valid {
		h.audit.Record("auth.mfa_recovery", userID, user.Username, userID, "user", h.middleware.ClientIP(r), r.UserAgent(), "failure", nil)
		http.Error(w, `{"error":"invalid_recovery_code","error_description":"Invalid or already used recovery code"}`, http.StatusUnauthorized)
		return
	}

	h.audit.Record("auth.mfa_recovery_consumed", userID, user.Username, userID, "user", h.middleware.ClientIP(r), r.UserAgent(), "success", nil)
	h.createSessionAndRespond(w, r, user)
}

type PushPollRequest struct {
	ChallengeID string `json:"challengeId"`
}

// PollPushChallenge checks the status of a pending push challenge.
func (h *AuthHandler) PollPushChallenge(w http.ResponseWriter, r *http.Request) {
	var req PushPollRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.ChallengeID == "" {
		http.Error(w, `{"error":"invalid_request"}`, http.StatusBadRequest)
		return
	}

	status, err := h.mfaEngine.CheckPushChallenge(req.ChallengeID)
	if err != nil {
		http.Error(w, `{"error":"not_found"}`, http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": status})
}

type PushFinishRequest struct {
	MFAToken    string `json:"mfaToken"`
	ChallengeID string `json:"challengeId"`
}

// FinishPushLogin establishes session after push challenge is approved.
func (h *AuthHandler) FinishPushLogin(w http.ResponseWriter, r *http.Request) {
	var req PushFinishRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.MFAToken == "" || req.ChallengeID == "" {
		http.Error(w, `{"error":"invalid_request"}`, http.StatusBadRequest)
		return
	}

	parts := strings.Split(req.MFAToken, ":")
	if len(parts) != 2 {
		http.Error(w, `{"error":"invalid_mfa_token"}`, http.StatusUnauthorized)
		return
	}
	userID := parts[1]

	user, err := h.store.GetUserByID(userID)
	if err != nil || user == nil || user.Status != "active" {
		http.Error(w, `{"error":"invalid_user"}`, http.StatusUnauthorized)
		return
	}

	status, err := h.mfaEngine.CheckPushChallenge(req.ChallengeID)
	if err != nil || status != "approved" {
		http.Error(w, `{"error":"mfa_not_approved","error_description":"Push challenge is not approved"}`, http.StatusUnauthorized)
		return
	}

	h.audit.Record("auth.mfa_push_approved", userID, user.Username, userID, "user", h.middleware.ClientIP(r), r.UserAgent(), "success", nil)
	h.createSessionAndRespond(w, r, user)
}

type PushRespondRequest struct {
	ChallengeID    string `json:"challengeId"`
	SelectedDigits string `json:"selectedDigits"`
	Approve        bool   `json:"approve"`
}

// RespondPush handles incoming match digits response from paired mobile authenticator.
func (h *AuthHandler) RespondPush(w http.ResponseWriter, r *http.Request) {
	var req PushRespondRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.ChallengeID == "" {
		http.Error(w, `{"error":"invalid_request"}`, http.StatusBadRequest)
		return
	}

	ok, err := h.mfaEngine.RespondPushChallenge(req.ChallengeID, req.SelectedDigits, req.Approve)
	if err != nil {
		http.Error(w, `{"error":"challenge_error","error_description":"`+err.Error()+`"}`, http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]bool{"success": ok})
}

// PullNotifications provides pull queue for clients without direct push relays.
func (h *AuthHandler) PullNotifications(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"notifications": []any{}})
}

// Logout revokes active session.
func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	sess := GetSessionFromContext(r.Context())
	user := GetUserFromContext(r.Context())

	if sess != nil {
		_ = h.store.DeleteSession(sess.ID)
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "kysignon_session",
		Value:    "",
		Path:     "/",
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
		SameSite: http.SameSiteLaxMode,
		HttpOnly: true,
	})

	if user != nil {
		h.audit.Record("auth.logout", user.ID, user.Username, user.ID, "user", h.middleware.ClientIP(r), r.UserAgent(), "success", nil)
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

// Me returns the current authenticated user profile.
func (h *AuthHandler) Me(w http.ResponseWriter, r *http.Request) {
	user := GetUserFromContext(r.Context())
	if user == nil {
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		return
	}

	mfaMethods, _ := h.store.ListUserMFAMethods(user.ID)
	var methodTypes []string
	for _, m := range mfaMethods {
		methodTypes = append(methodTypes, m.MethodType)
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"id":          user.ID,
		"username":    user.Username,
		"displayName": user.DisplayName,
		"email":       user.Email,
		"role":        user.Role,
		"mfaMethods":  methodTypes,
		"createdAt":   user.CreatedAt,
	})
}
