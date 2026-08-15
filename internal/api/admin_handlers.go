package api

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"github.com/Yoshiofthewire/kysignon-server/internal/audit"
	"github.com/Yoshiofthewire/kysignon-server/internal/auth"
	"github.com/Yoshiofthewire/kysignon-server/internal/crypto"
	"github.com/Yoshiofthewire/kysignon-server/internal/store"
	"github.com/Yoshiofthewire/kysignon-server/internal/sync"
)

type AdminHandler struct {
	store      *store.Store
	syncEngine *sync.Engine
	audit      *audit.Logger
	middleware *MiddlewareManager
	issuerURL  string
}

func NewAdminHandler(s *store.Store, syncEngine *sync.Engine, audit *audit.Logger, mm *MiddlewareManager, issuerURL string) *AdminHandler {
	return &AdminHandler{
		store:      s,
		syncEngine: syncEngine,
		audit:      audit,
		middleware: mm,
		issuerURL:  issuerURL,
	}
}

// ListUsers lists all user accounts.
func (h *AdminHandler) ListUsers(w http.ResponseWriter, r *http.Request) {
	users, err := h.store.ListUsers()
	if err != nil {
		http.Error(w, `{"error":"internal_error"}`, http.StatusInternalServerError)
		return
	}
	if users == nil {
		users = []store.User{}
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"users": users})
}

type CreateUserRequest struct {
	Username    string `json:"username"`
	DisplayName string `json:"displayName"`
	Email       string `json:"email"`
	Password    string `json:"password"`
	Role        string `json:"role"`   // "user", "admin"
	Status      string `json:"status"` // "active", "disabled"
}

// CreateUser creates a new user account and dispatches replication event.
func (h *AdminHandler) CreateUser(w http.ResponseWriter, r *http.Request) {
	admin := GetUserFromContext(r.Context())
	var req CreateUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid_request"}`, http.StatusBadRequest)
		return
	}

	req.Username = strings.TrimSpace(req.Username)
	req.Email = strings.TrimSpace(req.Email)
	req.DisplayName = strings.TrimSpace(req.DisplayName)

	if req.Username == "" || req.Email == "" || req.Password == "" {
		http.Error(w, `{"error":"missing_fields","error_description":"Username, email, and password are required"}`, http.StatusBadRequest)
		return
	}

	if req.Role != "admin" {
		req.Role = "user"
	}
	if req.Status != "disabled" {
		req.Status = "active"
	}

	passHash, err := auth.HashPassword(req.Password)
	if err != nil {
		http.Error(w, `{"error":"password_policy","error_description":"`+err.Error()+`"}`, http.StatusBadRequest)
		return
	}

	user := &store.User{
		ID:           uuid.New().String(),
		Username:     req.Username,
		DisplayName:  req.DisplayName,
		Email:        req.Email,
		PasswordHash: passHash,
		Role:         req.Role,
		Status:       req.Status,
	}

	if err := h.store.CreateUser(user); err != nil {
		http.Error(w, `{"error":"user_exists","error_description":"Username or email already exists"}`, http.StatusConflict)
		return
	}

	// Queue account replication to downstream KySecurity products
	_ = h.syncEngine.QueueAccountSyncEvent(user.ID, "user.created", map[string]any{
		"id":          user.ID,
		"username":    user.Username,
		"displayName": user.DisplayName,
		"email":       user.Email,
		"role":        user.Role,
		"status":      user.Status,
	})

	h.audit.Record("admin.user_created", admin.ID, admin.Username, user.ID, "user", h.middleware.ClientIP(r), r.UserAgent(), "success", map[string]any{
		"username": user.Username,
		"role":     user.Role,
	})

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"success": true,
		"user":    user,
	})
}

// UpdateUser updates user profile and dispatches replication event.
func (h *AdminHandler) UpdateUser(w http.ResponseWriter, r *http.Request) {
	admin := GetUserFromContext(r.Context())
	userID := r.PathValue("id")

	var req struct {
		DisplayName string `json:"displayName"`
		Email       string `json:"email"`
		Role        string `json:"role"`
		Status      string `json:"status"`
		Password    string `json:"password,omitempty"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid_request"}`, http.StatusBadRequest)
		return
	}

	user, err := h.store.GetUserByID(userID)
	if err != nil || user == nil {
		http.Error(w, `{"error":"user_not_found"}`, http.StatusNotFound)
		return
	}

	if req.DisplayName != "" {
		user.DisplayName = req.DisplayName
	}
	if req.Email != "" {
		user.Email = req.Email
	}
	if req.Role == "user" || req.Role == "admin" {
		user.Role = req.Role
	}
	if req.Status == "active" || req.Status == "disabled" {
		user.Status = req.Status
		if user.Status == "disabled" {
			_ = h.store.DeleteUserSessions(user.ID)
		}
	}

	if err := h.store.UpdateUser(user); err != nil {
		http.Error(w, `{"error":"internal_error"}`, http.StatusInternalServerError)
		return
	}

	if req.Password != "" {
		passHash, err := auth.HashPassword(req.Password)
		if err != nil {
			http.Error(w, `{"error":"password_policy","error_description":"`+err.Error()+`"}`, http.StatusBadRequest)
			return
		}
		_ = h.store.UpdateUserPassword(user.ID, passHash)
		_ = h.store.DeleteUserSessions(user.ID)
	}

	// Queue account replication update
	_ = h.syncEngine.QueueAccountSyncEvent(user.ID, "user.updated", map[string]any{
		"id":          user.ID,
		"username":    user.Username,
		"displayName": user.DisplayName,
		"email":       user.Email,
		"role":        user.Role,
		"status":      user.Status,
	})

	h.audit.Record("admin.user_updated", admin.ID, admin.Username, user.ID, "user", h.middleware.ClientIP(r), r.UserAgent(), "success", map[string]any{
		"username": user.Username,
	})

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"success": true,
		"user":    user,
	})
}

// ResetUserMFA clears MFA methods/devices, revokes active sessions, and dispatches sync event.
func (h *AdminHandler) ResetUserMFA(w http.ResponseWriter, r *http.Request) {
	admin := GetUserFromContext(r.Context())
	userID := r.PathValue("id")

	user, err := h.store.GetUserByID(userID)
	if err != nil || user == nil {
		http.Error(w, `{"error":"user_not_found"}`, http.StatusNotFound)
		return
	}

	if err := h.store.DeleteUserMFAMethods(user.ID); err != nil {
		http.Error(w, `{"error":"internal_error"}`, http.StatusInternalServerError)
		return
	}

	_ = h.store.DeleteUserSessions(user.ID)

	_ = h.syncEngine.QueueAccountSyncEvent(user.ID, "user.mfa_reset", map[string]any{
		"id":       user.ID,
		"username": user.Username,
	})

	h.audit.Record("admin.user_mfa_reset", admin.ID, admin.Username, user.ID, "user", h.middleware.ClientIP(r), r.UserAgent(), "success", map[string]any{
		"username": user.Username,
	})

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

// RevokeUserSessions revokes all sessions for a user.
func (h *AdminHandler) RevokeUserSessions(w http.ResponseWriter, r *http.Request) {
	admin := GetUserFromContext(r.Context())
	userID := r.PathValue("id")

	_ = h.store.DeleteUserSessions(userID)
	h.audit.Record("admin.sessions_revoked", admin.ID, admin.Username, userID, "user", h.middleware.ClientIP(r), r.UserAgent(), "success", nil)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

// DeleteUser deletes a user.
func (h *AdminHandler) DeleteUser(w http.ResponseWriter, r *http.Request) {
	admin := GetUserFromContext(r.Context())
	userID := r.PathValue("id")

	user, err := h.store.GetUserByID(userID)
	if err != nil || user == nil {
		http.Error(w, `{"error":"user_not_found"}`, http.StatusNotFound)
		return
	}

	// Prevent deleting last active admin
	if user.Role == "admin" {
		count, _ := h.store.CountAdmins()
		if count <= 1 {
			http.Error(w, `{"error":"cannot_delete_last_admin","error_description":"Cannot delete the only active administrator"}`, http.StatusBadRequest)
			return
		}
	}

	_ = h.store.DeleteUser(userID)

	_ = h.syncEngine.QueueAccountSyncEvent(userID, "user.deleted", map[string]any{
		"id":       userID,
		"username": user.Username,
	})

	h.audit.Record("admin.user_deleted", admin.ID, admin.Username, userID, "user", h.middleware.ClientIP(r), r.UserAgent(), "success", map[string]any{
		"username": user.Username,
	})

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

// GenerateSystemPairingToken generates a 90s pairing token to connect a KySecurity product.
func (h *AdminHandler) GenerateSystemPairingToken(w http.ResponseWriter, r *http.Request) {
	admin := GetUserFromContext(r.Context())
	var req struct {
		SystemType string `json:"systemType"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.SystemType == "" {
		http.Error(w, `{"error":"system_type_required"}`, http.StatusBadRequest)
		return
	}

	token, pin, expiresAt, err := h.syncEngine.GenerateSystemPairingToken(req.SystemType, admin.ID)
	if err != nil {
		http.Error(w, `{"error":"internal_error"}`, http.StatusInternalServerError)
		return
	}

	qrPayload := map[string]any{
		"type":         "kysignon_system_pairing",
		"serverUrl":    h.issuerURL,
		"systemType":   req.SystemType,
		"pairingToken": token,
		"pinCode":      pin,
		"expiresAt":    expiresAt.Unix(),
	}
	qrBytes, _ := json.Marshal(qrPayload)

	h.audit.Record("admin.system_pairing_token_generated", admin.ID, admin.Username, req.SystemType, "system", h.middleware.ClientIP(r), r.UserAgent(), "success", nil)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"pairingToken": token,
		"pinCode":      pin,
		"systemType":   req.SystemType,
		"expiresAt":    expiresAt,
		"qrPayload":    string(qrBytes),
	})
}

// RegisterPairedSystem handles redemption of a system pairing token.
func (h *AdminHandler) RegisterPairedSystem(w http.ResponseWriter, r *http.Request) {
	var req sync.SystemRegistrationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid_request"}`, http.StatusBadRequest)
		return
	}

	resp, err := h.syncEngine.RegisterPairedSystem(&req)
	if err != nil {
		http.Error(w, `{"error":"registration_failed","error_description":"`+err.Error()+`"}`, http.StatusBadRequest)
		return
	}

	h.audit.Record("system.paired", "", req.SystemName, resp.SystemID, "system", h.middleware.ClientIP(r), r.UserAgent(), "success", map[string]any{
		"systemType": req.SystemType,
	})

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

// ListPairedSystems lists connected KySecurity products.
func (h *AdminHandler) ListPairedSystems(w http.ResponseWriter, r *http.Request) {
	systems, err := h.store.ListAllPairedSystems()
	if err != nil {
		http.Error(w, `{"error":"internal_error"}`, http.StatusInternalServerError)
		return
	}
	if systems == nil {
		systems = []store.PairedSystem{}
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"systems": systems})
}

// ResyncSystem triggers manual full directory replication.
func (h *AdminHandler) ResyncSystem(w http.ResponseWriter, r *http.Request) {
	admin := GetUserFromContext(r.Context())
	systemID := r.PathValue("id")

	if err := h.syncEngine.ResyncAllAccounts(systemID); err != nil {
		http.Error(w, `{"error":"resync_failed","error_description":"`+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}

	h.audit.Record("admin.system_resynced", admin.ID, admin.Username, systemID, "system", h.middleware.ClientIP(r), r.UserAgent(), "success", nil)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

// DeletePairedSystem removes a connected KySecurity product.
func (h *AdminHandler) DeletePairedSystem(w http.ResponseWriter, r *http.Request) {
	admin := GetUserFromContext(r.Context())
	systemID := r.PathValue("id")

	if err := h.store.DeletePairedSystem(systemID); err != nil {
		http.Error(w, `{"error":"internal_error"}`, http.StatusInternalServerError)
		return
	}

	h.audit.Record("admin.system_deleted", admin.ID, admin.Username, systemID, "system", h.middleware.ClientIP(r), r.UserAgent(), "success", nil)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

// OAuth Client Management
func (h *AdminHandler) ListOAuthClients(w http.ResponseWriter, r *http.Request) {
	clients, err := h.store.ListOAuthClients()
	if err != nil {
		http.Error(w, `{"error":"internal_error"}`, http.StatusInternalServerError)
		return
	}
	if clients == nil {
		clients = []store.OAuthClient{}
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"clients": clients})
}

type CreateClientRequest struct {
	ClientID      string   `json:"clientId"`
	ClientName    string   `json:"clientName"`
	ClientType    string   `json:"clientType"` // "public", "confidential"
	RedirectURIs  []string `json:"redirectUris"`
	AllowedScopes []string `json:"allowedScopes"`
}

func (h *AdminHandler) CreateOAuthClient(w http.ResponseWriter, r *http.Request) {
	admin := GetUserFromContext(r.Context())
	var req CreateClientRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.ClientName == "" {
		http.Error(w, `{"error":"invalid_request"}`, http.StatusBadRequest)
		return
	}

	if req.ClientType != "confidential" {
		req.ClientType = "public"
	}
	if len(req.AllowedScopes) == 0 {
		req.AllowedScopes = []string{"openid", "profile", "email"}
	}

	var rawSecret string
	var secretHash string
	if req.ClientType == "confidential" {
		rawSecret, _ = crypto.GenerateRandomHex(32)
		secretHash = crypto.HashSHA256(rawSecret)
	}

	redirectURIsJSON, _ := json.Marshal(req.RedirectURIs)
	scopesJSON, _ := json.Marshal(req.AllowedScopes)

	clientID := strings.TrimSpace(req.ClientID)
	if clientID == "" {
		clientID = uuid.New().String()
	}

	client := &store.OAuthClient{
		ID:                clientID,
		ClientName:        req.ClientName,
		ClientType:        req.ClientType,
		ClientSecretHash:  secretHash,
		RedirectURIsJSON:  string(redirectURIsJSON),
		AllowedScopesJSON: string(scopesJSON),
		Enabled:           true,
	}

	if err := h.store.CreateOAuthClient(client); err != nil {
		http.Error(w, `{"error":"internal_error"}`, http.StatusInternalServerError)
		return
	}

	h.audit.Record("admin.oauth_client_created", admin.ID, admin.Username, client.ID, "client", h.middleware.ClientIP(r), r.UserAgent(), "success", map[string]any{
		"clientName": client.ClientName,
	})

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"success":      true,
		"client":       client,
		"clientSecret": rawSecret, // Displayed once at creation
	})
}

func (h *AdminHandler) DeleteOAuthClient(w http.ResponseWriter, r *http.Request) {
	admin := GetUserFromContext(r.Context())
	clientID := r.PathValue("id")

	_ = h.store.DeleteOAuthClient(clientID)
	h.audit.Record("admin.oauth_client_deleted", admin.ID, admin.Username, clientID, "client", h.middleware.ClientIP(r), r.UserAgent(), "success", nil)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

// Applications Management
func (h *AdminHandler) CreateApplication(w http.ResponseWriter, r *http.Request) {
	admin := GetUserFromContext(r.Context())
	var req struct {
		Name        string `json:"name"`
		URL         string `json:"url"`
		IconName    string `json:"iconName"`
		Description string `json:"description"`
		SortOrder   int    `json:"sortOrder"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Name == "" || req.URL == "" {
		http.Error(w, `{"error":"invalid_request"}`, http.StatusBadRequest)
		return
	}

	app := &store.Application{
		ID:          uuid.New().String(),
		Name:        req.Name,
		URL:         req.URL,
		IconName:    req.IconName,
		Description: req.Description,
		SortOrder:   req.SortOrder,
		Enabled:     true,
	}

	if err := h.store.CreateApplication(app); err != nil {
		http.Error(w, `{"error":"internal_error"}`, http.StatusInternalServerError)
		return
	}

	h.audit.Record("admin.application_created", admin.ID, admin.Username, app.ID, "application", h.middleware.ClientIP(r), r.UserAgent(), "success", nil)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "application": app})
}

func (h *AdminHandler) DeleteApplication(w http.ResponseWriter, r *http.Request) {
	admin := GetUserFromContext(r.Context())
	appID := r.PathValue("id")

	_ = h.store.DeleteApplication(appID)
	h.audit.Record("admin.application_deleted", admin.ID, admin.Username, appID, "application", h.middleware.ClientIP(r), r.UserAgent(), "success", nil)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

// ListAuditEvents returns audit trail for admin inspection.
func (h *AdminHandler) ListAuditEvents(w http.ResponseWriter, r *http.Request) {
	limitStr := r.URL.Query().Get("limit")
	limit := 100
	if l, err := strconv.Atoi(limitStr); err == nil && l > 0 && l <= 500 {
		limit = l
	}

	events, err := h.store.ListAuditEvents(limit)
	if err != nil {
		http.Error(w, `{"error":"internal_error"}`, http.StatusInternalServerError)
		return
	}
	if events == nil {
		events = []store.AuditEvent{}
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"auditEvents": events})
}
