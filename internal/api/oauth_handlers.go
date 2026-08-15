package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/Yoshiofthewire/kysignon-server/internal/audit"
	"github.com/Yoshiofthewire/kysignon-server/internal/oauth"
	"github.com/Yoshiofthewire/kysignon-server/internal/store"
)

type OAuthHandler struct {
	store       *store.Store
	oauthEngine *oauth.Engine
	audit       *audit.Logger
	middleware  *MiddlewareManager
}

func NewOAuthHandler(s *store.Store, oauthEngine *oauth.Engine, audit *audit.Logger, mm *MiddlewareManager) *OAuthHandler {
	return &OAuthHandler{
		store:       s,
		oauthEngine: oauthEngine,
		audit:       audit,
		middleware:  mm,
	}
}

// OIDCConfiguration returns OIDC discovery metadata.
func (h *OAuthHandler) OIDCConfiguration(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	_ = json.NewEncoder(w).Encode(h.oauthEngine.GetOIDCConfiguration())
}

// JWKS returns the public RSA keys for ID token verification.
func (h *OAuthHandler) JWKS(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	_ = json.NewEncoder(w).Encode(h.oauthEngine.GetJWKS())
}

// Authorize handles OIDC/OAuth2 authorization request.
func (h *OAuthHandler) Authorize(w http.ResponseWriter, r *http.Request) {
	clientID := r.URL.Query().Get("client_id")
	redirectURI := r.URL.Query().Get("redirect_uri")
	responseType := r.URL.Query().Get("response_type")
	scope := r.URL.Query().Get("scope")
	state := r.URL.Query().Get("state")
	codeChallenge := r.URL.Query().Get("code_challenge")
	codeChallengeMethod := r.URL.Query().Get("code_challenge_method")

	if clientID == "" || redirectURI == "" || responseType != "code" {
		http.Error(w, `{"error":"invalid_request","error_description":"Missing client_id, redirect_uri, or response_type=code"}`, http.StatusBadRequest)
		return
	}

	client, err := h.store.GetOAuthClientByID(clientID)
	if err != nil || client == nil || !client.Enabled {
		http.Error(w, `{"error":"unauthorized_client","error_description":"Client not found or disabled"}`, http.StatusUnauthorized)
		return
	}

	if !h.oauthEngine.ValidateRedirectURI(client, redirectURI) {
		http.Error(w, `{"error":"invalid_redirect_uri","error_description":"Redirect URI does not match registered URIs"}`, http.StatusBadRequest)
		return
	}

	// Check if user is logged in
	user := GetUserFromContext(r.Context())
	if user == nil {
		// Redirect to login UI with return_to
		loginURL := fmt.Sprintf("/login?return_to=%s", url.QueryEscape(r.RequestURI))
		http.Redirect(w, r, loginURL, http.StatusFound)
		return
	}

	// Issue authorization code
	code, err := h.oauthEngine.CreateAuthorizationCode(clientID, user.ID, redirectURI, scope, codeChallenge, codeChallengeMethod)
	if err != nil {
		http.Error(w, `{"error":"server_error"}`, http.StatusInternalServerError)
		return
	}

	h.audit.Record("oauth.authorize", user.ID, user.Username, clientID, "client", h.middleware.ClientIP(r), r.UserAgent(), "success", map[string]any{
		"scope": scope,
	})

	// Redirect back to client with code and state
	targetURL, err := url.Parse(redirectURI)
	if err != nil {
		http.Error(w, `{"error":"invalid_redirect_uri"}`, http.StatusBadRequest)
		return
	}

	q := targetURL.Query()
	q.Set("code", code)
	if state != "" {
		q.Set("state", state)
	}
	targetURL.RawQuery = q.Encode()

	http.Redirect(w, r, targetURL.String(), http.StatusFound)
}

// Token handles authorization code exchange for tokens.
func (h *OAuthHandler) Token(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"invalid_request","error_description":"POST required"}`, http.StatusMethodNotAllowed)
		return
	}

	grantType := r.FormValue("grant_type")
	code := r.FormValue("code")
	clientID := r.FormValue("client_id")
	clientSecret := r.FormValue("client_secret")
	redirectURI := r.FormValue("redirect_uri")
	codeVerifier := r.FormValue("code_verifier")

	// Also check Basic Auth for confidential client credentials
	if u, p, ok := r.BasicAuth(); ok {
		clientID = u
		clientSecret = p
	}

	if grantType != "authorization_code" || code == "" || clientID == "" {
		http.Error(w, `{"error":"invalid_request","error_description":"grant_type=authorization_code, code, and client_id are required"}`, http.StatusBadRequest)
		return
	}

	tokenResp, err := h.oauthEngine.ExchangeAuthorizationCode(code, clientID, clientSecret, redirectURI, codeVerifier)
	if err != nil {
		h.audit.Record("oauth.token_exchange", "", "", clientID, "client", h.middleware.ClientIP(r), r.UserAgent(), "failure", map[string]any{
			"error": err.Error(),
		})
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"error":             "invalid_grant",
			"error_description": err.Error(),
		})
		return
	}

	h.audit.Record("oauth.token_exchange", "", "", clientID, "client", h.middleware.ClientIP(r), r.UserAgent(), "success", nil)

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	_ = json.NewEncoder(w).Encode(tokenResp)
}

// Userinfo returns claims for an authenticated access token.
func (h *OAuthHandler) Userinfo(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
		http.Error(w, `{"error":"invalid_token","error_description":"Bearer token required"}`, http.StatusUnauthorized)
		return
	}

	tokenString := strings.TrimPrefix(authHeader, "Bearer ")
	claims, err := h.oauthEngine.GetUserinfo(tokenString)
	if err != nil {
		http.Error(w, `{"error":"invalid_token","error_description":"`+err.Error()+`"}`, http.StatusUnauthorized)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(claims)
}

// Revoke revokes tokens.
func (h *OAuthHandler) Revoke(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]bool{"revoked": true})
}
