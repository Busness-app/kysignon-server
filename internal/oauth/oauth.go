package oauth

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/Yoshiofthewire/kysignon-server/internal/crypto"
	"github.com/Yoshiofthewire/kysignon-server/internal/store"
	"github.com/google/uuid"
)

type Engine struct {
	store      *store.Store
	keyManager *crypto.JWTKeyManager
	issuerURL  string
}

func NewEngine(s *store.Store, km *crypto.JWTKeyManager, issuerURL string) *Engine {
	return &Engine{
		store:      s,
		keyManager: km,
		issuerURL:  issuerURL,
	}
}

// OIDCConfiguration returns RFC 8414 / OpenID Connect Discovery metadata.
type OIDCConfiguration struct {
	Issuer                           string   `json:"issuer"`
	AuthorizationEndpoint            string   `json:"authorization_endpoint"`
	TokenEndpoint                    string   `json:"token_endpoint"`
	UserinfoEndpoint                 string   `json:"userinfo_endpoint"`
	JwksURI                          string   `json:"jwks_uri"`
	RevocationEndpoint               string   `json:"revocation_endpoint"`
	ResponseTypesSupported           []string `json:"response_types_supported"`
	SubjectTypesSupported            []string `json:"subject_types_supported"`
	IDTokenSigningAlgValuesSupported []string `json:"id_token_signing_alg_values_supported"`
	ScopesSupported                  []string `json:"scopes_supported"`
	TokenEndpointAuthMethods         []string `json:"token_endpoint_auth_methods_supported"`
	CodeChallengeMethodsSupported    []string `json:"code_challenge_methods_supported"`
	ClaimsSupported                  []string `json:"claims_supported"`
}

func (e *Engine) GetOIDCConfiguration() OIDCConfiguration {
	return OIDCConfiguration{
		Issuer:                           e.issuerURL,
		AuthorizationEndpoint:            e.issuerURL + "/oauth/authorize",
		TokenEndpoint:                    e.issuerURL + "/oauth/token",
		UserinfoEndpoint:                 e.issuerURL + "/oauth/userinfo",
		JwksURI:                          e.issuerURL + "/.well-known/jwks.json",
		RevocationEndpoint:               e.issuerURL + "/oauth/revoke",
		ResponseTypesSupported:           []string{"code"},
		SubjectTypesSupported:            []string{"public"},
		IDTokenSigningAlgValuesSupported: []string{"RS256"},
		ScopesSupported:                  []string{"openid", "profile", "email"},
		TokenEndpointAuthMethods:         []string{"client_secret_post", "client_secret_basic", "none"},
		CodeChallengeMethodsSupported:    []string{"S256", "plain"},
		ClaimsSupported:                  []string{"sub", "iss", "aud", "exp", "iat", "auth_time", "preferred_username", "name", "email"},
	}
}

func (e *Engine) GetJWKS() crypto.JWKS {
	return e.keyManager.GetJWKS()
}

// ValidatePKCE checks code_verifier against the recorded code_challenge and code_challenge_method.
func ValidatePKCE(verifier, challenge, method string) bool {
	switch method {
	case "S256":
		h := sha256.Sum256([]byte(verifier))
		computed := base64.RawURLEncoding.EncodeToString(h[:])
		return computed == challenge
	case "plain", "":
		return verifier == challenge
	default:
		return false
	}
}

// CreateAuthorizationCode creates a short-lived (5 min) authorization code for a user.
func (e *Engine) CreateAuthorizationCode(clientID, userID, redirectURI, scope, challenge, method string) (string, error) {
	rawCode, err := crypto.GenerateRandomHex(32)
	if err != nil {
		return "", err
	}

	codeHash := crypto.HashSHA256(rawCode)
	item := &store.AuthorizationCode{
		ID:                  uuid.New().String(),
		CodeHash:            codeHash,
		ClientID:            clientID,
		UserID:              userID,
		RedirectURI:         redirectURI,
		Scope:               scope,
		CodeChallenge:       challenge,
		CodeChallengeMethod: method,
		ExpiresAt:           time.Now().UTC().Add(5 * time.Minute),
	}

	if err := e.store.CreateAuthorizationCode(item); err != nil {
		return "", err
	}

	return rawCode, nil
}

type TokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	IDToken     string `json:"id_token,omitempty"`
	Scope       string `json:"scope,omitempty"`
}

// ExchangeAuthorizationCode validates code and PKCE verifier, issuing ID Token and Access Token.
func (e *Engine) ExchangeAuthorizationCode(codeStr, clientID, clientSecret, redirectURI, codeVerifier string) (*TokenResponse, error) {
	codeHash := crypto.HashSHA256(codeStr)
	authCode, err := e.store.GetValidAuthorizationCode(codeHash)
	if err != nil {
		return nil, err
	}
	if authCode == nil {
		return nil, errors.New("invalid or expired authorization code")
	}

	// Invalidate code immediately (single-use)
	if err := e.store.MarkAuthorizationCodeUsed(authCode.ID); err != nil {
		return nil, err
	}

	// Validate client
	if authCode.ClientID != clientID {
		return nil, errors.New("client mismatch")
	}

	client, err := e.store.GetOAuthClientByID(clientID)
	if err != nil || client == nil || !client.Enabled {
		return nil, errors.New("invalid or disabled client")
	}

	// If confidential client, verify secret
	if client.ClientType == "confidential" {
		if client.ClientSecretHash != "" {
			if crypto.HashSHA256(clientSecret) != client.ClientSecretHash {
				return nil, errors.New("invalid client secret")
			}
		}
	}

	// Validate redirect URI
	if authCode.RedirectURI != redirectURI {
		return nil, errors.New("redirect uri mismatch")
	}

	// Validate PKCE
	if authCode.CodeChallenge != "" {
		if !ValidatePKCE(codeVerifier, authCode.CodeChallenge, authCode.CodeChallengeMethod) {
			return nil, errors.New("invalid PKCE code verifier")
		}
	}

	user, err := e.store.GetUserByID(authCode.UserID)
	if err != nil || user == nil || user.Status != "active" {
		return nil, errors.New("user not found or inactive")
	}

	now := time.Now().UTC()
	exp := now.Add(1 * time.Hour)

	// Access Token (RS256 JWT)
	accessTokenClaims := map[string]any{
		"iss":       e.issuerURL,
		"sub":       user.ID,
		"aud":       clientID,
		"exp":       exp.Unix(),
		"iat":       now.Unix(),
		"scope":     authCode.Scope,
		"token_use": "access_token",
	}
	accessToken, err := e.keyManager.SignJWT(accessTokenClaims)
	if err != nil {
		return nil, fmt.Errorf("failed to sign access token: %w", err)
	}

	var idToken string
	if strings.Contains(authCode.Scope, "openid") {
		idTokenClaims := map[string]any{
			"iss":                e.issuerURL,
			"sub":                user.ID,
			"aud":                clientID,
			"exp":                exp.Unix(),
			"iat":                now.Unix(),
			"auth_time":          now.Unix(),
			"username":           user.Username,
			"preferred_username": user.Username,
			"name":               user.DisplayName,
			"email":              user.Email,
			"role":               user.Role,
		}
		idToken, err = e.keyManager.SignJWT(idTokenClaims)
		if err != nil {
			return nil, fmt.Errorf("failed to sign ID token: %w", err)
		}
	}

	return &TokenResponse{
		AccessToken: accessToken,
		TokenType:   "Bearer",
		ExpiresIn:   3600,
		IDToken:     idToken,
		Scope:       authCode.Scope,
	}, nil
}

// GetUserinfo returns standard OIDC userinfo profile claims from an access token.
func (e *Engine) GetUserinfo(tokenString string) (map[string]any, error) {
	claims, err := e.keyManager.VerifyJWT(tokenString)
	if err != nil {
		return nil, err
	}

	sub, ok := claims["sub"].(string)
	if !ok || sub == "" {
		return nil, errors.New("missing sub claim in token")
	}

	user, err := e.store.GetUserByID(sub)
	if err != nil || user == nil || user.Status != "active" {
		return nil, errors.New("user not found or inactive")
	}

	return map[string]any{
		"sub":                user.ID,
		"username":           user.Username,
		"preferred_username": user.Username,
		"name":               user.DisplayName,
		"email":              user.Email,
		"email_verified":     true,
		"role":               user.Role,
	}, nil
}

// ValidateRedirectURI verifies that the given URI matches one of the client's registered redirect URIs.
func (e *Engine) ValidateRedirectURI(client *store.OAuthClient, uri string) bool {
	var uris []string
	_ = json.Unmarshal([]byte(client.RedirectURIsJSON), &uris)

	reqParsed, reqErr := url.Parse(uri)

	for _, registered := range uris {
		registered = strings.TrimSpace(registered)
		if registered == "" {
			continue
		}
		if registered == uri {
			return true
		}
		// Match trimmed trailing slash
		if strings.TrimRight(registered, "/") == strings.TrimRight(uri, "/") {
			return true
		}

		if reqErr == nil {
			regParsed, regErr := url.Parse(registered)
			if regErr == nil {
				// Compare path (ignoring trailing slash)
				regPath := strings.TrimRight(regParsed.Path, "/")
				reqPath := strings.TrimRight(reqParsed.Path, "/")

				// Allow standard SSO callback path aliases
				pathMatch := (regPath == reqPath) ||
					(strings.HasSuffix(regPath, "/callback") && strings.HasSuffix(reqPath, "/callback"))

				if pathMatch {
					// 1. Direct host match
					if strings.EqualFold(regParsed.Host, reqParsed.Host) {
						return true
					}
					// 2. Localhost alias match (e.g. 127.0.0.1:PORT == localhost:PORT)
					regHostname := regParsed.Hostname()
					reqHostname := reqParsed.Hostname()
					if (regHostname == "localhost" || regHostname == "127.0.0.1") &&
						(reqHostname == "localhost" || reqHostname == "127.0.0.1") {
						if regParsed.Port() == reqParsed.Port() {
							return true
						}
					}
					// 3. Container DNS alias match on kypost-net
					if (regHostname == "kypasswords" || regHostname == "kypassword-server" || regHostname == "passwords") &&
						(reqHostname == "kypasswords" || reqHostname == "kypassword-server" || reqHostname == "passwords" || reqHostname == "10.89.0.4") {
						return true
					}
				}
			}
		}
	}

	// Suite-specific fallback for built-in KySecurity suite clients
	if reqErr == nil && strings.HasSuffix(reqParsed.Path, "/callback") {
		clientID := strings.ToLower(client.ID)
		reqHost := strings.ToLower(reqParsed.Hostname())
		reqPort := reqParsed.Port()

		switch clientID {
		case "kypasswords", "kypassword":
			if reqHost == "passwords.urlxl.com" || reqHost == "kypasswords.urlxl.com" ||
				((reqHost == "localhost" || reqHost == "127.0.0.1" || reqHost == "10.89.0.4" || reqHost == "kypassword-server") && (reqPort == "5877" || reqPort == "5868" || reqPort == "")) {
				return true
			}
		case "kypost":
			if reqHost == "mail.urlxl.com" || reqHost == "kypost.urlxl.com" ||
				((reqHost == "localhost" || reqHost == "127.0.0.1" || reqHost == "10.89.0.5" || reqHost == "kypost-server") && (reqPort == "5866" || reqPort == "")) {
				return true
			}
		case "kydns":
			if reqHost == "dns.urlxl.com" || reqHost == "kydns.urlxl.com" ||
				((reqHost == "localhost" || reqHost == "127.0.0.1" || reqHost == "10.89.0.3" || reqHost == "kydns-server") && (reqPort == "8053" || reqPort == "53" || reqPort == "")) {
				return true
			}
		case "kybookmarks":
			if reqHost == "bookmarks.urlxl.com" || reqHost == "kybookmarks.urlxl.com" ||
				((reqHost == "localhost" || reqHost == "127.0.0.1" || reqHost == "10.89.0.6" || reqHost == "kybookmarks-server") && (reqPort == "5869" || reqPort == "")) {
				return true
			}
		case "kynotes":
			if reqHost == "notes.urlxl.com" || reqHost == "kynotes.urlxl.com" ||
				((reqHost == "localhost" || reqHost == "127.0.0.1" || reqHost == "10.89.0.7" || reqHost == "kynotes-server") && (reqPort == "5870" || reqPort == "5868" || reqPort == "8080" || reqPort == "")) {
				return true
			}
		}
	}

	return false
}
