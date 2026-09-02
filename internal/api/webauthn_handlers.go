package api

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"time"

	"github.com/Yoshiofthewire/kysignon-server/internal/audit"
	"github.com/Yoshiofthewire/kysignon-server/internal/crypto"
	"github.com/Yoshiofthewire/kysignon-server/internal/mfa"
	"github.com/Yoshiofthewire/kysignon-server/internal/store"
	"github.com/Yoshiofthewire/kysignon-server/internal/webauthn"
	"github.com/google/uuid"
)

// challengeTTL bounds how long a ceremony may sit half-finished. Long enough for a user to
// find their phone, short enough that a captured challenge is worthless by the time it
// could be replayed — and it is single-use regardless.
const challengeTTL = 3 * time.Minute

// maxPasskeysPerUser caps enrolment. Unbounded credentials per account is a place for an
// attacker with one borrowed session to leave many durable factors behind.
const maxPasskeysPerUser = 10

type WebAuthnHandler struct {
	store      *store.Store
	audit      *audit.Logger
	mfaEngine  *mfa.Engine
	middleware *MiddlewareManager
	rpID       string
	origin     string
}

// NewWebAuthnHandler takes the relying party identity already derived and validated by
// config.Load, so a malformed issuer URL is a startup failure rather than a ceremony that
// fails for the first user who tries it.
func NewWebAuthnHandler(s *store.Store, auditLogger *audit.Logger, mfaEngine *mfa.Engine, mm *MiddlewareManager, rpID, origin string) *WebAuthnHandler {
	return &WebAuthnHandler{store: s, audit: auditLogger, mfaEngine: mfaEngine, middleware: mm, rpID: rpID, origin: origin}
}

type beginRegistrationResponse struct {
	Challenge  string   `json:"challenge"`
	RPID       string   `json:"rpId"`
	RPName     string   `json:"rpName"`
	UserHandle string   `json:"userHandle"`
	Username   string   `json:"username"`
	Exclude    []string `json:"excludeCredentials"`
}

// issueChallenge mints and stores a single-use nonce for one user and one ceremony.
func (h *WebAuthnHandler) issueChallenge(userID, purpose string) (string, error) {
	raw, err := crypto.GenerateRandomBytes(32)
	if err != nil {
		return "", err
	}
	challenge := base64.RawURLEncoding.EncodeToString(raw)
	return challenge, h.store.CreateWebAuthnChallenge(&store.WebAuthnChallenge{
		ID:        uuid.New().String(),
		UserID:    userID,
		Challenge: challenge,
		Purpose:   purpose,
		ExpiresAt: time.Now().UTC().Add(challengeTTL),
	})
}

// BeginRegistration returns the parameters for navigator.credentials.create. The step-up
// grant is checked but not spent: failing here rather than after the user has touched their
// authenticator is the better experience, and FinishRegistration spends it.
func (h *WebAuthnHandler) BeginRegistration(w http.ResponseWriter, r *http.Request) {
	user := GetUserFromContext(r.Context())
	if user == nil {
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		return
	}
	if err := requireStepUp(h.store, r); err != nil {
		writeStepUpError(w, err)
		return
	}

	existing, err := h.store.ListUserWebAuthnCredentials(user.ID)
	if err != nil {
		http.Error(w, `{"error":"internal_error"}`, http.StatusInternalServerError)
		return
	}
	if len(existing) >= maxPasskeysPerUser {
		http.Error(w, `{"error":"too_many_passkeys","error_description":"Remove an existing passkey before enrolling another"}`, http.StatusConflict)
		return
	}

	challenge, err := h.issueChallenge(user.ID, "register")
	if err != nil {
		http.Error(w, `{"error":"internal_error"}`, http.StatusInternalServerError)
		return
	}

	// Existing credentials are excluded so an authenticator that already holds one for this
	// account says so instead of silently enrolling a duplicate.
	exclude := make([]string, 0, len(existing))
	for _, c := range existing {
		exclude = append(exclude, c.CredentialID)
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(beginRegistrationResponse{
		Challenge:  challenge,
		RPID:       h.rpID,
		RPName:     "KySignOn",
		UserHandle: base64.RawURLEncoding.EncodeToString([]byte(user.ID)),
		Username:   user.Username,
		Exclude:    exclude,
	})
}

type finishRegistrationRequest struct {
	CredentialID      string `json:"credentialId"`
	AuthenticatorData string `json:"authenticatorData"`
	ClientDataJSON    string `json:"clientDataJSON"`
	PublicKey         string `json:"publicKey"`
	Name              string `json:"name"`
}

func (h *WebAuthnHandler) FinishRegistration(w http.ResponseWriter, r *http.Request) {
	user := GetUserFromContext(r.Context())
	if user == nil {
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		return
	}

	var req finishRegistrationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil ||
		req.CredentialID == "" || req.AuthenticatorData == "" || req.ClientDataJSON == "" || req.PublicKey == "" {
		http.Error(w, `{"error":"invalid_request"}`, http.StatusBadRequest)
		return
	}

	// A ceremony the caller conducted with their own authenticator proves nothing about
	// the account holder, so entitlement comes from the step-up grant, as it does for TOTP.
	if err := consumeStepUp(h.store, r); err != nil {
		writeStepUpError(w, err)
		return
	}

	authData, err1 := base64.RawURLEncoding.DecodeString(req.AuthenticatorData)
	clientData, err2 := base64.RawURLEncoding.DecodeString(req.ClientDataJSON)
	publicKey, err3 := base64.RawURLEncoding.DecodeString(req.PublicKey)
	if err1 != nil || err2 != nil || err3 != nil {
		http.Error(w, `{"error":"invalid_request","error_description":"Ceremony fields must be base64url"}`, http.StatusBadRequest)
		return
	}

	var cd struct {
		Challenge string `json:"challenge"`
	}
	if err := json.Unmarshal(clientData, &cd); err != nil || cd.Challenge == "" {
		http.Error(w, `{"error":"invalid_request"}`, http.StatusBadRequest)
		return
	}

	// Redeem before verifying. A challenge that fails verification is burned either way,
	// so a caller cannot grind attempts against one issued nonce.
	spent, err := h.store.ConsumeWebAuthnChallenge(cd.Challenge, "register", user.ID)
	if err != nil {
		http.Error(w, `{"error":"internal_error"}`, http.StatusInternalServerError)
		return
	}
	if !spent {
		http.Error(w, `{"error":"invalid_challenge","error_description":"Registration challenge is unknown, expired, or already used"}`, http.StatusBadRequest)
		return
	}

	ad, err := webauthn.VerifyRegistration(webauthn.RegistrationInput{
		AuthenticatorData: authData,
		ClientDataJSON:    clientData,
		PublicKeySPKI:     publicKey,
		Challenge:         cd.Challenge,
		Origin:            h.origin,
		RPID:              h.rpID,
	})
	if err != nil {
		h.audit.Record("mfa.passkey_enrol", user.ID, user.Username, user.ID, "user",
			h.middleware.ClientIP(r), r.UserAgent(), "failure", map[string]any{"reason": "verification_failed"})
		http.Error(w, `{"error":"invalid_credential","error_description":"Passkey registration could not be verified"}`, http.StatusBadRequest)
		return
	}

	name := req.Name
	if name == "" {
		name = "Passkey"
	}
	if len(name) > 64 {
		name = name[:64]
	}

	enrolled := h.audit.Prepare("mfa.passkey_enrol", user.ID, user.Username, user.ID, "user",
		h.middleware.ClientIP(r), r.UserAgent(), "success",
		map[string]any{"backupEligible": ad.BackupEligible(), "userVerified": ad.UserVerified()})
	if err := h.store.CreateWebAuthnCredential(&store.WebAuthnCredential{
		ID:             uuid.New().String(),
		UserID:         user.ID,
		CredentialID:   req.CredentialID,
		PublicKeySPKI:  req.PublicKey,
		SignCount:      ad.SignCount,
		Name:           name,
		BackupEligible: ad.BackupEligible(),
		BackupState:    ad.BackupState(),
	}, enrolled.Row); err != nil {
		http.Error(w, `{"error":"internal_error"}`, http.StatusInternalServerError)
		return
	}
	enrolled.Committed()

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"success": true})
}
