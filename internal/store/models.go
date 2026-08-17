package store

import (
	"time"
)

type User struct {
	ID           string    `json:"id"`
	Username     string    `json:"username"`
	DisplayName  string    `json:"displayName"`
	Email        string    `json:"email"`
	PasswordHash string    `json:"-"`
	Role         string    `json:"role"`   // "user", "admin"
	Status       string    `json:"status"` // "active", "disabled"
	CreatedAt    time.Time `json:"createdAt"`
	UpdatedAt    time.Time `json:"updatedAt"`
}

type Session struct {
	ID               string    `json:"id"`
	UserID           string    `json:"userId"`
	SessionTokenHash string    `json:"-"`
	IPAddress        string    `json:"ipAddress"`
	UserAgent        string    `json:"userAgent"`
	ExpiresAt        time.Time `json:"expiresAt"`
	CreatedAt        time.Time `json:"createdAt"`
	LastActiveAt     time.Time `json:"lastActiveAt"`
}

type PairedSystem struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	SystemType  string `json:"systemType"` // "kypost", "kypasswords", "kybookmarks", "kynotes", "custom"
	CallbackURL string `json:"callbackUrl"`
	// HMACSecretEncrypted holds the webhook signing secret under the deployment encryption
	// key. It signs outbound webhooks, so it must be recoverable, not hashed.
	HMACSecretEncrypted string     `json:"-"`
	Status              string     `json:"status"` // "active", "failing", "disabled"
	LastSyncedAt        *time.Time `json:"lastSyncedAt,omitempty"`
	CreatedAt           time.Time  `json:"createdAt"`
}

type SystemPairingToken struct {
	ID              string     `json:"id"`
	TokenHash       string     `json:"-"`
	PINHash         string     `json:"-"`
	PINAttempts     int        `json:"-"`
	SystemType      string     `json:"systemType"`
	CreatedByUserID string     `json:"createdByUserId"`
	ExpiresAt       time.Time  `json:"expiresAt"`
	UsedAt          *time.Time `json:"usedAt,omitempty"`
	CreatedAt       time.Time  `json:"createdAt"`
}

type AccountSyncEvent struct {
	ID          string     `json:"id"`
	UserID      string     `json:"userId"`
	SystemID    string     `json:"systemId"`
	EventType   string     `json:"eventType"` // "created", "updated", "status_changed", "mfa_reset"
	PayloadJSON string     `json:"payloadJson"`
	Attempts    int        `json:"attempts"`
	Status      string     `json:"status"` // "pending", "delivered", "failed"
	LastError   string     `json:"lastError,omitempty"`
	NextAttempt *time.Time `json:"nextAttemptAt,omitempty"`
	CreatedAt   time.Time  `json:"createdAt"`
	UpdatedAt   time.Time  `json:"updatedAt"`
}

type NativeDevice struct {
	ID               string     `json:"id"`
	UserID           string     `json:"userId"`
	DeviceName       string     `json:"deviceName"`
	DeviceIdentifier string     `json:"deviceIdentifier"`
	Platform         string     `json:"platform"`
	PublicKey        string     `json:"publicKey,omitempty"`
	PushToken        string     `json:"pushToken,omitempty"`
	IsMFAApprover    bool       `json:"isMfaApprover"`
	LastSeenAt       *time.Time `json:"lastSeenAt,omitempty"`
	CreatedAt        time.Time  `json:"createdAt"`
}

type DevicePairingToken struct {
	ID        string     `json:"id"`
	UserID    string     `json:"userId"`
	TokenHash string     `json:"-"`
	PINHash   string     `json:"-"`
	ExpiresAt time.Time  `json:"expiresAt"`
	UsedAt    *time.Time `json:"usedAt,omitempty"`
	CreatedAt time.Time  `json:"createdAt"`
}

type MFAMethod struct {
	ID              string    `json:"id"`
	UserID          string    `json:"userId"`
	MethodType      string    `json:"methodType"` // "totp", "push"
	EncryptedSecret string    `json:"-"`
	IsPrimary       bool      `json:"isPrimary"`
	CreatedAt       time.Time `json:"createdAt"`
}

type MFAChallenge struct {
	ID              string    `json:"id"`
	UserID          string    `json:"userId"`
	MethodType      string    `json:"methodType"`
	MatchDigits     string    `json:"matchDigits"`
	DecoyDigitsJSON string    `json:"decoyDigitsJson"`
	Status          string    `json:"status"` // "pending", "approved", "denied", "expired"
	ExpiresAt       time.Time `json:"expiresAt"`
	CreatedAt       time.Time `json:"createdAt"`
}

// MFAToken is a single-use, server-side bearer token issued after primary password
// verification and redeemed by exactly one second-factor completion.
type MFAToken struct {
	ID          string     `json:"id"`
	UserID      string     `json:"userId"`
	TokenHash   string     `json:"-"`
	ChallengeID string     `json:"challengeId,omitempty"`
	Attempts    int        `json:"-"`
	ExpiresAt   time.Time  `json:"expiresAt"`
	UsedAt      *time.Time `json:"usedAt,omitempty"`
	CreatedAt   time.Time  `json:"createdAt"`
}

type RecoveryCode struct {
	ID        string     `json:"id"`
	UserID    string     `json:"userId"`
	CodeHash  string     `json:"-"`
	UsedAt    *time.Time `json:"usedAt,omitempty"`
	CreatedAt time.Time  `json:"createdAt"`
}

type OAuthClient struct {
	ID                string    `json:"id"`
	ClientName        string    `json:"clientName"`
	ClientType        string    `json:"clientType"` // "public", "confidential"
	ClientSecretHash  string    `json:"-"`
	RedirectURIsJSON  string    `json:"redirectUrisJson"`
	AllowedScopesJSON string    `json:"allowedScopesJson"`
	LaunchURL         string    `json:"launchUrl,omitempty"`
	Enabled           bool      `json:"enabled"`
	CreatedAt         time.Time `json:"createdAt"`
}

type AuthorizationCode struct {
	ID                  string     `json:"id"`
	CodeHash            string     `json:"-"`
	ClientID            string     `json:"clientId"`
	UserID              string     `json:"userId"`
	RedirectURI         string     `json:"redirectUri"`
	Scope               string     `json:"scope"`
	CodeChallenge       string     `json:"codeChallenge"`
	CodeChallengeMethod string     `json:"codeChallengeMethod"`
	Nonce               string     `json:"-"`
	ExpiresAt           time.Time  `json:"expiresAt"`
	UsedAt              *time.Time `json:"usedAt,omitempty"`
	CreatedAt           time.Time  `json:"createdAt"`
}

// IssuedToken records an access token so it can be revoked before it expires.
type IssuedToken struct {
	JTI       string     `json:"jti"`
	UserID    string     `json:"userId"`
	ClientID  string     `json:"clientId"`
	ExpiresAt time.Time  `json:"expiresAt"`
	RevokedAt *time.Time `json:"revokedAt,omitempty"`
	CreatedAt time.Time  `json:"createdAt"`
}

type Application struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	URL         string    `json:"url"`
	IconName    string    `json:"iconName"`
	Description string    `json:"description,omitempty"`
	SortOrder   int       `json:"sortOrder"`
	Enabled     bool      `json:"enabled"`
	CreatedAt   time.Time `json:"createdAt"`
}

type AuditEvent struct {
	ID            string    `json:"id"`
	ActorID       string    `json:"actorId,omitempty"`
	ActorUsername string    `json:"actorUsername,omitempty"`
	Action        string    `json:"action"`
	TargetID      string    `json:"targetId,omitempty"`
	TargetType    string    `json:"targetType,omitempty"`
	IPAddress     string    `json:"ipAddress"`
	UserAgent     string    `json:"userAgent"`
	Outcome       string    `json:"outcome"` // "success", "failure", "denied"
	DetailsJSON   string    `json:"detailsJson,omitempty"`
	CreatedAt     time.Time `json:"createdAt"`
}
