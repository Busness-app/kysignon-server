package sync

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"syscall"
	"time"

	"github.com/Yoshiofthewire/kysignon-server/internal/crypto"
	"github.com/Yoshiofthewire/kysignon-server/internal/store"
	"github.com/google/uuid"
)

// AllowPrivateCallbacks permits callback URLs on loopback and private ranges. Deployments
// where every service shares a container network need this; it is off by default because
// an attacker-chosen callback is otherwise a request forgery primitive aimed at the
// internal network.
var AllowPrivateCallbacks = false

type Engine struct {
	store         *store.Store
	httpClient    *http.Client
	encryptionKey []byte
}

func NewEngine(s *store.Store, encryptionKey []byte) *Engine {
	return &Engine{
		store:         s,
		encryptionKey: encryptionKey,
		httpClient: &http.Client{
			Timeout: 5 * time.Second,
			CheckRedirect: func(r *http.Request, via []*http.Request) error {
				// A redirect would let a validated callback bounce the payload to an
				// internal address that failed validation.
				return errors.New("redirects are not followed for sync delivery")
			},
			Transport: &http.Transport{
				DialContext:         guardedDialer().DialContext,
				TLSHandshakeTimeout: 5 * time.Second,
			},
		},
	}
}

// guardedDialer rejects connection attempts to loopback and private networks unless
// explicitly allowed.
func guardedDialer() *net.Dialer {
	return &net.Dialer{
		Timeout: 5 * time.Second,
		Control: func(network, address string, c syscall.RawConn) error {
			if AllowPrivateCallbacks {
				return nil
			}
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				return err
			}
			ip := net.ParseIP(host)
			if ip == nil {
				return fmt.Errorf("refusing to dial unparseable address %q", address)
			}
			if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
				ip.IsLinkLocalMulticast() || ip.IsUnspecified() || ip.IsMulticast() {
				return fmt.Errorf("refusing to deliver to the non-public address %s", ip)
			}
			return nil
		},
	}
}

// ValidateCallbackURL rejects anything the server should not be made to POST the user
// directory at.
func ValidateCallbackURL(raw string) error {
	if strings.TrimSpace(raw) == "" {
		return errors.New("callbackUrl is required")
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("callbackUrl is not a valid URL: %w", err)
	}
	if parsed.Scheme != "https" && !(parsed.Scheme == "http" && AllowPrivateCallbacks) {
		return errors.New("callbackUrl must use https")
	}
	host := parsed.Hostname()
	if host == "" {
		return errors.New("callbackUrl must include a host")
	}
	if parsed.User != nil {
		return errors.New("callbackUrl must not embed credentials")
	}
	if AllowPrivateCallbacks {
		return nil
	}

	// A literal internal address is rejected outright. Hostnames are not resolved here:
	// resolution at registration proves nothing about resolution at delivery, so the real
	// enforcement lives in the dialer, which sees the address actually being connected to.
	if ip := net.ParseIP(host); ip != nil {
		if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
			ip.IsLinkLocalMulticast() || ip.IsUnspecified() || ip.IsMulticast() {
			return fmt.Errorf("callbackUrl points at the non-public address %s; "+
				"set KYSIGNON_ALLOW_PRIVATE_CALLBACKS=true if that is intended", ip)
		}
	}
	return nil
}

// SigningSecret recovers the webhook/SCIM bearer signing secret for a paired system.
func (e *Engine) SigningSecret(sys *store.PairedSystem) (string, error) {
	if sys.HMACSecretEncrypted == "" {
		return "", errors.New("paired system has no signing secret; re-pair it")
	}
	plain, err := crypto.DecryptAESGCM(e.encryptionKey, sys.HMACSecretEncrypted)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt signing secret for %s: %w", sys.Name, err)
	}
	return string(plain), nil
}

// QueueAccountSyncEvent queues one event per active paired system. Fanning out at queue
// time is what keeps a system's delivery state, and its retries, its own.
func (e *Engine) QueueAccountSyncEvent(userID, eventType string, userPayload any) error {
	events, err := e.newAccountSyncEvents(userID, eventType, userPayload)
	if err != nil {
		return err
	}
	for i := range events {
		if err := e.store.CreateAccountSyncEvent(&events[i]); err != nil {
			return err
		}
	}
	return nil
}

// CreateUserAndQueueSyncEvents atomically records a new source-of-truth account and every
// downstream delivery obligation.
func (e *Engine) CreateUserAndQueueSyncEvents(user *store.User, userPayload any) error {
	events, err := e.newAccountSyncEvents(user.ID, "user.created", userPayload)
	if err != nil {
		return err
	}
	return e.store.CreateUserWithSyncEvents(user, events)
}

// UpdateUserAndQueueSyncEvents atomically records an account mutation and its outbox events.
func (e *Engine) UpdateUserAndQueueSyncEvents(user *store.User, revokeAccess bool, userPayload any) error {
	events, err := e.newAccountSyncEvents(user.ID, "user.updated", userPayload)
	if err != nil {
		return err
	}
	return e.store.UpdateUserWithSyncEvents(user, revokeAccess, events)
}

// DeleteUserAndQueueSyncEvents removes a user and queues its deletion atomically, so a
// downstream product cannot retain an account when the source deletion succeeds.
func (e *Engine) DeleteUserAndQueueSyncEvents(userID string, userPayload any) error {
	events, err := e.newAccountSyncEvents(userID, "user.deleted", userPayload)
	if err != nil {
		return err
	}
	return e.store.DeleteUserWithSyncEvents(userID, events)
}

func (e *Engine) newAccountSyncEvents(userID, eventType string, userPayload any) ([]store.AccountSyncEvent, error) {
	systems, err := e.store.ListActivePairedSystems()
	if err != nil {
		return nil, err
	}
	if len(systems) == 0 {
		return nil, nil
	}

	payloadBytes, err := json.Marshal(userPayload)
	if err != nil {
		return nil, err
	}
	events := make([]store.AccountSyncEvent, 0, len(systems))
	for _, sys := range systems {
		events = append(events, store.AccountSyncEvent{
			ID:          uuid.New().String(),
			UserID:      userID,
			SystemID:    sys.ID,
			EventType:   eventType,
			PayloadJSON: string(payloadBytes),
			Status:      "pending",
		})
	}
	return events, nil
}

// SCIM Schema URIs and standard types (RFC 7643 / RFC 7644)
const (
	SCIMUserSchema = "urn:ietf:params:scim:schemas:core:2.0:User"
)

type SCIMName struct {
	Formatted  string `json:"formatted,omitempty"`
	FamilyName string `json:"familyName,omitempty"`
	GivenName  string `json:"givenName,omitempty"`
}

type SCIMEmail struct {
	Value   string `json:"value"`
	Type    string `json:"type,omitempty"`
	Primary bool   `json:"primary"`
}

type SCIMRole struct {
	Value   string `json:"value"`
	Primary bool   `json:"primary"`
}

type SCIMMeta struct {
	ResourceType string     `json:"resourceType"`
	Created      *time.Time `json:"created,omitempty"`
	LastModified *time.Time `json:"lastModified,omitempty"`
	Location     string     `json:"location,omitempty"`
}

type SCIMUserResource struct {
	Schemas     []string    `json:"schemas"`
	ID          string      `json:"id"`
	ExternalID  string      `json:"externalId,omitempty"`
	UserName    string      `json:"userName"`
	DisplayName string      `json:"displayName,omitempty"`
	Name        *SCIMName   `json:"name,omitempty"`
	Emails      []SCIMEmail `json:"emails,omitempty"`
	Roles       []SCIMRole  `json:"roles,omitempty"`
	Active      bool        `json:"active"`
	Meta        *SCIMMeta   `json:"meta,omitempty"`
}

// UserToSCIMResource converts an internal KySignOn user into a standard SCIM 2.0 User resource.
func UserToSCIMResource(u *store.User) *SCIMUserResource {
	if u == nil {
		return nil
	}
	res := &SCIMUserResource{
		Schemas:     []string{SCIMUserSchema},
		ID:          u.ID,
		ExternalID:  u.ID,
		UserName:    u.Username,
		DisplayName: u.DisplayName,
		Name: &SCIMName{
			Formatted: u.DisplayName,
		},
		Active: u.Status == "active",
		Meta: &SCIMMeta{
			ResourceType: "User",
			Created:      &u.CreatedAt,
			LastModified: &u.UpdatedAt,
		},
	}
	if u.Email != "" {
		res.Emails = []SCIMEmail{
			{
				Value:   u.Email,
				Type:    "work",
				Primary: true,
			},
		}
	}
	if u.Role != "" {
		res.Roles = []SCIMRole{
			{
				Value:   u.Role,
				Primary: true,
			},
		}
	}
	return res
}

// FormatUserAsSCIM parses arbitrary user payload data into a SCIM 2.0 User resource.
func FormatUserAsSCIM(userPayload any) (*SCIMUserResource, error) {
	if userPayload == nil {
		return nil, errors.New("nil user payload")
	}
	switch v := userPayload.(type) {
	case *SCIMUserResource:
		return v, nil
	case SCIMUserResource:
		return &v, nil
	case *store.User:
		return UserToSCIMResource(v), nil
	case store.User:
		return UserToSCIMResource(&v), nil
	default:
		data, err := json.Marshal(userPayload)
		if err != nil {
			return nil, err
		}
		var temp struct {
			Schemas     []string `json:"schemas"`
			ID          string   `json:"id"`
			UserName    string   `json:"userName"`
			DisplayName string   `json:"displayName"`
			Email       string   `json:"email"`
			Username    string   `json:"username"`
			Role        string   `json:"role"`
			Status      string   `json:"status"`
			Active      *bool    `json:"active"`
		}
		if err := json.Unmarshal(data, &temp); err != nil {
			return nil, err
		}
		if len(temp.Schemas) > 0 {
			var scimRes SCIMUserResource
			if err := json.Unmarshal(data, &scimRes); err == nil {
				return &scimRes, nil
			}
		}
		uname := temp.UserName
		if uname == "" {
			uname = temp.Username
		}
		active := true
		if temp.Active != nil {
			active = *temp.Active
		} else if temp.Status != "" {
			active = (temp.Status == "active")
		}

		res := &SCIMUserResource{
			Schemas:     []string{SCIMUserSchema},
			ID:          temp.ID,
			ExternalID:  temp.ID,
			UserName:    uname,
			DisplayName: temp.DisplayName,
			Name: &SCIMName{
				Formatted: temp.DisplayName,
			},
			Active: active,
			Meta: &SCIMMeta{
				ResourceType: "User",
			},
		}
		if temp.Email != "" {
			res.Emails = []SCIMEmail{
				{Value: temp.Email, Type: "work", Primary: true},
			}
		}
		if temp.Role != "" {
			res.Roles = []SCIMRole{
				{Value: temp.Role, Primary: true},
			}
		}
		return res, nil
	}
}

type SyncWebhookPayload struct {
	Schemas     []string        `json:"schemas,omitempty"`
	ID          string          `json:"id,omitempty"`
	EventID     string          `json:"eventId"`
	EventType   string          `json:"eventType"`
	Timestamp   string          `json:"timestamp"`
	User        json.RawMessage `json:"user"`
	UserName    string          `json:"userName,omitempty"`
	DisplayName string          `json:"displayName,omitempty"`
	Name        *SCIMName       `json:"name,omitempty"`
	Emails      []SCIMEmail     `json:"emails,omitempty"`
	Roles       []SCIMRole      `json:"roles,omitempty"`
	Active      bool            `json:"active"`
	Meta        *SCIMMeta       `json:"meta,omitempty"`
}

type CreateSystemRequest struct {
	Name        string `json:"name"`
	SystemType  string `json:"systemType"`
	Description string `json:"description,omitempty"`
	IconURL     string `json:"iconUrl,omitempty"`
	CallbackURL string `json:"callbackUrl"`
}

// CreateSystem connects a downstream SCIM target service directly with a server-generated Bearer API token.
func (e *Engine) CreateSystem(req *CreateSystemRequest) (*store.PairedSystem, string, error) {
	if req.Name == "" {
		req.Name = req.SystemType
	}
	if req.Name == "" {
		return nil, "", errors.New("name is required")
	}
	if req.SystemType == "" {
		req.SystemType = "scim"
	}
	if err := ValidateCallbackURL(req.CallbackURL); err != nil {
		return nil, "", err
	}

	// Always generate a cryptographically secure 256-bit Bearer API token
	token, err := crypto.GenerateRandomHex(32)
	if err != nil {
		return nil, "", err
	}

	encrypted, err := crypto.EncryptAESGCM(e.encryptionKey, []byte(token))
	if err != nil {
		return nil, "", fmt.Errorf("failed to encrypt bearer token: %w", err)
	}

	ps := &store.PairedSystem{
		ID:                  uuid.New().String(),
		Name:                req.Name,
		SystemType:          req.SystemType,
		Description:         req.Description,
		IconURL:             req.IconURL,
		CallbackURL:         req.CallbackURL,
		HMACSecretEncrypted: encrypted,
		Status:              "active",
	}
	if err := e.store.CreatePairedSystem(ps); err != nil {
		return nil, "", err
	}
	return ps, token, nil
}

// retryDelay is exponential with a ceiling, so a system that is down is not hammered every
// tick until its attempt budget runs out.
func retryDelay(attempts int) time.Duration {
	delay := time.Duration(1<<attempts) * 30 * time.Second
	if delay > 30*time.Minute {
		delay = 30 * time.Minute
	}
	return delay
}

// DispatchPendingEvents delivers due events to the system each was queued for.
func (e *Engine) DispatchPendingEvents(ctx context.Context) error {
	events, err := e.store.GetDueSyncEvents(50)
	if err != nil || len(events) == 0 {
		return err
	}

	// Cache systems and their decrypted secrets for this pass.
	systems := map[string]*store.PairedSystem{}
	secrets := map[string]string{}

	for _, ev := range events {
		sys, ok := systems[ev.SystemID]
		if !ok {
			sys, err = e.store.GetPairedSystemByID(ev.SystemID)
			if err != nil {
				return err
			}
			systems[ev.SystemID] = sys
			if sys != nil {
				if secret, serr := e.SigningSecret(sys); serr == nil {
					secrets[ev.SystemID] = secret
				}
			}
		}

		// A system that has been deleted can never receive this event. Anything else stays
		// queued: "nobody is listening yet" is not the same as "delivered".
		if sys == nil {
			_ = e.store.UpdateSyncEventStatus(ev.ID, "failed", "paired system no longer exists", ev.Attempts, nil)
			continue
		}
		if sys.Status == "disabled" {
			continue
		}
		secret, ok := secrets[ev.SystemID]
		if !ok {
			next := time.Now().UTC().Add(retryDelay(ev.Attempts))
			_ = e.store.UpdateSyncEventStatus(ev.ID, "pending", "signing secret unavailable", ev.Attempts+1, &next)
			continue
		}

		scimUser, _ := FormatUserAsSCIM(json.RawMessage(ev.PayloadJSON))
		var payloadBytes []byte
		if scimUser != nil {
			payloadBytes, err = json.Marshal(scimUser)
		} else {
			payloadBytes = []byte(ev.PayloadJSON)
		}
		if err != nil {
			_ = e.store.UpdateSyncEventStatus(ev.ID, "failed", err.Error(), ev.Attempts+1, nil)
			continue
		}

		if err := e.deliver(ctx, sys, secret, ev.EventType, ev.UserID, payloadBytes); err != nil {
			attempts := ev.Attempts + 1
			_ = e.store.UpdatePairedSystemStatus(sys.ID, "failing")
			if attempts >= 5 {
				_ = e.store.UpdateSyncEventStatus(ev.ID, "failed", err.Error(), attempts, nil)
			} else {
				next := time.Now().UTC().Add(retryDelay(ev.Attempts))
				_ = e.store.UpdateSyncEventStatus(ev.ID, "pending", err.Error(), attempts, &next)
			}
			continue
		}

		_ = e.store.UpdatePairedSystemStatus(sys.ID, "active")
		_ = e.store.UpdateSyncEventStatus(ev.ID, "delivered", "", ev.Attempts+1, nil)
	}

	return nil
}

// resolveSCIMURL calculates the RESTful SCIM 2.0 route and HTTP method according to RFC 7644.
func resolveSCIMURL(sys *store.PairedSystem, eventType, userID string) (method string, targetURL string, isBodyRequired bool) {
	trimmed := strings.TrimRight(sys.CallbackURL, "/")

	// If system is explicitly scim or callback URL contains /scim or ends with /Users or /v2
	isRESTfulSCIM := sys.SystemType == "scim" ||
		strings.Contains(trimmed, "/scim") ||
		strings.HasSuffix(trimmed, "/Users") ||
		strings.HasSuffix(trimmed, "/v2")

	if isRESTfulSCIM {
		var baseUsersURL string
		if strings.HasSuffix(trimmed, "/Users") {
			baseUsersURL = trimmed
		} else {
			baseUsersURL = trimmed + "/Users"
		}

		switch eventType {
		case "user.created":
			return http.MethodPost, baseUsersURL, true
		case "user.updated":
			return http.MethodPut, fmt.Sprintf("%s/%s", baseUsersURL, url.PathEscape(userID)), true
		case "user.deleted":
			return http.MethodDelete, fmt.Sprintf("%s/%s", baseUsersURL, url.PathEscape(userID)), false
		default:
			return http.MethodPost, baseUsersURL, true
		}
	}

	// For legacy webhooks, default to POST callback URL directly
	return http.MethodPost, trimmed, true
}

func (e *Engine) deliver(ctx context.Context, sys *store.PairedSystem, secret, eventType, userID string, payload []byte) error {
	method, targetURL, isBodyRequired := resolveSCIMURL(sys, eventType, userID)

	var bodyReader *bytes.Reader
	var signPayload []byte
	if isBodyRequired && payload != nil {
		bodyReader = bytes.NewReader(payload)
		signPayload = payload
	} else {
		bodyReader = bytes.NewReader(nil)
		signPayload = []byte{}
	}

	// Sign the timestamp alongside the body for KySecurity HMAC authenticity
	timestamp := time.Now().UTC().Format(time.RFC3339)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(timestamp))
	mac.Write([]byte("."))
	mac.Write(signPayload)
	signature := hex.EncodeToString(mac.Sum(nil))

	req, err := http.NewRequestWithContext(ctx, method, targetURL, bodyReader)
	if err != nil {
		return err
	}
	if isBodyRequired {
		req.Header.Set("Content-Type", "application/scim+json")
	}
	req.Header.Set("Accept", "application/scim+json, application/json")
	req.Header.Set("Authorization", "Bearer "+secret)
	req.Header.Set("X-KySignOn-Signature", signature)
	req.Header.Set("X-KySignOn-Timestamp", timestamp)
	req.Header.Set("X-KySignOn-Event-Type", eventType)

	resp, err := e.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("system %s error: %w", sys.Name, err)
	}
	defer resp.Body.Close()

	// SCIM success codes: 200, 201, 204, or 404 on DELETE (already gone), or 409 on POST (already exists)
	if (resp.StatusCode >= 200 && resp.StatusCode < 300) ||
		(eventType == "user.deleted" && resp.StatusCode == http.StatusNotFound) ||
		(eventType == "user.created" && resp.StatusCode == http.StatusConflict) {
		return nil
	}

	return fmt.Errorf("system %s returned status %d", sys.Name, resp.StatusCode)
}

// ResyncAllAccounts pushes every current account to one paired system.
func (e *Engine) ResyncAllAccounts(systemID string) error {
	sys, err := e.store.GetPairedSystemByID(systemID)
	if err != nil {
		return err
	}
	if sys == nil {
		return errors.New("paired system not found")
	}

	users, err := e.store.ListUsers()
	if err != nil {
		return err
	}
	for _, u := range users {
		scimRes := UserToSCIMResource(&u)
		payload, err := json.Marshal(scimRes)
		if err != nil {
			return err
		}
		if err := e.store.CreateAccountSyncEvent(&store.AccountSyncEvent{
			ID:          uuid.New().String(),
			UserID:      u.ID,
			SystemID:    sys.ID,
			EventType:   "user.created",
			PayloadJSON: string(payload),
			Status:      "pending",
		}); err != nil {
			return err
		}
	}
	return nil
}

// StartWorker runs the background sync dispatcher.
func (e *Engine) StartWorker(ctx context.Context) {
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			_ = e.DispatchPendingEvents(ctx)
		}
	}
}
