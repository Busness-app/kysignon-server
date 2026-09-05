package sync

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Busness-app/ky-primitives/syncauth"
	"github.com/Busness-app/kysignon-server/internal/crypto"
	"github.com/Busness-app/kysignon-server/internal/netguard"
	"github.com/Busness-app/kysignon-server/internal/store"
	"github.com/google/uuid"
)

type Engine struct {
	store         *store.Store
	httpClient    *http.Client
	encryptionKey []byte
}

func NewEngine(s *store.Store, encryptionKey []byte) *Engine {
	return &Engine{
		store:         s,
		encryptionKey: encryptionKey,
		httpClient:    netguard.Client(5 * time.Second),
	}
}

// ValidateCallbackURL rejects anything the server should not be made to POST the user
// directory at.
func ValidateCallbackURL(raw string) error {
	return netguard.ValidateURL(raw, "callbackUrl")
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
func (e *Engine) CreateUserAndQueueSyncEvents(user *store.User, userPayload any, audit *store.AuditEvent) error {
	events, err := e.newAccountSyncEvents(user.ID, "user.created", userPayload)
	if err != nil {
		return err
	}
	return e.store.CreateUserWithSyncEvents(user, events, audit)
}

// UpdateUserAndQueueSyncEvents atomically records an account mutation and its outbox events.
func (e *Engine) UpdateUserAndQueueSyncEvents(user *store.User, revokeAccess bool, userPayload any, audit *store.AuditEvent) error {
	events, err := e.newAccountSyncEvents(user.ID, "user.updated", userPayload)
	if err != nil {
		return err
	}
	return e.store.UpdateUserWithSyncEvents(user, revokeAccess, events, audit)
}

// DeleteUserAndQueueSyncEvents removes a user and queues its deletion atomically, so a
// downstream product cannot retain an account when the source deletion succeeds.
// ResetUserMFAAndRevoke atomically strips every factor, revokes everything those factors
// were protecting, and queues the downstream notification.
func (e *Engine) ResetUserMFAAndRevoke(userID string, userPayload any, audit *store.AuditEvent) error {
	events, err := e.newAccountSyncEvents(userID, "user.mfa_reset", userPayload)
	if err != nil {
		return err
	}
	return e.store.ResetUserMFA(userID, events, audit)
}

func (e *Engine) DeleteUserAndQueueSyncEvents(userID string, userPayload any, audit *store.AuditEvent) error {
	events, err := e.newAccountSyncEvents(userID, "user.deleted", userPayload)
	if err != nil {
		return err
	}
	return e.store.DeleteUserWithSyncEvents(userID, events, audit)
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

// deliveryLease bounds how long one dispatcher owns a claimed event. It must exceed the
// delivery timeout so a slow-but-live delivery is never double-sent, and stay short enough
// that a crashed dispatcher's events are retried promptly.
const deliveryLease = 60 * time.Second

// DispatchPendingEvents delivers due events to the system each was queued for.
//
// Events are claimed before any network I/O. Reading without claiming let two dispatchers —
// overlapping ticks, or two instances during a rolling deploy — both deliver the same
// user.created and create duplicate downstream accounts.
func (e *Engine) DispatchPendingEvents(ctx context.Context) error {
	events, err := e.store.ClaimDueSyncEvents(50, deliveryLease)
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
				_ = e.store.ReleaseSyncEventLease(ev.ID)
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
			if err := e.store.UpdateSyncEventStatus(ev.ID, "failed", "paired system no longer exists", ev.Attempts, nil); err != nil {
				return err
			}
			continue
		}
		if sys.Status == "disabled" {
			if err := e.store.ReleaseSyncEventLease(ev.ID); err != nil {
				return err
			}
			continue
		}
		secret, ok := secrets[ev.SystemID]
		if !ok {
			next := time.Now().UTC().Add(retryDelay(ev.Attempts))
			if err := e.store.UpdateSyncEventStatus(ev.ID, "pending", "signing secret unavailable", ev.Attempts+1, &next); err != nil {
				return err
			}
			continue
		}

		scimUser, _ := FormatUserAsSCIM(json.RawMessage(ev.PayloadJSON))
		// Scoped to this event on purpose. Assigning to the function-scoped err let a
		// marshal failure on one event survive into the next iteration and fail an event
		// that was perfectly deliverable.
		var payloadBytes []byte
		var merr error
		if scimUser != nil {
			payloadBytes, merr = json.Marshal(scimUser)
		} else {
			payloadBytes = []byte(ev.PayloadJSON)
		}
		if merr != nil {
			if serr := e.store.UpdateSyncEventStatus(ev.ID, "failed", merr.Error(), ev.Attempts+1, nil); serr != nil {
				return serr
			}
			continue
		}

		if derr := e.deliver(ctx, sys, secret, ev.ID, ev.EventType, ev.UserID, payloadBytes); derr != nil {
			attempts := ev.Attempts + 1
			if serr := e.store.UpdatePairedSystemStatus(sys.ID, "failing"); serr != nil {
				return serr
			}
			if attempts >= 5 {
				if serr := e.store.UpdateSyncEventStatus(ev.ID, "failed", derr.Error(), attempts, nil); serr != nil {
					return serr
				}
			} else {
				next := time.Now().UTC().Add(retryDelay(ev.Attempts))
				if serr := e.store.UpdateSyncEventStatus(ev.ID, "pending", derr.Error(), attempts, &next); serr != nil {
					return serr
				}
			}
			continue
		}

		// The remote accepted the event but the local record of that fact has not landed
		// yet. If this write fails the lease eventually expires and the event is delivered
		// again, so delivery is at-least-once and recipients must be idempotent; surfacing
		// the error is what lets the operator see that happening.
		if serr := e.store.UpdatePairedSystemStatus(sys.ID, "active"); serr != nil {
			return serr
		}
		if serr := e.store.UpdateSyncEventStatus(ev.ID, "delivered", "", ev.Attempts+1, nil); serr != nil {
			return serr
		}
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

func (e *Engine) deliver(ctx context.Context, sys *store.PairedSystem, secret, eventID, eventType, userID string, payload []byte) error {
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

	headers, err := syncauth.Sign([]byte(secret), time.Now().UTC(), eventType, eventID, signPayload)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, method, targetURL, bodyReader)
	if err != nil {
		return err
	}
	if isBodyRequired {
		req.Header.Set("Content-Type", "application/scim+json")
	}
	req.Header.Set("Accept", "application/scim+json, application/json")
	headers.Apply(req)
	// A stable key per queued event. Retries reuse it, so a recipient that saw the request
	// but whose response was lost can recognise the replay instead of acting twice.
	req.Header.Set("Idempotency-Key", eventID)

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
			if err := e.DispatchPendingEvents(ctx); err != nil && ctx.Err() == nil {
				// Delivery failures are recorded per event; this is the local persistence
				// layer failing, which leaves events leased and silently un-retried until
				// the lease expires. It has to be visible somewhere.
				log.Printf(`{"level":"ERROR","component":"sync","error":%q}`, err.Error())
			}
		}
	}
}
