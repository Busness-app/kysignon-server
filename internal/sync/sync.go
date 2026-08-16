package sync

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
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

// MaxPINAttempts bounds guesses against a pairing PIN before the token is burned.
const MaxPINAttempts = 3

// PairingTokenTTL is how long a pairing token and its PIN remain redeemable.
const PairingTokenTTL = 90 * time.Second

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
				// address that was never checked.
				return http.ErrUseLastResponse
			},
			Transport: &http.Transport{
				DialContext: guardedDialer().DialContext,
			},
		},
	}
}

// guardedDialer refuses to connect to non-public addresses. Checking here rather than at
// registration is what makes the check meaningful: a hostname that resolves publicly when
// it is registered can resolve to 127.0.0.1 by the time delivery happens, and only the
// address actually being dialled tells the truth.
func guardedDialer() *net.Dialer {
	return &net.Dialer{
		Timeout: 5 * time.Second,
		Control: func(network, address string, _ syscall.RawConn) error {
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

// GenerateSystemPairingToken creates an ephemeral pairing token and the PIN that must
// accompany it. Only hashes are stored, so a database read is not a pairing capability.
func (e *Engine) GenerateSystemPairingToken(systemType, adminUserID string) (token string, pin string, expiresAt time.Time, err error) {
	rawToken, err := crypto.GenerateRandomHex(24)
	if err != nil {
		return "", "", time.Time{}, err
	}
	pin, err = crypto.GenerateRandomAlphanumeric(8)
	if err != nil {
		return "", "", time.Time{}, err
	}
	expiresAt = time.Now().UTC().Add(PairingTokenTTL)

	item := &store.SystemPairingToken{
		ID:              uuid.New().String(),
		TokenHash:       crypto.HashSHA256(rawToken),
		PINHash:         crypto.HashSHA256(pin),
		SystemType:      systemType,
		CreatedByUserID: adminUserID,
		ExpiresAt:       expiresAt,
	}
	if err := e.store.CreateSystemPairingToken(item); err != nil {
		return "", "", time.Time{}, err
	}
	return rawToken, pin, expiresAt, nil
}

type SystemRegistrationRequest struct {
	PairingToken string `json:"pairingToken"`
	PINCode      string `json:"pinCode"`
	SystemName   string `json:"systemName"`
	SystemType   string `json:"systemType"`
	CallbackURL  string `json:"callbackUrl"`
}

type SystemRegistrationResponse struct {
	SystemID   string `json:"systemId"`
	HMACSecret string `json:"hmacSecret"`
	Status     string `json:"status"`
}

// ValidateCallbackURL rejects anything the server should not be made to POST the user
// directory at. The caller of this endpoint is unauthenticated apart from the pairing
// token, so the URL it supplies is hostile input.
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

// RegisterPairedSystem redeems a pairing token and issues webhook credentials.
func (e *Engine) RegisterPairedSystem(req *SystemRegistrationRequest) (*SystemRegistrationResponse, error) {
	if req.PairingToken == "" {
		return nil, errors.New("pairingToken is required")
	}
	if req.PINCode == "" {
		return nil, errors.New("pinCode is required")
	}
	if err := ValidateCallbackURL(req.CallbackURL); err != nil {
		return nil, err
	}

	validToken, err := e.store.GetValidSystemPairingToken(crypto.HashSHA256(req.PairingToken), MaxPINAttempts)
	if err != nil {
		return nil, err
	}
	if validToken == nil {
		return nil, errors.New("invalid or expired pairing token")
	}

	if subtle.ConstantTimeCompare([]byte(crypto.HashSHA256(req.PINCode)), []byte(validToken.PINHash)) != 1 {
		attempts, _ := e.store.RecordSystemPairingPINFailure(validToken.ID)
		return nil, fmt.Errorf("incorrect pairing PIN (%d of %d attempts used)", attempts, MaxPINAttempts)
	}

	// Spend the token before creating anything, so two racing registrations cannot both
	// redeem it.
	spent, err := e.store.ConsumeSystemPairingToken(validToken.ID)
	if err != nil {
		return nil, err
	}
	if !spent {
		return nil, errors.New("pairing token has already been redeemed")
	}

	hmacSecret, err := crypto.GenerateRandomHex(32)
	if err != nil {
		return nil, err
	}
	encrypted, err := crypto.EncryptAESGCM(e.encryptionKey, []byte(hmacSecret))
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt webhook signing secret: %w", err)
	}

	name := req.SystemName
	if name == "" {
		name = req.SystemType
	}

	pairedSystem := &store.PairedSystem{
		ID:                  uuid.New().String(),
		Name:                name,
		SystemType:          req.SystemType,
		CallbackURL:         req.CallbackURL,
		HMACSecretEncrypted: encrypted,
		Status:              "active",
	}
	if err := e.store.CreatePairedSystem(pairedSystem); err != nil {
		return nil, err
	}

	return &SystemRegistrationResponse{
		SystemID:   pairedSystem.ID,
		HMACSecret: hmacSecret,
		Status:     "active",
	}, nil
}

// SigningSecret recovers the webhook signing secret for a paired system.
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

type SyncWebhookPayload struct {
	EventID   string          `json:"eventId"`
	EventType string          `json:"eventType"`
	Timestamp string          `json:"timestamp"`
	User      json.RawMessage `json:"user"`
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

		payloadBytes, err := json.Marshal(SyncWebhookPayload{
			EventID:   ev.ID,
			EventType: ev.EventType,
			Timestamp: ev.CreatedAt.Format(time.RFC3339),
			User:      json.RawMessage(ev.PayloadJSON),
		})
		if err != nil {
			_ = e.store.UpdateSyncEventStatus(ev.ID, "failed", err.Error(), ev.Attempts+1, nil)
			continue
		}

		if err := e.deliver(ctx, sys, secret, ev.EventType, payloadBytes); err != nil {
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

func (e *Engine) deliver(ctx context.Context, sys *store.PairedSystem, secret, eventType string, payload []byte) error {
	// Sign the timestamp alongside the body so a captured delivery cannot be replayed
	// indefinitely against a downstream that checks it.
	timestamp := time.Now().UTC().Format(time.RFC3339)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(timestamp))
	mac.Write([]byte("."))
	mac.Write(payload)
	signature := hex.EncodeToString(mac.Sum(nil))

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, sys.CallbackURL, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-KySignOn-Signature", signature)
	req.Header.Set("X-KySignOn-Timestamp", timestamp)
	req.Header.Set("X-KySignOn-Event-Type", eventType)

	resp, err := e.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("system %s error: %w", sys.Name, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("system %s returned status %d", sys.Name, resp.StatusCode)
	}
	return nil
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
		payload, err := json.Marshal(map[string]any{
			"id":          u.ID,
			"username":    u.Username,
			"displayName": u.DisplayName,
			"email":       u.Email,
			"role":        u.Role,
			"status":      u.Status,
		})
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
