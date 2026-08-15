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
	"net/http"
	"time"

	"github.com/Yoshiofthewire/kysignon-server/internal/crypto"
	"github.com/Yoshiofthewire/kysignon-server/internal/store"
	"github.com/google/uuid"
)

type Engine struct {
	store      *store.Store
	httpClient *http.Client
}

func NewEngine(s *store.Store) *Engine {
	return &Engine{
		store: s,
		httpClient: &http.Client{
			Timeout: 5 * time.Second,
		},
	}
}

// GenerateSystemPairingToken creates an ephemeral (90s TTL) pairing key for connecting a KySecurity product.
func (e *Engine) GenerateSystemPairingToken(systemType, adminUserID string) (token string, pin string, expiresAt time.Time, err error) {
	rawToken, err := crypto.GenerateRandomHex(24)
	if err != nil {
		return "", "", time.Time{}, err
	}

	pin = crypto.GenerateRandomAlphanumeric(8)
	tokenHash := crypto.HashSHA256(rawToken)
	expiresAt = time.Now().UTC().Add(90 * time.Second)

	item := &store.SystemPairingToken{
		ID:              uuid.New().String(),
		TokenHash:       tokenHash,
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
	SystemName   string `json:"systemName"`
	SystemType   string `json:"systemType"`
	CallbackURL  string `json:"callbackUrl"`
}

type SystemRegistrationResponse struct {
	SystemID   string `json:"systemId"`
	HMACSecret string `json:"hmacSecret"`
	Status     string `json:"status"`
}

// RegisterPairedSystem redeems a pairing token and establishes mutual HMAC credentials.
func (e *Engine) RegisterPairedSystem(req *SystemRegistrationRequest) (*SystemRegistrationResponse, error) {
	if req.PairingToken == "" || req.CallbackURL == "" {
		return nil, errors.New("pairingToken and callbackUrl are required")
	}

	tokenHash := crypto.HashSHA256(req.PairingToken)
	validToken, err := e.store.GetValidSystemPairingToken(tokenHash)
	if err != nil {
		return nil, err
	}
	if validToken == nil {
		return nil, errors.New("invalid or expired pairing token")
	}

	// Mark token used
	if err := e.store.MarkSystemPairingTokenUsed(validToken.ID); err != nil {
		return nil, err
	}

	// Generate shared HMAC-SHA256 secret (32 bytes hex)
	hmacSecret, err := crypto.GenerateRandomHex(32)
	if err != nil {
		return nil, err
	}

	name := req.SystemName
	if name == "" {
		name = req.SystemType
	}

	pairedSystem := &store.PairedSystem{
		ID:             uuid.New().String(),
		Name:           name,
		SystemType:     req.SystemType,
		CallbackURL:    req.CallbackURL,
		HMACSecretHash: hmacSecret, // stored to sign outbound webhooks
		Status:         "active",
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

// QueueAccountSyncEvent creates a sync event to be delivered to downstream systems.
func (e *Engine) QueueAccountSyncEvent(userID, eventType string, userPayload any) error {
	payloadBytes, err := json.Marshal(userPayload)
	if err != nil {
		return err
	}

	event := &store.AccountSyncEvent{
		ID:          uuid.New().String(),
		UserID:      userID,
		EventType:   eventType,
		PayloadJSON: string(payloadBytes),
		Attempts:    0,
		Status:      "pending",
	}

	return e.store.CreateAccountSyncEvent(event)
}

type SyncWebhookPayload struct {
	EventID   string          `json:"eventId"`
	EventType string          `json:"eventType"`
	Timestamp string          `json:"timestamp"`
	User      json.RawMessage `json:"user"`
}

// DispatchPendingEvents delivers queued sync events to all active paired systems.
func (e *Engine) DispatchPendingEvents(ctx context.Context) error {
	events, err := e.store.GetPendingSyncEvents(50)
	if err != nil || len(events) == 0 {
		return err
	}

	systems, err := e.store.ListActivePairedSystems()
	if err != nil || len(systems) == 0 {
		// No active systems to receive events
		for _, ev := range events {
			_ = e.store.UpdateSyncEventStatus(ev.ID, "delivered", "", ev.Attempts)
		}
		return nil
	}

	for _, ev := range events {
		webhookPayload := SyncWebhookPayload{
			EventID:   ev.ID,
			EventType: ev.EventType,
			Timestamp: ev.CreatedAt.Format(time.RFC3339),
			User:      json.RawMessage(ev.PayloadJSON),
		}
		payloadBytes, err := json.Marshal(webhookPayload)
		if err != nil {
			_ = e.store.UpdateSyncEventStatus(ev.ID, "failed", err.Error(), ev.Attempts+1)
			continue
		}

		allSuccess := true
		var lastErrMsg string

		for _, sys := range systems {
			h := hmac.New(sha256.New, []byte(sys.HMACSecretHash))
			h.Write(payloadBytes)
			signature := hex.EncodeToString(h.Sum(nil))

			httpReq, err := http.NewRequestWithContext(ctx, "POST", sys.CallbackURL, bytes.NewReader(payloadBytes))
			if err != nil {
				allSuccess = false
				lastErrMsg = err.Error()
				continue
			}

			httpReq.Header.Set("Content-Type", "application/json")
			httpReq.Header.Set("X-KySignOn-Signature", signature)
			httpReq.Header.Set("X-KySignOn-Event-Type", ev.EventType)

			resp, err := e.httpClient.Do(httpReq)
			if err != nil {
				allSuccess = false
				lastErrMsg = fmt.Sprintf("system %s error: %v", sys.Name, err)
				_ = e.store.UpdatePairedSystemStatus(sys.ID, "failing")
				continue
			}
			resp.Body.Close()

			if resp.StatusCode < 200 || resp.StatusCode >= 300 {
				allSuccess = false
				lastErrMsg = fmt.Sprintf("system %s returned status %d", sys.Name, resp.StatusCode)
				_ = e.store.UpdatePairedSystemStatus(sys.ID, "failing")
			} else {
				_ = e.store.UpdatePairedSystemStatus(sys.ID, "active")
			}
		}

		if allSuccess {
			_ = e.store.UpdateSyncEventStatus(ev.ID, "delivered", "", ev.Attempts+1)
		} else {
			attempts := ev.Attempts + 1
			status := "pending"
			if attempts >= 5 {
				status = "failed"
			}
			_ = e.store.UpdateSyncEventStatus(ev.ID, status, lastErrMsg, attempts)
		}
	}

	return nil
}

// ResyncAllAccounts pushes all current users to a paired system.
func (e *Engine) ResyncAllAccounts(systemID string) error {
	users, err := e.store.ListUsers()
	if err != nil {
		return err
	}

	for _, u := range users {
		userPayload := map[string]any{
			"id":          u.ID,
			"username":    u.Username,
			"displayName": u.DisplayName,
			"email":       u.Email,
			"role":        u.Role,
			"status":      u.Status,
		}
		_ = e.QueueAccountSyncEvent(u.ID, "user.created", userPayload)
	}

	return nil
}

// StartWorker runs the background sync worker.
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
