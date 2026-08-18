package backup

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// KyRecoveryClient implements the Zero-Code Pairing & Push client contract for KyRecovery.
type KyRecoveryClient struct {
	client *http.Client
}

func NewKyRecoveryClient() *KyRecoveryClient {
	return &KyRecoveryClient{
		client: &http.Client{Timeout: 30 * time.Second},
	}
}

// ClaimPairing exchanges a 6-digit ephemeral pairing PIN with KyRecovery server for a permanent API bearer token.
func (c *KyRecoveryClient) ClaimPairing(ctx context.Context, serverURL, pairingCode, appName string) (string, error) {
	serverURL = strings.TrimRight(serverURL, "/")
	endpoint := fmt.Sprintf("%s/api/pairing/claim", serverURL)

	reqBody := map[string]string{
		"pairing_code": strings.TrimSpace(pairingCode),
		"app_name":     appName,
	}
	bodyBytes, _ := json.Marshal(reqBody)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(bodyBytes))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("pairing claim request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("pairing claim rejected (%d): %s", resp.StatusCode, string(b))
	}

	var claimResp struct {
		APIToken string `json:"api_token"`
		Status   string `json:"status"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&claimResp); err != nil {
		return "", err
	}

	if claimResp.APIToken == "" {
		return "", errors.New("empty api_token in claim response")
	}

	return claimResp.APIToken, nil
}

// PushBackupPayload defines the self-declaring backup ingest schema.
type PushBackupPayload struct {
	ServiceName        string                 `json:"service_name"`
	AppVersion         string                 `json:"app_version"`
	Threshold          int                    `json:"threshold"`
	TotalShares        int                    `json:"total_shares"`
	Files              []PushBackupFile       `json:"files"`
	Dependencies       map[string]interface{} `json:"dependencies"`
	VerificationRecipe map[string]interface{} `json:"verification_recipe"`
}

type PushBackupFile struct {
	Path       string `json:"path"`
	DataBase64 string `json:"data_base64"`
	Mode       int64  `json:"mode"`
}

type PushResponse struct {
	Status       string      `json:"status"`
	CapsuleID    string      `json:"capsule_id"`
	ServiceName  string      `json:"service_name"`
	SizeBytes    int64       `json:"size_bytes"`
	PayloadHash  string      `json:"payload_hash"`
	DrillSummary DrillResult `json:"drill_summary"`
}

// PushBackup pushes a self-declaring backup payload to the remote KyRecovery instance.
func (c *KyRecoveryClient) PushBackup(ctx context.Context, serverURL, apiToken string, payload PushBackupPayload) (*PushResponse, error) {
	serverURL = strings.TrimRight(serverURL, "/")
	endpoint := fmt.Sprintf("%s/api/backup/push", serverURL)

	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+apiToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("backup push failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("backup push rejected (%d): %s", resp.StatusCode, string(b))
	}

	var pushResp PushResponse
	if err := json.NewDecoder(resp.Body).Decode(&pushResp); err != nil {
		return nil, err
	}

	return &pushResp, nil
}
