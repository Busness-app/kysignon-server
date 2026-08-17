package mfa

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Yoshiofthewire/kysignon-server/internal/store"
)

var ErrStalePushToken = errors.New("push token is stale")

type RelayConfig struct {
	URL     string
	Key     string
	KeyFile string
	Label   string
}

type RelaySender struct {
	fcm    relayEndpoint
	apns   relayEndpoint
	client *http.Client
}

type relayEndpoint struct {
	url string
	key string
}

type relayRegisterResponse struct {
	Key string `json:"key"`
}

func NewRelaySender(fcm, apns RelayConfig) (*RelaySender, error) {
	fcmEndpoint, err := prepareRelay(fcm)
	if err != nil {
		return nil, err
	}
	apnsEndpoint, err := prepareRelay(apns)
	if err != nil {
		return nil, err
	}
	if fcmEndpoint.url == "" && apnsEndpoint.url == "" {
		return nil, nil
	}
	return &RelaySender{
		fcm:    fcmEndpoint,
		apns:   apnsEndpoint,
		client: &http.Client{Timeout: 5 * time.Second},
	}, nil
}

func prepareRelay(cfg RelayConfig) (relayEndpoint, error) {
	if cfg.URL == "" {
		return relayEndpoint{}, nil
	}
	if cfg.Key != "" {
		return relayEndpoint{url: cfg.URL, key: cfg.Key}, nil
	}
	if cfg.KeyFile != "" {
		key, err := os.ReadFile(cfg.KeyFile)
		if err == nil && strings.TrimSpace(string(key)) != "" {
			return relayEndpoint{url: cfg.URL, key: strings.TrimSpace(string(key))}, nil
		}
	}
	key, err := registerRelayKey(cfg.URL, cfg.Label)
	if err != nil {
		return relayEndpoint{}, err
	}
	if cfg.KeyFile != "" {
		if err := os.MkdirAll(filepath.Dir(cfg.KeyFile), 0700); err != nil {
			return relayEndpoint{}, err
		}
		if err := os.WriteFile(cfg.KeyFile, []byte(key+"\n"), 0600); err != nil {
			return relayEndpoint{}, err
		}
	}
	return relayEndpoint{url: cfg.URL, key: key}, nil
}

func registerRelayKey(relayURL, label string) (string, error) {
	body, _ := json.Marshal(map[string]string{"label": label})
	req, err := http.NewRequest(http.MethodPost, relayURL+"/register", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return "", fmt.Errorf("relay registration failed: %s", resp.Status)
	}
	var parsed relayRegisterResponse
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return "", err
	}
	if parsed.Key == "" {
		return "", errors.New("relay registration response did not include a key")
	}
	return parsed.Key, nil
}

func (s *RelaySender) SendPush(dev store.NativeDevice, ch MFAChallengePush) error {
	endpoint, err := s.endpointFor(dev.Platform)
	if err != nil {
		return err
	}
	if endpoint.url == "" {
		return nil
	}
	body, _ := json.Marshal(map[string]any{
		"token":    dev.PushToken,
		"title":    "Sign-in approval",
		"body":     "Approve the request in KySecurity.",
		"platform": dev.Platform,
		"data": map[string]string{
			"type":           "mfa_challenge",
			"challengeId":    ch.ChallengeID,
			"matchDigits":    ch.MatchDigits,
			"decoyDigits":    strings.Join(ch.Decoys, ","),
			"deviceId":       dev.ID,
			"deviceUserId":   dev.UserID,
			"devicePlatform": dev.Platform,
		},
	})
	req, err := http.NewRequest(http.MethodPost, endpoint.url+"/send", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+endpoint.key)
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		return nil
	}
	if resp.StatusCode == http.StatusGone {
		return ErrStalePushToken
	}
	return fmt.Errorf("push relay send failed: %s", resp.Status)
}

func (s *RelaySender) endpointFor(platform string) (relayEndpoint, error) {
	switch platform {
	case "", "android":
		return s.fcm, nil
	case "ios", "macos":
		return s.apns, nil
	default:
		return relayEndpoint{}, fmt.Errorf("unsupported push platform %q", platform)
	}
}
