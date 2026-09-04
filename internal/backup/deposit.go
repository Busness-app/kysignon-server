package backup

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/Busness-app/ky-primitives/capsule"
	"github.com/Busness-app/kysignon-server/internal/config"
	"github.com/Busness-app/kysignon-server/internal/crypto"
	"github.com/Busness-app/kysignon-server/internal/store"
)

// Settings keys. The token lives under its own key so a value written by an older build,
// which stored it in the clear, is never mistaken for ciphertext.
const (
	settingRecoveryURL   = "kyrecovery_url"
	settingRecoveryToken = "kyrecovery_token_enc"
	settingLastDeposit   = "kyrecovery_last_deposit"

	// recoveryTokenLabel domain-separates this ciphertext from every other value encrypted
	// under the deployment key, so a row copied here from elsewhere will not decrypt.
	recoveryTokenLabel = "kysignon:setting:kyrecovery_token"
)

// ErrReceiptUnrecorded means KyRecovery holds the capsule but this instance failed to write
// the receipt. The deposit happened; the caller must say so rather than report a refusal.
var ErrReceiptUnrecorded = errors.New("backup: deposit succeeded but the receipt was not recorded")

// ErrDepositInProgress answers a second deposit started while one is still uploading.
var ErrDepositInProgress = errors.New("backup: a deposit is already in progress")

// depositMu makes deposits single-flight across the scheduler, the admin route and the CLI
// within one process: two at once would upload the same data twice and race on the receipt.
var depositMu sync.Mutex

// Depositor is the deposit half of the KyRecovery client, narrowed so callers can stand in
// a fake without reaching the network.
type Depositor interface {
	Deposit(ctx context.Context, serverURL, apiToken string, container []byte) (Receipt, error)
}

// Pairing is everything a deposit needs: where to send it, the bearer token, and the key
// the container is sealed to.
type Pairing struct {
	URL   string
	Token string
	Key   RecoveryKey
}

// StorePairing records the server URL and the bearer token after StoreRecoveryKey has pinned
// the key. The token is the standing credential to the service holding every historical
// identity backup, so it is sealed under a key derived for this setting alone: a single
// database disclosure must not hand it over.
func StorePairing(settings SettingsStore, encryptionKey []byte, serverURL, token string) error {
	if strings.TrimSpace(token) == "" {
		return errors.New("backup: refusing to store an empty KyRecovery token")
	}
	sealed, err := crypto.EncryptAESGCM(crypto.DeriveKey(encryptionKey, recoveryTokenLabel), []byte(token))
	if err != nil {
		return fmt.Errorf("backup: failed to encrypt the KyRecovery token: %w", err)
	}
	if err := settings.SetSetting(settingRecoveryURL, serverURL); err != nil {
		return err
	}
	return settings.SetSetting(settingRecoveryToken, sealed)
}

// HasPairing reports whether a URL and a sealed token are stored, without decrypting.
func HasPairing(settings SettingsStore) bool {
	u, err := settings.GetSetting(settingRecoveryURL)
	if err != nil || u == "" {
		return false
	}
	t, err := settings.GetSetting(settingRecoveryToken)
	return err == nil && t != ""
}

// LoadPairing returns ErrNotPaired unless the key, URL and token are all present.
func LoadPairing(dataDir string, settings SettingsStore, encryptionKey []byte) (Pairing, error) {
	key, err := LoadRecoveryKey(dataDir, settings)
	if err != nil {
		return Pairing{}, err
	}
	p := Pairing{Key: key}
	if p.URL, err = settings.GetSetting(settingRecoveryURL); err != nil {
		return Pairing{}, notPaired(err)
	}
	sealed, err := settings.GetSetting(settingRecoveryToken)
	if err != nil {
		return Pairing{}, notPaired(err)
	}
	if p.URL == "" || sealed == "" {
		return Pairing{}, ErrNotPaired
	}
	plain, err := crypto.DecryptAESGCM(crypto.DeriveKey(encryptionKey, recoveryTokenLabel), sealed)
	if err != nil {
		return Pairing{}, fmt.Errorf("backup: the stored KyRecovery token will not decrypt under this deployment's encryption key: %w", err)
	}
	p.Token = string(plain)
	return p, nil
}

func notPaired(err error) error {
	if errors.Is(err, store.ErrNotFound) {
		return ErrNotPaired
	}
	return err
}

// DepositBackup seals the instance's backup to the pinned key, deposits it, and records the
// receipt. The receipt is what a restore is checked against, so it is written only after
// kyrecovery has confirmed the digest of the bytes sent.
func DepositBackup(ctx context.Context, cfg *config.Config, settings SettingsStore, snap Snapshotter, client Depositor, appVersion string) (Receipt, capsule.Manifest, error) {
	if !depositMu.TryLock() {
		return Receipt{}, capsule.Manifest{}, ErrDepositInProgress
	}
	defer depositMu.Unlock()
	pairing, err := LoadPairing(cfg.DataDir, settings, cfg.EncryptionKey)
	if err != nil {
		return Receipt{}, capsule.Manifest{}, err
	}
	payload, err := CollectSealable(cfg, snap, appVersion)
	if err != nil {
		return Receipt{}, capsule.Manifest{}, err
	}
	raw, m, err := Seal(payload.ServiceName, payload.AppVersion, payload.Files, payload.Dependencies, payload.VerificationRecipe, pairing.Key)
	if err != nil {
		return Receipt{}, capsule.Manifest{}, err
	}
	rcpt, err := client.Deposit(ctx, pairing.URL, pairing.Token, raw)
	if err != nil {
		return Receipt{}, m, err
	}
	if rcpt.CapsuleID != m.CapsuleID {
		return Receipt{}, m, fmt.Errorf("%w: deposit receipt names capsule %s, sent %s", ErrRemote, rcpt.CapsuleID, m.CapsuleID)
	}
	b, _ := json.Marshal(rcpt)
	if err := settings.SetSetting(settingLastDeposit, string(b)); err != nil {
		return rcpt, m, fmt.Errorf("%w: %s: %w", ErrReceiptUnrecorded, rcpt.CapsuleID, err)
	}
	return rcpt, m, nil
}

// Outcome classifies a DepositBackup result for the audit log, so every caller records the
// same event for the same result. A capsule KyRecovery holds is "deposited" even when this
// side failed to write the receipt; the cause rides in the details. Every field is bounded
// here, so the guarantee does not depend on what a caller verified two packages away.
func Outcome(rcpt Receipt, m capsule.Manifest, err error) (action, outcome string, details map[string]any) {
	switch {
	case err == nil:
		return "admin.backup_deposit", "success", map[string]any{"capsule_id": AuditSafe(rcpt.CapsuleID), "digest": AuditSafe(rcpt.Digest), "size_bytes": rcpt.SizeBytes}
	case errors.Is(err, ErrReceiptUnrecorded):
		return "admin.backup_deposit", "success", map[string]any{"capsule_id": AuditSafe(rcpt.CapsuleID), "digest": AuditSafe(rcpt.Digest), "size_bytes": rcpt.SizeBytes, "receipt_unrecorded": AuditSafe(err.Error())}
	default:
		return "admin.backup_deposit", "failure", map[string]any{"capsule_id": AuditSafe(m.CapsuleID), "error": AuditSafe(err.Error())}
	}
}

// LastDeposit is the most recent receipt, or ok=false when nothing has been deposited.
func LastDeposit(settings SettingsStore) (Receipt, bool, error) {
	v, err := settings.GetSetting(settingLastDeposit)
	if errors.Is(err, store.ErrNotFound) || (err == nil && v == "") {
		return Receipt{}, false, nil
	}
	if err != nil {
		return Receipt{}, false, err
	}
	var r Receipt
	if err := json.Unmarshal([]byte(v), &r); err != nil {
		return Receipt{}, false, err
	}
	return r, true, nil
}
