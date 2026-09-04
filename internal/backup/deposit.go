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

// ErrKeyPinMissing means the instance has a pairing record but the recovery public key it
// seals to cannot be resolved: recovery.pub is gone or disagrees with the pin. Unlike
// ErrNotPaired it is a failure to report, not a quiet skip, because scheduled backups have
// stopped on an instance the operator believes is covered.
var ErrKeyPinMissing = errors.New("backup: paired with KyRecovery but the recovery public key is missing or does not match the pin")

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
	if (errors.Is(err, ErrNotPaired) || errors.Is(err, ErrRecoveryKeyMismatch)) && HasPairing(settings) {
		return Pairing{}, fmt.Errorf("%w: %v", ErrKeyPinMissing, err)
	}
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

// ErrNoDestination means a key is pinned but there is nowhere to put a capsule: not paired
// with KyRecovery and no KYSIGNON_BACKUP_DIR.
var ErrNoDestination = errors.New("backup: no destination; pair with KyRecovery or set KYSIGNON_BACKUP_DIR")

// Result is what one backup run produced. LocalPath is set when a copy landed in the local
// backup directory, LocalError when that destination failed; Receipt when KyRecovery
// confirmed the deposit. The destinations are independent: a full local disk does not stop
// the off-site copy, and the run is an error only when every configured destination failed.
type Result struct {
	Manifest   capsule.Manifest `json:"manifest"`
	SizeBytes  int              `json:"size_bytes"`
	LocalPath  string           `json:"local_path,omitempty"`
	LocalError string           `json:"local_error,omitempty"`
	Receipt    *Receipt         `json:"receipt,omitempty"`
}

// RunBackup seals the instance once and sends the capsule everywhere it is configured to
// go: the local backup directory when one is set, KyRecovery when paired. The receipt is
// what a restore is checked against, so it is written only after kyrecovery has confirmed
// the digest of the bytes sent. The attempt is stamped first, so a failing run is retried
// once per interval rather than on every scheduler tick.
func RunBackup(ctx context.Context, cfg *config.Config, settings SettingsStore, snap Snapshotter, client Depositor, appVersion string) (Result, error) {
	if !depositMu.TryLock() {
		return Result{}, ErrDepositInProgress
	}
	defer depositMu.Unlock()
	if err := markAttempt(settings); err != nil {
		return Result{}, err
	}
	key, err := LoadRecoveryKey(cfg.DataDir, settings)
	if (errors.Is(err, ErrNotPaired) || errors.Is(err, ErrRecoveryKeyMismatch)) && HasPairing(settings) {
		return Result{}, fmt.Errorf("%w: %v", ErrKeyPinMissing, err)
	}
	if err != nil {
		return Result{}, err
	}
	paired := HasPairing(settings)
	if !paired && cfg.BackupDir == "" {
		return Result{}, ErrNoDestination
	}
	payload, err := CollectSealable(cfg, snap, appVersion)
	if err != nil {
		return Result{}, err
	}
	raw, m, err := Seal(payload.ServiceName, payload.AppVersion, payload.Files, payload.Dependencies, payload.VerificationRecipe, key)
	if err != nil {
		return Result{}, err
	}
	res := Result{Manifest: m, SizeBytes: len(raw)}
	var localErr error
	if cfg.BackupDir != "" {
		if res.LocalPath, localErr = WriteLocalCopy(cfg.BackupDir, cfg.AppName, m.CapsuleID, raw, cfg.BackupKeep); localErr != nil {
			localErr = fmt.Errorf("local copy: %w", localErr)
			res.LocalError = AuditSafe(localErr.Error())
		}
	}
	if !paired {
		return res, localErr
	}
	pairing, err := LoadPairing(cfg.DataDir, settings, cfg.EncryptionKey)
	if err != nil {
		return res, err
	}
	rcpt, err := client.Deposit(ctx, pairing.URL, pairing.Token, raw)
	if err != nil {
		return res, err
	}
	if rcpt.CapsuleID != m.CapsuleID {
		return res, fmt.Errorf("%w: deposit receipt names capsule %s, sent %s", ErrRemote, rcpt.CapsuleID, m.CapsuleID)
	}
	res.Receipt = &rcpt
	b, _ := json.Marshal(rcpt)
	if err := settings.SetSetting(settingLastDeposit, string(b)); err != nil {
		return res, fmt.Errorf("%w: %s: %w", ErrReceiptUnrecorded, rcpt.CapsuleID, err)
	}
	return res, nil
}

// Outcome classifies a RunBackup result for the audit log, so every caller records the
// same event for the same result. A capsule KyRecovery holds is "deposited" even when this
// side failed to write the receipt; the cause rides in the details. A local copy that was
// written before the deposit failed is named too, so the row says what the operator has.
// Every field is bounded here, so the guarantee does not depend on what a caller verified
// two packages away.
func Outcome(res Result, err error) (action, outcome string, details map[string]any) {
	details = map[string]any{"capsule_id": AuditSafe(res.Manifest.CapsuleID), "size_bytes": res.SizeBytes}
	if res.LocalPath != "" {
		details["local_path"] = AuditSafe(res.LocalPath)
	}
	if res.LocalError != "" {
		details["local_error"] = AuditSafe(res.LocalError)
	}
	if res.Receipt != nil {
		details["digest"] = AuditSafe(res.Receipt.Digest)
		details["deposited"] = true
	}
	switch {
	case err == nil:
		return "admin.backup_run", "success", details
	case errors.Is(err, ErrReceiptUnrecorded):
		details["receipt_unrecorded"] = AuditSafe(err.Error())
		return "admin.backup_run", "success", details
	default:
		details["error"] = AuditSafe(err.Error())
		return "admin.backup_run", "failure", details
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
