package backup

import (
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"strconv"

	"github.com/Busness-app/ky-primitives/keyfile"
	"github.com/Busness-app/ky-primitives/recoverykey"
	"github.com/Busness-app/kysignon-server/internal/store"
)

var (
	ErrNotPaired           = errors.New("backup: no recovery public key; pair with KyRecovery first")
	ErrRecoveryKeyMismatch = errors.New("backup: stored recovery public key does not match the pinned key ID")
)

const (
	settingRecoveryKeyID  = "kyrecovery_key_id"
	settingThreshold      = "kyrecovery_threshold"
	settingTotalShares    = "kyrecovery_total_shares"
	recoveryPublicKeyFile = "recovery.pub"
)

// SettingsStore is the slice of the store this package needs. GetSetting returns
// store.ErrNotFound for a key never written.
type SettingsStore interface {
	GetSetting(key string) (string, error)
	SetSetting(key, value string) error
	DeleteSetting(key string) error
}

// RecoveryKey is what a product holds after pairing: the suite recovery public key and the
// custodian topology kyrecovery reported for it. There is no private half here, ever.
type RecoveryKey struct {
	Public      recoverykey.PublicKey
	Threshold   int
	TotalShares int
}

// RecoveryKeyPath is where the raw 1216-byte public key lives.
func RecoveryKeyPath(dataDir string) string {
	return filepath.Join(dataDir, recoveryPublicKeyFile)
}

// validTopology reports whether a k-of-n custodian split is one a suite can actually recover.
func validTopology(threshold, total int) bool {
	return threshold >= 2 && total >= threshold && total <= 255
}

// StoreRecoveryKey persists k. A second pairing to a different key fails with fs.ErrExist —
// whether or not recovery.pub still exists, because the settings pin is what decides; the
// same key again is an idempotent refresh that recreates a missing file.
func StoreRecoveryKey(dataDir string, settings SettingsStore, k RecoveryKey) error {
	if k.Public.IsZero() {
		return errors.New("backup: refusing to store a zero recovery public key")
	}
	if !validTopology(k.Threshold, k.TotalShares) {
		return fmt.Errorf("backup: %d-of-%d is not a custodian topology", k.Threshold, k.TotalShares)
	}
	path := RecoveryKeyPath(dataDir)
	// The settings pin decides, not the file: recovery.pub is absent on every restored
	// instance and deletable by anyone with the data directory.
	pinned, perr := settings.GetSetting(settingRecoveryKeyID)
	if perr != nil && !errors.Is(perr, store.ErrNotFound) {
		return perr
	}
	if perr == nil && pinned != k.Public.ID() {
		return fmt.Errorf("%w: already paired to recovery key %s; rotating requires clearing both %s and the %s, %s and %s settings",
			fs.ErrExist, pinned, path, settingRecoveryKeyID, settingThreshold, settingTotalShares)
	}
	err := keyfile.Store(path, k.Public.Bytes(), keyfile.Raw)
	if errors.Is(err, fs.ErrExist) {
		existing, lerr := keyfile.LoadEncoded(path, recoverykey.PublicKeyBytes, keyfile.Raw)
		if lerr != nil {
			return lerr
		}
		if pk, pkerr := recoverykey.ParsePublicKey(existing); pkerr != nil || pk.ID() != k.Public.ID() {
			return fmt.Errorf("%w: %s holds recovery key %s; remove it to re-pair", err, path, pinnedID(existing))
		}
	} else if err != nil {
		return err
	}
	if err := settings.SetSetting(settingRecoveryKeyID, k.Public.ID()); err != nil {
		return err
	}
	if err := settings.SetSetting(settingThreshold, strconv.Itoa(k.Threshold)); err != nil {
		return err
	}
	return settings.SetSetting(settingTotalShares, strconv.Itoa(k.TotalShares))
}

func pinnedID(raw []byte) string {
	pk, err := recoverykey.ParsePublicKey(raw)
	if err != nil {
		return "(unparseable)"
	}
	return pk.ID()
}

// LoadRecoveryKey reads the public key file and checks it against the pinned key ID in the
// settings table, so a swapped file is detected before anything is sealed to it.
func LoadRecoveryKey(dataDir string, settings SettingsStore) (RecoveryKey, error) {
	raw, err := keyfile.LoadEncoded(RecoveryKeyPath(dataDir), recoverykey.PublicKeyBytes, keyfile.Raw)
	if errors.Is(err, fs.ErrNotExist) {
		return RecoveryKey{}, ErrNotPaired
	}
	if err != nil {
		return RecoveryKey{}, err
	}
	pk, err := recoverykey.ParsePublicKey(raw)
	if err != nil {
		return RecoveryKey{}, err
	}
	id, err := settings.GetSetting(settingRecoveryKeyID)
	if errors.Is(err, store.ErrNotFound) {
		return RecoveryKey{}, ErrNotPaired
	}
	if err != nil {
		return RecoveryKey{}, err
	}
	if id != pk.ID() {
		return RecoveryKey{}, ErrRecoveryKeyMismatch
	}
	k := RecoveryKey{Public: pk}
	if k.Threshold, err = intSetting(settings, settingThreshold); err != nil {
		return RecoveryKey{}, err
	}
	if k.TotalShares, err = intSetting(settings, settingTotalShares); err != nil {
		return RecoveryKey{}, err
	}
	return k, nil
}

// intSetting reads a pinned integer. A key ID with no topology beside it is a pairing that
// died halfway, which is not paired.
func intSetting(settings SettingsStore, key string) (int, error) {
	v, err := settings.GetSetting(key)
	if errors.Is(err, store.ErrNotFound) {
		return 0, ErrNotPaired
	}
	if err != nil {
		return 0, fmt.Errorf("%s: %w", key, err)
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", key, err)
	}
	return n, nil
}
