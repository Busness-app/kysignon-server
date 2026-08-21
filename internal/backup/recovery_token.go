package backup

import (
	"errors"
	"fmt"
	"strings"

	"github.com/Yoshiofthewire/kysignon-server/internal/crypto"
)

// Settings keys. The token lives under its own key so a value written by an older build,
// which stored it in the clear, is never mistaken for ciphertext.
const (
	recoveryURLSetting         = "kyrecovery_url"
	recoveryTokenSetting       = "kyrecovery_token_enc"
	legacyRecoveryTokenSetting = "kyrecovery_token"

	// recoveryTokenLabel domain-separates this ciphertext from every other value encrypted
	// under the deployment key, so a row copied here from elsewhere will not decrypt.
	recoveryTokenLabel = "kysignon:setting:kyrecovery_token"
)

// SettingsStore is the slice of the store this file needs, kept narrow so the backup package
// does not depend on the store package.
type SettingsStore interface {
	GetSetting(key string) (string, error)
	SetSetting(key, value string) error
}

// SaveRecoveryToken persists the KyRecovery bearer credential encrypted under the deployment
// key. It is the standing key to the service holding every historical identity backup, so it
// does not belong in a plaintext settings table where a single database disclosure hands it
// over.
func SaveRecoveryToken(s SettingsStore, encryptionKey []byte, token string) error {
	if strings.TrimSpace(token) == "" {
		return errors.New("refusing to store an empty KyRecovery token")
	}
	sealed, err := crypto.EncryptAESGCM(crypto.DeriveKey(encryptionKey, recoveryTokenLabel), []byte(token))
	if err != nil {
		return fmt.Errorf("failed to encrypt the KyRecovery token: %w", err)
	}
	if err := s.SetSetting(recoveryTokenSetting, sealed); err != nil {
		return err
	}
	// Drop any plaintext an older build left behind, so the migration is not one-way only in
	// theory.
	_ = s.SetSetting(legacyRecoveryTokenSetting, "")
	return nil
}

// LoadRecoveryToken returns the decrypted KyRecovery credential, or "" when unpaired.
//
// A value left in the clear by an older build is re-sealed on first read rather than being
// rejected: an operator who cannot push a backup because of a storage-format change is an
// operator with no backups.
func LoadRecoveryToken(s SettingsStore, encryptionKey []byte) (string, error) {
	sealed, err := s.GetSetting(recoveryTokenSetting)
	if err != nil {
		return "", err
	}
	if sealed != "" {
		plain, err := crypto.DecryptAESGCM(crypto.DeriveKey(encryptionKey, recoveryTokenLabel), sealed)
		if err != nil {
			return "", fmt.Errorf("the stored KyRecovery token will not decrypt under this deployment's encryption key: %w", err)
		}
		return string(plain), nil
	}

	legacy, err := s.GetSetting(legacyRecoveryTokenSetting)
	if err != nil || legacy == "" {
		return "", err
	}
	if err := SaveRecoveryToken(s, encryptionKey, legacy); err != nil {
		return "", err
	}
	return legacy, nil
}

// HasRecoveryToken reports whether a credential is stored, without decrypting it. Used by
// status endpoints that only need to know whether pairing is configured.
func HasRecoveryToken(s SettingsStore) bool {
	if v, err := s.GetSetting(recoveryTokenSetting); err == nil && v != "" {
		return true
	}
	v, err := s.GetSetting(legacyRecoveryTokenSetting)
	return err == nil && v != ""
}

// SaveRecoveryURL and LoadRecoveryURL keep the paired endpoint next to its credential.
func SaveRecoveryURL(s SettingsStore, url string) error {
	return s.SetSetting(recoveryURLSetting, url)
}

func LoadRecoveryURL(s SettingsStore) (string, error) {
	return s.GetSetting(recoveryURLSetting)
}

// ClearRecoveryPairing removes both halves of the pairing.
func ClearRecoveryPairing(s SettingsStore) {
	_ = s.SetSetting(recoveryURLSetting, "")
	_ = s.SetSetting(recoveryTokenSetting, "")
	_ = s.SetSetting(legacyRecoveryTokenSetting, "")
}
