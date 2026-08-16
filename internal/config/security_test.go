package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func withEnv(t *testing.T, kv map[string]string) {
	t.Helper()
	for k, v := range kv {
		t.Setenv(k, v)
	}
}

// A key that is too short, or not hex, must stop the server. Silently padding it to 32
// bytes gives an operator who tried to configure security less of it than one who did nothing.
func TestWeakEncryptionKeyIsRejected(t *testing.T) {
	for _, bad := range []string{"changeme", "a", "deadbeef", strings.Repeat("z", 64)} {
		t.Run(bad[:min(len(bad), 12)], func(t *testing.T) {
			withEnv(t, map[string]string{
				"KYSIGNON_DATA_DIR":       t.TempDir(),
				"KYSIGNON_ENCRYPTION_KEY": bad,
				"BOOTSTRAP_ADMIN_PASS":    "",
			})
			if _, err := Load(); err == nil {
				t.Errorf("KYSIGNON_ENCRYPTION_KEY=%q was accepted; it must be rejected", bad)
			}
		})
	}
}

func TestWeakSecretKeyIsRejected(t *testing.T) {
	withEnv(t, map[string]string{
		"KYSIGNON_DATA_DIR":   t.TempDir(),
		"KYSIGNON_SECRET_KEY": "hunter2",
	})
	if _, err := Load(); err == nil {
		t.Error("a 7-byte KYSIGNON_SECRET_KEY was accepted")
	}
}

func TestValidHexKeysAreAccepted(t *testing.T) {
	key := strings.Repeat("ab", 32) // 64 hex chars = 32 bytes
	withEnv(t, map[string]string{
		"KYSIGNON_DATA_DIR":       t.TempDir(),
		"KYSIGNON_ENCRYPTION_KEY": key,
		"KYSIGNON_SECRET_KEY":     key,
	})
	cfg, err := Load()
	if err != nil {
		t.Fatalf("valid 32-byte hex keys were rejected: %v", err)
	}
	if len(cfg.EncryptionKey) != 32 || len(cfg.SecretKey) != 32 {
		t.Errorf("key lengths = %d/%d, want 32/32", len(cfg.EncryptionKey), len(cfg.SecretKey))
	}
}

// Generated key files must survive a restart. Overwriting a short or unreadable file
// silently invalidates every session and every TOTP secret on disk.
func TestExistingShortKeyFileIsNotSilentlyReplaced(t *testing.T) {
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "encryption.key")
	if err := os.WriteFile(keyFile, []byte("truncated"), 0600); err != nil {
		t.Fatal(err)
	}
	withEnv(t, map[string]string{"KYSIGNON_DATA_DIR": dir})

	if _, err := Load(); err == nil {
		t.Error("a truncated encryption.key was silently regenerated instead of reported")
	}

	after, err := os.ReadFile(keyFile)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != "truncated" {
		t.Error("the existing key file was overwritten; every TOTP secret on disk just became undecryptable")
	}
}

func TestGeneratedKeysPersistAcrossLoads(t *testing.T) {
	dir := t.TempDir()
	withEnv(t, map[string]string{"KYSIGNON_DATA_DIR": dir})

	first, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	second, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if string(first.EncryptionKey) != string(second.EncryptionKey) {
		t.Error("encryption key changed between loads; TOTP secrets would not decrypt after a restart")
	}
	if string(first.SecretKey) != string(second.SecretKey) {
		t.Error("secret key changed between loads")
	}
}

// The shipped default must not believe forwarding headers from the whole RFC1918 space.
func TestNoProxiesAreTrustedByDefault(t *testing.T) {
	withEnv(t, map[string]string{"KYSIGNON_DATA_DIR": t.TempDir()})
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.TrustedProxyCIDRs) != 0 {
		t.Errorf("TrustedProxyCIDRs defaults to %v; it must default to empty", cfg.TrustedProxyCIDRs)
	}
}

// A CIDR that does not parse must be reported, not skipped, or an operator's typo
// silently drops their proxy out of the trusted set.
func TestMalformedTrustedProxyCIDRIsRejected(t *testing.T) {
	withEnv(t, map[string]string{
		"KYSIGNON_DATA_DIR":   t.TempDir(),
		"TRUSTED_PROXY_CIDRS": "10.89.0.1/32,not-a-cidr",
	})
	if _, err := Load(); err == nil {
		t.Error("a malformed entry in TRUSTED_PROXY_CIDRS was silently ignored")
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
