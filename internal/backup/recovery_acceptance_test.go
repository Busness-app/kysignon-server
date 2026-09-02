package backup_test

import (
	"bytes"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Busness-app/kysignon-server/internal/backup"
	"github.com/Busness-app/kysignon-server/internal/config"
	"github.com/Busness-app/kysignon-server/internal/crypto"
	"github.com/Busness-app/kysignon-server/internal/store"
	"github.com/google/uuid"
)

// This is the test the disaster-recovery feature exists for: production is gone, and the
// exported kit is all there is. It starts from the artifacts an operator actually holds —
// the .kycap file and a quorum of custodian shards — with no live process, no retained key,
// and no access to the original directory, and requires the database back byte-for-byte.
func TestRestoreFromExportedKitOnly(t *testing.T) {
	tmp := t.TempDir()
	live := filepath.Join(tmp, "live")
	if err := os.MkdirAll(live, 0700); err != nil {
		t.Fatal(err)
	}

	dbPath := filepath.Join(live, "kysignon.db")
	keyPath := filepath.Join(live, "jwt_rs256.key")
	dbStore, err := store.New(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	admin := &store.User{
		ID: uuid.New().String(), Username: "recovery-admin", DisplayName: "Recovery Admin",
		Email: "admin@recovery.test", PasswordHash: "argon2id$x", Role: "admin", Status: "active",
	}
	if err := dbStore.CreateUser(admin); err != nil {
		t.Fatal(err)
	}
	if _, err := crypto.LoadOrCreateRSAKey(keyPath); err != nil {
		t.Fatal(err)
	}

	// The deployment keys. Everything encrypted in the database is encrypted under encKey,
	// so a capsule that omits it restores rows nobody can read.
	encKey := bytes.Repeat([]byte{0x1f}, config.KeyLength)
	secretKey := bytes.Repeat([]byte{0x2e}, config.KeyLength)

	const totpSecret = "JBSWY3DPEHPK3PXP"
	encryptedSecret, err := crypto.EncryptAESGCM(encKey, []byte(totpSecret))
	if err != nil {
		t.Fatal(err)
	}
	if err := dbStore.SetMFAMethod(&store.MFAMethod{
		ID: uuid.New().String(), UserID: admin.ID, MethodType: "totp",
		EncryptedSecret: encryptedSecret, IsPrimary: true,
	}, nil); err != nil {
		t.Fatal(err)
	}

	cfg := &config.Config{
		Port: "5867", IssuerURL: "https://sso.example.test", DBPath: dbPath, DataDir: live,
		RSAKeyPath: keyPath, EncryptionKey: encKey, SecretKey: secretKey,
	}

	payload, err := backup.BuildLocalPayload(cfg, dbStore, "1.0.0")
	if err != nil {
		t.Fatalf("BuildLocalPayload: %v", err)
	}
	files, err := backup.AsBackupFiles(payload)
	if err != nil {
		t.Fatal(err)
	}
	capsule, _, err := backup.CreateCapsule("KySignOn", "1.0.0", files,
		payload.Dependencies, payload.VerificationRecipe, payload.Threshold, payload.TotalShares)
	if err != nil {
		t.Fatal(err)
	}

	// Export exactly what an operator walks away with.
	exportDir := filepath.Join(tmp, "export")
	if err := os.MkdirAll(exportDir, 0700); err != nil {
		t.Fatal(err)
	}
	capsuleBytes, err := backup.SerializeCapsule(capsule)
	if err != nil {
		t.Fatalf("SerializeCapsule: %v", err)
	}
	capsulePath := filepath.Join(exportDir, "backup.kycap")
	if err := os.WriteFile(capsulePath, capsuleBytes, 0600); err != nil {
		t.Fatal(err)
	}
	var cardPaths []string
	for _, share := range capsule.Shares {
		card := backup.GenerateCustodianCardHTML(capsule.Manifest, share, "KySignOn", cfg.IssuerURL)
		p := filepath.Join(exportDir, "custodian-"+string(rune('0'+share.Index))+".html")
		if err := os.WriteFile(p, []byte(card), 0600); err != nil {
			t.Fatal(err)
		}
		cardPaths = append(cardPaths, p)
	}

	// A reference snapshot taken the same consistent way is the expected result. Note what
	// the raw main database file looks like at this moment: in WAL mode it is a stub, which
	// is exactly what the previous file-copy backup would have shipped.
	rawMainFile, err := os.ReadFile(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	refPath := filepath.Join(tmp, "reference.db")
	if err := dbStore.SnapshotTo(refPath); err != nil {
		t.Fatal(err)
	}
	wantDB, err := os.ReadFile(refPath)
	if err != nil {
		t.Fatal(err)
	}
	_ = dbStore.Close()
	if err := os.RemoveAll(live); err != nil {
		t.Fatal(err)
	}

	// Recover the shards the way a custodian does: read them off their own document.
	quorum := capsule.Manifest.Threshold
	var shards []backup.Share
	for i := 0; i < quorum; i++ {
		raw, err := os.ReadFile(cardPaths[i])
		if err != nil {
			t.Fatal(err)
		}
		share, err := backup.ParseShardHex(capsule.Shares[i].Index, extractShardHex(t, string(raw)))
		if err != nil {
			t.Fatal(err)
		}
		shards = append(shards, share)
	}

	// From here on, only exportDir exists.
	raw, err := os.ReadFile(capsulePath)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := backup.ParseCapsule(raw)
	if err != nil {
		t.Fatalf("ParseCapsule: %v", err)
	}
	key, err := backup.CombineShares(shards, quorum)
	if err != nil {
		t.Fatalf("CombineShares: %v", err)
	}

	restoreDir := filepath.Join(tmp, "restored")
	restored, err := backup.ExtractCapsule(parsed, key, restoreDir)
	if err != nil {
		t.Fatalf("ExtractCapsule from exported kit: %v", err)
	}

	gotDB, err := os.ReadFile(filepath.Join(restoreDir, "data/kysignon.db"))
	if err != nil {
		t.Fatalf("the recovery kit did not yield a database: %v", err)
	}
	if !bytes.Equal(gotDB, wantDB) {
		t.Fatalf("restored database differs from the snapshot (%d vs %d bytes)", len(gotDB), len(wantDB))
	}
	if _, err := os.Stat(filepath.Join(restoreDir, "data/jwt_rs256.key")); err != nil {
		t.Errorf("the recovery kit did not yield the signing key: %v", err)
	}
	if len(restored) < 5 {
		t.Errorf("expected database, signing key, both deployment keys and config; got %d files", len(restored))
	}

	// The point of the whole exercise: the restored directory must be readable, not just
	// present. A capsule that restores a database of ciphertext nobody holds the key for is
	// a drill that passes and a recovery that fails.
	gotEncKey, err := os.ReadFile(filepath.Join(restoreDir, "data/encryption.key"))
	if err != nil {
		t.Fatalf("the recovery kit did not yield the encryption key: %v", err)
	}
	if !bytes.Equal(gotEncKey, encKey) {
		t.Fatal("the restored encryption key does not match the one the data was encrypted under")
	}
	gotSecretKey, err := os.ReadFile(filepath.Join(restoreDir, "data/secret.key"))
	if err != nil {
		t.Fatalf("the recovery kit did not yield the session secret: %v", err)
	}
	if !bytes.Equal(gotSecretKey, secretKey) {
		t.Fatal("the restored session secret does not match the live one")
	}

	// The restored directory must hold the account that existed before the loss.
	recovered, err := store.New(filepath.Join(restoreDir, "data/kysignon.db"))
	if err != nil {
		t.Fatalf("restored database will not open: %v", err)
	}
	defer recovered.Close()
	u, err := recovered.GetUserByUsername("recovery-admin")
	if err != nil || u == nil {
		t.Fatalf("the administrator did not survive the restore: %v", err)
	}

	// Decrypt the restored MFA state with the restored key, which is the operation the very
	// next login after a recovery has to perform.
	method, err := recovered.GetMFAMethod(u.ID, "totp")
	if err != nil || method == nil {
		t.Fatalf("the enrolled TOTP factor did not survive the restore: %v", err)
	}
	plain, err := crypto.DecryptAESGCM(gotEncKey, method.EncryptedSecret)
	if err != nil {
		t.Fatalf("the restored TOTP secret does not decrypt under the restored key: %v", err)
	}
	if string(plain) != totpSecret {
		t.Fatalf("restored TOTP secret is %q, want %q", plain, totpSecret)
	}

	// The raw main file the old backup path copied would not have restored this account.
	// This is the regression the snapshot exists to prevent, so it is asserted rather than
	// assumed.
	naivePath := filepath.Join(tmp, "naive.db")
	if err := os.WriteFile(naivePath, rawMainFile, 0600); err != nil {
		t.Fatal(err)
	}
	naive, err := store.New(naivePath)
	if err == nil {
		if u, err := naive.GetUserByUsername("recovery-admin"); err == nil && u != nil {
			t.Error("a raw copy of the main database file also contained the account; " +
				"this test is no longer proving the WAL snapshot is necessary")
		}
		_ = naive.Close()
	}

	// A sub-quorum must not be enough, or the custody model is decoration.
	if _, err := backup.CombineShares(shards[:quorum-1], quorum); err == nil {
		t.Error("fewer than the threshold number of shards reconstructed the key")
	}
}

// extractShardHex pulls the shard out of a custodian card the way a person reading the page
// would, so the test fails if the card stops actually containing a usable shard.
func extractShardHex(t *testing.T, html string) string {
	t.Helper()
	marker := "<code>"
	start := strings.Index(html, marker)
	if start < 0 {
		t.Fatal("custodian card contains no shard block")
	}
	start += len(marker)
	end := strings.Index(html[start:], "</code>")
	if end < 0 {
		t.Fatal("custodian card shard block is unterminated")
	}
	candidate := strings.TrimSpace(html[start : start+end])
	if _, err := hex.DecodeString(candidate); err != nil {
		t.Fatalf("custodian card shard block %q is not hex: %v", candidate, err)
	}
	return candidate
}
