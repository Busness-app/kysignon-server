package backup_test

import (
	"context"
	"database/sql"
	"encoding/hex"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Busness-app/kysignon-server/internal/backup"
	"github.com/Busness-app/kysignon-server/internal/crypto"
	_ "modernc.org/sqlite"
)

func TestShamirSecretSharing(t *testing.T) {
	secret := []byte("32-byte-master-encryption-key-!!")
	threshold := 3
	totalShares := 5

	// 1. Split
	shares, err := backup.SplitSecret(secret, threshold, totalShares)
	if err != nil {
		t.Fatalf("SplitSecret failed: %v", err)
	}
	if len(shares) != totalShares {
		t.Fatalf("expected %d shares, got %d", totalShares, len(shares))
	}

	// 2. Reconstruct with exact threshold (shares [0, 2, 4])
	subset := []backup.Share{shares[0], shares[2], shares[4]}
	reconstructed, err := backup.CombineShares(subset, threshold)
	if err != nil {
		t.Fatalf("CombineShares failed: %v", err)
	}

	if string(reconstructed) != string(secret) {
		t.Errorf("expected %s, got %s", string(secret), string(reconstructed))
	}

	// 3. Reconstruct with another combination (shares [1, 3, 4])
	subset2 := []backup.Share{shares[1], shares[3], shares[4]}
	reconstructed2, err := backup.CombineShares(subset2, threshold)
	if err != nil {
		t.Fatalf("CombineShares subset2 failed: %v", err)
	}
	if string(reconstructed2) != string(secret) {
		t.Errorf("subset2 expected %s, got %s", string(secret), string(reconstructed2))
	}

	// 4. Reconstruct with less than threshold should fail
	_, err = backup.CombineShares(shares[:2], threshold)
	if err != backup.ErrNotEnoughShares {
		t.Errorf("expected ErrNotEnoughShares, got %v", err)
	}
}

func TestCapsuleLifecycleAndRestoreDrill(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()

	// 1. Create a dummy SQLite DB with data
	dbFile := filepath.Join(tmpDir, "test.db")
	db, err := sql.Open("sqlite", dbFile)
	if err != nil {
		t.Fatalf("failed to create sqlite db: %v", err)
	}
	_, _ = db.Exec("CREATE TABLE users (id TEXT PRIMARY KEY, username TEXT);")
	_, _ = db.Exec("INSERT INTO users (id, username) VALUES ('u1', 'admin');")
	_ = db.Close()

	files := []backup.BackupFile{
		{
			Path: "data/kysignon.db",
			Data: []byte("SQLite format 3\x00mock-header-data-for-testing"),
			Mode: 0600,
		},
		{
			Path: "config/kysignon.json",
			Data: []byte(`{"app_name":"KySignOn","port":"5867"}`),
			Mode: 0600,
		},
	}

	recipe := map[string]interface{}{
		"check_sqlite_integrity": false,
		"required_files":         []interface{}{"data/kysignon.db", "config/kysignon.json"},
		"expected_env":           []interface{}{"KYSIGNON_PORT"},
		"expected_ports":         []interface{}{5867},
	}

	deps := map[string]interface{}{
		"ports": []int{5867},
	}

	// 2. Create Capsule
	capsule, key, err := backup.CreateCapsule("KySignOn", "1.0.0", files, deps, recipe, 2, 3)
	if err != nil {
		t.Fatalf("CreateCapsule failed: %v", err)
	}

	if len(capsule.Shares) != 3 {
		t.Errorf("expected 3 shares, got %d", len(capsule.Shares))
	}

	// 3. Run Restore Drill
	drillResult, err := backup.RunRestoreDrill(ctx, capsule, key)
	if err != nil {
		t.Fatalf("RunRestoreDrill failed: %v", err)
	}

	if !drillResult.Passed {
		t.Errorf("expected drill to pass, failed with: %s", drillResult.ErrorMessage)
	}

	if len(drillResult.Checks) == 0 {
		t.Error("expected drill checks to be populated")
	}

	// 4. Test Corrupted Capsule Key
	badKey, _ := crypto.GenerateRandomBytes(32)
	badResult, _ := backup.RunRestoreDrill(ctx, capsule, badKey)
	if badResult.Passed {
		t.Error("expected drill with wrong key to fail")
	}

	// 5. A custodian card carries exactly one shard.
	card := backup.GenerateCustodianCardHTML(capsule.Manifest, capsule.Shares[0], "KySignOn", "https://sso.example.test")
	if len(card) == 0 {
		t.Fatal("expected non-empty custodian card")
	}
	for _, other := range capsule.Shares[1:] {
		if strings.Contains(card, hex.EncodeToString(other.Data)) {
			t.Fatalf("custodian card for shard %d also contains shard %d; a single file holds a quorum",
				capsule.Shares[0].Index, other.Index)
		}
	}
	if !strings.Contains(card, hex.EncodeToString(capsule.Shares[0].Data)) {
		t.Error("custodian card is missing its own shard")
	}
	_ = dbFile
}
