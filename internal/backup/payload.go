package backup

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/Yoshiofthewire/kysignon-server/internal/config"
)

// Snapshotter produces a transactionally consistent copy of the live database. The store
// implements it; the interface exists so the backup package does not depend on the store.
type Snapshotter interface {
	SnapshotTo(destPath string) error
}

// BuildLocalPayload collects local KySignOn files (SQLite snapshot, RSA key, config
// manifest) into a backup package.
//
// A missing or unreadable database or signing key is fatal. Skipping them produced a
// well-formed capsule that could not restore the service, which is worse than no capsule:
// the drill passes, the operator believes they are covered, and the gap surfaces only when
// production is already gone.
func BuildLocalPayload(cfg *config.Config, snap Snapshotter, appVersion string) (*PushBackupPayload, error) {
	if cfg.DBPath == "" {
		return nil, fmt.Errorf("backup requires a database path; none is configured")
	}
	if snap == nil {
		return nil, fmt.Errorf("backup requires a live database handle to snapshot")
	}

	var files []PushBackupFile
	var sqlitePaths []string
	var reqFiles []string

	// 1. Snapshot the database through the live connection. Reading the main database file
	// is not a live backup procedure in WAL mode: committed transactions can exist only in
	// the -wal file, so a file copy silently restores an older user directory.
	scratch, err := os.MkdirTemp("", "kysignon-snapshot-*")
	if err != nil {
		return nil, fmt.Errorf("failed to create snapshot scratch directory: %w", err)
	}
	defer func() { _ = os.RemoveAll(scratch) }()
	if err := os.Chmod(scratch, 0700); err != nil {
		return nil, err
	}

	snapPath := filepath.Join(scratch, "kysignon.db")
	if err := snap.SnapshotTo(snapPath); err != nil {
		return nil, err
	}
	dbBytes, err := os.ReadFile(snapPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read database snapshot: %w", err)
	}
	if len(dbBytes) == 0 {
		return nil, fmt.Errorf("database snapshot is empty")
	}
	dbRelPath := "data/kysignon.db"
	files = append(files, PushBackupFile{
		Path:       dbRelPath,
		DataBase64: base64.StdEncoding.EncodeToString(dbBytes),
		Mode:       0600,
	})
	sqlitePaths = append(sqlitePaths, dbRelPath)
	reqFiles = append(reqFiles, dbRelPath)

	// 2. The RSA signing key. Without it every issued token and OIDC client breaks on
	// restore, so its absence is fatal too.
	if cfg.RSAKeyPath == "" {
		return nil, fmt.Errorf("backup requires an RSA signing key path; none is configured")
	}
	keyBytes, err := os.ReadFile(cfg.RSAKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read RSA signing key %s: %w", cfg.RSAKeyPath, err)
	}
	if len(keyBytes) == 0 {
		return nil, fmt.Errorf("RSA signing key %s is empty", cfg.RSAKeyPath)
	}
	keyRelPath := "data/jwt_rs256.key"
	files = append(files, PushBackupFile{
		Path:       keyRelPath,
		DataBase64: base64.StdEncoding.EncodeToString(keyBytes),
		Mode:       0600,
	})
	reqFiles = append(reqFiles, keyRelPath)

	// 3. Include Configuration Manifest
	cfgSnapshot := map[string]interface{}{
		"app_name":                "KySignOn",
		"version":                 appVersion,
		"port":                    cfg.Port,
		"issuer_url":              cfg.IssuerURL,
		"data_dir":                cfg.DataDir,
		"allow_private_callbacks": cfg.AllowPrivateCallbacks,
		"secure_cookies":          cfg.SecureCookies,
		"session_ttl_sec":         int64(cfg.SessionTTL / time.Second),
		"session_idle_ttl_sec":    int64(cfg.SessionIdleTTL / time.Second),
	}
	cfgJSON, err := json.MarshalIndent(cfgSnapshot, "", "  ")
	if err != nil {
		return nil, err
	}
	cfgPath := "config/kysignon.json"
	files = append(files, PushBackupFile{
		Path:       cfgPath,
		DataBase64: base64.StdEncoding.EncodeToString(cfgJSON),
		Mode:       0600,
	})
	reqFiles = append(reqFiles, cfgPath)

	portNum, _ := strconv.Atoi(cfg.Port)
	if portNum == 0 {
		portNum = 5867
	}

	payload := &PushBackupPayload{
		ServiceName: "KySignOn",
		AppVersion:  appVersion,
		Threshold:   2,
		TotalShares: 3,
		Files:       files,
		Dependencies: map[string]interface{}{
			"ports": []int{portNum},
			"env":   []string{"KYSIGNON_PORT", "KYSIGNON_ISSUER_URL"},
		},
		VerificationRecipe: map[string]interface{}{
			"check_sqlite_integrity": true,
			"sqlite_paths":           sqlitePaths,
			"required_files":         reqFiles,
			// The drill asserts these tables exist and the admin directory is non-empty.
			// PRAGMA integrity_check only proves the file is not corrupt; it says nothing
			// about whether the identity data survived.
			"required_tables":   []string{"users", "oauth_clients", "mfa_methods", "paired_systems"},
			"require_any_admin": true,
			"expected_env":      []string{"KYSIGNON_PORT", "KYSIGNON_ISSUER_URL"},
			"expected_ports":    []int{portNum},
		},
	}

	return payload, nil
}

// AsBackupFiles decodes a push payload back into raw capsule input.
func AsBackupFiles(payload *PushBackupPayload) ([]BackupFile, error) {
	files := make([]BackupFile, 0, len(payload.Files))
	for _, f := range payload.Files {
		data, err := base64.StdEncoding.DecodeString(f.DataBase64)
		if err != nil {
			return nil, fmt.Errorf("payload file %s is not valid base64: %w", f.Path, err)
		}
		files = append(files, BackupFile{Path: f.Path, Data: data, Mode: f.Mode})
	}
	return files, nil
}
