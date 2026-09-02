package backup

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/Busness-app/kysignon-server/internal/config"
)

// Relative paths inside a capsule. They are constants because the restore drill and
// kyrestore both have to find the same files the builder wrote.
const (
	dbRelPath        = "data/kysignon.db"
	keyRelPath       = "data/jwt_rs256.key"
	encKeyRelPath    = "data/encryption.key"
	secretKeyRelPath = "data/secret.key"
	configRelPath    = "config/kysignon.json"
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
	files = append(files, PushBackupFile{
		Path:       keyRelPath,
		DataBase64: base64.StdEncoding.EncodeToString(keyBytes),
		Mode:       0600,
	})
	reqFiles = append(reqFiles, keyRelPath)

	// 3. The deployment key material. The database ships every TOTP secret and paired-system
	// token encrypted under the encryption key, so a capsule without that key restores a
	// directory whose MFA state is permanently unreadable: the drill passes, SQLite is
	// intact, and not one enrolled user can complete a login. The secret key is included for
	// the same reason at a lower stake — without it every session and CSRF token minted
	// before the restore is silently invalid.
	//
	// These are taken from the loaded config rather than read off disk, so a deployment that
	// supplies them by environment variable is backed up as faithfully as one using files.
	for _, k := range []struct {
		relPath  string
		material []byte
		name     string
	}{
		{encKeyRelPath, cfg.EncryptionKey, "encryption key"},
		{secretKeyRelPath, cfg.SecretKey, "secret key"},
	} {
		if len(k.material) != config.KeyLength {
			return nil, fmt.Errorf("backup requires a %d-byte %s; the loaded one is %d bytes",
				config.KeyLength, k.name, len(k.material))
		}
		files = append(files, PushBackupFile{
			Path:       k.relPath,
			DataBase64: base64.StdEncoding.EncodeToString(k.material),
			Mode:       0600,
		})
		reqFiles = append(reqFiles, k.relPath)
	}

	// 4. Include Configuration Manifest
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
	files = append(files, PushBackupFile{
		Path:       configRelPath,
		DataBase64: base64.StdEncoding.EncodeToString(cfgJSON),
		Mode:       0600,
	})
	reqFiles = append(reqFiles, configRelPath)

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
			// Proving the restored bytes are also usable. "The archive unpacked" says
			// nothing about whether the encrypted columns can still be read or whether the
			// service could issue a token, which is the only outcome a restore is for.
			"encryption_key_file":     encKeyRelPath,
			"secret_key_file":         secretKeyRelPath,
			"rsa_key_file":            keyRelPath,
			"prove_secret_decryption": true,
			"prove_token_signing":     true,
			"expected_env":            []string{"KYSIGNON_PORT", "KYSIGNON_ISSUER_URL"},
			"expected_ports":          []int{portNum},
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
