package backup

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"strconv"
	"time"

	"github.com/Yoshiofthewire/kysignon-server/internal/config"
)

// BuildLocalPayload collects local KySignOn files (SQLite DB, RSA keys, config manifest) into a backup package.
func BuildLocalPayload(cfg *config.Config, appVersion string) (*PushBackupPayload, error) {
	var files []PushBackupFile
	var sqlitePaths []string
	var reqFiles []string

	// 1. Read SQLite Database if present
	if cfg.DBPath != "" {
		if dbBytes, err := os.ReadFile(cfg.DBPath); err == nil {
			relPath := "data/kysignon.db"
			files = append(files, PushBackupFile{
				Path:       relPath,
				DataBase64: base64.StdEncoding.EncodeToString(dbBytes),
				Mode:       0600,
			})
			sqlitePaths = append(sqlitePaths, relPath)
			reqFiles = append(reqFiles, relPath)
		}
	}

	// 2. Read RSA Key if present
	if cfg.RSAKeyPath != "" {
		if keyBytes, err := os.ReadFile(cfg.RSAKeyPath); err == nil {
			relPath := "data/jwt_rs256.key"
			files = append(files, PushBackupFile{
				Path:       relPath,
				DataBase64: base64.StdEncoding.EncodeToString(keyBytes),
				Mode:       0600,
			})
			reqFiles = append(reqFiles, relPath)
		}
	}

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
	cfgJSON, _ := json.MarshalIndent(cfgSnapshot, "", "  ")
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
			"check_sqlite_integrity": len(sqlitePaths) > 0,
			"sqlite_paths":          sqlitePaths,
			"required_files":        reqFiles,
			"expected_env":          []string{"KYSIGNON_PORT", "KYSIGNON_ISSUER_URL"},
			"expected_ports":        []int{portNum},
		},
	}

	return payload, nil
}
