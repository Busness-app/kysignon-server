package backup

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/Busness-app/ky-primitives/capsule"
	"github.com/Busness-app/ky-primitives/recoverykey"
	"github.com/Busness-app/kysignon-server/internal/config"
	"github.com/Busness-app/kysignon-server/internal/crypto"
	_ "modernc.org/sqlite"
)

// CheckItem represents a discrete verification result in a restore drill.
type CheckItem struct {
	Name    string `json:"name"`
	Passed  bool   `json:"passed"`
	Message string `json:"message"`
}

// DrillResult contains the structured outcome of a restore drill.
type DrillResult struct {
	Passed       bool        `json:"passed"`
	DurationMS   int64       `json:"duration_ms"`
	Checks       []CheckItem `json:"checks"`
	ErrorMessage string      `json:"error_message,omitempty"`
}

// RunRestoreDrill proves the backup pipeline: it seals files exactly as a real backup would,
// but to a throwaway keypair it then opens with, extracts into a 0700 scratch directory, and
// runs the verification recipe. The product has no recovery private key, so this is the only
// end-to-end check it can run alone. A separate check reports whether the suite key is pinned.
func RunRestoreDrill(ctx context.Context, serviceName, appVersion string, files []BackupFile, deps, recipe map[string]any, pinned RecoveryKey) (*DrillResult, error) {
	start := time.Now()
	result := &DrillResult{Passed: true, Checks: make([]CheckItem, 0)}

	if pinned.Public.IsZero() {
		result.Passed = false
		result.Checks = append(result.Checks, CheckItem{Name: "Recovery Key", Passed: false, Message: ErrNotPaired.Error()})
	} else {
		result.Checks = append(result.Checks, CheckItem{Name: "Recovery Key", Passed: true,
			Message: fmt.Sprintf("Sealing to recovery key %s (%d-of-%d custodians)", pinned.Public.ID()[:16], pinned.Threshold, pinned.TotalShares)})
	}

	// Seal to a throwaway key and open with it. Topology is display metadata here; the
	// drill key has no custodians and is dropped when this call returns.
	drillKey, err := recoverykey.Generate()
	if err != nil {
		return nil, fmt.Errorf("drill key: %w", err)
	}
	var payloadBytes int64
	for _, f := range files {
		payloadBytes += int64(len(f.Data))
	}
	raw, _, err := capsule.Seal(serviceName, appVersion, toCapsuleFiles(files), deps, recipe, 2, 3, drillKey.Public())
	if err != nil {
		result.Passed = false
		result.ErrorMessage = fmt.Sprintf("Seal failed: %v", err)
		result.Checks = append(result.Checks, CheckItem{Name: "Seal", Passed: false,
			Message: fmt.Sprintf("%s (payload %d bytes across %d files)", result.ErrorMessage, payloadBytes, len(files))})
		result.DurationMS = time.Since(start).Milliseconds()
		return result, nil
	}

	scratchDir, err := os.MkdirTemp("", "kybackup-drill-*")
	if err != nil {
		return nil, fmt.Errorf("failed to create drill sandbox: %w", err)
	}
	defer func() { _ = os.RemoveAll(scratchDir) }()
	_ = os.Chmod(scratchDir, 0700)

	m, extracted, err := capsule.Open(raw, drillKey, scratchDir)
	if err != nil {
		result.Passed = false
		result.ErrorMessage = fmt.Sprintf("Open failed: %v", err)
		result.Checks = append(result.Checks, CheckItem{Name: "Directory Unpack", Passed: false, Message: result.ErrorMessage})
		result.DurationMS = time.Since(start).Milliseconds()
		return result, nil
	}
	var totalBytes int64
	for _, f := range extracted {
		totalBytes += int64(len(f.Content))
	}
	result.Checks = append(result.Checks, CheckItem{Name: "Directory Unpack", Passed: true,
		Message: fmt.Sprintf("Extracted %d files (%d bytes) into isolated sandbox", len(extracted), totalBytes)})

	recipe, _ = m.VerificationRecipe.(map[string]any)
	if recipe == nil {
		recipe = make(map[string]any)
	}

	// 2. Verify Required Files
	if reqFiles := stringList(recipe["required_files"]); len(reqFiles) > 0 {
		allFound := true
		for _, pathStr := range reqFiles {
			fullPath := filepath.Join(scratchDir, pathStr)
			fi, err := os.Stat(fullPath)
			if err != nil || fi.Size() == 0 {
				allFound = false
				result.Passed = false
				result.Checks = append(result.Checks, CheckItem{
					Name:    fmt.Sprintf("Required File: %s", pathStr),
					Passed:  false,
					Message: "File missing or empty in unpacked capsule",
				})
			}
		}
		if allFound && len(reqFiles) > 0 {
			result.Checks = append(result.Checks, CheckItem{
				Name:    "Required Files",
				Passed:  true,
				Message: fmt.Sprintf("All %d required files verified", len(reqFiles)),
			})
		}
	}

	// 3. SQLite Integrity Check
	if checkDB, ok := recipe["check_sqlite_integrity"].(bool); ok && checkDB {
		sqlitePaths := stringList(recipe["sqlite_paths"])
		if len(sqlitePaths) == 0 {
			result.Passed = false
			result.Checks = append(result.Checks, CheckItem{
				Name:    "SQLite Verification",
				Passed:  false,
				Message: "Recipe requires a SQLite integrity check but names no database",
			})
		}
		{
			for _, dbRelPath := range sqlitePaths {
				fullDBPath := filepath.Join(scratchDir, dbRelPath)

				db, err := sql.Open("sqlite", fullDBPath)
				if err != nil {
					result.Passed = false
					result.Checks = append(result.Checks, CheckItem{
						Name:    fmt.Sprintf("SQLite Open: %s", dbRelPath),
						Passed:  false,
						Message: fmt.Sprintf("Failed to open extracted DB: %v", err),
					})
					continue
				}

				// Run PRAGMA integrity_check
				var integrityResult string
				row := db.QueryRowContext(ctx, "PRAGMA integrity_check;")
				if err := row.Scan(&integrityResult); err != nil || integrityResult != "ok" {
					result.Passed = false
					result.Checks = append(result.Checks, CheckItem{
						Name:    fmt.Sprintf("DB Integrity Check: %s", dbRelPath),
						Passed:  false,
						Message: fmt.Sprintf("Integrity failure (%s): %v", integrityResult, err),
					})
				} else {
					var tableCount int
					_ = db.QueryRowContext(ctx, "SELECT count(*) FROM sqlite_master WHERE type='table';").Scan(&tableCount)

					result.Checks = append(result.Checks, CheckItem{
						Name:    fmt.Sprintf("DB Integrity Check: %s", dbRelPath),
						Passed:  true,
						Message: fmt.Sprintf("SQLite PRAGMA integrity_check passed (found %d tables)", tableCount),
					})

					// integrity_check only proves the file is not corrupt. A restore is
					// only useful if the identity records are actually in it.
					checkApplicationRecords(ctx, db, dbRelPath, recipe, result)
				}
				_ = db.Close()
			}
		}
	}

	// 4. Prove the restored bytes are usable, not merely present. This is the difference
	// between a drill and a recovery test: encrypted MFA state that cannot be decrypted and
	// a signing key that cannot mint a token both survive every check above unnoticed.
	proveRestoreIsUsable(ctx, scratchDir, recipe, result)

	// 5. Validate Expected Environment Dependencies
	if expEnv := stringList(recipe["expected_env"]); len(expEnv) > 0 {
		var setEnvs []string
		for _, envName := range expEnv {
			if os.Getenv(envName) != "" {
				setEnvs = append(setEnvs, envName)
			}
		}
		result.Checks = append(result.Checks, CheckItem{
			Name:    "Environment Configuration",
			Passed:  true,
			Message: fmt.Sprintf("%d/%d expected environment variables active", len(setEnvs), len(expEnv)),
		})
	}

	// 6. Verification Recipe Completed
	result.DurationMS = time.Since(start).Milliseconds()
	return result, nil
}

// checkApplicationRecords asserts the restored database contains the tables and rows the
// service cannot start without. This is the difference between "the file parses" and "the
// identity directory survived".
func checkApplicationRecords(ctx context.Context, db *sql.DB, dbRelPath string, recipe map[string]interface{}, result *DrillResult) {
	for _, table := range stringList(recipe["required_tables"]) {
		{
			var rows int
			err := db.QueryRowContext(ctx,
				`SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?`, table).Scan(&rows)
			if err != nil || rows != 1 {
				result.Passed = false
				result.Checks = append(result.Checks, CheckItem{
					Name:    fmt.Sprintf("Table Present: %s", table),
					Passed:  false,
					Message: fmt.Sprintf("Table %q is missing from the restored database", table),
				})
			}
		}
	}

	if requireAdmin, ok := recipe["require_any_admin"].(bool); ok && requireAdmin {
		var admins int
		err := db.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM users WHERE role = 'admin' AND status = 'active'`).Scan(&admins)
		passed := err == nil && admins > 0
		if !passed {
			result.Passed = false
		}
		msg := fmt.Sprintf("%d active administrator(s) present in the restored directory", admins)
		if err != nil {
			msg = fmt.Sprintf("Could not read the restored user directory: %v", err)
		} else if admins == 0 {
			msg = "The restored directory has no active administrator; nobody could log in after a restore"
		}
		result.Checks = append(result.Checks, CheckItem{
			Name:    fmt.Sprintf("Administrator Directory: %s", dbRelPath),
			Passed:  passed,
			Message: msg,
		})
	}
}

// stringList reads a recipe list that may be []string (an in-process capsule) or
// []interface{} (the same recipe after a JSON round trip). Asserting only one of the two
// silently skipped every check whose list came from the other path.
func stringList(v interface{}) []string {
	switch typed := v.(type) {
	case []string:
		return typed
	case []interface{}:
		out := make([]string, 0, len(typed))
		for _, item := range typed {
			out = append(out, fmt.Sprintf("%v", item))
		}
		return out
	default:
		return nil
	}
}

// proveRestoreIsUsable loads the restored key material and exercises it against the restored
// database: decrypt what the service must decrypt on the next login, and sign and verify a
// token the way the token endpoint would. Everything here is read-only and confined to the
// drill sandbox.
func proveRestoreIsUsable(ctx context.Context, scratchDir string, recipe map[string]interface{}, result *DrillResult) {
	fail := func(name, msg string) {
		result.Passed = false
		result.Checks = append(result.Checks, CheckItem{Name: name, Passed: false, Message: msg})
	}
	pass := func(name, msg string) {
		result.Checks = append(result.Checks, CheckItem{Name: name, Passed: true, Message: msg})
	}

	if secretPath, _ := recipe["secret_key_file"].(string); secretPath != "" {
		data, err := os.ReadFile(filepath.Join(scratchDir, secretPath))
		if err != nil || len(data) != config.KeyLength {
			fail("Session Secret Restored",
				fmt.Sprintf("%s is missing or not %d bytes; every session and CSRF token would be invalidated by a restore", secretPath, config.KeyLength))
		} else {
			pass("Session Secret Restored", "Session and CSRF secret recovered intact")
		}
	}

	if prove, _ := recipe["prove_secret_decryption"].(bool); prove {
		proveSecretDecryption(ctx, scratchDir, recipe, fail, pass)
	}

	if prove, _ := recipe["prove_token_signing"].(bool); prove {
		rsaPath, _ := recipe["rsa_key_file"].(string)
		if rsaPath == "" {
			fail("Token Signing", "Recipe asks to prove token signing but names no signing key")
			return
		}
		// LoadOrCreateRSAKey would generate a fresh key if the restored one were unreadable,
		// which would turn this proof into a tautology, so the file is checked first.
		full := filepath.Join(scratchDir, rsaPath)
		if fi, err := os.Stat(full); err != nil || fi.Size() == 0 {
			fail("Token Signing", fmt.Sprintf("Restored signing key %s is missing or empty", rsaPath))
			return
		}
		km, err := crypto.LoadOrCreateRSAKey(full)
		if err != nil {
			fail("Token Signing", fmt.Sprintf("Restored signing key will not load: %v", err))
			return
		}
		token, err := km.SignJWT(map[string]any{
			"iss": "kysignon-restore-drill",
			"sub": "drill",
			"exp": time.Now().Add(time.Minute).Unix(),
		})
		if err != nil {
			fail("Token Signing", fmt.Sprintf("Restored signing key could not sign a token: %v", err))
			return
		}
		if _, err := km.VerifyJWT(token); err != nil {
			fail("Token Signing", fmt.Sprintf("Token signed by the restored key did not verify: %v", err))
			return
		}
		pass("Token Signing", "Restored RSA key signed and verified a JWT; issued tokens survive a restore")
	}
}

// proveSecretDecryption reads the encrypted columns the service cannot start a login without
// and decrypts them under the restored encryption key.
func proveSecretDecryption(ctx context.Context, scratchDir string, recipe map[string]interface{}, fail, pass func(string, string)) {
	keyPath, _ := recipe["encryption_key_file"].(string)
	if keyPath == "" {
		fail("MFA Secret Decryption", "Recipe asks to prove decryption but names no encryption key")
		return
	}
	key, err := os.ReadFile(filepath.Join(scratchDir, keyPath))
	if err != nil || len(key) != config.KeyLength {
		fail("MFA Secret Decryption",
			fmt.Sprintf("Restored capsule has no usable %s; every enrolled TOTP secret and paired-system token would be unreadable after a restore", keyPath))
		return
	}

	dbPaths := stringList(recipe["sqlite_paths"])
	if len(dbPaths) == 0 {
		fail("MFA Secret Decryption", "Recipe asks to prove decryption but names no database")
		return
	}
	db, err := sql.Open("sqlite", filepath.Join(scratchDir, dbPaths[0]))
	if err != nil {
		fail("MFA Secret Decryption", fmt.Sprintf("Could not open the restored database: %v", err))
		return
	}
	defer func() { _ = db.Close() }()

	for _, target := range []struct {
		name  string
		query string
		empty string
	}{
		{
			"MFA Secret Decryption",
			`SELECT encrypted_secret FROM mfa_methods WHERE method_type = 'totp' AND encrypted_secret IS NOT NULL AND encrypted_secret != ''`,
			"No TOTP secrets are enrolled, so none could be checked",
		},
		{
			"Paired System Token Decryption",
			`SELECT hmac_secret_encrypted FROM paired_systems WHERE hmac_secret_encrypted IS NOT NULL AND hmac_secret_encrypted != ''`,
			"No paired systems are configured, so none could be checked",
		},
	} {
		rows, err := db.QueryContext(ctx, target.query)
		if err != nil {
			fail(target.name, fmt.Sprintf("Could not read the restored ciphertext: %v", err))
			continue
		}
		var checked, failed int
		for rows.Next() {
			var ciphertext string
			if err := rows.Scan(&ciphertext); err != nil {
				failed++
				continue
			}
			checked++
			if _, err := crypto.DecryptAESGCM(key, ciphertext); err != nil {
				failed++
			}
		}
		_ = rows.Close()

		switch {
		case failed > 0:
			fail(target.name, fmt.Sprintf("%d of %d restored secrets did not decrypt under the restored encryption key", failed, checked))
		case checked == 0:
			// Nothing to prove is not the same as proven. Say so rather than showing a tick
			// the operator would read as "MFA state verified".
			pass(target.name, target.empty)
		default:
			pass(target.name, fmt.Sprintf("All %d restored secrets decrypted under the restored encryption key", checked))
		}
	}
}
