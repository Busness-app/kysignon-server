package backup

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"time"

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

// RunRestoreDrill decapsulates the container into an ephemeral 0700 scratch directory, executes the recipe, and scrubs the directory.
func RunRestoreDrill(ctx context.Context, capsule *Capsule, key []byte) (*DrillResult, error) {
	start := time.Now()

	scratchDir, err := os.MkdirTemp("", "kybackup-drill-*")
	if err != nil {
		return nil, fmt.Errorf("failed to create drill sandbox: %w", err)
	}
	defer func() {
		_ = os.RemoveAll(scratchDir)
	}()

	_ = os.Chmod(scratchDir, 0700)

	result := &DrillResult{
		Passed: true,
		Checks: make([]CheckItem, 0),
	}

	// 1. Decapsulate and extract
	files, err := ExtractCapsule(capsule, key, scratchDir)
	if err != nil {
		result.Passed = false
		result.ErrorMessage = fmt.Sprintf("Decapsulation failed: %v", err)
		result.Checks = append(result.Checks, CheckItem{
			Name:    "Directory Unpack",
			Passed:  false,
			Message: result.ErrorMessage,
		})
		result.DurationMS = time.Since(start).Milliseconds()
		return result, nil
	}

	var totalBytes int64
	for _, f := range files {
		totalBytes += int64(len(f.Data))
	}

	result.Checks = append(result.Checks, CheckItem{
		Name:    "Directory Unpack",
		Passed:  true,
		Message: fmt.Sprintf("Extracted %d files (%d bytes) into isolated sandbox", len(files), totalBytes),
	})

	recipe := capsule.Manifest.VerificationRecipe
	if recipe == nil {
		recipe = make(map[string]interface{})
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

	// 4. Validate Expected Environment Dependencies
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

	// 5. Verification Recipe Completed
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
