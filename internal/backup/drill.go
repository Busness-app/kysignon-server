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
	if reqFiles, ok := recipe["required_files"].([]interface{}); ok {
		allFound := true
		for _, rf := range reqFiles {
			pathStr := fmt.Sprintf("%v", rf)
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
		if sqlitePaths, ok := recipe["sqlite_paths"].([]interface{}); ok {
			for _, sp := range sqlitePaths {
				dbRelPath := fmt.Sprintf("%v", sp)
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
					// Count tables to ensure schema is present
					var tableCount int
					_ = db.QueryRowContext(ctx, "SELECT count(*) FROM sqlite_master WHERE type='table';").Scan(&tableCount)

					result.Checks = append(result.Checks, CheckItem{
						Name:    fmt.Sprintf("DB Integrity Check: %s", dbRelPath),
						Passed:  true,
						Message: fmt.Sprintf("SQLite PRAGMA integrity_check passed (found %d tables)", tableCount),
					})
				}
				_ = db.Close()
			}
		}
	}

	// 4. Validate Expected Environment Dependencies
	if expEnv, ok := recipe["expected_env"].([]interface{}); ok {
		var setEnvs []string
		for _, e := range expEnv {
			envName := fmt.Sprintf("%v", e)
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
