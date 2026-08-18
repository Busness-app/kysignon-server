package store

import (
	"database/sql"
	"errors"
	"fmt"
	"runtime"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

type Store struct {
	db *sql.DB
}

var ErrLastActiveAdmin = errors.New("cannot remove the last active administrator")

// New opens the SQLite database and creates the schema.
func New(dbPath string) (*Store, error) {
	// Enable WAL mode, busy timeout, and foreign keys in DSN
	dsn := fmt.Sprintf("%s?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(ON)", dbPath)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to open sqlite database: %w", err)
	}

	// WAL supports one writer alongside many concurrent readers. Capping the whole pool at
	// one connection serialised every request in the server behind the slowest handler,
	// including outbound webhook delivery and Argon2 verification.
	db.SetMaxOpenConns(runtime.NumCPU() + 4)
	db.SetMaxIdleConns(4)
	db.SetConnMaxLifetime(time.Hour)

	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("schema creation failed: %w", err)
	}

	return s, nil
}

func (s *Store) Close() error {
	return s.db.Close()
}

func (s *Store) migrate() error {
	schema := `
	CREATE TABLE IF NOT EXISTS users (
		id TEXT PRIMARY KEY,
		username TEXT NOT NULL UNIQUE COLLATE NOCASE,
		display_name TEXT NOT NULL,
		email TEXT NOT NULL UNIQUE COLLATE NOCASE,
		password_hash TEXT NOT NULL,
		role TEXT NOT NULL CHECK (role IN ('user', 'admin')),
		status TEXT NOT NULL CHECK (status IN ('active', 'disabled')),
		created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS sessions (
		id TEXT PRIMARY KEY,
		user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
		session_token_hash TEXT NOT NULL UNIQUE,
		ip_address TEXT NOT NULL,
		user_agent TEXT NOT NULL,
		expires_at DATETIME NOT NULL,
		created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		last_active_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
	);
	CREATE INDEX IF NOT EXISTS idx_sessions_token_hash ON sessions(session_token_hash);
	CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);

	CREATE TABLE IF NOT EXISTS login_failures (
		user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
		failures INTEGER NOT NULL DEFAULT 0,
		last_failure_at DATETIME NOT NULL
	);

	-- hmac_secret_encrypted holds the webhook signing secret sealed under the deployment
	-- encryption key. It signs outbound webhooks, so it must be recoverable, not hashed.
	CREATE TABLE IF NOT EXISTS paired_systems (
		id TEXT PRIMARY KEY,
		name TEXT NOT NULL,
		system_type TEXT NOT NULL,
		callback_url TEXT NOT NULL,
		hmac_secret_encrypted TEXT NOT NULL,
		status TEXT NOT NULL CHECK (status IN ('active', 'failing', 'disabled')),
		last_synced_at DATETIME,
		created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS system_pairing_tokens (
		id TEXT PRIMARY KEY,
		token_hash TEXT NOT NULL UNIQUE,
		pin_hash TEXT NOT NULL,
		pin_attempts INTEGER NOT NULL DEFAULT 0,
		system_type TEXT NOT NULL,
		created_by_user_id TEXT NOT NULL REFERENCES users(id),
		expires_at DATETIME NOT NULL,
		used_at DATETIME,
		created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
	);
	CREATE INDEX IF NOT EXISTS idx_system_pairing_tokens_hash ON system_pairing_tokens(token_hash);

	CREATE TABLE IF NOT EXISTS account_sync_events (
		id TEXT PRIMARY KEY,
		-- Deletion events must remain deliverable after their user has been removed.
		user_id TEXT NOT NULL,
		system_id TEXT NOT NULL,
		event_type TEXT NOT NULL,
		payload_json TEXT NOT NULL,
		attempts INTEGER NOT NULL DEFAULT 0,
		status TEXT NOT NULL CHECK (status IN ('pending', 'delivered', 'failed')),
		last_error TEXT,
		next_attempt_at DATETIME,
		created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
	);
	CREATE INDEX IF NOT EXISTS idx_sync_events_status ON account_sync_events(status);

	CREATE TABLE IF NOT EXISTS native_devices (
		id TEXT PRIMARY KEY,
		user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
		device_name TEXT NOT NULL,
		device_identifier TEXT NOT NULL,
		platform TEXT NOT NULL DEFAULT 'android' CHECK (platform IN ('android', 'ios', 'macos')),
		public_key TEXT,
		push_token TEXT,
		is_mfa_approver BOOLEAN NOT NULL DEFAULT 0,
		last_seen_at DATETIME,
		created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		UNIQUE(user_id, device_identifier)
	);
	CREATE INDEX IF NOT EXISTS idx_native_devices_user ON native_devices(user_id);

	CREATE TABLE IF NOT EXISTS device_pairing_tokens (
		id TEXT PRIMARY KEY,
		user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
		token_hash TEXT NOT NULL UNIQUE,
		pin_hash TEXT NOT NULL,
		expires_at DATETIME NOT NULL,
		used_at DATETIME,
		created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
	);
	CREATE INDEX IF NOT EXISTS idx_device_pairing_tokens_hash ON device_pairing_tokens(token_hash);

	CREATE TABLE IF NOT EXISTS mfa_methods (
		id TEXT PRIMARY KEY,
		user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
		method_type TEXT NOT NULL CHECK (method_type IN ('totp', 'push')),
		encrypted_secret TEXT,
		is_primary BOOLEAN NOT NULL DEFAULT 0,
		-- The highest TOTP time step accepted so far, so a code cannot be replayed inside
		-- its validity window.
		last_totp_counter INTEGER NOT NULL DEFAULT 0,
		created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		UNIQUE(user_id, method_type)
	);

	CREATE TABLE IF NOT EXISTS mfa_challenges (
		id TEXT PRIMARY KEY,
		user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
		method_type TEXT NOT NULL,
		match_digits TEXT NOT NULL,
		decoy_digits_json TEXT NOT NULL,
		status TEXT NOT NULL CHECK (status IN ('pending', 'approved', 'denied', 'expired')),
		expires_at DATETIME NOT NULL,
		created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
	);
	CREATE INDEX IF NOT EXISTS idx_mfa_challenges_user ON mfa_challenges(user_id);

	CREATE TABLE IF NOT EXISTS mfa_tokens (
		id TEXT PRIMARY KEY,
		user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
		token_hash TEXT NOT NULL UNIQUE,
		challenge_id TEXT,
		attempts INTEGER NOT NULL DEFAULT 0,
		expires_at DATETIME NOT NULL,
		used_at DATETIME,
		created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
	);
	CREATE INDEX IF NOT EXISTS idx_mfa_tokens_hash ON mfa_tokens(token_hash);

	CREATE TABLE IF NOT EXISTS recovery_codes (
		id TEXT PRIMARY KEY,
		user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
		code_hash TEXT NOT NULL,
		used_at DATETIME,
		created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
	);
	CREATE INDEX IF NOT EXISTS idx_recovery_codes_user ON recovery_codes(user_id);

	CREATE TABLE IF NOT EXISTS oauth_clients (
		id TEXT PRIMARY KEY,
		client_name TEXT NOT NULL,
		client_type TEXT NOT NULL CHECK (client_type IN ('public', 'confidential')),
		client_secret_hash TEXT,
		redirect_uris_json TEXT NOT NULL,
		allowed_scopes_json TEXT NOT NULL,
		launch_url TEXT,
		enabled BOOLEAN NOT NULL DEFAULT 1,
		created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS authorization_codes (
		id TEXT PRIMARY KEY,
		code_hash TEXT NOT NULL UNIQUE,
		client_id TEXT NOT NULL REFERENCES oauth_clients(id) ON DELETE CASCADE,
		user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
		redirect_uri TEXT NOT NULL,
		scope TEXT NOT NULL,
		code_challenge TEXT NOT NULL,
		code_challenge_method TEXT NOT NULL,
		nonce TEXT NOT NULL DEFAULT '',
		expires_at DATETIME NOT NULL,
		used_at DATETIME,
		created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
	);
	CREATE INDEX IF NOT EXISTS idx_auth_codes_hash ON authorization_codes(code_hash);

	CREATE TABLE IF NOT EXISTS applications (
		id TEXT PRIMARY KEY,
		name TEXT NOT NULL,
		url TEXT NOT NULL,
		icon_name TEXT NOT NULL,
		description TEXT,
		sort_order INTEGER NOT NULL DEFAULT 0,
		enabled BOOLEAN NOT NULL DEFAULT 1,
		created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
	);

	-- Every access token this server mints is registered here so it can be revoked before
	-- it expires. Services that validate tokens offline against JWKS will not observe a
	-- revocation until expiry; those needing immediate effect must call /oauth/userinfo.
	CREATE TABLE IF NOT EXISTS issued_tokens (
		jti TEXT PRIMARY KEY,
		user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
		client_id TEXT NOT NULL,
		expires_at DATETIME NOT NULL,
		revoked_at DATETIME,
		created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
	);
	CREATE INDEX IF NOT EXISTS idx_issued_tokens_user ON issued_tokens(user_id);
	CREATE INDEX IF NOT EXISTS idx_issued_tokens_expiry ON issued_tokens(expires_at);

	CREATE TABLE IF NOT EXISTS audit_events (
		id TEXT PRIMARY KEY,
		actor_id TEXT,
		actor_username TEXT,
		action TEXT NOT NULL,
		target_id TEXT,
		target_type TEXT,
		ip_address TEXT NOT NULL,
		user_agent TEXT NOT NULL,
		outcome TEXT NOT NULL CHECK (outcome IN ('success', 'failure', 'denied')),
		details_json TEXT,
		created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
	);
	CREATE INDEX IF NOT EXISTS idx_audit_events_created ON audit_events(created_at DESC);
	`
	if _, err := s.db.Exec(schema); err != nil {
		return err
	}
	if err := s.migrateSyncEventsUserReference(); err != nil {
		return err
	}
	if err := s.migrateNativeDevicePlatform(); err != nil {
		return err
	}
	return s.migrateLegacyDevicePairingTokens()
}

func (s *Store) migrateNativeDevicePlatform() error {
	rows, err := s.db.Query(`PRAGMA table_info(native_devices)`)
	if err != nil {
		return err
	}
	defer rows.Close()

	for rows.Next() {
		var cid int
		var name, typ string
		var notNull int
		var defaultValue any
		var pk int
		if err := rows.Scan(&cid, &name, &typ, &notNull, &defaultValue, &pk); err != nil {
			return err
		}
		if name == "platform" {
			return nil
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	_, err = s.db.Exec(`ALTER TABLE native_devices ADD COLUMN platform TEXT NOT NULL DEFAULT 'android' CHECK (platform IN ('android', 'ios', 'macos'))`)
	return err
}

// migrateLegacyDevicePairingTokens removes the pre-hash pin_code column. Pairing tokens
// expire in 90 seconds, so preserving plaintext credentials during a schema migration is
// strictly worse than forcing a fresh pairing attempt.
func (s *Store) migrateLegacyDevicePairingTokens() error {
	var definition string
	if err := s.db.QueryRow(`SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'device_pairing_tokens'`).Scan(&definition); err != nil {
		return err
	}
	if !strings.Contains(strings.ToUpper(definition), "PIN_CODE") {
		return nil
	}
	_, err := s.db.Exec(`
		DROP TABLE device_pairing_tokens;
		CREATE TABLE device_pairing_tokens (
			id TEXT PRIMARY KEY,
			user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
			token_hash TEXT NOT NULL UNIQUE,
			pin_hash TEXT NOT NULL,
			expires_at DATETIME NOT NULL,
			used_at DATETIME,
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
		);
		CREATE INDEX idx_device_pairing_tokens_hash ON device_pairing_tokens(token_hash);`)
	return err
}

// migrateSyncEventsUserReference removes the legacy foreign key that deleted a user's
// queued deletion event with the user record. SQLite requires rebuilding a table to
// change a foreign key definition.
func (s *Store) migrateSyncEventsUserReference() error {
	var definition string
	if err := s.db.QueryRow(`SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'account_sync_events'`).Scan(&definition); err != nil {
		return err
	}
	if !strings.Contains(strings.ToUpper(definition), "REFERENCES USERS") {
		return nil
	}

	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if _, err := tx.Exec(`
		CREATE TABLE account_sync_events_new (
			id TEXT PRIMARY KEY,
			user_id TEXT NOT NULL,
			system_id TEXT NOT NULL,
			event_type TEXT NOT NULL,
			payload_json TEXT NOT NULL,
			attempts INTEGER NOT NULL DEFAULT 0,
			status TEXT NOT NULL CHECK (status IN ('pending', 'delivered', 'failed')),
			last_error TEXT,
			next_attempt_at DATETIME,
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
		);
		INSERT INTO account_sync_events_new
			(id, user_id, system_id, event_type, payload_json, attempts, status, last_error, next_attempt_at, created_at, updated_at)
			SELECT id, user_id, system_id, event_type, payload_json, attempts, status, last_error, next_attempt_at, created_at, updated_at
			FROM account_sync_events;
		DROP TABLE account_sync_events;
		ALTER TABLE account_sync_events_new RENAME TO account_sync_events;
		CREATE INDEX idx_sync_events_status ON account_sync_events(status);`); err != nil {
		return err
	}
	return tx.Commit()
}

// User CRUD
func (s *Store) CreateUser(u *User) error {
	query := `
	INSERT INTO users (id, username, display_name, email, password_hash, role, status, created_at, updated_at)
	VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
	now := time.Now().UTC()
	u.CreatedAt = now
	u.UpdatedAt = now
	_, err := s.db.Exec(query, u.ID, u.Username, u.DisplayName, u.Email, u.PasswordHash, u.Role, u.Status, u.CreatedAt, u.UpdatedAt)
	return err
}

// CreateUserWithSyncEvents is the transactional outbox path for directory creation.
func (s *Store) CreateUserWithSyncEvents(u *User, events []AccountSyncEvent) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	now := time.Now().UTC()
	u.CreatedAt, u.UpdatedAt = now, now
	if _, err := tx.Exec(`INSERT INTO users (id, username, display_name, email, password_hash, role, status, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`, u.ID, u.Username, u.DisplayName, u.Email, u.PasswordHash, u.Role, u.Status, u.CreatedAt, u.UpdatedAt); err != nil {
		return err
	}
	if err := insertSyncEvents(tx, events, now); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) GetUserByID(id string) (*User, error) {
	query := `SELECT id, username, display_name, email, password_hash, role, status, created_at, updated_at FROM users WHERE id = ?`
	u := &User{}
	err := s.db.QueryRow(query, id).Scan(&u.ID, &u.Username, &u.DisplayName, &u.Email, &u.PasswordHash, &u.Role, &u.Status, &u.CreatedAt, &u.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return u, err
}

func (s *Store) GetUserByUsername(username string) (*User, error) {
	query := `SELECT id, username, display_name, email, password_hash, role, status, created_at, updated_at FROM users WHERE username = ? COLLATE NOCASE`
	u := &User{}
	err := s.db.QueryRow(query, username).Scan(&u.ID, &u.Username, &u.DisplayName, &u.Email, &u.PasswordHash, &u.Role, &u.Status, &u.CreatedAt, &u.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return u, err
}

func (s *Store) GetUserByEmail(email string) (*User, error) {
	query := `SELECT id, username, display_name, email, password_hash, role, status, created_at, updated_at FROM users WHERE email = ? COLLATE NOCASE`
	u := &User{}
	err := s.db.QueryRow(query, email).Scan(&u.ID, &u.Username, &u.DisplayName, &u.Email, &u.PasswordHash, &u.Role, &u.Status, &u.CreatedAt, &u.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return u, err
}

func (s *Store) ListUsers() ([]User, error) {
	query := `SELECT id, username, display_name, email, password_hash, role, status, created_at, updated_at FROM users ORDER BY username ASC`
	rows, err := s.db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []User
	for rows.Next() {
		var u User
		if err := rows.Scan(&u.ID, &u.Username, &u.DisplayName, &u.Email, &u.PasswordHash, &u.Role, &u.Status, &u.CreatedAt, &u.UpdatedAt); err != nil {
			return nil, err
		}
		users = append(users, u)
	}
	return users, nil
}

func (s *Store) UpdateUser(u *User) error {
	query := `UPDATE users SET display_name = ?, email = ?, role = ?, status = ?, updated_at = ? WHERE id = ?`
	u.UpdatedAt = time.Now().UTC()
	_, err := s.db.Exec(query, u.DisplayName, u.Email, u.Role, u.Status, u.UpdatedAt, u.ID)
	return err
}

// UpdateUserWithSyncEvents preserves the active-admin invariant and writes its outbox event
// in the same transaction as the account change.
func (s *Store) UpdateUserWithSyncEvents(u *User, revokeAccess bool, events []AccountSyncEvent) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var oldRole, oldStatus string
	if err := tx.QueryRow(`SELECT role, status FROM users WHERE id = ?`, u.ID).Scan(&oldRole, &oldStatus); err != nil {
		return err
	}
	if oldRole == "admin" && oldStatus == "active" && (u.Role != "admin" || u.Status != "active") {
		var admins int
		if err := tx.QueryRow(`SELECT COUNT(*) FROM users WHERE role = 'admin' AND status = 'active'`).Scan(&admins); err != nil {
			return err
		}
		if admins <= 1 {
			return ErrLastActiveAdmin
		}
	}
	now := time.Now().UTC()
	u.UpdatedAt = now
	if _, err := tx.Exec(`UPDATE users SET display_name = ?, email = ?, password_hash = ?, role = ?, status = ?, updated_at = ? WHERE id = ?`, u.DisplayName, u.Email, u.PasswordHash, u.Role, u.Status, now, u.ID); err != nil {
		return err
	}
	if revokeAccess {
		if _, err := tx.Exec(`DELETE FROM sessions WHERE user_id = ?`, u.ID); err != nil {
			return err
		}
		if _, err := tx.Exec(`UPDATE issued_tokens SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL`, now, u.ID); err != nil {
			return err
		}
	}
	if err := insertSyncEvents(tx, events, now); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) UpdateUserPassword(userID, passwordHash string) error {
	query := `UPDATE users SET password_hash = ?, updated_at = ? WHERE id = ?`
	_, err := s.db.Exec(query, passwordHash, time.Now().UTC(), userID)
	return err
}

func (s *Store) UpdateUserStatus(userID, status string) error {
	query := `UPDATE users SET status = ?, updated_at = ? WHERE id = ?`
	_, err := s.db.Exec(query, status, time.Now().UTC(), userID)
	return err
}

func (s *Store) CountAdmins() (int, error) {
	var count int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM users WHERE role = 'admin' AND status = 'active'`).Scan(&count)
	return count, err
}

func (s *Store) DeleteUser(userID string) error {
	_, err := s.db.Exec(`DELETE FROM users WHERE id = ?`, userID)
	return err
}

// DeleteUserWithSyncEvents atomically removes a user and queues its deletion for every
// active paired system. Older queued user events are discarded so a downstream system
// cannot receive stale updates after the deletion.
func (s *Store) DeleteUserWithSyncEvents(userID string, events []AccountSyncEvent) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var role, status string
	if err := tx.QueryRow(`SELECT role, status FROM users WHERE id = ?`, userID).Scan(&role, &status); err != nil {
		return err
	}
	if role == "admin" && status == "active" {
		var admins int
		if err := tx.QueryRow(`SELECT COUNT(*) FROM users WHERE role = 'admin' AND status = 'active'`).Scan(&admins); err != nil {
			return err
		}
		if admins <= 1 {
			return ErrLastActiveAdmin
		}
	}

	if _, err := tx.Exec(`DELETE FROM account_sync_events WHERE user_id = ?`, userID); err != nil {
		return err
	}
	result, err := tx.Exec(`DELETE FROM users WHERE id = ?`, userID)
	if err != nil {
		return err
	}
	if deleted, err := result.RowsAffected(); err != nil {
		return err
	} else if deleted != 1 {
		return sql.ErrNoRows
	}

	if err := insertSyncEvents(tx, events, time.Now().UTC()); err != nil {
		return err
	}
	return tx.Commit()
}

func insertSyncEvents(tx *sql.Tx, events []AccountSyncEvent, now time.Time) error {
	stmt, err := tx.Prepare(`INSERT INTO account_sync_events (id, user_id, system_id, event_type, payload_json, attempts, status, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return err
	}
	defer stmt.Close()
	for _, event := range events {
		if _, err := stmt.Exec(event.ID, event.UserID, event.SystemID, event.EventType, event.PayloadJSON, event.Attempts, event.Status, now, now); err != nil {
			return err
		}
	}
	return nil
}

// Session Management
func (s *Store) CreateSession(sess *Session) error {
	query := `INSERT INTO sessions (id, user_id, session_token_hash, ip_address, user_agent, expires_at, created_at, last_active_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
	now := time.Now().UTC()
	sess.CreatedAt = now
	sess.LastActiveAt = now
	_, err := s.db.Exec(query, sess.ID, sess.UserID, sess.SessionTokenHash, sess.IPAddress, sess.UserAgent, sess.ExpiresAt, sess.CreatedAt, sess.LastActiveAt)
	return err
}

// GetSessionByTokenHash returns a session within both its absolute and idle lifetime, or
// nil. Both limits live in the query so callers cannot accidentally authenticate a stale
// session by forgetting either check.
func (s *Store) GetSessionByTokenHash(tokenHash string, idleTTL time.Duration) (*Session, error) {
	now := time.Now().UTC()
	query := `SELECT id, user_id, session_token_hash, ip_address, user_agent, expires_at, created_at, last_active_at FROM sessions WHERE session_token_hash = ? AND expires_at > ? AND last_active_at > ?`
	sess := &Session{}
	err := s.db.QueryRow(query, tokenHash, now, now.Add(-idleTTL)).Scan(&sess.ID, &sess.UserID, &sess.SessionTokenHash, &sess.IPAddress, &sess.UserAgent, &sess.ExpiresAt, &sess.CreatedAt, &sess.LastActiveAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return sess, err
}

func (s *Store) TouchSession(sessionID string) error {
	query := `UPDATE sessions SET last_active_at = ? WHERE id = ?`
	_, err := s.db.Exec(query, time.Now().UTC(), sessionID)
	return err
}

func (s *Store) DeleteSession(sessionID string) error {
	_, err := s.db.Exec(`DELETE FROM sessions WHERE id = ?`, sessionID)
	return err
}

func (s *Store) DeleteUserSessions(userID string) error {
	_, err := s.db.Exec(`DELETE FROM sessions WHERE user_id = ?`, userID)
	return err
}

// HasAnySession reports whether anyone has ever established a session, used to decide when
// the first-run credentials file has served its purpose.
func (s *Store) HasAnySession() (bool, error) {
	var count int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM sessions`).Scan(&count); err != nil {
		return false, err
	}
	return count > 0, nil
}

func (s *Store) CleanupExpiredSessions() error {
	_, err := s.db.Exec(`DELETE FROM sessions WHERE expires_at < ?`, time.Now().UTC())
	return err
}

// Account lockout
//
// MaxFailedLogins consecutive wrong passwords lock an account for LockoutDuration. This is
// keyed on the account, not the source address, because a password spray distributed
// across hosts never trips a per-IP limiter.
const (
	MaxFailedLogins = 10
	LockoutDuration = 15 * time.Minute
)

// RecordFailedLogin increments the failure counter and returns the new count.
func (s *Store) RecordFailedLogin(userID string) (int, error) {
	now := time.Now().UTC()
	if _, err := s.db.Exec(`
		INSERT INTO login_failures (user_id, failures, last_failure_at)
		VALUES (?, 1, ?)
		ON CONFLICT(user_id) DO UPDATE SET
			failures = login_failures.failures + 1,
			last_failure_at = excluded.last_failure_at`, userID, now); err != nil {
		return 0, err
	}
	var failures int
	err := s.db.QueryRow(`SELECT failures FROM login_failures WHERE user_id = ?`, userID).Scan(&failures)
	if err == sql.ErrNoRows {
		return 0, nil
	}
	return failures, err
}

// IsAccountLocked reports whether the account is inside its lockout window.
func (s *Store) IsAccountLocked(userID string) (bool, error) {
	var failures int
	var last time.Time
	err := s.db.QueryRow(
		`SELECT failures, last_failure_at FROM login_failures WHERE user_id = ?`, userID).
		Scan(&failures, &last)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if failures < MaxFailedLogins {
		return false, nil
	}
	return time.Since(last.UTC()) < LockoutDuration, nil
}

func (s *Store) ClearFailedLogins(userID string) error {
	_, err := s.db.Exec(`DELETE FROM login_failures WHERE user_id = ?`, userID)
	return err
}

// System Pairing & Sync Management
func (s *Store) CreateSystemPairingToken(token *SystemPairingToken) error {
	query := `INSERT INTO system_pairing_tokens (id, token_hash, pin_hash, system_type, created_by_user_id, expires_at, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)`
	token.CreatedAt = time.Now().UTC()
	_, err := s.db.Exec(query, token.ID, token.TokenHash, token.PINHash, token.SystemType, token.CreatedByUserID, token.ExpiresAt, token.CreatedAt)
	return err
}

// GetValidSystemPairingToken returns an unspent, unexpired token that still has PIN
// attempts left.
func (s *Store) GetValidSystemPairingToken(tokenHash string, maxPINAttempts int) (*SystemPairingToken, error) {
	query := `SELECT id, token_hash, pin_hash, pin_attempts, system_type, created_by_user_id, expires_at, used_at, created_at
	          FROM system_pairing_tokens WHERE token_hash = ? AND used_at IS NULL AND expires_at > ? AND pin_attempts < ?`
	t := &SystemPairingToken{}
	err := s.db.QueryRow(query, tokenHash, time.Now().UTC(), maxPINAttempts).
		Scan(&t.ID, &t.TokenHash, &t.PINHash, &t.PINAttempts, &t.SystemType, &t.CreatedByUserID, &t.ExpiresAt, &t.UsedAt, &t.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return t, err
}

// RecordSystemPairingPINFailure counts a wrong PIN against the token.
func (s *Store) RecordSystemPairingPINFailure(tokenID string) (int, error) {
	if _, err := s.db.Exec(`UPDATE system_pairing_tokens SET pin_attempts = pin_attempts + 1 WHERE id = ?`, tokenID); err != nil {
		return 0, err
	}
	var attempts int
	err := s.db.QueryRow(`SELECT pin_attempts FROM system_pairing_tokens WHERE id = ?`, tokenID).Scan(&attempts)
	if err == sql.ErrNoRows {
		return 0, nil
	}
	return attempts, err
}

// ConsumeSystemPairingToken atomically spends a pairing token.
func (s *Store) ConsumeSystemPairingToken(tokenID string) (bool, error) {
	res, err := s.db.Exec(
		`UPDATE system_pairing_tokens SET used_at = ? WHERE id = ? AND used_at IS NULL`,
		time.Now().UTC(), tokenID)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	return n == 1, nil
}

// ExpireSystemPairingTokens forces outstanding pairing tokens to expire.
func (s *Store) ExpireSystemPairingTokens(at time.Time) error {
	_, err := s.db.Exec(`UPDATE system_pairing_tokens SET expires_at = ?`, at)
	return err
}

func (s *Store) DeleteExpiredSystemPairingTokens() error {
	_, err := s.db.Exec(`DELETE FROM system_pairing_tokens WHERE expires_at < ?`, time.Now().UTC())
	return err
}

func (s *Store) CreatePairedSystem(ps *PairedSystem) error {
	query := `INSERT INTO paired_systems (id, name, system_type, callback_url, hmac_secret_encrypted, status, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)`
	ps.CreatedAt = time.Now().UTC()
	_, err := s.db.Exec(query, ps.ID, ps.Name, ps.SystemType, ps.CallbackURL, ps.HMACSecretEncrypted, ps.Status, ps.CreatedAt)
	return err
}

func (s *Store) GetPairedSystemByID(id string) (*PairedSystem, error) {
	query := `SELECT id, name, system_type, callback_url, hmac_secret_encrypted, status, last_synced_at, created_at FROM paired_systems WHERE id = ?`
	ps := &PairedSystem{}
	err := s.db.QueryRow(query, id).Scan(&ps.ID, &ps.Name, &ps.SystemType, &ps.CallbackURL, &ps.HMACSecretEncrypted, &ps.Status, &ps.LastSyncedAt, &ps.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return ps, err
}

func (s *Store) ListAllPairedSystems() ([]PairedSystem, error) {
	query := `SELECT id, name, system_type, callback_url, hmac_secret_encrypted, status, last_synced_at, created_at FROM paired_systems ORDER BY created_at ASC`
	rows, err := s.db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var systems []PairedSystem
	for rows.Next() {
		var ps PairedSystem
		if err := rows.Scan(&ps.ID, &ps.Name, &ps.SystemType, &ps.CallbackURL, &ps.HMACSecretEncrypted, &ps.Status, &ps.LastSyncedAt, &ps.CreatedAt); err != nil {
			return nil, err
		}
		systems = append(systems, ps)
	}
	return systems, nil
}

func (s *Store) ListActivePairedSystems() ([]PairedSystem, error) {
	query := `SELECT id, name, system_type, callback_url, hmac_secret_encrypted, status, last_synced_at, created_at FROM paired_systems WHERE status != 'disabled' ORDER BY created_at ASC`
	rows, err := s.db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var systems []PairedSystem
	for rows.Next() {
		var ps PairedSystem
		if err := rows.Scan(&ps.ID, &ps.Name, &ps.SystemType, &ps.CallbackURL, &ps.HMACSecretEncrypted, &ps.Status, &ps.LastSyncedAt, &ps.CreatedAt); err != nil {
			return nil, err
		}
		systems = append(systems, ps)
	}
	return systems, nil
}

func (s *Store) UpdatePairedSystemStatus(systemID, status string) error {
	now := time.Now().UTC()
	_, err := s.db.Exec(`UPDATE paired_systems SET status = ?, last_synced_at = ? WHERE id = ?`, status, now, systemID)
	return err
}

func (s *Store) DeletePairedSystem(systemID string) error {
	_, err := s.db.Exec(`DELETE FROM paired_systems WHERE id = ?`, systemID)
	return err
}

// Account Sync Events
func (s *Store) CreateAccountSyncEvent(event *AccountSyncEvent) error {
	query := `INSERT INTO account_sync_events (id, user_id, system_id, event_type, payload_json, attempts, status, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
	now := time.Now().UTC()
	event.CreatedAt = now
	event.UpdatedAt = now
	_, err := s.db.Exec(query, event.ID, event.UserID, event.SystemID, event.EventType, event.PayloadJSON, event.Attempts, event.Status, event.CreatedAt, event.UpdatedAt)
	return err
}

const syncEventColumns = `id, user_id, system_id, event_type, payload_json, attempts, status, last_error, next_attempt_at, created_at, updated_at`

func scanSyncEvents(rows *sql.Rows) ([]AccountSyncEvent, error) {
	defer rows.Close()
	var events []AccountSyncEvent
	for rows.Next() {
		var ev AccountSyncEvent
		var lastErr sql.NullString
		var next sql.NullTime
		if err := rows.Scan(&ev.ID, &ev.UserID, &ev.SystemID, &ev.EventType, &ev.PayloadJSON,
			&ev.Attempts, &ev.Status, &lastErr, &next, &ev.CreatedAt, &ev.UpdatedAt); err != nil {
			return nil, err
		}
		if lastErr.Valid {
			ev.LastError = lastErr.String
		}
		if next.Valid {
			t := next.Time
			ev.NextAttempt = &t
		}
		events = append(events, ev)
	}
	return events, rows.Err()
}

// GetPendingSyncEvents returns undelivered events regardless of when they are next due.
func (s *Store) GetPendingSyncEvents(limit int) ([]AccountSyncEvent, error) {
	rows, err := s.db.Query(`SELECT `+syncEventColumns+` FROM account_sync_events
		WHERE status IN ('pending', 'failed') AND attempts < 5 ORDER BY created_at ASC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	return scanSyncEvents(rows)
}

// GetDueSyncEvents returns pending events whose backoff has elapsed.
func (s *Store) GetDueSyncEvents(limit int) ([]AccountSyncEvent, error) {
	rows, err := s.db.Query(`SELECT `+syncEventColumns+` FROM account_sync_events
		WHERE status = 'pending' AND attempts < 5
		  AND (next_attempt_at IS NULL OR next_attempt_at <= ?)
		ORDER BY created_at ASC LIMIT ?`, time.Now().UTC(), limit)
	if err != nil {
		return nil, err
	}
	return scanSyncEvents(rows)
}

func (s *Store) UpdateSyncEventStatus(eventID, status, lastError string, attempts int, nextAttempt *time.Time) error {
	query := `UPDATE account_sync_events SET status = ?, last_error = ?, attempts = ?, next_attempt_at = ?, updated_at = ? WHERE id = ?`
	var next any
	if nextAttempt != nil {
		next = *nextAttempt
	}
	_, err := s.db.Exec(query, status, lastError, attempts, next, time.Now().UTC(), eventID)
	return err
}

func (s *Store) DeleteDeliveredSyncEvents(olderThan time.Time) error {
	_, err := s.db.Exec(`DELETE FROM account_sync_events WHERE status = 'delivered' AND updated_at < ?`, olderThan)
	return err
}

// Native Device & MFA Methods
func (s *Store) CreateDevicePairingToken(token *DevicePairingToken) error {
	query := `INSERT INTO device_pairing_tokens (id, user_id, token_hash, pin_hash, expires_at, created_at) VALUES (?, ?, ?, ?, ?, ?)`
	token.CreatedAt = time.Now().UTC()
	_, err := s.db.Exec(query, token.ID, token.UserID, token.TokenHash, token.PINHash, token.ExpiresAt, token.CreatedAt)
	return err
}

const devicePairingTokenColumns = `id, user_id, token_hash, pin_hash, expires_at, used_at, created_at`

func scanDevicePairingToken(row *sql.Row) (*DevicePairingToken, error) {
	t := &DevicePairingToken{}
	err := row.Scan(&t.ID, &t.UserID, &t.TokenHash, &t.PINHash, &t.ExpiresAt, &t.UsedAt, &t.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return t, err
}

func (s *Store) GetValidDevicePairingToken(tokenHash string) (*DevicePairingToken, error) {
	return scanDevicePairingToken(s.db.QueryRow(
		`SELECT `+devicePairingTokenColumns+` FROM device_pairing_tokens
		 WHERE token_hash = ? AND used_at IS NULL AND expires_at > ?`,
		tokenHash, time.Now().UTC()))
}

// GetDevicePairingTokenByUserPIN resolves a PIN within a single user's pairing tokens.
// A global PIN lookup would let any live 6-digit PIN in the deployment match, which turns
// one user's pairing window into everyone's.
func (s *Store) GetDevicePairingTokenByUserPIN(userID, pinHash string) (*DevicePairingToken, error) {
	return scanDevicePairingToken(s.db.QueryRow(
		`SELECT `+devicePairingTokenColumns+` FROM device_pairing_tokens
		 WHERE user_id = ? AND pin_hash = ? AND pin_hash != '' AND used_at IS NULL AND expires_at > ?`,
		userID, pinHash, time.Now().UTC()))
}

// ExpireDevicePairingTokens forces a user's outstanding pairing tokens to expire.
func (s *Store) ExpireDevicePairingTokens(userID string, at time.Time) error {
	_, err := s.db.Exec(`UPDATE device_pairing_tokens SET expires_at = ? WHERE user_id = ?`, at, userID)
	return err
}

func (s *Store) DeleteExpiredDevicePairingTokens() error {
	_, err := s.db.Exec(`DELETE FROM device_pairing_tokens WHERE expires_at < ?`, time.Now().UTC())
	return err
}

// ConsumeDevicePairingToken atomically spends a pairing token, reporting false if another
// registration spent it first.
func (s *Store) ConsumeDevicePairingToken(tokenID string) (bool, error) {
	now := time.Now().UTC()
	res, err := s.db.Exec(
		`UPDATE device_pairing_tokens SET used_at = ? WHERE id = ? AND used_at IS NULL AND expires_at > ?`,
		now, tokenID, now)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	return n == 1, nil
}

// RegisterNativeDeviceWithPairingToken atomically spends a live pairing token and
// enrols the device as a push MFA approver.
func (s *Store) RegisterNativeDeviceWithPairingToken(tokenID string, dev *NativeDevice, method *MFAMethod) (bool, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return false, err
	}
	defer tx.Rollback()

	now := time.Now().UTC()
	res, err := tx.Exec(
		`UPDATE device_pairing_tokens SET used_at = ? WHERE id = ? AND used_at IS NULL AND expires_at > ?`,
		now, tokenID, now)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	if n != 1 {
		return false, nil
	}

	dev.CreatedAt = now
	dev.LastSeenAt = &now
	if dev.Platform == "" {
		dev.Platform = "android"
	}
	if _, err := tx.Exec(`
		INSERT INTO native_devices (id, user_id, device_name, device_identifier, platform, public_key, push_token, is_mfa_approver, last_seen_at, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(user_id, device_identifier) DO UPDATE SET
			device_name = excluded.device_name,
			platform = excluded.platform,
			public_key = excluded.public_key,
			push_token = excluded.push_token,
			is_mfa_approver = excluded.is_mfa_approver,
			last_seen_at = excluded.last_seen_at
	`, dev.ID, dev.UserID, dev.DeviceName, dev.DeviceIdentifier, dev.Platform, dev.PublicKey, dev.PushToken, dev.IsMFAApprover, dev.LastSeenAt, dev.CreatedAt); err != nil {
		return false, err
	}

	method.CreatedAt = now
	if _, err := tx.Exec(`
		INSERT INTO mfa_methods (id, user_id, method_type, encrypted_secret, is_primary, created_at)
		VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT(user_id, method_type) DO UPDATE SET
			encrypted_secret = excluded.encrypted_secret,
			is_primary = excluded.is_primary
	`, method.ID, method.UserID, method.MethodType, method.EncryptedSecret, method.IsPrimary, method.CreatedAt); err != nil {
		return false, err
	}

	return true, tx.Commit()
}

func (s *Store) UpsertNativeDevice(dev *NativeDevice) error {
	query := `
	INSERT INTO native_devices (id, user_id, device_name, device_identifier, platform, public_key, push_token, is_mfa_approver, last_seen_at, created_at)
	VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	ON CONFLICT(user_id, device_identifier) DO UPDATE SET
		device_name = excluded.device_name,
		platform = excluded.platform,
		public_key = excluded.public_key,
		push_token = excluded.push_token,
		is_mfa_approver = excluded.is_mfa_approver,
		last_seen_at = excluded.last_seen_at
	`
	now := time.Now().UTC()
	dev.CreatedAt = now
	dev.LastSeenAt = &now
	if dev.Platform == "" {
		dev.Platform = "android"
	}
	_, err := s.db.Exec(query, dev.ID, dev.UserID, dev.DeviceName, dev.DeviceIdentifier, dev.Platform, dev.PublicKey, dev.PushToken, dev.IsMFAApprover, dev.LastSeenAt, dev.CreatedAt)
	return err
}

func (s *Store) ListUserNativeDevices(userID string) ([]NativeDevice, error) {
	query := `SELECT id, user_id, device_name, device_identifier, platform, public_key, push_token, is_mfa_approver, last_seen_at, created_at FROM native_devices WHERE user_id = ? ORDER BY created_at DESC`
	rows, err := s.db.Query(query, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var devices []NativeDevice
	for rows.Next() {
		var dev NativeDevice
		var pubKey, pushTok sql.NullString
		if err := rows.Scan(&dev.ID, &dev.UserID, &dev.DeviceName, &dev.DeviceIdentifier, &dev.Platform, &pubKey, &pushTok, &dev.IsMFAApprover, &dev.LastSeenAt, &dev.CreatedAt); err != nil {
			return nil, err
		}
		if pubKey.Valid {
			dev.PublicKey = pubKey.String
		}
		if pushTok.Valid {
			dev.PushToken = pushTok.String
		}
		devices = append(devices, dev)
	}
	return devices, nil
}

func (s *Store) SetNativeDeviceMFAApprover(deviceID, userID string, isApprover bool) error {
	_, err := s.db.Exec(`UPDATE native_devices SET is_mfa_approver = ? WHERE id = ? AND user_id = ?`, isApprover, deviceID, userID)
	return err
}

func (s *Store) DeleteNativeDevice(deviceID, userID string) error {
	_, err := s.db.Exec(`DELETE FROM native_devices WHERE id = ? AND user_id = ?`, deviceID, userID)
	return err
}

func (s *Store) ClearNativeDevicePushToken(deviceID, userID string) error {
	_, err := s.db.Exec(`UPDATE native_devices SET push_token = '' WHERE id = ? AND user_id = ?`, deviceID, userID)
	return err
}

func (s *Store) SetMFAMethod(m *MFAMethod) error {
	query := `
	INSERT INTO mfa_methods (id, user_id, method_type, encrypted_secret, is_primary, created_at)
	VALUES (?, ?, ?, ?, ?, ?)
	ON CONFLICT(user_id, method_type) DO UPDATE SET
		encrypted_secret = excluded.encrypted_secret,
		is_primary = excluded.is_primary
	`
	m.CreatedAt = time.Now().UTC()
	_, err := s.db.Exec(query, m.ID, m.UserID, m.MethodType, m.EncryptedSecret, m.IsPrimary, m.CreatedAt)
	return err
}

// ConsumeTOTPCounter records that a TOTP time-step has been used. It reports false if the
// step was already spent, which is what stops a sniffed code being replayed inside its
// validity window (RFC 6238 section 5.2).
func (s *Store) ConsumeTOTPCounter(userID string, counter int64) (bool, error) {
	res, err := s.db.Exec(
		`UPDATE mfa_methods SET last_totp_counter = ?
		 WHERE user_id = ? AND method_type = 'totp' AND last_totp_counter < ?`,
		counter, userID, counter)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	return n == 1, nil
}

func (s *Store) GetMFAMethod(userID, methodType string) (*MFAMethod, error) {
	query := `SELECT id, user_id, method_type, encrypted_secret, is_primary, created_at FROM mfa_methods WHERE user_id = ? AND method_type = ?`
	m := &MFAMethod{}
	var encSecret sql.NullString
	err := s.db.QueryRow(query, userID, methodType).Scan(&m.ID, &m.UserID, &m.MethodType, &encSecret, &m.IsPrimary, &m.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if encSecret.Valid {
		m.EncryptedSecret = encSecret.String
	}
	return m, err
}

func (s *Store) ListUserMFAMethods(userID string) ([]MFAMethod, error) {
	query := `SELECT id, user_id, method_type, encrypted_secret, is_primary, created_at FROM mfa_methods WHERE user_id = ?`
	rows, err := s.db.Query(query, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var methods []MFAMethod
	for rows.Next() {
		var m MFAMethod
		var encSecret sql.NullString
		if err := rows.Scan(&m.ID, &m.UserID, &m.MethodType, &encSecret, &m.IsPrimary, &m.CreatedAt); err != nil {
			return nil, err
		}
		if encSecret.Valid {
			m.EncryptedSecret = encSecret.String
		}
		methods = append(methods, m)
	}
	return methods, nil
}

func (s *Store) DeleteUserMFAMethods(userID string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if _, err := tx.Exec(`DELETE FROM mfa_methods WHERE user_id = ?`, userID); err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM recovery_codes WHERE user_id = ?`, userID); err != nil {
		return err
	}
	if _, err := tx.Exec(`UPDATE native_devices SET is_mfa_approver = 0 WHERE user_id = ?`, userID); err != nil {
		return err
	}
	if _, err := tx.Exec(`UPDATE device_pairing_tokens SET expires_at = ? WHERE user_id = ? AND used_at IS NULL`, time.Now().UTC(), userID); err != nil {
		return err
	}
	return tx.Commit()
}

// MFA Challenges
func (s *Store) CreateMFAChallenge(ch *MFAChallenge) error {
	query := `INSERT INTO mfa_challenges (id, user_id, method_type, match_digits, decoy_digits_json, status, expires_at, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
	ch.CreatedAt = time.Now().UTC()
	_, err := s.db.Exec(query, ch.ID, ch.UserID, ch.MethodType, ch.MatchDigits, ch.DecoyDigitsJSON, ch.Status, ch.ExpiresAt, ch.CreatedAt)
	return err
}

func (s *Store) GetMFAChallenge(challengeID string) (*MFAChallenge, error) {
	query := `SELECT id, user_id, method_type, match_digits, decoy_digits_json, status, expires_at, created_at FROM mfa_challenges WHERE id = ?`
	ch := &MFAChallenge{}
	err := s.db.QueryRow(query, challengeID).Scan(&ch.ID, &ch.UserID, &ch.MethodType, &ch.MatchDigits, &ch.DecoyDigitsJSON, &ch.Status, &ch.ExpiresAt, &ch.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return ch, err
}

// TransitionMFAChallengeStatus atomically moves a challenge from one status to another.
// It reports false when the challenge was not in the expected starting status, so concurrent
// responders cannot both observe a successful transition.
func (s *Store) TransitionMFAChallengeStatus(challengeID, from, to string) (bool, error) {
	res, err := s.db.Exec(`UPDATE mfa_challenges SET status = ? WHERE id = ? AND status = ?`, to, challengeID, from)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	return n == 1, nil
}

func (s *Store) DeleteExpiredMFAChallenges() error {
	_, err := s.db.Exec(`DELETE FROM mfa_challenges WHERE expires_at < ?`, time.Now().UTC())
	return err
}

// MFA Tokens
func (s *Store) CreateMFAToken(t *MFAToken) error {
	query := `INSERT INTO mfa_tokens (id, user_id, token_hash, challenge_id, expires_at, created_at) VALUES (?, ?, ?, ?, ?, ?)`
	t.CreatedAt = time.Now().UTC()
	var challengeID any
	if t.ChallengeID != "" {
		challengeID = t.ChallengeID
	}
	_, err := s.db.Exec(query, t.ID, t.UserID, t.TokenHash, challengeID, t.ExpiresAt, t.CreatedAt)
	return err
}

// GetValidMFAToken returns an unused, unexpired token that still has attempts left.
func (s *Store) GetValidMFAToken(tokenHash string, maxAttempts int) (*MFAToken, error) {
	query := `SELECT id, user_id, token_hash, challenge_id, attempts, expires_at, used_at, created_at
	          FROM mfa_tokens WHERE token_hash = ? AND used_at IS NULL AND expires_at > ? AND attempts < ?`
	t := &MFAToken{}
	var challengeID sql.NullString
	err := s.db.QueryRow(query, tokenHash, time.Now().UTC(), maxAttempts).
		Scan(&t.ID, &t.UserID, &t.TokenHash, &challengeID, &t.Attempts, &t.ExpiresAt, &t.UsedAt, &t.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if challengeID.Valid {
		t.ChallengeID = challengeID.String
	}
	return t, nil
}

// RecordMFAFailure counts a wrong second-factor guess against the token and returns the
// new total. Without this one token funds unlimited guesses for its whole lifetime.
func (s *Store) RecordMFAFailure(tokenID string) (int, error) {
	if _, err := s.db.Exec(`UPDATE mfa_tokens SET attempts = attempts + 1 WHERE id = ?`, tokenID); err != nil {
		return 0, err
	}
	var attempts int
	err := s.db.QueryRow(`SELECT attempts FROM mfa_tokens WHERE id = ?`, tokenID).Scan(&attempts)
	if err == sql.ErrNoRows {
		return 0, nil
	}
	return attempts, err
}

// ConsumeMFAToken atomically marks a token used. It reports false if it was already consumed.
func (s *Store) ConsumeMFAToken(tokenID string) (bool, error) {
	res, err := s.db.Exec(`UPDATE mfa_tokens SET used_at = ? WHERE id = ? AND used_at IS NULL`, time.Now().UTC(), tokenID)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	return n == 1, nil
}

// DeleteExpiredMFATokens removes spent and expired tokens.
func (s *Store) DeleteExpiredMFATokens() error {
	_, err := s.db.Exec(`DELETE FROM mfa_tokens WHERE expires_at < ?`, time.Now().UTC())
	return err
}

// Recovery Codes
// ReplaceRecoveryCodes atomically swaps a user's recovery codes for a new set. Adding to
// the old set instead would leave leaked codes valid forever, which is the opposite of
// what a user pressing "regenerate" is asking for.
func (s *Store) ReplaceRecoveryCodes(userID string, codes []RecoveryCode) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if _, err := tx.Exec(`DELETE FROM recovery_codes WHERE user_id = ?`, userID); err != nil {
		return err
	}

	stmt, err := tx.Prepare(`INSERT INTO recovery_codes (id, user_id, code_hash, created_at) VALUES (?, ?, ?, ?)`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	now := time.Now().UTC()
	for _, code := range codes {
		if _, err := stmt.Exec(code.ID, code.UserID, code.CodeHash, now); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) GetValidRecoveryCodes(userID string) ([]RecoveryCode, error) {
	query := `SELECT id, user_id, code_hash, used_at, created_at FROM recovery_codes WHERE user_id = ? AND used_at IS NULL`
	rows, err := s.db.Query(query, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var codes []RecoveryCode
	for rows.Next() {
		var c RecoveryCode
		if err := rows.Scan(&c.ID, &c.UserID, &c.CodeHash, &c.UsedAt, &c.CreatedAt); err != nil {
			return nil, err
		}
		codes = append(codes, c)
	}
	return codes, nil
}

// ConsumeRecoveryCode atomically spends a recovery code. A separate lookup and update lets
// concurrent logins redeem the same code.
func (s *Store) ConsumeRecoveryCode(userID, codeHash string) (bool, error) {
	now := time.Now().UTC()
	res, err := s.db.Exec(`UPDATE recovery_codes SET used_at = ? WHERE user_id = ? AND code_hash = ? AND used_at IS NULL`, now, userID, codeHash)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n == 1, err
}

// OAuth Clients
func (s *Store) CreateOAuthClient(c *OAuthClient) error {
	query := `INSERT INTO oauth_clients (id, client_name, client_type, client_secret_hash, redirect_uris_json, allowed_scopes_json, launch_url, enabled, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
	c.CreatedAt = time.Now().UTC()
	_, err := s.db.Exec(query, c.ID, c.ClientName, c.ClientType, c.ClientSecretHash, c.RedirectURIsJSON, c.AllowedScopesJSON, c.LaunchURL, c.Enabled, c.CreatedAt)
	return err
}

func (s *Store) GetOAuthClientByID(id string) (*OAuthClient, error) {
	query := `SELECT id, client_name, client_type, client_secret_hash, redirect_uris_json, allowed_scopes_json, launch_url, enabled, created_at FROM oauth_clients WHERE id = ?`
	c := &OAuthClient{}
	var secretHash sql.NullString
	var launchURL sql.NullString
	err := s.db.QueryRow(query, id).Scan(&c.ID, &c.ClientName, &c.ClientType, &secretHash, &c.RedirectURIsJSON, &c.AllowedScopesJSON, &launchURL, &c.Enabled, &c.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if secretHash.Valid {
		c.ClientSecretHash = secretHash.String
	}
	if launchURL.Valid {
		c.LaunchURL = launchURL.String
	}
	return c, err
}

func (s *Store) ListOAuthClients() ([]OAuthClient, error) {
	query := `SELECT id, client_name, client_type, client_secret_hash, redirect_uris_json, allowed_scopes_json, launch_url, enabled, created_at FROM oauth_clients ORDER BY client_name ASC`
	rows, err := s.db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var clients []OAuthClient
	for rows.Next() {
		var c OAuthClient
		var secretHash sql.NullString
		var launchURL sql.NullString
		if err := rows.Scan(&c.ID, &c.ClientName, &c.ClientType, &secretHash, &c.RedirectURIsJSON, &c.AllowedScopesJSON, &launchURL, &c.Enabled, &c.CreatedAt); err != nil {
			return nil, err
		}
		if secretHash.Valid {
			c.ClientSecretHash = secretHash.String
		}
		if launchURL.Valid {
			c.LaunchURL = launchURL.String
		}
		clients = append(clients, c)
	}
	return clients, nil
}

func (s *Store) UpdateOAuthClient(c *OAuthClient) error {
	query := `UPDATE oauth_clients SET client_name = ?, client_type = ?, client_secret_hash = ?, redirect_uris_json = ?, allowed_scopes_json = ?, launch_url = ?, enabled = ? WHERE id = ?`
	_, err := s.db.Exec(query, c.ClientName, c.ClientType, c.ClientSecretHash, c.RedirectURIsJSON, c.AllowedScopesJSON, c.LaunchURL, c.Enabled, c.ID)
	return err
}

func (s *Store) DeleteOAuthClient(id string) error {
	_, err := s.db.Exec(`DELETE FROM oauth_clients WHERE id = ?`, id)
	return err
}

// Authorization Codes
func (s *Store) CreateAuthorizationCode(code *AuthorizationCode) error {
	query := `INSERT INTO authorization_codes (id, code_hash, client_id, user_id, redirect_uri, scope, code_challenge, code_challenge_method, nonce, expires_at, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
	code.CreatedAt = time.Now().UTC()
	_, err := s.db.Exec(query, code.ID, code.CodeHash, code.ClientID, code.UserID, code.RedirectURI, code.Scope, code.CodeChallenge, code.CodeChallengeMethod, code.Nonce, code.ExpiresAt, code.CreatedAt)
	return err
}

func (s *Store) GetValidAuthorizationCode(codeHash string) (*AuthorizationCode, error) {
	query := `SELECT id, code_hash, client_id, user_id, redirect_uri, scope, code_challenge, code_challenge_method, nonce, expires_at, used_at, created_at FROM authorization_codes WHERE code_hash = ? AND used_at IS NULL AND expires_at > ?`
	code := &AuthorizationCode{}
	err := s.db.QueryRow(query, codeHash, time.Now().UTC()).Scan(&code.ID, &code.CodeHash, &code.ClientID, &code.UserID, &code.RedirectURI, &code.Scope, &code.CodeChallenge, &code.CodeChallengeMethod, &code.Nonce, &code.ExpiresAt, &code.UsedAt, &code.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return code, err
}

// ConsumeAuthorizationCode atomically spends a code. It reports false if another request
// spent it first, which is what makes the code single-use under concurrency.
func (s *Store) ConsumeAuthorizationCode(codeID string) (bool, error) {
	res, err := s.db.Exec(
		`UPDATE authorization_codes SET used_at = ? WHERE id = ? AND used_at IS NULL`,
		time.Now().UTC(), codeID)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	return n == 1, nil
}

func (s *Store) DeleteExpiredAuthorizationCodes() error {
	_, err := s.db.Exec(`DELETE FROM authorization_codes WHERE expires_at < ?`, time.Now().UTC())
	return err
}

// Issued Tokens (revocation registry)
func (s *Store) RecordIssuedToken(t *IssuedToken) error {
	query := `INSERT INTO issued_tokens (jti, user_id, client_id, expires_at, created_at) VALUES (?, ?, ?, ?, ?)`
	t.CreatedAt = time.Now().UTC()
	_, err := s.db.Exec(query, t.JTI, t.UserID, t.ClientID, t.ExpiresAt, t.CreatedAt)
	return err
}

// IsTokenRevoked reports whether a token has been revoked. A jti that is not on the
// registry at all is treated as revoked: it was either already cleaned up after expiry
// or never issued by this server.
func (s *Store) IsTokenRevoked(jti string) (bool, error) {
	var revokedAt sql.NullTime
	err := s.db.QueryRow(
		`SELECT revoked_at FROM issued_tokens WHERE jti = ? AND expires_at > ?`,
		jti, time.Now().UTC()).Scan(&revokedAt)
	if err == sql.ErrNoRows {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	return revokedAt.Valid, nil
}

func (s *Store) RevokeToken(jti string) error {
	_, err := s.db.Exec(
		`UPDATE issued_tokens SET revoked_at = ? WHERE jti = ? AND revoked_at IS NULL`,
		time.Now().UTC(), jti)
	return err
}

// RevokeUserTokens revokes every outstanding token for a user. This is what makes
// "revoke sessions", "disable user", and "delete user" actually deprovision.
func (s *Store) RevokeUserTokens(userID string) error {
	_, err := s.db.Exec(
		`UPDATE issued_tokens SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL`,
		time.Now().UTC(), userID)
	return err
}

func (s *Store) DeleteExpiredIssuedTokens() error {
	_, err := s.db.Exec(`DELETE FROM issued_tokens WHERE expires_at < ?`, time.Now().UTC())
	return err
}

// Applications (Launcher)
func (s *Store) CreateApplication(app *Application) error {
	query := `INSERT INTO applications (id, name, url, icon_name, description, sort_order, enabled, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
	app.CreatedAt = time.Now().UTC()
	_, err := s.db.Exec(query, app.ID, app.Name, app.URL, app.IconName, app.Description, app.SortOrder, app.Enabled, app.CreatedAt)
	return err
}

func (s *Store) GetApplicationByID(id string) (*Application, error) {
	query := `SELECT id, name, url, icon_name, description, sort_order, enabled, created_at FROM applications WHERE id = ?`
	app := &Application{}
	var desc sql.NullString
	err := s.db.QueryRow(query, id).Scan(&app.ID, &app.Name, &app.URL, &app.IconName, &desc, &app.SortOrder, &app.Enabled, &app.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if desc.Valid {
		app.Description = desc.String
	}
	return app, err
}

func (s *Store) ListApplications() ([]Application, error) {
	query := `SELECT id, name, url, icon_name, description, sort_order, enabled, created_at FROM applications ORDER BY sort_order ASC, name ASC`
	rows, err := s.db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var apps []Application
	for rows.Next() {
		var app Application
		var desc sql.NullString
		if err := rows.Scan(&app.ID, &app.Name, &app.URL, &app.IconName, &desc, &app.SortOrder, &app.Enabled, &app.CreatedAt); err != nil {
			return nil, err
		}
		if desc.Valid {
			app.Description = desc.String
		}
		apps = append(apps, app)
	}
	return apps, nil
}

func (s *Store) UpdateApplication(app *Application) error {
	query := `UPDATE applications SET name = ?, url = ?, icon_name = ?, description = ?, sort_order = ?, enabled = ? WHERE id = ?`
	_, err := s.db.Exec(query, app.Name, app.URL, app.IconName, app.Description, app.SortOrder, app.Enabled, app.ID)
	return err
}

func (s *Store) DeleteApplication(id string) error {
	_, err := s.db.Exec(`DELETE FROM applications WHERE id = ?`, id)
	return err
}

// Audit Events
func (s *Store) RecordAuditEvent(e *AuditEvent) error {
	query := `INSERT INTO audit_events (id, actor_id, actor_username, action, target_id, target_type, ip_address, user_agent, outcome, details_json, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
	e.CreatedAt = time.Now().UTC()
	_, err := s.db.Exec(query, e.ID, e.ActorID, e.ActorUsername, e.Action, e.TargetID, e.TargetType, e.IPAddress, e.UserAgent, e.Outcome, e.DetailsJSON, e.CreatedAt)
	return err
}

// DeleteAuditEventsOlderThan trims the audit trail. It is the fastest growing table here
// and nothing else bounds it.
func (s *Store) DeleteAuditEventsOlderThan(cutoff time.Time) error {
	_, err := s.db.Exec(`DELETE FROM audit_events WHERE created_at < ?`, cutoff)
	return err
}

func (s *Store) ListAuditEvents(limit, offset int) ([]AuditEvent, int, error) {
	var total int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM audit_events`).Scan(&total)
	if err != nil {
		return nil, 0, err
	}

	query := `SELECT id, actor_id, actor_username, action, target_id, target_type, ip_address, user_agent, outcome, details_json, created_at FROM audit_events ORDER BY created_at DESC LIMIT ? OFFSET ?`
	rows, err := s.db.Query(query, limit, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var events []AuditEvent
	for rows.Next() {
		var e AuditEvent
		var actorID, actorUser, targetID, targetType, details sql.NullString
		if err := rows.Scan(&e.ID, &actorID, &actorUser, &e.Action, &targetID, &targetType, &e.IPAddress, &e.UserAgent, &e.Outcome, &details, &e.CreatedAt); err != nil {
			return nil, 0, err
		}
		if actorID.Valid {
			e.ActorID = actorID.String
		}
		if actorUser.Valid {
			e.ActorUsername = actorUser.String
		}
		if targetID.Valid {
			e.TargetID = targetID.String
		}
		if targetType.Valid {
			e.TargetType = targetType.String
		}
		if details.Valid {
			e.DetailsJSON = details.String
		}
		events = append(events, e)
	}
	return events, total, nil
}
