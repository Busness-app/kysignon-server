package store

import (
	"database/sql"
	"fmt"
	"time"

	_ "modernc.org/sqlite"
)

type Store struct {
	db *sql.DB
}

// New opens SQLite database and applies migrations.
func New(dbPath string) (*Store, error) {
	// Enable WAL mode, busy timeout, and foreign keys in DSN
	dsn := fmt.Sprintf("%s?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(ON)", dbPath)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to open sqlite database: %w", err)
	}

	db.SetMaxOpenConns(1) // SQLite single-writer pattern

	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("migration failed: %w", err)
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

	CREATE TABLE IF NOT EXISTS paired_systems (
		id TEXT PRIMARY KEY,
		name TEXT NOT NULL,
		system_type TEXT NOT NULL,
		callback_url TEXT NOT NULL,
		hmac_secret_hash TEXT NOT NULL,
		status TEXT NOT NULL CHECK (status IN ('active', 'failing', 'disabled')),
		last_synced_at DATETIME,
		created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS system_pairing_tokens (
		id TEXT PRIMARY KEY,
		token_hash TEXT NOT NULL UNIQUE,
		system_type TEXT NOT NULL,
		created_by_user_id TEXT NOT NULL REFERENCES users(id),
		expires_at DATETIME NOT NULL,
		used_at DATETIME,
		created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
	);
	CREATE INDEX IF NOT EXISTS idx_system_pairing_tokens_hash ON system_pairing_tokens(token_hash);

	CREATE TABLE IF NOT EXISTS account_sync_events (
		id TEXT PRIMARY KEY,
		user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
		event_type TEXT NOT NULL,
		payload_json TEXT NOT NULL,
		attempts INTEGER NOT NULL DEFAULT 0,
		status TEXT NOT NULL CHECK (status IN ('pending', 'delivered', 'failed')),
		last_error TEXT,
		created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
	);
	CREATE INDEX IF NOT EXISTS idx_sync_events_status ON account_sync_events(status);

	CREATE TABLE IF NOT EXISTS native_devices (
		id TEXT PRIMARY KEY,
		user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
		device_name TEXT NOT NULL,
		device_identifier TEXT NOT NULL,
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
		pin_code TEXT NOT NULL,
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
	_, err := s.db.Exec(schema)
	if err != nil {
		return err
	}
	_, _ = s.db.Exec(`ALTER TABLE oauth_clients ADD COLUMN launch_url TEXT`)
	return nil
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

// Session Management
func (s *Store) CreateSession(sess *Session) error {
	query := `INSERT INTO sessions (id, user_id, session_token_hash, ip_address, user_agent, expires_at, created_at, last_active_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
	now := time.Now().UTC()
	sess.CreatedAt = now
	sess.LastActiveAt = now
	_, err := s.db.Exec(query, sess.ID, sess.UserID, sess.SessionTokenHash, sess.IPAddress, sess.UserAgent, sess.ExpiresAt, sess.CreatedAt, sess.LastActiveAt)
	return err
}

func (s *Store) GetSessionByTokenHash(tokenHash string) (*Session, error) {
	query := `SELECT id, user_id, session_token_hash, ip_address, user_agent, expires_at, created_at, last_active_at FROM sessions WHERE session_token_hash = ?`
	sess := &Session{}
	err := s.db.QueryRow(query, tokenHash).Scan(&sess.ID, &sess.UserID, &sess.SessionTokenHash, &sess.IPAddress, &sess.UserAgent, &sess.ExpiresAt, &sess.CreatedAt, &sess.LastActiveAt)
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

func (s *Store) CleanupExpiredSessions() error {
	_, err := s.db.Exec(`DELETE FROM sessions WHERE expires_at < ?`, time.Now().UTC())
	return err
}

// System Pairing & Sync Management
func (s *Store) CreateSystemPairingToken(token *SystemPairingToken) error {
	query := `INSERT INTO system_pairing_tokens (id, token_hash, system_type, created_by_user_id, expires_at, created_at) VALUES (?, ?, ?, ?, ?, ?)`
	token.CreatedAt = time.Now().UTC()
	_, err := s.db.Exec(query, token.ID, token.TokenHash, token.SystemType, token.CreatedByUserID, token.ExpiresAt, token.CreatedAt)
	return err
}

func (s *Store) GetValidSystemPairingToken(tokenHash string) (*SystemPairingToken, error) {
	query := `SELECT id, token_hash, system_type, created_by_user_id, expires_at, used_at, created_at FROM system_pairing_tokens WHERE token_hash = ? AND used_at IS NULL AND expires_at > ?`
	t := &SystemPairingToken{}
	err := s.db.QueryRow(query, tokenHash, time.Now().UTC()).Scan(&t.ID, &t.TokenHash, &t.SystemType, &t.CreatedByUserID, &t.ExpiresAt, &t.UsedAt, &t.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return t, err
}

func (s *Store) MarkSystemPairingTokenUsed(tokenID string) error {
	now := time.Now().UTC()
	_, err := s.db.Exec(`UPDATE system_pairing_tokens SET used_at = ? WHERE id = ?`, now, tokenID)
	return err
}

func (s *Store) CreatePairedSystem(ps *PairedSystem) error {
	query := `INSERT INTO paired_systems (id, name, system_type, callback_url, hmac_secret_hash, status, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)`
	ps.CreatedAt = time.Now().UTC()
	_, err := s.db.Exec(query, ps.ID, ps.Name, ps.SystemType, ps.CallbackURL, ps.HMACSecretHash, ps.Status, ps.CreatedAt)
	return err
}

func (s *Store) GetPairedSystemByID(id string) (*PairedSystem, error) {
	query := `SELECT id, name, system_type, callback_url, hmac_secret_hash, status, last_synced_at, created_at FROM paired_systems WHERE id = ?`
	ps := &PairedSystem{}
	err := s.db.QueryRow(query, id).Scan(&ps.ID, &ps.Name, &ps.SystemType, &ps.CallbackURL, &ps.HMACSecretHash, &ps.Status, &ps.LastSyncedAt, &ps.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return ps, err
}

func (s *Store) ListAllPairedSystems() ([]PairedSystem, error) {
	query := `SELECT id, name, system_type, callback_url, hmac_secret_hash, status, last_synced_at, created_at FROM paired_systems ORDER BY created_at ASC`
	rows, err := s.db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var systems []PairedSystem
	for rows.Next() {
		var ps PairedSystem
		if err := rows.Scan(&ps.ID, &ps.Name, &ps.SystemType, &ps.CallbackURL, &ps.HMACSecretHash, &ps.Status, &ps.LastSyncedAt, &ps.CreatedAt); err != nil {
			return nil, err
		}
		systems = append(systems, ps)
	}
	return systems, nil
}

func (s *Store) ListActivePairedSystems() ([]PairedSystem, error) {
	query := `SELECT id, name, system_type, callback_url, hmac_secret_hash, status, last_synced_at, created_at FROM paired_systems WHERE status != 'disabled' ORDER BY created_at ASC`
	rows, err := s.db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var systems []PairedSystem
	for rows.Next() {
		var ps PairedSystem
		if err := rows.Scan(&ps.ID, &ps.Name, &ps.SystemType, &ps.CallbackURL, &ps.HMACSecretHash, &ps.Status, &ps.LastSyncedAt, &ps.CreatedAt); err != nil {
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
	query := `INSERT INTO account_sync_events (id, user_id, event_type, payload_json, attempts, status, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
	now := time.Now().UTC()
	event.CreatedAt = now
	event.UpdatedAt = now
	_, err := s.db.Exec(query, event.ID, event.UserID, event.EventType, event.PayloadJSON, event.Attempts, event.Status, event.CreatedAt, event.UpdatedAt)
	return err
}

func (s *Store) GetPendingSyncEvents(limit int) ([]AccountSyncEvent, error) {
	query := `SELECT id, user_id, event_type, payload_json, attempts, status, last_error, created_at, updated_at FROM account_sync_events WHERE status IN ('pending', 'failed') AND attempts < 5 ORDER BY created_at ASC LIMIT ?`
	rows, err := s.db.Query(query, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var events []AccountSyncEvent
	for rows.Next() {
		var ev AccountSyncEvent
		var lastErr sql.NullString
		if err := rows.Scan(&ev.ID, &ev.UserID, &ev.EventType, &ev.PayloadJSON, &ev.Attempts, &ev.Status, &lastErr, &ev.CreatedAt, &ev.UpdatedAt); err != nil {
			return nil, err
		}
		if lastErr.Valid {
			ev.LastError = lastErr.String
		}
		events = append(events, ev)
	}
	return events, nil
}

func (s *Store) UpdateSyncEventStatus(eventID, status, lastError string, attempts int) error {
	query := `UPDATE account_sync_events SET status = ?, last_error = ?, attempts = ?, updated_at = ? WHERE id = ?`
	_, err := s.db.Exec(query, status, lastError, attempts, time.Now().UTC(), eventID)
	return err
}

// Native Device & MFA Methods
func (s *Store) CreateDevicePairingToken(token *DevicePairingToken) error {
	query := `INSERT INTO device_pairing_tokens (id, user_id, token_hash, pin_code, expires_at, created_at) VALUES (?, ?, ?, ?, ?, ?)`
	token.CreatedAt = time.Now().UTC()
	_, err := s.db.Exec(query, token.ID, token.UserID, token.TokenHash, token.PINCode, token.ExpiresAt, token.CreatedAt)
	return err
}

func (s *Store) GetValidDevicePairingToken(tokenHash string) (*DevicePairingToken, error) {
	query := `SELECT id, user_id, token_hash, pin_code, expires_at, used_at, created_at FROM device_pairing_tokens WHERE token_hash = ? AND used_at IS NULL AND expires_at > ?`
	t := &DevicePairingToken{}
	err := s.db.QueryRow(query, tokenHash, time.Now().UTC()).Scan(&t.ID, &t.UserID, &t.TokenHash, &t.PINCode, &t.ExpiresAt, &t.UsedAt, &t.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return t, err
}

func (s *Store) GetValidDevicePairingTokenByPIN(pinCode string) (*DevicePairingToken, error) {
	query := `SELECT id, user_id, token_hash, pin_code, expires_at, used_at, created_at FROM device_pairing_tokens WHERE pin_code = ? AND used_at IS NULL AND expires_at > ?`
	t := &DevicePairingToken{}
	err := s.db.QueryRow(query, pinCode, time.Now().UTC()).Scan(&t.ID, &t.UserID, &t.TokenHash, &t.PINCode, &t.ExpiresAt, &t.UsedAt, &t.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return t, err
}

func (s *Store) MarkDevicePairingTokenUsed(tokenID string) error {
	now := time.Now().UTC()
	_, err := s.db.Exec(`UPDATE device_pairing_tokens SET used_at = ? WHERE id = ?`, now, tokenID)
	return err
}

func (s *Store) UpsertNativeDevice(dev *NativeDevice) error {
	query := `
	INSERT INTO native_devices (id, user_id, device_name, device_identifier, public_key, push_token, is_mfa_approver, last_seen_at, created_at)
	VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
	ON CONFLICT(user_id, device_identifier) DO UPDATE SET
		device_name = excluded.device_name,
		public_key = excluded.public_key,
		push_token = excluded.push_token,
		is_mfa_approver = excluded.is_mfa_approver,
		last_seen_at = excluded.last_seen_at
	`
	now := time.Now().UTC()
	dev.CreatedAt = now
	dev.LastSeenAt = &now
	_, err := s.db.Exec(query, dev.ID, dev.UserID, dev.DeviceName, dev.DeviceIdentifier, dev.PublicKey, dev.PushToken, dev.IsMFAApprover, dev.LastSeenAt, dev.CreatedAt)
	return err
}

func (s *Store) ListUserNativeDevices(userID string) ([]NativeDevice, error) {
	query := `SELECT id, user_id, device_name, device_identifier, public_key, push_token, is_mfa_approver, last_seen_at, created_at FROM native_devices WHERE user_id = ? ORDER BY created_at DESC`
	rows, err := s.db.Query(query, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var devices []NativeDevice
	for rows.Next() {
		var dev NativeDevice
		var pubKey, pushTok sql.NullString
		if err := rows.Scan(&dev.ID, &dev.UserID, &dev.DeviceName, &dev.DeviceIdentifier, &pubKey, &pushTok, &dev.IsMFAApprover, &dev.LastSeenAt, &dev.CreatedAt); err != nil {
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
	_, err := s.db.Exec(`DELETE FROM mfa_methods WHERE user_id = ?`, userID)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(`DELETE FROM recovery_codes WHERE user_id = ?`, userID)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(`UPDATE native_devices SET is_mfa_approver = 0 WHERE user_id = ?`, userID)
	return err
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

func (s *Store) UpdateMFAChallengeStatus(challengeID, status string) error {
	_, err := s.db.Exec(`UPDATE mfa_challenges SET status = ? WHERE id = ?`, status, challengeID)
	return err
}

// Recovery Codes
func (s *Store) SaveRecoveryCodes(codes []RecoveryCode) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

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

func (s *Store) MarkRecoveryCodeUsed(codeID string) error {
	now := time.Now().UTC()
	_, err := s.db.Exec(`UPDATE recovery_codes SET used_at = ? WHERE id = ?`, now, codeID)
	return err
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
	query := `INSERT INTO authorization_codes (id, code_hash, client_id, user_id, redirect_uri, scope, code_challenge, code_challenge_method, expires_at, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
	code.CreatedAt = time.Now().UTC()
	_, err := s.db.Exec(query, code.ID, code.CodeHash, code.ClientID, code.UserID, code.RedirectURI, code.Scope, code.CodeChallenge, code.CodeChallengeMethod, code.ExpiresAt, code.CreatedAt)
	return err
}

func (s *Store) GetValidAuthorizationCode(codeHash string) (*AuthorizationCode, error) {
	query := `SELECT id, code_hash, client_id, user_id, redirect_uri, scope, code_challenge, code_challenge_method, expires_at, used_at, created_at FROM authorization_codes WHERE code_hash = ? AND used_at IS NULL AND expires_at > ?`
	code := &AuthorizationCode{}
	err := s.db.QueryRow(query, codeHash, time.Now().UTC()).Scan(&code.ID, &code.CodeHash, &code.ClientID, &code.UserID, &code.RedirectURI, &code.Scope, &code.CodeChallenge, &code.CodeChallengeMethod, &code.ExpiresAt, &code.UsedAt, &code.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return code, err
}

func (s *Store) MarkAuthorizationCodeUsed(codeID string) error {
	now := time.Now().UTC()
	_, err := s.db.Exec(`UPDATE authorization_codes SET used_at = ? WHERE id = ?`, now, codeID)
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

func (s *Store) ListAuditEvents(limit int) ([]AuditEvent, error) {
	query := `SELECT id, actor_id, actor_username, action, target_id, target_type, ip_address, user_agent, outcome, details_json, created_at FROM audit_events ORDER BY created_at DESC LIMIT ?`
	rows, err := s.db.Query(query, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var events []AuditEvent
	for rows.Next() {
		var e AuditEvent
		var actorID, actorUser, targetID, targetType, details sql.NullString
		if err := rows.Scan(&e.ID, &actorID, &actorUser, &e.Action, &targetID, &targetType, &e.IPAddress, &e.UserAgent, &e.Outcome, &details, &e.CreatedAt); err != nil {
			return nil, err
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
	return events, nil
}
