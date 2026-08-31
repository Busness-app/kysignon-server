package store

import (
	"database/sql"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDeleteUserWithSyncEventsMigratesLegacyForeignKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.db")
	legacy, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	_, err = legacy.Exec(`
		PRAGMA foreign_keys = ON;
		CREATE TABLE users (
			id TEXT PRIMARY KEY,
			username TEXT NOT NULL,
			display_name TEXT NOT NULL,
			email TEXT NOT NULL,
			password_hash TEXT NOT NULL,
			role TEXT NOT NULL,
			status TEXT NOT NULL,
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
		);
		CREATE TABLE account_sync_events (
			id TEXT PRIMARY KEY,
			user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
			system_id TEXT NOT NULL,
			event_type TEXT NOT NULL,
			payload_json TEXT NOT NULL,
			attempts INTEGER NOT NULL DEFAULT 0,
			status TEXT NOT NULL,
			last_error TEXT,
			next_attempt_at DATETIME,
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
		);
		CREATE INDEX idx_sync_events_status ON account_sync_events(status);
		INSERT INTO users (id, username, display_name, email, password_hash, role, status)
			VALUES ('deleted-user', 'deleted', 'Deleted User', 'deleted@example.test', 'hash', 'user', 'active');
		INSERT INTO account_sync_events (id, user_id, system_id, event_type, payload_json, status)
			VALUES ('stale-event', 'deleted-user', 'system', 'user.updated', '{}', 'pending');`)
	if err != nil {
		_ = legacy.Close()
		t.Fatal(err)
	}
	if err := legacy.Close(); err != nil {
		t.Fatal(err)
	}

	s, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	if err := s.DeleteUserWithSyncEvents("deleted-user", []AccountSyncEvent{{
		ID: "deletion-event", UserID: "deleted-user", SystemID: "system",
		EventType: "user.deleted", PayloadJSON: `{"id":"deleted-user"}`, Status: "pending",
	}}, nil); err != nil {
		t.Fatal(err)
	}

	var definition string
	if err := s.db.QueryRow(`SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'account_sync_events'`).Scan(&definition); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.ToUpper(definition), "REFERENCES USERS") {
		t.Fatal("legacy user foreign key was not removed")
	}
	pending, err := s.GetPendingSyncEvents(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 1 || pending[0].ID != "deletion-event" || pending[0].EventType != "user.deleted" {
		t.Fatalf("deletion event was not retained: %+v", pending)
	}
}

func TestUpdateUserWithSyncEventsPreservesLastAdmin(t *testing.T) {
	s, err := New(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	u := &User{ID: "admin", Username: "admin", DisplayName: "Admin", Email: "admin@example.test", PasswordHash: "hash", Role: "admin", Status: "active"}
	if err := s.CreateUser(u); err != nil {
		t.Fatal(err)
	}
	u.Role = "user"
	if err := s.UpdateUserWithSyncEvents(u, false, nil, nil); !errors.Is(err, ErrLastActiveAdmin) {
		t.Fatalf("demoting final admin error = %v", err)
	}
}

func TestIdleSessionIsRejectedBeforeAbsoluteExpiry(t *testing.T) {
	s, err := New(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	user := &User{ID: "user", Username: "user", DisplayName: "User", Email: "user@example.test", PasswordHash: "hash", Role: "user", Status: "active"}
	if err := s.CreateUser(user); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateSession(&Session{ID: "session", UserID: user.ID, SessionTokenHash: "token", IPAddress: "127.0.0.1", UserAgent: "test", ExpiresAt: time.Now().UTC().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`UPDATE sessions SET last_active_at = ? WHERE id = ?`, time.Now().UTC().Add(-31*time.Minute), "session"); err != nil {
		t.Fatal(err)
	}
	session, err := s.GetSessionByTokenHash("token", 30*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if session != nil {
		t.Fatal("idle session remained valid before its absolute expiry")
	}
}

func TestLegacyDevicePairingTokensAreRebuiltWithoutPlaintextPINs(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.db")
	legacy, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	_, err = legacy.Exec(`
		CREATE TABLE users (id TEXT PRIMARY KEY, username TEXT NOT NULL, display_name TEXT NOT NULL, email TEXT NOT NULL, password_hash TEXT NOT NULL, role TEXT NOT NULL, status TEXT NOT NULL, created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP, updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP);
		CREATE TABLE device_pairing_tokens (id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id), token_hash TEXT NOT NULL UNIQUE, pin_code TEXT NOT NULL, expires_at DATETIME NOT NULL, used_at DATETIME, created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP);
		INSERT INTO users (id, username, display_name, email, password_hash, role, status) VALUES ('u1', 'user', 'User', 'user@example.test', 'hash', 'user', 'active');
		INSERT INTO device_pairing_tokens (id, user_id, token_hash, pin_code, expires_at) VALUES ('old', 'u1', 'hash', '123456', CURRENT_TIMESTAMP);`)
	if err != nil {
		t.Fatal(err)
	}
	if err := legacy.Close(); err != nil {
		t.Fatal(err)
	}
	s, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	var definition string
	if err := s.db.QueryRow(`SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'device_pairing_tokens'`).Scan(&definition); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.ToUpper(definition), "PIN_CODE") {
		t.Fatal("legacy plaintext pairing PIN column survived migration")
	}
	if err := s.CreateDevicePairingToken(&DevicePairingToken{ID: "new", UserID: "u1", TokenHash: "new-hash", PINHash: "new-pin-hash", ExpiresAt: time.Now().UTC().Add(time.Minute)}); err != nil {
		t.Fatalf("new pairing token failed after migration: %v", err)
	}
}

func TestNativeDevicePushTokenReplayStateMigrates(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy-native-device.db")
	legacy, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	_, err = legacy.Exec(`CREATE TABLE native_devices (
		id TEXT PRIMARY KEY, user_id TEXT NOT NULL, device_name TEXT NOT NULL,
		device_identifier TEXT NOT NULL, platform TEXT NOT NULL DEFAULT 'android',
		public_key TEXT, push_token TEXT, is_mfa_approver BOOLEAN NOT NULL DEFAULT 0,
		last_seen_at DATETIME, created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		UNIQUE(user_id, device_identifier));`)
	if err != nil {
		t.Fatal(err)
	}
	if err := legacy.Close(); err != nil {
		t.Fatal(err)
	}

	s, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	var count int
	if err := s.db.QueryRow(`SELECT count(*) FROM pragma_table_info('native_devices') WHERE name = 'push_token_updated_at_ms'`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatal("push-token replay state column was not migrated")
	}
}

func TestListAuditEventsPagination(t *testing.T) {
	s, err := New(filepath.Join(t.TempDir(), "audit_test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	for i := 1; i <= 15; i++ {
		err := s.RecordAuditEvent(&AuditEvent{
			ID:            strings.Repeat("a", 10) + string(rune('0'+i)),
			ActorUsername: "admin",
			Action:        "test.action",
			Outcome:       "success",
			IPAddress:     "127.0.0.1",
		})
		if err != nil {
			t.Fatalf("RecordAuditEvent failed: %v", err)
		}
	}

	// Page 1 with limit 5
	events, total, err := s.ListAuditEvents(5, 0)
	if err != nil {
		t.Fatalf("ListAuditEvents failed: %v", err)
	}
	if total != 15 {
		t.Fatalf("expected total 15, got %d", total)
	}
	if len(events) != 5 {
		t.Fatalf("expected 5 events on page 1, got %d", len(events))
	}

	// Page 2 with limit 5 offset 5
	events2, total2, err := s.ListAuditEvents(5, 5)
	if err != nil {
		t.Fatalf("ListAuditEvents page 2 failed: %v", err)
	}
	if total2 != 15 {
		t.Fatalf("expected total 15, got %d", total2)
	}
	if len(events2) != 5 {
		t.Fatalf("expected 5 events on page 2, got %d", len(events2))
	}

	// Page 4 with limit 5 offset 15 (empty)
	events4, total4, err := s.ListAuditEvents(5, 15)
	if err != nil {
		t.Fatalf("ListAuditEvents page 4 failed: %v", err)
	}
	if total4 != 15 {
		t.Fatalf("expected total 15, got %d", total4)
	}
	if len(events4) != 0 {
		t.Fatalf("expected 0 events on page 4, got %d", len(events4))
	}
}
