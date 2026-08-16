package store

import (
	"database/sql"
	"errors"
	"path/filepath"
	"strings"
	"testing"
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
	}}); err != nil {
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
	if err := s.UpdateUserWithSyncEvents(u, false, nil); !errors.Is(err, ErrLastActiveAdmin) {
		t.Fatalf("demoting final admin error = %v", err)
	}
}
