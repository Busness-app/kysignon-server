package store

import (
	"database/sql"
	"errors"
	"time"
)

var ErrAuthorizationInteraction = errors.New("authorization interaction expired, cancelled, or belongs to another login")

// AuthorizationInteraction contains only a validated authorization request. The browser
// binding is independent of the login cookie, which rotates after re-authentication.
type AuthorizationInteraction struct {
	Hash, BrowserHash, UserID, OriginalSessionID, SessionID, Request string
	CreatedAt, ExpiresAt                                             time.Time
}

func (s *Store) migrateAuthorizationInteractions() error {
	_, err := s.db.Exec(`CREATE TABLE IF NOT EXISTS authorization_interactions (
 hash TEXT PRIMARY KEY, browser_hash TEXT NOT NULL, user_id TEXT NOT NULL DEFAULT '',
 original_session_id TEXT NOT NULL DEFAULT '', session_id TEXT NOT NULL DEFAULT '',
 request TEXT NOT NULL, created_at DATETIME NOT NULL, expires_at DATETIME NOT NULL);
 CREATE INDEX IF NOT EXISTS idx_authorization_interactions_browser ON authorization_interactions(browser_hash);
 CREATE INDEX IF NOT EXISTS idx_authorization_interactions_expiry ON authorization_interactions(expires_at);`)
	return err
}

func (s *Store) CreateAuthorizationInteraction(i *AuthorizationInteraction) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.Exec(`DELETE FROM authorization_interactions WHERE expires_at<=?`, time.Now().UTC()); err != nil {
		return err
	}
	// Anonymous cookie churn cannot turn the global memory bound into a login
	// outage. Reclaim only the oldest pending, unowned requests under pressure;
	// signed-in requests and completed proofs must never be evicted.
	if _, err = tx.Exec(`DELETE FROM authorization_interactions WHERE hash IN (
 SELECT hash FROM authorization_interactions WHERE session_id='' AND user_id=''
 ORDER BY created_at,hash LIMIT MAX(0,(SELECT COUNT(*) FROM authorization_interactions)-9999))`); err != nil {
		return err
	}
	// Bound concurrent tabs per browser, and the total number of outstanding interactions.
	result, err := tx.Exec(`INSERT INTO authorization_interactions(hash,browser_hash,user_id,original_session_id,request,created_at,expires_at)
 SELECT ?,?,?,?,?,?,? WHERE (SELECT COUNT(*) FROM authorization_interactions WHERE browser_hash=?)<10
 AND (SELECT COUNT(*) FROM authorization_interactions)<10000`, i.Hash, i.BrowserHash, i.UserID, i.OriginalSessionID, i.Request, i.CreatedAt, i.ExpiresAt, i.BrowserHash)
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return ErrAuthorizationInteraction
	}
	return tx.Commit()
}

func (s *Store) GetAuthorizationInteraction(hash, browserHash string) (*AuthorizationInteraction, error) {
	i := &AuthorizationInteraction{}
	err := s.db.QueryRow(`SELECT hash,browser_hash,user_id,original_session_id,session_id,request,created_at,expires_at FROM authorization_interactions i
 WHERE hash=? AND browser_hash=? AND expires_at>? AND (original_session_id='' OR EXISTS(SELECT 1 FROM sessions WHERE id=i.original_session_id AND expires_at>?))`, hash, browserHash, time.Now().UTC(), time.Now().UTC()).Scan(&i.Hash, &i.BrowserHash, &i.UserID, &i.OriginalSessionID, &i.SessionID, &i.Request, &i.CreatedAt, &i.ExpiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrAuthorizationInteraction
	}
	return i, err
}

func (s *Store) CancelAuthorizationInteraction(hash, browserHash string) error {
	_, err := s.db.Exec(`DELETE FROM authorization_interactions WHERE hash=? AND browser_hash=?`, hash, browserHash)
	return err
}
