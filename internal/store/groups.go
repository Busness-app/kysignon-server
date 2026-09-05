package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"modernc.org/sqlite"
)

var ErrGroupNameExists = errors.New("group name already exists")
var ErrGroupTargetMissing = errors.New("group or user not found")

type Group struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	MemberCount int       `json:"memberCount"`
	Member      bool      `json:"member"`
	CreatedAt   time.Time `json:"createdAt"`
	UpdatedAt   time.Time `json:"updatedAt"`
}

type GroupUser struct {
	ID          string `json:"id"`
	Username    string `json:"username"`
	DisplayName string `json:"displayName"`
	Email       string `json:"email"`
	Status      string `json:"status"`
	Member      bool   `json:"member"`
}

func groupWriteError(err error) error {
	var sqliteErr *sqlite.Error
	if errors.As(err, &sqliteErr) {
		switch sqliteErr.Code() {
		case 2067:
			return ErrGroupNameExists // SQLITE_CONSTRAINT_UNIQUE
		case 787:
			return ErrGroupTargetMissing // SQLITE_CONSTRAINT_FOREIGNKEY
		}
	}
	return err
}

func (s *Store) CreateGroup(g *Group, audit *AuditEvent) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	g.CreatedAt = time.Now().UTC()
	g.UpdatedAt = g.CreatedAt
	if _, err = tx.Exec(`INSERT INTO directory_groups(id,name,description,created_at,updated_at) VALUES (?,?,?,?,?)`, g.ID, g.Name, g.Description, g.CreatedAt, g.UpdatedAt); err != nil {
		return groupWriteError(err)
	}
	if err = recordAuditTx(tx, audit); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) UpdateGroup(g *Group, audit *AuditEvent) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	g.UpdatedAt = time.Now().UTC()
	result, err := tx.Exec(`UPDATE directory_groups SET name=?,description=?,updated_at=? WHERE id=?`, g.Name, g.Description, g.UpdatedAt, g.ID)
	if err != nil {
		return groupWriteError(err)
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrGroupTargetMissing
	}
	if err = recordAuditTx(tx, audit); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) DeleteGroup(id string, audit *AuditEvent) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var name string
	if err = tx.QueryRow(`DELETE FROM directory_groups WHERE id=? RETURNING name`, id).Scan(&name); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrGroupTargetMissing
		}
		return err
	}
	setGroupAuditDetails(audit, map[string]string{"name": name})
	if err = recordAuditTx(tx, audit); err != nil {
		return err
	}
	return tx.Commit()
}

// Individual membership writes cannot overwrite another administrator's edits.
// Repeating either desired state is idempotent; each accepted request is audited.
func (s *Store) SetGroupMembership(groupID, userID string, member bool, audit *AuditEvent) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if member {
		_, err = tx.Exec(`INSERT INTO group_memberships(group_id,user_id) VALUES (?,?) ON CONFLICT(group_id,user_id) DO NOTHING`, groupID, userID)
	} else {
		_, err = tx.Exec(`DELETE FROM group_memberships WHERE group_id=? AND user_id=?`, groupID, userID)
	}
	if err != nil {
		return groupWriteError(err)
	}
	// The preceding write acquires the writer lock before checking either parent.
	var groupName, username string
	if err = tx.QueryRow(`SELECT g.name,u.username FROM directory_groups g CROSS JOIN users u WHERE g.id=? AND u.id=?`, groupID, userID).Scan(&groupName, &username); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrGroupTargetMissing
		}
		return err
	}
	setGroupAuditDetails(audit, map[string]string{"userId": userID, "username": username, "groupName": groupName})
	if err = recordAuditTx(tx, audit); err != nil {
		return err
	}
	return tx.Commit()
}

// Count and page share a read snapshot. userID optionally annotates membership for
// the user-management view without downloading the entire directory.
// ponytail: substring searches scan names; add FTS if large-directory searches become slow.
func (s *Store) ListGroups(query, userID string, limit, offset int) ([]Group, int, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return nil, 0, err
	}
	defer tx.Rollback()
	if userID != "" {
		var exists bool
		if err = tx.QueryRow(`SELECT EXISTS(SELECT 1 FROM users WHERE id=?)`, userID).Scan(&exists); err != nil {
			return nil, 0, err
		}
		if !exists {
			return nil, 0, ErrGroupTargetMissing
		}
	}
	where := ` WHERE instr(lower(g.name),lower(?))>0`
	var total int
	if err = tx.QueryRow(`SELECT COUNT(*) FROM directory_groups g`+where, query).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := tx.Query(`SELECT g.id,g.name,g.description,g.created_at,g.updated_at,
 (SELECT COUNT(*) FROM group_memberships m WHERE m.group_id=g.id),
 EXISTS(SELECT 1 FROM group_memberships m WHERE m.group_id=g.id AND m.user_id=?)
 FROM directory_groups g`+where+` ORDER BY g.name COLLATE NOCASE,g.id LIMIT ? OFFSET ?`, userID, query, limit, offset)
	if err != nil {
		return nil, 0, err
	}
	groups := []Group{}
	for rows.Next() {
		var g Group
		if err = rows.Scan(&g.ID, &g.Name, &g.Description, &g.CreatedAt, &g.UpdatedAt, &g.MemberCount, &g.Member); err != nil {
			rows.Close()
			return nil, 0, err
		}
		groups = append(groups, g)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, 0, err
	}
	return groups, total, tx.Commit()
}

func (s *Store) ListGroupUsers(groupID, query string, includeNonMembers bool, limit, offset int) ([]GroupUser, int, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return nil, 0, err
	}
	defer tx.Rollback()
	var exists bool
	if err = tx.QueryRow(`SELECT EXISTS(SELECT 1 FROM directory_groups WHERE id=?)`, groupID).Scan(&exists); err != nil {
		return nil, 0, err
	}
	if !exists {
		return nil, 0, ErrGroupTargetMissing
	}
	from := ` FROM users u LEFT JOIN group_memberships m ON m.user_id=u.id AND m.group_id=?
 WHERE (? OR m.user_id IS NOT NULL) AND (instr(lower(u.username),lower(?))>0 OR instr(lower(u.display_name),lower(?))>0 OR instr(lower(u.email),lower(?))>0)`
	args := []any{groupID, includeNonMembers, query, query, query}
	var total int
	if err = tx.QueryRow(`SELECT COUNT(*)`+from, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := tx.Query(`SELECT u.id,u.username,u.display_name,u.email,u.status,m.user_id IS NOT NULL`+from+` ORDER BY u.username COLLATE NOCASE,u.id LIMIT ? OFFSET ?`, append(args, limit, offset)...)
	if err != nil {
		return nil, 0, err
	}
	users := []GroupUser{}
	for rows.Next() {
		var u GroupUser
		if err = rows.Scan(&u.ID, &u.Username, &u.DisplayName, &u.Email, &u.Status, &u.Member); err != nil {
			rows.Close()
			return nil, 0, err
		}
		users = append(users, u)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, 0, err
	}
	return users, total, tx.Commit()
}

// Capture readable identifiers while holding the mutation's writer lock, so renames
// and deletion cannot leave the audit referring to a different version of the target.
func setGroupAuditDetails(audit *AuditEvent, details map[string]string) {
	if audit != nil {
		encoded, _ := json.Marshal(details) // String maps cannot fail JSON encoding.
		audit.DetailsJSON = string(encoded)
	}
}
