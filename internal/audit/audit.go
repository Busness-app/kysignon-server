package audit

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"sync"
	"time"

	"github.com/Yoshiofthewire/kysignon-server/internal/store"
	"github.com/google/uuid"
)

type Logger struct {
	store  *store.Store
	stdout *log.Logger
	stderr *log.Logger

	mu           sync.Mutex
	lastFailure  time.Time
	failureCount uint64
	lastError    string
}

func NewLogger(s *store.Store) *Logger {
	return &Logger{
		store:  s,
		stdout: log.New(os.Stdout, "", 0),
		stderr: log.New(os.Stderr, "", 0),
	}
}

type LogEntry struct {
	Timestamp     string         `json:"timestamp"`
	Level         string         `json:"level"`
	Action        string         `json:"action"`
	ActorID       string         `json:"actorId,omitempty"`
	ActorUsername string         `json:"actorUsername,omitempty"`
	TargetID      string         `json:"targetId,omitempty"`
	TargetType    string         `json:"targetType,omitempty"`
	IPAddress     string         `json:"ipAddress,omitempty"`
	UserAgent     string         `json:"userAgent,omitempty"`
	Outcome       string         `json:"outcome"`
	Details       map[string]any `json:"details,omitempty"`
	// AuditPersistError is set when the durable write failed, which makes this console line
	// the only remaining copy of the event.
	AuditPersistError string `json:"auditPersistError,omitempty"`
}

// Record writes one audit event to durable storage and to the process log.
//
// It returns the storage error rather than swallowing it. An identity authority that reports
// "credential rotated" while the durable record of who rotated it silently vanished has no
// audit trail, only the appearance of one; callers performing a security-sensitive mutation
// are expected to check this and fail closed.
func (l *Logger) Record(action, actorID, actorUsername, targetID, targetType, ip, userAgent, outcome string, details map[string]any) error {
	now := time.Now().UTC()
	var detailsJSON string
	if details != nil {
		b, err := json.Marshal(details)
		if err != nil {
			// Detail that will not serialize must not take the whole event with it, but it
			// must not disappear unremarked either.
			detailsJSON = fmt.Sprintf(`{"audit_detail_error":%q}`, err.Error())
		} else {
			detailsJSON = string(b)
		}
	}

	event := &store.AuditEvent{
		ID:            uuid.New().String(),
		ActorID:       actorID,
		ActorUsername: actorUsername,
		Action:        action,
		TargetID:      targetID,
		TargetType:    targetType,
		IPAddress:     ip,
		UserAgent:     userAgent,
		Outcome:       outcome,
		DetailsJSON:   detailsJSON,
		CreatedAt:     now,
	}

	var storeErr error
	if l.store != nil {
		storeErr = l.store.RecordAuditEvent(event)
		l.noteResult(now, storeErr)
	}

	entry := LogEntry{
		Timestamp:     now.Format(time.RFC3339Nano),
		Level:         "INFO",
		Action:        action,
		ActorID:       actorID,
		ActorUsername: actorUsername,
		TargetID:      targetID,
		TargetType:    targetType,
		IPAddress:     ip,
		UserAgent:     userAgent,
		Outcome:       outcome,
		Details:       details,
	}

	if outcome == "failure" || outcome == "denied" {
		entry.Level = "WARN"
	}

	if storeErr != nil {
		// Escalate: the console line is now the only surviving copy of this event.
		entry.Level = "ERROR"
		entry.AuditPersistError = storeErr.Error()
	}

	raw, err := json.Marshal(entry)
	if err != nil {
		// Losing the console copy too would make the failure itself invisible.
		l.stderr.Printf(`{"level":"ERROR","action":%q,"outcome":%q,"auditLogError":%q}`, action, outcome, err.Error())
		return storeErr
	}
	if entry.Level == "INFO" {
		l.stdout.Println(string(raw))
	} else {
		l.stderr.Println(string(raw))
	}
	return storeErr
}

// noteResult tracks whether durable audit writes are succeeding, so readiness can report a
// server that is still serving logins while quietly keeping no record of them.
func (l *Logger) noteResult(now time.Time, err error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if err == nil {
		l.failureCount = 0
		l.lastError = ""
		return
	}
	l.failureCount++
	l.lastFailure = now
	l.lastError = err.Error()
}

// Health reports the state of durable audit persistence. degraded is true while the most
// recent write failed.
func (l *Logger) Health() (degraded bool, failures uint64, lastError string, lastFailure time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.failureCount > 0, l.failureCount, l.lastError, l.lastFailure
}
