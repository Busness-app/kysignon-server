package audit

import (
	"encoding/json"
	"log"
	"os"
	"time"

	"github.com/Yoshiofthewire/kysignon-server/internal/store"
	"github.com/google/uuid"
)

type Logger struct {
	store  *store.Store
	stdout *log.Logger
	stderr *log.Logger
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
}

func (l *Logger) Record(action, actorID, actorUsername, targetID, targetType, ip, userAgent, outcome string, details map[string]any) {
	now := time.Now().UTC()
	var detailsJSON string
	if details != nil {
		b, _ := json.Marshal(details)
		detailsJSON = string(b)
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

	if l.store != nil {
		_ = l.store.RecordAuditEvent(event)
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

	raw, _ := json.Marshal(entry)
	if entry.Level == "WARN" {
		l.stderr.Println(string(raw))
	} else {
		l.stdout.Println(string(raw))
	}
}
