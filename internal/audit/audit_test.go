package audit

import (
	"bytes"
	"encoding/json"
	"log"
	"testing"
)

func TestCommittedEmitsTransactionDetails(t *testing.T) {
	var output bytes.Buffer
	logger := NewLogger(nil)
	logger.stdout = log.New(&output, "", 0)
	pending := logger.Prepare("admin.group_deleted", "actor", "admin", "group-id", "group", "", "", "success", nil)
	// A store transaction captures the readable name before deleting the target.
	pending.Row.DetailsJSON = `{"name":"Operations"}`
	pending.Committed()
	var entry LogEntry
	if err := json.Unmarshal(output.Bytes(), &entry); err != nil {
		t.Fatal(err)
	}
	if entry.Details["name"] != "Operations" {
		t.Fatalf("stale console details: %+v", entry)
	}
}
