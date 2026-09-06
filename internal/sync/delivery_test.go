package sync

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Busness-app/kysignon-server/internal/store"
)

func TestTimedOutWriteBlocksLaterDelivery(t *testing.T) {
	e, s, u, cleanup := setupSync(t)
	defer cleanup()
	entered := make(chan struct{})
	release := make(chan struct{})
	finished := make(chan struct{})
	var calls atomic.Int32
	remote := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			close(entered)
			<-release
		}
		w.WriteHeader(204)
		close(finished)
	}))
	defer remote.Close()
	defer close(release)
	e.httpClient = remote.Client()
	e.httpClient.Timeout = 50 * time.Millisecond
	target, _, err := e.CreateSystem(&CreateSystemRequest{Name: "target", SystemType: "suite_webhook", CallbackURL: remote.URL})
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"old", "new"} {
		if err := s.CreateAccountSyncEvent(&store.AccountSyncEvent{ID: id, UserID: u.ID, SystemID: target.ID, EventType: "user.updated", PayloadJSON: `{}`, Status: "pending"}); err != nil {
			t.Fatal(err)
		}
	}
	if err := e.DispatchPendingEvents(context.Background()); err != nil {
		t.Fatal(err)
	}
	select {
	case <-entered:
	default:
		t.Fatal("request never reached remote")
	}
	if err := e.DispatchPendingEvents(context.Background()); err != nil {
		t.Fatal(err)
	}
	attempts, err := s.ListSyncDeliveryAttempts(target.ID)
	if err != nil || len(attempts) != 1 || calls.Load() != 1 {
		t.Fatal("later write bypassed uncertain request", attempts, calls.Load(), err)
	}
	// Read-back of suite protocols is explicitly unavailable, never an unblock.
	result, err := e.ReadBackSyncUser(context.Background(), target, u.ID)
	if err != nil || result["state"] != "unsupported" {
		t.Fatal(result, err)
	}
}

func TestDeliveryOutcomeClassification(t *testing.T) {
	for _, code := range []int{200, 201, 204, 202, 400, 408, 409, 429, 500, 503} {
		t.Run(http.StatusText(code), func(t *testing.T) {
			remote := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(code) }))
			defer remote.Close()
			tracker := &deliveryTransport{base: http.DefaultTransport}
			client := &http.Client{Transport: tracker}
			req, _ := http.NewRequest("PUT", remote.URL, nil)
			response, err := client.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			response.Body.Close()
			want := code == 202 || code == 408 || code >= 500
			if tracker.uncertain.Load() != want {
				t.Fatalf("status %d uncertain=%v", code, tracker.uncertain.Load())
			}
			// A later successful read cannot turn an uncertain mutation into an acknowledgment.
			response, err = client.Get(remote.URL)
			if err != nil {
				t.Fatal(err)
			}
			response.Body.Close()
			if tracker.uncertain.Load() != want {
				t.Fatal("read cleared mutation uncertainty")
			}
		})
	}
}
