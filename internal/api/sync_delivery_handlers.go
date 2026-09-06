package api

import (
	"encoding/json"
	"net/http"
)

func (h *AdminHandler) ListSyncDeliveries(w http.ResponseWriter, r *http.Request) {
	attempts, err := h.store.ListSyncDeliveryAttempts(r.PathValue("id"))
	if err != nil {
		http.Error(w, `{"error":"internal_error"}`, 500)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(attempts)
}

func (h *AdminHandler) ReadBackSyncDelivery(w http.ResponseWriter, r *http.Request) {
	sys, err := h.store.GetPairedSystemByID(r.PathValue("id"))
	if err != nil {
		http.Error(w, `{"error":"internal_error"}`, 500)
		return
	}
	if sys == nil {
		http.NotFound(w, r)
		return
	}
	attempts, err := h.store.ListSyncDeliveryAttempts(sys.ID)
	if err != nil {
		http.Error(w, `{"error":"internal_error"}`, 500)
		return
	}
	for _, a := range attempts {
		if a.Token != r.PathValue("token") {
			continue
		}
		result, err := h.syncEngine.ReadBackSyncUser(r.Context(), sys, a.UserID)
		if err != nil {
			http.Error(w, `{"error":"read_back_failed"}`, 502)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(result)
		return
	}
	http.NotFound(w, r)
}

func (h *AdminHandler) ResumeSyncDelivery(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ConfirmedQuiescent bool `json:"confirmedQuiescent"`
		AllowCreateRetry   bool `json:"allowCreateRetry"`
	}
	if json.NewDecoder(r.Body).Decode(&req) != nil || !req.ConfirmedQuiescent {
		http.Error(w, `{"error":"confirm_remote_quiescence"}`, 400)
		return
	}
	sys, err := h.store.GetPairedSystemByID(r.PathValue("id"))
	if err != nil {
		http.Error(w, `{"error":"internal_error"}`, 500)
		return
	}
	if sys == nil {
		http.NotFound(w, r)
		return
	}
	if req.AllowCreateRetry {
		attempts, err := h.store.ListSyncDeliveryAttempts(sys.ID)
		if err != nil {
			http.Error(w, `{"error":"internal_error"}`, 500)
			return
		}
		absent := false
		for _, a := range attempts {
			if a.Token != r.PathValue("token") {
				continue
			}
			result, err := h.syncEngine.ReadBackSyncUser(r.Context(), sys, a.UserID)
			absent = err == nil && result["state"] == "absent"
		}
		if !absent {
			http.Error(w, `{"error":"create_retry_requires_absent_remote_user"}`, 409)
			return
		}
	}
	admin := GetUserFromContext(r.Context())
	event := h.audit.Prepare("admin.sync_delivery_resumed", admin.ID, admin.Username, sys.ID, "system", h.middleware.ClientIP(r), r.UserAgent(), "success", map[string]any{"systemName": sys.Name, "attemptToken": r.PathValue("token"), "confirmedQuiescent": true, "allowCreateRetry": req.AllowCreateRetry})
	if err = h.store.ResumeSyncDelivery(sys.ID, r.PathValue("token"), req.AllowCreateRetry, event.Row); err != nil {
		http.Error(w, `{"error":"attempt_changed_or_still_running"}`, 409)
		return
	}
	event.Committed()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]bool{"success": true})
}
