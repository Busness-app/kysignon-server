package api

import (
	"encoding/json"
	"net/http"
)

func (h *AdminHandler) ListAppAccessUsers(w http.ResponseWriter, r *http.Request) {
	p, err := parseGroupPage(r)
	if err != nil {
		http.Error(w, `{"error":"invalid_request"}`, 400)
		return
	}
	mode := r.URL.Query().Get("mode")
	if mode != "" && mode != "all_active_users" && mode != "assigned_only" {
		http.Error(w, `{"error":"invalid_request"}`, 400)
		return
	}
	var enabled *bool
	if raw := r.URL.Query().Get("enabled"); raw != "" {
		if raw != "true" && raw != "false" {
			http.Error(w, `{"error":"invalid_request"}`, 400)
			return
		}
		b := raw == "true"
		enabled = &b
	}
	result, err := h.store.ListAppAccessUsers(r.PathValue("id"), p.Query, mode, enabled, p.Limit, p.Offset)
	if err != nil {
		writeAppRegistryError(w, err)
		return
	}
	writeGroupJSON(w, result)
}
func (h *AdminHandler) ListAppAccessGroups(w http.ResponseWriter, r *http.Request) {
	p, err := parseGroupPage(r)
	if err != nil {
		http.Error(w, `{"error":"invalid_request"}`, 400)
		return
	}
	groups, total, err := h.store.ListAppAccessGroups(r.PathValue("id"), p.Query, p.Limit, p.Offset)
	if err != nil {
		writeAppRegistryError(w, err)
		return
	}
	writeGroupJSON(w, map[string]any{"groups": groups, "total": total, "limit": p.Limit, "offset": p.Offset})
}
func (h *AdminHandler) SetAppPolicy(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Mode     string `json:"mode"`
		Enabled  *bool  `json:"enabled"`
		Revision int    `json:"revision"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Enabled == nil || req.Revision < 1 || (req.Mode != "assigned_only" && req.Mode != "all_active_users") {
		http.Error(w, `{"error":"invalid_request"}`, 400)
		return
	}
	actor := GetUserFromContext(r.Context())
	event := h.audit.Prepare("admin.app_access_changed", actor.ID, actor.Username, r.PathValue("id"), "application", h.middleware.ClientIP(r), r.UserAgent(), "success", nil)
	if err := h.store.SetAppPolicy(r.PathValue("id"), req.Mode, *req.Enabled, req.Revision, event.Row); err != nil {
		writeAppRegistryError(w, err)
		return
	}
	event.Committed()
	writeGroupJSON(w, map[string]bool{"success": true})
}
func (h *AdminHandler) SetAppAssignment(w http.ResponseWriter, r *http.Request) {
	kind := r.PathValue("kind")
	if kind != "users" && kind != "groups" {
		http.Error(w, `{"error":"invalid_request"}`, 400)
		return
	}
	assigned := r.Method == http.MethodPut
	action := "admin.app_assignment_removed"
	if assigned {
		action = "admin.app_assignment_added"
	}
	actor := GetUserFromContext(r.Context())
	event := h.audit.Prepare(action, actor.ID, actor.Username, r.PathValue("id"), "application", h.middleware.ClientIP(r), r.UserAgent(), "success", nil)
	if err := h.store.SetAppAssignment(r.PathValue("id"), kind, r.PathValue("principal"), assigned, event.Row); err != nil {
		writeAppRegistryError(w, err)
		return
	}
	event.Committed()
	writeGroupJSON(w, map[string]bool{"success": true})
}
