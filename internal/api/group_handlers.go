package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/Busness-app/kysignon-server/internal/store"
	"github.com/google/uuid"
)

type groupPage struct {
	Limit, Offset int
	Query         string
}

func parseGroupPage(r *http.Request) (groupPage, error) {
	p := groupPage{Limit: 25, Query: strings.TrimSpace(r.URL.Query().Get("q"))}
	for name, target := range map[string]*int{"limit": &p.Limit, "offset": &p.Offset} {
		if raw := r.URL.Query().Get(name); raw != "" {
			n, err := strconv.Atoi(raw)
			if err != nil {
				return p, err
			}
			*target = n
		}
	}
	if p.Limit < 1 || p.Limit > 100 || p.Offset < 0 || p.Offset > 1000000 || !utf8.ValidString(p.Query) || utf8.RuneCountInString(p.Query) > 200 {
		return p, errors.New("invalid pagination or search")
	}
	return p, nil
}

func writeGroupError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, store.ErrGroupNameExists):
		http.Error(w, `{"error":"group_name_exists","error_description":"A group with that name already exists"}`, 409)
	case errors.Is(err, store.ErrGroupTargetMissing):
		http.Error(w, `{"error":"not_found","error_description":"Group or user no longer exists"}`, 404)
	default:
		http.Error(w, `{"error":"internal_error"}`, 500)
	}
}
func writeGroupJSON(w http.ResponseWriter, body any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(body)
}

func (h *AdminHandler) ListGroups(w http.ResponseWriter, r *http.Request) {
	p, err := parseGroupPage(r)
	if err != nil {
		http.Error(w, `{"error":"invalid_request","error_description":"Use limit 1–100, a nonnegative offset, and search up to 200 characters"}`, 400)
		return
	}
	groups, total, err := h.store.ListGroups(p.Query, r.URL.Query().Get("userId"), p.Limit, p.Offset)
	if err != nil {
		writeGroupError(w, err)
		return
	}
	writeGroupJSON(w, map[string]any{"groups": groups, "total": total, "limit": p.Limit, "offset": p.Offset})
}

func (h *AdminHandler) ListGroupUsers(w http.ResponseWriter, r *http.Request) {
	p, err := parseGroupPage(r)
	include := r.URL.Query().Get("includeNonMembers")
	if err != nil || (include != "" && include != "true" && include != "false") {
		http.Error(w, `{"error":"invalid_request"}`, 400)
		return
	}
	users, total, err := h.store.ListGroupUsers(r.PathValue("id"), p.Query, include == "true", p.Limit, p.Offset)
	if err != nil {
		writeGroupError(w, err)
		return
	}
	writeGroupJSON(w, map[string]any{"users": users, "total": total, "limit": p.Limit, "offset": p.Offset})
}

func readGroup(r *http.Request) (*store.Group, error) {
	var req struct {
		Name        string `json:"name"`
		Description string `json:"description"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return nil, err
	}
	req.Name = strings.TrimSpace(req.Name)
	req.Description = strings.TrimSpace(req.Description)
	if req.Name == "" || !utf8.ValidString(req.Name) || !utf8.ValidString(req.Description) || utf8.RuneCountInString(req.Name) > 128 || utf8.RuneCountInString(req.Description) > 2048 || strings.ContainsFunc(req.Name, unicode.IsControl) {
		return nil, errors.New("invalid group")
	}
	return &store.Group{ID: r.PathValue("id"), Name: req.Name, Description: req.Description}, nil
}

func (h *AdminHandler) CreateGroup(w http.ResponseWriter, r *http.Request) { h.saveGroup(w, r, true) }
func (h *AdminHandler) UpdateGroup(w http.ResponseWriter, r *http.Request) { h.saveGroup(w, r, false) }
func (h *AdminHandler) saveGroup(w http.ResponseWriter, r *http.Request, create bool) {
	g, err := readGroup(r)
	if err != nil {
		http.Error(w, `{"error":"invalid_request","error_description":"Group name must be 1–128 characters without control characters; description may contain up to 2048 characters"}`, 400)
		return
	}
	action := "admin.group_updated"
	if create {
		g.ID = uuid.NewString()
		action = "admin.group_created"
	}
	actor := GetUserFromContext(r.Context())
	event := h.audit.Prepare(action, actor.ID, actor.Username, g.ID, "group", h.middleware.ClientIP(r), r.UserAgent(), "success", map[string]any{"name": g.Name, "description": g.Description})
	if create {
		err = h.store.CreateGroup(g, event.Row)
	} else {
		err = h.store.UpdateGroup(g, event.Row)
	}
	if err != nil {
		writeGroupError(w, err)
		return
	}
	event.Committed()
	if create {
		writeGroupJSON(w, map[string]any{"group": g})
	} else {
		writeGroupJSON(w, map[string]bool{"success": true})
	}
}

func (h *AdminHandler) DeleteGroup(w http.ResponseWriter, r *http.Request) {
	actor := GetUserFromContext(r.Context())
	id := r.PathValue("id")
	event := h.audit.Prepare("admin.group_deleted", actor.ID, actor.Username, id, "group", h.middleware.ClientIP(r), r.UserAgent(), "success", nil)
	if err := h.store.DeleteGroup(id, event.Row); err != nil {
		writeGroupError(w, err)
		return
	}
	event.Committed()
	writeGroupJSON(w, map[string]bool{"success": true})
}

func (h *AdminHandler) SetGroupMembership(w http.ResponseWriter, r *http.Request) {
	actor := GetUserFromContext(r.Context())
	groupID, userID := r.PathValue("id"), r.PathValue("userId")
	member := r.Method == http.MethodPut
	action := "admin.group_member_removed"
	if member {
		action = "admin.group_member_added"
	}
	event := h.audit.Prepare(action, actor.ID, actor.Username, groupID, "group", h.middleware.ClientIP(r), r.UserAgent(), "success", map[string]any{"userId": userID})
	if err := h.store.SetGroupMembership(groupID, userID, member, event.Row); err != nil {
		writeGroupError(w, err)
		return
	}
	event.Committed()
	writeGroupJSON(w, map[string]bool{"success": true})
}
