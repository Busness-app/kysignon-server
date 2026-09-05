package api

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/Busness-app/kysignon-server/internal/store"
)

func enrollmentError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, store.ErrEmergencyAdministrator):
		http.Error(w, `{"error":"compliant_admin_required","error_description":"Sign out and sign in with a permitted administrator factor, then apply within five minutes. This proves a local administrator can still sign in."}`, 409)
	case errors.Is(err, store.ErrEnrollmentPolicy):
		http.Error(w, `{"error":"invalid_policy","error_description":"Choose permitted factors and a grace period from 0 to 90 days. Organization and administrator factors must overlap."}`, 400)
	case errors.Is(err, store.ErrLastCompliantFactor):
		http.Error(w, `{"error":"required_factor","error_description":"Enroll another permitted factor before removing your last compliant factor."}`, 409)
	default:
		writeAppRegistryError(w, err)
	}
}
func (h *AdminHandler) ListEnrollmentPolicies(w http.ResponseWriter, r *http.Request) {
	p, err := h.store.ListEnrollmentPolicies()
	if err != nil {
		enrollmentError(w, err)
		return
	}
	writeGroupJSON(w, map[string]any{"policies": p})
}
func readEnrollmentPolicy(r *http.Request) (store.EnrollmentPolicy, error) {
	var req struct {
		Scope          string   `json:"scope"`
		Required       *bool    `json:"required"`
		AllowedMethods []string `json:"allowedMethods"`
		GraceSeconds   *int64   `json:"graceSeconds"`
		Revision       int      `json:"revision"`
	}
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if err := d.Decode(&req); err != nil || d.Decode(new(any)) != io.EOF || req.Required == nil || req.GraceSeconds == nil {
		return store.EnrollmentPolicy{}, store.ErrEnrollmentPolicy
	}
	p := store.EnrollmentPolicy{Scope: req.Scope, Required: *req.Required, AllowedMethods: req.AllowedMethods, GraceSeconds: *req.GraceSeconds, Revision: req.Revision}
	if !p.Valid() {
		return p, store.ErrEnrollmentPolicy
	}
	return p, nil
}
func (h *AdminHandler) PreviewEnrollmentPolicy(w http.ResponseWriter, r *http.Request) {
	p, err := readEnrollmentPolicy(r)
	if err != nil {
		enrollmentError(w, err)
		return
	}
	preview, err := h.store.PreviewEnrollmentPolicy(p, GetSessionFromContext(r.Context()).ID)
	if err != nil {
		enrollmentError(w, err)
		return
	}
	writeGroupJSON(w, preview)
}
func (h *AdminHandler) SetEnrollmentPolicy(w http.ResponseWriter, r *http.Request) {
	p, err := readEnrollmentPolicy(r)
	if err != nil {
		enrollmentError(w, err)
		return
	}
	u := GetUserFromContext(r.Context())
	event := h.audit.Prepare("admin.mfa_enrollment_policy_changed", u.ID, u.Username, p.Scope, "enrollment_policy", h.middleware.ClientIP(r), r.UserAgent(), "success", nil)
	if err = h.store.SetEnrollmentPolicy(p, GetSessionFromContext(r.Context()).ID, event.Row); err != nil {
		enrollmentError(w, err)
		return
	}
	event.Committed()
	writeGroupJSON(w, map[string]bool{"success": true})
}

// Restricted sessions may only inspect their identity, enroll a replacement factor,
// obtain an operation-bound enrollment grant, or leave. Authorization is gated separately.
func enrollmentRouteAllowed(method, path string) bool {
	switch method + " " + path {
	case "GET /api/auth/me", "POST /api/auth/logout", "GET /api/user/devices", "GET /api/user/passkeys",
		"GET /api/auth/step-up/methods", "POST /api/auth/step-up", "POST /api/auth/step-up/finish", "POST /api/auth/step-up/cancel",
		"POST /api/user/devices/pairing-token", "POST /api/user/mfa/totp/setup", "POST /api/user/mfa/totp/enable",
		"POST /api/user/passkeys/register/begin", "POST /api/user/passkeys/register/finish":
		return true
	}
	return false
}
func enrollmentOperationAllowed(operation string) bool {
	switch operation {
	case "POST /api/user/mfa/totp/enable", "POST /api/user/passkeys/register/finish", "POST /api/user/devices/pairing-token":
		return true
	}
	return false
}
