package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/staffauth"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/store"
)

// The staff console's session routes. Every one runs behind staffAuth, which
// has already resolved the session, checked CSRF on a mutation and applied
// the authorization table for the route's action (staff.go staffRoutes).

func (s *Server) handleStaffLogout(w http.ResponseWriter, r *http.Request) {
	p, _ := staffPrincipalFrom(r.Context())
	if err := s.staff.db.EndStaffSession(r.Context(), p.StaffID, p.Raw, s.now()); err != nil && !errors.Is(err, store.ErrStaffSessionInvalid) {
		s.log.Error("cloudserver/api: staff sign-out", "err", err)
		writeErr(w, http.StatusInternalServerError, "internal", "could not sign out")
		return
	}
	s.setStaffCookie(w, s.staffCookieName(), "", time.Time{}, -1)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleStaffMe(w http.ResponseWriter, r *http.Request) {
	p, _ := staffPrincipalFrom(r.Context())
	writeJSON(w, http.StatusOK, map[string]any{
		"staff_id":     p.StaffID,
		"display_name": p.DisplayName,
		"role":         p.Role,
		"asserted_at":  p.AssertedAt.UTC().Format(time.RFC3339),
		"fresh_until":  p.AssertedAt.Add(staffauth.FreshAssertionWindow).UTC().Format(time.RFC3339),
		"expires_at":   p.ExpiresAt.UTC().Format(time.RFC3339),
	})
}

func (s *Server) handleStaffLog(w http.ResponseWriter, r *http.Request) {
	limit := 100
	if v := r.URL.Query().Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 500 {
			writeErr(w, http.StatusBadRequest, "bad_request", "limit must be 1..500")
			return
		}
		limit = n
	}
	f, filtered, ok := staffLogFilter(w, r, limit)
	if !ok {
		return
	}
	var actions []store.StaffAction
	var err error
	if cs, has := s.staff.db.(staffConsoleStore); has && filtered {
		actions, err = cs.ListStaffActionsFiltered(r.Context(), f)
	} else {
		actions, err = s.staff.db.ListStaffActions(r.Context(), limit)
	}
	if err != nil {
		s.log.Error("cloudserver/api: staff log", "err", err)
		writeErr(w, http.StatusInternalServerError, "internal", "could not read the log")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"actions": actions})
}

func (s *Server) handleStaffAvailabilityList(w http.ResponseWriter, r *http.Request) {
	inputs, err := s.staff.db.ListAvailabilityInputs(r.Context())
	if err != nil {
		s.log.Error("cloudserver/api: staff availability list", "err", err)
		writeErr(w, http.StatusInternalServerError, "internal", "could not read the availability inputs")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"inputs": inputs})
}

// staffAvailabilityBody is a PUT or DELETE body. Value is ignored on DELETE.
type staffAvailabilityBody struct {
	Value  json.RawMessage `json:"value"`
	Reason string          `json:"reason"`
}

// readStaffAvailability decodes the body and validates the reason.
func readStaffAvailability(w http.ResponseWriter, r *http.Request) (staffAvailabilityBody, string, bool) {
	var body staffAvailabilityBody
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "invalid JSON body")
		return body, "", false
	}
	reason, err := staffauth.ValidateReason(body.Reason)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "reason_required", "a reason is required for every staff change: "+err.Error())
		return body, "", false
	}
	return body, reason, true
}

func (s *Server) handleStaffAvailabilitySet(w http.ResponseWriter, r *http.Request) {
	p, _ := staffPrincipalFrom(r.Context())
	body, reason, ok := readStaffAvailability(w, r)
	if !ok {
		return
	}
	in, err := staffauth.ValidateAvailabilityInput(r.PathValue("section"), r.PathValue("key"), body.Value)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_input", err.Error())
		return
	}
	if err := s.staff.db.SetAvailabilityInput(r.Context(), p.StaffID, in, reason, s.now()); err != nil {
		s.log.Error("cloudserver/api: staff availability set", "err", err)
		writeErr(w, http.StatusInternalServerError, "internal", "could not write the availability input")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"section": in.Section, "key": in.Key, "value": json.RawMessage(in.Value)})
}

func (s *Server) handleStaffAvailabilityDelete(w http.ResponseWriter, r *http.Request) {
	p, _ := staffPrincipalFrom(r.Context())
	_, reason, ok := readStaffAvailability(w, r)
	if !ok {
		return
	}
	section, err := staffauth.ParseSection(r.PathValue("section"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_input", err.Error())
		return
	}
	switch err := s.staff.db.DeleteAvailabilityInput(r.Context(), p.StaffID, section, r.PathValue("key"), reason, s.now()); {
	case err == nil:
		w.WriteHeader(http.StatusNoContent)
	case errors.Is(err, store.ErrNotFound):
		writeErr(w, http.StatusNotFound, "not_found", "no such availability input")
	default:
		s.log.Error("cloudserver/api: staff availability delete", "err", err)
		writeErr(w, http.StatusInternalServerError, "internal", "could not remove the availability input")
	}
}
