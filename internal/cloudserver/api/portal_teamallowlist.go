package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/staffauth"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/store"
)

// The team create allow-list (managed-SaaS plan 07 wave 17 lane
// portal-guardrails; completion audit 2026-11-16 gap 8; L-111 A5; cloud 0130;
// docs/security.md TEAMGATE-1).
//
// While Options.TeamCreateAllowlist is on (SBCI_TEAM_CREATE_ALLOWLIST=on, the
// production kit's default until GO-3), POST /portal/api/orgs creates a TEAM
// org only for an account the staff allow-listed, by account id or by the
// domain of its verified email. The store decides inside the provisioning
// transaction (ProvisionOrgInput.TeamAllowlist); this file words the
// refusal and serves the staff routes that change the list. A personal org
// is never checked.
//
// Staff routes (the staff process only; staff.go staffRoutes), for the
// w17/staff-console UI to call:
//
//	GET    /staff/api/team-allowlist[?include_removed=1]   team_allowlist.read
//	POST   /staff/api/team-allowlist  {kind, value, reason} team_allowlist.write (fresh)
//	DELETE /staff/api/team-allowlist/{id}  {reason}         team_allowlist.write (fresh)
//
// Every add and remove writes a staff_actions row in its own transaction
// (team_allowlist.added / team_allowlist.removed), shown by GET /staff/api/log.

// teamCreateInviteOnlyMessage is what a refused account reads: plain words,
// what still works, and how to ask.
const teamCreateInviteOnlyMessage = "Team workspaces are by invitation while SuperBased is in early access. " +
	"Your personal workspace works as usual. To ask for a team workspace, contact support and quote your account reference."

// teamCreateInviteOnlyBody is the 403 body of a refused team create.
type teamCreateInviteOnlyBody struct {
	Error string `json:"error"`
	Code  string `json:"code"`
	// AccountRef is the caller's own account id, so support can add it
	// (the staff console never sees an email).
	AccountRef string `json:"account_ref"`
}

// writeTeamCreateInviteOnly answers a refused team create.
func writeTeamCreateInviteOnly(w http.ResponseWriter, accountID string) {
	writeJSON(w, http.StatusForbidden, teamCreateInviteOnlyBody{
		Error: teamCreateInviteOnlyMessage, Code: "team_create_invite_only", AccountRef: accountID,
	})
}

// teamCreateAllowedFor reports (inviteOnly, createAllowed) for the console's
// org list. A failed read says not allowed: the create route decides again
// inside its own transaction either way.
func (s *Server) teamCreateAllowedFor(r *http.Request, accountID string) (inviteOnly, allowed bool) {
	if !s.teamCreateAllowlist {
		return false, true
	}
	ok, err := s.store.TeamCreateAllowed(r.Context(), accountID)
	if err != nil {
		s.log.Error("cloudserver/api: team create allow-list read", "err", err)
		return true, false
	}
	return true, ok
}

// teamAllowlistStore is the slice of the store the staff allow-list routes
// use. It is not part of staffStore, so the staff fakes need not grow; a
// store without it answers the routes 501.
type teamAllowlistStore interface {
	ListTeamAllowlist(ctx context.Context, includeRemoved bool) ([]store.TeamAllowlistEntry, error)
	AddTeamAllowlistEntry(ctx context.Context, e staffauth.AllowlistEntry, c store.TeamAllowlistChange) (store.TeamAllowlistEntry, error)
	RemoveTeamAllowlistEntry(ctx context.Context, entryID string, c store.TeamAllowlistChange) (store.TeamAllowlistEntry, error)
}

func (s *Server) staffTeamAllowlist(w http.ResponseWriter) (teamAllowlistStore, bool) {
	ts, ok := s.staff.db.(teamAllowlistStore)
	if !ok {
		writeErr(w, http.StatusNotImplemented, "not_available", "the team allow-list is not available on this server")
	}
	return ts, ok
}

// handleStaffTeamAllowlistList is GET /staff/api/team-allowlist.
func (s *Server) handleStaffTeamAllowlistList(w http.ResponseWriter, r *http.Request) {
	ts, ok := s.staffTeamAllowlist(w)
	if !ok {
		return
	}
	v := r.URL.Query().Get("include_removed")
	entries, err := ts.ListTeamAllowlist(r.Context(), v == "1" || v == "true")
	if err != nil {
		s.log.Error("cloudserver/api: staff team allow-list list", "err", err)
		writeErr(w, http.StatusInternalServerError, "internal", "could not read the team allow-list")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"entries": entries})
}

// staffTeamAllowlistBody is a POST or DELETE body; kind and value are
// ignored on DELETE.
type staffTeamAllowlistBody struct {
	Kind   string `json:"kind"`
	Value  string `json:"value"`
	Reason string `json:"reason"`
}

func readStaffTeamAllowlist(w http.ResponseWriter, r *http.Request) (staffTeamAllowlistBody, string, bool) {
	var body staffTeamAllowlistBody
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

// handleStaffTeamAllowlistAdd is POST /staff/api/team-allowlist.
func (s *Server) handleStaffTeamAllowlistAdd(w http.ResponseWriter, r *http.Request) {
	ts, ok := s.staffTeamAllowlist(w)
	if !ok {
		return
	}
	p, _ := staffPrincipalFrom(r.Context())
	body, reason, ok := readStaffTeamAllowlist(w, r)
	if !ok {
		return
	}
	entry, err := staffauth.ValidateAllowlistEntry(body.Kind, body.Value)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_input", strings.TrimPrefix(err.Error(), staffauth.ErrAllowlistEntry.Error()+": "))
		return
	}
	got, err := ts.AddTeamAllowlistEntry(r.Context(), entry, store.TeamAllowlistChange{StaffID: p.StaffID, Reason: reason, Now: s.now()})
	switch {
	case err == nil:
		writeJSON(w, http.StatusCreated, got)
	case errors.Is(err, store.ErrTeamAllowlistExists):
		writeErr(w, http.StatusConflict, "exists", "that entry is already on the allow-list")
	default:
		s.log.Error("cloudserver/api: staff team allow-list add", "err", err)
		writeErr(w, http.StatusInternalServerError, "internal", "could not add the entry")
	}
}

// handleStaffTeamAllowlistRemove is DELETE /staff/api/team-allowlist/{id}.
func (s *Server) handleStaffTeamAllowlistRemove(w http.ResponseWriter, r *http.Request) {
	ts, ok := s.staffTeamAllowlist(w)
	if !ok {
		return
	}
	p, _ := staffPrincipalFrom(r.Context())
	_, reason, ok := readStaffTeamAllowlist(w, r)
	if !ok {
		return
	}
	got, err := ts.RemoveTeamAllowlistEntry(r.Context(), r.PathValue("id"), store.TeamAllowlistChange{StaffID: p.StaffID, Reason: reason, Now: s.now()})
	switch {
	case err == nil:
		writeJSON(w, http.StatusOK, got)
	case errors.Is(err, store.ErrNotFound):
		writeErr(w, http.StatusNotFound, "not_found", "no active entry with that id")
	default:
		s.log.Error("cloudserver/api: staff team allow-list remove", "err", err)
		writeErr(w, http.StatusInternalServerError, "internal", "could not remove the entry")
	}
}
