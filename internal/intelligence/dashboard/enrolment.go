package dashboard

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/orgclient"
)

// enrolmentStatusResponse is the wire shape of GET /api/enrolment/status.
// Enrolled is always present; the rest are populated only when enrolled.
type enrolmentStatusResponse struct {
	Enrolled        bool         `json:"enrolled"`
	OrgID           string       `json:"org_id,omitempty"`
	OrgName         string       `json:"org_name,omitempty"`
	OrgServerURL    string       `json:"org_server_url,omitempty"`
	UserEmail       string       `json:"user_email,omitempty"`
	EnrolledAt      string       `json:"enrolled_at,omitempty"`
	CredentialStore string       `json:"credential_store,omitempty"`
	LastPush        *lastPushDTO `json:"last_push,omitempty"`
	// PushPaused is present ONLY while the oversized-batch circuit is open —
	// the composed rollup exceeded the accepted push limit, so the loop is
	// parked and NO telemetry is reaching the org server. Absent is the normal
	// case; the UI must not render a scary state for a merely-idle push loop.
	PushPaused *pushPausedDTO `json:"push_paused,omitempty"`
}

type lastPushDTO struct {
	PushedAt string `json:"pushed_at"`
	Status   string `json:"status"`
	RowCount int64  `json:"row_count"`
	Bytes    int64  `json:"bytes"`
	Error    string `json:"error,omitempty"`
}

// pushPausedDTO is the open oversized-batch circuit. Reason is the underlying
// serialized-bytes-vs-limit diagnostic; Until is when the loop retries.
type pushPausedDTO struct {
	Reason string `json:"reason,omitempty"`
	Until  string `json:"until"`
}

// handleEnrolmentStatus serves GET /api/enrolment/status. When org mode is off
// (OrgClient nil) it reports {enrolled:false}, so the web UI hides the org
// surface on a solo-local install. Errors are isolated to this endpoint (the
// mux gives each handler its own request scope; a 500 here cannot affect any
// other endpoint — P1).
func (s *Server) handleEnrolmentStatus(w http.ResponseWriter, r *http.Request) {
	if s.opts.OrgClient == nil {
		writeJSON(w, enrolmentStatusResponse{Enrolled: false})
		return
	}
	st, err := s.opts.OrgClient.Status(r.Context())
	if err != nil {
		writeErr(w, err)
		return
	}
	resp := enrolmentStatusResponse{
		Enrolled:        st.Enrolled,
		OrgID:           st.OrgID,
		OrgName:         st.OrgName,
		OrgServerURL:    st.OrgServerURL,
		UserEmail:       st.UserEmail,
		EnrolledAt:      st.EnrolledAt,
		CredentialStore: st.Backend,
	}
	if st.LastPush != nil {
		resp.LastPush = &lastPushDTO{
			PushedAt: st.LastPush.PushedAt,
			Status:   st.LastPush.Status,
			RowCount: st.LastPush.RowCount,
			Bytes:    st.LastPush.Bytes,
			Error:    st.LastPush.Error,
		}
	}
	if st.PushPaused != nil {
		resp.PushPaused = &pushPausedDTO{
			Reason: st.PushPaused.Reason,
			Until:  st.PushPaused.Until.UTC().Format(time.RFC3339),
		}
	}
	writeJSON(w, resp)
}

// handleEnrolmentLastPayload serves GET /api/enrolment/last-payload: the exact
// JSON of the most recent shared rollup, byte-for-byte (the transparency
// view — "show me precisely what was sent"). Returns the JSON literal null when
// org mode is off or nothing has been pushed yet.
func (s *Server) handleEnrolmentLastPayload(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	if s.opts.OrgClient == nil {
		_, _ = w.Write([]byte("null"))
		return
	}
	payload, err := s.opts.OrgClient.LastPayload(r.Context())
	if err != nil {
		writeErr(w, err)
		return
	}
	if len(payload) == 0 {
		_, _ = w.Write([]byte("null"))
		return
	}
	_, _ = w.Write(payload) // verbatim — must equal the pushed bytes
}

// handleEnrolmentUnenroll serves POST /api/enrolment/unenroll: leaves the org
// and clears local credentials. Idempotent — a no-op when not enrolled / org
// mode off.
func (s *Server) handleEnrolmentUnenroll(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.opts.OrgClient == nil {
		writeJSON(w, map[string]bool{"unenrolled": false})
		return
	}
	if err := s.opts.OrgClient.Unenroll(r.Context()); err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, map[string]bool{"unenrolled": true})
}

// inviteRequest is the POST /api/enrolment/invite body: the teammate's email
// (they must already be a member of the org) and an optional token TTL.
type inviteRequest struct {
	Email   string `json:"email"`
	TTLDays int    `json:"ttl_days,omitempty"`
}

// inviteResponse is what the UI renders: the one-time token plus the org URL,
// so it can show a paste-ready `observer enroll <org-url> <token>` snippet.
// The token is shown once and is never stored node-side.
type inviteResponse struct {
	Token       string `json:"token"`
	TokenID     string `json:"token_id"`
	UserEmail   string `json:"user_email"`
	ExpiresAt   string `json:"expires_at"`
	OrgURL      string `json:"org_url"`
	MintedMonth int    `json:"minted_this_month"`
	MonthlyCap  int    `json:"monthly_cap"`
	Command     string `json:"command"`
}

// handleEnrolmentInvite serves POST /api/enrolment/invite: mint a one-time
// enrolment token for a teammate through the org server this node is already
// enrolled with (the loop-closing nudge of the Teams invite arc).
//
// It is a THIN PROXY over the orgclient seam — every authority decision is the
// org server's: whether delegated invites are allowed at all
// ([server].member_invites), who the mint is attributed to (the enrolment
// bearer's subject, which this node cannot choose), the monthly cap, and the
// audit row. Nothing here can widen any of that.
//
// The refusals are mapped to distinct statuses so the UI can be honest about
// the cause rather than showing a generic failure:
//
//	409 — this node is not enrolled (nothing to invite into)
//	403 — the org has not enabled member invites
//	404 — no such active member (an invite is a handoff, not a signup)
//	429 — this user's monthly invite allowance is spent
func (s *Server) handleEnrolmentInvite(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.opts.OrgClient == nil {
		writeJSONStatus(w, http.StatusConflict, map[string]string{
			"error": "not_enrolled",
			"message": "this agent is not enrolled in an organisation — enrol first with " +
				"`observer enroll <org-url> <token>` (see docs/teams-getting-started.md)",
		})
		return
	}

	var req inviteRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&req); err != nil {
		writeJSONStatus(w, http.StatusBadRequest, map[string]string{
			"error": "bad_request", "message": "invalid JSON body",
		})
		return
	}
	if strings.TrimSpace(req.Email) == "" {
		writeJSONStatus(w, http.StatusBadRequest, map[string]string{
			"error": "bad_request", "message": "email is required",
		})
		return
	}

	tok, err := s.opts.OrgClient.MintInviteToken(r.Context(), req.Email, req.TTLDays)
	switch {
	case errors.Is(err, orgclient.ErrNotEnrolled):
		writeJSONStatus(w, http.StatusConflict, map[string]string{
			"error": "not_enrolled",
			"message": "this agent is not enrolled in an organisation — enrol first with " +
				"`observer enroll <org-url> <token>` (see docs/teams-getting-started.md)",
		})
		return
	case errors.Is(err, orgclient.ErrInvitesDisabled):
		writeJSONStatus(w, http.StatusForbidden, map[string]string{
			"error": "invites_disabled",
			"message": "your organisation does not allow member invites — an org admin must set " +
				"[server].member_invites = true on the org server",
		})
		return
	case errors.Is(err, orgclient.ErrInviteTargetUnknown):
		writeJSONStatus(w, http.StatusNotFound, map[string]string{
			"error": "not_found",
			"message": "no active member with that email — an invite hands over a token for someone " +
				"your org has already provisioned; ask an admin to add them first",
		})
		return
	case errors.Is(err, orgclient.ErrInviteCapReached):
		writeJSONStatus(w, http.StatusTooManyRequests, map[string]string{
			"error":   "invite_cap_reached",
			"message": "you have used your monthly invite allowance; it resets at the start of next month",
		})
		return
	case err != nil:
		writeErr(w, err)
		return
	}

	writeJSON(w, inviteResponse{
		Token:       tok.Token,
		TokenID:     tok.TokenID,
		UserEmail:   tok.UserEmail,
		ExpiresAt:   tok.ExpiresAt,
		OrgURL:      tok.OrgServerURL,
		MintedMonth: tok.MintedMonth,
		MonthlyCap:  tok.MonthlyCap,
		Command:     "observer enroll " + tok.OrgServerURL + " " + tok.Token,
	})
}
