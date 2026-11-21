package dashboard

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"

	"github.com/marmutapp/superbased-observer/internal/orgenrol"
)

// Settings > Enrolment management (backlog item 6): the whole `observer
// enroll` / `observer org status|push-now|grant show` / `observer unenroll`
// surface from the dashboard. Every route here is CapabilityLocal (owner
// loopback only: it writes this machine's config.toml and keychain), and
// every state-changing route requires the double-submit confirm token minted
// by GET /api/enrolment/manage.
//
// The dashboard owns NO enrolment logic: cmd wires an EnrolmentManager whose
// methods run the same Go code paths as the CLI commands (cmd/observer
// orgenrol_dashboard.go), and the pure input checks and consent-screen
// wording live in internal/orgenrol. Handlers only decode, call, audit, and
// map a classified failure onto a status through enrolFailureStatus.

// enrolFailureStatus maps the closed orgenrol failure vocabulary onto HTTP
// statuses (table-driven, one row per code; enrolment_manage_test pins that
// every code has a row). 422 rather than 401 for a refused code so the SPA's
// remote-auth recovery never mistakes it for a lost dashboard session.
var enrolFailureStatus = map[orgenrol.Code]int{
	orgenrol.CodeInvalidInput:    http.StatusBadRequest,
	orgenrol.CodeUnreachable:     http.StatusBadGateway,
	orgenrol.CodeNotOrgServer:    http.StatusBadGateway,
	orgenrol.CodeTokenRejected:   http.StatusUnprocessableEntity,
	orgenrol.CodeMemberNotActive: http.StatusConflict,
	orgenrol.CodeIdPUnavailable:  http.StatusUnprocessableEntity,
	orgenrol.CodeNotEnrolled:     http.StatusConflict,
	orgenrol.CodeGone:            http.StatusGone,
	orgenrol.CodeStale:           http.StatusConflict,
	orgenrol.CodeUpstream:        http.StatusBadGateway,
	orgenrol.CodeUnsentRows:      http.StatusConflict,
}

// writeEnrolErr writes a classified failure as {error, message} with its
// mapped status, or falls back to writeErr for an unclassified error.
func writeEnrolErr(w http.ResponseWriter, err error) {
	if f, ok := orgenrol.AsFailure(err); ok {
		status, known := enrolFailureStatus[f.Code]
		if !known {
			status = http.StatusInternalServerError
		}
		writeJSONStatus(w, status, map[string]string{"error": string(f.Code), "message": f.Message})
		return
	}
	writeErr(w, err)
}

// enrolMu serializes the enrolment-state-changing verbs (enrol, grant
// decision, sign-in approval, leave): two concurrent enrolments would race
// the keychain, the enrolment row and the config block.
var enrolMu sync.Mutex

// enrolManagerOr501 returns the manager or writes 501.
func (s *Server) enrolManagerOr501(w http.ResponseWriter) EnrolmentManager {
	if s.opts.EnrolManager == nil {
		writeJSONStatus(w, http.StatusNotImplemented, map[string]string{
			"error":   "not_available",
			"message": "enrolment management needs the full daemon (observer start); this dashboard process cannot change the enrolment",
		})
		return nil
	}
	return s.opts.EnrolManager
}

// handleEnrolmentManage serves GET /api/enrolment/manage: the status overview
// plus the confirm token the write routes require.
func (s *Server) handleEnrolmentManage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "GET only", http.StatusMethodNotAllowed)
		return
	}
	m := s.enrolManagerOr501(w)
	if m == nil {
		return
	}
	tok := setConfirmCookie(w, r)
	ov, err := m.Overview(r.Context())
	if err != nil {
		writeEnrolErr(w, err)
		return
	}
	if ov.LastPush != nil {
		ov.LastPush.PushedAt = utcStamp(ov.LastPush.PushedAt)
	}
	writeJSON(w, map[string]any{"confirm_token": tok, "overview": ov})
}

// handleEnrolmentGrantReport serves GET /api/enrolment/grant.
func (s *Server) handleEnrolmentGrantReport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "GET only", http.StatusMethodNotAllowed)
		return
	}
	m := s.enrolManagerOr501(w)
	if m == nil {
		return
	}
	rep, err := m.GrantReport(r.Context())
	if err != nil {
		writeEnrolErr(w, err)
		return
	}
	writeJSON(w, rep)
}

type enrolProbeBody struct {
	OrgURL string `json:"org_url"`
}

// handleEnrolmentProbe serves POST /api/enrolment/probe.
func (s *Server) handleEnrolmentProbe(w http.ResponseWriter, r *http.Request) {
	if !requireConfirmToken(w, r) {
		return
	}
	m := s.enrolManagerOr501(w)
	if m == nil {
		return
	}
	var body enrolProbeBody
	if err := decodeJSONBody(r, &body); err != nil {
		writeEnrolErr(w, orgenrol.Fail(orgenrol.CodeInvalidInput, "invalid JSON body"))
		return
	}
	res, err := m.Probe(r.Context(), body.OrgURL)
	if err != nil {
		writeEnrolErr(w, err)
		return
	}
	writeJSON(w, res)
}

// handleEnrolmentEnrol serves POST /api/enrolment/enrol.
func (s *Server) handleEnrolmentEnrol(w http.ResponseWriter, r *http.Request) {
	if !requireConfirmToken(w, r) {
		return
	}
	m := s.enrolManagerOr501(w)
	if m == nil {
		return
	}
	var req EnrolRequest
	if err := decodeJSONBody(r, &req); err != nil {
		writeEnrolErr(w, orgenrol.Fail(orgenrol.CodeInvalidInput, "invalid JSON body"))
		return
	}
	if _, err := orgenrol.ParseMethod(req.Method); err != nil {
		writeEnrolErr(w, err)
		return
	}
	enrolMu.Lock()
	s.configWriteMu.Lock()
	out, err := m.Enrol(r.Context(), req)
	s.configWriteMu.Unlock()
	enrolMu.Unlock()
	if err != nil {
		s.recordManageAudit(r, "org_enrol_failed", "method="+strings.ToLower(strings.TrimSpace(req.Method))+" "+failureCode(err))
		writeEnrolErr(w, err)
		return
	}
	s.notifyConfigSaved()
	s.recordManageAudit(r, "org_enrol", fmt.Sprintf("method=%s org_id=%s tenancy=%s grant_pending=%t",
		strings.ToLower(strings.TrimSpace(req.Method)), out.OrgID, out.Tenancy, out.PendingGrant != nil))
	writeJSON(w, out)
}

type grantDecisionBody struct {
	OfferID string `json:"offer_id"`
	Accept  bool   `json:"accept"`
}

// handleEnrolmentGrantDecision serves POST /api/enrolment/grant-decision.
func (s *Server) handleEnrolmentGrantDecision(w http.ResponseWriter, r *http.Request) {
	if !requireConfirmToken(w, r) {
		return
	}
	m := s.enrolManagerOr501(w)
	if m == nil {
		return
	}
	var body grantDecisionBody
	if err := decodeJSONBody(r, &body); err != nil || strings.TrimSpace(body.OfferID) == "" {
		writeEnrolErr(w, orgenrol.Fail(orgenrol.CodeInvalidInput, "offer_id is required"))
		return
	}
	enrolMu.Lock()
	s.configWriteMu.Lock()
	out, err := m.DecideGrant(r.Context(), body.OfferID, body.Accept)
	s.configWriteMu.Unlock()
	enrolMu.Unlock()
	if err != nil {
		writeEnrolErr(w, err)
		return
	}
	if body.Accept {
		s.notifyConfigSaved()
	}
	s.recordManageAudit(r, "org_grant_decision", "status="+out.Status)
	writeJSON(w, out)
}

// handleEnrolmentIdPStart serves POST /api/enrolment/idp/start.
func (s *Server) handleEnrolmentIdPStart(w http.ResponseWriter, r *http.Request) {
	if !requireConfirmToken(w, r) {
		return
	}
	m := s.enrolManagerOr501(w)
	if m == nil {
		return
	}
	var body idpStartBody
	if err := decodeJSONBody(r, &body); err != nil {
		writeEnrolErr(w, orgenrol.Fail(orgenrol.CodeInvalidInput, "invalid JSON body"))
		return
	}
	out, err := m.StartIdP(r.Context(), body.OrgURL, SwitchOptions{DropUnsent: body.DropUnsent})
	if err != nil {
		writeEnrolErr(w, err)
		return
	}
	s.recordManageAudit(r, "org_enrol_idp_start", "")
	writeJSON(w, out)
}

// idpStartBody is the POST /api/enrolment/idp/start body: the server URL and
// the explicit "Switch anyway" after an unsent_rows refusal (R3-78).
type idpStartBody struct {
	OrgURL     string `json:"org_url"`
	DropUnsent bool   `json:"drop_unsent"`
}

type idpPollBody struct {
	FlowID string `json:"flow_id"`
}

// handleEnrolmentIdPPoll serves POST /api/enrolment/idp/poll.
func (s *Server) handleEnrolmentIdPPoll(w http.ResponseWriter, r *http.Request) {
	if !requireConfirmToken(w, r) {
		return
	}
	m := s.enrolManagerOr501(w)
	if m == nil {
		return
	}
	var body idpPollBody
	if err := decodeJSONBody(r, &body); err != nil || strings.TrimSpace(body.FlowID) == "" {
		writeEnrolErr(w, orgenrol.Fail(orgenrol.CodeInvalidInput, "flow_id is required"))
		return
	}
	// The approval step enrols and may write config, so it shares the
	// enrolment lock; a pending poll holds it only for one server round trip.
	enrolMu.Lock()
	s.configWriteMu.Lock()
	out, err := m.PollIdP(r.Context(), body.FlowID)
	s.configWriteMu.Unlock()
	enrolMu.Unlock()
	if err != nil {
		writeEnrolErr(w, err)
		return
	}
	if out.Outcome != nil {
		s.notifyConfigSaved()
		s.recordManageAudit(r, "org_enrol", fmt.Sprintf("method=idp org_id=%s tenancy=%s", out.Outcome.OrgID, out.Outcome.Tenancy))
	}
	writeJSON(w, out)
}

// handleEnrolmentPushNow serves POST /api/enrolment/push-now.
func (s *Server) handleEnrolmentPushNow(w http.ResponseWriter, r *http.Request) {
	if !requireConfirmToken(w, r) {
		return
	}
	m := s.enrolManagerOr501(w)
	if m == nil {
		return
	}
	out, err := m.PushNow(r.Context())
	if err != nil {
		s.recordManageAudit(r, "org_push_now_failed", failureCode(err))
		writeEnrolErr(w, err)
		return
	}
	s.recordManageAudit(r, "org_push_now", fmt.Sprintf("rows=%d bytes=%d", out.RowCount, out.Bytes))
	writeJSON(w, out)
}

type shareHistoryBody struct {
	Confirm bool `json:"confirm"`
}

// handleEnrolmentShareHistory serves POST /api/enrolment/share-history
// (T-159): `observer org backfill --all`, a dry run unless the body says
// {"confirm": true}. Only a confirmed run writes an audit row, because only it
// changes anything (the cursor rewind is what makes the history ship).
func (s *Server) handleEnrolmentShareHistory(w http.ResponseWriter, r *http.Request) {
	if !requireConfirmToken(w, r) {
		return
	}
	m := s.enrolManagerOr501(w)
	if m == nil {
		return
	}
	var body shareHistoryBody
	if err := decodeJSONBody(r, &body); err != nil {
		writeEnrolErr(w, orgenrol.Fail(orgenrol.CodeInvalidInput, "invalid JSON body"))
		return
	}
	enrolMu.Lock()
	out, err := m.ShareHistory(r.Context(), body.Confirm)
	enrolMu.Unlock()
	if err != nil {
		if body.Confirm {
			s.recordManageAudit(r, "org_share_history_failed", failureCode(err))
		}
		writeEnrolErr(w, err)
		return
	}
	if out.Rewound {
		s.recordManageAudit(r, "org_share_history", fmt.Sprintf("unlocked=%d total=%d", out.WouldUnlock, out.Total))
	}
	writeJSON(w, out)
}

type resyncBody struct {
	Confirm bool `json:"confirm"`
}

// handleEnrolmentResync serves POST /api/enrolment/resync (T-642): `observer
// org resync` with its default window, a dry run unless the body says
// {"confirm": true}. Like Share history, only a confirmed run writes an audit
// row, because only it queues anything.
func (s *Server) handleEnrolmentResync(w http.ResponseWriter, r *http.Request) {
	if !requireConfirmToken(w, r) {
		return
	}
	m := s.enrolManagerOr501(w)
	if m == nil {
		return
	}
	var body resyncBody
	if err := decodeJSONBody(r, &body); err != nil {
		writeEnrolErr(w, orgenrol.Fail(orgenrol.CodeInvalidInput, "invalid JSON body"))
		return
	}
	enrolMu.Lock()
	out, err := m.Resync(r.Context(), body.Confirm)
	enrolMu.Unlock()
	if err != nil {
		if body.Confirm {
			s.recordManageAudit(r, "org_resync_failed", failureCode(err))
		}
		writeEnrolErr(w, err)
		return
	}
	if out.Confirmed {
		s.recordManageAudit(r, "org_resync", fmt.Sprintf("queued=%d manifests=%d window_days=%d", out.Queued, out.Manifests, out.WindowDays))
	}
	writeJSON(w, out)
}

// handleEnrolmentLeave serves POST /api/enrolment/leave: `observer unenroll`
// with its symmetric cleanup. Never governance-gated: a pin must not stop a
// developer leaving (the consent screen promises it).
func (s *Server) handleEnrolmentLeave(w http.ResponseWriter, r *http.Request) {
	if out, ok := s.leaveWithConfirm(w, r); ok {
		writeJSON(w, out)
	}
}

// leaveWithConfirm is the one Leave path every leave route runs: the confirm
// token, the manager's Leave under enrolMu, and the audit row. It writes the
// error response itself and reports false when the request was refused or
// failed.
func (s *Server) leaveWithConfirm(w http.ResponseWriter, r *http.Request) (LeaveReport, bool) {
	if !requireConfirmToken(w, r) {
		return LeaveReport{}, false
	}
	m := s.enrolManagerOr501(w)
	if m == nil {
		return LeaveReport{}, false
	}
	// The body is optional (the older /api/enrolment/unenroll alias posts
	// none): {"drop_unsent": true} is the explicit "Leave anyway" after an
	// unsent_rows refusal (R3-78). A body that is present must decode.
	var opts SwitchOptions
	if err := decodeJSONBody(r, &opts); err != nil && !errors.Is(err, io.EOF) {
		writeEnrolErr(w, orgenrol.Fail(orgenrol.CodeInvalidInput, "invalid JSON body"))
		return LeaveReport{}, false
	}
	enrolMu.Lock()
	out, err := m.Leave(r.Context(), opts)
	enrolMu.Unlock()
	if err != nil {
		writeEnrolErr(w, err)
		return LeaveReport{}, false
	}
	s.recordManageAudit(r, "org_leave", fmt.Sprintf("was_enrolled=%t drop_unsent=%t", out.WasEnrolled, opts.DropUnsent))
	return out, true
}

// failureCode renders an error's classified code for an audit row (never the
// message, which can echo user input).
func failureCode(err error) string {
	if f, ok := orgenrol.AsFailure(err); ok {
		return "code=" + string(f.Code)
	}
	if errors.Is(err, context.Canceled) {
		return "code=canceled"
	}
	return "code=internal"
}
