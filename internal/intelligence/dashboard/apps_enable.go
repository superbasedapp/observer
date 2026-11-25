package dashboard

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/firstrunstate"
	"github.com/marmutapp/superbased-observer/internal/planechoice"
)

// apps_enable.go is the dashboard half of the AI Apps hot-enable
// (first-run plan revision 2, sections 2.2, 3.5 and 3.8). The daemon
// (cmd/observer obs_wire_apps.go) owns the runtime: the gated obs routes,
// the trace switch, the late receiver bind. This file only serves it:
//
//   - POST /api/apps/enable: the ONE enable seam. The dashboard button,
//     `observer apps on` and the VS Code action all call it. It records the
//     apps_on arrival intent (first one wins) on success.
//   - POST /api/apps/disable: writes AI Apps off; takes effect at the next
//     start, and says so (a mux cannot drop a route).
//   - GET /api/apps/status: the same apps block /api/firstrun carries, plus
//     the confirm token a CLI echoes on its POST.
//
// The dashboard never imports the obs subsystem: the seams carry
// planechoice's plain types.

// appsSeams are the daemon's three AI Apps functions.
type appsSeams struct {
	status  func(context.Context) planechoice.AppsStatus
	enable  func(context.Context) planechoice.EnableReport
	disable func(context.Context) (string, error)
}

// SetApps installs the daemon's AI Apps seams. Called once, after New and
// before serving; a nil status leaves the server without them.
func (s *Server) SetApps(status func(context.Context) planechoice.AppsStatus,
	enable func(context.Context) planechoice.EnableReport,
	disable func(context.Context) (string, error),
) {
	if status == nil || enable == nil || disable == nil {
		return
	}
	s.apps.Store(&appsSeams{status: status, enable: enable, disable: disable})
}

// firstRunApps is the apps block of /api/firstrun and GET /api/apps/status.
type firstRunApps struct {
	// InBuild: app observability is compiled into this binary.
	InBuild bool `json:"in_build"`
	// Component: active | available | absent | blocked | unknown.
	Component planechoice.ComponentState `json:"component"`
	// Available is apps_available with its reason.
	Available planechoice.Availability `json:"available"`
	// On: AI Apps serves in this process now.
	On bool `json:"on"`
	// ConfiguredOn: the saved config says on (may differ from On until
	// the next start, after an off).
	ConfiguredOn bool `json:"configured_on"`
	// HotEnable: POST /api/apps/enable turns it on without a restart.
	HotEnable   bool                     `json:"hot_enable"`
	Receiver    planechoice.Receiver     `json:"receiver"`
	LatestTrace *planechoice.LatestTrace `json:"latest_trace"`
	// Consent is the one consent sentence and its facts (P-05).
	Consent planechoice.Consent `json:"consent"`
	// Pending names configured AI Apps features that start only with the
	// daemon (admission, alerts, organization share tiers).
	Pending []string `json:"pending_next_start,omitempty"`
}

// firstRunPlane is the plane block of /api/firstrun: the decided track and
// what it was decided from (the rule lives in internal/planechoice; no app
// keeps its own copy).
type firstRunPlane struct {
	planechoice.Decision
	// Focus is the stored choice ("" when never chosen).
	Focus planechoice.Choice `json:"focus"`
	// Intent / IntentSource are the first arrival intent recorded here.
	Intent       planechoice.Choice       `json:"intent"`
	IntentSource planechoice.IntentSource `json:"intent_source,omitempty"`
	// CodingHistory: captured AI coding sessions exist.
	CodingHistory bool `json:"coding_history"`
	// AppsAvailable is the capability input, with its reason.
	AppsAvailable planechoice.Availability `json:"apps_available"`
}

// appsBlock reads the daemon's AI Apps facts (or says it has none).
func (s *Server) appsBlock(ctx context.Context) firstRunApps {
	seams := s.apps.Load()
	if seams == nil {
		return firstRunApps{
			Component: planechoice.ComponentUnknown,
			Available: planechoice.AppsAvailable(planechoice.ComponentUnknown),
			Receiver:  planechoice.Receiver{State: planechoice.ReceiverUnknown},
			Consent:   planechoice.BuildConsent(planechoice.ConsentFacts{}),
		}
	}
	st := seams.status(ctx)
	return firstRunApps{
		InBuild: st.InBuild, Component: st.Component,
		Available: planechoice.AppsAvailable(st.Component),
		On:        st.On, ConfiguredOn: st.ConfiguredOn, HotEnable: st.HotEnable,
		Receiver: st.Receiver, LatestTrace: st.LatestTrace,
		Consent: planechoice.BuildConsent(st.Consent),
		Pending: st.Pending,
	}
}

// planeBlock decides the track from the stored state, the coding history
// and the apps facts.
func planeBlock(st firstrunstate.State, codingSessions int64, apps firstRunApps) firstRunPlane {
	in := planechoice.Inputs{
		Stored:        st.Focus,
		Intent:        st.IntentChoice(),
		CodingHistory: codingSessions > 0,
		AppsOn:        apps.On || apps.ConfiguredOn,
		TraceSeen:     apps.LatestTrace != nil,
		AppsAvailable: apps.Available.Available,
	}
	out := firstRunPlane{
		Decision: planechoice.Decide(in),
		Focus:    st.Focus, Intent: in.Intent,
		CodingHistory: in.CodingHistory, AppsAvailable: apps.Available,
	}
	if st.Intent != nil {
		out.IntentSource = st.Intent.Source
	}
	return out
}

// handleAppsStatus is GET /api/apps/status.
func (s *Server) handleAppsStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "GET only", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, struct {
		firstRunApps
		ConfirmToken string `json:"confirm_token"`
	}{s.appsBlock(r.Context()), setConfirmCookie(w, r)})
}

// appsEnableRequest is the enable body. Source names the caller for the
// audit row only; it never changes what enable does.
type appsEnableRequest struct {
	Source string `json:"source"`
}

// appsEnableSources is the closed caller table. "sdk-setup" is the SDK's
// `setup` command (SDK quickstart plan 3.7): on a terminal it shows the
// consent sentence (GET /api/apps/status `consent`) and asks the person y/N
// before it calls this seam; with no terminal it opens the AI Apps page
// instead, whose Turn on button calls it with source "dashboard". The source
// only names the caller in the audit row (ledger SDKQS-7).
var appsEnableSources = map[string]bool{"dashboard": true, "cli": true, "vscode": true, "sdk-setup": true}

// appsEnableStatus maps an outcome to the HTTP status: 200 only when AI
// Apps is on and listening.
var appsEnableStatus = map[planechoice.EnableOutcome]int{
	planechoice.OutcomeOn:           http.StatusOK,
	planechoice.OutcomeNotInBuild:   http.StatusConflict,
	planechoice.OutcomeBlocked:      http.StatusConflict,
	planechoice.OutcomeRefused:      http.StatusConflict,
	planechoice.OutcomeBindFailed:   http.StatusConflict,
	planechoice.OutcomeConfigFailed: http.StatusInternalServerError,
	planechoice.OutcomeNoAnswer:     http.StatusGatewayTimeout,
}

func decodeAppsRequest(w http.ResponseWriter, r *http.Request) (appsEnableRequest, bool) {
	var req appsEnableRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<10)).Decode(&req); err != nil && !errors.Is(err, io.EOF) {
		http.Error(w, "decode body: "+err.Error(), http.StatusBadRequest)
		return req, false
	}
	req.Source = strings.TrimSpace(req.Source)
	if req.Source == "" {
		req.Source = "dashboard"
	}
	if !appsEnableSources[req.Source] {
		http.Error(w, "unknown source "+req.Source, http.StatusBadRequest)
		return req, false
	}
	return req, true
}

// handleAppsEnable is POST /api/apps/enable. A process without the seam
// answers 501, so a caller tells "this daemon cannot hot-enable" (restart
// `observer start` to finish) from a refusal.
func (s *Server) handleAppsEnable(w http.ResponseWriter, r *http.Request) {
	if !requireConfirmToken(w, r) {
		return
	}
	req, ok := decodeAppsRequest(w, r)
	if !ok {
		return
	}
	seams := s.apps.Load()
	if seams == nil {
		http.Error(w, "AI Apps cannot be turned on from this process; run `observer apps on` against the running daemon, or restart `observer start` to finish", http.StatusNotImplemented)
		return
	}
	rep := seams.enable(r.Context())
	// The enable may have added the obs component through its own service:
	// drop the route guard's cached snapshot so the AI Apps routes answer
	// at once, not after the cache's few seconds (POLISH-F2 F2-1).
	s.comps.invalidate()
	if rep.OK {
		// `observer apps on` and the button are the apps arrival intent
		// (plan 2.2); the first intent seen wins.
		if _, _, err := s.firstRunState().RecordIntent(planechoice.ChoiceApps, planechoice.SourceAppsOn, s.now()); err != nil {
			s.opts.Logger.Warn("apps: intent not recorded", "err", err)
		}
	}
	s.recordManageAudit(r, "apps_enable", "source="+req.Source+" outcome="+string(rep.Outcome))
	code, ok := appsEnableStatus[rep.Outcome]
	if !ok {
		code = http.StatusInternalServerError
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(rep)
}

// handleAppsDisable is POST /api/apps/disable: writes AI Apps off, which
// takes effect at the next start.
func (s *Server) handleAppsDisable(w http.ResponseWriter, r *http.Request) {
	if !requireConfirmToken(w, r) {
		return
	}
	req, ok := decodeAppsRequest(w, r)
	if !ok {
		return
	}
	seams := s.apps.Load()
	if seams == nil {
		http.Error(w, "AI Apps cannot be turned off from this process", http.StatusNotImplemented)
		return
	}
	msg, err := seams.disable(r.Context())
	s.comps.invalidate()
	s.recordManageAudit(r, "apps_disable", "source="+req.Source)
	if err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	writeJSON(w, map[string]any{"ok": true, "effective": "next_start", "message": msg})
}
