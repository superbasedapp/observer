package api

import (
	"errors"
	"net/http"
	"time"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/connectflow"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/portalmfa"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/store"
	"github.com/marmutapp/superbased-observer/internal/platformcontract"
)

// portal_connect.go is the browser side of the connect flow (contract A,
// docs/plans/onboarding-v2-connect-flow.md; docs/security.md CONNECT-1):
//
//	GET  /portal/api/connect/requests/{id}           the approval page's view
//	POST /portal/api/connect/lookup                  code entry -> request id
//	POST /portal/api/connect/requests/{id}/approve   Connect (target) or Not now (no target)
//	POST /portal/api/connect/requests/{id}/decline   "This is not my machine"
//	GET  /portal/api/connect/machines                the account home's live state
//
// Every route sits behind portalAuth (session cookie, per-account limit, and
// for a POST the exact Origin and the double-submit CSRF check). A request
// some other account already resolved reads as not found.
//
// The same pages answer an AI Apps SDK setup's request for an SDK key
// (purpose sdk_key; the SDK quickstart plan section 3.6; docs/security.md
// SDKQS-1): the view names the purpose, the SDK and the project, every
// choice carries the SDK key's disclosure and whether its plan includes AI
// Apps (connect_sdkplan.go; a team without it is offered disabled, with the
// plan refusal's message and link), there is no "Not now", and the approved
// view's open_url is the chosen dashboard's AI apps page in waiting mode.

// mountPortalConnect registers the console's connect routes.
func (s *Server) mountPortalConnect(mux *http.ServeMux) {
	mux.Handle("GET /portal/api/connect/requests/{id}", s.portalAuth(http.HandlerFunc(s.handlePortalConnectRequest)))
	mux.Handle("POST /portal/api/connect/lookup", s.portalAuth(http.HandlerFunc(s.handlePortalConnectLookup)))
	mux.Handle("POST /portal/api/connect/requests/{id}/approve", s.portalAuth(http.HandlerFunc(s.handlePortalConnectApprove)))
	mux.Handle("POST /portal/api/connect/requests/{id}/decline", s.portalAuth(http.HandlerFunc(s.handlePortalConnectDecline)))
	mux.Handle("GET /portal/api/connect/machines", s.portalAuth(http.HandlerFunc(s.handlePortalConnectMachines)))
}

// connectChoiceJSON is one dashboard the approver may pick.
type connectChoiceJSON struct {
	OrgID       string                     `json:"org_id"`
	Kind        string                     `json:"kind"`
	DisplayName string                     `json:"display_name"`
	Slug        string                     `json:"slug,omitempty"`
	Status      string                     `json:"status"`
	ShareLevel  string                     `json:"share_level"`
	Disclosure  connectflow.DisclosureText `json:"disclosure"`
	Preselected bool                       `json:"preselected"`
	// Available is false for a dashboard listed but not choosable: for an SDK
	// key, a plan that does not include AI Apps (Refusal says why).
	Available bool `json:"available"`
	// Refusal is why an unavailable choice is disabled.
	Refusal *connectRefusalJSON `json:"refusal,omitempty"`
}

// connectRefusalJSON is why a dashboard cannot be chosen: the plan refusal's
// message, and where the billing owner changes the plan.
type connectRefusalJSON struct {
	Code       string `json:"code"`
	Message    string `json:"message"`
	UpgradeURL string `json:"upgrade_url,omitempty"`
}

// connectNetworkJSON is the requester's approximate network.
type connectNetworkJSON struct {
	// Prefix is the masked network ("203.0.113.0/24"); "" when unknown.
	Prefix string `json:"prefix"`
	// SameAsYou is true when this browser is on that network now.
	SameAsYou bool `json:"same_as_you"`
}

// connectRequestViewJSON is what the approval page shows.
type connectRequestViewJSON struct {
	RequestID string `json:"request_id"`
	// Purpose is machine (observer connect) or sdk_key (an SDK setup asking
	// for the member's own SDK key).
	Purpose         string `json:"purpose"`
	Status          string `json:"status"`
	UserCode        string `json:"user_code,omitempty"`
	MachineName     string `json:"machine_name"`
	OS              string `json:"os"`
	Arch            string `json:"arch"`
	ObserverVersion string `json:"observer_version"`
	// Client, ClientVersion and ProjectName say which SDK asks, for which
	// project (sdk_key only).
	Client        string             `json:"client,omitempty"`
	ClientVersion string             `json:"client_version,omitempty"`
	ProjectName   string             `json:"project_name,omitempty"`
	CreatedAt     string             `json:"created_at"`
	AgeSeconds    int64              `json:"age_seconds"`
	ExpiresIn     int64              `json:"expires_in"`
	Network       connectNetworkJSON `json:"network"`
	// Choices are the dashboards the account may connect to (pending only),
	// personal first.
	Choices []connectChoiceJSON `json:"choices"`
	// Target is the chosen dashboard once approved.
	Target *connectTargetJSON `json:"target"`
	// OpenURL opens the chosen dashboard (a button, never text), built by
	// tenantLink. For an SDK key it is the dashboard's AI apps page in
	// waiting mode (tenantPageAppsWaiting), where the browser goes after
	// Approve.
	OpenURL string `json:"open_url,omitempty"`
	// TargetReady says whether the chosen dashboard is active (sdk_key only:
	// a new account's personal dashboard is set up after the approval, and
	// the page waits before it goes to open_url).
	TargetReady *bool `json:"target_ready,omitempty"`
	// OnlineURL is OpenURL under its first name, kept for one release so an
	// older console bundle keeps working (additive wire).
	//
	// Deprecated: read open_url.
	OnlineURL string `json:"online_url,omitempty"`
}

// connectRequestForCaller reads a request the caller may see: an unresolved
// one, or one the caller resolved. Anything else is not found.
func (s *Server) connectRequestForCaller(w http.ResponseWriter, r *http.Request, accountID string) (store.ConnectRequest, bool) {
	id := r.PathValue("id")
	if id == "" || len(id) > connectRequestIDMax {
		writeErr(w, http.StatusNotFound, "not_found", "connect request not found")
		return store.ConnectRequest{}, false
	}
	c, err := s.store.ConnectRequestByID(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) || (err == nil && c.AccountID != "" && c.AccountID != accountID) {
		writeErr(w, http.StatusNotFound, "not_found", "connect request not found")
		return store.ConnectRequest{}, false
	}
	if err != nil {
		s.log.Error("cloudserver/api: read connect request", "err", err)
		writeErr(w, http.StatusInternalServerError, "internal", "could not read the connect request")
		return store.ConnectRequest{}, false
	}
	return c, true
}

// connectOpenPages is the dashboard page an approved request's Open link
// lands on, per answer: a machine opens the dashboard's home, an SDK key the
// AI apps page waiting for the first trace.
var connectOpenPages = []struct {
	answer connectflow.Answer
	page   tenantPage
}{
	{connectflow.AnswerSignIn, tenantPageDashboard},
	{connectflow.AnswerKeyGrant, tenantPageAppsWaiting},
}

// connectOpenURL is the chosen dashboard's Open target for a request of
// purpose p (tenantLink's page from connectOpenPages), or "" with no target.
func (s *Server) connectOpenURL(p connectflow.Purpose, t *store.ConnectTarget) string {
	if t == nil {
		return ""
	}
	answer, _ := connectflow.AnswerFor(p)
	for _, row := range connectOpenPages {
		if row.answer == answer {
			return s.tenantLink(t.Slug, row.page)
		}
	}
	return s.tenantLink(t.Slug, tenantPageDashboard)
}

// connectChoices lists the dashboards the caller may connect a machine to
// (or, for an SDK key, mint a key on): the personal dashboard (created here
// if the account has none yet; it may still be being set up) and every
// active team, the team whose slug is hint preselected, else the personal
// dashboard. Each carries its purpose's disclosure; for an SDK key, a
// dashboard whose plan does not include AI Apps is listed unavailable with
// the plan refusal, and is never preselected.
func (s *Server) connectChoices(r *http.Request, purpose connectflow.Purpose, accountID, hint string) ([]connectChoiceJSON, error) {
	if _, _, err := s.store.EnsurePersonalOrg(r.Context(), accountID, s.tenantDomain); err != nil {
		return nil, err
	}
	orgs, err := s.store.ListMyOrgs(r.Context(), accountID)
	if err != nil {
		return nil, err
	}
	deviceOrgOrder(orgs)
	out := make([]connectChoiceJSON, 0, len(orgs))
	hinted := false
	for _, o := range orgs {
		personal := o.Kind == store.OrgPersonal
		usable := o.Status == platformcontract.StateActive || (personal && o.Status == platformcontract.StateProvisioning)
		if !usable {
			continue
		}
		d, ok := connectflow.DisclosureFor(purpose, connectflow.DashboardKind(o.Kind), o.DisplayName)
		if !ok {
			continue
		}
		c := connectChoiceJSON{
			OrgID: o.OrgID, Kind: string(o.Kind), DisplayName: o.DisplayName,
			Status: string(o.Status), ShareLevel: string(d.Level), Disclosure: d, Available: true,
		}
		if answer, _ := connectflow.AnswerFor(purpose); answer == connectflow.AnswerKeyGrant {
			v, err := s.sdkPlanFor(r.Context(), accountID, o)
			if err != nil {
				return nil, err
			}
			if v.Refused {
				c.Available = false
				c.Refusal = &connectRefusalJSON{Code: connectPlanRequiredCode, Message: v.Message, UpgradeURL: v.UpgradeURL}
			}
		}
		if !personal {
			c.Slug = o.Slug // a team's address is its name; a personal one is never shown
			if hint != "" && o.Slug == hint && c.Available {
				c.Preselected, hinted = true, true
			}
		}
		out = append(out, c)
	}
	if !hinted {
		preselectFirst(out, func(c connectChoiceJSON) bool { return c.Available && c.Kind == string(store.OrgPersonal) })
	}
	return out, nil
}

// connectPlanRequiredCode is the code of a choice, or an approval, refused
// because the dashboard's plan does not include AI Apps (the host's own
// refusal code for the same cause).
const connectPlanRequiredCode = "plan_required"

// preselectFirst marks the first choice that matches as preselected.
func preselectFirst(choices []connectChoiceJSON, match func(connectChoiceJSON) bool) {
	for i := range choices {
		if match(choices[i]) {
			choices[i].Preselected = true
			return
		}
	}
}

// connectView builds the approval page's view of c for the caller.
func (s *Server) connectView(r *http.Request, accountID string, c store.ConnectRequest) (connectRequestViewJSON, error) {
	now := s.now()
	status := connectflow.EffectiveStatus(c.Status, c.ExpiresAt, now)
	ip, _ := edgeClientIP(r)
	v := connectRequestViewJSON{
		RequestID: c.RequestID, Purpose: string(c.Purpose), Status: string(status),
		MachineName: c.MachineName, OS: c.OS, Arch: c.Arch, ObserverVersion: c.ObserverVersion,
		Client: c.Client, ClientVersion: c.ClientVersion, ProjectName: c.ProjectName,
		CreatedAt:  rfc3339(c.CreatedAt),
		AgeSeconds: int64(now.Sub(c.CreatedAt) / time.Second),
		Network:    connectNetworkJSON{Prefix: c.OriginNetwork, SameAsYou: connectflow.SameNetwork(c.OriginNetwork, ip)},
		Choices:    []connectChoiceJSON{},
		Target:     connectTarget(c.Target),
	}
	v.OpenURL = s.connectOpenURL(c.Purpose, c.Target)
	v.OnlineURL = v.OpenURL
	if answer, _ := connectflow.AnswerFor(c.Purpose); answer == connectflow.AnswerKeyGrant && c.Target != nil {
		ready, err := s.connectTargetReady(r.Context(), c)
		if err != nil {
			return connectRequestViewJSON{}, err
		}
		v.TargetReady = &ready
	}
	if status == connectflow.StatusPending {
		v.UserCode = c.UserCode
		v.ExpiresIn = int64(c.ExpiresAt.Sub(now) / time.Second)
		choices, err := s.connectChoices(r, c.Purpose, accountID, c.TargetHint)
		if err != nil {
			return connectRequestViewJSON{}, err
		}
		v.Choices = choices
	}
	return v, nil
}

// handlePortalConnectRequest is GET /portal/api/connect/requests/{id}.
func (s *Server) handlePortalConnectRequest(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	p, _ := portalPrincipalFrom(r.Context())
	c, ok := s.connectRequestForCaller(w, r, p.AccountID)
	if !ok {
		return
	}
	v, err := s.connectView(r, p.AccountID, c)
	if err != nil {
		s.log.Error("cloudserver/api: connect request view", "err", err)
		writeErr(w, http.StatusInternalServerError, "internal", "could not read your dashboards")
		return
	}
	writeJSON(w, http.StatusOK, v)
}

// handlePortalConnectLookup is POST /portal/api/connect/lookup: a typed code
// to its pending request. Every attempt counts against the account's and the
// client IP's code-entry limits, so a code cannot be guessed at speed.
func (s *Server) handlePortalConnectLookup(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	p, _ := portalPrincipalFrom(r.Context())
	if !s.allowConnectDimension(w, r, func(l *rateLimiters) *rateLimitDimension { return l.connectCode }, p.AccountID) {
		return
	}
	ip, err := edgeClientIP(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_client_ip", "could not determine the client IP")
		return
	}
	if !s.allowConnectDimension(w, r, func(l *rateLimiters) *rateLimitDimension { return l.connectCodeIP }, ip) {
		return
	}
	var req struct {
		UserCode string `json:"user_code"`
	}
	if !readSmallJSON(w, r, &req) {
		return
	}
	code, err := connectflow.NormalizeUserCode(req.UserCode)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "code_invalid", "that is not a connect code")
		return
	}
	id, err := s.store.LookupConnectCode(r.Context(), code, s.now())
	if errors.Is(err, store.ErrNotFound) {
		s.audit(r.Context(), p.AccountID, "connect_code_miss")
		writeErr(w, http.StatusNotFound, "code_not_found", "no machine is waiting with that code; check it and try again")
		return
	}
	if err != nil {
		s.log.Error("cloudserver/api: connect code lookup", "err", err)
		writeErr(w, http.StatusInternalServerError, "internal", "could not look up the code")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"request_id": id})
}

// connectResolveRule maps one store refusal of an approval to its answer.
type connectResolveRule struct {
	err     error
	status  int
	code    string
	message string
}

// connectResolveRules are the approval refusals, in the order checked.
var connectResolveRules = []connectResolveRule{
	{store.ErrNotFound, http.StatusNotFound, "not_found", "connect request not found"},
	{store.ErrConnectNotPending, http.StatusConflict, "not_pending", "this request was already answered or has expired"},
	{store.ErrConnectTargetUnavailable, http.StatusConflict, "target_unavailable", "that dashboard cannot take a machine right now"},
	{store.ErrConnectDisclosureStale, http.StatusConflict, "disclosure_changed", "what this dashboard shares has changed; reload the page"},
	{store.ErrConnectAnswerNotAllowed, http.StatusBadRequest, "answer_not_allowed", "an SDK key needs a dashboard: choose one, or decline"},
}

// resolveConnect applies one browser answer and writes the request's new view.
func (s *Server) resolveConnect(w http.ResponseWriter, r *http.Request, in store.ResolveConnectInput, event string) {
	c, err := s.store.ResolveConnectRequest(r.Context(), in)
	for _, rule := range connectResolveRules {
		if errors.Is(err, rule.err) {
			writeErr(w, rule.status, rule.code, rule.message)
			return
		}
	}
	if err != nil {
		s.log.Error("cloudserver/api: resolve connect request", "err", err)
		writeErr(w, http.StatusInternalServerError, "internal", "could not answer the request")
		return
	}
	s.audit(r.Context(), in.AccountID, event)
	v, err := s.connectView(r, in.AccountID, c)
	if err != nil {
		s.log.Error("cloudserver/api: connect request view", "err", err)
		writeErr(w, http.StatusInternalServerError, "internal", "could not read the request")
		return
	}
	writeJSON(w, http.StatusOK, v)
}

// handlePortalConnectApprove is POST .../approve: Connect with
// {target_org_id, disclosure_version, disclosure_sha256}, or Not now with an
// empty target_org_id. Either signs the machine in, so an account that holds
// a passkey must have used it in this session (the "Approve a device" rule,
// portalmfa.ActionApproveDevice); the approval is then that device's approval.
func (s *Server) handlePortalConnectApprove(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	p, _ := portalPrincipalFrom(r.Context())
	if st, _ := secondFactorFrom(r.Context()); st.ActivePasskeys > 0 &&
		!s.portalMFADecision(w, r, portalmfa.ActionApproveDevice) {
		return
	}
	var req struct {
		TargetOrgID       string `json:"target_org_id"`
		DisclosureVersion string `json:"disclosure_version"`
		DisclosureSHA256  string `json:"disclosure_sha256"`
	}
	if !readSmallJSON(w, r, &req) {
		return
	}
	c, ok := s.connectRequestForCaller(w, r, p.AccountID)
	if !ok {
		return
	}
	if req.TargetOrgID != "" && !s.connectTargetPlanAllows(w, r, c, p.AccountID, req.TargetOrgID) {
		return
	}
	in := store.ResolveConnectInput{
		AccountID: p.AccountID, SessionID: p.SessionID, RequestID: r.PathValue("id"),
		Event: connectflow.EventNotNow, Now: s.now(),
	}
	event := "connect_not_now"
	if req.TargetOrgID != "" {
		in.Event = connectflow.EventConnect
		in.TargetOrgID = req.TargetOrgID
		in.DisclosureVersion = req.DisclosureVersion
		in.DisclosureSHA256 = req.DisclosureSHA256
		event = "connect_approved"
	}
	s.resolveConnect(w, r, in, event)
}

// connectTargetPlanAllows refuses an SDK key approval whose dashboard's plan
// does not include AI Apps (409 plan_required with the plan refusal's
// message), so no grant is ever signed for a key the host would refuse. It
// reports whether the approval may go on; any other purpose, or a dashboard
// that is not the caller's (the store refuses that), goes on.
func (s *Server) connectTargetPlanAllows(w http.ResponseWriter, r *http.Request, c store.ConnectRequest, accountID, orgID string) bool {
	if answer, _ := connectflow.AnswerFor(c.Purpose); answer != connectflow.AnswerKeyGrant {
		return true
	}
	orgs, err := s.store.ListMyOrgs(r.Context(), accountID)
	if err != nil {
		s.log.Error("cloudserver/api: connect approve: list orgs", "err", err)
		writeErr(w, http.StatusInternalServerError, "internal", "could not read your dashboards")
		return false
	}
	for _, o := range orgs {
		if o.OrgID != orgID {
			continue
		}
		v, err := s.sdkPlanFor(r.Context(), accountID, o)
		if err != nil {
			s.log.Error("cloudserver/api: connect approve: read plan", "err", err)
			writeErr(w, http.StatusInternalServerError, "internal", "could not read the dashboard's plan")
			return false
		}
		if v.Refused {
			s.audit(r.Context(), accountID, "connect_sdk_key_plan_refused")
			writeErr(w, http.StatusConflict, connectPlanRequiredCode, v.Message)
			return false
		}
		return true
	}
	return true
}

// handlePortalConnectDecline is POST .../decline ("This is not my machine").
func (s *Server) handlePortalConnectDecline(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	p, _ := portalPrincipalFrom(r.Context())
	if _, ok := s.connectRequestForCaller(w, r, p.AccountID); !ok {
		return
	}
	s.resolveConnect(w, r, store.ResolveConnectInput{
		AccountID: p.AccountID, SessionID: p.SessionID, RequestID: r.PathValue("id"),
		Event: connectflow.EventDecline, Now: s.now(),
	}, "connect_declined")
}

// connectMachineJSON is one recent approval on the account home.
type connectMachineJSON struct {
	RequestID   string             `json:"request_id"`
	MachineName string             `json:"machine_name"`
	OS          string             `json:"os"`
	ApprovedAt  string             `json:"approved_at"`
	Target      *connectTargetJSON `json:"target"`
	// OpenURL opens the dashboard the machine connected to (tenantLink).
	OpenURL string `json:"open_url,omitempty"`
	// OnlineURL is OpenURL under its first name, kept for one release.
	//
	// Deprecated: read open_url.
	OnlineURL string `json:"online_url,omitempty"`
}

// handlePortalConnectMachines is GET /portal/api/connect/machines: the
// account's signed-in machine count and its approvals of the last
// connectflow.ApprovedRetention, newest first. The account home polls it while
// it waits for a first machine.
func (s *Server) handlePortalConnectMachines(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	p, _ := portalPrincipalFrom(r.Context())
	home, err := s.store.ConnectHomeState(r.Context(), p.AccountID, s.now().Add(-connectflow.ApprovedRetention))
	if err != nil {
		s.log.Error("cloudserver/api: connect machines", "err", err)
		writeErr(w, http.StatusInternalServerError, "internal", "could not list your machines")
		return
	}
	recent := make([]connectMachineJSON, 0, len(home.Recent))
	for _, c := range home.Recent {
		open := s.connectOpenURL(c.Purpose, c.Target)
		recent = append(recent, connectMachineJSON{
			RequestID: c.RequestID, MachineName: c.MachineName, OS: c.OS,
			ApprovedAt: rfc3339(c.ResolvedAt), Target: connectTarget(c.Target),
			OpenURL: open, OnlineURL: open,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"devices": home.Devices, "recent": recent})
}
