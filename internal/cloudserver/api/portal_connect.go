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
	RequestID       string             `json:"request_id"`
	Status          string             `json:"status"`
	UserCode        string             `json:"user_code,omitempty"`
	MachineName     string             `json:"machine_name"`
	OS              string             `json:"os"`
	Arch            string             `json:"arch"`
	ObserverVersion string             `json:"observer_version"`
	CreatedAt       string             `json:"created_at"`
	AgeSeconds      int64              `json:"age_seconds"`
	ExpiresIn       int64              `json:"expires_in"`
	Network         connectNetworkJSON `json:"network"`
	// Choices are the dashboards the account may connect to (pending only),
	// personal first.
	Choices []connectChoiceJSON `json:"choices"`
	// Target is the chosen dashboard once approved.
	Target *connectTargetJSON `json:"target"`
	// OpenURL opens the chosen dashboard (a button, never text), built by
	// tenantLink.
	OpenURL string `json:"open_url,omitempty"`
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

// connectOpenURL is the chosen dashboard's Open button target (tenantLink's
// dashboard page), or "" with no target.
func (s *Server) connectOpenURL(t *store.ConnectTarget) string {
	if t == nil {
		return ""
	}
	return s.tenantLink(t.Slug, tenantPageDashboard)
}

// connectChoices lists the dashboards the caller may connect a machine to:
// the personal dashboard (created here if the account has none yet; it may
// still be being set up) and every active team, the team whose slug is hint
// preselected, else the personal dashboard.
func (s *Server) connectChoices(r *http.Request, accountID, hint string) ([]connectChoiceJSON, error) {
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
		level, ok := connectflow.ShareLevelFor(connectflow.DashboardKind(o.Kind))
		if !ok {
			continue
		}
		d, _ := connectflow.Disclosure(level, o.DisplayName)
		c := connectChoiceJSON{
			OrgID: o.OrgID, Kind: string(o.Kind), DisplayName: o.DisplayName,
			Status: string(o.Status), ShareLevel: string(level), Disclosure: d,
		}
		if !personal {
			c.Slug = o.Slug // a team's address is its name; a personal one is never shown
			if hint != "" && o.Slug == hint {
				c.Preselected, hinted = true, true
			}
		}
		out = append(out, c)
	}
	if !hinted {
		for i := range out {
			if out[i].Kind == string(store.OrgPersonal) {
				out[i].Preselected = true
				break
			}
		}
	}
	return out, nil
}

// connectView builds the approval page's view of c for the caller.
func (s *Server) connectView(r *http.Request, accountID string, c store.ConnectRequest) (connectRequestViewJSON, error) {
	now := s.now()
	status := connectflow.EffectiveStatus(c.Status, c.ExpiresAt, now)
	ip, _ := edgeClientIP(r)
	v := connectRequestViewJSON{
		RequestID: c.RequestID, Status: string(status),
		MachineName: c.MachineName, OS: c.OS, Arch: c.Arch, ObserverVersion: c.ObserverVersion,
		CreatedAt:  rfc3339(c.CreatedAt),
		AgeSeconds: int64(now.Sub(c.CreatedAt) / time.Second),
		Network:    connectNetworkJSON{Prefix: c.OriginNetwork, SameAsYou: connectflow.SameNetwork(c.OriginNetwork, ip)},
		Choices:    []connectChoiceJSON{},
		Target:     connectTarget(c.Target),
	}
	v.OpenURL = s.connectOpenURL(c.Target)
	v.OnlineURL = v.OpenURL
	if status == connectflow.StatusPending {
		v.UserCode = c.UserCode
		v.ExpiresIn = int64(c.ExpiresAt.Sub(now) / time.Second)
		choices, err := s.connectChoices(r, accountID, c.TargetHint)
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
	if _, ok := s.connectRequestForCaller(w, r, p.AccountID); !ok {
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
		open := s.connectOpenURL(c.Target)
		recent = append(recent, connectMachineJSON{
			RequestID: c.RequestID, MachineName: c.MachineName, OS: c.OS,
			ApprovedAt: rfc3339(c.ResolvedAt), Target: connectTarget(c.Target),
			OpenURL: open, OnlineURL: open,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"devices": home.Devices, "recent": recent})
}
