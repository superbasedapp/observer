package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/store"
	"github.com/marmutapp/superbased-observer/internal/platformcontract"
)

// portal_orgs.go is the webcloud console's org BFF (managed-SaaS plan 07
// M6.5; design docs/plans/managed-saas/m6.0-control-plane-design-2026-11-13.md
// 4.7; wave 14 lane front-door; wave 15 lane console-fixes; docs/security.md
// PORTALORG-1, -2, -7, -8, -10).
//
//	GET   /portal/api/orgs                      the caller's orgs (account home)
//	POST  /portal/api/orgs                      create a team org
//	POST  /portal/api/orgs/personal             find or create the personal org (portal_personal.go)
//	GET   /portal/api/orgs/slug-availability    is a slug free (?slug=)
//	GET   /portal/api/orgs/{id}                 one org: provisioning, plan, seats, links
//	PATCH /portal/api/orgs/{id}                 rename (display name only)
//	GET   /portal/api/orgs/{id}/billing         org billing (portal_orgs_billing.go)
//	POST  /portal/api/orgs/{id}/billing/checkout
//
// Every route sits behind portalAuth: the session cookie, the per-account
// rate limit, and for a mutation the exact portal Origin and the double-submit
// X-SBCI-CSRF check, exactly as every other portal route. None is CORS: the
// one cross-origin portal read stays GET /portal/api/me/orgs (meorgs.go).
//
// Create never reaches a host. It runs the store's provisioning transaction
// (store.ProvisionOrg): the org, the caller's owner and billing-owner
// membership, the slug, and the EXISTING create_tenant intent in org_outbox,
// all in one transaction. The worker sends the intent (hostclient); this file
// only reads its progress back (the 0091 status read), including a create the
// host put on its capacity waitlist.
//
// The browser never composes a tenant host: every host and link in a response
// is built here from the org's slug and Options.TenantDomain, and omitted when
// no tenant domain is configured.

// The tenant dashboard pages the console links to, and the one function that
// composes those links, live in tenantlink.go.

// createTeamTenancy is the tenancy of a team org created from the console:
// managed (an enterprise team's nodes ship full content by grant; CLAUDE.md
// "Teams / org-server invariants"). The console offers no choice, and the
// "Create a team" page says so before the create (C2.front-door-2).
const createTeamTenancy = store.TenancyManaged

// createReplayWindow bounds how long a repeated create of the same slug and
// name by the same caller answers as the original (a double-submit, a retry
// after a lost response) instead of slug_taken.
const createReplayWindow = 15 * time.Minute

// mountPortalOrgs registers the console org routes on mux.
func (s *Server) mountPortalOrgs(mux *http.ServeMux) {
	mux.Handle("GET /portal/api/orgs", s.portalAuth(http.HandlerFunc(s.handlePortalListOrgs)))
	mux.Handle("POST /portal/api/orgs", s.portalAuth(http.HandlerFunc(s.handlePortalCreateTeam)))
	// The lazy personal org (D-IND-1; portal_personal.go).
	mux.Handle("POST /portal/api/orgs/personal", s.portalAuth(http.HandlerFunc(s.handlePortalEnsurePersonal)))
	mux.Handle("GET /portal/api/orgs/slug-availability", s.portalAuth(http.HandlerFunc(s.handlePortalSlugAvailability)))
	mux.Handle("GET /portal/api/orgs/{id}", s.portalAuth(http.HandlerFunc(s.handlePortalGetOrg)))
	mux.Handle("PATCH /portal/api/orgs/{id}", s.portalAuth(http.HandlerFunc(s.handlePortalRenameOrg)))
	mux.Handle("GET /portal/api/orgs/{id}/billing", s.portalAuth(http.HandlerFunc(s.handlePortalOrgBilling)))
	mux.Handle("POST /portal/api/orgs/{id}/billing/checkout", s.portalAuth(http.HandlerFunc(s.handlePortalOrgCheckout)))
	mux.Handle("POST /portal/api/orgs/{id}/billing/portal-session", s.portalAuth(http.HandlerFunc(s.handlePortalOrgBillingPortalSession)))
}

// --- views -------------------------------------------------------------

// portalOrgJSON is one org as the console shows it.
type portalOrgJSON struct {
	OrgID          string `json:"org_id"`
	Slug           string `json:"slug"`
	DisplayName    string `json:"display_name"`
	Kind           string `json:"kind"`
	Status         string `json:"status"`
	Tenancy        string `json:"tenancy"`
	ConsoleRole    string `json:"console_role"`
	IsBillingOwner bool   `json:"is_billing_owner"`
	CreatedAt      string `json:"created_at"`
	// Host is <slug>.<tenant domain>; empty when no tenant domain is set.
	Host string `json:"host,omitempty"`
	// MachinesPageURL is the tenant page listing the caller's own machines
	// in this org, for an active org with a host (C2.front-door-4 B).
	MachinesPageURL string `json:"machines_page_url,omitempty"`
	// OpenURL opens the org's dashboard, for an active org with a host
	// (every "Open your dashboard" button; a personal dashboard's address is
	// opened from buttons only, never shown). Built by tenantLink.
	OpenURL string `json:"open_url,omitempty"`
	// DashboardURL is OpenURL under its first name, kept for one release so
	// a console bundle older than open_url keeps working (additive wire).
	//
	// Deprecated: read open_url.
	DashboardURL string `json:"dashboard_url,omitempty"`
	// InviteURL is the team dashboard's invite page, for an active team
	// with a host (the account home's "Invite people").
	InviteURL string `json:"invite_url,omitempty"`
	// Members is the member count of the team's latest usage report, on the
	// org list only; absent before the first report.
	Members *int64 `json:"members,omitempty"`
	// Provisioning is set while the org is being created.
	Provisioning *provisioningJSON `json:"provisioning,omitempty"`
}

// provisioningJSON is the progress of an org's create.
type provisioningJSON struct {
	// Stage is the console's one word (provisioningRules).
	Stage          string `json:"stage"`
	State          string `json:"state,omitempty"`
	Attempts       int    `json:"attempts"`
	LastErrorClass string `json:"last_error_class,omitempty"`
	NextAttemptAt  string `json:"next_attempt_at,omitempty"`
	QueuedAt       string `json:"queued_at,omitempty"`
	// CreatedOnHostAt is when the host acked the create (the launch window's
	// start).
	CreatedOnHostAt string `json:"created_on_host_at,omitempty"`
}

// orgCapsJSON says what the caller may do with the org.
type orgCapsJSON struct {
	Rename      bool `json:"rename"`
	ViewBilling bool `json:"view_billing"`
	Checkout    bool `json:"checkout"`
}

// orgDetailJSON is GET /portal/api/orgs/{id}.
type orgDetailJSON struct {
	Org portalOrgJSON `json:"org"`
	// LaunchURL is the tenant's "Connect a machine" page, once the tenant
	// exists and a tenant domain is configured.
	LaunchURL string        `json:"launch_url,omitempty"`
	Plan      *orgPlanJSON  `json:"plan,omitempty"`
	Seats     *orgSeatsJSON `json:"seats,omitempty"`
	Can       orgCapsJSON   `json:"can"`
	// Replayed is true when a repeated create answered with the org the
	// first one made (createReplay).
	Replayed bool `json:"replayed,omitempty"`
}

// orgSeatsJSON is the latest usage day the tenant reported.
type orgSeatsJSON struct {
	InUse   int    `json:"in_use"`
	Members int64  `json:"members"`
	Day     string `json:"day"`
}

func rfc3339(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

// tenantHost is <slug>.<tenant domain>, or "" with no tenant domain.
func (s *Server) tenantHost(slug string) string {
	if s.tenantDomain == "" || slug == "" {
		return ""
	}
	return slug + "." + s.tenantDomain
}

func (s *Server) orgJSON(o store.MyOrg) portalOrgJSON {
	v := portalOrgJSON{
		OrgID: o.OrgID, Slug: o.Slug, DisplayName: o.DisplayName,
		Kind: string(o.Kind), Status: string(o.Status), Tenancy: string(o.Tenancy),
		ConsoleRole: string(o.ConsoleRole), IsBillingOwner: o.IsBillingOwner,
		CreatedAt: rfc3339(o.CreatedAt), Host: s.tenantHost(o.Slug),
	}
	if v.Host != "" && o.Status == platformcontract.StateActive {
		v.MachinesPageURL = s.tenantLink(o.Slug, tenantPageMachines)
		v.OpenURL = s.tenantLink(o.Slug, tenantPageDashboard)
		v.DashboardURL = v.OpenURL
		if o.Kind == store.OrgTeam {
			v.InviteURL = s.tenantLink(o.Slug, tenantPageInvites)
		}
	}
	return v
}

// teamOrgsJSON is the caller's team org count against its cap (W15-D12), so
// the console can say before a create that the cap is reached.
type teamOrgsJSON struct {
	Used      int `json:"used"`
	Limit     int `json:"limit"`
	Remaining int `json:"remaining"`
	// InviteOnly is true while the team create allow-list is on (W17,
	// portal_teamallowlist.go); CreateAllowed then says whether this
	// account is on it. With the switch off CreateAllowed is always true.
	InviteOnly    bool `json:"invite_only"`
	CreateAllowed bool `json:"create_allowed"`
	// AccountRef is the caller's own account id, set only when a team
	// create would be refused as invite-only, so the console can say what
	// to quote to support.
	AccountRef string `json:"account_ref,omitempty"`
}

// --- the provisioning stage (a rule table) ---------------------------------

// provisioningFacts is one org's create, read once.
type provisioningFacts struct {
	status platformcontract.TenantState
	found  bool
	cs     store.OrgCreateStatus
}

// provisioningRule is one row of provisioningRules.
type provisioningRule struct {
	stage string
	match func(f provisioningFacts) bool
}

// waitlistErrorClass is the outbox class of a create the host put on its
// capacity waitlist (cloudserver/hostapi judge.go, W14-D4).
const waitlistErrorClass = "refused:capacity_waitlist"

// provisioningRules names an org's create stage, walked top-down, first
// match wins; the last row matches everything. One test case per row
// (portal_orgs_internal_test.go).
var provisioningRules = []provisioningRule{
	{stage: "ready", match: func(f provisioningFacts) bool {
		return f.status == platformcontract.StateActive || f.status == platformcontract.StateSuspended
	}},
	{stage: "closing", match: func(f provisioningFacts) bool { return f.status != platformcontract.StateProvisioning }},
	{stage: "unknown", match: func(f provisioningFacts) bool { return !f.found }},
	{stage: "failed", match: func(f provisioningFacts) bool { return f.cs.State == "failed" }},
	{stage: "finishing", match: func(f provisioningFacts) bool { return f.cs.State == "acked" }},
	{stage: "waitlisted", match: func(f provisioningFacts) bool { return f.cs.LastErrorClass == waitlistErrorClass }},
	{stage: "queued", match: func(f provisioningFacts) bool { return f.cs.Attempts == 0 }},
	{stage: "retrying", match: func(f provisioningFacts) bool { return f.cs.LastErrorClass != "" }},
	{stage: "creating", match: func(provisioningFacts) bool { return true }},
}

// provisioningStage walks provisioningRules.
func provisioningStage(f provisioningFacts) string {
	for _, r := range provisioningRules {
		if r.match(f) {
			return r.stage
		}
	}
	return "creating" // unreachable: the last row matches everything
}

// provisioning reads an org's create and names its stage. A failed read is
// logged and reported as the "unknown" stage, never as an error of the
// whole page.
func (s *Server) provisioning(r *http.Request, accountID string, o store.MyOrg) (*provisioningJSON, store.OrgCreateStatus, bool) {
	cs, err := s.store.OrgCreateStatus(r.Context(), accountID, o.OrgID)
	found := err == nil
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		s.log.Error("cloudserver/api: org create status", "err", err)
	}
	p := &provisioningJSON{Stage: provisioningStage(provisioningFacts{status: o.Status, found: found, cs: cs})}
	if found {
		p.State, p.Attempts, p.LastErrorClass = cs.State, cs.Attempts, cs.LastErrorClass
		p.QueuedAt = rfc3339(cs.CreatedAt)
		if cs.State == "pending" || cs.State == "sent" {
			p.NextAttemptAt = rfc3339(cs.NextAttemptAt)
		}
		if cs.State == "acked" && cs.DoneAt != nil {
			p.CreatedOnHostAt = rfc3339(*cs.DoneAt)
		}
	}
	return p, cs, found
}

// --- handlers ----------------------------------------------------------

// handlePortalListOrgs is GET /portal/api/orgs: every org the caller belongs
// to, oldest first, with the create stage of any still being created.
func (s *Server) handlePortalListOrgs(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	p, _ := portalPrincipalFrom(r.Context())
	orgs, err := s.store.ListMyOrgs(r.Context(), p.AccountID)
	if err != nil {
		s.log.Error("cloudserver/api: list orgs", "err", err)
		writeErr(w, http.StatusInternalServerError, "internal", "could not list orgs")
		return
	}
	out := make([]portalOrgJSON, 0, len(orgs))
	for _, o := range orgs {
		v := s.orgJSON(o)
		if o.Status == platformcontract.StateProvisioning {
			v.Provisioning, _, _ = s.provisioning(r, p.AccountID, o)
		}
		if o.Kind == store.OrgTeam {
			if seats, err := s.store.OrgSeatsInUse(r.Context(), p.AccountID, o.OrgID); err == nil {
				m := seats.Members
				v.Members = &m
			} else if !errors.Is(err, store.ErrNotFound) {
				s.log.Error("cloudserver/api: org members", "err", err)
			}
		}
		out = append(out, v)
	}
	resp := map[string]any{"orgs": out, "tenant_domain": s.tenantDomain}
	// Getting started v2: "Create a team" shows the price before the
	// create. The first configured team price of the catalogue, if any.
	if kind, ok := store.OrgEntitlementsKind(store.OrgTeam); ok {
		if prices := s.checkoutPricesFor(kind); len(prices) > 0 {
			resp["team_price"] = map[string]string{"display": prices[0].Display, "interval": prices[0].Interval}
		}
	}
	if a, err := s.store.TeamOrgAllowance(r.Context(), p.AccountID); err == nil {
		t := teamOrgsJSON{Used: a.Used, Limit: a.Limit, Remaining: a.Remaining()}
		t.InviteOnly, t.CreateAllowed = s.teamCreateAllowedFor(r, p.AccountID)
		if !t.CreateAllowed {
			t.AccountRef = p.AccountID
		}
		resp["team_orgs"] = t
	} else {
		// The create route enforces the cap itself; the list stays useful
		// without the count.
		s.log.Error("cloudserver/api: team org allowance", "err", err)
	}
	writeJSON(w, http.StatusOK, resp)
}

// slugAvailabilityJSON is GET /portal/api/orgs/slug-availability.
type slugAvailabilityJSON struct {
	Slug      string `json:"slug"`
	Available bool   `json:"available"`
	// Reason is "" when available, else invalid | reserved | taken.
	Reason string `json:"reason,omitempty"`
	Host   string `json:"host,omitempty"`
}

// normalizeSlugInput trims and lower-cases a typed slug (the slug grammar is
// lower case; the console sends what the user typed).
func normalizeSlugInput(raw string) string { return strings.ToLower(strings.TrimSpace(raw)) }

// slugRefusalReason maps a ValidateOrgSlug error to the console's reason.
func slugRefusalReason(err error) string {
	if errors.Is(err, store.ErrOrgSlugReserved) {
		return "reserved"
	}
	return "invalid"
}

// handlePortalSlugAvailability answers whether a slug is free for a new team
// org: the shape rules and the reserved list first (no database read), then
// the registry through the 0091 definer.
func (s *Server) handlePortalSlugAvailability(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	p, _ := portalPrincipalFrom(r.Context())
	slug := normalizeSlugInput(r.URL.Query().Get("slug"))
	out := slugAvailabilityJSON{Slug: slug}
	if err := store.ValidateOrgSlug(slug, store.OrgTeam); err != nil {
		out.Reason = slugRefusalReason(err)
		writeJSON(w, http.StatusOK, out)
		return
	}
	ok, err := s.store.OrgSlugAvailable(r.Context(), p.AccountID, slug)
	if err != nil {
		s.log.Error("cloudserver/api: slug availability", "err", err)
		writeErr(w, http.StatusInternalServerError, "internal", "could not check the slug")
		return
	}
	out.Available = ok
	if !ok {
		out.Reason = "taken"
	}
	out.Host = s.tenantHost(slug)
	writeJSON(w, http.StatusOK, out)
}

// createTeamRequest is POST /portal/api/orgs.
type createTeamRequest struct {
	DisplayName string `json:"display_name"`
	Slug        string `json:"slug"`
}

// createErrors maps a provisioning refusal to the console's answer, walked
// top-down.
var createErrors = []struct {
	err    error
	status int
	code   string
	msg    string
}{
	{store.ErrOrgSlugReserved, http.StatusBadRequest, "slug_reserved", "that name is reserved; choose another"},
	{store.ErrOrgSlugInvalid, http.StatusBadRequest, "slug_invalid", "the address must be 3 to 40 lowercase letters, digits or single hyphens, not starting with u-"},
	{store.ErrOrgSlugTaken, http.StatusConflict, "slug_taken", "that address is taken"},
	{store.ErrOrgInputInvalid, http.StatusBadRequest, "display_name_invalid", "the team name must be 1 to 100 characters"},
}

// teamOrgLimitMessage words a create past the cap (W15-D12): the cap, and
// that it is raised on request.
func teamOrgLimitMessage(limit int) string {
	if limit <= 0 {
		return "this account cannot create team orgs. Contact support if you need one."
	}
	plural := "s"
	if limit == 1 {
		plural = ""
	}
	return fmt.Sprintf("you already have %d team org%s, the most one account can create. "+
		"We can raise this on request: contact support with how many you need.", limit, plural)
}

// readSmallJSON decodes a small JSON body into v.
func readSmallJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 64<<10))
	if err != nil {
		writeErr(w, http.StatusRequestEntityTooLarge, "body_too_large", "request body too large")
		return false
	}
	if err := json.Unmarshal(body, v); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "invalid JSON body")
		return false
	}
	return true
}

// handlePortalCreateTeam is POST /portal/api/orgs: create a team org. It
// writes the org and enqueues its create_tenant intent in one transaction
// (store.ProvisionOrg) and returns at once; the worker creates the tenant.
func (s *Server) handlePortalCreateTeam(w http.ResponseWriter, r *http.Request) {
	p, _ := portalPrincipalFrom(r.Context())
	var req createTeamRequest
	if !readSmallJSON(w, r, &req) {
		return
	}
	slug := normalizeSlugInput(req.Slug)
	in := store.ProvisionOrgInput{
		Kind: store.OrgTeam, Slug: slug, DisplayName: req.DisplayName, Tenancy: createTeamTenancy, TenantDomain: s.tenantDomain,
		TeamAllowlist: s.teamCreateAllowlist,
	}
	org, err := s.store.ProvisionOrg(r.Context(), p.AccountID, in)
	// A repeat of a create that went through (a double submit, a retry after
	// a lost response) answers the first org, whether the repeat met the
	// slug's unique key or the cap the first create just filled.
	if errors.Is(err, store.ErrOrgSlugTaken) || errors.Is(err, store.ErrTeamOrgLimit) {
		if prior, ok := s.createReplay(r, p.AccountID, slug, req.DisplayName); ok {
			s.writeOrgDetail(w, r, p.AccountID, prior, http.StatusOK, true)
			return
		}
	}
	if errors.Is(err, store.ErrTeamCreateNotAllowed) {
		s.audit(r.Context(), p.AccountID, "portal_org_create_invite_only")
		writeTeamCreateInviteOnly(w, p.AccountID)
		return
	}
	var capErr *store.TeamOrgLimitError
	if errors.As(err, &capErr) {
		s.audit(r.Context(), p.AccountID, "portal_org_create_capped")
		writeErr(w, http.StatusConflict, "team_org_limit", teamOrgLimitMessage(capErr.Limit))
		return
	}
	if err != nil {
		for _, m := range createErrors {
			if errors.Is(err, m.err) {
				writeErr(w, m.status, m.code, m.msg)
				return
			}
		}
		s.log.Error("cloudserver/api: create team org", "err", err)
		writeErr(w, http.StatusInternalServerError, "internal", "could not create the team")
		return
	}
	s.audit(r.Context(), p.AccountID, "portal_org_created")
	s.writeOrgDetail(w, r, p.AccountID, org, http.StatusCreated, false)
}

// createReplay finds the caller's own org that a repeated create names: the
// same slug, created by the caller, still provisioning, the same display
// name, and recent. Anything else is a real slug_taken.
func (s *Server) createReplay(r *http.Request, accountID, slug, displayName string) (store.MyOrg, bool) {
	orgs, err := s.store.ListMyOrgs(r.Context(), accountID)
	if err != nil {
		return store.MyOrg{}, false
	}
	for _, o := range orgs {
		if o.Slug == slug && o.CreatedBy == accountID && o.Status == platformcontract.StateProvisioning &&
			o.DisplayName == strings.TrimSpace(displayName) && s.now().Sub(o.CreatedAt) <= createReplayWindow {
			return o, true
		}
	}
	return store.MyOrg{}, false
}

// handlePortalGetOrg is GET /portal/api/orgs/{id}.
func (s *Server) handlePortalGetOrg(w http.ResponseWriter, r *http.Request) {
	p, _ := portalPrincipalFrom(r.Context())
	org, err := s.store.GetOrg(r.Context(), p.AccountID, r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		writeErr(w, http.StatusNotFound, "not_found", "org not found")
		return
	}
	if err != nil {
		s.log.Error("cloudserver/api: get org", "err", err)
		writeErr(w, http.StatusInternalServerError, "internal", "could not read the org")
		return
	}
	s.writeOrgDetail(w, r, p.AccountID, org, http.StatusOK, false)
}

// orgCaps is what a caller may do with org o. Billing is for an owner, an
// admin or the billing owner (the 0091 subscription read checks the same);
// checkout is the billing owner's alone.
func orgCaps(o store.MyOrg) orgCapsJSON {
	admin := o.ConsoleRole == store.ConsoleOwner || o.ConsoleRole == store.ConsoleAdmin
	return orgCapsJSON{
		Rename:      admin && (o.Status == platformcontract.StateActive || o.Status == platformcontract.StateSuspended),
		ViewBilling: admin || o.IsBillingOwner,
		Checkout:    o.IsBillingOwner && o.Kind == store.OrgTeam,
	}
}

// writeOrgDetail builds and writes the org detail view.
func (s *Server) writeOrgDetail(w http.ResponseWriter, r *http.Request, accountID string, o store.MyOrg, status int, replayed bool) {
	w.Header().Set("Cache-Control", "no-store")
	view := orgDetailJSON{Org: s.orgJSON(o), Can: orgCaps(o), Replayed: replayed}
	prov, cs, found := s.provisioning(r, accountID, o)
	if o.Status == platformcontract.StateProvisioning {
		view.Org.Provisioning = prov
	}
	if o.Status == platformcontract.StateActive {
		view.LaunchURL = s.tenantLink(o.Slug, tenantPageInstall)
	}
	if view.Can.ViewBilling {
		var createdOnHost time.Time
		if found && cs.State == "acked" && cs.DoneAt != nil {
			createdOnHost = *cs.DoneAt
		}
		if pl, err := s.orgPlan(r, accountID, o, createdOnHost); err == nil {
			view.Plan = pl
		} else {
			s.log.Error("cloudserver/api: org plan", "err", err)
		}
	}
	if seats, err := s.store.OrgSeatsInUse(r.Context(), accountID, o.OrgID); err == nil {
		view.Seats = &orgSeatsJSON{InUse: seats.Seats, Members: seats.Members, Day: seats.Day.UTC().Format("2006-01-02")}
	} else if !errors.Is(err, store.ErrNotFound) {
		s.log.Error("cloudserver/api: org seats", "err", err)
	}
	writeJSON(w, status, view)
}

// renameOrgRequest is PATCH /portal/api/orgs/{id}. Slug is accepted only to
// refuse it by name.
type renameOrgRequest struct {
	DisplayName *string `json:"display_name"`
	Slug        *string `json:"slug"`
}

// renameErrors maps a rename refusal to the console's answer.
var renameErrors = []struct {
	err    error
	status int
	code   string
	msg    string
}{
	{store.ErrNotFound, http.StatusNotFound, "not_found", "org not found"},
	{store.ErrOrgRenameForbidden, http.StatusForbidden, "forbidden", "only an org owner or admin may rename the org"},
	{store.ErrOrgProvisioning, http.StatusConflict, "org_provisioning", "the team is still being created; rename it once it is ready"},
	{store.ErrOrgNotRenamable, http.StatusConflict, "org_not_renamable", "the org can no longer be renamed"},
	{store.ErrOrgInputInvalid, http.StatusBadRequest, "display_name_invalid", "the team name must be 1 to 100 characters"},
}

// handlePortalRenameOrg is PATCH /portal/api/orgs/{id}: a new display name.
// Refused while the org is still being created (store.ErrOrgProvisioning).
func (s *Server) handlePortalRenameOrg(w http.ResponseWriter, r *http.Request) {
	p, _ := portalPrincipalFrom(r.Context())
	var req renameOrgRequest
	if !readSmallJSON(w, r, &req) {
		return
	}
	if req.Slug != nil {
		writeErr(w, http.StatusBadRequest, "slug_rename_unsupported", "the team's address cannot be changed here")
		return
	}
	if req.DisplayName == nil {
		writeErr(w, http.StatusBadRequest, "display_name_invalid", "display_name is required")
		return
	}
	org, err := s.store.RenameOrg(r.Context(), p.AccountID, r.PathValue("id"), *req.DisplayName)
	if err != nil {
		for _, m := range renameErrors {
			if errors.Is(err, m.err) {
				writeErr(w, m.status, m.code, m.msg)
				return
			}
		}
		s.log.Error("cloudserver/api: rename org", "err", err)
		writeErr(w, http.StatusInternalServerError, "internal", "could not rename the org")
		return
	}
	s.audit(r.Context(), p.AccountID, "portal_org_renamed")
	s.writeOrgDetail(w, r, p.AccountID, org, http.StatusOK, false)
}

// --- account deletion and the orgs the account pays for -----------------

// paidOrgJSON is one org a deleting account pays for. Slug, name and link
// are empty for an org the account can no longer see.
type paidOrgJSON struct {
	OrgID       string `json:"org_id"`
	Slug        string `json:"slug,omitempty"`
	DisplayName string `json:"display_name,omitempty"`
}

// paysForLiveOrgJSON is the 409 body of a refused account deletion
// (C2.front-door-5 A): the usual error and code, plus the orgs.
type paysForLiveOrgJSON struct {
	Error string        `json:"error"`
	Code  string        `json:"code"`
	Orgs  []paidOrgJSON `json:"orgs"`
}

// paysForLiveOrgCode is the refusal's code (webcloud words it).
const paysForLiveOrgCode = "pays_for_live_org"

// writePaysForLiveOrg answers a deletion of an account that pays for a live
// org: 409 with a message naming the orgs and what to do first.
func writePaysForLiveOrg(w http.ResponseWriter, orgs []store.PaidLiveOrg) {
	names := make([]string, 0, len(orgs))
	body := paysForLiveOrgJSON{Code: paysForLiveOrgCode, Orgs: make([]paidOrgJSON, 0, len(orgs))}
	for _, o := range orgs {
		body.Orgs = append(body.Orgs, paidOrgJSON{OrgID: o.OrgID, Slug: o.Slug, DisplayName: o.DisplayName})
		if o.DisplayName != "" {
			names = append(names, o.DisplayName)
		}
	}
	what := "a team that is still live"
	if len(names) > 0 {
		what = "the team " + strings.Join(names, ", ")
		if len(names) > 1 {
			what = "the teams " + strings.Join(names, ", ")
		}
	}
	body.Error = "Your account pays for " + what + ", so it cannot be deleted yet. " +
		"Cancel that subscription from the team's billing page (or ask support to move the billing to another owner), then delete your account."
	writeJSON(w, http.StatusConflict, body)
}

// refuseDeletionWhilePaying answers 409 and returns false when the account
// pays for a live org, or has a live subscription the deletion would have to
// cancel at Paddle and this deployment cannot (ORGDEL-7). It is the early
// check, before a step-up the deletion would refuse anyway; the store
// re-checks inside the deletion. A failed read lets the request through to
// the store's own check.
func (s *Server) refuseDeletionWhilePaying(w http.ResponseWriter, r *http.Request, accountID string) bool {
	b, err := s.store.AccountDeletionBilling(r.Context(), accountID)
	if err != nil {
		s.log.Error("cloudserver/api: account deletion billing", "err", err)
		return true
	}
	if len(b.PaysFor) > 0 {
		s.audit(r.Context(), accountID, "deletion_refused_pays_for_org")
		writePaysForLiveOrg(w, b.PaysFor)
		return false
	}
	if b.Cancel > 0 && !b.CancelAvailable {
		s.audit(r.Context(), accountID, "deletion_refused_billing_cancel")
		writeBillingCancelRefused(w, store.BillingCancelUnavailable)
		return false
	}
	// M6.9: a team the account solely owns or is the billing owner of.
	return s.refuseDeletionBlockedByOrgs(w, r, accountID)
}

// deletionRefused answers a store refusal of a deletion: the account pays
// for a live org, a live subscription could not be canceled at Paddle
// (ORGDEL-7), or the account's orgs block it. false when err is none of
// them.
func (s *Server) deletionRefused(w http.ResponseWriter, r *http.Request, accountID string, err error) bool {
	var paid *store.PaysForLiveOrgError
	if errors.As(err, &paid) {
		s.audit(r.Context(), accountID, "deletion_refused_pays_for_org")
		writePaysForLiveOrg(w, paid.Orgs)
		return true
	}
	var cancel *store.BillingCancelError
	if errors.As(err, &cancel) {
		if cancel.Reason != store.BillingCancelUnavailable {
			// The class and the subscription id only; never Paddle's text.
			s.log.Warn("cloudserver/api: account deletion refused: a subscription was not canceled at Paddle",
				"reason", string(cancel.Reason), "class", cancel.Class, "subscription_id", cancel.SubscriptionID)
		}
		s.audit(r.Context(), accountID, "deletion_refused_billing_cancel")
		writeBillingCancelRefused(w, cancel.Reason)
		return true
	}
	return s.accountDeletionBlocked(w, r, accountID, err) // M6.9
}

// billingCancelAnswer is the console's answer to an account deletion refused
// because a live subscription was not canceled at Paddle (ORGDEL-7). In
// every case nothing was deleted and a step-up was not spent, so the same
// request can be sent again.
type billingCancelAnswer struct {
	status int
	code   string
	msg    string
	// retryAfter, when non-zero, is the Retry-After header in seconds.
	retryAfter int
}

// billingCancelAnswers is one answer per store.BillingCancelReason.
var billingCancelAnswers = map[store.BillingCancelReason]billingCancelAnswer{
	store.BillingCancelUnavailable: {
		status: http.StatusConflict, code: billingCancelUnavailableRefusal,
		msg: "Your account has a subscription that is still billing, and it cannot be canceled from here right now, so nothing was deleted. " +
			"Cancel the subscription from your billing page (or the link in Paddle's receipt email), then delete your account.",
	},
	store.BillingCancelRefused: {
		status: http.StatusConflict, code: "billing_cancel_refused",
		msg: "Paddle refused to cancel your subscription, so nothing was deleted. " +
			"Cancel it from your billing page or contact support, then delete your account.",
	},
	store.BillingCancelFailed: {
		status: http.StatusServiceUnavailable, code: "billing_cancel_failed", retryAfter: 60,
		msg: "Your subscription could not be canceled at Paddle just now, so nothing was deleted. Try again in a minute.",
	},
	store.BillingCancelChanged: {
		status: http.StatusConflict, code: "billing_changed",
		msg: "Your billing changed while your account was being deleted, so nothing was deleted. Try again.",
	},
}

// writeBillingCancelRefused answers reason's refusal.
func writeBillingCancelRefused(w http.ResponseWriter, reason store.BillingCancelReason) {
	a, ok := billingCancelAnswers[reason]
	if !ok {
		a = billingCancelAnswers[store.BillingCancelFailed]
	}
	if a.retryAfter > 0 {
		w.Header().Set("Retry-After", strconv.Itoa(a.retryAfter))
	}
	writeErr(w, a.status, a.code, a.msg)
}
