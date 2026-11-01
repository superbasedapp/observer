package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/marmutapp/superbased-observer/internal/dashapi"
	"github.com/marmutapp/superbased-observer/internal/orgclient"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/orgenrol"
	"github.com/marmutapp/superbased-observer/internal/routeprov"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// enrolDashboard is the dashapi.EnrolmentManager: Settings > Enrolment's
// seam onto the SAME code paths `observer enroll`, `observer org status`,
// `observer org grant show`, `observer org push-now` and `observer unenroll`
// run (backlog item 6). Every method opens an org bundle exactly as the CLI
// does (buildOrgBundle) and calls the shared collectors / performers in
// orgreport.go, the shared grant writer (storeGrantOffer), the shared config
// writers (ensureOrgClientBlock / ensureManagedPolicyBlock) and the shared
// input resolver (resolveEnrolCredentials + internal/orgenrol). What is
// dashboard-specific is only the shape of the conversation:
//
//   - the CLI asks for governance consent mid-command on a TTY; the dashboard
//     parks the verified offer server-side (pendingOfferTTL) and asks on a
//     consent screen. An offer nobody answers expires, and the node stays
//     enrolled-but-ungoverned - exactly the CLI's no-TTY outcome;
//   - the CLI's --idp loop blocks and polls; the dashboard advances it one
//     poll at a time (PollIdP), with the device code kept server-side.
//
// The CLI's --wire-clients step (hooks + MCP + proxy routing for every
// detected AI client) is deliberately NOT run from here: those writes have
// their own per-write consent surface in Settings > Setup, and the outcome
// says so instead of rewriting AI-client configs from a single click.
type enrolDashboard struct {
	configPath string
	// pushLoop reports whether this process runs the org push loop (the
	// daemon built an org client at start). False: a fresh enrolment needs a
	// daemon restart before pushes start.
	pushLoop bool
	// bundle opens the org bundle; buildOrgBundle in production, a test
	// double in tests.
	bundle func(ctx context.Context) (orgBundle, error)
	now    func() time.Time
	// identityChanged, when set, drops the daemon's cached governance
	// identity (nodeGovernanceHandle.InvalidateIdentity) so an enrol, a
	// grant decision or a leave made here shows on /api/governance at once
	// instead of after the 15s refresh interval.
	identityChanged func()
	// retired, when set, tells the daemon's own org client that the
	// enrolment is gone, so the budget rail recomposes onto local numbers at
	// once instead of at the next push cycle (T-718). nil in a process with
	// no push loop.
	retired func(ctx context.Context)

	mu     sync.Mutex
	offers map[string]*pendingGrantOffer
	flows  map[string]*pendingIdPFlow
}

// pendingOfferTTL bounds how long a verified grant offer waits for a decision.
const pendingOfferTTL = 30 * time.Minute

type pendingGrantOffer struct {
	offer   *orgclient.GrantOffer
	expires time.Time
	view    dashapi.PendingGrant
}

type pendingIdPFlow struct {
	orgURL     string
	deviceCode string
	userCode   string
	deadline   time.Time
	interval   time.Duration
	nextPoll   time.Time
}

// newEnrolDashboard wires the manager for `observer start` / `observer
// dashboard`. configPath is the resolved config.toml path the daemon uses.
func newEnrolDashboard(configPath string, pushLoop bool) *enrolDashboard {
	return &enrolDashboard{
		configPath: configPath,
		pushLoop:   pushLoop,
		bundle: func(ctx context.Context) (orgBundle, error) {
			return buildOrgBundle(ctx, configPath)
		},
		now:    time.Now,
		offers: map[string]*pendingGrantOffer{},
		flows:  map[string]*pendingIdPFlow{},
	}
}

var _ dashapi.EnrolmentManager = (*enrolDashboard)(nil)

// enrolManagerFor is the one way a process builds its dashboard enrolment
// manager: it always wires the governance handle's InvalidateIdentity, so an
// enrol, grant decision or leave shows on /api/governance at once in every
// host (the daemon and the standalone `observer dashboard` alike). Sol A3-09:
// the standalone dashboard used to build the manager without the hook, so
// its governance kept the previous identity for up to the refresh interval.
func enrolManagerFor(configPath string, pushLoop bool, gov *nodeGovernanceHandle) *enrolDashboard {
	return newEnrolDashboard(configPath, pushLoop).withIdentityChanged(gov.InvalidateIdentity)
}

// withIdentityChanged sets the governance-invalidation hook (start.go wires
// the daemon's governance handle; the dashboard-only command has none).
func (d *enrolDashboard) withIdentityChanged(fn func()) *enrolDashboard {
	d.identityChanged = fn
	return d
}

// withRetire sets the leave hook (start.go passes the daemon's org client).
func (d *enrolDashboard) withRetire(c *orgclient.Client) *enrolDashboard {
	if c != nil {
		d.retired = c.RetireIdentity
	}
	return d
}

// changed runs the governance-invalidation hook. Deferred by every method
// that can write or remove the enrolment or its grant; a spurious call costs
// one indexed SELECT on the next governance read.
func (d *enrolDashboard) changed() {
	if d.identityChanged != nil {
		d.identityChanged()
	}
}

// plainDashes swaps the CLI's em-dashes for hyphens on the way to the
// dashboard (the UI copy rule).
func plainDashes(s string) string {
	return strings.ReplaceAll(s, "—", "-")
}

// dashboardCLIPointers turns the shared CLI lines' "see/run this command"
// pointers into the part of Settings > Enrolment that shows the same thing,
// so a CLI line reused on the page is never a dead end. Ordered, applied
// top-down (CLAUDE.md #5).
var dashboardCLIPointers = []struct{ cli, ui string }{
	{"Run `observer org grant show`.", "See \"What this organization can manage\" below."},
	{"see `observer org grant show`", "see \"What this organization can manage\" below"},
	{"see `observer org status`", "see Share mode on this page"},
	{"run `observer org backfill --all --confirm` to share the history", "use Share history below to share it"},
	// orgIntelPendingSentence (T-642): the enrol outcome note used to keep
	// these CLI commands and append a page pointer after them.
	{"Review them: `observer intel accept`.", "Review them in Settings, Org enrichment."},
	{"Accept (`observer intel accept`), or leave the organization (`observer unenroll`).", "Accept them in Settings, Org enrichment, or leave the organization with Leave organization below."},
}

// dashboardCopy is a shared CLI status line as UI copy: one sentence, the
// CLI column padding squeezed, plain hyphens, and the CLI pointers swapped
// for the on-page panel (dashboardCLIPointers).
func dashboardCopy(line string) string {
	s := strings.Join(strings.Fields(collapse(line)), " ")
	for _, p := range dashboardCLIPointers {
		s = strings.ReplaceAll(s, p.cli, p.ui)
	}
	return s
}

// dashboardGovernanceWarning is the status posture line for the UI.
func dashboardGovernanceWarning(line string) string { return dashboardCopy(line) }

// collapse joins a multi-line CLI rendering (continuation lines indented)
// into one sentence for the UI.
func collapse(lines ...string) string {
	parts := make([]string, 0, len(lines))
	for _, l := range lines {
		for _, sub := range strings.Split(l, "\n") {
			if t := strings.TrimSpace(sub); t != "" {
				parts = append(parts, t)
			}
		}
	}
	return plainDashes(strings.Join(parts, " "))
}

func newOpaqueID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}

// cfgPath resolves the config.toml the enrolment writes, as the CLI does.
func (d *enrolDashboard) cfgPath() (string, error) { return resolveConfigPath(d.configPath) }

// leavePlanView is Leave's route plan for the confirm dialog. A planning
// failure yields one "keep" line saying nothing will be touched, which is
// what the apply step does on the same failure.
func leavePlanView(configPath string) []dashapi.EnrolLeaveRoute {
	routes, err := leaveRoutes(configPath, false)
	if err != nil {
		return []dashapi.EnrolLeaveRoute{{Tool: "", Action: "keep", Message: "Proxy routes could not be checked, so Leave will not change your AI tools' settings."}}
	}
	out := make([]dashapi.EnrolLeaveRoute, 0, len(routes))
	for _, r := range routes {
		msg := r.Message
		if r.Error != "" {
			msg = "The " + routeprov.ToolLabel(r.Tool) + " proxy route in " + r.ConfigPath + " could not be read, so it will be kept."
		}
		out = append(out, dashapi.EnrolLeaveRoute{Tool: r.Tool, Action: string(r.Action), Message: msg})
	}
	return out
}

// Overview implements dashapi.EnrolmentManager (`observer org status`).
func (d *enrolDashboard) Overview(ctx context.Context) (dashapi.EnrolmentOverview, error) {
	b, err := d.bundle(ctx)
	if err != nil {
		return dashapi.EnrolmentOverview{}, err
	}
	defer b.cleanup()
	rep, err := collectOrgStatus(ctx, b)
	if err != nil {
		return dashapi.EnrolmentOverview{}, err
	}
	st := rep.State
	ov := dashapi.EnrolmentOverview{
		Enrolled:        st.Enrolled,
		CredentialStore: st.Backend,
		PushingEnabled:  rep.PushingEnabled,
		PushLoopRunning: d.pushLoop,
		// `observer org push-status`'s cadence line (T-642).
		PushIntervalSeconds: configuredPushInterval(b.cfg.OrgClient),
	}
	if !st.Enrolled {
		return ov, nil
	}
	ov.OrgID, ov.OrgName, ov.OrgServerURL = st.OrgID, st.OrgName, st.OrgServerURL
	ov.OrgDisplay = orgenrol.DisplayName(st.OrgID, st.OrgServerURL, st.OrgName)
	ov.LeavePlan = leavePlanView(d.configPath)
	for _, s := range unenrolPlanRows() {
		ov.LeaveSteps = append(ov.LeaveSteps, dashapi.EnrolLeaveStep{ID: s.ID, Phase: s.Phase, Conferred: s.Conferred, Retired: s.Retired})
	}
	ov.UserEmail, ov.EnrolledAt = st.UserEmail, st.EnrolledAt
	ov.Tenancy = rep.Tenancy
	if ov.Tenancy == orgcontract.TenancyManaged {
		ov.MachineProofWarning = machineProofWarning(ctx, b.store)
	}
	// WINNODE2 item 1b: a running daemon that cannot read the credential.
	ov.DaemonCredentialWarning = daemonCredentialWarning(loadLiveDaemonCredentials(ctx, filepath.Dir(b.cfg.Observer.DBPath), b.store))
	ov.ShareMode, ov.ShareModeLine = rep.ShareRule, dashboardCopy(rep.ShareLine)
	ov.TargetActions = rep.TargetActions
	ov.GovernanceWarning = dashboardGovernanceWarning(rep.GovernanceLine)
	ov.Governed = rep.Governed
	for _, row := range rep.statusTableRows() {
		ov.Tables = append(ov.Tables, dashapi.EnrolTableCount{Table: row.name, Historical: row.historical, Eligible: row.eligible})
	}
	ov.PendingResends = rep.PendingResends
	ov.PendingDeletions, ov.PendingManifests = rep.Tombstones, rep.Manifests
	ov.EligibleReason = dashboardCopy(rep.EligibleReason)
	if lp := st.LastPush; lp != nil {
		ov.LastPush = &dashapi.EnrolLastPush{PushedAt: lp.PushedAt, Status: lp.Status, RowCount: lp.RowCount, Bytes: lp.Bytes, Error: lp.Error}
	}
	if pp := st.PushPaused; pp != nil {
		ov.PushPaused = &dashapi.EnrolPushPaused{Reason: pp.Reason, Until: pp.Until.UTC().Format(time.RFC3339)}
	}
	ov.PendingGrant = d.latestPendingOffer()
	return ov, nil
}

// latestPendingOffer returns the newest unexpired parked offer, so a page
// reload does not lose the consent screen.
func (d *enrolDashboard) latestPendingOffer() *dashapi.PendingGrant {
	d.mu.Lock()
	defer d.mu.Unlock()
	now := d.now()
	var best *pendingGrantOffer
	for id, p := range d.offers {
		if now.After(p.expires) {
			delete(d.offers, id)
			continue
		}
		if best == nil || p.expires.After(best.expires) {
			best = p
		}
	}
	if best == nil {
		return nil
	}
	v := best.view
	return &v
}

// classifyReachability maps a probe error onto the failure vocabulary.
func classifyReachability(orgURL string, err error) error {
	switch {
	case err == nil:
		return nil
	// T-718: every message carries what was actually answered (probeDetail),
	// never only a generic sentence, so the page shows the real cause.
	case errors.Is(err, orgclient.ErrServerUnreachable):
		return orgenrol.Fail(orgenrol.CodeUnreachable,
			"could not reach %s from this machine (%s). Check the address and that this machine can reach it (VPN, proxy, firewall)", orgURL, probeDetail(err))
	case errors.Is(err, orgclient.ErrNotOrgServer):
		return orgenrol.Fail(orgenrol.CodeNotOrgServer,
			"%s answered, but not like an Observer organization server (%s). Check the address with your admin - it is the same address as the organization dashboard", orgURL, probeDetail(err))
	default:
		return orgenrol.Fail(orgenrol.CodeUpstream, "checking %s failed: %v", orgURL, err)
	}
}

// probeDetail is the probe error without the sentinel prefixes: what the
// server (or the network) actually answered.
func probeDetail(err error) string {
	s := err.Error()
	for _, p := range []string{orgclient.ErrServerUnreachable.Error() + ": ", orgclient.ErrNotOrgServer.Error() + ": "} {
		s = strings.TrimPrefix(s, p)
	}
	return plainDashes(s)
}

// Probe implements dashapi.EnrolmentManager.
func (d *enrolDashboard) Probe(ctx context.Context, rawURL string) (dashapi.EnrolProbe, error) {
	orgURL, err := orgenrol.NormalizeServerURL(rawURL)
	if err != nil {
		return dashapi.EnrolProbe{}, err
	}
	b, err := d.bundle(ctx)
	if err != nil {
		return dashapi.EnrolProbe{}, err
	}
	defer b.cleanup()
	if f := classifyReachability(orgURL, b.client.ProbeServer(ctx, orgURL)); f != nil {
		return dashapi.EnrolProbe{OrgURL: orgURL, OK: false, Message: f.Error()}, nil
	}
	return dashapi.EnrolProbe{OrgURL: orgURL, OK: true, Message: "Reachable: " + orgURL + " is an Observer organization server."}, nil
}

// resolveDashboardEnrolInput runs the CLI's own credential resolver for the
// code and link methods, then the orgenrol shape checks.
func resolveDashboardEnrolInput(req dashapi.EnrolRequest) (string, string, error) {
	method, err := orgenrol.ParseMethod(req.Method)
	if err != nil {
		return "", "", err
	}
	var orgURL, token string
	switch method {
	case orgenrol.MethodLink:
		if strings.TrimSpace(req.Link) == "" {
			return "", "", orgenrol.Fail(orgenrol.CodeInvalidInput, "paste the enrolment link your admin shared (it looks like https://host/enrol/<code>)")
		}
		orgURL, token, err = resolveEnrolCredentials(strings.TrimSpace(req.Link), "", nil)
		if err != nil {
			var notLink *errNotAnEnrolmentLink
			if errors.As(err, &notLink) {
				return "", "", orgenrol.Fail(orgenrol.CodeInvalidInput,
					"%s is a dashboard sign-in invite, not a machine enrolment link. Open it in a browser to set your password; to enrol this machine use an enrolment link or sign in with your organization account", notLink.path)
			}
			return "", "", orgenrol.Fail(orgenrol.CodeInvalidInput, "that is not an enrolment link: it needs the form https://host/enrol/<code>")
		}
	case orgenrol.MethodIdP:
		return "", "", orgenrol.Fail(orgenrol.CodeInvalidInput, "sign-in enrolment starts with /api/enrolment/idp/start")
	default:
		orgURL, token, err = resolveEnrolCredentials("", "", []string{req.OrgURL, req.Token})
		if err != nil {
			return "", "", orgenrol.Fail(orgenrol.CodeInvalidInput, "%v", err)
		}
	}
	if orgURL, err = orgenrol.NormalizeServerURL(orgURL); err != nil {
		return "", "", err
	}
	if token, err = orgenrol.CheckTokenShape(token); err != nil {
		return "", "", err
	}
	return orgURL, token, nil
}

// Enrol implements dashapi.EnrolmentManager (`observer enroll` for the code
// and link methods).
func (d *enrolDashboard) Enrol(ctx context.Context, req dashapi.EnrolRequest) (dashapi.EnrolOutcome, error) {
	defer d.changed()
	orgURL, token, err := resolveDashboardEnrolInput(req)
	if err != nil {
		return dashapi.EnrolOutcome{}, err
	}
	return d.enrolWithToken(ctx, orgURL, token, true)
}

// classifyEnrolErr maps an orgclient.Enroll error onto the vocabulary.
func classifyEnrolErr(orgURL string, err error) error {
	var netErr net.Error
	var urlErr *url.Error
	switch {
	case errors.Is(err, orgclient.ErrAuthFailed):
		return orgenrol.Fail(orgenrol.CodeTokenRejected,
			"the organization refused this enrolment code: it is invalid, expired, or already used. Ask your admin for a new one, or sign in with your organization account instead")
	case errors.Is(err, orgclient.ErrMemberNotActive):
		return orgenrol.Fail(orgenrol.CodeMemberNotActive,
			"your organization account is not active yet. Open the set-password link from your invitation first, set your password and sign in to the organization dashboard once, then enrol again with the same code - it is still valid")
	case errors.As(err, &urlErr), errors.As(err, &netErr):
		return orgenrol.Fail(orgenrol.CodeUnreachable, "could not complete the enrolment with %s: the connection failed (%v)", orgURL, err)
	default:
		return orgenrol.Fail(orgenrol.CodeUpstream, "%s", strings.TrimPrefix(err.Error(), "orgclient.Enroll: "))
	}
}

// enrolWithToken is the dashboard's run of the CLI enrol sequence: probe,
// exchange, managed machine bind, default [org_client] block, then the grant
// (settled now when the organization's IdP approval already was the consent,
// parked for the consent screen otherwise).
func (d *enrolDashboard) enrolWithToken(ctx context.Context, orgURL, token string, probe bool) (dashapi.EnrolOutcome, error) {
	b, err := d.bundle(ctx)
	if err != nil {
		return dashapi.EnrolOutcome{}, err
	}
	defer b.cleanup()
	if probe {
		if f := classifyReachability(orgURL, b.client.ProbeServer(ctx, orgURL)); f != nil {
			return dashapi.EnrolOutcome{}, f
		}
	}
	// T-642: the one enrolment sequence `observer enroll` also runs
	// (exchange, managed bind, default [org_client] block). What follows only
	// renders it and runs the dashboard's side of the consent conversation.
	seq, err := runEnrolSequence(ctx, b, d.configPath, orgURL, token, true)
	if err != nil {
		return dashapi.EnrolOutcome{}, classifyEnrolErr(orgURL, err)
	}
	enr, offer, managed := seq.enr, seq.offer, seq.managed
	out := dashapi.EnrolOutcome{
		OrgID:           enr.OrgID,
		OrgName:         enr.OrgName,
		OrgDisplay:      orgenrol.DisplayName(enr.OrgID, enr.OrgServerURL, enr.OrgName),
		UserEmail:       enr.UserEmail,
		OrgServerURL:    enr.OrgServerURL,
		Tenancy:         orgcontract.TenancyIndividual,
		Managed:         managed,
		RestartRequired: !d.pushLoop,
	}
	if managed {
		out.Tenancy = orgcontract.TenancyManaged
		if level, text := managedBindNote(seq.bindRes, seq.bindErr); level != "" {
			out.Notes = append(out.Notes, dashapi.EnrolNote{Level: level, Text: text})
		}
	} else {
		// Cloud Intelligence parity (design 3.7): fetch the org's terms now so
		// a compulsory requirement shows at once (the Accept / Leave banner
		// and Settings, Org enrichment), not after the first push cycle.
		if _, rerr := b.client.RefreshIntelRequirement(ctx); rerr == nil {
			if line := orgIntelPendingLine(ctx, b); line != "" {
				out.Notes = append(out.Notes, dashapi.EnrolNote{
					Level: "warn",
					Text:  dashboardCopy(line),
				})
			}
		}
	}

	// The default [org_client] block, by tenancy (W4f): written by
	// runEnrolSequence, never a rewrite of an existing block.
	out.FullContent, out.ShareSummary = seq.posture.fullContent, seq.posture.summary
	cfgPath := seq.blockConfigPath()
	switch {
	case seq.cfgPathErr != nil:
		out.Notes = append(out.Notes, dashapi.EnrolNote{Level: "warn", Text: "could not resolve the config path to write the [org_client] block: " + seq.cfgPathErr.Error()})
	default:
		out.ConfigPath = cfgPath
		switch {
		case seq.blockErr != nil:
			out.Notes = append(out.Notes, dashapi.EnrolNote{Level: "warn", Text: fmt.Sprintf("could not write the [org_client] block to %s: %v", cfgPath, seq.blockErr)})
		case seq.blockAdded:
			out.BlockWritten = true
		case seq.cfgEditErr != nil || seq.cfgEdit.Wrote:
			// T-728: an existing block was updated (or could not be).
			text, warn := seq.cfgEditNote()
			level := "info"
			if warn {
				level = "warn"
			}
			out.Notes = append(out.Notes, dashapi.EnrolNote{Level: level, Text: text})
		case !seq.pushEnabled && !seq.pushEnabledNow:
			out.Notes = append(out.Notes, dashapi.EnrolNote{
				Level: "warn",
				Text:  "[org_client] enabled = false in your config.toml, so nothing will be pushed. Turn it on in Settings > Org sharing, then restart the daemon.",
			})
		}
	}
	out.Notes = append(out.Notes, dashapi.EnrolNote{
		Level: "info",
		Text:  "AI tools were not rewired from here. To route them through this observer and register hooks, use Settings > Setup (the CLI's --wire-clients step, one consent per file).",
	})

	if offer == nil {
		return out, nil
	}
	consent, problem := resolveGrantConsent(offer)
	switch {
	case problem != "":
		out.Grant = &dashapi.GrantDecision{Status: "refused", Message: "Grant REFUSED: " + problem +
			". This machine is enrolled and reporting, but NOT governed. Nothing was recorded. Tell your administrator what this said - it means the server and this machine disagree about how this enrolment was authorised."}
	case consent.AlreadyGiven:
		dec, derr := d.recordGrant(ctx, b, offer, consent, cfgPath)
		if derr != nil {
			return out, derr
		}
		dec.Status, dec.Message = "consented", collapse(consent.Summary)
		out.Grant = &dec
	default:
		id := newOpaqueID()
		p := &pendingGrantOffer{
			offer:   offer,
			expires: d.now().Add(pendingOfferTTL),
		}
		p.view = dashapi.PendingGrant{
			OfferID:    id,
			ExpiresAt:  p.expires.UTC().Format(time.RFC3339),
			Disclosure: grantDisclosure(offer, enr.OrgName),
		}
		d.mu.Lock()
		// A fresh enrolment supersedes any older parked offer.
		d.offers = map[string]*pendingGrantOffer{id: p}
		d.mu.Unlock()
		v := p.view
		out.PendingGrant = &v
	}
	return out, nil
}

// recordGrant stores an accepted grant through the shared writer and, for a
// managed enrolment, writes the W-5 [org_client.policy] consent keys.
func (d *enrolDashboard) recordGrant(ctx context.Context, b orgBundle, offer *orgclient.GrantOffer, consent grantConsent, cfgPath string) (dashapi.GrantDecision, error) {
	gOut, err := storeGrantOffer(ctx, b.store, offer, consent)
	if err != nil {
		return dashapi.GrantDecision{}, err
	}
	dec := dashapi.GrantDecision{
		Status:  "accepted",
		Message: "Recorded. The grant section below shows exactly what this machine granted; Leave organization revokes it.",
	}
	if families, added, werr := writeAcceptedGrantPolicy(cfgPath, gOut); len(families) > 0 {
		switch {
		case werr != nil:
			dec.Notes = append(dec.Notes, dashapi.EnrolNote{Level: "warn", Text: fmt.Sprintf("could not write the [org_client.policy] block to %s: %v", cfgPath, werr)})
		case added:
			dec.Notes = append(dec.Notes, dashapi.EnrolNote{
				Level: "info",
				Text:  fmt.Sprintf("Wrote [org_client.policy] %s to %s. Edit or remove them at any time.", managedPolicyKeyLinesText(families), cfgPath),
			})
		}
	}
	return dec, nil
}

// DecideGrant implements dashapi.EnrolmentManager.
func (d *enrolDashboard) DecideGrant(ctx context.Context, offerID string, accept bool) (dashapi.GrantDecision, error) {
	defer d.changed()
	d.mu.Lock()
	p, ok := d.offers[offerID]
	if ok {
		delete(d.offers, offerID)
	}
	d.mu.Unlock()
	if !ok || d.now().After(p.expires) {
		return dashapi.GrantDecision{}, orgenrol.Fail(orgenrol.CodeGone,
			"this consent request has expired or was already answered. The machine is enrolled but not governed; enrol again to be asked again")
	}
	b, err := d.bundle(ctx)
	if err != nil {
		return dashapi.GrantDecision{}, err
	}
	defer b.cleanup()
	// The offer must still belong to the enrolment this machine holds: a
	// re-enrolment or a leave in between makes it someone else's grant.
	_, live, err := governanceIdentityLoader(b.store)(ctx)
	if err != nil {
		return dashapi.GrantDecision{}, err
	}
	if !live.Enrolled || live.OrgKey != p.offer.OrgKey || live.Generation != p.offer.Generation {
		return dashapi.GrantDecision{}, orgenrol.Fail(orgenrol.CodeStale,
			"this consent request belongs to an enrolment this machine no longer holds, so nothing was recorded")
	}
	if !accept {
		return dashapi.GrantDecision{
			Status:  "declined",
			Message: "Declined. This machine is enrolled and reporting, but NOT governed: nothing about this dashboard will be changed by the organization.",
		}, nil
	}
	consent, problem := resolveGrantConsent(p.offer)
	if problem != "" {
		return dashapi.GrantDecision{Status: "refused", Message: "Grant REFUSED: " + problem + ". Nothing was recorded."}, nil
	}
	cfgPath, _ := d.cfgPath() //nolint:errcheck // an unresolvable path just skips the policy-block write, noted below
	return d.recordGrant(ctx, b, p.offer, consent, cfgPath)
}

// StartIdP implements dashapi.EnrolmentManager (`observer enroll --idp`).
func (d *enrolDashboard) StartIdP(ctx context.Context, rawURL string) (dashapi.IdPStart, error) {
	if strings.TrimSpace(rawURL) == "" {
		return dashapi.IdPStart{}, orgenrol.Fail(orgenrol.CodeInvalidInput, "the organization server URL is required")
	}
	orgURL, _, err := resolveEnrolCredentials("", strings.TrimSpace(rawURL), nil)
	if err != nil {
		return dashapi.IdPStart{}, orgenrol.Fail(orgenrol.CodeInvalidInput, "%v", err)
	}
	if orgURL, err = orgenrol.NormalizeServerURL(orgURL); err != nil {
		return dashapi.IdPStart{}, err
	}
	b, err := d.bundle(ctx)
	if err != nil {
		return dashapi.IdPStart{}, err
	}
	defer b.cleanup()
	if f := classifyReachability(orgURL, b.client.ProbeServer(ctx, orgURL)); f != nil {
		return dashapi.IdPStart{}, f
	}
	start, err := b.client.StartIdPEnrol(ctx, orgURL)
	if err != nil {
		if errors.Is(err, orgclient.ErrIdPEnrolUnavailable) {
			return dashapi.IdPStart{}, orgenrol.Fail(orgenrol.CodeIdPUnavailable,
				"this organization does not offer sign-in enrolment (it may be switched off, or the server may be older than the feature). Ask an administrator for an enrolment code or link instead")
		}
		return dashapi.IdPStart{}, orgenrol.Fail(orgenrol.CodeUpstream, "%v", err)
	}
	now := d.now()
	interval := durationOrDefault(start.Interval, idpDefaultInterval)
	life := durationOrDefault(start.ExpiresIn, idpDefaultDeadline)
	id := newOpaqueID()
	d.mu.Lock()
	// One sign-in at a time: a fresh start supersedes an abandoned one.
	d.flows = map[string]*pendingIdPFlow{id: {
		orgURL: orgURL, deviceCode: start.DeviceCode, userCode: start.UserCode,
		deadline: now.Add(life), interval: interval, nextPoll: now.Add(interval),
	}}
	d.mu.Unlock()
	return dashapi.IdPStart{
		FlowID:          id,
		UserCode:        start.UserCode,
		VerificationURI: verificationURIWithCodeHint(start.VerificationURI, start.UserCode),
		ExpiresIn:       int(life / time.Second),
		Interval:        int(interval / time.Second),
	}, nil
}

// PollIdP implements dashapi.EnrolmentManager: one step of the CLI's
// --idp loop, decided by the shared idpPollStep table.
func (d *enrolDashboard) PollIdP(ctx context.Context, flowID string) (dashapi.IdPPoll, error) {
	defer d.changed()
	d.mu.Lock()
	f, ok := d.flows[flowID]
	d.mu.Unlock()
	if !ok {
		return dashapi.IdPPoll{}, orgenrol.Fail(orgenrol.CodeGone, "this sign-in request is no longer active. Start again to get a fresh code")
	}
	drop := func() {
		d.mu.Lock()
		delete(d.flows, flowID)
		d.mu.Unlock()
	}
	now := d.now()
	if now.After(f.deadline) {
		drop()
		return dashapi.IdPPoll{
			Status:  orgclient.IdPStatusExpired,
			Message: fmt.Sprintf("Code %s expired before it was approved. Start again to get a fresh code.", f.userCode),
		}, nil
	}
	if now.Before(f.nextPoll) {
		// Honour the server's cadence: a browser that polls faster than the
		// interval would only earn slow_down answers.
		return dashapi.IdPPoll{Status: orgclient.IdPStatusPending, Interval: int(f.interval / time.Second)}, nil
	}
	b, err := d.bundle(ctx)
	if err != nil {
		return dashapi.IdPPoll{}, err
	}
	res, err := b.client.PollIdPEnrol(ctx, f.orgURL, f.deviceCode)
	b.cleanup()
	if err != nil {
		if errors.Is(err, orgclient.ErrIdPEnrolUnavailable) {
			drop()
			return dashapi.IdPPoll{}, orgenrol.Fail(orgenrol.CodeGone,
				"the organization no longer recognises code %s. Start again to get a fresh code", f.userCode)
		}
		return dashapi.IdPPoll{}, orgenrol.Fail(orgenrol.CodeUpstream, "%v", err)
	}
	step := idpPollStep(res, f.interval, f.userCode, f.orgURL)
	switch {
	case step.err != nil:
		drop()
		status, msg := res.Status, step.err.Error()
		if res.Status == orgclient.IdPStatusExpired {
			msg = fmt.Sprintf("Code %s expired before it was approved. Start again to get a fresh code.", f.userCode)
		}
		if status != orgclient.IdPStatusDenied && status != orgclient.IdPStatusExpired {
			status = "error"
		}
		return dashapi.IdPPoll{Status: status, Message: msg}, nil
	case step.token != "":
		drop()
		out, eerr := d.enrolWithToken(ctx, f.orgURL, step.token, false)
		if eerr != nil {
			return dashapi.IdPPoll{}, eerr
		}
		return dashapi.IdPPoll{Status: orgclient.IdPStatusApproved, Outcome: &out}, nil
	default:
		d.mu.Lock()
		f.interval = step.interval
		f.nextPoll = d.now().Add(step.interval)
		d.mu.Unlock()
		return dashapi.IdPPoll{Status: orgclient.IdPStatusPending, Interval: int(step.interval / time.Second)}, nil
	}
}

// GrantReport implements dashapi.EnrolmentManager (`observer org grant
// show`).
func (d *enrolDashboard) GrantReport(ctx context.Context) (dashapi.GrantReport, error) {
	b, err := d.bundle(ctx)
	if err != nil {
		return dashapi.GrantReport{}, err
	}
	defer b.cleanup()
	rep, err := collectGrantShow(ctx, b, d.configPath)
	if err != nil {
		return dashapi.GrantReport{}, err
	}
	switch {
	case !rep.Live.Enrolled:
		return dashapi.GrantReport{State: "not_enrolled"}, nil
	case rep.Grant == nil:
		return dashapi.GrantReport{State: "ungoverned"}, nil
	}
	g := rep.Grant
	// The grant row records the org id as its org_name; the enrolment holds
	// the real name.
	enrolName := ""
	if st, serr := b.client.Status(ctx); serr == nil {
		enrolName = st.OrgName
	}
	out := dashapi.GrantReport{
		State:       "governed",
		OrgName:     g.OrgName,
		OrgDisplay:  orgenrol.DisplayName(g.OrgID, g.OrgServerURL, enrolName, g.OrgName),
		OrgID:       g.OrgID,
		ServerURL:   g.OrgServerURL,
		GrantedAt:   formatGrantStamp(g.GrantedAt),
		ExpiryLine:  strings.TrimSpace(strings.TrimPrefix(expiryLine(g, rep.Row), "Expires:")),
		Consent:     grantConsentLine(g),
		Receipt:     g.ReceiptHash,
		ContentLine: strings.TrimSpace(strings.TrimPrefix(dashboardCopy(rep.ContentLine), "Content:")),
		Pinned:      pinnedSettingsLines(b.cfg, d.configPath),
	}
	for _, tok := range g.Authority {
		out.Authority = append(out.Authority, orgenrol.AuthorityLine{Token: tok, Text: orgenrol.AuthorityPlainEnglish(tok)})
	}
	for _, f := range rep.Families {
		out.Families = append(out.Families, dashapi.FamilyRow{Family: f.Family, Accepted: f.Accepted, Preauthorize: f.Preauthorized})
	}
	for _, v := range []verdictLines{rep.Key, rep.Signature} {
		out.Verification = append(out.Verification, dashapi.EnrolNote{Level: v.Level, Text: collapse(v.Lines...)})
	}
	if len(rep.Stale) > 0 {
		out.Verification = append(out.Verification, dashapi.EnrolNote{Level: "warn", Text: dashboardCopy(strings.Join(rep.Stale, "\n"))})
	}
	if rep.Expired {
		out.Verification = append(out.Verification, dashapi.EnrolNote{Level: "warn", Text: "Status: EXPIRED - local settings apply again."})
	}
	return out, nil
}

// PushNow implements dashapi.EnrolmentManager (`observer org push-now`).
func (d *enrolDashboard) PushNow(ctx context.Context) (dashapi.PushNowReport, error) {
	b, err := d.bundle(ctx)
	if err != nil {
		return dashapi.PushNowReport{}, err
	}
	defer b.cleanup()
	rep, err := performPushNow(ctx, b)
	switch {
	case errors.Is(err, orgclient.ErrNotEnrolled):
		return dashapi.PushNowReport{}, orgenrol.Fail(orgenrol.CodeNotEnrolled, "this machine is not enrolled in an organization, so there is nothing to push to")
	case errors.Is(err, orgclient.ErrAuthFailed):
		return dashapi.PushNowReport{}, orgenrol.Fail(orgenrol.CodeTokenRejected,
			"the organization no longer accepts this machine's credential (it may have been revoked). Leave and enrol again")
	case err != nil:
		return dashapi.PushNowReport{}, orgenrol.Fail(orgenrol.CodeUpstream, "push failed: %v", err)
	}
	var buf bytes.Buffer
	printPushNowReport(&buf, rep)
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	out := dashapi.PushNowReport{
		Empty:    rep.Result.Empty,
		RowCount: rep.Result.RowCount,
		Bytes:    rep.Result.Bytes,
		Accepted: rep.Result.AcceptedRows,
		Deduped:  rep.Result.DedupedRows,
		More:     rep.Result.More,
		Message:  plainDashes(lines[0]),
	}
	for _, ln := range lines[1:] {
		if t := strings.TrimSpace(ln); t != "" {
			out.Notes = append(out.Notes, dashapi.EnrolNote{Level: "info", Text: plainDashes(t)})
		}
	}
	return out, nil
}

// ShareHistory implements dashapi.EnrolmentManager (`observer org backfill
// --all [--confirm]`): the same performer the CLI runs, refused when this
// machine is not enrolled (there is nowhere to share the history to).
func (d *enrolDashboard) ShareHistory(ctx context.Context, confirm bool) (dashapi.ShareHistoryReport, error) {
	b, err := d.bundle(ctx)
	if err != nil {
		return dashapi.ShareHistoryReport{}, err
	}
	defer b.cleanup()
	st, err := b.client.Status(ctx)
	if err != nil {
		return dashapi.ShareHistoryReport{}, err
	}
	if !st.Enrolled {
		return dashapi.ShareHistoryReport{}, orgenrol.Fail(orgenrol.CodeNotEnrolled,
			"this machine is not enrolled in an organization, so there is no history to share")
	}
	rep, err := performOrgBackfill(ctx, b.store, confirm)
	if err != nil {
		return dashapi.ShareHistoryReport{}, err
	}
	return dashapi.ShareHistoryReport{Eligible: rep.Eligible, WouldUnlock: rep.WouldUnlock, Total: rep.Total, Rewound: rep.Rewound}, nil
}

// Resync implements dashapi.EnrolmentManager (`observer org resync
// [--confirm]` with its default window, T-642): the same performer the CLI
// runs, refused when this machine is not enrolled.
func (d *enrolDashboard) Resync(ctx context.Context, confirm bool) (dashapi.ResyncReport, error) {
	b, err := d.bundle(ctx)
	if err != nil {
		return dashapi.ResyncReport{}, err
	}
	defer b.cleanup()
	res, err := performOrgResync(ctx, b, orgResyncOptions{
		Since: resyncDefaultSince, Limit: resyncDefaultLimit, Confirm: confirm, Deletions: true,
	})
	if errors.Is(err, store.ErrPushNotTracked) {
		return dashapi.ResyncReport{}, orgenrol.Fail(orgenrol.CodeNotEnrolled,
			"this machine is not enrolled in an organization, so there is nothing to re-send")
	}
	if err != nil {
		return dashapi.ResyncReport{}, err
	}
	out := dashapi.ResyncReport{
		WindowDays:       int(resyncDefaultSince / (24 * time.Hour)),
		Limit:            resyncDefaultLimit,
		Queued:           res.Queued,
		EndedAtChecked:   res.Resync.EndedAtChecked,
		Manifests:        res.Manifests.Queued,
		ManifestsChecked: res.Manifests.Checked,
		ManifestsTooBig:  res.Manifests.TooBig,
		Confirmed:        confirm,
	}
	if !res.Manifests.NotBefore.IsZero() {
		out.NotBefore = res.Manifests.NotBefore.UTC().Format(time.RFC3339)
	}
	for _, l := range res.Resync.Tables {
		out.Tables = append(out.Tables, dashapi.ResyncTable{Table: l.Table, Queued: l.Queued})
	}
	return out, nil
}

// Leave implements dashapi.EnrolmentManager (`observer unenroll`).
func (d *enrolDashboard) Leave(ctx context.Context) (dashapi.LeaveReport, error) {
	defer d.changed()
	b, err := d.bundle(ctx)
	if err != nil {
		return dashapi.LeaveReport{}, err
	}
	defer b.cleanup()
	rep, err := performUnenrol(ctx, b, d.configPath)
	if err != nil {
		return dashapi.LeaveReport{}, err
	}
	if d.retired != nil {
		d.retired(ctx)
	}
	d.mu.Lock()
	d.offers = map[string]*pendingGrantOffer{}
	d.flows = map[string]*pendingIdPFlow{}
	d.mu.Unlock()
	var buf bytes.Buffer
	printUnenrolReport(&buf, rep)
	out := dashapi.LeaveReport{WasEnrolled: rep.WasEnrolled, OrgName: rep.OrgName, OrgDisplay: orgenrol.DisplayName("", "", rep.OrgName)}
	for _, ln := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		if t := strings.TrimSpace(ln); t != "" {
			level := "info"
			if strings.HasPrefix(t, "Warning:") {
				level = "warn"
			}
			out.Notes = append(out.Notes, dashapi.EnrolNote{Level: level, Text: plainDashes(t)})
		}
	}
	return out, nil
}
