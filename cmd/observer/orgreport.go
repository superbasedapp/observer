package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/budgetwarnfile"
	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/govern"
	"github.com/marmutapp/superbased-observer/internal/orgclient"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/proxyroute"
	"github.com/marmutapp/superbased-observer/internal/routeprov"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// orgreport.go: the `observer org status`, `org grant show`, `org push-now`
// and `unenroll` bodies as DATA. Each command used to compute and print in
// one RunE; they now collect a report here and print it, and the dashboard's
// Settings > Enrolment page (orgenrol_dashboard.go) renders the SAME report.
// One computation, two renderers: the backlog-item-6 rule that a dashboard
// action runs the CLI's code path rather than a re-implementation of it.

// orgStatusReport is `observer org status`.
type orgStatusReport struct {
	State          orgclient.EnrolmentState
	Tenancy        string
	PushingEnabled bool
	GovernanceLine string
	// TenancyLine explains a managed-consent grant refused because it would
	// cross tenancy (OSH-R-013, P-204); empty otherwise.
	TenancyLine   string
	Governed      bool
	ShareRule     string
	ShareLine     string
	TargetActions []string
	Cursor        store.PushCursor
	MaxIDs        store.PushCursor
	// Eligible is the per-table count of rows above Cursor
	// (store.PushEligibleCounts), never MaxIDs minus Cursor (T-373).
	Eligible       store.PushCursor
	PendingResends map[string]int64
	Tombstones     int64
	Manifests      int64
	EligibleReason string
	// IntelLine is the org-plane Cloud Intelligence consent line (design
	// 3.7 step 3), empty unless something is pending.
	IntelLine string
	// Oversized is the daemon's report of snapshot rows too large for any
	// push (family names and sizes only; store.LoadOrgPushOversizedRows).
	Oversized []store.OrgPushOversizedRow
}

// collectOrgStatus computes the status report through the same seams the
// push loop and the governance resolver use.
func collectOrgStatus(ctx context.Context, b orgBundle) (orgStatusReport, error) {
	st, err := b.client.Status(ctx)
	if err != nil {
		return orgStatusReport{}, err
	}
	rep := orgStatusReport{State: st, PushingEnabled: b.cfg.OrgClient.Enabled}
	if !st.Enrolled {
		return rep, nil
	}
	rep.Tenancy = orgcontract.TenancyIndividual
	if managed, merr := orgclient.NodeManaged(ctx, b.store); merr == nil && managed { // P-204
		rep.Tenancy = orgcontract.TenancyManaged
	}
	rep.GovernanceLine = governancePostureLine(ctx, b.store)
	rep.IntelLine = orgIntelPendingLine(ctx, b)
	if loader := governanceIdentityLoader(b.store); loader != nil {
		if grant, _, gerr := loader(ctx); gerr == nil && grant != nil {
			rep.Governed = true
			rep.TenancyLine = managedConsentRefusalLine(grant)
		}
	}
	// Share mode - the v1.8.0 per-node opt-in, read through the SAME
	// predicate the push seam uses (SF-12).
	rule := shareModeRuleFor(
		b.cfg.OrgClient.Share.FullContent,
		b.cfg.OrgClient.Share.AdminManaged,
		enterpriseContentGranted(ctx, b.cfg, b.store, newLogger("warn")),
	)
	rep.ShareRule, rep.ShareLine = rule.name, rule.line
	rep.TargetActions = b.cfg.OrgClient.Share.TargetActionAllowlist

	// Scope counts: historical (already in the DB) vs eligible-since-
	// enrolment (above the cursor, which the agent seeds to the current
	// high-water id at enrolment so only post-enrolment activity is ever
	// shareable).
	if rep.Cursor, err = b.store.LoadPushCursor(ctx); err != nil {
		return orgStatusReport{}, fmt.Errorf("load cursor: %w", err)
	}
	if rep.MaxIDs, err = b.store.CurrentMaxIDs(ctx); err != nil {
		return orgStatusReport{}, fmt.Errorf("current max ids: %w", err)
	}
	if rep.Eligible, err = b.store.PushEligibleCounts(ctx, rep.Cursor); err != nil {
		return orgStatusReport{}, fmt.Errorf("eligible counts: %w", err)
	}
	// Already-pushed rows that changed on this node and are queued to
	// re-send (agent migration 140), and deletions queued to propagate
	// (agent migration 141). Display-only: a read failure omits the line.
	if pending, perr := b.store.PushResendPending(ctx); perr == nil {
		rep.PendingResends = pending
	}
	if tomb, mans, perr := b.store.PushDeletionsPending(ctx); perr == nil {
		rep.Tombstones, rep.Manifests = tomb, mans
	}
	rep.EligibleReason = pushEligibilityReason(eligibleTotal(rep.Eligible), historicalTotal(rep.MaxIDs), st.LastPush)
	// Display-only: a read failure omits the line.
	if ov, oerr := b.store.LoadOrgPushOversizedRows(ctx); oerr == nil {
		rep.Oversized = ov
	}
	return rep, nil
}

// statusTableRows is the historical-vs-eligible table, in print order.
func (r orgStatusReport) statusTableRows() []struct {
	name                 string
	historical, eligible int64
} {
	return []struct {
		name                 string
		historical, eligible int64
	}{
		{"sessions", r.MaxIDs.Sessions, r.Eligible.Sessions},
		{"actions", r.MaxIDs.Actions, r.Eligible.Actions},
		{"api_turns", r.MaxIDs.APITurns, r.Eligible.APITurns},
		{"token_usage", r.MaxIDs.TokenUsage, r.Eligible.TokenUsage},
		{"guard_events", r.MaxIDs.GuardEvents, r.Eligible.GuardEvents},
	}
}

// printOrgStatus renders the status report exactly as `observer org status`
// always has.
func printOrgStatus(out io.Writer, rep orgStatusReport) {
	st := rep.State
	if !st.Enrolled {
		fmt.Fprintln(out, "Not enrolled.")
		fmt.Fprintf(out, "Credential store: %s\n", st.Backend)
		return
	}
	fmt.Fprintf(out, "Enrolled:         yes\n")
	fmt.Fprintf(out, "Organization:     %s (org_id %s)\n", st.OrgName, st.OrgID)
	fmt.Fprintf(out, "User:             %s\n", st.UserEmail)
	fmt.Fprintf(out, "Server:           %s\n", st.OrgServerURL)
	fmt.Fprintf(out, "Enrolled at:      %s\n", st.EnrolledAt)
	fmt.Fprintf(out, "Credential store: %s\n", st.Backend)
	fmt.Fprintf(out, "Pushing enabled:  %t\n", rep.PushingEnabled)
	fmt.Fprintln(out)

	// Governance posture - LOUD states only (Track C item 1). A healthy or
	// ungoverned node prints nothing here, so the line's presence is itself
	// the signal.
	if rep.GovernanceLine != "" {
		fmt.Fprintln(out, rep.GovernanceLine)
		fmt.Fprintln(out)
	}
	if rep.TenancyLine != "" {
		fmt.Fprintln(out, rep.TenancyLine)
		fmt.Fprintln(out)
	}
	if rep.IntelLine != "" {
		fmt.Fprintln(out, rep.IntelLine)
		fmt.Fprintln(out)
	}

	fmt.Fprintf(out, "Share mode:       %s\n", rep.ShareLine)
	if len(rep.TargetActions) > 0 {
		fmt.Fprintf(out, "Per-action raws: %v\n", rep.TargetActions)
	}
	fmt.Fprintln(out)

	fmt.Fprintf(out, "%-12s  %12s  %12s\n", "Table", "historical", "eligible")
	fmt.Fprintf(out, "%-12s  %12s  %12s\n", "----", "----------", "--------")
	for _, row := range rep.statusTableRows() {
		fmt.Fprintf(out, "%-12s  %12d  %12d\n", row.name, row.historical, row.eligible)
	}
	if p := rep.PendingResends; len(p) > 0 {
		fmt.Fprintf(out, "Pending re-sends: sessions=%d actions=%d api_turns=%d token_usage=%d\n",
			p["sessions"], p["actions"], p["api_turns"], p["token_usage"])
	}
	if rep.Tombstones+rep.Manifests > 0 {
		fmt.Fprintf(out, "Pending deletions: %d (session manifests: %d)\n", rep.Tombstones, rep.Manifests)
	}
	fmt.Fprintln(out)

	// Explain an eligible==0 state in plain language (Phase C #8) so
	// "historical N, eligible 0" isn't a silent dead end.
	if rep.EligibleReason != "" {
		fmt.Fprintln(out, "Why eligible = 0:")
		fmt.Fprintf(out, "  %s\n", rep.EligibleReason)
		fmt.Fprintln(out)
	}

	if st.LastPush == nil {
		fmt.Fprintln(out, "Last push:        (none yet)")
	} else {
		lp := st.LastPush
		fmt.Fprintf(out, "Last push:        %s - %s, %d rows, %d bytes%s\n",
			lp.PushedAt, lp.Status, lp.RowCount, lp.Bytes, errSuffix(lp.Error))
	}
	for _, r := range rep.Oversized {
		fmt.Fprintf(out, "Unshippable rows: %s\n", r.Summary())
	}
}

// grantShowReport is `observer org grant show`.
type grantShowReport struct {
	Live        govern.LiveIdentity
	Grant       *govern.Grant
	Row         store.EnrolmentGrant
	ContentLine string
	Families    []governedFamilyRow
	Key         verdictLines
	Signature   verdictLines
	Stale       []string
	Expired     bool
}

// verdictLines is one verification verdict: a tone ("ok"/"info"/"warn") and
// the CLI's lines (continuations already indented).
type verdictLines struct {
	Level string
	Lines []string
}

// governedFamilyRow is one [org_client.policy] family a grant governs, with
// whether this machine's config currently accepts / preauthorizes it.
type governedFamilyRow struct {
	Family        string
	Accepted      bool
	Preauthorized bool
}

// governedFamilyRows computes the W-7 family table (config-side only).
func governedFamilyRows(authority []string, policy config.OrgClientPolicyConfig) []governedFamilyRow {
	families := govern.GovernedFamilies(authority)
	accepted := make(map[string]bool, len(policy.AcceptFamilies))
	for _, f := range policy.AcceptedFamilies() {
		accepted[f] = true
	}
	preauth := make(map[string]bool, len(policy.PreauthorizeEnforce))
	for _, f := range policy.PreauthorizedFamilies() {
		preauth[f] = true
	}
	rows := make([]governedFamilyRow, 0, len(families))
	for _, f := range families {
		rows = append(rows, governedFamilyRow{Family: f, Accepted: accepted[f], Preauthorized: preauth[f]})
	}
	return rows
}

// grantConsentLine renders a grant's consent for the CLI and dashboard grant
// reports, presenting as the organization's statement only the fields its
// signature covers (Sol A3-03). An actor (or a mode) outside the signature is
// labelled as recorded on this machine, so a database edit to it cannot pass
// as signed attribution.
func grantConsentLine(g *govern.Grant) string {
	actor := func() string {
		if g.ConsentActor == "" {
			return ""
		}
		return "; actor " + g.ConsentActor + " recorded on this machine, not signed by the organization"
	}
	if g.Integrity != govern.GrantIntegrityValid {
		return fmt.Sprintf("%s (%s), not verified against the organization signature", g.ConsentMode, g.ConsentActor)
	}
	switch g.ConsentEvidence {
	case govern.ConsentEvidenceModeAndActor:
		if g.ConsentActor == "" {
			return g.ConsentMode
		}
		return fmt.Sprintf("%s (%s)", g.ConsentMode, g.ConsentActor)
	case govern.ConsentEvidenceMode:
		return g.ConsentMode + actor()
	default:
		return g.ConsentMode + " (from the enrolment type)" + actor()
	}
}

// managedConsentRefusalLine is the plain-language line for a grant that
// claims managed consent and carries authority but is REFUSED as managed
// because it would cross tenancy (OSH-R-013, P-204), naming why. A node whose
// org switched it to enterprise is managed and prints nothing; so does a
// node whose org switched back (its narrowing grant claims nothing).
func managedConsentRefusalLine(g *govern.Grant) string {
	why := govern.ManagedConsentRefusal(g)
	if why == "" {
		return ""
	}
	return "Managed:      REFUSED - " + why + ",\n" +
		"              so the managed consent this grant claims is not honoured (no enforce.*,\n" +
		"              extract.managed or managed dashboard visibility)."
}

// grantKeyVerdict answers "is this grant bound to the key I pin?".
func grantKeyVerdict(grant *govern.Grant, live govern.LiveIdentity) verdictLines {
	switch {
	case grant.KeyPinSHA256 == "":
		return verdictLines{"warn", []string{"Signing key:  NOT BOUND (this grant predates key binding and will not be honoured)"}}
	case grant.KeyPinSHA256 == live.KeyPinSHA256:
		return verdictLines{"ok", []string{fmt.Sprintf("Signing key:  verified against the pinned organization key (%s)", short(grant.KeyPinSHA256))}}
	default:
		return verdictLines{"warn", []string{
			fmt.Sprintf("Signing key:  MISMATCH - grant bound to %s, this machine now pins %s.", short(grant.KeyPinSHA256), short(live.KeyPinSHA256)),
			"              The grant is NOT being honoured. Re-enrol to re-establish it.",
		}}
	}
}

// grantSignatureVerdict answers "is this still the document the organization
// signed?" (Track C item 1's runtime re-verification).
func grantSignatureVerdict(grant *govern.Grant) verdictLines {
	switch grant.Integrity {
	case govern.GrantIntegrityValid:
		return verdictLines{"ok", []string{"Signature:    re-verified just now against the organization key recorded at enrolment"}}
	case govern.GrantIntegrityInvalid:
		return verdictLines{"warn", []string{
			"Signature:    DOES NOT VERIFY - the stored grant is not the document the organization signed.",
			"              This machine's authority record has been altered. The grant is NOT being",
			"              honoured. Re-enrol to re-establish it; the organization can see this too.",
		}}
	default:
		return verdictLines{"info", []string{
			"Signature:    NOT RE-CHECKED - this machine holds no organization signing key material",
			"              (an older enrolment, or a server that delivered no policy key). Re-enrol to record it.",
		}}
	}
}

// collectGrantShow resolves the recorded grant through the daemon's own
// identity loader.
func collectGrantShow(ctx context.Context, b orgBundle, _ string) (grantShowReport, error) {
	grant, live, err := governanceIdentityLoader(b.store)(ctx)
	if err != nil {
		return grantShowReport{}, err
	}
	rep := grantShowReport{Live: live, Grant: grant}
	if !live.Enrolled || grant == nil {
		return rep, nil
	}
	rep.Row, _, _ = b.store.LoadEnrolmentGrant(ctx, live.OrgKey) //nolint:errcheck // display-only; a read failure just omits the renewal detail
	// W4f (R9.5 / R11.10): the one line that says what the grant DOES to
	// this machine's content sharing, resolved through the same predicate
	// the push seam ships under.
	rep.ContentLine = enterpriseContentLine(ctx, b.cfg, b.store, newLogger("warn"))
	rep.Families = governedFamilyRows(grant.Authority, b.cfg.OrgClient.Policy)
	rep.Key = grantKeyVerdict(grant, live)
	rep.Signature = grantSignatureVerdict(grant)
	if grant.Generation != live.Generation {
		rep.Stale = []string{
			fmt.Sprintf("Enrolment:    STALE - grant recorded for enrolment %d, this machine is on %d.", grant.Generation, live.Generation),
			"              The grant is NOT being honoured.",
		}
	}
	rep.Expired = !grant.ExpiresAt.IsZero() && time.Now().UTC().After(grant.ExpiresAt)
	return rep, nil
}

// printGrantShow renders the grant report exactly as `observer org grant
// show` always has.
func printGrantShow(out io.Writer, rep grantShowReport, cfg config.Config, configPath string) {
	if !rep.Live.Enrolled {
		fmt.Fprintln(out, "Not enrolled, so nothing manages this machine.")
		return
	}
	grant := rep.Grant
	if grant == nil {
		fmt.Fprintln(out, "Enrolled, but NOT governed: this machine granted no authority to the organization.")
		fmt.Fprintln(out, "Your dashboard and settings are entirely local.")
		return
	}
	fmt.Fprintf(out, "Granted to:   %s (org_id %s)\n", grant.OrgName, grant.OrgID)
	fmt.Fprintf(out, "Server:       %s\n", grant.OrgServerURL)
	fmt.Fprintf(out, "Granted at:   %s\n", formatGrantStamp(grant.GrantedAt))
	fmt.Fprintln(out, expiryLine(grant, rep.Row))
	fmt.Fprintf(out, "Consent:      %s\n", grantConsentLine(grant))
	if line := managedConsentRefusalLine(grant); line != "" {
		fmt.Fprintln(out, line)
	}
	fmt.Fprintf(out, "Receipt:      %s\n", grant.ReceiptHash)
	fmt.Fprintln(out, "\nAuthority granted:")
	for _, tok := range grant.Authority {
		fmt.Fprintf(out, "  - %-24s %s\n", tok, authorityPlainEnglish(tok))
	}
	fmt.Fprintln(out, rep.ContentLine)
	printGovernedFamilies(out, grant.Authority, cfg.OrgClient.Policy)
	fmt.Fprintln(out)
	for _, v := range []verdictLines{rep.Key, rep.Signature, {Lines: rep.Stale}} {
		for _, ln := range v.Lines {
			fmt.Fprintln(out, ln)
		}
	}
	if rep.Expired {
		fmt.Fprintln(out, "Status:       EXPIRED - local settings apply again.")
	}
	printPinnedSettings(out, cfg, configPath)
	fmt.Fprintln(out, "\nRun `observer unenroll` to revoke this at any time.")
}

// pinnedSettingsLines captures the §1.7 pinned-settings disclosure as lines
// (header dropped) so the dashboard shows the same mechanism disclosure the
// CLI prints, from the same function.
func pinnedSettingsLines(cfg config.Config, configPath string) []string {
	var buf bytes.Buffer
	printPinnedSettings(&buf, cfg, configPath)
	var lines []string
	for _, ln := range strings.Split(buf.String(), "\n") {
		t := strings.TrimSpace(ln)
		if t == "" || t == "Pinned settings:" {
			continue
		}
		lines = append(lines, t)
	}
	return lines
}

// pushNowReport is `observer org push-now`.
type pushNowReport struct {
	Result        orgclient.PushResult
	HaveIDs       bool
	Cursor        store.PushCursor
	MaxIDs        store.PushCursor
	LastPush      *store.PushLogEntry
	DisplayPolicy string
}

// performPushNow runs one push cycle the way a loop cycle does: rails first
// (the budget posture boundary the daemon wires), envelope second
// (demo-estate finding 2026-09-20), then the developer cost-display rail.
func performPushNow(ctx context.Context, b orgBundle) (pushNowReport, error) {
	wireCLIBudgetPosture(ctx, b, newLogger("warn"))
	res, err := b.client.PushNow(ctx)
	if err != nil {
		return pushNowReport{}, err
	}
	rep := pushNowReport{Result: res}
	if res.Empty {
		// M5.3: don't say "nothing to push" without the why.
		cur, cerr := b.store.LoadPushCursor(ctx)
		maxIDs, mErr := b.store.CurrentMaxIDs(ctx)
		if cerr == nil && mErr == nil {
			rep.HaveIDs, rep.Cursor, rep.MaxIDs = true, cur, maxIDs
		}
		if lp, lpErr := b.store.LastPushLog(ctx); lpErr == nil {
			rep.LastPush = lp
		}
	}
	var buf bytes.Buffer
	reportDisplayPolicy(ctx, &buf, b.client)
	rep.DisplayPolicy = strings.TrimSpace(buf.String())
	return rep, nil
}

// printPushNowReport renders the push-now report as the CLI always has.
func printPushNowReport(out io.Writer, rep pushNowReport) {
	if rep.Result.Empty {
		fmt.Fprintln(out, "Nothing to push - the cursor is up to date.")
		if rep.HaveIDs {
			cur, maxIDs := rep.Cursor, rep.MaxIDs
			fmt.Fprintf(out, "  cursor:   sessions=%d actions=%d api_turns=%d token_usage=%d guard_events=%d\n",
				cur.Sessions, cur.Actions, cur.APITurns, cur.TokenUsage, cur.GuardEvents)
			fmt.Fprintf(out, "  max ids:  sessions=%d actions=%d api_turns=%d token_usage=%d guard_events=%d\n",
				maxIDs.Sessions, maxIDs.Actions, maxIDs.APITurns, maxIDs.TokenUsage, maxIDs.GuardEvents)
		}
		if lp := rep.LastPush; lp != nil {
			fmt.Fprintf(out, "  last push: %s - %s, %d rows, %d bytes%s\n",
				lp.PushedAt, lp.Status, lp.RowCount, lp.Bytes, errSuffix(lp.Error))
		}
	} else {
		res := rep.Result
		fmt.Fprintf(out, "Pushed %d rows (%d bytes): accepted=%d deduped=%d\n",
			res.RowCount, res.Bytes, res.AcceptedRows, res.DedupedRows)
	}
	if rep.DisplayPolicy != "" {
		fmt.Fprintln(out, rep.DisplayPolicy)
	}
}

// unenrolReport is `observer unenroll`.
type unenrolReport struct {
	WasEnrolled bool
	OrgName     string
	// Routes is what Leave did with each proxy route: removed when this
	// machine's enrolment wrote it, kept (and why) otherwise
	// (proxyroute.LeaveRoutes). RoutesWarn is set when the route step itself
	// failed; nothing was removed then.
	Routes     []proxyroute.LeaveRoute
	RoutesWarn string
	// BundleRemoved / BundleWarn describe the org policy bundle cache.
	BundleRemoved string
	BundleWarn    string
	// AdmissionWarn is set when the hook-path budget admission file could
	// not be removed (D-359, review P3-05).
	AdmissionWarn string
	// OrgNotified / OrgNotice: whether the organization recorded the leave
	// (T-718), and why not when it did not.
	OrgNotified bool
	OrgNotice   string
	// StepWarns are best-effort steps of the structured unenrol that failed;
	// the leave still completed.
	StepWarns []string
	// ConfigEdit / ConfigWarn describe the [org_client] enabled = false edit
	// (T-728); ConfigWarn is set when it could not be made.
	ConfigEdit orgClientCfgEdit
	ConfigWarn string
}

// unenrolLocalSteps are the rows of the conferred -> retired table that this
// package (not internal/orgclient) owns: local enforcement files. They run
// BEFORE the client's walk, so enforcement retires before identity.
var unenrolLocalSteps = []orgclient.UnenrolStep{
	{
		ID: "budget_stop_file", Phase: "enforcement",
		Conferred: "the hook-path budget stop file the daemon publishes for hook-capable tools",
		Retired:   "deleted, so no hook refuses a prompt or a tool call on the organization's behalf",
	},
	{
		ID: "org_policy_bundle", Phase: "enforcement",
		Conferred: "the organization's guard policy bundle (its strictness floor)",
		Retired:   "deleted; your own guard rules apply",
	},
}

// unenrolAfterSteps are this package's rows that run AFTER the client's walk
// succeeded (REVIEW-4 P4-13): rewriting the AI tools' own settings is the one
// change that would leave a still-enrolled managed node unrouted if the walk
// then failed, so it waits until the leave can no longer fail.
var unenrolAfterSteps = []orgclient.UnenrolStep{
	{
		ID: "proxy_routes", Phase: "after",
		Conferred: "proxy routes the enrolment's --wire-clients step wrote into your AI tools",
		Retired:   "removed once the leave has completed, only where they are still exactly what enrolment wrote; routes you set are kept",
	},
	{
		// T-728 (D-542): the push switch the enrolment block set. AFTER the
		// walk for the same reason as the routes: a failed leave leaves a
		// still-enrolled node, which must keep pushing.
		ID: "org_client_enabled", Phase: "after",
		Conferred: "[org_client] enabled = true in your config.toml, the push switch the enrolment block set",
		Retired:   "set to false once the leave has completed, as a one-line edit that keeps every comment and every other line; re-enrolling sets it back to true and rewrites org_server_url",
	},
}

// unenrolKeptRows are what leaving deliberately does NOT touch, so the preview
// states the outcome: a plain individual node with all of its data.
var unenrolKeptRows = []orgclient.UnenrolStep{
	{
		ID: "local_config", Phase: "kept",
		Conferred: "the rest of your config.toml, including the [org_client] block's org_server_url, share and scope settings",
		Retired:   "kept untouched; with no enrolment nothing is pushed",
	},
	{
		// T-728: the machine key is this machine's identity towards each
		// organization (one Ed25519 seed per org, REVIEW-4 P4-15 / ledger
		// GRANT-18), not a credential the enrolment conferred: it proves
		// nothing without the org bearer the credentials step deletes, and
		// the server keeps the (org, machine, member) registration after a
		// leave, so deleting it would make a return to the same organization
		// a permanent 409 until an admin reset.
		ID: "machine_key", Phase: "kept",
		Conferred: "this machine's per-organization machine key (the org-machine-key slot beside the org credentials)",
		Retired:   "kept: it is the machine's identity, not an access credential (it signs nothing useful without the org bearer, which is removed), and keeping it lets a return to the same organization reuse its registration; an organization admin can reset it",
	},
	{
		ID: "local_data", Phase: "kept",
		Conferred: "every local session, action, cost and budget row on this machine",
		Retired:   "kept; data already shared stays with the organization",
	},
}

// unenrolPlanRows is the whole preview, in apply order: this package's
// enforcement rows (performUnenrol runs them first), the client's ordered walk,
// the rows that wait for the walk to succeed, then what is kept. `observer
// unenroll --plan` and the dashboard's Leave dialog both render it.
func unenrolPlanRows() []orgclient.UnenrolStep {
	out := append([]orgclient.UnenrolStep{}, unenrolLocalSteps...)
	out = append(out, orgclient.UnenrolPlan()...)
	out = append(out, unenrolAfterSteps...)
	return append(out, unenrolKeptRows...)
}

// printUnenrolPlan renders the preview for `observer unenroll --plan`.
func printUnenrolPlan(out io.Writer, enrolled bool, orgName string) {
	if !enrolled {
		fmt.Fprintln(out, "Not enrolled; leaving would change nothing.")
		return
	}
	fmt.Fprintf(out, "Leaving %s would do this, in order (nothing has been changed):\n", orgName)
	for i, s := range unenrolPlanRows() {
		fmt.Fprintf(out, "%2d. [%s] %s\n    -> %s\n", i+1, s.Phase, s.Conferred, s.Retired)
	}
	fmt.Fprintln(out, "Agent sessions keep working at every step: requests are admitted the moment the enrolment is fenced.")
	fmt.Fprintln(out, "Outcome: a plain individual node with no organization policy. Run `observer unenroll` to apply.")
}

// leaveRoutes plans (apply false) or performs (apply true) the proxy-route
// part of leaving, through the registrar for this config's proxy port. One
// function for `observer unenroll`, the dashboard's Leave and its confirm
// dialog, so the three can never disagree about what Leave touches.
func leaveRoutes(configPath string, apply bool) ([]proxyroute.LeaveRoute, error) {
	proxyPort := 8820
	if cfg, err := config.Load(config.LoadOptions{GlobalPath: configPath}); err == nil && cfg.Proxy.Port > 0 {
		proxyPort = cfg.Proxy.Port
	}
	reg, err := proxyroute.NewRegistrar(proxyroute.RegisterOptions{ProxyPort: proxyPort})
	if err != nil {
		return nil, err
	}
	return reg.LeaveRoutes(apply)
}

// performUnenrol leaves the organization and runs the symmetric cleanup.
func performUnenrol(ctx context.Context, b orgBundle, configPath string) (unenrolReport, error) {
	st, err := b.client.Status(ctx)
	if err != nil {
		return unenrolReport{}, err
	}
	if !st.Enrolled {
		return unenrolReport{}, nil
	}
	rep := unenrolReport{WasEnrolled: true, OrgName: st.OrgName}
	// ENFORCEMENT BEFORE IDENTITY (T-718): the local enforcement artifacts go
	// first (unenrolLocalSteps), then the client's ordered walk.
	//
	// The organization's budget stops leave with it (D-359, review P3-05):
	// the hook-path admission file's only publisher runs while enrolled, so
	// a stop left here would deny every hook until its period ended.
	if aerr := clearBudgetAdmission(b.cfg.Observer.DBPath); aerr != nil {
		rep.AdmissionWarn = fmt.Sprintf("org budget stop file not removed (%v); delete %s manually.", aerr,
			budgetwarnfile.AdmissionPath(b.cfg.Observer.DBPath))
	}
	defer func() {
		// Belt and braces: a publisher tick that raced the walk is gone too.
		_ = clearBudgetAdmission(b.cfg.Observer.DBPath)
	}()

	// Symmetric cleanup for the org policy bundle (guard spec §14.2):
	// leaving the org removes its strictness floor. Best-effort (the file
	// may never have existed); the append-only key-pin history in
	// guard_policy_state deliberately stays as audit.
	cfg, cfgErr := config.Load(config.LoadOptions{GlobalPath: configPath})
	if cfgErr == nil {
		if cachePath := orgBundleCachePath(cfg); cachePath != "" {
			if rmErr := os.Remove(cachePath); rmErr == nil {
				rep.BundleRemoved = cachePath
			} else if !os.IsNotExist(rmErr) {
				rep.BundleWarn = fmt.Sprintf("org policy bundle not removed (%v) - delete %s manually to drop the org policy layer.", rmErr, cachePath)
			}
		}
	}
	// The client's ordered walk: fence, grant, budget, documents, governance,
	// the org notice, then credentials and the enrolment row (orgclient/unenrol.go).
	res, err := b.client.UnenrollWithReport(ctx)
	if err != nil {
		return unenrolReport{}, err
	}
	rep.OrgNotified, rep.OrgNotice = res.OrgNotified, res.OrgNotice
	for _, s := range res.Steps {
		if s.Err != "" {
			rep.StepWarns = append(rep.StepWarns, fmt.Sprintf("%s: %s", s.ID, s.Err))
		}
	}
	// Symmetric cleanup for the proxy routes the enrolment's --wire-clients
	// step wrote (Claude Code's ANTHROPIC_BASE_URL, Codex's provider, ...):
	// remove exactly those, and only while they are still what enrolment
	// wrote. A route you, `observer init` or Settings > Setup set is kept;
	// the record of who wrote it is made at write time (internal/routeprov),
	// never guessed from the value. Best-effort: a failure here doesn't fail
	// unenroll.
	//
	// AFTER the walk succeeded (REVIEW-4 P4-13): removing them first left a
	// leave that failed at the fence or a later Required step with a
	// still-enrolled managed node whose AI tools now went to the vendor
	// directly, and the error path dropped the report of what was changed.
	if routes, rerr := leaveRoutes(configPath, true); rerr != nil {
		rep.RoutesWarn = fmt.Sprintf("proxy routes were not checked (%v); nothing was removed from your AI tools' settings.", rerr)
	} else {
		rep.Routes = routes
	}
	// T-728: turn the push switch off in the node's own config.toml, the
	// same AFTER-the-walk rule. Best-effort: a failure is reported, never
	// fails the leave.
	if p, perr := resolveConfigPath(configPath); perr != nil {
		rep.ConfigWarn = fmt.Sprintf("config.toml was not resolved (%v); set [org_client] enabled = false yourself.", perr)
	} else {
		edit, eerr := applyOrgClientConfigEdge(p, orgClientCfgLeave, "")
		rep.ConfigEdit = edit
		if eerr != nil {
			rep.ConfigWarn = fmt.Sprintf("[org_client] enabled was not set to false in %s (%v); set it yourself.", p, eerr)
		}
	}
	return rep, nil
}

// printUnenrolReport renders the unenrol report as the CLI always has.
func printUnenrolReport(out io.Writer, rep unenrolReport) {
	if !rep.WasEnrolled {
		fmt.Fprintln(out, "Not enrolled; nothing to do.")
		return
	}
	fmt.Fprintf(out, "Unenrolled from %s. Local credentials cleared.\n", rep.OrgName)
	// Admin-controlled Plane B (spec §5.1): Unenroll deleted the enrolment
	// grant, so any organization governance of this machine's dashboard
	// lifted with it. Say so explicitly.
	fmt.Fprintln(out, "Any organization governance of this dashboard has been removed; your own settings apply again.")
	fmt.Fprintln(out, "Settings the organization pinned (guard.mode, guard.budget.hard, ...) return to your own values when the daemon next restarts; the budget fail_closed posture follows at once.")
	fmt.Fprintln(out, "Data already shared with the organization stays with the organization.")
	for _, r := range rep.Routes {
		switch {
		case r.Error != "":
			fmt.Fprintf(out, "Warning: kept the %s proxy route in %s: %s\n", routeprov.ToolLabel(r.Tool), r.ConfigPath, r.Error)
		case r.Removed:
			fmt.Fprintln(out, "Removed "+strings.TrimPrefix(r.Message, "Removes "))
		default:
			fmt.Fprintln(out, r.Message)
		}
	}
	if rep.RoutesWarn != "" {
		fmt.Fprintf(out, "Warning: %s\n", rep.RoutesWarn)
	}
	if rep.BundleRemoved != "" {
		fmt.Fprintf(out, "Removed org policy bundle %s.\n", rep.BundleRemoved)
	}
	if rep.BundleWarn != "" {
		fmt.Fprintf(out, "Warning: %s\n", rep.BundleWarn)
	}
	if rep.AdmissionWarn != "" {
		fmt.Fprintf(out, "Warning: %s\n", rep.AdmissionWarn)
	}
	for _, w := range rep.StepWarns {
		fmt.Fprintf(out, "Warning: a best-effort leave step did not finish (%s); the leave itself completed.\n", w)
	}
	switch {
	case rep.ConfigWarn != "":
		fmt.Fprintf(out, "Warning: %s\n", rep.ConfigWarn)
	case rep.ConfigEdit.Wrote:
		fmt.Fprintf(out, "Set [org_client] enabled = false in %s (one line; comments and every other setting kept). Re-enrolling turns it back on.\n", rep.ConfigEdit.Path)
	}
	fmt.Fprintln(out, "Kept this machine's machine key: it identifies the machine to an organization and grants nothing without the org credentials removed above.")
	if rep.OrgNotified {
		fmt.Fprintln(out, "The organization recorded that this node left.")
	} else if rep.OrgNotice != "" {
		fmt.Fprintf(out, "The organization was not told: %s.\n", rep.OrgNotice)
	}
	fmt.Fprintln(out, "This is now a plain individual node: no organization policy applies, and your local data and the rest of config.toml are kept.")
}
