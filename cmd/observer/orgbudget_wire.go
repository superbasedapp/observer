package main

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"strings"
	"sync/atomic"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/guard"
	"github.com/marmutapp/superbased-observer/internal/orgbudget"
	"github.com/marmutapp/superbased-observer/internal/orgclient"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// The org BUDGET boundary
// (docs/plans/org-budget-enforcement-and-token-display-plan-2026-09-07.md
// §3.3c/§3.3d, wave W3b).
//
// This is the ONE place the three subsystems meet, and each of them stays
// ignorant of the others (CLAUDE.md #2):
//
//   - internal/orgclient fetches and verifies a signed body and hands over a
//     typed outcome. It knows nothing about the guard.
//   - internal/orgbudget composes local ∧ org into effective numbers + an
//     enum-only posture. It is pure: no config, no guard, no store.
//   - internal/guard receives ONE config.GuardBudgetConfig and rebuilds. It
//     never learns whether a number was lowered, replaced, or purely local.
//
// The capability resolution — "is this node MANAGED and does its grant carry
// enforce.budget?" — happens HERE, once, and is passed as a bool. Nothing
// downstream branches on tenancy, on an authority token, or on where a number
// came from (CLAUDE.md #3).
//
// COVERAGE, stated once and carried onto the wire: the guard can only refuse a
// request on the PROXY path (internal/guard/budget.go::scanBudget). Hook-path
// and watcher-path events are stamped but nothing there can block. The posture
// therefore always ships Coverage = proxy_only, so an admin reading the
// dashboard can tell "enforced" from "advisory" from "not covered" instead of
// assuming the first.

// orgBudgetHandle owns the daemon-lifetime budget composition state: the
// node's OWN configured numbers (the composition's left operand, never
// mutated), the capability resolvers, and the last posture.
type orgBudgetHandle struct {
	guard *guard.Guard
	// local is the node's own [guard.budget] block, captured once at wiring.
	// It is the left operand of every composition: composing against the
	// PREVIOUS effective value instead would ratchet a node permanently
	// tighter, because each cycle would re-lower an already-lowered number and
	// a withdrawn org cap could never be released.
	local config.GuardBudgetConfig
	// authoritative reports whether this node is MANAGED and its grant carries
	// govern.AuthorityEnforceBudget. Resolved LIVE on every cycle (the
	// routingHandle.SetManagedEnforce precedent) so a revoked grant stops
	// being authoritative without a restart. nil = never authoritative, which
	// is every individual/BYO node.
	authoritative func() bool
	// identityStore resolves the current enrollment epoch at publication time.
	// It prevents a delayed fetch outcome from replacing the proxy engine with
	// another member's cap after an external re-enrollment.
	identityStore *store.Store
	logger        *slog.Logger
	posture       atomic.Pointer[orgcontract.BudgetPostureRow]
}

// newOrgBudgetHandle wires the boundary. g may be nil (the guard is off or
// failed to construct): the handle then applies nothing and reports a posture
// whose mode is "off", which is the honest answer — a node with no guard
// enforces no budget.
func newOrgBudgetHandle(g *guard.Guard, local config.GuardBudgetConfig, authoritative func() bool, identityStore *store.Store, logger *slog.Logger) *orgBudgetHandle {
	h := &orgBudgetHandle{
		guard: g, local: local, authoritative: authoritative,
		identityStore: identityStore, logger: logger,
	}
	if g != nil && identityStore != nil {
		g.SetBudgetBindingLookup(func() (string, bool) {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			identity, active, err := orgclient.CurrentBudgetIdentity(ctx, identityStore)
			return identity.Binding, err == nil && active && identity.Binding != ""
		})
	}
	return h
}

// Prime publishes the FIRST posture, and it is deliberately NOT done at
// construction (org-observer fundamentals finding H3c).
//
// The capability this handle branches on — "is this node managed and does its
// grant carry enforce.budget?" — is resolved through the governance handle's
// IDENTITY LOADER, which `observer start` installs LATER than it builds this
// wire. A posture published before that loader exists answers the question
// with `false` for every node, so a push landing in that window reports a
// managed fleet as un-required and un-armed: the wire would say the org's
// budget is not needed here, on precisely the machines where it is.
//
// Publishing nothing until Prime is called is the honest alternative: the
// posture provider reports ok=false, no row ships, and the server reads "not
// reported" — which is true — instead of a verdict that is false.
//
// outcome is what the node knows before its first poll: the PERSISTED document
// restored from org_budget_cache (state unreachable + HaveBody, so the last
// verified caps are in force and the posture says the org has not been reached
// yet), or an empty outcome when nothing is stored — which on a node that
// requires an org budget arms the block immediately rather than a push
// interval later.
func (h *orgBudgetHandle) Prime(outcome orgclient.BudgetFetchOutcome) {
	if h == nil {
		return
	}
	if outcome.State == "" {
		outcome.State = initialFetchState(h.local.FromOrg)
	}
	h.apply(outcome)
}

// initialFetchState is the honest pre-first-poll state: "disabled" when the
// node never opted in, otherwise "unreachable" — nothing has been fetched yet,
// and claiming ok before a single successful poll would be a lie in the
// dangerous direction.
func initialFetchState(fromOrg bool) string {
	if !fromOrg {
		return orgcontract.BudgetFetchDisabled
	}
	return orgcontract.BudgetFetchUnreachable
}

// onBudgetFetch is the orgclient.SetBudgetSink callback: one composition +
// apply per poll cycle. It never returns an error and never blocks the push
// loop — a failed apply leaves the running engine untouched (guard's own
// fail-safe) and is logged.
func (h *orgBudgetHandle) onBudgetFetch(o orgclient.BudgetFetchOutcome) {
	if h == nil {
		return
	}
	h.apply(o)
}

// apply composes and publishes. Split from onBudgetFetch so construction can
// seed the initial posture through exactly the same path.
func (h *orgBudgetHandle) apply(o orgclient.BudgetFetchOutcome) {
	o = h.bindOutcomeToCurrentIdentity(o)
	granted := false
	caps := orgbudget.Capabilities{
		FromOrg:    h.local.FromOrg,
		HaveBody:   o.HaveBody,
		FetchState: o.State,
		GuardMode:  h.guardMode(),
		// The clock and the staleness window for the org's CROSS-MACHINE spend
		// baseline (bundle BUD-N / P1-9). The window is derived from the
		// cadence the poll loop stamped on this very outcome, because the org's
		// measurement can only be as fresh as this node's own reporting; the
		// pure composer takes both as inputs so a freshness test is a table row
		// and not a sleep.
		Now:            time.Now().UTC(),
		BaselineMaxAge: orgbudget.BaselineMaxAge(o.PushInterval),
		// ONE SUBJECT IDENTITY, taken from the guard rather than rebuilt here
		// (bundle BUD-N, adversarial review P1-3). The same function the
		// accounting owner keys ByTool / ByModel with and the budget stamp reads
		// the event's tool and model through — so the org's cap id, this node's
		// accounting key and the evaluated event cannot spell a subject three
		// ways. A nil guard (guard off, or the CLI's own recomposition) leaves
		// it nil, which is the plain trim+lowercase rule the contract already
		// applied.
		ResolveSubjectID: h.guard.BudgetSubjectResolver(),
	}
	if h.authoritative != nil {
		// ONE predicate, TWO capabilities (org-budget ruling R2). The
		// governance grant answers "managed tenancy AND enforce.budget", and
		// that same answer is what makes the org's numbers authoritative and
		// what makes their ABSENCE a block. They are set as two flags rather
		// than one because they are two different questions the pure composer
		// must be able to answer independently — see orgbudget.Capabilities.
		granted = h.authoritative()
		caps.OrgAuthoritative = granted
		caps.RequireOrgBudget = granted
	}
	effective, posture := orgbudget.Compose(thresholdsOf(h.local), o.Body, caps)
	// WHICH PRICE TABLE the caps are measured in (pricing arc §3.3). It is
	// stamped HERE, at the boundary, rather than inside Compose: internal/
	// orgbudget composes CAPS, and threading a pricing outcome through its
	// signature would couple two rails that share a config switch and nothing
	// else. The value is published by the pricing boundary
	// (orgpricing_wire.go) on its own cycle and read here, so the pair on the
	// wire always describes the engine that is actually running.
	//
	// A cap without its unit is not a cap: an admin authoring $500 needs to
	// know whether this developer's dollars are the org's negotiated ones.
	posture.PricingSource, posture.PricingVersion = nodePricingPostureFor()
	row := posture.Row()
	h.posture.Store(&row)

	if effective.BudgetRequired {
		// LOUD, because this posture refuses traffic. It is the intended
		// enterprise outcome (ruling R2) and it is also what a broken budget
		// rail looks like, so the line names the fetch state that caused it.
		h.logger.Warn("no verified organization budget on a managed node; proxied requests are refused until one arrives",
			"fetch_state", posture.FetchState, "guard_mode", posture.Mode)
	}
	if h.guard == nil {
		return
	}
	// ONE COMPOSITION, ONE PUBLICATION (adversarial review of BUD-N, P2-6).
	//
	// The org's PER-TOOL / PER-MODEL caps and the cross-machine baseline are
	// not ceilings on config.GuardBudgetConfig — that type is the operator's
	// own [guard.budget] block and a comparable value the guard's no-op check
	// depends on — so they travel as what they are: a resolved cap table and
	// one set of addends. They used to travel on their OWN apply, which meant
	// two engine rebuilds per cycle and, between them, a live engine holding
	// the NEW cap table against the PREVIOUS authority provenance and the
	// previous fail-closed posture — a snapshot no composition ever produced. A
	// request arriving in that window could be judged against a cap the org had
	// just authored under authority it had just revoked, or the reverse.
	//
	// They come out of one signed body and one Compose call, so they are
	// published together and the engine is rebuilt once. The call is a no-op
	// when nothing changed, so the steady state stays free.
	if err := h.guard.ApplyOrgComposedBudget(
		withThresholds(h.local, effective), effective.SoftWindows,
		effective.BudgetRequired, budgetProtectionOf(effective.Protection),
		o.Binding, guardBudgetDocumentWitness(o.Witness),
		budgetBaselineOf(effective.Baseline), effective.Baseline.FlagOnly, subjectCapsOf(effective.Subjects),
		guard.BudgetCalendars{DailyTimezone: effective.DailyTimezone, MonthlyTimezone: effective.MonthlyTimezone},
	); err != nil {
		// Fail-open and LOUD: the guard kept its previous engine, so nothing
		// broke, but an org cap that could not be applied must not be silent.
		h.logger.Warn("org budget not applied; the guard kept its previous thresholds and cap table",
			"source", posture.Source, "fetch_state", posture.FetchState, "err", err)
	}
}

func guardBudgetDocumentWitness(w store.OrgBudgetWitness) guard.BudgetDocumentWitness {
	return guard.BudgetDocumentWitness{Known: w.Known, Present: w.Present, SHA256: w.SHA256}
}

// bindOutcomeToCurrentIdentity is the final publication fence shared by proxy
// and native enforcement. FetchBudgetPolicy fences its own cache writes, but
// re-enrollment can occur after it returns and before the push loop invokes
// this sink. Only an exact current binding may publish a verified body. A
// current no-body outcome is stamped with the current binding so B-625 and the
// native authority check describe the same enrollment epoch.
func (h *orgBudgetHandle) bindOutcomeToCurrentIdentity(o orgclient.BudgetFetchOutcome) orgclient.BudgetFetchOutcome {
	if h == nil || h.identityStore == nil {
		return o
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	identity, active, err := orgclient.CurrentBudgetIdentity(ctx, h.identityStore)
	if err != nil {
		h.logger.Warn("org budget publication refused: current enrollment identity is unavailable", "err", err)
		return orgclient.BudgetFetchOutcome{State: orgcontract.BudgetFetchUnverified}
	}
	if !active || identity.Binding == "" {
		return orgclient.BudgetFetchOutcome{State: orgcontract.BudgetFetchNotEnrolled}
	}
	if o.Binding == identity.Binding {
		return o
	}
	if o.Binding == "" && !o.HaveBody {
		o.Binding = identity.Binding
		return o
	}
	h.logger.Warn("org budget publication refused: fetch outcome belongs to a replaced enrollment")
	return orgclient.BudgetFetchOutcome{
		State: orgcontract.BudgetFetchUnverified, Binding: identity.Binding,
	}
}

// guardMode reports the guard's live mode for the posture. A nil guard is
// "off" — there is no enforcement point at all.
func (h *orgBudgetHandle) guardMode() string {
	if h.guard == nil {
		return "off"
	}
	return string(h.guard.Mode())
}

// postureProvider is the store seam: the last published posture, or ok=false
// before anything has been composed (in which case no row ships at all).
//
// OrgSubjectUnmatched is stamped HERE rather than inside Compose, and read at
// PUSH time rather than at budget-fetch time, for the reason the pricing
// coverage decorator gives (cmd/observer/budgetpricingcoverage.go): it is not a
// property of the COMPOSITION, it is what the node's own accounting observed
// about the caps that composition produced. Compose knows the cap ids and has
// never seen a row; the guard's budget stamp holds both and records the answer
// there. Reading it at push time means the row describes the accounting that is
// actually running, not the accounting that was running when the org's document
// last arrived.
func (h *orgBudgetHandle) postureProvider() store.BudgetPostureProvider {
	return func() (orgcontract.BudgetPostureRow, bool) {
		if h == nil {
			return orgcontract.BudgetPostureRow{}, false
		}
		row := h.posture.Load()
		if row == nil {
			return orgcontract.BudgetPostureRow{}, false
		}
		out := *row
		out.OrgSubjectUnmatched = h.guard.BudgetSubjectUnmatched()
		return out, true
	}
}

// thresholdsOf projects the node's [guard.budget] block onto the pure
// composition type. The two conversions live HERE, at the boundary, so
// internal/orgbudget never imports internal/config.
func thresholdsOf(c config.GuardBudgetConfig) orgbudget.Thresholds {
	return orgbudget.Thresholds{
		SessionUSD: c.SessionUSD, DailyUSD: c.DailyUSD,
		WeeklyUSD: c.WeeklyUSD, MonthlyUSD: c.MonthlyUSD,
		SessionTokens: c.SessionTokens, DailyTokens: c.DailyTokens,
		WeeklyTokens: c.WeeklyTokens, MonthlyTokens: c.MonthlyTokens,
		Hard: c.Hard,
	}
}

func budgetProtectionOf(p orgbudget.BudgetProtection) policy.BudgetProtection {
	return policy.BudgetProtection{
		SessionUSD: p.SessionUSD, DailyUSD: p.DailyUSD,
		WeeklyUSD: p.WeeklyUSD, MonthlyUSD: p.MonthlyUSD,
		SessionTokens: p.SessionTokens, DailyTokens: p.DailyTokens,
		WeeklyTokens: p.WeeklyTokens, MonthlyTokens: p.MonthlyTokens,
		ToolUSD: p.ToolUSD, ToolTokens: p.ToolTokens,
		ModelUSD: p.ModelUSD, ModelTokens: p.ModelTokens,
	}
}

// subjectCapsOf projects the composed per-subject caps onto the guard's shape.
// The third conversion at this boundary, for the same reason as the other two:
// internal/orgbudget must not import internal/policy.
func subjectCapsOf(in []orgbudget.SubjectCap) []policy.BudgetSubjectCap {
	if len(in) == 0 {
		return nil
	}
	out := make([]policy.BudgetSubjectCap, 0, len(in))
	for _, sc := range in {
		out = append(out, policy.BudgetSubjectCap{
			Kind: sc.Kind, ID: sc.ID, Window: sc.Window,
			CapUSD: sc.CapUSD, CapTokens: sc.CapTokens,
			BaselineUSD: sc.BaselineUSD, BaselineTokens: sc.BaselineTokens,
			BaselineFlagOnly: sc.BaselineFlagOnly,
			Hard:             sc.Hard,
		})
	}
	return out
}

// budgetBaselineOf projects the composed cross-machine baseline onto the shape
// the guard stamps onto every budget event.
func budgetBaselineOf(b orgbudget.Baseline) policy.BudgetWindowAmounts {
	return policy.BudgetWindowAmounts{
		SessionUSD: b.SessionUSD, DailyUSD: b.DailyUSD,
		WeeklyUSD: b.WeeklyUSD, MonthlyUSD: b.MonthlyUSD,
		SessionTokens: b.SessionTokens, DailyTokens: b.DailyTokens,
		WeeklyTokens: b.WeeklyTokens, MonthlyTokens: b.MonthlyTokens,
	}
}

// withThresholds returns base with its numeric ceilings replaced by t. Every
// NON-numeric field (the [guard.budget.window] utilization block, from_org)
// is carried through untouched: an org budget governs ceilings, not the
// provider usage-window guardrails, which are a different rule category with
// their own explicit deny thresholds.
//
// The composition's two NON-config outputs — the per-window soft set and the
// per-window timezones — are deliberately NOT folded in here:
// config.GuardBudgetConfig is a comparable value the guard's no-op check
// depends on, and neither output is a [guard.budget] key an operator can
// author. ApplyOrgBudget receives softWindows and calendars alongside the
// thresholds and seals all of them into the same policy snapshot.
func withThresholds(base config.GuardBudgetConfig, t orgbudget.Thresholds) config.GuardBudgetConfig {
	out := base
	out.SessionUSD, out.DailyUSD = t.SessionUSD, t.DailyUSD
	out.WeeklyUSD, out.MonthlyUSD = t.WeeklyUSD, t.MonthlyUSD
	out.SessionTokens, out.DailyTokens = t.SessionTokens, t.DailyTokens
	out.WeeklyTokens, out.MonthlyTokens = t.WeeklyTokens, t.MonthlyTokens
	out.Hard = t.Hard
	return out
}

// budgetDocumentMaxAge parses [guard.budget].max_document_age into the
// freshness window the org-budget rail applies to a signed document's
// issued_at (finding M3).
//
// An empty value is the 1h default. An UNPARSABLE value is also the default,
// and it WARNS: the alternative — treating garbage as "no limit" — would let
// a typo silently disable a replay defence, which is the class of failure
// that makes a security control worse than not having one.
func budgetDocumentMaxAge(cfg config.GuardBudgetConfig, logger *slog.Logger) time.Duration {
	raw := strings.TrimSpace(cfg.MaxDocumentAge)
	if raw == "" {
		return orgcontract.BudgetPolicyDefaultMaxAge
	}
	d, err := time.ParseDuration(raw)
	if err != nil || d <= 0 {
		if logger != nil {
			logger.Warn("guard budget: [guard.budget].max_document_age is not a positive Go duration; using the default",
				"value", raw, "default", orgcontract.BudgetPolicyDefaultMaxAge)
		}
		return orgcontract.BudgetPolicyDefaultMaxAge
	}
	return d
}

// guardBudgetPostureLine renders the budget posture for `observer guard
// status` (fundamentals finding H5).
//
// WHY THE CLI RECOMPOSES RATHER THAN READING A STORED POSTURE. The posture the
// daemon publishes lives in memory behind store.BudgetPostureProvider, and the
// CLI is a DIFFERENT PROCESS — there is nothing on disk to read. So it
// reassembles the posture from the same three inputs the daemon composes from,
// all of which ARE durable: the node's own [guard.budget] block, the
// governance grant (loaded through the same last-known-good path
// budgetEnforcementGranted uses), and the last VERIFIED body persisted in
// org_budget_cache (finding H3, which is what made this possible at all).
//
// The composition itself is orgbudget.Compose, not a second implementation:
// that is the whole point — the line a developer reads and the thresholds
// their proxy enforces come from one function, so they cannot disagree.
//
// The honest gap it CANNOT close: fetch_state describes the last poll THIS
// PROCESS made, and the CLI has made none. It reports what the stored evidence
// supports and says so, rather than inventing an `ok` it did not observe.
func guardBudgetPostureLine(ctx context.Context, cfg config.Config, database *sql.DB) string {
	if database == nil {
		return "not determined (no database)"
	}
	granted := budgetEnforcementGranted(ctx, cfg, database, slog.Default())
	return guardBudgetPostureLineWithGrant(ctx, cfg, database, granted)
}

// guardBudgetPostureLineWithGrant composes the CLI posture after the durable
// governance answer has been resolved. Managed authority requires the same
// binding and signature checks as daemon restore; an individual/status-only
// read may display a current-bound cache body even when the CLI has no live
// daemon key material to verify it with.
func guardBudgetPostureLineWithGrant(ctx context.Context, cfg config.Config, database *sql.DB, granted bool) string {
	if database == nil {
		return "not determined (no database)"
	}
	caps := orgbudget.Capabilities{
		FromOrg:          cfg.Guard.Budget.FromOrg,
		OrgAuthoritative: granted,
		RequireOrgBudget: granted,
		GuardMode:        cfg.Guard.Mode,
	}
	var (
		cached store.OrgBudgetCache
		err    error
	)
	if granted {
		cached, err = loadVerifiedOrgBudgetCache(ctx, cfg, store.New(database))
	} else {
		cached, err = loadCurrentBoundOrgBudgetCache(ctx, store.New(database))
	}
	switch {
	case err != nil:
		// A read failure is NOT "no body": on a node that requires one those
		// are opposite verdicts, and guessing the safe-looking one here would
		// print "armed" over a node that is fine (or the reverse).
		caps.FetchState = orgcontract.BudgetFetchUnverified
	case cached.Have:
		// The body is real and verified, but not by this process — the same
		// pair LoadPersistedBudget reports, for the same reason.
		caps.HaveBody = true
		caps.FetchState = orgcontract.BudgetFetchUnreachable
	default:
		caps.FetchState = initialFetchState(cfg.Guard.Budget.FromOrg)
	}
	_, posture := orgbudget.Compose(thresholdsOf(cfg.Guard.Budget), cached.Body, caps)
	return budgetPostureStatusLine(posture.Row())
}

// loadVerifiedOrgBudgetCache restores a managed budget through the one cold
// restore verifier. Reusing orgclient.Client.LoadPersistedBudget keeps the
// CLI and daemon aligned on enrollment binding, key fingerprint, signature,
// and the identity recheck around publication.
func loadVerifiedOrgBudgetCache(ctx context.Context, cfg config.Config, st *store.Store) (store.OrgBudgetCache, error) {
	if st == nil {
		return store.OrgBudgetCache{}, fmt.Errorf("org budget cache: store unavailable")
	}
	client := orgclient.New(cfg.OrgClient, st, nil, "", nil, nil)
	outcome, err := client.LoadPersistedBudget(ctx)
	result := store.OrgBudgetCache{
		Have: outcome.HaveBody, Body: outcome.Body, Binding: outcome.Binding, Witness: outcome.Witness,
	}
	if err != nil {
		return result, err
	}
	if !outcome.HaveBody {
		if !outcome.Witness.Valid() {
			return result, fmt.Errorf("org budget cache: durable document witness unavailable")
		}
		if outcome.Witness.Present {
			return result, fmt.Errorf("org budget cache: persisted body has no active enrollment binding")
		}
		return result, nil
	}
	return result, nil
}

// loadCurrentBoundOrgBudgetCache reads a cache for a status-only display when
// the node is not currently authoritative. It still fences the row to the
// current enrollment epoch, so an old member's or legacy unbound body cannot
// be presented as this node's current budget.
func loadCurrentBoundOrgBudgetCache(ctx context.Context, st *store.Store) (store.OrgBudgetCache, error) {
	if st == nil {
		return store.OrgBudgetCache{}, fmt.Errorf("org budget cache: store unavailable")
	}
	identity, active, err := orgclient.CurrentBudgetIdentity(ctx, st)
	if err != nil {
		return store.OrgBudgetCache{}, err
	}
	cached, err := st.LoadOrgBudget(ctx)
	if err != nil {
		return store.OrgBudgetCache{}, err
	}
	if !cached.Have {
		return store.OrgBudgetCache{}, nil
	}
	if !active || identity.Binding == "" {
		return store.OrgBudgetCache{}, fmt.Errorf("org budget cache: current enrollment binding unavailable")
	}
	if cached.Binding == "" || cached.Binding != identity.Binding {
		return store.OrgBudgetCache{}, fmt.Errorf("org budget cache: stored enrollment binding does not match the current enrollment")
	}
	return cached, nil
}

// budgetPostureStatusLine renders one posture row as the status line. Split
// from the resolver above so the RENDERING can be tested on the shape that
// matters most — the fail-closed one — without standing up a signed grant.
func budgetPostureStatusLine(row orgcontract.BudgetPostureRow) string {
	// budget_required is named FIRST and in full when it is set: it is the
	// only value on this line that means "your proxied requests are being
	// denied right now", and a developer reading this screen after a wall of
	// deny verdicts needs the word they can search for.
	blocked := row.Coverage == orgcontract.BudgetCoverageBudgetRequired
	lead := "coverage=" + row.Coverage
	if blocked {
		lead += " (this node is managed and BLOCKS all proxied requests until a verified org budget arrives)"
	}
	return fmt.Sprintf("%s fetch_state=%s from_org=%v last_fetch_ok=%v budget_required=%v",
		lead, row.FetchState, row.FromOrg, row.LastFetchOK, blocked)
}
