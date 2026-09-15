package main

import (
	"context"
	"log/slog"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/govern"
	"github.com/marmutapp/superbased-observer/internal/orgclient"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// Admin-controlled Plane B Phase 1b, the daemon-side loops and seams
// (docs/plans/admin-controlled-plane-b-phase-1b-mini-spec-2026-08-15.md
// §1.4, §2.4, §4).
//
// Three things live here, all of them daemon-only and all of them no-ops on
// a node that is not enrolled:
//
//  1. the sidecar refresh tick (the ONE writer),
//  2. the hot share-posture provider (lowering-only),
//  3. the grant-renewal tick, including §4.3's idle-node probe.

// grantRenewalTickInterval is how often the renewal loop wakes. It is much
// shorter than the write rate limit below: waking often is free, writing to
// a table that is READ every 15 s is not.
const grantRenewalTickInterval = 15 * time.Minute

// grantRenewalMinWriteGap / grantRenewalMinMove are the §4.4 rate limit: at
// most one write per hour, and only when the new expiry would move the clock
// by more than an hour.
const (
	grantRenewalMinWriteGap = time.Hour
	grantRenewalMinMove     = time.Hour
)

// renewalProbeInterval bounds §4.3's explicit authorization probe. It fires
// ONLY while the authDenied latch is set, so a healthy idle node is
// completely silent and an idle fleet never becomes chatty.
const renewalProbeInterval = time.Hour

// runGovernanceSidecarWriter is the ONE writer of the governance sidecar
// (CLAUDE.md #4). It rewrites the file whenever the resolved posture's hash
// changes — which includes the grant lapsing, an unenrol landing from
// another process, and a new body being accepted — and refreshes an
// unchanged file every sidecarRefreshInterval so written_at stays a
// meaningful liveness signal.
//
// It never returns an error: a write failure is surfaced as an INERT
// condition on the node's own effective-state report (§1.4.1), which is a
// louder and more honest signal than a daemon that dies over a policy file.
// Logging happens inside the handle's own WriteSidecar (it owns the
// write-failure warning), so this loop takes no logger of its own.
func runGovernanceSidecarWriter(ctx context.Context, ngov *nodeGovernanceHandle) {
	if ngov == nil || ngov.SidecarPath() == "" {
		return
	}
	// Write once immediately so a daemon that starts against an existing
	// grant does not leave a stale (or absent) file for a whole interval.
	ngov.WriteSidecar(ctx)
	t := time.NewTicker(governanceGrantRefreshInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			ngov.WriteSidecar(ctx)
		}
	}
}

// intelOrgEnrichmentShareKey is the govern share-tier / nodegov.ShareKey
// identifier for the org-served Cloud Intelligence result-rail gate
// ([intelligence].org_enrichment). It is named once here so the resolver and
// its test cannot drift from the govern/nodegov tables that own the string.
const intelOrgEnrichmentShareKey = "intelligence.org_enrichment"

// intelRailEnabled resolves whether the org-served Cloud Intelligence RESULT
// rail is ON for this node (org-served-cloud-intelligence plan §2.1/W5). It is
// the single resolver orgclient.Client.SetIntelRail is bound to.
//
// `local` is the node-authored [intelligence].org_enrichment value (config
// default false — the "never server-forced" floor of the individual posture;
// the enterprise posture is where a managed grant may raise it). This is the
// SAME gated merge every other share tier uses (govern.Effective.MergeBoolGated,
// via lowerShareOptions): the org may LOWER the node's value unconditionally,
// and may RAISE it only when the node is MANAGED, holds the tier's extraction
// authority (extract.intel), AND the org body's own `share` directive turns the
// tier on. Using a bare `local || ExtractionAuthorized(...)` (the pre-fix code)
// ignored the org directive entirely, so a managed node with the authority went
// ON even when the org said false — finding 4. Reading the tier through the one
// table (govern.shareTierTable) keeps this rail and the push seam in lockstep.
//
// Truth table (the resolver test pins it):
//   - individual + config false                        -> off
//   - individual + config true                         -> on   (node-authored)
//   - managed, no extract.intel, config false          -> off
//   - managed + extract.intel, no org directive        -> off  (raise needs the org's own share:true)
//   - managed + extract.intel + org directive true     -> on   (managed raise)
//   - managed + extract.intel + org directive false    -> off  (org lowers/withholds)
func intelRailEnabled(local bool, eff govern.Effective) bool {
	return eff.MergeBoolGated(intelOrgEnrichmentShareKey, local)
}

// governanceShareProvider resolves the share posture each push ships under:
// the node's OWN [org_client.share] block, LOWERED by whatever the
// organization has directed (§2.1/§2.4).
//
// The direction is the whole point. For a raise, restart-bound would have
// been acceptable; for a lowering it is not — a node that keeps shipping
// content for hours after the org said stop is exactly the failure the
// directive exists to prevent. So this is called on every push, reading the
// same handle the dashboard guard reads.
//
// One owner (store.ShareOptions), two feed paths (TOML, governance).
func governanceShareProvider(cfg config.OrgClientConfig, ngov *nodeGovernanceHandle) func() store.ShareOptions {
	base := orgclient.ShareOptionsFromConfig(cfg)
	if ngov == nil {
		return func() store.ShareOptions { return base }
	}
	return func() store.ShareOptions {
		eff := ngov.Effective(context.Background())
		return lowerShareOptions(base, eff)
	}
}

// lowerShareOptions applies the lowering merge, one row per share key, then —
// for a MANAGED node only — the Enterprise-Managed extraction RAISE.
//
// The lowering rows are `local AND org` (or an intersection for the list), so
// on an INDIVIDUAL node the result can only ever share LESS than the node's
// own config. AdminManaged is deliberately absent from the org vocabulary, so
// nothing here can touch it.
//
// The RAISE block is the sanctioned lift for the enterprise plane: on a node
// that enrolled MANAGED and was granted the relevant extraction authority, the
// admin may turn extraction tiers ON remotely (full observer-DB access). It is
// applied AFTER lowering and gated per-tier on the GrantsXxxExtraction
// predicates (Arc 4 P4a split the former one-bloc GrantsManagedExtraction gate
// into independent per-tier gates), and RaiseBool itself no-ops unless
// Effective.Managed — so an individual node is structurally excluded and
// shipsRawContent()/shipsToolBodies() can still only go true → false there
// under any org body, grant, or signing key.
func lowerShareOptions(local store.ShareOptions, eff govern.Effective) store.ShareOptions {
	out := local
	out.FullContent = eff.LowerBool("full_content", local.FullContent)
	out.FullToolBodies = eff.LowerBool("full_tool_bodies", local.FullToolBodies)
	out.RoutingSummary = eff.LowerBool("routing_summary", local.RoutingSummary)
	out.CacheDetail = eff.LowerBool("cache_detail", local.CacheDetail)
	out.RoutingDetail = eff.LowerBool("routing_detail", local.RoutingDetail)
	out.LimitGauge = eff.LowerBool("limit_gauge", local.LimitGauge)
	out.CodeintelDetail = eff.LowerBool("codeintel_detail", local.CodeintelDetail)
	out.ProcessDetail = eff.LowerBool("process_detail", local.ProcessDetail)
	out.TerminalDetail = eff.LowerBool("terminal_detail", local.TerminalDetail)
	out.TaskDetail = eff.LowerBool("task_detail", local.TaskDetail)
	out.ToolAccountDetail = eff.LowerBool("tool_account_detail", local.ToolAccountDetail)
	out.ObsSummary = eff.LowerBool("obs.summary", local.ObsSummary)
	out.ObsTraces = eff.LowerBool("obs.traces", local.ObsTraces)
	out.ObsContent = eff.LowerBool("obs.content", local.ObsContent)
	out.ObsEvalSummary = eff.LowerBool("obs.eval_summary", local.ObsEvalSummary)
	out.ObsAdmission = eff.LowerBool("obs.admission", local.ObsAdmission)
	out.ObsEvalItems = eff.LowerBool("obs.eval_items", local.ObsEvalItems)
	out.ObsEgress = eff.LowerBool("obs.egress", local.ObsEgress)
	out.TargetActionAllowlist = eff.LowerList("target_action_allowlist", local.TargetActionAllowlist)

	// Enterprise-Managed Tenancy extraction raise (managed plane only;
	// structurally inert on the individual plane). The raise is the exact
	// MIRROR of the lowering above for every boolean tier: the admin's org body
	// decides which tiers go on (RaiseBool flips a tier true only where the
	// body's `share` block set it true).
	//
	// W-8: the per-tier gate is no longer spelled out here as one
	// eff.GrantsXxxExtraction() if-block per tier — that was a second,
	// DUPLICATE encoding of the exact key -> extraction-authority mapping
	// internal/govern/sharetiers.go now owns as the single source of truth
	// (the same table backs the dashboard Privacy card's "in force" column
	// via MergeBoolGated/SourceForBoolGated, so the seam and every
	// transparency surface read the gate off ONE table and can never
	// disagree). shareRaiseFields below is only the get/set plumbing this
	// loop needs to reach store.ShareOptions' fields; govern.ExtractionAuthorized
	// is the one place the gate itself is decided — including the operator
	// ruling that the three highest-sensitivity tiers (codeintel/process/
	// terminal) each require their OWN token and are never satisfied by the
	// extract.managed umbrella alone. admin_managed is absent from the org
	// vocabulary in BOTH directions by construction.
	for _, f := range shareRaiseFields {
		if !govern.ExtractionAuthorized(eff, f.Key) {
			continue
		}
		f.Set(&out, eff.RaiseBool(f.Key, f.Get(&out)))
	}

	// The list tier (target_action_allowlist) is NOT boolean, so it cannot
	// ride shareRaiseFields/RaiseBool — it rides govern.RaiseList instead,
	// gated on the SAME ExtractionAuthorized(eff, key) check as every other
	// tier (its own strict AuthorityExtractTargetActions token, per
	// sharetiers.go; the umbrella extract.managed does not satisfy it). Union
	// semantics: the org may only ADD action types to what already ships raw,
	// never remove one the node itself allowed (Plane B dual-mode gateway /
	// RBAC-IA design, 2026-08-29 §5.3).
	if govern.ExtractionAuthorized(eff, "target_action_allowlist") {
		out.TargetActionAllowlist = eff.RaiseList("target_action_allowlist", out.TargetActionAllowlist)
	}

	// The Plane B enterprise-content grant (§5.3 scope item 4): a managed
	// node whose enrolment grant honors extract.managed AND all three
	// highest-sensitivity extraction tokens unlocks the SAME raw-content
	// posture FullContent/AdminManaged already provide, without requiring the
	// node operator to separately flip full_content. Computed fresh every
	// push from the live grant (govern.Effective), never cached, so a grant
	// lapsing takes effect on the very next push — same posture as every
	// other raise in this function.
	out.EnterpriseGranted = eff.GrantsEnterpriseContent()
	return out
}

// shareRaiseField is one boolean [org_client.share] tier's get/set plumbing
// into store.ShareOptions, keyed by the same key string
// internal/govern/sharetiers.go maps to an extraction authority. Get/Set are
// small enough that a reflection-based table would buy nothing over explicit
// closures, and closures keep this list a plain, greppable data table
// (CLAUDE.md "decision logic is table-driven, not nested conditionals").
type shareRaiseField struct {
	Key string
	Get func(*store.ShareOptions) bool
	Set func(*store.ShareOptions, bool)
}

// shareRaiseFields is every BOOLEAN tier lowerShareOptions may raise on the
// managed plane via RaiseBool — one row per shareTierTable entry in
// internal/govern/sharetiers.go that is boolean-kind. The two exceptions are
// handled separately, right after this loop runs in lowerShareOptions:
// target_action_allowlist is list-valued (govern.RaiseList, not RaiseBool)
// and policy_state is not a store.ShareOptions field at all (it rides its
// own reporting channel — see cmd/observer/policystate_wire.go). Order does
// not matter: every row touches a distinct ShareOptions field, so this loop
// commutes with the eff.GrantsXxxExtraction()-block form it replaces.
var shareRaiseFields = []shareRaiseField{
	{"full_tool_bodies", func(o *store.ShareOptions) bool { return o.FullToolBodies }, func(o *store.ShareOptions, v bool) { o.FullToolBodies = v }},
	{"full_content", func(o *store.ShareOptions) bool { return o.FullContent }, func(o *store.ShareOptions, v bool) { o.FullContent = v }},
	{"routing_summary", func(o *store.ShareOptions) bool { return o.RoutingSummary }, func(o *store.ShareOptions, v bool) { o.RoutingSummary = v }},
	{"routing_detail", func(o *store.ShareOptions) bool { return o.RoutingDetail }, func(o *store.ShareOptions, v bool) { o.RoutingDetail = v }},
	{"cache_detail", func(o *store.ShareOptions) bool { return o.CacheDetail }, func(o *store.ShareOptions, v bool) { o.CacheDetail = v }},
	{"limit_gauge", func(o *store.ShareOptions) bool { return o.LimitGauge }, func(o *store.ShareOptions, v bool) { o.LimitGauge = v }},
	// Full traces / obs family (Arc 4 P5b) — the obs T2 structure + T3
	// content tiers plus the eval/admission tiers the obs dashboard shows.
	{"obs.summary", func(o *store.ShareOptions) bool { return o.ObsSummary }, func(o *store.ShareOptions, v bool) { o.ObsSummary = v }},
	{"obs.traces", func(o *store.ShareOptions) bool { return o.ObsTraces }, func(o *store.ShareOptions, v bool) { o.ObsTraces = v }},
	{"obs.content", func(o *store.ShareOptions) bool { return o.ObsContent }, func(o *store.ShareOptions, v bool) { o.ObsContent = v }},
	{"obs.eval_summary", func(o *store.ShareOptions) bool { return o.ObsEvalSummary }, func(o *store.ShareOptions, v bool) { o.ObsEvalSummary = v }},
	{"obs.admission", func(o *store.ShareOptions) bool { return o.ObsAdmission }, func(o *store.ShareOptions, v bool) { o.ObsAdmission = v }},
	{"obs.eval_items", func(o *store.ShareOptions) bool { return o.ObsEvalItems }, func(o *store.ShareOptions, v bool) { o.ObsEvalItems = v }},
	// obs.egress (§5.3 scope item 3) — the obs admission/egress-routing
	// destination surface, added alongside its obs.* siblings above. It is
	// HEADLINE-gated (govern.sharetiers.go's GrantsObsEgressExtraction is the
	// non-strict grantsExtractionOrManaged form), not strict, so the umbrella
	// extract.managed authority alone is enough to raise it — unlike
	// codeintel_detail/process_detail/terminal_detail below.
	{"obs.egress", func(o *store.ShareOptions) bool { return o.ObsEgress }, func(o *store.ShareOptions, v bool) { o.ObsEgress = v }},
	// Highest-sensitivity per-tier extraction raises (Arc 4 P5f-h). Each
	// gates on its OWN managed authority, NOT the umbrella extract.managed
	// alias — by operator ruling, granting the headline tiers (cache/
	// routing/predictions) must NOT also unlock the developer's
	// source-symbol graph, process trees, or terminal/remote-audit
	// activity. internal/govern/sharetiers.go encodes this via the strict
	// (non-umbrella) GrantsXxxExtraction predicates for exactly these three
	// keys — see its shareTierRow.Authorized doc comment.
	{"codeintel_detail", func(o *store.ShareOptions) bool { return o.CodeintelDetail }, func(o *store.ShareOptions, v bool) { o.CodeintelDetail = v }},
	{"process_detail", func(o *store.ShareOptions) bool { return o.ProcessDetail }, func(o *store.ShareOptions, v bool) { o.ProcessDetail = v }},
	{"terminal_detail", func(o *store.ShareOptions) bool { return o.TerminalDetail }, func(o *store.ShareOptions, v bool) { o.TerminalDetail = v }},
	// Node session-detail trickle-up W2/W3. Same STRICT posture as the three
	// above (their own extract.tasks / extract.tool_accounts token, never the
	// umbrella — operator decision D4): a work plan and a developer's vendor
	// login are highest-sensitivity surfaces. Raising either tier still does
	// NOT disclose the item prose or the raw account identity — those ride the
	// node's own shipsRawContent() posture, decided inside the push seam.
	{"task_detail", func(o *store.ShareOptions) bool { return o.TaskDetail }, func(o *store.ShareOptions, v bool) { o.TaskDetail = v }},
	{"tool_account_detail", func(o *store.ShareOptions) bool { return o.ToolAccountDetail }, func(o *store.ShareOptions, v bool) { o.ToolAccountDetail = v }},
}

// grantRenewer owns the renewal clock for one daemon run.
type grantRenewer struct {
	client  *orgclient.Client
	store   *store.Store
	tracker *orgclient.RenewalTracker
	logger  *slog.Logger
	now     func() time.Time

	lastWrite time.Time
}

// runGrantRenewal is the §4 renewal tick.
//
// Renewal is a LOCAL write, and the TTL is derived from the grant itself:
//
//	ttl       := signed_expires_at - granted_at
//	newExpiry := now + ttl
//
// so a renewal can never extend the grant beyond the window the organization
// actually signed for, and no ttl_days field is added anywhere.
func runGrantRenewal(ctx context.Context, oc *orgclient.Client, st *store.Store, tracker *orgclient.RenewalTracker, logger *slog.Logger) {
	if oc == nil || st == nil || tracker == nil {
		return
	}
	if logger == nil {
		logger = slog.Default()
	}
	r := &grantRenewer{client: oc, store: st, tracker: tracker, logger: logger, now: time.Now}
	t := time.NewTicker(grantRenewalTickInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			r.tick(ctx)
		}
	}
}

func (r *grantRenewer) tick(ctx context.Context) {
	now := r.now().UTC()
	if r.tracker.Latched() {
		// While latched, NO renewal is written no matter how many 2xx or 304
		// responses arrive from other paths (R5). The latch clears only on an
		// authorized response on the PUSH path, and an idle node produces
		// none — hence the explicit probe (review M2).
		if r.tracker.ShouldProbe(now, renewalProbeInterval) {
			if err := r.client.ProbePushAuthorization(ctx); err != nil {
				r.logger.Debug("governance: renewal probe failed", "err", err)
			}
		}
		return
	}
	if !r.lastWrite.IsZero() && now.Sub(r.lastWrite) < grantRenewalMinWriteGap {
		return
	}
	enr, err := r.store.LoadEnrolment(ctx)
	if err != nil || enr == nil {
		return
	}
	orgKey := orgclient.OrgKey(enr.OrgServerURL, enr.OrgID)
	grant, ok, err := r.store.LoadEnrolmentGrant(ctx, orgKey)
	if err != nil || !ok {
		return
	}
	newExpiry, ok := renewedExpiry(grant, now)
	if !ok {
		return
	}
	if err := r.store.RenewEnrolmentGrant(ctx, orgKey, grant.Generation, newExpiry); err != nil {
		r.logger.Warn("governance: could not renew the enrolment grant", "err", err)
		return
	}
	r.lastWrite = now
}

// renewedExpiry computes the renewed working expiry, or reports that this
// tick must not renew.
//
// The guards are review M1's: a non-positive TTL, or one derived from a zero
// GrantedAt, SKIPS renewal rather than computing nonsense. Without them a
// grant written before migration 083's backfill (or by a store write that
// forgot the column) would yield a large NEGATIVE duration and an expiry in
// the past.
func renewedExpiry(grant store.EnrolmentGrant, now time.Time) (time.Time, bool) {
	if grant.GrantedAt.IsZero() || grant.SignedExpiresAt.IsZero() {
		return time.Time{}, false
	}
	ttl := grant.SignedExpiresAt.Sub(grant.GrantedAt)
	if ttl <= 0 {
		return time.Time{}, false
	}
	newExpiry := now.Add(ttl)
	// Only write when the clock actually moves. A DB write per poll cycle is
	// needless churn on a table that is read every 15 s.
	if newExpiry.Sub(grant.ExpiresAt) <= grantRenewalMinMove {
		return time.Time{}, false
	}
	return newExpiry, true
}
