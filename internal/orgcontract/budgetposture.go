package orgcontract

// Node -> server BUDGET POSTURE self-report
// (docs/plans/org-budget-enforcement-and-token-display-plan-2026-09-07.md
// §3.3d, wave W3b).
//
// It is the answer to ONE admin question: "is the budget I authored actually
// holding on this developer's machine?" — and it answers it with enums only.
//
// WHAT IT DELIBERATELY DOES NOT CARRY, and why: no cap value, no resolved
// scope, no spend, no period, no timezone. A resolved scope is the string
// "team:<id>" — shipping it back would tell a reader which TEAM a node belongs
// to, which the push wire does not otherwise disclose, and a cap VALUE is a
// number an admin can correlate to one team's budget row. Both are already
// known to the SERVER (it resolved and signed them); echoing them adds no
// information and only widens what a compromised node could assert about
// somebody else. So the row narrows: posture, never numbers.
//
// It is composed by internal/store/budgetposture.go and CALLED BY
// internal/store/orgpush.go through a func seam, exactly like RoutingSummaries
// and UpdatePostureRow, so the privacy sentinel keeps its module boundary.
//
// COVERAGE HONESTY (the whole reason Coverage and DirectControl exist):
// Coverage describes the guard's proxy-request chokepoint
// (internal/guard/budget.go::scanBudget). DirectControl separately describes
// the node's direct-vendor intervention controller. A proxy guard must never
// be presented as proof that native vendor sessions are controlled, and the
// direct controller must never manufacture a fully-ready state, so the two
// axes remain explicit closed enums.
//
// THE ONE COUNTER-EXAMPLE, admitted deliberately (pricing arc §3.3, F7/F8):
// PricingVersion is a NUMBER on a row whose whole rule is "posture, never
// numbers". It is admitted because the rule above is narrower than its name:
// the ban targets cap VALUES and resolved SCOPES — facts the server already
// knows because it resolved and signed them, or facts a compromised node could
// assert ABOUT SOMEBODY ELSE. A monotonic version of THIS NODE'S OWN applied
// pricing document is neither. It asserts nothing about any other member, it
// names no team, it is not a quantity of anything, and it is the one datum the
// server cannot derive: the server knows which version it PUBLISHED, and the
// entire question the field answers is whether this node ever applied it.
// Without it "the org lowered its rates last week" and "this developer's
// dollars are still being computed at last quarter's rates" are the same wire
// state, which is precisely the not-covered-vs-not-reported confusion the row
// exists to remove.
//
// The field set is pinned structurally by
// tests/invariant/budget_posture_test.go::TestBudgetPostureRowWireShapeIsEnumOnly
// (the cite here previously named privacy_test.go, which never held it) and
// again, at the layer that BUILDS the row, by
// internal/orgbudget/orgbudget_test.go::TestPostureRowIsEnumOnly — a new field
// fails both before it can ship.
type BudgetPostureRow struct {
	// EnforcementPoint is always BudgetPointGuard. It is present rather than
	// implied so the row reads the same way as a PolicyStateRow and so a
	// second chokepoint (were one ever added) is a value, not a schema.
	EnforcementPoint string `json:"enforcement_point,omitempty"`
	// Mode is off / observe / enforce — the guard's own mode, which is what
	// decides whether a breach flags or blocks.
	Mode string `json:"mode,omitempty"`
	// Source says WHERE the effective numbers came from:
	// local / org_lowered / org_authoritative.
	Source string `json:"source,omitempty"`
	// FetchState is the last budget-policy fetch's outcome:
	// ok / not_enrolled / unreachable / auth_failed / no_budget /
	// channel_off / unverified / disabled. "unverified" is the honest
	// answer for a served body this node could not check a signature on;
	// "disabled" means [guard.budget].from_org is off.
	FetchState string `json:"fetch_state,omitempty"`
	// FromOrg mirrors [guard.budget].from_org: has this node opted into
	// applying the org's budget at all.
	FromOrg bool `json:"from_org,omitempty"`
	// LastFetchOK is true when the most recent fetch produced a VERIFIED
	// body (FetchState == ok). False with FromOrg true is the fail-open
	// state the plan requires the node to SAY OUT LOUD: the node is running
	// its own local thresholds because it could not get the org's.
	LastFetchOK bool `json:"last_fetch_ok,omitempty"`
	// Hard is the effective [guard.budget].hard: does a breach DENY (in
	// enforce mode) or merely flag.
	Hard bool `json:"hard,omitempty"`
	// Capped reports whether any effective window has a non-zero ceiling at
	// all. A boolean, never the ceiling: "this node has a budget" is the
	// fact the coverage column needs; "the budget is 40,000,000" is not.
	Capped bool `json:"capped,omitempty"`
	// ResolvedScopeNone says the node applied a VERIFIED body that resolved
	// to an explicit NONE for this caller: the org signed a document, and
	// the document says this developer has no cap.
	//
	// It exists because Capped=false + LastFetchOK=true is AMBIGUOUS and the
	// two readings need opposite sentences (finding M2). Reading one: the
	// org signed an explicit none, so no ceiling is in force and that is
	// deliberate. Reading two: the org DID author a cap, but its only window
	// is a period the node rail cannot enforce (a `rolling_30d` cap maps to
	// no node window), so no ceiling is in force and that is a COVERAGE GAP.
	// Only the node can tell them apart, because only the node saw the body.
	// A bool, never the body.
	ResolvedScopeNone bool `json:"resolved_scope_none,omitempty"`
	// Coverage is the closed vocabulary that keeps the dashboard from
	// rendering "enforced" over a developer whose traffic never passes the
	// proxy: BudgetCoverageProxyOnly on every ordinary node, and
	// BudgetCoverageBudgetRequired on a managed node that is refusing
	// proxied requests because no verified org budget has ever reached it.
	Coverage string `json:"coverage,omitempty"`
	// DirectControl reports the node's aggregate direct-vendor intervention
	// posture. It is deliberately separate from Coverage: proxy_only says
	// what the guard sees and cannot imply anything about native sessions.
	// There is no "ready" value. The controller can report partial coverage,
	// pending setup, an unavailable control path, or that policy does not
	// require direct control; a legacy node reports nothing and the server
	// normalises that absence to DirectControlNotReported.
	DirectControl string `json:"direct_control,omitempty"`
	// PricingSource says which price table the dollars this budget is
	// enforced against were computed from (the closed PricingSource* enum
	// below). A cap is meaningless without the rate it is measured in: a
	// node enforcing the org's $500 cap at LIST prices is enforcing a
	// different budget than the admin authored, and nothing else on this row
	// would say so.
	PricingSource string `json:"pricing_source,omitempty"`
	// PricingVersion is the org_pricing_version of the document this node has
	// APPLIED, or 0 when it has applied none. See the counter-example
	// paragraph in this file's header for why a number is admitted here.
	PricingVersion int64 `json:"pricing_version,omitempty"`
	// PRICING COVERAGE (ruling A3, 2026-09-15). The three fields below answer
	// the question the pricing pair above cannot: the org's rates are applied,
	// but did they actually PRICE this developer's usage?
	//
	// They exist because the answer was, on a real managed node, "almost none
	// of it" — every row came from `muse` and `opencode` models the org had
	// never quoted — and nothing said so. The managed accounting refused those
	// rows outright, the guard read the refusal as unavailable accounting, and
	// the developer's processes were stopped at $0.26 of a $2 cap while the
	// node's own dashboard priced the same day at $0.97. That denial is gone
	// (ruling A1/A2: the fallback ladder prices the row and the cap counts it);
	// what replaces it is this report, so an admin can SEE the gap and close it
	// with an org price instead of discovering it as an outage.
	//
	// UnpricedRows is a count of ROWS, not of dollars and not of a ceiling, so
	// the "posture, never numbers" rule of this file's header is untouched: it
	// names no team, quantifies no spend, and asserts nothing about any other
	// member. UnpricedModels is the only free text on this row and it is the
	// vendor's own model identifiers — which already travel on this same push
	// wire, ungated, on every token_usage and api_turns row (orgpush.go). It is
	// bounded at 8 and sorted so it reads as a fact rather than a log.
	//
	// TWO LISTS, NOT ONE (BUDGET-COV-3, 2026-09-15 later). The first live cap
	// crossing was priced at a FAMILY rate (muse-spark-1.3-contributor) and
	// counted correctly by both the node and the org - yet the org's coverage
	// note said that model "has no rate at all and counts as $0", because one
	// combined list carried fallback-priced models and true misses together and
	// a single true miss (big-pickle) chose the wording for the whole list. A
	// fallback-priced row and an unpriced row are opposite facts about a cap
	// (one counts toward it at an estimated rate, the other silently under-reads
	// it), so they travel as separate lists and get separate sentences.
	//
	// FallbackRows counts rows priced by a rung the org did NOT author: a
	// date-stripped, family or local rate, or the adapter's own reported cost.
	// They count against the cap; they are estimates, not the org's number.
	FallbackRows int `json:"fallback_rows,omitempty"`
	// FallbackModels names the distinct models behind FallbackRows, sorted and
	// capped at 8.
	FallbackModels []string `json:"fallback_models,omitempty"`
	// UnpricedRows counts rows NOTHING could price (a true miss with no stored
	// cost) plus invalid rows (broken counters, a timestamp belonging to no
	// window). Every one of them contributes $0 to the cap - the one shape where
	// a cap silently under-reads - which is why the sentence this feeds says
	// "count as $0" rather than naming a cause the row cannot prove.
	//
	// COMPAT: a node that predates the split (server migration 152) ships ONE
	// combined list here for BOTH classes. The server's reader relabels a
	// legacy `fallback` posture (which by the old definition held zero true
	// misses) onto the fallback fields; a legacy `partial` posture cannot be
	// split and keeps reading worst-case until the node is upgraded.
	UnpricedRows int `json:"unpriced_rows,omitempty"`
	// UnpricedModels names the distinct models behind the TRUE-MISS part of
	// UnpricedRows (invalid rows name no model - their model is not the cause),
	// sorted and capped at 8. Empty when nothing missed, or when the node has
	// not measured yet.
	UnpricedModels []string `json:"unpriced_models,omitempty"`
	// PricingCoverage is the closed enum complete / fallback / partial:
	//
	//	complete — every priced row resolved to an org or exact rate.
	//	fallback — some rows resolved through a date-stripped / family / local
	//	           rate, or through the adapter's own reported cost (the
	//	           FallbackRows list), and NO row went unpriced.
	//	partial  — at least one row nothing could price (the UnpricedRows list).
	//	           It counts as $0, which is the one shape where a cap silently
	//	           under-reads. FallbackRows may be non-zero at the same time.
	//
	// "" means NOT MEASURED (a node that predates this field, or one whose
	// managed accounting has not run yet) and must never be rendered as
	// "complete" — the not-covered-vs-not-reported distinction this whole row
	// exists to preserve.
	PricingCoverage string `json:"pricing_coverage,omitempty"`
	// PushIntervalSeconds is THIS NODE'S OWN reporting cadence — the resolved
	// [org_client].push_interval_seconds the push loop is ticking at, stamped
	// by internal/orgclient when it builds the envelope.
	//
	// It exists because the server's freshness horizon for the DirectControl
	// half of this row is minutes, not days (a process controller can die
	// between pushes, so its last observation must stop being presented as
	// current), and a horizon shorter than the reporter's cadence turns every
	// delivered posture into an expired one. The live estate pushes every 15
	// minutes against a 5-minute horizon, so a correctly-reporting node read
	// as not_reported forever (SF-19). Only the node knows its cadence; the
	// server cannot derive it, and inferring it from the gap between arrivals
	// would make a single missed push look like a slow node.
	//
	// It is the SECOND number admitted onto a row whose rule is "posture,
	// never numbers", under the same narrow reading as PricingVersion (see
	// this file's header): the ban targets cap VALUES and resolved SCOPES —
	// facts the server already knows, or facts a compromised node could
	// assert about somebody else. A reporting cadence is neither. It names no
	// team, quantifies no spend, and asserts nothing about any other member.
	//
	// 0 means "not reported" (a pre-SF-19 agent, or a node that has not
	// resolved one), and the server falls back to its own default horizon —
	// so the compat invariant holds in both directions.
	PushIntervalSeconds int `json:"push_interval_seconds,omitempty"`
}

// Budget posture vocabulary. Closed enums; a value outside these sets is a bug
// in the composer, not an extension point.
const (
	// BudgetPointGuard is the node-side chokepoint: the guard layer's
	// proxy-request budget check.
	BudgetPointGuard = "guard"

	// BudgetSourceLocal means the node's own [guard.budget] numbers are in
	// force, unchanged.
	BudgetSourceLocal = "local"
	// BudgetSourceOrgLowered means an org body was applied through the
	// lowering-only composition (govern.LowerFloat / LowerInt): the org
	// tightened one or more windows and could never have loosened one.
	BudgetSourceOrgLowered = "org_lowered"
	// BudgetSourceOrgAuthoritative means a MANAGED node holding
	// govern.AuthorityEnforceBudget replaced its local numbers and
	// enforcement mode with the org's.
	BudgetSourceOrgAuthoritative = "org_authoritative"

	// BudgetFetchDisabled — [guard.budget].from_org is off.
	BudgetFetchDisabled = "disabled"
	// BudgetFetchOK — a signed body verified and was applied.
	BudgetFetchOK = "ok"
	// BudgetFetchNotEnrolled — no org enrolment on this node.
	BudgetFetchNotEnrolled = "not_enrolled"
	// BudgetFetchUnreachable — transport error / timeout / 5xx.
	BudgetFetchUnreachable = "unreachable"
	// BudgetFetchAuthFailed — 401/403: the server answered, our credential
	// was refused.
	BudgetFetchAuthFailed = "auth_failed"
	// BudgetFetchNoBudget — 404: the org has no budget applicable to this
	// member. An explicit NONE, never a cap of zero.
	BudgetFetchNoBudget = "no_budget"
	// BudgetFetchChannelOff — 409: the org has published no signing key, so
	// the rail cannot serve a trustworthy body.
	BudgetFetchChannelOff = "channel_off"
	// BudgetFetchUnverified — a body arrived but this node could not verify
	// it (no pinned org key, a key mismatch, or a bad signature). It is
	// REFUSED, never applied; the node keeps its local numbers.
	BudgetFetchUnverified = "unverified"

	// BudgetCoverageProxyOnly — the node can only enforce a budget on
	// requests that route through its proxy.
	BudgetCoverageProxyOnly = "proxy_only"
	// BudgetCoverageBudgetRequired — this node is MANAGED and its grant
	// carries enforce.budget, and no verified org budget body has ever been
	// applied here, so the guard refuses every proxied request until one
	// arrives (ruling R2, fail closed on managed nodes).
	//
	// WHY COVERAGE AND NOT FETCH_STATE. It was tempting to spell this as a
	// ninth BudgetFetch* value, and that would have been wrong: fetch_state
	// answers "what happened on the last poll", and overwriting it here would
	// have destroyed exactly the datum the 2026-09-13 diagnosis turned on — a
	// fleet reporting `unverified` because the org signs with two identities.
	// A node in this state still has a last-fetch outcome and must still
	// report it. Coverage answers the other question, "what is this budget
	// doing to this node's traffic": proxy_only means "it bites on proxied
	// requests only", budget_required means "it refuses them all". One axis
	// each, and a reader needs both.
	BudgetCoverageBudgetRequired = "budget_required"

	// DIRECT CONTROL vocabulary. These values report only an aggregate
	// controller posture; per-surface process, path, and adapter details stay
	// node-local. There is intentionally no fully-ready value because the
	// controller cannot truthfully claim complete direct-vendor coverage.
	//
	// DirectControlNotReported means the field was absent (a legacy node) or
	// the server received a value outside this closed vocabulary.
	DirectControlNotReported = "not_reported"
	// DirectControlPending means the node is authorized for direct control but
	// the controller has not yet established a usable intervention posture.
	DirectControlPending = "pending_control"
	// DirectControlPartial means the controller can stop observed running
	// processes only; execution admission and request admission are unavailable.
	DirectControlPartial = "partial"
	// DirectControlUnavailable means the node cannot currently provide the
	// direct-vendor control its policy calls for.
	DirectControlUnavailable = "control_unavailable"
	// DirectControlNotRequired means the node's current policy does not require
	// direct-vendor intervention.
	DirectControlNotRequired = "not_required"

	// PRICING SOURCE vocabulary (pricing arc §3.3). It answers "which price
	// table produced the dollars this node's budget is enforced against",
	// and it deliberately merges two axes that a reader must never have to
	// join by hand: where the rates came from, and — when they did not come
	// from the org — why not. Splitting them into a source enum and a
	// separate failure enum would let a surface render "seed" over a node
	// that is silently refusing an unverifiable org document.
	//
	// PricingSourceSeed — the compiled default table, unmodified. The
	// ordinary state of an individual node and of any node whose operator
	// authored no overrides.
	PricingSourceSeed = "seed"
	// PricingSourceLocal — the node's own [intelligence.pricing] overrides
	// are the top of its ladder. On an individual node these WIN over the
	// org's rates (ruling R3): a developer who typed a rate meant it.
	PricingSourceLocal = "local"
	// PricingSourceOrg — the org's signed rates are applied, with any local
	// override still winning above them (the individual-node ladder).
	PricingSourceOrg = "org"
	// PricingSourceOrgAuthoritative — a MANAGED node holding
	// govern.AuthorityEnforceBudget: the org's rates sit ABOVE the node's own
	// overrides, so a developer cannot re-price their way around a cap.
	PricingSourceOrgAuthoritative = "org_authoritative"
	// PricingSourceUnverified — a body arrived and was REFUSED (no pinned
	// key, bad signature, replayed version). The node is pricing from
	// whatever it had before, and this value says so out loud rather than
	// letting the surface read "seed" and infer everything is fine.
	PricingSourceUnverified = "unverified"
	// PricingSourceNotSupported — the org server predates the pricing rail
	// (404). Not a failure of this node, and not a reason to clear anything.
	PricingSourceNotSupported = "not_supported"
	// PRICING COVERAGE vocabulary (ruling A3, 2026-09-15). It answers "did the
	// rates named by PricingSource actually price this developer's usage", and
	// the empty value is NOT a member: "" means not measured.
	//
	// PricingCoverageComplete — every priced row resolved to an org or exact
	// rate. The cap is measured in exactly the unit the admin authored.
	PricingCoverageComplete = "complete"
	// PricingCoverageFallback — some rows were priced through a date-stripped,
	// family or local rate, or through the adapter's own reported cost, and
	// none went unpriced. They count against the cap; they are estimates, not
	// the org's number.
	PricingCoverageFallback = "fallback"
	// PricingCoveragePartial — at least one row nothing could price at all. It
	// counts as $0, so the cap under-reads until an org price exists. Fallback-
	// priced rows may coexist and are reported on their own list.
	PricingCoveragePartial = "partial"

	// PricingSourceNoPricing — the org SIGNED an empty document: it has
	// negotiated nothing and the fleet prices at seed. An explicit none,
	// distinct from "we never asked" (seed) and from "we asked and could not
	// tell" (unverified).
	PricingSourceNoPricing = "no_pricing"
)
