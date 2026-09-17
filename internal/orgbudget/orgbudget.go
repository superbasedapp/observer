package orgbudget

import (
	"time"

	"github.com/marmutapp/superbased-observer/internal/govern"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
)

// Thresholds is the node's four-window budget ceiling set, in both units, plus
// the hard flag. It mirrors internal/config.GuardBudgetConfig's numeric fields
// WITHOUT importing it: this package must stay free of the config graph, and
// the caller (cmd/observer's guard wiring) owns the two-line conversion.
//
// 0 is "unset" in every field, never a cap of zero — the same sentinel
// [guard.budget] and the `budgets` table both use.
type Thresholds struct {
	SessionUSD float64
	DailyUSD   float64
	WeeklyUSD  float64
	MonthlyUSD float64

	SessionTokens int64
	DailyTokens   int64
	WeeklyTokens  int64
	MonthlyTokens int64

	// Protection identifies the exact effective ceilings that came from a
	// managed organization's hard budget. It is runtime provenance, not a
	// locally configurable posture. A preserved local ceiling stays false even
	// when another unit or window is organization-authoritative and hard.
	Protection BudgetProtection

	// Hard is [guard.budget].hard: in enforce mode a breach DENIES instead of
	// flagging. It is a posture, not a number, so an org-authoritative
	// composition takes it from the org's enforcement mode and a lowering-only
	// composition can only turn it ON (tightening), never off.
	//
	// It is the NODE-WIDE flag — true when ANY window must deny. Which windows
	// those are is SoftWindows' business; a caller that applies Hard without
	// also applying SoftWindows re-introduces the cross-period fold (see
	// SoftWindows).
	Hard bool

	// DailyTimezone / MonthlyTimezone are the IANA names the org's calendar
	// boundary for that window is anchored in ("" means UTC, the node's own
	// default and the only calendar a purely local budget has ever had).
	//
	// They exist because the org's `budgets` row carries a timezone that the
	// dashboard percentage and the alert ladder both honour
	// (rollup.BudgetWindowSince). A node that buckets the SAME cap on the UTC
	// day renders and enforces a different window than the surface the admin
	// is reading — at 23:30 in America/Los_Angeles the node is 6.5 hours into
	// a day the Budgets page has not started. One budget, one calendar.
	//
	// A window's zone is adopted ONLY when the org's number for that window
	// was actually adopted (see capAdopted): an org cap that lost to a tighter
	// local ceiling governs nothing, and moving the developer's own day
	// boundary because of it would be a change nobody asked for.
	DailyTimezone   string
	MonthlyTimezone string

	// SoftWindows names the windows whose org rule is NOT hard, when some
	// OTHER window's is. It is the per-window half of Hard.
	//
	// The org authors enforcement PER PERIOD (`budgets.enforcement`), and the
	// gateway honours it per cap: internal/aigateway/gwstore's capRow.soft()
	// admits-and-warns on a soft row and denies on a hard one, per row. Folding
	// the strictest mode across periods into one node-wide flag made a soft
	// daily cap DENY on the node while the same cap merely warns at the
	// gateway — same budget, two answers (review fix round 2, MEDIUM-3).
	//
	// Values are the window names "session" / "daily" / "weekly" / "monthly".
	// The boundary maps them onto the rule rows that must stay flag; this
	// package names windows, never rule IDs.
	SoftWindows []string

	// BudgetRequired is the FAIL-CLOSED outcome (ruling R2): this node is
	// managed, its grant carries enforce.budget, and no verified org budget
	// body has ever been applied here. Every proxied request must be refused
	// until one arrives.
	//
	// It is a FLAG rather than a cap of zero for a structural reason: the
	// guard's proxy check returns early when every stamped window is zero
	// (internal/guard/budget.go::scanBudget), so a "ceiling of 0" would be
	// the one shape that enforces nothing at all. The boundary hands this
	// flag to the guard as its own argument, and the guard turns it into one
	// rule row (B-625) that does not depend on a stamped number.
	//
	// It NEVER travels with a body: a node that has a verified body — even a
	// stale one kept in force across an outage — is not in this state.
	BudgetRequired bool

	// Baseline is the ORGANIZATION's measurement of what this caller already
	// spent in each window on its OTHER machines (bundle BUD-N / P1-9). Every
	// comparison the node makes is `Baseline + local spend` against the
	// ceiling, so one developer's two machines burn one budget.
	//
	// It travels with an ADOPTED cap and only with an adopted cap, exactly as
	// the timezone and the enforcement mode do: an org cap that lost to a
	// tighter local ceiling governs nothing, and adding its fleet-wide spend to
	// a ceiling the developer set themselves would tighten a number the org
	// never actually reached. Zero on every window the org did not govern, and
	// zero whenever the baseline was stale, absent or uncomposable — see
	// baseline.go, whose whole point is that all three of those keep running.
	Baseline Baseline

	// Subjects are the org's PER-TOOL and PER-MODEL caps, resolved per node
	// window. They are REAL caps: the node enforces them at the same
	// chokepoints, in whichever unit the org authored, with their own baseline
	// and their own hardness.
	//
	// They are a LIST rather than more fields because the number of capped
	// subjects is the org's to choose. An empty list is every node whose org
	// authored none, and composes to the pre-feature thresholds exactly.
	Subjects []SubjectCap
}

// BudgetProtection carries managed hard-budget provenance per window and
// unit. A zero value grants no native-intervention authority.
type BudgetProtection struct {
	SessionUSD bool
	DailyUSD   bool
	WeeklyUSD  bool
	MonthlyUSD bool

	SessionTokens bool
	DailyTokens   bool
	WeeklyTokens  bool
	MonthlyTokens bool

	// ToolUSD / ToolTokens / ModelUSD / ModelTokens are the SUBJECT rows'
	// provenance (bundle BUD-N): a managed organization authored at least one
	// HARD per-tool / per-model cap in that unit. Per kind+unit rather than per
	// subject because that is the granularity of the rule row the authority is
	// asked about; which subject crossed is the matcher's business, and each
	// cap carries its own Hard flag.
	ToolUSD     bool
	ToolTokens  bool
	ModelUSD    bool
	ModelTokens bool
}

// Any reports whether any effective ceiling carries managed hard-budget
// authority.
func (p BudgetProtection) Any() bool {
	return p.SessionUSD || p.DailyUSD || p.WeeklyUSD || p.MonthlyUSD ||
		p.SessionTokens || p.DailyTokens || p.WeeklyTokens || p.MonthlyTokens ||
		p.ToolUSD || p.ToolTokens || p.ModelUSD || p.ModelTokens
}

type adoptedUnits struct {
	usd    bool
	tokens bool
}

func (a adoptedUnits) any() bool { return a.usd || a.tokens }

func (p *BudgetProtection) set(w window, adopted adoptedUnits, protected bool) {
	if p == nil {
		return
	}
	switch w {
	case windowSession:
		if adopted.usd {
			p.SessionUSD = protected
		}
		if adopted.tokens {
			p.SessionTokens = protected
		}
	case windowDaily:
		if adopted.usd {
			p.DailyUSD = protected
		}
		if adopted.tokens {
			p.DailyTokens = protected
		}
	case windowWeekly:
		if adopted.usd {
			p.WeeklyUSD = protected
		}
		if adopted.tokens {
			p.WeeklyTokens = protected
		}
	case windowMonthly:
		if adopted.usd {
			p.MonthlyUSD = protected
		}
		if adopted.tokens {
			p.MonthlyTokens = protected
		}
	}
}

// Capabilities is what the BOUNDARY resolved about this node. Compose branches
// on these, never on where a number came from (CLAUDE.md #3).
type Capabilities struct {
	// FromOrg is [guard.budget].from_org — the node opted into applying the
	// organization's budget at all. False means Compose returns local
	// unchanged, which is byte-identical to a build without this feature.
	FromOrg bool
	// OrgAuthoritative is (managed tenancy AND the grant carries
	// govern.AuthorityEnforceBudget), resolved by the caller through
	// govern.Effective.GrantsBudgetEnforcement(). It is the ONLY thing that
	// lets the org's numbers replace rather than merely lower the local ones.
	OrgAuthoritative bool
	// RequireOrgBudget is the FAIL-CLOSED capability (ruling R2): this node
	// may not run without the organization's budget, so an absent body is a
	// BLOCK rather than a fall-back to local numbers.
	//
	// It is a SECOND field rather than a reading of OrgAuthoritative even
	// though today's boundary resolves both from the same predicate
	// (govern.Effective.GrantsBudgetEnforcement — managed tenancy AND
	// enforce.budget). They are two different capabilities: one answers "may
	// the org REPLACE my numbers", the other "may this node run WITHOUT
	// them". Folding them would make a future deployment that wants
	// authoritative-but-fail-open (or the reverse) a branch on tenancy here
	// instead of a flag at the boundary, which is the thing CLAUDE.md #3
	// forbids.
	//
	// It is deliberately NOT gated on FromOrg: on a managed node the
	// developer's own opt-out is not the authority, and an org that holds
	// enforce.budget pins guard.budget.from_org through its node.governance
	// body anyway (ruling R3).
	RequireOrgBudget bool
	// HaveBody is false when no VERIFIED org body is in hand — not enrolled,
	// the org published none, the fetch failed, or the signature did not
	// verify. Compose then returns local unchanged and the posture says so;
	// it never treats an absent body as a cap of zero.
	HaveBody bool
	// FetchState is the closed orgcontract.BudgetFetch* enum describing the
	// last fetch. It is carried through to the posture verbatim so the node
	// reports WHY it is running local numbers.
	FetchState string
	// GuardMode is the guard's own mode (off / observe / enforce), reported
	// on the posture because it, not the caps, decides whether a breach
	// blocks.
	GuardMode string
	// Now is the composition clock, INJECTED so this package stays pure and so
	// a baseline-freshness test is a table row rather than a sleep. A zero Now
	// makes every baseline stale (an undated comparison cannot show a
	// measurement to be current), which is the safe direction: the node
	// enforces on its own rows.
	Now time.Time
	// BaselineMaxAge is how old the org's spend measurement may be. The
	// boundary computes it from THIS node's own push cadence
	// ([org_client].push_interval_seconds) through [BaselineMaxAge]; zero
	// falls back to the same default.
	BaselineMaxAge time.Duration
	// ResolveSubjectID folds a per-tool / per-model cap's id onto the SAME
	// identity this node's own accounting keys its totals by. It is INJECTED —
	// this package must not reach the price table any more than it may reach
	// the config graph — and nil means "trim + lowercase only", which is what
	// shipped before and what a node with no price table still gets.
	//
	// WHY IT IS NEEDED AT ALL (adversarial review of BUD-N, P1-3). A model cap
	// compares an id the ORG typed against an id an ADAPTER captured, and both
	// sides were only trimmed and lowercased. `claude-sonnet-5` and
	// `claude-sonnet-5-20260501` are the same model and never compared equal,
	// so an authored cap bit nothing and reported as in force — the worst shape
	// a ceiling can have. The boundary therefore resolves BOTH sides through
	// the price table's own alias ladder (exact -> date-stripped -> family),
	// which is the one place in the product that already knows two model
	// strings name one model.
	//
	// It is applied at COMPOSE time to the cap and at SNAPSHOT time to the
	// accounting keys, through this one func, so the two can never drift onto
	// two rules. kind is orgcontract.BudgetSubjectTool / BudgetSubjectModel: a
	// tool id has no alias ladder and resolves to the plain normalisation.
	ResolveSubjectID func(kind, id string) string
}

// resolveSubjectID applies the injected resolver, falling back to the id the
// contract already normalized. A resolver that answers "" is ignored for the
// same reason an unknown subject kind is: an empty id would widen a cap that
// named one thing into a cap that matches nothing at all, and silently.
func (c Capabilities) resolveSubjectID(kind, id string) string {
	if c.ResolveSubjectID == nil {
		return id
	}
	if out := c.ResolveSubjectID(kind, id); out != "" {
		return out
	}
	return id
}

// Posture is the enum-only self-report of what Compose actually did. It
// carries no cap value and no resolved scope by construction — see
// orgcontract.BudgetPostureRow for why.
type Posture struct {
	EnforcementPoint string
	Mode             string
	Source           string
	FetchState       string
	FromOrg          bool
	LastFetchOK      bool
	Hard             bool
	Capped           bool
	// ResolvedScopeNone is set only on the composition path, and only when
	// the VERIFIED body in hand carries no caps at all: the org signed an
	// explicit none for this caller.
	//
	// It is deliberately NOT `Capped == false`. A body with a real
	// `rolling_30d` cap also composes to Capped=false, because that period
	// maps to no node window — same bool, opposite meaning for the operator
	// (finding M2). See orgcontract.BudgetPostureRow.ResolvedScopeNone.
	ResolvedScopeNone bool
	Coverage          string
	// OrgBaseline is the closed orgcontract.BudgetBaseline* enum: did the
	// cross-machine baseline get APPLIED, or was it stale / absent /
	// uncomposable, leaving these caps enforced against this machine's own
	// rows only. OrgBaselineUnattributed rides with it: an applied baseline
	// that counted rows the server could not attribute to any machine may
	// overlap this node's own spend, and an admin reading "over budget"
	// should see that caveat rather than discover it.
	OrgBaseline             string
	OrgBaselineUnattributed bool
	// PricingSource / PricingVersion describe the price table the dollars
	// this budget is enforced against were computed from (pricing arc §3.3).
	//
	// [Compose] does NOT set them and must not: this package composes CAPS,
	// and the price table is a different subsystem with a different rail, a
	// different signature domain and a different failure ladder. Threading a
	// pricing outcome through Compose's signature would couple two rails that
	// only meet at one place — the daemon's boundary (cmd/observer's
	// orgbudget_wire.go), which sets these two fields on the returned Posture
	// before calling Row.
	//
	// They live on THIS type rather than being appended straight onto the
	// wire row at the boundary so that the enum vocabulary keeps exactly one
	// owner: Row is the only mapping from posture to wire, and a field that
	// bypassed it would be the second owner this package exists to prevent.
	PricingSource  string
	PricingVersion int64
}

// Row renders the posture as the wire row. Kept here rather than in the store
// seam so the enum vocabulary has ONE owner and a test can assert the mapping
// without a database.
func (p Posture) Row() orgcontract.BudgetPostureRow {
	return orgcontract.BudgetPostureRow{
		EnforcementPoint:  p.EnforcementPoint,
		Mode:              p.Mode,
		Source:            p.Source,
		FetchState:        p.FetchState,
		FromOrg:           p.FromOrg,
		LastFetchOK:       p.LastFetchOK,
		Hard:              p.Hard,
		Capped:            p.Capped,
		ResolvedScopeNone: p.ResolvedScopeNone,
		Coverage:          p.Coverage,

		OrgBaseline:             p.OrgBaseline,
		OrgBaselineUnattributed: p.OrgBaselineUnattributed,
		PricingSource:           p.PricingSource,
		PricingVersion:          p.PricingVersion,
	}
}

// window identifies which of the node's four budget windows a resolved org cap
// lands on. The empty window means "this period maps to no node window".
type window string

const (
	windowNone    window = ""
	windowSession window = "session"
	windowDaily   window = "daily"
	windowWeekly  window = "weekly"
	windowMonthly window = "monthly"
)

// nodeWindows is every window the node enforces, in the order SoftWindows is
// reported. session and weekly are LOCAL-ONLY — the org's period vocabulary
// maps onto daily and monthly alone (periodRules) — so their hardness is
// always the developer's own flag.
var nodeWindows = []window{windowSession, windowDaily, windowWeekly, windowMonthly}

// periodRule is one row of the period -> window table (CLAUDE.md #5). Reason is
// carried for the rows that map to NOTHING so the table documents the gap
// instead of hiding it behind an absent case.
type periodRule struct {
	period string
	window window
	reason string
}

// periodRules is the ordered, total mapping from the org's period vocabulary to
// the node's windows. Every period orgcontract declares has a row; a period
// this table does not know is treated exactly like an unmapped one (ignored,
// never guessed), which is what keeps a future server-side period from
// silently enforcing the wrong window on an old node.
var periodRules = []periodRule{
	{period: orgcontract.BudgetPolicyPeriodCalendarDay, window: windowDaily},
	{period: orgcontract.BudgetPolicyPeriodCalendarMonth, window: windowMonthly},
	{
		period: orgcontract.BudgetPolicyPeriodRolling30d, window: windowNone,
		reason: "the node has no rolling-30-day window, and ruling R7 keeps rolling_30d report-only",
	},
}

// windowFor resolves a period to a node window through the table.
func windowFor(period string) window {
	for _, r := range periodRules {
		if r.period == period {
			return r.window
		}
	}
	return windowNone
}

// enforcementRank orders the org's enforcement vocabulary report < soft < hard
// so "strictest wins" is a comparison rather than a nest of ifs. An unknown
// value ranks lowest (report), because a mode this build does not understand
// must never be read as a licence to block.
func enforcementRank(s string) int {
	switch s {
	case orgcontract.BudgetPolicyEnforcementHard:
		return 2
	case orgcontract.BudgetPolicyEnforcementSoft:
		return 1
	default:
		return 0
	}
}

// preCompositionRule is one row of the table Compose walks BEFORE it does any
// arithmetic: the outcomes that are decided entirely by CAPABILITIES, with no
// reference to a cap value.
//
// A table rather than two guard clauses because the two rows say opposite
// things about the same missing body — one blocks, one falls back — and an
// order-sensitive pair of opposites is exactly the decision that must be
// readable as data (CLAUDE.md #5). One test case per row.
type preCompositionRule struct {
	// name is for the tests and for reading the table; it reaches no surface.
	name string
	// when reads ONLY capabilities: a row that needed a number would belong
	// in the arithmetic below, not here.
	when func(Capabilities) bool
	// apply renders the outcome from the node's own thresholds and the
	// posture Compose has already stamped with mode / fetch state / from_org.
	apply func(local Thresholds, posture Posture) (Thresholds, Posture)
}

// preCompositionRules is ordered: FAIL CLOSED is asked first, because the
// fail-open row's condition ("no verified body") is also true in the
// fail-closed state, and a table that asked it first would answer a managed
// node's missing budget with the individual node's answer.
var preCompositionRules = []preCompositionRule{
	{
		// Ruling R2. A managed node holding enforce.budget that has never
		// applied a verified body refuses proxied requests. Note what is NOT
		// in the condition: FromOrg. On a managed node the developer's own
		// opt-out is not the authority that decides this.
		// A SIGNED EXPLICIT NONE is NOT this state. The org answering "no
		// budget applies to you" in a document the node verified
		// (orgcontract.EmptyBudgetPolicyBody, ResolvedScope "none") arrives
		// with HaveBody true and no caps, and composes to the node's own
		// numbers like any body that authored nothing for a window. Blocking
		// on it would mean a managed fleet in an org that deliberately
		// authors no budgets could never make a request — and the unsigned
		// 404 that used to be the only way to say "nothing applies" is
		// exactly what this row still, correctly, refuses to trust.
		name:  "org_budget_required",
		when:  func(c Capabilities) bool { return c.RequireOrgBudget && !c.HaveBody },
		apply: blockingCeiling,
	},
	{
		// The fail-open path, unchanged for every individual node: no body,
		// or a node that never opted in, runs its own numbers.
		//
		// RequireOrgBudget appears here as an override of the opt-out, not of
		// the absence: a managed node that HAS a verified body applies it even
		// with [guard.budget].from_org still false, because the org is
		// authoritative there and the pin that turns the key on (ruling R3)
		// may not have reached the node yet.
		name: "local_unchanged",
		when: func(c Capabilities) bool {
			return !c.HaveBody || (!c.FromOrg && !c.RequireOrgBudget)
		},
		apply: localUnchanged,
	},
}

// blockingCeiling is the fail-closed outcome: the node keeps its own numbers
// (they are all it has) and additionally refuses every proxied request.
//
// Source stays `local` because that is where the numbers came from — the org
// authored none. FetchState is left exactly as the fetch reported it, so the
// admin still reads WHY the body never arrived (unreachable / unverified /
// no_budget); Coverage is what says the node is blocking. LastFetchOK stays
// false: no verified body is in hand, and that is the whole reason for this
// row.
func blockingCeiling(local Thresholds, posture Posture) (Thresholds, Posture) {
	eff := local
	eff.Protection = BudgetProtection{}
	eff.SoftWindows = nil
	// No body reached this node, so there is no cross-machine baseline and no
	// subject cap. Stated rather than inherited: `local` is the developer's own
	// block and has never carried either, and a future caller that passed a
	// pre-filled Thresholds must not have it survive into a fail-closed state.
	eff.Baseline, eff.Subjects = Baseline{}, nil
	posture.OrgBaseline = orgcontract.BudgetBaselineAbsent
	eff.Hard = true
	eff.BudgetRequired = true

	posture.Source = orgcontract.BudgetSourceLocal
	posture.Hard = true
	// Capped, because the block IS the ceiling: a surface that read "no
	// budget ceiling in force" over a node refusing every request would be
	// describing the opposite of what is happening.
	posture.Capped = true
	posture.Coverage = orgcontract.BudgetCoverageBudgetRequired
	return eff, posture
}

// localUnchanged is the fail-open outcome: byte-identical to a build that
// never had the org budget rail.
func localUnchanged(local Thresholds, posture Posture) (Thresholds, Posture) {
	local.Protection = BudgetProtection{}
	// Same reasoning as blockingCeiling: the fail-open path composes nothing,
	// so it carries no baseline and no subject cap, and the posture says the
	// cross-machine half is simply not there.
	local.Baseline, local.Subjects = Baseline{}, nil
	posture.OrgBaseline = orgcontract.BudgetBaselineAbsent
	posture.Hard = local.Hard
	posture.Capped = capped(local)
	return local, posture
}

// Compose returns the node's EFFECTIVE budget thresholds and the posture that
// describes how it got them.
//
// The rule (§3.3c + ruling R2), in the order it is applied:
//
//  0. RequireOrgBudget (a MANAGED node holding enforce.budget) with no
//     verified body ever applied -> a BLOCKING ceiling. The node refuses
//     proxied requests until the org's budget reaches it, and the posture
//     reports Coverage=budget_required beside the unchanged fetch_state.
//     TWO states are deliberately NOT this one: a verified body that arrived
//     earlier and is still in hand (orgclient keeps serving its cached body
//     across a failed poll — the last verified body stays in force and
//     LastFetchOK reports false), and a SIGNED EXPLICIT NONE (the org saying,
//     verifiably, that it authored nothing for this caller — that composes to
//     the node's own numbers, uncapped if it has none).
//  1. FromOrg off, or no verified body in hand -> local, unchanged. This is the
//     fail-open path: an unreachable org NEVER tightens or loosens anything,
//     and the posture says LastFetchOK=false so the fact is reported, not
//     inferred.
//  2. FromOrg on, INDIVIDUAL node -> numerically lowering only, per unit and
//     per window, through govern.LowerFloat / LowerInt. The org can turn a
//     window ON and can tighten one; it can never raise a ceiling the
//     developer set. Hard may only go false -> true (tightening).
//  3. FromOrg on, MANAGED node holding enforce.budget -> org-authoritative:
//     the org's numbers REPLACE the local ones for every window it authored, and
//     the org's enforcement mode decides that window's hardness. A window the
//     org did NOT author keeps its local value — the org replacing a cap it
//     never wrote with zero would DELETE the developer's own ceiling, which is
//     a loosening no enterprise posture asks for.
//
// ENFORCEMENT IS PER WINDOW, not per node (review fix round 2, MEDIUM-3). The
// org authors `budgets.enforcement` per period and the gateway honours it per
// cap, so a monthly `hard` cap beside a daily `soft` one denies at the month
// and warns at the day — at BOTH chokepoints. Compose reports that as
// Hard (any window denies) plus SoftWindows (the ones that must not); folding
// the strictest mode across periods, as the first cut did, made the node deny
// a cap the admin wrote as a nudge.
//
// The window's CALENDAR travels with its cap the same way: an adopted org cap
// brings its own timezone (DailyTimezone / MonthlyTimezone), so the node
// buckets the day the dashboard percentage and the alert ladder bucket
// (MEDIUM-2).
//
// Compose is total; it never returns an error, because every degenerate input
// (empty body, unknown period, negative cap) has a defined, non-enforcing
// answer.
func Compose(local Thresholds, body orgcontract.BudgetPolicyBody, caps Capabilities) (Thresholds, Posture) {
	posture := Posture{
		EnforcementPoint: orgcontract.BudgetPointGuard,
		Mode:             normalizeMode(caps.GuardMode),
		Source:           orgcontract.BudgetSourceLocal,
		FetchState:       caps.FetchState,
		FromOrg:          caps.FromOrg,
		Coverage:         orgcontract.BudgetCoverageProxyOnly,
	}
	if posture.FetchState == "" {
		posture.FetchState = orgcontract.BudgetFetchDisabled
	}
	// The two outcomes that need no arithmetic, resolved through an ordered
	// table so "fail closed" and "fail open" are two rows a reader can put
	// side by side rather than two arms of a nested condition (CLAUDE.md #5).
	for _, rule := range preCompositionRules {
		if rule.when(caps) {
			return rule.apply(local, posture)
		}
	}
	posture.LastFetchOK = caps.FetchState == orgcontract.BudgetFetchOK
	// The explicit-none bit is decided HERE, from the body, before any
	// arithmetic can blur it into Capped. Reaching this line means a verified
	// body is in hand (the pre-composition table returned otherwise), so an
	// empty body is the org's signed "this developer has no cap" and nothing
	// else.
	posture.ResolvedScopeNone = caps.HaveBody && body.Empty()

	eff := local
	eff.Protection = BudgetProtection{}
	eff.SoftWindows = nil
	eff.Baseline, eff.Subjects = Baseline{}, nil
	// hardOf starts every window on the DEVELOPER's own posture. session and
	// weekly stay there for good — the org's period vocabulary reaches neither.
	hardOf := map[window]bool{}
	for _, w := range nodeWindows {
		hardOf[w] = local.Hard
	}

	// The baseline state reported for the WHOLE body: the worst outcome any
	// applicable cap had (baselineStateRank). It starts unset and is only
	// stamped by a cap that actually reached the classification, so a body with
	// no caps at all reports absent rather than a verdict on nothing.
	baselineState := ""
	unattributed := false
	maxAge := caps.BaselineMaxAge
	if maxAge <= 0 {
		maxAge = BaselineMaxAge(0)
	}
	noteBaseline := func(state string, entry orgcontract.BudgetPolicyCap, applied bool) {
		if baselineState == "" || baselineStateRank[state] > baselineStateRank[baselineState] {
			baselineState = state
		}
		if applied && entry.SpentIncludesUnattributed {
			unattributed = true
		}
	}

	for _, entry := range capsOf(body) {
		// SUBJECT caps take the other path entirely: they do not touch the
		// node's four window ceilings, they carry their own, and a node that
		// folded a per-tool cap into the node-wide daily ceiling would enforce
		// it against every tool at once.
		if entry.Subject != nil {
			kind, id, ok := entry.SubjectKey()
			if !ok {
				// A subject this build does not understand — an unknown kind,
				// an empty id — is IGNORED, exactly as an unknown period is.
				// It must never fall through to the whole-caller branch: a cap
				// the org narrowed to one thing would then be enforced against
				// EVERYTHING, which is the worst possible misreading of an
				// authored ceiling and the one a future subject kind would
				// trigger on every old node.
				continue
			}
			if sc, added := subjectCapOf(entry, kind, id, caps, maxAge, noteBaseline); added {
				eff.Subjects = append(eff.Subjects, sc)
			}
			continue
		}
		w := windowFor(entry.Period)
		if w == windowNone {
			continue
		}
		adopted := applyCap(&eff, w, entry, caps.OrgAuthoritative)
		if !adopted.any() {
			// The org authored this window but its number governs nothing (it
			// was 0, or it lost to a tighter local ceiling). Its enforcement
			// mode and its calendar do not travel with a cap that is not in
			// force.
			continue
		}
		hardOf[w] = windowHard(local.Hard, entry.Enforcement, caps.OrgAuthoritative)
		eff.Protection.set(w, adopted,
			caps.OrgAuthoritative && enforcementRank(entry.Enforcement) >= enforcementRank(orgcontract.BudgetPolicyEnforcementHard))
		// The baseline rides with the ADOPTED cap, for the same reason the
		// calendar and the enforcement mode do.
		state, apply, flagOnly := classifyBaseline(entry, caps.Now, maxAge)
		noteBaseline(state, entry, apply)
		if apply {
			usd, tokens := baselineAmounts(entry)
			eff.Baseline.set(w, usd, tokens, flagOnly)
		}
	}
	if baselineState == "" {
		baselineState = orgcontract.BudgetBaselineAbsent
	}
	posture.OrgBaseline = baselineState
	posture.OrgBaselineUnattributed = unattributed

	eff.Protection.ToolUSD, eff.Protection.ToolTokens, eff.Protection.ModelUSD, eff.Protection.ModelTokens = SubjectProtection(eff.Subjects, caps.OrgAuthoritative)
	if caps.OrgAuthoritative {
		posture.Source = orgcontract.BudgetSourceOrgAuthoritative
	} else {
		posture.Source = orgcontract.BudgetSourceOrgLowered
	}
	eff.Hard, eff.SoftWindows = foldWindows(eff, hardOf)
	posture.Hard = eff.Hard
	posture.Capped = capped(eff)
	return eff, posture
}

// windowHard resolves ONE window's hardness from the org rule that governs it.
//
//   - authoritative: the org's mode decides in BOTH directions — a managed node
//     the org put in `soft` must stop denying, or the admin's own setting does
//     not mean what it says. `report` observes, `soft` warns, `hard` denies.
//   - lowering-only: the org can turn hardness ON (tightening) and never off,
//     so the developer's own flag survives a softer org rule.
func windowHard(localHard bool, enforcement string, authoritative bool) bool {
	orgHard := enforcementRank(enforcement) >= enforcementRank(orgcontract.BudgetPolicyEnforcementHard)
	if authoritative {
		return orgHard
	}
	return localHard || orgHard
}

// foldWindows renders the per-window hardness map as the pair the boundary
// applies: the node-wide flag (true when ANY window denies) and the windows
// that must stay flag despite it.
//
// Only windows that actually CARRY a ceiling are considered. An uncapped
// window has no breach to be hard about — its rule row is inert on both mode
// columns (both sides of the comparison must be non-zero) — and counting it
// would put an unenforceable window in SoftWindows, or worse, let one make the
// node-wide flag true.
//
// SoftWindows is empty whenever every capped window agrees, so a node with one
// uniform posture composes to exactly the pre-MEDIUM-3 shape.
func foldWindows(eff Thresholds, hardOf map[window]bool) (bool, []string) {
	anyHard := false
	for _, w := range nodeWindows {
		if windowCapped(eff, w) && hardOf[w] {
			anyHard = true
		}
	}
	if !anyHard {
		return false, nil
	}
	var soft []string
	for _, w := range nodeWindows {
		if windowCapped(eff, w) && !hardOf[w] {
			soft = append(soft, string(w))
		}
	}
	return true, soft
}

// windowCapped reports whether w carries a ceiling in either unit. It is
// capped()'s per-window sibling and uses the same 0-means-unset sentinel.
func windowCapped(t Thresholds, w window) bool {
	switch w {
	case windowSession:
		return t.SessionUSD > 0 || t.SessionTokens > 0
	case windowDaily:
		return t.DailyUSD > 0 || t.DailyTokens > 0
	case windowWeekly:
		return t.WeeklyUSD > 0 || t.WeeklyTokens > 0
	case windowMonthly:
		return t.MonthlyUSD > 0 || t.MonthlyTokens > 0
	case windowNone:
		return false
	}
	return false
}

// capsOf returns the body's per-period cap list, falling back to the body's
// own top-level fields when the list is absent. A pre-`caps` server (or a
// hand-written body) still delivers exactly one cap that way, which is the
// leading entry by definition — see orgcontract.BudgetPolicyBody.
func capsOf(body orgcontract.BudgetPolicyBody) []orgcontract.BudgetPolicyCap {
	if len(body.Caps) > 0 {
		return body.Caps
	}
	if body.Period == "" {
		return nil
	}
	return []orgcontract.BudgetPolicyCap{{
		Period:      body.Period,
		Timezone:    body.Timezone,
		CapTokens:   body.CapTokens,
		CapUSD:      body.CapUSD,
		Enforcement: body.Enforcement,
	}}
}

// applyCap folds ONE resolved org cap into the effective thresholds for its
// window. authoritative selects replacement over lowering; in both modes a cap
// the org left at 0 (unset) leaves the local value alone, because 0 is the
// absence of a ceiling and never a ceiling of zero.
//
// It reports whether the org's number was ADOPTED in either unit. That answer
// is what decides whether the org rule's enforcement mode and calendar travel
// with it: a cap that lost to a tighter local ceiling governs nothing, and
// letting it move the developer's day boundary or their deny posture would be
// a change the org never actually made.
func applyCap(eff *Thresholds, w window, entry orgcontract.BudgetPolicyCap, authoritative bool) adoptedUnits {
	usd, tokens := entry.CapUSD, entry.CapTokens
	if usd < 0 {
		usd = 0
	}
	if tokens < 0 {
		tokens = 0
	}
	var adopted adoptedUnits
	switch w {
	case windowDaily:
		adopted.usd = capAdopted(eff.DailyUSD, usd, authoritative)
		adopted.tokens = capAdopted(float64(eff.DailyTokens), float64(tokens), authoritative)
		eff.DailyUSD = mergeFloat(eff.DailyUSD, usd, authoritative)
		eff.DailyTokens = mergeInt(eff.DailyTokens, tokens, authoritative)
		if adopted.any() {
			eff.DailyTimezone = entry.Timezone
		}
	case windowMonthly:
		adopted.usd = capAdopted(eff.MonthlyUSD, usd, authoritative)
		adopted.tokens = capAdopted(float64(eff.MonthlyTokens), float64(tokens), authoritative)
		eff.MonthlyUSD = mergeFloat(eff.MonthlyUSD, usd, authoritative)
		eff.MonthlyTokens = mergeInt(eff.MonthlyTokens, tokens, authoritative)
		if adopted.any() {
			eff.MonthlyTimezone = entry.Timezone
		}
	case windowNone, windowSession, windowWeekly:
		// Unreachable: periodRules maps the org vocabulary onto daily/monthly
		// only, and the caller filtered windowNone. Kept so the switch is total.
	}
	return adopted
}

// capAdopted reports whether the org's number for one unit ends up governing,
// stated as the rule rather than inferred from a float comparison of before and
// after (an org cap identical to the local one is still the org's cap).
//
// 0 is "unset" on both sides — an org that authored no ceiling in this unit
// adopts nothing, and a local 0 means the org's cap turns the window ON.
func capAdopted(local, org float64, authoritative bool) bool {
	switch {
	case org <= 0:
		return false
	case authoritative:
		return true
	case local <= 0:
		return true
	default:
		return org <= local
	}
}

// mergeFloat is the one place the replace-vs-lower choice is made for a USD
// ceiling. govern.LowerFloat owns the lowering algebra (and its "0 means
// unset" rule); replacement is deliberately guarded by the same sentinel so an
// authoritative org that authored no USD cap does not delete the local one.
func mergeFloat(local, org float64, authoritative bool) float64 {
	if authoritative {
		if org == 0 {
			return local
		}
		return org
	}
	return govern.LowerFloat(local, org)
}

// mergeInt is mergeFloat for a token ceiling.
func mergeInt(local, org int64, authoritative bool) int64 {
	if authoritative {
		if org == 0 {
			return local
		}
		return org
	}
	return govern.LowerInt(local, org)
}

// capped reports whether ANY window carries a ceiling. It is the boolean the
// posture ships in place of the numbers.
func capped(t Thresholds) bool {
	return t.SessionUSD > 0 || t.DailyUSD > 0 || t.WeeklyUSD > 0 || t.MonthlyUSD > 0 ||
		t.SessionTokens > 0 || t.DailyTokens > 0 || t.WeeklyTokens > 0 || t.MonthlyTokens > 0
}

// normalizeMode folds a guard mode into the closed off/observe/enforce enum the
// posture ships. Unknown or empty collapses to "off" so the row never carries a
// mode a reader has no rule for.
func normalizeMode(m string) string {
	switch m {
	case "enforce":
		return "enforce"
	case "observe", "advise":
		return "observe"
	default:
		return "off"
	}
}
