package orgbudget

import (
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/orgcontract"
)

// The CROSS-MACHINE SPEND BASELINE and the per-subject caps (bundle BUD-N,
// P1-9).
//
// THE PROBLEM. A developer with a laptop and a devbox burns ONE organization
// budget from TWO nodes. Each node can only see its own captured rows, so each
// enforces the org's $200 monthly cap against its own half — and the pair of
// them spends $400 before either flags. The org, which sees both, has watched
// the budget go over and has no chokepoint that agrees with it.
//
// THE FIX, in one line: effective spend for a cap is
//
//	org_spend_excluding_this_machine  +  local_spend_of_this_machine
//
// The org measures the first half (it is the only party that can) and ships it
// on the SAME signed body that carries the cap; the node adds its own rows and
// compares. Nothing else changes: the windows, the units, the rule rows and the
// chokepoints are the ones that were already there.
//
// WHAT THIS FILE OWNS is the decision of whether that baseline may be applied
// AT ALL. It is a table (CLAUDE.md #5) of five outcomes, and three of them are
// "no":
//
//   - absent      — the caps carry no baseline. An org server that predates the
//     field, or one that measured nothing for this caller.
//   - unverified  — a baseline arrived that the server could NOT measure with
//     this machine excluded. Adding local spend to it would count
//     the same requests twice, so the node refuses it outright.
//   - stale       — the measurement is older than the node's staleness window
//     (or carries no time at all). An old number is worse
//     evidence than the node's own rows.
//   - applied_flag_only — fresh and machine-excluded, but the server ALSO
//     counted rows it could not attribute to any machine. The
//     number is good enough to WARN with and wrong to STOP a
//     developer with, so it travels to the flag rows only.
//   - applied     — fresh, machine-excluded, and being added.
//
// EVERY "no" COMPOSES TO A ZERO BASELINE AND KEEPS RUNNING. There is no
// fail-closed branch here, deliberately: the node still holds the org's CAP and
// still enforces it against local spend, which is exactly the behaviour that
// shipped before this feature existed. Refusing to run because the org could
// not tell us what another machine spent would turn a reporting gap into an
// outage, and the posture row says which of the four happened so the gap is
// visible instead of silent.

// BaselineMaxAge is how old the organization's spend measurement may be before
// the node stops applying it: TWO push intervals plus a minute.
//
// The reasoning is the reporting cadence, not a guess. The org's number can only
// be as fresh as this node's own last push plus the server's own aggregation, so
// a window shorter than the cadence would reject every measurement that ever
// arrives. One missed push is ordinary (a laptop lid, a flaky link); two in a
// row is a rail that has stopped, and a ceiling enforced against a picture that
// old is enforcing the past. The extra minute absorbs the jitter between a
// node's tick and the server's.
//
// A non-positive interval falls back to the shipped default cadence so a
// misconfigured node still gets a bounded window rather than an infinite one.
func BaselineMaxAge(pushInterval time.Duration) time.Duration {
	if pushInterval <= 0 {
		pushInterval = DefaultPushInterval
	}
	return 2*pushInterval + time.Minute
}

// DefaultPushInterval is the cadence BaselineMaxAge assumes when the caller
// passes none. It mirrors [org_client].push_interval_seconds' own default; it
// is re-stated rather than imported because this package must not reach the
// config graph.
const DefaultPushInterval = 120 * time.Second

// Baseline is the organization's spend on this caller's OTHER machines, per
// node window, in both units. Zero in every field is the ordinary state (no
// org, no baseline, or a baseline the node refused) and composes to exactly the
// pre-feature comparison.
type Baseline struct {
	SessionUSD float64
	DailyUSD   float64
	WeeklyUSD  float64
	MonthlyUSD float64

	SessionTokens int64
	DailyTokens   int64
	WeeklyTokens  int64
	MonthlyTokens int64

	// FlagOnly says this baseline may raise a WARNING and may not deny.
	//
	// It is set when an applied window's cap reported that the server counted
	// rows it could not attribute to any machine identity
	// (orgcontract.BudgetPolicyCap.SpentIncludesUnattributed): the number may
	// overlap the local spend it is about to be added to, and a request refused
	// — or a process stopped — on a total that may have counted the same turns
	// twice is the one failure this rail cannot afford.
	//
	// It is ONE bool for the whole baseline rather than one per window, and
	// that is deliberate. The baseline is published as ONE set of addends
	// beside ONE composed budget, the posture reports ONE enum for the body,
	// and the four windows are measured over the same rows by the same server
	// aggregate — a per-window split would let a caveat that is true of the
	// corpus quietly not apply to one window of it.
	FlagOnly bool
}

// Any reports whether any window carries a baseline.
func (b Baseline) Any() bool {
	return b.SessionUSD > 0 || b.DailyUSD > 0 || b.WeeklyUSD > 0 || b.MonthlyUSD > 0 ||
		b.SessionTokens > 0 || b.DailyTokens > 0 || b.WeeklyTokens > 0 || b.MonthlyTokens > 0
}

// set stores one window's baseline amounts. flagOnly is sticky across windows:
// once any applied window may only warn, the published baseline may only warn
// (see Baseline.FlagOnly for why it is not split per window).
func (b *Baseline) set(w window, usd float64, tokens int64, flagOnly bool) {
	b.FlagOnly = b.FlagOnly || flagOnly
	b.setAmounts(w, usd, tokens)
}

// setAmounts stores one window's numbers.
func (b *Baseline) setAmounts(w window, usd float64, tokens int64) {
	switch w {
	case windowSession:
		b.SessionUSD, b.SessionTokens = usd, tokens
	case windowDaily:
		b.DailyUSD, b.DailyTokens = usd, tokens
	case windowWeekly:
		b.WeeklyUSD, b.WeeklyTokens = usd, tokens
	case windowMonthly:
		b.MonthlyUSD, b.MonthlyTokens = usd, tokens
	case windowNone:
	}
}

// SubjectCap is one organization cap narrowed to ONE tool or ONE model, for one
// node window, with its own baseline and its own hardness. It is the pure
// package's own type; the boundary converts it to the guard's/policy's shape,
// exactly as it already does for Thresholds and BudgetProtection.
//
// There are no composite subjects (no "tool X on model Y") by ruling: a
// composite would need a resolution order against the plain tool cap and the
// plain model cap, and every such order is a judgement about numbers the ORG
// authored that the node would be making on its behalf.
type SubjectCap struct {
	// Kind is orgcontract.BudgetSubjectTool or BudgetSubjectModel.
	Kind string
	// ID is the normalized subject id (trimmed, ASCII-lowercased by
	// orgcontract.BudgetPolicyCap.SubjectKey).
	ID string
	// Window is the node window this cap's period maps onto.
	Window string
	// CapUSD / CapTokens are the ceilings; 0 is unset in both.
	CapUSD    float64
	CapTokens int64
	// BaselineUSD / BaselineTokens are this subject's cross-machine spend,
	// already filtered by the table below — zero whenever it was refused.
	BaselineUSD    float64
	BaselineTokens int64
	// BaselineFlagOnly is Baseline.FlagOnly for THIS cap: the baseline above
	// may warn and may not deny. It is per cap here, unlike the node-wide
	// bool, because each subject cap carries its own SpentIncludesUnattributed
	// on the wire — the precision is available, so it is kept.
	BaselineFlagOnly bool
	// Hard says a breach of this cap denies in enforce mode. It is resolved
	// per cap by the same windowHard rule the node windows use: the org's mode
	// decides on an authoritative node, and can only tighten on an individual
	// one.
	Hard bool
}

// baselineState ranks the four outcomes so a body carrying several caps can be
// reported with ONE enum. The rank is the honesty order, not the severity
// order: a WORSE state wins, because "one of your caps is being enforced
// against this machine only" is the fact an admin needs, and reporting
// `applied` because some other cap was fine would hide exactly that.
//
// absent ranks lowest so a body with no baselines anywhere reports `absent`
// rather than inheriting a state no cap actually had.
var baselineStateRank = map[string]int{
	orgcontract.BudgetBaselineAbsent:          0,
	orgcontract.BudgetBaselineApplied:         1,
	orgcontract.BudgetBaselineAppliedFlagOnly: 2,
	orgcontract.BudgetBaselineStale:           3,
	orgcontract.BudgetBaselineUnverified:      4,
}

// baselineRule is one row of the acceptance table. Each row reads ONLY the cap
// and the clock; none of them looks at tenancy, at authority, or at where the
// cap came from (CLAUDE.md #3).
type baselineRule struct {
	// name is for the tests and for reading the table.
	name string
	// when decides the row.
	when func(cap orgcontract.BudgetPolicyCap, now time.Time, maxAge time.Duration) bool
	// state is the posture enum this row reports.
	state string
	// apply says whether the baseline NUMBERS travel. Exactly one row sets it.
	apply bool
}

// baselineRules is ordered, and the order is load-bearing:
//
//  1. absent is asked first so a cap with no numbers is never described by a
//     freshness verdict on a timestamp it also does not have.
//  2. unverified is asked before stale because a baseline that would
//     double-count is unusable at ANY age — calling a fresh, unusable number
//     "fresh" would report a cap as fleet-wide when it is not.
//  3. stale is the remaining refusal.
//  4. applied_flag_only sits between the refusals and the full application: the
//     number is usable, but only for a comparison that cannot stop anything.
//     It is asked AFTER stale and unverified because a number that must not be
//     composed at all, or cannot be shown to be current, is not "applied" in any
//     degree.
//  5. applied is the fall-through, so a new refusal is added as a row above it
//     rather than as a condition inside it.
var baselineRules = []baselineRule{
	{
		name: "absent",
		when: func(c orgcontract.BudgetPolicyCap, _ time.Time, _ time.Duration) bool {
			return c.SpentUSD <= 0 && c.SpentTokens <= 0
		},
		state: orgcontract.BudgetBaselineAbsent,
	},
	{
		name: "unverified",
		when: func(c orgcontract.BudgetPolicyCap, _ time.Time, _ time.Duration) bool {
			return !c.SpentExcludesMachine
		},
		state: orgcontract.BudgetBaselineUnverified,
	},
	{
		// This row is the one with a DEPENDENCY OUTSIDE THIS PACKAGE, named
		// here because it was once broken silently: SpentAsOf only advances on
		// the node if a re-measurement actually reaches it, and that is true
		// only because orgcontract.BudgetPolicyDigest keeps SpentAsOf INSIDE
		// the ETag. While it was excluded, a stable baseline re-measured to the
		// same amounts answered 304 forever, the stamp froze, and this row
		// flipped a perfectly current measurement to `stale` — composing the
		// org's number to zero and under-counting the cap by whatever another
		// machine had spent. Do not "optimise" that field back out of the
		// digest without giving this row another source of truth.
		name: "stale",
		when: func(c orgcontract.BudgetPolicyCap, now time.Time, maxAge time.Duration) bool {
			return !baselineFresh(c.SpentAsOf, now, maxAge)
		},
		state: orgcontract.BudgetBaselineStale,
	},
	{
		name: "applied_flag_only",
		when: func(c orgcontract.BudgetPolicyCap, _ time.Time, _ time.Duration) bool {
			return c.SpentIncludesUnattributed
		},
		state: orgcontract.BudgetBaselineAppliedFlagOnly,
		apply: true,
	},
	{
		name:  "applied",
		when:  func(orgcontract.BudgetPolicyCap, time.Time, time.Duration) bool { return true },
		state: orgcontract.BudgetBaselineApplied,
		apply: true,
	},
}

// classifyBaseline walks the table for ONE cap. flagOnly is derived from the
// state rather than carried as a third table column, so the enum on the wire
// and the arithmetic on the node can never describe different things.
func classifyBaseline(c orgcontract.BudgetPolicyCap, now time.Time, maxAge time.Duration) (state string, apply, flagOnly bool) {
	for _, rule := range baselineRules {
		if rule.when(c, now, maxAge) {
			return rule.state, rule.apply, rule.state == orgcontract.BudgetBaselineAppliedFlagOnly
		}
	}
	return orgcontract.BudgetBaselineAbsent, false, false
}

// baselineFresh reports whether a measurement time is inside the window.
//
// An EMPTY or unparsable time is NOT fresh — the opposite of
// orgcontract.BudgetPolicyFresh's rule for a document's issued_at, and
// deliberately so. There, empty means "a server that predates the field" and
// refusing it would break every node that upgraded ahead of its org server; the
// document is still signed and still the org's. HERE the empty case is a NUMBER
// with no date, and an undated measurement cannot be shown to be current. The
// compatibility direction is safe anyway: a server that predates this field
// sends no Spent* either, so it lands on the `absent` row above and never
// reaches this test.
//
// A measurement from the FUTURE is treated as fresh up to the same skew the
// document rail allows, because node and server clocks drift and refusing a
// baseline over 20 seconds of NTP jitter would be an outage manufactured out of
// nothing.
func baselineFresh(spentAsOf string, now time.Time, maxAge time.Duration) bool {
	raw := strings.TrimSpace(spentAsOf)
	if raw == "" {
		return false
	}
	at, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return false
	}
	if maxAge <= 0 {
		maxAge = BaselineMaxAge(0)
	}
	if now.IsZero() {
		return false
	}
	if age := now.Sub(at); age > maxAge {
		return false
	}
	if ahead := at.Sub(now); ahead > orgcontract.BudgetPolicyMaxSkew {
		return false
	}
	return true
}

// baselineAmounts returns the cap's baseline numbers, floored at zero. A
// negative measurement is a server bug and is treated as none rather than as a
// credit — a baseline that could LOWER the effective spend would let a bad
// number raise a ceiling, and nothing on this rail may ever loosen a cap.
func baselineAmounts(c orgcontract.BudgetPolicyCap) (float64, int64) {
	usd, tokens := c.SpentUSD, c.SpentTokens
	if usd < 0 {
		usd = 0
	}
	if tokens < 0 {
		tokens = 0
	}
	return usd, tokens
}

// subjectCapOf resolves ONE per-tool / per-model cap into the node's own shape.
// It reports added=false for a cap that governs nothing — a period this node has
// no window for, or a cap the org left at 0 in both units — so an inert row never
// reaches the guard's table.
//
// note is the body-level baseline reporter, called for every cap that produced a
// real ceiling so a subject cap's stale baseline is as visible on the posture as
// a node-wide one's.
//
// THERE IS NO LOWERING HERE, and that is not an omission. A subject cap has no
// local counterpart to be lowered against: the node's own [guard.budget] block
// has never had a per-tool ceiling. Adding one can only RESTRICT, which is what
// the lowering-only posture protects — it forbids the org RAISING a ceiling the
// developer set, not the org introducing a narrower one.
//
// SUBJECT HARDNESS IS THE ORGANIZATION'S ALONE (adversarial review of BUD-N,
// P1-1). It is resolved with the LOCAL hard flag deliberately held at false, so
// a lowering-only node running [guard.budget].hard = true cannot turn an org
// cap the admin authored `soft` into a deny. That was a real defect: the node's
// own hard flag is the developer's posture about the DEVELOPER's own window
// ceilings, and folding it over a per-subject cap contradicted the exemption
// internal/policy/engine.go already grants B-626..B-629 from exactly that
// blanket upgrade. The rule is still windowHard — one owner for the hardness
// question — it is simply asked without a local operand:
//
//	local.Hard=true + org `soft`  =>  Hard=false   (a nudge stays a nudge)
//	local.Hard=*    + org `hard`  =>  Hard=true
//
// The org's `soft` therefore means soft on every node, authoritative or not,
// which is what "the gateway merely warns on it" already means everywhere else.
//
// SUBJECT IDENTITY is resolved through caps.ResolveSubjectID, so the id the org
// typed and the id this node captured meet on ONE spelling — see that field for
// why trim+lowercase alone silently missed every dated model name.
func subjectCapOf(
	entry orgcontract.BudgetPolicyCap,
	kind, id string,
	caps Capabilities,
	maxAge time.Duration,
	note func(state string, entry orgcontract.BudgetPolicyCap, applied bool),
) (SubjectCap, bool) {
	w := windowFor(entry.Period)
	if w == windowNone {
		return SubjectCap{}, false
	}
	usd, tokens := entry.CapUSD, entry.CapTokens
	if usd < 0 {
		usd = 0
	}
	if tokens < 0 {
		tokens = 0
	}
	if usd == 0 && tokens == 0 {
		return SubjectCap{}, false
	}
	out := SubjectCap{
		Kind: kind, ID: caps.resolveSubjectID(kind, id), Window: string(w),
		CapUSD: usd, CapTokens: tokens,
		Hard: windowHard(false, entry.Enforcement, caps.OrgAuthoritative),
	}
	state, apply, flagOnly := classifyBaseline(entry, caps.Now, maxAge)
	if note != nil {
		note(state, entry, apply)
	}
	if apply {
		out.BaselineUSD, out.BaselineTokens = baselineAmounts(entry)
		out.BaselineFlagOnly = flagOnly
	}
	return out, true
}

// SubjectProtection reports whether ANY adopted subject cap of each kind and
// unit is a managed organization's HARD cap. It is the subject half of
// BudgetProtection, computed here so the boundary does not re-derive it.
//
// authoritative is the same capability Compose branched on: only an
// org-authoritative node's hard cap grants process-intervention authority, the
// same rule the window ceilings follow (a lowering-only node's hardness is the
// developer's own flag, which authorizes nothing on the org's behalf).
func SubjectProtection(subjects []SubjectCap, authoritative bool) (toolUSD, toolTokens, modelUSD, modelTokens bool) {
	if !authoritative {
		return false, false, false, false
	}
	for _, sc := range subjects {
		if !sc.Hard {
			continue
		}
		switch sc.Kind {
		case orgcontract.BudgetSubjectTool:
			toolUSD = toolUSD || sc.CapUSD > 0
			toolTokens = toolTokens || sc.CapTokens > 0
		case orgcontract.BudgetSubjectModel:
			modelUSD = modelUSD || sc.CapUSD > 0
			modelTokens = modelTokens || sc.CapTokens > 0
		}
	}
	return toolUSD, toolTokens, modelUSD, modelTokens
}
