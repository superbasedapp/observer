package guard

import (
	"context"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/policy"
)

// Budget & stuck-loop integration (guard spec §12 / G12). The guard
// layer owns three pieces of session state here, all per the
// one-owner rule (§17.4):
//
//   - a TTL-cached spend lookup (SetBudgetLookup, injected at cmd
//     composition — guard never imports store) whose values stamp
//     Event.SessionCostUSD / DailyCostUSD on the watcher-ingest and
//     proxy-request boundaries. Hook processes never stamp: the
//     lookup lives in the daemon, and a per-tool-call DB query would
//     blow the §6.4 latency budget.
//   - a per-session record-dedup for the flag-class B-601/B-602
//     verdicts: cost only grows within a session, so a breach is
//     recorded ONCE per (session, rule) — without this every action
//     past the threshold would re-record. Denies (hard mode, proxy)
//     always record: each blocked request is its own audit event.
//   - the A-610 repeat tracker: consecutive-identical-action run
//     lengths per session, stamped as Event.RepeatCount on the
//     ingest path (watcher only — hook guards are process-local and
//     see one event; documented in the conformance notes).
//
// A-611 (MAD rate baselines) and A-612 (novelty) defer with reason —
// they need the per-project baseline plumbing in internal/intelligence
// (spec §22 tracker).

// BudgetSnapshot is the spend-and-utilization state the budget/limit
// rules compare against, filled once per session per TTL by the
// injected BudgetLookup. All fields zero-value to "unknown" (the rules
// treat 0 as no-match, never as "free" or "idle"): SessionUSD/DailyUSD/
// WeeklyUSD/MonthlyUSD are $ windows over captured spend; Util5h/Util7d
// are the provider's own 5h/weekly usage-window utilization (0..1) from
// the latest limit_snapshots row.
type BudgetSnapshot struct {
	// AccountingEvidence pins independently published accounting inputs (for
	// example a price table) for a subsequent process-control operation.
	AccountingEvidence *BudgetAccountingEvidence
	// PricingDocumentWitness is copied from the immutable price table used to
	// produce the USD totals. Known absence is the exact seed/local state.
	PricingDocumentWitness BudgetDocumentWitness
	// Unavailable windows must not masquerade as zero spend. The corresponding
	// configured rule flags in soft mode and refuses proxy admission in hard mode.
	USDUnavailable    policy.BudgetUnavailableWindows
	TokensUnavailable policy.BudgetUnavailableWindows
	// THERE IS NO PER-TOOL UNAVAILABILITY HERE ANY MORE (ruling A2,
	// 2026-09-15). A `USDUnavailableByTool` map used to carry "this tool
	// emitted a model no exact or org rate could price" into the process
	// controller, which then stopped that tool. It was removed rather than
	// merely ignored so nothing can re-grow the feed: unpriced usage is priced
	// by the same fallback ladder every other Observer surface uses, counted
	// against the cap, and reported through the budget posture
	// (store.GuardBudgetSpendResult.UnpricedModels). What remains above is
	// unavailability the accounting owner could not resolve AT ALL - no
	// verified price table, a failed read - which is still fail-closed.
	SessionUSD float64
	DailyUSD   float64
	WeeklyUSD  float64
	MonthlyUSD float64
	// Weekly*ExpiresAt is the earliest instant at which a currently counted
	// rolling-seven-day row leaves that unit's aggregate. A measured weekly
	// denial is valid only before this boundary; zero means no future horizon
	// was proven.
	WeeklyUSDExpiresAt    time.Time
	WeeklyTokensExpiresAt time.Time
	// SessionTokens / DailyTokens / WeeklyTokens / MonthlyTokens are the
	// TOKEN-denominated siblings of the four $ windows, filled by the SAME
	// injected lookup over the SAME windows (org-budget plan §3.3c). One
	// lookup, both units: a token budget and a dollar budget must never
	// disagree about which turns they are counting. 0 is unknown/unstamped.
	SessionTokens int64
	DailyTokens   int64
	WeeklyTokens  int64
	MonthlyTokens int64
	Util5h        float64
	Util7d        float64
	// ByTool / ByModel are the SAME four windows, in both units, narrowed to
	// one tool or one model — the per-subject slice of the identical read
	// (bundle BUD-N). They feed the organization's per-tool / per-model caps
	// (B-626..B-629) and nothing else.
	//
	// They come from the ONE spend query the lookup already runs, not from a
	// second one, for the reason the token windows were folded into it: a
	// subject total measured over different rows than the node-wide total
	// would let a per-tool cap and the daily cap disagree about the same
	// requests.
	//
	// Keys are NORMALIZED (trimmed, ASCII-lowercased) by the accounting owner,
	// because the org typed the cap's id and an adapter captured the event's.
	// A missing key is simply no usage — the rows treat it as no-match.
	//
	// HONEST LIMIT, stated at the type: proxy turns (api_turns) carry no tool
	// column, so per-TOOL totals see only the natively-captured substrate.
	// Per-MODEL totals see both. The store seam documents the consequence.
	ByTool  map[string]policy.BudgetWindowAmounts
	ByModel map[string]policy.BudgetWindowAmounts
	// SessionTool is the tool that produced THIS session's captured rows, when
	// they all name the same one. It exists because the proxy admission lane
	// has a session id and no tool, so without it a per-tool cap could only
	// ever bite on the process-control pass. Empty when the session has no
	// rows, when they disagree, or when the substrate names no tool at all —
	// never a guess.
	SessionTool string
	// SessionModel is SessionTool's sibling, for the same reason: the
	// process-control pass knows a session and a tool but no model.
	SessionModel string
}

// BudgetAccountingEvidence verifies that a captured accounting snapshot still
// applies while a bounded action runs. The composition owner supplies Fence;
// it must avoid database/network I/O and refuse contended publication locks.
type BudgetAccountingEvidence struct {
	Fence                  func(context.Context, func() error) error
	PricingDocumentWitness BudgetDocumentWitness
	// These horizons are copied from the exact snapshot stamped on the event,
	// so an intervention never consults a newer cache entry for an older
	// numeric decision.
	WeeklyUSDExpiresAt    time.Time
	WeeklyTokensExpiresAt time.Time
}

// BudgetLookup returns the spend-and-utilization snapshot for a
// session. ok=false means the data is unavailable (query error); the
// proxy marks accounting unavailable so configured hard windows fail closed.
// Watcher-only events stay advisory and do not invent a measured breach.
type BudgetLookup func(sessionID string) (BudgetSnapshot, bool)

// BudgetCalendars identifies the calendar windows in a composed budget.
// Empty names mean UTC. Values travel with the immutable numeric policy.
type BudgetCalendars struct {
	DailyTimezone   string
	MonthlyTimezone string
	documentWitness BudgetDocumentWitness
}

// BudgetDocumentWitness identifies the exact durable org-budget document
// state that produced an immutable engine. Known absence is a valid state;
// malformed or signed present documents are identified by their exact SHA-256.
// The command boundary converts this transport-neutral shape to the store's
// witness before entering the SQLite authority fence.
type BudgetDocumentWitness struct {
	Known   bool
	Present bool
	SHA256  string
}

// Valid reports whether the witness can authorize a fenced intervention.
func (w BudgetDocumentWitness) Valid() bool {
	return w.Known && ((!w.Present && w.SHA256 == "") || (w.Present && w.SHA256 != ""))
}

func normalizedBudgetCalendars(calendars []BudgetCalendars) BudgetCalendars {
	var out BudgetCalendars
	if len(calendars) > 0 {
		out = calendars[0]
	}
	if out.DailyTimezone == "" {
		out.DailyTimezone = "UTC"
	}
	if out.MonthlyTimezone == "" {
		out.MonthlyTimezone = "UTC"
	}
	return out
}

// BudgetAccountingContext selects the evidence and calendars belonging to
// the same immutable engine as the decision.
type BudgetAccountingContext struct {
	Managed       bool
	Calendars     BudgetCalendars
	BudgetBinding string
}

// BudgetAccountingLookup selects verified accounting for managed hard caps.
// Concurrent policy publication cannot select weaker evidence or a different
// calendar for an in-flight decision.
type BudgetAccountingLookup func(sessionID string, accounting BudgetAccountingContext) (BudgetSnapshot, bool)

// BudgetBindingLookup returns the exact current enrollment binding. ok=false
// means the node CONFIRMED it holds no live enrollment. A lookup that can fail
// (a store read) must not use this shape, because it cannot say "I do not
// know": install a BudgetIdentityLookup through SetBudgetIdentityLookup.
type BudgetBindingLookup func() (binding string, ok bool)

// BudgetIdentityState is the tri-state answer of an enrollment identity read
// (REVIEW-4 P4-01, operator ruling D-521).
type BudgetIdentityState uint8

const (
	// BudgetIdentityUnknown is the zero value on purpose: the read failed (a
	// timeout, a busy pool, a checkpoint), so nothing is known about the
	// enrollment. The node keeps enforcing the last composed engine.
	BudgetIdentityUnknown BudgetIdentityState = iota
	// BudgetIdentityEnrolled: a live enrollment was read; binding names it.
	BudgetIdentityEnrolled
	// BudgetIdentityNotEnrolled: the read succeeded and no live enrollment
	// exists (never enrolled, unenrolled, or the generation is tombstoned).
	// Only this confirmed answer lifts organization rules.
	BudgetIdentityNotEnrolled
)

// BudgetIdentityLookup returns the current enrollment binding and how sure the
// read is about it.
type BudgetIdentityLookup func() (binding string, state BudgetIdentityState)

// budgetLiveness is what the proxy admission path concludes about the
// enrolment an org-composed engine was built for (T-718 / D-502).
type budgetLiveness int

const (
	// budgetLiveMatch: the engine describes the live enrolment (or carries no
	// enrolment at all, or the identity read failed); evaluate it as composed.
	budgetLiveMatch budgetLiveness = iota
	// budgetLiveRetired: the node confirmed it holds no live enrolment.
	// Whatever the engine's enrolment conferred is retired; evaluate the
	// node's own [guard.budget] numbers only (P4-02).
	budgetLiveRetired
	// budgetLiveReplacedOpen: a DIFFERENT live enrolment, no verified body for
	// it yet, and the org did not opt into fail-closed; evaluate the node's
	// own numbers only.
	budgetLiveReplacedOpen
	// budgetLiveReplacedClosed: as above, but the org opted into fail-closed
	// ([guard.budget].fail_closed): B-625.
	budgetLiveReplacedClosed
)

// budgetLivenessInput is what one admission knows about identity.
type budgetLivenessInput struct {
	hasLookup     bool
	state         BudgetIdentityState
	current       string
	engineBinding string
	failClosed    bool
}

// budgetLivenessRules is the ordered table orgBudgetLiveness walks (CLAUDE.md
// #5). One test case per row (TestOrgBudgetLivenessTable).
//
// The rule it encodes is the B-625 fail-safe: a managed requirement whose
// enrolment no longer exists must never block, and one whose enrolment was
// replaced blocks only when the organization explicitly asked for that. A read
// that could not tell is neither (D-521 "keep last budget"): the last composed
// engine, org and local caps alike, keeps applying, as D-359 P3-11 ruled.
var budgetLivenessRules = []struct {
	name string
	when func(budgetLivenessInput) bool
	out  budgetLiveness
}{
	// No identity read is wired and the engine names no enrolment: a purely
	// local engine (or a test). Nothing to check.
	{"unbound_without_lookup", func(in budgetLivenessInput) bool { return !in.hasLookup && in.engineBinding == "" }, budgetLiveMatch},
	// The identity read failed. Unknown is not "not enrolled": keep enforcing
	// the last composed engine. Placed above every fail-open row so a busy
	// store can never lift a verified, exceeded cap.
	{"identity_unknown", func(in budgetLivenessInput) bool {
		return in.hasLookup && in.state == BudgetIdentityUnknown
	}, budgetLiveMatch},
	// The identity read CONFIRMED there is no live enrolment (unenrolled or
	// tombstoned). Never block on a requirement nobody holds.
	{"no_live_enrolment", func(in budgetLivenessInput) bool {
		return in.hasLookup && in.state == BudgetIdentityNotEnrolled
	}, budgetLiveRetired},
	// The engine was composed for exactly the live enrolment.
	{"same_enrolment", func(in budgetLivenessInput) bool {
		return in.state == BudgetIdentityEnrolled && in.current == in.engineBinding
	}, budgetLiveMatch},
	// Replaced and the org opted into fail-closed.
	{"replaced_fail_closed", func(in budgetLivenessInput) bool { return in.failClosed }, budgetLiveReplacedClosed},
	// Replaced, default posture: fail open onto the node's own numbers.
	{"replaced_fail_open", func(budgetLivenessInput) bool { return true }, budgetLiveReplacedOpen},
}

// orgBudgetLiveness resolves one admission's identity facts through the table.
func orgBudgetLiveness(hasLookup bool, state BudgetIdentityState, current, engineBinding string, failClosed bool) budgetLiveness {
	in := budgetLivenessInput{hasLookup: hasLookup, state: state, current: current, engineBinding: engineBinding, failClosed: failClosed}
	for _, r := range budgetLivenessRules {
		if r.when(in) {
			return r.out
		}
	}
	return budgetLiveReplacedOpen
}

// budgetCacheTTL bounds how stale a stamped spend value may be; a
// breach is detected at most one TTL after it happens, and the
// underlying store query runs at most once per session per TTL.
//
// THE TTL IS MEASURED ON THE GUARD'S OWN CLOCK, never on the event's
// timestamp (T-413). The lookup reads spend relative to wall-clock now
// (the daemon computes its day / week / month starts from time.Now), so
// the age of a cached answer is a wall-clock fact too. Keying it on
// Event.Now made every action of a backlog replay a cache miss: a
// transcript that fell behind replays hours of actions in one batch, each
// more than 30 s (of TRANSCRIPT time) after the previous one, and each
// paid a full node-wide spend read (about 1.2 s over a month of usage on
// the 2026-10-05 node), so the watcher landed 4 actions in 10 minutes.
const budgetCacheTTL = 30 * time.Second

// maxBudgetSessions bounds the cache + dedup maps (the proxySeen
// bound shape).
const maxBudgetSessions = 256

// budgetEntry is one cached lookup result. ok=false caches a FAILED
// lookup for the same TTL: an unavailable accounting read is stamped as
// unavailable either way, and retrying it on every action of a batch
// turned one slow read (bounded by the caller's own timeout) into one per
// action. A caller that needs a fresh answer (hard proxy admission, the
// intervention pass) passes fresh=true and bypasses the entry, failed or
// not, exactly as before.
//
// A failed ADVISORY lookup does NOT evict a good answer (review P3-41): when
// the session already holds a good snapshot measured within
// budgetKeepGoodMax, the failure keeps that snapshot (its retry clock
// restarts, its measuredAt does not), so one slow read no longer leaves every
// captured action of the session unmeasured for a whole TTL. An admission
// (an API request) never takes this path and ages the entry by measuredAt. Past budgetKeepGoodMax the failure
// is cached as before: an old number is not presented as a current one.
type budgetEntry struct {
	snap BudgetSnapshot
	// at is the retry clock: when this entry was last (re)validated.
	at time.Time
	// measuredAt is when snap was actually read (equal to at for a fresh
	// read; older when a failed refresh kept a good snapshot).
	measuredAt time.Time
	accounting BudgetAccountingContext
	ok         bool
}

// budgetKeepGoodMax bounds how old a good snapshot a failed non-fresh lookup
// may keep in place (review P3-41).
const budgetKeepGoodMax = 5 * time.Minute

// budgetClockFunc is the type of Guard.budgetClock.
type budgetClockFunc func() time.Time

// budgetNow is the clock the budget cache ages on: the injected test
// clock when one is set, wall-clock time otherwise.
func (g *Guard) budgetNow() time.Time {
	if g.budgetClock != nil {
		return g.budgetClock()
	}
	return time.Now().UTC()
}

// SetBudgetLookup wires the spend lookup. Nil keeps budget stamping
// off (events carry zero → B-601/B-602 and cost user-matchers are
// inert). Set once at composition.
func (g *Guard) SetBudgetLookup(fn BudgetLookup) {
	if fn == nil {
		g.budgetLookup = nil
		return
	}
	g.budgetLookup = func(sessionID string, _ BudgetAccountingContext) (BudgetSnapshot, bool) { return fn(sessionID) }
}

// SetBudgetAccountingLookup wires the daemon's shared accounting owner. Its
// managed mode must reject estimates and ambiguous source overlap. Install
// once at composition, before serving decisions.
func (g *Guard) SetBudgetAccountingLookup(fn BudgetAccountingLookup) {
	g.budgetLookup = fn
}

// SetBudgetBindingLookup wires a TWO-state enrollment identity read, where
// ok=false is a confirmed "no live enrollment". Kept for callers whose answer
// cannot fail (tests, fixed fixtures); the daemon installs the tri-state
// SetBudgetIdentityLookup.
func (g *Guard) SetBudgetBindingLookup(fn BudgetBindingLookup) {
	if fn == nil {
		g.budgetIdentityLookup = nil
		return
	}
	g.budgetIdentityLookup = func() (string, BudgetIdentityState) {
		if binding, ok := fn(); ok {
			return binding, BudgetIdentityEnrolled
		}
		return "", BudgetIdentityNotEnrolled
	}
}

// SetBudgetIdentityLookup wires the enrollment identity read used by proxy
// admission and the intervention pass. It is installed once by the org-budget
// composition boundary. A failed read must answer BudgetIdentityUnknown.
func (g *Guard) SetBudgetIdentityLookup(fn BudgetIdentityLookup) {
	g.budgetIdentityLookup = fn
}

// budgetIdentity runs the installed identity read. ok=false means none is
// installed.
func (g *Guard) budgetIdentity() (binding string, state BudgetIdentityState, ok bool) {
	if g.budgetIdentityLookup == nil {
		return "", BudgetIdentityUnknown, false
	}
	binding, state = g.budgetIdentityLookup()
	return binding, state, true
}

// SetBudgetSubjectResolver wires the ONE identity rule a per-tool / per-model
// cap is compared under (bundle BUD-N, adversarial review P1-3).
//
// A subject cap compares an id the ORG typed against an id an ADAPTER captured.
// Trimming and lowercasing both — the rule that shipped first — leaves
// `claude-sonnet-5` and `claude-sonnet-5-20260501` as two different subjects,
// so an authored model cap matched nothing while reporting as in force. The
// boundary injects a resolver built on the price table's own alias ladder
// (exact -> date-stripped -> family), which is the one component in the product
// that already knows when two model strings name one model.
//
// It is installed ONCE at composition, like SetBudgetLookup, and the SAME
// function is handed to the accounting owner so the caps, the accounting keys
// and the stamped event all spell a subject the same way. Nil leaves the plain
// normalisation in place — the pre-resolver behaviour, which every hook process
// and every node with no price table still gets.
func (g *Guard) SetBudgetSubjectResolver(fn func(kind, id string) string) {
	g.budgetSubjectResolver = fn
}

// BudgetSubjectResolver returns the installed resolver (nil when none is), so
// the org-budget composition boundary can resolve the org's cap ids through
// exactly the function the accounting and the stamp use.
func (g *Guard) BudgetSubjectResolver() func(kind, id string) string {
	if g == nil {
		return nil
	}
	return g.budgetSubjectResolver
}

// resolveBudgetSubject folds one captured id onto the cap's identity. An empty
// answer falls back to the plain normalisation for the reason the composer
// does: an empty subject id would turn a cap that named one thing into a cap
// that matches nothing, silently.
func (g *Guard) resolveBudgetSubject(kind, id string) string {
	norm := NormalizeBudgetSubjectID(id)
	if norm == "" || g == nil || g.budgetSubjectResolver == nil {
		return norm
	}
	if out := NormalizeBudgetSubjectID(g.budgetSubjectResolver(kind, norm)); out != "" {
		return out
	}
	return norm
}

// Subject KIND vocabulary as the guard spells it, mirroring
// orgcontract.BudgetSubject* / policy.BudgetSubjectKind*. Re-declared because
// this package must not learn the wire contract's types for two string
// constants.
const (
	budgetSubjectKindTool  = "tool"
	budgetSubjectKindModel = "model"
)

// BudgetSubjectUnmatched reports whether the last full accounting pass found a
// published per-tool / per-model cap whose id never appeared in its own
// accounting keys — a cap that is applied and governing nothing here.
//
// It is READ ONLY by the posture boundary, which ships it to the org as an
// enum-only bool. Nothing in the decision path consults it: a cap that matches
// no usage is not a reason to allow or deny anything, it is a reason for an
// admin to fix the id they typed.
func (g *Guard) BudgetSubjectUnmatched() bool {
	if g == nil {
		return false
	}
	return g.effBudgetSubjectUnmatched.Load()
}

// noteSubjectCoverage records whether any published subject cap's id is absent
// from this pass's accounting keys.
//
// "A FULL ACCOUNTING PASS" is the qualifier that makes this honest: it is
// evaluated against the maps the accounting owner just returned, so an id that
// is missing because the tool has never run on this node is exactly the fact
// reported — the cap bites nothing here — and an id that is missing because the
// two sides spell the subject differently reports the same way, which is also
// correct, because to this node they are the same failure. With no caps
// published there is nothing to be unmatched, so it clears.
func (g *Guard) noteSubjectCoverage(snap BudgetSnapshot) {
	if g == nil {
		return
	}
	caps := g.budgetSubjectCaps()
	unmatched := false
	for _, sc := range caps {
		keys := snap.ByTool
		if sc.Kind == budgetSubjectKindModel {
			keys = snap.ByModel
		}
		if _, ok := keys[sc.ID]; !ok {
			unmatched = true
			break
		}
	}
	g.effBudgetSubjectUnmatched.Store(unmatched)
}

// stampBudget fills the Event's spend fields from the cached lookup.
// An empty session ID still needs node-wide daily/weekly/monthly accounting.
func (g *Guard) stampBudget(ev *policy.Event) {
	g.stampBudgetWithFreshness(ev, false)
}

// stampBudgetWithFreshness bypasses a still-valid cache entry when fresh is
// true. Proxy admission uses this only when a budget row can deny; advisory
// watcher and soft proxy evaluations retain the bounded TTL cache.
func (g *Guard) stampBudgetWithFreshness(ev *policy.Event, fresh bool) {
	var calendars BudgetCalendars
	if es := g.set.Load(); es != nil {
		calendars = es.budgetCalendars
	}
	g.stampBudgetAccounting(ev, fresh, false, calendars)
}

func (g *Guard) stampBudgetAccounting(ev *policy.Event, fresh, managed bool, calendars ...BudgetCalendars) *BudgetAccountingEvidence {
	return g.stampBudgetSnapshot(ev, fresh, BudgetAccountingContext{Managed: managed, Calendars: normalizedBudgetCalendars(calendars)})
}

// stampBudgetIfRead is the hot-path entry to stampBudgetSnapshot for the
// watcher-ingest and proxy-admission lanes: it stamps only when the engine
// that will evaluate ev can read a stamp at all (policy.Engine.
// ReadsBudgetStamps, resolved once when that engine was built).
//
// WHY (T-418): the lookup behind the stamp is a node-wide spend AND token
// read over the rolling windows, about 1.2 s on a month-old large node, paid
// once per session per cache TTL. On a node with no budget cap of any kind -
// local [guard.budget] all zero, no organization budget in force, no limit
// threshold, no policy-file spend matcher - every one of those reads fed
// rules that cannot match, and a backlog replay touching many sessions paid
// it once per session. With nothing to read, the event stays unstamped,
// which every budget row already treats as no-match.
//
// The posture flag noteSubjectCoverage maintains is cleared on the skip path
// when no subject cap is published, as the stamp's own pass would have, so
// retiring the last cap cannot leave a stale "unmatched" report behind.
func (g *Guard) stampBudgetIfRead(es *engineSet, ev *policy.Event, fresh bool, accounting BudgetAccountingContext) *BudgetAccountingEvidence {
	if es != nil && !es.engineFor(g, ev.ProjectRoot).ReadsBudgetStamps() {
		if len(g.budgetSubjectCaps()) == 0 {
			g.effBudgetSubjectUnmatched.Store(false)
		}
		return nil
	}
	return g.stampBudgetSnapshot(ev, fresh, accounting)
}

func (g *Guard) stampBudgetSnapshot(ev *policy.Event, fresh bool, accounting BudgetAccountingContext) *BudgetAccountingEvidence {
	return g.stampBudgetSnapshotWithin(ev, fresh, 0, accounting)
}

// stampBudgetSnapshotWithin is stampBudgetSnapshot with a freshness bound
// for a fresh caller: maxAge > 0 lets a fresh caller reuse a GOOD entry read
// within maxAge instead of paying another read (review P3-11: the hook-path
// admission publisher asks the node-wide decision and one per hard per-tool
// cap every tick; they share one read per maxAge rather than 1+N per tick).
// maxAge 0 is the old fresh rule: always read.
func (g *Guard) stampBudgetSnapshotWithin(ev *policy.Event, fresh bool, maxAge time.Duration, accounting BudgetAccountingContext) *BudgetAccountingEvidence {
	if g.budgetLookup == nil {
		stampBudgetUnavailable(ev)
		return nil
	}
	// The cache ages on the guard's clock, not on ev.Now (see budgetCacheTTL).
	now := g.budgetNow()
	g.budgetMu.Lock()
	e, ok := g.budgetCache[ev.SessionID]
	g.budgetMu.Unlock()
	reuseFresh := fresh && maxAge > 0 && ok && e.ok && e.accounting == accounting &&
		!now.Before(e.measuredAt) && now.Sub(e.measuredAt) <= maxAge
	// An admission (an API request) ages the entry by when its snapshot was
	// MEASURED, so a good snapshot an advisory lane kept through a failed
	// refresh never stands in for a read the admission needs: a hard
	// budget's proxy admission still fails closed on a failing read
	// (TestProxyBudgetLookupFailureAfterTTL).
	admission := ev.Kind == policy.KindAPIRequest
	retryAt := e.at
	if admission {
		retryAt = e.measuredAt
	}
	if (fresh && !reuseFresh) || !ok || e.accounting != accounting || now.Sub(retryAt) > budgetCacheTTL || now.Before(retryAt) {
		snap, lok := g.budgetLookup(ev.SessionID, accounting)
		if !lok && fresh {
			// A fresh caller's failure never replaces a cached answer: the
			// advisory lanes keep whatever they had, as before.
			stampBudgetUnavailable(ev)
			return nil
		}
		switch {
		case !lok && !admission && ok && e.ok && e.accounting == accounting &&
			!now.Before(e.measuredAt) && now.Sub(e.measuredAt) <= budgetKeepGoodMax:
			// A failed refresh keeps the good snapshot it would have replaced
			// (P3-41); only the retry clock moves.
			e.at = now
		default:
			e = budgetEntry{snap: snap, at: now, measuredAt: now, accounting: accounting, ok: lok}
		}
		g.budgetMu.Lock()
		if g.budgetCache == nil {
			g.budgetCache = make(map[string]budgetEntry)
		}
		if len(g.budgetCache) >= maxBudgetSessions {
			evictOldestBudget(g.budgetCache)
		}
		g.budgetCache[ev.SessionID] = e
		g.budgetMu.Unlock()
	}
	if !e.ok {
		stampBudgetUnavailable(ev)
		return nil
	}
	ev.SessionCostUSD = e.snap.SessionUSD
	ev.DailyCostUSD = e.snap.DailyUSD
	ev.WeeklyCostUSD = e.snap.WeeklyUSD
	ev.MonthlyCostUSD = e.snap.MonthlyUSD
	ev.SessionTokens = e.snap.SessionTokens
	ev.DailyTokens = e.snap.DailyTokens
	ev.WeeklyTokens = e.snap.WeeklyTokens
	ev.MonthlyTokens = e.snap.MonthlyTokens
	ev.USDUnavailable = e.snap.USDUnavailable
	ev.TokensUnavailable = e.snap.TokensUnavailable
	// The per-subject slices for the organization's tool/model caps. Keyed by
	// the event's OWN tool and model, normalized the same way the caps were:
	// this is a lookup, never a branch on which tool it is.
	// THE PROXY LANE KNOWS NO TOOL. A proxied request names a model and a
	// provider; which adapter sent it is not on the wire. The accounting owner
	// resolves it from the session's own captured rows when they agree on one
	// (BudgetSnapshot.SessionTool) — a resolution at the boundary, from data,
	// never a guess about which tool this is. An event that already carries its
	// own tool (every watcher and hook path) keeps it.
	if ev.Tool == "" {
		ev.Tool = e.snap.SessionTool
	}
	// ONE identity for the cap, the accounting key and the event (bundle BUD-N,
	// adversarial review P1-3). The resolved id is stamped onto the event so
	// the rule rows compare the same spelling the accounting owner keyed its
	// totals by, and the RAW Tool/Model are left untouched — they are reporting
	// data for every other rule and a verdict that renamed a developer's model
	// would be lying about what ran.
	ev.ToolSubjectID = g.resolveBudgetSubject(budgetSubjectKindTool, ev.Tool)
	ev.ToolUsage = subjectUsage(e.snap.ByTool, ev.ToolSubjectID)
	// The same resolution for the model, and the same precedence: a caller
	// that KNOWS the model (the proxy parses it out of the request body) keeps
	// its own, and only a caller that does not — the process-control pass —
	// falls back to the session's own unanimous evidence.
	if ev.Model == "" {
		ev.Model = e.snap.SessionModel
	}
	ev.ModelSubjectID = g.resolveBudgetSubject(budgetSubjectKindModel, ev.Model)
	ev.ModelUsage = subjectUsage(e.snap.ByModel, ev.ModelSubjectID)
	// The cap-vs-usage identity check rides the same pass, because this is the
	// one place that holds BOTH the published caps and the accounting keys.
	g.noteSubjectCoverage(e.snap)
	// The cross-machine baseline is POLICY, not measurement: it arrives on the
	// organization's signed body and is published with the composed budget, so
	// it is read from the engine's own published state rather than from the
	// spend snapshot. Stamping it here — beside the totals it is added to —
	// keeps every budget row comparing one consistent pair.
	ev.OrgBaseline = g.budgetBaseline()
	ev.OrgBaselineFlagOnly = g.budgetBaselineFlagOnly()
	ev.Window5hUtil = e.snap.Util5h
	ev.Window7dUtil = e.snap.Util7d
	evidence := BudgetAccountingEvidence{
		PricingDocumentWitness: e.snap.PricingDocumentWitness,
		WeeklyUSDExpiresAt:     e.snap.WeeklyUSDExpiresAt, WeeklyTokensExpiresAt: e.snap.WeeklyTokensExpiresAt,
	}
	if e.snap.AccountingEvidence != nil {
		evidence.Fence = e.snap.AccountingEvidence.Fence
	}
	return &evidence
}

// subjectUsage reads one subject's window totals out of a stamped map.
// An empty id or an absent key is the zero value, which every budget row
// treats as no-match — never as "free".
func subjectUsage(m map[string]policy.BudgetWindowAmounts, id string) policy.BudgetWindowAmounts {
	if len(m) == 0 || id == "" {
		return policy.BudgetWindowAmounts{}
	}
	return m[NormalizeBudgetSubjectID(id)]
}

// NormalizeBudgetSubjectID folds a tool or model identifier onto the one
// spelling both ends of a subject cap are compared in: trimmed, ASCII-lowered.
//
// It is EXPORTED because the accounting owner (the daemon's budget lookup) must
// key its per-subject totals exactly as the stamp reads them, and two private
// copies of "lowercase it" in two packages is how a cap silently stops matching.
func NormalizeBudgetSubjectID(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
}

func stampBudgetUnavailable(ev *policy.Event) {
	if ev.Kind != policy.KindAPIRequest {
		return
	}
	all := policy.BudgetUnavailableWindows{Session: true, Daily: true, Weekly: true, Monthly: true}
	ev.USDUnavailable, ev.TokensUnavailable = all, all
}

// evictOldestBudget drops the stalest cache entry (called locked).
func evictOldestBudget(m map[string]budgetEntry) {
	var oldest string
	var at time.Time
	first := true
	for k, e := range m {
		if first || e.at.Before(at) {
			oldest, at, first = k, e.at, false
		}
	}
	delete(m, oldest)
}

// isBudgetRuleID marks the rows the budget seam owns (flag-dedup +
// which winning rule the proxy budget check records). Covers every
// $ budget window (B-601..B-604) and the provider usage-window limit
// rows (B-610..B-613) — all share the "B-6" prefix.
func isBudgetRuleID(id string) bool { return strings.HasPrefix(id, "B-6") }

// budgetAlreadyRecorded reports (and marks) whether a flag-class
// budget verdict was already recorded for this session+rule. Denies
// never consult this — they always record.
func (g *Guard) budgetAlreadyRecorded(sessionID, ruleID string) bool {
	if sessionID == "" {
		return false
	}
	g.budgetMu.Lock()
	defer g.budgetMu.Unlock()
	if g.budgetRecorded == nil {
		g.budgetRecorded = make(map[string]map[string]bool)
	}
	rules := g.budgetRecorded[sessionID]
	if rules == nil {
		if len(g.budgetRecorded) >= maxBudgetSessions {
			for k := range g.budgetRecorded {
				delete(g.budgetRecorded, k)
				break
			}
		}
		rules = make(map[string]bool)
		g.budgetRecorded[sessionID] = rules
	}
	if rules[ruleID] {
		return true
	}
	rules[ruleID] = true
	return false
}

// scanBudget is the §12.1 proxy-request budget check: one stamped
// api_request event through the real engine BEFORE the egress scan
// (cheapest check first; a hard-mode deny skips the rest of the
// pipeline — the request never reaches the provider). Soft breaches
// flag once per session per rule. es is the caller's already-Loaded
// snapshot so the Evaluate+CategoryFor pair stays consistent (NIT).
//
// model is the model the request names, when the caller parsed one — the proxy
// body carries it and the scan already has it in hand. It scopes the
// organization's per-MODEL caps (B-628/B-629) on this chokepoint. It is
// VARIADIC for the reason ApplyOrgBudget's calendars are: an additive fact that
// every existing caller (and every existing test) may keep omitting, rather
// than a signature change rippling through call sites that have no model to
// give. Absent means a model cap cannot match here, which is the honest answer.
// budgetEventIsVacant reports whether a stamped event carries NOTHING a budget
// rule could compare: every node-wide window amount zero, every per-subject
// slice zero, every unavailability set empty, both limit-window utilizations
// zero.
//
// It is ONE predicate rather than a conjunction spelled out on the scan path
// (CLAUDE.md #1) so that a newly-added stamp is a single line here and cannot
// be forgotten in the shortcut — which is exactly the bug the token stamps
// had: the early return swallowed the one comparison that would have fired.
func budgetEventIsVacant(ev policy.Event) bool {
	return ev.USDUnavailable == (policy.BudgetUnavailableWindows{}) &&
		ev.TokensUnavailable == (policy.BudgetUnavailableWindows{}) &&
		ev.SessionCostUSD == 0 && ev.DailyCostUSD == 0 &&
		ev.WeeklyCostUSD == 0 && ev.MonthlyCostUSD == 0 &&
		ev.SessionTokens == 0 && ev.DailyTokens == 0 &&
		ev.WeeklyTokens == 0 && ev.MonthlyTokens == 0 &&
		ev.ToolUsage == (policy.BudgetWindowAmounts{}) &&
		ev.ModelUsage == (policy.BudgetWindowAmounts{}) &&
		ev.OrgBaseline == (policy.BudgetWindowAmounts{}) &&
		ev.Window5hUtil == 0 && ev.Window7dUtil == 0
}

func (g *Guard) scanBudget(es *engineSet, res *ProxyRequestResult, sessionID, target string, now time.Time, model ...string) {
	ev := policy.Event{
		Kind:      policy.KindAPIRequest,
		Target:    target,
		SessionID: sessionID,
		Caps:      proxyRequestCaps,
		Now:       now,
	}
	if len(model) > 0 {
		ev.Model = model[0]
	}
	bindingMismatch := false
	if es.budgetBinding != "" || es.base().BudgetRequired() {
		current, state, hasLookup := g.budgetIdentity()
		switch orgBudgetLiveness(hasLookup, state, current, es.budgetBinding, g.budgetConfig().FailClosed) {
		case budgetLiveRetired, budgetLiveReplacedOpen:
			// THE B-625 FAIL-SAFE (T-718), on the node's OWN numbers (P4-02).
			//
			// Retired: the engine was composed for an enrolment this node
			// confirmed no longer exists (`observer unenroll` in another
			// process, or the dashboard's Leave) and the daemon has not
			// recomposed yet. Replaced-open: a DIFFERENT live enrolment with
			// no verified body yet and no fail-closed opt-in (D-502). Either
			// way nothing the old enrolment composed may refuse a request,
			// least of all B-625. But "fail open" means open onto the node's
			// own [guard.budget] caps, never onto no caps at all, so the
			// request is evaluated against the local-only engine built from
			// the same layers. A local engine that cannot be built admits, as
			// before (the guard never takes a request down with it).
			local := es.localBudgetSet(g)
			if local == nil {
				return
			}
			es = local
		case budgetLiveReplacedClosed:
			bindingMismatch = true
		}
	}
	if !bindingMismatch {
		g.stampBudgetIfRead(es, &ev, es.base().BudgetAdmissionRequiresFresh(), es.accountingContext(es.base().ManagedBudgetRequired()))
	}
	// The all-zero early return below is the cheap "nothing to compare"
	// shortcut, and it is exactly wrong for the one row that compares
	// nothing: B-625 fires BECAUSE no organization budget was ever verified
	// here, so an unstamped request is the common case, not an exemption.
	// The engine's own flag decides, so the shortcut and the evaluation can
	// never disagree about whether the fail-closed posture is armed.
	// The SUBJECT stamps join the same shortcut (bundle BUD-N): a per-tool or
	// per-model cap compares its own slice of spend, so an event whose
	// node-wide stamps are all zero can still be over one. Leaving them out of
	// this condition is precisely the bug the token stamps had — the early
	// return swallowed the one comparison that would have fired.
	if !bindingMismatch && !es.base().BudgetRequired() && budgetEventIsVacant(ev) {
		return
	}
	var verdict policy.Verdict
	var guardErr error
	if bindingMismatch {
		verdict = es.base().EvaluateMissingManagedBudget(ev)
	} else {
		verdict, guardErr = g.evaluateBudgetWith(es, ev)
	}
	if verdict.Decision < policy.DecisionFlag && guardErr == nil {
		return
	}
	if !isBudgetRuleID(verdict.RuleID) && guardErr == nil {
		// Some other api_request row won (it will get its own pass on
		// the egress event); the budget seam only owns B-6xx records.
		return
	}
	if guardErr == nil {
		if es.localBudgetOnly {
			// The node's own cap: no organization label may claim it.
			verdict = g.displayBudgetVerdict(verdict)
		} else {
			verdict = g.labelOrgBudgetVerdict(verdict)
		}
	}
	var appr approvalOutcome
	if !bindingMismatch && !es.base().BudgetRuleProtected(verdict.RuleID) {
		// Budget rules never take an org guard grant (grantEligible): a
		// budget increase is its own grant type folded into the cap.
		verdict, appr = g.applyApprovals(verdict, &ev, OrgGrantLaneProxy)
	}

	av := ActionVerdict{
		Input: ActionInput{
			SessionID: sessionID,
			Target:    target,
			Timestamp: now,
		},
		Kind:       policy.KindAPIRequest,
		Category:   g.categoryWith(es, verdict.RuleID),
		Verdict:    verdict,
		GuardError: guardErr != nil,
	}
	g.stampOrgOverride(es, &av)
	appr.stamp(&av)
	em := ResolveEmission(verdict, proxyRequestCaps)
	if em.Permission == "deny" {
		av.Enforced = true
		res.Deny = true
		res.DenyRuleID = verdict.RuleID
		res.DenyReason = verdict.Reason
		res.DenyHumanLine = HumanBlockLine(av, sessionID)
		res.Verdicts = append(res.Verdicts, av)
		return
	}
	if g.budgetAlreadyRecorded(sessionID, verdict.RuleID) {
		return
	}
	if guardErr == nil && g.hasOrgBudgetOrigin(verdict.RuleID) {
		// The budget-warning service announces org-window crossings on
		// every developer surface (once per period); the guard's own
		// desktop alert for the same flag would be a duplicate.
		av.SuppressAlert = true
	}
	res.Verdicts = append(res.Verdicts, av)
}
