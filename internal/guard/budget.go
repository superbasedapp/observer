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
// means identity is unavailable and therefore cannot authorize an existing
// managed budget snapshot.
type BudgetBindingLookup func() (binding string, ok bool)

// budgetCacheTTL bounds how stale a stamped spend value may be; a
// breach is detected at most one TTL after it happens, and the
// underlying store query runs at most once per session per TTL.
const budgetCacheTTL = 30 * time.Second

// maxBudgetSessions bounds the cache + dedup maps (the proxySeen
// bound shape).
const maxBudgetSessions = 256

// budgetEntry is one cached lookup result.
type budgetEntry struct {
	snap       BudgetSnapshot
	at         time.Time
	accounting BudgetAccountingContext
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

// SetBudgetBindingLookup wires the enrollment identity read used by proxy
// admission. It is installed once by the org-budget composition boundary.
func (g *Guard) SetBudgetBindingLookup(fn BudgetBindingLookup) {
	g.budgetBindingLookup = fn
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

func (g *Guard) stampBudgetSnapshot(ev *policy.Event, fresh bool, accounting BudgetAccountingContext) *BudgetAccountingEvidence {
	if g.budgetLookup == nil {
		stampBudgetUnavailable(ev)
		return nil
	}
	now := ev.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	g.budgetMu.Lock()
	e, ok := g.budgetCache[ev.SessionID]
	g.budgetMu.Unlock()
	if fresh || !ok || e.accounting != accounting || now.Sub(e.at) > budgetCacheTTL || now.Before(e.at) {
		snap, lok := g.budgetLookup(ev.SessionID, accounting)
		if !lok {
			stampBudgetUnavailable(ev)
			return nil
		}
		e = budgetEntry{snap: snap, at: now, accounting: accounting}
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
	if es.budgetBinding != "" {
		current := ""
		ok := false
		if g.budgetBindingLookup != nil {
			current, ok = g.budgetBindingLookup()
		}
		bindingMismatch = !ok || current != es.budgetBinding
	}
	if !bindingMismatch {
		g.stampBudgetSnapshot(&ev, es.base.BudgetAdmissionRequiresFresh(), es.accountingContext(es.base.ManagedBudgetRequired()))
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
	if !bindingMismatch && !es.base.BudgetRequired() && budgetEventIsVacant(ev) {
		return
	}
	var verdict policy.Verdict
	var guardErr error
	if bindingMismatch {
		verdict = es.base.EvaluateMissingManagedBudget(ev)
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
	approved := false
	if !bindingMismatch && !es.base.BudgetRuleProtected(verdict.RuleID) {
		verdict, approved = g.applyApprovals(verdict, &ev)
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
	if approved {
		av.DegradedFrom = "approved"
	}
	em := ResolveEmission(verdict, proxyRequestCaps)
	if em.Permission == "deny" {
		av.Enforced = true
		res.Deny = true
		res.DenyRuleID = verdict.RuleID
		res.DenyReason = verdict.Reason
		res.Verdicts = append(res.Verdicts, av)
		return
	}
	if g.budgetAlreadyRecorded(sessionID, verdict.RuleID) {
		return
	}
	res.Verdicts = append(res.Verdicts, av)
}
