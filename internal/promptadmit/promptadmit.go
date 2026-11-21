package promptadmit

import (
	"container/list"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"time"

	policyfamadmission "github.com/marmutapp/superbased-observer/internal/policyfam/admission"
	"github.com/marmutapp/superbased-observer/internal/promptturn"
)

// Scope is how much of a coding agent's traffic the judge reads.
type Scope string

// The closed scope vocabulary of the signed planeb.admission body.
const (
	// ScopeUserPrompts judges only a request whose newest turn is the
	// developer's own prompt (the default: about 5 to 8 percent of the judge
	// calls of ScopeAllCalls on a typical tool loop).
	ScopeUserPrompts Scope = "user_prompts"
	// ScopeAllCalls judges every request's new trailing segment, tool
	// results included.
	ScopeAllCalls Scope = "all_calls"
)

// ParseScope maps the body token onto a Scope. Empty is ScopeUserPrompts (an
// older body has no scope key); anything else outside the closed set is an
// error, so a typo can never silently widen or narrow the judge.
func ParseScope(s string) (Scope, error) {
	switch Scope(s) {
	case "", ScopeUserPrompts:
		return ScopeUserPrompts, nil
	case ScopeAllCalls:
		return ScopeAllCalls, nil
	default:
		return "", fmt.Errorf("promptadmit: unknown scope %q (want %q or %q)", s, ScopeUserPrompts, ScopeAllCalls)
	}
}

// Skip names why a request is not judged ("" when it is).
type Skip string

// The closed skip vocabulary (recorded on debug logs, never on a verdict).
const (
	SkipNone         Skip = ""
	SkipContinuation Skip = "continuation"
	SkipNoUserTurn   Skip = "no_user_turn"
	SkipEmptyText    Skip = "empty_text"
)

// Plan is what one request contributes to the judge.
type Plan struct {
	// Judge is true when Text must be evaluated.
	Judge bool
	// Text is the judged text (the prompt, or the trailing segment under
	// all_calls).
	Text string
	// Skip is the reason Judge is false.
	Skip Skip
	// Continuation is true when the request is a tool-loop continuation:
	// a seam that finds its verdict cached calls Cache.Refresh, so a loop
	// in use keeps the verdict of the prompt that opened it.
	Continuation bool
}

// planRow is one row of the plan table: for a scope and turn kind, which
// field of the turn is judged, and the skip reason when that field is blank.
type planRow struct {
	scope     Scope
	kind      promptturn.Kind
	text      func(promptturn.Turn) string
	emptySkip Skip
}

func promptText(t promptturn.Turn) string   { return t.Text }
func trailingText(t promptturn.Turn) string { return t.Trailing }
func openingText(t promptturn.Turn) string  { return t.Opening }

// planTable is walked top-down; the first row matching scope and kind wins.
//
// Under user_prompts a continuation judges the prompt that OPENED the loop.
// Through the seam's verdict cache that is a lookup on a real loop (the
// prompt was judged when it was newest, under the same policy version), and
// a real judge call only on a miss: a hand-built body that dresses a prompt
// up as a tool loop is still judged (fix round 1, F3). A loop with no typed
// prompt at all is not judged under user_prompts.
//
// Under all_calls every request's new trailing segment is judged, a fresh
// prompt and a tool-output-only request included.
var planTable = []planRow{
	{ScopeUserPrompts, promptturn.KindUserPrompt, promptText, SkipEmptyText},
	{ScopeUserPrompts, promptturn.KindContinuation, openingText, SkipContinuation},
	{ScopeAllCalls, promptturn.KindUserPrompt, trailingText, SkipEmptyText},
	{ScopeAllCalls, promptturn.KindContinuation, trailingText, SkipEmptyText},
}

// PlanTurn decides what of one classified request is judged. A kind with no
// row (none) is SkipNoUserTurn; a row whose text is empty or whitespace only
// gets the row's skip reason, so the judge is never called on nothing.
func PlanTurn(scope Scope, t promptturn.Turn) Plan {
	for _, r := range planTable {
		if r.scope != scope || r.kind != t.Kind {
			continue
		}
		text := r.text(t)
		if strings.TrimSpace(text) == "" {
			return Plan{Skip: r.emptySkip}
		}
		return Plan{Judge: true, Text: text, Continuation: t.Kind == promptturn.KindContinuation}
	}
	return Plan{Skip: SkipNoUserTurn}
}

// EngineResult is the shared admission engine's plain verdict for one text.
type EngineResult struct {
	Decision  policyfamadmission.Decision
	Criterion string
	Reason    string
	// JudgeUnavailable is true when the judge could not deliver a verdict
	// (no route, no credential, timeout, transport error, unreadable reply).
	// It is carried so the outcome follows the policy's strict flag, says so,
	// and is never cached. Set ONLY from the engine's own degradation
	// classification, never inferred by a seam.
	JudgeUnavailable bool
	// SecretWithheld is true when the engine's secret gate kept the text
	// from a remote judge (it carried a pattern-certain secret), so the
	// judged criteria were not evaluated (fix round 2, N4).
	SecretWithheld bool
}

// Action is the seam's resulting action.
type Action string

// The closed action vocabulary.
const (
	ActionAllow Action = "allow"
	ActionFlag  Action = "flag"
	ActionBlock Action = "block"
)

// Basis is why an outcome is what it is (the audit criterion when the policy
// named none).
type Basis string

// The closed basis vocabulary.
const (
	BasisAllow            Basis = "allow"
	BasisFlag             Basis = "flag"
	BasisAsk              Basis = "ask"
	BasisDeny             Basis = "deny"
	BasisJudgeUnavailable Basis = "judge_unavailable"
	// BasisEngineMissing: a policy applies but this build has no admission
	// engine to evaluate it.
	BasisEngineMissing Basis = "engine_missing"
	// BasisUnknownShape: the request's wire shape is unknown (an upstream
	// kind the shape table does not name), so nothing could be classified.
	BasisUnknownShape Basis = "unknown_wire_shape"
	// BasisSecretGate: the secret gate kept the prompt from the remote judge
	// and a strict enforce policy refuses a prompt it could not judge.
	BasisSecretGate Basis = "secret_gate"
)

// Outcome is the seam's decision for one request.
type Outcome struct {
	Action    Action
	Basis     Basis
	Reason    string
	Criterion string
}

// Allowed reports whether the request is forwarded.
func (o Outcome) Allowed() bool { return o.Action != ActionBlock }

// decideIn is the decision table's input: the policy's mode and strict
// flag, and the engine's verdict.
type decideIn struct {
	enforce bool
	strict  bool
	r       EngineResult
}

// decideRow is one row of the decision table.
type decideRow struct {
	// match reports whether the row applies.
	match func(decideIn) bool
	// action and basis are the outcome.
	action Action
	basis  Basis
	// prefix is prepended to the engine's reason.
	prefix string
}

// decideTable is walked top-down; the first matching row wins.
//
// A judge that could not answer is first, and only the policy's strict flag
// turns it into a refusal: strict fails closed under enforce (flagged under
// observe); a non-strict policy admits and flags the engine's fail-open
// allow. A non-strict failure that still carries an ask or deny is a REAL
// verdict (a deterministic layer or another chunk decided it), so it falls
// through to the ordinary rows and is never labelled "judge unavailable"
// (fix round 1, F6).
var decideTable = []decideRow{
	{match: judgeFailedStrictEnforce, action: ActionBlock, basis: BasisJudgeUnavailable, prefix: "judge unavailable (strict): "},
	{match: judgeFailedStrictObserve, action: ActionFlag, basis: BasisJudgeUnavailable, prefix: "judge unavailable (strict, observe): "},
	{match: judgeFailedOpen, action: ActionFlag, basis: BasisJudgeUnavailable, prefix: "judge unavailable, not enforced: "},
	// The secret gate withheld the prompt from the judge, so the judged
	// criteria were never evaluated: a strict enforce policy refuses it
	// (the reason names the gate, never the secret); otherwise the engine's
	// own decision stands (flag by default). Fix round 2, N4.
	{match: secretWithheldStrictEnforce, action: ActionBlock, basis: BasisSecretGate, prefix: secretGateRefusal},
	{match: verdict(policyfamadmission.DecisionDeny, true), action: ActionBlock, basis: BasisDeny},
	{match: verdict(policyfamadmission.DecisionDeny, false), action: ActionFlag, basis: BasisDeny},
	// An ask is never silently admitted: no prompt seam here can stop and ask
	// the developer, so under enforce it is a refusal with the reason, and
	// under observe a flag.
	{match: verdict(policyfamadmission.DecisionAsk, true), action: ActionBlock, basis: BasisAsk, prefix: "needs review, refused because this seam cannot ask: "},
	{match: verdict(policyfamadmission.DecisionAsk, false), action: ActionFlag, basis: BasisAsk},
	{match: flagged, action: ActionFlag, basis: BasisFlag},
	{match: always, action: ActionAllow, basis: BasisAllow},
}

func judgeFailedStrictEnforce(in decideIn) bool {
	return in.r.JudgeUnavailable && in.strict && in.enforce
}

func judgeFailedStrictObserve(in decideIn) bool {
	return in.r.JudgeUnavailable && in.strict && !in.enforce
}

func judgeFailedOpen(in decideIn) bool {
	return in.r.JudgeUnavailable && !in.strict && in.r.Decision < policyfamadmission.DecisionAsk
}

// secretGateRefusal is the reason for a secret-gate refusal. It names the
// gate, never the secret.
const secretGateRefusal = "the prompt contains a detected secret, so the secret gate kept it from the remote judge, and this strict policy refuses a prompt it could not judge"

func secretWithheldStrictEnforce(in decideIn) bool {
	return in.r.SecretWithheld && in.strict && in.enforce && in.r.Decision < policyfamadmission.DecisionDeny
}

func verdict(d policyfamadmission.Decision, enforce bool) func(decideIn) bool {
	return func(in decideIn) bool { return in.enforce == enforce && in.r.Decision == d }
}

func flagged(in decideIn) bool { return in.r.Decision == policyfamadmission.DecisionFlag }

func always(decideIn) bool { return true }

// Decide maps the engine's verdict onto the seam's outcome under the
// policy's mode (enforce true, else observe) and strict flag.
func Decide(enforce, strict bool, r EngineResult) Outcome {
	in := decideIn{enforce: enforce, strict: strict, r: r}
	for _, row := range decideTable {
		if !row.match(in) {
			continue
		}
		o := Outcome{Action: row.action, Basis: row.basis, Criterion: r.Criterion}
		if row.action != ActionAllow {
			o.Reason = row.prefix + r.Reason
			if row.basis == BasisSecretGate {
				o.Reason = row.prefix
			}
			if o.Criterion == "" || row.basis == BasisJudgeUnavailable || row.basis == BasisSecretGate {
				o.Criterion = string(row.basis)
			}
		}
		return o
	}
	return Outcome{Action: ActionAllow, Basis: BasisAllow}
}

// EngineMissing is the outcome when a policy applies to a request but the
// build has no admission engine to evaluate it (fix round 1, F7). It is never
// a silent admit: strict under enforce refuses, anything else admits and
// flags. Unlike a judge failure it is a fixed property of the build, so it is
// cached (and audited once per prompt) like a verdict.
func EngineMissing(enforce, strict bool) Outcome {
	return NotEvaluated(BasisEngineMissing, "this build has no admission engine, the prompt was not evaluated", enforce, strict)
}

// UnknownShape is the outcome when the request's wire shape is unknown, so the
// prompt could not even be found (fix round 2, N3): never a silent admit.
func UnknownShape(enforce, strict bool) Outcome {
	return NotEvaluated(BasisUnknownShape, "the request's wire shape is not known to the admission classifier, the prompt was not evaluated", enforce, strict)
}

// NotEvaluated is the one rule for a request a policy applies to but that
// could not be evaluated: strict under enforce refuses (the reason names the
// cause), anything else admits and flags.
func NotEvaluated(basis Basis, reason string, enforce, strict bool) Outcome {
	if enforce && strict {
		return Outcome{Action: ActionBlock, Basis: basis, Criterion: string(basis), Reason: string(basis) + " (strict): " + reason}
	}
	return Outcome{Action: ActionFlag, Basis: basis, Criterion: string(basis), Reason: reason}
}

// Digest is the content-free fingerprint of judged text (sha256 hex). It is
// the cache key's text half and the only form of the text an audit row
// carries.
func Digest(text string) string {
	sum := sha256.Sum256([]byte(text))
	return hex.EncodeToString(sum[:])
}

// DefaultCacheTTL is how long a verdict is reused.
const DefaultCacheTTL = 10 * time.Minute

// DefaultNegativeTTL is how long a judge-unavailable outcome is reused (fix
// round 2, N1). Short on purpose: long enough that a relay outage costs one
// judge budget and one audit row per prompt per window instead of one per
// model call of a tool loop, short enough that a recovered judge is asked
// again within a minute.
const DefaultNegativeTTL = 45 * time.Second

// DefaultMaxAge bounds how long Refresh can keep a verdict alive after it was
// judged (fix round 2, N1): a tool loop in use keeps its opening prompt's
// verdict, so it is neither re-judged every DefaultCacheTTL nor refused
// mid-loop by a second, different answer, but a policy-version change still
// re-judges at once and a very long loop is re-judged after this age.
const DefaultMaxAge = 2 * time.Hour

// DefaultCacheEntries bounds the cache.
const DefaultCacheEntries = 4096

// Cache is a bounded, TTL, least-recently-used verdict cache. The zero value
// is not usable; build one with NewCache. Safe for concurrent use.
type Cache struct {
	mu      sync.Mutex
	ttl     time.Duration
	negTTL  time.Duration
	maxAge  time.Duration
	max     int
	now     func() time.Time
	order   *list.List
	entries map[string]*list.Element
}

type cacheEntry struct {
	key     string
	outcome Outcome
	expires time.Time
	// created is when this outcome was judged (a changed outcome resets it);
	// Refresh never extends an entry past created + maxAge.
	created time.Time
	// audited is set by MarkAudited: the entry's verdict has been recorded.
	audited bool
}

// NewCache builds a cache. ttl <= 0 or max <= 0 use the defaults; now nil is
// time.Now.
func NewCache(ttl time.Duration, max int, now func() time.Time) *Cache {
	if ttl <= 0 {
		ttl = DefaultCacheTTL
	}
	if max <= 0 {
		max = DefaultCacheEntries
	}
	if now == nil {
		now = time.Now
	}
	return &Cache{ttl: ttl, negTTL: DefaultNegativeTTL, maxAge: DefaultMaxAge, max: max, now: now, order: list.New(), entries: make(map[string]*list.Element)}
}

// CacheKey joins the policy identity (its version or body hash, and its
// scope) with the judged text's digest. A new policy version never reuses an
// older version's verdict.
func CacheKey(policy string, scope Scope, digest string) string {
	return policy + "|" + string(scope) + "|" + digest
}

// Get returns a live cached outcome.
func (c *Cache) Get(key string) (Outcome, bool) {
	if c == nil {
		return Outcome{}, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	el, ok := c.entries[key]
	if !ok {
		return Outcome{}, false
	}
	e := el.Value.(*cacheEntry) //nolint:forcetypeassert // the list only ever holds *cacheEntry
	if !c.now().Before(e.expires) {
		c.order.Remove(el)
		delete(c.entries, key)
		return Outcome{}, false
	}
	c.order.MoveToFront(el)
	return e.outcome, true
}

// Put stores an outcome. A judge-unavailable outcome lives only
// DefaultNegativeTTL (fix round 2, N1: before, it was never stored, so during
// a relay outage every model call of a tool loop waited the full judge
// budget and wrote its own audit row); every other outcome lives the TTL.
func (c *Cache) Put(key string, o Outcome) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	exp := now.Add(c.ttl)
	if o.Basis == BasisJudgeUnavailable {
		exp = now.Add(c.negTTL)
	}
	if el, ok := c.entries[key]; ok {
		e := el.Value.(*cacheEntry) //nolint:forcetypeassert // the list only ever holds *cacheEntry
		if e.outcome != o {
			e.audited = false
			e.created = now
		}
		e.outcome, e.expires = o, exp
		c.order.MoveToFront(el)
		return
	}
	c.entries[key] = c.order.PushFront(&cacheEntry{key: key, outcome: o, expires: exp, created: now})
	for c.order.Len() > c.max {
		last := c.order.Back()
		c.order.Remove(last)
		delete(c.entries, last.Value.(*cacheEntry).key) //nolint:forcetypeassert // the list only ever holds *cacheEntry
	}
}

// Refresh extends a live verdict's life by the TTL from now, never past the
// time it was judged plus DefaultMaxAge, and reports whether it did. A seam
// calls it when a tool-loop continuation hits the verdict of the prompt that
// opened the loop, so a loop in use keeps one answer. A judge-unavailable
// entry is never refreshed (the judge is asked again once its short window
// ends).
func (c *Cache) Refresh(key string) bool {
	if c == nil {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	el, ok := c.entries[key]
	if !ok {
		return false
	}
	e := el.Value.(*cacheEntry) //nolint:forcetypeassert // the list only ever holds *cacheEntry
	now := c.now()
	if !now.Before(e.expires) || e.outcome.Basis == BasisJudgeUnavailable {
		return false
	}
	exp := now.Add(c.ttl)
	if limit := e.created.Add(c.maxAge); exp.After(limit) {
		exp = limit
	}
	if !exp.After(e.expires) {
		return false
	}
	e.expires = exp
	c.order.MoveToFront(el)
	return true
}

// MarkAudited reports whether the caller should record the audit row for the
// live entry at key, and marks it recorded: true exactly once per entry life
// (a Put of a new outcome starts a new life), false for an absent or expired
// entry. A seam calls it for every non-allow cached outcome, so a repeated
// prompt is recorded once per cache life, not once per request (fix round 1,
// F6).
func (c *Cache) MarkAudited(key string) bool {
	if c == nil {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	el, ok := c.entries[key]
	if !ok {
		return false
	}
	e := el.Value.(*cacheEntry) //nolint:forcetypeassert // the list only ever holds *cacheEntry
	if !c.now().Before(e.expires) || e.audited {
		return false
	}
	e.audited = true
	return true
}

// Len reports the number of entries (expired ones included until touched).
func (c *Cache) Len() int {
	if c == nil {
		return 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.order.Len()
}
