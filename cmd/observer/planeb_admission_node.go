package main

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/marmutapp/superbased-observer/internal/guard"
	"github.com/marmutapp/superbased-observer/internal/orgclient"
	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/policyfam"
	policyfamadmission "github.com/marmutapp/superbased-observer/internal/policyfam/admission"
	"github.com/marmutapp/superbased-observer/internal/policyfam/planebadmission"
	"github.com/marmutapp/superbased-observer/internal/promptadmit"
	"github.com/marmutapp/superbased-observer/internal/promptturn"
)

// planeb_admission_node.go is the NODE half of the Plane-B coding-agent
// prompt admission judge (P-228, docs/guard.md "Org prompt admission judge"):
// the daemon consumes the signed planeb.admission family and, ONLY on a
// managed node holding the enforce.admission authority whose body sets
// node_lane, judges the developer's prompts in the proxy's prompt phase.
//
// What it never does:
//
//   - run on an individual node. managedEnforceFor is false on the
//     individual plane, and the lane is then not even run in observe mode,
//     because observing would send prompt text off the node. Nothing remote
//     can turn it on there.
//   - use the node's own [observability] judge, or the Plane A OpenRouter
//     default in obs_wire.go. The only judge route is the org's: the C1
//     relay under the coding_admission purpose, which the org server
//     dispatches to its coding_admission_judge provider.
//   - write a new table. Each non-allow verdict is one guard_events row
//     (store.PersistGuardVerdicts, the guard's one writer) carrying a
//     content-free reason and the prompt's digest, never the prompt; it
//     reaches the org on the existing guard events push.
//
// This file links in every build. The engine (internal/obs/admission) and
// the breaker-wrapped relay judge are bound by obs_wire.go's init in builds
// that link Plane A obs; without them the lane stays off and the node never
// advertises planebadmission.NodeJudgeCapability, so the org server's
// capability gate NACKs a node-lane body this build cannot honour.

// codingAdmissionEngine runs the shared admission engine over one text. Set
// by obs_wire.go's init; nil in a build without obs.
var codingAdmissionEngine func(ctx context.Context, text string, spec policyfamadmission.PolicySpec, judge func(context.Context, string) (string, error)) promptadmit.EngineResult

// codingAdmissionRelayJudge builds the breaker-wrapped C1 relay judge for the
// coding_admission purpose. Set by obs_wire.go's init; nil without obs.
var codingAdmissionRelayJudge func(relay orgJudgeRelayFunc) func(context.Context, string) (string, error)

// planeBPromptJudgeRuleID is the guard_events rule id of an org prompt judge
// verdict. It is not a catalog rule: the org's signed planeb.admission body is
// the policy, and its criterion id rides the row's reason.
const planeBPromptJudgeRuleID = guard.OrgPromptJudgeRuleID

// planeBPromptJudgeCategory is the guard_events category of those rows.
const planeBPromptJudgeCategory = "admission"

// nodeLaneRelayDefaultBudget is the judge budget when the body set no
// latency_budget_ms (planebadmission.NodeLaneRelayDefaultBudgetMS, the one
// owner the org admin's simulate reads too).
const nodeLaneRelayDefaultBudget = planebadmission.NodeLaneRelayDefaultBudgetMS * time.Millisecond

// nodeLaneJudgeBudget is the node lane's judge budget
// (planebadmission.NodeLaneJudgeBudget).
func nodeLaneJudgeBudget(spec planebadmission.PolicySpec) time.Duration {
	return planebadmission.NodeLaneJudgeBudget(spec)
}

// managedRecheckTTL bounds how stale the managed + enforce.admission answer
// can be on the request path (a grant revocation turns the lane off within
// this window).
const managedRecheckTTL = 15 * time.Second

// planeBNodePolicy is the installed, verified planeb.admission body.
type planeBNodePolicy struct {
	spec           planebadmission.PolicySpec
	version        int64
	bodyHash       string
	enforceAllowed bool
}

// planeBNodeLane is the daemon-lifetime owner of the node lane's state: the
// installed policy (written by the policy-resource publish path), the judge
// and the audit writer (bound by buildProxy). One owner, two feed paths.
type planeBNodeLane struct {
	mu        sync.Mutex
	policy    *planeBNodePolicy
	ngov      *nodeGovernanceHandle
	judge     func(context.Context, string) (string, error)
	persist   func(context.Context, []guard.ActionVerdict) error
	logger    *slog.Logger
	cache     *promptadmit.Cache
	now       func() time.Time
	engine    func(ctx context.Context, text string, spec policyfamadmission.PolicySpec, judge func(context.Context, string) (string, error)) promptadmit.EngineResult
	managedFn func() bool
	// hookVerdicts is the hook lane's last verdict per session (adm-2),
	// read by the proxy lane so one prompt is judged once.
	hookVerdicts map[string]hookVerdict
	managed      bool
	managedAt    time.Time
	warned       bool
}

// processPlaneBLane is the daemon's one lane. It exists from process start so
// a policy published (LKG or poller) before the proxy is built is kept.
var processPlaneBLane = newPlaneBNodeLane()

func newPlaneBNodeLane() *planeBNodeLane {
	l := &planeBNodeLane{now: time.Now}
	l.cache = promptadmit.NewCache(0, 0, func() time.Time { return l.now() })
	return l
}

// configure binds the judge route and the audit writer (buildProxy). relay nil
// (not enrolled, or org push off) leaves the judge unbound, so judged
// criteria degrade and the capability is not advertised.
func (l *planeBNodeLane) configure(relay orgJudgeRelayFunc, persist func(context.Context, []guard.ActionVerdict) error, logger *slog.Logger) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.engine = codingAdmissionEngine
	l.judge = nil
	if relay != nil && codingAdmissionRelayJudge != nil {
		l.judge = codingAdmissionRelayJudge(relay)
	}
	l.persist = persist
	l.logger = logger
}

// judgeAvailable reports whether this node can run the node lane's judge:
// the engine is linked and the org relay is bound. It is what the
// planeb_judge capability token advertises.
func (l *planeBNodeLane) judgeAvailable() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.engine != nil && l.judge != nil
}

// engineAvailable reports whether the lane has the admission engine bound
// (the build links it and buildProxy configured the lane).
func (l *planeBNodeLane) engineAvailable() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.engine != nil
}

// planeBNodeLiveCapabilities is the node lane's capability token list:
// planeb_engine when the engine is bound, plus planeb_judge when the org
// relay judge is bound too. A build without the engine advertises neither,
// so a judged or strict node_lane body NACKs capability_mismatch through the
// ordinary accept path (fix round 2, N5).
func planeBNodeLiveCapabilities() []string {
	return processPlaneBLane.liveCapabilities()
}

func (l *planeBNodeLane) liveCapabilities() []string {
	var caps []string
	if l.engineAvailable() {
		caps = append(caps, planebadmission.NodeEngineCapability)
	}
	if l.judgeAvailable() {
		caps = append(caps, planebadmission.NodeJudgeCapability)
	}
	return caps
}

// publish installs a verified planeb.admission result.
func (l *planeBNodeLane) publish(res orgclient.PolicyResourceResult, ngov *nodeGovernanceHandle) {
	spec, ok := res.Spec.(planebadmission.PolicySpec)
	if !ok {
		return
	}
	l.mu.Lock()
	l.policy = &planeBNodePolicy{spec: spec, version: res.Version, bodyHash: res.BodyHash, enforceAllowed: res.EnforceAllowed}
	l.ngov = ngov
	l.managedAt = time.Time{}
	logger := l.logger
	l.mu.Unlock()
	if logger != nil {
		logger.Info("policy resource: planeb.admission installed",
			"version", res.Version, "node_lane", spec.NodeLane, "scope", spec.Scope,
			"mode", spec.Admission.Mode.String(), "inert_reason", res.InertReason)
	}
}

// clear removes the installed policy (a signed withdrawal).
func (l *planeBNodeLane) clear() {
	l.mu.Lock()
	l.policy = nil
	l.mu.Unlock()
}

// planeBAdmissionPublish is the planeb.admission hook publishPolicyResourceResult
// calls.
func planeBAdmissionPublish(res orgclient.PolicyResourceResult, ngov *nodeGovernanceHandle) {
	processPlaneBLane.publish(res, ngov)
}

// planeBAdmissionClear is the planeb.admission hook clearOrgLayer calls.
func planeBAdmissionClear() { processPlaneBLane.clear() }

// managedNow answers managed + enforce.admission, memoized for
// managedRecheckTTL.
func (l *planeBNodeLane) managedNow() bool {
	l.mu.Lock()
	if !l.managedAt.IsZero() && l.now().Sub(l.managedAt) < managedRecheckTTL {
		m := l.managed
		l.mu.Unlock()
		return m
	}
	fn, ngov := l.managedFn, l.ngov
	l.mu.Unlock()
	var m bool
	if fn != nil {
		m = fn()
	} else {
		m = managedEnforceFor(ngov, policyfam.FamilyPlaneBAdmission)
	}
	l.mu.Lock()
	l.managed, l.managedAt = m, l.now()
	l.mu.Unlock()
	return m
}

// active reports whether an installed policy could judge anything: a body
// with node_lane whose mode is not off. Cheap (one lock, no governance read),
// so the proxy can ask it on every request.
func (l *planeBNodeLane) active() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.policy != nil && l.policy.spec.NodeLane && l.policy.spec.Admission.Mode != policyfamadmission.ModeOff
}

// planeBPromptInput is the lane's plain input (the proxy adapter maps
// proxy.PromptAdmitInput onto it, so this file needs no proxy import).
type planeBPromptInput struct {
	Provider  string
	Body      []byte
	SessionID string
	Tool      string
	// Lane is the seam ("proxy" or "hook") for the audit row.
	Lane string
}

// admit judges one request. It never errors: every failure is the policy's
// strict flag, through promptadmit.
func (l *planeBNodeLane) admit(ctx context.Context, in planeBPromptInput) promptadmit.Outcome {
	allow := promptadmit.Outcome{Action: promptadmit.ActionAllow, Basis: promptadmit.BasisAllow}
	g, ok := l.gate()
	if !ok {
		return allow
	}
	if in.Lane == "" {
		in.Lane = planeBLaneProxy
	}
	shape := promptturn.ShapeFor(in.Provider, in.Body)
	if shape == promptturn.ShapeUnknown {
		// A provider lane whose wire shape the classifier does not know: the
		// prompt cannot be found, so it is never admitted silently (fix
		// round 2, N3), and it is recorded once per window per lane (adm-2,
		// L2).
		o := promptadmit.UnknownShape(g.enforce, g.pol.spec.Admission.Strict)
		l.recordOnce(g, in, "unknown_shape:"+in.Provider, o)
		return o
	}
	turn := promptturn.Classify(shape, in.Body)
	if hv, key, siblings, reused := l.hookVerdictFor(g, in.SessionID, turn); reused {
		// The hook lane already judged this prompt for this session (adm-2):
		// its verdict stands for the matched block only. Any other block of
		// the turn (an attachment, a reminder, an @file part) is judged here
		// through the same secret gate, cache and judge, and the turn takes
		// the stricter of the two (adm-2 fixes-2, N1). The turn's verdict is
		// cached under the proxy's own key so the loop's continuations hit
		// it, and never recorded a second time.
		o := hv
		if siblings != "" {
			o = stricterOutcome(hv, l.decide(ctx, g, in, promptadmit.Plan{Judge: true, Text: siblings}))
		}
		l.cache.Put(key, o)
		l.cache.MarkAudited(key)
		return o
	}
	return l.decide(ctx, g, in, promptadmit.PlanTurn(g.pol.spec.Scope, turn))
}

// planeBLaneProxy / planeBLaneHook name the seam a verdict came from on its
// audit row.
const (
	planeBLaneProxy = "proxy"
	planeBLaneHook  = "hook"
)

// planeBGate is the installed policy as one judgement sees it.
type planeBGate struct {
	pol     *planeBNodePolicy
	engine  func(ctx context.Context, text string, spec policyfamadmission.PolicySpec, judge func(context.Context, string) (string, error)) promptadmit.EngineResult
	judge   func(context.Context, string) (string, error)
	logger  *slog.Logger
	enforce bool
	polKey  string
}

// gate reports whether the lane runs for this request: a node_lane policy
// whose mode is not off, on a managed node holding enforce.admission. An
// individual node is off entirely (not even observe, which would send prompt
// text off the node).
func (l *planeBNodeLane) gate() (planeBGate, bool) {
	l.mu.Lock()
	g := planeBGate{pol: l.policy, engine: l.engine, judge: l.judge, logger: l.logger}
	l.mu.Unlock()
	if g.pol == nil || !g.pol.spec.NodeLane || g.pol.spec.Admission.Mode == policyfamadmission.ModeOff {
		return g, false
	}
	if !l.managedNow() {
		return g, false
	}
	g.enforce = planebadmission.Enforces(g.pol.spec) && g.pol.enforceAllowed
	g.polKey = fmt.Sprintf("v%d:%s:enforce=%t", g.pol.version, g.pol.bodyHash, g.enforce)
	return g, true
}

// decide runs one planned judgement through the ONE verdict cache, engine and
// audit seam both lanes share.
func (l *planeBNodeLane) decide(ctx context.Context, g planeBGate, in planeBPromptInput, plan promptadmit.Plan) promptadmit.Outcome {
	if !plan.Judge {
		return promptadmit.Outcome{Action: promptadmit.ActionAllow, Basis: promptadmit.BasisAllow}
	}
	digest := promptadmit.Digest(plan.Text)
	key := promptadmit.CacheKey(g.polKey, g.pol.spec.Scope, digest)
	o, cached := l.cache.Get(key)
	switch {
	case cached:
		if plan.Continuation {
			// A loop in use keeps the verdict of the prompt that opened it
			// (fix round 2, N1): no re-judge every TTL, no second answer
			// mid-loop, bounded by the cache's maximum age.
			l.cache.Refresh(key)
		}
	case g.engine == nil:
		// A build without the admission engine never admits silently (fix
		// round 1, F7): strict under enforce refuses, anything else flags,
		// and `observer guard status` says the engine is missing.
		l.warnOnce(g.logger, "planeb admission: a node-lane policy is installed but this build has no admission engine - prompts are flagged (refused under a strict enforce policy), not evaluated")
		o = promptadmit.EngineMissing(g.enforce, g.pol.spec.Admission.Strict)
		l.cache.Put(key, o)
	default:
		var j func(context.Context, string) (string, error)
		if planebadmission.RequiresJudge(g.pol.spec) {
			j = g.judge // nil when no relay: the engine reports the judge unavailable
		}
		evalCtx, cancel := context.WithTimeout(ctx, nodeLaneJudgeBudget(g.pol.spec))
		res := g.engine(evalCtx, plan.Text, g.pol.spec.Admission, j)
		cancel()
		o = promptadmit.Decide(g.enforce, g.pol.spec.Admission.Strict, res)
		l.cache.Put(key, o)
	}
	// One audit row per cached verdict, not per request (fix round 1, F6). A
	// judge-unavailable outcome is cached for a short window too (fix round
	// 2, N1), so an outage writes one row per prompt per window.
	if o.Action != promptadmit.ActionAllow && l.cache.MarkAudited(key) {
		l.audit(in, g.pol, digest, o)
	}
	return o
}

// recordOnce caches an outcome that needed no engine (an unknown shape, an
// oversize prompt) under a key of its own and audits it once per cache life.
func (l *planeBNodeLane) recordOnce(g planeBGate, in planeBPromptInput, what string, o promptadmit.Outcome) {
	key := promptadmit.CacheKey(g.polKey, g.pol.spec.Scope, promptadmit.Digest(in.Lane+"|"+in.SessionID+"|"+what))
	if _, ok := l.cache.Get(key); !ok {
		l.cache.Put(key, o)
	}
	if o.Action != promptadmit.ActionAllow && l.cache.MarkAudited(key) {
		l.audit(in, g.pol, promptadmit.Digest(what), o)
	}
}

// basisPromptTooLarge is the not-evaluated basis of a hook prompt over the
// ask channel's size cap.
const basisPromptTooLarge promptadmit.Basis = "prompt_too_large"

// admitHook judges a prompt a prompt-gate hook typed into ANY tool (adm-2):
// the same gate, cache, engine, secret gate and audit seam as the proxy lane.
// The hook only fires on a typed prompt, so the turn is a user prompt (under
// all_calls too: the hook never sees tool results; the proxy lane covers
// them for proxy-routed tools). active=false means no policy applies here.
func (l *planeBNodeLane) admitHook(ctx context.Context, in planeBPromptInput, prompt string, oversize bool) (promptadmit.Outcome, bool) {
	g, ok := l.gate()
	if !ok {
		return promptadmit.Outcome{Action: promptadmit.ActionAllow, Basis: promptadmit.BasisAllow}, false
	}
	in.Lane = planeBLaneHook
	if oversize {
		o := promptadmit.NotEvaluated(basisPromptTooLarge, "the prompt is over the hook's size cap for the organization's judge, so it was not evaluated", g.enforce, g.pol.spec.Admission.Strict)
		l.recordOnce(g, in, "oversize", o)
		return o, true
	}
	turn := promptturn.Turn{Kind: promptturn.KindUserPrompt, Text: prompt, Trailing: prompt}
	o := l.decide(ctx, g, in, promptadmit.PlanTurn(g.pol.spec.Scope, turn))
	l.rememberHookVerdict(g, in.SessionID, prompt, o)
	return o, true
}

// actionRank orders the turn's actions by strictness.
var actionRank = map[promptadmit.Action]int{
	promptadmit.ActionAllow: 0,
	promptadmit.ActionFlag:  1,
	promptadmit.ActionBlock: 2,
}

// stricterOutcome is the turn's verdict from two judged parts: the stricter
// action wins, and on a tie the first (the hook's verdict) stands.
func stricterOutcome(a, b promptadmit.Outcome) promptadmit.Outcome {
	if actionRank[b.Action] > actionRank[a.Action] {
		return b
	}
	return a
}

// definitiveHookBases are the outcomes a hook verdict may stand in for the
// proxy lane with (adm-2 fixes-2, N2): a judgement the engine actually made.
// A judge that could not answer within the hook's shorter budget, a missing
// engine, a withheld secret or an oversize prompt is not remembered, so the
// proxy lane judges with its own budget.
var definitiveHookBases = map[promptadmit.Basis]bool{
	promptadmit.BasisAllow: true,
	promptadmit.BasisFlag:  true,
	promptadmit.BasisAsk:   true,
	promptadmit.BasisDeny:  true,
}

// hookVerdictWindow is how long a hook verdict stands in for the proxy lane's
// judgement of the same prompt in the same session.
const hookVerdictWindow = 10 * time.Minute

// maxHookVerdicts bounds the per-session record (one entry per session, a
// few hundred bytes each: digests, never prompt text or a raw session id).
const maxHookVerdicts = 1024

// hookVerdict is the hook lane's last verdict for one session. It holds the
// prompt's DIGEST only (adm-2 fixes-1, M1), never the prompt.
type hookVerdict struct {
	digest  string
	polKey  string
	outcome promptadmit.Outcome
	at      time.Time
}

// hookPromptDigest is the digest a hook prompt and a proxy text block are
// compared by: the trimmed text, so the client's surrounding whitespace does
// not defeat equality.
func hookPromptDigest(text string) string {
	return promptadmit.Digest(strings.TrimSpace(text))
}

// hookSessionKey is the map key for a session: a digest, so a caller of the
// local endpoint cannot grow the map with long ids.
func hookSessionKey(sessionID string) string {
	return promptadmit.Digest("hook-session|" + sessionID)
}

// rememberHookVerdict records the hook's verdict for a session so the proxy
// lane does not judge the same prompt again. In memory only, never persisted.
func (l *planeBNodeLane) rememberHookVerdict(g planeBGate, sessionID, prompt string, o promptadmit.Outcome) {
	if sessionID == "" || strings.TrimSpace(prompt) == "" || !definitiveHookBases[o.Basis] {
		return
	}
	now := l.now()
	hv := hookVerdict{digest: hookPromptDigest(prompt), polKey: g.polKey, outcome: o, at: now}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.hookVerdicts == nil {
		l.hookVerdicts = make(map[string]hookVerdict)
	}
	if len(l.hookVerdicts) >= maxHookVerdicts {
		for k, v := range l.hookVerdicts {
			if now.Sub(v.at) >= hookVerdictWindow {
				delete(l.hookVerdicts, k)
			}
		}
		if len(l.hookVerdicts) >= maxHookVerdicts {
			l.hookVerdicts = make(map[string]hookVerdict)
		}
	}
	l.hookVerdicts[hookSessionKey(sessionID)] = hv
}

// hookVerdictFor returns the hook lane's verdict when the proxy request is
// the same prompt in the same session (adm-2 fixes-1, H1). The rule, all of
// which must hold:
//
//   - the scope is user_prompts: under all_calls the proxy judges the
//     trailing segment (tool results included), which the hook never saw, so
//     a hook verdict never stands in for it;
//   - the request is a fresh user prompt (a continuation is answered by the
//     verdict cache under the opening prompt's own key);
//   - ONE text block of that user turn has exactly the hook prompt's digest
//     (equality, never a substring: a later prompt that merely contains an
//     earlier allowed one is judged on its own);
//   - same policy key, within the window;
//
// and the entry is consumed on the match, so it answers one request. The
// verdict covers the matched block(s) only: siblings is every OTHER
// non-blank block of the turn, joined in turn order, which the caller judges
// on the node lane (adm-2 fixes-2, N1); "" when the turn holds nothing else.
// key is the proxy's own cache key for the whole turn, so a retry of the
// same request and the loop's continuations hit the verdict cache.
func (l *planeBNodeLane) hookVerdictFor(g planeBGate, sessionID string, turn promptturn.Turn) (o promptadmit.Outcome, key, siblings string, ok bool) {
	if sessionID == "" || g.pol.spec.Scope != promptadmit.ScopeUserPrompts || turn.Kind != promptturn.KindUserPrompt || len(turn.Blocks) == 0 {
		return promptadmit.Outcome{}, "", "", false
	}
	plan := promptadmit.PlanTurn(g.pol.spec.Scope, turn)
	if !plan.Judge {
		return promptadmit.Outcome{}, "", "", false
	}
	sk := hookSessionKey(sessionID)
	now := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()
	hv, found := l.hookVerdicts[sk]
	if !found || hv.polKey != g.polKey || now.Sub(hv.at) >= hookVerdictWindow {
		return promptadmit.Outcome{}, "", "", false
	}
	matched := false
	var rest []string
	for _, b := range turn.Blocks {
		if hookPromptDigest(b) == hv.digest {
			matched = true
			continue
		}
		rest = append(rest, b)
	}
	if !matched {
		return promptadmit.Outcome{}, "", "", false
	}
	delete(l.hookVerdicts, sk)
	return hv.outcome, promptadmit.CacheKey(g.polKey, g.pol.spec.Scope, promptadmit.Digest(plan.Text)), strings.Join(rest, "\n"), true
}

// hookPosture is what the daemon signs into the guard posture for the hook
// lane: whether the judge is active here, and whether a hook that cannot
// reach the daemon must refuse (strict, in enforce mode, preauthorized).
func (l *planeBNodeLane) hookPosture() (active, failClosed bool) {
	g, ok := l.gate()
	if !ok {
		return false, false
	}
	return true, g.enforce && g.pol.spec.Admission.Strict
}

// audit records one non-allow verdict as a guard_events row, off the request
// path. The reason is content-free: the judge's own reason may quote the
// prompt, so it is shown to the developer in the refusal but never stored.
func (l *planeBNodeLane) audit(in planeBPromptInput, pol *planeBNodePolicy, digest string, o promptadmit.Outcome) {
	l.mu.Lock()
	persist, logger := l.persist, l.logger
	l.mu.Unlock()
	if persist == nil {
		return
	}
	v := planeBVerdictRow(in, pol, digest, o, l.now())
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := persist(ctx, []guard.ActionVerdict{v}); err != nil && logger != nil {
			logger.Warn("planeb admission: could not record the prompt judge verdict", "err", err)
		}
	}()
}

// planeBVerdictRow builds the guard_events row for one outcome.
func planeBVerdictRow(in planeBPromptInput, pol *planeBNodePolicy, digest string, o promptadmit.Outcome, now time.Time) guard.ActionVerdict {
	decision, severity := policy.DecisionFlag, policy.SeverityWarn
	if o.Action == promptadmit.ActionBlock {
		decision, severity = policy.DecisionDeny, policy.SeverityHigh
	}
	lane := in.Lane
	if lane == "" {
		lane = planeBLaneProxy
	}
	reason := fmt.Sprintf("org prompt judge: %s (criterion %s, scope %s, lane %s, policy v%d", o.Basis, o.Criterion, pol.spec.Scope, lane, pol.version)
	reason += ")"
	short := digest
	if len(short) > 16 {
		short = short[:16]
	}
	return guard.ActionVerdict{
		Input: guard.ActionInput{
			SessionID: in.SessionID,
			Tool:      in.Tool,
			Target:    "prompt sha256:" + short,
			Timestamp: now,
		},
		Kind:     policy.KindUserPrompt,
		Category: planeBPromptJudgeCategory,
		Verdict: policy.Verdict{
			Decision: decision,
			RuleID:   planeBPromptJudgeRuleID,
			Severity: severity,
			Reason:   reason,
			Source:   policy.SourceOrg,
		},
		Enforced: o.Action == promptadmit.ActionBlock,
	}
}

func (l *planeBNodeLane) warnOnce(logger *slog.Logger, msg string) {
	l.mu.Lock()
	first := !l.warned
	l.warned = true
	l.mu.Unlock()
	if first && logger != nil {
		logger.Warn(msg)
	}
}
