package guard

import (
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/policy"
)

// Bundle BUD-N guard tests: the publication seam for the organization's
// per-subject caps and the cross-machine baseline, and the stamping that
// actually puts them in front of a rule.

// TestApplyOrgBudgetSubjects_PublishesAndRebuilds pins that a published cap
// reaches the LIVE engine (not merely a field), that republishing the same
// values is a no-op, and that an empty publication withdraws them.
func TestApplyOrgBudgetSubjects_PublishesAndRebuilds(t *testing.T) {
	t.Parallel()
	cfg := guardCfg()
	cfg.Mode = "enforce"
	g := newTestGuard(t, cfg, nil)

	caps := []policy.BudgetSubjectCap{{
		Kind: policy.BudgetSubjectKindTool, ID: "claude-code",
		Window: policy.BudgetWindowDaily, CapUSD: 2, Hard: true,
	}}
	baseline := policy.BudgetWindowAmounts{DailyUSD: 1.5}
	if err := g.ApplyOrgBudgetSubjects(baseline, false, caps); err != nil {
		t.Fatalf("ApplyOrgBudgetSubjects: %v", err)
	}
	before := g.set.Load().revision
	if got := g.EffectiveBudgetSubjects(); len(got) != 1 || got[0].ID != "claude-code" {
		t.Fatalf("EffectiveBudgetSubjects = %+v", got)
	}
	if g.budgetBaseline() != baseline {
		t.Errorf("baseline = %+v, want %+v", g.budgetBaseline(), baseline)
	}
	// Idempotent: the push cycle calls this every cycle and must not churn the
	// engine (and therefore the project-engine cache) for unchanged values.
	if err := g.ApplyOrgBudgetSubjects(baseline, false, caps); err != nil {
		t.Fatalf("second apply: %v", err)
	}
	if g.set.Load().revision != before {
		t.Errorf("an unchanged publication rebuilt the engine")
	}
	// Withdrawal: an org that retires its subject caps leaves the node with
	// none, not with the last ones it ever saw.
	if err := g.ApplyOrgBudgetSubjects(policy.BudgetWindowAmounts{}, false, nil); err != nil {
		t.Fatalf("withdraw: %v", err)
	}
	if len(g.EffectiveBudgetSubjects()) != 0 || g.budgetBaseline() != (policy.BudgetWindowAmounts{}) {
		t.Errorf("withdrawal left state behind: %+v / %+v", g.EffectiveBudgetSubjects(), g.budgetBaseline())
	}
}

// TestApplyOrgBudgetSubjectsOnANilGuardIsANoOp: the wiring may hold a nil guard
// (guard off, or construction failed) and the push cycle must not panic.
func TestApplyOrgBudgetSubjectsOnANilGuardIsANoOp(t *testing.T) {
	t.Parallel()
	var g *Guard
	if err := g.ApplyOrgBudgetSubjects(policy.BudgetWindowAmounts{DailyUSD: 1}, false, []policy.BudgetSubjectCap{{ID: "x"}}); err != nil {
		t.Fatalf("nil guard: %v", err)
	}
	if got := g.EffectiveBudgetSubjects(); got != nil {
		t.Errorf("nil guard returned %+v", got)
	}
}

// TestStampBudget_SubjectUsageAndBaseline walks the stamping seam: the event
// gets ITS OWN tool's and model's slice of spend, plus the published baseline.
func TestStampBudget_SubjectUsageAndBaseline(t *testing.T) {
	t.Parallel()
	g := newTestGuard(t, guardCfg(), nil)
	g.SetBudgetLookup(func(string) (BudgetSnapshot, bool) {
		return BudgetSnapshot{
			DailyUSD: 9,
			ByTool: map[string]policy.BudgetWindowAmounts{
				"claude-code": {DailyUSD: 4},
				"codex":       {DailyUSD: 5},
			},
			ByModel: map[string]policy.BudgetWindowAmounts{
				"claude-sonnet": {DailyUSD: 4, DailyTokens: 700},
			},
			SessionTool:  "claude-code",
			SessionModel: "claude-sonnet",
		}, true
	})
	if err := g.ApplyOrgBudgetSubjects(policy.BudgetWindowAmounts{DailyUSD: 12}, false, nil); err != nil {
		t.Fatalf("ApplyOrgBudgetSubjects: %v", err)
	}

	// An event that NAMES its tool gets that tool's slice, whatever the
	// session's own evidence says.
	ev := policy.Event{Kind: policy.KindAPIRequest, SessionID: "s1", Tool: "Codex", Now: time.Now().UTC()}
	g.stampBudget(&ev)
	if ev.ToolUsage.DailyUSD != 5 {
		t.Errorf("ToolUsage.DailyUSD = %v, want codex's 5", ev.ToolUsage.DailyUSD)
	}
	if ev.OrgBaseline.DailyUSD != 12 {
		t.Errorf("OrgBaseline.DailyUSD = %v, want the published 12", ev.OrgBaseline.DailyUSD)
	}

	// An event that names NEITHER — the proxy admission lane — falls back to
	// the session's own unanimous evidence for both.
	bare := policy.Event{Kind: policy.KindAPIRequest, SessionID: "s1", Now: time.Now().UTC()}
	g.stampBudget(&bare)
	if bare.Tool != "claude-code" || bare.ToolUsage.DailyUSD != 4 {
		t.Errorf("session fallback: tool = %q usage = %v", bare.Tool, bare.ToolUsage.DailyUSD)
	}
	if bare.Model != "claude-sonnet" || bare.ModelUsage.DailyTokens != 700 {
		t.Errorf("session fallback: model = %q tokens = %d", bare.Model, bare.ModelUsage.DailyTokens)
	}
	// The node-wide stamps are untouched by any of it.
	if bare.DailyCostUSD != 9 {
		t.Errorf("DailyCostUSD = %v, want 9", bare.DailyCostUSD)
	}
}

// TestProxyBudgetScanDeniesOnASubjectCap walks the REAL proxy seam end to end:
// an organization per-tool cap refuses the request, and a session on an
// uncapped tool with the same spend is admitted.
func TestProxyBudgetScanDeniesOnASubjectCap(t *testing.T) {
	t.Parallel()
	cfg := guardCfg()
	cfg.Mode = "enforce"
	g := newTestGuard(t, cfg, nil)
	g.SetBudgetLookup(func(sessionID string) (BudgetSnapshot, bool) {
		usage := map[string]policy.BudgetWindowAmounts{"claude-code": {DailyUSD: 4}, "codex": {DailyUSD: 4}}
		switch sessionID {
		case "capped":
			return BudgetSnapshot{ByTool: usage, SessionTool: "claude-code"}, true
		default:
			return BudgetSnapshot{ByTool: usage, SessionTool: "codex"}, true
		}
	})
	if err := g.ApplyOrgBudgetSubjects(policy.BudgetWindowAmounts{}, false, []policy.BudgetSubjectCap{{
		Kind: policy.BudgetSubjectKindTool, ID: "claude-code",
		Window: policy.BudgetWindowDaily, CapUSD: 3, Hard: true,
	}}); err != nil {
		t.Fatalf("ApplyOrgBudgetSubjects: %v", err)
	}

	var denied ProxyRequestResult
	g.scanBudget(g.set.Load(), &denied, "capped", "api.anthropic.com", time.Now().UTC())
	if !denied.Deny || denied.DenyRuleID != "B-626" {
		t.Fatalf("capped tool: deny=%v rule=%q, want a B-626 denial", denied.Deny, denied.DenyRuleID)
	}

	var admitted ProxyRequestResult
	g.scanBudget(g.set.Load(), &admitted, "uncapped", "api.anthropic.com", time.Now().UTC())
	if admitted.Deny {
		t.Fatalf("an uncapped tool was denied by another tool's cap: %s", admitted.DenyReason)
	}
}

// TestProxyBudgetScanDeniesOnAModelCapFromTheRequestBody pins the one subject
// the proxy lane knows FIRST-HAND: the model is parsed out of the request body,
// so a per-model cap bites there without any session evidence at all.
func TestProxyBudgetScanDeniesOnAModelCapFromTheRequestBody(t *testing.T) {
	t.Parallel()
	cfg := guardCfg()
	cfg.Mode = "enforce"
	g := newTestGuard(t, cfg, nil)
	g.SetBudgetLookup(func(string) (BudgetSnapshot, bool) {
		return BudgetSnapshot{ByModel: map[string]policy.BudgetWindowAmounts{
			"claude-x": {MonthlyTokens: 900},
		}}, true
	})
	if err := g.ApplyOrgBudgetSubjects(policy.BudgetWindowAmounts{}, false, []policy.BudgetSubjectCap{{
		Kind: policy.BudgetSubjectKindModel, ID: "claude-x",
		Window: policy.BudgetWindowMonthly, CapTokens: 800, Hard: true,
	}}); err != nil {
		t.Fatalf("ApplyOrgBudgetSubjects: %v", err)
	}
	res := g.ScanProxyRequest("anthropic", []byte(`{"model":"claude-x","messages":[]}`), "s1", time.Now().UTC())
	if !res.Deny || res.DenyRuleID != "B-629" {
		t.Fatalf("deny=%v rule=%q, want a B-629 denial from the parsed model", res.Deny, res.DenyRuleID)
	}
}

// TestCheckInterventionBudget_CarriesTheSubject pins that the PROCESS-CONTROL
// pass evaluates subject caps too, keyed by the session's tool: a cap the org
// authored for one tool must be able to stop that tool's running process, not
// only refuse its proxied requests.
func TestCheckInterventionBudget_CarriesTheSubject(t *testing.T) {
	t.Parallel()
	cfg := guardCfg()
	cfg.Mode = "enforce"
	g := newTestGuard(t, cfg, nil)
	g.SetBudgetLookup(func(string) (BudgetSnapshot, bool) {
		return BudgetSnapshot{ByTool: map[string]policy.BudgetWindowAmounts{
			"claude-code": {DailyUSD: 6},
		}}, true
	})
	if err := g.ApplyOrgBudgetSubjects(policy.BudgetWindowAmounts{}, false, []policy.BudgetSubjectCap{{
		Kind: policy.BudgetSubjectKindTool, ID: "claude-code",
		Window: policy.BudgetWindowDaily, CapUSD: 5, Hard: true,
	}}); err != nil {
		t.Fatalf("ApplyOrgBudgetSubjects: %v", err)
	}
	// Protection is what authorizes an intervention; without it a managed hard
	// cap could deny a request but never stop a process.
	if err := g.ApplyOrgBudget(g.EffectiveBudget(), nil, false,
		policy.BudgetProtection{ToolUSD: true}, ""); err != nil {
		t.Fatalf("ApplyOrgBudget: %v", err)
	}
	decision := g.CheckInterventionBudget(InterventionBudgetInput{
		SessionID: "s1", Tool: "claude-code", SourceReady: true, Now: time.Now().UTC(),
	})
	if !decision.Required {
		t.Fatalf("decision.Required = false — a protected hard subject cap must require control")
	}
	if !decision.Deny || decision.RuleID != "B-626" {
		t.Fatalf("decision = %+v, want a B-626 denial", decision)
	}
}

// TestApplyOrgComposedBudget_IsOneRebuild is P2-6: the caps, the baseline, the
// numbers and the authority provenance come out of ONE composition and must
// reach the live engine in ONE publication. Two applies meant an intermediate
// engine holding new caps against old protection.
//
// Deliberately NOT t.Parallel(): the "exactly one rebuild" assertion below
// reads engineRevision, a package-global atomic.Uint64 (engineset.go) that
// every Guard in the process shares to stamp its own engineSet.revision. A
// sibling test's guard rebuilding between this test's before/after snapshots
// moves the shared counter too, so `g.set.Load().revision` can advance by
// more than 1 for THIS guard even though it rebuilt exactly once — that's
// what made this test flaky under -race with other parallel tests in the
// package (moved by 2, not a bug in ApplyOrgComposedBudget). Running serially
// makes the global-delta assertion trustworthy again.
func TestApplyOrgComposedBudget_IsOneRebuild(t *testing.T) {
	cfg := guardCfg()
	cfg.Mode = "enforce"
	g := newTestGuard(t, cfg, nil)

	caps := []policy.BudgetSubjectCap{{
		Kind: policy.BudgetSubjectKindTool, ID: "claude-code",
		Window: policy.BudgetWindowDaily, CapUSD: 2, Hard: true,
	}}
	baseline := policy.BudgetWindowAmounts{DailyUSD: 1.5}
	numbers := g.EffectiveBudget()
	numbers.DailyUSD = 20
	protection := policy.BudgetProtection{ToolUSD: true, DailyUSD: true}

	before := g.set.Load().revision
	p0 := g.set.Load()
	if err := g.ApplyOrgComposedBudget(numbers, nil, false, protection, "bind",
		BudgetDocumentWitness{Known: true}, baseline, true, caps); err != nil {
		t.Fatalf("ApplyOrgComposedBudget: %v", err)
	}
	// ONE rebuild, not two: the engineSet pointer swapped exactly once (a
	// second, intermediate publication would still leave p1 != p0 here, so
	// this alone doesn't prove "exactly one" — the revision delta below
	// does, and is trustworthy because this test is not t.Parallel()).
	p1 := g.set.Load()
	if p1 == p0 {
		t.Fatalf("engineSet pointer did not change — no rebuild published")
	}
	if got := p1.revision; got != before+1 {
		t.Errorf("revision moved by %d, want exactly 1 rebuild", got-before)
	}
	// Every half landed, together.
	if len(g.EffectiveBudgetSubjects()) != 1 || g.budgetBaseline() != baseline || !g.budgetBaselineFlagOnly() {
		t.Errorf("subject half not published: %+v / %+v / %v",
			g.EffectiveBudgetSubjects(), g.budgetBaseline(), g.budgetBaselineFlagOnly())
	}
	if g.EffectiveBudget().DailyUSD != 20 || g.budgetProtection() != protection || g.budgetBinding() != "bind" {
		t.Errorf("numeric half not published: %+v / %+v / %q",
			g.EffectiveBudget(), g.budgetProtection(), g.budgetBinding())
	}
	// Idempotent across BOTH halves: the push cycle calls this every cycle.
	steady := g.set.Load().revision
	if err := g.ApplyOrgComposedBudget(numbers, nil, false, protection, "bind",
		BudgetDocumentWitness{Known: true}, baseline, true, caps); err != nil {
		t.Fatalf("second apply: %v", err)
	}
	if g.set.Load().revision != steady {
		t.Errorf("an unchanged composition rebuilt the engine")
	}
	// A change in EITHER half republishes.
	if err := g.ApplyOrgComposedBudget(numbers, nil, false, protection, "bind",
		BudgetDocumentWitness{Known: true}, baseline, false, caps); err != nil {
		t.Fatalf("flag-only flip: %v", err)
	}
	if g.set.Load().revision == steady {
		t.Errorf("a changed baseline posture did not republish")
	}
	if g.budgetBaselineFlagOnly() {
		t.Errorf("baseline flag-only did not clear")
	}
}

// TestBudgetSubjectUnmatched is P1-3's reporting half: a composed cap whose id
// never appears in the accounting keys is an applied cap governing nothing, and
// the node must be able to say so.
func TestBudgetSubjectUnmatched(t *testing.T) {
	t.Parallel()
	cfg := guardCfg()
	cfg.Mode = "enforce"
	g := newTestGuard(t, cfg, nil)
	g.SetBudgetLookup(func(string) (BudgetSnapshot, bool) {
		return BudgetSnapshot{
			ByTool:  map[string]policy.BudgetWindowAmounts{"claude-code": {DailyUSD: 1}},
			ByModel: map[string]policy.BudgetWindowAmounts{"claude-sonnet-5": {DailyUSD: 1}},
		}, true
	})
	stamp := func() {
		ev := policy.Event{Kind: policy.KindAPIRequest, SessionID: "s1", Now: time.Now().UTC()}
		g.stampBudget(&ev)
	}

	// No caps: nothing can be unmatched.
	stamp()
	if g.BudgetSubjectUnmatched() {
		t.Errorf("unmatched with no caps published")
	}
	// A cap whose id IS a key.
	if err := g.ApplyOrgBudgetSubjects(policy.BudgetWindowAmounts{}, false, []policy.BudgetSubjectCap{{
		Kind: policy.BudgetSubjectKindTool, ID: "claude-code",
		Window: policy.BudgetWindowDaily, CapUSD: 5,
	}}); err != nil {
		t.Fatalf("apply: %v", err)
	}
	stamp()
	if g.BudgetSubjectUnmatched() {
		t.Errorf("a cap that matches an accounting key reported unmatched")
	}
	// A cap whose id is NOT a key — the dated spelling the resolver would have
	// folded, on a node whose price table never saw the model.
	if err := g.ApplyOrgBudgetSubjects(policy.BudgetWindowAmounts{}, false, []policy.BudgetSubjectCap{{
		Kind: policy.BudgetSubjectKindModel, ID: "claude-sonnet-5-20260501",
		Window: policy.BudgetWindowDaily, CapUSD: 5,
	}}); err != nil {
		t.Fatalf("apply: %v", err)
	}
	stamp()
	if !g.BudgetSubjectUnmatched() {
		t.Errorf("a cap whose id no accounting key carries reported as matched")
	}
}

// TestBudgetSubjectResolverStampsOneIdentity pins the stamp half of P1-3: the
// resolved id is what the usage lookup and the rule rows key on, while the raw
// Tool/Model stay exactly what ran.
func TestBudgetSubjectResolverStampsOneIdentity(t *testing.T) {
	t.Parallel()
	cfg := guardCfg()
	cfg.Mode = "enforce"
	g := newTestGuard(t, cfg, nil)
	g.SetBudgetLookup(func(string) (BudgetSnapshot, bool) {
		return BudgetSnapshot{ByModel: map[string]policy.BudgetWindowAmounts{
			"claude-sonnet-5": {DailyUSD: 7},
		}}, true
	})
	g.SetBudgetSubjectResolver(func(kind, id string) string {
		if kind == "model" && strings.HasPrefix(id, "claude-sonnet-5") {
			return "claude-sonnet-5"
		}
		return id
	})
	ev := policy.Event{
		Kind: policy.KindAPIRequest, SessionID: "s1", Now: time.Now().UTC(),
		Model: "Claude-Sonnet-5-20260501",
	}
	g.stampBudget(&ev)
	if ev.Model != "Claude-Sonnet-5-20260501" {
		t.Errorf("the raw model was rewritten: %q", ev.Model)
	}
	if ev.ModelSubjectID != "claude-sonnet-5" {
		t.Errorf("ModelSubjectID = %q, want claude-sonnet-5", ev.ModelSubjectID)
	}
	if ev.ModelUsage.DailyUSD != 7 {
		t.Errorf("ModelUsage.DailyUSD = %v, want the resolved subject's 7", ev.ModelUsage.DailyUSD)
	}
	if g.BudgetSubjectResolver() == nil {
		t.Errorf("BudgetSubjectResolver() = nil after SetBudgetSubjectResolver")
	}
}
