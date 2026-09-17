package routing

import (
	"sort"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/models"
)

// testSnapshot returns a snapshot over the seed tier table with a
// simple linear price: opus $10/M-in $50/M-out style ratios collapsed to
// per-token multipliers so savings are easy to assert.
func testSnapshot() *Snapshot {
	prices := map[string]struct{ in, out, cacheWrite float64 }{
		// claude-opus-5 and claude-opus-4-8 price IDENTICALLY on
		// purpose ($5 in / $25 out per MTok, 5m cache write $6.25) —
		// that rate parity is load-bearing for
		// TestApplyPin_OpusFivePromotionEconomics, which asserts that a
		// rewrite between the two SKUs has exactly zero gross saving.
		"claude-opus-5":     {5, 25, 6.25},
		"claude-opus-4-8":   {5, 25, 6.25},
		"claude-sonnet-4-6": {3, 15, 3.75},
		"claude-haiku-4-5":  {1, 5, 1.25},
	}
	price := func(model string, u PromptUsage) (float64, bool) {
		p, ok := prices[model]
		if !ok {
			return 0, false
		}
		return (float64(u.Input)*p.in + float64(u.Output)*p.out + float64(u.CacheCreation)*p.cacheWrite) / 1e6, true
	}
	return &Snapshot{Price: price, Tiers: NewTierResolver().Table()}
}

// readOnlyInput is an opus read_only turn with observed usage.
func readOnlyInput() DecisionInput {
	return DecisionInput{
		Shape: TurnShape{Model: "claude-opus-4-8", MessageCount: 8, ToolUseCount: 4},
		Session: SessionState{
			TurnsSinceSwitch: -1,
			RecentActions: []ActionSignal{
				{Type: models.ActionReadFile, Success: true},
				{Type: models.ActionSearchText, Success: true},
			},
		},
		ObservedUsage: &PromptUsage{Input: 100_000, Output: 10_000},
	}
}

func valuePolicy(t *testing.T) Policy {
	t.Helper()
	p, ok := TemplateByName("value")
	if !ok {
		t.Fatal("value template missing")
	}
	return p
}

// TestDecide_DownshiftHappyPath pins the core decision: an opus
// read_only turn under "value" reroutes to the same-shape haiku
// representative with the rule's reason and net positive savings.
func TestDecide_DownshiftHappyPath(t *testing.T) {
	t.Parallel()
	d := Decide(valuePolicy(t), testSnapshot(), readOnlyInput())
	if !d.Changed || d.SelectedModel != "claude-haiku-4-5" {
		t.Fatalf("decision = %+v, want change to claude-haiku-4-5", d)
	}
	if d.TurnKind != TurnReadOnly || d.RuleName != "read_only_overpowered" {
		t.Errorf("kind/rule = %s/%s", d.TurnKind, d.RuleName)
	}
	if len(d.ReasonCodes) != 1 || d.ReasonCodes[0] != ReasonOverpoweredRead {
		t.Errorf("reasons = %v", d.ReasonCodes)
	}
	// gross = (100k×5 + 10k×25)/1e6 − (100k×1 + 10k×5)/1e6 = 0.75 − 0.15 = 0.60
	if d.EstSavingsUSD < 0.59 || d.EstSavingsUSD > 0.61 {
		t.Errorf("savings = %v, want ≈0.60", d.EstSavingsUSD)
	}
	if d.EstimateVersion != EstimateVersion || d.PolicyName != "value" || d.PolicyHash == "" {
		t.Errorf("attribution fields = %+v", d)
	}
}

// TestDecide_FailOpenGuards walks the fail-open rows: nil snapshot, nil
// tier table, empty model — original model passes through with
// fail_open (§R9.2, G7).
func TestDecide_FailOpenGuards(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		snap *Snapshot
		in   DecisionInput
	}{
		{"nil_snapshot", nil, readOnlyInput()},
		{"nil_tiers", &Snapshot{}, readOnlyInput()},
		{"empty_model", testSnapshot(), DecisionInput{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			d := Decide(valuePolicy(t), tc.snap, tc.in)
			if d.Changed || d.SelectedModel != d.OriginalModel {
				t.Errorf("fail-open mutated the model: %+v", d)
			}
			if len(d.ReasonCodes) != 1 || d.ReasonCodes[0] != ReasonFailOpen {
				t.Errorf("reasons = %v, want [fail_open]", d.ReasonCodes)
			}
		})
	}
}

// TestDecide_UnknownTurnKindNeverRoutes pins §R8.3: a degraded
// classification yields no change.
func TestDecide_UnknownTurnKindNeverRoutes(t *testing.T) {
	t.Parallel()
	in := readOnlyInput()
	in.Session.RecentActions = nil // empty window → unknown
	d := Decide(valuePolicy(t), testSnapshot(), in)
	if d.Changed {
		t.Fatalf("unknown turn rerouted: %+v", d)
	}
	if d.TurnKind != TurnUnknown || d.ReasonCodes[0] != ReasonUnknownTurnKind {
		t.Errorf("kind/reasons = %s/%v", d.TurnKind, d.ReasonCodes)
	}
}

// TestDecide_UnclassifiedModelRefused pins §R7.1: a model the tier
// table cannot place is never reasoned about.
func TestDecide_UnclassifiedModelRefused(t *testing.T) {
	t.Parallel()
	in := readOnlyInput()
	in.Shape.Model = "mystery-model-9000"
	d := Decide(valuePolicy(t), testSnapshot(), in)
	if d.Changed || d.ReasonCodes[0] != ReasonUnclassifiedModel {
		t.Errorf("decision = %+v, want unclassified_model hold", d)
	}
}

// TestDecide_NoRuleMatch pins the quiet default: a kind no rule targets
// (edit under "value") passes through with no rule and no reasons.
func TestDecide_NoRuleMatch(t *testing.T) {
	t.Parallel()
	in := readOnlyInput()
	in.Session.RecentActions = []ActionSignal{{Type: models.ActionEditFile, Success: true}}
	d := Decide(valuePolicy(t), testSnapshot(), in)
	if d.Changed || d.RuleName != "" || len(d.ReasonCodes) != 0 {
		t.Errorf("decision = %+v, want untouched edit turn", d)
	}
	if d.TurnKind != TurnEdit {
		t.Errorf("kind = %s, want edit", d.TurnKind)
	}
}

// TestDecide_NoRoutePin pins the explicit exemption: plan under
// plan-exec records no_route + phase_pin and never moves.
func TestDecide_NoRoutePin(t *testing.T) {
	t.Parallel()
	p, _ := TemplateByName("plan-exec")
	in := readOnlyInput()
	in.Session.ClientPhase = "plan"
	d := Decide(p, testSnapshot(), in)
	if d.Changed {
		t.Fatalf("pinned plan turn moved: %+v", d)
	}
	if d.RuleName != "plan_pin" || len(d.ReasonCodes) != 2 ||
		d.ReasonCodes[0] != ReasonNoRoute || d.ReasonCodes[1] != ReasonPhasePin {
		t.Errorf("rule/reasons = %s/%v", d.RuleName, d.ReasonCodes)
	}
}

// TestDecide_NoCandidateSameShape pins §R11.4: a model with no
// same-shape representative in the target tier holds with no_candidate.
// grok-4.3 is sonnet-class but ShapeUnknown — no candidate exists.
func TestDecide_NoCandidateSameShape(t *testing.T) {
	t.Parallel()
	in := readOnlyInput()
	in.Shape.Model = "grok-4.3"
	d := Decide(valuePolicy(t), testSnapshot(), in)
	if d.Changed || d.ReasonCodes[0] != ReasonNoCandidate {
		t.Errorf("decision = %+v, want no_candidate hold", d)
	}
}

// TestDecide_StickinessHold pins the §R13 coherence floor: a proposed
// switch within min-turns-between-switches holds.
func TestDecide_StickinessHold(t *testing.T) {
	t.Parallel()
	in := readOnlyInput()
	in.Session.TurnsSinceSwitch = 2 // value template floor is 5
	d := Decide(valuePolicy(t), testSnapshot(), in)
	if d.Changed || d.ReasonCodes[0] != ReasonStickinessHold {
		t.Errorf("decision = %+v, want stickiness hold", d)
	}
}

// TestDecide_CacheHold pins the headline §R13 economics: when the warm
// prefix is worth more than the switch saves, the engine stays put and
// says why, with the negative net on the row.
func TestDecide_CacheHold(t *testing.T) {
	t.Parallel()
	in := readOnlyInput()
	// Tiny turn (gross ≈ $0.0006) behind a huge warm prefix: forfeit =
	// 1M × $1.25/M = $1.25 at the candidate's cache-write rate.
	in.ObservedUsage = &PromptUsage{Input: 100, Output: 10}
	in.Session.PriorCacheReadTokens = 1_000_000
	d := Decide(valuePolicy(t), testSnapshot(), in)
	if d.Changed {
		t.Fatalf("cache-held turn moved: %+v", d)
	}
	if d.ReasonCodes[0] != ReasonCacheHold {
		t.Errorf("reasons = %v, want [cache_hold]", d.ReasonCodes)
	}
	if d.CacheForfeitUSD < 1.24 || d.CacheForfeitUSD > 1.26 {
		t.Errorf("forfeit = %v, want ≈1.25", d.CacheForfeitUSD)
	}
	if d.EstSavingsUSD >= 0 {
		t.Errorf("net savings = %v, want negative (that's why we held)", d.EstSavingsUSD)
	}
}

// TestDecide_NoDollarClaimWithoutUsage pins estimate honesty: without
// observed usage the switch still happens (the rule is sound) but no
// dollar figures are invented — and no cache-hold either, since a hold
// is itself a dollar claim.
func TestDecide_NoDollarClaimWithoutUsage(t *testing.T) {
	t.Parallel()
	in := readOnlyInput()
	in.ObservedUsage = nil
	in.Session.PriorCacheReadTokens = 1_000_000
	d := Decide(valuePolicy(t), testSnapshot(), in)
	if !d.Changed || d.SelectedModel != "claude-haiku-4-5" {
		t.Fatalf("decision = %+v, want downshift", d)
	}
	if d.EstSavingsUSD != 0 || d.CacheForfeitUSD != 0 {
		t.Errorf("invented dollars: savings %v forfeit %v", d.EstSavingsUSD, d.CacheForfeitUSD)
	}
}

// TestDecide_Deterministic pins §R9.3 end to end.
func TestDecide_Deterministic(t *testing.T) {
	t.Parallel()
	p := valuePolicy(t)
	snap := testSnapshot()
	in := readOnlyInput()
	first := Decide(p, snap, in)
	for i := 0; i < 10; i++ {
		got := Decide(p, snap, in)
		if got.SelectedModel != first.SelectedModel || got.EstSavingsUSD != first.EstSavingsUSD ||
			got.PolicyHash != first.PolicyHash || got.RuleName != first.RuleName {
			t.Fatalf("run %d diverged: %+v != %+v", i, got, first)
		}
	}
}

// TestPolicyHash_ContentSensitive pins §R6.6 attribution: the hash
// changes with rule content and is stable across calls.
func TestPolicyHash_ContentSensitive(t *testing.T) {
	t.Parallel()
	p1, _ := TemplateByName("value")
	p2, _ := TemplateByName("value")
	if p1.Hash() != p2.Hash() {
		t.Error("hash not stable across template instantiations")
	}
	p2.Rules[0].When.TierAtLeast = TierOpusClass
	if p1.Hash() == p2.Hash() {
		t.Error("hash blind to rule content change")
	}
	frugal, _ := TemplateByName("frugal")
	if p1.Hash() == frugal.Hash() {
		t.Error("distinct templates share a hash")
	}
}

// TestTemplates_Registry pins the shipped template set and that every
// rule's reason code is in the closed enum.
func TestTemplates_Registry(t *testing.T) {
	t.Parallel()
	names := TemplateNames()
	want := []string{"value", "frugal", "fast", "strict-privacy", "plan-exec", "enterprise-default"}
	if len(names) != len(want) {
		t.Fatalf("templates = %v, want %v", names, want)
	}
	for i := range want {
		if names[i] != want[i] {
			t.Errorf("template[%d] = %q, want %q", i, names[i], want[i])
		}
	}
	known := map[ReasonCode]bool{}
	for _, rc := range KnownReasonCodes() {
		known[rc] = true
	}
	for _, p := range Templates() {
		for _, r := range p.Rules {
			if !known[r.Reason] {
				t.Errorf("policy %s rule %s uses unknown reason %q", p.Name, r.Name, r.Reason)
			}
		}
	}
}

// TestRuleWhen_Matches covers each matcher dimension (one row per
// clause field).
func TestRuleWhen_Matches(t *testing.T) {
	t.Parallel()
	yes, no := true, false
	_ = no
	cases := []struct {
		name string
		when RuleWhen
		kind TurnKind
		tier Tier
		in   DecisionInput
		want bool
	}{
		{"empty_matches_all", RuleWhen{}, TurnEdit, TierOpusClass, DecisionInput{}, true},
		{"kind_in_set", RuleWhen{TurnKinds: []TurnKind{TurnReadOnly, TurnEdit}}, TurnEdit, TierOpusClass, DecisionInput{}, true},
		{"kind_not_in_set", RuleWhen{TurnKinds: []TurnKind{TurnReadOnly}}, TurnEdit, TierOpusClass, DecisionInput{}, false},
		{"tier_at_least_pass", RuleWhen{TierAtLeast: TierSonnetClass}, TurnEdit, TierOpusClass, DecisionInput{}, true},
		{"tier_at_least_fail", RuleWhen{TierAtLeast: TierSonnetClass}, TurnEdit, TierHaikuClass, DecisionInput{}, false},
		{"max_tools_pass", RuleWhen{MaxToolUses: 3}, TurnEdit, TierOpusClass, DecisionInput{Shape: TurnShape{ToolUseCount: 2}}, true},
		{"max_tools_fail", RuleWhen{MaxToolUses: 3}, TurnEdit, TierOpusClass, DecisionInput{Shape: TurnShape{ToolUseCount: 4}}, false},
		{"sidechain_match", RuleWhen{Sidechain: &yes}, TurnSubagent, TierOpusClass, DecisionInput{Session: SessionState{IsSidechain: true}}, true},
		{"sidechain_mismatch", RuleWhen{Sidechain: &yes}, TurnEdit, TierOpusClass, DecisionInput{}, false},
		{"phase_match", RuleWhen{Phase: "plan"}, TurnPlan, TierOpusClass, DecisionInput{Session: SessionState{ClientPhase: "plan"}}, true},
		{"phase_mismatch", RuleWhen{Phase: "plan"}, TurnEdit, TierOpusClass, DecisionInput{}, false},
		{"model_glob_match", RuleWhen{ModelGlob: "claude-opus-*"}, TurnEdit, TierOpusClass, DecisionInput{Shape: TurnShape{Model: "claude-opus-4-8"}}, true},
		{"model_glob_mismatch", RuleWhen{ModelGlob: "gpt-*"}, TurnEdit, TierOpusClass, DecisionInput{Shape: TurnShape{Model: "claude-opus-4-8"}}, false},
		{"project_match", RuleWhen{Project: "acme"}, TurnEdit, TierOpusClass, DecisionInput{Project: "acme"}, true},
		{"project_mismatch", RuleWhen{Project: "acme"}, TurnEdit, TierOpusClass, DecisionInput{Project: "other"}, false},
		{"path_class_hit", RuleWhen{PathClass: "secrets"}, TurnEdit, TierOpusClass, DecisionInput{PathClassHits: []string{"secrets"}}, true},
		{"path_class_miss", RuleWhen{PathClass: "secrets"}, TurnEdit, TierOpusClass, DecisionInput{}, false},
		{"session_age_min_pass", RuleWhen{SessionAgeTurnsMin: 5}, TurnEdit, TierOpusClass, DecisionInput{Session: SessionState{SessionAgeTurns: 6}}, true},
		{"session_age_min_fail", RuleWhen{SessionAgeTurnsMin: 5}, TurnEdit, TierOpusClass, DecisionInput{Session: SessionState{SessionAgeTurns: 4}}, false},
		{"session_age_max_pass", RuleWhen{SessionAgeTurnsMax: 5}, TurnEdit, TierOpusClass, DecisionInput{Session: SessionState{SessionAgeTurns: 5}}, true},
		{"session_age_max_fail", RuleWhen{SessionAgeTurnsMax: 5}, TurnEdit, TierOpusClass, DecisionInput{Session: SessionState{SessionAgeTurns: 6}}, false},
		{"min_prompt_tokens_pass", RuleWhen{MinPromptTokens: 1000}, TurnEdit, TierOpusClass, DecisionInput{Shape: TurnShape{PromptTokens: 2000}}, true},
		{"min_prompt_tokens_fail", RuleWhen{MinPromptTokens: 1000}, TurnEdit, TierOpusClass, DecisionInput{Shape: TurnShape{PromptTokens: 500}}, false},
		{"max_prompt_tokens_pass", RuleWhen{MaxPromptTokens: 1000}, TurnEdit, TierOpusClass, DecisionInput{Shape: TurnShape{PromptTokens: 800}}, true},
		{"max_prompt_tokens_fail", RuleWhen{MaxPromptTokens: 1000}, TurnEdit, TierOpusClass, DecisionInput{Shape: TurnShape{PromptTokens: 1200}}, false},
		{"entitlement_match", RuleWhen{Entitlement: EntitlementSubscription}, TurnEdit, TierOpusClass, DecisionInput{Entitlement: EntitlementSubscription}, true},
		{"entitlement_mismatch", RuleWhen{Entitlement: EntitlementAPIKey}, TurnEdit, TierOpusClass, DecisionInput{Entitlement: EntitlementSubscription}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := tc.when.Matches(MatchContext{Kind: tc.kind, Tier: tc.tier, In: tc.in}); got != tc.want {
				t.Errorf("Matches = %v, want %v", got, tc.want)
			}
		})
	}

	// The budget-band matcher reads the snapshot-derived burn, not the
	// input — covered separately.
	t.Run("budget_band_at_least", func(t *testing.T) {
		t.Parallel()
		w := RuleWhen{BudgetBandAtLeast: 0.8}
		if w.Matches(MatchContext{Kind: TurnEdit, Tier: TierOpusClass, BudgetBurnMax: 0.85}) != true {
			t.Error("burn 0.85 should match band 0.8")
		}
		if w.Matches(MatchContext{Kind: TurnEdit, Tier: TierOpusClass, BudgetBurnMax: 0.5}) != false {
			t.Error("burn 0.5 should not match band 0.8")
		}
	})
}

// TestDecideHotPathBudget pins the §R9.2 / §R25 hot-path contract:
// p99 decision latency < 5 ms. Decide is pure in-memory work
// (classify + tier-place + pipeline + rule walk), so this passes with
// orders-of-magnitude headroom — the test exists to catch an accidental
// I/O or quadratic-blowup regression on the path, not to be tight.
//
// It is a WALL-CLOCK assertion, so it is skipped under -short (F3,
// codebase audit 2026-09-16) and widened by decideLatencyRaceMultiplier
// under -race, where the detector's instrumentation is what the 5 ms
// would otherwise be measuring.
func TestDecideHotPathBudget(t *testing.T) {
	if testing.Short() {
		t.Skip("wall-clock latency budget: not a -short gate")
	}
	budget := 5 * time.Millisecond * decideLatencyRaceMultiplier
	p := valuePolicy(t)
	snap := testSnapshot()
	snap.BudgetBurn = []BudgetBurnState{{Scope: "global", LimitUSD: 100, SpentUSD: 40, Window: "week", Bands: DefaultBudgetBands}}
	snap.Health = map[string]HealthState{"claude-sonnet-4-6": HealthDegraded}
	in := readOnlyInput()

	const n = 5000
	durations := make([]time.Duration, n)
	for i := 0; i < n; i++ {
		start := time.Now()
		_ = Decide(p, snap, in)
		durations[i] = time.Since(start)
	}
	sort.Slice(durations, func(i, j int) bool { return durations[i] < durations[j] })
	p99 := durations[n*99/100]
	if p99 >= budget {
		t.Fatalf("Decide p99 = %v, budget is < %v (§R25, ×%d race headroom)", p99, budget, decideLatencyRaceMultiplier)
	}
}

// TestDecide_CacheHoldSuggestsEffort pins the §R6.5 borderline-case
// default: a cache-held switch carries the zero-cache-loss effort
// downshift suggestion.
func TestDecide_CacheHoldSuggestsEffort(t *testing.T) {
	t.Parallel()
	in := readOnlyInput()
	in.ObservedUsage = &PromptUsage{Input: 100, Output: 10}
	in.Session.PriorCacheReadTokens = 1_000_000
	d := Decide(valuePolicy(t), testSnapshot(), in)
	if d.Changed {
		t.Fatalf("cache-held turn moved: %+v", d)
	}
	if d.SetEffort != EffortLow {
		t.Errorf("SetEffort = %q, want %q (the borderline suggestion)", d.SetEffort, EffortLow)
	}
	if !hasReason(d.ReasonCodes, ReasonCacheHold) || !hasReason(d.ReasonCodes, ReasonEffortDownshift) {
		t.Errorf("reasons = %v, want cache_hold + effort_downshift", d.ReasonCodes)
	}
}

// TestDecide_EffortRuleAction pins the set_effort rule action: the
// model is untouched, the decision carries the effort level.
func TestDecide_EffortRuleAction(t *testing.T) {
	t.Parallel()
	p, issues := Compile(PolicySpec{
		Policy: "custom",
		Rules: []RuleSpec{{
			Name:   "effort_reads",
			When:   WhenSpec{TurnKind: "read_only", TierAtLeast: "sonnet-class"},
			Action: ActionSpec{SetEffort: "low", Reason: "overpowered_read"},
		}},
	})
	if LintHasErrors(issues) {
		t.Fatalf("lint: %+v", issues)
	}
	d := Decide(p, testSnapshot(), readOnlyInput())
	if d.Changed || d.SelectedModel != d.OriginalModel {
		t.Fatalf("effort rule changed the model: %+v", d)
	}
	if d.SetEffort != "low" || !hasReason(d.ReasonCodes, ReasonEffortDownshift) {
		t.Errorf("decision = %+v, want effort-only", d)
	}
}

// TestDecide_EscalatedKindHolds pins §R7.4 at the engine: an escalated
// turn-kind never downshifts — the original model passes through with
// reason=escalation, even though a rule matches.
func TestDecide_EscalatedKindHolds(t *testing.T) {
	t.Parallel()
	in := readOnlyInput()
	in.Session.EscalatedKinds = []TurnKind{TurnReadOnly}
	d := Decide(valuePolicy(t), testSnapshot(), in)
	if d.Changed {
		t.Fatalf("escalated kind downshifted: %+v", d)
	}
	if len(d.ReasonCodes) != 1 || d.ReasonCodes[0] != ReasonEscalation {
		t.Errorf("reasons = %v, want [escalation]", d.ReasonCodes)
	}
	// A DIFFERENT kind under escalation does not hold this one.
	in.Session.EscalatedKinds = []TurnKind{TurnHousekeeping}
	d = Decide(valuePolicy(t), testSnapshot(), in)
	if !d.Changed {
		t.Errorf("unrelated escalation held the turn: %+v", d)
	}
}

// pinOpusClassPolicy compiles the minimal `pin_tier = opus-class` policy
// used by TestApplyPin_OpusFivePromotionEconomics — the opusplan-style
// quality pin, reduced to one rule so the assertions are about applyPin
// and nothing else.
func pinOpusClassPolicy(t *testing.T) Policy {
	t.Helper()
	p, issues := Compile(PolicySpec{
		Policy: "custom",
		Rules: []RuleSpec{{
			Name:   "pin_reads_to_opus",
			When:   WhenSpec{TurnKind: "read_only"},
			Action: ActionSpec{PinTier: "opus-class", Reason: "phase_pin"},
		}},
	})
	if LintHasErrors(issues) {
		t.Fatalf("lint: %+v", issues)
	}
	return p
}

// TestApplyPin_OpusFivePromotionEconomics pins the DECISION-level half of
// the 2026-07-25 operator-approved flagship promotion
// (seedRepresentatives[ShapeAnthropic][TierOpusClass]: claude-opus-4-8 →
// claude-opus-5). tiers_test.go pins the table cell; this pins what the
// engine DOES with it, because that cell is live traffic under
// `[routing] mode = "enforce"`.
//
// Do NOT "fix" a failure here by reverting the representative. The
// promotion is deliberate: Claude Opus 5 is the current Anthropic
// flagship, it is the same ProviderShape (so the §R11.4 same-shape
// constraint is untouched), and it prices identically to Opus 4.8 at
// $5/$25 per MTok — there is no per-token cost delta. Four claims, in the
// order they matter:
//
//  1. Reachable pins now land on claude-opus-5. `pin_tier = opus-class`
//     is an UPSHIFT intent (the opusplan case), so the reachable path is
//     a LOWER-tier incumbent — and its target moved SKU.
//  2. That upshift is priced honestly: a warm prefix is forfeited
//     (CacheForfeitUSD > 0) and the net goes negative. Pins bypass
//     stickiness and cache-hold by design (§R13, they are explicit
//     quality intents), so the forfeit is recorded, never avoided.
//  3. An incumbent ALREADY on either Opus SKU is NOT rewritten. applyPin's
//     FIRST guard is `tier == r.Action.PinTier`, which short-circuits on
//     TIER identity before the representative is ever resolved — so the
//     promotion does not churn live claude-opus-4-8 sessions onto
//     claude-opus-5 and does not invalidate their prompt caches. This is
//     the anti-churn pin: if that early return is ever "optimized" away,
//     opus-class sessions start paying a same-tier, cache-invalidating
//     rewrite that buys nothing, and these rows fail loudly. Note the
//     later `candidate == in.Shape.Model` guard is NOT what protects
//     them — with a consistent tier table it is unreachable, since
//     `tier != PinTier` already excludes the pinned tier's own
//     representative. These rows also pin that the hold carries the
//     RULE's reason (phase_pin), not no_candidate.
//  4. When a cross-SKU rewrite IS forced — here by an operator tier
//     override demoting claude-opus-4-8, the only supported way to reach
//     it — the rate identity makes the gross saving exactly $0, so the net
//     is precisely the negative of the cache forfeit: a rewrite that costs
//     money and saves nothing. With no warm prefix there is nothing to
//     forfeit and the net is $0 — which pins cache forfeit as the SOLE
//     cause of the negative, not the SKU swap itself.
func TestApplyPin_OpusFivePromotionEconomics(t *testing.T) {
	t.Parallel()

	// demotedSnapshot is claim 4's fixture: an operator tier override
	// (§R7.1) places claude-opus-4-8 below opus-class, which is what makes
	// applyPin resolve the opus-class representative for an Opus
	// incumbent instead of short-circuiting on tier identity.
	demotedSnapshot := func() *Snapshot {
		snap := testSnapshot()
		res := NewTierResolver()
		res.Reload(map[string]Tier{"claude-opus-4-8": TierSonnetClass})
		snap.Tiers = res.Table()
		return snap
	}

	const (
		negative = -1
		zero     = 0
	)

	cases := []struct {
		name  string
		snap  *Snapshot
		model string
		// priorCacheRead is the warm prefix the switch would forfeit.
		priorCacheRead int64
		wantChanged    bool
		wantModel      string
		wantForfeitPos bool
		wantSavingsSig int
		// wantNetIsPureForfeit asserts EstSavingsUSD == -CacheForfeitUSD,
		// i.e. the gross saving was exactly zero (rate-identical SKUs).
		wantNetIsPureForfeit bool
	}{
		// Claims 1 + 2: the reachable upshift pin, retargeted to Opus 5.
		{
			name:           "upshift_pin_targets_opus5_and_forfeits_cache",
			snap:           testSnapshot(),
			model:          "claude-sonnet-4-6",
			priorCacheRead: 1_000_000,
			wantChanged:    true,
			wantModel:      "claude-opus-5",
			wantForfeitPos: true,
			wantSavingsSig: negative,
		},
		// Claim 3: neither Opus SKU is churned by the promotion.
		{
			name:           "incumbent_opus48_not_rewritten_to_opus5",
			snap:           testSnapshot(),
			model:          "claude-opus-4-8",
			priorCacheRead: 1_000_000,
			wantChanged:    false,
			wantModel:      "claude-opus-4-8",
			wantSavingsSig: zero,
		},
		{
			name:           "incumbent_opus5_not_rewritten",
			snap:           testSnapshot(),
			model:          "claude-opus-5",
			priorCacheRead: 1_000_000,
			wantChanged:    false,
			wantModel:      "claude-opus-5",
			wantSavingsSig: zero,
		},
		// Claim 4: a forced cross-SKU rewrite saves nothing and costs the
		// forfeit — and is $0, not negative, without a warm prefix.
		{
			name:                 "forced_cross_sku_rewrite_costs_exactly_the_forfeit",
			snap:                 demotedSnapshot(),
			model:                "claude-opus-4-8",
			priorCacheRead:       1_000_000,
			wantChanged:          true,
			wantModel:            "claude-opus-5",
			wantForfeitPos:       true,
			wantSavingsSig:       negative,
			wantNetIsPureForfeit: true,
		},
		{
			name:                 "forced_cross_sku_rewrite_cold_prefix_is_free",
			snap:                 demotedSnapshot(),
			model:                "claude-opus-4-8",
			priorCacheRead:       0,
			wantChanged:          true,
			wantModel:            "claude-opus-5",
			wantForfeitPos:       false,
			wantSavingsSig:       zero,
			wantNetIsPureForfeit: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			in := readOnlyInput()
			in.Shape.Model = tc.model
			in.Session.PriorCacheReadTokens = tc.priorCacheRead

			d := Decide(pinOpusClassPolicy(t), tc.snap, in)

			if d.Changed != tc.wantChanged || d.SelectedModel != tc.wantModel {
				t.Fatalf("changed/model = %v/%q, want %v/%q (decision %+v)",
					d.Changed, d.SelectedModel, tc.wantChanged, tc.wantModel, d)
			}
			if d.RuleName != "pin_reads_to_opus" {
				t.Errorf("rule = %q, want pin_reads_to_opus", d.RuleName)
			}
			// The pin always attributes to its own reason — a held
			// incumbent is an intentional tier-identity no-op, not a
			// no_candidate failure.
			if len(d.ReasonCodes) != 1 || d.ReasonCodes[0] != ReasonPhasePin {
				t.Errorf("reasons = %v, want [phase_pin]", d.ReasonCodes)
			}

			if got := d.CacheForfeitUSD > 0; got != tc.wantForfeitPos {
				t.Errorf("CacheForfeitUSD = %v, want positive=%v", d.CacheForfeitUSD, tc.wantForfeitPos)
			}
			if !tc.wantForfeitPos && d.CacheForfeitUSD != 0 {
				t.Errorf("CacheForfeitUSD = %v, want exactly 0", d.CacheForfeitUSD)
			}
			switch tc.wantSavingsSig {
			case negative:
				if d.EstSavingsUSD >= 0 {
					t.Errorf("EstSavingsUSD = %v, want strictly negative", d.EstSavingsUSD)
				}
			case zero:
				if d.EstSavingsUSD != 0 {
					t.Errorf("EstSavingsUSD = %v, want exactly 0", d.EstSavingsUSD)
				}
			}
			if tc.wantNetIsPureForfeit && d.EstSavingsUSD != -d.CacheForfeitUSD {
				t.Errorf("EstSavingsUSD = %v, want -CacheForfeitUSD (%v): rate-identical SKUs must have zero gross saving",
					d.EstSavingsUSD, -d.CacheForfeitUSD)
			}
		})
	}
}
