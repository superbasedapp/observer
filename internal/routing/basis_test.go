package routing

import "testing"

// Fake bases for pipeline-composition tests. The shipped bases get
// their own per-behavior tests in bases_test.go; these fakes isolate
// the FIXED composition semantics (§R6.2).

type fakeFilter struct {
	name string
	deny map[string]bool
}

func (f fakeFilter) Name() string      { return f.name }
func (f fakeFilter) Class() BasisClass { return ClassFilter }
func (f fakeFilter) Allow(c ModelCandidate, _ BasisInput) (bool, ReasonCode) {
	if f.deny[c.Model] {
		return false, ReasonCapabilityHold
	}
	return true, ""
}

type fakeRank struct {
	name string
	keys map[string]float64
}

func (r fakeRank) Name() string      { return r.name }
func (r fakeRank) Class() BasisClass { return ClassRank }
func (r fakeRank) Key(c ModelCandidate, _ BasisInput) float64 {
	return r.keys[c.Model]
}

type fakeModifier struct {
	name string
	mod  Modifier
}

func (m fakeModifier) Name() string               { return m.name }
func (m fakeModifier) Class() BasisClass          { return ClassModifier }
func (m fakeModifier) Modify(BasisInput) Modifier { return m.mod }

func pipelineCandidates() []ModelCandidate {
	return []ModelCandidate{
		{Model: "claude-opus-4-8", Tier: TierOpusClass, Shape: ShapeAnthropic},
		{Model: "claude-sonnet-4-6", Tier: TierSonnetClass, Shape: ShapeAnthropic},
		{Model: "claude-haiku-4-5", Tier: TierHaikuClass, Shape: ShapeAnthropic},
	}
}

func pipelineInput(kind TurnKind) BasisInput {
	return BasisInput{
		In: DecisionInput{
			Shape:       TurnShape{Model: "claude-opus-4-8"},
			Entitlement: EntitlementAPIKey,
		},
		Kind:         kind,
		OriginalTier: TierOpusClass,
		Snap:         testSnapshot(),
	}
}

// TestRunPipeline_FiltersIntersect: a candidate denied by ANY filter
// is out, regardless of filter order.
func TestRunPipeline_FiltersIntersect(t *testing.T) {
	t.Parallel()
	bases := []Basis{
		fakeFilter{name: "f1", deny: map[string]bool{"claude-sonnet-4-6": true}},
		fakeFilter{name: "f2", deny: map[string]bool{"claude-haiku-4-5": true}},
	}
	res := RunPipeline(bases, pipelineCandidates(), pipelineInput(TurnReadOnly))
	allowed := res.Allowed()
	if len(allowed) != 1 || allowed[0].Model != "claude-opus-4-8" {
		t.Fatalf("allowed = %+v, want only the opus candidate", allowed)
	}
	for _, c := range res.Candidates {
		if c.Model == "claude-sonnet-4-6" && (c.Allowed || len(c.DenyReasons) == 0) {
			t.Error("denied candidate missing deny reason")
		}
	}
}

// TestRunPipeline_FirstRankerPrimary: the first ranker is the primary
// sort; the second only breaks ties (§R6.2 — no weighted blending).
func TestRunPipeline_FirstRankerPrimary(t *testing.T) {
	t.Parallel()
	bases := []Basis{
		fakeRank{name: "primary", keys: map[string]float64{
			"claude-opus-4-8": 2, "claude-sonnet-4-6": 1, "claude-haiku-4-5": 1,
		}},
		fakeRank{name: "tiebreak", keys: map[string]float64{
			"claude-opus-4-8": 0, "claude-sonnet-4-6": 5, "claude-haiku-4-5": 1,
		}},
	}
	res := RunPipeline(bases, pipelineCandidates(), pipelineInput(TurnReadOnly))
	allowed := res.Allowed()
	want := []string{"claude-haiku-4-5", "claude-sonnet-4-6", "claude-opus-4-8"}
	for i, w := range want {
		if allowed[i].Model != w {
			t.Fatalf("rank order = %v, want %v (primary first, tie-break second)",
				modelsOf(allowed), want)
		}
	}
}

// TestRunPipeline_ModifierExclusionRerunsOnce: a modifier exclusion is
// applied and the surviving set re-ranked — the §R6.2 single re-run.
func TestRunPipeline_ModifierExclusionRerunsOnce(t *testing.T) {
	t.Parallel()
	bases := []Basis{
		fakeRank{name: "rank", keys: map[string]float64{
			"claude-opus-4-8": 3, "claude-sonnet-4-6": 1, "claude-haiku-4-5": 2,
		}},
		fakeModifier{name: "avail", mod: Modifier{ExcludeModels: []string{"claude-sonnet-4-6"}}},
	}
	res := RunPipeline(bases, pipelineCandidates(), pipelineInput(TurnReadOnly))
	allowed := res.Allowed()
	if len(allowed) != 2 || allowed[0].Model != "claude-haiku-4-5" {
		t.Fatalf("allowed after exclusion = %v, want haiku first", modelsOf(allowed))
	}
}

// TestRunPipeline_TierCapSoftKindsOnly pins §R14: a modifier tier cap
// demotes soft kinds; plan/edit floors hold unless degrade_all.
func TestRunPipeline_TierCapSoftKindsOnly(t *testing.T) {
	t.Parallel()
	cap := fakeModifier{name: "budget", mod: Modifier{
		TierCap: TierHaikuClass, Reasons: []ReasonCode{ReasonBudgetBand95},
	}}

	// Soft kind: opus + sonnet candidates fall to the cap.
	res := RunPipeline([]Basis{cap}, pipelineCandidates(), pipelineInput(TurnReadOnly))
	if got := modelsOf(res.Allowed()); len(got) != 1 || got[0] != "claude-haiku-4-5" {
		t.Fatalf("soft-kind cap: allowed = %v, want only haiku", got)
	}

	// Hard kind: the cap must NOT apply (plan floors hold).
	res = RunPipeline([]Basis{cap}, pipelineCandidates(), pipelineInput(TurnPlan))
	if got := modelsOf(res.Allowed()); len(got) != 3 {
		t.Fatalf("hard-kind cap leaked: allowed = %v, want all 3", got)
	}

	// degrade_all escalation: the cap applies to every kind.
	capAll := fakeModifier{name: "budget", mod: Modifier{
		TierCap: TierHaikuClass, TierCapAllKinds: true, Reasons: []ReasonCode{ReasonBudgetExhausted},
	}}
	res = RunPipeline([]Basis{capAll}, pipelineCandidates(), pipelineInput(TurnPlan))
	if got := modelsOf(res.Allowed()); len(got) != 1 || got[0] != "claude-haiku-4-5" {
		t.Fatalf("degrade_all cap: allowed = %v, want only haiku", got)
	}
}

// TestRunPipeline_ModifierMergeMostRestrictive: two modifiers merge to
// the lower cap, the union of exclusions, and OR'd escalations.
func TestRunPipeline_ModifierMergeMostRestrictive(t *testing.T) {
	t.Parallel()
	bases := []Basis{
		fakeModifier{name: "m1", mod: Modifier{TierCap: TierSonnetClass, AdviseOnly: true}},
		fakeModifier{name: "m2", mod: Modifier{TierCap: TierHaikuClass, ExcludeModels: []string{"claude-haiku-4-5"}}},
	}
	res := RunPipeline(bases, pipelineCandidates(), pipelineInput(TurnReadOnly))
	if res.Mod.TierCap != TierHaikuClass {
		t.Errorf("merged cap = %q, want haiku-class (lower wins)", res.Mod.TierCap)
	}
	if !res.Mod.AdviseOnly {
		t.Error("merged AdviseOnly lost")
	}
	if got := modelsOf(res.Allowed()); len(got) != 0 {
		t.Errorf("allowed = %v, want none (cap + exclusion)", got)
	}
}

// TestRunPipeline_Deterministic: equal inputs → byte-equal order.
func TestRunPipeline_Deterministic(t *testing.T) {
	t.Parallel()
	bases := []Basis{
		fakeRank{name: "rank", keys: map[string]float64{}}, // all ties → model-id order
	}
	first := modelsOf(RunPipeline(bases, pipelineCandidates(), pipelineInput(TurnReadOnly)).Allowed())
	for i := 0; i < 5; i++ {
		got := modelsOf(RunPipeline(bases, pipelineCandidates(), pipelineInput(TurnReadOnly)).Allowed())
		for j := range first {
			if got[j] != first[j] {
				t.Fatalf("run %d diverged: %v != %v", i, got, first)
			}
		}
	}
}

func modelsOf(cs []CandidateState) []string {
	out := make([]string, len(cs))
	for i, c := range cs {
		out[i] = c.Model
	}
	return out
}

// mapWindows is a test ContextWindowFn over a literal table.
func mapWindows(m map[string]int64) ContextWindowFn {
	return func(model string) (int64, bool) {
		v, ok := m[model]
		return v, ok && v > 0
	}
}

// TestCapabilityBasis_Rows — one row per capability behavior (§R11.2,
// §R11.3): incumbent immunity, cross-shape denial, unknown shape,
// context-window fit, subscription entitlement vs router slugs.
func TestCapabilityBasis_Rows(t *testing.T) {
	t.Parallel()
	cb := capabilityBasisSingleton.(FilterBasis)
	cases := []struct {
		name      string
		candidate ModelCandidate
		in        DecisionInput
		// windows backs Snapshot.ContextWindow; nil = no resolver.
		windows map[string]int64
		want    bool
		reason  ReasonCode
	}{
		{
			name:      "incumbent_never_denied",
			candidate: ModelCandidate{Model: "claude-opus-4-8", Tier: TierOpusClass, Shape: ShapeAnthropic},
			in:        DecisionInput{Shape: TurnShape{Model: "claude-opus-4-8", PromptTokens: 999_999_999}},
			want:      true,
		},
		{
			name:      "cross_shape_denied",
			candidate: ModelCandidate{Model: "gpt-5.4", Tier: TierSonnetClass, Shape: ShapeOpenAI},
			in:        DecisionInput{Shape: TurnShape{Model: "claude-opus-4-8"}, Entitlement: EntitlementAPIKey},
			want:      false,
			reason:    ReasonCapabilityHold,
		},
		{
			name:      "unknown_shape_denied",
			candidate: ModelCandidate{Model: "mystery-model", Tier: TierSonnetClass, Shape: ShapeUnknown},
			in:        DecisionInput{Shape: TurnShape{Model: "claude-opus-4-8"}, Entitlement: EntitlementAPIKey},
			want:      false,
			reason:    ReasonCapabilityHold,
		},
		{
			name:      "context_window_known_too_small_denied",
			candidate: ModelCandidate{Model: "claude-haiku-4-5", Tier: TierHaikuClass, Shape: ShapeAnthropic},
			in:        DecisionInput{Shape: TurnShape{Model: "claude-opus-4-8", PromptTokens: 250_000}, Entitlement: EntitlementAPIKey},
			windows:   map[string]int64{"claude-haiku-4-5": 200_000},
			want:      false,
			reason:    ReasonCapabilityHold,
		},
		{
			name:      "context_window_known_fits_allowed",
			candidate: ModelCandidate{Model: "claude-haiku-4-5", Tier: TierHaikuClass, Shape: ShapeAnthropic},
			in:        DecisionInput{Shape: TurnShape{Model: "claude-opus-4-8", PromptTokens: 50_000}, Entitlement: EntitlementAPIKey},
			windows:   map[string]int64{"claude-haiku-4-5": 200_000},
			want:      true,
		},
		{
			name:      "context_window_exact_fit_allowed",
			candidate: ModelCandidate{Model: "claude-haiku-4-5", Tier: TierHaikuClass, Shape: ShapeAnthropic},
			in:        DecisionInput{Shape: TurnShape{Model: "claude-opus-4-8", PromptTokens: 200_000}, Entitlement: EntitlementAPIKey},
			windows:   map[string]int64{"claude-haiku-4-5": 200_000},
			want:      true,
		},
		{
			name:      "context_window_unknown_not_excluded",
			candidate: ModelCandidate{Model: "claude-haiku-4-5", Tier: TierHaikuClass, Shape: ShapeAnthropic},
			in:        DecisionInput{Shape: TurnShape{Model: "claude-opus-4-8", PromptTokens: 5_000_000}, Entitlement: EntitlementAPIKey},
			windows:   map[string]int64{"some-other-model": 100},
			want:      true,
		},
		{
			name:      "context_window_no_resolver_not_excluded",
			candidate: ModelCandidate{Model: "claude-haiku-4-5", Tier: TierHaikuClass, Shape: ShapeAnthropic},
			in:        DecisionInput{Shape: TurnShape{Model: "claude-opus-4-8", PromptTokens: 5_000_000}, Entitlement: EntitlementAPIKey},
			want:      true,
		},
		{
			name:      "subscription_denies_router_slug",
			candidate: ModelCandidate{Model: "openrouter/claude-haiku-4-5", Tier: TierHaikuClass, Shape: ShapeAnthropic},
			in:        DecisionInput{Shape: TurnShape{Model: "claude-opus-4-8"}, Entitlement: EntitlementSubscription},
			want:      false,
			reason:    ReasonEntitlementHold,
		},
		{
			name:      "unknown_entitlement_treated_restrictively",
			candidate: ModelCandidate{Model: "openrouter/claude-haiku-4-5", Tier: TierHaikuClass, Shape: ShapeAnthropic},
			in:        DecisionInput{Shape: TurnShape{Model: "claude-opus-4-8"}},
			want:      false,
			reason:    ReasonEntitlementHold,
		},
		{
			name:      "subscription_allows_plan_native",
			candidate: ModelCandidate{Model: "claude-haiku-4-5", Tier: TierHaikuClass, Shape: ShapeAnthropic},
			in:        DecisionInput{Shape: TurnShape{Model: "claude-opus-4-8"}, Entitlement: EntitlementSubscription},
			want:      true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			bin := BasisInput{In: tc.in}
			if tc.windows != nil {
				bin.Snap = &Snapshot{ContextWindow: mapWindows(tc.windows)}
			}
			got, reason := cb.Allow(tc.candidate, bin)
			if got != tc.want {
				t.Fatalf("Allow = %v, want %v", got, tc.want)
			}
			if !tc.want && reason != tc.reason {
				t.Errorf("reason = %q, want %q", reason, tc.reason)
			}
		})
	}
}
