package routing

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/models"
)

// One test per basis per behavior row (§R6.2). The fixed-composition
// semantics live in basis_test.go; these pin each shipped basis's own
// behavior, then the engine-integration rows at the bottom pin the
// no-rule pipeline paths (§R14 demotion, §R16 enforcement).

func anthCandidate(model string, tier Tier) ModelCandidate {
	return ModelCandidate{Model: model, Tier: tier, Shape: ShapeAnthropic}
}

// ---------------------------------------------------------------- quality_floor

func TestQualityFloorBasis_Rows(t *testing.T) {
	t.Parallel()
	qf := basisRegistry[BasisQualityFloor].(FilterBasis)
	planFloorSonnet := &Policy{Floors: map[TurnKind]Tier{TurnPlan: TierSonnetClass}}
	cases := []struct {
		name   string
		policy *Policy
		kind   TurnKind
		cand   ModelCandidate
		want   bool
	}{
		{"below_explicit_floor_denied", planFloorSonnet, TurnPlan, anthCandidate("claude-haiku-4-5", TierHaikuClass), false},
		{"at_explicit_floor_allowed", planFloorSonnet, TurnPlan, anthCandidate("claude-sonnet-4-6", TierSonnetClass), true},
		{"kind_absent_floors_at_haiku", planFloorSonnet, TurnReadOnly, anthCandidate("claude-haiku-4-5", TierHaikuClass), true},
		{"kind_absent_denies_free", planFloorSonnet, TurnReadOnly, ModelCandidate{Model: "gpt-5-nano", Tier: TierFree, Shape: ShapeOpenAI}, false},
		{"nil_policy_floors_at_haiku", nil, TurnReadOnly, ModelCandidate{Model: "ollama/x", Tier: TierLocal, Shape: ShapeOpenAI}, false},
		{"free_floor_admits_free", &Policy{Floors: map[TurnKind]Tier{TurnHousekeeping: TierFree}}, TurnHousekeeping, ModelCandidate{Model: "gpt-5-nano", Tier: TierFree, Shape: ShapeOpenAI}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, reason := qf.Allow(tc.cand, BasisInput{Kind: tc.kind, Policy: tc.policy})
			if got != tc.want {
				t.Fatalf("Allow = %v, want %v", got, tc.want)
			}
			if !tc.want && reason != ReasonQualityFloorHold {
				t.Errorf("reason = %q, want quality_floor_hold", reason)
			}
		})
	}
}

// ---------------------------------------------------------------- privacy

func TestPrivacyBasis_Rows(t *testing.T) {
	t.Parallel()
	pb := basisRegistry[BasisPrivacy].(FilterBasis)
	cloud := anthCandidate("claude-haiku-4-5", TierHaikuClass)
	local := ModelCandidate{Model: "ollama/llama4", Tier: TierLocal, Shape: ShapeOpenAI}
	routed := ModelCandidate{Model: "openrouter/claude-haiku-4-5", Tier: TierHaikuClass, Shape: ShapeAnthropic}
	cases := []struct {
		name  string
		rules []PrivacyRule
		in    DecisionInput
		cand  ModelCandidate
		want  bool
	}{
		{
			name:  "local_only_denies_cloud",
			rules: []PrivacyRule{{Project: "internal-ml", LocalOnly: true}},
			in:    DecisionInput{Project: "internal-ml"},
			cand:  cloud,
			want:  false,
		},
		{
			name:  "local_only_allows_local",
			rules: []PrivacyRule{{Project: "internal-ml", LocalOnly: true}},
			in:    DecisionInput{Project: "internal-ml"},
			cand:  local,
			want:  true,
		},
		{
			name:  "selector_project_mismatch_is_noop",
			rules: []PrivacyRule{{Project: "internal-ml", LocalOnly: true}},
			in:    DecisionInput{Project: "public-site"},
			cand:  cloud,
			want:  true,
		},
		{
			name:  "path_class_selector_fires_on_hit",
			rules: []PrivacyRule{{PathClass: "secrets", DenyProviders: []string{"openrouter"}}},
			in:    DecisionInput{PathClassHits: []string{"secrets"}},
			cand:  routed,
			want:  false,
		},
		{
			name:  "path_class_selector_quiet_without_hit",
			rules: []PrivacyRule{{PathClass: "secrets", DenyProviders: []string{"openrouter"}}},
			in:    DecisionInput{},
			cand:  routed,
			want:  true,
		},
		{
			name:  "deny_star_allow_list",
			rules: []PrivacyRule{{Project: "p", DenyProviders: []string{"*"}, AllowProviders: []string{"local"}}},
			in:    DecisionInput{Project: "p"},
			cand:  cloud,
			want:  false,
		},
		{
			name:  "deny_star_allow_list_admits_allowed",
			rules: []PrivacyRule{{Project: "p", DenyProviders: []string{"*"}, AllowProviders: []string{"local"}}},
			in:    DecisionInput{Project: "p"},
			cand:  local,
			want:  true,
		},
		{
			name:  "specific_deny_leaves_others",
			rules: []PrivacyRule{{Project: "p", DenyProviders: []string{"openrouter"}}},
			in:    DecisionInput{Project: "p"},
			cand:  cloud,
			want:  true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			pol := &Policy{PrivacyRules: tc.rules}
			got, reason := pb.Allow(tc.cand, BasisInput{In: tc.in, Policy: pol})
			if got != tc.want {
				t.Fatalf("Allow = %v, want %v", got, tc.want)
			}
			if !tc.want && reason != ReasonPrivacyHold {
				t.Errorf("reason = %q, want privacy_hold", reason)
			}
		})
	}
}

// ---------------------------------------------------------------- cost_minimize

func TestCostMinimizeBasis_Rows(t *testing.T) {
	t.Parallel()
	cm := basisRegistry[BasisCostMinimize].(RankBasis)
	snap := testSnapshot()

	t.Run("cheaper_model_lower_key", func(t *testing.T) {
		t.Parallel()
		bin := BasisInput{In: readOnlyInput(), Snap: snap}
		haiku := cm.Key(anthCandidate("claude-haiku-4-5", TierHaikuClass), bin)
		opus := cm.Key(anthCandidate("claude-opus-4-8", TierOpusClass), bin)
		if haiku >= opus {
			t.Errorf("haiku key %v not below opus key %v", haiku, opus)
		}
	})

	t.Run("forfeit_added_to_switch_candidates_only", func(t *testing.T) {
		t.Parallel()
		in := readOnlyInput()
		in.Session.PriorCacheReadTokens = 500_000
		bin := BasisInput{In: in, Snap: snap}
		cold := cm.Key(anthCandidate("claude-haiku-4-5", TierHaikuClass), BasisInput{In: readOnlyInput(), Snap: snap})
		warm := cm.Key(anthCandidate("claude-haiku-4-5", TierHaikuClass), bin)
		if warm <= cold {
			t.Errorf("warm-prefix switch key %v not above cold key %v (forfeit missing)", warm, cold)
		}
		// The incumbent pays no forfeit.
		incCold := cm.Key(anthCandidate("claude-opus-4-8", TierOpusClass), BasisInput{In: readOnlyInput(), Snap: snap})
		incWarm := cm.Key(anthCandidate("claude-opus-4-8", TierOpusClass), bin)
		if incWarm != incCold {
			t.Errorf("incumbent key moved with warm prefix: %v != %v", incWarm, incCold)
		}
	})

	t.Run("unpriceable_ranks_after_priced_cheaper_tier_first", func(t *testing.T) {
		t.Parallel()
		bin := BasisInput{In: readOnlyInput(), Snap: snap}
		mystery := cm.Key(anthCandidate("claude-mystery", TierSonnetClass), bin)
		priced := cm.Key(anthCandidate("claude-opus-4-8", TierOpusClass), bin)
		if mystery <= priced {
			t.Errorf("unpriceable key %v not after priced %v", mystery, priced)
		}
		mysteryHaiku := cm.Key(anthCandidate("claude-mystery-mini", TierHaikuClass), bin)
		if mysteryHaiku >= mystery {
			t.Errorf("unpriceable haiku-class %v not before unpriceable sonnet-class %v", mysteryHaiku, mystery)
		}
	})

	t.Run("live_path_estimates_from_prompt_tokens", func(t *testing.T) {
		t.Parallel()
		in := DecisionInput{Shape: TurnShape{Model: "claude-opus-4-8", PromptTokens: 100_000}}
		bin := BasisInput{In: in, Snap: snap}
		haiku := cm.Key(anthCandidate("claude-haiku-4-5", TierHaikuClass), bin)
		opus := cm.Key(anthCandidate("claude-opus-4-8", TierOpusClass), bin)
		if haiku >= opus {
			t.Errorf("live estimate: haiku %v not below opus %v", haiku, opus)
		}
	})
}

// ---------------------------------------------------------------- latency

func TestLatencyBasis_Rows(t *testing.T) {
	t.Parallel()
	lb := basisRegistry[BasisLatency].(RankBasis)
	snap := testSnapshot()
	snap.LatencyP75Ms = map[string]int64{
		"claude-haiku-4-5": 800,
		"claude-opus-4-8":  4200,
	}
	bin := BasisInput{Snap: snap}
	if lb.Key(anthCandidate("claude-haiku-4-5", TierHaikuClass), bin) >= lb.Key(anthCandidate("claude-opus-4-8", TierOpusClass), bin) {
		t.Error("observed-faster model does not rank first")
	}
	unobserved := lb.Key(anthCandidate("claude-sonnet-4-6", TierSonnetClass), bin)
	if unobserved <= lb.Key(anthCandidate("claude-opus-4-8", TierOpusClass), bin) {
		t.Error("unobserved model ranks before observed one (no data, no preference)")
	}
}

// ---------------------------------------------------------------- quality_max

func TestQualityMaxBasis_Rows(t *testing.T) {
	t.Parallel()
	qm := basisRegistry[BasisQualityMax].(RankBasis)
	if qm.Key(anthCandidate("claude-opus-4-8", TierOpusClass), BasisInput{}) >=
		qm.Key(anthCandidate("claude-haiku-4-5", TierHaikuClass), BasisInput{}) {
		t.Error("higher tier does not rank first under quality_max")
	}
}

// ---------------------------------------------------------------- budget

func TestBudgetBasis_Rows(t *testing.T) {
	t.Parallel()
	bb := basisRegistry[BasisBudget].(ModifierBasis)
	scope := func(burnFraction float64, exhausted string) *Snapshot {
		s := testSnapshot()
		s.BudgetBurn = []BudgetBurnState{{
			Scope: "global", LimitUSD: 100, SpentUSD: burnFraction * 100,
			Window: "week", Bands: DefaultBudgetBands, Exhausted: exhausted,
		}}
		return s
	}
	cases := []struct {
		name        string
		snap        *Snapshot
		in          DecisionInput
		wantCap     Tier
		wantAll     bool
		wantAdvise  bool
		wantStop    bool
		wantReasons []ReasonCode
	}{
		{
			name: "below_first_band_noop",
			snap: scope(0.4, ""),
		},
		{
			name:        "band_50_caps_sonnet",
			snap:        scope(0.6, ""),
			wantCap:     TierSonnetClass,
			wantReasons: []ReasonCode{ReasonBudgetBand50},
		},
		{
			name:        "band_80_caps_haiku",
			snap:        scope(0.85, ""),
			wantCap:     TierHaikuClass,
			wantReasons: []ReasonCode{ReasonBudgetBand80},
		},
		{
			name:        "band_95_caps_haiku",
			snap:        scope(0.97, ""),
			wantCap:     TierHaikuClass,
			wantReasons: []ReasonCode{ReasonBudgetBand95},
		},
		{
			name:        "exhausted_default_advise_only",
			snap:        scope(1.05, ""),
			wantCap:     TierHaikuClass,
			wantAdvise:  true,
			wantReasons: []ReasonCode{ReasonBudgetBand95, ReasonBudgetExhausted},
		},
		{
			name:        "exhausted_degrade_all",
			snap:        scope(1.05, BudgetDegradeAll),
			wantCap:     TierHaikuClass,
			wantAll:     true,
			wantReasons: []ReasonCode{ReasonBudgetBand95, ReasonBudgetExhausted},
		},
		{
			name:        "exhausted_hard_stop_flagged_and_recorded",
			snap:        scope(1.05, BudgetHardStop),
			wantCap:     TierHaikuClass,
			wantAll:     true,
			wantStop:    true,
			wantReasons: []ReasonCode{ReasonBudgetBand95, ReasonBudgetExhausted, ReasonBudgetHardStop},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			mod := bb.Modify(BasisInput{In: tc.in, Snap: tc.snap})
			if mod.TierCap != tc.wantCap || mod.TierCapAllKinds != tc.wantAll ||
				mod.AdviseOnly != tc.wantAdvise || mod.HardStop != tc.wantStop {
				t.Fatalf("modifier = %+v", mod)
			}
			if len(mod.Reasons) != len(tc.wantReasons) {
				t.Fatalf("reasons = %v, want %v", mod.Reasons, tc.wantReasons)
			}
			for i := range tc.wantReasons {
				if mod.Reasons[i] != tc.wantReasons[i] {
					t.Errorf("reasons = %v, want %v", mod.Reasons, tc.wantReasons)
				}
			}
		})
	}

	t.Run("scoped_budget_needs_scope_key", func(t *testing.T) {
		t.Parallel()
		s := testSnapshot()
		s.BudgetBurn = []BudgetBurnState{{
			Scope: "project:acme", LimitUSD: 100, SpentUSD: 90,
			Window: "week", Bands: DefaultBudgetBands,
		}}
		if mod := bb.Modify(BasisInput{In: DecisionInput{}, Snap: s}); mod.TierCap != "" {
			t.Errorf("scope acted without its key: %+v", mod)
		}
		in := DecisionInput{ScopeKeys: []string{"project:acme"}}
		if mod := bb.Modify(BasisInput{In: in, Snap: s}); mod.TierCap != TierHaikuClass {
			t.Errorf("scoped burn 0.9 should cap haiku: %+v", mod)
		}
	})
}

// ---------------------------------------------------------------- availability

func TestAvailabilityBasis_Rows(t *testing.T) {
	t.Parallel()
	ab := basisRegistry[BasisAvailability].(ModifierBasis)
	snap := testSnapshot()
	snap.Health = map[string]HealthState{
		"claude-haiku-4-5":  HealthOpen,
		"claude-opus-4-8":   HealthDegraded,
		"claude-sonnet-4-6": HealthHalfOpen,
	}
	mod := ab.Modify(BasisInput{Snap: snap})
	if len(mod.ExcludeModels) != 1 || mod.ExcludeModels[0] != "claude-haiku-4-5" {
		t.Errorf("exclusions = %v, want only the OPEN breaker", mod.ExcludeModels)
	}
	if len(mod.Reasons) != 1 || mod.Reasons[0] != ReasonAvailabilityFallback {
		t.Errorf("reasons = %v", mod.Reasons)
	}
	if m := ab.Modify(BasisInput{Snap: testSnapshot()}); len(m.ExcludeModels) != 0 {
		t.Errorf("no health data still excluded: %v", m.ExcludeModels)
	}
}

// ---------------------------------------------------------------- rate_limit_window

func TestRateLimitWindowBasis_Rows(t *testing.T) {
	t.Parallel()
	rl := basisRegistry[BasisRateLimitWindow].(ModifierBasis)
	enabled := &Policy{RateLimit: RateLimitPolicy{Enabled: true, HeadroomPct: 15}}
	pressured := testSnapshot()
	pressured.Window = &WindowState{BurnFraction: 0.9, ProjectedExhaustion: true}
	relaxed := testSnapshot()
	relaxed.Window = &WindowState{BurnFraction: 0.4}

	if mod := rl.Modify(BasisInput{Policy: enabled, Snap: pressured}); mod.TierCap != TierHaikuClass ||
		len(mod.Reasons) != 1 || mod.Reasons[0] != ReasonRateLimitWindow {
		t.Errorf("pressured window: %+v", mod)
	}
	if mod := rl.Modify(BasisInput{Policy: enabled, Snap: relaxed}); mod.TierCap != "" {
		t.Errorf("relaxed window acted: %+v", mod)
	}
	disabled := &Policy{RateLimit: RateLimitPolicy{Enabled: false}}
	if mod := rl.Modify(BasisInput{Policy: disabled, Snap: pressured}); mod.TierCap != "" {
		t.Errorf("disabled feature acted: %+v", mod)
	}
	if mod := rl.Modify(BasisInput{Policy: enabled, Snap: testSnapshot()}); mod.TierCap != "" {
		t.Errorf("nil window state acted: %+v", mod)
	}
}

// ---------------------------------------------------------------- phase sugar

func TestPhaseBasis_CompilesToRules(t *testing.T) {
	t.Parallel()
	p, issues := Compile(PolicySpec{
		Policy: "custom",
		Bases:  []string{BasisCapability, BasisCostMinimize, BasisPhase},
		Rules: []RuleSpec{{
			Name:   "reads",
			When:   WhenSpec{TurnKind: "read_only", TierAtLeast: "sonnet-class"},
			Action: ActionSpec{RouteToTier: "haiku-class", Reason: "overpowered_read"},
		}},
	})
	if LintHasErrors(issues) {
		t.Fatalf("lint errors: %+v", issues)
	}
	if len(p.Rules) != 2 || p.Rules[0].Name != "phase_plan_pin" || !p.Rules[0].Action.NoRoute {
		t.Fatalf("phase sugar did not prepend the plan pin: %+v", p.Rules)
	}
	for _, b := range p.Bases {
		if b == BasisPhase {
			t.Error("phase sugar left in the basis list (it has no evaluator)")
		}
	}
	// Idempotence: a policy that already pins plan gets no duplicate.
	p2, _ := Compile(PolicySpec{
		Policy: "plan-exec",
		Bases:  append([]string{}, append(TemplateMustGet(t, "plan-exec").Bases, BasisPhase)...),
	})
	count := 0
	for _, r := range p2.Rules {
		if len(r.When.TurnKinds) == 1 && r.When.TurnKinds[0] == TurnPlan {
			count++
		}
	}
	if count != 1 {
		t.Errorf("plan rules = %d, want 1 (no duplicate from sugar)", count)
	}
}

func TemplateMustGet(t *testing.T, name string) Policy {
	t.Helper()
	p, ok := TemplateByName(name)
	if !ok {
		t.Fatalf("template %s missing", name)
	}
	return p
}

// ---------------------------------------------------------------- engine integration

// TestDecide_BudgetDemotionWithoutRule pins the no-rule §R14 path: a
// soft turn under burn-band pressure demotes to the pipeline's best
// surviving candidate; a hard turn does not.
func TestDecide_BudgetDemotionWithoutRule(t *testing.T) {
	t.Parallel()
	snap := testSnapshot()
	snap.BudgetBurn = []BudgetBurnState{{
		Scope: "global", LimitUSD: 100, SpentUSD: 85,
		Window: "week", Bands: DefaultBudgetBands,
	}}
	p := Policy{Name: "custom", Bases: defaultBases(), Floors: defaultFloors()}

	d := Decide(p, snap, readOnlyInput())
	if !d.Changed || d.SelectedModel != "claude-haiku-4-5" {
		t.Fatalf("soft turn under band 80 not demoted: %+v", d)
	}
	if !hasReason(d.ReasonCodes, ReasonBudgetBand80) {
		t.Errorf("reasons = %v, want budget_band_80", d.ReasonCodes)
	}

	// A plan turn holds its tier (§R14: plan/edit floors hold).
	in := readOnlyInput()
	in.Session.ClientPhase = "plan"
	d = Decide(p, snap, in)
	if d.Changed {
		t.Fatalf("plan turn demoted by budget band: %+v", d)
	}
}

// TestDecide_BudgetExhaustedAdviseOnly pins the §R14 advise_only
// exhaustion behavior: the decision changes but is flagged AdviseOnly.
func TestDecide_BudgetExhaustedAdviseOnly(t *testing.T) {
	t.Parallel()
	snap := testSnapshot()
	snap.BudgetBurn = []BudgetBurnState{{
		Scope: "global", LimitUSD: 100, SpentUSD: 105,
		Window: "week", Bands: DefaultBudgetBands, Exhausted: BudgetAdviseOnly,
	}}
	p := Policy{Name: "custom", Bases: defaultBases(), Floors: defaultFloors()}
	d := Decide(p, snap, readOnlyInput())
	if !d.AdviseOnly {
		t.Fatalf("advise_only exhaustion not flagged: %+v", d)
	}
}

// TestDecide_PrivacyEnforcementWithoutRule pins §R16: a privacy-denied
// incumbent with NO conforming candidate stays put with a loud
// privacy_hold row — G7, never a broken turn.
func TestDecide_PrivacyEnforcementWithoutRule(t *testing.T) {
	t.Parallel()
	p := Policy{
		Name: "custom", Bases: defaultBases(), Floors: defaultFloors(),
		PrivacyRules: []PrivacyRule{{Project: "internal-ml", LocalOnly: true}},
	}
	in := readOnlyInput()
	in.Project = "internal-ml"
	d := Decide(p, testSnapshot(), in)
	if d.Changed {
		t.Fatalf("no local candidate exists, yet the turn moved: %+v", d)
	}
	if !hasReason(d.ReasonCodes, ReasonPrivacyHold) {
		t.Errorf("reasons = %v, want privacy_hold", d.ReasonCodes)
	}
}

// TestDecide_AvailabilityExclusionRedirectsRule pins §R12.3 + rule
// interplay: the rule's haiku target sits behind an OPEN breaker, so
// the pipeline's next survivor (sonnet) takes the turn.
func TestDecide_AvailabilityExclusionRedirectsRule(t *testing.T) {
	t.Parallel()
	snap := testSnapshot()
	snap.Health = map[string]HealthState{"claude-haiku-4-5": HealthOpen}
	d := Decide(valuePolicy(t), snap, readOnlyInput())
	if !d.Changed || d.SelectedModel != "claude-sonnet-4-6" {
		t.Fatalf("decision = %+v, want redirect to sonnet (haiku breaker open)", d)
	}
}

// TestDecide_QualityFloorRedirectsRuleTarget pins floor-vs-rule: with
// a read_only floor of sonnet-class, the rule's haiku target is denied
// and the downshift lands on the floor instead — both the floor AND
// the cost intent are honored.
func TestDecide_QualityFloorRedirectsRuleTarget(t *testing.T) {
	t.Parallel()
	p := valuePolicy(t)
	p.Floors = map[TurnKind]Tier{TurnReadOnly: TierSonnetClass}
	d := Decide(p, testSnapshot(), readOnlyInput())
	if !d.Changed || d.SelectedModel != "claude-sonnet-4-6" {
		t.Fatalf("decision = %+v, want floor-respecting downshift to sonnet", d)
	}

	// With the floor AT the original tier, no downshift is legal: hold.
	p.Floors = map[TurnKind]Tier{TurnReadOnly: TierOpusClass}
	d = Decide(p, testSnapshot(), readOnlyInput())
	if d.Changed {
		t.Fatalf("floor at original tier still moved: %+v", d)
	}
	if !hasReason(d.ReasonCodes, ReasonQualityFloorHold) {
		t.Errorf("reasons = %v, want quality_floor_hold", d.ReasonCodes)
	}
}

// TestClassifierWindowStillKind sanity-pins that the new pipeline kept
// the classifier contract intact for a mixed window.
func TestClassifierWindowStillKind(t *testing.T) {
	t.Parallel()
	in := readOnlyInput()
	in.Session.RecentActions = append(in.Session.RecentActions, ActionSignal{Type: models.ActionEditFile, Success: true})
	d := Decide(valuePolicy(t), testSnapshot(), in)
	if d.TurnKind != TurnEdit {
		t.Errorf("kind = %s, want edit", d.TurnKind)
	}
}
