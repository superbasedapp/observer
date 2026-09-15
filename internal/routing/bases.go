package routing

import "strings"

// The shipped bases (§R6.2). Each is a small, stateless evaluator over
// BasisInput; the FIXED composition in RunPipeline (filters intersect →
// rankers order → modifiers adjust → re-run once) is the only way they
// combine. One test per basis per behavior row in bases_test.go.

func init() {
	for _, b := range []Basis{
		qualityFloorBasis{},
		privacyBasis{},
		costMinimizeBasis{},
		latencyBasis{},
		qualityMaxBasis{},
		budgetBasis{},
		availabilityBasis{},
		rateLimitWindowBasis{},
	} {
		basisRegistry[b.Name()] = b
	}
	// BasisPhase is rule sugar (§R6.2): it compiles to rules in
	// Compile/expandPhaseBasis and has no runtime evaluator.
}

// ---------------------------------------------------------------- quality_floor

// qualityFloorBasis denies candidates below the policy's per-turn-kind
// floor (§R6.2). A kind absent from Floors (or a nil map) floors at
// haiku-class — the engine never auto-routes below the smallest paid
// class without an explicit floor saying so.
type qualityFloorBasis struct{}

func (qualityFloorBasis) Name() string      { return BasisQualityFloor }
func (qualityFloorBasis) Class() BasisClass { return ClassFilter }

func (qualityFloorBasis) Allow(c ModelCandidate, bin BasisInput) (bool, ReasonCode) {
	floor := TierHaikuClass
	if bin.Policy != nil {
		if f, ok := bin.Policy.Floors[bin.Kind]; ok {
			floor = f
		}
	}
	if c.Tier.Rank() < floor.Rank() {
		return false, ReasonQualityFloorHold
	}
	return true, ""
}

// ---------------------------------------------------------------- privacy

// privacyBasis is the §R16 hard filter: per-project / per-path-class
// provider constraints. Selectors were resolved at the boundary into
// DecisionInput.Project + PathClassHits — no path content here.
type privacyBasis struct{}

func (privacyBasis) Name() string      { return BasisPrivacy }
func (privacyBasis) Class() BasisClass { return ClassFilter }

func (privacyBasis) Allow(c ModelCandidate, bin BasisInput) (bool, ReasonCode) {
	if bin.Policy == nil {
		return true, ""
	}
	for _, rule := range bin.Policy.PrivacyRules {
		if !rule.AppliesTo(bin.In) {
			continue
		}
		if !privacyRuleAllows(rule, c) {
			return false, ReasonPrivacyHold
		}
	}
	return true, ""
}

// privacyRuleAllows evaluates one matching privacy rule against a
// candidate's provider class.
func privacyRuleAllows(rule PrivacyRule, c ModelCandidate) bool {
	class := providerClassForCandidate(c)
	if rule.LocalOnly {
		return class == "local"
	}
	if containsString(rule.AllowProviders, class) {
		return true
	}
	if containsString(rule.DenyProviders, "*") {
		// Deny-all-except-allowed; the allow list was already checked.
		return false
	}
	return !containsString(rule.DenyProviders, class)
}

// providerClassForCandidate resolves the provider-class vocabulary the
// privacy rules speak: "local" for local-tier models, the router host
// for path-prefixed slugs ("openrouter/..."), else the wire shape's
// provider name.
func providerClassForCandidate(c ModelCandidate) string {
	if c.Tier == TierLocal {
		return "local"
	}
	if i := strings.Index(c.Model, "/"); i > 0 {
		return strings.ToLower(c.Model[:i])
	}
	switch c.Shape {
	case ShapeAnthropic:
		return "anthropic"
	case ShapeOpenAI:
		return "openai"
	case ShapeGoogle:
		return "google"
	default:
		return "unknown"
	}
}

// ---------------------------------------------------------------- cost_minimize

// costMinimizeBasis ranks candidates by effective cost (§R13):
//
//	effective_cost = est_prompt_cost(candidate) + cache_forfeit(switch)
//
// The expected-cache-savings term from the §R13 formula is deliberately
// omitted in p1-v1: estimating a stickiness horizon is speculative, and
// omitting the credit only OVERSTATES switch cost — the conservative
// direction (stickier, never cheaper-than-real). The estimate version
// on the decision row lets calibration grade this choice.
//
// Pricing: the observed bundle when present (replay), else a coarse
// {Input: PromptTokens} estimate (live). Unpriceable candidates rank by
// tier (cheaper class first) after all priced ones.
type costMinimizeBasis struct{}

func (costMinimizeBasis) Name() string      { return BasisCostMinimize }
func (costMinimizeBasis) Class() BasisClass { return ClassRank }

func (costMinimizeBasis) Key(c ModelCandidate, bin BasisInput) float64 {
	if bin.Snap == nil || bin.Snap.Price == nil {
		return unpricedRankKey(c)
	}
	bundle := PromptUsage{Input: bin.In.Shape.PromptTokens}
	if bin.In.ObservedUsage != nil {
		bundle = *bin.In.ObservedUsage
	}
	cost, ok := bin.Snap.Price(c.Model, bundle)
	if !ok {
		return unpricedRankKey(c)
	}
	if c.Model != bin.In.Shape.Model && bin.In.Session.PriorCacheReadTokens > 0 {
		if forfeit, fok := bin.Snap.Price(c.Model, PromptUsage{CacheCreation: bin.In.Session.PriorCacheReadTokens}); fok {
			cost += forfeit
		}
	}
	return cost
}

// unpricedRankKey sorts unpriceable candidates after every plausible
// priced cost, ordered cheaper-tier-first among themselves.
func unpricedRankKey(c ModelCandidate) float64 {
	return 1e12 + float64(c.Tier.Rank())
}

// ---------------------------------------------------------------- latency

// latencyBasis ranks by observed p75 total latency (§R6.2). Candidates
// with no observation rank after every observed one — no data, no
// preference.
type latencyBasis struct{}

func (latencyBasis) Name() string      { return BasisLatency }
func (latencyBasis) Class() BasisClass { return ClassRank }

func (latencyBasis) Key(c ModelCandidate, bin BasisInput) float64 {
	if bin.Snap != nil {
		if p75, ok := bin.Snap.LatencyP75Ms[c.Model]; ok && p75 > 0 {
			return float64(p75)
		}
	}
	return 1e12
}

// ---------------------------------------------------------------- quality_max

// qualityMaxBasis ranks by descending tier — "the best model my
// constraints allow" (§R6.2).
type qualityMaxBasis struct{}

func (qualityMaxBasis) Name() string      { return BasisQualityMax }
func (qualityMaxBasis) Class() BasisClass { return ClassRank }

func (qualityMaxBasis) Key(c ModelCandidate, _ BasisInput) float64 {
	return -float64(c.Tier.Rank())
}

// ---------------------------------------------------------------- budget

// budgetBasis is the §R14 modifier: as the worst-burning matching scope
// crosses its burn bands, the max allowed tier for SOFT kinds steps
// down (sonnet-class, then haiku-class); plan/edit floors hold. At
// 100% the scope's configured behavior fires:
//
//   - advise_only — the cap stays and the decision is logged without
//     acting (Decision.AdviseOnly).
//   - degrade_all — the cap extends to every turn-kind.
//   - hard_stop   — the degrade_all cap PLUS Modifier.HardStop, which the
//     engine threads onto Decision.HardStop and records on the decision
//     row as ReasonBudgetHardStop (G1-HARDSTOP). The engine itself never
//     blocks a turn (G7): blocking is a boundary-channel decision made
//     only in enforce mode by a channel that has a deny outcome. Outside
//     enforce mode hard_stop degrades exactly like degrade_all and the
//     operator sees budget_hard_stop rows and the dashboard burn-down.
type budgetBasis struct{}

func (budgetBasis) Name() string      { return BasisBudget }
func (budgetBasis) Class() BasisClass { return ClassModifier }

func (budgetBasis) Modify(bin BasisInput) Modifier {
	if bin.Snap == nil {
		return Modifier{}
	}
	var worst *BudgetBurnState
	worstBurn := 0.0
	for i := range bin.Snap.BudgetBurn {
		b := &bin.Snap.BudgetBurn[i]
		if b.Scope != "global" && !containsString(bin.In.ScopeKeys, b.Scope) {
			continue
		}
		if burn := b.Burn(); burn > worstBurn {
			worst, worstBurn = b, burn
		}
	}
	if worst == nil {
		return Modifier{}
	}
	bands := worst.Bands
	if len(bands) == 0 {
		bands = DefaultBudgetBands
	}
	crossed := 0
	for _, band := range bands {
		if worstBurn >= band {
			crossed++
		}
	}
	if crossed == 0 && worstBurn < 1.0 {
		return Modifier{}
	}

	var mod Modifier
	// Progressive demotion (§R14): first band caps at sonnet-class,
	// every further band at haiku-class. The quality_floor filter
	// keeps the cap from pushing below the policy's floors.
	switch {
	case crossed == 1:
		mod.TierCap = TierSonnetClass
	case crossed >= 2:
		mod.TierCap = TierHaikuClass
	}
	mod.Reasons = append(mod.Reasons, budgetRegionReason(worstBurn))

	if worstBurn >= 1.0 {
		mod.Reasons = append(mod.Reasons, ReasonBudgetExhausted)
		mod.TierCap = TierHaikuClass
		switch worst.Exhausted {
		case BudgetDegradeAll:
			mod.TierCapAllKinds = true
		case BudgetHardStop:
			mod.TierCapAllKinds = true
			mod.HardStop = true
			mod.Reasons = append(mod.Reasons, ReasonBudgetHardStop)
		default: // advise_only (and the compile-time default)
			mod.AdviseOnly = true
		}
	}
	return mod
}

// budgetRegionReason maps a burn fraction to the standard §R9.1 region
// code. Custom band values control WHEN demotion steps fire; the
// reason code reports the burn region so dashboard aggregation stays
// stable across configs.
func budgetRegionReason(burn float64) ReasonCode {
	switch {
	case burn >= 0.95:
		return ReasonBudgetBand95
	case burn >= 0.8:
		return ReasonBudgetBand80
	default:
		return ReasonBudgetBand50
	}
}

// ---------------------------------------------------------------- availability

// availabilityBasis is the §R12.3 modifier: models whose circuit
// breaker is OPEN are excluded from candidacy. Degraded models stay
// candidates (rankers may still prefer them); half-open models stay
// candidates — the next natural request IS the probe.
type availabilityBasis struct{}

func (availabilityBasis) Name() string      { return BasisAvailability }
func (availabilityBasis) Class() BasisClass { return ClassModifier }

func (availabilityBasis) Modify(bin BasisInput) Modifier {
	if bin.Snap == nil || len(bin.Snap.Health) == 0 {
		return Modifier{}
	}
	var mod Modifier
	for model, state := range bin.Snap.Health {
		if state == HealthOpen {
			mod.ExcludeModels = append(mod.ExcludeModels, model)
		}
	}
	if len(mod.ExcludeModels) > 0 {
		// Deterministic exclusion order for stable decision rows.
		sortStrings(mod.ExcludeModels)
		mod.Reasons = append(mod.Reasons, ReasonAvailabilityFallback)
	}
	return mod
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}

// ---------------------------------------------------------------- rate_limit_window

// rateLimitWindowBasis is the §R15 modifier: when the learned
// subscription-window cadence projects the cap to be hit before reset
// (beyond the configured headroom), soft turn-kinds demote to preserve
// window headroom for plan/edit work. Pure observation — no provider
// API.
type rateLimitWindowBasis struct{}

func (rateLimitWindowBasis) Name() string      { return BasisRateLimitWindow }
func (rateLimitWindowBasis) Class() BasisClass { return ClassModifier }

func (rateLimitWindowBasis) Modify(bin BasisInput) Modifier {
	if bin.Policy == nil || !bin.Policy.RateLimit.Enabled {
		return Modifier{}
	}
	if bin.Snap == nil || bin.Snap.Window == nil || !bin.Snap.Window.ProjectedExhaustion {
		return Modifier{}
	}
	return Modifier{
		TierCap: TierHaikuClass,
		Reasons: []ReasonCode{ReasonRateLimitWindow},
	}
}
