package routing

// EstimateVersion versions the savings / cache-forfeit math so the
// calibration loop can grade the estimator itself (§R13). Bump whenever
// the dollar formulas below change.
//
// p1-v1 semantics:
//   - gross savings  = price(original, observed usage) − price(candidate,
//     observed usage): the same realized bundle re-priced at candidate
//     rates. Replay-exact; live paths without ObservedUsage report 0.
//   - cache forfeit  = price(candidate, {CacheCreation: prior turn's
//     cache_read}): re-creating the session's warm prefix at the
//     candidate's cache-write rate.
//   - EstSavingsUSD  = gross − forfeit (net). A switch is held with
//     ReasonCacheHold when the net is negative (§R13: stickiness from
//     math, not a timer).
//   - cost_minimize ranking omits the §R13 expected-cache-savings
//     credit (conservative: switches look more expensive, never
//     cheaper, than reality) — see costMinimizeBasis.
const EstimateVersion = "p1-v1"

// Decide evaluates one request against a policy and snapshot (§R9).
// Pure and deterministic given (policy, snapshot, input) — replayable by
// construction, which is what makes simulate counterfactuals
// trustworthy (§R9.3). Every guard fails open: the original model passes
// through with a reason code, never an error (G7).
//
// Flow: classify → tier-place → run the basis pipeline over the
// same-shape candidate set (filters intersect → rankers order →
// modifiers adjust, §R6.2) → walk the rule table top-down (first match
// wins, §24.5) and resolve the matched intent against the pipeline's
// survivors → with no rule, apply privacy enforcement and modifier
// demotions from the pipeline alone.
func Decide(p Policy, snap *Snapshot, in DecisionInput) Decision {
	d := Decision{
		OriginalModel:   in.Shape.Model,
		SelectedModel:   in.Shape.Model,
		PolicyName:      p.Name,
		PolicyHash:      p.Hash(),
		EstimateVersion: EstimateVersion,
		TurnKind:        TurnUnknown,
	}
	if snap == nil || snap.Tiers == nil || snap.Stale || in.Shape.Model == "" {
		d.ReasonCodes = []ReasonCode{ReasonFailOpen}
		return d
	}

	cls := ClassifyTurnKind(in)
	d.TurnKind = cls.Kind
	if cls.Kind == TurnUnknown {
		// Never route an unknown turn (§R8.3).
		d.ReasonCodes = []ReasonCode{ReasonUnknownTurnKind}
		return d
	}

	tier, _ := snap.Tiers.Lookup(in.Shape.Model)
	if tier == TierUnclassified {
		// The engine refuses to reason about models it cannot place
		// (§R7.1).
		d.ReasonCodes = []ReasonCode{ReasonUnclassifiedModel}
		return d
	}

	// Cross-turn escalation (§R7.4): a downshifted turn of this kind
	// failed recently, so the kind runs at its pre-downshift tier —
	// the original model passes through and the row says why.
	// Calibration consumes these rows as negative evidence (§R18.3).
	for _, k := range in.Session.EscalatedKinds {
		if k == cls.Kind {
			d.ReasonCodes = []ReasonCode{ReasonEscalation}
			return d
		}
	}

	bases := resolveBases(p.Bases)
	bin := BasisInput{In: in, Kind: cls.Kind, OriginalTier: tier, Policy: &p, Snap: snap}
	res := RunPipeline(bases, assembleCandidates(snap.Tiers, in, tier), bin)
	d.AdviseOnly = res.Mod.AdviseOnly
	d.HardStop = res.Mod.HardStop

	mc := MatchContext{
		Kind:          cls.Kind,
		Tier:          tier,
		In:            in,
		BudgetBurnMax: budgetBurnMax(snap, in),
	}

	for _, r := range p.Rules {
		if !r.When.Matches(mc) {
			continue
		}
		d.RuleName = r.Name
		d = applyRule(r, snap, in, tier, p, d, bases, bin, res)
		if len(d.FallbackModels) == 0 {
			d.FallbackModels = resolveFallbacks(p, snap, d.SelectedModel)
		}
		return stampHardStop(d, res)
	}

	// No rule matched: privacy enforcement and modifier demotions still
	// apply from the pipeline alone; otherwise the quiet no-change
	// default. The fallback chain resolves either way so reliability
	// (§R12.1) covers unrouted turns too.
	d = stampHardStop(applyPipelineDefaults(snap, in, tier, p, d, res), res)
	if len(d.FallbackModels) == 0 {
		d.FallbackModels = resolveFallbacks(p, snap, d.SelectedModel)
	}
	return d
}

// assembleCandidates builds the pipeline's candidate set: the shape's
// curated tier representatives plus the original model itself.
func assembleCandidates(t *TierTable, in DecisionInput, origTier Tier) []ModelCandidate {
	shape := ShapeForModel(in.Shape.Model)
	cands := t.RepresentativesForShape(shape)
	for _, c := range cands {
		if c.Model == in.Shape.Model {
			return cands
		}
	}
	return append(cands, ModelCandidate{Model: in.Shape.Model, Tier: origTier, Shape: shape})
}

// applyRule resolves a matched rule into the final decision. First match
// wins — this function always returns.
func applyRule(r Rule, snap *Snapshot, in DecisionInput, tier Tier, p Policy, d Decision, bases []Basis, bin BasisInput, res PipelineResult) Decision {
	switch {
	case r.Action.NoRoute:
		d.ReasonCodes = []ReasonCode{ReasonNoRoute, r.Reason}
		return d

	case r.Action.SetEffort != "":
		// Effort routing (§R6.5): downshift effort instead of model —
		// zero cache loss, no tier-mapping risk. The model is untouched.
		d.SetEffort = r.Action.SetEffort
		d.ReasonCodes = []ReasonCode{ReasonEffortDownshift, r.Reason}
		return d

	case len(r.Action.SetFallbackChain) > 0:
		// Reliability sugar (§R12.1): override the fallback chain for
		// matching turns; the model is untouched.
		d.FallbackModels = r.Action.SetFallbackChain
		d.ReasonCodes = []ReasonCode{r.Reason}
		return d

	case len(r.Action.DenyProviders) > 0 || len(r.Action.AllowProviders) > 0:
		return applyProviderFilter(r, snap, in, d, res)

	case r.Action.PinTier != "":
		return applyPin(r, snap, in, tier, d, res)

	case r.Action.RouteToModel != "":
		return applyExplicitModel(r, snap, in, p, d, bases, bin, res)

	default:
		target := r.Action.RouteToTier
		if !target.DownshiftTargetable() || target.Rank() >= tier.Rank() {
			// Lint rejects templates that get here; a custom rule that
			// proposes a sideways/upward "downshift" or an untargetable
			// tier fails open.
			d.ReasonCodes = []ReasonCode{ReasonNoCandidate}
			return d
		}
		// The rule names an intent (≤ target tier); the pipeline's
		// surviving order picks the concrete model under the policy's
		// floors, privacy rules, and modifier caps.
		cand, ok := topAllowedAtOrBelow(res, target, in.Shape.Model)
		if ok {
			return applySwitch(r.Reason, snap, in, p, d, cand.Model)
		}
		// Target tier unavailable (breaker open, floor) but the
		// downshift intent can still be honored by the best survivor
		// strictly below the ORIGINAL tier (§R12.3 fallback behavior) —
		// annotated with the modifier's reasons so the deviation from
		// the rule's named target stays visible.
		if cand, ok = topAllowedBelow(res, tier, in.Shape.Model); ok {
			reasons := dedupReasons(append([]ReasonCode{r.Reason}, res.Mod.Reasons...))
			return applySwitchReasons(reasons, snap, in, p, d, cand.Model)
		}
		d.ReasonCodes = holdReasons(res, snap, in, target)
		return d
	}
}

// applyProviderFilter resolves a deny/allow-providers rule action
// (§R6.3): a synthetic privacy rule scoped to this turn. The selection
// reuses the pipeline's surviving rank order; the constraint is hard
// (privacy-class), so economics gates don't apply.
func applyProviderFilter(r Rule, snap *Snapshot, in DecisionInput, d Decision, res PipelineResult) Decision {
	synth := PrivacyRule{
		DenyProviders:  r.Action.DenyProviders,
		AllowProviders: r.Action.AllowProviders,
	}
	if st, ok := stateFor(res, in.Shape.Model); ok && st.Allowed && privacyRuleAllows(synth, st.ModelCandidate) {
		// The incumbent already satisfies the constraint: quiet stay,
		// attributed to the rule.
		d.ReasonCodes = []ReasonCode{r.Reason}
		return d
	}
	for _, c := range res.Allowed() {
		if c.Model == in.Shape.Model || !privacyRuleAllows(synth, c.ModelCandidate) {
			continue
		}
		gross, forfeit, priced := switchEconomics(snap.Price, in, c.Model)
		d.SelectedModel = c.Model
		d.Changed = true
		d.ReasonCodes = []ReasonCode{ReasonPrivacyHold, r.Reason}
		d.CacheForfeitUSD = forfeit
		if priced {
			d.EstSavingsUSD = gross - forfeit
		}
		return d
	}
	// No conforming candidate: the turn proceeds on its original model
	// (G7) with a loud hold row.
	d.ReasonCodes = []ReasonCode{ReasonPrivacyHold, r.Reason}
	return d
}

// applyPin resolves a pin_tier action: the turn runs on the pinned
// tier's same-shape representative, both directions (opusplan pins
// plan turns UP). Pins bypass stickiness and cache-hold — they are
// explicit quality intents — but the forfeit is still priced and
// recorded so the cost of the pin stays visible. Filters still vet the
// target: a pin never overrides capability or privacy.
func applyPin(r Rule, snap *Snapshot, in DecisionInput, tier Tier, d Decision, res PipelineResult) Decision {
	if tier == r.Action.PinTier {
		d.ReasonCodes = []ReasonCode{r.Reason}
		return d
	}
	shape := ShapeForModel(in.Shape.Model)
	candidate, ok := snap.Tiers.Representative(shape, r.Action.PinTier)
	if !ok || candidate == in.Shape.Model {
		d.ReasonCodes = []ReasonCode{ReasonNoCandidate}
		return d
	}
	if st, found := stateFor(res, candidate); found && !st.Allowed {
		d.ReasonCodes = dedupReasons(st.DenyReasons)
		return d
	}
	gross, forfeit, priced := switchEconomics(snap.Price, in, candidate)
	d.SelectedModel = candidate
	d.Changed = true
	d.ReasonCodes = []ReasonCode{r.Reason}
	d.CacheForfeitUSD = forfeit
	if priced {
		d.EstSavingsUSD = gross - forfeit
	}
	return d
}

// applyExplicitModel resolves a route_to_model action. The explicit
// target is vetted through every filter basis (it may not be in the
// curated candidate set) and the modifier cap, then runs the normal
// coherence + economics gates.
func applyExplicitModel(r Rule, snap *Snapshot, in DecisionInput, p Policy, d Decision, bases []Basis, bin BasisInput, res PipelineResult) Decision {
	target := r.Action.RouteToModel
	if target == in.Shape.Model {
		d.ReasonCodes = []ReasonCode{ReasonNoCandidate}
		return d
	}
	ctier, _ := snap.Tiers.Lookup(target)
	if ctier == TierUnclassified {
		d.ReasonCodes = []ReasonCode{ReasonUnclassifiedModel}
		return d
	}
	c := ModelCandidate{Model: target, Tier: ctier, Shape: ShapeForModel(target)}
	for _, b := range bases {
		f, ok := b.(FilterBasis)
		if !ok {
			continue
		}
		if allowed, reason := f.Allow(c, bin); !allowed {
			d.ReasonCodes = []ReasonCode{reason}
			return d
		}
	}
	if res.Mod.TierCap != "" && tierCapApplies(res.Mod, bin.Kind) && c.Tier.Rank() > res.Mod.TierCap.Rank() {
		d.ReasonCodes = dedupReasons(res.Mod.Reasons)
		return d
	}
	return applySwitch(r.Reason, snap, in, p, d, target)
}

// applyPipelineDefaults handles the no-rule-matched paths that the
// pipeline alone drives:
//
//  1. Privacy enforcement (§R16): an incumbent the privacy filter
//     denied moves to the top-ranked conforming candidate (hard
//     constraint — no economics gates); with no conforming candidate
//     the turn proceeds with a loud privacy_hold row (G7).
//  2. Modifier demotion (§R14/§R15): a tier cap below the incumbent's
//     tier moves soft-kind turns to the best surviving candidate,
//     through the normal coherence + economics gates.
//  3. Otherwise: the quiet no-change default.
func applyPipelineDefaults(snap *Snapshot, in DecisionInput, tier Tier, p Policy, d Decision, res PipelineResult) Decision {
	if st, ok := stateFor(res, in.Shape.Model); ok && !st.Allowed && hasReason(st.DenyReasons, ReasonPrivacyHold) {
		for _, c := range res.Allowed() {
			if c.Model == in.Shape.Model {
				continue
			}
			gross, forfeit, priced := switchEconomics(snap.Price, in, c.Model)
			d.SelectedModel = c.Model
			d.Changed = true
			d.ReasonCodes = dedupReasons(st.DenyReasons)
			d.CacheForfeitUSD = forfeit
			if priced {
				d.EstSavingsUSD = gross - forfeit
			}
			return d
		}
		d.ReasonCodes = dedupReasons(st.DenyReasons)
		return d
	}

	if res.Mod.TierCap != "" && tierCapApplies(res.Mod, d.TurnKind) && res.Mod.TierCap.Rank() < tier.Rank() {
		cand, ok := topAllowedAtOrBelow(res, res.Mod.TierCap, in.Shape.Model)
		if !ok {
			d.ReasonCodes = dedupReasons(res.Mod.Reasons)
			return d
		}
		d2 := applySwitchReasons(dedupReasons(res.Mod.Reasons), snap, in, p, d, cand.Model)
		return d2
	}
	return d
}

// applySwitch runs the coherence and economics gates (§R13) for a
// proposed model switch and commits it when they pass.
func applySwitch(reason ReasonCode, snap *Snapshot, in DecisionInput, p Policy, d Decision, candidate string) Decision {
	return applySwitchReasons([]ReasonCode{reason}, snap, in, p, d, candidate)
}

func applySwitchReasons(reasons []ReasonCode, snap *Snapshot, in DecisionInput, p Policy, d Decision, candidate string) Decision {
	// A switch target must stay same-shape (§R11.4) — an explicit
	// cross-shape target is refused, not attempted.
	if ShapeForModel(candidate) != ShapeForModel(in.Shape.Model) {
		d.ReasonCodes = []ReasonCode{ReasonCapabilityHold}
		return d
	}

	// Session coherence floor (§R13): a recent switch holds this one.
	// TurnsSinceSwitch < 0 means the session never switched.
	if p.MinTurnsBetweenSwitches > 0 &&
		in.Session.TurnsSinceSwitch >= 0 &&
		in.Session.TurnsSinceSwitch < p.MinTurnsBetweenSwitches {
		d.ReasonCodes = []ReasonCode{ReasonStickinessHold}
		return d
	}

	gross, forfeit, priced := switchEconomics(snap.Price, in, candidate)
	d.CacheForfeitUSD = forfeit
	if p.RespectCache && priced && gross-forfeit < 0 {
		// The warm cache is worth more than the switch saves: stay
		// (§R13 — the inverse of every market router). This is the
		// §R6.5 borderline case — the policy wanted to save money but
		// the cache math said no — so the decision carries the
		// zero-cache-loss alternative: an effort downshift suggestion
		// (the default suggestion for borderline cases; the proxy's
		// replace-only contract makes it a no-op for requests with no
		// effort fields).
		d.ReasonCodes = []ReasonCode{ReasonCacheHold, ReasonEffortDownshift}
		d.SetEffort = EffortLow
		d.EstSavingsUSD = gross - forfeit
		return d
	}

	d.SelectedModel = candidate
	d.Changed = true
	d.ReasonCodes = reasons
	if priced {
		d.EstSavingsUSD = gross - forfeit
	}
	return d
}

// switchEconomics prices a proposed switch under the p1-v1 estimate:
// gross saving from re-pricing the observed bundle, forfeit from
// re-creating the warm prefix. priced=false when the input carries no
// observed usage or either model is unpriceable — the engine then makes
// no dollar claim (and no cache-hold, which is a dollar claim too).
func switchEconomics(price PriceFn, in DecisionInput, candidate string) (gross, forfeit float64, priced bool) {
	if price == nil || in.ObservedUsage == nil {
		return 0, 0, false
	}
	origUSD, ok1 := price(in.Shape.Model, *in.ObservedUsage)
	candUSD, ok2 := price(candidate, *in.ObservedUsage)
	if !ok1 || !ok2 {
		return 0, 0, false
	}
	gross = origUSD - candUSD
	if in.Session.PriorCacheReadTokens > 0 {
		f, ok := price(candidate, PromptUsage{CacheCreation: in.Session.PriorCacheReadTokens})
		if ok {
			forfeit = f
		}
	}
	return gross, forfeit, true
}

// budgetBurnMax returns the highest burn fraction among the snapshot's
// budget scopes that apply to this turn: the global scope always
// applies; other scopes apply when the boundary listed their key in
// DecisionInput.ScopeKeys. Zero when no scope data exists.
func budgetBurnMax(snap *Snapshot, in DecisionInput) float64 {
	max := 0.0
	for _, b := range snap.BudgetBurn {
		if b.Scope != "global" && !containsString(in.ScopeKeys, b.Scope) {
			continue
		}
		if burn := b.Burn(); burn > max {
			max = burn
		}
	}
	return max
}

// resolveFallbacks resolves the §R12.1 fallback chain for a model:
// a model-keyed chain wins; otherwise the model's tier name keys the
// chain. Nil when the policy declares neither.
func resolveFallbacks(p Policy, snap *Snapshot, model string) []string {
	if len(p.Fallbacks) == 0 {
		return nil
	}
	if chain, ok := p.Fallbacks[model]; ok {
		return chain
	}
	tier, _ := snap.Tiers.Lookup(model)
	if chain, ok := p.Fallbacks[string(tier)]; ok {
		return chain
	}
	return nil
}

// stateFor finds a model's pipeline state.
func stateFor(res PipelineResult, model string) (CandidateState, bool) {
	for _, c := range res.Candidates {
		if c.Model == model {
			return c, true
		}
	}
	return CandidateState{}, false
}

// topAllowedAtOrBelow returns the best-ranked surviving candidate at
// or below the tier bound, excluding the named model.
func topAllowedAtOrBelow(res PipelineResult, bound Tier, exclude string) (CandidateState, bool) {
	for _, c := range res.Allowed() {
		if c.Model == exclude {
			continue
		}
		if c.Tier.Rank() <= bound.Rank() {
			return c, true
		}
	}
	return CandidateState{}, false
}

// topAllowedBelow returns the best-ranked surviving candidate STRICTLY
// below the tier bound, excluding the named model.
func topAllowedBelow(res PipelineResult, bound Tier, exclude string) (CandidateState, bool) {
	for _, c := range res.Allowed() {
		if c.Model == exclude {
			continue
		}
		if c.Tier.Rank() < bound.Rank() {
			return c, true
		}
	}
	return CandidateState{}, false
}

// holdReasons explains why a route_to_tier intent found no candidate:
// the target tier's representative's deny reasons when it was filtered
// out, else plain no_candidate.
func holdReasons(res PipelineResult, snap *Snapshot, in DecisionInput, target Tier) []ReasonCode {
	shape := ShapeForModel(in.Shape.Model)
	if rep, ok := snap.Tiers.Representative(shape, target); ok {
		if st, found := stateFor(res, rep); found && !st.Allowed && len(st.DenyReasons) > 0 {
			return dedupReasons(st.DenyReasons)
		}
	}
	return []ReasonCode{ReasonNoCandidate}
}

func hasReason(set []ReasonCode, want ReasonCode) bool {
	for _, r := range set {
		if r == want {
			return true
		}
	}
	return false
}

func dedupReasons(in []ReasonCode) []ReasonCode {
	seen := map[ReasonCode]bool{}
	out := make([]ReasonCode, 0, len(in))
	for _, r := range in {
		if !seen[r] {
			seen[r] = true
			out = append(out, r)
		}
	}
	return out
}

// stampHardStop guarantees a hard_stop exhaustion (§R14) is visible on the
// decision row whatever branch produced it: the flag is already threaded from
// the modifier, and ReasonBudgetHardStop is appended (deduped) so the row's
// reason codes name it even when the winning rule/branch replaced the reason
// list (G1-HARDSTOP). No other reason is touched, so rows for the other two
// exhaustion behaviors are unchanged.
func stampHardStop(d Decision, res PipelineResult) Decision {
	if !res.Mod.HardStop {
		return d
	}
	d.HardStop = true
	if !hasReason(d.ReasonCodes, ReasonBudgetHardStop) {
		d.ReasonCodes = append(d.ReasonCodes, ReasonBudgetHardStop)
	}
	return d
}
