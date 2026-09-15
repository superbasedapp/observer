package cachetrack

import "math"

// Forecast is the pure-function core of the spec §14.2 model-switch
// cost forecaster. Inputs are caller-assembled from the existing
// tables (cache_entries → P, cache_events / api_turns → S + T +
// out + cadence, cost.Pricing.Lookup → rates) — no DB, no I/O.
// Output is the headline numbers + a closed-set warning list the
// dashboard widget renders as pills.
//
// §15.3 (c)-phase-2 calibration note: the engine's per-session
// SessionEMA (consumed by the dashboard widget that assembles
// ForecastInput) is now driven by the snapshot-before-push
// lookup + CacheableTokens-gated predictKind path, so
// continuation turns no longer feed false-mispredict samples
// into the EMA. Pre-fix, every Tier-2 (and Tier-1 Haiku-tier)
// continuation turn fired `rec.Mispredicted=true` →
// `matched.Apply(TriggerMispredict)` demoted the matched entry
// AND `UpdateEMA(rec.EstimateScale)` fed spurious samples. The
// forecaster's `EstimatedNetSavingsUSD` / `BreakEvenTurns`
// drifted in proportion to how cache-hit-heavy the session was.
// Post-fix calibration is honest on Tier-1 cumulative + Tier-2
// delta both. See docs/cache-tracking.md "Tier-2 continuation
// Hit-prediction (§15.3 (c)-phase-2 CLOSED)" for the closure
// footprint + v1 limitations.
//
// Math per spec §14.2:
//
//	switch_cost      = P × r'_write
//	per_turn_before  = P × r_read  + S × r_in   + O × r_out
//	per_turn_after   = P × r'_read + S × r'_in  + O × r'_out
//	break_even_turns = switch_cost / max(ε, per_turn_before − per_turn_after)
//
// where (r_in, r_read, r_write, r_out) are the OLD model rates and
// the primed set is the CANDIDATE model rates. O is the average
// per-turn output tokens observed so far. The cold write at the
// candidate's r'_write tier (NOT r_write — the old model's tier
// is unrelated to what the candidate charges to seed its cache)
// is the one-time switch cost; the per-turn delta amortises it.

// ForecastInput is the per-turn cost-shape snapshot the forecaster
// scores. Every field is a non-negative quantity; the engine
// guards against zero / negative input so a caller that hands
// in an empty snapshot (no cache yet, no prior turns) gets a
// defensible-but-empty forecast rather than NaN.
type ForecastInput struct {
	// CurrentPrefixTokens is the deepest cached prefix the
	// current model has built up — the P term. Caller derives
	// from MAX(token_count) over cache_entries WHERE session_id=?
	// AND state='live'. Zero when the session has no cache yet
	// (P0 first turn / pre-cachetrack history); the forecaster
	// returns a zero switch_cost in that case.
	CurrentPrefixTokens int64
	// AvgSuffixTokens is the average per-turn new-content size
	// the session has shown — the S term. Caller derives from
	// AVG(tokens_written) on cache_events with kind='write' AND
	// cause='suffix_growth' for this session, or as a fallback
	// from api_turns.input_tokens − cache_read_tokens.
	AvgSuffixTokens int64
	// AvgOutputTokens is the average per-turn output size — the
	// O term. From AVG(output_tokens) on api_turns for the
	// session. Zero is tolerated (per_turn rates fall back to
	// prefix+suffix only).
	AvgOutputTokens int64
	// EstimatedRemainingTurns is the caller's best guess at how
	// many MORE turns this session will run; the forecaster uses
	// it ONLY to compute estimated_net_savings_usd and to flag
	// "switch won't pay off in this session" when break_even_turns
	// > T. Zero means "no estimate" → estimated_net_savings_usd
	// stays 0 and the comparison warning is suppressed.
	EstimatedRemainingTurns int64

	// Current names the model the session is using today. Used
	// in the response payload for the dashboard widget's
	// "Switch from X to Y" headline; the math reads from
	// CurrentRates directly.
	Current string
	// Candidate names the model the operator wants to switch to.
	Candidate string

	// CurrentRates is the current model's per-token Pricing
	// (input / output / cache_read / cache_creation /
	// fast_multiplier). Caller resolves via cost.Table.Lookup at
	// the dashboard seam — the forecaster stays cost-package
	// free.
	CurrentRates RatePair
	// CandidateRates is the candidate model's per-token Pricing.
	CandidateRates RatePair

	// CandidateMinCacheable is the candidate model's minimum
	// cacheable prefix size. Anthropic publishes per-model
	// thresholds (typically 1024 for Haiku / 4096 for Sonnet /
	// 8192 for Opus 4 family); the candidate's cache won't
	// engage at all until the prefix grows past it. Zero
	// disables the threshold warning.
	CandidateMinCacheable int64

	// CurrentFast indicates the current model is being served
	// in the provider's low-latency "fast" tier (Anthropic
	// Opus 4.8 speed="fast"; 2× multiplier). The forecaster
	// folds CurrentRates.FastMultiplier into the per_turn_before
	// math when this is true.
	CurrentFast bool
	// HasGapsOver5Min reports whether the session has any
	// inter-turn gap longer than 5 minutes. If so AND the
	// candidate has a non-zero 1h-tier rate, surface the "1h-
	// tier suggestion" warning per spec §14.2.
	HasGapsOver5Min bool
}

// RatePair is the per-token Pricing slice the forecaster reads.
// Mirrors the fields it needs from cost.Pricing without coupling
// internal/cachetrack to internal/intelligence/cost (the cost
// package imports internal/cachetrack via store.PersistCacheObservation;
// keeping the forecaster cost-import-free avoids the cycle).
type RatePair struct {
	Input         float64
	Output        float64
	CacheRead     float64
	CacheCreation float64
	// CacheCreation1h is the 1-hour write tier, carried purely so the
	// forecaster can tell a provider that PRICES writes by TTL (this
	// exceeds CacheCreation — Anthropic, OpenAI 5.6+) from one whose
	// write rate is TTL-independent (equal — Gemini, where a write is
	// just an input token). No dollar math reads it; only the
	// WarningTryOneHourTier gate does. Zero when the caller predates
	// the field, which correctly suppresses the advice.
	CacheCreation1h float64
	FastMultiplier  float64
}

// ForecastResult is the headline payload the dashboard widget
// renders. Every dollar field is in raw USD (no scaling); the
// dashboard handler echoes them as-is.
type ForecastResult struct {
	// SwitchCostUSD is P × r'_write — the one-time cost of seeding
	// the candidate's cache at the deepest currently-cached prefix.
	SwitchCostUSD float64
	// PerTurnBeforeUSD is the average per-turn cost on the current
	// model (P × r_read + S × r_in + O × r_out). Applies the
	// fast-mode multiplier when CurrentFast is set.
	PerTurnBeforeUSD float64
	// PerTurnAfterUSD is the average per-turn cost on the
	// candidate (P × r'_read + S × r'_in + O × r'_out).
	PerTurnAfterUSD float64
	// SavingsPerTurnUSD is PerTurnBeforeUSD − PerTurnAfterUSD;
	// signed so the dashboard can render negative ("switching
	// would cost MORE per turn") in warn tone.
	SavingsPerTurnUSD float64
	// BreakEvenTurns is the integer count of turns after which
	// the switch_cost has been recouped through the per-turn
	// delta. Zero when SavingsPerTurnUSD ≤ 0 (no per-turn
	// savings; the switch never pays off — surfaces as
	// WarningSwitchNeverPaysOff). Capped at math.MaxInt32 to
	// avoid the dashboard rendering an absurdly large number
	// when the delta is just barely positive.
	BreakEvenTurns int64
	// EstimatedNetSavingsUSD is
	// (SavingsPerTurnUSD × EstimatedRemainingTurns) − SwitchCostUSD
	// — what the operator nets if the switch happens now and the
	// session runs for the estimated T more turns. Negative =
	// switching loses money over the estimated window.
	EstimatedNetSavingsUSD float64
	// Warnings carries the closed-set list the dashboard renders
	// as pills. See WarningKind constants for the vocabulary.
	Warnings []WarningKind
}

// WarningKind is the closed vocabulary the forecaster emits. The
// dashboard renders these as pills; values are stable across
// releases (consumed by webapp UI mapping).
type WarningKind string

const (
	// WarningCacheWontEngage fires when CandidateMinCacheable >
	// CurrentPrefixTokens. The candidate's cache won't engage at
	// all on day one; switching means starting from a cold cache
	// AND paying the per_turn_after rate without any cache_read
	// benefit until the prefix grows past the threshold.
	WarningCacheWontEngage WarningKind = "cache_wont_engage"
	// WarningFastModeActive surfaces when CurrentFast is set and
	// the current pricing has a FastMultiplier > 1. The
	// PerTurnBeforeUSD ALREADY includes the multiplier; the
	// warning just makes the source of the inflated per-turn
	// number visible to the operator (they may realize the
	// answer is "turn fast off," not "switch models").
	WarningFastModeActive WarningKind = "fast_mode_active"
	// WarningTryOneHourTier fires when HasGapsOver5Min is set
	// AND the candidate's rate card actually HAS a separately
	// priced 1h write tier to move to — i.e. CacheCreation1h >
	// CacheCreation. That is a capability test, not a provider
	// test: Anthropic (1.25× vs 2× input) and OpenAI 5.6+ pass
	// it, while a provider whose write rate is TTL-independent
	// does not, so the advice is never offered where there is
	// no tier to switch to. Until 2026-09-03 the gate was
	// simply "CacheCreation > 0", which was equivalent while
	// only Anthropic-shape rows carried a write rate at all;
	// Gemini rows now derive one (a write is an ordinary input
	// token there, identical at every TTL — see
	// cost.cacheWriteRules), and would have drawn 1h-tier
	// advice for a tier Google does not sell.
	// Operator-facing: "you're idle long enough that 5m TTL
	// expires between turns; 1h tier is cheaper over the same
	// lifecycle."
	WarningTryOneHourTier WarningKind = "try_1h_tier"
	// WarningSwitchNeverPaysOff fires when the per-turn delta
	// is ≤ 0 (candidate isn't cheaper per turn). Switching
	// costs SwitchCostUSD up-front and never recovers; break-
	// even is undefined / infinity. The dashboard renders this
	// in warn tone alongside a zero break_even_turns.
	WarningSwitchNeverPaysOff WarningKind = "switch_never_pays_off"
	// WarningEmptyPrefix fires when CurrentPrefixTokens is 0.
	// No cache to invalidate; switch_cost is 0 and the forecast
	// degenerates to "compare per-turn rates." Surfaced so the
	// dashboard doesn't show a confidently-zero break-even
	// without context.
	WarningEmptyPrefix WarningKind = "empty_prefix"
)

// epsilon is the divide-by-zero guard for break_even. A 1 µ-USD
// floor avoids returning math.MaxInt32 break_even on a
// perfectly-tied per-turn delta (the dashboard would otherwise
// render a confusing "switching pays off in 2 billion turns").
const forecastEpsilon = 1e-6

// Forecast scores the input and returns the headline numbers +
// warnings. Pure function; deterministic; safe to call from
// concurrent handlers.
func Forecast(in ForecastInput) ForecastResult {
	var out ForecastResult

	// Apply fast-mode multiplier to the current rates when active.
	cur := in.CurrentRates
	if in.CurrentFast && cur.FastMultiplier > 1 {
		cur.Input *= cur.FastMultiplier
		cur.Output *= cur.FastMultiplier
		cur.CacheRead *= cur.FastMultiplier
		cur.CacheCreation *= cur.FastMultiplier
	}
	cand := in.CandidateRates

	p := float64(in.CurrentPrefixTokens)
	s := float64(in.AvgSuffixTokens)
	o := float64(in.AvgOutputTokens)

	out.SwitchCostUSD = p * cand.CacheCreation
	out.PerTurnBeforeUSD = p*cur.CacheRead + s*cur.Input + o*cur.Output
	out.PerTurnAfterUSD = p*cand.CacheRead + s*cand.Input + o*cand.Output
	out.SavingsPerTurnUSD = out.PerTurnBeforeUSD - out.PerTurnAfterUSD

	if out.SavingsPerTurnUSD > forecastEpsilon {
		be := out.SwitchCostUSD / out.SavingsPerTurnUSD
		// Round to ceiling — operators read break-even as "how
		// many MORE turns until I'm in the black"; rounding down
		// would understate by up to one turn.
		ceil := math.Ceil(be)
		if ceil > float64(math.MaxInt32) {
			ceil = float64(math.MaxInt32)
		}
		out.BreakEvenTurns = int64(ceil)
		if in.EstimatedRemainingTurns > 0 {
			out.EstimatedNetSavingsUSD = out.SavingsPerTurnUSD*float64(in.EstimatedRemainingTurns) - out.SwitchCostUSD
		}
	} else {
		out.BreakEvenTurns = 0
		out.Warnings = append(out.Warnings, WarningSwitchNeverPaysOff)
	}

	// Warnings.
	if in.CurrentPrefixTokens == 0 {
		out.Warnings = append(out.Warnings, WarningEmptyPrefix)
	}
	if in.CandidateMinCacheable > 0 && in.CandidateMinCacheable > in.CurrentPrefixTokens {
		out.Warnings = append(out.Warnings, WarningCacheWontEngage)
	}
	if in.CurrentFast && in.CurrentRates.FastMultiplier > 1 {
		out.Warnings = append(out.Warnings, WarningFastModeActive)
	}
	if in.HasGapsOver5Min && cand.CacheCreation1h > cand.CacheCreation {
		out.Warnings = append(out.Warnings, WarningTryOneHourTier)
	}

	return out
}
