package predict

import (
	"math"
	"sort"
)

// RatePair is the per-token price slice the estimator reads. Mirrors
// the fields it needs from cost.Pricing without coupling internal/predict
// to internal/intelligence/cost (same boundary cachetrack.RatePair
// keeps). Caller converts cost.Pricing's $/million-token values to
// per-token at the store seam.
type RatePair struct {
	Input          float64
	Output         float64
	CacheRead      float64
	CacheCreation  float64
	FastMultiplier float64
}

// TurnSample is one observed assistant turn's variable token shape.
// FreshInput is input_tokens − cache_read_tokens floored at 0 (the S
// term — near-zero for cached Claude Code, the full prompt for an
// uncached provider). Output is output_tokens (the O term).
type TurnSample struct {
	FreshInput int64
	Output     int64
}

// EstimateInput is the caller-assembled snapshot the estimator scores.
// Assembled by internal/store/predict.go::LoadSessionShape from
// token_usage (+ user_prompt boundaries for T). Pure — no DB types
// leak in.
type EstimateInput struct {
	// Model is the session's current model id (echoed in the result).
	Model string
	// Rates is the current model's per-token pricing.
	Rates RatePair
	// CurrentFast folds the provider's low-latency multiplier into the
	// per-turn math (Anthropic Opus speed="fast", 2×).
	CurrentFast bool

	// PricingUnknown reports that the cost engine has NO pricing row for
	// Model, so Rates carries nothing (an alias/codename model id such as
	// opencode's "big-pickle"). The estimator still scores the whole
	// FACTUAL half — PrefixTokens, the per-turn (S, O) quantiles, the
	// fan-out tier and the sample counts are OBSERVATIONS of the session,
	// not prices — and leaves only the USD columns at zero, emitting
	// WarnNoPricing with HasEstimate=false.
	//
	// This is an explicit flag and NOT inferred from all-zero Rates: a
	// genuinely free model (the pricing table's ":free" rung) resolves to
	// an exact, all-zero Pricing and must keep producing a real $0 band.
	// Zero value = pricing known, so existing callers are unaffected.
	PricingUnknown bool

	// PrefixTokens is P "now": the cache prefix re-read on every turn —
	// the LATEST turn's cache_read_tokens, not an average (the prefix
	// grows across a session; the next message starts from the current
	// size). Priced at the cache-read rate. Zero for an uncached
	// provider, in which case FreshInput carries the input cost.
	PrefixTokens int64

	// TurnSamples are the session's observed per-turn (S, O) shapes.
	// The estimator takes p25/p50/p75 over these for the band's input
	// and output dimensions. Empty → no_session_history (unless prior
	// samples are supplied).
	TurnSamples []TurnSample

	// TurnsPerMessage are the observed turns-per-user-message counts
	// (one per user message, derived from user_prompt boundaries).
	// Empty when the session has no user_prompt actions (~68% of
	// sessions per §0) → T falls back through the ladder below.
	TurnsPerMessage []int

	// ObservedMessages is len(TurnsPerMessage); below YoungThreshold
	// the session is "young" and T prefers the cross-session prior.
	ObservedMessages int
	// YoungThreshold is the [predict].young_session_messages config
	// (default 3): at or above it the session's own T distribution is
	// trusted; below it the prior wins when available.
	YoungThreshold int

	// PriorTurnsPerMessage is the cross-session (tool/project) T
	// distribution — the tier-2 fallback. Empty when no comparable
	// session carries user_prompt boundaries.
	PriorTurnsPerMessage []int
	// PriorTurnSamples optionally seeds the (S, O) quantiles when the
	// current session is young (blend toward the prior shape). Empty
	// disables the blend.
	PriorTurnSamples []TurnSample

	// DefaultTurns is the tier-3 last-resort T ([predict].
	// default_turns_per_message, default 12) used when neither the
	// session nor a prior yields a fan-out.
	DefaultTurns int
}

// TurnsTier names which rung of the 3-tier ladder produced T, so every
// surface can show whether the fan-out was observed or inferred.
type TurnsTier string

const (
	// TurnsObserved — T quantiled from this session's own user_prompt
	// boundaries (≥ YoungThreshold messages). No T warning.
	TurnsObserved TurnsTier = "observed"
	// TurnsPrior — T from the cross-session tool/project prior (the
	// session lacks usable boundaries). Emits WarnTurnsInferredPrior.
	TurnsPrior TurnsTier = "prior"
	// TurnsDefault — T from DefaultTurns (no session and no prior).
	// Emits WarnTurnsInferredDefault.
	TurnsDefault TurnsTier = "default"
)

// Warning is the closed vocabulary the estimator emits; surfaces render
// each as a pill. Stable across releases (consumed by the webapp).
type Warning string

const (
	// WarnNoSessionHistory — no turn samples at all (session has no
	// token rows, or hook-only with no model/tokens). The result is
	// empty; the surface shows "route through the proxy / send a
	// message to populate", not a fake $0.
	WarnNoSessionHistory Warning = "no_session_history"
	// WarnTurnsInferredPrior — T came from the cross-session prior.
	WarnTurnsInferredPrior Warning = "turns_inferred_prior"
	// WarnTurnsInferredDefault — T came from the static default.
	WarnTurnsInferredDefault Warning = "turns_inferred_default"
	// WarnEmptyPrefix — P is 0 (uncached / first turn). Cost is driven
	// by fresh input + output only; surfaced so a confidently-small
	// number has context.
	WarnEmptyPrefix Warning = "empty_prefix"
	// WarnFastModeActive — the session is in the provider's fast tier;
	// the per-turn numbers already include the multiplier. The operator
	// may prefer turning fast off to switching models.
	WarnFastModeActive Warning = "fast_mode_active"
	// WarnNoPricing — the model has no pricing entry, so the dollar
	// columns are absent (HasEstimate=false) while the token facts in
	// the result are real. Distinct from WarnNoSessionHistory, which
	// means there is no observed substrate at all: reporting a pricing
	// gap as a data gap is what made the context-window surface claim
	// "no prefix observed yet" over three observed turns.
	WarnNoPricing Warning = "no_pricing"
)

// Band is one quantile column of the estimate (low / mid / high). Turns
// is the T quantile used; FreshInput / Output are the S / O quantiles;
// PerTurnUSD is the single-turn cost at those quantiles; MessageUSD is
// Turns × PerTurnUSD — the headline a surface shows for that column.
type Band struct {
	Turns      float64 `json:"turns"`
	FreshInput int64   `json:"fresh_input"`
	Output     int64   `json:"output"`
	PerTurnUSD float64 `json:"per_turn_usd"`
	MessageUSD float64 `json:"message_usd"`
}

// EstimateResult is the headline payload.
//
// Two INDEPENDENT halves, and surfaces must read the right flag:
//
//   - the FACTUAL half — PrefixTokens, TurnsTier, the bands' token
//     dimensions (Turns / FreshInput / Output), SampleTurns,
//     SampleMessages — is present whenever the session has any observed
//     turn, gated by HasShape. It never depends on pricing.
//   - the COST half — the bands' PerTurnUSD / MessageUSD — additionally
//     requires a pricing entry for the model, gated by HasEstimate.
//
// HasEstimate=false with HasShape=true is the "observed turns, unpriced
// model" case: show the token facts, omit the dollars.
type EstimateResult struct {
	Model        string    `json:"model"`
	PrefixTokens int64     `json:"prefix_tokens"`
	HasEstimate  bool      `json:"has_estimate"`
	HasShape     bool      `json:"has_shape"`
	TurnsTier    TurnsTier `json:"turns_tier"`
	Low          Band      `json:"low"`
	Mid          Band      `json:"mid"`
	High         Band      `json:"high"`
	// SampleTurns / SampleMessages echo how much data backed the
	// estimate, so a surface can convey confidence.
	SampleTurns    int       `json:"sample_turns"`
	SampleMessages int       `json:"sample_messages"`
	Warnings       []Warning `json:"warnings,omitempty"`
}

// Estimate scores the input and returns the low/mid/high band. Pure;
// deterministic; safe to call concurrently. Fail-soft: an empty or
// degenerate snapshot yields a defensible empty result, never NaN.
//
// Facts are decoupled from prices. A missing pricing entry
// (in.PricingUnknown) suppresses ONLY the USD columns; the prefix, the
// per-turn token quantiles, the fan-out tier and the sample counts are
// still computed and returned with HasShape=true.
func Estimate(in EstimateInput) EstimateResult {
	out := EstimateResult{Model: in.Model, PrefixTokens: in.PrefixTokens}

	// Blend the session's own (S, O) samples toward the prior when the
	// session is young. At/above the threshold the session dominates.
	samples := in.TurnSamples
	if len(in.PriorTurnSamples) > 0 && in.ObservedMessages < in.YoungThreshold {
		samples = append(append([]TurnSample(nil), samples...), in.PriorTurnSamples...)
	}
	if len(samples) == 0 {
		out.Warnings = append(out.Warnings, WarnNoSessionHistory)
		return out
	}

	freshSorted := make([]float64, len(samples))
	outSorted := make([]float64, len(samples))
	for i, t := range samples {
		freshSorted[i] = float64(t.FreshInput)
		outSorted[i] = float64(t.Output)
	}
	sort.Float64s(freshSorted)
	sort.Float64s(outSorted)

	// Resolve the T quantiles via the 3-tier ladder.
	turnsLow, turnsMid, turnsHigh, tier := resolveTurns(in)
	out.TurnsTier = tier

	// Per-token rates, fast multiplier folded in like cachetrack.
	r := in.Rates
	if in.CurrentFast && r.FastMultiplier > 1 {
		r.Input *= r.FastMultiplier
		r.Output *= r.FastMultiplier
		r.CacheRead *= r.FastMultiplier
		r.CacheCreation *= r.FastMultiplier
	}
	p := float64(in.PrefixTokens)

	// The band's token dimensions are quantiles of observed turns, so
	// they are computed unconditionally; only the two USD columns are
	// gated on pricing.
	build := func(turns, freshQ, outQ float64) Band {
		s := math.Max(0, freshQ)
		o := math.Max(0, outQ)
		t := math.Max(0, turns)
		b := Band{
			Turns:      round1(t),
			FreshInput: int64(math.Round(s)),
			Output:     int64(math.Round(o)),
		}
		if !in.PricingUnknown {
			b.PerTurnUSD = p*r.CacheRead + s*r.Input + o*r.Output
			b.MessageUSD = t * b.PerTurnUSD
		}
		return b
	}

	out.Low = build(turnsLow, quantile(freshSorted, 0.25), quantile(outSorted, 0.25))
	out.Mid = build(turnsMid, quantile(freshSorted, 0.50), quantile(outSorted, 0.50))
	out.High = build(turnsHigh, quantile(freshSorted, 0.75), quantile(outSorted, 0.75))

	out.HasShape = true
	out.HasEstimate = !in.PricingUnknown
	out.SampleTurns = len(in.TurnSamples)
	out.SampleMessages = in.ObservedMessages
	if in.PricingUnknown {
		out.Warnings = append(out.Warnings, WarnNoPricing)
	}

	switch tier {
	case TurnsPrior:
		out.Warnings = append(out.Warnings, WarnTurnsInferredPrior)
	case TurnsDefault:
		out.Warnings = append(out.Warnings, WarnTurnsInferredDefault)
	}
	if in.PrefixTokens == 0 {
		out.Warnings = append(out.Warnings, WarnEmptyPrefix)
	}
	if in.CurrentFast && in.Rates.FastMultiplier > 1 {
		out.Warnings = append(out.Warnings, WarnFastModeActive)
	}
	return out
}

// resolveTurns walks the 3-tier ladder and returns the low/mid/high T
// quantiles plus the tier that produced them.
func resolveTurns(in EstimateInput) (lo, mid, hi float64, tier TurnsTier) {
	young := in.YoungThreshold
	if young <= 0 {
		young = 3
	}
	if len(in.TurnsPerMessage) > 0 && in.ObservedMessages >= young {
		s := intsToSorted(in.TurnsPerMessage)
		return quantile(s, 0.25), quantile(s, 0.50), quantile(s, 0.75), TurnsObserved
	}
	if len(in.PriorTurnsPerMessage) > 0 {
		s := intsToSorted(in.PriorTurnsPerMessage)
		return quantile(s, 0.25), quantile(s, 0.50), quantile(s, 0.75), TurnsPrior
	}
	d := float64(in.DefaultTurns)
	if d <= 0 {
		d = 12
	}
	return d, d, d, TurnsDefault
}

func intsToSorted(xs []int) []float64 {
	s := make([]float64, len(xs))
	for i, x := range xs {
		s[i] = float64(x)
	}
	sort.Float64s(s)
	return s
}

// quantile returns the q∈[0,1] percentile of an ALREADY-SORTED slice
// using linear interpolation (type R-7, the NumPy/Excel default).
// Empty → 0; single element → that element.
func quantile(sorted []float64, q float64) float64 {
	n := len(sorted)
	if n == 0 {
		return 0
	}
	if n == 1 {
		return sorted[0]
	}
	if q <= 0 {
		return sorted[0]
	}
	if q >= 1 {
		return sorted[n-1]
	}
	pos := q * float64(n-1)
	lo := int(math.Floor(pos))
	hi := int(math.Ceil(pos))
	if lo == hi {
		return sorted[lo]
	}
	frac := pos - float64(lo)
	return sorted[lo]*(1-frac) + sorted[hi]*frac
}

func round1(x float64) float64 { return math.Round(x*10) / 10 }
