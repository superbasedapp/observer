package cachetrack

import (
	"math"
	"testing"
)

// Realistic Anthropic rates for the tests (per-token USD, not
// per-million; the cost engine emits per-token throughout).
// These are illustrative — the production pricing.go tables are
// the source of truth at request time.
var (
	opusRates = RatePair{
		Input: 15e-6, Output: 75e-6,
		CacheRead: 1.5e-6, CacheCreation: 18.75e-6,
		// 1h tier = 2 × input, the Anthropic ratio fillDefaults
		// derives. Strictly above the 5m rate, which is what marks a
		// provider as pricing writes BY TTL.
		CacheCreation1h: 30e-6,
		FastMultiplier:  2.0,
	}
	haikuRates = RatePair{
		Input: 0.8e-6, Output: 4e-6,
		CacheRead: 0.08e-6, CacheCreation: 1e-6,
		CacheCreation1h: 1.6e-6,
	}
)

// TestForecast_OpusToHaikuBreakEven covers the headline case: a
// session with a deep cached prefix on opus considering a switch
// to haiku. Haiku's cache_read rate is ~19× cheaper than opus,
// so the per-turn delta is large; break-even should land in a
// small number of turns even with the cold-write cost.
func TestForecast_OpusToHaikuBreakEven(t *testing.T) {
	t.Parallel()
	in := ForecastInput{
		CurrentPrefixTokens:     50000,
		AvgSuffixTokens:         500,
		AvgOutputTokens:         800,
		EstimatedRemainingTurns: 100,
		Current:                 "claude-opus-4-8",
		Candidate:               "claude-haiku-4-5-20251001",
		CurrentRates:            opusRates,
		CandidateRates:          haikuRates,
		CandidateMinCacheable:   1024,
	}
	got := Forecast(in)

	// Switch cost = P × candidate cache_creation = 50000 × 1e-6 = $0.05
	if math.Abs(got.SwitchCostUSD-0.05) > 1e-9 {
		t.Errorf("SwitchCostUSD = %v, want ~0.05", got.SwitchCostUSD)
	}
	// Per-turn before > per-turn after by a lot — savings_per_turn positive.
	if got.SavingsPerTurnUSD <= 0 {
		t.Errorf("SavingsPerTurnUSD = %v, want > 0", got.SavingsPerTurnUSD)
	}
	// Break-even should be a reasonable integer.
	if got.BreakEvenTurns < 1 || got.BreakEvenTurns > 100 {
		t.Errorf("BreakEvenTurns = %d, want a small positive integer", got.BreakEvenTurns)
	}
	// Estimated net savings over 100 turns should be positive
	// (the SwitchCost amortises before T=100).
	if got.EstimatedNetSavingsUSD <= 0 {
		t.Errorf("EstimatedNetSavingsUSD = %v, want > 0", got.EstimatedNetSavingsUSD)
	}
	// Candidate min cacheable (1024) < P (50000) so the warning
	// must NOT fire.
	for _, w := range got.Warnings {
		if w == WarningCacheWontEngage {
			t.Errorf("WarningCacheWontEngage fired but P=%d > min=%d", in.CurrentPrefixTokens, in.CandidateMinCacheable)
		}
	}
}

// TestForecast_NeverPaysOff covers the inverse: switching from
// haiku to opus. The per-turn delta is NEGATIVE (opus is more
// expensive per token across the board), so the switch never
// recovers and the warning fires.
func TestForecast_NeverPaysOff(t *testing.T) {
	t.Parallel()
	in := ForecastInput{
		CurrentPrefixTokens:     50000,
		AvgSuffixTokens:         500,
		AvgOutputTokens:         800,
		EstimatedRemainingTurns: 100,
		Current:                 "claude-haiku-4-5-20251001",
		Candidate:               "claude-opus-4-8",
		CurrentRates:            haikuRates,
		CandidateRates:          opusRates,
	}
	got := Forecast(in)
	if got.SavingsPerTurnUSD >= 0 {
		t.Errorf("SavingsPerTurnUSD = %v, want < 0 (haiku→opus is more expensive)", got.SavingsPerTurnUSD)
	}
	if got.BreakEvenTurns != 0 {
		t.Errorf("BreakEvenTurns = %d, want 0 (never pays off)", got.BreakEvenTurns)
	}
	var sawNeverPaysOff bool
	for _, w := range got.Warnings {
		if w == WarningSwitchNeverPaysOff {
			sawNeverPaysOff = true
		}
	}
	if !sawNeverPaysOff {
		t.Errorf("WarningSwitchNeverPaysOff must fire when delta ≤ 0; got %+v", got.Warnings)
	}
}

// TestForecast_FastModeWarning pins the FastMultiplier folding:
// when CurrentFast is true and the current rates have a
// FastMultiplier > 1, per_turn_before SCALES by the multiplier
// AND the WarningFastModeActive surfaces so the operator sees
// the source of the inflated per-turn number.
func TestForecast_FastModeWarning(t *testing.T) {
	t.Parallel()
	baseIn := ForecastInput{
		CurrentPrefixTokens: 50000,
		AvgSuffixTokens:     500,
		AvgOutputTokens:     800,
		Current:             "claude-opus-4-8",
		Candidate:           "claude-haiku-4-5-20251001",
		CurrentRates:        opusRates,
		CandidateRates:      haikuRates,
	}
	withoutFast := Forecast(baseIn)

	fastIn := baseIn
	fastIn.CurrentFast = true
	withFast := Forecast(fastIn)

	if withFast.PerTurnBeforeUSD < 1.9*withoutFast.PerTurnBeforeUSD {
		t.Errorf("FastMultiplier (2×) should ~double PerTurnBeforeUSD: without=%v with=%v",
			withoutFast.PerTurnBeforeUSD, withFast.PerTurnBeforeUSD)
	}
	var sawFast bool
	for _, w := range withFast.Warnings {
		if w == WarningFastModeActive {
			sawFast = true
		}
	}
	if !sawFast {
		t.Errorf("WarningFastModeActive must fire when CurrentFast=true and multiplier>1")
	}
}

// TestForecast_CacheWontEngageWarning pins the candidate-min-
// cacheable guardrail: when the candidate's threshold is larger
// than the current prefix, the cache won't engage immediately
// even after the switch, and the warning surfaces.
func TestForecast_CacheWontEngageWarning(t *testing.T) {
	t.Parallel()
	in := ForecastInput{
		CurrentPrefixTokens:   500, // tiny prefix
		AvgSuffixTokens:       100,
		AvgOutputTokens:       200,
		Current:               "claude-opus-4-8",
		Candidate:             "claude-haiku-4-5-20251001",
		CurrentRates:          opusRates,
		CandidateRates:        haikuRates,
		CandidateMinCacheable: 1024, // candidate threshold above P
	}
	got := Forecast(in)
	var sawCacheWontEngage bool
	for _, w := range got.Warnings {
		if w == WarningCacheWontEngage {
			sawCacheWontEngage = true
		}
	}
	if !sawCacheWontEngage {
		t.Errorf("WarningCacheWontEngage must fire when P (%d) < CandidateMinCacheable (%d)",
			in.CurrentPrefixTokens, in.CandidateMinCacheable)
	}
}

// TestForecast_OneHourTierSuggestion pins the gap-based warning:
// when the session has gaps > 5 min and the candidate has a
// non-zero CacheCreation rate, suggest the 1h TTL tier.
func TestForecast_OneHourTierSuggestion(t *testing.T) {
	t.Parallel()
	in := ForecastInput{
		CurrentPrefixTokens: 50000,
		AvgSuffixTokens:     500,
		AvgOutputTokens:     800,
		Current:             "claude-opus-4-8",
		Candidate:           "claude-haiku-4-5-20251001",
		CurrentRates:        opusRates,
		CandidateRates:      haikuRates,
		HasGapsOver5Min:     true,
	}
	got := Forecast(in)
	var saw bool
	for _, w := range got.Warnings {
		if w == WarningTryOneHourTier {
			saw = true
		}
	}
	if !saw {
		t.Errorf("WarningTryOneHourTier must fire when HasGapsOver5Min=true and candidate has cache_creation")
	}
}

// TestForecast_NoOneHourTierSuggestionWithoutATier pins the capability
// gate on the 1h-tier advice: a candidate whose write rate does not vary
// by TTL has no 1h tier to move to, so the advice must stay silent even
// with gaps over 5 minutes.
//
// This is the Gemini shape as of 2026-09-03: Google publishes no
// cache-write line (a write is an ordinary input token), so the cost
// table derives CacheCreation == CacheCreation1h == Input. The older
// "CacheCreation > 0" gate would have offered a tier Google does not
// sell.
func TestForecast_NoOneHourTierSuggestionWithoutATier(t *testing.T) {
	t.Parallel()
	flatWrite := RatePair{
		Input: 2e-6, Output: 12e-6, CacheRead: 0.2e-6,
		// TTL-independent write rate: 5m == 1h == input.
		CacheCreation: 2e-6, CacheCreation1h: 2e-6,
	}
	in := ForecastInput{
		CurrentPrefixTokens: 50000,
		AvgSuffixTokens:     500,
		AvgOutputTokens:     800,
		Current:             "gemini-3-pro-high",
		Candidate:           "gemini-3-flash-agent",
		CurrentRates:        flatWrite,
		CandidateRates:      flatWrite,
		HasGapsOver5Min:     true,
	}
	for _, w := range Forecast(in).Warnings {
		if w == WarningTryOneHourTier {
			t.Fatal("WarningTryOneHourTier must NOT fire for a candidate whose write rate is TTL-independent — there is no 1h tier to switch to")
		}
	}
}

// TestForecast_EmptyPrefix pins the P=0 edge: switch_cost is 0,
// break-even depends only on per-turn delta, and the
// WarningEmptyPrefix surfaces so the dashboard doesn't show a
// confidently-zero break-even without context.
func TestForecast_EmptyPrefix(t *testing.T) {
	t.Parallel()
	in := ForecastInput{
		CurrentPrefixTokens: 0,
		AvgSuffixTokens:     500,
		AvgOutputTokens:     800,
		Current:             "claude-opus-4-8",
		Candidate:           "claude-haiku-4-5-20251001",
		CurrentRates:        opusRates,
		CandidateRates:      haikuRates,
	}
	got := Forecast(in)
	if got.SwitchCostUSD != 0 {
		t.Errorf("SwitchCostUSD = %v, want 0 with P=0", got.SwitchCostUSD)
	}
	var sawEmpty bool
	for _, w := range got.Warnings {
		if w == WarningEmptyPrefix {
			sawEmpty = true
		}
	}
	if !sawEmpty {
		t.Errorf("WarningEmptyPrefix must fire when P=0; got %+v", got.Warnings)
	}
}

// TestForecast_ZeroRemainingTurns pins the T=0 contract: when
// the caller hands in no T estimate, EstimatedNetSavingsUSD
// stays 0 (we don't fabricate a session-end horizon) but the
// break-even number still lands.
func TestForecast_ZeroRemainingTurns(t *testing.T) {
	t.Parallel()
	in := ForecastInput{
		CurrentPrefixTokens:     50000,
		AvgSuffixTokens:         500,
		AvgOutputTokens:         800,
		EstimatedRemainingTurns: 0, // explicitly no estimate
		Current:                 "claude-opus-4-8",
		Candidate:               "claude-haiku-4-5-20251001",
		CurrentRates:            opusRates,
		CandidateRates:          haikuRates,
	}
	got := Forecast(in)
	if got.EstimatedNetSavingsUSD != 0 {
		t.Errorf("EstimatedNetSavingsUSD = %v, want 0 when T=0", got.EstimatedNetSavingsUSD)
	}
	if got.BreakEvenTurns == 0 {
		t.Errorf("BreakEvenTurns must still compute when T=0: got 0")
	}
}

// TestForecast_BreakEvenCeil pins the ceiling-not-floor rounding:
// operators read break-even as "how many MORE turns until I'm in
// the black"; rounding down would understate by up to one turn.
func TestForecast_BreakEvenCeil(t *testing.T) {
	t.Parallel()
	// Craft inputs so break_even = 5.0001 exactly. SwitchCostUSD
	// / SavingsPerTurnUSD = 5.0001 → ceil = 6.
	in := ForecastInput{
		CurrentPrefixTokens: 10000,
		AvgSuffixTokens:     100,
		AvgOutputTokens:     100,
		CurrentRates:        RatePair{Input: 10e-6, Output: 10e-6, CacheRead: 1e-6, CacheCreation: 5e-6},
		CandidateRates:      RatePair{Input: 1e-6, Output: 1e-6, CacheRead: 0.1e-6, CacheCreation: 1e-6},
	}
	got := Forecast(in)
	// SwitchCostUSD = 10000 × 1e-6 = 0.01
	// PerTurnBefore = 10000 × 1e-6 + 100 × 10e-6 + 100 × 10e-6 = 0.01 + 0.001 + 0.001 = 0.012
	// PerTurnAfter  = 10000 × 0.1e-6 + 100 × 1e-6 + 100 × 1e-6 = 0.001 + 0.0001 + 0.0001 = 0.0012
	// Savings       = 0.0108
	// BreakEven     = 0.01 / 0.0108 = 0.9259 → ceil = 1
	if got.BreakEvenTurns != 1 {
		t.Errorf("BreakEvenTurns = %d, want 1 (ceiling on 0.9259)", got.BreakEvenTurns)
	}
}

// TestForecast_EpsilonGuard pins the divide-by-zero protection:
// when SavingsPerTurnUSD is effectively zero (rates equal), the
// engine returns BreakEvenTurns=0 + WarningSwitchNeverPaysOff
// instead of overflowing.
func TestForecast_EpsilonGuard(t *testing.T) {
	t.Parallel()
	in := ForecastInput{
		CurrentPrefixTokens: 50000,
		AvgSuffixTokens:     500,
		AvgOutputTokens:     800,
		CurrentRates:        opusRates,
		CandidateRates:      opusRates, // same rates → zero delta
	}
	got := Forecast(in)
	if got.BreakEvenTurns != 0 {
		t.Errorf("BreakEvenTurns = %d, want 0 (epsilon guard)", got.BreakEvenTurns)
	}
}
