package predict

import (
	"math"
	"testing"
)

// opusRates mirrors the per-token Opus-class rates the store seam hands
// in (cost.Pricing $/M ÷ 1e6). Cache-read is the dominant term for a
// large cached prefix.
var opusRates = RatePair{
	Input:          15e-6,
	Output:         75e-6,
	CacheRead:      1.5e-6,
	CacheCreation:  18.75e-6,
	FastMultiplier: 2,
}

func hasWarn(ws []Warning, w Warning) bool {
	for _, x := range ws {
		if x == w {
			return true
		}
	}
	return false
}

func TestEstimate_EmptyInput(t *testing.T) {
	got := Estimate(EstimateInput{Model: "claude-opus-4-8", Rates: opusRates})
	if got.HasEstimate {
		t.Fatalf("expected no estimate on empty input")
	}
	if !hasWarn(got.Warnings, WarnNoSessionHistory) {
		t.Errorf("want no_session_history, got %v", got.Warnings)
	}
}

func TestEstimate_ObservedTier_CachedClaudeCode(t *testing.T) {
	// Cached CC shape: P large (200k), fresh≈0, output varies. Cost is
	// dominated by P·CacheRead × T.
	in := EstimateInput{
		Model:        "claude-opus-4-8",
		Rates:        opusRates,
		PrefixTokens: 200_000,
		TurnSamples: []TurnSample{
			{FreshInput: 0, Output: 100},
			{FreshInput: 1, Output: 400},
			{FreshInput: 0, Output: 800},
			{FreshInput: 2, Output: 1600},
		},
		TurnsPerMessage:  []int{8, 12, 16, 24},
		ObservedMessages: 4,
		YoungThreshold:   3,
	}
	got := Estimate(in)
	if !got.HasEstimate {
		t.Fatal("expected an estimate")
	}
	if got.TurnsTier != TurnsObserved {
		t.Errorf("want observed tier, got %q", got.TurnsTier)
	}
	if hasWarn(got.Warnings, WarnTurnsInferredPrior) || hasWarn(got.Warnings, WarnTurnsInferredDefault) {
		t.Errorf("observed tier must not warn inferred: %v", got.Warnings)
	}
	// Band must be monotonic non-decreasing in message cost.
	if !(got.Low.MessageUSD <= got.Mid.MessageUSD && got.Mid.MessageUSD <= got.High.MessageUSD) {
		t.Errorf("band not monotonic: low=%.6f mid=%.6f high=%.6f",
			got.Low.MessageUSD, got.Mid.MessageUSD, got.High.MessageUSD)
	}
	// Sanity on the dominant term: mid per-turn ≈ P·CacheRead = 200000×1.5e-6 = 0.30 + output.
	wantFloor := 200_000 * opusRates.CacheRead
	if got.Mid.PerTurnUSD < wantFloor {
		t.Errorf("mid per-turn %.6f below cache-read floor %.6f", got.Mid.PerTurnUSD, wantFloor)
	}
	// Mid message ≈ T_mid(=14) × per-turn.
	if got.Mid.Turns != 14 {
		t.Errorf("want mid turns 14 (median of 8,12,16,24), got %.1f", got.Mid.Turns)
	}
}

func TestEstimate_PriorTier(t *testing.T) {
	in := EstimateInput{
		Model:                "claude-opus-4-8",
		Rates:                opusRates,
		PrefixTokens:         50_000,
		TurnSamples:          []TurnSample{{FreshInput: 0, Output: 500}},
		TurnsPerMessage:      nil, // no boundaries this session
		ObservedMessages:     0,
		YoungThreshold:       3,
		PriorTurnsPerMessage: []int{10, 15, 20},
		DefaultTurns:         12,
	}
	got := Estimate(in)
	if got.TurnsTier != TurnsPrior {
		t.Errorf("want prior tier, got %q", got.TurnsTier)
	}
	if !hasWarn(got.Warnings, WarnTurnsInferredPrior) {
		t.Errorf("want turns_inferred_prior, got %v", got.Warnings)
	}
	if got.Mid.Turns != 15 {
		t.Errorf("want mid turns 15 (median of prior), got %.1f", got.Mid.Turns)
	}
}

func TestEstimate_DefaultTier(t *testing.T) {
	in := EstimateInput{
		Model:        "gpt-5.4-codex",
		Rates:        opusRates,
		PrefixTokens: 0, // uncached
		TurnSamples:  []TurnSample{{FreshInput: 3000, Output: 600}},
		DefaultTurns: 12,
	}
	got := Estimate(in)
	if got.TurnsTier != TurnsDefault {
		t.Errorf("want default tier, got %q", got.TurnsTier)
	}
	if !hasWarn(got.Warnings, WarnTurnsInferredDefault) {
		t.Errorf("want turns_inferred_default, got %v", got.Warnings)
	}
	if !hasWarn(got.Warnings, WarnEmptyPrefix) {
		t.Errorf("want empty_prefix (P=0), got %v", got.Warnings)
	}
	if got.Mid.Turns != 12 {
		t.Errorf("want default 12 turns, got %.1f", got.Mid.Turns)
	}
	// Uncached: per-turn is fresh-input + output priced; cache-read term 0.
	wantPerTurn := 3000*opusRates.Input + 600*opusRates.Output
	if math.Abs(got.Mid.PerTurnUSD-wantPerTurn) > 1e-9 {
		t.Errorf("uncached per-turn %.9f want %.9f", got.Mid.PerTurnUSD, wantPerTurn)
	}
}

func TestEstimate_FastMode(t *testing.T) {
	base := EstimateInput{
		Model:            "claude-opus-4-8",
		Rates:            opusRates,
		PrefixTokens:     100_000,
		TurnSamples:      []TurnSample{{FreshInput: 0, Output: 500}},
		TurnsPerMessage:  []int{10, 10, 10},
		ObservedMessages: 3,
		YoungThreshold:   3,
	}
	slow := Estimate(base)
	base.CurrentFast = true
	fast := Estimate(base)
	if !hasWarn(fast.Warnings, WarnFastModeActive) {
		t.Errorf("want fast_mode_active, got %v", fast.Warnings)
	}
	if !(fast.Mid.PerTurnUSD > slow.Mid.PerTurnUSD) {
		t.Errorf("fast per-turn %.6f should exceed slow %.6f", fast.Mid.PerTurnUSD, slow.Mid.PerTurnUSD)
	}
}

func TestEstimate_YoungSessionBlendsPrior(t *testing.T) {
	// Young session (1 msg < threshold 3) with a prior shape blends the
	// prior samples into the (S,O) quantiles AND uses the prior T.
	in := EstimateInput{
		Model:                "claude-opus-4-8",
		Rates:                opusRates,
		PrefixTokens:         80_000,
		TurnSamples:          []TurnSample{{FreshInput: 0, Output: 100}},
		TurnsPerMessage:      []int{30}, // 1 message, below threshold
		ObservedMessages:     1,
		YoungThreshold:       3,
		PriorTurnsPerMessage: []int{8, 12, 16},
		PriorTurnSamples:     []TurnSample{{FreshInput: 0, Output: 2000}, {FreshInput: 0, Output: 3000}},
	}
	got := Estimate(in)
	if got.TurnsTier != TurnsPrior {
		t.Errorf("young session should use prior T, got %q", got.TurnsTier)
	}
	// High output quantile should reflect the blended prior (2000/3000),
	// not just the lone session sample (100).
	if got.High.Output < 1000 {
		t.Errorf("expected prior-blended high output, got %d", got.High.Output)
	}
}

func TestQuantile(t *testing.T) {
	s := []float64{10, 20, 30, 40} // sorted
	cases := []struct {
		q    float64
		want float64
	}{
		{0, 10}, {1, 40}, {0.5, 25}, {0.25, 17.5}, {0.75, 32.5},
	}
	for _, c := range cases {
		if got := quantile(s, c.q); math.Abs(got-c.want) > 1e-9 {
			t.Errorf("quantile(%.2f)=%.4f want %.4f", c.q, got, c.want)
		}
	}
	if quantile(nil, 0.5) != 0 {
		t.Errorf("empty quantile should be 0")
	}
	if quantile([]float64{7}, 0.9) != 7 {
		t.Errorf("single-element quantile should be the element")
	}
}

// TestEstimate_PricingDecoupledFromFacts pins the invariant that a
// missing pricing entry suppresses ONLY the dollar columns. The token
// facts (prefix, per-turn quantiles, fan-out tier, sample counts) are
// observations of the session, so they must be identical whether or not
// the model has a rate card.
//
// Regression: the dashboard handler used to bail on a pricing miss and
// return a zeroed EstimateResult carrying a false no_session_history,
// which the context-window surface rendered as "no prefix observed yet"
// on a session with three observed turns (opencode alias model
// "big-pickle", latest cache_read 8448).
func TestEstimate_PricingDecoupledFromFacts(t *testing.T) {
	// The real remote-node shape: 3 turns, cache_read 8320/8320/8448,
	// P "now" = the latest read.
	shape := func() EstimateInput {
		return EstimateInput{
			Model:        "big-pickle",
			PrefixTokens: 8448,
			TurnSamples: []TurnSample{
				{FreshInput: 120, Output: 300},
				{FreshInput: 240, Output: 700},
				{FreshInput: 360, Output: 1500},
			},
			TurnsPerMessage:  []int{2, 3, 4},
			ObservedMessages: 3,
			YoungThreshold:   3,
		}
	}

	cases := []struct {
		name    string
		mutate  func(*EstimateInput)
		wantEst bool // HasEstimate (dollar half)
		wantSh  bool // HasShape (fact half)
		wantUSD bool // mid.MessageUSD > 0
		want    []Warning
		notWant []Warning
	}{
		{
			name:    "priced model keeps the cost band",
			mutate:  func(in *EstimateInput) { in.Rates = opusRates },
			wantEst: true, wantSh: true, wantUSD: true,
			notWant: []Warning{WarnNoPricing, WarnNoSessionHistory},
		},
		{
			name: "unpriced model keeps the facts and drops the dollars",
			mutate: func(in *EstimateInput) {
				in.PricingUnknown = true // Rates stays zero, as the miss leaves it
			},
			wantEst: false, wantSh: true, wantUSD: false,
			want:    []Warning{WarnNoPricing},
			notWant: []Warning{WarnNoSessionHistory},
		},
		{
			name: "free model is priced, not unknown",
			mutate: func(in *EstimateInput) {
				in.Rates = RatePair{} // ":free" resolves exact with all-zero rates
			},
			wantEst: true, wantSh: true, wantUSD: false,
			notWant: []Warning{WarnNoPricing, WarnNoSessionHistory},
		},
		{
			name: "no substrate at all stays fully empty",
			mutate: func(in *EstimateInput) {
				in.TurnSamples = nil
				in.TurnsPerMessage = nil
				in.ObservedMessages = 0
				in.PrefixTokens = 0
				in.PricingUnknown = true
			},
			wantEst: false, wantSh: false, wantUSD: false,
			want:    []Warning{WarnNoSessionHistory},
			notWant: []Warning{WarnNoPricing},
		},
	}

	// The priced run is the reference the unpriced run's facts must match.
	priced := shape()
	priced.Rates = opusRates
	ref := Estimate(priced)

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := shape()
			tc.mutate(&in)
			got := Estimate(in)

			if got.HasEstimate != tc.wantEst {
				t.Errorf("HasEstimate = %v, want %v (warnings %v)", got.HasEstimate, tc.wantEst, got.Warnings)
			}
			if got.HasShape != tc.wantSh {
				t.Errorf("HasShape = %v, want %v", got.HasShape, tc.wantSh)
			}
			if (got.Mid.MessageUSD > 0) != tc.wantUSD {
				t.Errorf("mid.MessageUSD = %v, want positive=%v", got.Mid.MessageUSD, tc.wantUSD)
			}
			for _, w := range tc.want {
				if !hasWarn(got.Warnings, w) {
					t.Errorf("missing warning %q; got %v", w, got.Warnings)
				}
			}
			for _, w := range tc.notWant {
				if hasWarn(got.Warnings, w) {
					t.Errorf("unexpected warning %q; got %v", w, got.Warnings)
				}
			}
			if !tc.wantSh {
				return
			}
			// Every FACT must be byte-identical to the priced reference.
			if got.PrefixTokens != 8448 {
				t.Errorf("PrefixTokens = %d, want 8448 (latest observed cache_read)", got.PrefixTokens)
			}
			if got.SampleTurns != ref.SampleTurns || got.SampleTurns != 3 {
				t.Errorf("SampleTurns = %d, want 3", got.SampleTurns)
			}
			if got.SampleMessages != ref.SampleMessages || got.SampleMessages != 3 {
				t.Errorf("SampleMessages = %d, want 3", got.SampleMessages)
			}
			if got.TurnsTier != ref.TurnsTier || got.TurnsTier != TurnsObserved {
				t.Errorf("TurnsTier = %q, want %q", got.TurnsTier, TurnsObserved)
			}
			for _, b := range []struct {
				name     string
				got, ref Band
			}{
				{"low", got.Low, ref.Low},
				{"mid", got.Mid, ref.Mid},
				{"high", got.High, ref.High},
			} {
				if b.got.Turns != b.ref.Turns || b.got.FreshInput != b.ref.FreshInput || b.got.Output != b.ref.Output {
					t.Errorf("%s band token dims = (T %.1f, S %d, O %d), want (T %.1f, S %d, O %d)",
						b.name, b.got.Turns, b.got.FreshInput, b.got.Output,
						b.ref.Turns, b.ref.FreshInput, b.ref.Output)
				}
			}
			if !tc.wantEst {
				for _, b := range []struct {
					name string
					band Band
				}{{"low", got.Low}, {"mid", got.Mid}, {"high", got.High}} {
					if b.band.PerTurnUSD != 0 || b.band.MessageUSD != 0 {
						t.Errorf("%s band should carry no dollars without pricing: per_turn=%v message=%v",
							b.name, b.band.PerTurnUSD, b.band.MessageUSD)
					}
				}
			}
		})
	}
}
