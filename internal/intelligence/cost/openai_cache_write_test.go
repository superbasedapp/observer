package cost

import (
	"math"
	"testing"
)

// TestComputeBreakdown_GPT56CacheWrite proves the 1h-semantics decision for
// OpenAI cache writes: they are untiered, so the proxy sets CacheCreation =
// write count and leaves CacheCreation1h = 0. The engine then prices the
// whole write at the base CacheCreation rate exactly once (cc5m =
// CacheCreation - cc1h = write - 0), never touching the 1h rate.
func TestComputeBreakdown_GPT56CacheWrite(t *testing.T) {
	t.Parallel()
	const eps = 1e-9

	// Real gpt-5.6-sol pricing from the base table.
	p, ok := NewTable().Lookup("gpt-5.6-sol")
	if !ok {
		t.Fatal("gpt-5.6-sol not in pricing table")
	}

	b := TokenBundle{
		Input:           1000,
		Output:          200,
		CacheRead:       500,
		CacheCreation:   300, // cache_write_tokens from the proxy
		CacheCreation1h: 0,   // untiered — always 0 for OpenAI
	}
	got := ComputeBreakdown(p, b)

	wantCreation := 300 * 5.00 / 1_000_000 // billed once at base CacheCreation rate (1.25 x the repriced $4 input)
	if math.Abs(got.CacheCreationCost-wantCreation) > eps {
		t.Errorf("CacheCreationCost = %v, want %v (write x CacheCreation rate, once)", got.CacheCreationCost, wantCreation)
	}

	wantAI := 1000*4.0/1e6 + 200*20.0/1e6 + 500*0.40/1e6 + wantCreation
	if math.Abs(got.AICost-wantAI) > eps {
		t.Errorf("AICost = %v, want %v", got.AICost, wantAI)
	}
	// Bucket-sum invariant holds.
	sum := got.InputCost + got.OutputCost + got.CacheReadCost + got.CacheCreationCost
	if math.Abs(sum-got.AICost) > eps {
		t.Errorf("bucket sum %v != AICost %v", sum, got.AICost)
	}

	// Zero-write turn: cache_creation cost is exactly 0 — byte-identical
	// accounting to before write capture existed.
	zero := ComputeBreakdown(p, TokenBundle{Input: 1000, Output: 200, CacheRead: 500})
	if zero.CacheCreationCost != 0 {
		t.Errorf("zero-write CacheCreationCost = %v, want 0", zero.CacheCreationCost)
	}
}

// TestComputeBreakdown_OpenAIWriteNeverHits1hRate distinguishes the base rate
// from the 1h rate with a synthetic pricing where they DIFFER. With
// CacheCreation1h = 0 in the bundle, the whole write must bill at the base
// rate — proving the 1h rate is not applied to untiered OpenAI writes.
func TestComputeBreakdown_OpenAIWriteNeverHits1hRate(t *testing.T) {
	t.Parallel()
	const eps = 1e-9
	p := Pricing{Input: 5, Output: 30, CacheRead: 0.5, CacheCreation: 6.25, CacheCreation1h: 99}
	got := ComputeBreakdown(p, TokenBundle{CacheCreation: 300, CacheCreation1h: 0})
	want := 300 * 6.25 / 1_000_000 // base rate, NOT the 99 1h rate
	if math.Abs(got.CacheCreationCost-want) > eps {
		t.Errorf("CacheCreationCost = %v, want %v (base rate, not 1h rate)", got.CacheCreationCost, want)
	}
}
