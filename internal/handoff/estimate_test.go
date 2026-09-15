package handoff

import (
	"math"
	"strings"
	"testing"
)

func pinnedPrice(model string, tokens int64) float64 {
	// $10 per million input tokens, flat — a fixture, not a real rate.
	return float64(tokens) * 10 / 1_000_000
}

// TestContextFitWarning covers the context-window mismatch advisory: it fires
// only when a full carry is present AND exceeds the threshold, is silent below
// it, is silent when the full row is absent (unknown context), and disables at
// threshold 0.
func TestContextFitWarning(t *testing.T) {
	big := Estimate(EstimateInput{
		TargetModel: "m", ContextTokens: 350_000, ForkShare: 1,
		DistilledTokens: 2_000, TailTokens: 1_000, Price: pinnedPrice,
	})
	if w := ContextFitWarning(big, 200_000); w == "" {
		t.Error("350K full carry over a 200K floor must warn")
	} else if !strings.Contains(w, "350K") || !strings.Contains(w, "200K") {
		t.Errorf("warning should cite the compact token figures, got %q", w)
	}

	small := Estimate(EstimateInput{
		TargetModel: "m", ContextTokens: 50_000, ForkShare: 1, Price: pinnedPrice,
	})
	if w := ContextFitWarning(small, 200_000); w != "" {
		t.Errorf("50K full carry under the floor must not warn, got %q", w)
	}

	// No full row (ContextTokens unknown) → never warn.
	noFull := Estimate(EstimateInput{TargetModel: "m", DistilledTokens: 9, Price: pinnedPrice})
	if w := ContextFitWarning(noFull, 200_000); w != "" {
		t.Errorf("absent full row must not warn, got %q", w)
	}

	// Threshold 0 disables the check.
	if w := ContextFitWarning(big, 0); w != "" {
		t.Errorf("threshold 0 disables the warning, got %q", w)
	}
}

// TestEstimate_CarryTable exercises one case per plan §9 carry row.
func TestEstimate_CarryTable(t *testing.T) {
	res := Estimate(EstimateInput{
		TargetModel:     "gpt-5.5",
		MetadataTokens:  1000,
		DistilledTokens: 3000,
		TailTokens:      2000,
		ContextTokens:   100_000,
		ForkShare:       0.5,
		Price:           pinnedPrice,
	})
	if len(res.Rows) != 5 {
		t.Fatalf("want 5 rows, got %d", len(res.Rows))
	}
	byMode := map[CarryMode]CarryEstimate{}
	for _, r := range res.Rows {
		byMode[r.Mode] = r
	}
	if got := byMode[CarryMetadata].Tokens; got != 1000 {
		t.Errorf("metadata tokens = %d", got)
	}
	if got := byMode[CarryDistilledTail].Tokens; got != 5000 {
		t.Errorf("distilled_tail tokens = %d, want distilled+tail", got)
	}
	full := byMode[CarryFull]
	if full.Tokens != 50_000 {
		t.Errorf("full tokens = %d, want fork-scaled 50000", full.Tokens)
	}
	if math.Abs(full.CostUSD-0.5) > 1e-9 {
		t.Errorf("full cost = %v, want 0.5", full.CostUSD)
	}
	if full.Note == "" {
		t.Error("full row must carry the resend caveat")
	}
	fullCache := byMode[CarryFullCache]
	if fullCache.Tokens != 50_000 {
		t.Errorf("full_cache tokens = %d, want fork-scaled 50000 (same warm-context basis as full)", fullCache.Tokens)
	}
	if fullCache.Note == "" {
		t.Error("full_cache row must carry a note")
	}
}

// TestEstimate_OmitsUngroundedFullRow pins the honesty rule: no context
// weight ⇒ no full row.
func TestEstimate_OmitsUngroundedFullRow(t *testing.T) {
	res := Estimate(EstimateInput{TargetModel: "m", MetadataTokens: 10, DistilledTokens: 20, TailTokens: 5, Price: pinnedPrice})
	for _, r := range res.Rows {
		if r.Mode == CarryFull {
			t.Fatal("full row must be omitted when ContextTokens is unknown")
		}
	}
}

func TestEstimate_DefensiveDefaults(t *testing.T) {
	res := Estimate(EstimateInput{TargetModel: "m", ContextTokens: 100, ForkShare: -3})
	if res.ForkShare != 1 {
		t.Errorf("out-of-range fork share must clamp to 1, got %v", res.ForkShare)
	}
	for _, r := range res.Rows {
		if r.CostUSD != 0 {
			t.Errorf("nil PriceFunc must price 0, got %v", r.CostUSD)
		}
	}
}

func TestTokenEstimate(t *testing.T) {
	if TokenEstimate("") != 0 {
		t.Error("empty string is 0 tokens")
	}
	if got := TokenEstimate("abcd"); got != 1 {
		t.Errorf("4 chars = %d tokens, want 1", got)
	}
	if got := TokenEstimate("abcde"); got != 2 {
		t.Errorf("5 chars = %d tokens, want 2 (round up)", got)
	}
}

// TestEstimate_FullCacheNoteReflectsSourceCapability pins that the full_cache
// price-table row is HONEST about the source adapter's capability: without an
// un-excerpted (FullTranscriptReader) reader it degrades to full and the note
// says so, instead of advertising a distinct "prompt cache" option that the
// source cannot actually produce (the "Full" == "Full + cache" confusion).
func TestEstimate_FullCacheNoteReflectsSourceCapability(t *testing.T) {
	fullCacheRow := func(hasReader bool) CarryEstimate {
		res := Estimate(EstimateInput{
			TargetModel:         "m",
			ContextTokens:       100_000,
			ForkShare:           1,
			SourceHasFullReader: hasReader,
			Price:               pinnedPrice,
		})
		for _, r := range res.Rows {
			if r.Mode == CarryFullCache {
				return r
			}
		}
		t.Fatal("no full_cache row")
		return CarryEstimate{}
	}
	noReader := fullCacheRow(false)
	if !strings.Contains(noReader.Note, "= full") || !strings.Contains(noReader.Note, "no un-excerpted") {
		t.Errorf("full_cache note (no reader) must say it degrades to full: %q", noReader.Note)
	}
	withReader := fullCacheRow(true)
	if !strings.Contains(withReader.Note, "prompt cache") {
		t.Errorf("full_cache note (with reader) must describe cache replication: %q", withReader.Note)
	}
	if noReader.Note == withReader.Note {
		t.Error("full_cache note must differ by source capability")
	}
}

// TestEstimate_SourceHasFullReaderMirrorsInput pins that EstimateResult
// exposes SourceHasFullReader as a structured field (not just baked into the
// full_cache row's Note text) — the dashboard handoff API reads this field
// directly to grey out the full_cache option, so it must be the same fact
// the input carried, never re-derived.
func TestEstimate_SourceHasFullReaderMirrorsInput(t *testing.T) {
	for _, hasReader := range []bool{false, true} {
		res := Estimate(EstimateInput{TargetModel: "m", ContextTokens: 100, ForkShare: 1, SourceHasFullReader: hasReader, Price: pinnedPrice})
		if res.SourceHasFullReader != hasReader {
			t.Errorf("SourceHasFullReader = %v, want %v", res.SourceHasFullReader, hasReader)
		}
	}
}
