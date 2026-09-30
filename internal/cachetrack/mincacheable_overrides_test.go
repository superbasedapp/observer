package cachetrack

import "testing"

// TestMinCacheableOverrides_TableDriven pins the published-data seam that lets
// a Tokenomics model_economics row supersede the compiled minCacheableTable
// without a release.
//
// Every case restores the previous state with t.Cleanup, because the overrides
// are process-wide by design (one registry, the routing TierTable precedent)
// and a leaked override would silently change every later test's grading.
func TestMinCacheableOverrides_TableDriven(t *testing.T) {
	for _, tc := range []struct {
		name      string
		overrides map[string]int
		model     string
		want      int
	}{
		{
			// The default, and every build before the seam existed.
			name:  "no overrides leaves the compiled table untouched",
			model: "claude-opus-4-7",
			want:  2048,
		},
		{
			name:      "an override supersedes the compiled table",
			overrides: map[string]int{"claude-opus-4-7": 777},
			model:     "claude-opus-4-7",
			want:      777,
		},
		{
			// The override speaks where it speaks and is SILENT elsewhere.
			// Partial publisher coverage is the normal case, and a gap must
			// fall back to the compiled value, never to the 1,024 default.
			name:      "an override is silent for models it does not name",
			overrides: map[string]int{"gpt-6-sol": 1},
			model:     "haiku-4-5",
			want:      4096,
		},
		{
			// Live model strings carry SKU decorations the publisher's
			// canonical id does not, so the match is a substring scan - the
			// same rule the compiled table uses, for the same reason.
			name:      "a decorated vendor id still matches the published id",
			overrides: map[string]int{"claude-opus-5-5": 512},
			model:     "US.ANTHROPIC.CLAUDE-OPUS-5-5-V1:0",
			want:      512,
		},
		{
			// Two published ids can be substrings of one another. Longest
			// first makes the answer deterministic and the most specific id
			// win; map iteration order would make it a coin flip.
			name:      "the longest published id wins over a shorter prefix",
			overrides: map[string]int{"claude-opus-5": 512, "claude-opus-5-5": 256},
			model:     "claude-opus-5-5-20260922",
			want:      256,
		},
		{
			// Zero is how "the publisher said nothing" survives a JSON round
			// trip. Storing it would claim every prefix is cacheable.
			name:      "a non-positive published value is dropped",
			overrides: map[string]int{"claude-opus-4-7": 0},
			model:     "claude-opus-4-7",
			want:      2048,
		},
		{
			// The honest reset: a node whose feed was withdrawn falls back to
			// what it shipped with, never to "no minimum".
			name:      "clearing restores the compiled table exactly",
			overrides: nil,
			model:     "opus-5",
			want:      512,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			SetMinCacheableOverrides(tc.overrides)
			t.Cleanup(func() { SetMinCacheableOverrides(nil) })
			if got := MinCacheableTokens(tc.model); got != tc.want {
				t.Errorf("MinCacheableTokens(%q) = %d, want %d", tc.model, got, tc.want)
			}
		})
	}
}

func TestMinCacheableOverrideCount(t *testing.T) {
	t.Cleanup(func() { SetMinCacheableOverrides(nil) })
	if got := MinCacheableOverrideCount(); got != 0 {
		t.Fatalf("a fresh process must carry no overrides; got %d", got)
	}
	SetMinCacheableOverrides(map[string]int{"a": 1, "b": 2, "c": 0})
	// "c" is dropped: a non-positive value is not a published minimum.
	if got := MinCacheableOverrideCount(); got != 2 {
		t.Errorf("MinCacheableOverrideCount() = %d, want 2", got)
	}
	SetMinCacheableOverrides(nil)
	if got := MinCacheableOverrideCount(); got != 0 {
		t.Errorf("clearing left %d overrides behind", got)
	}
}
