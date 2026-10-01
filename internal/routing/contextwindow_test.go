package routing

import (
	"slices"
	"testing"
)

// TestDecide_ContextWindowFromResolver pins the §R11.2 fit check end to end
// against the injected Tokenomics window resolver (Snapshot.ContextWindow):
// a known window that fits routes cleanly, a known window that is too small
// excludes the candidate, and an UNKNOWN window (no entry, or no resolver at
// all) never excludes the candidate and never assumes a default size - the
// switch goes through carrying ReasonContextWindowUnknown instead.
func TestDecide_ContextWindowFromResolver(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		// windows backs Snapshot.ContextWindow; nil = no resolver.
		windows      map[string]int64
		promptTokens int64
		wantHaiku    bool
		wantUnknown  bool
	}{
		{name: "known_fits", windows: map[string]int64{"claude-haiku-4-5": 200_000, "claude-opus-4-8": 1_000_000}, promptTokens: 120_000, wantHaiku: true},
		{name: "known_too_small", windows: map[string]int64{"claude-haiku-4-5": 100_000, "claude-sonnet-4-6": 1_000_000, "claude-opus-4-8": 1_000_000}, promptTokens: 120_000, wantHaiku: false},
		// 150K stays under the 200K long_context band so the turn is still
		// read_only; the candidate's window is simply not stated.
		{name: "unknown_not_excluded", windows: map[string]int64{"claude-opus-4-8": 1_000_000}, promptTokens: 150_000, wantHaiku: true, wantUnknown: true},
		{name: "no_resolver_not_excluded", windows: nil, promptTokens: 150_000, wantHaiku: true, wantUnknown: true},
		{name: "no_prompt_size_no_annotation", windows: nil, promptTokens: 0, wantHaiku: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			snap := testSnapshot()
			if tc.windows != nil {
				snap.ContextWindow = mapWindows(tc.windows)
			}
			in := readOnlyInput()
			in.Shape.PromptTokens = tc.promptTokens
			d := Decide(valuePolicy(t), snap, in)
			if gotHaiku := d.Changed && d.SelectedModel == "claude-haiku-4-5"; gotHaiku != tc.wantHaiku {
				t.Fatalf("selected %q (changed=%v), want haiku=%v; reasons %v", d.SelectedModel, d.Changed, tc.wantHaiku, d.ReasonCodes)
			}
			if got := slices.Contains(d.ReasonCodes, ReasonContextWindowUnknown); got != tc.wantUnknown {
				t.Errorf("context_window_unknown annotated = %v, want %v (reasons %v)", got, tc.wantUnknown, d.ReasonCodes)
			}
		})
	}
}
