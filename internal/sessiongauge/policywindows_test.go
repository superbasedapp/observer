package sessiongauge

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/orgcontract"
)

func TestDocWindows(t *testing.T) {
	list := []orgcontract.ModelContextWindow{
		{Model: " Claude-Sonnet-4-5 ", Tokens: 200_000},
		{Model: "gpt-5.6", Tokens: 0}, // non-positive: unknown
		{Model: "neg", Tokens: -5},    // non-positive: unknown
		{Model: "", Tokens: 1},        // no model: skipped
	}
	got := DocWindows(list)
	if len(got) != 1 || got["claude-sonnet-4-5"] != 200_000 {
		t.Fatalf("DocWindows = %v, want only claude-sonnet-4-5=200000", got)
	}
	if DocWindows(nil).WindowFor("x") != 0 {
		t.Fatal("empty list must read unknown")
	}
}

func TestPolicyWindowListRoundTripsThroughDocWindows(t *testing.T) {
	org := Windows{"claude-sonnet-4-5": 200_000, "gpt-5.6": 400_000, "zero": 0, " Mixed-Case ": 9} //nolint:gocritic // the padded key is the case under test: windows are keyed trimmed and lower-cased
	list := PolicyWindowList(org)
	want := []orgcontract.ModelContextWindow{
		{Model: "claude-sonnet-4-5", Tokens: 200_000}, {Model: "gpt-5.6", Tokens: 400_000}, {Model: "mixed-case", Tokens: 9},
	}
	if len(list) != len(want) {
		t.Fatalf("PolicyWindowList = %+v, want %+v", list, want)
	}
	for i := range want {
		if list[i] != want[i] {
			t.Fatalf("PolicyWindowList[%d] = %+v, want %+v (sorted, positive only, normalized)", i, list[i], want[i])
		}
	}
	if PolicyWindowList(nil) != nil || PolicyWindowList(Windows{"a": 0}) != nil {
		t.Fatal("an empty table must render as no list (omitted on the wire)")
	}
	// The node's table answers every lookup rung exactly as the org's does.
	node := DocWindows(list)
	for _, m := range []string{"claude-sonnet-4-5-20250929", "openai/gpt-5.6", "gpt-5.6", "local-model", "zero"} {
		if node.WindowFor(m) != org.WindowFor(m) {
			t.Errorf("%s: node %d != org %d", m, node.WindowFor(m), org.WindowFor(m))
		}
	}
}

// TestMergeWindowsIsLayeredLookup pins MergeWindows' contract: for every
// model id, the merged table answers exactly what walking the layers
// top-down (first non-zero WindowFor) would.
func TestMergeWindowsIsLayeredLookup(t *testing.T) {
	ids := []string{
		"x", "x-20250101", "x-2025-01-01", "anthropic/x", "anthropic/x-20250101", "openai/x",
		"y", "y-20250101", "vendor/y", "z", "",
	}
	// Every layer shape over a small key universe: each id either absent or
	// present with a layer-distinct value.
	keys := []string{"x", "x-20250101", "anthropic/x", "anthropic/x-20250101", "y", "vendor/y"}
	layerOf := func(mask int, base int64) Windows {
		w := Windows{}
		for i, k := range keys {
			if mask&(1<<i) != 0 {
				w[k] = base + int64(i)
			}
		}
		return w
	}
	n := 1 << len(keys)
	for hi := 0; hi < n; hi += 3 { // a stride keeps the test fast yet broad
		for lo := 0; lo < n; lo += 5 {
			high, low := layerOf(hi, 1000), layerOf(lo, 2000)
			merged := MergeWindows(high, low)
			for _, m := range ids {
				want := high.WindowFor(m)
				if want == 0 {
					want = low.WindowFor(m)
				}
				if got := merged.WindowFor(m); got != want {
					t.Fatalf("hi=%b lo=%b model %q: merged %d, layered %d", hi, lo, m, got, want)
				}
			}
		}
	}
	if len(MergeWindows()) != 0 || MergeWindows(nil, Windows{"a": 0}).WindowFor("a") != 0 {
		t.Fatal("empty / non-positive layers must stay unknown")
	}
}
