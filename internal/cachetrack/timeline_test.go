package cachetrack

import "testing"

func tev(kind, cause string, read, write int64, ts string) TimelineEvent {
	return TimelineEvent{
		Timestamp: ts, Tier: "proxy", Model: "claude-opus-4-8",
		Kind: kind, Cause: cause, TokensRead: read, TokensWritten: write,
	}
}

// TestBuildTimeline_Empty pins the empty-input shape: an empty (non-nil)
// slice, not nil, matching the JSON `"timeline": []` contract.
func TestBuildTimeline_Empty(t *testing.T) {
	t.Parallel()
	tl := BuildTimeline(nil)
	if tl == nil {
		t.Fatalf("BuildTimeline(nil) = nil, want non-nil empty slice")
	}
	if len(tl) != 0 {
		t.Fatalf("BuildTimeline(nil) = %d items, want 0", len(tl))
	}
}

// TestBuildTimeline_AllBaseline pins operator UI steer #1: a run of
// suffix_growth hit/write events collapses into ONE roll-up entry.
func TestBuildTimeline_AllBaseline(t *testing.T) {
	t.Parallel()
	events := []TimelineEvent{
		tev("hit", "suffix_growth", 10000, 0, "2026-06-09T00:00:00Z"),
		tev("write", "suffix_growth", 9000, 200, "2026-06-09T00:00:10Z"),
		tev("hit", "suffix_growth", 9100, 0, "2026-06-09T00:00:20Z"),
		tev("write", "suffix_growth", 9200, 250, "2026-06-09T00:00:30Z"),
	}
	tl := BuildTimeline(events)
	if len(tl) != 1 {
		t.Fatalf("got %d timeline items, want 1 (all baseline -> single roll-up)", len(tl))
	}
	item := tl[0]
	if item.Kind != "baseline" {
		t.Errorf("Kind = %q, want baseline", item.Kind)
	}
	if item.Count != 4 {
		t.Errorf("Count = %d, want 4", item.Count)
	}
	if item.BaselineReadSum != 37300 || item.BaselineWriteSum != 450 {
		t.Errorf("token sums = (%d,%d), want (37300,450)", item.BaselineReadSum, item.BaselineWriteSum)
	}
	if item.FirstAt != "2026-06-09T00:00:00Z" || item.LastAt != "2026-06-09T00:00:30Z" {
		t.Errorf("timestamps = (%s,%s), want first/last", item.FirstAt, item.LastAt)
	}
}

// TestBuildTimeline_AnomalyBreaksRun pins the contiguous-run semantics:
// an anomaly between two baseline runs SPLITS the timeline into
// baseline-run, anomaly, baseline-run.
func TestBuildTimeline_AnomalyBreaksRun(t *testing.T) {
	t.Parallel()
	events := []TimelineEvent{
		tev("hit", "suffix_growth", 10000, 0, "2026-06-09T00:00:00Z"),
		tev("write", "suffix_growth", 9000, 200, "2026-06-09T00:00:10Z"),
		tev("invalidation_rewrite", "system_changed", 1500, 8000, "2026-06-09T00:00:20Z"),
		tev("hit", "suffix_growth", 11000, 0, "2026-06-09T00:00:30Z"),
		tev("write", "suffix_growth", 11500, 250, "2026-06-09T00:00:40Z"),
	}
	tl := BuildTimeline(events)
	if len(tl) != 3 {
		t.Fatalf("got %d timeline items, want 3 (baseline + anomaly + baseline)", len(tl))
	}
	if tl[0].Kind != "baseline" || tl[0].Count != 2 {
		t.Errorf("item 0: %+v, want baseline count=2", tl[0])
	}
	if tl[1].Kind != "anomaly" || tl[1].Event == nil {
		t.Fatalf("item 1: %+v, want anomaly", tl[1])
	}
	if tl[1].Event.Cause != "system_changed" {
		t.Errorf("anomaly cause = %q, want system_changed", tl[1].Event.Cause)
	}
	if tl[1].Flagged {
		t.Errorf("system_changed should NOT be flagged (it's a real invalidation when it fires)")
	}
	if tl[2].Kind != "baseline" || tl[2].Count != 2 {
		t.Errorf("item 2: %+v, want baseline count=2", tl[2])
	}
}

// TestBuildTimeline_FlaggedCause pins operator UI steer #2: tools_changed
// is a known-limitation flagged cause; system_changed is not.
func TestBuildTimeline_FlaggedCause(t *testing.T) {
	t.Parallel()
	events := []TimelineEvent{
		tev("invalidation_rewrite", "tools_changed", 39056, 5400, "2026-06-09T00:00:00Z"),
		tev("invalidation_rewrite", "system_changed", 1500, 8000, "2026-06-09T00:00:10Z"),
	}
	tl := BuildTimeline(events)
	if len(tl) != 2 {
		t.Fatalf("got %d items, want 2", len(tl))
	}
	if !tl[0].Flagged {
		t.Errorf("tools_changed must be Flagged=true per docs/cache-tracking.md")
	}
	if tl[1].Flagged {
		t.Errorf("system_changed must NOT be flagged (real invalidation)")
	}
}

// TestBuildTimeline_ZeroUsageMispredictItemized pins that zero-usage
// mispredicts land in the timeline as anomalies — diagnostic-relevant
// even though the rate excludes them.
func TestBuildTimeline_ZeroUsageMispredictItemized(t *testing.T) {
	t.Parallel()
	events := []TimelineEvent{
		tev("hit", "suffix_growth", 10000, 0, "2026-06-09T00:00:00Z"),
		{
			Timestamp: "2026-06-09T00:00:10Z", Tier: "proxy", Model: "claude-opus-4-8",
			Kind: "mispredict", Cause: "unknown", TokensRead: 0, TokensWritten: 0, ZeroUsage: true,
		},
		tev("hit", "suffix_growth", 10000, 0, "2026-06-09T00:00:20Z"),
	}
	tl := BuildTimeline(events)
	if len(tl) != 3 {
		t.Fatalf("got %d items, want 3 (baseline + anomaly + baseline)", len(tl))
	}
	if tl[1].Kind != "anomaly" || tl[1].Event == nil {
		t.Fatalf("item 1 not an anomaly: %+v", tl[1])
	}
	if !tl[1].Event.ZeroUsage {
		t.Errorf("event.zero_usage must be propagated to the timeline item")
	}
}

// TestBuildTimeline_ReanchorNotBaseline pins that reanchor events are
// itemized as anomalies (not folded into a baseline run), even though
// they're excluded from the mispredict-rate denominator elsewhere.
func TestBuildTimeline_ReanchorNotBaseline(t *testing.T) {
	t.Parallel()
	events := []TimelineEvent{
		tev("reanchor", "session_start", 0, 12000, "2026-06-09T00:00:00Z"),
		tev("hit", "suffix_growth", 10000, 0, "2026-06-09T00:00:10Z"),
	}
	tl := BuildTimeline(events)
	if len(tl) != 2 {
		t.Fatalf("got %d items, want 2 (anomaly + baseline)", len(tl))
	}
	if tl[0].Kind != "anomaly" || tl[0].Event == nil || tl[0].Event.Kind != "reanchor" {
		t.Errorf("item 0 = %+v, want itemized reanchor anomaly", tl[0])
	}
	if tl[1].Kind != "baseline" || tl[1].Count != 1 {
		t.Errorf("item 1 = %+v, want baseline count=1", tl[1])
	}
}

// TestIsBaselineEvent table-drives the baseline predicate.
func TestIsBaselineEvent(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		ev   TimelineEvent
		want bool
	}{
		{"hit+suffix_growth", TimelineEvent{Kind: "hit", Cause: "suffix_growth"}, true},
		{"write+suffix_growth", TimelineEvent{Kind: "write", Cause: "suffix_growth"}, true},
		{"reanchor+suffix_growth", TimelineEvent{Kind: "reanchor", Cause: "suffix_growth"}, false},
		{"hit+system_changed", TimelineEvent{Kind: "hit", Cause: "system_changed"}, false},
		{"mispredict+suffix_growth", TimelineEvent{Kind: "mispredict", Cause: "suffix_growth"}, false},
		{"empty cause", TimelineEvent{Kind: "hit", Cause: ""}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := IsBaselineEvent(tt.ev); got != tt.want {
				t.Errorf("IsBaselineEvent(%+v) = %v, want %v", tt.ev, got, tt.want)
			}
		})
	}
}

// TestIsFlaggedCause table-drives the flagged-cause predicate.
func TestIsFlaggedCause(t *testing.T) {
	t.Parallel()
	tests := []struct {
		cause string
		want  bool
	}{
		{"tools_changed", true},
		{"system_changed", false},
		{"ttl_expired", false},
		{"", false},
	}
	for _, tt := range tests {
		t.Run(tt.cause, func(t *testing.T) {
			t.Parallel()
			if got := IsFlaggedCause(tt.cause); got != tt.want {
				t.Errorf("IsFlaggedCause(%q) = %v, want %v", tt.cause, got, tt.want)
			}
		})
	}
}

// TestCollapseTier mirrors the dashboard's tier-collapse contract.
func TestCollapseTier(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		events []TimelineEvent
		want   string
	}{
		{"empty", nil, "none"},
		{"proxy only", []TimelineEvent{{Tier: "proxy"}, {Tier: "proxy"}}, "proxy"},
		{"transcript only", []TimelineEvent{{Tier: "transcript"}}, "transcript"},
		{"mixed proxy+transcript", []TimelineEvent{{Tier: "proxy"}, {Tier: "transcript"}}, "mixed"},
		{"blank tiers only", []TimelineEvent{{Tier: ""}, {Tier: ""}}, "none"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := CollapseTier(tt.events); got != tt.want {
				t.Errorf("CollapseTier(%v) = %q, want %q", tt.events, got, tt.want)
			}
		})
	}
}

// TestBuildEfficiency rolls token counts + ratio.
func TestBuildEfficiency(t *testing.T) {
	t.Parallel()
	events := []TimelineEvent{
		tev("hit", "suffix_growth", 10000, 0, "2026-06-09T00:00:00Z"),
		tev("write", "suffix_growth", 9000, 200, "2026-06-09T00:00:10Z"),
		tev("invalidation_rewrite", "system_changed", 0, 5000, "2026-06-09T00:00:20Z"),
	}
	eff := BuildEfficiency(events)
	if eff.ReadTokens != 19000 || eff.WrittenTokens != 5200 {
		t.Errorf("tokens = (%d,%d), want (19000,5200)", eff.ReadTokens, eff.WrittenTokens)
	}
	wantRatio := 19000.0 / 5200.0
	if eff.Ratio < wantRatio-1e-6 || eff.Ratio > wantRatio+1e-6 {
		t.Errorf("ratio = %v, want %v", eff.Ratio, wantRatio)
	}
}

// TestBuildEfficiency_NoWritesNoRatio pins the divide-by-zero guard.
func TestBuildEfficiency_NoWritesNoRatio(t *testing.T) {
	t.Parallel()
	events := []TimelineEvent{
		tev("hit", "suffix_growth", 10000, 0, "2026-06-09T00:00:00Z"),
		tev("hit", "suffix_growth", 9500, 0, "2026-06-09T00:00:10Z"),
	}
	eff := BuildEfficiency(events)
	if eff.Ratio != 0 {
		t.Errorf("ratio with zero writes = %v, want 0 (divide-by-zero guard)", eff.Ratio)
	}
}

// usd is a test helper returning a *float64, so a cost_delta_usd can be set to
// a concrete value (0 included) as distinct from nil ("not computed").
func usd(v float64) *float64 { return &v }

// TestBuildEfficiency_AvoidableUSD pins the AvoidableUSD rule: only the non-nil
// POSITIVE cost_delta_usd of NON-baseline events is summed. A nil delta folds
// in nothing, a baseline suffix-growth write is unavoidable by definition, and
// a negative delta is a saving, not avoidable spend.
func TestBuildEfficiency_AvoidableUSD(t *testing.T) {
	t.Parallel()

	withDelta := func(kind, cause string, read, write int64, delta *float64) TimelineEvent {
		ev := tev(kind, cause, read, write, "2026-06-09T00:00:00Z")
		ev.CostDeltaUSD = delta
		return ev
	}

	tests := []struct {
		name   string
		events []TimelineEvent
		want   float64
	}{
		{
			name: "all nil deltas -> 0 (never fabricated)",
			events: []TimelineEvent{
				withDelta("hit", "suffix_growth", 10000, 0, nil),
				withDelta("invalidation_rewrite", "system_changed", 100, 8000, nil),
			},
			want: 0,
		},
		{
			name: "baseline positive delta is ignored",
			events: []TimelineEvent{
				withDelta("write", "suffix_growth", 9000, 200, usd(0.05)),
			},
			want: 0,
		},
		{
			name: "anomaly positive delta is summed",
			events: []TimelineEvent{
				withDelta("invalidation_rewrite", "system_changed", 100, 8000, usd(0.12)),
				withDelta("expiry_rewrite", "ttl_expired", 0, 6000, usd(0.08)),
			},
			want: 0.20,
		},
		{
			name: "negative delta (a saving) is ignored",
			events: []TimelineEvent{
				withDelta("model_switch_rewrite", "model_changed", 0, 5000, usd(-0.30)),
			},
			want: 0,
		},
		{
			name: "mixed: only the non-baseline non-nil positive delta counts",
			events: []TimelineEvent{
				withDelta("hit", "suffix_growth", 10000, 0, usd(0.99)),            // baseline -> ignored
				withDelta("write", "suffix_growth", 9000, 200, usd(0.99)),         // baseline -> ignored
				withDelta("invalidation_rewrite", "system_changed", 0, 8000, nil), // nil -> ignored
				withDelta("invalidation_rewrite", "system_changed", 0, 8000, usd(0.15)),
				withDelta("expiry_rewrite", "ttl_expired", 0, 6000, usd(-0.10)), // negative -> ignored
			},
			want: 0.15,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := BuildEfficiency(tt.events).AvoidableUSD
			if got < tt.want-1e-9 || got > tt.want+1e-9 {
				t.Errorf("AvoidableUSD = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestIsZeroUsage table-drives THE one zero-usage rule: only a mispredict with
// a zero token pair is vacant. A hit/write/reanchor with 0/0 is a real,
// gradeable event and must NOT be marked vacant.
func TestIsZeroUsage(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		kind    string
		read    int64
		written int64
		want    bool
	}{
		{"mispredict 0/0 -> vacant", "mispredict", 0, 0, true},
		{"mispredict read>0 -> graded", "mispredict", 100, 0, false},
		{"mispredict write>0 -> graded", "mispredict", 0, 50, false},
		{"hit 0/0 -> not vacant", "hit", 0, 0, false},
		{"write 0/0 -> not vacant", "write", 0, 0, false},
		{"reanchor 0/0 -> not vacant", "reanchor", 0, 0, false},
		{"empty kind 0/0 -> not vacant", "", 0, 0, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := IsZeroUsage(tt.kind, tt.read, tt.written); got != tt.want {
				t.Errorf("IsZeroUsage(%q,%d,%d) = %v, want %v", tt.kind, tt.read, tt.written, got, tt.want)
			}
		})
	}
}
