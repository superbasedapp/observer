package sessiongauge

import (
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/pricingfeed"
)

func i64(v int64) *int64     { return &v }
func f64(v float64) *float64 { return &v }

func TestLatestPrefixAndObserved(t *testing.T) {
	cases := []struct {
		name     string
		turns    []Turn
		prefix   int64
		observed bool
	}{
		{name: "empty", turns: nil, prefix: 0, observed: false},
		{name: "uncached provider", turns: []Turn{{Timestamp: "a", Input: 10, Output: 5}}, prefix: 0, observed: true},
		{name: "newest non-zero wins", turns: []Turn{
			{Timestamp: "2026-01-01T00:00:02Z", CacheRead: 300, Input: 1},
			{Timestamp: "2026-01-01T00:00:01Z", CacheRead: 900, Input: 1},
			{Timestamp: "2026-01-01T00:00:03Z", CacheRead: 0, Input: 1},
		}, prefix: 300, observed: true},
		{name: "timestamp tie takes the larger", turns: []Turn{
			{Timestamp: "t", CacheRead: 100, Output: 1},
			{Timestamp: "t", CacheRead: 400, Output: 1},
		}, prefix: 400, observed: true},
		{name: "cache-only rows are not observed usage", turns: []Turn{{Timestamp: "t", CacheRead: 50}}, prefix: 50, observed: false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := LatestPrefix(c.turns); got != c.prefix {
				t.Errorf("LatestPrefix = %d, want %d", got, c.prefix)
			}
			if got := Observed(c.turns); got != c.observed {
				t.Errorf("Observed = %v, want %v", got, c.observed)
			}
			// Order independence: reversing the slice changes nothing.
			rev := make([]Turn, len(c.turns))
			for i := range c.turns {
				rev[len(c.turns)-1-i] = c.turns[i]
			}
			if got := LatestPrefix(rev); got != c.prefix {
				t.Errorf("LatestPrefix(reversed) = %d, want %d", got, c.prefix)
			}
		})
	}
}

func TestDominantModel(t *testing.T) {
	turns := []Turn{
		{Model: "b", Input: 10, Output: 10},
		{Model: "a", Input: 20},
		{Model: "", Input: 1000},
	}
	if got := DominantModel(turns); got != "a" {
		t.Fatalf("DominantModel = %q, want a (tie by name)", got)
	}
	if got := DominantModel(nil); got != "" {
		t.Fatalf("DominantModel(nil) = %q, want empty", got)
	}
}

func TestContextLadder(t *testing.T) {
	windows := Windows{"claude-sonnet-4-5": 200_000}
	turns := []Turn{{Timestamp: "t1", Model: "claude-sonnet-4-5-20250929", Input: 10, Output: 5, CacheRead: 50_000}}
	cases := []struct {
		name       string
		in         ContextInput
		wantRatio  *float64
		wantBudget int64
		wantSource string
		wantOver   bool
		wantModel  string
	}{
		{
			name:      "no ceiling at all is unknown, not 0%",
			in:        ContextInput{Turns: turns},
			wantModel: "claude-sonnet-4-5-20250929",
		},
		{
			name:       "reported budget wins over the catalog window",
			in:         ContextInput{Turns: turns, ReportedBudget: 100_000, Windows: windows},
			wantRatio:  f64(0.5),
			wantBudget: 100_000, wantSource: BudgetReported,
			wantModel: "claude-sonnet-4-5-20250929",
		},
		{
			name:       "catalog window via the date-suffix rung",
			in:         ContextInput{Turns: turns, Windows: windows},
			wantRatio:  f64(0.25),
			wantBudget: 200_000, wantSource: BudgetModelWindow,
			wantModel: "claude-sonnet-4-5-20250929",
		},
		{
			name:       "session model overrides the dominant turn model",
			in:         ContextInput{Turns: turns, SessionModel: "unknown-model", Windows: windows},
			wantModel:  "unknown-model",
			wantBudget: 0,
		},
		{
			name:       "reported budget exceeded clips to a full ring",
			in:         ContextInput{Turns: turns, ReportedBudget: 10_000},
			wantRatio:  f64(1),
			wantBudget: 10_000, wantSource: BudgetReported,
			wantModel: "claude-sonnet-4-5-20250929",
		},
		{
			name:       "catalog window exceeded is unknown, flagged",
			in:         ContextInput{Turns: []Turn{{Timestamp: "t", Model: "claude-sonnet-4-5", Input: 1, CacheRead: 600_000}}, Windows: windows},
			wantBudget: 200_000, wantSource: BudgetModelWindow, wantOver: true,
			wantModel: "claude-sonnet-4-5",
		},
		{
			name:       "ceiling known, no prefix: no ratio",
			in:         ContextInput{Turns: []Turn{{Timestamp: "t", Model: "claude-sonnet-4-5", Input: 1}}, Windows: windows},
			wantBudget: 200_000, wantSource: BudgetModelWindow,
			wantModel: "claude-sonnet-4-5",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			g := Context(c.in)
			if (g.Ratio == nil) != (c.wantRatio == nil) || (g.Ratio != nil && *g.Ratio != *c.wantRatio) {
				t.Errorf("Ratio = %v, want %v", deref(g.Ratio), deref(c.wantRatio))
			}
			if g.BudgetTokens != c.wantBudget || g.BudgetSource != c.wantSource {
				t.Errorf("budget = %d/%q, want %d/%q", g.BudgetTokens, g.BudgetSource, c.wantBudget, c.wantSource)
			}
			if g.OverWindow != c.wantOver {
				t.Errorf("OverWindow = %v, want %v", g.OverWindow, c.wantOver)
			}
			if g.Model != c.wantModel {
				t.Errorf("Model = %q, want %q", g.Model, c.wantModel)
			}
		})
	}
}

func deref(p *float64) any {
	if p == nil {
		return nil
	}
	return *p
}

func TestModelWindowsAndLookup(t *testing.T) {
	w := ModelWindows(map[string]*pricingfeed.Economics{
		" Claude-Opus-4-1 ": {ContextWindowTokens: i64(200_000)}, //nolint:gocritic // padded on purpose: the lookup trims and lower-cases
		"gpt-5":             {ContextWindowTokens: i64(272_000)},
		"no-window":         {},
		"zero-window":       {ContextWindowTokens: i64(0)},
		"nil-econ":          nil,
	})
	cases := map[string]int64{
		"claude-opus-4-1":           200_000,
		"anthropic/claude-opus-4-1": 200_000,
		"claude-opus-4-1-20250805":  200_000,
		"openai/gpt-5-2025-08-07":   272_000,
		"no-window":                 0,
		"zero-window":               0,
		"nil-econ":                  0,
		"claude-opus":               0,
		"":                          0,
	}
	for model, want := range cases {
		if got := w.WindowFor(model); got != want {
			t.Errorf("WindowFor(%q) = %d, want %d", model, got, want)
		}
	}
	if got := Windows(nil).WindowFor("gpt-5"); got != 0 {
		t.Errorf("nil table lookup = %d, want 0", got)
	}
}

func TestLimitLadder(t *testing.T) {
	now := time.Date(2026, 9, 28, 12, 0, 0, 0, time.UTC)
	obs := now.Add(-5 * time.Minute)
	withWindow := &Window{ObservedAt: obs, Window5hUtil: f64(0.4), Window5hReset: i64(100), Window7dUtil: f64(0.2)}
	noWindow := &Window{ObservedAt: obs}
	cases := []struct {
		name string
		in   LimitInput
		want func(t *testing.T, g LimitGauge)
	}{
		{
			name: "audited no-source tool short-circuits even with a proxy window", in: LimitInput{Tool: "cursor", Proxy: withWindow, Now: now},
			want: func(t *testing.T, g LimitGauge) {
				if !g.NoSource || g.SourceNote == "" || g.Available || g.NeedsProxy {
					t.Errorf("got %+v, want NoSource with a note", g)
				}
			},
		},
		{
			name: "proxy window wins", in: LimitInput{Tool: "claude-code", Proxy: withWindow, Transcript: withWindow, Now: now},
			want: func(t *testing.T, g LimitGauge) {
				if !g.Available || g.Source != LimitSourceProxy || *g.Window5hUtil != 0.4 || g.Window7dReset != nil ||
					g.ObservedAge != "5m ago" || g.ObservedAtUnix == nil || *g.ObservedAtUnix != obs.Unix() {
					t.Errorf("got %+v", g)
				}
			},
		},
		{
			name: "proxy without window falls to transcript", in: LimitInput{Tool: "codex", Proxy: noWindow, Transcript: withWindow, Now: now},
			want: func(t *testing.T, g LimitGauge) {
				if !g.Available || g.Source != LimitSourceTranscript {
					t.Errorf("got %+v", g)
				}
			},
		},
		{
			name: "proxy without window and no transcript is no_window", in: LimitInput{Tool: "codex", Proxy: noWindow, Now: now},
			want: func(t *testing.T, g LimitGauge) {
				if g.Available || !g.NoWindow || g.NeedsProxy || g.ObservedAge != "5m ago" {
					t.Errorf("got %+v", g)
				}
			},
		},
		{
			name: "nothing is needs_proxy", in: LimitInput{Tool: "claude-code", Now: now},
			want: func(t *testing.T, g LimitGauge) {
				if g.Available || !g.NeedsProxy || g.NoWindow {
					t.Errorf("got %+v", g)
				}
			},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) { c.want(t, Limit(c.in)) })
	}
}

func TestProviderForTool(t *testing.T) {
	for tool, want := range map[string]string{"codex": "openai", "copilot": "openai", "copilot-cli": "openai", "claude-code": "anthropic", "": "anthropic"} {
		if got := ProviderForTool(tool); got != want {
			t.Errorf("ProviderForTool(%q) = %q, want %q", tool, got, want)
		}
	}
}

func TestHumanizeAge(t *testing.T) {
	for d, want := range map[time.Duration]string{30 * time.Second: "just now", 5 * time.Minute: "5m ago", 3 * time.Hour: "3h ago", 50 * time.Hour: "2d ago"} {
		if got := HumanizeAge(d); got != want {
			t.Errorf("HumanizeAge(%v) = %q, want %q", d, got, want)
		}
	}
}

func TestReportedBudget(t *testing.T) {
	got := ReportedBudget([]string{"Rules - 15580 tokens, 61924 chars", "no count here", "Files — 420 tokens", ""})
	if got != 16000 {
		t.Fatalf("ReportedBudget = %d, want 16000", got)
	}
	if ReportedBudget(nil) != 0 {
		t.Fatal("ReportedBudget(nil) != 0")
	}
}
