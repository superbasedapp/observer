package budgetwarn

import (
	"strings"
	"testing"
	"time"
)

// TestEvaluateRaisedCapFollowsCurrentReading is the node 1 report of
// 2026-10-06: a team token cap of 1,000,000 was crossed (101%), the admin
// raised it to 10,000,000, and the banner kept reading "Budget exceeded" at
// 11%. Every row is one evaluation in sequence over the same state.
func TestEvaluateRaisedCapFollowsCurrentReading(t *testing.T) {
	day := time.Date(2026, 10, 5, 6, 8, 0, 0, time.UTC)
	team := func(capV, spent float64, mode string) Window {
		return Window{Window: "monthly", Unit: "tokens", Cap: capV, Spent: spent, Scope: "team:t1", Enforcement: mode}
	}
	steps := []struct {
		name       string
		w          Window
		at         time.Time
		wantNew    []float64
		wantLevel  string
		wantActive int
		wantText   string
		noText     string
	}{
		{"crossed the 1M cap", team(1_000_000, 1_005_193, "soft"), day, []float64{1}, "exceeded", 1, "101% used", ""},
		{"cap raised to 10M: 11% is not exceeded", team(10_000_000, 1_102_379, "soft"), day.Add(36 * time.Hour), nil, "ok", 0, "", ""},
		{"still under the raised cap", team(10_000_000, 2_000_000, "soft"), day.Add(37 * time.Hour), nil, "ok", 0, "", ""},
		{"crossing the raised cap announces again", team(10_000_000, 10_000_001, "soft"), day.Add(38 * time.Hour), []float64{1}, "exceeded", 1, "100% used", ""},
	}
	var state State
	for _, s := range steps {
		st, next := Evaluate([]Window{s.w}, state, s.at)
		state = next
		var got []float64
		for _, n := range st.New {
			got = append(got, n.Threshold)
		}
		if len(got) != len(s.wantNew) || (len(got) == 1 && got[0] != s.wantNew[0]) {
			t.Fatalf("%s: new = %v, want %v", s.name, got, s.wantNew)
		}
		if len(st.Windows) != 1 || st.Windows[0].Level != s.wantLevel {
			t.Fatalf("%s: windows = %+v, want level %s", s.name, st.Windows, s.wantLevel)
		}
		if len(st.Active) != s.wantActive {
			t.Fatalf("%s: active = %+v, want %d", s.name, st.Active, s.wantActive)
		}
		if s.wantText != "" && !strings.Contains(st.Active[0].Message, s.wantText) {
			t.Fatalf("%s: message %q missing %q", s.name, st.Active[0].Message, s.wantText)
		}
	}
}

// TestEvaluateNeverExceededBelowCap pins the invariant every surface relies
// on: no window and no active notice is "exceeded" while the reading is under
// its cap, and a hard cap the reading is under is never described as
// blocking. It walks raised caps, lowered caps and dips with a ladder.
func TestEvaluateNeverExceededBelowCap(t *testing.T) {
	base := time.Date(2026, 10, 6, 1, 0, 0, 0, time.UTC)
	w := func(capV, spent float64, mode string) Window {
		return Window{
			Window: "daily", Unit: "usd", Cap: capV, Spent: spent, Scope: "member:m", Enforcement: mode, Thresholds: []float64{0.75, 0.9, 1},
			GuardMode: "enforce", OrgAuthoritative: true,
		}
	}
	seq := []Window{
		w(0.30, 0.40, "hard"), // 133%: exceeded, blocking
		w(1.00, 0.40, "hard"), // cap raised: 40%, under every rung
		w(1.00, 0.80, "hard"), // 80%: the 75% rung against the new cap
		w(1.00, 0.95, "hard"), // 95%
		w(1.00, 0.50, "hard"), // dip, same cap
		w(0.50, 0.50, "hard"), // cap lowered: exactly at 100%
		w(0.80, 0.50, "soft"), // raised again and soft: 62%
	}
	var state State
	for i, win := range seq {
		st, next := Evaluate([]Window{win}, state, base.Add(time.Duration(i)*time.Minute))
		state = next
		ratio := win.Spent / win.Cap
		for _, ws := range st.Windows {
			if ws.Level == "exceeded" && ratio < 1 {
				t.Fatalf("step %d: window exceeded at %.2f: %+v", i, ratio, ws)
			}
		}
		for _, n := range st.Active {
			if n.Level == "exceeded" && ratio < 1 {
				t.Fatalf("step %d: active notice exceeded at %.2f: %+v", i, ratio, n)
			}
			if ratio < 1 && strings.Contains(n.Message, "are blocked") {
				t.Fatalf("step %d: message claims blocking at %.2f: %q", i, ratio, n.Message)
			}
			if n.Threshold > ratio+1e-9 {
				t.Fatalf("step %d: active rung %.2f above the reading %.2f", i, n.Threshold, ratio)
			}
		}
	}
}
