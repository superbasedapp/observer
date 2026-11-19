package budgetwarn

import (
	"strings"
	"testing"
	"time"
)

func daily(spent float64) Window {
	return Window{
		Window: "daily", Unit: "usd", Cap: 0.75, Spent: spent, Scope: "member:m1",
		Enforcement: "soft", Thresholds: []float64{0.75, 0.9, 1}, Timezone: "UTC",
	}
}

// TestEvaluateLadderOncePerPeriod walks the demo-estate incident as a table:
// the budget is created at 96% (both the 75% and 90% rungs are already
// crossed, so ONE notice - the highest - is announced), the next turn takes
// it past 100% (one new notice), later turns at the same rung announce
// nothing, and the next calendar day re-arms the ladder.
func TestEvaluateLadderOncePerPeriod(t *testing.T) {
	day1 := time.Date(2026, 10, 2, 5, 13, 0, 0, time.UTC)
	steps := []struct {
		name      string
		spent     float64
		at        time.Time
		wantNew   []float64
		wantLevel string
	}{
		{"budget born at 96%", 0.718, day1, []float64{0.9}, "warning"},
		{"same rung again", 0.72, day1.Add(time.Minute), nil, "warning"},
		{"the $0.54 turn crosses 100%", 1.26, day1.Add(5 * time.Minute), []float64{1}, "exceeded"},
		{"further spend at the top rung", 1.28, day1.Add(6 * time.Minute), nil, "exceeded"},
		// The memory keeps the 100% rung (nothing is re-announced), but the
		// level is the reading NOW: 67% of the cap is under every rung, so it
		// is never shown as exceeded (node 1, 2026-10-06).
		{"a dip (stale baseline) does not re-arm", 0.5, day1.Add(7 * time.Minute), nil, "ok"},
		{"back over the cap after the dip announces nothing new", 1.3, day1.Add(8 * time.Minute), nil, "exceeded"},
		{"next day starts clean", 0.1, day1.Add(24 * time.Hour), nil, "ok"},
		{"next day 75%", 0.6, day1.Add(25 * time.Hour), []float64{0.75}, "warning"},
	}
	var state State
	for _, s := range steps {
		st, next := Evaluate([]Window{daily(s.spent)}, state, s.at)
		state = next
		var got []float64
		for _, n := range st.New {
			got = append(got, n.Threshold)
		}
		if len(got) != len(s.wantNew) {
			t.Fatalf("%s: new = %v, want %v", s.name, got, s.wantNew)
		}
		for i := range got {
			if got[i] != s.wantNew[i] {
				t.Fatalf("%s: new = %v, want %v", s.name, got, s.wantNew)
			}
		}
		if len(st.Windows) != 1 || st.Windows[0].Level != s.wantLevel {
			t.Fatalf("%s: windows = %+v, want level %s", s.name, st.Windows, s.wantLevel)
		}
	}
}

// TestEvaluateMessagesAndActive pins the developer-facing text and that the
// active list carries the CURRENT spend, not the spend at crossing time.
func TestEvaluateMessagesAndActive(t *testing.T) {
	now := time.Date(2026, 10, 2, 5, 15, 0, 0, time.UTC)
	st, state := Evaluate([]Window{daily(0.72)}, State{}, now)
	if len(st.New) != 1 {
		t.Fatalf("new = %+v", st.New)
	}
	msg := st.New[0].Message
	for _, want := range []string{"Org daily budget (you, warning only)", "96% used", "$0.72 of $0.75", "Requests are not blocked."} {
		if !strings.Contains(msg, want) {
			t.Fatalf("message %q missing %q", msg, want)
		}
	}
	st, _ = Evaluate([]Window{daily(0.74)}, state, now.Add(time.Minute))
	if len(st.Active) != 1 || st.Active[0].Spent != 0.74 || !strings.Contains(st.Active[0].Message, "99% used") {
		t.Fatalf("active = %+v", st.Active)
	}
	if st.Active[0].ID != "daily-usd-2026-10-02-0.9" {
		t.Fatalf("active id = %q", st.Active[0].ID)
	}
}

// TestEvaluateTable covers the remaining rows: hard text, tokens, empty
// ladder, zero cap, monthly period in a timezone.
func TestEvaluateTable(t *testing.T) {
	now := time.Date(2026, 10, 31, 23, 30, 0, 0, time.UTC)
	cases := []struct {
		name     string
		w        Window
		wantNew  int
		wantText string
		period   string
	}{
		{"hard at 100%", Window{Window: "daily", Unit: "usd", Cap: 1, Spent: 1.2, Enforcement: "hard", Thresholds: []float64{1}, GuardMode: "enforce", OrgAuthoritative: true}, 1, "blocked until the period resets", "2026-10-31"},
		{"hard at 90%", Window{Window: "daily", Unit: "usd", Cap: 1, Spent: 0.92, Enforcement: "hard", Thresholds: []float64{0.9, 1}, GuardMode: "enforce", OrgAuthoritative: true}, 1, "blocked at 100%", "2026-10-31"},
		{"hard at 100%, observe mode", Window{Window: "daily", Unit: "usd", Cap: 1, Spent: 1.2, Enforcement: "hard", Thresholds: []float64{1}, GuardMode: "observe", OrgAuthoritative: true}, 1, "observe mode, so requests are not blocked", "2026-10-31"},
		{"tokens", Window{Window: "monthly", Unit: "tokens", Cap: 1_000_000, Spent: 960_000, Scope: "team:t", Enforcement: "soft", Thresholds: []float64{0.75, 0.9, 1}}, 1, "960,000 tokens of 1,000,000 tokens", "2026-10"},
		{"empty ladder means 100% only", Window{Window: "daily", Unit: "usd", Cap: 1, Spent: 0.99, Enforcement: "soft"}, 0, "", "2026-10-31"},
		{"zero cap is skipped", Window{Window: "daily", Unit: "usd", Cap: 0, Spent: 5}, 0, "", ""},
		{"monthly in a zone ahead of UTC is already November", Window{Window: "monthly", Unit: "usd", Cap: 10, Spent: 9.5, Timezone: "Asia/Kolkata", Thresholds: []float64{0.9}}, 1, "your organization", "2026-11"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			st, _ := Evaluate([]Window{tc.w}, State{}, now)
			if len(st.New) != tc.wantNew {
				t.Fatalf("new = %+v, want %d", st.New, tc.wantNew)
			}
			if tc.wantText != "" && !strings.Contains(st.New[0].Message, tc.wantText) {
				t.Fatalf("message %q missing %q", st.New[0].Message, tc.wantText)
			}
			if tc.period != "" && (len(st.Windows) != 1 || st.Windows[0].Period != tc.period) {
				t.Fatalf("windows = %+v, want period %s", st.Windows, tc.period)
			}
		})
	}
}

func TestLabels(t *testing.T) {
	for _, c := range [][2]string{{"member:x", "you"}, {"team:t", "your team"}, {"org", "your organization"}, {"", "your organization"}} {
		if got := ScopeLabel(c[0]); got != c[1] {
			t.Errorf("ScopeLabel(%q) = %q want %q", c[0], got, c[1])
		}
	}
	for _, c := range [][2]string{{"hard", "blocking"}, {"soft", "warning only"}, {"report", "report only"}} {
		if got := EnforcementLabel(c[0]); got != c[1] {
			t.Errorf("EnforcementLabel(%q) = %q want %q", c[0], got, c[1])
		}
	}
	for _, c := range [][3]string{
		{"hard", EffectBlocks, "blocking"},
		{"hard", EffectBlocksProxied, "blocking"},
		{"hard", EffectObserve, "warning only on this machine"},
		{"hard", EffectGuardOff, "warning only on this machine"},
		{"soft", EffectNone, "warning only"},
		{"report", EffectNone, "report only"},
	} {
		if got := EffectiveLabel(c[0], c[1]); got != c[2] {
			t.Errorf("EffectiveLabel(%q, %q) = %q want %q", c[0], c[1], got, c[2])
		}
	}
	if Amount("tokens", 1234567) != "1,234,567 tokens" || Amount("usd", 0.5) != "$0.50" {
		t.Fatal("Amount formatting")
	}
}
