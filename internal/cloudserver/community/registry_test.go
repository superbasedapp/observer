package community

import (
	"testing"
	"time"
)

func TestLookupAndForbiddenMetric(t *testing.T) {
	if _, ok := LookupMetric("sessions_per_active_day", 1); !ok {
		t.Error("registered metric not found")
	}
	if _, ok := LookupMetric("sessions_per_active_day", 2); ok {
		t.Error("unregistered version resolved")
	}
	if _, ok := LookupMetric("made_up_metric", 1); ok {
		t.Error("forbidden metric resolved")
	}
}

func TestValidCohort(t *testing.T) {
	if !ValidCohort("global") {
		t.Error("global cohort should be valid")
	}
	if ValidCohort("arbitrary-slice") {
		t.Error("arbitrary cohort must be rejected")
	}
}

func TestBandMatchesEdges(t *testing.T) {
	m, _ := LookupMetric("sessions_per_active_day", 1) // edges [1,2,3,5,8,13]
	cases := []struct {
		v    float64
		want int
	}{
		{0.5, 0}, {1, 1}, {1.9, 1}, {2, 2}, {4, 3}, {6, 4}, {8, 5}, {12.9, 5}, {13, 6}, {100, 6},
	}
	for _, c := range cases {
		if got := m.Band(c.v); got != c.want {
			t.Errorf("Band(%v) = %d, want %d", c.v, got, c.want)
		}
	}
}

// TestRecentFinalizedWindows pins the finalized-window ladder. Anchor at MIDDAY
// on a mid-month day so no UTC-midnight/boundary flake (project UTC-midnight
// test class). The current month is never returned (it is not finalized).
func TestRecentFinalizedWindows(t *testing.T) {
	now := time.Date(2026, 3, 15, 12, 0, 0, 0, time.UTC)
	got := RecentFinalizedWindows(now, 3)
	want := []string{"2026-02", "2026-01", "2025-12"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("window[%d] = %q, want %q (got %v)", i, got[i], want[i], got)
		}
	}
	if RecentFinalizedWindows(now, 0) != nil {
		t.Error("n=0 should yield nil")
	}
	// January boundary: previous finalized month is the prior December.
	jan := time.Date(2026, 1, 10, 12, 0, 0, 0, time.UTC)
	if w := RecentFinalizedWindows(jan, 1); len(w) != 1 || w[0] != "2025-12" {
		t.Errorf("Jan boundary: got %v, want [2025-12]", w)
	}
}

// TestIsWindowFinalized pins the F5 freeze predicate at a midday anchor (no
// UTC-midnight flake). A past month is finalized; the current and future months
// are not; a malformed window is treated as not-finalized.
func TestIsWindowFinalized(t *testing.T) {
	now := time.Date(2026, 3, 15, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		window string
		want   bool
	}{
		{"2026-02", true},  // last month — fully elapsed
		{"2026-01", true},  // older — finalized
		{"2025-12", true},  // prior year — finalized
		{"2026-03", false}, // current month — in progress
		{"2026-04", false}, // future — not finalized
		{"2099-01", false},
		{"bad", false},
		{"2026-13", false}, // invalid month
	}
	for _, c := range cases {
		if got := IsWindowFinalized(now, c.window); got != c.want {
			t.Errorf("IsWindowFinalized(%q) = %v, want %v", c.window, got, c.want)
		}
	}
	// Exactly at the month boundary: 2026-03-01T00:00Z means Feb is finalized.
	boundary := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	if !IsWindowFinalized(boundary, "2026-02") {
		t.Error("at 2026-03-01T00:00Z, 2026-02 should be finalized")
	}
	if IsWindowFinalized(boundary, "2026-03") {
		t.Error("at 2026-03-01T00:00Z, 2026-03 should NOT be finalized")
	}
}

// TestIsCurrentWindow pins the Sol F10 tightening: IsCurrentWindow is STRICTER
// than !IsWindowFinalized — it accepts only the single in-progress UTC month, so
// a future window (which !IsWindowFinalized would happily accept) is rejected
// too. Anchored at midday (UTC-midnight test class).
func TestIsCurrentWindow(t *testing.T) {
	now := time.Date(2026, 3, 15, 12, 0, 0, 0, time.UTC)
	if got := CurrentWindow(now); got != "2026-03" {
		t.Fatalf("CurrentWindow = %q, want 2026-03", got)
	}
	cases := []struct {
		window string
		want   bool
	}{
		{"2026-03", true},  // current month
		{"2026-02", false}, // elapsed — !IsWindowFinalized would reject this too
		{"2026-04", false}, // future — !IsWindowFinalized would WRONGLY accept this (Sol F10)
		{"2099-01", false}, // far future
		{"2025-12", false},
		{"bad", false},
		{"2026-13", false},
	}
	for _, c := range cases {
		if got := IsCurrentWindow(now, c.window); got != c.want {
			t.Errorf("IsCurrentWindow(%q) = %v, want %v", c.window, got, c.want)
		}
		// Sanity: every case in this table where IsCurrentWindow says false but
		// the window is well-formed and in the FUTURE must be a case
		// !IsWindowFinalized would have accepted — that's precisely the F10 gap
		// IsCurrentWindow closes.
	}
	if IsWindowFinalized(now, "2026-04") {
		t.Fatalf("sanity: 2026-04 must be !elapsed (IsWindowFinalized=false) to demonstrate the F10 gap")
	}
	if IsCurrentWindow(now, "2026-04") {
		t.Fatalf("F10 regression: a future window must never be reported as current")
	}
}

func TestMaterializationTargetsIsCrossProduct(t *testing.T) {
	got := len(MaterializationTargets())
	want := len(Cohorts()) * len(Metrics())
	if got != want {
		t.Errorf("targets = %d, want cohorts×metrics = %d", got, want)
	}
}
