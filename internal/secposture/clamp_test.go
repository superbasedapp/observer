package secposture

import (
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/policy"
)

// TestClampQuickScanBudget (lane LEFT2-SEC item R-039): the arithmetic,
// row by row.
func TestClampQuickScanBudget(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		name         string
		budget, host time.Duration
		want         time.Duration
		wantClamped  bool
	}{
		{"an unknown host timeout changes nothing", 30 * time.Second, 0, 30 * time.Second, false},
		{"a budget that fits stays", 2 * time.Second, 60 * time.Second, 2 * time.Second, false},
		{"a long budget under a long timeout is clamped", 600 * time.Second, 60 * time.Second, 56 * time.Second, true},
		{"30 s under a 30 s timeout", 30 * time.Second, 30 * time.Second, 26 * time.Second, true},
		{"10 s under a 10 s timeout", 10 * time.Second, 10 * time.Second, 6 * time.Second, true},
		{"5 s under a 5 s timeout keeps quarter margins", 5 * time.Second, 5 * time.Second, 2500 * time.Millisecond, true},
		{"the built-in 2 s fits a 5 s timeout", IndividualQuickScan, 5 * time.Second, IndividualQuickScan, false},
	} {
		got, clamped := ClampQuickScanBudget(c.budget, c.host)
		if got != c.want || clamped != c.wantClamped {
			t.Errorf("%s: %v %v, want %v %v", c.name, got, clamped, c.want, c.wantClamped)
		}
	}
}

// TestQuickScanFitsEveryVendorTimeout: for every registry hook row that
// declares a host timeout, and every quick-scan budget a posture may sign,
// the clamped scan ends at least one margin before the host gives up, and
// a budget that already fits is never shortened.
func TestQuickScanFitsEveryVendorTimeout(t *testing.T) {
	t.Parallel()
	budgets := []time.Duration{IndividualQuickScan}
	for _, s := range QuickScanBudgetsS {
		budgets = append(budgets, time.Duration(s)*time.Second)
	}
	rows := 0
	for _, c := range integration.Capabilities() {
		for _, b := range c.Hook.Bindings {
			if b.HostTimeout <= 0 {
				continue
			}
			rows++
			for _, budget := range budgets {
				got, clamped := ClampQuickScanBudget(budget, b.HostTimeout)
				margin := min(QuickScanHostMarginMax, b.HostTimeout/4)
				if got+margin > b.HostTimeout || got <= 0 {
					t.Errorf("%s %s (timeout %v): budget %v runs to %v, too close to the host timeout", c.Tool, b.NativeEvent, b.HostTimeout, budget, got)
				}
				if fits := budget+2*margin <= b.HostTimeout; fits == clamped || (fits && got != budget) {
					t.Errorf("%s %s (timeout %v): budget %v gave %v clamped=%v", c.Tool, b.NativeEvent, b.HostTimeout, budget, got, clamped)
				}
			}
		}
	}
	if rows == 0 {
		t.Fatal("no registry hook row declares a host timeout")
	}
}

// TestClampQuickScanBudgetAfter (LEFT2 audit E4): the margin also covers
// the time the hook spent before the scan starts; with no time left the
// budget is zero (the hook then answers the scan as unknown).
func TestClampQuickScanBudgetAfter(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		name                  string
		budget, host, elapsed time.Duration
		want                  time.Duration
		wantClamped           bool
	}{
		{"no time spent is ClampQuickScanBudget", 30 * time.Second, 10 * time.Second, 0, 6 * time.Second, true},
		{"a second spent shortens the scan by a second", 30 * time.Second, 10 * time.Second, time.Second, 5 * time.Second, true},
		{"a budget that still fits stays", 2 * time.Second, 10 * time.Second, 3 * time.Second, 2 * time.Second, false},
		{"a budget that fit at the start is clamped once time was spent", 6 * time.Second, 10 * time.Second, 3 * time.Second, 3 * time.Second, true},
		{"no time left is zero", 5 * time.Second, 5 * time.Second, 3 * time.Second, 0, true},
		{"an unknown host timeout changes nothing", 30 * time.Second, 0, 9 * time.Second, 30 * time.Second, false},
	} {
		got, clamped := ClampQuickScanBudgetAfter(c.budget, c.host, c.elapsed)
		if got != c.want || clamped != c.wantClamped {
			t.Errorf("%s: %v %v, want %v %v", c.name, got, clamped, c.want, c.wantClamped)
		}
	}
}

// TestEffectiveQuickScanBudget (LEFT2 audit E4): the one budget the hook
// and doctor read from a project's posture: the signed per-project value
// on a current, verified file, else the built-in default.
func TestEffectiveQuickScanBudget(t *testing.T) {
	t.Parallel()
	if got := EffectiveQuickScanBudget(Reading{}); got != IndividualQuickScan {
		t.Fatalf("no file: %v, want the default %v", got, IndividualQuickScan)
	}
	f := &File{QuickScanBudgetS: QuickScanBudgetsS[len(QuickScanBudgetsS)-1]}
	r := Reading{File: f}
	r.State.Posture = policy.SecurityPostureClean
	if got := EffectiveQuickScanBudget(r); got != time.Duration(f.QuickScanBudgetS)*time.Second {
		t.Fatalf("a signed budget: %v", got)
	}
	r.State.Posture = policy.SecurityPostureUnknown
	if got := EffectiveQuickScanBudget(r); got != IndividualQuickScan {
		t.Fatalf("an unknown posture: %v, want the default", got)
	}
}
