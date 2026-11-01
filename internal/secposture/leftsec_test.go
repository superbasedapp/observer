package secposture

import (
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/policy"
)

// TestScanStaleness (lane LEFT-SEC milestone 1): a file that signs a
// staleness reads as unknown (scan_stale) once its newest scan is older,
// or when it was never scanned; a fresh scan, or no staleness (the
// default), reads as before.
func TestScanStaleness(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	base := File{Packs: []string{"security"}, IssuedAt: now, ExpiresAt: now.Add(DefaultTTL), ScannedAt: now.Add(-2 * time.Hour)}
	for _, tc := range []struct {
		name      string
		staleness int
		scanned   time.Time
		want      policy.SecurityPosture
		reason    Reason
	}{
		{"off (default)", 0, now.Add(-2 * time.Hour), policy.SecurityPostureClean, ReasonClean},
		{"inside", 240, now.Add(-2 * time.Hour), policy.SecurityPostureClean, ReasonClean},
		{"past", 60, now.Add(-2 * time.Hour), policy.SecurityPostureUnknown, ReasonScanStale},
		{"never scanned", 60, time.Time{}, policy.SecurityPostureUnknown, ReasonScanStale},
	} {
		f := base
		f.MaxScanStalenessMin, f.ScannedAt = tc.staleness, tc.scanned
		st := Derive(Input{Module: ModuleActive, Read: ReadOK, File: &f, Now: now, SeenOK: true, DirtyOK: true})
		if st.Posture != tc.want || st.Reason != tc.reason {
			t.Errorf("%s: %s (%s), want %s (%s)", tc.name, st.Posture, st.Reason, tc.want, tc.reason)
		}
	}
}

// TestScanningFieldsNormalize: the budget keeps only a picker value above
// 2 s, the staleness only a value inside the floor's bound, and the capped
// keys only history-only ones; all are omitted at their defaults.
func TestScanningFieldsNormalize(t *testing.T) {
	f := normalize(File{QuickScanBudgetS: 10, MaxScanStalenessMin: 30, Blocking: []string{"a", "b"}, HistoryOnly: []string{"a"}, HistoryCapped: []string{"a", "b", "c"}})
	if f.QuickScanBudgetS != 10 || f.MaxScanStalenessMin != 30 || len(f.HistoryCapped) != 1 || f.HistoryCapped[0] != "a" {
		t.Fatalf("normalized %+v", f)
	}
	for _, b := range []int{0, 2, 3, 60} {
		if got := normalize(File{QuickScanBudgetS: b}).QuickScanBudgetS; got != 0 {
			t.Errorf("budget %d normalized to %d, want 0 (the built-in 2 s)", b, got)
		}
	}
	if got := normalize(File{MaxScanStalenessMin: MaxScanStalenessMin + 1}).MaxScanStalenessMin; got != 0 {
		t.Errorf("staleness past the bound kept: %d", got)
	}
	if QuickScanBudgetOf(&File{QuickScanBudgetS: 30}) != 30*time.Second || QuickScanBudgetOf(&File{}) != IndividualQuickScan || QuickScanBudgetOf(nil) != IndividualQuickScan {
		t.Fatal("QuickScanBudgetOf")
	}
	st := Derive(Input{Module: ModuleActive, Read: ReadOK, Now: time.Unix(10, 0), SeenOK: true, DirtyOK: true, File: &File{
		Packs: []string{"security"}, ExpiresAt: time.Unix(100, 0), Blocking: []string{"a", "b"}, HistoryOnly: []string{"a", "b"}, HistoryCapped: []string{"a", "b"},
	}})
	if st.HistoryCapped != 2 || Facts(Reading{State: st}).BlockingHistoryCapped != 2 {
		t.Fatalf("capped count %+v", st)
	}
}
