package sandboxadopt

import (
	"testing"
	"time"
)

// TestKeepOnHangup pins the hangup table (R-033), one case per row.
func TestKeepOnHangup(t *testing.T) {
	now := time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)
	ok := HangupFacts{Active: true, Kept: true, Marked: true, MarkedAt: now.Add(-2 * time.Second), Now: now}
	cases := []struct {
		name string
		edit func(*HangupFacts)
		keep bool
	}{
		{"a daemon exit of a re-adoptable run keeps the container", func(*HangupFacts) {}, true},
		{"component off", func(f *HangupFacts) { f.Active = false }, false},
		{"plan not kept", func(f *HangupFacts) { f.Kept = false }, false},
		{"terminal closed (no mark)", func(f *HangupFacts) { f.Marked = false }, false},
		{"stale mark", func(f *HangupFacts) { f.MarkedAt = now.Add(-HangupGrace - time.Second) }, false},
		{"a mark from the future", func(f *HangupFacts) { f.MarkedAt = now.Add(HangupGrace + time.Second) }, false},
		{"a mark at the grace edge", func(f *HangupFacts) { f.MarkedAt = now.Add(-HangupGrace) }, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := ok
			c.edit(&f)
			keep, why := KeepOnHangup(f)
			if keep != c.keep || (keep && why != "") || (!keep && why == "") {
				t.Fatalf("KeepOnHangup(%+v) = %v, %q; want keep %v", f, keep, why, c.keep)
			}
		})
	}
}
