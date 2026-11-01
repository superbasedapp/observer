package git

import (
	"testing"
	"time"
)

// TestHeadWriteBefore (lane SEC-P4 decision 6): a HEAD write with no
// sub-second part compares at one-second granularity, so a write in the
// resolution's own second reads as at or after it.
func TestHeadWriteBefore(t *testing.T) {
	at := time.Date(2026, 10, 23, 10, 0, 5, 300_000_000, time.UTC)
	for _, tc := range []struct {
		name   string
		latest time.Time
		want   bool
	}{
		{"sub-second write before", at.Add(-time.Millisecond), true},
		{"sub-second write after", at.Add(time.Millisecond), false},
		{"sub-second write at the same instant", at, false},
		{"whole-second write in the resolution's second", at.Truncate(time.Second), false},
		{"whole-second write the second before", at.Truncate(time.Second).Add(-time.Second), true},
		{"whole-second write the second after", at.Truncate(time.Second).Add(time.Second), false},
	} {
		if got := HeadWriteBefore(tc.latest, at); got != tc.want {
			t.Errorf("%s: %v, want %v", tc.name, got, tc.want)
		}
	}
}
