package retention

import (
	"testing"
	"time"
)

// TestAgeingHorizon pins the retention-safe horizon the resync deletion heal
// never reaches past: one row per ageing configuration.
func TestAgeingHorizon(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 27, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		name string
		opts Options
		want time.Time
	}{
		{"no ageing configured", Options{}, time.Time{}},
		{"age pass only", Options{MaxAgeDays: 90}, now.AddDate(0, 0, -89)},
		{"size cap only: the 30-day keep-floor", Options{MaxDBSizeMB: 2048}, now.AddDate(0, 0, -(sizeCapActionFloorDays - 1))},
		{"size cap tighter than the age pass", Options{MaxAgeDays: 180, MaxDBSizeMB: 2048}, now.AddDate(0, 0, -(sizeCapActionFloorDays - 1))},
		{"age pass tighter than the size cap", Options{MaxAgeDays: 7, MaxDBSizeMB: 2048}, now.AddDate(0, 0, -6)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			if got := AgeingHorizon(c.opts, now); !got.Equal(c.want) {
				t.Fatalf("AgeingHorizon = %v, want %v", got, c.want)
			}
		})
	}
}
