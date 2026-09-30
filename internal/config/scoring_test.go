package config

import (
	"testing"
	"time"
)

// TestIntelligenceScoringDefaults pins [intelligence.scoring]: default-on in
// Default() (the partial-merge seed), and the accessors never let a zero or
// negative value disable or stall scoring.
func TestIntelligenceScoringDefaults(t *testing.T) {
	d := Default().Intelligence.Scoring
	if !d.Auto {
		t.Fatal("Default().Intelligence.Scoring.Auto must be true (default-on)")
	}
	cases := []struct {
		name         string
		in           IntelligenceScoringConfig
		wantInterval time.Duration
		wantIdle     time.Duration
		wantLimit    int
	}{
		{"defaults", d, 5 * time.Minute, 30 * time.Minute, 200},
		{"zero falls back", IntelligenceScoringConfig{}, 5 * time.Minute, 30 * time.Minute, 200},
		{"negative falls back", IntelligenceScoringConfig{IntervalMinutes: -1, IdleMinutes: -2, MaxPerPass: -3}, 5 * time.Minute, 30 * time.Minute, 200},
		{"explicit values", IntelligenceScoringConfig{IntervalMinutes: 1, IdleMinutes: 10, MaxPerPass: 7}, time.Minute, 10 * time.Minute, 7},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.in.Interval(); got != tc.wantInterval {
				t.Errorf("Interval = %v, want %v", got, tc.wantInterval)
			}
			if got := tc.in.Idle(); got != tc.wantIdle {
				t.Errorf("Idle = %v, want %v", got, tc.wantIdle)
			}
			if got := tc.in.PassLimit(); got != tc.wantLimit {
				t.Errorf("PassLimit = %d, want %d", got, tc.wantLimit)
			}
		})
	}
}
