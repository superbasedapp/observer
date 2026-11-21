package sandboxvocab

import (
	"testing"
	"time"
)

// TestEgressRefusalMinute is one row per bucket edge.
func TestEgressRefusalMinute(t *testing.T) {
	t.Parallel()
	t0 := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		name string
		at   time.Time
		want int64
	}{
		{"start of a minute", t0, t0.Unix() / 60},
		{"end of the same minute", t0.Add(59*time.Second + 999*time.Millisecond), t0.Unix() / 60},
		{"the next minute", t0.Add(time.Minute), t0.Unix()/60 + 1},
		{"another zone is the same instant", t0.In(time.FixedZone("x", 5*3600+1800)), t0.Unix() / 60},
	}
	for _, tc := range cases {
		if got := EgressRefusalMinute(tc.at); got != tc.want {
			t.Errorf("%s: %d, want %d", tc.name, got, tc.want)
		}
	}
}
