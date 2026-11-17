package store

import "testing"

// TestTokensRemaining pins the remaining figure the usage view publishes:
// budget minus committed, floored at zero when settled actuals overshoot the
// budget, and always a value (a spent window reads 0, never omitted).
func TestTokensRemaining(t *testing.T) {
	cases := []struct{ budget, used, want int64 }{
		{250000, 0, 250000},
		{250000, 249999, 1},
		{250000, 250000, 0},
		{250000, 260000, 0},
	}
	for _, tc := range cases {
		got := tokensRemaining(tc.budget, tc.used)
		if got == nil || *got != tc.want {
			t.Errorf("tokensRemaining(%d, %d) = %v, want %d", tc.budget, tc.used, got, tc.want)
		}
	}
}
