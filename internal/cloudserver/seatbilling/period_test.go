package seatbilling

import "testing"

func TestClosedPeriod(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		in, start, end string
		err            bool
	}{
		{"2026-12-01T00:00:00Z", "2026-11-01", "2026-12-01", false},
		{"2026-11-15T10:30:00Z", "2026-10-15", "2026-11-15", false},
		{"2027-01-05T00:00:00Z", "2026-12-05", "2027-01-05", false},
		{"2026-03-31T00:00:00Z", "2026-03-03", "2026-03-31", false},      // AddDate normalization
		{"2026-12-01T01:00:00+05:30", "2026-10-30", "2026-11-30", false}, // the UTC day
		{"not a time", "", "", true},
		{"", "", "", true},
	} {
		s, e, err := ClosedPeriod(tc.in)
		if (err != nil) != tc.err || s != tc.start || e != tc.end {
			t.Errorf("ClosedPeriod(%q) = %q, %q, %v; want %q, %q, err=%v", tc.in, s, e, err, tc.start, tc.end, tc.err)
		}
	}
}
