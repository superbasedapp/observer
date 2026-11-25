package updatespec

import "testing"

// TestComparePrecedence pins SemVer 2.0 precedence, the ordering every wire
// field gate uses (review row C156-35): a pre-release is OLDER than its
// release, unlike update.CompareSemver.
func TestComparePrecedence(t *testing.T) {
	cases := []struct {
		a, b string
		want int
		ok   bool
	}{
		{"1.35.0", "1.35.0", 0, true},
		{"1.35.0-rc.1", "1.35.0", -1, true},
		{"1.35.0", "1.35.0-rc.1", 1, true},
		{"1.35.0-rc.2", "1.35.0-rc.11", -1, true},
		{"1.35.0-rc.11", "1.35.0-rc.2", 1, true},
		{"1.35.0-alpha", "1.35.0-1", 1, true},
		{"1.35.0-rc", "1.35.0-rc.1", -1, true},
		{"v1.36.0-rc.1", "1.35.0", 1, true},
		{"1.34.0-rc.12+node1.abc", "1.34.0-rc.12", 0, true},
		{"1.34.9", "1.35.0-rc.1", -1, true},
		{"dev", "1.35.0", 0, false},
		{"", "1.35.0", 0, false},
		{"1.35.0-", "1.35.0", 0, false},
	}
	for _, tc := range cases {
		got, ok := ComparePrecedence(tc.a, tc.b)
		if got != tc.want || ok != tc.ok {
			t.Errorf("ComparePrecedence(%q, %q) = %d, %v; want %d, %v", tc.a, tc.b, got, ok, tc.want, tc.ok)
		}
	}
}
