package localipc

import (
	"errors"
	"testing"
)

// TestIdentityAllowed is the server identity rule, one case per row.
func TestIdentityAllowed(t *testing.T) {
	const me = "S-1-5-21-1-2-3-1001"
	cases := []struct {
		server, self string
		ok           bool
	}{
		{me, me, true},
		{localSystemSID, me, true},
		{"S-1-5-21-1-2-3-1002", me, false}, // another local user
		{"S-1-5-32-544", me, false},        // BUILTIN\\Administrators is not the user
		{"", me, false},
		{me, "", false},
	}
	for _, tc := range cases {
		err := identityAllowed(tc.server, tc.self)
		if tc.ok != (err == nil) {
			t.Errorf("identityAllowed(%q, %q) = %v, want ok=%v", tc.server, tc.self, err, tc.ok)
		}
		if err != nil && !errors.Is(err, ErrServerUnverified) {
			t.Errorf("refusal does not wrap ErrServerUnverified: %v", err)
		}
	}
}
