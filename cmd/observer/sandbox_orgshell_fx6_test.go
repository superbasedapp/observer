//go:build !sbo_omit_terminals_sandbox_openshell_org && !sbo_omit_terminals_sandbox_openshell && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import "testing"

// TestOrgShellHeldAs (lane FX6, F-P7-3): the hold verb's hint names the id
// the organization answered (the box's ledger key) when it is well-formed,
// else the id the member typed (an older server answers none).
func TestOrgShellHeldAs(t *testing.T) {
	cases := []struct{ asked, answered, want string }{
		{"ACTIVE", "HELD", "HELD"},
		{"HELD", "HELD", "HELD"},
		{"ACTIVE", "", "ACTIVE"},
		{"ACTIVE", "bad id/with space", "ACTIVE"},
		{"ACTIVE", "-flag", "ACTIVE"},
	}
	for _, tc := range cases {
		if got := orgShellHeldAs(tc.asked, tc.answered); got != tc.want {
			t.Errorf("orgShellHeldAs(%q, %q) = %q, want %q", tc.asked, tc.answered, got, tc.want)
		}
	}
}
