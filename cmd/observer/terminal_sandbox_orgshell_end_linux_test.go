//go:build linux && !sbo_omit_terminals_sandbox_openshell_org && !sbo_omit_terminals_sandbox_openshell && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import "testing"

// TestOrgShellEndBranch: one case per row of the branch table.
func TestOrgShellEndBranch(t *testing.T) {
	cases := []struct {
		f    orgShellEndFacts
		want orgShellEndBranch
	}{
		{orgShellEndFacts{ReturnToNode: false, HoldPolicy: "off"}, orgShellEndHold},
		// FX3 item 9: a cut stream is held as a disconnect wherever the org
		// holds at all, and returned only where holding is off.
		{orgShellEndFacts{ReturnToNode: true, HoldPolicy: "on_disconnect", StreamCut: true}, orgShellEndHold},
		{orgShellEndFacts{ReturnToNode: true, HoldPolicy: "off", StreamCut: true}, orgShellEndReturn},
		{orgShellEndFacts{ReturnToNode: true, HoldPolicy: "on_disconnect_and_end", HoldOnEnd: true}, orgShellEndHold},
		{orgShellEndFacts{ReturnToNode: true, HoldPolicy: "on_disconnect", HoldOnEnd: true}, orgShellEndReturn},
		{orgShellEndFacts{ReturnToNode: true, HoldPolicy: "on_disconnect_and_end", HoldOnEnd: false}, orgShellEndReturn},
	}
	for i, tc := range cases {
		if got := orgShellEndBranchFor(tc.f); got != tc.want {
			t.Errorf("case %d: %s, want %s", i, got, tc.want)
		}
	}
}
