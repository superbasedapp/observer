//go:build !sbo_omit_security

package main

import (
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/policyfam/securityscanning"
)

// TestSecurityKeyNoteNamesTheRefusedPath is SEC-E4 merge finding 8: on a
// managed node require.online_checks = required is applied to the install
// gate (through the org relay) while the dependency scanners' online
// matching stays refused, and status says both instead of a bare
// "applied"; an individual node and the not_built keys are unchanged.
func TestSecurityKeyNoteNamesTheRefusedPath(t *testing.T) {
	req := securityscanning.KeyState{Key: securityscanning.AxisOnlineChecks, State: securityscanning.StateApplied, Floor: "required"}
	got := securityKeyNote(req, securityscanning.NodeFacts{Managed: true})
	// Since lane SEC-H2 both paths go to the org relay, and the note says so.
	if !strings.Contains(got, "install gate") || !strings.Contains(got, "org relay only") || !strings.Contains(got, "online matching") {
		t.Fatalf("managed note: %q", got)
	}
	if got := securityKeyNote(req, securityscanning.NodeFacts{}); got != "" {
		t.Fatalf("an individual node's applied key needs no note: %q", got)
	}
	// Lane LEFT-SEC built the last not_built keys: an applied
	// install_unknown needs no note, and a key with no reason gets none.
	ap := securityscanning.KeyState{Key: securityscanning.AxisInstallUnknown, State: securityscanning.StateApplied, Floor: "ask"}
	if got := securityKeyNote(ap, securityscanning.NodeFacts{Managed: true}); got != "" {
		t.Fatalf("applied install_unknown note: %q", got)
	}
}
