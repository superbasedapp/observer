package openshellorg

import (
	"strings"
	"testing"
)

// TestProbeNotOfferedNamesTheMissingAuthority (FX1 item 7, live finding
// F-B2): a managed enrolment whose grant does not hold enforce.sandbox never
// applies the sandbox body, so the row is not offered; the verdict stays
// org_gateway_not_offered but its reason names the missing authority, not
// the generic "none is published".
func TestProbeNotOfferedNamesTheMissingAuthority(t *testing.T) {
	row, v, why := Probe(ProbeFacts{SandboxAuthorityMissing: true})
	if row != "R0" || v != VerdictNotOffered || !strings.Contains(why, "sandbox body not applied: this enrolment does not hold enforce.sandbox") {
		t.Fatalf("%s %s %q", row, v, why)
	}
	if _, _, why := Probe(ProbeFacts{}); strings.Contains(why, "enforce.sandbox") {
		t.Fatalf("the generic not-offered reason names the authority: %q", why)
	}
	// An offered row is never refused for it (the fact only explains R0).
	if row, _, _ := Probe(ProbeFacts{Offered: true, SandboxAuthorityMissing: true}); row == "R0" {
		t.Fatal("an offered row was refused at R0")
	}
}
