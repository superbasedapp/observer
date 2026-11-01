package policyfam

import (
	"testing"
)

// TestTerminalsIsolationRegistersOnce: the pair file links the family once
// in every build that compiles it (no duplicate registration), and the legs
// reach their accessors.
func TestTerminalsIsolationRegistersOnce(t *testing.T) {
	if c := LinkedConflicts(); len(c) != 0 {
		t.Fatalf("linked families registered more than once: %v", c)
	}
	if !terminalsIsolationInBuild {
		return
	}
	spec, _, err := CompileFamilyBody(FamilyTerminalsIsolation, []byte(`{"min_isolation":"process"}`), 4096)
	if err != nil {
		t.Fatal(err)
	}
	if got := LinkedRequiredCapabilities(FamilyTerminalsIsolation, spec); len(got) != 1 || got[0] != "terminals.isolation.min_isolation" {
		t.Fatalf("required %v", got)
	}
	if !SpecRequestsEnforceMode(FamilyTerminalsIsolation, spec) {
		t.Fatal("a floor needs the node's preauthorize_enforce consent")
	}
	if axis, err := CheckLinkedPosture(FamilyTerminalsIsolation, spec); axis != "" || err != nil {
		t.Fatalf("a floor never loosens: %q %v", axis, err)
	}
	_ = LinkedLintWarnings(FamilyTerminalsIsolation, spec)
}
