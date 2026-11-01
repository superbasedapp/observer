package policyfam

import (
	"errors"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/policyfam/securityscanning"
)

// TestSecurityScanningRegistersOnce: the pair file links the family exactly
// once in this build (no conflict), or, under a security omit tag, not at
// all, and a body then NACKs with ErrFamilyNotLinked rather than being
// ignored. Run it with -tags sbo_omit_security and -tags
// sbo_omit_org_security too.
func TestSecurityScanningRegistersOnce(t *testing.T) {
	if conflicts := LinkedConflicts(); len(conflicts) != 0 {
		t.Fatalf("LinkedConflicts = %v, want none", conflicts)
	}
	if FamilySecurityScanning != securityscanning.Family {
		t.Fatalf("family spelling drift: %q vs %q", FamilySecurityScanning, securityscanning.Family)
	}
	if got := IsFamilyLinked(FamilySecurityScanning); got != securityScanningInBuild {
		t.Fatalf("IsFamilyLinked = %v, want %v", got, securityScanningInBuild)
	}
	spec, canon, err := CompileFamilyBody(FamilySecurityScanning, []byte(`{"require":{"prelaunch_trust":"ask"},"sections":{"deps":{"capability":"security.deps.v1"}}}`), 0)
	if !securityScanningInBuild {
		if !errors.Is(err, ErrFamilyNotLinked) {
			t.Fatalf("err = %v, want ErrFamilyNotLinked", err)
		}
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	if len(canon) == 0 || !SpecRequestsEnforceMode(FamilySecurityScanning, spec) {
		t.Fatal("a linked floor body must compile and need enforce consent")
	}
	if caps := LinkedRequiredCapabilities(FamilySecurityScanning, spec); len(caps) != 1 || caps[0] != "security.deps.v1" {
		t.Fatalf("required caps = %v", caps)
	}
}
