package policyfam

import (
	"errors"
	"reflect"
	"testing"
)

// snapshotLinked saves and restores the process-wide linked registry so a
// test can register freely.
func snapshotLinked(t *testing.T) {
	t.Helper()
	linkedMu.Lock()
	fams := make(map[string]LinkedFamily, len(linkedFamilies))
	for k, v := range linkedFamilies {
		fams[k] = v
	}
	conf := make(map[string]int, len(linkedConflicts))
	for k, v := range linkedConflicts {
		conf[k] = v
	}
	linkedMu.Unlock()
	t.Cleanup(func() {
		linkedMu.Lock()
		linkedFamilies, linkedConflicts = fams, conf
		linkedMu.Unlock()
	})
}

func impostor() LinkedFamily {
	return LinkedFamily{
		Compile:  func([]byte, int64) (any, []byte, error) { return "impostor", []byte(`{}`), nil },
		Enforces: func(any) bool { return false },
	}
}

// TestNoLinkedConflictsInThisBuild: no family is registered twice by the
// pair files compiled into this build.
func TestNoLinkedConflictsInThisBuild(t *testing.T) {
	if c := LinkedConflicts(); len(c) != 0 {
		t.Fatalf("families registered more than once: %v", c)
	}
}

// TestDuplicateRegistrationIsRefused registers tools.mcp_access twice (JSP-1
// R5: the old seam let the impostor win silently). Both registrations are
// dropped, every body NACKs, and the conflict is listed.
func TestDuplicateRegistrationIsRefused(t *testing.T) {
	snapshotLinked(t)
	linkedMu.Lock()
	linkedFamilies, linkedConflicts = map[string]LinkedFamily{}, map[string]int{}
	linkedMu.Unlock()

	RegisterLinkedFamily(FamilyMCPAccess, impostor())
	if !IsFamilyLinked(FamilyMCPAccess) {
		t.Fatal("the first registration must link the family")
	}
	RegisterLinkedFamily(FamilyMCPAccess, impostor())
	if IsFamilyLinked(FamilyMCPAccess) {
		t.Fatal("a duplicate registration must unlink the family")
	}
	spec, _, err := CompileFamilyBody(FamilyMCPAccess, []byte(`{}`), 4096)
	if !errors.Is(err, ErrFamilyConflict) || !errors.Is(err, ErrFamilyNotLinked) || spec != nil {
		t.Fatalf("compile after a duplicate: spec=%v err=%v, want ErrFamilyConflict", spec, err)
	}
	if got := LinkedConflicts(); !reflect.DeepEqual(got, []string{FamilyMCPAccess}) {
		t.Fatalf("LinkedConflicts = %v", got)
	}
	// A third registration does not relink it.
	RegisterLinkedFamily(FamilyMCPAccess, impostor())
	if IsFamilyLinked(FamilyMCPAccess) {
		t.Fatal("a later registration must not relink a conflicted family")
	}
	if !SpecRequestsEnforceMode(FamilyMCPAccess, nil) {
		t.Fatal("a conflicted family must answer the conservative enforce=true")
	}
}

// TestLinkedFamilyLegs: the optional capability and posture legs reach their
// accessors; an unlinked family answers none of them.
func TestLinkedFamilyLegs(t *testing.T) {
	snapshotLinked(t)
	// Both module families have real pair files (family_securityscanning.go,
	// lane SEC-E; family_terminalsisolation.go, lane SBX-P1B), linked unless
	// the module is omitted. Pin that, then unlink both for this test so the
	// legs are exercised on a stub (snapshotLinked restores them).
	if IsFamilyLinked(FamilySecurityScanning) != securityScanningInBuild {
		t.Fatalf("security.scanning linked = %v, want %v", !securityScanningInBuild, securityScanningInBuild)
	}
	if IsFamilyLinked(FamilyTerminalsIsolation) != terminalsIsolationInBuild {
		t.Fatalf("terminals.isolation linked = %v, want %v", !terminalsIsolationInBuild, terminalsIsolationInBuild)
	}
	linkedMu.Lock()
	delete(linkedFamilies, FamilySecurityScanning)
	delete(linkedFamilies, FamilyTerminalsIsolation)
	linkedMu.Unlock()
	if IsFamilyLinked(FamilySecurityScanning) || IsFamilyLinked(FamilyTerminalsIsolation) {
		t.Fatal("both module families must be unlinked here")
	}
	if _, _, err := CompileFamilyBody(FamilyTerminalsIsolation, []byte(`{}`), 4096); !errors.Is(err, ErrFamilyNotLinked) {
		t.Fatalf("unlinked terminals.isolation: %v", err)
	}
	if axis, err := CheckLinkedPosture(FamilySecurityScanning, nil); axis != "" || err != nil {
		t.Fatal("an unlinked family's posture check must pass")
	}
	RegisterLinkedFamily(FamilySecurityScanning, LinkedFamily{
		Compile:              func([]byte, int64) (any, []byte, error) { return "spec", []byte(`{}`), nil },
		Enforces:             func(any) bool { return false },
		RequiredCapabilities: func(any) []string { return []string{"security.deps.v1", "security.deps.v1", "security.trust.v1"} },
		LiveCapabilities:     func() []string { return []string{"security.trust.v1"} },
		CheckPosture: func(spec any) (string, error) {
			return "prelaunch_trust", errors.New("weaker")
		},
	})
	if !IsFamilyLinked(FamilySecurityScanning) {
		t.Fatal("registration must link security.scanning")
	}
	spec, _, err := CompileFamilyBody(FamilySecurityScanning, []byte(`{}`), 4096)
	if err != nil || spec != "spec" {
		t.Fatalf("compile: %v %v", spec, err)
	}
	if got := LinkedRequiredCapabilities(FamilySecurityScanning, spec); !reflect.DeepEqual(got, []string{"security.deps.v1", "security.trust.v1"}) {
		t.Fatalf("required caps %v", got)
	}
	found := false
	for _, c := range LinkedLiveCapabilities() {
		found = found || c == "security.trust.v1"
	}
	if !found {
		t.Fatal("live capability missing")
	}
	if axis, err := CheckLinkedPosture(FamilySecurityScanning, spec); axis != "prelaunch_trust" || err == nil {
		t.Fatalf("posture: %q %v", axis, err)
	}
	if SpecRequestsEnforceMode(FamilySecurityScanning, spec) {
		t.Fatal("enforces leg not consulted")
	}
}

// TestFamilyTableOrder pins the stable order: the two module families are
// appended last, linked-only.
func TestFamilyTableOrder(t *testing.T) {
	n := len(SupportedFamilies)
	if n < 2 || SupportedFamilies[n-2] != FamilySecurityScanning || SupportedFamilies[n-1] != FamilyTerminalsIsolation {
		t.Fatalf("SupportedFamilies = %v", SupportedFamilies)
	}
	for _, f := range []string{FamilyMCPAccess, FamilySecurityScanning, FamilyTerminalsIsolation} {
		if !IsLinkedOnlyFamily(f) {
			t.Errorf("%s must be linked-only", f)
		}
	}
	if IsLinkedOnlyFamily(FamilyNodeGovernance) || IsLinkedOnlyFamily("nope") {
		t.Error("only the seam families are linked-only")
	}
}
