package sandboxbackend

import "testing"

// TestOnlyBwrapMasksWorkspaceSecrets pins the capability the security
// assessments module checks before it asks a launch to hide workspace secret
// files (internal/sandbox secretmask.go): bubblewrap has the planner, no other
// row does. A row gains it by growing a planner and a row here, not by a
// default.
func TestOnlyBwrapMasksWorkspaceSecrets(t *testing.T) {
	t.Parallel()
	for _, id := range IDs() {
		c, ok := Get(id)
		if !ok {
			t.Fatalf("IDs() names %q but Get does not find it", id)
		}
		want := id == BackendBwrap
		if got := c.CanMaskWorkspaceSecrets(); got != want {
			t.Errorf("%s: CanMaskWorkspaceSecrets() = %v, want %v", id, got, want)
		}
	}
}

// TestZeroCapabilityCannotMaskWorkspaceSecrets: the zero value means not
// grounded, never "can".
func TestZeroCapabilityCannotMaskWorkspaceSecrets(t *testing.T) {
	t.Parallel()
	var c Capability
	if c.CanMaskWorkspaceSecrets() {
		t.Fatal("a zero Capability must not claim it can mask workspace secrets")
	}
}
