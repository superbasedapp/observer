package guard

import (
	"testing"
)

// TestMCPRegistryPathsLeaveOutAnUnresolvedLocation pins FU-130 for the
// guard's rescan trigger: a location with no file (a relative relocation
// value) is left out, never watched as the "." an empty path normalizes to.
func TestMCPRegistryPathsLeaveOutAnUnresolvedLocation(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("CLINE_DIR", "relative/cline")
	paths := mcpRegistryPaths(home)
	if len(paths) == 0 {
		t.Fatal("no registry path at all")
	}
	for _, p := range paths {
		if p == "." || p == "" {
			t.Errorf("an unresolved location is watched as %q: %v", p, paths)
		}
	}
}
