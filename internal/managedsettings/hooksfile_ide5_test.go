package managedsettings

import (
	"strings"
	"testing"
)

// TestGenerateManagedHooksFile pins IDE-5 / the IDE-6 managed row: per-OS
// deploy steps, the file-only channel stated honestly, and refusals.
func TestGenerateManagedHooksFile(t *testing.T) {
	doc := []byte(`{"hooks":{"stop":[{"command":"observer hook cursor stop"}]},"version":1}`)
	arts, err := GenerateManagedHooksFile(ManagedHooksFileOptions{Product: "Cursor", Files: []ManagedHooksFile{
		{OS: "linux", Path: "/etc/cursor/hooks.json", Content: doc},
		{OS: "windows", Path: `C:\ProgramData\Cursor\hooks.json`, Content: doc},
	}})
	if err != nil {
		t.Fatalf("GenerateManagedHooksFile: %v", err)
	}
	for _, want := range []string{
		`sudo install -m 0644 -o root -g root "hooks.linux.json" "/etc/cursor/hooks.json"`,
		`icacls "C:\ProgramData\Cursor"`,
		"stands its own\nper-node registration down",
		"cannot carry them",
	} {
		if !strings.Contains(arts.Readme, want) {
			t.Errorf("README missing %q:\n%s", want, arts.Readme)
		}
	}
	for _, bad := range []ManagedHooksFileOptions{
		{Product: "Cursor"},
		{Product: "Cursor", Files: []ManagedHooksFile{{OS: "plan9", Path: "/x", Content: doc}}},
		{Product: "Cursor", Files: []ManagedHooksFile{{OS: "linux", Path: "/x", Content: []byte(`{}`)}}},
		// A path with no separator is refused, never sliced (audit low item).
		{Product: "Cursor", Files: []ManagedHooksFile{{OS: "linux", Path: "hooks.json", Content: doc}}},
	} {
		if _, err := GenerateManagedHooksFile(bad); err == nil {
			t.Errorf("GenerateManagedHooksFile(%+v) should fail", bad)
		}
	}
}
