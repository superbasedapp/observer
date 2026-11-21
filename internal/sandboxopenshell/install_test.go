package sandboxopenshell

import "testing"

// TestInstallIDFileFor: one bound name per real path, never the legacy
// name, recognised by IsBoundInstallIDFile.
func TestInstallIDFileFor(t *testing.T) {
	t.Parallel()
	a, b := InstallIDFileFor("/home/dev/.observer/sandbox-openshell"), InstallIDFileFor("/home/dev/.observer-2/sandbox-openshell")
	if a == b || a == LegacyInstallIDFile || !IsBoundInstallIDFile(a) || !IsBoundInstallIDFile(b) {
		t.Fatalf("got %q %q", a, b)
	}
	for _, n := range []string{LegacyInstallIDFile, "install-id-", "install-id-XYZ", "install-id-0123456789abcdef0", "gateways.json"} {
		if IsBoundInstallIDFile(n) {
			t.Errorf("%q read as bound", n)
		}
	}
}

// TestInstallIDSource: one case per row.
func TestInstallIDSource(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name                                   string
		boundValid, anyBound, legacy, unitOurs bool
		want                                   string
	}{
		{"this path's bound file", true, true, true, false, InstallIDBound},
		{"an install from before the binding", false, false, true, true, InstallIDAdoptLegacy},
		{"a pre-binding copy whose legacy unit runs another dir", false, false, true, false, InstallIDMint},
		{"a copy (another path's bound file)", false, true, true, true, InstallIDMint},
		{"a fresh install", false, false, false, true, InstallIDMint},
	} {
		if got := InstallIDSource(tc.boundValid, tc.anyBound, tc.legacy, tc.unitOurs); got != tc.want {
			t.Errorf("%s: got %s", tc.name, got)
		}
	}
}
