package sandboxopenshell

import (
	"strings"
	"testing"
)

// TestBinaryTrust: one case per row of the trust table (ledger row
// OSH-44), plus the package path that passes.
func TestBinaryTrust(t *testing.T) {
	t.Parallel()
	pkg := func() BinaryTrustFacts {
		return BinaryTrustFacts{
			Program: GatewayProgram, Path: "/usr/bin/openshell-gateway", Real: "/usr/bin/openshell-gateway", Read: true,
			File: PathOwner{Path: "/usr/bin/openshell-gateway", UID: 0, Mode: 0o755},
			Dirs: []PathOwner{{Path: "/usr/bin", UID: 0, Mode: 0o755}, {Path: "/usr", UID: 0, Mode: 0o755}, {Path: "/", UID: 0, Mode: 0o755}},
		}
	}
	for _, tc := range []struct {
		name string
		mut  func(*BinaryTrustFacts)
		says string
	}{
		{"the package path", func(*BinaryTrustFacts) {}, ""},
		{"T1 not read", func(f *BinaryTrustFacts) { f.Read, f.Detail = false, "permission denied" }, `could not check who owns openshell-gateway at "/usr/bin/openshell-gateway" ("permission denied")`},
		{"T2 a user's copy in a fallback dir", func(f *BinaryTrustFacts) {
			f.Path, f.Real = "/home/dev/.local/bin/openshell-gateway", "/home/dev/.local/bin/openshell-gateway"
			f.File = PathOwner{Path: f.Real, UID: 1000, Mode: 0o755}
			f.Dirs = []PathOwner{{Path: "/home/dev/.local/bin", UID: 1000, Mode: 0o755}, {Path: "/", UID: 0, Mode: 0o755}}
		}, "owned by uid 1000, not root"},
		// FU7-A9: a user copy that shadows the package's binary on PATH.
		{"T2 the remedy names the shadowing case", func(f *BinaryTrustFacts) {
			f.Path, f.Real = "/home/dev/bin/openshell-gateway", "/home/dev/bin/openshell-gateway"
			f.File = PathOwner{Path: f.Real, UID: 1000, Mode: 0o755}
		}, `shadows it: remove "/home/dev/bin/openshell-gateway" or put /usr/bin before its directory on PATH`},
		{"T3 root's file, group-writable", func(f *BinaryTrustFacts) { f.File.Mode = 0o775 }, "mode 775"},
		{"T4 root's file in a user's dir", func(f *BinaryTrustFacts) {
			f.Real = "/opt/tools/openshell-gateway"
			f.Dirs = []PathOwner{{Path: "/opt/tools", UID: 1000, Mode: 0o755}, {Path: "/opt", UID: 0, Mode: 0o755}, {Path: "/", UID: 0, Mode: 0o755}}
		}, "/opt/tools (uid 1000, mode 755)"},
		{"T4 a world-writable parent", func(f *BinaryTrustFacts) { f.Dirs[1].Mode = 0o1777 }, "/usr (uid 0, mode 1777)"},
		{"T4 no directory read", func(f *BinaryTrustFacts) { f.Dirs = nil }, "(no directory read)"},
	} {
		f := pkg()
		tc.mut(&f)
		got := BinaryTrust(f)
		if tc.says == "" {
			if got != "" {
				t.Errorf("%s: refused: %s", tc.name, got)
			}
			continue
		}
		if !strings.Contains(got, tc.says) || !strings.Contains(got, "sudo install -o root") {
			t.Errorf("%s: got %q", tc.name, got)
		}
	}
}
