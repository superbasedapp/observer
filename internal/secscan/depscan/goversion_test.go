package depscan

import (
	"strings"
	"testing"
)

// TestNormalizeGoVersion: one case per normalization row and spelling of
// the version string a Go binary's build info carries (item 4 Go stdlib,
// ruling 2026-11-05 (a)); "" is "unknown", never clean.
func TestNormalizeGoVersion(t *testing.T) {
	for _, tc := range []struct{ name, in, want string }{
		{"release", "go1.22.3", "1.22.3"},
		{"release without the go prefix (SCALIBR strips it)", "1.22.3", "1.22.3"},
		{"two components is the .0 release", "go1.22", "1.22.0"},
		{"two components without prefix", "1.21", "1.21.0"},
		{"release candidate", "go1.22rc1", "1.22.0-rc.1"},
		{"release candidate without prefix", "1.22rc2", "1.22.0-rc.2"},
		{"beta", "go1.21beta2", "1.21.0-beta.2"},
		{"patch release candidate", "go1.21.0rc4", "1.21.0-rc.4"},
		{"experiment after a space", "go1.21.0 X:boringcrypto", "1.21.0"},
		{"experiment after a space, no prefix", "1.21.0 X:boringcrypto", "1.21.0"},
		{"experiment with a colon", "go1.21.0:boringcrypto", "1.21.0"},
		{"several experiments", "go1.22.1 X:boringcrypto,cgocheck2", "1.22.1"},
		{"distro note in parentheses", "go1.21.9 (Red Hat 1.21.9-1.el9)", "1.21.9"},
		{"vendor hyphen suffix", "go1.22.3-bookworm", "1.22.3"},
		{"distro revision suffix", "1.21.9-1.el9", "1.21.9"},
		{"build metadata", "go1.22.3+build5", "1.22.3"},
		{"surrounding space", "  go1.20.14  ", "1.20.14"},
		{"development build", "devel go1.23-abc +def Mon Jan 1 00:00:00 2024", ""},
		{"development build, SCALIBR's cut", "devel", ""},
		{"development build with a revision", "devel +abc123", ""},
		{"development build colon form", "devel:abc123", ""},
		{"pre-release snapshot", "go1.20-pre3 +a813be86df", ""},
		{"pre-release snapshot, SCALIBR's cut", "1.20-pre3", ""},
		{"empty", "", ""},
		{"blank", "   ", ""},
		{"garbage", "banana", ""},
		{"another major", "go2.0.0", ""},
		{"too many components", "go1.22.3.4", ""},
		{"a leading v", "v1.22.3", ""},
		{"not a number", "go1.x.3", ""},
		{"unterminated rc", "go1.22rc", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := NormalizeGoVersion(tc.in); got != tc.want {
				t.Fatalf("NormalizeGoVersion(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// TestGoBinaryUnknownVersionIsAGap: a Go binary whose version is a
// development build or unreadable is never matched and never clean: the
// run is partial and the gap names the binary (ruling (a): "unknown,
// never clean"). The same binary with a release version is matched.
func TestGoBinaryUnknownVersionIsAGap(t *testing.T) {
	resp := ChildResponse{
		Packages: []Package{
			{Ecosystem: "Go", Name: "stdlib", Path: "bin/app", Artifact: true, VersionUnknown: true},
			{Ecosystem: "Go", Name: "stdlib", Version: "1.22.3", Path: "bin/ok", Artifact: true},
			{Ecosystem: "Go", Name: "toolchain", Version: "1.22.3", Path: "bin/ok", Artifact: true},
		},
		Ecosystems: []EcoResult{{Ecosystem: "Go", Outcome: EcoScanned, Packages: 1}},
	}
	keep, dropped := Prepare(resp.Packages)
	if len(keep["Go"]) != 1 || keep["Go"][0] != 1 || dropped["go_version_unknown"] != 1 || dropped["artifact_toolchain"] != 1 {
		t.Fatalf("kept %v dropped %v", keep, dropped)
	}
	_, gaps := Finalize(resp)
	if len(gaps) != 1 || gaps[0].Reason != ReasonGoVersionUnknown || gaps[0].Path != "bin/app" || gaps[0].Packages != 1 {
		t.Fatalf("gaps %+v (the toolchain drop is not a gap)", gaps)
	}
	if ReasonWords(ReasonGoVersionUnknown) == ReasonGoVersionUnknown {
		t.Fatal("the gap reason has no words")
	}
}

// TestBinaryStdlibFindingMessage: a Go binary's standard-library finding
// says it is matched by its Go version and potentially affected; a go.mod
// dependency's message is unchanged.
func TestBinaryStdlibFindingMessage(t *testing.T) {
	bin := message(Package{Ecosystem: "Go", Name: "stdlib", Version: "1.22.3", Artifact: true}, []string{"GO-2024-1"})
	if !strings.Contains(bin, "potentially affected") || !strings.Contains(bin, "GO-2024-1") {
		t.Fatalf("binary message %q", bin)
	}
	mod := message(Package{Ecosystem: "Go", Name: "golang.org/x/net", Version: "0.1.0"}, []string{"GO-2024-1"})
	if strings.Contains(mod, "potentially") {
		t.Fatalf("module message %q", mod)
	}
	if !IsBinaryStdlib(Package{Ecosystem: "Go", Name: "stdlib", Artifact: true}) || IsBinaryStdlib(Package{Ecosystem: "Go", Name: "stdlib"}) || IsBinaryStdlib(Package{Ecosystem: "Go", Name: "toolchain", Artifact: true}) {
		t.Fatal("IsBinaryStdlib")
	}
}
