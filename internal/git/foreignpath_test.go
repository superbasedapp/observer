package git

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestRelativePathForeignPOSIXOnWindows pins FU-112: on a Windows host a
// POSIX-shaped target never gains the working directory's drive.
func TestRelativePathForeignPOSIXOnWindows(t *testing.T) {
	SimulateWindowsHostForTest(t)
	cases := []struct {
		name, root, p, want string
	}{
		{"the FU-112 case", "/tmp/superbased-fixture-gen", "/tmp/x", "[external]//tmp/x"},
		{"inside the root", "/work/repo", "/work/repo/pkg/a.go", "pkg/a.go"},
		{"the root itself", "/work/repo", "/work/repo/", "."},
		{"a sibling with a shared prefix", "/work/repo", "/work/repository/a.go", "[external]//work/repository/a.go"},
		{"dot segments are cleaned", "/work/repo", "/work/repo/x/../b.go", "b.go"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := RelativePath(c.root, c.p); got != c.want {
				t.Errorf("RelativePath(%q, %q) = %q, want %q", c.root, c.p, got, c.want)
			}
		})
	}
}

// TestResolveForeignPOSIXOnWindows pins FU-119's root cause: Resolve and
// ResolveIdentity keep a POSIX root as given on a Windows host and look for
// no repository under it, even when one exists at that spelling on this
// machine (on Windows it would be the current drive's).
func TestResolveForeignPOSIXOnWindows(t *testing.T) {
	repo := t.TempDir()
	if err := os.MkdirAll(filepath.Join(repo, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	// The repository's spelling without its drive: on Linux the temp path
	// itself, on a real Windows host the same directory written as a POSIX
	// path, which filepath.Abs would root on the current drive and find
	// (the FU-112 invention) unless the foreign rule holds.
	posix := filepath.ToSlash(strings.TrimPrefix(repo, filepath.VolumeName(repo)))
	SimulateWindowsHostForTest(t)
	info, err := Resolve(posix)
	if err != nil || info.IsGit || info.Root != posix {
		t.Errorf("Resolve(%q) = %+v, %v; want the path kept, not a repository", posix, info, err)
	}
	id, err := ResolveIdentity("/work/repo", IdentityOptions{SkipContentFingerprint: true})
	if err != nil || id.Root != "/work/repo" || id.IsGit {
		t.Errorf("ResolveIdentity = %+v, %v", id, err)
	}
	if root, ok := FindRoot("/work/repo"); ok || root != "" {
		t.Errorf("FindRoot = %q, %v", root, ok)
	}
}

// TestForeignRuleIsInertOnAPOSIXHost pins that nothing changes off Windows.
func TestForeignRuleIsInertOnAPOSIXHost(t *testing.T) {
	prev := windowsHostOverride.Swap(2)
	t.Cleanup(func() { windowsHostOverride.Store(prev) })
	if foreignPOSIXAbs("/work/repo") {
		t.Error("a POSIX host treated its own path as foreign")
	}
	if got := RelativePath("/work/repo", "/work/repo/a.go"); got != "a.go" {
		t.Errorf("RelativePath = %q", got)
	}
}

// TestRelativePathBothFlavours is the FU-112 table over both path flavours:
// a Linux-shaped root and target stay Linux-shaped on a Windows host (run
// everywhere through the simulated host), and a Windows-shaped root and
// target keep the native Windows rules (run on a real Windows host only,
// since filepath on a POSIX host cannot parse a drive path).
func TestRelativePathBothFlavours(t *testing.T) {
	cases := []struct {
		name, root, p, want string
		windowsOnly         bool
	}{
		{name: "linux: the FU-112 case", root: "/tmp/superbased-fixture-gen", p: "/tmp/x", want: "[external]//tmp/x"},
		{name: "linux: inside the root", root: "/work/repo", p: "/work/repo/pkg/a.go", want: "pkg/a.go"},
		{name: "linux: a target under another root", root: "/home/me/proj", p: "/etc/hosts", want: "[external]//etc/hosts"},
		{name: "linux target under a windows root", root: `C:\work\repo`, p: "/work/repo/a.go", want: "[external]//work/repo/a.go"},
		{name: "windows: inside the root", root: `C:\work\repo`, p: `C:\work\repo\pkg\a.go`, want: "pkg/a.go", windowsOnly: true},
		{name: "windows: another drive", root: `C:\work\repo`, p: `D:\data\b.go`, want: "[external]/D:/data/b.go", windowsOnly: true},
		{name: "windows: forward slashes", root: "C:/work/repo", p: "C:/work/repo/a.go", want: "a.go", windowsOnly: true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if c.windowsOnly {
				if runtime.GOOS != "windows" {
					t.Skip("a Windows-shaped path needs a real Windows host's filepath")
				}
			} else {
				SimulateWindowsHostForTest(t)
			}
			if got := RelativePath(c.root, c.p); got != c.want {
				t.Errorf("RelativePath(%q, %q) = %q, want %q", c.root, c.p, got, c.want)
			}
		})
	}
}
