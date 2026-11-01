//go:build !sbo_omit_security

package main

import (
	"path/filepath"
	"runtime"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/policy"
)

// TestResolveShellDirMSYS (HOOK-MSYS-1, tracker R-169) pins the MSYS rules
// of resolveShellDir on every host: the target OS's path rules are a
// parameter, so the Windows rows and the POSIX rows each run by their own
// OS's rules on Linux and in the Windows test binary alike. A Git Bash
// drive mount resolves to the drive, any other rooted path is refused with
// a named reason (never joined under the event's directory), and nothing
// changes for another dialect or OS.
func TestResolveShellDirMSYS(t *testing.T) {
	posix, ps := policy.DialectPosix, policy.DialectPowerShell
	for _, tc := range []struct {
		name, goos string
		dialect    policy.Dialect
		arg, base  string
		want       shellDirResolution
	}{
		{"drive mount", "windows", posix, "/c/work", `C:\repo`, shellDirResolution{Dir: `C:\work`}},
		{"drive mount, nested, upper-cased", "windows", posix, "/d/work/repo/", `C:\repo`, shellDirResolution{Dir: `D:\work\repo`}},
		{"bare drive mount", "windows", posix, "/e", `C:\repo`, shellDirResolution{Dir: `E:\`}},
		{"the default dialect is POSIX", "windows", "", "/c/x", `C:\repo`, shellDirResolution{Dir: `C:\x`}},
		{"an MSYS root under the install folder", "windows", posix, "/tmp/a", `C:\repo`, shellDirResolution{Reason: shellDirMSYSRootUnmapped}},
		{"/mnt/c is not a Git Bash drive mount", "windows", posix, "/mnt/c/other", `C:\repo`, shellDirResolution{Reason: shellDirMSYSRootUnmapped}},
		{"the MSYS root itself", "windows", posix, "/", `C:\repo`, shellDirResolution{Reason: shellDirMSYSRootUnmapped}},
		{"a two-letter first segment is not a drive", "windows", posix, "/cd/x", `C:\repo`, shellDirResolution{Reason: shellDirMSYSRootUnmapped}},
		{"network root /net", "windows", posix, "/net/host/r", `C:\repo`, shellDirResolution{Reason: shellDirNetworkRoot}},
		{"automount root /misc", "windows", posix, "/misc/r", `C:\repo`, shellDirResolution{Reason: shellDirNetworkRoot}},
		{"/afs", "windows", posix, "/afs/cell/r", `C:\repo`, shellDirResolution{Reason: shellDirNetworkRoot}},
		{"/Network", "windows", posix, "/Network/Servers/h", `C:\repo`, shellDirResolution{Reason: shellDirNetworkRoot}},
		// RB1 sweep H3: a drive-relative operand is that drive's own
		// current directory, never a folder under the event's directory.
		{"drive-relative bare drive", "windows", posix, "D:", `C:\repo`, shellDirResolution{Reason: shellDirDriveRelative}},
		{"drive-relative path", "windows", posix, "D:sub", `C:\repo`, shellDirResolution{Reason: shellDirDriveRelative}},
		{"drive-relative in PowerShell", "windows", ps, "C:foo", `C:\repo`, shellDirResolution{Reason: shellDirDriveRelative}},
		{"Git Bash: a relative path joins a Windows base", "windows", posix, "sub/x", `C:\repo`, shellDirResolution{Dir: `C:\repo\sub\x`}},
		{"Git Bash: dot segments fold", "windows", posix, "../b", `C:\repo\a`, shellDirResolution{Dir: `C:\repo\b`}},
		{"PowerShell: a drive path stays", "windows", ps, `D:\x`, `C:\repo`, shellDirResolution{Dir: `D:\x`}},
		{"PowerShell: a UNC path stays", "windows", ps, `\\host\share\r`, `C:\repo`, shellDirResolution{Dir: `\\host\share\r`}},
		// PowerShell on Windows is not Git Bash: the MSYS rules never
		// apply; Windows's own rules join a root-relative operand under the
		// event's directory, as before this lane (audit F4, out of scope).
		{"PowerShell: no MSYS rules", "windows", ps, "/c/work", `C:\repo`, shellDirResolution{Dir: `C:\repo\c\work`}},
		{"POSIX host: a rooted path stays", "linux", posix, "/c/work", "/repo", shellDirResolution{Dir: "/c/work"}},
		{"POSIX host: a relative path joins", "linux", posix, "sub", "/repo", shellDirResolution{Dir: "/repo/sub"}},
		{"POSIX host: a backslash is a file name character", "linux", posix, `a\b`, "/repo", shellDirResolution{Dir: `/repo/a\b`}},
		{"macOS: a rooted path stays", "darwin", posix, "/tmp/a", "/repo", shellDirResolution{Dir: "/tmp/a"}},
		{"macOS: a relative path joins", "darwin", posix, "x/../y", "/repo", shellDirResolution{Dir: "/repo/y"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := resolveShellDir(shellPathRulesFor(tc.goos), tc.dialect, tc.arg, tc.base); got != tc.want {
				t.Fatalf("resolveShellDir(%s, %q, %q, %q) = %+v, want %+v", tc.goos, tc.dialect, tc.arg, tc.base, got, tc.want)
			}
		})
	}
}

// TestShellPathRulesMatchTheHost pins the hand-written rules of the host's
// own OS to its filepath, so the pure rules the rows above use are the
// rules production gets (hostShellPathRules): on Linux the POSIX rules,
// in the Windows test binary the Windows rules.
func TestShellPathRulesMatchTheHost(t *testing.T) {
	rules := shellPathRulesFor(runtime.GOOS)
	if got, want := rules.GitBash, hostShellPathRules().GitBash; got != want {
		t.Fatalf("GitBash = %v, host rules say %v", got, want)
	}
	for _, p := range []string{
		"", "/", "/a", "a", "a/b", `\`, `\a`, `a\b`, "C:", `C:\`, "C:/", `C:\a`, "C:a", "c:/x/y",
		`\\host\share`, `\\host\share\x`, "//host/share/x", `\\host`, `\\`,
	} {
		if got, want := rules.IsAbs(p), filepath.IsAbs(p); got != want {
			t.Errorf("IsAbs(%q) = %v, filepath says %v", p, got, want)
		}
	}
	for _, elem := range [][]string{
		{},
		{""},
		{"a"},
		{"a", "b"},
		{"/repo", "sub"},
		{"/repo", "/c/work"},
		{"/repo", "../x"},
		{`C:\repo`, "sub"},
		{`C:\repo`, "/c/work"},
		{`C:\repo\a`, `..\b`},
		{`C:\repo`, `.\x\.\y`},
		{"C:", "a"},
		{"C:", "", `\a`},
		{`C:\`, "x"},
		{`\\host\share`, "x"},
		{`\\host\share\`, `..\..`},
		{"a", "", "b"},
		{"a/", "/b"},
		{`a\`, `\b`},
		{"x", ".."},
		{"..", "..", "y"},
	} {
		if got, want := rules.Join(elem...), filepath.Join(elem...); got != want {
			t.Errorf("Join(%q) = %q, filepath says %q", elem, got, want)
		}
	}
}
