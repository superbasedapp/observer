package winshell

import (
	"strings"
	"testing"
)

// fsOf is an injected file-exists probe over a fixed set of paths. ci makes
// it case-insensitive, as NTFS and DrvFs are.
func fsOf(ci bool, paths ...string) func(string) bool {
	set := map[string]bool{}
	for _, p := range paths {
		if ci {
			p = strings.ToLower(p)
		}
		set[p] = true
	}
	return func(p string) bool {
		if ci {
			p = strings.ToLower(p)
		}
		return set[p]
	}
}

func TestCheck(t *testing.T) {
	const (
		gitCmd    = `C:\Program Files\Git\cmd`
		gitBin    = `C:\Program Files\Git\bin`
		gitUsrBin = `C:\Program Files\Git\usr\bin`
		sys32     = `C:\Windows\system32`
	)
	gitFS := fsOf(true,
		gitCmd+`\git.exe`,
		gitBin+`\sh.exe`, gitBin+`\bash.exe`,
		gitUsrBin+`\sh.exe`,
		`/mnt/c/Program Files/Git/bin/sh.exe`,
		`/mnt/c/Program Files/Git/cmd/git.exe`,
		`/mnt/d/tools/sh.cmd`,
		`C:\tools\sh.cmd`,
	)
	cases := []struct {
		name     string
		goos     string
		path     string
		fs       func(string) bool
		want     Status
		wantPath string
	}{
		{"found in Git bin", "windows", sys32 + ";" + gitBin, gitFS, Found, gitBin + `\sh.exe`},
		{"found in Git usr bin", "windows", gitCmd + ";" + gitUsrBin, gitFS, Found, gitUsrBin + `\sh.exe`},
		{"not found with only Git cmd", "windows", sys32 + ";" + gitCmd, gitFS, NotFound, ""},
		{"sh.cmd does not count (runner appends .exe only)", "windows", `C:\tools`, gitFS, NotFound, ""},
		{"quoted entry and trailing separator", "windows", `"` + gitBin + `\";;`, gitFS, Found, gitBin + `\sh.exe`},
		{"case-insensitive Windows path", "windows", `C:\PROGRAM FILES\GIT\BIN`, gitFS, Found, `C:\PROGRAM FILES\GIT\BIN\sh.exe`},
		{"empty Windows PATH is unknown", "windows", "", gitFS, Unknown, ""},
		{"WSL sees Git bin", "linux", "/usr/local/bin:/usr/bin:/mnt/c/Program Files/Git/bin:/mnt/c/WINDOWS", gitFS, Found, "/mnt/c/Program Files/Git/bin/sh.exe"},
		{"WSL sees only Git cmd", "linux", "/usr/bin:/bin:/mnt/c/Program Files/Git/cmd:/mnt/c/WINDOWS/system32", gitFS, NotFound, ""},
		{"WSL Linux sh never counts", "linux", "/usr/bin:/bin:/mnt/d/tools", fsOf(false, "/usr/bin/sh", "/bin/sh"), NotFound, ""},
		{"WSL with no Windows dirs is unknown", "linux", "/usr/local/sbin:/usr/local/bin:/usr/bin:/bin", gitFS, Unknown, ""},
		{"WSL /mnt alone and /mntx are not drives", "linux", "/mnt:/mnt/:/mntx/c/bin:/mnt/cdrom", gitFS, Unknown, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, p := Check("sh", tc.goos, tc.path, tc.fs)
			if got != tc.want || p != tc.wantPath {
				t.Fatalf("Check(sh, %s, %q) = %s %q, want %s %q", tc.goos, tc.path, got, p, tc.want, tc.wantPath)
			}
		})
	}
}

func TestResolve(t *testing.T) {
	fs := fsOf(true, `C:\Git\bin\sh.exe`, `C:\alt\sh.COM`)
	cases := []struct {
		name string
		l    Lookup
		want Status
	}{
		{"found via a PATHEXT-style extension list", Lookup{Shell: "sh", Exts: []string{".COM", ".EXE", ".BAT"}, Dirs: []string{`C:\Git\bin`}, Exists: fs}, Found},
		{"extension without its dot", Lookup{Shell: "sh", Exts: []string{"EXE"}, Dirs: []string{`C:\Git\bin`}, Exists: fs}, Found},
		{"name that already carries an extension", Lookup{Shell: "sh.exe", Dirs: []string{`C:\Git\bin`}, Exists: fs}, Found},
		{"default extensions skip .com", Lookup{Shell: "sh", Dirs: []string{`C:\alt`}, Exists: fs}, NotFound},
		{"nil exists is unknown", Lookup{Shell: "sh", Dirs: []string{`C:\Git\bin`}}, Unknown},
		{"empty shell is unknown", Lookup{Dirs: []string{`C:\Git\bin`}, Exists: fs}, Unknown},
		{"drive root dir joins with a backslash", Lookup{Shell: "sh", Dirs: []string{`C:`}, Exists: fsOf(true, `C:\sh.exe`)}, Found},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got, _ := Resolve(tc.l); got != tc.want {
				t.Fatalf("Resolve = %s, want %s", got, tc.want)
			}
		})
	}
}

// TestResolveDedupesCaseInsensitively: the same directory spelled twice is
// probed once.
func TestResolveDedupesCaseInsensitively(t *testing.T) {
	var probes int
	exists := func(string) bool { probes++; return false }
	st, _ := Resolve(Lookup{Shell: "sh", Dirs: []string{`C:\Git\cmd`, `c:\git\CMD\`, `C:\Git\cmd`}, Exists: exists})
	if st != NotFound || probes != 1 {
		t.Fatalf("Resolve = %s after %d probes, want not_found after 1", st, probes)
	}
}

func TestWSLPathList(t *testing.T) {
	for _, tc := range []struct{ name, in, want string }{
		{"empty", "", ""},
		{"git_cmd_only", `C:\Program Files\Git\cmd;C:\Program Files\GitHub CLI\`, "/mnt/c/Program Files/Git/cmd:/mnt/c/Program Files/GitHub CLI"},
		{"drive_root_and_lower", `D:\;e:\tools`, "/mnt/d:/mnt/e/tools"},
		{"quoted_and_blank", `"C:\Git\bin";;  `, "/mnt/c/Git/bin"},
		{"drops_unexpanded_relative_unc", `%SystemRoot%\system32;bin;\server\share\x;C:\ok`, "/mnt/c/ok"},
		{"forward_slashes", `C:/Git/usr/bin/`, "/mnt/c/Git/usr/bin"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := WSLPathList(tc.in); got != tc.want {
				t.Fatalf("WSLPathList(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
	// The converted list feeds Check as the WSL view: Git\cmd alone has no sh.
	exists := func(p string) bool { return p == "/mnt/c/Program Files/Git/bin/sh.exe" }
	if st, _ := Check("sh", "linux", WSLPathList(`C:\Program Files\Git\cmd`), exists); st != NotFound {
		t.Fatalf("Git cmd only: %s, want not_found", st)
	}
	if st, p := Check("sh", "linux", WSLPathList(`C:\Program Files\Git\cmd;C:\Program Files\Git\bin`), exists); st != Found || p == "" {
		t.Fatalf("with Git bin: %s %q, want found", st, p)
	}
}
