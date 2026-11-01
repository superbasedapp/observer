package policy

import "testing"

// TestNormPath pins the canonical comparable form: forward slashes,
// collapsed separators, lexical dot-resolution, lowercased drive
// letters, root clamping.
func TestNormPath(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name, in, want string
	}{
		{"posix passthrough", "/a/b", "/a/b"},
		{"backslashes", `C:\Users\X`, "c:/Users/X"},
		{"drive lowercased", `D:\x`, "d:/x"},
		{"collapse repeats", "//a///b", "/a/b"},
		{"dot segments", "/a/./b", "/a/b"},
		{"dotdot resolved", "/a/b/../c", "/a/c"},
		{"dotdot clamped at root", "/a/../../b", "/b"},
		{"relative dotdot preserved", "../x", "../x"},
		{"relative inner dotdot", "a/b/../c", "a/c"},
		{"trailing slash trimmed", "/a/b/", "/a/b"},
		{"bare root", "/", "/"},
		{"bare drive", "C:", "c:"},
		{"drive root slash", `C:\`, "c:/"},
		{"tilde preserved", "~/x/../y", "~/y"},
		{"empty", "", ""},
		// WINNODE item 2: a UNC path stays UNC (it used to fold to
		// "/server/share/x", a POSIX look-alike no Windows root compared with).
		{"unc", `\\server\share\x`, `\\server/share/x`},
		{"unc dotdot clamps at the share", `\\server\share\..\..\x`, `\\server/share/x`},
		{"unc idempotent", `\\server/share/x`, `\\server/share/x`},
		{"extended-length drive", `\\?\C:\Users\x`, "c:/Users/x"},
		{"extended-length unc", `\\?\UNC\server\share\x`, `\\server/share/x`},
		{"posix double slash is not unc", "//server/share", "/server/share"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := normPath(tc.in); got != tc.want {
				t.Errorf("normPath(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// TestFlavorHelpers pins Windows-shape detection and absoluteness.
func TestFlavorHelpers(t *testing.T) {
	t.Parallel()
	if !isWindowsPath(`C:\x`) || !isWindowsPath("c:/x") || !isWindowsPath(`\\srv\s`) {
		t.Error("windows shapes not detected")
	}
	if isWindowsPath("/etc/hosts") || isWindowsPath("rel/path") {
		t.Error("posix shapes misdetected as windows")
	}
	if !isAbsPath("/a") || !isAbsPath(`C:\x`) || !isAbsPath("c:/x") {
		t.Error("absolute shapes not detected")
	}
	if isAbsPath("rel") || isAbsPath("./x") || isAbsPath("~/x") {
		t.Error("relative shapes misdetected as absolute")
	}
}

// TestExpandHome covers every recognized home-reference prefix plus
// the empty-home degradation (reference left in place so "~"-anchored
// patterns still match literally).
func TestExpandHome(t *testing.T) {
	t.Parallel()
	const home = "/home/u"
	cases := []struct {
		in, home, want string
	}{
		{"~", home, home},
		{"~/x", home, "/home/u/x"},
		{`~\x`, home, "/home/u/x"},
		{"$HOME/x", home, "/home/u/x"},
		{"%USERPROFILE%/x", `C:\Users\u`, `C:\Users\u/x`},
		{"%userprofile%/x", `C:\Users\u`, `C:\Users\u/x`},
		{"~/x", "", "~/x"}, // empty home: unchanged
		{"/abs", home, "/abs"},
		{"~x", home, "~x"}, // ~user form: not ours, unchanged
	}
	for _, tc := range cases {
		if got := expandHome(tc.in, tc.home); got != tc.want {
			t.Errorf("expandHome(%q, %q) = %q, want %q", tc.in, tc.home, got, tc.want)
		}
	}
}

// TestResolvePath pins anchor selection: cwd first, projectRoot
// fallback, and "" (never a guess) when no anchor exists.
func TestResolvePath(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name, target, home, cwd, root, want string
	}{
		{"absolute passthrough", "/etc/hosts", "/home/u", "/home/u/p", "/home/u/p", "/etc/hosts"},
		{"relative via cwd", "src/main.go", "", "/home/u/p", "", "/home/u/p/src/main.go"},
		{"relative via root fallback", "src/main.go", "", "", "/home/u/p", "/home/u/p/src/main.go"},
		{"relative no anchor", "src/main.go", "", "", "", ""},
		{"dotdot escape", "../other", "", "/home/u/p", "", "/home/u/other"},
		{"home expansion", "~/.ssh/id_rsa", "/home/u", "", "", "/home/u/.ssh/id_rsa"},
		{"windows relative", `sub\f.txt`, "", `C:\Users\u\p`, "", "c:/Users/u/p/sub/f.txt"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := resolvePath(tc.target, tc.home, tc.cwd, tc.root); got != tc.want {
				t.Errorf("resolvePath = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestIsUnder pins containment semantics: segment-boundary prefixes
// only, case-insensitive for Windows shapes, mixed flavors never
// comparable.
func TestIsUnder(t *testing.T) {
	t.Parallel()
	cases := []struct {
		child, root string
		want        bool
	}{
		{"/a/b/c", "/a/b", true},
		{"/a/b", "/a/b", true},
		{"/a/bc", "/a/b", false}, // not a segment boundary
		{"/x", "/a", false},
		{`C:\Users\U\P\f.go`, "c:/users/u/p", true}, // case-insensitive
		{`C:\elsewhere`, "/home/u", false},          // mixed flavors: unknown
		{"", "/a", false},
		{"/a", "", false},
		// A drvfs mount folds onto its drive, in either direction.
		{`C:\Users\U\P\f.go`, "/mnt/c/Users/u/p", true},
		{"/mnt/c/Users/u/p/f.go", `C:\Users\U\P`, true},
		{`D:\Users\U\P\f.go`, "/mnt/c/Users/u/p", false}, // other drive
		{`C:\anything`, "/mnt/c", true},                  // drive root
		{`C:\Users\u`, "/mnt/cache/Users/u", false},      // /mnt/cache is no drive
	}
	for _, tc := range cases {
		if got := isUnder(tc.child, tc.root); got != tc.want {
			t.Errorf("isUnder(%q, %q) = %v, want %v", tc.child, tc.root, got, tc.want)
		}
	}
}

// TestPathsEqualDrvfs pins that a drvfs mount and its drive spelling
// are one location, and that the fold never reaches a non-drive /mnt
// directory or a non-drvfs POSIX path.
func TestPathsEqualDrvfs(t *testing.T) {
	t.Parallel()
	cases := []struct {
		a, b string
		want bool
	}{
		{"/mnt/c/Users/u", `C:\Users\U`, true},
		{`c:/users/u/`, "/mnt/c/Users/u", true},
		{"/mnt/c", `C:\`, true},
		{"/mnt/d/x", `C:\x`, false},
		{"/home/u", `C:\home\u`, false},
		{"/mnt/cache/x", `C:\x`, false},
		{"/mnt/c/x", "/mnt/c/x", true},
		{"/mnt/c/X", "/mnt/c/x", false}, // POSIX pair stays case-sensitive
	}
	for _, tc := range cases {
		if got := pathsEqual(tc.a, tc.b); got != tc.want {
			t.Errorf("pathsEqual(%q, %q) = %v, want %v", tc.a, tc.b, got, tc.want)
		}
	}
}

// TestRootAndGlobShapes pins the R-101 catastrophic-target helpers.
func TestRootAndGlobShapes(t *testing.T) {
	t.Parallel()
	for _, p := range []string{"/", "C:", "c:/", `C:\`} {
		if !isFilesystemRoot(p) {
			t.Errorf("isFilesystemRoot(%q) = false, want true", p)
		}
	}
	for _, p := range []string{"/a", "c:/x", "", "~"} {
		if isFilesystemRoot(p) {
			t.Errorf("isFilesystemRoot(%q) = true, want false", p)
		}
	}
	home := "/home/u"
	for _, p := range []string{"/*", "c:/*", `C:\*`, "~/*", "/home/u/*"} {
		if !isRootDepthGlob(p, home) {
			t.Errorf("isRootDepthGlob(%q) = false, want true", p)
		}
	}
	for _, p := range []string{"/tmp/*", "/home/u/p/*", "*", ""} {
		if isRootDepthGlob(p, home) {
			t.Errorf("isRootDepthGlob(%q) = true, want false", p)
		}
	}
}

// TestMatchGlob pins the segment-wise matcher: "**" spans zero or
// more segments (including matching the anchor dir itself), "*"/"?"
// stay within a segment, ci folds ASCII case.
func TestMatchGlob(t *testing.T) {
	t.Parallel()
	cases := []struct {
		pattern, path string
		ci, want      bool
	}{
		{"~/.ssh/**", "~/.ssh/id_rsa", false, true},
		{"~/.ssh/**", "~/.ssh/sub/key", false, true},
		{"~/.ssh/**", "~/.ssh", false, true}, // ** matches zero segments
		{"~/.ssh/**", "~/.sshx", false, false},
		{"/tmp/**", "/tmp/a/b/c", false, true},
		{"/tmp/**", "/var/tmp/x", false, false},
		{"**/.git/hooks/**", "/p/.git/hooks/pre-commit", false, true},
		{"**/.git/hooks/**", "/p/.github/hooks/x", false, false},
		{"release/*", "release/1.0", false, true},
		{"release/*", "release/a/b", false, false}, // * is one segment
		{"main", "main", false, true},
		{"?:/users/*/.ssh/**", "c:/users/bob/.ssh/key", false, true},
		{"~/Library/**", "~/library/Keychains/x", true, true}, // ci fold
		{"~/Library/**", "~/library/x", false, false},
		{"*.pem", "server.pem", false, true},
		{"*.pem", "server.pem.example", false, false},
		{"id_rsa*", "id_rsa.pub", false, true},
	}
	for _, tc := range cases {
		if got := matchGlob(tc.pattern, tc.path, tc.ci); got != tc.want {
			t.Errorf("matchGlob(%q, %q, ci=%v) = %v, want %v", tc.pattern, tc.path, tc.ci, got, tc.want)
		}
	}
}

// TestPathSmallHelpers pins baseName, hasComponent, pathsEqual and
// looksPathish.
func TestPathSmallHelpers(t *testing.T) {
	t.Parallel()
	if baseName("/a/b/c.txt") != "c.txt" || baseName(`C:\x\y`) != "y" || baseName("plain") != "plain" {
		t.Error("baseName mismatch")
	}
	if !hasComponent("/p/.git/config", ".git") || hasComponent("/p/.github/x", ".git") {
		t.Error("hasComponent mismatch")
	}
	if !hasComponent(`C:\P\.GIT\config`, ".git") {
		t.Error("hasComponent should fold case on windows shapes")
	}
	if !pathsEqual(`C:\Users\U`, "c:/users/u") || pathsEqual("/a", "/A") {
		t.Error("pathsEqual flavor-sensitivity mismatch")
	}
	for _, tok := range []string{"/abs", "rel/x", `win\x`, "~/x", "$HOME/x", "./x", "..", "%USERPROFILE%\\x"} {
		if !looksPathish(tok) {
			t.Errorf("looksPathish(%q) = false, want true", tok)
		}
	}
	for _, tok := range []string{"word", "-rf", "", ".env"} {
		if looksPathish(tok) {
			t.Errorf("looksPathish(%q) = true, want false", tok)
		}
	}
}

// TestHomeRelative pins the "~/"-anchored rewrite used by the pattern
// tables.
func TestHomeRelative(t *testing.T) {
	t.Parallel()
	if rel, ok := homeRelative("/home/u/.ssh/id_rsa", "/home/u"); !ok || rel != "~/.ssh/id_rsa" {
		t.Errorf("homeRelative = %q/%v", rel, ok)
	}
	if rel, ok := homeRelative(`C:\Users\U\AppData\Roaming\x`, `C:\Users\u`); !ok || rel != "~/AppData/Roaming/x" {
		t.Errorf("homeRelative windows = %q/%v", rel, ok)
	}
	if _, ok := homeRelative("/etc/hosts", "/home/u"); ok {
		t.Error("homeRelative should fail outside home")
	}
	if _, ok := homeRelative("/home/u/x", ""); ok {
		t.Error("homeRelative should fail with empty home")
	}
}
