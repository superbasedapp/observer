package sandboxrelay

import (
	"path/filepath"
	"strings"
)

// paths.go is the path syntax the relay reads a box's paths in (Windows 11
// Pro run 3, 2026-10-22). A box sees the host's paths at the same spelling
// under every driver (bwrap and the containers on Linux, Seatbelt and Apple
// container on macOS, the MXC ProcessContainer on Windows), so a path a box
// sends is judged in the syntax of the host that judges it. The schema once
// knew only the POSIX syntax: every Windows box request carrying its working
// directory (C:\...) failed it at the host helper, which closed the box's
// stream without an answer, and the in-box launch check was refused as an
// unreachable relay while the daemon was answering.
//
// The syntax is a row of a table chosen by the host's own path separator
// (HostPaths), never by an operating system name; RequestRules.Paths
// overrides it, so a test on one host can judge the other syntax.

// PathSyntax is one host path syntax.
type PathSyntax struct {
	// Name names the syntax in a refusal ("posix", "windows").
	Name string
	// Separator is the separator a clean path uses.
	Separator byte
	// Alternate is a second separator a vendor's payload may use, read as
	// Separator (0: none).
	Alternate byte
	// FoldCase compares paths case-insensitively.
	FoldCase bool
	// rootLen is the length of p's absolute root ("/" or `C:\`), or 0 when
	// p is not absolute in this syntax.
	rootLen func(p string) int
	// forbidden are bytes no component may hold.
	forbidden string
}

// The syntax table's rows.
var (
	// PosixPaths: an absolute path starts with "/".
	PosixPaths = PathSyntax{Name: "posix", Separator: '/', rootLen: posixRoot}
	// WindowsPaths: an absolute path starts with a drive root (C:\). A UNC
	// or device path (\\server\share, \\?\, \\.\) is not one: no driver
	// runs a box there, and the device forms bypass the path rules.
	WindowsPaths = PathSyntax{
		Name: "windows", Separator: '\\', Alternate: '/', FoldCase: true,
		rootLen: windowsDriveRoot, forbidden: `:*?"<>|`,
	}
)

// pathSyntaxes is the table HostPaths walks.
var pathSyntaxes = []PathSyntax{PosixPaths, WindowsPaths}

// PathsFor is the row whose separator is sep (PosixPaths when none is).
func PathsFor(sep byte) PathSyntax {
	for _, s := range pathSyntaxes {
		if s.Separator == sep {
			return s
		}
	}
	return PosixPaths
}

// HostPaths is the syntax of this host's paths.
func HostPaths() PathSyntax { return PathsFor(filepath.Separator) }

func posixRoot(p string) int {
	if strings.HasPrefix(p, "/") {
		return 1
	}
	return 0
}

func windowsDriveRoot(p string) int {
	if len(p) < 3 || p[1] != ':' || p[2] != '\\' {
		return 0
	}
	if c := p[0] | 0x20; c < 'a' || c > 'z' {
		return 0
	}
	return 3
}

// Valid reports whether s is a row of the table (the zero value is not).
func (s PathSyntax) Valid() bool { return s.rootLen != nil }

// Clean returns p in this syntax's clean spelling (the alternate separator
// read as the separator, one trailing separator dropped) and whether p is an
// absolute path with no NUL, no empty, "." or ".." component and no
// forbidden byte. A host process resolves ".." after following a link, a
// lexical check before it, so such a path is refused rather than reasoned
// about.
func (s PathSyntax) Clean(p string) (string, bool) {
	if !s.Valid() || p == "" || strings.IndexByte(p, 0) >= 0 {
		return "", false
	}
	sep := string(s.Separator)
	if s.Alternate != 0 {
		p = strings.ReplaceAll(p, string(s.Alternate), sep)
	}
	n := s.rootLen(p)
	if n == 0 {
		return "", false
	}
	rest := strings.TrimSuffix(p[n:], sep)
	if rest == "" {
		return p[:n], true
	}
	for _, c := range strings.Split(rest, sep) {
		if c == "" || c == "." || c == ".." || strings.ContainsAny(c, s.forbidden) {
			return "", false
		}
	}
	return p[:n] + rest, true
}

// IsClean reports whether p is a clean absolute path already (Clean returns
// it unchanged).
func (s PathSyntax) IsClean(p string) bool {
	c, ok := s.Clean(p)
	return ok && c == p
}

// Within reports whether the clean absolute path p is root or lies under
// it (case-insensitively in a syntax that folds case).
func (s PathSyntax) Within(p, root string) bool {
	eq := func(a, b string) bool {
		if s.FoldCase {
			return strings.EqualFold(a, b)
		}
		return a == b
	}
	if eq(p, root) {
		return true
	}
	if !s.Valid() {
		return false
	}
	if n := s.rootLen(root); n > 0 && n == len(root) {
		// A bare root ("/", `C:\`) holds every path under it.
		return len(p) >= n && eq(p[:n], root)
	}
	pre := root + string(s.Separator)
	return len(p) >= len(pre) && eq(p[:len(pre)], pre)
}
