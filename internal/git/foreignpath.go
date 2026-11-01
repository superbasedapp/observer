package git

import (
	"path"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
)

// # POSIX-shaped paths on a Windows host (surface-gap FU-112, FU-119)
//
// Cross-OS ingestion hands a Windows-native daemon paths recorded by a tool
// that ran in Linux, macOS or WSL (/work/repo, /home/me/proj). On Windows
// filepath.Abs treats such a path as rooted on the CURRENT drive and returns
// D:\work\repo: a drive the tool never named, invented into the project root
// and every [external]/ target. The same lookup would then stat
// D:\work\repo\.git and could attribute the session to an unrelated
// repository on that drive.
//
// The rule: on a Windows host an absolute POSIX path (a single leading
// "/") is a foreign path. It is cleaned with POSIX semantics and kept as
// is, and no .git is looked for under it, because this host cannot address
// it as written. Every other input, and every input on a POSIX host, keeps
// today's behaviour.

// windowsHostOverride is the test seam of hostIsWindows: 0 follows
// runtime.GOOS, 1 forces a Windows host, 2 forces a POSIX host.
var windowsHostOverride atomic.Int32

// hostIsWindows reports whether this process resolves paths with Windows
// rules.
func hostIsWindows() bool {
	switch windowsHostOverride.Load() {
	case 1:
		return true
	case 2:
		return false
	}
	return runtime.GOOS == "windows"
}

// foreignPOSIXAbs reports whether p is an absolute POSIX path this host
// cannot address as written (a Windows host only).
func foreignPOSIXAbs(p string) bool {
	return hostIsWindows() && strings.HasPrefix(p, "/") && !strings.HasPrefix(p, "//")
}

// cleanForeign is the POSIX-cleaned spelling of a foreign path.
func cleanForeign(p string) string { return path.Clean(p) }

// posixRel is filepath.Rel for two cleaned POSIX paths: the relative path
// of target under base, and false when target is not under base.
func posixRel(base, target string) (string, bool) {
	if target == base {
		return ".", true
	}
	prefix := strings.TrimSuffix(base, "/") + "/"
	if rest, ok := strings.CutPrefix(target, prefix); ok {
		return rest, true
	}
	return "", false
}

// SimulateWindowsHostForTest makes this package resolve paths with the
// Windows host rule for the rest of the test, so a POSIX CI host exercises
// it (an adapter test of cross-OS ingestion uses it too). Test-only by
// contract.
func SimulateWindowsHostForTest(tb testing.TB) {
	tb.Helper()
	prev := windowsHostOverride.Swap(1)
	tb.Cleanup(func() { windowsHostOverride.Store(prev) })
}
