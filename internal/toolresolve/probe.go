package toolresolve

import (
	"path/filepath"

	"github.com/marmutapp/superbased-observer/internal/integration"
)

// commonNativeProbeDirs is the shared, HOME-relative table of directories the
// resolver scans for a tool's binary when it is not first on PATH, on a
// UNIX-flavored (linux/darwin) daemon. These are the npm/volta/pnpm/bun/nvm/
// fnm/asdf/mise/cargo/go/yarn/deno-style install prefixes common ACROSS tools;
// a per-tool BinaryResolveSpec carries only the EXTRAS the common table misses
// (integration.BinaryResolveSpec doc comment). An entry containing a single "*"
// segment (e.g. the nvm node-version dir) is glob-expanded by the resolver
// against the home.
//
// A native-Windows daemon walks commonWindowsNativeProbeDirs instead (selected
// by the daemon's own GOOS in nativeProbeTable — DI-22, 2026-09-02); before
// that split a Windows daemon walked this Unix table, where nothing exists.
//
// CAVEAT (docs: §4.1.1 of the 2026-09-02 remediation research): a probe dir can
// only rescue a version manager that exports a plain DIRECTORY. A LAZY LOADER
// (nvm's sourced shell function) cannot be rescued by any directory — the
// ".nvm/versions/node/*/bin" entry finds *a* node, not necessarily the
// operator's default. The login-shell capture and this table are complementary,
// neither is a superset of the other.
var commonNativeProbeDirs = []string{
	".local/bin",
	"bin",
	".npm-global/bin",
	".volta/bin",
	".bun/bin",
	".local/share/pnpm",
	".nvm/versions/node/*/bin",
	".hermes/node/bin",
	".opencode/bin",
	// fnm (both the XDG default and the legacy ~/.fnm base).
	".local/share/fnm/aliases/default/bin",
	".local/share/fnm/node-versions/*/installation/bin",
	".fnm/aliases/default/bin",
	// asdf / mise shims (a shim IS a plain directory, unlike an activate hook).
	".asdf/shims",
	".local/share/mise/shims",
	// language toolchains that install CLI tools into a fixed home dir.
	".cargo/bin",
	"go/bin",
	".yarn/bin",
	".config/yarn/global/node_modules/.bin",
	".deno/bin",
}

// commonNativeAbsProbeDirs is the sibling ABSOLUTE table walked alongside
// commonNativeProbeDirs — these dirs are NOT home-relative, so the resolver
// walks them verbatim (no home join) and skips the whole list on a Windows
// daemon, where none of them exist. Homebrew (both the Linux and the Apple
// Silicon prefix), a manually installed Go toolchain, and snap are the common
// off-PATH cases a daemon started from a minimal environment misses.
var commonNativeAbsProbeDirs = []string{
	"/home/linuxbrew/.linuxbrew/bin",
	"/opt/homebrew/bin",
	"/usr/local/go/bin",
	"/snap/bin",
}

// commonWindowsNativeProbeDirs is the shared, %USERPROFILE%-relative table a
// NATIVE-Windows daemon walks (DI-22). It is distinct from
// commonForeignWindowsDirs, which is walked under a Windows home reached over
// /mnt from a WSL daemon and whose hits are foreign evidence, never launchable.
// The table is selected by the daemon's OS in nativeProbeTable — a capability
// shape, never a tool name (CLAUDE.md #3).
var commonWindowsNativeProbeDirs = []string{
	"AppData/Roaming/npm",                  // npm -g shim trios (x.cmd/x.ps1/x)
	"AppData/Local/Microsoft/WinGet/Links", // winget portable command aliases
	"AppData/Local/Programs",               // per-app installers (deeper dirs come from per-tool ProbeDirs)
	"scoop/shims",
	".local/bin", // claude native installer, uv tools (aider, vibe)
	"bin",        // droid
}

// commonForeignWindowsDirs is the shared, HOME-relative table of directories
// the resolver scans under each Windows user home reached over /mnt from a WSL
// daemon (foreign probe). These are the standard npm / packaged-app / winget /
// scoop install prefixes a Windows install lays down. Scanned ONLY when the
// tool has grounded Windows binary spellings (BinaryNames.Windows non-empty); a
// hit is classified Foreign — evidence the tool is installed on Windows but not
// natively, never a launchable candidate.
var commonForeignWindowsDirs = []string{
	"AppData/Roaming/npm",
	"AppData/Local/Microsoft/WinGet/Links",
	"AppData/Local/Programs",
	"scoop/shims",
	".local/bin",
}

// nativeProbeTable returns the shared HOME-relative probe table for a daemon
// running on goos. The selection is by daemon OS SHAPE (the same nativeOS the
// resolver already computes for per-tool ProbeDirs), never by tool.
func nativeProbeTable(goos string) []string {
	if goos == "windows" {
		return commonWindowsNativeProbeDirs
	}
	return commonNativeProbeDirs
}

// daemonProbeOSes is the table mapping a daemon GOOS to the ProbeOS tokens it
// walks. It is a DATA table (CLAUDE.md #5), not an if-ladder, so adding a new
// host shape is one row. A darwin daemon walks BOTH ProbeUnix (the shared
// Unix-flavored extras every POSIX host has) and ProbeDarwin (the macOS-only
// extras — app bundles, ~/Applications — that would be dead weight on Linux);
// a linux daemon walks ProbeUnix alone, so an existing registry row's behaviour
// is unchanged by the ProbeDarwin addition.
var daemonProbeOSes = map[string][]integration.ProbeOS{
	"windows": {integration.ProbeWindows},
	"darwin":  {integration.ProbeUnix, integration.ProbeDarwin},
}

// probeOSMatchesDaemon reports whether a ProbeDir's OS token applies to a
// daemon running on goos. An unlisted goos falls back to the Unix shape (the
// linux/BSD floor), matching what the resolver did before ProbeDarwin existed.
func probeOSMatchesDaemon(os integration.ProbeOS, goos string) bool {
	want, ok := daemonProbeOSes[goos]
	if !ok {
		want = []integration.ProbeOS{integration.ProbeUnix}
	}
	for _, w := range want {
		if os == w {
			return true
		}
	}
	return false
}

// resolveProbeDirRoot expands ONE per-tool ProbeDir into the absolute dirs the
// resolver should walk, dispatching on the row's SHAPE — Abs (walk Rel
// verbatim), EnvRoot (root at an environment variable), or the HOME-relative
// default. It returns nil when the row's root cannot be resolved on this host
// (an unset EnvRoot variable, an unknown HOME): a root that does not exist is
// skipped rather than degraded into probing a bare relative path, which would
// resolve against the daemon's cwd. Glob expansion happens later, in
// expandGlobDirs, for every dir at once.
func resolveProbeDirRoot(pd integration.ProbeDir, env Env) []string {
	switch {
	case pd.Abs:
		return []string{filepath.Clean(pd.Rel)}
	case pd.EnvRoot != "":
		if env.Getenv == nil {
			return nil
		}
		root := env.Getenv(pd.EnvRoot)
		if root == "" {
			return nil
		}
		return []string{filepath.Join(root, pd.Rel)}
	default:
		if env.Home == "" {
			return nil
		}
		return []string{filepath.Join(env.Home, pd.Rel)}
	}
}
