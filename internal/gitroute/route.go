package gitroute

import "strings"

// Route names the git a quick-scan read ran with. The non-empty spellings
// are the closed vocabulary of policy.QuickScanDetail.Git (the daemon's
// test pins the two tables equal).
type Route string

const (
	// RouteHost is the host's own git on PATH, unchanged (every host and
	// path but a WSL daemon reading a Windows drive).
	RouteHost Route = ""
	// RouteWindowsGit is the Windows git.exe started through WSL interop
	// with the same argv, for a checkout on a Windows drive.
	RouteWindowsGit Route = "windows_git"
	// RouteDrvFsStat is the WSL git reading a Windows drive with
	// core.checkStat=minimal and core.trustctime=false (R3-66): no usable
	// Windows git (interop off, no git.exe found, or an argument git.exe
	// would read differently).
	RouteDrvFsStat Route = "wsl_git_drvfs"
	// RouteDrvFsAfterWindows is RouteDrvFsStat run because the Windows git
	// failed for an environmental reason (Environmental).
	RouteDrvFsAfterWindows Route = "wsl_git_drvfs_fallback"
)

// DrvFsStatArgs are the config overrides the WSL git runs with on a Windows
// drive (R3-66): the Windows-written index is compared by whole-second
// mtime and size, which is what Windows git's own commit compares; racily
// clean entries are still content-checked.
var DrvFsStatArgs = []string{"-c", "core.checkStat=minimal", "-c", "core.trustctime=false"}

// Facts is what Choose decides from. The Router gathers them.
type Facts struct {
	// GOOS is the host's operating system (runtime.GOOS).
	GOOS string
	// Mount is the mount holding the root; MountOK is false when none was
	// found (the root is not absolute, or no table entry holds it).
	Mount   Mount
	MountOK bool
	// Interop reports that WSL interop can start a Windows program
	// (binfmt_misc's WSLInterop registration is enabled).
	Interop bool
	// WindowsGit is the resolved git.exe path ("" when none was usable).
	WindowsGit string
}

// Plan is how one git read runs.
type Plan struct {
	Route Route
	// Why is the rule that chose the plan (for the daemon's log).
	Why string
	// Program is the git.exe path, Dir the root's Windows spelling
	// (RouteWindowsGit only).
	Program string
	Dir     string
	// ConfigArgs are -c overrides placed before the subcommand.
	ConfigArgs []string
	// Fallback is the plan to run when the Windows git fails for an
	// environmental reason (RouteWindowsGit only).
	Fallback *Plan
}

// rule is one row of the route table: the first row whose when holds
// builds the plan.
type rule struct {
	why   string
	when  func(f Facts, root string, args []string) bool
	build func(f Facts, root string) (Plan, bool)
}

// rules is the route table, read top to bottom. Nothing here names a tool
// or a repository: the rows read the host, the mount and the argv.
var rules = []rule{
	{
		why:   "not a Linux host: the host's own git",
		when:  func(f Facts, _ string, _ []string) bool { return f.GOOS != "linux" },
		build: hostPlan,
	},
	{
		why:   "not on a Windows drive mount: the host's own git",
		when:  func(f Facts, _ string, _ []string) bool { return !f.MountOK || !f.Mount.DrvFs },
		build: hostPlan,
	},
	{
		why: "a Windows drive with interop and a Windows git: git.exe",
		when: func(f Facts, _ string, args []string) bool {
			return f.Interop && f.WindowsGit != "" && portableArgs(args)
		},
		build: func(f Facts, root string) (Plan, bool) {
			dir, ok := WindowsPath(f.Mount, root)
			if !ok {
				return Plan{}, false
			}
			fb := drvfsPlan(RouteDrvFsAfterWindows, "the Windows git failed: the WSL git with the minimal stat check")
			return Plan{Route: RouteWindowsGit, Program: f.WindowsGit, Dir: dir, Fallback: &fb}, true
		},
	},
	{
		why:  "a Windows drive without a usable Windows git: the WSL git with the minimal stat check",
		when: func(Facts, string, []string) bool { return true },
		build: func(Facts, string) (Plan, bool) {
			return drvfsPlan(RouteDrvFsStat, ""), true
		},
	},
}

func hostPlan(Facts, string) (Plan, bool) { return Plan{Route: RouteHost}, true }

func drvfsPlan(r Route, why string) Plan {
	return Plan{Route: r, Why: why, ConfigArgs: append([]string(nil), DrvFsStatArgs...)}
}

// Choose returns the plan for one git read of root with args. A row whose
// plan cannot be built (a root the Windows spelling cannot name) passes to
// the next row.
func Choose(f Facts, root string, args []string) Plan {
	for _, r := range rules {
		if !r.when(f, root, args) {
			continue
		}
		p, ok := r.build(f, root)
		if !ok {
			continue
		}
		if p.Why == "" {
			p.Why = r.why
		}
		return p
	}
	return Plan{Route: RouteHost, Why: "no rule"}
}

// portableArgs reports whether git.exe reads args the way the WSL git
// does. Every path operand after "--" must be relative (an absolute POSIX
// path, /mnt/d/x, means nothing to Windows git), and no argument may carry
// a double quote, a control character or a trailing backslash: WSL interop
// joins the argv into one Windows command line that git.exe splits again,
// and those are what that quoting turns into a different argument list.
// The quick scan's own argv never carries one; a pathspec form from the
// hook could, and such a read stays on the WSL git.
func portableArgs(args []string) bool {
	after := false
	for _, a := range args {
		if strings.ContainsAny(a, "\"") || strings.HasSuffix(a, `\`) || hasControl(a) {
			return false
		}
		if !after {
			after = a == "--"
			continue
		}
		if strings.HasPrefix(a, "/") || strings.HasPrefix(a, `\`) {
			return false
		}
	}
	return true
}

// hasControl reports an ASCII control character.
func hasControl(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] == 0x7f {
			return true
		}
	}
	return false
}
