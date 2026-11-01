package sandboxmxc

import "strings"

// ancestors.go grants a box the directory metadata Windows itself needs to
// resolve a path it may read (Windows 11 Pro run 4, 2026-10-23). MXC 1.0.1's
// BaseContainer tier denies every path the policy does not grant ("Paths are
// denied by default unless granted via readwritePaths or readonlyPaths",
// mxc_ffi.dll), and a read-only grant of a directory reaches only that
// directory's own subtree. A process that opens a granted file by its full
// path needs nothing more, which is why the inner observer.exe (read-only
// bundle directory) starts; a runtime that resolves a path component by
// component needs to list each parent too, and the run's evidence fits
// exactly that: cmd.exe running the read-only `$iso\bin\claude.cmd` (under
// C:\Users\<user>\AppData\Local\Temp, none of whose parents the policy
// granted) printed "Access is denied.", and a .NET console stand-in in the
// same directory was mapped and started but failed its DLL initialisation
// (0x8007045A). MXC's own
// package names the need: its DACL tier warns that "AppContainer processes
// may be unable to read metadata of the system-drive root (e.g. `cmd.exe`,
// `pwsh.exe`, `node.exe` startup stats of `C:\`)", and its PowerShell policy
// grants the drive root because "pwsh.exe enumerates the drive root on
// startup" (dist/v1/policy/filesystem.js). The 1.0.0 contract's field for it
// is processContainer.filesystem.enumeratePaths, "paths that may be queried
// or enumerated without granting file-content reads"
// (dist/generated/v1_0_0/wire.d.ts), served when the host's BaseContainer
// reports baseContainerSupportsEnumeratePaths. So the run's document lists,
// enumerate-only, every directory above a grant: no file content and no
// write is granted there, only names and attributes.

// EnumerateAncestors returns every proper ancestor directory of grants, the
// drive root included, nearest first per grant and each once, leaving out
// any directory that is itself a grant, lies inside one, or lies inside (or
// is) a denied path: MXC applies the narrower intent to a path listed twice,
// so an enumerate-only entry there would take a grant away, and a denied
// path stays denied. Comparison is case-insensitive with either separator,
// as Windows paths are.
func EnumerateAncestors(grants, denied []string) []string {
	return enumerateAncestorsOf(grants, grants, denied)
}

// enumerateAncestorsOf walks the parents of every path in from (the grants,
// and a run's cwd before them, which is walked but is not itself a grant)
// against grants and denied.
func enumerateAncestorsOf(from, grants, denied []string) []string {
	var out []string
	seen := map[string]bool{}
	for _, g := range from {
		for p := parentDir(g); p != ""; p = parentDir(p) {
			k := winPathKey(p)
			if seen[k] {
				// Every ancestor above it was walked when it was first seen.
				break
			}
			seen[k] = true
			if withinAnyPath(p, grants) || withinAnyPath(p, denied) {
				continue
			}
			out = append(out, p)
		}
	}
	return out
}

// parentDir is the directory above p ("C:\a" for "C:\a\b", "C:\" for
// "C:\a"), or "" for a drive root or a path with no parent.
func parentDir(p string) string {
	s := strings.TrimRight(p, `\/`)
	if len(s) <= 2 {
		return ""
	}
	i := strings.LastIndexAny(s, `\/`)
	switch {
	case i < 2:
		return ""
	case i == 2:
		return s[:2] + `\`
	}
	return s[:i]
}

// winPathKey is p's comparison key: lower case, backslashes, no trailing
// separator (a drive root keys as "c:").
func winPathKey(p string) string {
	return strings.TrimRight(strings.ToLower(strings.ReplaceAll(p, "/", `\`)), `\`)
}

// withinPath reports whether p is root or lies under it.
func withinPath(p, root string) bool {
	kp, kr := winPathKey(p), winPathKey(root)
	return kr != "" && (kp == kr || strings.HasPrefix(kp, kr+`\`))
}

// withinAnyPath reports whether p is or lies under one of roots.
func withinAnyPath(p string, roots []string) bool {
	for _, r := range roots {
		if withinPath(p, r) {
			return true
		}
	}
	return false
}
