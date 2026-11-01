//go:build !sbo_omit_security

package main

import (
	"path"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/policy"
)

// hook_security_msys.go resolves the operand of a directory change on a
// shell line (cd, pushd, Set-Location) the way the shell that runs it does
// (HOOK-MSYS-1, tracker R-169). On Windows a POSIX-dialect line runs in Git
// Bash (MSYS), where a rooted path is not a Windows path: `/c/work` is
// `C:\work`, and `/tmp` or `/home` live under the Git install folder,
// which the hook does not know. Before this file such an operand was joined
// under the event's directory (`<event dir>\c\work`), so the commit gate
// could judge the wrong directory.

// Reasons a directory-change operand is not resolved (the walk stops there
// and the gate treats the place as unknown).
const (
	// shellDirMSYSRootUnmapped: a Git Bash rooted path that is not a drive
	// (`/tmp`, `/home/x`, `/`): MSYS maps it under its install folder.
	shellDirMSYSRootUnmapped = "msys_root_unmapped"
	// shellDirNetworkRoot: a POSIX network or automount root (/net, /misc,
	// /afs, /Network), never statted on the hook path.
	shellDirNetworkRoot = "posix_network_root"
	// shellDirDriveRelative: a Windows drive-relative operand (`C:` or
	// `C:foo`) moves to that drive's own current directory, which the hook
	// does not know (RB1 sweep finding H3); it is never joined under the
	// event's directory.
	shellDirDriveRelative = "windows_drive_relative"
)

// shellDirResolution is where one directory-change operand leads.
type shellDirResolution struct {
	Dir string
	// Reason is empty when Dir is resolved; otherwise one of the
	// shellDir* reasons and Dir is empty.
	Reason string
}

// msysNetworkRoots are the POSIX network and automount roots
// (policy.IsNetworkPlace recognises them on a POSIX host only).
var msysNetworkRoots = map[string]bool{"net": true, "misc": true, "afs": true, "Network": true}

// shellPathRules are one target OS's path rules, the parameter that keeps
// resolveShellDir pure: it never reads the host's filepath, so a Windows
// row and a POSIX row each resolve by their own OS's rules on any host
// (the rows run on Linux and in the Windows test binary alike).
type shellPathRules struct {
	// GitBash: a POSIX-dialect line on this target runs in Git Bash
	// (MSYS), so its rooted operands take the MSYS rules.
	GitBash bool
	// IsAbs and Join are the target's own absolute test and join.
	IsAbs func(string) bool
	Join  func(elem ...string) string
}

// posixShellPathRules are Linux's and macOS's rules ("/" only), the same on
// every host.
var posixShellPathRules = shellPathRules{IsAbs: path.IsAbs, Join: path.Join}

// windowsShellPathRules are Windows's rules written by hand (drive and UNC
// volumes, both separators), the same on every host. They cover the
// ordinary spellings; the host's filepath also knows device paths and
// reserved names, so production on Windows uses that (hostShellPathRules).
var windowsShellPathRules = shellPathRules{GitBash: true, IsAbs: windowsIsAbs, Join: windowsJoin}

// shellPathRulesFor returns goos's pure path rules.
func shellPathRulesFor(goos string) shellPathRules {
	if goos == "windows" {
		return windowsShellPathRules
	}
	return posixShellPathRules
}

// hostShellPathRules are the hook host's own rules. The target is always
// the host in production, so the host's filepath is the target's rules
// exactly. This is the one place the host's filepath enters.
func hostShellPathRules() shellPathRules {
	r := shellPathRulesFor(runtime.GOOS)
	r.IsAbs, r.Join = filepath.IsAbs, filepath.Join
	return r
}

// resolveShellDir resolves arg against base for a line in dialect under
// the target OS's path rules. It is pure (the rules are a parameter, the
// Windows spellings are built by hand) so the Windows rules are tested on
// every host. Only a POSIX-dialect line on a Git Bash target takes the
// MSYS rules; everything else keeps the target's path rules: an absolute
// operand stays, a relative one joins base.
func resolveShellDir(rules shellPathRules, dialect policy.Dialect, arg, base string) shellDirResolution {
	if rules.GitBash && securityDialectOf(dialect) == policy.DialectPosix && msysRooted(arg) {
		segs := strings.Split(strings.Trim(arg, "/"), "/")
		switch first := segs[0]; {
		case msysNetworkRoots[first]:
			return shellDirResolution{Reason: shellDirNetworkRoot}
		case len(first) == 1 && isASCIILetter(first[0]):
			// Git Bash's drive mount: /c/x/y is C:\x\y.
			rest := strings.Join(segs[1:], `\`)
			return shellDirResolution{Dir: strings.ToUpper(first) + `:\` + rest}
		default:
			return shellDirResolution{Reason: shellDirMSYSRootUnmapped}
		}
	}
	if rules.GitBash && windowsDriveRelative(arg) {
		return shellDirResolution{Reason: shellDirDriveRelative}
	}
	if !rules.IsAbs(arg) {
		return shellDirResolution{Dir: rules.Join(base, arg)}
	}
	return shellDirResolution{Dir: arg}
}

// msysRooted reports a single-slash rooted POSIX spelling (`/x`), not a UNC
// spelling (`//host`), which the network rules handle.
func msysRooted(arg string) bool {
	return strings.HasPrefix(arg, "/") && !strings.HasPrefix(arg, "//")
}

// windowsDriveRelative reports a drive letter and colon not followed by a
// separator (`C:`, `C:foo`): relative to that drive's current directory.
func windowsDriveRelative(arg string) bool {
	return len(arg) >= 2 && isASCIILetter(arg[0]) && arg[1] == ':' && (len(arg) == 2 || !isWindowsSep(arg[2]))
}

func isASCIILetter(b byte) bool { return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') }

func isWindowsSep(b byte) bool { return b == '\\' || b == '/' }

// windowsVolumeLen is the length of p's Windows volume, as Windows's
// filepath reads it: a drive (`C:`), or after a double separator the UNC
// host and share (`\\host\share`, or all of p when it has no second
// separator), else 0. Device paths (`\\.\`, `\\?\`) read as UNC here.
func windowsVolumeLen(p string) int {
	switch {
	case len(p) >= 2 && p[1] == ':':
		return 2
	case len(p) < 2 || !isWindowsSep(p[0]) || !isWindowsSep(p[1]):
		return 0
	}
	seps := 0
	for i := 2; i < len(p); i++ {
		if isWindowsSep(p[i]) {
			if seps++; seps == 2 {
				return i
			}
		}
	}
	return len(p)
}

// windowsIsAbs is Windows's filepath.IsAbs for the ordinary spellings: a
// UNC volume, or a drive followed by a separator.
func windowsIsAbs(p string) bool {
	l := windowsVolumeLen(p)
	if l == 0 {
		return false
	}
	if isWindowsSep(p[0]) && isWindowsSep(p[1]) {
		return true
	}
	return l < len(p) && isWindowsSep(p[l])
}

// windowsJoin is Windows's filepath.Join for the ordinary spellings (its
// element rules: a backslash between elements, the leading separators of
// an element after a separator dropped so no UNC is made, nothing added
// after a drive's colon), then cleaned.
func windowsJoin(elem ...string) string {
	var b strings.Builder
	var last byte
	for _, e := range elem {
		switch {
		case b.Len() == 0:
		case isWindowsSep(last):
			for e != "" && isWindowsSep(e[0]) {
				e = e[1:]
			}
		case last == ':':
		default:
			b.WriteByte('\\')
			last = '\\'
		}
		if e != "" {
			b.WriteString(e)
			last = e[len(e)-1]
		}
	}
	if b.Len() == 0 {
		return ""
	}
	return windowsClean(b.String())
}

// windowsClean is Windows's filepath.Clean for the ordinary spellings:
// both separators read, `.` and `..` folded lexically, the volume kept,
// backslashes out.
func windowsClean(p string) string {
	l := windowsVolumeLen(p)
	vol, rest := strings.ReplaceAll(p[:l], "/", `\`), p[l:]
	if rest == "" {
		if l > 0 && isWindowsSep(vol[0]) {
			return vol // a UNC volume alone
		}
		return vol + "."
	}
	return vol + strings.ReplaceAll(path.Clean(strings.ReplaceAll(rest, `\`, "/")), "/", `\`)
}
