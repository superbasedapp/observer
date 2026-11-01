package crossmount

import (
	"path/filepath"
	"strings"
)

// # The Windows to WSL direction (surface-gap Wave 7, D7 / DEC-10)
//
// A Windows-native daemon reaches each WSL distro's Linux homes over
// \\wsl.localhost\<distro>\home\<user> (windowsWSLHomes). The cross-OS
// writers that mirror the WSL to Windows "-windows" targets in this
// direction ("<tool>-wsl") need three facts this file owns:
//
//   - which enumerated homes are WSL homes (IsWSLHostHome), as opposed to
//     the native home, which on a Linux host is OS=="linux" too;
//   - whether a WSL home belongs to the operator (WSLHomeOwnedByCurrentUser),
//     the twin of HomeOwnedByCurrentWindowsUser;
//   - how a path is spelled on the other side: the Linux spelling of a
//     \\wsl.localhost path (LinuxPathFromWSLHost) and the WSL interop
//     spelling of a Windows drive path (MountPathFromWindows, the inverse of
//     WindowsPathFromMount), so a hook command written into the distro can
//     run the Windows observer.exe.

// wslHostOriginPrefix marks a home enumerated by windowsWSLHomes.
const wslHostOriginPrefix = "wslhost:"

// IsWSLHostHome reports whether h is a Linux home inside a WSL distro, seen
// from a Windows host (\\wsl.localhost\<distro>\home\<user>).
func IsWSLHostHome(h HomeRoot) bool {
	return h.OS == OSLinux && strings.HasPrefix(h.Origin, wslHostOriginPrefix)
}

// WSLHostDistro returns the distro of a home enumerated from a Windows host
// (its Origin "wslhost:<distro>/<user>"), "" for any other home.
func WSLHostDistro(h HomeRoot) string {
	if !IsWSLHostHome(h) {
		return ""
	}
	rest := strings.TrimPrefix(h.Origin, wslHostOriginPrefix)
	distro, _, _ := strings.Cut(rest, "/")
	return distro
}

// WSLHomeOwnedByCurrentUser reports whether the WSL Linux home dir (seen from
// Windows as \\wsl.localhost\<distro>\home\<user>) belongs to the operator.
//
// A Windows user sees only the distros registered to their own account under
// \\wsl.localhost, so the distro itself is theirs. Inside it, the home is
// accepted only when it is the ONE user directory under the distro's /home:
// a distro with several Linux users is ambiguous, and the caller must be told
// which home to use (an explicit override). That is the safe default the
// WSL to Windows rule (HomeOwnedByCurrentWindowsUser) also keeps: no proof,
// no automatic write.
func WSLHomeOwnedByCurrentUser(home string) bool {
	return soleUserHome(home, readDirNames, isExistingDir)
}

// soleUserHome is the pure core of WSLHomeOwnedByCurrentUser: home's parent
// directory holds exactly one directory, and it is home.
func soleUserHome(home string, readDir func(string) ([]string, error), isDir func(string) bool) bool {
	if home == "" {
		return false
	}
	parent := filepath.Dir(filepath.Clean(home))
	names, err := readDir(parent)
	if err != nil {
		return false
	}
	var dirs []string
	for _, n := range names {
		if isDir(filepath.Join(parent, n)) {
			dirs = append(dirs, n)
		}
	}
	return len(dirs) == 1 && dirs[0] == filepath.Base(filepath.Clean(home))
}

// LinuxPathFromWSLHost converts a Windows spelling of a WSL path
// (\\wsl.localhost\<distro>\x or \\wsl$\<distro>\x, either separator,
// any case of the host name) to the path a process inside that distro uses
// (/x). ok is false for any other path. Pure string work; the path need not
// exist.
func LinuxPathFromWSLHost(p string) (string, bool) {
	s := strings.ReplaceAll(p, `\`, "/")
	lower := strings.ToLower(s)
	var rest string
	switch {
	case strings.HasPrefix(lower, "//wsl.localhost/"):
		rest = s[len("//wsl.localhost/"):]
	case strings.HasPrefix(lower, "//wsl$/"):
		rest = s[len("//wsl$/"):]
	default:
		return "", false
	}
	distro, tail, found := strings.Cut(rest, "/")
	if distro == "" {
		return "", false
	}
	if !found || tail == "" {
		return "/", true
	}
	return "/" + strings.TrimRight(tail, "/"), true
}

// MountPathFromWindows converts a Windows drive path (C:\x or C:/x) to the
// spelling a WSL process uses for the same file (/mnt/c/x): the inverse of
// WindowsPathFromMount. ok is false for anything that is not an absolute
// drive path (a UNC path, a relative path, a POSIX path). Pure string work.
func MountPathFromWindows(p string) (string, bool) {
	if len(p) < 3 || p[1] != ':' || (p[2] != '\\' && p[2] != '/') {
		return "", false
	}
	drive := p[0]
	if (drive < 'a' || drive > 'z') && (drive < 'A' || drive > 'Z') {
		return "", false
	}
	rest := strings.Trim(strings.ReplaceAll(p[3:], `\`, "/"), "/")
	out := "/mnt/" + strings.ToLower(string(drive))
	if rest != "" {
		out += "/" + rest
	}
	return out, true
}
