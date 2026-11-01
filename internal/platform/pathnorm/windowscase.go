package pathnorm

import "strings"

// Windows path case (WINNODE2 item 11). Windows paths are case-insensitive,
// and one folder reached two ways (VS Code reports a cwd with a lower-case
// drive letter, git and Go's EvalSymlinks an upper-case one) became two
// node projects, `C:\x` and `c:\x`. These helpers are shape-based: they
// look only at the path, so a POSIX path is never touched and a test on any
// OS sees what a Windows node sees.

// IsWindowsShaped reports whether p is a Windows drive path (`C:\x`,
// `c:/x`) or a UNC path (`\\server\share`): the paths whose case does not
// name a different file.
func IsWindowsShaped(p string) bool {
	return looksLikeWindowsDriveAbsolute(p) || strings.HasPrefix(p, `\\`)
}

// CanonicalDriveLetter returns p with a Windows drive letter upper-cased
// (`c:\x` -> `C:\x`), the spelling git and Go's own path canonicalisation
// use. Every other path is returned unchanged.
func CanonicalDriveLetter(p string) string {
	if !looksLikeWindowsDriveAbsolute(p) || (p[0] >= 'A' && p[0] <= 'Z') {
		return p
	}
	return strings.ToUpper(p[:1]) + p[1:]
}
