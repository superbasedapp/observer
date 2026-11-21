package pathnorm

import (
	"runtime"
	"strings"
)

// IsLocalAbsPath reports whether a STORED path (a source_file column, never
// a fresh user argument) is safe for this process to open as a local file:
// an absolute path on this OS's local filesystem. It is the one gate every
// reader that re-opens a stored transcript path consults before os.Open
// (the dashboard's Raw events tab, the handoff substrate behind handoffsvc
// and the MCP get_session_message tool), so a row that names a network or
// device location is never followed.
//
// Why it exists (ledger CLOUDSESS-12): stored paths are not all written by
// this node. A cloud-session batch arrives from a vendor sandbox that may be
// prompt-injected, and before the landing path stopped keeping the
// sandbox's source_file verbatim, a token holder could plant a UNC path
// (`\\host@SSL\s\a.jsonl`, `//host/s/a.jsonl`) whose open leaks the owner's
// NTLM hash on Windows, or a home-directory secret file. The landing side
// no longer stores those; this gate is the defence in depth on the read
// side.
//
// Refused on EVERY OS, before the OS rule: an empty path, a path with a NUL
// byte, and any path that starts with two separators of either kind (`\\`,
// `//`, `\/`, `/\`), which covers UNC shares and the Win32 device and
// extended-length namespaces (`\\?\`, `\\.\`). Legitimate transcript paths
// are stored normalised (Normalize strips `\\?\`), so nothing a local
// adapter writes is lost.
//
// Then the OS rule. On Windows: a drive letter, a colon and a separator
// (`C:\Users\...` or `C:/Users/...`), no further colon (alternate data
// streams) and no reserved device name (CON, NUL, COM1, ...) as a path
// element. A rooted but volume-less `\Users\x` is relative to the current
// drive and refused. Elsewhere: exactly one leading `/`.
func IsLocalAbsPath(p string) bool {
	return isLocalAbsPathFor(p, runtime.GOOS)
}

// isLocalAbsPathFor is IsLocalAbsPath for a named GOOS, so the rules for
// both OS families are testable on any host. It is purely lexical: it never
// touches the filesystem.
func isLocalAbsPathFor(p, goos string) bool {
	if p == "" || strings.ContainsRune(p, 0) {
		return false
	}
	if len(p) >= 2 && isSep(p[0]) && isSep(p[1]) {
		return false
	}
	if goos == "windows" {
		return isLocalWindowsAbs(p)
	}
	return p[0] == '/'
}

func isSep(c byte) bool { return c == '/' || c == '\\' }

// isLocalWindowsAbs is the Windows rule of isLocalAbsPathFor.
func isLocalWindowsAbs(p string) bool {
	if len(p) < 3 || !isASCIILetter(p[0]) || p[1] != ':' || !isSep(p[2]) {
		return false
	}
	if strings.ContainsRune(p[2:], ':') {
		return false
	}
	for _, elem := range strings.FieldsFunc(p[3:], func(r rune) bool { return r == '/' || r == '\\' }) {
		if isWindowsReservedName(elem) {
			return false
		}
	}
	return true
}

func isASCIILetter(c byte) bool { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') }

// windowsReservedNames are the DOS device names Win32 resolves to a device
// in any directory, with or without an extension.
var windowsReservedNames = map[string]bool{
	"CON": true, "PRN": true, "AUX": true, "NUL": true, "CONIN$": true, "CONOUT$": true,
	"COM1": true, "COM2": true, "COM3": true, "COM4": true, "COM5": true, "COM6": true, "COM7": true, "COM8": true, "COM9": true,
	"LPT1": true, "LPT2": true, "LPT3": true, "LPT4": true, "LPT5": true, "LPT6": true, "LPT7": true, "LPT8": true, "LPT9": true,
}

// isWindowsReservedName reports whether one path element names a DOS
// device: the part before the first dot, trailing spaces trimmed, compared
// case-insensitively.
func isWindowsReservedName(elem string) bool {
	base, _, _ := strings.Cut(elem, ".")
	base = strings.TrimRight(base, " ")
	return windowsReservedNames[strings.ToUpper(base)]
}
