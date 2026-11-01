package crossmount

import "strings"

// WindowsPathFromMount converts a WSL DrvFs path (/mnt/<drive>/x) to the
// spelling a Windows process uses for the same file (<DRIVE>:\x): an upper-
// case drive letter and backslashes, the form Windows' own profile lookup
// returns. ok is false for anything not under a /mnt drive mount. Pure
// string work; the path need not exist.
//
// A Windows tool that keys state by a path it resolved itself (Codex's
// [hooks.state] trust keys, for one) needs this spelling, not the /mnt view
// a WSL daemon reads the file through.
func WindowsPathFromMount(p string) (string, bool) {
	const prefix = "/mnt/"
	if !strings.HasPrefix(p, prefix) || len(p) < len(prefix)+1 {
		return "", false
	}
	drive := p[len(prefix)]
	if (drive < 'a' || drive > 'z') && (drive < 'A' || drive > 'Z') {
		return "", false
	}
	rest := p[len(prefix)+1:]
	if rest == "" {
		return strings.ToUpper(string(drive)) + `:\`, true
	}
	if rest[0] != '/' {
		return "", false // "/mnt/cfoo" is a directory named cfoo, not drive C
	}
	return strings.ToUpper(string(drive)) + ":" + strings.ReplaceAll(rest, "/", `\`), true
}
