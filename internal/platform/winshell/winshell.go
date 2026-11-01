package winshell

import "strings"

// Status is the answer of Check / Resolve.
type Status string

const (
	// Unknown: no Windows PATH directory is visible to this process, so
	// nothing can be said (never a warning).
	Unknown Status = "unknown"
	// Found: the shell resolves in a visible Windows PATH directory.
	Found Status = "found"
	// NotFound: Windows PATH directories are visible and none holds the
	// shell.
	NotFound Status = "not_found"
)

// RunnerExts are the extensions a Windows runner appends to a bare program
// name. Rust's std::process::Command (VT Code's runner) and CreateProcess
// append ".exe" only; they do NOT walk PATHEXT, so a sh.cmd or sh.bat on
// PATH would not be spawned and does not count.
var RunnerExts = []string{".exe"}

// Lookup is Resolve's input.
type Lookup struct {
	// Shell is the bare executable name the host spawns ("sh"). A name that
	// already carries an extension is looked up as is.
	Shell string
	// Exts are the extensions appended to a bare Shell (RunnerExts when
	// empty). Compared case-insensitively.
	Exts []string
	// Dirs are the Windows PATH directories as this process addresses them
	// (C:\... natively, /mnt/c/... from WSL); WindowsDirs builds them.
	Dirs []string
	// Exists reports whether path names an existing file. Required.
	Exists func(path string) bool
}

// Resolve looks Shell up in Dirs in PATH order. It returns Unknown when Dirs
// is empty or Exists is nil, Found with the matching path, or NotFound.
// Directories are de-duplicated case-insensitively (Windows paths are).
func Resolve(l Lookup) (Status, string) {
	if len(l.Dirs) == 0 || l.Exists == nil || strings.TrimSpace(l.Shell) == "" {
		return Unknown, ""
	}
	names := candidateNames(l.Shell, l.Exts)
	seen := map[string]bool{}
	for _, dir := range l.Dirs {
		key := strings.ToLower(strings.TrimRight(dir, `\/`))
		if key == "" || seen[key] {
			continue
		}
		seen[key] = true
		for _, n := range names {
			p := joinDir(dir, n)
			if l.Exists(p) {
				return Found, p
			}
		}
	}
	return NotFound, ""
}

// Check is the one entry the hook registrars and the doctor call: the
// Windows PATH directories of pathEnv as a process on goos sees them
// (WindowsDirs), resolved for shell with RunnerExts.
func Check(shell, goos, pathEnv string, exists func(string) bool) (Status, string) {
	return Resolve(Lookup{Shell: shell, Dirs: WindowsDirs(goos, pathEnv), Exists: exists})
}

// WindowsDirs returns the Windows PATH directories visible in pathEnv to a
// process running on goos:
//
//   - "windows": every ';'-separated entry, surrounding quotes trimmed;
//   - anything else (a WSL daemon): the ':'-separated entries under
//     /mnt/<drive>/, which WSL interop appends from the Windows PATH when
//     appendWindowsPath is on. None visible yields nil, which Resolve
//     reports as Unknown.
func WindowsDirs(goos, pathEnv string) []string {
	var out []string
	if goos == "windows" {
		for _, e := range strings.Split(pathEnv, ";") {
			e = strings.TrimSpace(strings.Trim(strings.TrimSpace(e), `"`))
			if e != "" {
				out = append(out, e)
			}
		}
		return out
	}
	for _, e := range strings.Split(pathEnv, ":") {
		if isWSLDriveDir(e) {
			out = append(out, e)
		}
	}
	return out
}

// WSLPathList turns a Windows `;`-separated PATH (C:\Program Files\Git\cmd;...)
// into the `:`-separated /mnt/<drive>/... form a WSL process addresses, for
// Check with goos "linux". Entries that are not drive-absolute (a relative
// dir, an unexpanded %VAR%, a UNC path) are dropped.
func WSLPathList(windowsPath string) string {
	var out []string
	for _, e := range strings.Split(windowsPath, ";") {
		e = strings.Trim(strings.TrimSpace(e), `"`)
		if len(e) < 3 || e[1] != ':' || (e[2] != '\\' && e[2] != '/') || strings.Contains(e, "%") {
			continue
		}
		c := e[0]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z') {
			continue
		}
		rest := strings.TrimRight(strings.ReplaceAll(e[3:], `\`, "/"), "/")
		d := "/mnt/" + strings.ToLower(string(c))
		if rest != "" {
			d += "/" + rest
		}
		out = append(out, d)
	}
	return strings.Join(out, ":")
}

// isWSLDriveDir reports whether p is a directory under a WSL drive mount
// (/mnt/<letter> or /mnt/<letter>/...).
func isWSLDriveDir(p string) bool {
	rest, ok := strings.CutPrefix(p, "/mnt/")
	if !ok || rest == "" {
		return false
	}
	c := rest[0]
	if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z') {
		return false
	}
	return len(rest) == 1 || rest[1] == '/'
}

// candidateNames is shell as is when it carries an extension, else shell
// with each extension appended (RunnerExts when exts is empty), lower-cased
// extension first.
func candidateNames(shell string, exts []string) []string {
	base := shell
	if i := strings.LastIndexAny(base, `\/`); i >= 0 {
		base = base[i+1:]
	}
	if strings.Contains(base, ".") {
		return []string{base}
	}
	if len(exts) == 0 {
		exts = RunnerExts
	}
	out := make([]string, 0, len(exts))
	seen := map[string]bool{}
	for _, e := range exts {
		e = strings.ToLower(strings.TrimSpace(e))
		if e == "" || seen[e] {
			continue
		}
		seen[e] = true
		if !strings.HasPrefix(e, ".") {
			e = "." + e
		}
		out = append(out, base+e)
	}
	return out
}

// joinDir joins dir and name with the separator dir itself uses: a
// backslash for a Windows-native path (C:\..., \\server\...), a slash
// otherwise (/mnt/c/...).
func joinDir(dir, name string) string {
	d := strings.TrimRight(dir, `\/`)
	if strings.Contains(dir, `\`) || (len(d) == 2 && d[1] == ':') {
		return d + `\` + name
	}
	return d + "/" + name
}
