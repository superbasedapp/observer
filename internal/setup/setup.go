package setup

import (
	"fmt"
	"path"
	"sort"
	"strings"
)

// DownloadURL is the page a downloaded install upgrades from: run the newer
// setup program (or archive) from there. One constant so the dashboard
// advice, the install-method row and every printed hint agree.
const DownloadURL = "https://superbased.app/download"

// RunValueName is the value `observer setup autostart on` writes under the
// user's HKCU\Software\Microsoft\Windows\CurrentVersion\Run key.
const RunValueName = "SuperBasedObserver"

// RunKeyPath is the per-user Run key (no elevation needed). A scheduled
// task with an ONLOGON trigger would need elevation, see
// cmd/observer/process_bridge_task.go.
const RunKeyPath = `Software\Microsoft\Windows\CurrentVersion\Run`

// WindowlessName is the file name of the no-console launcher shipped beside
// observer.exe by the Windows setup program (cmd/observerw). A console
// program named in the Run key would open a visible console window at every
// sign-in; observerw starts observer.exe with no window instead.
const WindowlessName = "observerw.exe"

// LaunchArgs are the arguments the Run value and the Start menu shortcut
// pass through observerw to observer.exe. The shortcut adds "--open".
var LaunchArgs = []string{"setup", "launch"}

// RunValue renders the Run key value for a windowless launcher path: the
// quoted launcher followed by LaunchArgs.
func RunValue(observerwPath string) string {
	return `"` + observerwPath + `" ` + strings.Join(LaunchArgs, " ")
}

// ---------------------------------------------------------------- Path list

// pathKey normalises one Path entry for comparison: Windows Path entries
// compare case-insensitively and ignore a trailing backslash or slash.
func pathKey(entry string) string {
	e := strings.TrimSpace(entry)
	e = strings.TrimRight(e, `\/`)
	return strings.ToLower(e)
}

// splitList splits a ';'-separated Windows Path value. Empty entries are
// kept so an Add leaves an unrelated value byte-identical apart from the
// appended directory.
func splitList(value string) []string {
	if value == "" {
		return nil
	}
	return strings.Split(value, ";")
}

// HasPathEntry reports whether dir is already one of value's entries.
func HasPathEntry(value, dir string) bool {
	want := pathKey(dir)
	if want == "" {
		return false
	}
	for _, e := range splitList(value) {
		if pathKey(e) == want {
			return true
		}
	}
	return false
}

// AddPathEntry appends dir to the END of a user Path value, the same place
// scripts/install.ps1 puts it, so an existing copy earlier on the Path keeps
// winning (and the coexistence check says so). It reports false, and the
// value unchanged, when dir is already there.
func AddPathEntry(value, dir string) (string, bool) {
	if strings.TrimSpace(dir) == "" || HasPathEntry(value, dir) {
		return value, false
	}
	trimmed := strings.TrimRight(value, ";")
	if trimmed == "" {
		return dir, true
	}
	return trimmed + ";" + dir, true
}

// RemovePathEntry drops every entry equal to dir (case-insensitive, trailing
// separator ignored) and nothing else: the rest of the user's Path, empty
// entries included, comes back byte-identical, so an install followed by an
// uninstall leaves the Path exactly as it was. It reports false, and the
// value unchanged, when dir was not there.
func RemovePathEntry(value, dir string) (string, bool) {
	if !HasPathEntry(value, dir) {
		return value, false
	}
	want := pathKey(dir)
	kept := make([]string, 0, 8)
	for _, e := range splitList(value) {
		if pathKey(e) == want && strings.TrimSpace(e) != "" {
			continue
		}
		kept = append(kept, e)
	}
	return strings.Join(kept, ";"), true
}

// ------------------------------------------------------- another install

// DaemonInfo is a running `observer start`, from the start lock beside the
// database (diag.LiveLocks): its pid and the binary it runs.
type DaemonInfo struct {
	PID        int
	BinaryPath string
}

// Other is one observer found outside the install directory.
type Other struct {
	// Path is the executable (or npm .cmd shim) found on the Path.
	Path string
	// Kind names the install channel in plain words ("npm install").
	Kind string
	// Upgrade is the channel's own upgrade command, "" when it has none.
	Upgrade string
}

// PreflightInput is everything the coexistence check needs, gathered by the
// cmd layer.
type PreflightInput struct {
	// InstallDir is the directory this install writes observer.exe into.
	InstallDir string
	// OnPath lists every observer executable found on the Path, first
	// match per directory, in Path order.
	OnPath []string
	// Daemon is the live daemon from the start lock, nil when none runs.
	Daemon *DaemonInfo
	// GOOS decides path comparison (case-insensitive on windows/darwin).
	GOOS string
	// SiblingExists answers "does <dir>/<name> exist" for the channel
	// markers (an npm shim's node_modules, a venv's pyvenv.cfg). Nil is
	// "no" for every question.
	SiblingExists func(dir, name string) bool
}

// PreflightResult is the verdict.
type PreflightResult struct {
	// Others are observers on the Path that this install would not replace.
	Others []Other
	// ForeignDaemon is a running daemon whose binary is outside InstallDir.
	ForeignDaemon *DaemonInfo
	// OwnDaemon is a running daemon from this install (an upgrade: its
	// binary is renamed aside, never stopped).
	OwnDaemon *DaemonInfo
}

// Blocked reports whether a second copy would be installed: another install
// on the Path, or a daemon running from somewhere else.
func (r PreflightResult) Blocked() bool {
	return len(r.Others) > 0 || r.ForeignDaemon != nil
}

// sameDir compares two directories the way the OS does.
func sameDir(a, b, goos string) bool {
	ca := strings.TrimRight(toSlash(a), "/")
	cb := strings.TrimRight(toSlash(b), "/")
	if goos == "windows" || goos == "darwin" {
		return strings.EqualFold(ca, cb)
	}
	return ca == cb
}

func toSlash(p string) string { return strings.ReplaceAll(p, `\`, "/") }

// Preflight decides whether installing into InstallDir would put a second
// copy on this computer. Two copies fight over the registered hooks and the
// :8820 proxy port, so the setup program refuses unless forced, exactly like
// scripts/install.ps1.
func Preflight(in PreflightInput) PreflightResult {
	var res PreflightResult
	seen := map[string]bool{}
	for _, p := range in.OnPath {
		if strings.TrimSpace(p) == "" || sameDir(path.Dir(toSlash(p)), in.InstallDir, in.GOOS) {
			continue
		}
		key := strings.ToLower(toSlash(p))
		if seen[key] {
			continue
		}
		seen[key] = true
		res.Others = append(res.Others, Classify(p, in.SiblingExists))
	}
	if in.Daemon != nil && strings.TrimSpace(in.Daemon.BinaryPath) != "" {
		d := *in.Daemon
		if sameDir(path.Dir(toSlash(d.BinaryPath)), in.InstallDir, in.GOOS) {
			res.OwnDaemon = &d
		} else {
			res.ForeignDaemon = &d
		}
	}
	return res
}

// npmShimMarker is the directory npm's global .cmd shims sit beside on
// Windows (%APPDATA%\npm\observer.cmd next to node_modules\@superbased\observer).
const npmShimMarker = "node_modules/@superbased/observer"

// InstallerMarker is the uninstaller the Windows setup program writes one
// level above bin\observer.exe. It must equal update.InstallerUninstallerName
// (pinned by setup_test.go); it is repeated rather than imported because
// internal/update belongs to the omittable org.update component and this
// package is core.
const InstallerMarker = "superbased-uninstall.exe"

// channelRules names the channel an observer on the Path came from, first
// match wins. It reads path shape and marker files only, like
// scripts/install.ps1's Get-InstallKind; `lower` is the slash-normalised,
// lowercased path and `dir` its directory as found.
var channelRules = []struct {
	kind    string
	upgrade string
	match   func(lower, dir string, sibling func(dir, name string) bool) bool
}{
	{"npm install", "npm i -g @superbased/observer@latest", func(lower, dir string, sib func(string, string) bool) bool {
		return strings.Contains(lower, "node_modules/@superbased/observer") || strings.Contains(lower, "/node_modules/.bin/") || sib(dir, npmShimMarker)
	}},
	{"VS Code extension copy", "update the SuperBased Observer extension in VS Code", func(lower, _ string, _ func(string, string) bool) bool {
		return strings.Contains(lower, "superbased.superbased-observer") || strings.Contains(lower, "globalstorage/superbased")
	}},
	{"pipx install", "pipx upgrade superbased-observer", func(lower, _ string, _ func(string, string) bool) bool {
		return strings.Contains(lower, "/pipx/")
	}},
	{"pip install", "pip install -U superbased-observer", func(lower, dir string, sib func(string, string) bool) bool {
		base := path.Base(strings.ToLower(dir))
		venv := (base == "bin" || base == "scripts") && (sib(path.Dir(dir), "pyvenv.cfg") || sib(dir, "activate"))
		return strings.Contains(lower, "/site-packages/") || strings.Contains(lower, "/dist-packages/") || venv
	}},
	{"Homebrew install", "brew upgrade superbased-observer", func(lower, _ string, _ func(string, string) bool) bool {
		return strings.Contains(lower, "/cellar/") || strings.Contains(lower, "/opt/homebrew/") || strings.Contains(lower, "/home/linuxbrew/")
	}},
	{"installed copy", "run the newer installer from " + DownloadURL, func(_, dir string, sib func(string, string) bool) bool {
		return sib(path.Dir(dir), InstallerMarker)
	}},
}

// Classify names the channel an observer found on the Path came from and the
// channel's own upgrade command ("" for a plain downloaded copy).
func Classify(exe string, sibling func(dir, name string) bool) Other {
	if sibling == nil {
		sibling = func(string, string) bool { return false }
	}
	dir := path.Dir(toSlash(exe))
	lower := strings.ToLower(toSlash(exe))
	for _, r := range channelRules {
		if r.match(lower, dir, sibling) {
			return Other{Path: exe, Kind: r.kind, Upgrade: r.upgrade}
		}
	}
	return Other{Path: exe, Kind: "downloaded copy"}
}

// PreflightReport renders a blocked verdict in plain words for the setup
// program's message box and the terminal.
func PreflightReport(r PreflightResult, forceHint string) string {
	if !r.Blocked() {
		return ""
	}
	var b strings.Builder
	b.WriteString("SuperBased Observer is already installed on this computer:\n")
	for _, o := range r.Others {
		fmt.Fprintf(&b, "  %s: %s\n", o.Kind, o.Path)
		if o.Upgrade != "" {
			fmt.Fprintf(&b, "      upgrade it with: %s\n", o.Upgrade)
		}
	}
	if d := r.ForeignDaemon; d != nil {
		fmt.Fprintf(&b, "  running daemon: pid %d (%s)\n", d.PID, d.BinaryPath)
	}
	b.WriteString("\nUse one install per computer: two copies fight over the hooks your AI tools call and the proxy port.\n")
	b.WriteString("Upgrade the existing one with its own command, or uninstall it first.\n")
	if forceHint != "" {
		b.WriteString(forceHint + "\n")
	}
	return b.String()
}

// ------------------------------------------------------------- uninstall

// StaleAsideNames filters a directory listing down to the binaries an
// earlier upgrade renamed aside (<name>.exe.old-<stamp>, or <name>.old-<stamp>
// on other platforms), sorted, for removal once nothing runs them.
func StaleAsideNames(names []string) []string {
	var out []string
	for _, n := range names {
		if strings.Contains(n, ".old-") {
			out = append(out, n)
		}
	}
	sort.Strings(out)
	return out
}

// AsideName is the name a running binary is renamed to before the new one
// takes its place (Windows refuses to overwrite a running .exe but allows a
// rename). stamp is a caller-supplied timestamp, so this stays pure.
func AsideName(name, stamp string) string {
	return name + ".old-" + stamp
}
