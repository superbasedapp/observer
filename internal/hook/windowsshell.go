package hook

import (
	"os"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/platform/winshell"
)

// windowsshell.go - a Windows hook runner that spawns its shell BY NAME
// (integration.HookSpec.WindowsHookShell; VT Code's `Command::new("sh")`)
// cannot run any hook when that shell is not on the Windows PATH, and the
// host then fails OPEN, so guard enforcement silently stops. Registration
// and `observer doctor` WARN about it, never block: the PATH examined is the
// persistent Windows PATH when it can be read (Options.WindowsPATH), else
// this process's view, while the host inherits the PATH of whatever launched
// it (a Git Bash terminal adds Git\bin itself), so a NotFound is a strong
// hint, not proof. Unknown (no Windows PATH entry visible at all, e.g. a WSL
// daemon with interop appendWindowsPath=false) never warns.
//
// Everything here dispatches on the capability row, never on a tool name.

// windowsShellTarget reports whether target is a Windows-side registration
// of a tool whose Windows hook runner needs a shell on PATH, and the GOOS
// whose PATH view applies: a "-windows" cross-OS bridge is written by a WSL
// daemon (the Windows PATH as WSL interop appends it), a native target on a
// Windows observer reads its own process PATH.
func (r *Registry) windowsShellTarget(target string) (req integration.HookShellRequirement, pathGOOS string, ok bool) {
	req, ok = integration.WindowsHookShellFor(target)
	if !ok {
		return req, "", false
	}
	switch {
	case strings.HasSuffix(target, "-windows"):
		return req, "linux", true
	case r.hostGOOS() == "windows":
		return req, "windows", true
	}
	return req, "", false
}

// windowsShellStatus resolves req's shell on the persistent Windows PATH
// (Options.WindowsPATH) when it can be read, else on the PATH visible to this
// process (Options.Getenv; nil means no environment, so Unknown). The
// persistent PATH comes first because the process view is whatever launched
// this observer: a WSL session started from Git Bash inherits Git's own bin
// dirs and would report sh found when a VT Code started from Windows
// Terminal cannot spawn it (seen 2026-10-24).
func (r *Registry) windowsShellStatus(req integration.HookShellRequirement, pathGOOS string) (winshell.Status, string) {
	pathEnv := ""
	persistent := false
	if r.opts.WindowsPATH != nil {
		if p, ok := r.opts.WindowsPATH(); ok {
			pathEnv, persistent = p, true
		}
	}
	if !persistent && r.opts.Getenv != nil {
		pathEnv = r.opts.Getenv("PATH")
	}
	exists := r.opts.fileExists
	if exists == nil {
		exists = regularFileExists
	}
	return winshell.Check(req.Shell, pathGOOS, pathEnv, exists)
}

// regularFileExists is the production file probe.
func regularFileExists(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && !fi.IsDir()
}

// withWindowsShellWarning appends the Windows hook-shell warning to a
// successful registration of a Windows-side target whose hooks are (or, on a
// dry run, would be) in place while the runner's shell does not resolve on
// the Windows PATH. It never changes anything else on res.
func (r *Registry) withWindowsShellWarning(target string, res RegistrationResult) RegistrationResult {
	if res.Error != nil || res.Skipped || len(res.HooksAdded)+len(res.AlreadySet) == 0 {
		return res
	}
	req, pathGOOS, ok := r.windowsShellTarget(target)
	if !ok {
		return res
	}
	if st, _ := r.windowsShellStatus(req, pathGOOS); st == winshell.NotFound {
		res.Warnings = append(res.Warnings, integration.WindowsHookShellWarning(target))
	}
	return res
}

// WindowsShellReport is one Windows-side hook target whose host runner needs
// a shell on PATH, as `observer doctor` reports it.
type WindowsShellReport struct {
	// Target is the registration target ("vtcode-windows" from WSL,
	// "vtcode" on a Windows observer).
	Target string
	// ConfigPath is the target's hook config file ("" when unresolved).
	ConfigPath string
	// Registered is true when Observer's hooks are in that file: a dry-run
	// registration finds its entries already set, or hook_checksums.json
	// records a successful Observer install of the file (an entry naming an
	// older binary or --config still counts).
	Registered bool
	// Shell is the executable the runner spawns by name.
	Shell string
	// Status is the PATH lookup's answer; ShellPath the match when Found.
	Status    winshell.Status
	ShellPath string
	// Warning is the operator sentence for a NotFound (always set, so a
	// caller renders the same text registration does).
	Warning string
}

// WindowsHookShellReports lists every Windows-side hook target this registry
// can address whose host runner needs a shell on PATH: on a Windows observer
// the native target, elsewhere the "-windows" cross-OS bridge of a row that
// declares one. Read-only: registration status comes from a dry run (Probe)
// and hook_checksums.json, the shell from the injected PATH and file probe.
func (r *Registry) WindowsHookShellReports() []WindowsShellReport {
	var out []WindowsShellReport
	for _, tool := range integration.WindowsHookShellTools() {
		target := tool
		if r.hostGOOS() != "windows" {
			c, _ := integration.For(tool)
			target = tool + "-windows"
			if _, known := hookTargetWriters[target]; !known || !c.Hook.CrossOSBridge {
				continue
			}
		}
		req, pathGOOS, ok := r.windowsShellTarget(target)
		if !ok {
			continue
		}
		rep := WindowsShellReport{Target: target, Shell: req.Shell, Warning: integration.WindowsHookShellWarning(target)}
		res := r.Probe(target)
		rep.ConfigPath = res.ConfigPath
		if res.Error == nil && !res.Skipped {
			rep.Registered = len(res.AlreadySet) > 0 ||
				(res.ConfigPath != "" && regularFileExists(res.ConfigPath) && r.observerInstalled(res.ConfigPath))
		}
		rep.Status, rep.ShellPath = r.windowsShellStatus(req, pathGOOS)
		out = append(out, rep)
	}
	return out
}
