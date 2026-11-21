//go:build !sbo_omit_org_update

package dashboard

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/update"
)

// updateTerminalRule is one row of the "Update in a terminal" plan table,
// walked top-down: the first row whose match holds decides. A row with no
// argv refuses with its reason.
type updateTerminalRule struct {
	name   string
	match  func(d update.Detection, lowerExec, goos string) bool
	argv   []string
	reason func(d update.Detection) string
}

// updateTerminalRules is the table (CLAUDE.md #5). The install method comes
// from internal/update.Detect, the one owner of that verdict; this table only
// maps a method to the fixed argv that updates it.
//
// Windows comes first: the daemon IS the running observer.exe, which Windows
// keeps locked, so neither npm nor pipx can replace it while the daemon runs.
// Plain pip is not offered: `pip install -U` against whichever pip is first
// on PATH may not be the interpreter this copy lives in, so the card shows
// the command to run in the right environment instead.
var updateTerminalRules = []updateTerminalRule{
	{
		name:  "windows-locked",
		match: func(_ update.Detection, _ string, goos string) bool { return goos == "windows" },
		reason: func(d update.Detection) string {
			return "Windows keeps the running observer.exe locked, so it cannot be replaced while the daemon runs. Stop the daemon, then update" + updateAdviceSuffix(d)
		},
	},
	{
		name:  "npm",
		match: func(d update.Detection, _, _ string) bool { return d.Method == update.MethodNPM },
		argv:  []string{"npm", "i", "-g", "@superbased/observer@latest"},
	},
	{
		name: "pipx",
		match: func(d update.Detection, lowerExec, _ string) bool {
			return d.Method == update.MethodPip && strings.Contains(lowerExec, "/pipx/venvs/")
		},
		argv: []string{"pipx", "upgrade", "superbased-observer"},
	},
	{
		name:  "other",
		match: func(update.Detection, string, string) bool { return true },
		reason: func(d update.Detection) string {
			return "This copy was not installed with npm or pipx, so there is no one command to run here. Update it" + updateAdviceSuffix(d)
		},
	},
}

// updateAdviceSuffix is the install method's own advice, or the download page.
func updateAdviceSuffix(d update.Detection) string {
	if a := strings.TrimSpace(update.AdviceFor(d, "")); a != "" {
		return " with: " + strings.ReplaceAll(a, "@<version>", "@latest") + "."
	}
	return " from https://superbased.app/download."
}

// updateTerminalPlanFor walks the table for one detection. Pure.
func updateTerminalPlanFor(d update.Detection, execPath, goos string) updateTerminalPlan {
	lower := strings.ToLower(filepath.ToSlash(execPath))
	for _, r := range updateTerminalRules {
		if !r.match(d, lower, goos) {
			continue
		}
		p := updateTerminalPlan{Method: string(d.Method)}
		if len(r.argv) == 0 {
			p.Reason = r.reason(d)
			return p
		}
		p.Available = true
		p.argv = append([]string(nil), r.argv...)
		p.Command = strings.Join(p.argv, " ")
		return p
	}
	return updateTerminalPlan{Method: string(d.Method), Reason: "no update command for this install"}
}

// detectRunningInstall is the I/O half: the running executable (symlinks
// resolved) and its install-method verdict.
func detectRunningInstall() (update.Detection, string) {
	exe, err := os.Executable()
	if err != nil {
		return update.Detect(update.PathProbe{GOOS: runtime.GOOS}), ""
	}
	if resolved, rerr := filepath.EvalSymlinks(exe); rerr == nil {
		exe = resolved
	}
	return update.Detect(update.PathProbe{
		ExecPath: exe,
		GOOS:     runtime.GOOS,
		SiblingExists: func(dir, name string) bool {
			_, serr := os.Stat(filepath.Join(filepath.FromSlash(dir), name)) //nolint:gosec // G703: an existence check beside the running executable
			return serr == nil
		},
	}), exe
}

// runningUpdatePlan is the plan for this daemon's own executable. A var so
// the handler tests can stand in a plan without touching the filesystem.
var runningUpdatePlan = func() updateTerminalPlan {
	det, exe := detectRunningInstall()
	return updateTerminalPlanFor(det, exe, runtime.GOOS)
}
