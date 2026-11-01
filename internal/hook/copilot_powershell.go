package hook

import "path/filepath"

// copilot_powershell.go - FU-166 (Windows rig run 2026-10-29, round 4): an
// older Observer build wrote ~/.copilot/hooks/superbased-observer.json with
// only a "bash" command. Copilot CLI on Windows runs only a handler's
// "powershell" field (copilot 1.0.80 bundle: hookSelectShellScript(bash,
// powershell, platform === "win32")), so that file's hook exits 127 and
// Copilot fails it closed: every Copilot CLI tool call on the node is
// blocked. The current writer adds the powershell field for a Windows-native
// Observer (copilotCLIHooksTarget), and a registration replaces Observer's
// own entry whenever it differs from the one this binary writes, so the next
// `observer start` (or `observer init`) rewrites the stale entry. This is
// the read-only check the doctor reports from, so a node that has not
// re-registered yet says so instead of failing every tool call silently.

// CopilotCLIPowerShellReport is what Observer's own Copilot CLI hooks file
// says about the field Copilot CLI runs on Windows.
type CopilotCLIPowerShellReport struct {
	// Applies is true on a Windows-native Observer only: a Linux or macOS
	// Copilot CLI runs the "bash" field, so there is nothing to check.
	Applies bool
	// Unreadable is true when the hooks file exists but could not be read
	// or decoded; nothing else is then known.
	Unreadable bool
	// Target is the registration target that owns the file: "copilot-cli"
	// (a Windows-native Observer) or "copilot-cli-windows" (the bridge a
	// WSL Observer writes into the Windows home).
	Target string
	// ConfigPath is the hooks file that registration owns.
	ConfigPath string
	// Registered are the events holding an entry that is positively
	// Observer's (its "bash" command names `observer hook copilot-cli`), in
	// the registration's event order.
	Registered []string
	// Stale are the Registered events whose Observer entry carries no
	// "powershell" command running Observer's hook, so Copilot CLI on
	// Windows cannot run it.
	Stale []string
}

// CopilotCLIPowerShell checks Observer's own Copilot CLI hooks file (the
// copilot-cli target, so a COPILOT_HOME relocation is the writer's) on a
// Windows-native Observer. It only reads (regularfile, capped), and only
// Observer's own entries count: a foreign entry in the file is never
// reported. A missing file reads as nothing registered.
func (r *Registry) CopilotCLIPowerShell() CopilotCLIPowerShellReport {
	if r.hostGOOS() != "windows" {
		return CopilotCLIPowerShellReport{}
	}
	return copilotPowerShellReport("copilot-cli", r.copilotCLIHooksTarget())
}

// CopilotCLIWindowsPowerShell is CopilotCLIPowerShell for the
// copilot-cli-windows bridge (FU-166 tail): a WSL (or other non-Windows)
// Observer that wrote the Windows-side ~/.copilot/hooks file. An older build
// wrote that bridge with bash only too, and the Windows Copilot CLI runs only
// the powershell field, so the same check applies there. The target resolves
// read-only through the bridge's own detection (detectWindowsCopilotHome:
// the operator's WindowsCopilotHome, else the one Windows home proven the
// current user's that carries .copilot; a pinned home suppresses it), and
// Applies is false when no such home resolves. Ownership is read from each
// entry's bash command, so the distro does not have to match.
func (r *Registry) CopilotCLIWindowsPowerShell() CopilotCLIPowerShellReport {
	if r.hostGOOS() == "windows" {
		return CopilotCLIPowerShellReport{}
	}
	dir := r.detectWindowsCopilotHome()
	if dir == "" {
		return CopilotCLIPowerShellReport{}
	}
	return copilotPowerShellReport("copilot-cli-windows", r.copilotCLIWindowsHooksTarget(dir, r.opts.WSLDistro))
}

// copilotPowerShellReport reads target t's hooks file for Observer's entries
// and the ones whose powershell command does not run Observer's hook.
func copilotPowerShellReport(target string, t jsonHooksTarget) CopilotCLIPowerShellReport {
	rep := CopilotCLIPowerShellReport{Applies: true, Target: target}
	if t.dirErr == nil {
		rep.ConfigPath = filepath.Join(t.dir, t.file)
	}
	owned, ok := jsonHooksObserverEvents(t, "")
	if !ok {
		rep.Unreadable = true
		return rep
	}
	runs, ok := jsonHooksObserverEvents(t, "powershell")
	if !ok {
		rep.Unreadable = true
		return rep
	}
	for _, ev := range t.events {
		if !owned[ev] {
			continue
		}
		rep.Registered = append(rep.Registered, ev)
		if !runs[ev] {
			rep.Stale = append(rep.Stale, ev)
		}
	}
	return rep
}
