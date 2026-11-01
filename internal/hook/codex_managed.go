package hook

import (
	"fmt"
	"strings"
)

// Codex managed hooks (surface-gap review CX-2, operator decision D15,
// 2026-10-25). requirements.toml's allow_managed_hooks_only = true makes
// Codex skip every user, project, session and plugin hook, so the
// ~/.codex/hooks.json entries registerCodex writes stop firing. Codex
// still loads the managed hooks the same requirements layer declares
// ([hooks] managed_dir / windows_managed_dir plus [[hooks.<Event>]]
// groups), and treats them as trusted by policy: no /hooks trust step
// (vendor source codex-rs/hooks/src/engine/discovery.rs,
// append_managed_requirement_handlers; codex-rs/config/src/hook_config.rs
// ManagedHooksRequirementsToml).
//
// Codex installs nothing into the managed directory, so the admin deploys
// one small script there that runs the node's observer binary; the
// managed [[hooks.<Event>]] commands call it with the event name. This is
// the IBM Bob EnforcedHooks precedent (ibmbob_policy.go): this package owns
// the command text, so the managed script and the per-node writer run the
// same `<observer> hook codex <Event>` and cannot drift.

// CodexManagedHookScriptPOSIX and CodexManagedHookScriptWindows are the
// file names of Observer's managed hook script in the Codex managed
// directory (managed_dir on Linux and macOS, windows_managed_dir on
// Windows). A managed hook command naming one of them is Observer's.
const (
	CodexManagedHookScriptPOSIX   = "observer-codex-hook.sh"
	CodexManagedHookScriptWindows = "observer-codex-hook.cmd"
)

// CodexManagedHookScripts returns the bodies of Observer's managed hook
// scripts: the POSIX one runs binary, the Windows one binaryWindows. ""
// means a bare "observer" resolved on PATH (as IBMBobEnforcedHooks). The
// scripts pass the event argument and stdin through and keep the hook's
// exit code, which is how a PreToolUse deny reaches Codex. They carry no
// --config: a managed node's hook reads its default config.
func CodexManagedHookScripts(binary, binaryWindows string) (posix, windows string, err error) {
	binary = strings.TrimSpace(binary)
	if binary == "" {
		binary = "observer"
	}
	binaryWindows = strings.TrimSpace(binaryWindows)
	if binaryWindows == "" {
		binaryWindows = binary
	}
	if strings.ContainsAny(binary, "\r\n\x00") {
		return "", "", fmt.Errorf("hook.CodexManagedHookScripts: binary %q has a line break", binary)
	}
	// A batch file expands %...% and cannot carry a double quote inside a
	// quoted path: refuse both rather than write a script that runs
	// something else.
	if strings.ContainsAny(binaryWindows, "\r\n\x00\"%") {
		return "", "", fmt.Errorf("hook.CodexManagedHookScripts: Windows binary %q has a character a .cmd script cannot carry (%%, \", line break)", binaryWindows)
	}
	posix = "#!/bin/sh\n" +
		"# Observer's Codex managed hook (requirements.toml [hooks]). Deployed by the\n" +
		"# administrator into the Codex managed_dir; Codex runs it as\n" +
		"# `" + CodexManagedHookScriptPOSIX + " <Event>` with the hook payload on stdin.\n" +
		"exec " + shellQuoteIfNeeded(binary) + " hook codex \"$@\"\n"
	windows = "@echo off\r\n" +
		"rem Observer's Codex managed hook (requirements.toml [hooks]). Deployed by the\r\n" +
		"rem administrator into the Codex windows_managed_dir; Codex runs it as\r\n" +
		"rem " + CodexManagedHookScriptWindows + " ^<Event^> with the hook payload on stdin.\r\n" +
		cmdQuoteIfNeeded(binaryWindows) + " hook codex %*\r\n" +
		"exit /b %ERRORLEVEL%\r\n"
	return posix, windows, nil
}

// IsObserverCodexManagedHookCommand reports whether a Codex managed hook
// command (command or commandWindows) runs Observer: it names Observer's
// managed hook script, or it runs `hook codex` directly.
func IsObserverCodexManagedHookCommand(cmd string) bool {
	return strings.Contains(cmd, CodexManagedHookScriptPOSIX) ||
		strings.Contains(cmd, CodexManagedHookScriptWindows) ||
		isObserverCodexEntry(cmd)
}
