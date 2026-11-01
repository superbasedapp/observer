//go:build !sbo_omit_terminals

package main

// terminal_osc52.go is the run-level rule for OSC 52 (WINFIX4 audit finding
// 2, ruling P-175): a sandboxed run's clipboard escape sequences are removed
// from what its terminal shows, on the dashboard terminal (termsession,
// Spec.StripOSC52) and the CLI host console (sandbox_cli_console_windows.go),
// unless the user's local [terminal.sandbox].allow_osc52_clipboard says
// otherwise. An unsandboxed run is never filtered.

// sandboxStripsOSC52 reports whether a run's output loses its OSC 52
// sequences.
func sandboxStripsOSC52(sandboxed, allowed bool) bool { return sandboxed && !allowed }

// sandboxOSC52Notice is the run's posture line when the opt-in lets the box
// write the clipboard through the terminal ("" otherwise, like pass_env's).
func sandboxOSC52Notice(sandboxed, allowed bool) string {
	if !sandboxed || !allowed {
		return ""
	}
	return "observer sandbox: [terminal.sandbox].allow_osc52_clipboard lets this box set and read your clipboard through the terminal (OSC 52)"
}

// sandboxCLIOSC52Label is the CLI posture line's part: "" by default,
// ", allow_osc52_clipboard" when the opt-in is on.
func sandboxCLIOSC52Label(allowed bool) string {
	if !allowed {
		return ""
	}
	return ", allow_osc52_clipboard"
}
