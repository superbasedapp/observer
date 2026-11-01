package main

import "testing"

// TestStartReRegistersCopilotCLIOnWindows pins the FU-166 repair path:
// `observer start` (autoRegisterHooks, also the update handshake's child and
// a managed node's heartbeat pass) writes the copilot-cli target on a
// Windows host, so a Windows-native Observer replaces its own stale
// bash-only Copilot CLI entry (internal/hook
// TestCopilotCLIRegisterRewritesTheStaleBashOnlyFile) the next time it runs.
func TestStartReRegistersCopilotCLIOnWindows(t *testing.T) {
	prev := autoRegisterHostGOOS
	autoRegisterHostGOOS = "windows"
	t.Cleanup(func() { autoRegisterHostGOOS = prev })
	if !autoRegisterDecision("copilot-cli", true) || !autoRegisterDecision("copilot-cli", false) {
		t.Fatal("observer start does not register copilot-cli on a Windows host, so a stale bash-only entry is never rewritten")
	}
}
