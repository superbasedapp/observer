package main

import "testing"

// TestClineGateServedUnderClineCLI pins T-342 and guard-fix lane B: the
// Cline CLI gate belongs to the cline-cli row (the CLI reads ~/.cline, live
// 2026-10-04) and is now the plugin's beforeTool, a per-call gate (the
// ~/.cline/hooks file gate it replaces stopped the whole run), so `observer
// hook cline-cli beforeTool` is a served tool gate whose verdicts
// runToolGate records under cline-cli, and the VS Code extension row does
// not claim it.
func TestClineGateServedUnderClineCLI(t *testing.T) {
	b, ok := standaloneToolGate("cline-cli", "beforeTool")
	if !ok || !b.Registered {
		t.Fatalf("cline-cli beforeTool: served=%v registered=%v, want a registered tool gate on the binding route", ok, b.Registered)
	}
	if _, ok := standaloneToolGate("cline", "PreToolUse"); ok {
		t.Error("cline PreToolUse is still served as a tool gate: the extension row must keep the vendor surface only")
	}
	if !hookSupported("cline-cli") {
		t.Error("cline-cli: hookSupported = false, want the ~/.cline/hooks writer")
	}
	if hookSupported("cline") {
		t.Error("cline: hookSupported = true, want no hook writer on the extension row")
	}
}
