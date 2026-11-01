package main

import "testing"

// TestCanonicalHookEvent (gfiD, 2026-10-15): Kiro CLI's V3 standalone hooks
// file invokes Observer with the PascalCase trigger; the receiver folds it
// onto the binding's camelCase native event, and leaves every other event
// (and every other mechanism) alone.
func TestCanonicalHookEvent(t *testing.T) {
	for _, tc := range []struct{ tool, in, want string }{
		{"kiro-cli", "preToolUse", "preToolUse"},
		{"kiro-cli", "PreToolUse", "preToolUse"},
		{"kiro-cli", "UserPromptSubmit", "userPromptSubmit"},
		{"kiro-cli", "Nonsense", "Nonsense"},
		{"claude-code", "pre-tool", "pre-tool"},
		{"codex", "PreToolUse", "PreToolUse"},
		{"no-such-tool", "PreToolUse", "PreToolUse"},
	} {
		if got := canonicalHookEvent(tc.tool, tc.in); got != tc.want {
			t.Errorf("canonicalHookEvent(%q, %q) = %q, want %q", tc.tool, tc.in, got, tc.want)
		}
	}
	// The folded event resolves to the wired tool gate the agent JSON uses.
	b, ok := standaloneToolGate("kiro-cli", canonicalHookEvent("kiro-cli", "PreToolUse"))
	if !ok || b.NativeEvent != "preToolUse" {
		t.Errorf("kiro-cli PreToolUse: standaloneToolGate = (%+v, %v)", b, ok)
	}
}
