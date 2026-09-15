package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/integration"
)

// TestAutoRegisterRemediation pins the per-tool remediation hint
// autoRegisterHooks attaches to a failure WARN (F3,
// docs/audits/cursor-windows-capture-diagnosis-2026-08-07.md §4).
// Table-driven over hook.Registry's Installed()/Register()
// vocabulary; an unrecognised tool still gets a usable generic hint
// rather than a malformed command string.
func TestAutoRegisterRemediation(t *testing.T) {
	t.Parallel()
	cases := []struct {
		tool     string
		wantFlag string // "" means no --tool flag expected in the hint
	}{
		{"claude-code", "--claude-code"},
		{"claude-code-windows", "--claude-code"},
		{"cursor", "--cursor"},
		{"cursor-windows", "--cursor"},
		{"codex", "--codex"},
		{"some-future-tool", ""},
	}
	for _, c := range cases {
		t.Run(c.tool, func(t *testing.T) {
			t.Parallel()
			got := autoRegisterRemediation(c.tool)
			if !strings.Contains(got, "observer init") {
				t.Errorf("autoRegisterRemediation(%q) = %q, want it to mention `observer init`", c.tool, got)
			}
			if !strings.Contains(got, "--force") {
				t.Errorf("autoRegisterRemediation(%q) = %q, want it to mention --force", c.tool, got)
			}
			if c.wantFlag != "" && !strings.Contains(got, c.wantFlag) {
				t.Errorf("autoRegisterRemediation(%q) = %q, want it to mention %q", c.tool, got, c.wantFlag)
			}
			if strings.Contains(got, "  ") {
				t.Errorf("autoRegisterRemediation(%q) = %q, want no double-space artifact from an empty flag", c.tool, got)
			}
		})
	}
}

// TestAutoRegisterHooks_PromptLaneOnlyGate pins B4 (phase-3a review):
// a PromptLaneOnly mechanism (Gemini CLI's HookGeminiSettings today)
// must not be written at all when [guard.prompt].enabled/hook_lane
// resolves to false — writing a hook whose only reason to exist is
// prompt-submit evaluation that will never run is dead weight the
// operator never consented to. A mechanism that carries OTHER value
// (Claude Code's session/tool-call events, PromptLaneOnly=false) must
// still register regardless of this gate.
func TestAutoRegisterHooks_PromptLaneOnlyGate(t *testing.T) {
	setupHome := func(t *testing.T) string {
		t.Helper()
		home := t.TempDir()
		for _, dir := range []string{".claude", ".gemini"} {
			if err := os.MkdirAll(filepath.Join(home, dir), 0o755); err != nil {
				t.Fatal(err)
			}
		}
		t.Setenv("HOME", home)
		t.Setenv("USERPROFILE", home) // os.UserHomeDir reads USERPROFILE on Windows
		return home
	}

	t.Run("promptLaneEnabled=false: PromptLaneOnly (gemini-cli) skipped, claude-code still registered", func(t *testing.T) {
		home := setupHome(t)
		var stdout, stderr bytes.Buffer
		autoRegisterHooks(&stdout, &stderr, "", false)
		out := stdout.String()
		if strings.Contains(out, "gemini-cli") {
			t.Errorf("stdout = %q, must not mention gemini-cli when promptLaneEnabled=false", out)
		}
		if !strings.Contains(out, "claude-code") {
			t.Errorf("stdout = %q, want claude-code to still be auto-registered (PromptLaneOnly=false)", out)
		}
		if _, err := os.Stat(filepath.Join(home, ".gemini", "settings.json")); err == nil {
			t.Errorf("~/.gemini/settings.json was written even though promptLaneEnabled=false")
		}
		if _, err := os.Stat(filepath.Join(home, ".claude", "settings.json")); err != nil {
			t.Errorf("~/.claude/settings.json was NOT written: %v", err)
		}
	})

	t.Run("promptLaneEnabled=true: both register", func(t *testing.T) {
		setupHome(t)
		var stdout, stderr bytes.Buffer
		autoRegisterHooks(&stdout, &stderr, "", true)
		out := stdout.String()
		if !strings.Contains(out, "gemini-cli") {
			t.Errorf("stdout = %q, want gemini-cli auto-registered when promptLaneEnabled=true", out)
		}
		if !strings.Contains(out, "claude-code") {
			t.Errorf("stdout = %q, want claude-code auto-registered", out)
		}
	})
}

// TestAutoRegisterRemediation_LongTailVendorsNameNoDedicatedFlag pins
// B2/B2-remediation (phase-3a review): the Part B item 1/2 long-tail
// vendors have NO dedicated `observer init --<tool>` flag at all — they
// are only reachable via --all or the zero-selector auto-detect
// default (resolveTools). Naming a flag that doesn't exist would be a
// broken remediation hint, so these get an explicit, honest message
// rather than silently falling to the same-looking generic text a
// TRULY unknown tool gets.
func TestAutoRegisterRemediation_LongTailVendorsNameNoDedicatedFlag(t *testing.T) {
	t.Parallel()
	for _, tool := range []string{"gemini-cli", "qwen-code", "droid", "qoder", "poolside", "devin", "command-code"} {
		t.Run(tool, func(t *testing.T) {
			t.Parallel()
			got := autoRegisterRemediation(tool)
			if !strings.Contains(got, "no dedicated --"+tool+" flag") {
				t.Errorf("autoRegisterRemediation(%q) = %q, want it to say it has no dedicated flag", tool, got)
			}
			if !strings.Contains(got, "--all") {
				t.Errorf("autoRegisterRemediation(%q) = %q, want it to mention --all", tool, got)
			}
			if !strings.Contains(got, "observer init --force") {
				t.Errorf("autoRegisterRemediation(%q) = %q, want it to still say `observer init --force`", tool, got)
			}
		})
	}
}

// TestAutoRegisterHooks_PromptLaneOnlyGateAppliesToWindowsBridgeTargets pins
// B3 (final-fix review): the PromptLaneOnly gate inside autoRegisterHooks
// (cmd/observer/start.go) resolves via advertisedCapability, not a bare
// integration.For(tool) lookup. reg.Installed() surfaces a Windows-bridge
// install as "<tool>-windows" (e.g. "gemini-cli-windows") — a string that is
// NOT itself a registry key (integration.For only knows the base "gemini-cli"
// id), so the pre-fix `if c, ok := integration.For(tool); ok && …` always
// missed (ok=false) for every one of the six PromptLaneOnly Windows-bridge
// targets, which silently short-circuited the whole gate to false and let
// autoRegisterHooks write those six vendor configs even when the operator
// had the prompt-submit hook lane disabled.
func TestAutoRegisterHooks_PromptLaneOnlyGateAppliesToWindowsBridgeTargets(t *testing.T) {
	t.Parallel()
	windowsTargets := []string{
		"gemini-cli-windows", "qwen-code-windows", "droid-windows",
		"qoder-windows", "poolside-windows", "command-code-windows",
	}
	for _, tool := range windowsTargets {
		t.Run(tool, func(t *testing.T) {
			t.Parallel()
			// Document the trap this fix closes: the bare registry
			// lookup autoRegisterHooks used to use never resolves a
			// "-windows" suffixed id — it is not a registry key.
			if _, ok := integration.For(tool); ok {
				t.Fatalf("integration.For(%q) ok = true — this tool now IS a bare registry key; the whole premise of the advertisedCapability fix (and this test) is stale, re-check the gate", tool)
			}
			// The FIX: advertisedCapability strips the suffix and
			// resolves the base row, so the gate this feeds
			// (autoRegisterHooks / wireAIClients) can actually see
			// PromptLaneOnly for a Windows-bridge target.
			c, isWindows, ok := advertisedCapability(tool)
			if !ok {
				t.Fatalf("advertisedCapability(%q) ok = false, want true", tool)
			}
			if !isWindows {
				t.Errorf("advertisedCapability(%q) isWindows = false, want true", tool)
			}
			if !c.Hook.PromptLaneOnly {
				t.Errorf("advertisedCapability(%q).Hook.PromptLaneOnly = false, want true — the base row must be PromptLaneOnly for this regression to be meaningful", tool)
			}
		})
	}

	// The three cross-OS bridges that carry OTHER value beyond the
	// prompt-submit event (session/tool-call capture) must NOT be
	// PromptLaneOnly — a disabled prompt lane must never suppress their
	// registration.
	for _, tool := range []string{"claude-code-windows", "cursor-windows", "codex-windows"} {
		t.Run(tool+"_not_prompt_lane_only", func(t *testing.T) {
			t.Parallel()
			c, _, ok := advertisedCapability(tool)
			if !ok {
				t.Fatalf("advertisedCapability(%q) ok = false, want true", tool)
			}
			if c.Hook.PromptLaneOnly {
				t.Errorf("advertisedCapability(%q).Hook.PromptLaneOnly = true, want false — this mechanism carries session/tool-call value beyond prompt-submit and must always register", tool)
			}
		})
	}
}
