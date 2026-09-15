package main

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/diag"
	"github.com/marmutapp/superbased-observer/internal/hook"
)

// Part B item 3 (docs/plans/prompt-submit-intervention-exploration-2026-09-07.md
// §10 item 11, phase-2 review): `observer doctor --probe-hook` tests.

func TestProbeHookDialectFor(t *testing.T) {
	cases := []struct {
		tool        string
		wantDialect string
		wantEvent   string
		wantOK      bool
	}{
		{"claude-code", hook.PromptDialectClaudeCode, "user-prompt-submit", true},
		{"codex", hook.PromptDialectTopLevelBlock, "UserPromptSubmit", true},
		{"droid", hook.PromptDialectTopLevelBlock, "UserPromptSubmit", true},
		{"qwen-code", hook.PromptDialectTopLevelBlock, "UserPromptSubmit", true},
		{"gemini-cli", hook.PromptDialectGemini, "BeforeAgent", true},
		{"cursor", hook.PromptDialectCursor, "beforeSubmitPrompt", true},
		{"qoder", hook.PromptDialectQoder, "UserPromptSubmit", true},
		{"poolside", hook.PromptDialectPoolside, "UserPromptSubmit", true},
		{"zcode", hook.PromptDialectZcode, "UserPromptSubmit", true},
		{"devin", hook.PromptDialectCascade, "pre_user_prompt", true},
		{"command-code", hook.PromptDialectCommandCode, "transformInput", true},
		{"kiro-cli", "", "", false},
		{"definitely-not-a-tool", "", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.tool, func(t *testing.T) {
			dialect, event, ok := probeHookDialectFor(tc.tool)
			if dialect != tc.wantDialect || event != tc.wantEvent || ok != tc.wantOK {
				t.Errorf("probeHookDialectFor(%q) = (%q, %q, %v), want (%q, %q, %v)",
					tc.tool, dialect, event, ok, tc.wantDialect, tc.wantEvent, tc.wantOK)
			}
		})
	}
}

// TestProbeHookPayload_ParsesUnderEachDialectExtractor pins that the
// synthetic payload actually round-trips through the extractor shape
// each dialect's REAL receiver expects (internal/hook/promptsubmit.go)
// — a probe payload that the receiver itself can't parse would always
// read as a false "ALLOWED" (a parse failure falls through to the
// unguarded default reply), silently defeating the whole probe.
func TestProbeHookPayload_ParsesUnderEachDialectExtractor(t *testing.T) {
	cases := []struct {
		dialect      string
		sessionField string // "" means this dialect carries no session/identity field at all (commandcode)
	}{
		{hook.PromptDialectClaudeCode, "session_id"},
		{hook.PromptDialectTopLevelBlock, "session_id"},
		{hook.PromptDialectGemini, "session_id"},
		{hook.PromptDialectCursor, "conversation_id"},
		{hook.PromptDialectQoder, "session_id"},
		{hook.PromptDialectPoolside, "session_id"},
		{hook.PromptDialectZcode, "session_id"},
		{hook.PromptDialectCascade, "trajectory_id"},
		{hook.PromptDialectCommandCode, ""},
	}
	for _, tc := range cases {
		t.Run(tc.dialect, func(t *testing.T) {
			body := probeHookPayload(tc.dialect, "sess-probe-1")
			var m map[string]any
			if err := json.Unmarshal(body, &m); err != nil {
				t.Fatalf("payload not valid JSON: %v (%s)", err, body)
			}
			if tc.sessionField != "" && m[tc.sessionField] != "sess-probe-1" {
				t.Errorf("payload[%q] = %v, want sess-probe-1 (%s)", tc.sessionField, m[tc.sessionField], body)
			}
			if !strings.Contains(string(body), probeFakeSecret) {
				t.Errorf("payload missing the fake secret marker: %s", body)
			}
		})
	}
}

func TestProbeHookOutcome(t *testing.T) {
	cases := []struct {
		name        string
		dialect     string
		reply       string
		wantBlocked bool
	}{
		// LIVE CORRECTION 2026-09-07: Claude Code's block is exit code 2
		// (probeHookExitCodeDialects); a stdout reply is never a block, and
		// the PreToolUse-only permissionDecision must not be read as one.
		{"claude-code allow envelope", hook.PromptDialectClaudeCode, `{"hookSpecificOutput":{"hookEventName":"UserPromptSubmit"}}`, false},
		{"claude-code stray permissionDecision deny is NOT a block", hook.PromptDialectClaudeCode, `{"hookSpecificOutput":{"permissionDecision":"deny"}}`, false},
		{"top-level-block block", hook.PromptDialectTopLevelBlock, `{"decision":"block","reason":"x"}`, true},
		{"top-level-block empty", hook.PromptDialectTopLevelBlock, `{}`, false},
		{"gemini deny", hook.PromptDialectGemini, `{"decision":"deny"}`, true},
		{"gemini empty", hook.PromptDialectGemini, `{}`, false},
		{"cursor continue false", hook.PromptDialectCursor, `{"continue":false,"user_message":"x"}`, true},
		{"cursor continue true", hook.PromptDialectCursor, `{"continue":true}`, false},
		{"poolside block", hook.PromptDialectPoolside, `{"decision":"block","reason":"x"}`, true},
		{"poolside empty", hook.PromptDialectPoolside, `{}`, false},
		{"zcode continue false", hook.PromptDialectZcode, `{"continue":false,"reason":"x"}`, true},
		{"zcode continue true", hook.PromptDialectZcode, `{"continue":true}`, false},
		{"command-code handled", hook.PromptDialectCommandCode, `{"action":"handled","message":"x"}`, true},
		{"command-code continue", hook.PromptDialectCommandCode, `{"action":"continue"}`, false},
		{"unparseable reply", hook.PromptDialectClaudeCode, `not json`, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			blocked, detail := probeHookOutcome(tc.dialect, []byte(tc.reply))
			if blocked != tc.wantBlocked {
				t.Errorf("probeHookOutcome(%q, %s) blocked = %v, want %v (detail=%q)", tc.dialect, tc.reply, blocked, tc.wantBlocked, detail)
			}
		})
	}
}

// probeHookTestBinary compiles a real observer binary ONCE per test
// process (cached across subtests via sync.Once) so runProbeHook's
// os/exec subprocess invocation can be exercised faithfully — this is
// the ONLY way to prove the probe actually talks to a live `observer
// hook <tool> <event>` invocation end-to-end, not just its own
// parsing helpers.
var (
	probeHookBinaryOnce sync.Once
	probeHookBinaryPath string
	probeHookBinaryErr  error
)

func probeHookTestBinary(t *testing.T) string {
	t.Helper()
	probeHookBinaryOnce.Do(func() {
		dir, err := os.MkdirTemp("", "observer-probe-hook-bin")
		if err != nil {
			probeHookBinaryErr = err
			return
		}
		out := filepath.Join(dir, "observer")
		if os.PathSeparator == '\\' {
			out += ".exe"
		}
		c := exec.Command("go", "build", "-o", out, ".")
		if output, err := c.CombinedOutput(); err != nil {
			probeHookBinaryErr = err
			t.Logf("go build output: %s", output)
			return
		}
		probeHookBinaryPath = out
	})
	if probeHookBinaryErr != nil {
		t.Skipf("could not build a test observer binary: %v", probeHookBinaryErr)
	}
	return probeHookBinaryPath
}

// probeHookSetupHome points os.UserHomeDir() at a fresh, isolated temp
// dir for the duration of the calling test — B3 (phase-3a review)
// made runProbeHook consult the REAL registration state
// (hook.Registry.Register's own dry-run read of the tool's config
// file) before ever invoking anything, so every end-to-end test must
// run against a controlled HOME: without this, a test would either
// pollute the developer's real ~/.claude/~/.qoder/etc, or (worse)
// silently pass/fail depending on whatever this dev box happens to
// have registered for real already.
func probeHookSetupHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home) // os.UserHomeDir reads USERPROFILE on Windows
	return home
}

// probeHookRegister actually registers tool's prompt-submit hook
// (non-dry-run) against home, using the same binary+configPath the
// probe itself will later invoke — so checkHookRegistration's
// AlreadySet comparison genuinely matches.
func probeHookRegister(t *testing.T, home, binary, configPath, tool string) {
	t.Helper()
	reg, err := hook.NewRegistry(hook.Options{BinaryPath: binary, HomeDir: home, ConfigPath: configPath})
	if err != nil {
		t.Fatalf("hook.NewRegistry: %v", err)
	}
	res := reg.Register(tool)
	if res.Error != nil {
		t.Fatalf("register %s: %v", tool, res.Error)
	}
}

// TestRunProbeHook_EndToEnd drives runProbeHook against a REAL compiled
// binary — the blocked case (guard enabled + mode=block, hook actually
// registered), the allowed case (guard disabled, hook registered), and
// B3's own new case (hook NOT registered at all, guard on) — mirroring
// the exact scenario BLOCK-1 existed to catch: a registry claiming
// PromptLaneHook that a live probe would have shown was actually
// inert, PLUS B3's own false-green (a probe that "passes" even though
// nothing in the vendor's real config would ever call it).
func TestRunProbeHook_EndToEnd(t *testing.T) {
	binary := probeHookTestBinary(t)

	guardOnBlockConfig := func(t *testing.T, dir string) string {
		t.Helper()
		cfgPath := filepath.Join(dir, "config.toml")
		cfgBody := "[observer]\ndb_path = " + quoteTOMLPath(filepath.Join(dir, "observer.db")) + "\n\n" +
			"[guard]\nenabled = true\nmode = \"observe\"\n\n" +
			"[guard.prompt]\nenabled = true\nmode = \"block\"\nhook_lane = true\nenforce_independent = true\n"
		if err := os.WriteFile(cfgPath, []byte(cfgBody), 0o600); err != nil {
			t.Fatal(err)
		}
		return cfgPath
	}
	guardOffConfig := func(t *testing.T, dir string) string {
		t.Helper()
		cfgPath := filepath.Join(dir, "config.toml")
		cfgBody := "[observer]\ndb_path = " + quoteTOMLPath(filepath.Join(dir, "observer.db")) + "\n\n" +
			"[guard]\nenabled = false\n"
		if err := os.WriteFile(cfgPath, []byte(cfgBody), 0o600); err != nil {
			t.Fatal(err)
		}
		return cfgPath
	}

	t.Run("blocked when guard is on, mode=block, and the hook IS registered", func(t *testing.T) {
		home := probeHookSetupHome(t)
		cfgPath := guardOnBlockConfig(t, t.TempDir())
		probeHookRegister(t, home, binary, cfgPath, "claude-code")
		c := runProbeHook(context.Background(), binary, cfgPath, "claude-code")
		if c.Status != diag.StatusOK {
			t.Errorf("Status = %v, want StatusOK. Message=%s Details=%v", c.Status, c.Message, c.Details)
		}
		if !strings.Contains(c.Message, "BLOCKED") {
			t.Errorf("Message = %q, want it to say BLOCKED", c.Message)
		}
	})

	t.Run("allowed (fails) when guard is disabled but the hook IS registered", func(t *testing.T) {
		home := probeHookSetupHome(t)
		cfgPath := guardOffConfig(t, t.TempDir())
		probeHookRegister(t, home, binary, cfgPath, "claude-code")
		c := runProbeHook(context.Background(), binary, cfgPath, "claude-code")
		if c.Status != diag.StatusFail {
			t.Errorf("Status = %v, want StatusFail. Message=%s", c.Status, c.Message)
		}
		if !strings.Contains(c.Message, "ALLOWED") {
			t.Errorf("Message = %q, want it to say ALLOWED", c.Message)
		}
	})

	// B3 (phase-3a review): the false-green this whole rewrite exists
	// to close — a tool with a perfectly good dialect/receiver, guard
	// ON and mode=block, but whose hook was simply never registered
	// (a fresh install, or `observer init` never run for it) must FAIL
	// with an honest NOT REGISTERED message, never a BLOCKED "the
	// guard is live" green.
	t.Run("B3: NOT REGISTERED fails even when guard is on and mode=block", func(t *testing.T) {
		probeHookSetupHome(t) // fresh HOME — nothing registered
		cfgPath := guardOnBlockConfig(t, t.TempDir())
		c := runProbeHook(context.Background(), binary, cfgPath, "claude-code")
		if c.Status != diag.StatusFail {
			t.Errorf("Status = %v, want StatusFail (unregistered must never read as blocked/live). Message=%s", c.Status, c.Message)
		}
		if !strings.Contains(c.Message, "NOT REGISTERED") {
			t.Errorf("Message = %q, want it to say NOT REGISTERED", c.Message)
		}
		if len(c.Details) == 0 || !strings.Contains(c.Details[0], "observer init") {
			t.Errorf("Details = %v, want an `observer init` remedy", c.Details)
		}
	})

	// Part B item 2 (phase-3a): the exit-code-only dialects (Qoder,
	// Cascade) — this is the ONE test that actually exercises
	// runProbeHook's probeHookExitCodeDialects branch end to end
	// through a REAL subprocess, proving a legitimate block (non-zero
	// exit, no stdout at all) is correctly distinguished from a
	// genuine invocation failure.
	for _, tool := range []string{"qoder", "devin"} {
		t.Run(tool+": blocked when guard is on, mode=block, and the hook IS registered", func(t *testing.T) {
			home := probeHookSetupHome(t)
			cfgPath := guardOnBlockConfig(t, t.TempDir())
			probeHookRegister(t, home, binary, cfgPath, tool)
			c := runProbeHook(context.Background(), binary, cfgPath, tool)
			if c.Status != diag.StatusOK {
				t.Errorf("Status = %v, want StatusOK. Message=%s Details=%v", c.Status, c.Message, c.Details)
			}
			if !strings.Contains(c.Message, "BLOCKED") {
				t.Errorf("Message = %q, want it to say BLOCKED", c.Message)
			}
		})

		t.Run(tool+": allowed (fails) when guard is disabled but the hook IS registered", func(t *testing.T) {
			home := probeHookSetupHome(t)
			cfgPath := guardOffConfig(t, t.TempDir())
			probeHookRegister(t, home, binary, cfgPath, tool)
			c := runProbeHook(context.Background(), binary, cfgPath, tool)
			if c.Status != diag.StatusFail {
				t.Errorf("Status = %v, want StatusFail. Message=%s", c.Status, c.Message)
			}
			if !strings.Contains(c.Message, "ALLOWED") {
				t.Errorf("Message = %q, want it to say ALLOWED", c.Message)
			}
		})

		t.Run(tool+": B3 NOT REGISTERED fails even when guard is on and mode=block", func(t *testing.T) {
			probeHookSetupHome(t) // fresh HOME — nothing registered
			cfgPath := guardOnBlockConfig(t, t.TempDir())
			c := runProbeHook(context.Background(), binary, cfgPath, tool)
			if c.Status != diag.StatusFail {
				t.Errorf("Status = %v, want StatusFail. Message=%s", c.Status, c.Message)
			}
			if !strings.Contains(c.Message, "NOT REGISTERED") {
				t.Errorf("Message = %q, want it to say NOT REGISTERED", c.Message)
			}
		})
	}

	// zcode: AutoWired:false — documented, not auto-wired. This must
	// report distinctly from both REGISTERED and NOT REGISTERED, and
	// must never depend on registration state at all (no HOME setup
	// needed, and none is done here on purpose).
	t.Run("zcode: documented, not auto-wired", func(t *testing.T) {
		probeHookSetupHome(t) // fresh HOME — must not matter for zcode
		c := runProbeHook(context.Background(), binary, "", "zcode")
		if c.Status != diag.StatusWarn {
			t.Errorf("Status = %v, want StatusWarn. Message=%s", c.Status, c.Message)
		}
		if !strings.Contains(c.Message, "not auto-wired") {
			t.Errorf("Message = %q, want it to say \"not auto-wired\"", c.Message)
		}
	})

	t.Run("no dialect known: warn, not fail", func(t *testing.T) {
		c := runProbeHook(context.Background(), binary, "", "kiro-cli")
		if c.Status != diag.StatusWarn {
			t.Errorf("Status = %v, want StatusWarn. Message=%s", c.Status, c.Message)
		}
	})
}

// quoteTOMLPath forward-slashes and quotes a path for a TOML string
// value, avoiding the Windows \U-escape trap documented elsewhere in
// this package's tests (backslash sequences like \Us are interpreted
// as invalid unicode escapes by the TOML parser).
func quoteTOMLPath(p string) string {
	return `"` + filepath.ToSlash(p) + `"`
}
