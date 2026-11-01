//go:build !sbo_omit_adapter_cursor

package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/hook"
)

// TestClaudeCodeHook_CursorReplayJudgedWithoutCursorRegistration drives the
// REAL claude-code receiver with the preToolUse payload Cursor IDE's Agents
// window gives the Claude Code hooks (FU-122, Mac round 4 row 2: Cursor runs
// ~/.cursor/hooks.json AND ~/.claude/settings.json, the replay carrying
// conversation_id, cursor_version and hook_event_name preToolUse). While
// Observer's own cursor registration holds preToolUse the replay is answered
// with Cursor's neutral {} and nothing is written (the cursor receiver judges
// the call once). With the registration absent the replay is the only gate
// Observer has on the call, so it is judged as cursor: Cursor's permission
// deny under guard enforcement, the guard_events row under cursor.
func TestClaudeCodeHook_CursorReplayJudgedWithoutCursorRegistration(t *testing.T) {
	const conv = "c0c0c001-0000-4000-8000-0000000f0122"
	payload := `{"conversation_id":"` + conv + `","generation_id":"g-1","model":"default",` +
		`"tool_name":"Shell","tool_input":{"command":"rm -rf ~/"},"tool_use_id":"tu-1","cwd":"/Users/dev/proj",` +
		`"session_id":"` + conv + `","hook_event_name":"preToolUse","cursor_version":"3.4.1",` +
		`"workspace_roots":["/Users/dev/proj"],"user_email":null,"transcript_path":null}`
	cursorHome := func(t *testing.T, registered bool) (configPath, dbPath string) {
		t.Helper()
		configPath, dbPath = enforcedGuardConfig(t)
		home := t.TempDir()
		pinToolHomesAt(t, home)
		if err := os.MkdirAll(filepath.Join(home, ".cursor"), 0o755); err != nil {
			t.Fatal(err)
		}
		if registered {
			// Written by another Observer install path: the entry is
			// Observer's whatever binary wrote it.
			reg, err := hook.NewRegistry(hook.Options{BinaryPath: filepath.Join(home, "bin", "observer"), ConfigPath: configPath})
			if err != nil {
				t.Fatal(err)
			}
			if res := reg.Register("cursor"); res.Error != nil {
				t.Fatalf("register cursor: %v", res.Error)
			}
		}
		return configPath, dbPath
	}
	t.Run("cursor registration present", func(t *testing.T) {
		configPath, dbPath := cursorHome(t, true)
		h := newFailureHarness(t, resolveHookFailurePlan("claude-code", "pre-tool", configPath))
		withStdinT(t, payload, func() { handleClaudeCodeHook(context.Background(), "pre-tool", configPath) })
		if out := h.stdout.String(); out != "{}\n" {
			t.Fatalf("stdout %q, want Cursor's neutral {}", out)
		}
		if _, err := os.Stat(dbPath); err == nil {
			t.Fatal("a Cursor replay opened the observer DB while the cursor registration is present")
		}
	})
	t.Run("cursor registration absent", func(t *testing.T) {
		configPath, dbPath := cursorHome(t, false)
		h := newFailureHarness(t, resolveHookFailurePlan("claude-code", "pre-tool", configPath))
		withStdinT(t, payload, func() { handleClaudeCodeHook(context.Background(), "pre-tool", configPath) })
		if out := h.stdout.String(); !strings.Contains(out, `"permission":"deny"`) {
			t.Fatalf("stdout %q, want Cursor's permission deny", out)
		}
		if got := guardEventTools(t, dbPath, conv); len(got) == 0 || got[0] != "cursor" {
			t.Fatalf("guard_events tools %v, want a cursor row", got)
		}
	})
}
