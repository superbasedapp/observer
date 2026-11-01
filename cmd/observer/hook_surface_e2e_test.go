package main

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/db/dbtemplate"
	"github.com/marmutapp/superbased-observer/internal/hook"
)

// guardEventTools returns the tool column of every guard_events row of
// session in the config's database.
func guardEventTools(t *testing.T, dbPath, session string) []string {
	t.Helper()
	database, err := dbtemplate.Open(context.Background(), db.Options{Path: dbPath})
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	rows, err := database.Query(`SELECT COALESCE(tool, '') FROM guard_events WHERE session_id = ? ORDER BY id`, session)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var tool string
		if err := rows.Scan(&tool); err != nil {
			t.Fatal(err)
		}
		out = append(out, tool)
	}
	return out
}

// enforcedGuardConfig writes a guard-enforcing config in a temp dir and
// returns its path and database path.
func enforcedGuardConfig(t *testing.T) (configPath, dbPath string) {
	t.Helper()
	dir := t.TempDir()
	dbPath = filepath.Join(dir, "observer.db")
	configPath = filepath.Join(dir, "config.toml")
	body := "[observer]\ndb_path = " + strconv.Quote(filepath.ToSlash(dbPath)) + "\n\n[guard]\nenabled = true\nmode = \"enforce\"\n"
	if err := os.WriteFile(configPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	writePosture(t, configPath, enforcedPosture)
	return configPath, dbPath
}

// TestClaudeCodeHook_DeepSeekReplayGatedAsDeepSeek drives the REAL
// claude-code receiver with the PreToolUse payload DeepSeek Harness's
// dsh-hooks-claude-code bridge sends (vendor source 0.2.1-rc.3: session_id,
// transcript_path "", hook_event_name, cwd, the harness's own tool_name):
// a destructive bash command is blocked in the Claude JSON shape and the
// guard_events row is under deepseek, never claude-code (surface-gap S-20).
func TestClaudeCodeHook_DeepSeekReplayGatedAsDeepSeek(t *testing.T) {
	configPath, dbPath := enforcedGuardConfig(t)
	const session = "dsh-session-0001"
	payload := `{"session_id":"` + session + `","transcript_path":"","hook_event_name":"PreToolUse","cwd":"/home/dev/repo","tool_name":"bash","tool_input":{"command":"rm -rf ~/"},"tool_use_id":"call_1"}`
	h := newFailureHarness(t, resolveHookFailurePlan("claude-code", "pre-tool", configPath))
	withStdinT(t, payload, func() { handleClaudeCodeHook(context.Background(), "pre-tool", configPath) })
	if out := h.stdout.String(); !strings.Contains(out, "deny") {
		t.Fatalf("stdout %q, want the Claude JSON deny", out)
	}
	if got := guardEventTools(t, dbPath, session); len(got) == 0 || got[0] != "deepseek" {
		t.Fatalf("guard_events tools %v, want a deepseek row", got)
	}
}

// TestClaudeCodeHook_CopilotRuntimePayloadIsNeutral drives the REAL
// claude-code receiver with the Claude-compatible PreToolUse payload the
// Copilot CLI runtime (VS Code's local agent, live check 12) sends, with
// COPILOT_CLI and COPILOT_HOOK_DIR in the hook environment. While Observer's
// own copilot-cli hook is registered in the home's ~/.copilot/hooks, a
// destructive command is NOT judged here (that hook sees the same call): the
// reply is the neutral {} and nothing is written. With the registration
// absent (G2, surface-gap Wave 5 audit finding 2) the replay is the only
// gate Observer has, so the same call is judged as copilot-cli and denied
// under guard enforcement, the guard_events row under copilot-cli. Without
// the environment the same payload is judged as Claude Code's, which proves
// the fixture would block.
func TestClaudeCodeHook_CopilotRuntimePayloadIsNeutral(t *testing.T) {
	const session = "a27ee083-0000-4000-8000-0000000000c1"
	payload := `{"hook_event_name":"PreToolUse","session_id":"` + session + `","timestamp":"2026-10-26T09:27:24.356Z","cwd":"/home/dev/repo","tool_name":"Bash","tool_input":{"command":"rm -rf ~/"}}`
	copilotRuntime := func(t *testing.T, registered bool) (configPath, dbPath string) {
		t.Helper()
		configPath, dbPath = enforcedGuardConfig(t)
		home := t.TempDir()
		pinToolHomesAt(t, home)
		if err := os.MkdirAll(filepath.Join(home, ".copilot"), 0o755); err != nil {
			t.Fatal(err)
		}
		if registered {
			// Written by another Observer install path (an npm shim, the VS
			// Code bundle): the entry is Observer's whatever binary wrote it.
			reg, err := hook.NewRegistry(hook.Options{BinaryPath: filepath.Join(home, "bin", "observer"), ConfigPath: configPath})
			if err != nil {
				t.Fatal(err)
			}
			if res := reg.Register("copilot-cli"); res.Error != nil {
				t.Fatalf("register copilot-cli: %v", res.Error)
			}
		}
		t.Setenv("COPILOT_CLI", "1")
		t.Setenv("COPILOT_HOOK_DIR", filepath.Join(home, ".copilot", "hooks"))
		return configPath, dbPath
	}
	t.Run("copilot runtime, copilot-cli registration present", func(t *testing.T) {
		configPath, dbPath := copilotRuntime(t, true)
		h := newFailureHarness(t, resolveHookFailurePlan("claude-code", "pre-tool", configPath))
		withStdinT(t, payload, func() { handleClaudeCodeHook(context.Background(), "pre-tool", configPath) })
		if out := h.stdout.String(); out != "{}\n" {
			t.Fatalf("stdout %q, want the neutral {}", out)
		}
		if _, err := os.Stat(dbPath); err == nil {
			t.Fatal("a copilot runtime payload opened the observer DB")
		}
	})
	t.Run("copilot runtime, copilot-cli registration absent", func(t *testing.T) {
		configPath, dbPath := copilotRuntime(t, false)
		h := newFailureHarness(t, resolveHookFailurePlan("claude-code", "pre-tool", configPath))
		withStdinT(t, payload, func() { handleClaudeCodeHook(context.Background(), "pre-tool", configPath) })
		if out := h.stdout.String(); !strings.Contains(out, "deny") {
			t.Fatalf("stdout %q, want the Claude JSON deny", out)
		}
		if got := guardEventTools(t, dbPath, session); len(got) == 0 || got[0] != "copilot-cli" {
			t.Fatalf("guard_events tools %v, want a copilot-cli row", got)
		}
	})
	t.Run("same payload as claude code", func(t *testing.T) {
		configPath, _ := enforcedGuardConfig(t)
		t.Setenv("COPILOT_CLI", "")
		t.Setenv("COPILOT_HOOK_DIR", "")
		h := newFailureHarness(t, resolveHookFailurePlan("claude-code", "pre-tool", configPath))
		withStdinT(t, payload, func() { handleClaudeCodeHook(context.Background(), "pre-tool", configPath) })
		if out := h.stdout.String(); !strings.Contains(out, "deny") {
			t.Fatalf("stdout %q, want the Claude Code deny", out)
		}
	})
}

// TestAntigravityAppPayloadGatedAsAntigravity drives the antigravity-cli
// tool-gate receiver with an Antigravity App payload (transcriptPath under
// the App's app_data_dir) and with the CLI's own: both are blocked in the
// agy dialect, the App's verdict is recorded under antigravity and the
// CLI's under antigravity-cli (surface-gap W-2c).
func TestAntigravityAppPayloadGatedAsAntigravity(t *testing.T) {
	for _, tc := range []struct {
		name, dataDir, want string
	}{
		{"app", "antigravity", "antigravity"},
		{"ide", "antigravity-ide", "antigravity"},
		{"cli", "antigravity-cli", "antigravity-cli"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			configPath, dbPath := enforcedGuardConfig(t)
			session := "agy-" + tc.name
			transcript := "/home/u/.gemini/" + tc.dataDir + "/brain/" + session + "/.system_generated/logs/transcript.jsonl"
			payload := `{"conversationId":"` + session + `","workspacePaths":["/home/u/repo"],"transcriptPath":"` + transcript + `","toolCall":{"name":"run_command","args":{"CommandLine":"rm -rf ~/"}},"stepIdx":0}`
			b, ok := standaloneToolGate("antigravity-cli", "PreToolUse")
			if !ok {
				t.Fatal("antigravity-cli PreToolUse is not a served tool gate")
			}
			h := newFailureHarness(t, resolveHookFailurePlan("antigravity-cli", "PreToolUse", configPath))
			handleToolGateHook("antigravity-cli", "antigravity-cli:PreToolUse", b, strings.NewReader(payload), configPath)
			if out := h.stdout.String(); !strings.Contains(out, "deny") {
				t.Fatalf("stdout %q, want the agy deny", out)
			}
			if got := guardEventTools(t, dbPath, session); len(got) == 0 || got[0] != tc.want {
				t.Fatalf("guard_events tools %v, want a %s row", got, tc.want)
			}
		})
	}
}
