package main

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/db/dbtemplate"
	"github.com/marmutapp/superbased-observer/internal/hook"
)

// TestClaudeCodeHook_ForeignCursorPayloadIsNoOp drives the REAL claude-code
// dispatcher with the payloads cursor-agent sends when it runs the user's
// Claude Code hooks (~/.claude/settings.json, hookSource "claude-user" in
// Cursor's log): Cursor's own field set with hook_event_name set to the
// Cursor step and cursor_version always present (anonymized). For every
// event Cursor maps a Claude hook onto, the receiver must exit 0 with
// Cursor's NEUTRAL reply for the step (T-034h: an empty stdout is logged by
// cursor-agent as a failed hook, errorClass empty_stdout; the neutral reply
// was live-grounded as status "success" on node 1, 2026-10-03), evaluate no
// guard (no exit-2 block even for a prompt carrying a live-shaped secret
// under an enforcing prompt guard), and write nothing (no actions /
// guard_events / compaction / pidbridge rows). The control run at the end sends the SAME secret in a
// genuine Claude Code payload and must be blocked, proving the fixture's
// guard would have fired.
func TestClaudeCodeHook_ForeignCursorPayloadIsNoOp(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "observer.db")
	configPath := filepath.Join(dir, "config.toml")
	cfgBody := "[observer]\ndb_path = " + strconv.Quote(filepath.ToSlash(dbPath)) + "\n\n" +
		"[guard]\nenabled = true\nmode = \"enforce\"\n\n" +
		"[guard.prompt]\nenabled = true\nmode = \"ask-once\"\nhook_lane = true\nreconsider_min_delay = \"0s\"\n"
	if err := os.WriteFile(configPath, []byte(cfgBody), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	// Observer's own cursor hooks are registered in the hook's home (FU-122:
	// the replay stands down only while they are; TestClaudeCodeHook_
	// CursorReplayJudgedWithoutCursorRegistration covers the absent case).
	home := t.TempDir()
	pinToolHomesAt(t, home)
	if err := os.MkdirAll(filepath.Join(home, ".cursor"), 0o755); err != nil {
		t.Fatal(err)
	}
	reg, err := hook.NewRegistry(hook.Options{BinaryPath: filepath.Join(home, "bin", "observer"), ConfigPath: configPath})
	if err != nil {
		t.Fatal(err)
	}
	if res := reg.Register("cursor"); res.Error != nil {
		t.Fatalf("register cursor: %v", res.Error)
	}
	var exitCodes []int
	prevExit := hookOSExit
	hookOSExit = func(code int) { exitCodes = append(exitCodes, code) }
	t.Cleanup(func() { hookOSExit = prevExit })

	run := func(event, payload string) (stdout, stderr string) {
		t.Helper()
		hookReplied, hookPendingExitCode, hookExpectsStdoutReply = false, 0, true
		stdinR, stdinW, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		go func() {
			_, _ = stdinW.Write([]byte(payload))
			_ = stdinW.Close()
		}()
		stdoutR, stdoutW, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		stderrR, stderrW, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		oldIn, oldOut, oldErr := os.Stdin, os.Stdout, os.Stderr
		os.Stdin, os.Stdout, os.Stderr = stdinR, stdoutW, stderrW
		handleClaudeCodeHook(context.Background(), event, configPath)
		os.Stdin, os.Stdout, os.Stderr = oldIn, oldOut, oldErr
		_ = stdoutW.Close()
		_ = stderrW.Close()
		o, _ := io.ReadAll(stdoutR)
		e, _ := io.ReadAll(stderrR)
		return string(o), string(e)
	}

	const conv = "c0c0c001-0000-4000-8000-00000000f0e1"
	const secret = "sk-ant-api03-1234567890ABCDEFGhijKLmnopqRSTuvwxyz"
	cursorPayload := func(step, extra string) string {
		return `{"conversation_id":"` + conv + `","generation_id":"g-1","model":"default",` + extra +
			`"session_id":"` + conv + `","hook_event_name":"` + step + `","cursor_version":"2026.09.18-9a7762b",` +
			`"workspace_roots":["/home/dev/aa-cc-test"],"user_email":"dev@example.test","transcript_path":null}`
	}
	for _, tc := range []struct{ event, payload, reply string }{
		{"session-start", cursorPayload("sessionStart", `"is_background_agent":false,"composer_mode":"agent",`), "{}\n"},
		{"user-prompt-submit", cursorPayload("beforeSubmitPrompt", `"prompt":"my key is `+secret+`","attachments":[],`), "{\"continue\":true}\n"},
		{"pre-tool", cursorPayload("preToolUse", `"tool_name":"Shell","tool_input":{"command":"rm -rf ~"},"tool_use_id":"tu-1","cwd":"/home/dev/aa-cc-test",`), "{}\n"},
		{"post-tool", cursorPayload("postToolUse", `"tool_name":"Shell","tool_input":{"command":"ls"},"tool_use_id":"tu-2","tool_output":"ok",`), "{}\n"},
		{"stop", cursorPayload("stop", `"status":"completed","loop_count":0,`), "{}\n"},
		{"pre-compact", cursorPayload("preCompact", `"trigger":"auto",`), "{}\n"},
		{"session-end", cursorPayload("sessionEnd", `"reason":"user_exit",`), "{}\n"},
	} {
		t.Run(tc.event, func(t *testing.T) {
			before := len(exitCodes)
			stdout, stderr := run(tc.event, tc.payload)
			if stdout != tc.reply {
				t.Errorf("stdout = %q, want Cursor's neutral reply %q (no decision for the foreign host)", stdout, tc.reply)
			}
			if len(exitCodes) != before {
				t.Errorf("exit codes %v: a foreign payload must exit 0 on the normal return", exitCodes[before:])
			}
			if !strings.Contains(stderr, "payload from cursor") {
				t.Errorf("stderr = %q, want the foreign-host note", stderr)
			}
		})
	}
	if _, err := os.Stat(dbPath); err == nil {
		t.Fatalf("a foreign payload opened the observer DB")
	}

	// Control: the SAME secret in a genuine Claude Code payload is blocked.
	run("user-prompt-submit", `{"session_id":"s-claude","cwd":"/r","hook_event_name":"UserPromptSubmit","prompt":"my key is `+secret+`"}`)
	if len(exitCodes) != 1 || exitCodes[0] != 2 {
		t.Fatalf("control exit codes = %v, want [2] (the fixture's prompt guard must block a Claude Code payload)", exitCodes)
	}
	database, err := dbtemplate.Open(context.Background(), db.Options{Path: dbPath})
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	for _, q := range []string{
		`SELECT COUNT(*) FROM actions WHERE session_id = '` + conv + `'`,
		`SELECT COUNT(*) FROM guard_events WHERE session_id = '` + conv + `'`,
		`SELECT COUNT(*) FROM compaction_events`,
		`SELECT COUNT(*) FROM session_pid_bridge WHERE session_id = '` + conv + `'`,
		`SELECT COUNT(*) FROM sessions WHERE id = '` + conv + `'`,
	} {
		var n int
		if err := database.QueryRow(q).Scan(&n); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
		if n != 0 {
			t.Errorf("%s = %d, want 0", q, n)
		}
	}
}

// TestClaudeCodeHook_GrokReplayDispatchesLifecycle drives the REAL
// claude-code dispatcher with the payload shapes Grok Build 1.0.46 sends
// when it replays ~/.claude/settings.json (node 1 capture, 2026-10-03,
// anonymized): both session_id and sessionId, PascalCase hook_event_name
// beside a snake_case hookEventName, workspaceRoot, and the turn's final
// text as lastAssistantMessage. A lifecycle event is dispatched to the grok
// row's lifecycle binding (a spooled row under tool grok, never a
// claude-code row); any other event is answered with the neutral {} and
// recorded nowhere.
func TestClaudeCodeHook_GrokReplayDispatchesLifecycle(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "observer.db")
	configPath := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(configPath, []byte("[observer]\ndb_path = "+strconv.Quote(filepath.ToSlash(dbPath))+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	run := func(event, payload string) (stdout, stderr string) {
		t.Helper()
		hookReplied, hookPendingExitCode, hookExpectsStdoutReply = false, 0, true
		stdinR, stdinW, _ := os.Pipe()
		go func() { _, _ = stdinW.Write([]byte(payload)); _ = stdinW.Close() }()
		stdoutR, stdoutW, _ := os.Pipe()
		stderrR, stderrW, _ := os.Pipe()
		oldIn, oldOut, oldErr := os.Stdin, os.Stdout, os.Stderr
		os.Stdin, os.Stdout, os.Stderr = stdinR, stdoutW, stderrW
		handleClaudeCodeHook(context.Background(), event, configPath)
		os.Stdin, os.Stdout, os.Stderr = oldIn, oldOut, oldErr
		_ = stdoutW.Close()
		_ = stderrW.Close()
		o, _ := io.ReadAll(stdoutR)
		e, _ := io.ReadAll(stderrR)
		return string(o), string(e)
	}
	const sid = "01a10244-aea6-7000-8000-00000000c0de"
	grok := func(pascal, snake, extra string) string {
		return `{"session_id":"` + sid + `","sessionId":"` + sid + `","hook_event_name":"` + pascal + `","hookEventName":"` + snake +
			`","cwd":"/home/dev/work","workspaceRoot":"/home/dev/work",` + extra + `"transcriptPath":"/home/dev/.grok/sessions/x/` + sid + `/updates.jsonl"}`
	}
	for _, tc := range []struct{ event, payload string }{
		{"pre-tool", grok("PreToolUse", "pre_tool_use", `"toolName":"run_terminal_cmd","toolInput":{"command":"ls"},`)},
		{"stop", grok("Stop", "stop", `"lastAssistantMessage":"Done: listed the files.",`)},
		{"session-end", grok("SessionEnd", "session_end", `"reason":"other",`)},
	} {
		t.Run(tc.event, func(t *testing.T) {
			stdout, stderr := run(tc.event, tc.payload)
			if stdout != "{}\n" {
				t.Errorf("stdout = %q, want the neutral {}", stdout)
			}
			if !strings.Contains(stderr, "payload from grok") {
				t.Errorf("stderr = %q, want the grok note", stderr)
			}
		})
	}
	spool, err := os.ReadFile(filepath.Join(dir, "hook-lifecycle.jsonl"))
	if err != nil {
		t.Fatalf("lifecycle spool: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(spool)), "\n")
	if len(lines) != 2 {
		t.Fatalf("spool lines = %d, want 2 (Stop task_complete + SessionEnd session_end):\n%s", len(lines), spool)
	}
	for _, want := range []string{`"action_type":"task_complete"`, `"action_type":"session_end"`} {
		if !strings.Contains(string(spool), want) {
			t.Errorf("spool lacks %s", want)
		}
	}
	if strings.Contains(string(spool), `"tool":"claude-code"`) || !strings.Contains(string(spool), `"tool":"grok"`) {
		t.Errorf("grok replay must spool under tool grok, never claude-code:\n%s", spool)
	}
	if _, err := os.Stat(dbPath); err == nil {
		t.Errorf("a grok end event opened the observer DB (the end path must stay DB-free)")
	}
}
