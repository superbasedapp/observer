package copilot

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/models"
)

func writeFixture(t *testing.T, lines []string) string {
	t.Helper()
	root := t.TempDir()
	ws := filepath.Join(root, "workspaceStorage", "ws-1")
	dir := filepath.Join(ws, "GitHub.copilot-chat", "debug-logs", "sess-1")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ws, "workspace.json"), []byte("{\n  \"folder\": \"file:///d%3A/programsx/test-project\"\n}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "main.jsonl")
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestAdapter_Name(t *testing.T) {
	if New().Name() != models.ToolCopilot {
		t.Fatalf("name: %s", New().Name())
	}
}

// TestAdapter_pathShapeFilters covers the string-based shape filters
// (isLegacySessionPath / isModernSessionPath) which intentionally
// normalize Windows backslashes so they recognize foreign-OS paths
// in fixtures. These run independently of the v1.4.51
// under-WatchPaths constraint — the integrated IsSessionFile is
// covered by TestAdapter_IsSessionFile below.
func TestAdapter_pathShapeFilters(t *testing.T) {
	cases := map[string]bool{
		`C:\Users\x\AppData\Roaming\Code\User\workspaceStorage\a\GitHub.copilot-chat\debug-logs\sess\main.jsonl`:           true,
		`/Users/x/Library/Application Support/Code/User/workspaceStorage/a/GitHub.copilot-chat/debug-logs/sess/main.jsonl`: true,
		`C:\Users\x\AppData\Roaming\Code\User\workspaceStorage\a\chatSessions\sess.jsonl`:                                  true,
		`/home/u/.config/Code/User/workspaceStorage/a/chatSessions/sess.jsonl`:                                             true,
		`C:\Users\x\AppData\Roaming\Code\User\globalStorage\emptyWindowChatSessions\sess.jsonl`:                            true,
		`/Users/x/Library/Application Support/Code/User/globalStorage/emptyWindowChatSessions/sess.jsonl`:                  true,
		`/tmp/GitHub.copilot-chat/debug-logs/sess/tools_0.json`:                                                            false,
		`/tmp/chatSessions/sess.json`: false,
		`/tmp/some/path/main.jsonl`:   false,
	}
	for path, want := range cases {
		got := isLegacySessionPath(path) || isModernSessionPath(path)
		if got != want {
			t.Errorf("shape-match(%q) = %v want %v", path, got, want)
		}
	}
}

// TestAdapter_IsSessionFile pins the integrated public API: shape
// filter AND adapter.UnderAnyWatchRoot. Uses host-OS paths so
// filepath.Abs behaves correctly (Windows-shaped paths on Linux CI
// resolve to "<cwd>/C:\\..." which is not what crossmount produces in
// production — production WSL2 paths arrive as /mnt/c/Users/...).
func TestAdapter_IsSessionFile(t *testing.T) {
	root := t.TempDir()
	a := NewWithOptions(nil, []string{root})

	// Positive: shape match AND under the watch root.
	mod := filepath.Join(root, "ws", "chatSessions", "sess.jsonl")
	if !a.IsSessionFile(mod) {
		t.Errorf("modern chatSessions under root should match: %s", mod)
	}
	// Positive: legacy debug-log under root.
	leg := filepath.Join(root, "ws", "GitHub.copilot-chat", "debug-logs", "sess", "main.jsonl")
	if !a.IsSessionFile(leg) {
		t.Errorf("legacy debug-log under root should match: %s", leg)
	}
	// Negative: shape match but outside watch root (v1.4.51 invariant).
	if a.IsSessionFile("/tmp/foreign/chatSessions/sess.jsonl") {
		t.Error("shape-match outside watch root must NOT match")
	}
	// Negative: under root but shape-mismatch.
	if a.IsSessionFile(filepath.Join(root, "random", "tools_0.json")) {
		t.Error("shape-mismatch under root must NOT match")
	}
}

func TestSessionIDFromPath_Modern(t *testing.T) {
	// All paths use the host's native separator because the watcher feeds
	// real on-disk paths into ParseSessionFile (and thus sessionIDFromPath).
	cases := map[string]string{
		filepath.Join("a", "chatSessions", "abc123.jsonl"):                                                   "abc123",
		filepath.Join("globalStorage", "emptyWindowChatSessions", "empty-1.jsonl"):                           "empty-1",
		filepath.Join("workspaceStorage", "ws", "GitHub.copilot-chat", "debug-logs", "sess-1", "main.jsonl"): "sess-1",
	}
	for path, want := range cases {
		if got := sessionIDFromPath(path); got != want {
			t.Errorf("sessionIDFromPath(%q) = %q want %q", path, got, want)
		}
	}
}

func TestParseSessionFile_DebugLogMainJSONL(t *testing.T) {
	lines := []string{
		`{"v":1,"ts":1776928112439,"dur":0,"sid":"sess-1","type":"session_start","name":"session_start","spanId":"session-start","status":"ok","attrs":{"copilotVersion":"0.45.0"}}`,
		`{"ts":1776928112440,"dur":0,"sid":"sess-1","type":"user_message","name":"user_message","spanId":"user-1","status":"ok","attrs":{"content":"hello4"}}`,
		`{"ts":1776928112559,"dur":3,"sid":"sess-1","type":"tool_call","name":"manage_todo_list","spanId":"tool-1","parentSpanId":"user-1","status":"ok","attrs":{"args":"{\"operation\":\"read\",\"chatSessionResource\":{\"scheme\":\"vscode-chat-session\"}}","result":"No todo list found."}}`,
		`{"ts":1776928112610,"dur":42356,"sid":"sess-1","type":"llm_request","name":"chat:oswe-vscode-prime","spanId":"llm-1","parentSpanId":"user-1","status":"ok","attrs":{"model":"oswe-vscode-prime","inputTokens":11136,"outputTokens":56,"ttft":31875}}`,
		`{"ts":1776928154966,"dur":0,"sid":"sess-1","type":"agent_response","name":"agent_response","spanId":"agent-1","parentSpanId":"user-1","status":"ok","attrs":{"response":"[{\"role\":\"assistant\",\"parts\":[{\"type\":\"text\",\"content\":\"Hello! How can I help with your project?\"}]}]","reasoning":"Responding to greetings"}}`,
	}
	path := writeFixture(t, lines)

	res, err := New().ParseSessionFile(context.Background(), path, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	// 3: user_prompt + todo_update + assistant_message. B3
	// (2026-07-31): attrs.reasoning no longer mints a standalone
	// `copilot.reasoning` row — it rides the assistant_message's
	// PrecedingReasoning (asserted below).
	if len(res.ToolEvents) != 3 {
		t.Fatalf("ToolEvents: got %d want 3", len(res.ToolEvents))
	}
	for _, ev := range res.ToolEvents {
		if strings.Contains(strings.ToLower(ev.RawToolName), "reasoning") {
			t.Fatalf("reasoning-named action row emitted: raw=%q %#v", ev.RawToolName, ev)
		}
	}
	if len(res.TokenEvents) != 1 {
		t.Fatalf("TokenEvents: got %d want 1", len(res.TokenEvents))
	}

	if res.ToolEvents[0].ActionType != models.ActionUserPrompt || res.ToolEvents[0].Target != "hello4" {
		t.Fatalf("user prompt event mismatch: %#v", res.ToolEvents[0])
	}
	// v1.6.29: workspaceFolderFromMetadata now routes the workspace.json
	// folder URI through pathnorm.NormalizeWithFormat, which applies
	// cross-mount translation in addition to URI decoding. The fixture
	// URI `file:///d%3A/programsx/test-project` becomes
	// `/mnt/d/programsx/test-project` on Linux (a real path the
	// observer can stat) instead of the pre-fix `d:/programsx/...`
	// shape that wasn't reachable from a Linux observer. On Windows
	// pathnorm leaves the drive-letter path as-is (no translation),
	// so the assertion picks the right shape per host.
	wantProjectRoot := "/mnt/d/programsx/test-project"
	if runtime.GOOS == "windows" {
		wantProjectRoot = "d:/programsx/test-project"
	}
	if res.ToolEvents[0].ProjectRoot != wantProjectRoot {
		t.Fatalf("project root mismatch: %#v want %q", res.ToolEvents[0], wantProjectRoot)
	}
	if res.ToolEvents[0].MessageID != "user:user-1" {
		t.Fatalf("user message_id mismatch: %#v", res.ToolEvents[0])
	}
	if res.ToolEvents[1].ActionType != models.ActionTodoUpdate {
		t.Fatalf("tool event action mismatch: %#v", res.ToolEvents[1])
	}
	if res.ToolEvents[1].MessageID != "assistant:user-1" {
		t.Fatalf("tool message_id mismatch: %#v", res.ToolEvents[1])
	}
	if res.ToolEvents[1].ToolOutput != "No todo list found." {
		t.Fatalf("tool event output mismatch: %#v", res.ToolEvents[1])
	}
	// [2] = the assistant_message response, carrying attrs.reasoning as
	// PrecedingReasoning (B3: reasoning is never an action row).
	if res.ToolEvents[2].ActionType != models.ActionAssistantMessage {
		t.Fatalf("assistant message mismatch: %#v", res.ToolEvents[2])
	}
	if res.ToolEvents[2].MessageID != "assistant:user-1" {
		t.Fatalf("assistant message_id mismatch: %#v", res.ToolEvents[2])
	}
	if !strings.Contains(res.ToolEvents[2].ToolOutput, "How can I help") {
		t.Fatalf("assistant output mismatch: %#v", res.ToolEvents[2])
	}
	if res.ToolEvents[2].PrecedingReasoning != "Responding to greetings" {
		t.Fatalf("assistant PrecedingReasoning = %q, want the threaded attrs.reasoning",
			res.ToolEvents[2].PrecedingReasoning)
	}

	if res.TokenEvents[0].Model != "oswe-vscode-prime" {
		t.Fatalf("token model mismatch: %#v", res.TokenEvents[0])
	}
	if res.TokenEvents[0].MessageID != "assistant:user-1" {
		t.Fatalf("token message_id mismatch: %#v", res.TokenEvents[0])
	}
	if res.TokenEvents[0].InputTokens != 11136 || res.TokenEvents[0].OutputTokens != 56 {
		t.Fatalf("token counts mismatch: %#v", res.TokenEvents[0])
	}
	// The llm_request line's own "dur":42356 is already milliseconds
	// (same scale as "ts") and covers exactly this call, so it stamps
	// verbatim.
	if res.TokenEvents[0].GenMs != 42356 || res.TokenEvents[0].GenBasis != models.GenBasisNative || res.TokenEvents[0].GenTimingV != 1 {
		t.Fatalf("token GenMs/GenBasis/GenTimingV = %d/%q/%d, want 42356/native/1",
			res.TokenEvents[0].GenMs, res.TokenEvents[0].GenBasis, res.TokenEvents[0].GenTimingV)
	}

	stat, _ := os.Stat(path)
	if res.NewOffset != stat.Size() {
		t.Fatalf("NewOffset: got %d want %d", res.NewOffset, stat.Size())
	}
}

// TestDecodeFileURI deleted in v1.6.29 — the standalone decodeFileURI
// helper was removed when workspaceFolderFromMetadata migrated to
// pathnorm.NormalizeWithFormat. URI-decoding behaviour is now pinned
// by the format-matrix tests at internal/platform/pathnorm/pathnorm_test.go
// (FormatFileURI rows).

func TestParseSessionFile_MalformedLineSkipped(t *testing.T) {
	path := writeFixture(t, []string{
		`{"ts":1,"sid":"sess-1","type":"user_message","spanId":"u1","attrs":{"content":"hello"}}`,
		`{not json}`,
		`{"ts":2,"sid":"sess-1","type":"agent_response","spanId":"a1","attrs":{"response":"[{\"role\":\"assistant\",\"parts\":[{\"type\":\"text\",\"content\":\"done\"}]}]"}}`,
	})

	res, err := New().ParseSessionFile(context.Background(), path, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	if len(res.ToolEvents) != 2 {
		t.Fatalf("ToolEvents: got %d want 2", len(res.ToolEvents))
	}
	if len(res.Warnings) != 1 {
		t.Fatalf("Warnings: got %d want 1", len(res.Warnings))
	}
}

// TestParseSessionFile_LLMRequestGenMs is table-driven over the legacy
// debug-log llm_request line's "dur" field (rawLine.DurationMS, adapter.go
// ~L122) -> TokenEvent.GenMs, covering the zero/missing negative shapes
// the happy-path test doesn't exercise.
func TestParseSessionFile_LLMRequestGenMs(t *testing.T) {
	llmLine := func(dur string) string {
		return `{"ts":1776928112610,` + dur + `"sid":"sess-1","type":"llm_request","name":"chat:m","spanId":"llm-1","attrs":{"model":"m","inputTokens":10,"outputTokens":5}}`
	}
	tests := []struct {
		name      string
		durField  string // e.g. `"dur":42356,` or "" to omit
		wantStamp bool
		wantGenMs int64
	}{
		{"positive stamps verbatim (already ms)", `"dur":42356,`, true, 42356},
		{"field omitted leaves unset", "", false, 0},
		{"zero leaves unset", `"dur":0,`, false, 0},
		{"negative leaves unset", `"dur":-5,`, false, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := writeFixture(t, []string{llmLine(tt.durField)})
			res, err := New().ParseSessionFile(context.Background(), path, 0)
			if err != nil {
				t.Fatalf("ParseSessionFile: %v", err)
			}
			if len(res.TokenEvents) != 1 {
				t.Fatalf("TokenEvents: got %d want 1", len(res.TokenEvents))
			}
			ev := res.TokenEvents[0]
			if tt.wantStamp {
				if ev.GenMs != tt.wantGenMs || ev.GenBasis != models.GenBasisNative || ev.GenTimingV != 1 {
					t.Errorf("GenMs/GenBasis/GenTimingV = %d/%q/%d, want %d/native/1", ev.GenMs, ev.GenBasis, ev.GenTimingV, tt.wantGenMs)
				}
			} else if ev.GenMs != 0 || ev.GenBasis != "" || ev.GenTimingV != 0 {
				t.Errorf("GenMs/GenBasis/GenTimingV = %d/%q/%d, want zero value (no stamp)", ev.GenMs, ev.GenBasis, ev.GenTimingV)
			}
		})
	}
}

// TestParseSessionFile_ReasoningNeverMintsAnAction is the B3 regression
// pin for the CLI-debug-log path: `agent_response.attrs.reasoning`
// produces NO action row of its own, only the sibling assistant_message
// row's PrecedingReasoning — and a reasoning-only agent_response (no
// response text) produces nothing at all, since there is no successor
// event to carry it.
func TestParseSessionFile_ReasoningNeverMintsAnAction(t *testing.T) {
	lines := []string{
		`{"v":1,"ts":1776928112439,"dur":0,"sid":"sess-b3","type":"session_start","name":"session_start","spanId":"session-start","status":"ok","attrs":{"copilotVersion":"0.45.0"}}`,
		`{"ts":1776928112440,"dur":0,"sid":"sess-b3","type":"user_message","name":"user_message","spanId":"user-1","status":"ok","attrs":{"content":"do the thing"}}`,
		// Reasoning-only agent_response — nothing to carry it.
		`{"ts":1776928154900,"dur":0,"sid":"sess-b3","type":"agent_response","name":"agent_response","spanId":"agent-0","parentSpanId":"user-1","status":"ok","attrs":{"reasoning":"LONELY_REASONING"}}`,
		// Reasoning + response text — the assistant row carries it.
		`{"ts":1776928154966,"dur":0,"sid":"sess-b3","type":"agent_response","name":"agent_response","spanId":"agent-1","parentSpanId":"user-1","status":"ok","attrs":{"response":"[{\"role\":\"assistant\",\"parts\":[{\"type\":\"text\",\"content\":\"Done.\"}]}]","reasoning":"THREADED_REASONING"}}`,
	}
	path := writeFixture(t, lines)

	res, err := New().ParseSessionFile(context.Background(), path, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	var assistantRows int
	for _, ev := range res.ToolEvents {
		if strings.Contains(strings.ToLower(ev.RawToolName), "reasoning") {
			t.Fatalf("reasoning-named action row emitted: raw=%q %#v", ev.RawToolName, ev)
		}
		if ev.Target == "LONELY_REASONING" || ev.ToolOutput == "LONELY_REASONING" ||
			ev.Target == "THREADED_REASONING" || ev.ToolOutput == "THREADED_REASONING" {
			t.Fatalf("reasoning body surfaced as action content: %#v", ev)
		}
		if ev.ActionType != models.ActionAssistantMessage {
			continue
		}
		assistantRows++
		if ev.PrecedingReasoning != "THREADED_REASONING" {
			t.Errorf("assistant PrecedingReasoning = %q, want THREADED_REASONING", ev.PrecedingReasoning)
		}
	}
	if assistantRows != 1 {
		t.Fatalf("assistant_message rows = %d, want 1 (the reasoning-only response emits nothing): %#v",
			assistantRows, res.ToolEvents)
	}
}
