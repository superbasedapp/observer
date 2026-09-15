package openclaw

import (
	"context"
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	_ "modernc.org/sqlite"

	"github.com/marmutapp/superbased-observer/internal/models"
)

func TestParseSessionFile_TaskRunsCapturesPromptAndCompletion(t *testing.T) {
	root := t.TempDir()
	dbPath := filepath.Join(root, "runs.sqlite")
	setupTaskRunsDB(t, dbPath)

	a := NewWithOptions(nil, []string{root})
	res, err := a.ParseSessionFile(context.Background(), dbPath, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	if got := len(res.ToolEvents); got != 2 {
		t.Fatalf("expected 2 events, got %d", got)
	}
	if got := res.ToolEvents[0].ActionType; got != models.ActionUserPrompt {
		t.Fatalf("first event action_type = %q, want %q", got, models.ActionUserPrompt)
	}
	if got := res.ToolEvents[0].Target; got != "Say hello from OpenClaw setup smoke test." {
		t.Fatalf("prompt target = %q", got)
	}
	if got := res.ToolEvents[1].ActionType; got != models.ActionTaskComplete {
		t.Fatalf("second event action_type = %q, want %q", got, models.ActionTaskComplete)
	}
	if res.ToolEvents[1].Success {
		t.Fatalf("failed task should not be successful")
	}
	if got := res.ToolEvents[1].DurationMs; got != 7258 {
		t.Fatalf("duration = %d, want 7258", got)
	}
	if res.NewOffset != 1776892389769 {
		t.Fatalf("NewOffset = %d", res.NewOffset)
	}
}

func TestParseSessionFile_TaskRunsWatermarkSkipsOldRows(t *testing.T) {
	root := t.TempDir()
	dbPath := filepath.Join(root, "runs.sqlite")
	setupTaskRunsDB(t, dbPath)

	a := NewWithOptions(nil, []string{root})
	res, err := a.ParseSessionFile(context.Background(), dbPath, 1776892389769)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	if len(res.ToolEvents) != 0 {
		t.Fatalf("expected no events, got %d", len(res.ToolEvents))
	}
	if res.NewOffset != 1776892389769 {
		t.Fatalf("NewOffset = %d", res.NewOffset)
	}
}

func TestParseSessionFile_TaskRunsSuppressesRowsWhenSessionTraceExists(t *testing.T) {
	root := t.TempDir()
	dbPath := filepath.Join(root, "tasks", "runs.sqlite")
	setupTaskRunsDB(t, dbPath)
	indexPath := filepath.Join(root, "agents", "main", "sessions", "sessions.json")
	if err := os.MkdirAll(filepath.Dir(indexPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(indexPath, []byte(`{
		"agent:main:explicit:observer-smoke": {
			"sessionId": "observer-smoke",
			"sessionFile": "C:\\Users\\marmu\\.openclaw\\agents\\main\\sessions\\ced44276-571e-4bc8-8777-e6653fc1634d.jsonl"
		}
	}`), 0o644); err != nil {
		t.Fatal(err)
	}

	a := NewWithOptions(nil, []string{root})
	res, err := a.ParseSessionFile(context.Background(), dbPath, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	if got := len(res.ToolEvents); got != 0 {
		t.Fatalf("expected task-run rows to be suppressed, got %d", got)
	}
}

func TestParseSessionFile_SessionsIndexSkipsEntriesWithSessionFile(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "sessions.json")
	body := `{
		"agent:main:explicit:observer-ollama-gemma4-smoke": {
			"sessionId": "9ca34b34-65cb-4389-9f52-522f3f962144",
			"updatedAt": 1776893738354,
			"status": "succeeded",
			"endedAt": 1776893738354,
			"runtimeMs": 44486,
			"sessionFile": "C:\\Users\\marmu\\.openclaw\\agents\\main\\sessions\\9ca34b34-65cb-4389-9f52-522f3f962144.jsonl"
		}
	}`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}

	a := NewWithOptions(nil, []string{root})
	res, err := a.ParseSessionFile(context.Background(), path, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	if got := len(res.ToolEvents); got != 0 {
		t.Fatalf("expected session-index completion to be suppressed, got %d", got)
	}
}

func TestParseSessionFile_JSONLCapturesMessagesToolsAndUsage(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "session.jsonl")
	body := strings.Join([]string{
		`{"type":"session","version":3,"id":"ses_1","timestamp":"2026-04-22T21:34:53.850Z","cwd":"D:\\work\\openclaw"}`,
		`{"type":"model_change","id":"m1","timestamp":"2026-04-22T21:34:53.855Z","provider":"ollama","modelId":"gemma4:e4b"}`,
		`{"type":"message","id":"u1","timestamp":"2026-04-22T21:34:53.870Z","message":{"role":"user","content":[{"type":"text","text":"Read the file"}],"timestamp":1776893693868}}`,
		`{"type":"message","id":"a1","timestamp":"2026-04-22T21:35:24.489Z","message":{"role":"assistant","content":[{"type":"toolCall","id":"call_1","name":"read","arguments":{"path":"BOOTSTRAP.md"}}],"stopReason":"toolUse","provider":"ollama","model":"gemma4:e4b","usage":{"input":10,"output":2,"cacheRead":1,"cacheWrite":0,"totalTokens":12},"timestamp":1776893724488}}`,
		`{"type":"message","id":"r1","timestamp":"2026-04-22T21:35:24.536Z","message":{"role":"toolResult","toolCallId":"call_1","toolName":"read","content":[{"type":"text","text":"hello"}],"isError":false,"timestamp":1776893724520}}`,
		`{"type":"message","id":"a2","timestamp":"2026-04-22T21:35:38.353Z","message":{"role":"assistant","content":[{"type":"text","text":"Done"}],"stopReason":"stop","provider":"ollama","model":"gemma4:e4b","usage":{"input":20,"output":3,"cacheRead":0,"cacheWrite":0,"totalTokens":23},"timestamp":1776893738351}}`,
		"",
	}, "\n")
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}

	a := NewWithOptions(nil, []string{root})
	res, err := a.ParseSessionFile(context.Background(), path, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	// v1.4.49: line 130's assistant message ("Done", stopReason=stop) now
	// emits BOTH the new `openclaw.assistant_text` row AND the existing
	// `message.assistant.stop` marker row. Total: 4 events.
	//   [0] user_prompt              (from u1)
	//   [1] ReadFile (toolCall)      (from a1)
	//   [2] openclaw.assistant_text  (from a2 text part "Done")
	//   [3] message.assistant.stop   (from a2 stopReason=stop)
	if got := len(res.ToolEvents); got != 4 {
		t.Fatalf("expected 4 tool events, got %d", got)
	}
	if got := res.ToolEvents[0].ActionType; got != models.ActionUserPrompt {
		t.Fatalf("first action_type = %q", got)
	}
	if got := res.ToolEvents[0].MessageID; got != "user:u1" {
		t.Fatalf("user message_id = %q", got)
	}
	if got := res.ToolEvents[1].ActionType; got != models.ActionReadFile {
		t.Fatalf("second action_type = %q", got)
	}
	if got := res.ToolEvents[1].MessageID; got != "a1" {
		t.Fatalf("tool message_id = %q", got)
	}
	if got := res.ToolEvents[1].Target; got != "BOOTSTRAP.md" {
		t.Fatalf("tool target = %q", got)
	}
	if got := res.ToolEvents[1].ToolOutput; got != "hello" {
		t.Fatalf("tool output = %q", got)
	}
	// Index [2] is the new openclaw.assistant_text row (emitted in
	// content-block order, before stopReason-marker emission).
	if got := res.ToolEvents[2].RawToolName; got != "openclaw.assistant_text" {
		t.Fatalf("third raw_tool_name = %q want openclaw.assistant_text", got)
	}
	if got := res.ToolEvents[2].ToolOutput; got != "Done" {
		t.Fatalf("third tool_output = %q want Done", got)
	}
	if got := res.ToolEvents[3].ActionType; got != models.ActionTaskComplete {
		t.Fatalf("fourth action_type = %q", got)
	}
	if got := res.ToolEvents[3].RawToolName; got != "message.assistant.stop" {
		t.Fatalf("fourth raw_tool_name = %q want message.assistant.stop", got)
	}
	if res.ToolEvents[3].Metadata == nil || res.ToolEvents[3].Metadata.StopReason != "stop" {
		t.Fatalf("task_complete StopReason = %+v want stop", res.ToolEvents[3].Metadata)
	}
	if got := res.ToolEvents[3].MessageID; got != "a2" {
		t.Fatalf("task_complete message_id = %q", got)
	}
	if got := len(res.TokenEvents); got != 2 {
		t.Fatalf("expected 2 token events, got %d", got)
	}
	if got := res.TokenEvents[0].Model; got != "ollama/gemma4:e4b" {
		t.Fatalf("token model = %q", got)
	}
	if got := res.TokenEvents[0].MessageID; got != "a1" {
		t.Fatalf("token[0] message_id = %q", got)
	}
	if got := res.TokenEvents[1].MessageID; got != "a2" {
		t.Fatalf("token[1] message_id = %q", got)
	}
}

// TestParseSessionFile_JSONLEmitsAPIErrorOnStopReasonError pins the
// v1.4.22 stopReason="error" → ActionAPIError parity. Real openclaw
// JSONL emits an empty-content assistant message with stopReason="error"
// and an `errorMessage` field carrying the upstream provider's verbatim
// response (e.g. `400 {"error":"...does not support tools"}`). Pre-fix
// these were silently dropped because the existing stop-reason gate
// only fired on "stop".
func TestParseSessionFile_JSONLEmitsAPIErrorOnStopReasonError(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "session.jsonl")
	body := strings.Join([]string{
		`{"type":"session","version":3,"id":"ses_e","timestamp":"2026-04-22T21:33:00.000Z","cwd":"D:\\work\\openclaw"}`,
		`{"type":"model_change","id":"m1","timestamp":"2026-04-22T21:33:00.500Z","provider":"ollama","modelId":"gemma3:1b"}`,
		`{"type":"message","id":"u1","timestamp":"2026-04-22T21:33:01.000Z","message":{"role":"user","content":[{"type":"text","text":"do thing"}],"timestamp":1776893581000}}`,
		`{"type":"message","id":"a_err","timestamp":"2026-04-22T21:33:10.063Z","message":{"role":"assistant","content":[],"stopReason":"error","provider":"ollama","model":"gemma3:1b","errorMessage":"400 {\"error\":\"registry.ollama.ai/library/gemma3:1b does not support tools\"}","usage":{"input":0,"output":0,"cacheRead":0,"cacheWrite":0,"totalTokens":0}}}`,
		"",
	}, "\n")
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}

	a := NewWithOptions(nil, []string{root})
	res, err := a.ParseSessionFile(context.Background(), path, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	// 1 user_prompt + 1 api_error
	if got := len(res.ToolEvents); got != 2 {
		t.Fatalf("expected 2 tool events, got %d", got)
	}
	row := res.ToolEvents[1]
	if row.ActionType != models.ActionAPIError {
		t.Errorf("action: %s want api_error", row.ActionType)
	}
	if row.Success {
		t.Errorf("api_error row should be Success=false")
	}
	if row.Target != "http_400" {
		t.Errorf("target: %q want http_400 (status-prefix discriminator)", row.Target)
	}
	if !strings.Contains(row.ErrorMessage, "does not support tools") {
		t.Errorf("error_message: %q", row.ErrorMessage)
	}
	if row.RawToolName != "http_400" {
		t.Errorf("raw_tool_name: %q want http_400", row.RawToolName)
	}
}

// TestParseSessionFile_JSONLEmitsSystemPromptOnBootstrapContext pins
// the v1.4.23 capture for openclaw custom/openclaw:bootstrap-context:full
// events. The data payload in observed corpora is just a marker
// (timestamp + runId + sessionId, no embedded prompt body) — pre-fix
// these were silently dropped because the adapter had no `case
// "custom":`. Per user direction (2026-05-01) we capture the marker
// anyway as ActionSystemPrompt with the data JSON in RawToolInput,
// hash-deduped so duplicate emissions on resume only land once.
// model-snapshot custom events stay no-op'd (redundant with
// model_change which already lifts provider+model).
func TestParseSessionFile_JSONLEmitsSystemPromptOnBootstrapContext(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "session.jsonl")
	body := strings.Join([]string{
		`{"type":"session","version":3,"id":"ses_b","timestamp":"2026-04-22T21:35:00.000Z","cwd":"D:\\work\\openclaw"}`,
		`{"type":"custom","customType":"model-snapshot","data":{"timestamp":1776893693864,"provider":"ollama","modelApi":"ollama","modelId":"gemma4:e4b"}}`,
		`{"type":"custom","customType":"openclaw:bootstrap-context:full","data":{"timestamp":1776893738357,"runId":"r1","sessionId":"ses_b"}}`,
		`{"type":"custom","customType":"openclaw:bootstrap-context:full","data":{"timestamp":1776893738357,"runId":"r1","sessionId":"ses_b"}}`,
		"",
	}, "\n")
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}

	a := NewWithOptions(nil, []string{root})
	res, err := a.ParseSessionFile(context.Background(), path, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	var sysPrompts []models.ToolEvent
	for _, ev := range res.ToolEvents {
		if ev.ActionType == models.ActionSystemPrompt {
			sysPrompts = append(sysPrompts, ev)
		}
	}
	// 2 identical bootstrap-context events → 1 row (dedup'd).
	// 1 model-snapshot → 0 rows (no-op'd).
	if len(sysPrompts) != 1 {
		t.Fatalf("system_prompt rows: %d want 1 (duplicate bootstrap dedup'd, model-snapshot ignored)", len(sysPrompts))
	}
	row := sysPrompts[0]
	if row.RawToolName != "system_prompt.bootstrap" {
		t.Errorf("raw_tool_name: %q want system_prompt.bootstrap", row.RawToolName)
	}
	if !strings.Contains(row.Target, "bootstrap-context") {
		t.Errorf("target: %q", row.Target)
	}
	if !strings.Contains(row.RawToolInput, "runId") {
		t.Errorf("raw_tool_input should include runId field: %q", row.RawToolInput)
	}
	if !strings.HasPrefix(row.MessageID, "system:") {
		t.Errorf("message_id: %q want 'system:<hash>'", row.MessageID)
	}
}

func TestParseSessionFile_JSONLUsesSessionsIndexAlias(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "sessions.json"), []byte(`{
		"agent:main:explicit:observer-ollama-gemma4-smoke": {
			"sessionId": "9ca34b34-65cb-4389-9f52-522f3f962144",
			"modelProvider": "ollama",
			"model": "gemma4:e4b",
			"sessionFile": "C:\\Users\\marmu\\.openclaw\\agents\\main\\sessions\\9ca34b34-65cb-4389-9f52-522f3f962144.jsonl",
			"systemPromptReport": {
				"workspaceDir": "C:\\Users\\marmu\\.openclaw\\workspace",
				"sessionKey": "agent:main:explicit:observer-ollama-gemma4-smoke",
				"provider": "ollama",
				"model": "gemma4:e4b"
			}
		}
	}`), 0o644); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "9ca34b34-65cb-4389-9f52-522f3f962144.jsonl")
	body := strings.Join([]string{
		`{"type":"session","version":3,"id":"9ca34b34-65cb-4389-9f52-522f3f962144","timestamp":"2026-04-22T21:34:53.850Z","cwd":"C:\\Users\\marmu\\.openclaw\\workspace"}`,
		`{"type":"model_change","id":"m1","timestamp":"2026-04-22T21:34:53.855Z","provider":"ollama","modelId":"gemma4:e4b"}`,
		`{"type":"message","id":"a1","timestamp":"2026-04-22T21:35:24.489Z","message":{"role":"assistant","content":[{"type":"toolCall","id":"call_1","name":"read","arguments":{"path":"BOOTSTRAP.md"}}],"stopReason":"toolUse","provider":"ollama","model":"gemma4:e4b","usage":{"input":10,"output":2,"cacheRead":1,"cacheWrite":0,"totalTokens":12},"timestamp":1776893724488}}`,
		"",
	}, "\n")
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}

	a := NewWithOptions(nil, []string{root})
	res, err := a.ParseSessionFile(context.Background(), path, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	if len(res.ToolEvents) != 1 || len(res.TokenEvents) != 1 {
		t.Fatalf("unexpected counts: tools=%d tokens=%d", len(res.ToolEvents), len(res.TokenEvents))
	}
	if got := res.ToolEvents[0].SessionID; got != "agent:main:explicit:observer-ollama-gemma4-smoke" {
		t.Fatalf("tool session_id = %q", got)
	}
	if got := res.TokenEvents[0].SessionID; got != "agent:main:explicit:observer-ollama-gemma4-smoke" {
		t.Fatalf("token session_id = %q", got)
	}
	if got := res.TokenEvents[0].Model; got != "ollama/gemma4:e4b" {
		t.Fatalf("token model = %q", got)
	}
}

// TestMapToolName_SessionsSpawnIsSubagent pins the parity fix: sessions_spawn
// is OpenClaw's sub-agent invocation. It used to be bucketed with the rest of
// sessions_* / agents_* / gateway calls under ActionMCPCall, which hid agent
// fan-out from dashboard counts that key off ActionSpawnSubagent.
func TestMapToolName_SessionsSpawnIsSubagent(t *testing.T) {
	if got := mapToolName("sessions_spawn"); got != models.ActionSpawnSubagent {
		t.Errorf("mapToolName(sessions_spawn) = %q, want %q", got, models.ActionSpawnSubagent)
	}
	// The other sessions_* tools stay as MCP calls — they're not spawns.
	for _, n := range []string{
		"agents_list", "canvas", "cron", "gateway", "memory_get", "message",
		"nodes", "session_status", "sessions_history", "sessions_list",
		"sessions_send", "sessions_yield", "subagents", "tts",
	} {
		if got := mapToolName(n); got != models.ActionMCPCall {
			t.Errorf("mapToolName(%q) = %q, want %q (still mcp_call)", n, got, models.ActionMCPCall)
		}
	}
	if got := mapToolName("process"); got != models.ActionRunCommand {
		t.Errorf("mapToolName(process) = %q, want %q", got, models.ActionRunCommand)
	}
}

// TestParseSessionFile_JSONLPropagatesPrecedingTextToToolCalls pins
// the parity fix: the assistant's text/thinking content that introduces
// a tool call now flows through to the tool event's PrecedingReasoning,
// the same way claudecode and pi do it. Pre-fix the field was always
// empty for OpenClaw jsonl tool calls.
func TestParseSessionFile_JSONLPropagatesPrecedingTextToToolCalls(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "session.jsonl")
	body := strings.Join([]string{
		`{"type":"session","version":3,"id":"ses_1","timestamp":"2026-04-22T21:34:53.850Z","cwd":"/tmp/oc"}`,
		`{"type":"message","id":"a1","timestamp":"2026-04-22T21:35:24.489Z","message":{"role":"assistant","content":[{"type":"text","text":"I'll inspect BOOTSTRAP.md to understand the layout."},{"type":"toolCall","id":"call_1","name":"read","arguments":{"path":"BOOTSTRAP.md"}},{"type":"toolCall","id":"call_2","name":"read","arguments":{"path":"README.md"}},{"type":"text","text":"Now I'll search."},{"type":"toolCall","id":"call_3","name":"memory_search","arguments":{"query":"hello"}}],"stopReason":"toolUse","provider":"ollama","model":"gemma4:e4b","timestamp":1776893724488}}`,
		"",
	}, "\n")
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}

	a := NewWithOptions(nil, []string{root})
	res, err := a.ParseSessionFile(context.Background(), path, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	// v1.4.49: each `type:"text"` part on an assistant message now emits
	// a standalone `openclaw.assistant_text` row in content-block order,
	// so the full event sequence is:
	//   [0] openclaw.assistant_text — "I'll inspect..."
	//   [1] toolCall read BOOTSTRAP.md
	//   [2] toolCall read README.md
	//   [3] openclaw.assistant_text — "Now I'll search."
	//   [4] toolCall memory_search
	if len(res.ToolEvents) != 5 {
		t.Fatalf("expected 5 tool events, got %d", len(res.ToolEvents))
	}
	// Filter to just tool calls so the preceding-reasoning assertions
	// remain ordering-stable across future emission tweaks.
	var tools []models.ToolEvent
	for _, ev := range res.ToolEvents {
		if ev.RawToolName != "openclaw.assistant_text" {
			tools = append(tools, ev)
		}
	}
	if len(tools) != 3 {
		t.Fatalf("expected 3 tool_use rows, got %d", len(tools))
	}
	// Both tool calls that follow the same text inherit the same preamble.
	preamble := "I'll inspect BOOTSTRAP.md to understand the layout."
	if got := tools[0].PrecedingReasoning; got != preamble {
		t.Errorf("tool[0] PrecedingReasoning = %q, want %q", got, preamble)
	}
	if got := tools[1].PrecedingReasoning; got != preamble {
		t.Errorf("tool[1] PrecedingReasoning = %q, want %q", got, preamble)
	}
	// The third tool call follows a fresh text part — it should pick up the new one.
	if got := tools[2].PrecedingReasoning; got != "Now I'll search." {
		t.Errorf("tool[2] PrecedingReasoning = %q, want %q", got, "Now I'll search.")
	}
}

// TestParseSessionFile_TaskRunsLiftsModelFromSessionsAlias pins the
// parity fix: the sqlite path now backfills Model + ProjectRoot from
// the matching sessions.json alias instead of emitting empty model
// strings + the literal "[openclaw]" placeholder. The alias's
// systemPromptReport carries provider/model + workspaceDir.
func TestParseSessionFile_TaskRunsLiftsModelFromSessionsAlias(t *testing.T) {
	root := t.TempDir()
	dbPath := filepath.Join(root, "tasks", "runs.sqlite")
	setupTaskRunsDB(t, dbPath)
	indexPath := filepath.Join(root, "agents", "main", "sessions", "sessions.json")
	if err := os.MkdirAll(filepath.Dir(indexPath), 0o755); err != nil {
		t.Fatal(err)
	}
	workspaceDir := filepath.Join(root, "openclaw-ws")
	if err := os.MkdirAll(workspaceDir, 0o755); err != nil {
		t.Fatal(err)
	}
	// Note the absence of `sessionFile` — without it suppressTaskRun keeps
	// the row, so it reaches taskPromptEvent / taskCompleteEvent and the
	// alias's model + workspaceDir flow through.
	if err := os.WriteFile(indexPath, []byte(`{
		"agent:main:explicit:observer-smoke": {
			"sessionId": "observer-smoke",
			"modelProvider": "anthropic",
			"model": "claude-sonnet-4-5",
			"systemPromptReport": {
				"workspaceDir": `+jsonString(workspaceDir)+`,
				"provider": "anthropic",
				"model": "claude-sonnet-4-5"
			}
		}
	}`), 0o644); err != nil {
		t.Fatal(err)
	}

	a := NewWithOptions(nil, []string{root})
	res, err := a.ParseSessionFile(context.Background(), dbPath, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	if len(res.ToolEvents) != 2 {
		t.Fatalf("expected 2 events, got %d", len(res.ToolEvents))
	}
	wantModel := "anthropic/claude-sonnet-4-5"
	if res.ToolEvents[0].Model != wantModel {
		t.Errorf("prompt model = %q, want %q", res.ToolEvents[0].Model, wantModel)
	}
	if res.ToolEvents[1].Model != wantModel {
		t.Errorf("complete model = %q, want %q", res.ToolEvents[1].Model, wantModel)
	}
	// ProjectRoot lifted from systemPromptReport.workspaceDir; resolveProjectRoot
	// returns it unchanged because the temp workspace isn't a git repo.
	if res.ToolEvents[0].ProjectRoot != workspaceDir {
		t.Errorf("prompt project_root = %q, want %q", res.ToolEvents[0].ProjectRoot, workspaceDir)
	}
}

func TestParseSessionFile_SessionsIndexUsesCanonicalSessionKey(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "sessions.json")
	if err := os.WriteFile(path, []byte(`{
		"agent:main:explicit:observer-smoke": {
			"sessionId": "observer-smoke",
			"status": "succeeded",
			"updatedAt": 1776893738357,
			"endedAt": 1776893738357,
			"runtimeMs": 7258,
			"systemPromptReport": {
				"sessionKey": "agent:main:explicit:observer-smoke"
			}
		}
	}`), 0o644); err != nil {
		t.Fatal(err)
	}

	a := NewWithOptions(nil, []string{root})
	res, err := a.ParseSessionFile(context.Background(), path, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	if len(res.ToolEvents) != 1 {
		t.Fatalf("expected 1 tool event, got %d", len(res.ToolEvents))
	}
	if got := res.ToolEvents[0].SessionID; got != "agent:main:explicit:observer-smoke" {
		t.Fatalf("session_id = %q, want canonical alias key", got)
	}
}

func TestResolveProjectRoot_PreservesUnreachableForeignPath(t *testing.T) {
	a := NewWithOptions(nil, []string{t.TempDir()})
	const foreign = `C:\definitely-missing\observer-openclaw`
	if got, _ := a.resolveProjectRoot(foreign, map[string]projectGitInfo{}); got != foreign {
		t.Fatalf("resolveProjectRoot(%q) = %q, want unchanged foreign path", foreign, got)
	}
}

func jsonString(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

func setupTaskRunsDB(t *testing.T, path string) {
	t.Helper()

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	stmts := []string{
		`CREATE TABLE task_runs (
			task_id TEXT PRIMARY KEY,
			runtime TEXT NOT NULL,
			task_kind TEXT,
			source_id TEXT,
			requester_session_key TEXT,
			owner_key TEXT NOT NULL,
			scope_kind TEXT NOT NULL,
			child_session_key TEXT,
			parent_flow_id TEXT,
			parent_task_id TEXT,
			agent_id TEXT,
			run_id TEXT,
			label TEXT,
			task TEXT NOT NULL,
			status TEXT NOT NULL,
			delivery_status TEXT NOT NULL,
			notify_policy TEXT NOT NULL,
			created_at INTEGER NOT NULL,
			started_at INTEGER,
			ended_at INTEGER,
			last_event_at INTEGER,
			cleanup_after INTEGER,
			error TEXT,
			progress_summary TEXT,
			terminal_summary TEXT,
			terminal_outcome TEXT
		)`,
		`INSERT INTO task_runs (
			task_id, runtime, source_id, requester_session_key, owner_key,
			scope_kind, child_session_key, agent_id, run_id, label, task, status,
			delivery_status, notify_policy, created_at, started_at, ended_at,
			last_event_at, cleanup_after, error, progress_summary,
			terminal_summary, terminal_outcome
		) VALUES (
			'task_1', 'cli', 'run_1', 'agent:main:explicit:observer-smoke',
			'agent:main:explicit:observer-smoke', 'session',
			'agent:main:explicit:observer-smoke', 'main', 'run_1', '',
			'[Thu 2026-04-23 02:42 GMT+5:30] Say hello from OpenClaw setup smoke test.',
			'failed', 'not_applicable', 'silent', 1776892338035, 1776892382511,
			1776892389769, 1776892389769, 1777497189769,
			'No API key found for provider "openai".', '', '', ''
		)`,
	}
	for _, stmt := range stmts {
		if _, err := db.Exec(stmt); err != nil {
			t.Fatalf("exec %q: %v", stmt, err)
		}
	}
}

// TestParseTrajectoryJSONL pins extraction of accurate per-call token usage
// from a *.trajectory.jsonl trace (model.completed → lastCallUsage), the
// real source when the plain message log is gateway-zeroed. Shape mirrors
// the 2026-06-26 live WSL capture (provider=openai-codex, NET input).
func TestParseTrajectoryJSONL(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, ".openclaw", "agents", "main", "sessions")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	sid := "4de1bfff-50c3-4d6d-adab-9f04fd6ca18a"
	path := filepath.Join(dir, sid+".trajectory.jsonl")
	lines := []string{
		`{"type":"session.started","ts":"2026-06-26T07:15:00.000Z","sessionId":"` + sid + `"}`,
		`{"type":"model.completed","ts":"2026-06-26T07:15:24.820Z","seq":5,"sessionId":"` + sid + `","runId":"r1","provider":"openai-codex","modelId":"gpt-5.5","data":{"usage":{"input":29831,"output":136,"total":29967},"promptCache":{"lastCallUsage":{"input":15133,"output":89,"cacheRead":0,"cacheWrite":0,"total":15222}}}}`,
		`{"type":"model.completed","ts":"2026-06-26T07:16:10.000Z","seq":5,"sessionId":"` + sid + `","runId":"r2","provider":"openai-codex","modelId":"gpt-5.5","data":{"usage":{"input":2654,"output":387,"total":48097},"promptCache":{"lastCallUsage":{"input":302,"output":140,"cacheRead":15872,"cacheWrite":0,"total":16314}}}}`,
		`{"type":"model.completed","ts":"2026-06-26T07:17:00.000Z","sessionId":"` + sid + `","runId":"r3","provider":"openai-codex","modelId":"gpt-5.5","data":{"promptCache":{"lastCallUsage":{"input":0,"output":0,"cacheRead":0,"cacheWrite":0,"total":0}}}}`,
	}
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	a := NewWithOptions(nil, []string{root})
	res, err := a.ParseSessionFile(context.Background(), path, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	// Two non-zero model.completed events → 2 token rows; the empty one skipped.
	if len(res.TokenEvents) != 2 {
		t.Fatalf("TokenEvents = %d, want 2", len(res.TokenEvents))
	}
	e := res.TokenEvents[1] // the cached call
	if e.InputTokens != 302 || e.OutputTokens != 140 || e.CacheReadTokens != 15872 {
		t.Errorf("cached call tokens wrong: in=%d out=%d cR=%d (want 302/140/15872)", e.InputTokens, e.OutputTokens, e.CacheReadTokens)
	}
	if e.Model != "gpt-5.5" {
		t.Errorf("model = %q, want gpt-5.5", e.Model)
	}
	if e.SessionID != sid {
		t.Errorf("session = %q", e.SessionID)
	}
	// Determinism: a full re-parse yields identical SourceEventIDs.
	res2, _ := a.ParseSessionFile(context.Background(), path, 0)
	for i := range res.TokenEvents {
		if res.TokenEvents[i].SourceEventID != res2.TokenEvents[i].SourceEventID {
			t.Errorf("SourceEventID drift at %d: %q vs %q", i, res.TokenEvents[i].SourceEventID, res2.TokenEvents[i].SourceEventID)
		}
	}
}

// --- WP-T6 O1 / O2 -----------------------------------------------------
//
// The fixtures below are a scrubbed transposition of the 2026-07-31 live
// probe (`openclaw agent --local --agent main --session-id wpt6probe`):
// sessions.json keyed "agent:main:explicit:<stem>" with sessionId = the
// stem, a message log carrying per-call usage, and a trajectory whose lone
// model.completed repeats the LAST call.

const (
	wpSessionKey = "agent:main:explicit:probe"
	wpStem       = "probe"
	wpWorkspace  = "/nonexistent/openclaw/workspace"
	// The verbatim bootstrap preamble OpenClaw's buildAgentUserPromptPrefix
	// emits in "full" mode, joined to the operator's prompt with "\n\n".
	wpBootstrapPrefix = "[Bootstrap pending]\n" +
		"Please read BOOTSTRAP.md from the workspace and follow it before replying normally.\n" +
		"If this run can complete the BOOTSTRAP.md workflow, do so.\n" +
		"If it cannot, explain the blocker briefly, continue with any bootstrap steps that are still possible here, and offer the simplest next step.\n" +
		"Do not pretend bootstrap is complete when it is not.\n" +
		"Do not use a generic first greeting or reply normally until after you have handled BOOTSTRAP.md.\n" +
		"Your first user-visible reply for a bootstrap-pending workspace must follow BOOTSTRAP.md, not a generic greeting."
	wpHumanPrompt = "Read /tmp/wpt6/openclaw/hello.txt, then create /tmp/wpt6/openclaw/probe_out.txt containing DONE, then run the shell command: echo probe-marker-openclaw"
)

// writeWPFixture lays down sessions.json + the message log + the trajectory
// for one run. lastCallZeroed simulates a gateway-injected final turn (usage
// all zero) so the trajectory becomes that call's only token source.
func writeWPFixture(t *testing.T, lastCallZeroed bool) (dir, msgLog, traj string) {
	t.Helper()
	dir = t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "sessions.json"), []byte(`{
		"`+wpSessionKey+`": {
			"sessionId": "`+wpStem+`",
			"modelProvider": "openai",
			"model": "gpt-5.4-nano",
			"sessionFile": "`+filepath.ToSlash(filepath.Join(dir, wpStem+".jsonl"))+`",
			"systemPromptReport": {
				"workspaceDir": "`+wpWorkspace+`",
				"sessionKey": "`+wpSessionKey+`",
				"provider": "openai",
				"model": "gpt-5.4-nano"
			}
		}
	}`), 0o644); err != nil {
		t.Fatal(err)
	}

	// Two model calls. ts 1785498612187 (14228/149/0) then ts 1785498625318
	// (368/542/14848) — the second is the one the trajectory repeats.
	lastUsage := `{"input":368,"output":542,"cacheRead":14848,"cacheWrite":0,"totalTokens":15758}`
	lastModel := "gpt-5.4-nano"
	if lastCallZeroed {
		lastUsage = `{"input":0,"output":0,"cacheRead":0,"cacheWrite":0,"totalTokens":0}`
		lastModel = "gateway-injected"
	}
	msgLog = filepath.Join(dir, wpStem+".jsonl")
	body := strings.Join([]string{
		`{"type":"session","id":"` + wpStem + `","timestamp":"2026-07-31T11:50:12.080Z"}`,
		`{"type":"model_change","id":"m1","timestamp":"2026-07-31T11:50:12.099Z","provider":"openai","modelId":"gpt-5.4-nano"}`,
		`{"type":"message","id":"u1","timestamp":"2026-07-31T11:50:12.175Z","message":{"role":"user","content":[{"type":"text","text":` +
			mustJSONString(t, wpBootstrapPrefix+"\n\n"+wpHumanPrompt) + `}],"timestamp":1785498612175}}`,
		`{"type":"message","id":"01be8795","timestamp":"2026-07-31T11:50:12.187Z","message":{"role":"assistant","content":[{"type":"toolCall","id":"c1","name":"read","arguments":{"path":"/tmp/wpt6/openclaw/hello.txt"}}],"stopReason":"toolUse","provider":"openai","model":"gpt-5.4-nano","usage":{"input":14228,"output":149,"cacheRead":0,"cacheWrite":0,"totalTokens":14377},"timestamp":1785498612187}}`,
		`{"type":"message","id":"dcbe52ab","timestamp":"2026-07-31T11:50:25.318Z","message":{"role":"assistant","content":[{"type":"text","text":"done"}],"stopReason":"stop","provider":"openai","model":"` + lastModel + `","usage":` + lastUsage + `,"timestamp":1785498625318}}`,
		"",
	}, "\n")
	if err := os.WriteFile(msgLog, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}

	// One model.completed for the run. lastCallUsage == the message log's
	// second call; messagesSnapshot's last assistant entry carries the same
	// timestamp, which is the dedup join key.
	traj = filepath.Join(dir, wpStem+".trajectory.jsonl")
	trajBody := strings.Join([]string{
		`{"type":"session.started","ts":"2026-07-31T11:50:12.083Z","sessionId":"` + wpStem + `","sessionKey":"` + wpSessionKey + `"}`,
		// trace.metadata carries the verbatim preamble this run prepended
		// (live shape: data.prompting.userPromptPrefixText, emitted right
		// after session.started). It is what makes the O2 split a check
		// rather than a guess.
		`{"type":"trace.metadata","ts":"2026-07-31T11:50:12.084Z","sessionId":"` + wpStem + `","sessionKey":"` + wpSessionKey +
			`","data":{"prompting":{"userPromptPrefixText":` + mustJSONString(t, wpBootstrapPrefix) + `}}}`,
		`{"type":"model.completed","ts":"2026-07-31T11:50:30.085Z","seq":5,"sessionId":"` + wpStem + `","sessionKey":"` + wpSessionKey + `","runId":"` + wpStem + `","workspaceDir":"` + wpWorkspace + `","provider":"openai","modelId":"gpt-5.4-nano","data":{"usage":{"input":14596,"output":691,"cacheRead":14848,"total":30135},"promptCache":{"lastCallUsage":{"input":368,"output":542,"cacheRead":14848,"cacheWrite":0,"total":15758},"lastCacheTouchAt":1785498625318},"messagesSnapshot":[{"role":"user","content":[],"timestamp":1785498612175},{"role":"assistant","usage":{"input":14228,"output":149,"cacheRead":0,"cacheWrite":0},"timestamp":1785498612187},{"role":"assistant","usage":{"input":368,"output":542,"cacheRead":14848,"cacheWrite":0},"timestamp":1785498625318}]}}`,
		"",
	}, "\n")
	if err := os.WriteFile(traj, []byte(trajBody), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir, msgLog, traj
}

func mustJSONString(t *testing.T, s string) string {
	t.Helper()
	b, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// TestParseBothPaths_TurnCountedOnce is the O1 proof. It parses BOTH files
// of one run and asserts (a) every row lands on the single canonical session
// id, (b) the call both files describe produces exactly ONE token row, (c)
// that row carries the accurate numbers, and (d) no call is lost — the
// message log's other call still has its row.
func TestParseBothPaths_TurnCountedOnce(t *testing.T) {
	dir, msgLog, traj := writeWPFixture(t, false)
	a := NewWithOptions(nil, []string{dir})
	ctx := context.Background()

	msgRes, err := a.ParseSessionFile(ctx, msgLog, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile(message log): %v", err)
	}
	trajRes, err := a.ParseSessionFile(ctx, traj, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile(trajectory): %v", err)
	}

	// (a) ONE session id across both halves of the run.
	all := append(append([]models.TokenEvent{}, msgRes.TokenEvents...), trajRes.TokenEvents...)
	for _, e := range all {
		if e.SessionID != wpSessionKey {
			t.Errorf("token row on session %q, want the canonical %q (O1 split)", e.SessionID, wpSessionKey)
		}
		if e.ProjectRoot != wpWorkspace {
			t.Errorf("token row project root %q, want %q", e.ProjectRoot, wpWorkspace)
		}
	}
	for _, e := range msgRes.ToolEvents {
		if e.SessionID != wpSessionKey {
			t.Errorf("action on session %q, want %q", e.SessionID, wpSessionKey)
		}
	}

	// (b) + (d) two model calls in the run ⇒ exactly two token rows total.
	if len(msgRes.TokenEvents) != 2 {
		t.Fatalf("message-log TokenEvents = %d, want 2", len(msgRes.TokenEvents))
	}
	if len(trajRes.TokenEvents) != 0 {
		t.Fatalf("trajectory TokenEvents = %d, want 0 — the message log already covers this call: %+v",
			len(trajRes.TokenEvents), trajRes.TokenEvents)
	}

	// Each call appears once, and the shared call carries the accurate
	// numbers at the accurate tier.
	byTS := map[int64]models.TokenEvent{}
	for _, e := range all {
		ms := e.Timestamp.UnixMilli()
		if prev, dup := byTS[ms]; dup {
			t.Fatalf("call at %d counted twice: %+v and %+v", ms, prev, e)
		}
		byTS[ms] = e
		if e.Reliability != models.ReliabilityAccurate {
			t.Errorf("row at %d reliability = %q, want %q", ms, e.Reliability, models.ReliabilityAccurate)
		}
	}
	shared, ok := byTS[1785498625318]
	if !ok {
		t.Fatalf("the shared call (ts 1785498625318) produced no row at all")
	}
	if shared.InputTokens != 368 || shared.OutputTokens != 542 || shared.CacheReadTokens != 14848 || shared.CacheCreationTokens != 0 {
		t.Errorf("shared call tokens = %d/%d/%d/%d, want 368/542/14848/0",
			shared.InputTokens, shared.OutputTokens, shared.CacheReadTokens, shared.CacheCreationTokens)
	}
	first, ok := byTS[1785498612187]
	if !ok || first.InputTokens != 14228 || first.OutputTokens != 149 {
		t.Errorf("the uncovered first call was lost or wrong: %+v (ok=%v)", first, ok)
	}

	// Union totals equal the run's real usage — no inflation, no loss.
	var in, out, cr int64
	for _, e := range all {
		in, out, cr = in+e.InputTokens, out+e.OutputTokens, cr+e.CacheReadTokens
	}
	if in != 14596 || out != 691 || cr != 14848 {
		t.Errorf("union totals = %d/%d/%d, want 14596/691/14848", in, out, cr)
	}
}

// TestParseBothPaths_DedupIsIndependentOfParseOrder pins the property that
// makes watcher scheduling irrelevant to the O1 dedup (WP-T6 codex round):
// messageLogUsageTimestamps re-reads the sibling log from DISK at offset 0,
// so parsing the TRAJECTORY FIRST — the order fsnotify can hand us whenever
// the trace's write event is delivered before the log's — still yields
// exactly one row per model call. (OpenClaw itself can never put the
// trajectory on disk first: assistant messages are appendFileSync'd at
// message_end while model.completed is queued at run end. See doc.go.)
func TestParseBothPaths_DedupIsIndependentOfParseOrder(t *testing.T) {
	dir, msgLog, traj := writeWPFixture(t, false)
	a := NewWithOptions(nil, []string{dir})
	ctx := context.Background()

	// Reversed vs TestParseBothPaths_TurnCountedOnce: trajectory first.
	trajRes, err := a.ParseSessionFile(ctx, traj, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile(trajectory): %v", err)
	}
	msgRes, err := a.ParseSessionFile(ctx, msgLog, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile(message log): %v", err)
	}
	if len(trajRes.TokenEvents) != 0 {
		t.Fatalf("trajectory-first TokenEvents = %d, want 0 — the on-disk message log already covers the call: %+v",
			len(trajRes.TokenEvents), trajRes.TokenEvents)
	}
	byTS := map[int64]bool{}
	for _, e := range append(append([]models.TokenEvent{}, trajRes.TokenEvents...), msgRes.TokenEvents...) {
		ms := e.Timestamp.UnixMilli()
		if byTS[ms] {
			t.Fatalf("call at %d counted twice under trajectory-first parse order", ms)
		}
		byTS[ms] = true
	}
	if len(byTS) != 2 {
		t.Errorf("distinct calls = %d, want 2", len(byTS))
	}
}

// TestParseBothPaths_TrajectoryCoversGatewayZeroedCall is the control for the
// suppression above: when the message log's final turn is gateway-injected
// (usage all zero, so it emits no row), the trajectory MUST still emit — and
// on the canonical session id.
func TestParseBothPaths_TrajectoryCoversGatewayZeroedCall(t *testing.T) {
	dir, msgLog, traj := writeWPFixture(t, true)
	a := NewWithOptions(nil, []string{dir})
	ctx := context.Background()

	msgRes, err := a.ParseSessionFile(ctx, msgLog, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile(message log): %v", err)
	}
	if len(msgRes.TokenEvents) != 1 {
		t.Fatalf("message-log TokenEvents = %d, want 1 (the zeroed turn must not emit)", len(msgRes.TokenEvents))
	}
	trajRes, err := a.ParseSessionFile(ctx, traj, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile(trajectory): %v", err)
	}
	if len(trajRes.TokenEvents) != 1 {
		t.Fatalf("trajectory TokenEvents = %d, want 1 — the zeroed call has no other source", len(trajRes.TokenEvents))
	}
	e := trajRes.TokenEvents[0]
	if e.SessionID != wpSessionKey {
		t.Errorf("trajectory session = %q, want %q", e.SessionID, wpSessionKey)
	}
	if e.InputTokens != 368 || e.OutputTokens != 542 || e.CacheReadTokens != 14848 {
		t.Errorf("trajectory tokens = %d/%d/%d, want 368/542/14848", e.InputTokens, e.OutputTokens, e.CacheReadTokens)
	}
	if e.Reliability != models.ReliabilityAccurate {
		t.Errorf("trajectory reliability = %q", e.Reliability)
	}
}

// TestParseTrajectoryJSONL_FallsBackToWorkspaceDir pins the other half of the
// O1 ProjectRoot fix: with no sessions.json alias to lean on (the orphan
// shape in the corpus, where the message log has been rotated away), the
// trace's own sessionKey + workspaceDir replace the "[openclaw]" hardcode,
// and the SourceEventID stays keyed on the file stem so a rescan upgrades
// the pre-fix row instead of adding another.
func TestParseTrajectoryJSONL_FallsBackToWorkspaceDir(t *testing.T) {
	dir := t.TempDir()
	stem := "4de1bfff-50c3-4d6d-adab-9f04fd6ca18a"
	path := filepath.Join(dir, stem+".trajectory.jsonl")
	line := `{"type":"model.completed","ts":"2026-06-26T07:15:24.820Z","sessionId":"` + stem +
		`","sessionKey":"agent:main:main","runId":"r1","workspaceDir":"` + wpWorkspace +
		`","provider":"openai","modelId":"gpt-5.5","data":{"promptCache":{"lastCallUsage":{"input":17330,"output":78,"cacheRead":0,"cacheWrite":0,"total":17408},"lastCacheTouchAt":1782552263070}}}`
	if err := os.WriteFile(path, []byte(line+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	a := NewWithOptions(nil, []string{dir})
	res, err := a.ParseSessionFile(context.Background(), path, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	if len(res.TokenEvents) != 1 {
		t.Fatalf("TokenEvents = %d, want 1", len(res.TokenEvents))
	}
	e := res.TokenEvents[0]
	if e.SessionID != "agent:main:main" {
		t.Errorf("session = %q, want agent:main:main (the trace's own sessionKey)", e.SessionID)
	}
	if e.ProjectRoot != wpWorkspace {
		t.Errorf("project root = %q, want %q (not the [openclaw] hardcode)", e.ProjectRoot, wpWorkspace)
	}
	if !strings.HasPrefix(e.SourceEventID, "traj:"+stem+":") {
		t.Errorf("SourceEventID = %q, want it keyed on the file stem", e.SourceEventID)
	}
}

// TestSplitBootstrapPrompt pins the O2 boundary. With no trace to lean on the
// split point is the harness's own "\n\n" join, so it holds for both prefix
// flavours and for a multi-paragraph human prompt, and it declines rather
// than guesses when the marker or the join point is absent.
func TestSplitBootstrapPrompt(t *testing.T) {
	limitedPrefix := "[Bootstrap pending]\n" +
		"Bootstrap is still pending for this workspace, but this run cannot safely complete the full BOOTSTRAP.md workflow here.\n" +
		"Do not claim bootstrap is complete, and do not use a generic first greeting."
	for _, tc := range []struct {
		name string
		in   string
		want string
		ok   bool
	}{
		{"full prefix", wpBootstrapPrefix + "\n\n" + wpHumanPrompt, wpHumanPrompt, true},
		{"limited prefix", limitedPrefix + "\n\n" + wpHumanPrompt, wpHumanPrompt, true},
		{"multi-paragraph human half", wpBootstrapPrefix + "\n\nfirst\n\nsecond", "first\n\nsecond", true},
		{"no marker", "just a normal prompt\n\nwith a blank line", "", false},
		{"marker but no join point", wpBootstrapPrefix, "", false},
		{"marker with empty tail", wpBootstrapPrefix + "\n\n   ", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := splitBootstrapPrompt(tc.in, nil)
			if ok != tc.ok || got != tc.want {
				t.Errorf("splitBootstrapPrompt() = (%q, %v), want (%q, %v)", got, ok, tc.want, tc.ok)
			}
		})
	}
}

// TestSplitBootstrapPrompt_TraceCorroboratedBoundary is the WP-T6 codex-round
// finding: the marker alone is not evidence of a harness preamble. When the
// run's trajectory declares the exact prefix it prepended
// (trace.metadata data.prompting.userPromptPrefixText), the split must happen
// ONLY on that literal `prefix + "\n\n"` — so a human prompt that opens
// "[Bootstrap pending]" and merely contains a blank line keeps every word.
func TestSplitBootstrapPrompt_TraceCorroboratedBoundary(t *testing.T) {
	// A person typing about bootstrapping, with a paragraph break. The old
	// marker + first-"\n\n" rule silently dropped the first paragraph.
	humanMimic := "[Bootstrap pending]\nI am writing my own note about the bootstrap state.\n\n" +
		"Please summarise what the harness does here."
	prefixFn := func(s string) func() string { return func() string { return s } }

	for _, tc := range []struct {
		name   string
		in     string
		prefix func() string
		want   string
		ok     bool
	}{
		{
			name:   "real preamble, trace agrees",
			in:     wpBootstrapPrefix + "\n\n" + wpHumanPrompt,
			prefix: prefixFn(wpBootstrapPrefix),
			want:   wpHumanPrompt,
			ok:     true,
		},
		{
			name:   "human mimic, trace disagrees — NOT truncated",
			in:     humanMimic,
			prefix: prefixFn(wpBootstrapPrefix),
			want:   "",
			ok:     false,
		},
		{
			name:   "human mimic, no trace — documented heuristic fallback",
			in:     humanMimic,
			prefix: prefixFn(""),
			want:   "Please summarise what the harness does here.",
			ok:     true,
		},
		{
			name:   "trace prefix present but text carries the other flavour",
			in:     "[Bootstrap pending]\nlimited flavour line.\n\n" + wpHumanPrompt,
			prefix: prefixFn(wpBootstrapPrefix),
			want:   "",
			ok:     false,
		},
		{
			name:   "trace-agreeing preamble with a multi-paragraph human half",
			in:     wpBootstrapPrefix + "\n\nfirst\n\nsecond",
			prefix: prefixFn(wpBootstrapPrefix),
			want:   "first\n\nsecond",
			ok:     true,
		},
		{
			name:   "trace agrees but nothing follows",
			in:     wpBootstrapPrefix + "\n\n   ",
			prefix: prefixFn(wpBootstrapPrefix),
			want:   "",
			ok:     false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := splitBootstrapPrompt(tc.in, tc.prefix)
			if ok != tc.ok || got != tc.want {
				t.Errorf("splitBootstrapPrompt() = (%q, %v), want (%q, %v)", got, ok, tc.want, tc.ok)
			}
		})
	}
}

// TestParseSessionFile_HumanPromptMimickingPreambleIsNotTruncated is the
// end-to-end proof of the same finding, through the real file layout: the
// sibling trajectory declares the run's preamble, the message log's user
// message only LOOKS like one, and actions.target must keep the whole thing.
func TestParseSessionFile_HumanPromptMimickingPreambleIsNotTruncated(t *testing.T) {
	dir, msgLog, _ := writeWPFixture(t, false)
	humanMimic := "[Bootstrap pending]\nnote to self about the bootstrap state.\n\nnow do the actual work."

	// Rewrite the fixture's user message with the mimicking text, leaving
	// the trajectory (and its declared prefix) exactly as the live run had.
	body, err := os.ReadFile(msgLog)
	if err != nil {
		t.Fatal(err)
	}
	rewritten := strings.Replace(string(body),
		mustJSONString(t, wpBootstrapPrefix+"\n\n"+wpHumanPrompt),
		mustJSONString(t, humanMimic), 1)
	if rewritten == string(body) {
		t.Fatal("fixture rewrite matched nothing — the user message shape changed")
	}
	if err := os.WriteFile(msgLog, []byte(rewritten), 0o644); err != nil {
		t.Fatal(err)
	}

	a := NewWithOptions(nil, []string{dir})
	res, err := a.ParseSessionFile(context.Background(), msgLog, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	var prompt *models.ToolEvent
	for i := range res.ToolEvents {
		if res.ToolEvents[i].ActionType == models.ActionUserPrompt {
			prompt = &res.ToolEvents[i]
			break
		}
	}
	if prompt == nil {
		t.Fatal("no user_prompt action emitted")
	}
	if prompt.Target != humanMimic {
		t.Errorf("target = %q, want the untouched human prompt %q", prompt.Target, humanMimic)
	}
	if !strings.Contains(prompt.Target, "note to self about the bootstrap state.") {
		t.Errorf("target lost the human first paragraph: %q", prompt.Target)
	}
}

// TestBootstrapPrefixFromTrace pins the sibling-trace read the split leans on:
// the prefix comes from trace.metadata, and a message log with no readable
// trajectory yields "" (so the heuristic fallback engages) rather than an error.
func TestBootstrapPrefixFromTrace(t *testing.T) {
	_, msgLog, traj := writeWPFixture(t, false)
	if got := bootstrapPrefixFromTrace(msgLog); got != wpBootstrapPrefix {
		t.Errorf("bootstrapPrefixFromTrace() = %q, want the trace-declared preamble", got)
	}
	if err := os.Remove(traj); err != nil {
		t.Fatal(err)
	}
	if got := bootstrapPrefixFromTrace(msgLog); got != "" {
		t.Errorf("with no trajectory, bootstrapPrefixFromTrace() = %q, want \"\"", got)
	}
}

// TestParseSessionFile_UserPromptTargetSkipsBootstrapPreamble is O2
// end-to-end: actions.target must show the operator's words, while
// raw_tool_input keeps the whole message so the preamble is not discarded.
func TestParseSessionFile_UserPromptTargetSkipsBootstrapPreamble(t *testing.T) {
	dir, msgLog, _ := writeWPFixture(t, false)
	a := NewWithOptions(nil, []string{dir})
	res, err := a.ParseSessionFile(context.Background(), msgLog, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	var prompt *models.ToolEvent
	for i := range res.ToolEvents {
		if res.ToolEvents[i].ActionType == models.ActionUserPrompt {
			prompt = &res.ToolEvents[i]
			break
		}
	}
	if prompt == nil {
		t.Fatal("no user_prompt action emitted")
	}
	if !strings.HasPrefix(prompt.Target, "Read /tmp/wpt6/openclaw/hello.txt") {
		t.Errorf("target = %q, want it to start with the human prompt", prompt.Target)
	}
	if strings.Contains(prompt.Target, "[Bootstrap pending]") {
		t.Errorf("target still carries the harness preamble: %q", prompt.Target)
	}
	if prompt.PrecedingReasoning != prompt.Target {
		t.Errorf("preceding_reasoning %q should mirror target %q", prompt.PrecedingReasoning, prompt.Target)
	}
	if !strings.Contains(prompt.RawToolInput, "[Bootstrap pending]") ||
		!strings.Contains(prompt.RawToolInput, "probe-marker-openclaw") {
		t.Errorf("raw_tool_input must keep the FULL message: %q", prompt.RawToolInput)
	}
}

// TestParseSessionFile_ThinkingNeverMintsAnAction is the B3 regression
// pin. A `thinking` content part must emit NO action row (it briefly
// minted `openclaw.reasoning` task_complete rows) while the openclaw
// SHARED-PREAMBLE threading is preserved exactly: every tool call that
// follows a preamble carries it, and multiple calls sharing one
// preamble all carry the same string.
func TestParseSessionFile_ThinkingNeverMintsAnAction(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "session.jsonl")
	body := strings.Join([]string{
		`{"type":"session","version":3,"id":"ses_b3","timestamp":"2026-04-22T21:34:53.850Z","cwd":"/tmp/oc"}`,
		`{"type":"message","id":"a1","timestamp":"2026-04-22T21:35:24.489Z","message":{"role":"assistant","content":[` +
			`{"type":"thinking","text":"THINK_ONE: I need to read both files."},` +
			`{"type":"toolCall","id":"call_1","name":"read","arguments":{"path":"A.md"}},` +
			`{"type":"toolCall","id":"call_2","name":"read","arguments":{"path":"B.md"}},` +
			`{"type":"thinking","text":"THINK_TWO: now search."},` +
			`{"type":"toolCall","id":"call_3","name":"memory_search","arguments":{"query":"hello"}}` +
			`],"stopReason":"toolUse","provider":"ollama","model":"gemma4:e4b","timestamp":1776893724488}}`,
		"",
	}, "\n")
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}

	a := NewWithOptions(nil, []string{root})
	res, err := a.ParseSessionFile(context.Background(), path, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}

	var tools []models.ToolEvent
	for _, ev := range res.ToolEvents {
		if strings.Contains(strings.ToLower(ev.RawToolName), "reasoning") ||
			strings.Contains(strings.ToLower(ev.RawToolName), "thinking") {
			t.Fatalf("reasoning-named action row emitted: raw=%q %+v", ev.RawToolName, ev)
		}
		if strings.HasPrefix(ev.Target, "THINK_") || strings.HasPrefix(ev.ToolOutput, "THINK_") {
			t.Fatalf("thinking body surfaced as action content: %+v", ev)
		}
		if ev.RawToolName != "openclaw.assistant_text" {
			tools = append(tools, ev)
		}
	}
	// Three tool calls, no assistant_text row (the message carries only
	// thinking + toolCall parts) and no reasoning row.
	if len(res.ToolEvents) != 3 || len(tools) != 3 {
		t.Fatalf("want exactly 3 tool-call events, got %d (%+v)", len(res.ToolEvents), res.ToolEvents)
	}
	// SHARED PREAMBLE: both calls after THINK_ONE carry it verbatim.
	const one = "THINK_ONE: I need to read both files."
	const two = "THINK_TWO: now search."
	if got := tools[0].PrecedingReasoning; got != one {
		t.Errorf("tool[0] PrecedingReasoning = %q, want %q", got, one)
	}
	if got := tools[1].PrecedingReasoning; got != one {
		t.Errorf("tool[1] PrecedingReasoning = %q, want %q (shared preamble — NOT consumed-once)", got, one)
	}
	if got := tools[2].PrecedingReasoning; got != two {
		t.Errorf("tool[2] PrecedingReasoning = %q, want %q (a newer preamble replaces the older)", got, two)
	}
}

// Lineage emission: a task run with a DISTINCT child session key stamps a
// migration-069 lineage (parent = requester, thread_source=subagent); a
// self-run (child == requester == owner) emits nothing.
func TestParseSessionFile_TaskRunsEmitChildLineages(t *testing.T) {
	root := t.TempDir()
	dbPath := filepath.Join(root, "runs.sqlite")
	setupTaskRunsDB(t, dbPath)
	// Add a proper spawn row: distinct requester and child keys.
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(`INSERT INTO task_runs (
			task_id, runtime, source_id, requester_session_key, owner_key,
			scope_kind, child_session_key, agent_id, run_id, label, task, status,
			delivery_status, notify_policy, created_at, started_at, ended_at,
			last_event_at, cleanup_after
		) VALUES (
			'task_spawn', 'cli', 'run_2', 'agent:main:explicit:parent-conv',
			'agent:worker', 'session',
			'agent:worker:child-sess-key', 'worker', 'run_2', '',
			'do the subtask',
			'succeeded', 'not_applicable', 'silent', 1776892400000, 1776892401000,
			1776892402000, 1776892402000, 1777497202000
		)`)
	db.Close()
	if err != nil {
		t.Fatal(err)
	}

	a := NewWithOptions(nil, []string{root})
	res, err := a.ParseSessionFile(context.Background(), dbPath, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	if len(res.SessionLineages) != 1 {
		t.Fatalf("got %d lineages (%+v), want 1", len(res.SessionLineages), res.SessionLineages)
	}
	lin := res.SessionLineages[0]
	if lin.SessionID != "agent:worker:child-sess-key" ||
		lin.ParentThreadID != "agent:main:explicit:parent-conv" ||
		lin.ThreadSource != "subagent" {
		t.Fatalf("lineage wrong: %+v", lin)
	}
}

// A task lineage can be stored before its child session row exists, making the
// store upsert a no-op. The unchanged task watermark must still replay that
// durable link on the next scan so the later child ingest converges.
func TestParseSessionFile_TaskRunsReplayLineagePastWatermark(t *testing.T) {
	root := t.TempDir()
	dbPath := filepath.Join(root, "runs.sqlite")
	setupTaskRunsDB(t, dbPath)
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(`INSERT INTO task_runs (
			task_id, runtime, requester_session_key, owner_key, scope_kind,
			child_session_key, task, status, delivery_status, notify_policy,
			created_at, last_event_at
		) VALUES (
			'replay_spawn', 'cli', 'parent-late', 'worker', 'session',
			'child-late', 'late child', 'running', 'not_applicable', 'silent',
			1776892500000, 1776892500000
		)`)
	db.Close()
	if err != nil {
		t.Fatal(err)
	}

	a := NewWithOptions(nil, []string{root})
	first, err := a.ParseSessionFile(context.Background(), dbPath, 0)
	if err != nil {
		t.Fatal(err)
	}
	second, err := a.ParseSessionFile(context.Background(), dbPath, first.NewOffset)
	if err != nil {
		t.Fatal(err)
	}
	if len(second.ToolEvents) != 0 {
		t.Fatalf("watermarked events replayed: %+v", second.ToolEvents)
	}
	if len(second.SessionLineages) != 1 || second.SessionLineages[0].SessionID != "child-late" || second.SessionLineages[0].ParentThreadID != "parent-late" {
		t.Fatalf("durable lineage did not replay past watermark: %+v", second.SessionLineages)
	}
}

// TestMessageContentListUnmarshal pins the dual-shape content decoder that
// the live openclaw@2026.8.2 store surfaced: user turns store content as a
// bare string, assistant turns as an array of typed blocks. Both must
// decode without error; a string becomes a single text block.
func TestMessageContentListUnmarshal(t *testing.T) {
	cases := []struct {
		name    string
		in      string
		wantLen int
		wantErr bool
		text0   string
	}{
		{"string form (user turn)", `"just some prose"`, 1, false, "just some prose"},
		{"array form (assistant turn)", `[{"type":"text","text":"a"},{"type":"tool_use","name":"bash"}]`, 2, false, "a"},
		{"empty string", `""`, 1, false, ""},
		{"null", `null`, 0, false, ""},
		{"object is rejected", `{"type":"text"}`, 0, true, ""},
		{"number is rejected", `42`, 0, true, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var m messageContentList
			err := json.Unmarshal([]byte(tc.in), &m)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("want error for %q, got none", tc.in)
				}
				return
			}
			if err != nil {
				t.Fatalf("unmarshal %q: %v", tc.in, err)
			}
			if len(m) != tc.wantLen {
				t.Fatalf("len = %d, want %d", len(m), tc.wantLen)
			}
			if tc.wantLen > 0 && m[0].Text != tc.text0 {
				t.Fatalf("m[0].Text = %q, want %q", m[0].Text, tc.text0)
			}
		})
	}
}
