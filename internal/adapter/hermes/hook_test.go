package hermes

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/scrub"
)

// TestBuildToolEvent_ToolCall pins the happy-path mapping from the
// Python-bridge `tool_call` event JSON to a ToolEvent. Mirrors the
// live wire shape from §17.1.F (args= dict + result= JSON string +
// tool_call_id + cwd + timestamp + telemetry_schema_version).
func TestBuildToolEvent_ToolCall(t *testing.T) {
	t.Parallel()
	body := []byte(`{
		"event": "tool_call",
		"session_id": "20260605_154029_7b8623",
		"task_id": "task-1",
		"tool_call_id": "call_abc123",
		"tool_name": "terminal",
		"args": {"command": "ls -la /tmp"},
		"result": "{\"output\": \"total 4\\n...\", \"exit_code\": 0, \"error\": null}",
		"duration_ms": 250,
		"cwd": "/home/dev/project",
		"timestamp": 1717500000.123,
		"model": "anthropic/claude-sonnet-4.6",
		"telemetry_schema_version": "hermes.observer.v1"
	}`)
	evt, ok, err := BuildToolEvent(EventToolCall, body, scrub.New())
	if err != nil {
		t.Fatalf("BuildToolEvent: %v", err)
	}
	if !ok {
		t.Fatal("BuildToolEvent ok = false, want true")
	}
	if evt.SourceFile != SourceFileHook {
		t.Errorf("SourceFile = %q, want %q", evt.SourceFile, SourceFileHook)
	}
	if evt.SourceEventID != "20260605_154029_7b8623:call_abc123" {
		t.Errorf("SourceEventID = %q, want composite", evt.SourceEventID)
	}
	if evt.SessionID != "20260605_154029_7b8623" {
		t.Errorf("SessionID = %q", evt.SessionID)
	}
	if evt.ProjectRoot != "/home/dev/project" {
		t.Errorf("ProjectRoot = %q, want from cwd field", evt.ProjectRoot)
	}
	if evt.Tool != models.ToolHermes {
		t.Errorf("Tool = %q, want %q", evt.Tool, models.ToolHermes)
	}
	if evt.Model != "claude-sonnet-4.6" {
		t.Errorf("Model = %q, want provider-prefix stripped", evt.Model)
	}
	if evt.ActionType != models.ActionRunCommand {
		t.Errorf("ActionType = %q, want %q", evt.ActionType, models.ActionRunCommand)
	}
	if evt.Target != "ls -la /tmp" {
		t.Errorf("Target = %q, want the command string", evt.Target)
	}
	if evt.RawToolName != "terminal" {
		t.Errorf("RawToolName = %q", evt.RawToolName)
	}
	if evt.DurationMs != 250 {
		t.Errorf("DurationMs = %d, want 250", evt.DurationMs)
	}
	if !evt.Success {
		t.Errorf("Success = false, want true (exit_code 0)")
	}
}

// TestBuildToolEvent_ToolCall_FailureFromExitCode pins the result-
// pairing path: exit_code != 0 yields Success=false even when error
// is null. Mirrors the live `sudo: A terminal is required` capture
// from testdata/hermes/reality-check.txt.
func TestBuildToolEvent_ToolCall_FailureFromExitCode(t *testing.T) {
	t.Parallel()
	body := []byte(`{
		"event": "tool_call",
		"session_id": "s1",
		"tool_call_id": "call_x",
		"tool_name": "terminal",
		"args": {"command": "sudo apt install y"},
		"result": "{\"output\": \"sudo: A terminal is required\", \"exit_code\": 1, \"error\": null}",
		"timestamp": 1717500000
	}`)
	evt, ok, _ := BuildToolEvent(EventToolCall, body, nil)
	if !ok {
		t.Fatal("ok = false")
	}
	if evt.Success {
		t.Error("Success = true, want false (exit_code 1)")
	}
	if evt.ToolOutput == "" {
		t.Error("ToolOutput empty, want stderr-like text")
	}
}

// TestBuildToolEvent_ToolCall_ResultFallbackScrubsJSONWithoutCorruption
// pins MHC-4 (docs/audits/codebase-audit-2026-09-16.md): when
// parseToolResult finds neither an "output" nor a "content" key, it
// falls back to the WHOLE raw JSON result body — which must then be
// scrubbed with RawJSON, not String, or a secret-shaped value sitting
// next to another field truncates/corrupts the stored JSON instead of
// just getting redacted.
func TestBuildToolEvent_ToolCall_ResultFallbackScrubsJSONWithoutCorruption(t *testing.T) {
	t.Parallel()
	const secret = "sk_live_abcdef1234567890"
	const sibling = "echo hi"
	// No "output"/"content" key present, so parseToolResult's fallback
	// (output = body) fires, handing the WHOLE object to the scrubber.
	body := []byte(`{
		"event": "tool_call",
		"session_id": "s1",
		"tool_call_id": "call_x",
		"tool_name": "terminal",
		"args": {"command": "` + sibling + `"},
		"result": "{\"api_key\": \"` + secret + `\", \"exit_code\": 0, \"note\": \"` + sibling + `\"}",
		"timestamp": 1717500000
	}`)
	evt, ok, err := BuildToolEvent(EventToolCall, body, scrub.New())
	if err != nil {
		t.Fatalf("BuildToolEvent: %v", err)
	}
	if !ok {
		t.Fatal("ok = false")
	}
	if !json.Valid([]byte(evt.ToolOutput)) {
		t.Fatalf("ToolOutput is not valid JSON after scrubbing: %q", evt.ToolOutput)
	}
	if strings.Contains(evt.ToolOutput, secret) {
		t.Errorf("secret survived scrubbing: %q", evt.ToolOutput)
	}
	if !strings.Contains(evt.ToolOutput, sibling) {
		t.Errorf("sibling field lost — scrubbing truncated/corrupted the JSON: %q", evt.ToolOutput)
	}
}

// TestBuildToolEvent_SessionStart pins the session_start mapping. CWD
// from the bridge feeds ProjectRoot.
func TestBuildToolEvent_SessionStart(t *testing.T) {
	t.Parallel()
	body := []byte(`{
		"event": "session_start",
		"session_id": "s1",
		"model": "openai/gpt-4o-mini",
		"source": "cli",
		"cwd": "/home/dev/project",
		"started_at": 1717500000
	}`)
	evt, ok, err := BuildToolEvent(EventSessionStart, body, nil)
	if err != nil || !ok {
		t.Fatalf("BuildToolEvent: err=%v ok=%v", err, ok)
	}
	if evt.ActionType != models.ActionSessionStart {
		t.Errorf("ActionType = %q", evt.ActionType)
	}
	if evt.SourceEventID != "s1:session_start" {
		t.Errorf("SourceEventID = %q", evt.SourceEventID)
	}
	if evt.Target != "cli" {
		t.Errorf("Target = %q, want %q (source)", evt.Target, "cli")
	}
	if evt.Model != "gpt-4o-mini" {
		t.Errorf("Model = %q, want stripped", evt.Model)
	}
}

// TestBuildToolEvent_SessionEnd pins the session_end mapping.
func TestBuildToolEvent_SessionEnd(t *testing.T) {
	t.Parallel()
	body := []byte(`{
		"event": "session_end",
		"session_id": "s1",
		"end_reason": "user_exit",
		"ended_at": 1717500999
	}`)
	evt, ok, _ := BuildToolEvent(EventSessionEnd, body, nil)
	if !ok {
		t.Fatal("ok = false")
	}
	if evt.ActionType != models.ActionSessionEnd {
		t.Errorf("ActionType = %q", evt.ActionType)
	}
	if evt.Target != "user_exit" {
		t.Errorf("Target = %q, want end_reason", evt.Target)
	}
	if evt.SourceEventID != "s1:session_end" {
		t.Errorf("SourceEventID = %q", evt.SourceEventID)
	}
}

// TestBuildToolEvent_APIRequestReturnsFalse confirms BuildToolEvent
// emits no row for api_request events — those go through
// BuildTokenEvent.
func TestBuildToolEvent_APIRequestReturnsFalse(t *testing.T) {
	t.Parallel()
	body := []byte(`{"event": "api_request", "session_id": "s1"}`)
	_, ok, err := BuildToolEvent(EventAPIRequest, body, nil)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if ok {
		t.Error("ok = true, want false")
	}
}

// TestBuildToolEvent_UnknownEventReturnsFalseNoErr pins the forward-
// compat path: a future Hermes plugin firing a new event name we
// don't recognise must not error.
func TestBuildToolEvent_UnknownEventReturnsFalseNoErr(t *testing.T) {
	t.Parallel()
	body := []byte(`{"event": "some_future_event", "session_id": "s1"}`)
	_, ok, err := BuildToolEvent("some_future_event", body, nil)
	if err != nil {
		t.Errorf("err = %v, want nil", err)
	}
	if ok {
		t.Error("ok = true, want false")
	}
}

// TestBuildToolEvent_MissingSessionIDReturnsError pins the
// required-field validation. SessionID-less payloads can't be
// inserted (the session upsert would fail downstream).
func TestBuildToolEvent_MissingSessionIDReturnsError(t *testing.T) {
	t.Parallel()
	body := []byte(`{"event": "tool_call", "tool_name": "terminal"}`)
	_, ok, err := BuildToolEvent(EventToolCall, body, nil)
	if ok {
		t.Error("ok = true, want false")
	}
	if err == nil {
		t.Error("err = nil, want non-nil")
	}
}

// TestBuildToolEvent_MalformedJSONReturnsError pins parser-error
// surfacing. Caller logs and continues — the hook stays non-blocking.
func TestBuildToolEvent_MalformedJSONReturnsError(t *testing.T) {
	t.Parallel()
	_, ok, err := BuildToolEvent(EventToolCall, []byte(`not json`), nil)
	if ok {
		t.Error("ok = true")
	}
	if err == nil {
		t.Error("err = nil, want parse error")
	}
}

// TestBuildToolEvent_SubagentStart pins the subagent_start mapping —
// forward-compatible groundwork since the bundled plugin bridge
// doesn't fire this event today (see the BuildToolEvent doc comment).
// The row must carry IsSidechain=true to mark the child's own
// runtime bracket starting.
func TestBuildToolEvent_SubagentStart(t *testing.T) {
	t.Parallel()
	body := []byte(`{
		"event": "subagent_start",
		"session_id": "parent-sess",
		"child_role": "code-reviewer",
		"cwd": "/home/dev/project",
		"timestamp": 1717500000.5
	}`)
	evt, ok, err := BuildToolEvent(EventSubagentStart, body, nil)
	if err != nil {
		t.Fatalf("BuildToolEvent: %v", err)
	}
	if !ok {
		t.Fatal("ok = false, want true")
	}
	if evt.ActionType != models.ActionSubagentStart {
		t.Errorf("ActionType = %q, want %q", evt.ActionType, models.ActionSubagentStart)
	}
	if !evt.IsSidechain {
		t.Error("IsSidechain = false, want true (child's own runtime bracket)")
	}
	if evt.Target != "code-reviewer" {
		t.Errorf("Target = %q, want child_role", evt.Target)
	}
	if evt.SessionID != "parent-sess" {
		t.Errorf("SessionID = %q", evt.SessionID)
	}
	if !evt.Success {
		t.Error("Success = false, want true")
	}
	if evt.SourceEventID != "parent-sess:subagent_start:1717500000500" {
		t.Errorf("SourceEventID = %q, want timestamp-derived key", evt.SourceEventID)
	}
}

// TestBuildToolEvent_SubagentStop pins the existing subagent_stop
// mapping (previously untested). IsSidechain must be true here too —
// it already was before this change, this test just pins it.
func TestBuildToolEvent_SubagentStop(t *testing.T) {
	t.Parallel()
	body := []byte(`{
		"event": "subagent_stop",
		"session_id": "parent-sess",
		"child_summary": "Reviewed the diff, found 2 issues",
		"child_status": "completed",
		"duration_ms": 4200,
		"timestamp": 1717500999
	}`)
	evt, ok, err := BuildToolEvent(EventSubagentStop, body, nil)
	if err != nil {
		t.Fatalf("BuildToolEvent: %v", err)
	}
	if !ok {
		t.Fatal("ok = false, want true")
	}
	if evt.ActionType != models.ActionSubagentStop {
		t.Errorf("ActionType = %q, want %q", evt.ActionType, models.ActionSubagentStop)
	}
	if !evt.IsSidechain {
		t.Error("IsSidechain = false, want true")
	}
	if evt.Target != "completed" {
		t.Errorf("Target = %q, want child_status", evt.Target)
	}
	if !evt.Success {
		t.Error("Success = false, want true (child_status completed)")
	}
	if evt.DurationMs != 4200 {
		t.Errorf("DurationMs = %d, want 4200", evt.DurationMs)
	}
}

// TestBuildTokenEvent_HappyPath pins the post_api_request -> TokenEvent
// translation. usage{input_tokens, output_tokens, cache_*} land
// directly; model strips provider prefix; Source/Reliability are
// hook/approximate per §10.8.
func TestBuildTokenEvent_HappyPath(t *testing.T) {
	t.Parallel()
	body := []byte(`{
		"event": "api_request",
		"session_id": "s1",
		"task_id": "task-1",
		"platform": "cli",
		"model": "anthropic/claude-sonnet-4.6",
		"provider": "anthropic",
		"api_call_count": 3,
		"finish_reason": "stop",
		"usage": {
			"input_tokens": 2048,
			"output_tokens": 512,
			"cache_read_tokens": 100,
			"cache_write_tokens": 50,
			"reasoning_tokens": 64
		},
		"timestamp": 1717500000.5
	}`)
	tok, ok, err := BuildTokenEvent(EventAPIRequest, body)
	if err != nil {
		t.Fatalf("BuildTokenEvent: %v", err)
	}
	if !ok {
		t.Fatal("ok = false")
	}
	if tok.SourceFile != SourceFileHook {
		t.Errorf("SourceFile = %q", tok.SourceFile)
	}
	if tok.SourceEventID != "s1:api:3" {
		t.Errorf("SourceEventID = %q, want s1:api:3", tok.SourceEventID)
	}
	if tok.Model != "claude-sonnet-4.6" {
		t.Errorf("Model = %q", tok.Model)
	}
	if tok.InputTokens != 2048 || tok.OutputTokens != 512 {
		t.Errorf("Input/Output = %d/%d, want 2048/512", tok.InputTokens, tok.OutputTokens)
	}
	if tok.CacheReadTokens != 100 || tok.CacheCreationTokens != 50 {
		t.Errorf("Cache read/create = %d/%d, want 100/50", tok.CacheReadTokens, tok.CacheCreationTokens)
	}
	if tok.ReasoningTokens != 64 {
		t.Errorf("Reasoning = %d, want 64", tok.ReasoningTokens)
	}
	if tok.Source != models.TokenSourceHook {
		t.Errorf("Source = %q", tok.Source)
	}
	if tok.Reliability != models.ReliabilityApproximate {
		t.Errorf("Reliability = %q", tok.Reliability)
	}
}

// TestBuildTokenEvent_CacheCreationLegacyKey pins the
// cache_write_tokens fallback. Older plugin payloads carry only
// cache_write_tokens; newer ones add cache_creation_tokens. Both must
// land on the same TokenEvent column.
func TestBuildTokenEvent_CacheCreationLegacyKey(t *testing.T) {
	t.Parallel()
	body := []byte(`{
		"event": "api_request",
		"session_id": "s1",
		"api_call_count": 1,
		"usage": {"input_tokens": 100, "cache_write_tokens": 30}
	}`)
	tok, ok, _ := BuildTokenEvent(EventAPIRequest, body)
	if !ok {
		t.Fatal("ok = false")
	}
	if tok.CacheCreationTokens != 30 {
		t.Errorf("CacheCreationTokens = %d, want 30 (legacy cache_write_tokens fallback)", tok.CacheCreationTokens)
	}
}

// TestBuildTokenEvent_NotAPIRequestReturnsFalse confirms non-token
// events produce no TokenEvent.
func TestBuildTokenEvent_NotAPIRequestReturnsFalse(t *testing.T) {
	t.Parallel()
	body := []byte(`{"event": "tool_call", "session_id": "s1"}`)
	_, ok, _ := BuildTokenEvent(EventToolCall, body)
	if ok {
		t.Error("ok = true, want false for tool_call")
	}
}

// TestBuildTokenEvent_EmptyUsageReturnsFalse confirms a zero-usage
// payload doesn't generate a row. The DB layer's check is identical
// but doing it here avoids pointless inserts.
func TestBuildTokenEvent_EmptyUsageReturnsFalse(t *testing.T) {
	t.Parallel()
	body := []byte(`{
		"event": "api_request",
		"session_id": "s1",
		"usage": {}
	}`)
	_, ok, err := BuildTokenEvent(EventAPIRequest, body)
	if err != nil {
		t.Errorf("err = %v", err)
	}
	if ok {
		t.Error("ok = true, want false for empty usage")
	}
}
