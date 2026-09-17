package claudecode

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/contentcap"
	"github.com/marmutapp/superbased-observer/internal/models"
)

func fixturePath(t *testing.T, name string) string {
	t.Helper()
	return filepath.Join("..", "..", "..", "testdata", "claudecode", name)
}

// TestActionMap_ClaudeCodeBuiltinTools pins the v1.6.11 Issue #6
// extension: TodoWrite, EnterPlanMode, ExitPlanMode are now mapped
// (alongside the pre-existing TaskCreate/Update/List/Get/Output/Stop,
// Agent, AskUserQuestion). Migration 024 backfills the historical
// rows that pre-date these additions; this test pins the runtime
// behavior so new ingests land correctly.
func TestActionMap_ClaudeCodeBuiltinTools(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		want string
	}{
		{"TaskCreate", "todo_update"},
		{"TaskUpdate", "todo_update"},
		{"TaskList", "todo_update"},
		{"TaskGet", "todo_update"},
		{"TaskOutput", "todo_update"},
		{"TaskStop", "todo_update"},
		{"TodoWrite", "todo_update"},
		{"Agent", "spawn_subagent"},
		{"AskUserQuestion", "ask_user"},
		{"EnterPlanMode", "permission_mode"},
		{"ExitPlanMode", "permission_mode"},
	}
	for _, c := range cases {
		if got := actionMap[c.name]; got != c.want {
			t.Errorf("actionMap[%q] = %q; want %q", c.name, got, c.want)
		}
	}
}

// TestActionMap_ShellVariants pins the v1.6.11 Issue #6 shell sweep:
// PowerShell / pwsh / cmd / cmd.exe / sh / Bash all route to
// ActionRunCommand. Pre-fix only "Bash" was mapped; PowerShell-on-Windows
// sessions fell through to ActionUnknown and silently dropped from
// dashboard run_command-filtered views.
func TestActionMap_ShellVariants(t *testing.T) {
	t.Parallel()
	want := models.ActionRunCommand
	for _, name := range []string{
		"Bash",
		"PowerShell",
		"powershell",
		"pwsh",
		"cmd",
		"cmd.exe",
		"sh",
	} {
		if got := actionMap[name]; got != want {
			t.Errorf("actionMap[%q] = %q; want %q", name, got, want)
		}
	}
}

// TestParseAPIError pins the v1.4.20 fix: Claude Code writes upstream
// API failures (content-policy blocks, rate limits, invalid-request
// errors) as JSONL records with type="system" + subtype="api_error" +
// no `message` field. Pre-fix the adapter dropped these because the
// `len(line.Message) == 0` short-circuit fired first. Now they emit
// ActionAPIError rows with the upstream request_id + error class +
// human message preserved.
func TestParseAPIError(t *testing.T) {
	t.Parallel()
	a := New()
	res, err := a.ParseSessionFile(context.Background(), fixturePath(t, "api-error.jsonl"), 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}

	var errors []models.ToolEvent
	for _, ev := range res.ToolEvents {
		if ev.ActionType == models.ActionAPIError {
			errors = append(errors, ev)
		}
	}
	if len(errors) != 3 {
		t.Fatalf("expected 3 api_error events, got %d (total events: %d)", len(errors), len(res.ToolEvents))
	}

	// First error: invalid_request_error / content-policy block.
	e0 := errors[0]
	if e0.RawToolName != "invalid_request_error" {
		t.Errorf("first error class: got %q want invalid_request_error", e0.RawToolName)
	}
	if e0.Target != "req_011CaZnwqf6Cw5zQpQq7VUAp" {
		t.Errorf("first error target (request_id): got %q", e0.Target)
	}
	if !strings.Contains(e0.ErrorMessage, "content filtering") {
		t.Errorf("first error message: got %q", e0.ErrorMessage)
	}
	if e0.Success {
		t.Error("api_error event must have Success=false")
	}
	if e0.SessionID != "sess-err" {
		t.Errorf("session id: got %q want sess-err", e0.SessionID)
	}
	if e0.MessageID != "req_011CaZnwqf6Cw5zQpQq7VUAp" {
		t.Errorf("message_id should mirror request_id for join compatibility with api_turns: got %q", e0.MessageID)
	}

	// Second error: rate_limit_error.
	e1 := errors[1]
	if e1.RawToolName != "rate_limit_error" {
		t.Errorf("second error class: got %q want rate_limit_error", e1.RawToolName)
	}
	if !strings.Contains(e1.ErrorMessage, "rate limit") {
		t.Errorf("second error message: got %q", e1.ErrorMessage)
	}

	// Third error: overloaded_error in a doubly-nested envelope —
	// matches the live Claude Code shape where error.error.error.{type,
	// message} is the leaf. findInnermostAPIError walks until message
	// is non-empty, so the leaf wins over the generic "error" middle.
	e2 := errors[2]
	if e2.RawToolName != "overloaded_error" {
		t.Errorf("doubly-nested error class: got %q want overloaded_error", e2.RawToolName)
	}
	if e2.ErrorMessage != "Overloaded" {
		t.Errorf("doubly-nested error message: got %q want Overloaded", e2.ErrorMessage)
	}
	if e2.Target != "req_011deeplynest" {
		t.Errorf("doubly-nested target: got %q want req_011deeplynest", e2.Target)
	}
}

func TestParseSimpleSession(t *testing.T) {
	t.Parallel()
	a := New()
	res, err := a.ParseSessionFile(context.Background(), fixturePath(t, "simple-session.jsonl"), 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	// 4 tool events: user_prompt (from msg-001 user text) + assistant_text
	// (msg-002's leading "I'll read main.go for you." text block) + Read +
	// Bash. The two follow-up user lines (msg-003, msg-005) carry only
	// tool_result blocks and don't emit user_prompts.
	if len(res.ToolEvents) != 4 {
		t.Fatalf("expected 4 tool events, got %d", len(res.ToolEvents))
	}
	// Event 0: user_prompt — mirrors what every other adapter produces.
	up := res.ToolEvents[0]
	if up.ActionType != models.ActionUserPrompt {
		t.Errorf("event 0 action_type: %q want %q", up.ActionType, models.ActionUserPrompt)
	}
	if up.MessageID != "user:msg-001" {
		t.Errorf("event 0 message_id: %q want user:msg-001", up.MessageID)
	}
	if up.SourceEventID != "msg-001" {
		t.Errorf("event 0 source_event_id: %q want msg-001 (line.UUID)", up.SourceEventID)
	}
	if up.RawToolName != "user_message" {
		t.Errorf("event 0 raw_tool_name: %q want user_message", up.RawToolName)
	}
	if !strings.Contains(up.Target, "main.go") {
		t.Errorf("event 0 target should echo prompt text: %q", up.Target)
	}

	// Event 1: claudecode.assistant_text — emitted before the sibling Read
	// tool_use because the text block precedes it in content-block order.
	asst := res.ToolEvents[1]
	if asst.ActionType != models.ActionAssistantMessage {
		t.Errorf("event 1 action_type: %q want assistant_message", asst.ActionType)
	}
	if asst.RawToolName != "claudecode.assistant_text" {
		t.Errorf("event 1 raw_tool_name: %q want claudecode.assistant_text", asst.RawToolName)
	}
	if !strings.Contains(asst.ToolOutput, "read main.go") {
		t.Errorf("event 1 tool_output: %q", asst.ToolOutput)
	}

	// Event 2: Read
	e1 := res.ToolEvents[2]
	if e1.ActionType != models.ActionReadFile {
		t.Errorf("event 2: action_type %q", e1.ActionType)
	}
	if e1.RawToolName != "Read" {
		t.Errorf("event 2: raw name %q", e1.RawToolName)
	}
	if e1.SessionID != "sess-001" {
		t.Errorf("event 2: session_id %q", e1.SessionID)
	}
	if e1.SourceEventID != "toolu_01" {
		t.Errorf("event 2: source_event_id %q", e1.SourceEventID)
	}
	if e1.Tool != models.ToolClaudeCode {
		t.Errorf("event 2: tool %q", e1.Tool)
	}
	if !e1.Success {
		t.Error("event 2 should be success")
	}
	if e1.PrecedingReasoning == "" {
		t.Error("event 2 should have preceding reasoning")
	}
	if !strings.Contains(e1.Target, "main.go") {
		t.Errorf("event 2 target: %q", e1.Target)
	}

	// Event 3: Bash, failed
	e2 := res.ToolEvents[3]
	if e2.ActionType != models.ActionRunCommand {
		t.Errorf("event 3: action_type %q", e2.ActionType)
	}
	if e2.Success {
		t.Error("event 3 should be failure (is_error=true)")
	}
	if !strings.Contains(e2.ErrorMessage, "FAIL") {
		t.Errorf("event 3 error_message: %q", e2.ErrorMessage)
	}
	if !strings.Contains(e2.Target, "go test") {
		t.Errorf("event 3 target: %q", e2.Target)
	}

	// Token events: one per assistant message with usage.
	if len(res.TokenEvents) < 1 {
		t.Fatalf("expected at least 1 token event, got %d", len(res.TokenEvents))
	}
	tk := res.TokenEvents[0]
	if tk.Source != models.TokenSourceJSONL || tk.Reliability != models.ReliabilityUnreliable {
		t.Errorf("token reliability: source=%s reliability=%s", tk.Source, tk.Reliability)
	}
	if tk.CacheReadTokens != 200 {
		t.Errorf("cache read tokens: %d", tk.CacheReadTokens)
	}

	if res.NewOffset <= 0 {
		t.Errorf("offset not advanced: %d", res.NewOffset)
	}
}

func TestParseMultiToolTurn(t *testing.T) {
	t.Parallel()
	a := New()
	res, err := a.ParseSessionFile(context.Background(), fixturePath(t, "multi-tool-turn.jsonl"), 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	if len(res.ToolEvents) != 4 {
		t.Fatalf("expected 4 tool events, got %d", len(res.ToolEvents))
	}
	// Leading assistant_text ("Searching in parallel") + three tool_use rows.
	want := []string{models.ActionAssistantMessage, models.ActionSearchText, models.ActionSearchFiles, models.ActionWebSearch}
	for i, w := range want {
		if res.ToolEvents[i].ActionType != w {
			t.Errorf("event %d: %s, want %s", i, res.ToolEvents[i].ActionType, w)
		}
	}
	if res.ToolEvents[0].RawToolName != "claudecode.assistant_text" {
		t.Errorf("event 0 raw_tool_name: %q want claudecode.assistant_text", res.ToolEvents[0].RawToolName)
	}
	// WebSearch (now at index 3) should be marked failed from the tool_result.
	if res.ToolEvents[3].Success {
		t.Error("WebSearch should be failure")
	}
	// First two should be success.
	if !res.ToolEvents[0].Success || !res.ToolEvents[1].Success {
		t.Error("Grep/Glob should be success")
	}
}

func TestMalformedLineSkipped(t *testing.T) {
	t.Parallel()
	a := New()
	res, err := a.ParseSessionFile(context.Background(), fixturePath(t, "malformed-line.jsonl"), 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	if len(res.ToolEvents) != 2 {
		t.Fatalf("expected 2 tool events around the malformed line, got %d", len(res.ToolEvents))
	}
	if len(res.Warnings) == 0 {
		t.Error("expected at least one warning for the malformed line")
	}
}

// TestConcatenatedRecordsRecovered pins recoverConcatenatedJSONLines:
// when Claude Code's JSONL writer concatenates two records without a
// separating newline (observed on the user's host 2026-05-04, see
// the helper's USE CASE doc), the leading-record fragment is
// unrecoverable but the trailing record(s) parse cleanly. The
// adapter should emit a single warning for the malformed line AND
// surface the recovered tool_use as if it had been on its own line.
func TestConcatenatedRecordsRecovered(t *testing.T) {
	t.Parallel()
	a := New()
	res, err := a.ParseSessionFile(context.Background(), fixturePath(t, "concatenated-records.jsonl"), 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	// 3 expected tool_use rows: line 1 Read, line 2 recovered Bash,
	// line 3 Glob. The truncated leading record on line 2 is dropped.
	if len(res.ToolEvents) != 3 {
		t.Fatalf("expected 3 tool events (2 from valid lines + 1 recovered), got %d", len(res.ToolEvents))
	}
	wantNames := []string{"Read", "Bash", "Glob"}
	for i, want := range wantNames {
		if got := res.ToolEvents[i].RawToolName; got != want {
			t.Errorf("ToolEvents[%d].RawToolName = %q, want %q", i, got, want)
		}
	}
	// The recovered Bash event must carry the trailing record's UUID
	// (recovered-002), confirming we used the suffix-record content
	// and not the truncated leading one.
	if got := res.ToolEvents[1].SourceEventID; got != "toolu_recovered" {
		t.Errorf("recovered tool ToolEvents[1].SourceEventID = %q, want toolu_recovered (the suffix record's tool_use id)", got)
	}
	// One warning for line 2 mentioning the recovery.
	var sawRecovery bool
	for _, w := range res.Warnings {
		if strings.Contains(w, "recovered") && strings.Contains(w, "sub-record") {
			sawRecovery = true
			break
		}
	}
	if !sawRecovery {
		t.Errorf("expected a warning mentioning recovered sub-records; got %v", res.Warnings)
	}
}

func TestIncrementalParse(t *testing.T) {
	t.Parallel()
	// Copy fixture so we can truncate and grow it.
	src := fixturePath(t, "simple-session.jsonl")
	body, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(t.TempDir(), "incr.jsonl")
	// Write only the first 2 lines initially.
	lines := strings.Split(string(body), "\n")
	if err := os.WriteFile(dst, []byte(strings.Join(lines[:2], "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	a := New()
	res1, err := a.ParseSessionFile(context.Background(), dst, 0)
	if err != nil {
		t.Fatalf("first parse: %v", err)
	}
	// 3 events from the first 2 lines: user_prompt (from line 1's user
	// text) + claudecode.assistant_text (from line 2's leading text block)
	// + Read (from line 2's tool_use).
	if len(res1.ToolEvents) != 3 {
		t.Fatalf("first parse expected 3 events, got %d", len(res1.ToolEvents))
	}

	// Append the rest and resume.
	if err := os.WriteFile(dst, body, 0o600); err != nil {
		t.Fatal(err)
	}
	res2, err := a.ParseSessionFile(context.Background(), dst, res1.NewOffset)
	if err != nil {
		t.Fatalf("second parse: %v", err)
	}
	// Lines 3-5 add: tool_result (no event), Bash tool_use, tool_result is_error
	// (updates Bash). So 1 new tool event: the Bash.
	if len(res2.ToolEvents) != 1 {
		t.Fatalf("second parse expected 1 new event, got %d", len(res2.ToolEvents))
	}
	if res2.ToolEvents[0].ActionType != models.ActionRunCommand {
		t.Errorf("second event: %s", res2.ToolEvents[0].ActionType)
	}
	if res2.NewOffset <= res1.NewOffset {
		t.Errorf("offset did not advance: %d -> %d", res1.NewOffset, res2.NewOffset)
	}
}

// TestParseDedupsByMessageID guards against the A1 finding: Claude Code
// writes one JSONL line per content block of an assistant message, all
// sharing the same Anthropic message.id and echoing the same accumulating
// usage envelope. The adapter must collapse same-msg.id events into one
// TokenEvent (with the final cumulative output_tokens) so the cost engine
// doesn't sum them as N independent API calls.
func TestParseDedupsByMessageID(t *testing.T) {
	t.Parallel()
	a := New()
	res, err := a.ParseSessionFile(context.Background(), fixturePath(t, "multi-block-dedup.jsonl"), 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}

	// Fixture: 4 blocks share msg_01ABCDEDUP (collapse → 1) + 1 synthetic
	// no-msg.id row (kept as-is, falls back to per-record UUID).
	if got, want := len(res.TokenEvents), 2; got != want {
		t.Fatalf("TokenEvents: got %d want %d (4-block dedup + 1 no-id)", got, want)
	}

	dd := res.TokenEvents[0]
	if dd.SourceEventID != "msg_01ABCDEDUP" {
		t.Errorf("SourceEventID: got %q want msg_01ABCDEDUP", dd.SourceEventID)
	}
	if dd.OutputTokens != 197 {
		t.Errorf("OutputTokens: got %d want 197 (final cumulative, not 8+8+8+197)", dd.OutputTokens)
	}
	if dd.InputTokens != 3 || dd.CacheCreationTokens != 13316 {
		t.Errorf("Input/CacheCreation should match the echoed envelope: in=%d cc=%d",
			dd.InputTokens, dd.CacheCreationTokens)
	}

	noID := res.TokenEvents[1]
	if noID.SourceEventID != "u-no-msg-id" {
		t.Errorf("no-msg.id row should fall back to line.UUID, got %q", noID.SourceEventID)
	}

	// C4: a JSONL line with model="<synthetic>" must never produce a
	// TokenEvent. Fixture has one; if the filter regresses we'll see 3
	// events instead of 2.
	for _, ev := range res.TokenEvents {
		if ev.Model == "<synthetic>" {
			t.Errorf("synthetic-model rows must be dropped: %+v", ev)
		}
	}

	// All three tool_use blocks across the four msg-id-shared lines
	// remain distinct ToolEvents (Grep, Grep, WebSearch) — dedup affects
	// token counting only, not tool-call capture. Plus:
	//   - the leading user_prompt from u-prompt's text content (line 1)
	//   - the assistant_text from line 2 ("Doing two greps.")
	//   - the assistant_text from line 6 (compaction-style, no msg.id)
	// Line 7 (model="<synthetic>" compaction placeholder) is dropped
	// entirely by the synthetic-row filter at adapter.go:367. = 6 events.
	if got, want := len(res.ToolEvents), 6; got != want {
		t.Fatalf("ToolEvents: got %d want %d (user_prompt + 2 assistant_text + Grep+Grep+WebSearch)", got, want)
	}
	if res.ToolEvents[0].ActionType != models.ActionUserPrompt {
		t.Errorf("first event should be user_prompt, got %s", res.ToolEvents[0].ActionType)
	}
}

// TestParseUserPromptEmission pins the parity fix: claudecode now
// emits a user_prompt action for user-role lines that carry text,
// matching what every other adapter produces. Tool-result-only user
// messages stay as-is — their tool_result blocks update the matching
// tool event but no user_prompt is emitted.
func TestParseUserPromptEmission(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	body := strings.Join([]string{
		// User text → user_prompt expected.
		`{"sessionId":"s","cwd":"/tmp","timestamp":"2026-04-30T00:00:00Z","uuid":"u-1","message":{"role":"user","content":[{"type":"text","text":"hello world"}]}}`,
		// Assistant tool_use → Read tool event.
		`{"sessionId":"s","cwd":"/tmp","timestamp":"2026-04-30T00:00:01Z","uuid":"u-2","message":{"id":"msg_a","role":"assistant","model":"claude-sonnet-4-5","content":[{"type":"tool_use","id":"toolu_1","name":"Read","input":{"file_path":"/x.go"}}]}}`,
		// User with only tool_result → NO user_prompt.
		`{"sessionId":"s","cwd":"/tmp","timestamp":"2026-04-30T00:00:02Z","uuid":"u-3","message":{"role":"user","content":[{"type":"tool_result","tool_use_id":"toolu_1","content":"ok","is_error":false}]}}`,
		// User with text AND tool_result → user_prompt fires; tool_result
		// updates pending tool (none here, so it's a no-op).
		`{"sessionId":"s","cwd":"/tmp","timestamp":"2026-04-30T00:00:03Z","uuid":"u-4","message":{"role":"user","content":[{"type":"text","text":"thanks, now do this"},{"type":"tool_result","tool_use_id":"toolu_orphan","content":"x","is_error":false}]}}`,
	}, "\n") + "\n"
	p := filepath.Join(dir, "session.jsonl")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := New().ParseSessionFile(context.Background(), p, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	// Expect: user_prompt (u-1) + Read (u-2) + user_prompt (u-4 — text portion).
	// u-3 emits nothing (tool_result-only).
	if len(res.ToolEvents) != 3 {
		t.Fatalf("ToolEvents: got %d want 3 (%+v)", len(res.ToolEvents), res.ToolEvents)
	}
	for i, want := range []struct{ action, sourceID, msgID string }{
		{models.ActionUserPrompt, "u-1", "user:u-1"},
		{models.ActionReadFile, "toolu_1", "msg_a"},
		{models.ActionUserPrompt, "u-4", "user:u-4"},
	} {
		got := res.ToolEvents[i]
		if got.ActionType != want.action {
			t.Errorf("event %d action_type: got %q want %q", i, got.ActionType, want.action)
		}
		if got.SourceEventID != want.sourceID {
			t.Errorf("event %d source_event_id: got %q want %q", i, got.SourceEventID, want.sourceID)
		}
		if got.MessageID != want.msgID {
			t.Errorf("event %d message_id: got %q want %q", i, got.MessageID, want.msgID)
		}
	}
}

// TestParseToolUseDurationMs pins the v1.4.28 wall-clock duration
// capture: claude-code's JSONL doesn't emit a structured per-tool
// elapsed field, so the adapter computes DurationMs as the gap from
// the assistant's tool_use timestamp to the matching user
// tool_result timestamp.
func TestParseToolUseDurationMs(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	body := strings.Join([]string{
		// Assistant tool_use at t0.
		`{"sessionId":"s","cwd":"/tmp","timestamp":"2026-05-03T10:00:00Z","uuid":"u-1","message":{"id":"msg_a","role":"assistant","model":"claude-sonnet-4-5","content":[{"type":"tool_use","id":"toolu_dur","name":"Read","input":{"file_path":"/x.go"}}]}}`,
		// User tool_result at t0+2.5s — adapter should record 2500ms.
		`{"sessionId":"s","cwd":"/tmp","timestamp":"2026-05-03T10:00:02.500Z","uuid":"u-2","message":{"role":"user","content":[{"type":"tool_result","tool_use_id":"toolu_dur","content":"ok","is_error":false}]}}`,
	}, "\n") + "\n"
	p := filepath.Join(dir, "session.jsonl")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := New().ParseSessionFile(context.Background(), p, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	if len(res.ToolEvents) != 1 {
		t.Fatalf("ToolEvents: got %d want 1", len(res.ToolEvents))
	}
	got := res.ToolEvents[0].DurationMs
	if got != 2500 {
		t.Errorf("DurationMs: got %d want 2500 (t0+2500ms tool_result)", got)
	}
}

// TestStopReasonAndServiceTierCaptured verifies the adapter stamps the
// assistant message's per-turn stop_reason (message.stop_reason) and
// service_tier (message.usage.service_tier) onto the emitted events'
// Metadata so session review surfaces them per message.
func TestStopReasonAndServiceTierCaptured(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	body := strings.Join([]string{
		// Assistant tool_use turn: stop_reason=tool_use, service_tier=priority.
		`{"sessionId":"s","cwd":"/tmp","timestamp":"2026-06-07T10:00:00Z","uuid":"u-1","message":{"id":"msg_a","role":"assistant","model":"claude-opus-4-8","stop_reason":"tool_use","content":[{"type":"tool_use","id":"toolu_x","name":"Read","input":{"file_path":"/x.go"}}],"usage":{"input_tokens":10,"output_tokens":5,"service_tier":"priority"}}}`,
		// Assistant text-only final turn: stop_reason=end_turn, service_tier=standard.
		`{"sessionId":"s","cwd":"/tmp","timestamp":"2026-06-07T10:00:01Z","uuid":"u-2","message":{"id":"msg_b","role":"assistant","model":"claude-opus-4-8","stop_reason":"end_turn","content":[{"type":"text","text":"done"}],"usage":{"input_tokens":10,"output_tokens":5,"service_tier":"standard"}}}`,
	}, "\n") + "\n"
	p := filepath.Join(dir, "stopreason.jsonl")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := New().ParseSessionFile(context.Background(), p, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}

	// The tool_use row carries the turn's stop_reason + service_tier.
	var tu *models.ToolEvent
	stopReasons := map[string]bool{}
	serviceTiers := map[string]bool{}
	for i := range res.ToolEvents {
		ev := &res.ToolEvents[i]
		if ev.SourceEventID == "toolu_x" {
			tu = ev
		}
		if ev.Metadata != nil {
			if ev.Metadata.StopReason != "" {
				stopReasons[ev.Metadata.StopReason] = true
			}
			if ev.Metadata.ServiceTier != "" {
				serviceTiers[ev.Metadata.ServiceTier] = true
			}
		}
	}
	if tu == nil || tu.Metadata == nil {
		t.Fatalf("tool_use row or its metadata missing")
	}
	if tu.Metadata.StopReason != "tool_use" {
		t.Errorf("tool_use StopReason=%q want tool_use", tu.Metadata.StopReason)
	}
	if tu.Metadata.ServiceTier != "priority" {
		t.Errorf("tool_use ServiceTier=%q want priority", tu.Metadata.ServiceTier)
	}
	// Both turns' values are present across the emitted rows (text turn too).
	for _, want := range []string{"tool_use", "end_turn"} {
		if !stopReasons[want] {
			t.Errorf("missing stop_reason %q (got %v)", want, stopReasons)
		}
	}
	for _, want := range []string{"priority", "standard"} {
		if !serviceTiers[want] {
			t.Errorf("missing service_tier %q (got %v)", want, serviceTiers)
		}
	}
}

// TestParseCacheCreationTierBreakdown verifies the adapter captures
// usage.cache_creation.{ephemeral_5m_input_tokens, ephemeral_1h_input_tokens}
// when present and falls back to cache_creation_input_tokens otherwise.
// Audit item C5.
func TestParseCacheCreationTierBreakdown(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	body := strings.Join([]string{
		// Tier-aware line: both legacy total and breakdown.
		`{"sessionId":"s","cwd":"/tmp","timestamp":"2026-04-25T10:00:00Z","uuid":"u-tier","message":{"id":"msg_tier","model":"claude-sonnet-4-6","content":[{"type":"text","text":"x"}],"usage":{"input_tokens":10,"output_tokens":5,"cache_read_input_tokens":100,"cache_creation_input_tokens":600,"cache_creation":{"ephemeral_5m_input_tokens":400,"ephemeral_1h_input_tokens":200}}}}`,
		// Tier-only line: breakdown without legacy total.
		`{"sessionId":"s","cwd":"/tmp","timestamp":"2026-04-25T10:00:01Z","uuid":"u-only","message":{"id":"msg_only","model":"claude-sonnet-4-6","content":[{"type":"text","text":"x"}],"usage":{"input_tokens":10,"output_tokens":5,"cache_creation":{"ephemeral_5m_input_tokens":300,"ephemeral_1h_input_tokens":150}}}}`,
		// Legacy-only line: total set, no breakdown.
		`{"sessionId":"s","cwd":"/tmp","timestamp":"2026-04-25T10:00:02Z","uuid":"u-legacy","message":{"id":"msg_legacy","model":"claude-sonnet-4-6","content":[{"type":"text","text":"x"}],"usage":{"input_tokens":10,"output_tokens":5,"cache_creation_input_tokens":800}}}`,
	}, "\n") + "\n"
	p := filepath.Join(dir, "tier.jsonl")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	a := New()
	res, err := a.ParseSessionFile(context.Background(), p, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	if len(res.TokenEvents) != 3 {
		t.Fatalf("TokenEvents: got %d want 3", len(res.TokenEvents))
	}

	// Index by message.id since map ordering isn't guaranteed across
	// Go versions but the slice preserves insertion order in practice.
	byID := map[string]models.TokenEvent{}
	for _, ev := range res.TokenEvents {
		byID[ev.SourceEventID] = ev
	}

	tier := byID["msg_tier"]
	if tier.CacheCreationTokens != 600 {
		t.Errorf("tier total: got %d want 600 (legacy field wins when both present)", tier.CacheCreationTokens)
	}
	if tier.CacheCreation1hTokens != 200 {
		t.Errorf("tier 1h: got %d want 200", tier.CacheCreation1hTokens)
	}

	only := byID["msg_only"]
	if only.CacheCreationTokens != 450 {
		t.Errorf("breakdown-only total: got %d want 450 (sum of 5m+1h)", only.CacheCreationTokens)
	}
	if only.CacheCreation1hTokens != 150 {
		t.Errorf("breakdown-only 1h: got %d want 150", only.CacheCreation1hTokens)
	}

	legacy := byID["msg_legacy"]
	if legacy.CacheCreationTokens != 800 {
		t.Errorf("legacy total: got %d want 800", legacy.CacheCreationTokens)
	}
	if legacy.CacheCreation1hTokens != 0 {
		t.Errorf("legacy 1h: got %d want 0 (no breakdown present)", legacy.CacheCreation1hTokens)
	}
}

func TestIsSessionFile(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	a := NewWithOptions(nil, root)
	if !a.IsSessionFile(filepath.Join(root, "x.jsonl")) {
		t.Error(".jsonl under watch root should be recognized")
	}
	if a.IsSessionFile(filepath.Join(root, "x.json")) {
		t.Error(".json should NOT be a session file")
	}
	// v1.4.51 invariant: same-shape file outside the watch root is
	// rejected. Closes the misrouting bug class where claude-code
	// claimed any .jsonl on disk regardless of location.
	if a.IsSessionFile("/tmp/foreign/x.jsonl") {
		t.Error(".jsonl outside watch root must NOT be recognized")
	}
}

// TestAssistantTextEmission pins the field shape of claudecode.assistant_text
// rows: ActionTaskComplete + 200-char preview in Target/PrecedingReasoning,
// up to 4000-char body in ToolOutput, MessageID prefers msg.id, SourceEventID
// embeds line.UUID + block index for re-parse stability. Also exercises the
// fallback path where msg.id is absent (compaction-style assistant records).
func TestAssistantTextEmission(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	body := strings.Join([]string{
		`{"sessionId":"s","cwd":"/tmp","gitBranch":"main","timestamp":"2026-05-12T00:00:00Z","uuid":"line-1","message":{"id":"msg_a","role":"assistant","model":"claude-sonnet-4-5","content":[{"type":"text","text":"First block."},{"type":"text","text":"Second block."}]}}`,
		`{"sessionId":"s","cwd":"/tmp","gitBranch":"main","timestamp":"2026-05-12T00:00:01Z","uuid":"line-2","message":{"role":"assistant","model":"claude-sonnet-4-5","content":[{"type":"text","text":"Compaction-style — no msg.id."}]}}`,
		`{"sessionId":"s","cwd":"/tmp","gitBranch":"main","timestamp":"2026-05-12T00:00:02Z","uuid":"line-3","message":{"role":"user","content":[{"type":"text","text":"User text — must NOT emit assistant_text."}]}}`,
	}, "\n") + "\n"
	p := filepath.Join(dir, "session.jsonl")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	res, err := New().ParseSessionFile(context.Background(), p, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}

	// Expected: 4 events total.
	//   [0] claudecode.assistant_text — line-1 block 0 ("First block.")
	//   [1] claudecode.assistant_text — line-1 block 1 ("Second block.")
	//   [2] claudecode.assistant_text — line-2 block 0 (no msg.id fallback)
	//   [3] user_prompt                — line-3 user text
	if len(res.ToolEvents) != 4 {
		t.Fatalf("ToolEvents: got %d want 4 (%+v)", len(res.ToolEvents), res.ToolEvents)
	}

	checks := []struct {
		idx             int
		text            string
		rawTool         string
		actionType      string
		wantMessageID   string
		wantSourceEvent string
	}{
		{0, "First block.", "claudecode.assistant_text", models.ActionAssistantMessage, "msg_a", "line-1:text:0"},
		{1, "Second block.", "claudecode.assistant_text", models.ActionAssistantMessage, "msg_a", "line-1:text:1"},
		{2, "Compaction-style — no msg.id.", "claudecode.assistant_text", models.ActionAssistantMessage, "asst:line-2", "line-2:text:0"},
	}
	for _, c := range checks {
		ev := res.ToolEvents[c.idx]
		if ev.RawToolName != c.rawTool {
			t.Errorf("event[%d] raw_tool_name = %q, want %q", c.idx, ev.RawToolName, c.rawTool)
		}
		if ev.ActionType != c.actionType {
			t.Errorf("event[%d] action_type = %q, want %q", c.idx, ev.ActionType, c.actionType)
		}
		if ev.Target != c.text {
			t.Errorf("event[%d] target = %q, want %q", c.idx, ev.Target, c.text)
		}
		if ev.ToolOutput != c.text {
			t.Errorf("event[%d] tool_output = %q, want %q", c.idx, ev.ToolOutput, c.text)
		}
		if ev.MessageID != c.wantMessageID {
			t.Errorf("event[%d] message_id = %q, want %q", c.idx, ev.MessageID, c.wantMessageID)
		}
		if ev.SourceEventID != c.wantSourceEvent {
			t.Errorf("event[%d] source_event_id = %q, want %q", c.idx, ev.SourceEventID, c.wantSourceEvent)
		}
		if ev.Tool != models.ToolClaudeCode {
			t.Errorf("event[%d] tool = %q, want %q", c.idx, ev.Tool, models.ToolClaudeCode)
		}
	}

	// Event [3]: user_prompt — confirms text blocks on role=user lines
	// do NOT emit assistant_text rows.
	up := res.ToolEvents[3]
	if up.ActionType != models.ActionUserPrompt {
		t.Errorf("event[3] action_type = %q, want user_prompt", up.ActionType)
	}
	if up.RawToolName != "user_message" {
		t.Errorf("event[3] raw_tool_name = %q, want user_message", up.RawToolName)
	}
}

func TestWatchPathsUsesHome(t *testing.T) {
	t.Parallel()
	a := New()
	paths := a.WatchPaths()
	if len(paths) == 0 {
		t.Fatal("expected at least the native-home watch path")
	}
	// Invariant: every emitted path ends with ".claude/projects".
	// Count alone isn't asserted because crossmount expansion adds one
	// path per /mnt/c/Users/<u> on WSL2 hosts (and per
	// \\wsl.localhost\<distro>\home\<user> on Windows hosts), and the
	// CI machine's user list is host-dependent.
	for _, p := range paths {
		if !strings.HasSuffix(p, filepath.Join(".claude", "projects")) {
			t.Errorf("watch path doesn't end with .claude/projects: %q", p)
		}
	}
	// Native home is always present and comes first.
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skip("UserHomeDir unavailable")
	}
	want := filepath.Join(home, ".claude", "projects")
	if paths[0] != want {
		t.Errorf("native-home path: got %q want %q (must come first)", paths[0], want)
	}
}

// TestWindowsCwdResolvedViaCrossmount pins the V7a fix: Claude Code
// on Windows records cwd as a Windows-style path (e.g. "C:\…"). On a
// Linux-side observer (WSL2), the adapter must run
// crossmount.TranslateForeignPath BEFORE git.Resolve, or filepath.Abs
// inside git.Resolve treats the unrecognised drive prefix as relative,
// prepends the observer's own CWD, and the .git-walk lands on the
// observer's own repo — misattributing every Windows-side claude-code
// session in the dashboard's project view.
//
// Audit B1 (2026-05-18 claude-code audit): 90 sessions / 3,536 rows
// affected on the maintainer DB before the fix.
func TestWindowsCwdResolvedViaCrossmount(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	p := filepath.Join(dir, "windows-cwd.jsonl")
	// cwd is the Windows path Claude Code writes; assistant line carries
	// real usage so a TokenEvent is emitted (whose ProjectRoot we inspect).
	body := `{"type":"assistant","sessionId":"s-win","cwd":"C:\\programsx\\superbased","uuid":"u1","timestamp":"2026-05-18T00:00:00Z","message":{"id":"msg_win","role":"assistant","model":"claude-opus-4-7","content":[{"type":"text","text":"ok"}],"usage":{"input_tokens":1,"output_tokens":1}}}
`
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	a := New()
	res, err := a.ParseSessionFile(context.Background(), p, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	if len(res.TokenEvents) != 1 {
		t.Fatalf("expected 1 TokenEvent, got %d", len(res.TokenEvents))
	}
	got := res.TokenEvents[0].ProjectRoot
	// The bug symptom we're regressing against: ProjectRoot ends up as
	// the test process's CWD (the observer's own repo when run from the
	// repo root). Assert the resolved path retains the foreign-path
	// shape — either translated to /mnt/c/... on Linux, left as C:\...
	// on Windows, or as-is fallback — but NEVER the observer's CWD.
	cwd, _ := os.Getwd()
	if got == cwd || strings.HasPrefix(got, cwd+string(filepath.Separator)) {
		t.Errorf("ProjectRoot=%q resolved to the observer's own CWD %q (B1 regression — crossmount.TranslateForeignPath missing before git.Resolve)", got, cwd)
	}
	// Post-fix: on a Linux host the path is translated to /mnt/c/…; on
	// Windows it stays C:\…; either way it's not the observer's CWD.
	wantLinux := "/mnt/c/programsx/superbased"
	wantWin := `C:\programsx\superbased`
	if got != wantLinux && got != wantWin {
		t.Logf("ProjectRoot=%q (acceptable as long as it's not observer-CWD; expected one of %q / %q)", got, wantLinux, wantWin)
	}
}

// TestCompactBoundaryCaptured pins V7d / audit B4: claude-code's
// `system / compact_boundary` lines carry compactMetadata.preTokens
// and the discovered-tools roster at compaction time. Pre-v1.6.10
// the adapter dropped them silently; post-fix they emit
// ActionContextCompacted rows mirroring the codex shape.
func TestCompactBoundaryCaptured(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	p := filepath.Join(dir, "compact.jsonl")
	// Real compact_boundary shape (sampled from session 853e0bc0).
	body := `{"type":"system","subtype":"compact_boundary","uuid":"u-comp","sessionId":"s-comp","cwd":"/tmp","timestamp":"2026-04-05T16:41:29.502Z","compactMetadata":{"trigger":"manual","preTokens":566341,"preCompactDiscoveredTools":["TaskCreate","TaskUpdate"]}}
`
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	a := New()
	res, err := a.ParseSessionFile(context.Background(), p, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	if len(res.ToolEvents) != 1 {
		t.Fatalf("expected 1 ToolEvent, got %d", len(res.ToolEvents))
	}
	ev := res.ToolEvents[0]
	if ev.ActionType != models.ActionContextCompacted {
		t.Errorf("ActionType=%q want %q", ev.ActionType, models.ActionContextCompacted)
	}
	if !strings.Contains(ev.Target, "566341") || !strings.Contains(ev.Target, "manual") {
		t.Errorf("Target=%q should mention 566341 preTokens + manual trigger", ev.Target)
	}
	if !strings.Contains(ev.RawToolInput, "TaskCreate") {
		t.Errorf("RawToolInput=%q should include discovered-tools list", ev.RawToolInput)
	}
}

// TestTurnDurationCaptured pins V7d / audit B4: `system /
// turn_duration` lines carry durationMs + messageCount with a
// parentUuid linking to the assistant message that ended the turn.
// Post-v1.6.10 the adapter emits an ActionPostToolBatch row with the
// duration so a future per-turn-time surface can use the authoritative
// wall-clock signal Claude Code already records.
func TestTurnDurationCaptured(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	p := filepath.Join(dir, "turn-dur.jsonl")
	body := `{"type":"system","subtype":"turn_duration","uuid":"u-td","sessionId":"s-td","cwd":"/tmp","timestamp":"2026-04-03T12:24:02.990Z","parentUuid":"6f0d73be-30e5-4c8d-b95b-6c26c5b2568a","durationMs":691917,"messageCount":177}
`
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	a := New()
	res, err := a.ParseSessionFile(context.Background(), p, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	if len(res.ToolEvents) != 1 {
		t.Fatalf("expected 1 ToolEvent, got %d", len(res.ToolEvents))
	}
	ev := res.ToolEvents[0]
	if ev.RawToolName != "turn_duration" {
		t.Errorf("RawToolName=%q want turn_duration", ev.RawToolName)
	}
	if ev.DurationMs != 691917 {
		t.Errorf("DurationMs=%d want 691917", ev.DurationMs)
	}
	if !strings.Contains(ev.RawToolInput, "6f0d73be") {
		t.Errorf("RawToolInput=%q should include parentUuid link", ev.RawToolInput)
	}
}

// TestAgentNameCapturedDedupedByName pins V7d / audit B4: agent-name
// lines re-emit the same persona name per assistant turn. The
// adapter emits ONE ActionSubagentStart per unique name (first-seen
// or change), not one per re-assertion line.
func TestAgentNameCapturedDedupedByName(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	p := filepath.Join(dir, "agent-name.jsonl")
	// First agent-name line establishes lastTs / lastCwd via the
	// timestamp-bearing assistant line. Then four agent-name lines
	// (three identical + one different) — expect 2 emitted events.
	body := `{"type":"assistant","sessionId":"s-an","cwd":"/tmp","uuid":"u-1","timestamp":"2026-04-05T10:00:00Z","message":{"id":"m1","role":"assistant","model":"opus","content":[{"type":"text","text":"x"}],"usage":{"output_tokens":1}}}
{"type":"agent-name","agentName":"enterprise-tier-foundation-plan","sessionId":"s-an"}
{"type":"agent-name","agentName":"enterprise-tier-foundation-plan","sessionId":"s-an"}
{"type":"agent-name","agentName":"enterprise-tier-foundation-plan","sessionId":"s-an"}
{"type":"agent-name","agentName":"other-persona","sessionId":"s-an"}
`
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	a := New()
	res, err := a.ParseSessionFile(context.Background(), p, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	var agentEvents []models.ToolEvent
	for _, ev := range res.ToolEvents {
		if ev.RawToolName == "agent-name" {
			agentEvents = append(agentEvents, ev)
		}
	}
	if len(agentEvents) != 2 {
		t.Fatalf("expected 2 agent-name events (deduped), got %d", len(agentEvents))
	}
	if agentEvents[0].Target != "enterprise-tier-foundation-plan" {
		t.Errorf("first agent-name Target=%q want enterprise-tier-foundation-plan", agentEvents[0].Target)
	}
	if agentEvents[1].Target != "other-persona" {
		t.Errorf("second agent-name Target=%q want other-persona", agentEvents[1].Target)
	}
}

// TestPermissionModeCapturedDedupedByMode pins V7d / audit B4: same
// dedup logic as agent-name. permission-mode is re-asserted per
// user prompt; only mode-CHANGE events get emitted.
func TestPermissionModeCapturedDedupedByMode(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	p := filepath.Join(dir, "perm.jsonl")
	body := `{"type":"assistant","sessionId":"s-pm","cwd":"/tmp","uuid":"u-1","timestamp":"2026-04-05T10:00:00Z","message":{"id":"m1","role":"assistant","model":"opus","content":[{"type":"text","text":"x"}],"usage":{"output_tokens":1}}}
{"type":"permission-mode","permissionMode":"default","sessionId":"s-pm"}
{"type":"permission-mode","permissionMode":"default","sessionId":"s-pm"}
{"type":"permission-mode","permissionMode":"plan","sessionId":"s-pm"}
{"type":"permission-mode","permissionMode":"plan","sessionId":"s-pm"}
{"type":"permission-mode","permissionMode":"acceptEdits","sessionId":"s-pm"}
`
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	a := New()
	res, err := a.ParseSessionFile(context.Background(), p, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	var modeEvents []models.ToolEvent
	for _, ev := range res.ToolEvents {
		if ev.ActionType == models.ActionPermissionMode {
			modeEvents = append(modeEvents, ev)
		}
	}
	if len(modeEvents) != 3 {
		t.Fatalf("expected 3 permission-mode events (deduped), got %d", len(modeEvents))
	}
	wantSequence := []string{"default", "plan", "acceptEdits"}
	for i, ev := range modeEvents {
		if ev.Target != wantSequence[i] {
			t.Errorf("permission-mode[%d].Target=%q want %q", i, ev.Target, wantSequence[i])
		}
	}
}

// TestBashDurationCappedAt30Min pins V7e / audit B5: any inferred
// per-tool wallclock above the Bash tool's documented 30-minute
// hard ceiling is a capture artifact (auto-compact stitch, session
// idle resume, etc.) and gets zeroed out, not silently double-counted
// into the dashboard's tool-time charts. Prior bash-duration audit
// measured 246.4 false hours across 62 rows on the maintainer corpus
// before this cap landed.
func TestBashDurationCappedAt30Min(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	p := filepath.Join(dir, "long-bash.jsonl")
	// tool_use at T=0, tool_result at T=2h (well over the 30min cap).
	// Pre-fix: DurationMs computed as 7,200,000 (2h). Post-fix: 0.
	body := `{"type":"assistant","sessionId":"s-bash","cwd":"/tmp","uuid":"u-asst","timestamp":"2026-04-03T10:00:00Z","message":{"id":"m1","role":"assistant","model":"opus","content":[{"type":"tool_use","id":"toolu_LongBash","name":"Bash","input":{"command":"sleep 1"}}],"usage":{"output_tokens":1}}}
{"type":"user","sessionId":"s-bash","cwd":"/tmp","uuid":"u-res","timestamp":"2026-04-03T12:00:00Z","message":{"role":"user","content":[{"type":"tool_result","tool_use_id":"toolu_LongBash","content":"done"}]}}
`
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	a := New()
	res, err := a.ParseSessionFile(context.Background(), p, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	var bash *models.ToolEvent
	for i := range res.ToolEvents {
		if res.ToolEvents[i].RawToolName == "Bash" {
			bash = &res.ToolEvents[i]
			break
		}
	}
	if bash == nil {
		t.Fatalf("no Bash ToolEvent emitted from fixture")
	}
	if bash.DurationMs != 0 {
		t.Errorf("DurationMs=%d (raw 2h gap above 30min cap) want 0 (capture-artifact zeroed)", bash.DurationMs)
	}
}

// TestBashDurationUnderCapPreserved pins that the V7e cap does NOT
// zero out legitimate Bash invocations under 30 minutes — the cap
// is forgiving of real long-running commands within the tool's ceiling.
func TestBashDurationUnderCapPreserved(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	p := filepath.Join(dir, "short-bash.jsonl")
	// 5-minute gap — well under the 30min cap.
	body := `{"type":"assistant","sessionId":"s-short","cwd":"/tmp","uuid":"u-asst","timestamp":"2026-04-03T10:00:00Z","message":{"id":"m1","role":"assistant","model":"opus","content":[{"type":"tool_use","id":"toolu_ShortBash","name":"Bash","input":{"command":"npm test"}}],"usage":{"output_tokens":1}}}
{"type":"user","sessionId":"s-short","cwd":"/tmp","uuid":"u-res","timestamp":"2026-04-03T10:05:00Z","message":{"role":"user","content":[{"type":"tool_result","tool_use_id":"toolu_ShortBash","content":"ok"}]}}
`
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	a := New()
	res, err := a.ParseSessionFile(context.Background(), p, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	var bash *models.ToolEvent
	for i := range res.ToolEvents {
		if res.ToolEvents[i].RawToolName == "Bash" {
			bash = &res.ToolEvents[i]
			break
		}
	}
	if bash == nil {
		t.Fatalf("no Bash ToolEvent emitted from fixture")
	}
	if bash.DurationMs != 300_000 {
		t.Errorf("DurationMs=%d want 300000 (5min under cap, must be preserved)", bash.DurationMs)
	}
}

// TestServerToolUseWebSearchRequestsCaptured pins the V7c / audit B3
// fix: Anthropic emits per-message server-side tool counts under
// message.usage.server_tool_use.{web_search_requests, web_fetch_requests}
// when the model uses native WebSearch / WebFetch. Pre-fix the
// adapter's rawUsage struct had no ServerToolUse field, so every
// JSONL-only WebSearch invocation silently lost its $0.01/call fee
// attribution. Post-fix the TokenEvent's WebSearchRequests carries
// the value forward into the cost engine.
func TestServerToolUseWebSearchRequestsCaptured(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	p := filepath.Join(dir, "websearch.jsonl")
	body := `{"type":"assistant","sessionId":"s-ws","cwd":"/tmp","uuid":"u-ws","timestamp":"2026-05-18T00:00:00Z","message":{"id":"msg_ws","role":"assistant","model":"claude-opus-4-7","content":[{"type":"text","text":"ok"}],"usage":{"input_tokens":10,"output_tokens":50,"server_tool_use":{"web_search_requests":3,"web_fetch_requests":1}}}}
`
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	a := New()
	res, err := a.ParseSessionFile(context.Background(), p, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	if len(res.TokenEvents) != 1 {
		t.Fatalf("expected 1 TokenEvent, got %d", len(res.TokenEvents))
	}
	if got, want := res.TokenEvents[0].WebSearchRequests, int64(3); got != want {
		t.Errorf("TokenEvent.WebSearchRequests=%d want %d (from server_tool_use.web_search_requests)", got, want)
	}
}

// TestServerToolUseAbsentImpliesZero pins that the adapter doesn't
// crash and emits zero WebSearchRequests on legacy / proxy-bypassed
// usage records that omit the server_tool_use object entirely (older
// Opus 4.5 shape, see scope doc §2c).
func TestServerToolUseAbsentImpliesZero(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	p := filepath.Join(dir, "no-ws.jsonl")
	body := `{"type":"assistant","sessionId":"s-old","cwd":"/tmp","uuid":"u-old","timestamp":"2026-05-18T00:00:00Z","message":{"id":"msg_old","role":"assistant","model":"claude-opus-4-5-20251101","content":[{"type":"text","text":"ok"}],"usage":{"input_tokens":10,"output_tokens":50}}}
`
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	a := New()
	res, err := a.ParseSessionFile(context.Background(), p, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	if len(res.TokenEvents) != 1 {
		t.Fatalf("expected 1 TokenEvent, got %d", len(res.TokenEvents))
	}
	if got := res.TokenEvents[0].WebSearchRequests; got != 0 {
		t.Errorf("TokenEvent.WebSearchRequests=%d want 0 (no server_tool_use in usage)", got)
	}
}

// TestSidechainTokenEventsFlagged pins migration 087's capture half: the
// line-level `isSidechain` bit rides TokenEvent.IsSidechain exactly as it
// already rides the tool events, so sub-agent usage rows persist flagged
// and the dashboard's per-sub-agent token/cost rollup can bucket them.
// Pre-fix only the ToolEvents carried the bit — usage rows silently
// counted toward no window.
func TestSidechainTokenEventsFlagged(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	p := filepath.Join(dir, "sidechain-tok.jsonl")
	body := `{"type":"assistant","sessionId":"s-side","cwd":"/tmp","uuid":"u-main","timestamp":"2026-08-21T10:00:00Z","message":{"role":"assistant","model":"claude-opus-4-8","content":[{"type":"text","text":"main"}],"usage":{"input_tokens":100,"output_tokens":10}}}
{"type":"assistant","sessionId":"s-side","cwd":"/tmp","uuid":"u-side","isSidechain":true,"timestamp":"2026-08-21T10:00:05Z","message":{"role":"assistant","model":"claude-opus-4-8","content":[{"type":"text","text":"side"}],"usage":{"input_tokens":200,"output_tokens":20}}}
`
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	a := New()
	res, err := a.ParseSessionFile(context.Background(), p, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	if len(res.TokenEvents) != 2 {
		t.Fatalf("expected 2 TokenEvents, got %d", len(res.TokenEvents))
	}
	for _, ev := range res.TokenEvents {
		want := ev.SourceEventID == "u-side" // no msg.id → line uuid is the key
		if got := ev.IsSidechain; got != want {
			t.Errorf("TokenEvent %s IsSidechain=%v want %v", ev.SourceEventID, got, want)
		}
	}
}

// TestFastModeSpeedCaptured pins the JSONL-path fast-tier capture: Opus
// 4.8's interactive `/fast` mode sends speed:"fast" on the request, and
// the response usage envelope — which the on-disk transcript mirrors —
// echoes it back as `usage.speed`. The adapter stamps TokenEvent.Fast so
// the cost engine applies Pricing.FastMultiplier on the JSONL path, the
// same way the proxy does on the api_turns path. The usage shape (incl.
// the co-resident service_tier:"standard") is the verbatim live capture
// from a real Claude Code 2.1.167 /fast turn. The table also locks the
// don't-conflate guard: service_tier:"standard" without speed → Fast=false.
func TestFastModeSpeedCaptured(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name  string
		usage string
		want  bool
	}{
		{
			name:  "speed_fast",
			usage: `"input_tokens":2361,"output_tokens":17,"service_tier":"standard","speed":"fast"`,
			want:  true,
		},
		{
			name:  "speed_absent",
			usage: `"input_tokens":2361,"output_tokens":17,"service_tier":"standard"`,
			want:  false,
		},
		{
			name:  "speed_empty",
			usage: `"input_tokens":2361,"output_tokens":17,"speed":""`,
			want:  false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			p := filepath.Join(dir, "fast.jsonl")
			body := `{"type":"assistant","sessionId":"s-fast","cwd":"/tmp","uuid":"u-fast","timestamp":"2026-06-06T23:32:34Z","message":{"id":"msg_fast","role":"assistant","model":"claude-opus-4-8","content":[{"type":"text","text":"ok"}],"usage":{` + tc.usage + `}}}
`
			if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			a := New()
			res, err := a.ParseSessionFile(context.Background(), p, 0)
			if err != nil {
				t.Fatalf("ParseSessionFile: %v", err)
			}
			if len(res.TokenEvents) != 1 {
				t.Fatalf("expected 1 TokenEvent, got %d", len(res.TokenEvents))
			}
			if got := res.TokenEvents[0].Fast; got != tc.want {
				t.Errorf("TokenEvent.Fast=%v want %v (usage: %s)", got, tc.want, tc.usage)
			}
		})
	}
}

func TestScrubbingAppliedToBashCommand(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	p := filepath.Join(dir, "secret.jsonl")
	body := `{"type":"assistant","sessionId":"s","cwd":"/tmp","uuid":"u","timestamp":"2026-04-16T00:00:00Z","message":{"role":"assistant","model":"m","content":[{"type":"tool_use","id":"t1","name":"Bash","input":{"command":"curl -H 'Authorization: Bearer sk-secret-abc123XYZ99999' https://api"}}]}}
`
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	a := New()
	res, err := a.ParseSessionFile(context.Background(), p, 0)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(res.ToolEvents) != 1 {
		t.Fatalf("expected 1 event, got %d", len(res.ToolEvents))
	}
	evt := res.ToolEvents[0]
	if strings.Contains(evt.Target, "sk-secret-abc123XYZ99999") {
		t.Errorf("secret leaked into target: %q", evt.Target)
	}
	if strings.Contains(evt.RawToolInput, "sk-secret-abc123XYZ99999") {
		t.Errorf("secret leaked into raw_tool_input: %q", evt.RawToolInput)
	}
}

// TestStampEffortFromSidecar verifies that the EffortLookup callback
// fills Metadata.EffortLevel on tool_use rows whose source_event_id
// matches the hook-captured Anthropic toolu_xxx ID, and leaves other
// rows alone. multi-tool-turn.jsonl emits sess-002 with three tool_use
// blocks (tu_p1 Grep / tu_p2 Glob / tu_p3 WebSearch); we stamp two of
// them and verify the third stays empty.
func TestStampEffortFromSidecar(t *testing.T) {
	t.Parallel()
	calls := 0
	a := New().WithEffortLookup(func(ctx context.Context, sid string) (map[string]string, error) {
		calls++
		if sid == "sess-002" {
			return map[string]string{"tu_p1": "max", "tu_p2": "low"}, nil
		}
		return nil, nil
	})
	res, err := a.ParseSessionFile(context.Background(), fixturePath(t, "multi-tool-turn.jsonl"), 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}

	want := map[string]string{
		"tu_p1": "max",
		"tu_p2": "low",
		"tu_p3": "",
	}
	got := map[string]string{}
	for _, ev := range res.ToolEvents {
		if ev.RawToolName == "" || ev.SourceEventID == "" {
			continue
		}
		if _, ok := want[ev.SourceEventID]; !ok {
			continue
		}
		eff := ""
		if ev.Metadata != nil {
			eff = ev.Metadata.EffortLevel
		}
		got[ev.SourceEventID] = eff
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("tool_use %s effort: got %q want %q", k, got[k], v)
		}
	}
	// Multi-session would call once per session; sess-002 only — exactly 1.
	if calls != 1 {
		t.Errorf("lookup call count: got %d want 1", calls)
	}
}

// TestStampEffortFromSidecar_NoLookup pins the default behavior: when
// WithEffortLookup is never wired, parse output is unchanged (no
// EffortLevel stamping, no spurious metadata allocation on tool_use
// rows).
func TestStampEffortFromSidecar_NoLookup(t *testing.T) {
	t.Parallel()
	a := New()
	res, err := a.ParseSessionFile(context.Background(), fixturePath(t, "multi-tool-turn.jsonl"), 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	for _, ev := range res.ToolEvents {
		if ev.RawToolName == "" {
			continue
		}
		if ev.Metadata != nil && ev.Metadata.EffortLevel != "" {
			t.Errorf("tool_use %s: leaked effort %q without lookup wired", ev.SourceEventID, ev.Metadata.EffortLevel)
		}
	}
}

// TestStampEffortFromSidecar_LookupError pins best-effort semantics:
// a callback that errors must NOT abort the parse — the tool_use rows
// still come back, just unstamped. Real-world cause: a DB-locked
// busy_timeout while the observer daemon is shutting down.
func TestStampEffortFromSidecar_LookupError(t *testing.T) {
	t.Parallel()
	a := New().WithEffortLookup(func(ctx context.Context, sid string) (map[string]string, error) {
		return nil, context.DeadlineExceeded
	})
	res, err := a.ParseSessionFile(context.Background(), fixturePath(t, "multi-tool-turn.jsonl"), 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	if len(res.ToolEvents) == 0 {
		t.Fatal("lookup error swallowed all events")
	}
	for _, ev := range res.ToolEvents {
		if ev.Metadata != nil && ev.Metadata.EffortLevel != "" {
			t.Errorf("tool_use %s: stamped despite lookup error", ev.SourceEventID)
		}
	}
}

// TestToolResultCrossTickEmitsOutcomeUpdate pins the parser half of the
// store outcome-update seam. A tool_use and its tool_result are separate
// JSONL records; when a watcher poll tick ends between them the call row
// is already persisted optimistically successful, and the next parse
// window resumes past the tool_use with an empty correlation map. The
// result must leave as an ActionOutcomeUpdate keyed by the SAME
// (source_file, bare tool_use id) pair toolUseEvent used — anything else
// silently drops the outcome, which the store's action upsert cannot
// recover (ON CONFLICT never touches success / error_message).
func TestToolResultCrossTickEmitsOutcomeUpdate(t *testing.T) {
	t.Parallel()
	const toolUseLine = `{"sessionId":"s","cwd":"/tmp","timestamp":"2026-07-09T10:00:00Z","uuid":"u-1","message":{"id":"msg_a","role":"assistant","model":"claude-sonnet-4-5","content":[{"type":"tool_use","id":"toolu_xt","name":"Bash","input":{"command":"go test ./..."}}]}}`

	cases := []struct {
		name       string
		resultLine string
		wantOK     bool
		wantErrMsg bool
		wantOutput string
	}{
		{
			name:       "error result",
			resultLine: `{"sessionId":"s","cwd":"/tmp","timestamp":"2026-07-09T10:00:05Z","uuid":"u-2","message":{"role":"user","content":[{"type":"tool_result","tool_use_id":"toolu_xt","content":"--- FAIL: TestFoo\nexit status 1","is_error":true}]}}`,
			wantOK:     false,
			wantErrMsg: true,
			wantOutput: "--- FAIL: TestFoo",
		},
		{
			name:       "success result",
			resultLine: `{"sessionId":"s","cwd":"/tmp","timestamp":"2026-07-09T10:00:05Z","uuid":"u-2","message":{"role":"user","content":[{"type":"tool_result","tool_use_id":"toolu_xt","content":"ok 12 tests","is_error":false}]}}`,
			wantOK:     true,
			wantOutput: "ok 12 tests",
		},
		{
			name:       "result with no tool_use_id is unkeyable and dropped",
			resultLine: `{"sessionId":"s","cwd":"/tmp","timestamp":"2026-07-09T10:00:05Z","uuid":"u-2","message":{"role":"user","content":[{"type":"tool_result","content":"orphan","is_error":true}]}}`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			p := filepath.Join(t.TempDir(), "session.jsonl")

			// Window 1: the transcript ends right after the tool_use.
			if err := os.WriteFile(p, []byte(toolUseLine+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			res1, err := New().ParseSessionFile(context.Background(), p, 0)
			if err != nil {
				t.Fatalf("first parse: %v", err)
			}
			if len(res1.ToolEvents) != 1 || res1.ToolEvents[0].SourceEventID != "toolu_xt" {
				t.Fatalf("first parse: got %+v, want one toolu_xt event", res1.ToolEvents)
			}
			if !res1.ToolEvents[0].Success {
				t.Error("first parse: call should be optimistically successful")
			}
			if !res1.ToolEvents[0].OutcomePending {
				t.Error("first parse: an unanswered call must be flagged OutcomePending, or the store files failure-context bookkeeping on an outcome nobody observed")
			}
			if len(res1.OutcomeUpdates) != 0 {
				t.Errorf("first parse emitted %d outcome updates, want 0", len(res1.OutcomeUpdates))
			}

			// Window 2: the result lands and the cursor resumes past the call.
			if err := os.WriteFile(p, []byte(toolUseLine+"\n"+tc.resultLine+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			res2, err := New().ParseSessionFile(context.Background(), p, res1.NewOffset)
			if err != nil {
				t.Fatalf("second parse: %v", err)
			}
			if len(res2.ToolEvents) != 0 {
				t.Errorf("second parse re-emitted %d tool events, want 0", len(res2.ToolEvents))
			}
			if tc.wantOutput == "" {
				if len(res2.OutcomeUpdates) != 0 {
					t.Fatalf("unkeyable result produced %+v, want no updates", res2.OutcomeUpdates)
				}
				return
			}

			// The same transcript parsed WHOLE resolves the pair
			// in-window, so nothing is left pending.
			resFull, err := New().ParseSessionFile(context.Background(), p, 0)
			if err != nil {
				t.Fatalf("full parse: %v", err)
			}
			if len(resFull.ToolEvents) == 0 || resFull.ToolEvents[0].OutcomePending {
				t.Errorf("in-window pairing left OutcomePending set: %+v", resFull.ToolEvents)
			}
			if len(res2.OutcomeUpdates) != 1 {
				t.Fatalf("OutcomeUpdates: got %d want 1 (%+v)", len(res2.OutcomeUpdates), res2.OutcomeUpdates)
			}
			up := res2.OutcomeUpdates[0]
			if up.SourceFile != p {
				t.Errorf("SourceFile = %q, want %q", up.SourceFile, p)
			}
			if up.SourceEventID != "toolu_xt" {
				t.Errorf("SourceEventID = %q, want the BARE tool_use id toolu_xt", up.SourceEventID)
			}
			if up.Success != tc.wantOK {
				t.Errorf("Success = %v, want %v", up.Success, tc.wantOK)
			}
			if tc.wantErrMsg && up.ErrorMessage == "" {
				t.Error("ErrorMessage empty on an is_error result")
			}
			if !tc.wantErrMsg && up.ErrorMessage != "" {
				t.Errorf("ErrorMessage = %q on a clean result, want empty", up.ErrorMessage)
			}
			if !strings.Contains(up.ToolOutput, tc.wantOutput) {
				t.Errorf("ToolOutput = %q, want it to contain %q", up.ToolOutput, tc.wantOutput)
			}
			if up.DurationMs != 0 {
				t.Errorf("DurationMs = %d, want 0 (the call timestamp lived in the prior window)", up.DurationMs)
			}
		})
	}
}

// TestToolResultOutputCappedAtContract pins the models.ToolEvent
// ToolOutput contract (1 MiB, enforced by internal/contentcap) on the
// claudecode tool_result path — in-window AND cross-tick, which share
// one harvest. A multi-megabyte result body (a `cat` of a large file,
// a verbose test log) previously left the adapter uncapped and rode
// straight into actions.raw_tool_output.
func TestToolResultOutputCappedAtContract(t *testing.T) {
	t.Parallel()
	huge := strings.Repeat("A", 3*contentcap.DefaultMaxBytes)
	body := strings.Join([]string{
		`{"sessionId":"s","cwd":"/tmp","timestamp":"2026-07-09T10:00:00Z","uuid":"u-1","message":{"id":"msg_a","role":"assistant","model":"claude-sonnet-4-5","content":[{"type":"tool_use","id":"toolu_big","name":"Bash","input":{"command":"cat big.log"}}]}}`,
		`{"sessionId":"s","cwd":"/tmp","timestamp":"2026-07-09T10:00:01Z","uuid":"u-2","message":{"role":"user","content":[{"type":"tool_result","tool_use_id":"toolu_big","content":"` + huge + `","is_error":false}]}}`,
	}, "\n") + "\n"
	p := filepath.Join(t.TempDir(), "big.jsonl")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	// contentcap.Cap appends a truncation marker, so the ceiling is the
	// cap PLUS that marker — measured, not assumed.
	ceiling := len(contentcap.Cap(strings.Repeat("B", contentcap.DefaultMaxBytes+1), contentcap.DefaultMaxBytes))

	res, err := New().ParseSessionFile(context.Background(), p, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	if len(res.ToolEvents) != 1 {
		t.Fatalf("ToolEvents: got %d want 1", len(res.ToolEvents))
	}
	if got := len(res.ToolEvents[0].ToolOutput); got > ceiling {
		t.Errorf("in-window ToolOutput = %d bytes, want <= %d (1 MiB + marker)", got, ceiling)
	}

	// Cross-tick: same harvest, same ceiling.
	half := int64(len(body) - len(strings.Split(body, "\n")[1]) - 1)
	res2, err := New().ParseSessionFile(context.Background(), p, half)
	if err != nil {
		t.Fatalf("resume parse: %v", err)
	}
	if len(res2.OutcomeUpdates) != 1 {
		t.Fatalf("OutcomeUpdates: got %d want 1", len(res2.OutcomeUpdates))
	}
	if got := len(res2.OutcomeUpdates[0].ToolOutput); got > ceiling {
		t.Errorf("cross-tick ToolOutput = %d bytes, want <= %d (1 MiB + marker)", got, ceiling)
	}
}

// TestExtractTarget is the per-tool target-picker table. The load-bearing
// row is `Skill`: the Claude Code Skill tool_use input is
// {"skill":"<name>","args":"…"}, and until wave 2 no case matched it, so
// every skill_invoke action carried an empty target and the skill's name
// lived only inside raw_tool_input — nothing a guidance.SkillKey join
// could land on. `args` is free user text and must stay out of the
// target.
func TestExtractTarget(t *testing.T) {
	t.Parallel()
	a := New()
	cases := []struct {
		name  string
		tool  string
		input string
		root  string
		want  string
	}{
		{"skill", "Skill", `{"skill":"update-config","args":"allow npm"}`, "", "update-config"},
		{"skill trimmed", "Skill", `{"skill":"  code-review  "}`, "", "code-review"},
		{"skill absent", "Skill", `{"args":"no skill key"}`, "", ""},
		{"skill empty", "Skill", `{"skill":"","args":"x"}`, "", ""},
		{"skill ignores args when skill missing", "Skill", `{"args":"deploy"}`, "", ""},
		{"read relative to root", "Read", `{"file_path":"/repo/a/b.go"}`, "/repo", "a/b.go"},
		{"read absolute without root", "Read", `{"file_path":"/repo/a/b.go"}`, "", "/repo/a/b.go"},
		{"grep pattern", "Grep", `{"pattern":"TODO"}`, "", "TODO"},
		{"glob pattern", "Glob", `{"pattern":"**/*.go"}`, "", "**/*.go"},
		{"websearch query", "WebSearch", `{"query":"sqlite index"}`, "", "sqlite index"},
		{"webfetch url", "WebFetch", `{"url":"https://example.com/x"}`, "", "https://example.com/x"},
		{"unmapped tool", "TodoWrite", `{"todos":[]}`, "", ""},
		{"empty input", "Skill", ``, "", ""},
		{"malformed input", "Skill", `{not json`, "", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := a.extractTarget(c.tool, []byte(c.input), c.root)
			if got != c.want {
				t.Errorf("extractTarget(%q, %q, %q) = %q, want %q", c.tool, c.input, c.root, got, c.want)
			}
		})
	}
}
