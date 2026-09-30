package kimicode

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/adapter"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/tooltax"
)

const (
	rootDemo    = "../../../testdata/kimicode/sessions"
	mainWire    = rootDemo + "/wd_demo-project_ab12cd34ef56/session_11111111-1111-4111-8111-111111111111/agents/main/wire.jsonl"
	winWire     = rootDemo + "/wd_winproj_ffee00112233/session_22222222-2222-4222-8222-222222222222/agents/main/wire.jsonl"
	malformWire = rootDemo + "/wd_malformed_445566778899/session_33333333-3333-4333-8333-333333333333/agents/main/wire.jsonl"
	subMainWire = rootDemo + "/wd_subagent_aabbccddeeff/session_44444444-4444-4444-8444-444444444444/agents/main/wire.jsonl"
	subResWire  = rootDemo + "/wd_subagent_aabbccddeeff/session_44444444-4444-4444-8444-444444444444/agents/researcher/wire.jsonl"
)

func parseAll(t *testing.T, path string) adapter.ParseResult {
	t.Helper()
	a := NewWithOptions(nil, rootDemo)
	res, err := a.ParseSessionFile(context.Background(), path, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile(%s): %v", path, err)
	}
	return res
}

func toolByAction(res adapter.ParseResult, action string) *models.ToolEvent {
	for i := range res.ToolEvents {
		if res.ToolEvents[i].ActionType == action {
			return &res.ToolEvents[i]
		}
	}
	return nil
}

func toolByRawName(res adapter.ParseResult, raw string) *models.ToolEvent {
	for i := range res.ToolEvents {
		if res.ToolEvents[i].RawToolName == raw {
			return &res.ToolEvents[i]
		}
	}
	return nil
}

func countAction(res adapter.ParseResult, action string) int {
	n := 0
	for _, e := range res.ToolEvents {
		if e.ActionType == action {
			n++
		}
	}
	return n
}

func TestName(t *testing.T) {
	if got := New().Name(); got != models.ToolKimiCode {
		t.Fatalf("Name() = %q, want %q", got, models.ToolKimiCode)
	}
	if got := New().Name(); got != "kimi-code" {
		t.Fatalf("Name() = %q, want kimi-code", got)
	}
}

func TestIsSessionFile(t *testing.T) {
	a := NewWithOptions(nil, rootDemo)
	abs, _ := filepath.Abs(mainWire)
	tests := []struct {
		name string
		path string
		want bool
	}{
		{"main wire under root", abs, true},
		{"foreign wire same shape", "/tmp/foreign/.kimi-code/sessions/wd_x/session_y/agents/main/wire.jsonl", false},
		{"wrong basename", filepath.Join(filepath.Dir(abs), "state.json"), false},
		{"not a wire file", filepath.Join(filepath.Dir(abs), "other.jsonl"), false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := a.IsSessionFile(tc.path); got != tc.want {
				t.Fatalf("IsSessionFile(%s) = %v, want %v", tc.path, got, tc.want)
			}
		})
	}
}

func TestParseMainSession(t *testing.T) {
	res := parseAll(t, mainWire)

	// Exactly one user prompt — the injected system-reminder is skipped.
	if n := countAction(res, models.ActionUserPrompt); n != 1 {
		t.Fatalf("user_prompt count = %d, want 1", n)
	}
	prompt := toolByAction(res, models.ActionUserPrompt)
	if !strings.Contains(prompt.RawToolInput, "hello.txt") {
		t.Errorf("prompt input = %q", prompt.RawToolInput)
	}
	if prompt.SessionID != "session_11111111-1111-4111-8111-111111111111" {
		t.Errorf("session id = %q", prompt.SessionID)
	}

	// Session start marker.
	if toolByAction(res, models.ActionSessionStart) == nil {
		t.Error("no session_start marker")
	}

	// Write → write_file with ContentBytes == len("hello from kimi") == 15.
	write := toolByRawName(res, "Write")
	if write == nil || write.ActionType != models.ActionWriteFile {
		t.Fatalf("Write mapping wrong: %+v", write)
	}
	if write.ContentBytes != 15 {
		t.Errorf("Write ContentBytes = %d, want 15", write.ContentBytes)
	}
	if !write.Success || write.ToolOutput == "" {
		t.Errorf("Write result not stamped: success=%v output=%q", write.Success, write.ToolOutput)
	}
	if write.Model != "gpt-4o" {
		t.Errorf("Write model = %q, want gpt-4o", write.Model)
	}

	// Bash → run_command, secret scrubbed.
	bash := toolByRawName(res, "Bash")
	if bash == nil || bash.ActionType != models.ActionRunCommand {
		t.Fatalf("Bash mapping wrong: %+v", bash)
	}
	if !strings.Contains(bash.RawToolInput, "[REDACTED]") {
		t.Errorf("Bash input not scrubbed: %q", bash.RawToolInput)
	}
	if strings.Contains(bash.RawToolInput, "0123456789abcdef") || strings.Contains(bash.RawToolInput, "sk-") {
		t.Errorf("Bash input leaked secret: %q", bash.RawToolInput)
	}

	// Grep → search_text, failed result.
	grep := toolByRawName(res, "Grep")
	if grep == nil || grep.ActionType != models.ActionSearchText {
		t.Fatalf("Grep mapping wrong: %+v", grep)
	}
	if grep.Success {
		t.Error("Grep should be marked failed")
	}
	if grep.ErrorMessage == "" {
		t.Error("Grep failure should carry an error message")
	}

	// Assistant message.
	if toolByAction(res, models.ActionAssistantMessage) == nil {
		t.Error("no assistant_message event")
	}

	// Project root from state.json workDir (non-git fallback).
	if prompt.ProjectRoot != "/home/auzy/demo-project" {
		t.Errorf("project root = %q, want /home/auzy/demo-project", prompt.ProjectRoot)
	}

	// Two token events with NET input (inputOther) + cache read carried.
	if len(res.TokenEvents) != 2 {
		t.Fatalf("token events = %d, want 2", len(res.TokenEvents))
	}
	t1, t2 := res.TokenEvents[0], res.TokenEvents[1]
	if t1.InputTokens != 18789 || t1.OutputTokens != 54 || t1.CacheReadTokens != 0 {
		t.Errorf("token1 = %+v", t1)
	}
	if t2.InputTokens != 55 || t2.OutputTokens != 30 || t2.CacheReadTokens != 18816 {
		t.Errorf("token2 = %+v", t2)
	}
	for _, te := range res.TokenEvents {
		if te.Model != "gpt-4o" {
			t.Errorf("token model = %q, want gpt-4o (provider prefix stripped)", te.Model)
		}
		if te.Source != models.TokenSourceJSONL || te.Reliability != models.ReliabilityApproximate {
			t.Errorf("token source/reliability = %s/%s", te.Source, te.Reliability)
		}
		if te.ReasoningTokens != 0 {
			t.Errorf("unexpected reasoning tokens = %d (no wire field exists)", te.ReasoningTokens)
		}
	}
}

func TestIdempotentReparse(t *testing.T) {
	a := NewWithOptions(nil, rootDemo)
	res1, err := a.ParseSessionFile(context.Background(), mainWire, 0)
	if err != nil {
		t.Fatal(err)
	}
	// A second parse resuming at the committed offset yields no new events.
	res2, err := a.ParseSessionFile(context.Background(), mainWire, res1.NewOffset)
	if err != nil {
		t.Fatal(err)
	}
	if len(res2.ToolEvents) != 0 || len(res2.TokenEvents) != 0 {
		t.Fatalf("resume from EOF produced events: %d tool, %d token", len(res2.ToolEvents), len(res2.TokenEvents))
	}
	if res2.NewOffset != res1.NewOffset {
		t.Fatalf("offset moved on empty resume: %d != %d", res2.NewOffset, res1.NewOffset)
	}
}

func TestIncrementalParseStableIDs(t *testing.T) {
	a := NewWithOptions(nil, rootDemo)
	// Full parse.
	full, err := a.ParseSessionFile(context.Background(), mainWire, 0)
	if err != nil {
		t.Fatal(err)
	}
	fullIDs := map[string]bool{}
	for _, e := range full.ToolEvents {
		fullIDs[e.SourceEventID] = true
	}
	for _, e := range full.TokenEvents {
		fullIDs["TOK:"+e.SourceEventID] = true
	}

	// Parse in two halves; every produced id must exist in the full parse
	// (deterministic ids survive a mid-file resume).
	half := full.NewOffset / 2
	part1, err := a.ParseSessionFile(context.Background(), mainWire, half)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range part1.ToolEvents {
		if !fullIDs[e.SourceEventID] {
			t.Errorf("resume produced unknown tool id %q", e.SourceEventID)
		}
	}
	for _, e := range part1.TokenEvents {
		if !fullIDs["TOK:"+e.SourceEventID] {
			t.Errorf("resume produced unknown token id %q", e.SourceEventID)
		}
	}
}

func TestMalformedLine(t *testing.T) {
	res := parseAll(t, malformWire)
	if len(res.Warnings) == 0 {
		t.Fatal("expected a warning for the malformed line")
	}
	// Parsing continues past the malformed line.
	if toolByAction(res, models.ActionUserPrompt) == nil {
		t.Error("prompt before malformed line dropped")
	}
	if toolByAction(res, models.ActionAssistantMessage) == nil {
		t.Error("assistant after malformed line dropped")
	}
	if len(res.TokenEvents) != 1 {
		t.Errorf("token events = %d, want 1 (after malformed line)", len(res.TokenEvents))
	}
}

func TestWindowsForwardSlashPath(t *testing.T) {
	res := parseAll(t, winWire)
	read := toolByRawName(res, "Read")
	if read == nil {
		t.Fatal("no Read event")
	}
	// The FORWARD-slash `C:/Users/...` workDir is translated to the WSL
	// mount by crossmount without any adapter-side fix.
	if read.ProjectRoot != "/mnt/c/Users/auzy_/winproj" {
		t.Fatalf("project root = %q, want /mnt/c/Users/auzy_/winproj", read.ProjectRoot)
	}
}

func TestSubagentSidechain(t *testing.T) {
	// Sub-agent trace: every event marked IsSidechain.
	sub := parseAll(t, subResWire)
	if len(sub.ToolEvents) == 0 {
		t.Fatal("no sub-agent events")
	}
	for _, e := range sub.ToolEvents {
		if !e.IsSidechain {
			t.Errorf("sub-agent event %s not marked IsSidechain", e.RawToolName)
		}
	}
	// Main trace: not sidechain, Agent call maps to spawn_subagent.
	main := parseAll(t, subMainWire)
	for _, e := range main.ToolEvents {
		if e.IsSidechain {
			t.Errorf("main event %s wrongly marked IsSidechain", e.RawToolName)
		}
	}
	if toolByRawName(main, "Agent").ActionType != models.ActionSpawnSubagent {
		t.Error("Agent should map to spawn_subagent")
	}
}

func TestReadTranscript(t *testing.T) {
	a := NewWithOptions(nil, rootDemo)
	sess := models.Session{ID: "session_11111111-1111-4111-8111-111111111111"}
	abs, _ := filepath.Abs(mainWire)
	msgs, err := a.ReadTranscript(context.Background(), sess, []string{abs})
	if err != nil {
		t.Fatalf("ReadTranscript: %v", err)
	}
	if len(msgs) < 2 {
		t.Fatalf("transcript too short: %d", len(msgs))
	}
	if msgs[0].Role != models.TranscriptUser || !strings.Contains(msgs[0].Text, "hello.txt") {
		t.Errorf("first message = %+v", msgs[0])
	}
	// Some assistant exchange carries a resolved tool call.
	foundResolved := false
	for _, m := range msgs {
		if m.Role != models.TranscriptAssistant {
			continue
		}
		for _, c := range m.ToolCalls {
			if c.Resolved {
				foundResolved = true
			}
		}
	}
	if !foundResolved {
		t.Error("expected at least one resolved tool call in the transcript")
	}
}

func TestReadTranscriptByWalk(t *testing.T) {
	// No hint: the reader must find the wire file by walking the root.
	a := NewWithOptions(nil, rootDemo)
	sess := models.Session{ID: "session_44444444-4444-4444-8444-444444444444"}
	msgs, err := a.ReadTranscript(context.Background(), sess, nil)
	if err != nil {
		t.Fatalf("ReadTranscript (walk): %v", err)
	}
	if len(msgs) == 0 {
		t.Fatal("no messages from walk-resolved transcript")
	}
}

// TestToolResultCrossTickEmitsOutcomeUpdate pins the parser half of the
// store outcome-update seam. A tool.call and its tool.result are separate
// wire records; when a poll tick ends between them the call row is
// already persisted optimistically successful and the next parse window
// resumes with an empty pendingCall map. The outcome must leave as an
// ActionOutcomeUpdate keyed by the same "tool:<id>" SourceEventID
// emitToolCall built — the store's action upsert cannot flip success /
// error_message, so a dropped update is permanent.
//
// The emit side keys on toolCallId||uuid and the result side on
// toolCallId||parentUuid; the cases below cover both the agreeing
// (toolCallId present) shape and the parentUuid fallback.
func TestToolResultCrossTickEmitsOutcomeUpdate(t *testing.T) {
	const (
		metaLine = `{"type": "metadata", "protocol_version": "1.4", "created_at": 1783573417212}`
		callLine = `{"type": "context.append_loop_event", "event": {"type": "tool.call", "uuid": "call_xt", "turnId": "0", "step": 1, "toolCallId": "call_xt", "name": "Bash", "args": {"command": "go test ./..."}, "display": {"kind": "command", "command": "go test ./...", "cwd": "/home/dev/proj", "language": "bash"}}, "time": 1783573418000}`
	)

	cases := []struct {
		name       string
		resultLine string
		wantOK     bool
		wantErrMsg bool
	}{
		{
			name:       "failed call keyed by toolCallId",
			resultLine: `{"type": "context.append_loop_event", "event": {"type": "tool.result", "parentUuid": "call_xt", "toolCallId": "call_xt", "result": {"error": "exit status 1: FAIL", "isError": true}}, "time": 1783573418200}`,
			wantErrMsg: true,
		},
		{
			name:       "successful call keyed by toolCallId",
			resultLine: `{"type": "context.append_loop_event", "event": {"type": "tool.result", "parentUuid": "call_xt", "toolCallId": "call_xt", "result": {"output": "ok 12 tests"}}, "time": 1783573418200}`,
			wantOK:     true,
		},
		{
			// No toolCallId: the result side falls back to parentUuid,
			// which the emit side wrote as the call's own uuid.
			name:       "failed call keyed by parentUuid fallback",
			resultLine: `{"type": "context.append_loop_event", "event": {"type": "tool.result", "parentUuid": "call_xt", "result": {"error": "exit status 1: FAIL", "isError": true}}, "time": 1783573418200}`,
			wantErrMsg: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			dst := filepath.Join(root, "wd_proj_ab12cd34ef56",
				"session_99999999-9999-4999-8999-999999999999", "agents", "main", "wire.jsonl")
			if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
				t.Fatal(err)
			}
			a := NewWithOptions(nil, root)

			// Window 1: the wire log ends right after the tool.call.
			if err := os.WriteFile(dst, []byte(metaLine+"\n"+callLine+"\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			res1, err := a.ParseSessionFile(context.Background(), dst, 0)
			if err != nil {
				t.Fatalf("first parse: %v", err)
			}
			var call *models.ToolEvent
			for i := range res1.ToolEvents {
				if res1.ToolEvents[i].SourceEventID == "tool:call_xt" {
					call = &res1.ToolEvents[i]
				}
			}
			if call == nil {
				t.Fatalf("first parse produced no tool:call_xt event: %+v", res1.ToolEvents)
			}
			if !call.Success {
				t.Error("first parse: call should be optimistically successful")
			}
			if !call.OutcomePending {
				t.Error("first parse: an unanswered call must be flagged OutcomePending, or the store files failure-context bookkeeping on an outcome nobody observed")
			}
			if len(res1.OutcomeUpdates) != 0 {
				t.Errorf("first parse emitted %d outcome updates, want 0", len(res1.OutcomeUpdates))
			}

			// Window 2: the result lands, cursor resumes past the call.
			if err := os.WriteFile(dst, []byte(metaLine+"\n"+callLine+"\n"+tc.resultLine+"\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			res2, err := a.ParseSessionFile(context.Background(), dst, res1.NewOffset)
			if err != nil {
				t.Fatalf("second parse: %v", err)
			}
			// The same transcript parsed WHOLE resolves the pair
			// in-window, so nothing is left pending.
			resFull, err := a.ParseSessionFile(context.Background(), dst, 0)
			if err != nil {
				t.Fatalf("full parse: %v", err)
			}
			var fullCall *models.ToolEvent
			for i := range resFull.ToolEvents {
				if resFull.ToolEvents[i].SourceEventID == "tool:call_xt" {
					fullCall = &resFull.ToolEvents[i]
				}
			}
			if fullCall == nil || fullCall.OutcomePending {
				t.Errorf("in-window pairing left OutcomePending set: %+v", resFull.ToolEvents)
			}
			if len(res2.OutcomeUpdates) != 1 {
				t.Fatalf("OutcomeUpdates: got %d want 1 (%+v)", len(res2.OutcomeUpdates), res2.OutcomeUpdates)
			}
			up := res2.OutcomeUpdates[0]
			if up.SourceFile != dst {
				t.Errorf("SourceFile = %q, want %q", up.SourceFile, dst)
			}
			if up.SourceEventID != "tool:call_xt" {
				t.Errorf("SourceEventID = %q, want tool:call_xt", up.SourceEventID)
			}
			if up.Success != tc.wantOK {
				t.Errorf("Success = %v, want %v", up.Success, tc.wantOK)
			}
			if tc.wantErrMsg && up.ErrorMessage == "" {
				t.Error("ErrorMessage empty on an isError result")
			}
			if !tc.wantErrMsg && up.ErrorMessage != "" {
				t.Errorf("ErrorMessage = %q on a clean result, want empty", up.ErrorMessage)
			}
			if up.ToolOutput == "" {
				t.Error("ToolOutput empty, want the result body")
			}
			if up.DurationMs != 0 {
				t.Errorf("DurationMs = %d, want 0 (the call lived in the prior window)", up.DurationMs)
			}
		})
	}
}

// TestMapKimiTool_V211Builtins pins the kimi-code 2.1.1 built-in tool
// names added 2026-09-28 (R2-TOOLMAP), spelled exactly as the shipped
// bundle registers them (@moonshot-ai/kimi-code 2.1.1 dist/main.mjs,
// `name = "..."`; source github.com/MoonshotAI/kimi-code
// packages/agent-core-v2). One case per new mapping, and each must agree
// with internal/tooltax through Resolve's normalized pass.
func TestMapKimiTool_V211Builtins(t *testing.T) {
	cases := []struct{ native, want string }{
		{"AskUserQuestion", models.ActionAskUser},
		{"EnterPlanMode", models.ActionPermissionMode},
		{"ExitPlanMode", models.ActionPermissionMode},
		{"Skill", models.ActionSkillInvoke},
		{"CronCreate", models.ActionSchedule},
		{"CronList", models.ActionSchedule},
		{"CronDelete", models.ActionSchedule},
		{"TaskList", models.ActionAgentControl},
		{"TaskOutput", models.ActionAgentControl},
		{"TaskStop", models.ActionAgentControl},
		{"WaitFor", models.ActionSubagentWait},
		{"NotifyUser", models.ActionNotification},
		{"CreateGoal", models.ActionHarnessCall},
		{"GetGoal", models.ActionHarnessCall},
		{"SetGoalBudget", models.ActionHarnessCall},
		{"UpdateGoal", models.ActionHarnessCall},
		{"TowerInit", models.ActionHarnessCall},
		{"TowerPlan", models.ActionTodoUpdate},
		{"TowerSpawn", models.ActionSpawnSubagent},
		{"TowerMerge", models.ActionHarnessCall},
		{"TowerTeardown", models.ActionWorktreeRemove},
		{"TowerSend", models.ActionAgentMessage},
		{"TowerInbox", models.ActionAgentControl},
		{"TowerFinding", models.ActionAgentMessage},
		{"TowerReview", models.ActionAgentMessage},
		{"TowerMission", models.ActionTodoUpdate},
		{"TowerStatus", models.ActionAgentControl},
	}
	for _, tc := range cases {
		t.Run(tc.native, func(t *testing.T) {
			if got := mapKimiTool(tc.native); got != tc.want {
				t.Errorf("mapKimiTool(%q) = %q, want %q", tc.native, got, tc.want)
			}
			e, ok := tooltax.Resolve(models.ToolKimiCode, tc.native)
			if !ok || e.Tool != models.ToolKimiCode || e.ActionType != tc.want {
				t.Errorf("tooltax.Resolve(kimi-code, %q) = %+v (ok=%v), want a kimi-code %q row", tc.native, e, ok, tc.want)
			}
		})
	}
}
