package codex

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/adapter"
	"github.com/marmutapp/superbased-observer/internal/models"
)

func fixture(t *testing.T, name string) string {
	t.Helper()
	return filepath.Join("..", "..", "..", "testdata", "codex", name)
}

// TestActionMap_ExecCommandAndShellVariants pins the v1.6.11 Issue #6
// codex additions: exec_command (the modern Codex Desktop tool name
// for shell exec — 260 historical maintainer-corpus rows were landing
// as ActionUnknown pre-fix), plus the Windows-shell-interpreter
// variants (powershell / pwsh / cmd.exe) that surface when codex's
// shell tool is invoked with a non-default interpreter.
func TestActionMap_ExecCommandAndShellVariants(t *testing.T) {
	t.Parallel()
	want := models.ActionRunCommand
	for _, name := range []string{
		// Pre-existing entries — guard against accidental removal.
		"shell",
		"shell_command",
		"exec",
		// New in v1.6.11.
		"exec_command",
		"powershell",
		"pwsh",
		"cmd.exe",
	} {
		if got := actionMap[name]; got != want {
			t.Errorf("actionMap[%q] = %q; want %q", name, got, want)
		}
	}
}

func TestActionMap_ObserverMCPHelpers(t *testing.T) {
	t.Parallel()
	want := models.ActionMCPCall
	for _, name := range []string{
		"list_mcp_resources",
		"list_mcp_resource_templates",
		"search_past_outputs",
		"get_session_summary",
		"get_project_patterns",
		"get_last_test_result",
		"get_session_recovery_context",
		"get_cost_summary",
		"check_command_freshness",
		"get_failure_context",
		"load_workspace_dependencies",
	} {
		if got := actionMap[name]; got != want {
			t.Errorf("actionMap[%q] = %q; want %q", name, got, want)
		}
	}
}

func TestAuthoredBytes(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name       string
		actionType string
		input      string
		want       int64
	}{
		{
			name:       "write counts content only",
			actionType: models.ActionWriteFile,
			input:      `{"path":"a.go","content":"package main"}`,
			want:       int64(len("package main")),
		},
		{
			name:       "edit counts replacement fields",
			actionType: models.ActionEditFile,
			input:      `{"old_string":"long old text","new_string":"new","new_source":"print(1)","edits":[{"old_string":"a","new_string":"bb"}]}`,
			want:       int64(len("new") + len("print(1)") + len("bb")),
		},
		{
			name:       "apply patch counts added lines only",
			actionType: models.ActionEditFile,
			input:      "*** Begin Patch\n*** Update File: a.go\n@@\n-old\n+new\n+next\n*** End Patch\n",
			want:       int64(len("new") + len("next")),
		},
		{
			name:       "command object counts command not envelope",
			actionType: models.ActionRunCommand,
			input:      `{"cmd":"go test ./...","workdir":"/repo"}`,
			want:       int64(len("go test ./...")),
		},
		{
			name:       "command array counts joined command",
			actionType: models.ActionRunCommand,
			input:      `["bash","-lc","go test ./..."]`,
			want:       int64(len("bash -lc go test ./...")),
		},
		{
			name:       "read authors nothing",
			actionType: models.ActionReadFile,
			input:      `{"path":"a.go"}`,
			want:       0,
		},
		{
			name:       "malformed write is zero",
			actionType: models.ActionWriteFile,
			input:      `{not json`,
			want:       0,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := authoredBytes(c.actionType, []byte(c.input)); got != c.want {
				t.Fatalf("authoredBytes(%s) = %d, want %d", c.actionType, got, c.want)
			}
		})
	}
}

func TestParseRolloutSession(t *testing.T) {
	t.Parallel()
	a := New()
	res, err := a.ParseSessionFile(context.Background(), fixture(t, "rollout-session.jsonl"), 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	if len(res.ToolEvents) != 3 {
		t.Fatalf("tool events: %d want 3", len(res.ToolEvents))
	}

	// file_read → read_file
	if res.ToolEvents[0].ActionType != models.ActionReadFile {
		t.Errorf("event 0: %s", res.ToolEvents[0].ActionType)
	}
	if res.ToolEvents[0].SessionID != "cx-001" {
		t.Errorf("event 0 session: %q", res.ToolEvents[0].SessionID)
	}
	if res.ToolEvents[0].Tool != models.ToolCodex {
		t.Errorf("event 0 tool: %q", res.ToolEvents[0].Tool)
	}
	if !res.ToolEvents[0].Success {
		t.Error("event 0 should be success")
	}
	if !strings.Contains(res.ToolEvents[0].Target, "main.go") {
		t.Errorf("event 0 target: %q", res.ToolEvents[0].Target)
	}

	// shell → run_command, failed
	e2 := res.ToolEvents[1]
	if e2.ActionType != models.ActionRunCommand {
		t.Errorf("event 1 action: %s", e2.ActionType)
	}
	if e2.Success {
		t.Error("event 1 should be failed (success=false)")
	}
	if !strings.Contains(e2.Target, "go test") {
		t.Errorf("event 1 target: %q", e2.Target)
	}
	if !strings.Contains(e2.ErrorMessage, "FAIL") {
		t.Errorf("event 1 error_message: %q", e2.ErrorMessage)
	}
	if !strings.Contains(e2.ToolOutput, "FAIL") {
		t.Errorf("event 1 tool_output: %q", e2.ToolOutput)
	}

	// web_search → web_search
	if res.ToolEvents[2].ActionType != models.ActionWebSearch {
		t.Errorf("event 2 action: %s", res.ToolEvents[2].ActionType)
	}
	if res.ToolEvents[2].Target != "go testing best practices" {
		t.Errorf("event 2 target: %q", res.ToolEvents[2].Target)
	}

	// Token events: 2 records, each carrying NET non-cached input
	// per-turn delta. Fixture's cumulative shape:
	//   tk1: gross=1000 cached=800 → net cumulative = 200 (delta = 200)
	//   tk2: gross=1600 cached=1200 → net cumulative = 400 (delta = 200)
	// Pre-v1.6.29 the adapter stored gross-input deltas (1000, 600)
	// and the cost engine then double-billed the cached portion at
	// the input rate. See internal/intelligence/cost/engine.go
	// TokenBundle docs for the NET-input contract.
	if len(res.TokenEvents) != 2 {
		t.Fatalf("token events: %d want 2", len(res.TokenEvents))
	}
	if res.TokenEvents[0].InputTokens != 200 {
		t.Errorf("tk1 input: %d want 200 (gross 1000 net of 800 cached)", res.TokenEvents[0].InputTokens)
	}
	if res.TokenEvents[1].InputTokens != 200 {
		t.Errorf("tk2 input (delta of net cumulative): %d want 200 (cum net 400 - prev 200)", res.TokenEvents[1].InputTokens)
	}
	if res.TokenEvents[0].Reliability != models.ReliabilityApproximate {
		t.Errorf("reliability: %q", res.TokenEvents[0].Reliability)
	}
	if res.TokenEvents[0].Tool != models.ToolCodex {
		t.Errorf("tk tool: %q", res.TokenEvents[0].Tool)
	}
	if res.TokenEvents[0].CacheReadTokens != 800 {
		t.Errorf("cache read: %d", res.TokenEvents[0].CacheReadTokens)
	}
}

// TestExecCommandFunctionCallTarget pins that an exec_command function_call (the
// modern Codex Desktop / CLI shell tool — {"cmd":"...","workdir":"..."}) lands
// its command in Target, the field the process→action message mapping
// (processobs.CorrelateActions) keys on. Regression: extractTarget once listed
// only "shell"/"shell_command", so exec_command fell through to an empty Target
// and codex process runs never mapped to the originating message/turn.
func TestExecCommandFunctionCallTarget(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "rollout-2026-06-19T01-20-23-thread.jsonl")
	body := strings.Join([]string{
		`{"timestamp":"2026-06-19T01:50:01.0Z","type":"session_meta","payload":{"id":"thread-x","cwd":"/home/u/proj","model":"gpt-5.4","git_branch":"main"}}`,
		`{"timestamp":"2026-06-19T01:50:02.0Z","type":"response_item","payload":{"type":"function_call","name":"exec_command","call_id":"call_K4","arguments":"{\"cmd\":\"python3 tmp/hello_every_2s.py\",\"workdir\":\"/home/u/proj\",\"yield_time_ms\":1000}"}}`,
		``,
	}, "\n")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	a := NewWithOptions(nil, dir)
	res, err := a.ParseSessionFile(context.Background(), path, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	var found *models.ToolEvent
	for i := range res.ToolEvents {
		if res.ToolEvents[i].RawToolName == "exec_command" {
			found = &res.ToolEvents[i]
			break
		}
	}
	if found == nil {
		t.Fatal("no exec_command tool event parsed")
	}
	if found.ActionType != models.ActionRunCommand {
		t.Errorf("action type = %s, want run_command", found.ActionType)
	}
	if found.Target != "python3 tmp/hello_every_2s.py" {
		t.Errorf("Target = %q, want %q", found.Target, "python3 tmp/hello_every_2s.py")
	}
}

// TestMergeExecZeroDurationFallsBackToTimestampGap pins §3.2: when an
// exec_command_end merges into its pending function_call but carries a zero
// structured Duration, the merge must fall back to the begin→end wall gap
// rather than clobbering DurationMs to 0 — mirroring the function_call_output
// path's fallback.
func TestMergeExecZeroDurationFallsBackToTimestampGap(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "rollout-2026-06-20T01-00-00-thread.jsonl")
	body := strings.Join([]string{
		`{"timestamp":"2026-06-20T01:00:00.0Z","type":"session_meta","payload":{"id":"thread-z","cwd":"/home/u/proj","model":"gpt-5.4","git_branch":"main"}}`,
		// function_call (begin) at +0.5s creates the pending row.
		`{"timestamp":"2026-06-20T01:00:00.500Z","type":"response_item","payload":{"type":"function_call","name":"exec_command","call_id":"call_z","arguments":"{\"cmd\":\"ls\",\"workdir\":\"/home/u/proj\"}"}}`,
		// exec_command_end (end) at +2.0s with a ZERO structured duration.
		`{"timestamp":"2026-06-20T01:00:02.000Z","type":"event_msg","payload":{"type":"exec_command_end","call_id":"call_z","command":["ls"],"cwd":"/home/u/proj","aggregated_output":"a\nb\n","exit_code":0,"duration":{"secs":0,"nanos":0},"status":"completed"}}`,
		``,
	}, "\n")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	a := NewWithOptions(nil, dir)
	res, err := a.ParseSessionFile(context.Background(), path, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	var got int64 = -1
	for _, e := range res.ToolEvents {
		if e.SourceEventID == "call_z" {
			got = e.DurationMs
		}
	}
	if got != 1500 {
		t.Errorf("DurationMs: got %d want 1500 (begin→end gap fallback on zero Duration)", got)
	}
}

func TestParseModernDesktopRollout(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows cwd (D:\\...) → /mnt/d canonicalization is a Linux/WSL-daemon-observing-a-Windows-mount behavior (windowsToWSLMnt short-circuits on Windows); can't run on a Windows host")
	}
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "rollout-2026-04-23T00-29-51-thread.jsonl")
	body := strings.Join([]string{
		`{"timestamp":"2026-04-22T19:00:01.055Z","type":"session_meta","payload":{"id":"thread-1","cwd":"D:\\programsx\\partner-names","model":"gpt-5.4","git_branch":"main"}}`,
		`{"timestamp":"2026-04-22T19:00:01.068Z","type":"event_msg","payload":{"type":"user_message","message":"Please run the tests\n"}}`,
		`{"timestamp":"2026-04-22T19:00:23.361Z","type":"event_msg","payload":{"type":"exec_command_end","call_id":"call_1","turn_id":"turn-1","command":["powershell","-Command","go test ./..."],"cwd":"D:\\programsx\\partner-names","aggregated_output":"FAIL\n","exit_code":1,"duration":{"secs":1,"nanos":500000000},"status":"failed"}}`,
		`{"timestamp":"2026-04-22T19:00:30.000Z","type":"event_msg","payload":{"type":"web_search_end","call_id":"ws_1","query":"codex rollout format"}}`,
		`{"timestamp":"2026-04-22T19:00:31.000Z","type":"event_msg","payload":{"type":"token_count","info":{"last_token_usage":{"input_tokens":10,"cached_input_tokens":4,"output_tokens":2,"reasoning_output_tokens":1,"total_tokens":12}}}}`,
		`{"timestamp":"2026-04-22T19:00:32.000Z","type":"event_msg","payload":{"type":"task_complete","turn_id":"turn-1","last_agent_message":"Done","completed_at":1776884432,"duration_ms":1234}}`,
		``,
	}, "\n")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	a := NewWithOptions(nil, dir)
	res, err := a.ParseSessionFile(context.Background(), path, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	if len(res.ToolEvents) != 4 {
		t.Fatalf("tool events: %d want 4", len(res.ToolEvents))
	}
	if res.ToolEvents[0].ActionType != models.ActionUserPrompt {
		t.Fatalf("event 0 action: %s", res.ToolEvents[0].ActionType)
	}
	if res.ToolEvents[0].MessageID != "user:turn-1" {
		t.Fatalf("event 0 message id: %q", res.ToolEvents[0].MessageID)
	}
	if res.ToolEvents[1].ActionType != models.ActionRunCommand || res.ToolEvents[1].Success {
		t.Fatalf("event 1: %+v", res.ToolEvents[1])
	}
	if res.ToolEvents[1].MessageID != "turn-1" {
		t.Fatalf("event 1 message id: %q", res.ToolEvents[1].MessageID)
	}
	if !strings.Contains(res.ToolEvents[1].Target, "go test ./...") {
		t.Fatalf("event 1 target: %q", res.ToolEvents[1].Target)
	}
	if res.ToolEvents[2].ActionType != models.ActionWebSearch {
		t.Fatalf("event 2 action: %s", res.ToolEvents[2].ActionType)
	}
	if res.ToolEvents[3].ActionType != models.ActionTaskComplete {
		t.Fatalf("event 3 action: %s", res.ToolEvents[3].ActionType)
	}

	if len(res.TokenEvents) != 1 {
		t.Fatalf("token events: %d want 1", len(res.TokenEvents))
	}
	// Modern path nets last_token_usage.input_tokens (10) against
	// cached_input_tokens (4) → InputTokens=6. CacheReadTokens
	// carries the 4 in its own column.
	if res.TokenEvents[0].InputTokens != 6 || res.TokenEvents[0].CacheReadTokens != 4 ||
		res.TokenEvents[0].ReasoningTokens != 1 {
		t.Fatalf("token event: %+v (want InputTokens=6 net of 4 cached)", res.TokenEvents[0])
	}
	// The wire's output_tokens (2) is GROSS — it already contains
	// reasoning_output_tokens (1). The adapter nets reasoning out of
	// OutputTokens so the cost engine (which bills Reasoning additively
	// at the output rate) doesn't double-bill it. The invariant that
	// pins the fix: net OutputTokens + ReasoningTokens == wire
	// output_tokens.
	if res.TokenEvents[0].OutputTokens != 1 {
		t.Fatalf("token event OutputTokens=%d, want 1 (wire 2 gross minus 1 reasoning)", res.TokenEvents[0].OutputTokens)
	}
	if got := res.TokenEvents[0].OutputTokens + res.TokenEvents[0].ReasoningTokens; got != 2 {
		t.Fatalf("net output + reasoning = %d, want 2 (wire output_tokens)", got)
	}
	// v1.7.24 (migration 032): MessageID is the per-event identifier
	// `tk:<file>:L<lineNum>`; TurnID carries the user-turn grouping
	// that pre-v1.7.24 was overloaded onto MessageID.
	wantTokenMsgID := fmt.Sprintf("tk:%s:L5", filepath.Base(path))
	if res.TokenEvents[0].MessageID != wantTokenMsgID {
		t.Fatalf("token event message id: %q want %q", res.TokenEvents[0].MessageID, wantTokenMsgID)
	}
	if res.TokenEvents[0].TurnID != "turn-1" {
		t.Fatalf("token event turn id: %q want turn-1", res.TokenEvents[0].TurnID)
	}
	if res.TokenEvents[0].Model != "gpt-5.4" {
		t.Fatalf("token event model: %q", res.TokenEvents[0].Model)
	}
	// v1.4.28 cwd translation: a Windows-style cwd ("D:\programsx\…")
	// captured by codex on Windows must NOT round-trip through
	// filepath.Abs on a Linux host (where it'd be treated as a relative
	// path, prepended with the test process's CWD, and walked up to
	// observer's own .git). Translate to the WSL2 mount equivalent so
	// ProjectRoot reflects the real source location.
	for i, e := range res.ToolEvents {
		if e.ProjectRoot != "/mnt/d/programsx/partner-names" {
			t.Errorf("event %d ProjectRoot: %q want /mnt/d/programsx/partner-names",
				i, e.ProjectRoot)
		}
	}
}

// TestCodexServiceTierCapture pins the Codex Fast mode capture (2026-06-08):
// the served tier is never in the rollout JSONL, so the adapter reads the
// operator's requested service_tier from the owning ~/.codex/config.toml and
// (a) stamps it on the message-row metadata (ServiceTier pill, like
// claudecode's transcript capture) and (b) sets TokenEvent.Fast when the
// tier is "priority" so the cost engine applies the gpt-5.x FastMultiplier.
// "default" is captured but is not fast; an absent config leaves both
// empty/false.
func TestCodexServiceTierCapture(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name     string
		tier     string // "" → no config.toml written
		wantTier string
		wantFast bool
	}{
		{"priority → fast + pill", "priority", "priority", true},
		{"default → captured, not fast", "default", "default", false},
		{"absent config → empty, not fast", "", "", false},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			tmp := t.TempDir()
			codexRoot := filepath.Join(tmp, ".codex")
			sessions := filepath.Join(codexRoot, "sessions", "2026", "06", "08")
			if err := os.MkdirAll(sessions, 0o755); err != nil {
				t.Fatal(err)
			}
			if tc.tier != "" {
				cfg := "model = \"gpt-5.4\"\nmodel_provider = \"openai-observer\"\nservice_tier = \"" +
					tc.tier + "\"\n\n[model_providers]\n  service_tier = \"ignored-in-table\"\n"
				if err := os.WriteFile(filepath.Join(codexRoot, "config.toml"), []byte(cfg), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			path := filepath.Join(sessions, "rollout-2026-06-08T00-00-00-thread.jsonl")
			body := strings.Join([]string{
				`{"timestamp":"2026-06-08T00:00:01Z","type":"session_meta","payload":{"id":"thread-tier","cwd":"/tmp/proj","model":"gpt-5.4","git_branch":"main"}}`,
				`{"timestamp":"2026-06-08T00:00:02Z","type":"turn_context","payload":{"turn_id":"turn-1","model":"gpt-5.4","cwd":"/tmp/proj"}}`,
				`{"timestamp":"2026-06-08T00:00:03Z","type":"event_msg","payload":{"type":"agent_message","turn_id":"turn-1","message":"Working on it"}}`,
				`{"timestamp":"2026-06-08T00:00:04Z","type":"event_msg","payload":{"type":"token_count","info":{"last_token_usage":{"input_tokens":10,"cached_input_tokens":4,"output_tokens":2,"reasoning_output_tokens":1,"total_tokens":12}}}}`,
				``,
			}, "\n")
			if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}

			a := NewWithOptions(nil, tmp)
			res, err := a.ParseSessionFile(context.Background(), path, 0)
			if err != nil {
				t.Fatalf("ParseSessionFile: %v", err)
			}

			// The assistant (agent_message) row carries the ServiceTier pill.
			var found bool
			for _, e := range res.ToolEvents {
				if e.RawToolName != "codex.assistant_text" {
					continue
				}
				found = true
				got := ""
				if e.Metadata != nil {
					got = e.Metadata.ServiceTier
				}
				if got != tc.wantTier {
					t.Errorf("agent_message ServiceTier = %q, want %q", got, tc.wantTier)
				}
			}
			if !found {
				t.Fatal("no codex.assistant_text row emitted")
			}

			// The token row carries Fast only for priority.
			if len(res.TokenEvents) != 1 {
				t.Fatalf("token events: %d want 1", len(res.TokenEvents))
			}
			if res.TokenEvents[0].Fast != tc.wantFast {
				t.Errorf("token Fast = %v, want %v", res.TokenEvents[0].Fast, tc.wantFast)
			}
		})
	}
}

// TestCodexConfigTierHelpers unit-tests the config.toml plumbing in
// isolation from the parse loop.
func TestCodexConfigTierHelpers(t *testing.T) {
	t.Parallel()

	// topLevelTomlString: top-level key before any [table], with quotes and
	// a trailing inline comment; same-named keys inside a table are ignored.
	doc := "model = \"gpt-5.4\"\nservice_tier = \"priority\"  # fast\n\n[model_providers]\nservice_tier = \"ignored\"\n"
	if got := topLevelTomlString(doc, "service_tier"); got != "priority" {
		t.Errorf("topLevelTomlString = %q, want priority", got)
	}
	if got := topLevelTomlString("model = \"x\"\n", "service_tier"); got != "" {
		t.Errorf("absent key = %q, want empty", got)
	}

	// codexRootFromRollout: the .codex root is the parent of sessions/.
	want := filepath.Join("/home", "u", ".codex")
	roll := filepath.Join(want, "sessions", "2026", "06", "08", "rollout-x.jsonl")
	if got := codexRootFromRollout(roll); got != want {
		t.Errorf("codexRootFromRollout = %q, want %q", got, want)
	}
	if got := codexRootFromRollout(filepath.Join("/tmp", "no-sessions", "rollout-x.jsonl")); got != "" {
		t.Errorf("codexRootFromRollout(no sessions) = %q, want empty", got)
	}
}

func TestParseModernTokenCountBeforeTurnContextStillGetsTurnModel(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "rollout-2026-04-29T00-00-00-thread.jsonl")
	body := strings.Join([]string{
		`{"timestamp":"2026-04-29T00:00:01.000Z","type":"session_meta","payload":{"id":"thread-2","cwd":"D:\\programsx\\partner-names","git_branch":"main"}}`,
		`{"timestamp":"2026-04-29T00:00:01.050Z","type":"event_msg","payload":{"type":"task_started","turn_id":"turn-2"}}`,
		`{"timestamp":"2026-04-29T00:00:01.100Z","type":"event_msg","payload":{"type":"user_message","message":"Check status\n"}}`,
		`{"timestamp":"2026-04-29T00:00:01.200Z","type":"event_msg","payload":{"type":"token_count","info":{"last_token_usage":{"input_tokens":12,"cached_input_tokens":5,"output_tokens":3,"reasoning_output_tokens":1,"total_tokens":15}}}}`,
		`{"timestamp":"2026-04-29T00:00:01.300Z","type":"turn_context","payload":{"turn_id":"turn-2","cwd":"D:\\programsx\\partner-names","model":"gpt-5.4","git_branch":"main"}}`,
		``,
	}, "\n")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	a := NewWithOptions(nil, dir)
	res, err := a.ParseSessionFile(context.Background(), path, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	if len(res.TokenEvents) != 1 {
		t.Fatalf("token events: %d want 1", len(res.TokenEvents))
	}
	// v1.7.24 (migration 032): per-event MessageID + TurnID for the
	// turn grouping. The token_count event is on line 4 of `body`
	// (1-indexed: session_meta L1, task_started L2, user_message L3,
	// token_count L4). Backfill at the prelude block fills in TurnID
	// once turn_context arrives on L5.
	wantTokenMsgID := fmt.Sprintf("tk:%s:L4", filepath.Base(path))
	if res.TokenEvents[0].MessageID != wantTokenMsgID {
		t.Fatalf("token message id: %q want %q", res.TokenEvents[0].MessageID, wantTokenMsgID)
	}
	if res.TokenEvents[0].TurnID != "turn-2" {
		t.Fatalf("token turn id: %q want turn-2", res.TokenEvents[0].TurnID)
	}
	if res.TokenEvents[0].Model != "gpt-5.4" {
		t.Fatalf("token model: %q", res.TokenEvents[0].Model)
	}
	if len(res.ToolEvents) != 1 || res.ToolEvents[0].MessageID != "user:turn-2" {
		t.Fatalf("user prompt grouping: %+v", res.ToolEvents)
	}
}

func TestParseForkedRolloutSessionMetaOwnership(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "rollout-2026-05-06T02-38-04-child.jsonl")
	body := strings.Join([]string{
		`{"timestamp":"2026-05-06T02:38:04.000Z","type":"session_meta","payload":{"id":"child-session","cwd":"D:\\programsx\\partner-names","model":"gpt-5.4","git_branch":"main"}}`,
		`{"timestamp":"2026-05-06T02:38:04.010Z","type":"session_meta","payload":{"id":"parent-session","cwd":"D:\\programsx\\partner-names","model":"gpt-5.4","git_branch":"main"}}`,
		`{"timestamp":"2026-05-06T02:38:04.020Z","type":"turn_context","payload":{"turn_id":"turn-child","cwd":"D:\\programsx\\partner-names","model":"gpt-5.4","git_branch":"main"}}`,
		`{"timestamp":"2026-05-06T02:38:05.000Z","type":"event_msg","payload":{"type":"exec_command_end","call_id":"call_child","turn_id":"turn-child","command":["powershell","-Command","go test ./..."],"cwd":"D:\\programsx\\partner-names","aggregated_output":"ok\n","exit_code":0,"duration":{"secs":0,"nanos":500000000},"status":"completed"}}`,
		`{"timestamp":"2026-05-06T02:38:06.000Z","type":"event_msg","payload":{"type":"token_count","info":{"last_token_usage":{"input_tokens":12,"cached_input_tokens":5,"output_tokens":3,"reasoning_output_tokens":1,"total_tokens":15}}}}`,
		``,
	}, "\n")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	a := NewWithOptions(nil, dir)
	assertChildOwnership := func(t *testing.T, res adapter.ParseResult) {
		t.Helper()
		if len(res.ToolEvents) != 1 {
			t.Fatalf("tool events: got %d want 1", len(res.ToolEvents))
		}
		if got := res.ToolEvents[0].SessionID; got != "child-session" {
			t.Fatalf("tool event session_id = %q; want child-session", got)
		}
		if got := res.ToolEvents[0].MessageID; got != "turn-child" {
			t.Fatalf("tool event message_id = %q; want turn-child", got)
		}
		if len(res.TokenEvents) != 1 {
			t.Fatalf("token events: got %d want 1", len(res.TokenEvents))
		}
		if got := res.TokenEvents[0].SessionID; got != "child-session" {
			t.Fatalf("token event session_id = %q; want child-session", got)
		}
		// v1.7.24 (migration 032): per-event MessageID, TurnID carries
		// the user-turn grouping. token_count is on L5 of the fixture
		// body (L1-L3 session_meta + turn_context, L4 exec_command_end,
		// L5 token_count).
		wantTokenMsgID := fmt.Sprintf("tk:%s:L5", filepath.Base(path))
		if got := res.TokenEvents[0].MessageID; got != wantTokenMsgID {
			t.Fatalf("token event message_id = %q; want %q", got, wantTokenMsgID)
		}
		if got := res.TokenEvents[0].TurnID; got != "turn-child" {
			t.Fatalf("token event turn_id = %q; want turn-child", got)
		}
	}

	full, err := a.ParseSessionFile(context.Background(), path, 0)
	if err != nil {
		t.Fatalf("full ParseSessionFile: %v", err)
	}
	assertChildOwnership(t, full)

	offset := int64(strings.Index(body, `{"timestamp":"2026-05-06T02:38:05.000Z"`))
	if offset <= 0 {
		t.Fatal("failed to locate resumed-parse offset")
	}
	resumed, err := a.ParseSessionFile(context.Background(), path, offset)
	if err != nil {
		t.Fatalf("resumed ParseSessionFile: %v", err)
	}
	assertChildOwnership(t, resumed)
}

// Owner-creation clock shared by the fork/subagent replay fixtures:
// payload timestamp 2026-07-16T20:32:04.469Z == unix second 1784233924.
const (
	forkOwnerCreateTS = "2026-07-16T20:32:04.469Z"
	forkReplayStartAt = 1784231668 // 19:54:28Z — earlier ⇒ replayed
	forkLiveStartAt   = 1784233924 // == owner second ⇒ live
)

// forkRolloutBody builds a synthetic fork/subagent rollout: the owning
// session_meta (with lineage markers) + a replayed parent session_meta,
// a replayed task_started governing two replayed token_count bursts
// (cumulative input to 670699), then the first LIVE task_started + live
// token_count (cumulative 688097; last_token_usage.input 17398 == the
// total delta). Shapes mirror the real 0.144 files in the diagnosis.
func forkRolloutBody(threadSource string) string {
	return strings.Join([]string{
		fmt.Sprintf(`{"timestamp":"2026-07-16T20:32:04.545Z","type":"session_meta","payload":{"id":"child-sess","session_id":"child-sess","forked_from_id":"parent-sess","parent_thread_id":"parent-sess","thread_source":%q,"timestamp":%q,"cwd":"/w","model":"gpt-5.6","git_branch":"main"}}`, threadSource, forkOwnerCreateTS),
		`{"timestamp":"2026-07-16T20:32:04.545Z","type":"session_meta","payload":{"id":"parent-sess","session_id":"parent-sess","timestamp":"2026-07-16T19:54:11.583Z","cwd":"/w","model":"gpt-5.6"}}`,
		fmt.Sprintf(`{"timestamp":"2026-07-16T20:32:04.545Z","type":"event_msg","payload":{"type":"task_started","turn_id":"turn-replay","started_at":%d}}`, forkReplayStartAt),
		`{"timestamp":"2026-07-16T20:32:04.546Z","type":"event_msg","payload":{"type":"token_count","info":{"last_token_usage":{"input_tokens":300000,"cached_input_tokens":0,"output_tokens":100,"reasoning_output_tokens":0,"total_tokens":300100},"total_token_usage":{"input_tokens":600000,"cached_input_tokens":0,"output_tokens":200,"reasoning_output_tokens":0,"total_tokens":600200}}}}`,
		`{"timestamp":"2026-07-16T20:32:04.547Z","type":"event_msg","payload":{"type":"token_count","info":{"last_token_usage":{"input_tokens":70699,"cached_input_tokens":0,"output_tokens":100,"reasoning_output_tokens":0,"total_tokens":70799},"total_token_usage":{"input_tokens":670699,"cached_input_tokens":0,"output_tokens":300,"reasoning_output_tokens":0,"total_tokens":670999}}}}`,
		fmt.Sprintf(`{"timestamp":"2026-07-16T20:32:04.646Z","type":"event_msg","payload":{"type":"task_started","turn_id":"turn-live","started_at":%d}}`, forkLiveStartAt),
		`{"timestamp":"2026-07-16T20:32:04.647Z","type":"event_msg","payload":{"type":"token_count","info":{"last_token_usage":{"input_tokens":17398,"cached_input_tokens":0,"output_tokens":237,"reasoning_output_tokens":88,"total_tokens":17635},"total_token_usage":{"input_tokens":688097,"cached_input_tokens":0,"output_tokens":537,"reasoning_output_tokens":88,"total_tokens":688634}}}}`,
		``,
	}, "\n")
}

// TestParseForkedRolloutReplaySkip pins the fork/subagent replay-skip
// (Part A): replayed parent token_count events emit NO token_usage rows,
// while the first LIVE event's delta is computed against the replayed
// cumulative total. Also asserts lineage capture (Part B).
func TestParseForkedRolloutReplaySkip(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name         string
		threadSource string
	}{
		{"user_fork", "user"},
		{"subagent", "subagent"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			path := filepath.Join(dir, "rollout-2026-07-16T20-32-04-child.jsonl")
			if err := os.WriteFile(path, []byte(forkRolloutBody(tc.threadSource)), 0o600); err != nil {
				t.Fatal(err)
			}
			res, err := NewWithOptions(nil, dir).ParseSessionFile(context.Background(), path, 0)
			if err != nil {
				t.Fatalf("ParseSessionFile: %v", err)
			}

			// (a) replayed token_count events (2) emit no rows; only the
			// single live event survives.
			if len(res.TokenEvents) != 1 {
				t.Fatalf("token events: got %d want 1 (replayed events must not emit)", len(res.TokenEvents))
			}
			// (b) first live delta == live_total(688097) − replayed_final(670699).
			if got := res.TokenEvents[0].InputTokens; got != 17398 {
				t.Errorf("first live InputTokens = %d; want 17398 (live_total − replayed_final)", got)
			}
			if got := res.TokenEvents[0].SessionID; got != "child-sess" {
				t.Errorf("token event session_id = %q; want child-sess", got)
			}

			// (f) lineage captured onto the owning session.
			if len(res.SessionLineages) != 1 {
				t.Fatalf("session lineages: got %d want 1", len(res.SessionLineages))
			}
			lin := res.SessionLineages[0]
			if lin.SessionID != "child-sess" || lin.ForkedFromID != "parent-sess" ||
				lin.ParentThreadID != "parent-sess" || lin.ThreadSource != tc.threadSource {
				t.Errorf("lineage = %+v; want child-sess/parent-sess/parent-sess/%s", lin, tc.threadSource)
			}
		})
	}
}

// TestParseUnforkedRolloutUnchanged is the control (c): a normal rollout
// (single session_meta, thread_source "user", no fork marker) emits every
// token_count row — the replay skip must never fire on an unmarked file.
func TestParseUnforkedRolloutUnchanged(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "rollout-2026-07-16T10-00-00-normal.jsonl")
	body := strings.Join([]string{
		fmt.Sprintf(`{"timestamp":"2026-07-16T10:00:00.000Z","type":"session_meta","payload":{"id":"norm-sess","session_id":"norm-sess","thread_source":"user","timestamp":"2026-07-16T10:00:00.000Z","cwd":"/w","model":"gpt-5.6","git_branch":"main"}}`),
		// task_started started_at earlier than the session_meta clock —
		// on an UNMARKED file this must NOT be read as replay.
		fmt.Sprintf(`{"timestamp":"2026-07-16T10:00:01.000Z","type":"event_msg","payload":{"type":"task_started","turn_id":"turn-1","started_at":%d}}`, forkReplayStartAt),
		`{"timestamp":"2026-07-16T10:00:02.000Z","type":"event_msg","payload":{"type":"token_count","info":{"last_token_usage":{"input_tokens":100,"cached_input_tokens":10,"output_tokens":20,"reasoning_output_tokens":0,"total_tokens":120},"total_token_usage":{"input_tokens":100,"cached_input_tokens":10,"output_tokens":20,"reasoning_output_tokens":0,"total_tokens":120}}}}`,
		`{"timestamp":"2026-07-16T10:00:03.000Z","type":"event_msg","payload":{"type":"token_count","info":{"last_token_usage":{"input_tokens":50,"cached_input_tokens":0,"output_tokens":10,"reasoning_output_tokens":0,"total_tokens":60},"total_token_usage":{"input_tokens":150,"cached_input_tokens":10,"output_tokens":30,"reasoning_output_tokens":0,"total_tokens":180}}}}`,
		``,
	}, "\n")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := NewWithOptions(nil, dir).ParseSessionFile(context.Background(), path, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	if len(res.TokenEvents) != 2 {
		t.Fatalf("token events: got %d want 2 (unmarked file must be unchanged)", len(res.TokenEvents))
	}
	// A normal codex session carries thread_source "user" — lineage
	// records it verbatim (fork ids empty).
	if len(res.SessionLineages) != 1 || res.SessionLineages[0].ThreadSource != "user" ||
		res.SessionLineages[0].ForkedFromID != "" {
		t.Errorf("lineage = %+v; want thread_source=user, no fork ids", res.SessionLineages)
	}
}

// TestReplayedTokenLines pins the exported backfill helper: it flags the
// same replayed line numbers the adapter skips, and returns an empty set
// for an unmarked file. A follow-up backfill command deletes the
// token_usage rows for these lines.
func TestReplayedTokenLines(t *testing.T) {
	t.Parallel()

	// Fork file: lines 4 and 5 are replayed token_count (governed by the
	// replayed task_started on line 3); line 7 is the live token_count.
	got, err := ReplayedTokenLines(strings.NewReader(forkRolloutBody("subagent")))
	if err != nil {
		t.Fatalf("ReplayedTokenLines: %v", err)
	}
	want := map[int]bool{4: true, 5: true}
	if len(got) != len(want) {
		t.Fatalf("replayed lines = %v; want %v", got, want)
	}
	for ln := range want {
		if !got[ln] {
			t.Errorf("line %d not flagged replayed; got %v", ln, got)
		}
	}
	if got[7] {
		t.Errorf("live token_count on line 7 wrongly flagged replayed")
	}

	// Unmarked file: no replayed lines.
	normal := `{"timestamp":"2026-07-16T10:00:00.000Z","type":"session_meta","payload":{"id":"norm","session_id":"norm","thread_source":"user","timestamp":"2026-07-16T10:00:00.000Z"}}` + "\n" +
		fmt.Sprintf(`{"timestamp":"2026-07-16T10:00:01.000Z","type":"event_msg","payload":{"type":"task_started","turn_id":"t","started_at":%d}}`, forkReplayStartAt) + "\n" +
		`{"timestamp":"2026-07-16T10:00:02.000Z","type":"event_msg","payload":{"type":"token_count","info":{"last_token_usage":{"input_tokens":1,"output_tokens":1,"total_tokens":2}}}}` + "\n"
	got2, err := ReplayedTokenLines(strings.NewReader(normal))
	if err != nil {
		t.Fatalf("ReplayedTokenLines(normal): %v", err)
	}
	if len(got2) != 0 {
		t.Errorf("unmarked file flagged replayed lines %v; want none", got2)
	}
}

// TestParseForkedRolloutIncrementalRace pins finding #1: a watcher poll
// that ends MID replay-burst must not let the resumed parse emit the
// remaining replayed history as live. The fork tracker is reconstructed
// from the prefix prefetch, so the second chunk still classifies the
// leftover replayed token_count as replayed. Across both chunks only the
// single live token event survives.
func TestParseForkedRolloutIncrementalRace(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "rollout-2026-07-16T20-32-04-child.jsonl")

	// Split the fork fixture and truncate mid-burst: chunk1 covers the
	// owner + replayed parent session_meta, the replayed task_started
	// (L3) and the FIRST replayed token_count (L4). The second replayed
	// token_count (L5) and the live turn (L6/L7) arrive in chunk2.
	lines := strings.Split(forkRolloutBody("subagent"), "\n")
	chunk1 := strings.Join(lines[:4], "\n") + "\n"
	if err := os.WriteFile(path, []byte(chunk1), 0o600); err != nil {
		t.Fatal(err)
	}
	a := NewWithOptions(nil, dir)

	first, err := a.ParseSessionFile(context.Background(), path, 0)
	if err != nil {
		t.Fatalf("first chunk parse: %v", err)
	}
	if len(first.TokenEvents) != 0 {
		t.Fatalf("first chunk emitted %d token events; want 0 (L4 is replayed)", len(first.TokenEvents))
	}
	// The owning session_meta is read in the first (fromOffset==0) chunk,
	// so lineage is emitted exactly once here.
	if len(first.SessionLineages) != 1 {
		t.Fatalf("first chunk session lineages = %d; want 1 (owner meta read this chunk)", len(first.SessionLineages))
	}

	// Grow the file to the full body; resume from where chunk1 ended.
	if err := os.WriteFile(path, []byte(forkRolloutBody("subagent")), 0o600); err != nil {
		t.Fatal(err)
	}
	second, err := a.ParseSessionFile(context.Background(), path, first.NewOffset)
	if err != nil {
		t.Fatalf("resumed parse: %v", err)
	}
	// Only the live token_count (L7) may emit; the leftover replayed
	// row (L5) must stay suppressed via the reconstructed tracker.
	if len(second.TokenEvents) != 1 {
		t.Fatalf("resumed parse emitted %d token events; want 1 (leftover replayed L5 must not emit)", len(second.TokenEvents))
	}
	if got := second.TokenEvents[0].InputTokens; got != 17398 {
		t.Errorf("live InputTokens = %d; want 17398", got)
	}
	if total := len(first.TokenEvents) + len(second.TokenEvents); total != 1 {
		t.Errorf("total token events across chunks = %d; want 1", total)
	}
	// The resumed chunk reads no session_meta itself (owner was in the
	// prefix, reconstructed by prefetch), so it must NOT re-emit lineage.
	if len(second.SessionLineages) != 0 {
		t.Errorf("resumed chunk session lineages = %d; want 0 (owner meta not read this chunk)", len(second.SessionLineages))
	}
}

// forkRolloutBodyWithMalformedTaskStarted builds a fork rollout whose
// replayed region is followed by a MALFORMED task_started, then a live
// token_count. Finding #2: the malformed record must CLEAR governance so
// the trailing token_count fails open as live (emitted at ingest; not
// marked by ReplayedTokenLines).
//
// Lines: 1 owner session_meta, 2 replayed parent session_meta,
// 3 replayed task_started, 4 replayed token_count, 5 malformed
// task_started (payload not an object), 6 live token_count.
func forkRolloutBodyWithMalformedTaskStarted() string {
	return strings.Join([]string{
		fmt.Sprintf(`{"timestamp":"2026-07-16T20:32:04.545Z","type":"session_meta","payload":{"id":"child-sess","session_id":"child-sess","forked_from_id":"parent-sess","parent_thread_id":"parent-sess","thread_source":"subagent","timestamp":%q,"cwd":"/w","model":"gpt-5.6","git_branch":"main"}}`, forkOwnerCreateTS),
		`{"timestamp":"2026-07-16T20:32:04.545Z","type":"session_meta","payload":{"id":"parent-sess","session_id":"parent-sess","timestamp":"2026-07-16T19:54:11.583Z","cwd":"/w","model":"gpt-5.6"}}`,
		fmt.Sprintf(`{"timestamp":"2026-07-16T20:32:04.545Z","type":"event_msg","payload":{"type":"task_started","turn_id":"turn-replay","started_at":%d}}`, forkReplayStartAt),
		`{"timestamp":"2026-07-16T20:32:04.546Z","type":"event_msg","payload":{"type":"token_count","info":{"last_token_usage":{"input_tokens":300000,"cached_input_tokens":0,"output_tokens":100,"reasoning_output_tokens":0,"total_tokens":300100},"total_token_usage":{"input_tokens":600000,"cached_input_tokens":0,"output_tokens":200,"reasoning_output_tokens":0,"total_tokens":600200}}}}`,
		// Malformed task_started: payload.type says task_started but the
		// body cannot unmarshal into taskStarted (started_at is a
		// string, and there's a stray non-numeric field). Clears gov.
		`{"timestamp":"2026-07-16T20:32:04.600Z","type":"event_msg","payload":{"type":"task_started","turn_id":"turn-x","started_at":"not-a-number"}}`,
		`{"timestamp":"2026-07-16T20:32:04.647Z","type":"event_msg","payload":{"type":"token_count","info":{"last_token_usage":{"input_tokens":17398,"cached_input_tokens":0,"output_tokens":237,"reasoning_output_tokens":88,"total_tokens":17635},"total_token_usage":{"input_tokens":688097,"cached_input_tokens":0,"output_tokens":537,"reasoning_output_tokens":88,"total_tokens":688634}}}}`,
		``,
	}, "\n")
}

// TestParseForkedRolloutMalformedTaskStartedClearsGovernance pins
// finding #2 on both the adapter and the backfill scan: a malformed
// task_started between the replayed and live regions clears governance,
// so the trailing live token_count still emits and is NOT flagged
// replayed.
func TestParseForkedRolloutMalformedTaskStartedClearsGovernance(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "rollout-2026-07-16T20-32-04-malformed.jsonl")
	if err := os.WriteFile(path, []byte(forkRolloutBodyWithMalformedTaskStarted()), 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := NewWithOptions(nil, dir).ParseSessionFile(context.Background(), path, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	// L4 replayed (suppressed), L6 live (emitted after gov cleared).
	if len(res.TokenEvents) != 1 {
		t.Fatalf("token events = %d; want 1 (L6 live emitted after malformed L5 clears governance)", len(res.TokenEvents))
	}
	if got := res.TokenEvents[0].InputTokens; got != 17398 {
		t.Errorf("live InputTokens = %d; want 17398", got)
	}

	// ReplayedTokenLines must flag L4 only — never L6 (the malformed L5
	// cleared governance, so L6 fails open as live).
	got, err := ReplayedTokenLines(strings.NewReader(forkRolloutBodyWithMalformedTaskStarted()))
	if err != nil {
		t.Fatalf("ReplayedTokenLines: %v", err)
	}
	if !got[4] {
		t.Errorf("L4 (replayed) not flagged; got %v", got)
	}
	if got[6] {
		t.Errorf("L6 (live, after malformed task_started) wrongly flagged replayed; got %v", got)
	}
}

// forkRolloutLinesWithMalformedRawLine builds a fork rollout whose
// replayed region is followed by a WHOLE malformed line — the envelope
// itself fails json.Unmarshal, as if the line that WOULD have been the
// live task_started got corrupted — then the live token_count. Residual:
// a whole-record envelope-unmarshal failure must ALSO clear governance
// (the earlier fix only handled a malformed task_started PAYLOAD under a
// well-formed envelope), or the live token_counts inherit replay
// governance and are wrongly suppressed at ingest / deleted by backfill.
//
// Lines: 1 owner session_meta, 2 replayed parent session_meta,
// 3 replayed task_started, 4 replayed token_count, 5 malformed raw line
// (not JSON), 6 live token_count.
func forkRolloutLinesWithMalformedRawLine() []string {
	return []string{
		fmt.Sprintf(`{"timestamp":"2026-07-16T20:32:04.545Z","type":"session_meta","payload":{"id":"child-sess","session_id":"child-sess","forked_from_id":"parent-sess","parent_thread_id":"parent-sess","thread_source":"subagent","timestamp":%q,"cwd":"/w","model":"gpt-5.6","git_branch":"main"}}`, forkOwnerCreateTS),
		`{"timestamp":"2026-07-16T20:32:04.545Z","type":"session_meta","payload":{"id":"parent-sess","session_id":"parent-sess","timestamp":"2026-07-16T19:54:11.583Z","cwd":"/w","model":"gpt-5.6"}}`,
		fmt.Sprintf(`{"timestamp":"2026-07-16T20:32:04.545Z","type":"event_msg","payload":{"type":"task_started","turn_id":"turn-replay","started_at":%d}}`, forkReplayStartAt),
		`{"timestamp":"2026-07-16T20:32:04.546Z","type":"event_msg","payload":{"type":"token_count","info":{"last_token_usage":{"input_tokens":300000,"cached_input_tokens":0,"output_tokens":100,"reasoning_output_tokens":0,"total_tokens":300100},"total_token_usage":{"input_tokens":670699,"cached_input_tokens":0,"output_tokens":300,"reasoning_output_tokens":0,"total_tokens":670999}}}}`,
		`this-is-not-json — a corrupted line that would have been the live task_started`,
		`{"timestamp":"2026-07-16T20:32:04.647Z","type":"event_msg","payload":{"type":"token_count","info":{"last_token_usage":{"input_tokens":17398,"cached_input_tokens":0,"output_tokens":237,"reasoning_output_tokens":88,"total_tokens":17635},"total_token_usage":{"input_tokens":688097,"cached_input_tokens":0,"output_tokens":537,"reasoning_output_tokens":88,"total_tokens":688634}}}}`,
	}
}

// TestParseForkedRolloutMalformedRawLineClearsGovernance pins the
// whole-record residual: a malformed ENVELOPE line between the replayed
// and live regions clears governance on the main parse loop, the
// prefetch reconstruction, AND the backfill scan, so the live
// token_count still emits and is never flagged replayed.
func TestParseForkedRolloutMalformedRawLineClearsGovernance(t *testing.T) {
	t.Parallel()
	lines := forkRolloutLinesWithMalformedRawLine()
	body := strings.Join(lines, "\n") + "\n"

	dir := t.TempDir()
	path := filepath.Join(dir, "rollout-2026-07-16T20-32-04-rawmalformed.jsonl")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	a := NewWithOptions(nil, dir)

	// Full parse: L4 replayed (suppressed), L6 live (emitted after the
	// malformed L5 clears governance).
	res, err := a.ParseSessionFile(context.Background(), path, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	if len(res.TokenEvents) != 1 {
		t.Fatalf("token events = %d; want 1 (L6 live emitted after malformed L5 clears governance)", len(res.TokenEvents))
	}
	if got := res.TokenEvents[0].InputTokens; got != 17398 {
		t.Errorf("live InputTokens = %d; want 17398", got)
	}

	// Backfill scan (reviewer repro: before the fix this returned
	// {4:true, 6:true}). L4 replayed, L6 live and NEVER flagged.
	got, err := ReplayedTokenLines(strings.NewReader(body))
	if err != nil {
		t.Fatalf("ReplayedTokenLines: %v", err)
	}
	if !got[4] {
		t.Errorf("L4 (replayed) not flagged; got %v", got)
	}
	if got[6] {
		t.Errorf("L6 (live, after malformed raw line) wrongly flagged replayed; got %v", got)
	}

	// Prefetch path: resume with the malformed L5 in the prefix. The
	// tracker is reconstructed by prefetchSessionContext, which must also
	// clear governance at L5 so the resumed parse emits L6 as live.
	offset := int64(strings.Index(body, lines[5]))
	if offset <= 0 {
		t.Fatal("failed to locate resumed-parse offset for L6")
	}
	resumed, err := a.ParseSessionFile(context.Background(), path, offset)
	if err != nil {
		t.Fatalf("resumed ParseSessionFile: %v", err)
	}
	if len(resumed.TokenEvents) != 1 {
		t.Fatalf("resumed token events = %d; want 1 (prefetch must clear gov at malformed L5)", len(resumed.TokenEvents))
	}
	if got := resumed.TokenEvents[0].InputTokens; got != 17398 {
		t.Errorf("resumed live InputTokens = %d; want 17398", got)
	}
}

// TestParseForkedRolloutWebSearchAbsorption pins finding #3: replayed
// web_search_end events must not have their per-request charge absorbed
// by the first live token_count row. The replayed token_count consumes
// (resets) the running web-search counter exactly as an emitted row
// would, so the surviving live row reports 0 replayed searches.
func TestParseForkedRolloutWebSearchAbsorption(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "rollout-2026-07-16T20-32-04-websearch.jsonl")
	// Owner + replayed parent meta, replayed task_started, a replayed
	// web_search_end (L4), the replayed token_count that governs it (L5),
	// then the live task_started + live token_count (L6/L7). The live row
	// must carry WebSearchRequests=0 (the replayed search belongs to the
	// suppressed replayed row).
	body := strings.Join([]string{
		fmt.Sprintf(`{"timestamp":"2026-07-16T20:32:04.545Z","type":"session_meta","payload":{"id":"child-sess","session_id":"child-sess","forked_from_id":"parent-sess","parent_thread_id":"parent-sess","thread_source":"subagent","timestamp":%q,"cwd":"/w","model":"gpt-5.6","git_branch":"main"}}`, forkOwnerCreateTS),
		`{"timestamp":"2026-07-16T20:32:04.545Z","type":"session_meta","payload":{"id":"parent-sess","session_id":"parent-sess","timestamp":"2026-07-16T19:54:11.583Z","cwd":"/w","model":"gpt-5.6"}}`,
		fmt.Sprintf(`{"timestamp":"2026-07-16T20:32:04.545Z","type":"event_msg","payload":{"type":"task_started","turn_id":"turn-replay","started_at":%d}}`, forkReplayStartAt),
		`{"timestamp":"2026-07-16T20:32:04.546Z","type":"event_msg","payload":{"type":"web_search_end","call_id":"ws-replay","turn_id":"turn-replay","query":"replayed search"}}`,
		`{"timestamp":"2026-07-16T20:32:04.547Z","type":"event_msg","payload":{"type":"token_count","info":{"last_token_usage":{"input_tokens":70699,"cached_input_tokens":0,"output_tokens":100,"reasoning_output_tokens":0,"total_tokens":70799},"total_token_usage":{"input_tokens":670699,"cached_input_tokens":0,"output_tokens":300,"reasoning_output_tokens":0,"total_tokens":670999}}}}`,
		fmt.Sprintf(`{"timestamp":"2026-07-16T20:32:04.646Z","type":"event_msg","payload":{"type":"task_started","turn_id":"turn-live","started_at":%d}}`, forkLiveStartAt),
		`{"timestamp":"2026-07-16T20:32:04.647Z","type":"event_msg","payload":{"type":"token_count","info":{"last_token_usage":{"input_tokens":17398,"cached_input_tokens":0,"output_tokens":237,"reasoning_output_tokens":88,"total_tokens":17635},"total_token_usage":{"input_tokens":688097,"cached_input_tokens":0,"output_tokens":537,"reasoning_output_tokens":88,"total_tokens":688634}}}}`,
		``,
	}, "\n")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := NewWithOptions(nil, dir).ParseSessionFile(context.Background(), path, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	if len(res.TokenEvents) != 1 {
		t.Fatalf("token events = %d; want 1 (replayed row suppressed)", len(res.TokenEvents))
	}
	if got := res.TokenEvents[0].WebSearchRequests; got != 0 {
		t.Errorf("live WebSearchRequests = %d; want 0 (replayed search must not be absorbed)", got)
	}
}

// TestParseForkedRolloutDuplicateTotalWebSearchAbsorption pins the
// residual on the identical-total dedup path: a replayed token (L4),
// a replayed web_search_end (L5), then a DUPLICATE replayed token with
// the same total (L6) that early-continues at the seenModernTotal dedup
// BEFORE the replay-skip branch. Without resetting the running search
// tally in that early-continue, the phantom search leaks onto the first
// live row ($0.01 each). The surviving live row must report 0.
func TestParseForkedRolloutDuplicateTotalWebSearchAbsorption(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "rollout-2026-07-16T20-32-04-duptotal.jsonl")
	body := strings.Join([]string{
		fmt.Sprintf(`{"timestamp":"2026-07-16T20:32:04.545Z","type":"session_meta","payload":{"id":"child-sess","session_id":"child-sess","forked_from_id":"parent-sess","parent_thread_id":"parent-sess","thread_source":"subagent","timestamp":%q,"cwd":"/w","model":"gpt-5.6","git_branch":"main"}}`, forkOwnerCreateTS),
		`{"timestamp":"2026-07-16T20:32:04.545Z","type":"session_meta","payload":{"id":"parent-sess","session_id":"parent-sess","timestamp":"2026-07-16T19:54:11.583Z","cwd":"/w","model":"gpt-5.6"}}`,
		fmt.Sprintf(`{"timestamp":"2026-07-16T20:32:04.545Z","type":"event_msg","payload":{"type":"task_started","turn_id":"turn-replay","started_at":%d}}`, forkReplayStartAt),
		// L4 replayed token_count (total 670699) → replay-skip resets tally.
		`{"timestamp":"2026-07-16T20:32:04.546Z","type":"event_msg","payload":{"type":"token_count","info":{"last_token_usage":{"input_tokens":70699,"cached_input_tokens":0,"output_tokens":100,"reasoning_output_tokens":0,"total_tokens":70799},"total_token_usage":{"input_tokens":670699,"cached_input_tokens":0,"output_tokens":300,"reasoning_output_tokens":0,"total_tokens":670999}}}}`,
		// L5 replayed web_search_end → increments tally to 1.
		`{"timestamp":"2026-07-16T20:32:04.547Z","type":"event_msg","payload":{"type":"web_search_end","call_id":"ws-replay","turn_id":"turn-replay","query":"replayed search"}}`,
		// L6 DUPLICATE replayed token_count (identical total 670699) →
		// early-continues at seenModernTotal dedup; must reset tally.
		`{"timestamp":"2026-07-16T20:32:04.548Z","type":"event_msg","payload":{"type":"token_count","info":{"last_token_usage":{"input_tokens":70699,"cached_input_tokens":0,"output_tokens":100,"reasoning_output_tokens":0,"total_tokens":70799},"total_token_usage":{"input_tokens":670699,"cached_input_tokens":0,"output_tokens":300,"reasoning_output_tokens":0,"total_tokens":670999}}}}`,
		fmt.Sprintf(`{"timestamp":"2026-07-16T20:32:04.646Z","type":"event_msg","payload":{"type":"task_started","turn_id":"turn-live","started_at":%d}}`, forkLiveStartAt),
		`{"timestamp":"2026-07-16T20:32:04.647Z","type":"event_msg","payload":{"type":"token_count","info":{"last_token_usage":{"input_tokens":17398,"cached_input_tokens":0,"output_tokens":237,"reasoning_output_tokens":88,"total_tokens":17635},"total_token_usage":{"input_tokens":688097,"cached_input_tokens":0,"output_tokens":537,"reasoning_output_tokens":88,"total_tokens":688634}}}}`,
		``,
	}, "\n")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := NewWithOptions(nil, dir).ParseSessionFile(context.Background(), path, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	if len(res.TokenEvents) != 1 {
		t.Fatalf("token events = %d; want 1 (replayed + duplicate suppressed)", len(res.TokenEvents))
	}
	if got := res.TokenEvents[0].WebSearchRequests; got != 0 {
		t.Errorf("live WebSearchRequests = %d; want 0 (duplicate-total dedup must reset the replayed tally)", got)
	}
}

// TestReplayedTokenLinesMargin pins finding #4: the DESTRUCTIVE
// ReplayedTokenLines scan applies a 2s safety margin, so a replayed turn
// that started only 1s before owner creation is NOT marked for deletion
// (even though ingest, at strict-<, suppresses it). Guards live rows
// against second-boundary / clock-regression auto-deletes.
func TestReplayedTokenLinesMargin(t *testing.T) {
	t.Parallel()
	// Owner created at forkOwnerCreateTS (unix forkLiveStartAt); the
	// replayed task_started starts exactly 1s earlier — inside the 2s
	// margin, so ReplayedTokenLines must not flag its token_count (L4).
	oneSecBefore := int64(forkLiveStartAt) - 1
	body := strings.Join([]string{
		fmt.Sprintf(`{"timestamp":"2026-07-16T20:32:04.545Z","type":"session_meta","payload":{"id":"child-sess","session_id":"child-sess","forked_from_id":"parent-sess","parent_thread_id":"parent-sess","thread_source":"subagent","timestamp":%q,"cwd":"/w","model":"gpt-5.6"}}`, forkOwnerCreateTS),
		`{"timestamp":"2026-07-16T20:32:04.545Z","type":"session_meta","payload":{"id":"parent-sess","session_id":"parent-sess","timestamp":"2026-07-16T19:54:11.583Z","cwd":"/w"}}`,
		fmt.Sprintf(`{"timestamp":"2026-07-16T20:32:04.545Z","type":"event_msg","payload":{"type":"task_started","turn_id":"turn-1s","started_at":%d}}`, oneSecBefore),
		`{"timestamp":"2026-07-16T20:32:04.546Z","type":"event_msg","payload":{"type":"token_count","info":{"last_token_usage":{"input_tokens":100,"cached_input_tokens":0,"output_tokens":10,"reasoning_output_tokens":0,"total_tokens":110},"total_token_usage":{"input_tokens":100,"cached_input_tokens":0,"output_tokens":10,"reasoning_output_tokens":0,"total_tokens":110}}}}`,
		``,
	}, "\n")

	// Backfill (destructive) path: margin 2s → NOT flagged.
	got, err := ReplayedTokenLines(strings.NewReader(body))
	if err != nil {
		t.Fatalf("ReplayedTokenLines: %v", err)
	}
	if got[4] {
		t.Errorf("L4 (1s before owner) flagged by destructive scan; want unflagged (2s margin)")
	}

	// Ingest (strict-<) path: the same turn IS suppressed. Assert via
	// the adapter: the token_count emits no row.
	dir := t.TempDir()
	path := filepath.Join(dir, "rollout-2026-07-16T20-32-04-margin.jsonl")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := NewWithOptions(nil, dir).ParseSessionFile(context.Background(), path, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	if len(res.TokenEvents) != 0 {
		t.Errorf("ingest emitted %d token events; want 0 (strict-< suppresses the 1s-before replayed row)", len(res.TokenEvents))
	}
}

// TestParseRolloutResponseItem pins the response_item envelope dispatch
// + dedup behavior introduced in v1.4.21. The fixture exercises seven
// distinct shapes from real Codex Desktop rollouts:
//
//  1. response_item/function_call(shell_command, call_paired) followed
//     by event_msg/exec_command_end(call_paired) → merged into a single
//     ActionRunCommand row carrying the richer end-event fields
//     (success, exit_code, duration, stdout). No double-counting.
//  2. response_item/function_call(shell_command, call_orphan) with NO
//     matching exec_command_end → standalone ActionRunCommand row from
//     the call alone (the user-flagged "first call without end" case).
//  3. response_item/function_call(update_plan, call_plan) with no
//     side-channel → standalone ActionTodoUpdate row.
//  4. response_item/web_search_call (no-op for Tier 1) followed by
//     event_msg/web_search_end → single ActionWebSearch row with the
//     query resolved from the end event. The response_item line MUST
//     NOT create a row in Tier 1.
//  5. response_item/custom_tool_call(apply_patch) +
//     custom_tool_call_output + event_msg/patch_apply_end → single
//     ActionEditFile row with success=true and target from the
//     post-execution `changes` map (preferred over the in-patch path).
//  6. response_item/custom_tool_call(apply_patch) WITHOUT patch_apply_end
//     → standalone ActionEditFile row with target parsed from the patch
//     text (the "*** Update File:" header).
//  7. event_msg/patch_apply_end without a paired custom_tool_call
//     (mid-session resume) → standalone ActionEditFile row.
func TestParseRolloutResponseItem(t *testing.T) {
	t.Parallel()
	a := New()
	res, err := a.ParseSessionFile(context.Background(), fixture(t, "rollout-response-item.jsonl"), 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	if len(res.ToolEvents) != 17 {
		var summary []string
		for i, evt := range res.ToolEvents {
			summary = append(summary, formatEventSummary(i, evt))
		}
		t.Fatalf("tool events: %d want 17\n%s", len(res.ToolEvents), strings.Join(summary, "\n"))
	}

	// 0: user_prompt
	if res.ToolEvents[0].ActionType != models.ActionUserPrompt {
		t.Errorf("event 0 action: %s", res.ToolEvents[0].ActionType)
	}

	// 1: codex.assistant_text — emitted from the agent_message line that
	// precedes the tool calls (also feeds the per-turn PrecedingReasoning
	// chain on the following tool events).
	row := res.ToolEvents[1]
	if row.ActionType != models.ActionAssistantMessage {
		t.Errorf("event 1 action: %s want assistant_message", row.ActionType)
	}
	if row.RawToolName != "codex.assistant_text" {
		t.Errorf("event 1 raw_tool_name: %q want codex.assistant_text", row.RawToolName)
	}
	if row.ToolOutput == "" {
		t.Errorf("event 1 tool_output empty; want agent_message body")
	}

	// 2: paired shell_command — merged.
	row = res.ToolEvents[2]
	if row.ActionType != models.ActionRunCommand {
		t.Errorf("event 2 action: %s want run_command", row.ActionType)
	}
	if !row.Success {
		t.Errorf("event 2 should be success (exit_code=0)")
	}
	if !strings.Contains(row.Target, "go test ./...") {
		t.Errorf("event 2 target should carry merged command: %q", row.Target)
	}
	if row.DurationMs != 1250 {
		t.Errorf("event 2 duration_ms: %d want 1250", row.DurationMs)
	}
	if !strings.Contains(row.ToolOutput, "ok all tests pass") {
		t.Errorf("event 2 tool_output: %q", row.ToolOutput)
	}
	if row.RawToolName != "exec_command_end" {
		t.Errorf("event 2 raw_tool_name: %q want exec_command_end (post-merge)", row.RawToolName)
	}
	if row.SourceEventID != "call_paired" {
		t.Errorf("event 2 source_event_id: %q want call_paired", row.SourceEventID)
	}
	if want := int64(len("bash -lc go test ./...")); row.ContentBytes != want {
		t.Errorf("event 2 content_bytes: %d want %d", row.ContentBytes, want)
	}

	// 3: orphan shell_command.
	row = res.ToolEvents[3]
	if row.ActionType != models.ActionRunCommand {
		t.Errorf("event 3 action: %s want run_command", row.ActionType)
	}
	if row.RawToolName != "shell_command" {
		t.Errorf("event 3 raw_tool_name: %q want shell_command (pre-merge)", row.RawToolName)
	}
	if row.SourceEventID != "call_orphan" {
		t.Errorf("event 3 source_event_id: %q", row.SourceEventID)
	}
	if want := int64(len("bash -lc echo interrupted")); row.ContentBytes != want {
		t.Errorf("event 3 content_bytes: %d want %d", row.ContentBytes, want)
	}

	// 4: update_plan → ActionTodoUpdate.
	row = res.ToolEvents[4]
	if row.ActionType != models.ActionTodoUpdate {
		t.Errorf("event 4 action: %s want todo_update", row.ActionType)
	}
	if row.RawToolName != "update_plan" {
		t.Errorf("event 4 raw_tool_name: %q", row.RawToolName)
	}

	// 5: web_search_end.
	row = res.ToolEvents[5]
	if row.ActionType != models.ActionWebSearch {
		t.Errorf("event 5 action: %s want web_search", row.ActionType)
	}
	if !strings.Contains(row.Target, "go testing patterns") {
		t.Errorf("event 5 target: %q", row.Target)
	}

	// 6: apply_patch fully paired (call + output + patch_apply_end).
	row = res.ToolEvents[6]
	if row.ActionType != models.ActionEditFile {
		t.Errorf("event 6 action: %s want edit_file", row.ActionType)
	}
	if !row.Success {
		t.Errorf("event 6 should be success")
	}
	if row.RawToolName != "patch_apply_end" {
		t.Errorf("event 6 raw_tool_name: %q want patch_apply_end (post-merge)", row.RawToolName)
	}
	if !strings.Contains(row.Target, "hello.go") {
		t.Errorf("event 6 target should reference hello.go from changes map: %q", row.Target)
	}
	if !strings.Contains(row.ToolOutput, "Success") {
		t.Errorf("event 6 tool_output: %q", row.ToolOutput)
	}
	if row.SourceEventID != "call_patch_paired" {
		t.Errorf("event 6 source_event_id: %q", row.SourceEventID)
	}
	if want := int64(len("package main\n\nfunc main() {}\n")); row.ContentBytes != want {
		t.Errorf("event 6 content_bytes: %d want %d", row.ContentBytes, want)
	}

	// 7: orphan apply_patch — target parsed from patch text.
	row = res.ToolEvents[7]
	if row.ActionType != models.ActionEditFile {
		t.Errorf("event 7 action: %s want edit_file", row.ActionType)
	}
	if row.RawToolName != "apply_patch" {
		t.Errorf("event 7 raw_tool_name: %q want apply_patch (pre-merge)", row.RawToolName)
	}
	if !strings.Contains(row.Target, "lone.go") {
		t.Errorf("event 7 target should be parsed from `*** Update File:` header: %q", row.Target)
	}
	if row.SourceEventID != "call_patch_orphan" {
		t.Errorf("event 7 source_event_id: %q", row.SourceEventID)
	}
	if want := int64(len("new")); row.ContentBytes != want {
		t.Errorf("event 7 content_bytes: %d want %d", row.ContentBytes, want)
	}

	// 8: standalone patch_apply_end (no preceding custom_tool_call).
	row = res.ToolEvents[8]
	if row.ActionType != models.ActionEditFile {
		t.Errorf("event 8 action: %s want edit_file", row.ActionType)
	}
	if row.RawToolName != "patch_apply_end" {
		t.Errorf("event 8 raw_tool_name: %q", row.RawToolName)
	}
	if !strings.Contains(row.Target, "recovered.go") {
		t.Errorf("event 8 target: %q", row.Target)
	}
	if want := int64(len("package recovered\n")); row.ContentBytes != want {
		t.Errorf("event 8 content_bytes: %d want %d", row.ContentBytes, want)
	}

	// 9: paired list_mcp_resources function_call + mcp_tool_call_end → merged.
	row = res.ToolEvents[9]
	if row.ActionType != models.ActionMCPCall {
		t.Errorf("event 9 action: %s want mcp_call", row.ActionType)
	}
	if row.Target != "codex:list_mcp_resources" {
		t.Errorf("event 9 target: %q want codex:list_mcp_resources", row.Target)
	}
	if !row.Success {
		t.Errorf("event 9 should be success (Ok branch + isError=false)")
	}
	if row.DurationMs != 300 {
		t.Errorf("event 9 duration_ms: %d want 300", row.DurationMs)
	}
	if row.RawToolName != "mcp_tool_call_end" {
		t.Errorf("event 9 raw_tool_name: %q want mcp_tool_call_end (post-merge)", row.RawToolName)
	}
	if !strings.Contains(row.ToolOutput, "resources") {
		t.Errorf("event 9 tool_output: %q", row.ToolOutput)
	}
	if row.SourceEventID != "call_mcp_paired" {
		t.Errorf("event 9 source_event_id: %q", row.SourceEventID)
	}

	// 10: standalone mcp_tool_call_end (no pending function_call) — Err branch.
	row = res.ToolEvents[10]
	if row.ActionType != models.ActionMCPCall {
		t.Errorf("event 10 action: %s want mcp_call", row.ActionType)
	}
	if row.Target != "docs:search" {
		t.Errorf("event 10 target: %q", row.Target)
	}
	if row.Success {
		t.Errorf("event 10 should be failed (Err branch)")
	}
	if !strings.Contains(row.ErrorMessage, "server unreachable") {
		t.Errorf("event 10 error_message: %q", row.ErrorMessage)
	}

	// 11: api_error — usage_limit_exceeded captured as ActionAPIError.
	row = res.ToolEvents[11]
	if row.ActionType != models.ActionAPIError {
		t.Errorf("event 11 action: %s want api_error", row.ActionType)
	}
	if row.Success {
		t.Errorf("event 11 should be failed (success=false)")
	}
	if row.Target != "usage_limit_exceeded" {
		t.Errorf("event 11 target: %q want usage_limit_exceeded", row.Target)
	}
	if !strings.Contains(row.ErrorMessage, "usage limit") {
		t.Errorf("event 11 error_message: %q", row.ErrorMessage)
	}
	if row.RawToolName != "usage_limit_exceeded" {
		t.Errorf("event 11 raw_tool_name: %q", row.RawToolName)
	}

	// 12: paired view_image function_call + view_image_tool_call → merged read_file.
	row = res.ToolEvents[12]
	if row.ActionType != models.ActionReadFile {
		t.Errorf("event 12 action: %s want read_file", row.ActionType)
	}
	if !strings.Contains(row.Target, "screen.png") {
		t.Errorf("event 12 target: %q", row.Target)
	}
	if row.RawToolName != "view_image_tool_call" {
		t.Errorf("event 12 raw_tool_name: %q want view_image_tool_call (post-merge)", row.RawToolName)
	}
	if row.SourceEventID != "call_view_paired" {
		t.Errorf("event 12 source_event_id: %q", row.SourceEventID)
	}

	// 13: standalone view_image_tool_call (no preceding function_call).
	row = res.ToolEvents[13]
	if row.ActionType != models.ActionReadFile {
		t.Errorf("event 13 action: %s want read_file", row.ActionType)
	}
	if !strings.Contains(row.Target, "orphan.png") {
		t.Errorf("event 13 target: %q", row.Target)
	}
	if row.RawToolName != "view_image_tool_call" {
		t.Errorf("event 13 raw_tool_name: %q", row.RawToolName)
	}

	// 14: dynamic_tool_call_request + response merged.
	row = res.ToolEvents[14]
	if row.RawToolName != "dynamic_tool_call_response" {
		t.Errorf("event 14 raw_tool_name: %q want dynamic_tool_call_response (post-merge)", row.RawToolName)
	}
	if !row.Success {
		t.Errorf("event 14 should be success")
	}
	if row.DurationMs != 55 {
		t.Errorf("event 14 duration_ms: %d want 55", row.DurationMs)
	}
	if !strings.Contains(row.ToolOutput, "Workspace dependencies") {
		t.Errorf("event 14 tool_output: %q", row.ToolOutput)
	}
	if row.SourceEventID != "call_dyn" {
		t.Errorf("event 14 source_event_id: %q", row.SourceEventID)
	}

	// 15: turn_aborted.
	row = res.ToolEvents[15]
	if row.ActionType != models.ActionTurnAborted {
		t.Errorf("event 15 action: %s want turn_aborted", row.ActionType)
	}
	if row.Success {
		t.Errorf("event 15 should be failed (success=false)")
	}
	if row.Target != "interrupted" {
		t.Errorf("event 15 target: %q", row.Target)
	}
	if row.DurationMs != 23898 {
		t.Errorf("event 15 duration_ms: %d want 23898", row.DurationMs)
	}

	// 16: task_complete — must remain last.
	if res.ToolEvents[16].ActionType != models.ActionTaskComplete {
		t.Errorf("event 16 action: %s want task_complete", res.ToolEvents[16].ActionType)
	}
}

func formatEventSummary(i int, evt models.ToolEvent) string {
	return fmt.Sprintf("  [%d] action=%s raw=%q target=%q src_event=%s", i, evt.ActionType, evt.RawToolName, evt.Target, evt.SourceEventID)
}

// TestParseResponseItemDurationFromTimestampGap pins v1.4.28: when
// codex's response_item function_call (or custom_tool_call) carries
// no structured duration field — typical of newer "Wall time: Xs"
// flat-text outputs and JSON-metadata variants — the adapter
// computes DurationMs from the gap between the call timestamp and
// the matching output timestamp. Previously these rows landed with
// DurationMs=0 even though wall-clock time was knowable from the
// records themselves.
func TestParseResponseItemDurationFromTimestampGap(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "rollout-2026-05-03T10-00-00-thread.jsonl")
	body := strings.Join([]string{
		`{"timestamp":"2026-05-03T10:00:00.000Z","type":"session_meta","payload":{"id":"thread-d","cwd":"/tmp","model":"gpt-5","git_branch":"main"}}`,
		`{"timestamp":"2026-05-03T10:00:00.100Z","type":"event_msg","payload":{"type":"task_started","turn_id":"turn-1"}}`,
		// function_call at +0.1s, no structured duration on output.
		`{"timestamp":"2026-05-03T10:00:00.500Z","type":"response_item","payload":{"type":"function_call","name":"shell","call_id":"call_dur","arguments":"{\"command\":[\"ls\"]}"}}`,
		// function_call_output at +3.7s — adapter should compute 3200ms.
		`{"timestamp":"2026-05-03T10:00:03.700Z","type":"response_item","payload":{"type":"function_call_output","call_id":"call_dur","output":"Exit code: 0\nWall time: 3.2 seconds\nOutput:\nfoo\nbar\n"}}`,
		"",
	}, "\n")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := New().ParseSessionFile(context.Background(), path, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	var got int64
	for _, e := range res.ToolEvents {
		if e.SourceEventID == "call_dur" {
			got = e.DurationMs
		}
	}
	if got != 3200 {
		t.Errorf("DurationMs: got %d want 3200 (call→output timestamp gap)", got)
	}
}

// TestParseRolloutSystemPrompts pins the v1.4.23 capture for codex
// system-prompt-shaped content. Three sources, all hash-deduped to
// the same row when their bodies match:
//
//  1. session_meta.base_instructions.text — emit once with role=base.
//  2. turn_context.developer_instructions — emit once per unique
//     content; identical instructions across turns dedup to the first
//     emission.
//  3. response_item.message.role=developer — same dedup behavior.
//
// The fixture has identical developer_instructions across two
// turn_contexts (must dedup to ONE row) plus a different
// developer-role response_item.message (must emit a SECOND row). The
// base_instructions text differs from both, so total = 3 system_prompt
// rows.
func TestParseRolloutSystemPrompts(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "rollout-2026-05-01T02-00-00-thread.jsonl")
	body := strings.Join([]string{
		`{"timestamp":"2026-05-01T02:00:00.000Z","type":"session_meta","payload":{"id":"thread-s","cwd":"/tmp","model":"gpt-5","base_instructions":{"text":"You are Codex, follow these rules."}}}`,
		`{"timestamp":"2026-05-01T02:00:00.500Z","type":"turn_context","payload":{"turn_id":"turn-1","model":"gpt-5","cwd":"/tmp","developer_instructions":"<permissions>workspace-write</permissions>"}}`,
		`{"timestamp":"2026-05-01T02:00:01.000Z","type":"event_msg","payload":{"type":"task_started","turn_id":"turn-1"}}`,
		`{"timestamp":"2026-05-01T02:00:02.000Z","type":"response_item","payload":{"type":"message","role":"developer","content":[{"type":"input_text","text":"<context>extra mid-turn instructions</context>"}]}}`,
		`{"timestamp":"2026-05-01T02:00:03.000Z","type":"turn_context","payload":{"turn_id":"turn-2","model":"gpt-5","cwd":"/tmp","developer_instructions":"<permissions>workspace-write</permissions>"}}`,
		``,
	}, "\n")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	a := NewWithOptions(nil, dir)
	res, err := a.ParseSessionFile(context.Background(), path, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	var sysPrompts []models.ToolEvent
	for _, e := range res.ToolEvents {
		if e.ActionType == models.ActionSystemPrompt {
			sysPrompts = append(sysPrompts, e)
		}
	}
	if len(sysPrompts) != 3 {
		t.Fatalf("system_prompt rows: %d want 3 (base + developer + mid-turn developer; second turn_context dedup'd)", len(sysPrompts))
	}
	// 0: base_instructions.
	if !strings.Contains(sysPrompts[0].RawToolName, "base") {
		t.Errorf("event 0 raw_tool_name: %q want system_prompt.base", sysPrompts[0].RawToolName)
	}
	if !strings.Contains(sysPrompts[0].Target, "You are Codex") {
		t.Errorf("event 0 target: %q", sysPrompts[0].Target)
	}
	// 1: turn 1 developer_instructions.
	if !strings.Contains(sysPrompts[1].RawToolName, "developer") {
		t.Errorf("event 1 raw_tool_name: %q", sysPrompts[1].RawToolName)
	}
	if !strings.Contains(sysPrompts[1].Target, "permissions") {
		t.Errorf("event 1 target: %q", sysPrompts[1].Target)
	}
	// 2: response_item.message.role=developer.
	if !strings.Contains(sysPrompts[2].Target, "extra mid-turn") {
		t.Errorf("event 2 target: %q", sysPrompts[2].Target)
	}
	// MessageID dedup: identical bodies share MessageID prefix.
	if !strings.HasPrefix(sysPrompts[1].MessageID, "system:") {
		t.Errorf("event 1 message_id should be 'system:<hash>': %q", sysPrompts[1].MessageID)
	}
}

// TestParseRolloutUserEnvelopeIsCapturedAsSystemPrompt pins a v1.4.24
// follow-up: response_item.message.role=user content split into two
// classes.
//
//   - Plain text and markdown — these ARE real user prompts that
//     event_msg/user_message already captures; emitting another row
//     here would double-count.
//   - XML-envelope-shaped (`<environment_context>...`,
//     `<user_instructions>...`, etc.) — these are synthetic context
//     injections from the Codex runtime, not user input. They look
//     like user-role messages to the model but originate from the
//     runtime. Capture as ActionSystemPrompt with role=user-envelope.
//
// Detection heuristic: body trimmed of leading whitespace must start
// with `<`. The plain-text "Can you find out..." MUST stay
// uncaptured here (event_msg/user_message owns it).
func TestParseRolloutUserEnvelopeIsCapturedAsSystemPrompt(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "rollout-2026-05-01T03-00-00-thread.jsonl")
	body := strings.Join([]string{
		`{"timestamp":"2026-05-01T03:00:00.000Z","type":"session_meta","payload":{"id":"thread-u","cwd":"/tmp","model":"gpt-5"}}`,
		`{"timestamp":"2026-05-01T03:00:00.500Z","type":"turn_context","payload":{"turn_id":"turn-u","model":"gpt-5","cwd":"/tmp"}}`,
		// Real user prompt via event_msg/user_message (Tier 1 path).
		`{"timestamp":"2026-05-01T03:00:01.000Z","type":"event_msg","payload":{"type":"user_message","message":"Can you find out all the active windows"}}`,
		// SAME content rebroadcast as response_item.message.role=user — should NOT emit a second row.
		`{"timestamp":"2026-05-01T03:00:01.100Z","type":"response_item","payload":{"type":"message","role":"user","content":[{"type":"input_text","text":"Can you find out all the active windows"}]}}`,
		// Synthetic envelope — should emit a system_prompt with role=user-envelope.
		`{"timestamp":"2026-05-01T03:00:02.000Z","type":"response_item","payload":{"type":"message","role":"user","content":[{"type":"input_text","text":"<environment_context>\n  <cwd>/tmp</cwd>\n  <shell>bash</shell>\n</environment_context>"}]}}`,
		``,
	}, "\n")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	a := NewWithOptions(nil, dir)
	res, err := a.ParseSessionFile(context.Background(), path, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	var userPrompts, systemPrompts []models.ToolEvent
	for _, ev := range res.ToolEvents {
		switch ev.ActionType {
		case models.ActionUserPrompt:
			userPrompts = append(userPrompts, ev)
		case models.ActionSystemPrompt:
			systemPrompts = append(systemPrompts, ev)
		}
	}
	if len(userPrompts) != 1 {
		t.Errorf("user_prompt rows: %d want 1 (the plain-text response_item must NOT emit a second user_prompt)", len(userPrompts))
	}
	if len(systemPrompts) != 1 {
		t.Fatalf("system_prompt rows: %d want 1 (only the <environment_context> envelope qualifies)", len(systemPrompts))
	}
	row := systemPrompts[0]
	if row.RawToolName != "system_prompt.user-envelope" {
		t.Errorf("raw_tool_name: %q want system_prompt.user-envelope", row.RawToolName)
	}
	if !strings.Contains(row.Target, "environment_context") {
		t.Errorf("target preview should reference envelope: %q", row.Target)
	}
}

// TestParseRolloutTokenCountDedupesRepeatedTotal pins the v1.4.25
// dedup behaviour: Codex's runtime sometimes re-emits identical
// event_msg/token_count records with the same last_token_usage AND
// total_token_usage. Pre-fix the adapter summed both, inflating
// session totals. The dedup uses total_token_usage as a
// fingerprint — total is monotonic, so any non-advancing total
// is a re-emission and the second event is skipped.
//
// User reported this against the
// rollout-2026-04-23T00-29-51-019db690 session: 22 token_count
// events but only 20 were real model calls; 2 were duplicates that
// inflated input by +122,680, cache_read by +88,704, etc. After
// fix, Observer's sum should equal Codex's own final
// total_token_usage figure.
func TestParseRolloutTokenCountDedupesRepeatedTotal(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "rollout-2026-05-01T05-00-00-thread.jsonl")
	body := strings.Join([]string{
		`{"timestamp":"2026-05-01T05:00:00.000Z","type":"session_meta","payload":{"id":"thread-d","cwd":"/tmp","model":"gpt-5"}}`,
		`{"timestamp":"2026-05-01T05:00:00.500Z","type":"turn_context","payload":{"turn_id":"turn-1","model":"gpt-5","cwd":"/tmp"}}`,
		// Real call 1: 100 input, 10 output, 5 cached, 2 reasoning.
		`{"timestamp":"2026-05-01T05:00:01.000Z","type":"event_msg","payload":{"type":"token_count","info":{"last_token_usage":{"input_tokens":100,"output_tokens":10,"cached_input_tokens":5,"reasoning_output_tokens":2,"total_tokens":112},"total_token_usage":{"input_tokens":100,"output_tokens":10,"cached_input_tokens":5,"reasoning_output_tokens":2,"total_tokens":112}}}}`,
		// Real call 2: 200 cumulative (delta +100), 20 cumulative output, etc.
		`{"timestamp":"2026-05-01T05:00:02.000Z","type":"event_msg","payload":{"type":"token_count","info":{"last_token_usage":{"input_tokens":100,"output_tokens":10,"cached_input_tokens":5,"reasoning_output_tokens":2,"total_tokens":112},"total_token_usage":{"input_tokens":200,"output_tokens":20,"cached_input_tokens":10,"reasoning_output_tokens":4,"total_tokens":224}}}}`,
		// DUPLICATE of call 2: same total, same last. Must be skipped.
		`{"timestamp":"2026-05-01T05:00:02.500Z","type":"event_msg","payload":{"type":"token_count","info":{"last_token_usage":{"input_tokens":100,"output_tokens":10,"cached_input_tokens":5,"reasoning_output_tokens":2,"total_tokens":112},"total_token_usage":{"input_tokens":200,"output_tokens":20,"cached_input_tokens":10,"reasoning_output_tokens":4,"total_tokens":224}}}}`,
		// Real call 3: total advances.
		`{"timestamp":"2026-05-01T05:00:03.000Z","type":"event_msg","payload":{"type":"token_count","info":{"last_token_usage":{"input_tokens":50,"output_tokens":5,"cached_input_tokens":3,"reasoning_output_tokens":1,"total_tokens":56},"total_token_usage":{"input_tokens":250,"output_tokens":25,"cached_input_tokens":13,"reasoning_output_tokens":5,"total_tokens":280}}}}`,
		``,
	}, "\n")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	a := NewWithOptions(nil, dir)
	res, err := a.ParseSessionFile(context.Background(), path, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	// 4 token_count events in fixture; 1 is a duplicate. Want 3 emitted.
	if got := len(res.TokenEvents); got != 3 {
		t.Fatalf("token events: %d want 3 (1 duplicate must be skipped)", got)
	}
	var sumIn, sumOut, sumCacheR, sumReasoning int64
	for _, e := range res.TokenEvents {
		sumIn += e.InputTokens
		sumOut += e.OutputTokens
		sumCacheR += e.CacheReadTokens
		sumReasoning += e.ReasoningTokens
	}
	// Real per-call deltas, NET of cached (input) and NET of reasoning
	// (output — the wire's output_tokens is gross and contains the
	// reasoning subset, so we subtract it to avoid double-billing):
	//   input:  (100-5) + (100-5) + (50-3) = 95+95+47 = 237
	//   output: (10-2) + (10-2) + (5-1)    =  8+ 8+ 4 =  20 (gross 25)
	//   cache:  5+5+3 = 13
	//   reason: 2+2+1 =  5
	// Gross input sum would be 250 (matches final total_token_usage),
	// gross output sum 25; we store net per the cost-engine
	// TokenBundle.Input / .Output contract (reasoning is billed
	// additively on top of Output).
	if sumIn != 237 {
		t.Errorf("sum input: %d want 237 (net of cached; gross would be 250)", sumIn)
	}
	if sumOut != 20 {
		t.Errorf("sum output: %d want 20 (net of reasoning; gross would be 25)", sumOut)
	}
	if sumCacheR != 13 {
		t.Errorf("sum cache_read: %d want 13", sumCacheR)
	}
	if sumReasoning != 5 {
		t.Errorf("sum reasoning: %d want 5", sumReasoning)
	}
	// Fix invariant: net output + reasoning == gross wire output_tokens.
	if sumOut+sumReasoning != 25 {
		t.Errorf("net output(%d) + reasoning(%d) = %d, want 25 (gross wire output_tokens)", sumOut, sumReasoning, sumOut+sumReasoning)
	}
}

// TestParseRolloutCompacted pins the v1.4.22 capture for upstream
// codex compaction events: top-level type="compacted" carries
// `replacement_history` of summarized messages; we emit a single
// ActionContextCompacted row with msg-count + byte/token estimate
// in Target / RawToolInput. Per user direction (2026-05-01) these
// rows are NOT searchable like file edits — but they ARE captured
// (the discriminator lets dashboards filter them out cleanly while
// keeping the data for cost/compaction analytics).
func TestParseRolloutCompacted(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "rollout-2026-05-01T01-00-00-thread.jsonl")
	body := strings.Join([]string{
		`{"timestamp":"2026-05-01T01:00:00.000Z","type":"session_meta","payload":{"id":"thread-c","cwd":"/tmp","model":"gpt-5"}}`,
		`{"timestamp":"2026-05-01T01:00:00.500Z","type":"turn_context","payload":{"turn_id":"turn-c","model":"gpt-5","cwd":"/tmp"}}`,
		`{"timestamp":"2026-05-01T01:00:01.000Z","type":"compacted","payload":{"message":"summary text","replacement_history":[{"role":"user","content":[{"type":"input_text","text":"please do X"}]},{"role":"assistant","content":[{"type":"output_text","text":"working on it"}]}]}}`,
		`{"timestamp":"2026-05-01T01:00:01.000Z","type":"event_msg","payload":{"type":"context_compacted"}}`,
		``,
	}, "\n")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	a := NewWithOptions(nil, dir)
	res, err := a.ParseSessionFile(context.Background(), path, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	if len(res.ToolEvents) != 1 {
		t.Fatalf("tool events: %d want 1 (event_msg/context_compacted is no-op'd)", len(res.ToolEvents))
	}
	row := res.ToolEvents[0]
	if row.ActionType != models.ActionContextCompacted {
		t.Errorf("action: %s want context_compacted", row.ActionType)
	}
	if !strings.Contains(row.Target, "2 msgs") {
		t.Errorf("target: %q want '2 msgs, ...' format", row.Target)
	}
	if !strings.Contains(row.RawToolInput, `"messages":2`) {
		t.Errorf("raw_tool_input should carry msg count: %q", row.RawToolInput)
	}
	if !strings.Contains(row.ToolOutput, "summary text") {
		t.Errorf("tool_output: %q", row.ToolOutput)
	}
}

// TestParseRolloutResponseItemReasoning pins the v1.4.22 forward-
// compat capture for response_item.reasoning. Current Codex Desktop
// builds emit summary:[] uniformly (0% non-empty across 838 items in
// the 2026-04 corpus), but if/when summary fills in with
// {type:"summary_text", text:"..."} segments, those should thread
// into the turn's PrecedingReasoning chain — same place agent_message
// already lives. This test forces a populated summary into the
// fixture and verifies the next exec_command_end inherits it, and
// (B3) that the reasoning item itself mints no action row.
func TestParseRolloutResponseItemReasoning(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "rollout-2026-05-01T00-00-00-thread.jsonl")
	body := strings.Join([]string{
		`{"timestamp":"2026-05-01T00:00:00.000Z","type":"session_meta","payload":{"id":"thread-r","cwd":"/tmp","model":"gpt-5"}}`,
		`{"timestamp":"2026-05-01T00:00:00.500Z","type":"turn_context","payload":{"turn_id":"turn-r","model":"gpt-5","cwd":"/tmp"}}`,
		`{"timestamp":"2026-05-01T00:00:01.000Z","type":"event_msg","payload":{"type":"task_started","turn_id":"turn-r"}}`,
		`{"timestamp":"2026-05-01T00:00:02.000Z","type":"response_item","payload":{"type":"reasoning","summary":[{"type":"summary_text","text":"I should run the test suite."}],"encrypted_content":"opaque..."}}`,
		`{"timestamp":"2026-05-01T00:00:03.000Z","type":"event_msg","payload":{"type":"exec_command_end","call_id":"call_R","turn_id":"turn-r","command":["bash","-lc","go test ./..."],"cwd":"/tmp","aggregated_output":"ok","exit_code":0,"duration":{"secs":1,"nanos":0},"status":"completed"}}`,
		``,
	}, "\n")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	a := NewWithOptions(nil, dir)
	res, err := a.ParseSessionFile(context.Background(), path, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	// B3 (2026-07-31): reasoning mints NO row of its own — v1.4.53's
	// standalone `codex.reasoning` row is retired. The ONLY event here
	// is the exec_command_end, which inherits the summary text through
	// the per-turn agentMessages cache as PrecedingReasoning.
	if len(res.ToolEvents) != 1 {
		t.Fatalf("tool events: %d want 1 (exec_command_end only; reasoning is never an action row)", len(res.ToolEvents))
	}
	var execRow *models.ToolEvent
	for i := range res.ToolEvents {
		if strings.Contains(strings.ToLower(res.ToolEvents[i].RawToolName), "reasoning") {
			t.Fatalf("reasoning-named action row emitted: raw=%q %+v", res.ToolEvents[i].RawToolName, res.ToolEvents[i])
		}
		if res.ToolEvents[i].RawToolName == "exec_command_end" {
			execRow = &res.ToolEvents[i]
		}
	}
	if execRow == nil {
		t.Fatalf("missing exec_command_end row; got %+v", res.ToolEvents)
	}
	if !strings.Contains(execRow.PrecedingReasoning, "run the test suite") {
		t.Errorf("exec_command_end PrecedingReasoning should carry reasoning summary text, got %q", execRow.PrecedingReasoning)
	}
}

// TestParseAgentMessagePropagatesToToolPrecedingReasoning pins the
// parity fix: Codex emits assistant-text preambles via
// `event_msg`/`agent_message` per turn, and every tool_call /
// exec_command_end / web_search_end inside that turn now inherits
// it as PrecedingReasoning. Pre-fix the field was always empty for
// Codex tool events while claudecode/pi/openclaw all carried it.
func TestParseAgentMessagePropagatesToToolPrecedingReasoning(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "rollout-2026-04-30T00-00-00-thread.jsonl")
	body := strings.Join([]string{
		`{"timestamp":"2026-04-30T00:00:01.000Z","type":"session_meta","payload":{"id":"thread-3","cwd":"/x","model":"gpt-5","git_branch":"main"}}`,
		`{"timestamp":"2026-04-30T00:00:01.050Z","type":"event_msg","payload":{"type":"task_started","turn_id":"turn-3"}}`,
		`{"timestamp":"2026-04-30T00:00:01.100Z","type":"event_msg","payload":{"type":"agent_message","turn_id":"turn-3","message":"I'll inspect main.go and run the tests."}}`,
		`{"timestamp":"2026-04-30T00:00:01.200Z","type":"tool_call","payload":{"call_id":"c1","tool":"file_read","input":{"path":"main.go"}}}`,
		`{"timestamp":"2026-04-30T00:00:01.300Z","type":"event_msg","payload":{"type":"exec_command_end","call_id":"c2","turn_id":"turn-3","command":["go","test"],"aggregated_output":"PASS","exit_code":0,"duration":{"secs":0,"nanos":500000000},"status":"completed"}}`,
		`{"timestamp":"2026-04-30T00:00:01.400Z","type":"event_msg","payload":{"type":"web_search_end","call_id":"c3","turn_id":"turn-3","query":"go test best practices"}}`,
		// New turn → new agent_message → tool_call inherits the new preamble.
		`{"timestamp":"2026-04-30T00:00:02.000Z","type":"event_msg","payload":{"type":"task_started","turn_id":"turn-4"}}`,
		`{"timestamp":"2026-04-30T00:00:02.100Z","type":"event_msg","payload":{"type":"agent_message","turn_id":"turn-4","message":"Now I'll patch the bug."}}`,
		`{"timestamp":"2026-04-30T00:00:02.200Z","type":"tool_call","payload":{"call_id":"c4","tool":"apply_patch","input":{"path":"main.go"}}}`,
		``,
	}, "\n")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	a := NewWithOptions(nil, dir)
	res, err := a.ParseSessionFile(context.Background(), path, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	// Expect 6 tool events: agent_message (turn-3), file_read (c1),
	// exec_command_end (c2), web_search_end (c3), agent_message (turn-4),
	// apply_patch (c4). The two agent_messages are standalone
	// assistant-text rows (codex.assistant_text) in addition to populating
	// the per-turn PrecedingReasoning chain on subsequent tool events.
	if len(res.ToolEvents) != 6 {
		t.Fatalf("tool events: %d want 6 (%+v)", len(res.ToolEvents), res.ToolEvents)
	}
	preamble1 := "I'll inspect main.go and run the tests."
	preamble2 := "Now I'll patch the bug."
	if got := res.ToolEvents[0].RawToolName; got != "codex.assistant_text" {
		t.Errorf("event[0] RawToolName = %q, want codex.assistant_text", got)
	}
	if got := res.ToolEvents[0].ToolOutput; got != preamble1 {
		t.Errorf("event[0] ToolOutput = %q, want %q", got, preamble1)
	}
	for i := 1; i < 4; i++ {
		if got := res.ToolEvents[i].PrecedingReasoning; got != preamble1 {
			t.Errorf("event[%d] (%s) PrecedingReasoning = %q, want %q",
				i, res.ToolEvents[i].RawToolName, got, preamble1)
		}
	}
	if got := res.ToolEvents[4].RawToolName; got != "codex.assistant_text" {
		t.Errorf("event[4] RawToolName = %q, want codex.assistant_text", got)
	}
	if got := res.ToolEvents[5].PrecedingReasoning; got != preamble2 {
		t.Errorf("event[5] PrecedingReasoning = %q, want fresh preamble", got)
	}
}

func TestParseSessionFile_AgentMessageEmitsAssistantTextRow(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "rollout-2026-05-11T12-00-00-thread.jsonl")
	body := strings.Join([]string{
		`{"timestamp":"2026-05-11T12:00:00.000Z","type":"session_meta","payload":{"id":"thread-asst","cwd":"/tmp","model":"gpt-5","git_branch":"main"}}`,
		`{"timestamp":"2026-05-11T12:00:00.100Z","type":"turn_context","payload":{"turn_id":"turn-A","cwd":"/tmp","model":"gpt-5","collaboration_mode":{"settings":{"reasoning_effort":"medium"}}}}`,
		`{"timestamp":"2026-05-11T12:00:01.000Z","type":"event_msg","payload":{"type":"task_started","turn_id":"turn-A"}}`,
		`{"timestamp":"2026-05-11T12:00:01.100Z","type":"event_msg","payload":{"type":"agent_message","turn_id":"turn-A","message":"First message body."}}`,
		`{"timestamp":"2026-05-11T12:00:01.200Z","type":"event_msg","payload":{"type":"agent_message","turn_id":"turn-A","message":"Second message body."}}`,
		``,
	}, "\n")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	a := NewWithOptions(nil, dir)
	res, err := a.ParseSessionFile(context.Background(), path, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	if len(res.ToolEvents) != 2 {
		t.Fatalf("tool events: %d want 2 (%+v)", len(res.ToolEvents), res.ToolEvents)
	}
	for i, want := range []string{"First message body.", "Second message body."} {
		ev := res.ToolEvents[i]
		if ev.RawToolName != "codex.assistant_text" {
			t.Errorf("event[%d] RawToolName = %q, want codex.assistant_text", i, ev.RawToolName)
		}
		if ev.ActionType != models.ActionAssistantMessage {
			t.Errorf("event[%d] ActionType = %q, want %q", i, ev.ActionType, models.ActionAssistantMessage)
		}
		if ev.Target != want {
			t.Errorf("event[%d] Target = %q, want %q", i, ev.Target, want)
		}
		if ev.ToolOutput != want {
			t.Errorf("event[%d] ToolOutput = %q, want %q", i, ev.ToolOutput, want)
		}
		if ev.PrecedingReasoning != want {
			t.Errorf("event[%d] PrecedingReasoning = %q, want %q", i, ev.PrecedingReasoning, want)
		}
		if !ev.Success {
			t.Errorf("event[%d] Success = false, want true", i)
		}
		if ev.SessionID != "thread-asst" {
			t.Errorf("event[%d] SessionID = %q, want thread-asst", i, ev.SessionID)
		}
		if ev.Model != "gpt-5" {
			t.Errorf("event[%d] Model = %q, want gpt-5", i, ev.Model)
		}
		if ev.GitBranch != "main" {
			t.Errorf("event[%d] GitBranch = %q, want main", i, ev.GitBranch)
		}
		// effort_level metadata rides via withEffort wrapper.
		if ev.Metadata == nil || ev.Metadata.EffortLevel != "medium" {
			t.Errorf("event[%d] EffortLevel metadata: got %+v, want medium", i, ev.Metadata)
		}
		// MessageIDs must distinguish multiple messages within the same turn.
		// Two messages with different bodies must produce different MessageIDs.
		if !strings.HasPrefix(ev.MessageID, "codex:agent:turn-A:") {
			t.Errorf("event[%d] MessageID = %q, want prefix codex:agent:turn-A:", i, ev.MessageID)
		}
	}
	if res.ToolEvents[0].MessageID == res.ToolEvents[1].MessageID {
		t.Errorf("MessageIDs must differ between distinct agent_messages in the same turn: %q vs %q",
			res.ToolEvents[0].MessageID, res.ToolEvents[1].MessageID)
	}
	if res.ToolEvents[0].SourceEventID == res.ToolEvents[1].SourceEventID {
		t.Errorf("SourceEventIDs must differ: %q vs %q",
			res.ToolEvents[0].SourceEventID, res.ToolEvents[1].SourceEventID)
	}
}

// TestParseSessionFile_AgentMessageEmitsNoTokenEvents pins the convention
// that codex.assistant_text rows are observability-only — emitting an
// agent_message must NOT produce any companion TokenEvent. Token accounting
// flows through dedicated `event_msg`/`token_count` lines (separate path),
// never through the assistant-text emission.
func TestParseSessionFile_AgentMessageEmitsNoTokenEvents(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "rollout-2026-05-11T13-00-00-thread.jsonl")
	body := strings.Join([]string{
		`{"timestamp":"2026-05-11T13:00:00.000Z","type":"session_meta","payload":{"id":"thread-cost","cwd":"/tmp","model":"gpt-5"}}`,
		`{"timestamp":"2026-05-11T13:00:01.000Z","type":"event_msg","payload":{"type":"task_started","turn_id":"turn-B"}}`,
		`{"timestamp":"2026-05-11T13:00:01.100Z","type":"event_msg","payload":{"type":"agent_message","turn_id":"turn-B","message":"costless"}}`,
		``,
	}, "\n")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	a := NewWithOptions(nil, dir)
	res, err := a.ParseSessionFile(context.Background(), path, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	if len(res.ToolEvents) != 1 {
		t.Fatalf("tool events: %d want 1", len(res.ToolEvents))
	}
	if len(res.TokenEvents) != 0 {
		t.Errorf("TokenEvents must be empty for agent_message rows, got %d", len(res.TokenEvents))
	}
}

// TestParseSessionFile_AgentMessageSourceEventIDStableAcrossReparse pins
// invariant 42 (L-num drift fix) for the new agent_message emission.
func TestParseSessionFile_AgentMessageSourceEventIDStableAcrossReparse(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "rollout-2026-05-11T14-00-00-thread.jsonl")
	headerLines := []string{
		`{"timestamp":"2026-05-11T14:00:00.000Z","type":"session_meta","payload":{"id":"thread-stable","cwd":"/tmp","model":"gpt-5"}}`,
		`{"timestamp":"2026-05-11T14:00:00.100Z","type":"event_msg","payload":{"type":"task_started","turn_id":"turn-C"}}`,
	}
	header := strings.Join(headerLines, "\n") + "\n"
	agentLine := `{"timestamp":"2026-05-11T14:00:01.000Z","type":"event_msg","payload":{"type":"agent_message","turn_id":"turn-C","message":"stable body"}}`
	body := header + agentLine + "\n"

	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	a := NewWithOptions(nil, dir)

	// Parse from offset 0 (cold rescan).
	resCold, err := a.ParseSessionFile(context.Background(), path, 0)
	if err != nil {
		t.Fatalf("cold ParseSessionFile: %v", err)
	}
	if len(resCold.ToolEvents) != 1 {
		t.Fatalf("cold events: %d want 1", len(resCold.ToolEvents))
	}

	// Parse from offset = end of header (incremental resume).
	resWarm, err := a.ParseSessionFile(context.Background(), path, int64(len(header)))
	if err != nil {
		t.Fatalf("warm ParseSessionFile: %v", err)
	}
	if len(resWarm.ToolEvents) != 1 {
		t.Fatalf("warm events: %d want 1", len(resWarm.ToolEvents))
	}

	if resCold.ToolEvents[0].SourceEventID != resWarm.ToolEvents[0].SourceEventID {
		t.Errorf("SourceEventID drift: cold=%q warm=%q",
			resCold.ToolEvents[0].SourceEventID, resWarm.ToolEvents[0].SourceEventID)
	}
}

// TestParseSessionFile_ItemCompletedAgentMessage pins the newer Codex CLI
// wire format (observed live 2026-09-02) that wraps assistant text in an
// event_msg/item_completed envelope with item.type=="AgentMessage" instead
// of the legacy flat event_msg/agent_message shape. Rollouts using this
// schema exclusively never emit "agent_message", so without a dedicated
// item_completed case, 0 assistant_message rows get captured for the
// entire session — the root cause of the dashboard's Messages tab falling
// back to "API call (no recovered text)" on every Llm Call row.
func TestParseSessionFile_ItemCompletedAgentMessage(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "rollout-2026-09-02T10-00-00-thread.jsonl")
	body := strings.Join([]string{
		`{"timestamp":"2026-09-02T10:00:00.000Z","type":"session_meta","payload":{"id":"thread-item-completed","cwd":"/tmp","model":"gpt-5.6"}}`,
		`{"timestamp":"2026-09-02T10:00:01.000Z","type":"event_msg","payload":{"type":"task_started","turn_id":"turn-1"}}`,
		`{"timestamp":"2026-09-02T10:00:01.100Z","type":"event_msg","payload":{"type":"item_completed","thread_id":"thread-item-completed","turn_id":"turn-1","item":{"type":"AgentMessage","id":"msg_1","content":[{"type":"Text","text":"Here is what I found."}],"phase":"commentary"}}}`,
		``,
	}, "\n")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	a := NewWithOptions(nil, dir)
	res, err := a.ParseSessionFile(context.Background(), path, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	if len(res.ToolEvents) != 1 {
		t.Fatalf("tool events: %d want 1", len(res.ToolEvents))
	}
	row := res.ToolEvents[0]
	if row.ActionType != models.ActionAssistantMessage {
		t.Errorf("action type: %s want assistant_message", row.ActionType)
	}
	if row.RawToolName != "codex.assistant_text" {
		t.Errorf("raw_tool_name: %q want codex.assistant_text", row.RawToolName)
	}
	if !strings.Contains(row.ToolOutput, "Here is what I found.") {
		t.Errorf("tool_output = %q want to contain the AgentMessage text", row.ToolOutput)
	}
	if len(res.TokenEvents) != 0 {
		t.Errorf("TokenEvents must be empty for item_completed/AgentMessage rows, got %d", len(res.TokenEvents))
	}
}

// TestParseSessionFile_ItemCompletedNonAgentMessageIgnored pins the
// deliberate exclusion of the other item_completed sub-types: Reasoning and
// CommandExecution are exact-count duplicates of the response_item
// "reasoning" / "custom_tool_call(+output)" entries captured elsewhere, and
// UserMessage is not a confirmed gap — handling any of them here would
// double-count or is unproven, so only AgentMessage produces a ToolEvent.
func TestParseSessionFile_ItemCompletedNonAgentMessageIgnored(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "rollout-2026-09-02T11-00-00-thread.jsonl")
	body := strings.Join([]string{
		`{"timestamp":"2026-09-02T11:00:00.000Z","type":"session_meta","payload":{"id":"thread-item-skip","cwd":"/tmp","model":"gpt-5.6"}}`,
		`{"timestamp":"2026-09-02T11:00:01.000Z","type":"event_msg","payload":{"type":"task_started","turn_id":"turn-1"}}`,
		`{"timestamp":"2026-09-02T11:00:01.100Z","type":"event_msg","payload":{"type":"item_completed","turn_id":"turn-1","item":{"type":"Reasoning","id":"rs_1","content":[{"type":"text","text":"thinking..."}]}}}`,
		`{"timestamp":"2026-09-02T11:00:01.200Z","type":"event_msg","payload":{"type":"item_completed","turn_id":"turn-1","item":{"type":"CommandExecution","id":"cmd_1","content":[{"type":"text","text":"ls -la"}]}}}`,
		`{"timestamp":"2026-09-02T11:00:01.300Z","type":"event_msg","payload":{"type":"item_completed","turn_id":"turn-1","item":{"type":"UserMessage","id":"um_1","content":[{"type":"text","text":"do the thing"}]}}}`,
		``,
	}, "\n")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	a := NewWithOptions(nil, dir)
	res, err := a.ParseSessionFile(context.Background(), path, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	if len(res.ToolEvents) != 0 {
		var summary []string
		for i, evt := range res.ToolEvents {
			summary = append(summary, formatEventSummary(i, evt))
		}
		t.Fatalf("tool events: %d want 0 (Reasoning/CommandExecution/UserMessage item_completed rows must not emit)\n%s",
			len(res.ToolEvents), strings.Join(summary, "\n"))
	}
}

func TestIsSessionFile(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	a := NewWithOptions(nil, root)
	if !a.IsSessionFile(filepath.Join(root, "rollout-2026-04-16-abc.jsonl")) {
		t.Error("rollout-*.jsonl under watch root should match")
	}
	if a.IsSessionFile(filepath.Join(root, "events.jsonl")) {
		t.Error("non-rollout .jsonl should not match")
	}
	if a.IsSessionFile(filepath.Join(root, "rollout-x.json")) {
		t.Error("non-jsonl should not match")
	}
	// v1.4.51 invariant: shape-correct file outside watch root rejected.
	if a.IsSessionFile("/tmp/foreign/rollout-foo.jsonl") {
		t.Error("rollout-*.jsonl outside watch root must NOT match")
	}
}

func TestWatchPathsHonorsCodexHome(t *testing.T) {
	t.Setenv("CODEX_HOME", "/custom/codex")
	a := New()
	paths := a.WatchPaths()
	want := filepath.Join("/custom/codex", "sessions")
	if len(paths) != 1 || paths[0] != want {
		t.Errorf("CODEX_HOME not honored: %v", paths)
	}
}

func TestIncrementalParse(t *testing.T) {
	t.Parallel()
	// Parse first half, then resume.
	a := New()
	res1, err := a.ParseSessionFile(context.Background(), fixture(t, "rollout-session.jsonl"), 0)
	if err != nil {
		t.Fatal(err)
	}
	if res1.NewOffset <= 0 {
		t.Fatal("offset not advanced")
	}
	// Re-parse from the end — should produce zero events.
	res2, err := a.ParseSessionFile(context.Background(), fixture(t, "rollout-session.jsonl"), res1.NewOffset)
	if err != nil {
		t.Fatal(err)
	}
	if len(res2.ToolEvents) != 0 || len(res2.TokenEvents) != 0 {
		t.Errorf("resume from EOF produced events: tool=%d token=%d",
			len(res2.ToolEvents), len(res2.TokenEvents))
	}
}

// TestTokenCountColdResume guards audit item C1: when an incremental
// parse resumes mid-session with a fresh in-memory lastInputByID map,
// the first token_count event (whose cumulative total may be huge)
// must NOT be emitted as a delta of that full cumulative. Old
// behaviour: in = tk.InputTokens - 0 → over-count by the entire
// cumulative. Fixed: emit in=0 for the resume-baseline event, then
// correct deltas thereafter.
func TestTokenCountColdResume(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "rollout-resume.jsonl")
	// Use the legacy top-level token_count line.Type — the path the C1
	// fix targets. The modern event_msg/token_count nested shape is
	// handled by parseModernTokenCount with no delta math.
	lines := []string{
		`{"timestamp":"2026-04-22T19:00:00.000Z","type":"session_meta","payload":{"id":"sess-resume","model":"gpt-5","cwd":"/x"}}`,
		// Pretend we already parsed this once: cumulative=200.
		`{"timestamp":"2026-04-22T19:00:01.000Z","type":"token_count","payload":{"input_tokens":200,"output_tokens":10}}`,
		// Then later, cumulative=350. Real delta: 150.
		`{"timestamp":"2026-04-22T19:00:02.000Z","type":"token_count","payload":{"input_tokens":350,"output_tokens":15}}`,
		// One more: cumulative=600. Real delta: 250.
		`{"timestamp":"2026-04-22T19:00:03.000Z","type":"token_count","payload":{"input_tokens":600,"output_tokens":20}}`,
	}
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	// First parse from offset 0 — establishes the baseline path.
	a := New()
	res1, err := a.ParseSessionFile(context.Background(), path, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(res1.TokenEvents) != 3 {
		t.Fatalf("first parse: %d events", len(res1.TokenEvents))
	}
	wantFresh := []int64{200, 150, 250} // cumulative 0→200→350→600
	for i, ev := range res1.TokenEvents {
		if ev.InputTokens != wantFresh[i] {
			t.Errorf("fresh parse event %d input=%d want %d", i, ev.InputTokens, wantFresh[i])
		}
	}

	// Now simulate a cold restart: new adapter instance + parse from
	// offset > 0. In a fresh process, lastInputByID is empty. The first
	// event we see (cumulative=350) must NOT emit input=350 — that would
	// double-count what was already in the DB.
	//
	// Find the offset of just before line 3 (the second token_count).
	body, _ := os.ReadFile(path)
	cut := strings.Index(string(body), `"input_tokens":350`)
	if cut <= 0 {
		t.Fatal("could not find resume cut point in fixture")
	}
	// Roll back to the start of that line.
	resumeOffset := int64(strings.LastIndex(string(body[:cut]), "\n") + 1)

	a2 := New()
	res2, err := a2.ParseSessionFile(context.Background(), path, resumeOffset)
	if err != nil {
		t.Fatal(err)
	}
	if len(res2.TokenEvents) != 2 {
		t.Fatalf("resume parse: %d events want 2", len(res2.TokenEvents))
	}
	// First post-resume event: must emit 0 (baseline), not 350.
	if res2.TokenEvents[0].InputTokens != 0 {
		t.Errorf("resume first event input=%d want 0 (baseline)",
			res2.TokenEvents[0].InputTokens)
	}
	// Second post-resume event: 600-350 = 250. Correct delta.
	if res2.TokenEvents[1].InputTokens != 250 {
		t.Errorf("resume second event input=%d want 250 (600-350)",
			res2.TokenEvents[1].InputTokens)
	}
}

// TestResumePreservesSessionContext guards the "short ChatGPT-auth
// Codex sessions show 4 actions, 0 tokens" failure mode reported
// 2026-05-06. Concrete reproduction: rollout file lands with
// session_meta + a few prompt rows, the watcher's first parse advances
// the cursor past those bytes, the file then grows with token_count +
// function_call + task_complete events. The resumed parse no longer
// sees session_meta in its chunk, so before this fix every emitted
// event lost SessionID (became filename-derived) and ProjectRoot
// (empty), and store.Ingest dropped the lot.
//
// After the fix the parser re-reads the leading bytes for context-
// bearing lines (session_meta / turn_context) so resumed events keep
// the canonical UUID SessionID and the recorded cwd, letting them
// reach the DB.
func TestResumePreservesSessionContext(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "rollout-resume-ctx.jsonl")

	leading := []string{
		`{"timestamp":"2026-05-06T04:29:01.304Z","type":"session_meta","payload":{"id":"019dfb8b-c9cb-73c2-a7f5-b0da8b9962a8","cwd":"D:\\programsx\\partner-names","model":"gpt-5.5"}}`,
		`{"timestamp":"2026-05-06T04:29:01.305Z","type":"event_msg","payload":{"type":"task_started","turn_id":"019dfb8b-d1dc-7850-92a5-111d872ea823"}}`,
		`{"timestamp":"2026-05-06T04:29:01.307Z","type":"event_msg","payload":{"type":"user_message","message":"hello"}}`,
	}
	tail := []string{
		`{"timestamp":"2026-05-06T04:29:03.793Z","type":"event_msg","payload":{"type":"token_count","info":{"last_token_usage":{"input_tokens":13443,"cached_input_tokens":7552,"output_tokens":51,"reasoning_output_tokens":12,"total_tokens":13494},"total_token_usage":{"input_tokens":13443,"cached_input_tokens":7552,"output_tokens":51,"reasoning_output_tokens":12,"total_tokens":13494}}}}`,
		`{"timestamp":"2026-05-06T04:29:03.796Z","type":"response_item","payload":{"type":"function_call","name":"shell_command","arguments":"{\"command\":\"Write-Output 'observer-token-test'\",\"workdir\":\"D:\\\\programsx\\\\partner-names\"}","call_id":"call_test"}}`,
		`{"timestamp":"2026-05-06T04:29:04.466Z","type":"response_item","payload":{"type":"function_call_output","call_id":"call_test","output":"observer-token-test\r\n"}}`,
		`{"timestamp":"2026-05-06T04:29:06.554Z","type":"event_msg","payload":{"type":"task_complete","turn_id":"019dfb8b-d1dc-7850-92a5-111d872ea823","last_agent_message":"ok","completed_at":1778041746,"duration_ms":8854}}`,
	}

	// First write: only the leading lines exist.
	first := strings.Join(leading, "\n") + "\n"
	if err := os.WriteFile(path, []byte(first), 0o600); err != nil {
		t.Fatal(err)
	}

	a := New()
	res1, err := a.ParseSessionFile(context.Background(), path, 0)
	if err != nil {
		t.Fatal(err)
	}
	if res1.NewOffset != int64(len(first)) {
		t.Fatalf("first parse offset: got %d want %d", res1.NewOffset, len(first))
	}

	// Now the file grows with the tail (token_count + function_call +
	// task_complete). The watcher's next pass resumes from res1.NewOffset
	// — and the resumed chunk lacks session_meta entirely.
	full := first + strings.Join(tail, "\n") + "\n"
	if err := os.WriteFile(path, []byte(full), 0o600); err != nil {
		t.Fatal(err)
	}

	res2, err := a.ParseSessionFile(context.Background(), path, res1.NewOffset)
	if err != nil {
		t.Fatal(err)
	}

	wantSession := "019dfb8b-c9cb-73c2-a7f5-b0da8b9962a8"
	wantCwd := "D:\\programsx\\partner-names"

	if len(res2.TokenEvents) == 0 {
		t.Fatalf("resumed parse produced 0 token events")
	}
	for i, ev := range res2.TokenEvents {
		if ev.SessionID != wantSession {
			t.Errorf("token[%d].SessionID = %q want %q", i, ev.SessionID, wantSession)
		}
		if ev.ProjectRoot == "" {
			t.Errorf("token[%d].ProjectRoot empty (cwd=%q expected)", i, wantCwd)
		}
	}
	if len(res2.ToolEvents) == 0 {
		t.Fatalf("resumed parse produced 0 tool events")
	}
	for i, ev := range res2.ToolEvents {
		if ev.SessionID != wantSession {
			t.Errorf("tool[%d](%s).SessionID = %q want %q", i, ev.ActionType, ev.SessionID, wantSession)
		}
		if ev.ProjectRoot == "" {
			t.Errorf("tool[%d](%s).ProjectRoot empty (cwd=%q expected)", i, ev.ActionType, wantCwd)
		}
	}
}

func TestIncrementalParseDefersTrailingJSONFragment(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "rollout-fragment.jsonl")
	line1 := `{"timestamp":"2026-05-06T09:00:00.000Z","type":"session_meta","payload":{"id":"sess-frag","model":"gpt-5.5","cwd":"D:\\programsx\\partner-names"}}`
	line2Full := `{"timestamp":"2026-05-06T09:00:01.000Z","type":"event_msg","payload":{"type":"token_count","info":{"last_token_usage":{"input_tokens":12,"output_tokens":3,"cached_input_tokens":4,"reasoning_output_tokens":1,"total_tokens":15},"total_token_usage":{"input_tokens":12,"output_tokens":3,"cached_input_tokens":4,"reasoning_output_tokens":1,"total_tokens":15}}}}`
	line2Partial := line2Full[:len(line2Full)-9]
	initial := line1 + "\n" + line2Partial
	if err := os.WriteFile(path, []byte(initial), 0o600); err != nil {
		t.Fatal(err)
	}

	a := New()
	res1, err := a.ParseSessionFile(context.Background(), path, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(res1.TokenEvents) != 0 {
		t.Fatalf("partial parse token events: got %d want 0", len(res1.TokenEvents))
	}
	wantOffset := int64(len(line1) + 1)
	if res1.NewOffset != wantOffset {
		t.Fatalf("partial parse offset: got %d want %d", res1.NewOffset, wantOffset)
	}

	if err := os.WriteFile(path, []byte(line1+"\n"+line2Full+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	res2, err := a.ParseSessionFile(context.Background(), path, res1.NewOffset)
	if err != nil {
		t.Fatal(err)
	}
	if len(res2.TokenEvents) != 1 {
		t.Fatalf("resumed parse token events: got %d want 1", len(res2.TokenEvents))
	}
	// Modern path nets last_token_usage.input_tokens (12) against
	// cached_input_tokens (4) → InputTokens=8, and output_tokens (3)
	// against reasoning_output_tokens (1) → OutputTokens=2.
	if res2.TokenEvents[0].InputTokens != 8 || res2.TokenEvents[0].OutputTokens != 2 {
		t.Fatalf("resumed token event mismatch: %+v (want InputTokens=8 net of 4 cached, OutputTokens=2 net of 1 reasoning)", res2.TokenEvents[0])
	}
}

// TestParseSessionFile_CapturesReasoningEffort pins the migration-017
// extension for codex JSONL: a turn_context line carrying
// payload.collaboration_mode.settings.reasoning_effort = "high"
// causes every subsequent ToolEvent emitted from that turn to land
// with Metadata.EffortLevel = "high". Verified path on real Codex
// 0.129+ rollouts (see PROGRESS.md Unreleased — codex effort
// extension).
func TestParseSessionFile_CapturesReasoningEffort(t *testing.T) {
	t.Parallel()
	a := New()
	dir := t.TempDir()
	path := filepath.Join(dir, "effort-rollout.jsonl")
	body := strings.Join([]string{
		`{"timestamp":"2026-05-09T00:00:00.000Z","type":"session_meta","payload":{"id":"sess-eff","cwd":"/repo","cli_version":"0.129.0"}}`,
		`{"timestamp":"2026-05-09T00:00:01.000Z","type":"turn_context","payload":{"turn_id":"t1","cwd":"/repo","model":"gpt-5.5","collaboration_mode":{"settings":{"reasoning_effort":"high"}}}}`,
		`{"timestamp":"2026-05-09T00:00:02.000Z","type":"event_msg","payload":{"type":"exec_command_end","turn_id":"t1","call_id":"c1","cwd":"/repo","command":["bash","-lc","ls"],"exit_code":0,"duration":{"secs":0,"nanos":100000000}}}`,
		"",
	}, "\n")
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	res, err := a.ParseSessionFile(context.Background(), path, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	// Find the exec_command_end ToolEvent.
	var found *models.ToolEvent
	for i := range res.ToolEvents {
		if res.ToolEvents[i].ActionType == models.ActionRunCommand {
			found = &res.ToolEvents[i]
			break
		}
	}
	if found == nil {
		t.Fatalf("no run_command ToolEvent emitted; events=%+v", res.ToolEvents)
	}
	if found.Metadata == nil {
		t.Fatalf("Metadata nil on emitted event; want EffortLevel=high")
	}
	if found.Metadata.EffortLevel != "high" {
		t.Errorf("EffortLevel = %q, want high", found.Metadata.EffortLevel)
	}
}

// TestParseSessionFile_EffortLevelStickyAcrossTurnContexts pins the
// sticky-propagation rule: a later turn_context that omits
// collaboration_mode (or sends explicit null reasoning_effort) MUST
// NOT wipe the previously-established EffortLevel. Subsequent tool
// events keep the prior value. Same precedence rule as Cwd / Model
// in applyContext.
func TestParseSessionFile_EffortLevelStickyAcrossTurnContexts(t *testing.T) {
	t.Parallel()
	a := New()
	dir := t.TempDir()
	path := filepath.Join(dir, "effort-sticky.jsonl")
	body := strings.Join([]string{
		`{"timestamp":"2026-05-09T00:00:00.000Z","type":"session_meta","payload":{"id":"sess-sticky","cwd":"/repo","cli_version":"0.129.0"}}`,
		// Turn 1: effort=medium.
		`{"timestamp":"2026-05-09T00:00:01.000Z","type":"turn_context","payload":{"turn_id":"t1","cwd":"/repo","model":"gpt-5.5","collaboration_mode":{"settings":{"reasoning_effort":"medium"}}}}`,
		`{"timestamp":"2026-05-09T00:00:02.000Z","type":"event_msg","payload":{"type":"exec_command_end","turn_id":"t1","call_id":"c1","cwd":"/repo","command":["bash","-lc","ls"],"exit_code":0,"duration":{"secs":0,"nanos":100000000}}}`,
		// Turn 2: turn_context with explicit null effort — should NOT wipe.
		`{"timestamp":"2026-05-09T00:00:03.000Z","type":"turn_context","payload":{"turn_id":"t2","cwd":"/repo","model":"gpt-5.5","collaboration_mode":{"settings":{"reasoning_effort":null}}}}`,
		`{"timestamp":"2026-05-09T00:00:04.000Z","type":"event_msg","payload":{"type":"exec_command_end","turn_id":"t2","call_id":"c2","cwd":"/repo","command":["bash","-lc","pwd"],"exit_code":0,"duration":{"secs":0,"nanos":100000000}}}`,
		// Turn 3: turn_context that omits collaboration_mode entirely — also should NOT wipe.
		`{"timestamp":"2026-05-09T00:00:05.000Z","type":"turn_context","payload":{"turn_id":"t3","cwd":"/repo","model":"gpt-5.5"}}`,
		`{"timestamp":"2026-05-09T00:00:06.000Z","type":"event_msg","payload":{"type":"exec_command_end","turn_id":"t3","call_id":"c3","cwd":"/repo","command":["bash","-lc","whoami"],"exit_code":0,"duration":{"secs":0,"nanos":100000000}}}`,
		"",
	}, "\n")
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	res, err := a.ParseSessionFile(context.Background(), path, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	var runs []models.ToolEvent
	for _, ev := range res.ToolEvents {
		if ev.ActionType == models.ActionRunCommand {
			runs = append(runs, ev)
		}
	}
	if len(runs) != 3 {
		t.Fatalf("expected 3 run_command events, got %d (%+v)", len(runs), res.ToolEvents)
	}
	for i, ev := range runs {
		if ev.Metadata == nil {
			t.Errorf("run[%d] Metadata nil; want EffortLevel=medium (sticky)", i)
			continue
		}
		if ev.Metadata.EffortLevel != "medium" {
			t.Errorf("run[%d] EffortLevel=%q, want medium (sticky across null + omitted-collaboration_mode)",
				i, ev.Metadata.EffortLevel)
		}
	}
}

// TestParseSessionFile_EffortLevelOverwriteOnExplicitChange confirms
// the sticky rule does NOT prevent legitimate overwrites: a later
// turn_context with a NEW non-empty effort updates ctxState and
// subsequent events get the new value. Pinned to make sure
// "sticky" doesn't accidentally become "frozen".
func TestParseSessionFile_EffortLevelOverwriteOnExplicitChange(t *testing.T) {
	t.Parallel()
	a := New()
	dir := t.TempDir()
	path := filepath.Join(dir, "effort-overwrite.jsonl")
	body := strings.Join([]string{
		`{"timestamp":"2026-05-09T00:00:00.000Z","type":"session_meta","payload":{"id":"sess-ow","cwd":"/repo","cli_version":"0.129.0"}}`,
		`{"timestamp":"2026-05-09T00:00:01.000Z","type":"turn_context","payload":{"turn_id":"t1","cwd":"/repo","model":"gpt-5.5","collaboration_mode":{"settings":{"reasoning_effort":"low"}}}}`,
		`{"timestamp":"2026-05-09T00:00:02.000Z","type":"event_msg","payload":{"type":"exec_command_end","turn_id":"t1","call_id":"c1","cwd":"/repo","command":["bash","-lc","ls"],"exit_code":0,"duration":{"secs":0,"nanos":100000000}}}`,
		`{"timestamp":"2026-05-09T00:00:03.000Z","type":"turn_context","payload":{"turn_id":"t2","cwd":"/repo","model":"gpt-5.5","collaboration_mode":{"settings":{"reasoning_effort":"high"}}}}`,
		`{"timestamp":"2026-05-09T00:00:04.000Z","type":"event_msg","payload":{"type":"exec_command_end","turn_id":"t2","call_id":"c2","cwd":"/repo","command":["bash","-lc","pwd"],"exit_code":0,"duration":{"secs":0,"nanos":100000000}}}`,
		"",
	}, "\n")
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	res, err := a.ParseSessionFile(context.Background(), path, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	want := map[string]string{"c1": "low", "c2": "high"}
	for _, ev := range res.ToolEvents {
		if ev.ActionType != models.ActionRunCommand {
			continue
		}
		// Find call_id from RawToolInput or Target. exec_command_end
		// builders typically set RawToolName="exec_command" and the
		// call_id isn't surfaced as a structured field — we'll match
		// on the command string instead.
		var matched string
		switch {
		case strings.Contains(ev.Target, "ls"):
			matched = "c1"
		case strings.Contains(ev.Target, "pwd"):
			matched = "c2"
		}
		if matched == "" {
			continue
		}
		w, ok := want[matched]
		if !ok {
			continue
		}
		if ev.Metadata == nil || ev.Metadata.EffortLevel != w {
			t.Errorf("call %s: EffortLevel=%v, want %s", matched, fmtMetadataEffort(ev.Metadata), w)
		}
	}
}

func fmtMetadataEffort(m *models.ActionMetadata) string {
	if m == nil {
		return "<nil>"
	}
	return fmt.Sprintf("%q", m.EffortLevel)
}

// TestParseSessionFile_SourceEventIDStableAcrossResume pins the
// 2026-05-11 fix for the L-num drift bug that caused
// `observer scan --force` to duplicate rows. SourceEventIDs that
// embed `:L<linenum>:` (user_prompt, task_complete, system_prompt,
// mcp, web, view_image, patch, compacted, error, and any call_id
// fallback) MUST match between a full-file parse and an
// incremental-resume parse of the same line. Pre-fix the lineNum
// counter restarted at 0 on every resume, so the same user prompt
// at file-line 7 was tagged L7 on full parse and L2 on resume from
// just-before-it. UPSERT couldn't match the two → duplicate row.
//
// The fix seeds lineNum from prefetchSessionContext's returned
// line count.
func TestParseSessionFile_SourceEventIDStableAcrossResume(t *testing.T) {
	t.Parallel()
	a := New()
	dir := t.TempDir()
	path := filepath.Join(dir, "linenum-stable.jsonl")
	// Header section (5 lines) + user_prompt at file-line 6. The
	// resume-from-offset test will seek past the 5 header lines and
	// parse just the user_prompt. SourceEventID must report L6
	// either way.
	header := strings.Join([]string{
		`{"timestamp":"2026-05-11T00:00:00.000Z","type":"session_meta","payload":{"id":"sess-linenum","cwd":"/repo","cli_version":"0.129.0"}}`,
		`{"timestamp":"2026-05-11T00:00:01.000Z","type":"turn_context","payload":{"turn_id":"t1","cwd":"/repo","model":"gpt-5.4"}}`,
		`{"timestamp":"2026-05-11T00:00:02.000Z","type":"response_item","payload":{"type":"message","role":"developer","content":[{"type":"input_text","text":"setup"}]}}`,
		`{"timestamp":"2026-05-11T00:00:03.000Z","type":"response_item","payload":{"type":"message","role":"developer","content":[{"type":"input_text","text":"env"}]}}`,
		`{"timestamp":"2026-05-11T00:00:04.000Z","type":"response_item","payload":{"type":"message","role":"developer","content":[{"type":"input_text","text":"permissions"}]}}`,
		"",
	}, "\n")
	body := strings.Join([]string{
		`{"timestamp":"2026-05-11T00:00:05.000Z","type":"event_msg","payload":{"type":"user_message","turn_id":"t1","message":"hello world"}}`,
		"",
	}, "\n")
	full := header + body
	if err := os.WriteFile(path, []byte(full), 0o644); err != nil {
		t.Fatal(err)
	}

	// Full parse (fromOffset=0).
	resFull, err := a.ParseSessionFile(context.Background(), path, 0)
	if err != nil {
		t.Fatalf("full parse: %v", err)
	}
	var fullPrompt models.ToolEvent
	for _, ev := range resFull.ToolEvents {
		if ev.ActionType == models.ActionUserPrompt {
			fullPrompt = ev
			break
		}
	}
	if fullPrompt.SourceEventID == "" {
		t.Fatalf("full parse: no user_prompt event; got %+v", resFull.ToolEvents)
	}

	// Resumed parse starting right at the user_prompt line.
	resumeOffset := int64(len(header))
	resResume, err := a.ParseSessionFile(context.Background(), path, resumeOffset)
	if err != nil {
		t.Fatalf("resumed parse: %v", err)
	}
	var resumePrompt models.ToolEvent
	for _, ev := range resResume.ToolEvents {
		if ev.ActionType == models.ActionUserPrompt {
			resumePrompt = ev
			break
		}
	}
	if resumePrompt.SourceEventID == "" {
		t.Fatalf("resumed parse: no user_prompt event; got %+v", resResume.ToolEvents)
	}

	if fullPrompt.SourceEventID != resumePrompt.SourceEventID {
		t.Errorf("SourceEventID drift across re-parse:\n  full   = %q\n  resume = %q\nUPSERT would create a duplicate row.", fullPrompt.SourceEventID, resumePrompt.SourceEventID)
	}
}

// TestParseSessionFile_Codex0_130TurnContextMetadata pins v1.4.52's
// capture of the four new turn_context fields added in codex
// 0.130.0-alpha.5: personality, collaboration_mode.mode,
// realtime_active, and truncation_policy.{mode,limit}. All ride on
// actions.metadata via withEffort the same way EffortLevel does.
func TestParseSessionFile_Codex0_130TurnContextMetadata(t *testing.T) {
	t.Parallel()
	a := New()
	dir := t.TempDir()
	path := filepath.Join(dir, "v0_130-fields.jsonl")
	body := strings.Join([]string{
		`{"timestamp":"2026-05-14T00:00:00.000Z","type":"session_meta","payload":{"id":"sess-v0_130","cwd":"/repo","cli_version":"0.130.0-alpha.5"}}`,
		`{"timestamp":"2026-05-14T00:00:01.000Z","type":"turn_context","payload":{"turn_id":"t1","cwd":"/repo","model":"gpt-5.4","personality":"friendly","realtime_active":true,"collaboration_mode":{"mode":"plan","settings":{"reasoning_effort":"high"}},"truncation_policy":{"mode":"tokens","limit":10000}}}`,
		`{"timestamp":"2026-05-14T00:00:02.000Z","type":"event_msg","payload":{"type":"exec_command_end","turn_id":"t1","call_id":"c1","cwd":"/repo","command":["bash","-lc","ls"],"exit_code":0,"duration":{"secs":0,"nanos":100000000}}}`,
		"",
	}, "\n")
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	res, err := a.ParseSessionFile(context.Background(), path, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	var run *models.ToolEvent
	for i, ev := range res.ToolEvents {
		if ev.ActionType == models.ActionRunCommand {
			run = &res.ToolEvents[i]
			break
		}
	}
	if run == nil {
		t.Fatalf("expected a run_command event; got %+v", res.ToolEvents)
	}
	if run.Metadata == nil {
		t.Fatalf("metadata nil; want codex 0.130+ fields")
	}
	if got, want := run.Metadata.CollaborationMode, "plan"; got != want {
		t.Errorf("CollaborationMode=%q want %q", got, want)
	}
	if got, want := run.Metadata.Personality, "friendly"; got != want {
		t.Errorf("Personality=%q want %q", got, want)
	}
	if !run.Metadata.RealtimeActive {
		t.Error("RealtimeActive=false want true")
	}
	if got, want := run.Metadata.TruncationMode, "tokens"; got != want {
		t.Errorf("TruncationMode=%q want %q", got, want)
	}
	if got, want := run.Metadata.TruncationLimit, int64(10000); got != want {
		t.Errorf("TruncationLimit=%d want %d", got, want)
	}
	if got, want := run.Metadata.EffortLevel, "high"; got != want {
		t.Errorf("EffortLevel=%q want %q (existing capture must still work)", got, want)
	}
}

// TestParseSessionFile_Codex0_130StickyMetadataAcrossTurns confirms
// the new metadata fields follow the same "sticky" rule as
// EffortLevel: a later turn_context that omits a field MUST NOT wipe
// a previously-established value. RealtimeActive is the exception —
// it's authoritative on every turn_context (bool can't distinguish
// absent from explicit-false).
func TestParseSessionFile_Codex0_130StickyMetadataAcrossTurns(t *testing.T) {
	t.Parallel()
	a := New()
	dir := t.TempDir()
	path := filepath.Join(dir, "v0_130-sticky.jsonl")
	body := strings.Join([]string{
		`{"timestamp":"2026-05-14T00:00:00.000Z","type":"session_meta","payload":{"id":"sess-sticky","cwd":"/repo","cli_version":"0.130.0-alpha.5"}}`,
		// Turn 1: full set.
		`{"timestamp":"2026-05-14T00:00:01.000Z","type":"turn_context","payload":{"turn_id":"t1","cwd":"/repo","model":"gpt-5.4","personality":"friendly","realtime_active":false,"collaboration_mode":{"mode":"default","settings":{"reasoning_effort":"medium"}},"truncation_policy":{"mode":"tokens","limit":5000}}}`,
		`{"timestamp":"2026-05-14T00:00:02.000Z","type":"event_msg","payload":{"type":"exec_command_end","turn_id":"t1","call_id":"c1","cwd":"/repo","command":["bash","-lc","ls"],"exit_code":0,"duration":{"secs":0,"nanos":100000000}}}`,
		// Turn 2: omits everything but model+turn_id. Should NOT wipe the strings/int.
		`{"timestamp":"2026-05-14T00:00:03.000Z","type":"turn_context","payload":{"turn_id":"t2","cwd":"/repo","model":"gpt-5.4"}}`,
		`{"timestamp":"2026-05-14T00:00:04.000Z","type":"event_msg","payload":{"type":"exec_command_end","turn_id":"t2","call_id":"c2","cwd":"/repo","command":["bash","-lc","pwd"],"exit_code":0,"duration":{"secs":0,"nanos":100000000}}}`,
		"",
	}, "\n")
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	res, err := a.ParseSessionFile(context.Background(), path, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	var runs []models.ToolEvent
	for _, ev := range res.ToolEvents {
		if ev.ActionType == models.ActionRunCommand {
			runs = append(runs, ev)
		}
	}
	if len(runs) != 2 {
		t.Fatalf("expected 2 run_command events, got %d", len(runs))
	}
	for i, ev := range runs {
		if ev.Metadata == nil {
			t.Errorf("run[%d] Metadata nil; sticky fields should be present", i)
			continue
		}
		if ev.Metadata.CollaborationMode != "default" {
			t.Errorf("run[%d] CollaborationMode=%q want default (sticky)", i, ev.Metadata.CollaborationMode)
		}
		if ev.Metadata.Personality != "friendly" {
			t.Errorf("run[%d] Personality=%q want friendly (sticky)", i, ev.Metadata.Personality)
		}
		if ev.Metadata.TruncationMode != "tokens" {
			t.Errorf("run[%d] TruncationMode=%q want tokens (sticky)", i, ev.Metadata.TruncationMode)
		}
		if ev.Metadata.TruncationLimit != 5000 {
			t.Errorf("run[%d] TruncationLimit=%d want 5000 (sticky)", i, ev.Metadata.TruncationLimit)
		}
	}
}

// TestParseSessionFile_Codex0_130TimeToFirstToken pins the
// time_to_first_token_ms capture on task_complete events added in
// codex 0.130.0-alpha.5. Older sessions without the field still
// produce task_complete rows without latency metadata.
func TestParseSessionFile_Codex0_130TimeToFirstToken(t *testing.T) {
	t.Parallel()
	a := New()
	dir := t.TempDir()
	path := filepath.Join(dir, "v0_130-ttft.jsonl")
	body := strings.Join([]string{
		`{"timestamp":"2026-05-14T00:00:00.000Z","type":"session_meta","payload":{"id":"sess-ttft","cwd":"/repo","cli_version":"0.130.0-alpha.5"}}`,
		`{"timestamp":"2026-05-14T00:00:01.000Z","type":"turn_context","payload":{"turn_id":"t1","cwd":"/repo","model":"gpt-5.4"}}`,
		`{"timestamp":"2026-05-14T00:00:05.000Z","type":"event_msg","payload":{"type":"task_complete","turn_id":"t1","last_agent_message":"done","completed_at":1778700562,"duration_ms":3882,"time_to_first_token_ms":3023}}`,
		"",
	}, "\n")
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	res, err := a.ParseSessionFile(context.Background(), path, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	var done *models.ToolEvent
	for i, ev := range res.ToolEvents {
		if ev.ActionType == models.ActionTaskComplete {
			done = &res.ToolEvents[i]
			break
		}
	}
	if done == nil {
		t.Fatalf("expected a task_complete event")
	}
	if done.Metadata == nil {
		t.Fatalf("metadata nil; want TimeToFirstTokenMS=3023")
	}
	if got, want := done.Metadata.TimeToFirstTokenMS, int64(3023); got != want {
		t.Errorf("TimeToFirstTokenMS=%d want %d", got, want)
	}
	// DurationMs (the existing typed column) should still be populated.
	if got, want := done.DurationMs, int64(3882); got != want {
		t.Errorf("DurationMs=%d want %d (existing capture must not regress)", got, want)
	}
}

// TestParseSessionFile_EffortLevelSurvivesWatcherCycle pins the
// 2026-05-11 fix: when the watcher resumes parsing partway through a
// JSONL (fromOffset > 0) and the leading `turn_context` lines with
// `reasoning_effort` live BEFORE the resume offset, the resumed parse
// must inherit the effort via prefetchSessionContext. Pre-fix:
// prefetch read the lines but mergeSessionContext didn't copy
// EffortLevel AND prefetch didn't call EffortFromPayload, so every
// resumed-cycle event landed with empty effort_level. Verified
// in-the-wild on the maintainer's session 019e1743 (2026-05-11):
// JSONL had reasoning_effort=medium but observer captured empty.
//
// Compound regression check: both bugs would re-introduce empty
// effort even if each is fixed in isolation, so the test exercises
// the full resume path against a fixture where the effort signal
// is wholly on the prefetched side of the offset.
func TestParseSessionFile_EffortLevelSurvivesWatcherCycle(t *testing.T) {
	t.Parallel()
	a := New()
	dir := t.TempDir()
	path := filepath.Join(dir, "effort-resume.jsonl")
	// Header section (sets effort=medium) + body section (the tool
	// event we'll re-parse with fromOffset pointing PAST the header).
	header := strings.Join([]string{
		`{"timestamp":"2026-05-11T13:39:51.930Z","type":"session_meta","payload":{"id":"sess-resume","cwd":"/repo","cli_version":"0.129.0"}}`,
		`{"timestamp":"2026-05-11T13:39:51.931Z","type":"turn_context","payload":{"turn_id":"t1","cwd":"/repo","model":"gpt-5.4","collaboration_mode":{"settings":{"reasoning_effort":"medium"}}}}`,
		"",
	}, "\n")
	body := strings.Join([]string{
		// Resumed chunk: just the tool event, no turn_context.
		`{"timestamp":"2026-05-11T13:39:55.536Z","type":"event_msg","payload":{"type":"exec_command_end","turn_id":"t1","call_id":"c1","cwd":"/repo","command":["bash","-lc","ls /tmp"],"exit_code":0,"duration":{"secs":0,"nanos":100000000}}}`,
		"",
	}, "\n")
	full := header + body
	if err := os.WriteFile(path, []byte(full), 0o644); err != nil {
		t.Fatal(err)
	}

	// Sanity: a full parse (fromOffset=0) gets effort=medium. This
	// verifies the live-parse path still works and isolates the
	// resume-path bug from any other regression.
	res, err := a.ParseSessionFile(context.Background(), path, 0)
	if err != nil {
		t.Fatalf("full parse: %v", err)
	}
	var fullRun models.ToolEvent
	for _, ev := range res.ToolEvents {
		if ev.ActionType == models.ActionRunCommand {
			fullRun = ev
			break
		}
	}
	if fullRun.Metadata == nil || fullRun.Metadata.EffortLevel != "medium" {
		t.Fatalf("full parse: EffortLevel=%v, want medium (live-parse path broken too?)", fmtMetadataEffort(fullRun.Metadata))
	}

	// Now the resume case: parse with fromOffset pointing past the
	// header. Pre-fix this produced an empty EffortLevel.
	resumeOffset := int64(len(header))
	resumed, err := a.ParseSessionFile(context.Background(), path, resumeOffset)
	if err != nil {
		t.Fatalf("resumed parse: %v", err)
	}
	var resumedRun models.ToolEvent
	for _, ev := range resumed.ToolEvents {
		if ev.ActionType == models.ActionRunCommand {
			resumedRun = ev
			break
		}
	}
	if resumedRun.ActionType == "" {
		t.Fatalf("resumed parse: no run_command event emitted; got %+v", resumed.ToolEvents)
	}
	if resumedRun.Metadata == nil {
		t.Fatalf("resumed parse: Metadata=nil, want EffortLevel=medium (prefetch should have lifted it from the header turn_context)")
	}
	if resumedRun.Metadata.EffortLevel != "medium" {
		t.Errorf("resumed parse: EffortLevel=%q, want medium — watcher-cycle continuity broken", resumedRun.Metadata.EffortLevel)
	}
}

// TestParseRolloutWebSearchCountAttribution pins v1.4.53 web-search
// billing normalization: each event_msg/web_search_end increments a
// per-session running counter, which is flushed onto the next
// non-dedup event_msg/token_count's TokenEvent.WebSearchRequests
// (so the cost engine can apply Pricing.WebSearchPerRequest as a
// flat per-call fee). Mirrors cowork v1.4.53 Phase 2 + closes
// Invariant #57 for the codex path.
func TestParseRolloutWebSearchCountAttribution(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "rollout-2026-05-15T12-50-47-019e2bb0.jsonl")
	body := strings.Join([]string{
		`{"timestamp":"2026-05-15T12:50:47.000Z","type":"session_meta","payload":{"id":"019e2bb0","cwd":"/tmp","model":"gpt-5.5"}}`,
		`{"timestamp":"2026-05-15T12:50:47.500Z","type":"turn_context","payload":{"turn_id":"turn-w","model":"gpt-5.5","cwd":"/tmp"}}`,
		// Three web_search_end events in this turn.
		`{"timestamp":"2026-05-15T12:50:58.000Z","type":"event_msg","payload":{"type":"web_search_end","call_id":"ws_1","turn_id":"turn-w","query":"LiteLLM funding investors","action":{"type":"search","query":"LiteLLM funding investors"}}}`,
		`{"timestamp":"2026-05-15T12:51:03.000Z","type":"event_msg","payload":{"type":"web_search_end","call_id":"ws_2","turn_id":"turn-w","query":"Portkey AI funding","action":{"type":"search","query":"Portkey AI funding"}}}`,
		`{"timestamp":"2026-05-15T12:51:11.000Z","type":"event_msg","payload":{"type":"web_search_end","call_id":"ws_3","turn_id":"turn-w","query":"Helicone seed investors","action":{"type":"search","query":"Helicone seed investors"}}}`,
		// token_count flushes the counter onto the emitted TokenEvent.
		`{"timestamp":"2026-05-15T12:52:20.000Z","type":"event_msg","payload":{"type":"token_count","info":{"last_token_usage":{"input_tokens":71135,"output_tokens":2738,"cached_input_tokens":14720,"reasoning_output_tokens":1496,"total_tokens":73873},"total_token_usage":{"input_tokens":71135,"output_tokens":2738,"cached_input_tokens":14720,"reasoning_output_tokens":1496,"total_tokens":73873}}}}`,
		``,
	}, "\n")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	a := NewWithOptions(nil, dir)
	res, err := a.ParseSessionFile(context.Background(), path, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}

	// Sanity: three ActionWebSearch rows still emitted.
	var webSearchRows int
	for _, ev := range res.ToolEvents {
		if ev.ActionType == models.ActionWebSearch {
			webSearchRows++
		}
	}
	if webSearchRows != 3 {
		t.Errorf("web_search action rows: %d want 3", webSearchRows)
	}

	// The single emitted TokenEvent must carry WebSearchRequests=3
	// (the flush count), and the counter must reset so a subsequent
	// emission would not double-attribute.
	if got := len(res.TokenEvents); got != 1 {
		t.Fatalf("token events: %d want 1", got)
	}
	if got := res.TokenEvents[0].WebSearchRequests; got != 3 {
		t.Errorf("TokenEvent.WebSearchRequests=%d, want 3 (counter flush)", got)
	}
}

// TestParseRolloutWebSearchCountResetsAcrossTokenCounts pins that
// the running web-search counter resets after each emitted
// TokenEvent — two adjacent turns each with their own web_searches
// + token_count must attribute their searches independently. Guards
// against accidental "cumulative" semantics where turn-N's count
// leaks onto turn-(N+1)'s TokenEvent.
func TestParseRolloutWebSearchCountResetsAcrossTokenCounts(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "rollout-2026-05-15T13-00-00-twoturns.jsonl")
	body := strings.Join([]string{
		`{"timestamp":"2026-05-15T13:00:00.000Z","type":"session_meta","payload":{"id":"twoturns","cwd":"/tmp","model":"gpt-5.5"}}`,
		`{"timestamp":"2026-05-15T13:00:00.500Z","type":"turn_context","payload":{"turn_id":"t1","model":"gpt-5.5","cwd":"/tmp"}}`,
		// Turn 1: 2 web searches → token_count.
		`{"timestamp":"2026-05-15T13:00:01.000Z","type":"event_msg","payload":{"type":"web_search_end","call_id":"ws_a","turn_id":"t1","query":"a"}}`,
		`{"timestamp":"2026-05-15T13:00:02.000Z","type":"event_msg","payload":{"type":"web_search_end","call_id":"ws_b","turn_id":"t1","query":"b"}}`,
		`{"timestamp":"2026-05-15T13:00:03.000Z","type":"event_msg","payload":{"type":"token_count","info":{"last_token_usage":{"input_tokens":100,"output_tokens":10,"cached_input_tokens":0,"reasoning_output_tokens":0,"total_tokens":110},"total_token_usage":{"input_tokens":100,"output_tokens":10,"cached_input_tokens":0,"reasoning_output_tokens":0,"total_tokens":110}}}}`,
		// Turn 2: 1 web search → token_count.
		`{"timestamp":"2026-05-15T13:00:04.000Z","type":"event_msg","payload":{"type":"web_search_end","call_id":"ws_c","turn_id":"t2","query":"c"}}`,
		`{"timestamp":"2026-05-15T13:00:05.000Z","type":"event_msg","payload":{"type":"token_count","info":{"last_token_usage":{"input_tokens":50,"output_tokens":5,"cached_input_tokens":0,"reasoning_output_tokens":0,"total_tokens":55},"total_token_usage":{"input_tokens":150,"output_tokens":15,"cached_input_tokens":0,"reasoning_output_tokens":0,"total_tokens":165}}}}`,
		``,
	}, "\n")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	a := NewWithOptions(nil, dir)
	res, err := a.ParseSessionFile(context.Background(), path, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	if got := len(res.TokenEvents); got != 2 {
		t.Fatalf("token events: %d want 2", got)
	}
	if got := res.TokenEvents[0].WebSearchRequests; got != 2 {
		t.Errorf("turn-1 TokenEvent.WebSearchRequests=%d, want 2", got)
	}
	if got := res.TokenEvents[1].WebSearchRequests; got != 1 {
		t.Errorf("turn-2 TokenEvent.WebSearchRequests=%d, want 1 (counter must reset between flushes)", got)
	}
}

// TestParseRolloutRateLimitsCapturedFromTokenCount pins v1.4.53
// codex rate_limits capture: Codex 0.130+ embeds
// `rate_limits.{primary,secondary,plan_type,rate_limit_reached_type}`
// inside every event_msg/token_count, INCLUDING the startup one
// with `info: null`. We emit one ActionRateLimit ToolEvent per
// token_count line that carries rate_limits, reusing the generic
// RateLimitStatus/Type/ResetsAt/OverageStatus schema cowork
// introduced. Closes the v1.4.52 deferred carryover.
func TestParseRolloutRateLimitsCapturedFromTokenCount(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "rollout-2026-05-15T12-50-47-019e2bb0.jsonl")
	body := strings.Join([]string{
		`{"timestamp":"2026-05-15T12:50:47.000Z","type":"session_meta","payload":{"id":"019e2bb0","cwd":"/tmp","model":"gpt-5.5"}}`,
		`{"timestamp":"2026-05-15T12:50:47.500Z","type":"turn_context","payload":{"turn_id":"turn-rl","model":"gpt-5.5","cwd":"/tmp"}}`,
		// Startup token_count: info=null, rate_limits populated. Must still emit a rate_limit row.
		`{"timestamp":"2026-05-15T12:50:48.000Z","type":"event_msg","payload":{"type":"token_count","info":null,"rate_limits":{"limit_id":"codex","primary":{"used_percent":1,"window_minutes":300,"resets_at":1778867450},"secondary":{"used_percent":0,"window_minutes":10080,"resets_at":1779454250},"plan_type":"plus","rate_limit_reached_type":null}}}`,
		// End-of-turn token_count: info populated, same rate_limits envelope.
		`{"timestamp":"2026-05-15T12:52:20.000Z","type":"event_msg","payload":{"type":"token_count","info":{"last_token_usage":{"input_tokens":100,"output_tokens":10,"cached_input_tokens":0,"reasoning_output_tokens":0,"total_tokens":110},"total_token_usage":{"input_tokens":100,"output_tokens":10,"cached_input_tokens":0,"reasoning_output_tokens":0,"total_tokens":110}},"rate_limits":{"limit_id":"codex","primary":{"used_percent":1,"window_minutes":300,"resets_at":1778867450},"secondary":{"used_percent":0,"window_minutes":10080,"resets_at":1779454250},"plan_type":"plus","rate_limit_reached_type":null}}}`,
		``,
	}, "\n")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	a := NewWithOptions(nil, dir)
	res, err := a.ParseSessionFile(context.Background(), path, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}

	var rlRows []models.ToolEvent
	for _, ev := range res.ToolEvents {
		if ev.ActionType == models.ActionRateLimit {
			rlRows = append(rlRows, ev)
		}
	}
	if got := len(rlRows); got != 2 {
		t.Fatalf("rate_limit rows: %d want 2 (1 startup + 1 end-of-turn)", got)
	}
	row := rlRows[0]
	if row.Tool != models.ToolCodex {
		t.Errorf("Tool=%q want %q", row.Tool, models.ToolCodex)
	}
	if row.Metadata == nil {
		t.Fatalf("Metadata=nil, want RateLimit fields populated")
	}
	if row.Metadata.RateLimitStatus != "ok" {
		t.Errorf("RateLimitStatus=%q, want ok (rate_limit_reached_type==null)", row.Metadata.RateLimitStatus)
	}
	if row.Metadata.RateLimitType != "codex" {
		t.Errorf("RateLimitType=%q, want codex", row.Metadata.RateLimitType)
	}
	if row.Metadata.RateLimitResetsAt != 1778867450 {
		t.Errorf("RateLimitResetsAt=%d, want 1778867450 (primary.resets_at)", row.Metadata.RateLimitResetsAt)
	}
	if row.Metadata.RateLimitOverageStatus != "plus" {
		t.Errorf("RateLimitOverageStatus=%q, want plus (plan_type)", row.Metadata.RateLimitOverageStatus)
	}
	if !strings.Contains(row.RawToolInput, `"secondary"`) || !strings.Contains(row.RawToolInput, `"window_minutes":10080`) {
		t.Errorf("RawToolInput must preserve full envelope for dashboard render; got %q", row.RawToolInput)
	}
	// Stable source_event_id derivable from filename + line — re-parses idempotent.
	if !strings.HasPrefix(row.SourceEventID, "ratelimit:") {
		t.Errorf("SourceEventID=%q, want prefix 'ratelimit:'", row.SourceEventID)
	}
}

// TestParseRolloutReasoningEmptySummaryEmitsNothing pins the B3
// contract for the dominant Codex shape: a response_item.reasoning
// with NO summary text (the 100% case in Codex Desktop builds
// inspected through 2026-05) produces NOTHING AT ALL. v1.4.53 minted
// an opaque "(encrypted reasoning, N bytes)" placeholder row for it —
// 15,040 content-free phantom task_complete rows in the live corpus.
// A placeholder is never an action and is never threaded either: with
// no readable summary there is nothing to carry.
func TestParseRolloutReasoningEmptySummaryEmitsNothing(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "rollout-2026-05-15T13-30-00-empty.jsonl")
	body := strings.Join([]string{
		`{"timestamp":"2026-05-15T13:30:00.000Z","type":"session_meta","payload":{"id":"empty","cwd":"/tmp","model":"gpt-5.5"}}`,
		`{"timestamp":"2026-05-15T13:30:00.500Z","type":"turn_context","payload":{"turn_id":"t","model":"gpt-5.5","cwd":"/tmp"}}`,
		// Reasoning with empty summary + encrypted_content.
		`{"timestamp":"2026-05-15T13:30:01.000Z","type":"response_item","payload":{"type":"reasoning","summary":[],"encrypted_content":"abcdefghijklmnopqrstuvwxyz0123456789ABCDEF"}}`,
		``,
	}, "\n")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	a := NewWithOptions(nil, dir)
	res, err := a.ParseSessionFile(context.Background(), path, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	for _, ev := range res.ToolEvents {
		if strings.Contains(strings.ToLower(ev.RawToolName), "reasoning") {
			t.Errorf("reasoning-named action row emitted: raw=%q %+v", ev.RawToolName, ev)
		}
		if strings.Contains(ev.Target, "encrypted reasoning") || ev.Target == "(reasoning)" {
			t.Errorf("placeholder reasoning text surfaced as an action target: %+v", ev)
		}
		if strings.Contains(ev.PrecedingReasoning, "encrypted reasoning") || ev.PrecedingReasoning == "(reasoning)" {
			t.Errorf("placeholder reasoning text threaded into PrecedingReasoning: %+v", ev)
		}
	}
	if len(res.ToolEvents) != 0 {
		t.Errorf("encrypted-only reasoning produced %d events, want 0: %+v", len(res.ToolEvents), res.ToolEvents)
	}
}

// TestParseRolloutWebSearchSurfacesFanOutQueries pins that each
// web_search_end's action.queries[] (the 3-4 sub-queries Codex's
// search tool issues per top-level call) lands in RawToolInput as
// JSON so the dashboard can render the full fan-out. Pre-fix only
// the top-level Query string was preserved, hiding the 3-4×
// per-call fan-out from operators.
func TestParseRolloutWebSearchSurfacesFanOutQueries(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "rollout-2026-05-15T14-00-00-fanout.jsonl")
	body := strings.Join([]string{
		`{"timestamp":"2026-05-15T14:00:00.000Z","type":"session_meta","payload":{"id":"fanout","cwd":"/tmp","model":"gpt-5.5"}}`,
		`{"timestamp":"2026-05-15T14:00:00.500Z","type":"turn_context","payload":{"turn_id":"t","model":"gpt-5.5","cwd":"/tmp"}}`,
		`{"timestamp":"2026-05-15T14:00:01.000Z","type":"event_msg","payload":{"type":"web_search_end","call_id":"ws_fan","turn_id":"t","query":"LiteLLM funding status investors","action":{"type":"search","query":"LiteLLM funding status investors","queries":["LiteLLM funding status investors","LiteLLM GitHub company funding seed round","LiteLLM competitors AI gateway proxy OpenAI compatible"]}}}`,
		``,
	}, "\n")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	a := NewWithOptions(nil, dir)
	res, err := a.ParseSessionFile(context.Background(), path, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	var row *models.ToolEvent
	for i := range res.ToolEvents {
		if res.ToolEvents[i].ActionType == models.ActionWebSearch {
			row = &res.ToolEvents[i]
			break
		}
	}
	if row == nil {
		t.Fatalf("no web_search row emitted")
	}
	// Target stays compact for the row label.
	if !strings.Contains(row.Target, "LiteLLM funding status") {
		t.Errorf("Target should contain top-level query; got %q", row.Target)
	}
	// RawToolInput must be JSON carrying the queries array, otherwise
	// the dashboard can't render the fan-out.
	if !strings.Contains(row.RawToolInput, `"queries"`) {
		t.Errorf("RawToolInput must be JSON with `queries`; got %q", row.RawToolInput)
	}
	if !strings.Contains(row.RawToolInput, "LiteLLM GitHub company funding seed round") {
		t.Errorf("RawToolInput missing sub-query #2; got %q", row.RawToolInput)
	}
	if !strings.Contains(row.RawToolInput, "AI gateway proxy OpenAI compatible") {
		t.Errorf("RawToolInput missing sub-query #3; got %q", row.RawToolInput)
	}
}

// TestParseTokenCount_NetsInputAgainstCached pins the v1.6.29
// audit fix in BOTH the modern (event_msg/token_count) and legacy
// (top-level type=token_count) parser paths: codex's input_tokens is
// the TOTAL prompt count INCLUDING cached_input_tokens; we must
// subtract cached at emit time so the cost engine (which treats
// TokenBundle.Input as NET non-cached) doesn't double-bill the
// cached portion at both input + cache_read rates. See
// internal/intelligence/cost/engine.go TokenBundle docstring.
func TestParseTokenCount_NetsInputAgainstCached(t *testing.T) {
	t.Run("modern event_msg/token_count nets input", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "rollout-2026-05-24T16-40-04-sess.jsonl")
		body := strings.Join([]string{
			`{"timestamp":"2026-05-24T16:40:10.000Z","type":"session_meta","payload":{"id":"sess-net","model":"gpt-5.4-mini","cwd":"/repo"}}`,
			`{"timestamp":"2026-05-24T16:40:13.000Z","type":"event_msg","payload":{"type":"token_count","info":{"last_token_usage":{"input_tokens":13923,"output_tokens":17,"cached_input_tokens":10624,"reasoning_output_tokens":10,"total_tokens":13950},"total_token_usage":{"input_tokens":13923,"output_tokens":17,"cached_input_tokens":10624,"reasoning_output_tokens":10,"total_tokens":13950}}}}`,
			``,
		}, "\n")
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		a := New()
		res, err := a.ParseSessionFile(context.Background(), path, 0)
		if err != nil {
			t.Fatalf("ParseSessionFile: %v", err)
		}
		if len(res.TokenEvents) != 1 {
			t.Fatalf("token events: got %d want 1", len(res.TokenEvents))
		}
		ev := res.TokenEvents[0]
		// 13923 gross - 10624 cached = 3299 net.
		if ev.InputTokens != 3299 {
			t.Errorf("InputTokens: got %d, want 3299 (13923 gross - 10624 cached)", ev.InputTokens)
		}
		if ev.CacheReadTokens != 10624 {
			t.Errorf("CacheReadTokens: got %d, want 10624 (raw from cached_input_tokens)", ev.CacheReadTokens)
		}
		// Wire output_tokens (17) is GROSS and contains the reasoning
		// subset (10); the adapter nets it → OutputTokens=7 so the cost
		// engine doesn't double-bill reasoning. Invariant: 7 + 10 == 17.
		if ev.OutputTokens != 7 {
			t.Errorf("OutputTokens: got %d, want 7 (17 gross - 10 reasoning)", ev.OutputTokens)
		}
		if ev.ReasoningTokens != 10 {
			t.Errorf("ReasoningTokens: got %d, want 10", ev.ReasoningTokens)
		}
		if ev.OutputTokens+ev.ReasoningTokens != 17 {
			t.Errorf("net output + reasoning = %d, want 17 (gross wire output_tokens)", ev.OutputTokens+ev.ReasoningTokens)
		}
	})

	t.Run("legacy top-level token_count nets cumulative input", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "rollout-legacy-net.jsonl")
		body := strings.Join([]string{
			`{"id":"sm","timestamp":"2026-04-16T12:00:00Z","type":"session_meta","payload":{"id":"sess-legacy-net","model":"gpt-5-codex","cwd":"/repo"}}`,
			// Turn 1: gross=1000 cached=800 → net cumulative = 200, delta = 200.
			`{"id":"tk1","timestamp":"2026-04-16T12:00:05Z","type":"token_count","payload":{"input_tokens":1000,"output_tokens":10,"cached_input_tokens":800,"model":"gpt-5-codex"}}`,
			// Turn 2: gross=1600 cached=1200 → net cumulative = 400, delta = 200.
			`{"id":"tk2","timestamp":"2026-04-16T12:00:10Z","type":"token_count","payload":{"input_tokens":1600,"output_tokens":15,"cached_input_tokens":1200,"model":"gpt-5-codex"}}`,
			``,
		}, "\n")
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		a := New()
		res, err := a.ParseSessionFile(context.Background(), path, 0)
		if err != nil {
			t.Fatalf("ParseSessionFile: %v", err)
		}
		if len(res.TokenEvents) != 2 {
			t.Fatalf("token events: got %d want 2", len(res.TokenEvents))
		}
		// tk1: first event, net cumulative = 200.
		if res.TokenEvents[0].InputTokens != 200 {
			t.Errorf("tk1 InputTokens: got %d, want 200", res.TokenEvents[0].InputTokens)
		}
		if res.TokenEvents[0].CacheReadTokens != 800 {
			t.Errorf("tk1 CacheReadTokens: got %d, want 800", res.TokenEvents[0].CacheReadTokens)
		}
		// tk2: net cumulative = 400, delta from prev (200) = 200.
		if res.TokenEvents[1].InputTokens != 200 {
			t.Errorf("tk2 InputTokens (delta of net cumulative): got %d, want 200", res.TokenEvents[1].InputTokens)
		}
		if res.TokenEvents[1].CacheReadTokens != 1200 {
			t.Errorf("tk2 CacheReadTokens: got %d, want 1200", res.TokenEvents[1].CacheReadTokens)
		}
	})
}

// --- issue #7: oversized-record handling -----------------------------
//
// Before the fix, ParseSessionFile read lines with a bufio.Scanner
// whose 16 MiB token cap failed the ENTIRE rollout the instant one
// record exceeded it ("bufio.Scanner: token too long"). A valid 91 MiB
// rollout carrying a single 22.3 MiB token_count record was discarded
// whole. The reader is now bufio.Reader.ReadString-style with a 64 MiB
// per-record memory-safety bound: records up to the bound parse, and a
// record larger than it degrades to a per-record SKIP (bytes consumed,
// cursor + line counter advanced, governance cleared) instead of a
// file-level failure.

// oversizePaddingLine builds a single valid JSON rollout record of an
// inert (unhandled) type whose filler string makes the whole line at
// least padBytes long. Kept a no-op for the parser so the test isolates
// the reader's size handling.
func oversizePaddingLine(ts string, padBytes int) string {
	return `{"timestamp":"` + ts + `","type":"padding_record","payload":{"filler":"` + strings.Repeat("a", padBytes) + `"}}`
}

// TestParseSessionFile_LargeRecordUnderBoundParsesWholeFile is the
// reporter regression (case a): a record far larger than the old 16 MiB
// scanner cap but under the 64 MiB bound must not fail the file, and the
// normal records around it must still ingest.
func TestParseSessionFile_LargeRecordUnderBoundParsesWholeFile(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "rollout-2026-07-16T10-00-00-big.jsonl")

	// 17 MiB > the old 16 MiB cap, < the 64 MiB bound (reporter: 22.3 MiB).
	big := oversizePaddingLine("2026-07-16T10:00:01.500Z", 17*1024*1024)
	body := strings.Join([]string{
		`{"timestamp":"2026-07-16T10:00:00.000Z","type":"session_meta","payload":{"id":"big-sess","session_id":"big-sess","thread_source":"user","timestamp":"2026-07-16T10:00:00.000Z","cwd":"/w","model":"gpt-5.6","git_branch":"main"}}`,
		`{"timestamp":"2026-07-16T10:00:01.000Z","type":"event_msg","payload":{"type":"task_started","turn_id":"turn-1","started_at":1784233924}}`,
		big,
		`{"timestamp":"2026-07-16T10:00:02.000Z","type":"event_msg","payload":{"type":"token_count","info":{"last_token_usage":{"input_tokens":100,"cached_input_tokens":10,"output_tokens":20,"reasoning_output_tokens":0,"total_tokens":120},"total_token_usage":{"input_tokens":100,"cached_input_tokens":10,"output_tokens":20,"reasoning_output_tokens":0,"total_tokens":120}}}}`,
		``,
	}, "\n")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	res, err := NewWithOptions(nil, dir).ParseSessionFile(context.Background(), path, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v (a large-but-valid record must not fail the file)", err)
	}
	if len(res.TokenEvents) != 1 {
		t.Fatalf("token events: got %d want 1 (record after the big line must ingest)", len(res.TokenEvents))
	}
	// token_count is L4 — the big record occupies L3 and must not shift
	// the counter.
	wantID := fmt.Sprintf("tk:%s:L4", filepath.Base(path))
	if got := res.TokenEvents[0].SourceEventID; got != wantID {
		t.Fatalf("token SourceEventID = %q; want %q", got, wantID)
	}
	if res.NewOffset != int64(len(body)) {
		t.Fatalf("NewOffset = %d; want %d (whole file consumed)", res.NewOffset, len(body))
	}
	for _, w := range res.Warnings {
		if strings.Contains(w, "oversized") {
			t.Fatalf("unexpected oversized warning for a sub-bound record: %q", w)
		}
	}
}

// TestParseSessionFile_OverBoundRecordSkippedNotFailed covers case (b):
// a record larger than the bound is skipped (not failed), the line
// counter advances across it, subsequent records still parse, a single
// recoverable warning is surfaced, and an incremental re-parse from the
// committed offset is stable. Lowers the bound so the test never
// allocates tens of megabytes; it therefore modifies package state and
// must not run in parallel.
func TestParseSessionFile_OverBoundRecordSkippedNotFailed(t *testing.T) {
	old := maxRecordBytes
	maxRecordBytes = 4096
	defer func() { maxRecordBytes = old }()

	dir := t.TempDir()
	path := filepath.Join(dir, "rollout-2026-07-16T11-00-00-over.jsonl")

	big := oversizePaddingLine("2026-07-16T11:00:01.500Z", 8192) // > 4096 bound
	body := strings.Join([]string{
		`{"timestamp":"2026-07-16T11:00:00.000Z","type":"session_meta","payload":{"id":"over-sess","session_id":"over-sess","thread_source":"user","timestamp":"2026-07-16T11:00:00.000Z","cwd":"/w","model":"gpt-5.6","git_branch":"main"}}`,
		`{"timestamp":"2026-07-16T11:00:01.000Z","type":"event_msg","payload":{"type":"task_started","turn_id":"turn-1","started_at":1784233924}}`,
		big,
		`{"timestamp":"2026-07-16T11:00:02.000Z","type":"event_msg","payload":{"type":"token_count","info":{"last_token_usage":{"input_tokens":100,"cached_input_tokens":10,"output_tokens":20,"reasoning_output_tokens":0,"total_tokens":120},"total_token_usage":{"input_tokens":100,"cached_input_tokens":10,"output_tokens":20,"reasoning_output_tokens":0,"total_tokens":120}}}}`,
		``,
	}, "\n")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	res, err := NewWithOptions(nil, dir).ParseSessionFile(context.Background(), path, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v (an over-bound record must skip, not fail)", err)
	}
	if len(res.TokenEvents) != 1 {
		t.Fatalf("token events: got %d want 1 (record after the skip must ingest)", len(res.TokenEvents))
	}
	// The skipped record (L3) still increments the counter, so the
	// token_count lands on L4.
	wantID := fmt.Sprintf("tk:%s:L4", filepath.Base(path))
	if got := res.TokenEvents[0].SourceEventID; got != wantID {
		t.Fatalf("token SourceEventID = %q; want %q (line counter must advance across the skip)", got, wantID)
	}
	var skipWarns int
	for _, w := range res.Warnings {
		if strings.Contains(w, "skipped oversized record") {
			skipWarns++
		}
	}
	if skipWarns != 1 {
		t.Fatalf("oversized-skip warnings: got %d want 1 (warnings=%v)", skipWarns, res.Warnings)
	}
	if res.NewOffset != int64(len(body)) {
		t.Fatalf("NewOffset = %d; want %d (whole file consumed past the skip)", res.NewOffset, len(body))
	}

	// Incremental re-parse from the committed offset: nothing new, cursor
	// stable (offsets are correct across the skip).
	res2, err := NewWithOptions(nil, dir).ParseSessionFile(context.Background(), path, res.NewOffset)
	if err != nil {
		t.Fatalf("incremental ParseSessionFile: %v", err)
	}
	if len(res2.TokenEvents) != 0 || len(res2.ToolEvents) != 0 {
		t.Fatalf("incremental re-parse events: got %d token / %d tool; want 0/0", len(res2.TokenEvents), len(res2.ToolEvents))
	}
	if res2.NewOffset != res.NewOffset {
		t.Fatalf("incremental NewOffset = %d; want stable %d", res2.NewOffset, res.NewOffset)
	}
}

// TestReplayedTokenLines_LineNumbersLockstepAcrossOversizeSkip covers
// case (c): ReplayedTokenLines (the destructive backfill scan) and
// ParseSessionFile must assign identical ABSOLUTE line numbers across an
// oversized skip, because token_usage rows are keyed
// "tk:<base>:L<line>". A desync would make the backfill delete the wrong
// row. Lowers the bound (modifies package state) so it must not run in
// parallel.
func TestReplayedTokenLines_LineNumbersLockstepAcrossOversizeSkip(t *testing.T) {
	old := maxRecordBytes
	maxRecordBytes = 4096
	defer func() { maxRecordBytes = old }()

	// Insert an oversized record right after the owning session_meta,
	// shifting every following line by one: the two replayed
	// token_counts move L4,L5 -> L5,L6 and the live token_count L7 -> L8.
	origLines := strings.Split(forkRolloutBody("subagent"), "\n")
	oversized := oversizePaddingLine("2026-07-16T20:32:04.545Z", 8192)
	shifted := append([]string{origLines[0], oversized}, origLines[1:]...)
	body := strings.Join(shifted, "\n")

	got, err := ReplayedTokenLines(strings.NewReader(body))
	if err != nil {
		t.Fatalf("ReplayedTokenLines: %v", err)
	}
	if len(got) != 2 || !got[5] || !got[6] {
		t.Fatalf("ReplayedTokenLines = %v; want exactly {5,6} (replayed token_counts at their post-skip line numbers)", got)
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "rollout-2026-07-16T20-32-04-child.jsonl")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := NewWithOptions(nil, dir).ParseSessionFile(context.Background(), path, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	if len(res.TokenEvents) != 1 {
		t.Fatalf("token events: got %d want 1 (only the live token_count survives)", len(res.TokenEvents))
	}
	// Main parser must place the live token_count on the SAME L8 the
	// replayed-scan numbering implies — lockstep across the skip.
	wantID := fmt.Sprintf("tk:%s:L8", filepath.Base(path))
	if got := res.TokenEvents[0].SourceEventID; got != wantID {
		t.Fatalf("live token SourceEventID = %q; want %q (line numbering must stay in lockstep with ReplayedTokenLines across the oversized skip)", got, wantID)
	}
}

// --- unified trailing-record deferral rule ---------------------------
//
// Adversarial-review HIGH: a complete record whose trailing '\n' has not
// yet been written by codex must be DEFERRED whole — never parsed and
// never allowed to advance NewOffset past its start — even when the
// fragment is syntactically valid JSON (and even on the oversized path).
// readRecord returns io.EOF exactly for such an unterminated final
// record; a '\n'-terminated final record returns a nil error and ingests
// normally. These tests pin all three at-EOF shapes plus the two-step
// (write body, then append terminator) re-read.

// TestParseSessionFile_DefersValidJSONFragmentWithoutTerminator is the
// reviewer scenario (a): a COMPLETE, syntactically valid session_meta
// written WITHOUT its trailing newline must not be parsed or committed —
// the cursor stays at the fragment's start (offset 0 here). Once codex
// appends the newline + the following token_count, a resume from that
// offset re-reads the session_meta (applying its context) and ingests
// the token record exactly once.
func TestParseSessionFile_DefersValidJSONFragmentWithoutTerminator(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "rollout-2026-07-17T09-00-00-frag.jsonl")

	meta := `{"timestamp":"2026-07-17T09:00:00.000Z","type":"session_meta","payload":{"id":"frag-sess","session_id":"frag-sess","thread_source":"user","timestamp":"2026-07-17T09:00:00.000Z","cwd":"/w","model":"gpt-5.6","git_branch":"main"}}`
	tokenLine := `{"timestamp":"2026-07-17T09:00:01.000Z","type":"event_msg","payload":{"type":"token_count","info":{"last_token_usage":{"input_tokens":100,"cached_input_tokens":10,"output_tokens":20,"reasoning_output_tokens":0,"total_tokens":120},"total_token_usage":{"input_tokens":100,"cached_input_tokens":10,"output_tokens":20,"reasoning_output_tokens":0,"total_tokens":120}}}}`

	// Step 1: the session_meta lands WITHOUT its trailing newline.
	if err := os.WriteFile(path, []byte(meta), 0o600); err != nil {
		t.Fatal(err)
	}
	a := NewWithOptions(nil, dir)
	res1, err := a.ParseSessionFile(context.Background(), path, 0)
	if err != nil {
		t.Fatalf("first parse: %v", err)
	}
	if len(res1.TokenEvents) != 0 || len(res1.ToolEvents) != 0 || len(res1.SessionLineages) != 0 {
		t.Fatalf("deferred valid-JSON fragment leaked output: %d token / %d tool / %d lineage (must be 0/0/0 until terminated)",
			len(res1.TokenEvents), len(res1.ToolEvents), len(res1.SessionLineages))
	}
	if res1.NewOffset != 0 {
		t.Fatalf("NewOffset = %d; want 0 (cursor must stay at the unterminated record's start)", res1.NewOffset)
	}

	// Step 2: codex finishes the record (adds '\n') and appends the
	// token_count. Resume from the deferred offset.
	full := meta + "\n" + tokenLine + "\n"
	if err := os.WriteFile(path, []byte(full), 0o600); err != nil {
		t.Fatal(err)
	}
	res2, err := a.ParseSessionFile(context.Background(), path, res1.NewOffset)
	if err != nil {
		t.Fatalf("resumed parse: %v", err)
	}
	if len(res2.TokenEvents) != 1 {
		t.Fatalf("resumed token events: got %d want 1 (record ingested exactly once)", len(res2.TokenEvents))
	}
	if got := res2.TokenEvents[0].SessionID; got != "frag-sess" {
		t.Errorf("token SessionID = %q; want frag-sess (session_meta context must apply on the re-read)", got)
	}
	if res2.TokenEvents[0].ProjectRoot == "" {
		t.Errorf("token ProjectRoot empty; want the session_meta cwd (context must apply on the re-read)")
	}
	if res2.NewOffset != int64(len(full)) {
		t.Fatalf("resumed NewOffset = %d; want %d (whole file consumed once terminated)", res2.NewOffset, len(full))
	}
}

// TestParseSessionFile_DefersLiveTaskStartedFragmentGoverns is scenario
// (b): the fork-replay-governing LIVE task_started arrives unterminated
// at EOF. It must be deferred (not committed), so on the two-step write
// its completion still flips governance replayed→live and the following
// live token_count is emitted (delta against the replayed cumulative),
// never suppressed as replayed.
func TestParseSessionFile_DefersLiveTaskStartedFragmentGoverns(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "rollout-2026-07-16T20-32-04-child.jsonl")

	// lines: L0 owner meta, L1 parent meta, L2 replayed task_started,
	// L3/L4 replayed token_counts, L5 live task_started, L6 live
	// token_count, L7 "".
	lines := strings.Split(forkRolloutBody("subagent"), "\n")

	// Step 1: everything through the LIVE task_started (L5) but with L5
	// left UNTERMINATED (no trailing '\n').
	chunk1 := strings.Join(lines[:6], "\n") // L0..L5, L5 has no terminator
	if err := os.WriteFile(path, []byte(chunk1), 0o600); err != nil {
		t.Fatal(err)
	}
	a := NewWithOptions(nil, dir)
	res1, err := a.ParseSessionFile(context.Background(), path, 0)
	if err != nil {
		t.Fatalf("first parse: %v", err)
	}
	if len(res1.TokenEvents) != 0 {
		t.Fatalf("first parse token events: got %d want 0 (2 replayed suppressed, live task_started deferred)", len(res1.TokenEvents))
	}
	wantOffset := int64(len(strings.Join(lines[:5], "\n")) + 1) // start of L5
	if res1.NewOffset != wantOffset {
		t.Fatalf("NewOffset = %d; want %d (cursor at the deferred live task_started's start)", res1.NewOffset, wantOffset)
	}

	// Step 2: codex terminates L5 and appends the live token_count (L6).
	if err := os.WriteFile(path, []byte(forkRolloutBody("subagent")), 0o600); err != nil {
		t.Fatal(err)
	}
	res2, err := a.ParseSessionFile(context.Background(), path, res1.NewOffset)
	if err != nil {
		t.Fatalf("resumed parse: %v", err)
	}
	if len(res2.TokenEvents) != 1 {
		t.Fatalf("resumed token events: got %d want 1 (live token_count must emit, not be suppressed as replayed)", len(res2.TokenEvents))
	}
	if got := res2.TokenEvents[0].InputTokens; got != 17398 {
		t.Errorf("live InputTokens = %d; want 17398 (live_total 688097 − replayed_final 670699 — governance correct after the deferred task_started completed)", got)
	}
}

// TestParseSessionFile_DefersOversizedFragmentWithoutTerminator is
// scenario (c): an oversized record whose terminator is still pending
// must be DEFERRED (offset at its start, no skip warning) rather than
// skipped — its buffered bytes are simply re-drained next pass. Once the
// record is terminated it is skipped exactly once with a warning, and
// the line numbering stays correct (the following token_count on L4).
func TestParseSessionFile_DefersOversizedFragmentWithoutTerminator(t *testing.T) {
	old := maxRecordBytes
	maxRecordBytes = 4096
	defer func() { maxRecordBytes = old }()

	dir := t.TempDir()
	path := filepath.Join(dir, "rollout-2026-07-17T11-00-00-over.jsonl")

	meta := `{"timestamp":"2026-07-17T11:00:00.000Z","type":"session_meta","payload":{"id":"over2-sess","session_id":"over2-sess","thread_source":"user","timestamp":"2026-07-17T11:00:00.000Z","cwd":"/w","model":"gpt-5.6","git_branch":"main"}}`
	started := `{"timestamp":"2026-07-17T11:00:01.000Z","type":"event_msg","payload":{"type":"task_started","turn_id":"turn-1","started_at":1784233924}}`
	big := oversizePaddingLine("2026-07-17T11:00:01.500Z", 8192) // > 4096 bound
	tokenLine := `{"timestamp":"2026-07-17T11:00:02.000Z","type":"event_msg","payload":{"type":"token_count","info":{"last_token_usage":{"input_tokens":100,"cached_input_tokens":10,"output_tokens":20,"reasoning_output_tokens":0,"total_tokens":120},"total_token_usage":{"input_tokens":100,"cached_input_tokens":10,"output_tokens":20,"reasoning_output_tokens":0,"total_tokens":120}}}}`

	// Step 1: the oversized record (L3) is the unterminated final frag.
	chunk1 := meta + "\n" + started + "\n" + big // no trailing '\n'
	if err := os.WriteFile(path, []byte(chunk1), 0o600); err != nil {
		t.Fatal(err)
	}
	a := NewWithOptions(nil, dir)
	res1, err := a.ParseSessionFile(context.Background(), path, 0)
	if err != nil {
		t.Fatalf("first parse: %v", err)
	}
	if len(res1.TokenEvents) != 0 {
		t.Fatalf("first parse token events: got %d want 0", len(res1.TokenEvents))
	}
	for _, w := range res1.Warnings {
		if strings.Contains(w, "skipped oversized record") {
			t.Fatalf("unterminated oversized fragment must NOT be skipped yet (warnings=%v)", res1.Warnings)
		}
	}
	wantOffset := int64(len(meta+"\n"+started) + 1) // start of the oversized record (L3)
	if res1.NewOffset != wantOffset {
		t.Fatalf("NewOffset = %d; want %d (cursor at the deferred oversized record's start)", res1.NewOffset, wantOffset)
	}

	// Step 2: codex terminates the oversized record and appends L4.
	full := meta + "\n" + started + "\n" + big + "\n" + tokenLine + "\n"
	if err := os.WriteFile(path, []byte(full), 0o600); err != nil {
		t.Fatal(err)
	}
	res2, err := a.ParseSessionFile(context.Background(), path, res1.NewOffset)
	if err != nil {
		t.Fatalf("resumed parse: %v", err)
	}
	if len(res2.TokenEvents) != 1 {
		t.Fatalf("resumed token events: got %d want 1 (record after the skip must ingest)", len(res2.TokenEvents))
	}
	var skipWarns int
	for _, w := range res2.Warnings {
		if strings.Contains(w, "skipped oversized record") {
			skipWarns++
		}
	}
	if skipWarns != 1 {
		t.Fatalf("oversized-skip warnings on resume: got %d want 1 (warnings=%v)", skipWarns, res2.Warnings)
	}
	// L1 meta, L2 task_started, L3 oversized (skipped, still counted),
	// L4 token_count — the counter must advance across the skip.
	wantID := fmt.Sprintf("tk:%s:L4", filepath.Base(path))
	if got := res2.TokenEvents[0].SourceEventID; got != wantID {
		t.Fatalf("token SourceEventID = %q; want %q (line counter must advance across the deferred-then-skipped record)", got, wantID)
	}
}
