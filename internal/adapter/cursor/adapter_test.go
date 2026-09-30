package cursor

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/contentcap"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/scrub"
)

func TestBuildEvent_BeforeShellExecution(t *testing.T) {
	body := []byte(`{
		"hook_event_name": "beforeShellExecution",
		"conversation_id": "conv-1",
		"generation_id": "gen-7",
		"workspace_roots": ["/home/me/repo"],
		"model": "claude-sonnet-4-5",
		"command": "go test ./..."
	}`)
	ev, ok, err := BuildEvent(EventBeforeShellCommand, body, scrub.New())
	if err != nil || !ok {
		t.Fatalf("BuildEvent: %v ok=%v", err, ok)
	}
	if ev.SessionID != "conv-1" {
		t.Errorf("session: %s", ev.SessionID)
	}
	if ev.MessageID != "gen-7" {
		t.Errorf("message id: %s", ev.MessageID)
	}
	if ev.ProjectRoot != "/home/me/repo" {
		t.Errorf("project_root: %s", ev.ProjectRoot)
	}
	if ev.Model != "claude-sonnet-4-5" {
		t.Errorf("model: %q", ev.Model)
	}
	if ev.Tool != models.ToolCursor {
		t.Errorf("tool: %s", ev.Tool)
	}
	if ev.ActionType != models.ActionRunCommand {
		t.Errorf("action: %s", ev.ActionType)
	}
	if ev.Target != "go test ./..." {
		t.Errorf("target: %s", ev.Target)
	}
	if ev.SourceEventID == "" || !strings.HasPrefix(ev.SourceEventID, "gen-7:") {
		t.Errorf("event id: %s", ev.SourceEventID)
	}
}

// TestBuildEvent_PopulatesModelAcrossEvents guards parity with the matching
// stop token event: every Cursor hook payload carries `model`, so action
// rows for the same generation_id should share that model. Before this
// fix BuildEvent decoded raw.Model but never assigned it, leaving the
// actions table with empty model strings while token rows had the real
// value.
func TestBuildEvent_PopulatesModelAcrossEvents(t *testing.T) {
	cases := []struct {
		name string
		evt  string
		body string
	}{
		{
			name: "afterFileEdit",
			evt:  EventAfterFileEdit,
			body: `{"hook_event_name":"afterFileEdit","conversation_id":"c1","generation_id":"g1","workspace_roots":["/repo"],"model":"claude-opus-4-5","file_path":"x.go"}`,
		},
		{
			name: "beforeSubmitPrompt",
			evt:  EventBeforeSubmitPrompt,
			body: `{"hook_event_name":"beforeSubmitPrompt","conversation_id":"c1","generation_id":"g1","workspace_roots":["/repo"],"model":"gpt-5","prompt":"hello"}`,
		},
		{
			name: "beforeMCPExecution",
			evt:  EventBeforeMCPExecution,
			body: `{"hook_event_name":"beforeMCPExecution","conversation_id":"c1","generation_id":"g1","workspace_roots":["/repo"],"model":"gemini-2.5-pro","server_name":"s","tool_name":"t","input":{}}`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ev, ok, err := BuildEvent(tc.evt, []byte(tc.body), scrub.New())
			if err != nil || !ok {
				t.Fatalf("BuildEvent: %v ok=%v", err, ok)
			}
			if ev.Model == "" {
				t.Fatalf("expected ev.Model populated from raw.Model, got empty")
			}
		})
	}
}

func TestBuildEvent_AfterFileEdit(t *testing.T) {
	body := []byte(`{
		"hook_event_name": "afterFileEdit",
		"conversation_id": "c1",
		"generation_id": "g1",
		"workspace_roots": [{"path": "/repo"}],
		"file_path": "internal/handler.go"
	}`)
	ev, ok, err := BuildEvent(EventAfterFileEdit, body, nil)
	if err != nil || !ok {
		t.Fatalf("BuildEvent: %v ok=%v", err, ok)
	}
	if ev.ActionType != models.ActionEditFile {
		t.Errorf("action: %s", ev.ActionType)
	}
	if ev.Target != "internal/handler.go" {
		t.Errorf("target: %s", ev.Target)
	}
	if ev.ProjectRoot != "/repo" {
		t.Errorf("workspace object form: %s", ev.ProjectRoot)
	}
}

func TestBuildEvent_BeforeMCPExecution(t *testing.T) {
	body := []byte(`{
		"hook_event_name": "beforeMCPExecution",
		"conversation_id": "c1",
		"generation_id": "g1",
		"workspace_roots": ["/repo"],
		"server_name": "github",
		"tool_name": "create_issue",
		"input": {"repo": "owner/x", "title": "bug"}
	}`)
	ev, ok, err := BuildEvent(EventBeforeMCPExecution, body, scrub.New())
	if err != nil || !ok {
		t.Fatalf("BuildEvent: %v ok=%v", err, ok)
	}
	if ev.ActionType != models.ActionMCPCall {
		t.Errorf("action: %s", ev.ActionType)
	}
	if ev.Target != "github:create_issue" {
		t.Errorf("target: %s", ev.Target)
	}
	if !strings.Contains(ev.RawToolInput, "owner/x") {
		t.Errorf("raw input lost: %s", ev.RawToolInput)
	}
}

func TestBuildEvent_BeforeSubmitPrompt(t *testing.T) {
	body := []byte(`{
		"hook_event_name": "beforeSubmitPrompt",
		"conversation_id": "c1",
		"generation_id": "g1",
		"workspace_roots": ["/repo"],
		"prompt": "fix the failing test in handler_test.go and explain why"
	}`)
	ev, ok, err := BuildEvent(EventBeforeSubmitPrompt, body, nil)
	if err != nil || !ok {
		t.Fatalf("BuildEvent: %v ok=%v", err, ok)
	}
	if ev.ActionType != models.ActionUserPrompt {
		t.Errorf("action: %s", ev.ActionType)
	}
	if ev.MessageID != "user:g1" {
		t.Errorf("message id: %s", ev.MessageID)
	}
	if !strings.Contains(ev.Target, "fix the failing test") {
		t.Errorf("target: %s", ev.Target)
	}
}

// TestBuildEvent_AfterAgentThought pins the B3-converged behaviour of
// the v1.6.18 finalized-thinking capture. UPDATED 2026-07-31: the event
// used to mint a `cursor.thinking` task_complete row carrying the
// thought in its own Target/PrecedingReasoning/ToolOutput. It now mints
// NO row at all — the scrubbed 200-char preview is stashed and threaded
// onto the next recordable event of the conversation instead (see
// pending.go). The old assertions on the minted row are replaced by
// assertions on the absence of the row plus the arrival of the text on
// the successor; the preview cap is unchanged.
func TestBuildEvent_AfterAgentThought(t *testing.T) {
	body := []byte(`{
		"hook_event_name": "afterAgentThought",
		"conversation_id": "32c83fe8-3763-4f29-b127-a0968203db01",
		"generation_id": "5ac8a876-8e4e-428d-8189-21d5a3ee129c",
		"workspace_roots": ["/c:/programsx/marmutmain"],
		"model": "default",
		"text": "The user wants to know my specific model name.\n\nThey are asking for my model name, likely to identify the underlying LLM powering me.",
		"duration_ms": 9468
	}`)
	ev, ok, err := BuildEvent(EventAfterAgentThought, body, nil)
	if err != nil {
		t.Fatalf("BuildEvent: %v", err)
	}
	if ok {
		t.Fatalf("afterAgentThought must mint NO row; got %+v", ev)
	}

	// The thought reaches the timeline on the NEXT recordable event.
	next := []byte(`{
		"hook_event_name": "beforeShellExecution",
		"conversation_id": "32c83fe8-3763-4f29-b127-a0968203db01",
		"generation_id": "5ac8a876-8e4e-428d-8189-21d5a3ee129c",
		"workspace_roots": ["/c:/programsx/marmutmain"],
		"command": "go test ./..."
	}`)
	shell, ok, err := BuildEvent(EventBeforeShellCommand, next, nil)
	if err != nil || !ok {
		t.Fatalf("BuildEvent(shell): %v ok=%v", err, ok)
	}
	if !strings.Contains(shell.PrecedingReasoning, "wants to know my specific model name") {
		t.Errorf("successor preceding reasoning = %q, want the stashed thought", shell.PrecedingReasoning)
	}
}

// TestAfterAgentThought_ConsumedOnceAndDiscardedOnUserTurn pins the
// three semantics the stash carries (pending.go): consumed-once (the
// second successor gets nothing), last-wins (a second thought before
// any successor replaces the first), and turn-boundary discard (a new
// user prompt drops an unclaimed thought).
func TestAfterAgentThought_ConsumedOnceAndDiscardedOnUserTurn(t *testing.T) {
	thought := func(conv, gen, text string) {
		t.Helper()
		body := []byte(`{"hook_event_name":"afterAgentThought","conversation_id":"` + conv +
			`","generation_id":"` + gen + `","workspace_roots":["/repo"],"text":"` + text + `"}`)
		if _, ok, err := BuildEvent(EventAfterAgentThought, body, nil); err != nil || ok {
			t.Fatalf("thought: err=%v ok=%v (want no row)", err, ok)
		}
	}
	shell := func(conv, gen, cmd string) models.ToolEvent {
		t.Helper()
		body := []byte(`{"hook_event_name":"beforeShellExecution","conversation_id":"` + conv +
			`","generation_id":"` + gen + `","workspace_roots":["/repo"],"command":"` + cmd + `"}`)
		ev, ok, err := BuildEvent(EventBeforeShellCommand, body, nil)
		if err != nil || !ok {
			t.Fatalf("shell: err=%v ok=%v", err, ok)
		}
		return ev
	}

	// last-wins: two thoughts, no successor between them.
	thought("conv-a", "g1", "first thought")
	thought("conv-a", "g1", "second thought")
	first := shell("conv-a", "g1", "ls")
	if first.PrecedingReasoning != "second thought" {
		t.Errorf("last-wins: preceding reasoning = %q, want %q", first.PrecedingReasoning, "second thought")
	}
	// consumed-once: the next successor of the same conversation gets none.
	second := shell("conv-a", "g2", "pwd")
	if second.PrecedingReasoning != "" {
		t.Errorf("consumed-once: second successor carried %q", second.PrecedingReasoning)
	}

	// turn boundary: a user prompt discards an unclaimed thought.
	thought("conv-b", "g1", "stale thought")
	promptBody := []byte(`{"hook_event_name":"beforeSubmitPrompt","conversation_id":"conv-b",` +
		`"generation_id":"g1","workspace_roots":["/repo"],"prompt":"do the thing"}`)
	if _, ok, err := BuildEvent(EventBeforeSubmitPrompt, promptBody, nil); err != nil || !ok {
		t.Fatalf("prompt: err=%v ok=%v", err, ok)
	}
	after := shell("conv-b", "g2", "ls")
	if after.PrecedingReasoning != "" {
		t.Errorf("user-turn discard: successor carried %q", after.PrecedingReasoning)
	}
}

// TestAfterAgentThought_LifecycleEventsDoNotConsume pins the consumer
// TABLE: a lifecycle marker firing between the thought and the model's
// real next act must neither claim the reasoning nor destroy it.
func TestAfterAgentThought_LifecycleEventsDoNotConsume(t *testing.T) {
	body := []byte(`{"hook_event_name":"afterAgentThought","conversation_id":"conv-c",` +
		`"generation_id":"g1","workspace_roots":["/repo"],"text":"planning the edit"}`)
	if _, ok, _ := BuildEvent(EventAfterAgentThought, body, nil); ok {
		t.Fatal("thought minted a row")
	}
	compact := []byte(`{"hook_event_name":"preCompact","conversation_id":"conv-c",` +
		`"generation_id":"g1","workspace_roots":["/repo"],"trigger":"auto"}`)
	ev, ok, err := BuildEvent(EventPreCompact, compact, nil)
	if err != nil || !ok {
		t.Fatalf("preCompact: err=%v ok=%v", err, ok)
	}
	if ev.PrecedingReasoning != "" {
		t.Errorf("preCompact consumed the thought: %q", ev.PrecedingReasoning)
	}
	edit := []byte(`{"hook_event_name":"afterFileEdit","conversation_id":"conv-c",` +
		`"generation_id":"g2","workspace_roots":["/repo"],"file_path":"/repo/main.go"}`)
	got, ok, err := BuildEvent(EventAfterFileEdit, edit, nil)
	if err != nil || !ok {
		t.Fatalf("afterFileEdit: err=%v ok=%v", err, ok)
	}
	if got.PrecedingReasoning != "planning the edit" {
		t.Errorf("real successor preceding reasoning = %q", got.PrecedingReasoning)
	}
}

// TestBuildEvent_AfterAgentThought_EmptyTextDropped guards against
// metadata-only thought events (observed rarely in capture dumps) —
// they carry duration but no prose, so there's nothing to render and
// we drop them rather than inserting empty rows.
func TestBuildEvent_AfterAgentThought_EmptyTextDropped(t *testing.T) {
	body := []byte(`{
		"hook_event_name": "afterAgentThought",
		"conversation_id": "c1",
		"generation_id": "g1",
		"workspace_roots": ["/repo"],
		"text": "   ",
		"duration_ms": 0
	}`)
	_, ok, err := BuildEvent(EventAfterAgentThought, body, nil)
	if err != nil {
		t.Fatalf("BuildEvent: %v", err)
	}
	if ok {
		t.Errorf("empty-text thought should be dropped")
	}
}

// TestBuildEvent_AfterAgentResponse pins the v1.6.18 capture of
// finalized assistant prose. Token counts are deliberately NOT
// consumed here (the `stop` event remains the single source of
// per-turn token truth — see the rationale in adapter.go's
// package-level commentary).
func TestBuildEvent_AfterAgentResponse(t *testing.T) {
	body := []byte(`{
		"hook_event_name": "afterAgentResponse",
		"conversation_id": "32c83fe8-3763-4f29-b127-a0968203db01",
		"generation_id": "4d5d4102-34a7-48fd-aeb8-eee33729bf98",
		"workspace_roots": ["/c:/programsx/marmutmain"],
		"model": "default",
		"text": "Auto is the agent/router identity in Cursor — how this chat is presented to you — not the foundation model.",
		"input_tokens": 21268,
		"output_tokens": 593,
		"cache_read_tokens": 20992,
		"cache_write_tokens": 0
	}`)
	ev, ok, err := BuildEvent(EventAfterAgentResponse, body, nil)
	if err != nil || !ok {
		t.Fatalf("BuildEvent: %v ok=%v", err, ok)
	}
	if ev.ActionType != models.ActionAssistantMessage {
		t.Errorf("action: %s want assistant_message", ev.ActionType)
	}
	if ev.RawToolName != "cursor.assistant_response" {
		t.Errorf("raw tool name: %s", ev.RawToolName)
	}
	if !strings.Contains(ev.ToolOutput, "Auto is the agent/router identity") {
		t.Errorf("tool output: %q", ev.ToolOutput)
	}
	// Token fields belong to `stop`, never afterAgentResponse — guard
	// against double-counting regression.
	if ev.DurationMs != 0 {
		t.Errorf("response event should not carry duration_ms (that's the thought event): got %d", ev.DurationMs)
	}
}

func TestBuildEvent_StopIsNotRecorded(t *testing.T) {
	body := []byte(`{"hook_event_name":"stop","conversation_id":"c1","workspace_roots":["/repo"]}`)
	_, ok, err := BuildEvent(EventStop, body, nil)
	if err != nil {
		t.Fatalf("BuildEvent: %v", err)
	}
	if ok {
		t.Errorf("stop should not produce an event")
	}
}

func TestBuildStopTokenEvent(t *testing.T) {
	body := []byte(`{
		"hook_event_name": "stop",
		"conversation_id": "c1",
		"generation_id": "g1",
		"workspace_roots": ["/repo"],
		"model": "default",
		"input_tokens": 54833,
		"output_tokens": 773,
		"cache_read_tokens": 41088,
		"cache_write_tokens": 0
	}`)
	ev, ok, err := BuildStopTokenEvent(body)
	if err != nil || !ok {
		t.Fatalf("BuildStopTokenEvent: %v ok=%v", err, ok)
	}
	if ev.SessionID != "c1" || ev.MessageID != "g1" {
		t.Fatalf("session/message mismatch: %+v", ev)
	}
	if ev.Model != "default" {
		t.Fatalf("model = %q", ev.Model)
	}
	// InputTokens is NET non-cached: Cursor's stop hook reports
	// input_tokens=54833 as the GROSS prompt total (including the
	// cached portion); cache_read_tokens=41088 is the subset. Net =
	// 54833 - 41088 = 13745. See BuildStopTokenEvent + the
	// cost-engine TokenBundle.Input contract.
	if ev.InputTokens != 13745 || ev.OutputTokens != 773 || ev.CacheReadTokens != 41088 {
		t.Fatalf("usage mismatch: %+v (want InputTokens=13745 net of 41088 cached)", ev)
	}
	if ev.Source != models.TokenSourceHook || ev.Reliability != models.ReliabilityAccurate {
		t.Fatalf("source/reliability mismatch: %+v", ev)
	}
}

// TestBuildStopTokenEvent_WindowsCLIWorkspaceRoot pins the
// Windows-cursor-agent-CLI fix: the CLI sends workspace_roots as a
// raw Windows backslash path (verified against session 90dd2512,
// 2026-05-24). decodeWorkspaceRoot must canonicalize it to the
// /mnt/c/... form via crossmount so the token row lands under a
// stat-able project root consistent with the rest of observer,
// rather than a raw `C:\...` string. Token netting still applies.
func TestBuildStopTokenEvent_WindowsCLIWorkspaceRoot(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows backslash workspace root (C:\\...) → /mnt/c canonicalization is a Linux/WSL-daemon-observing-a-Windows-mount behavior (windowsToWSLMnt short-circuits on Windows); can't run on a Windows host")
	}
	body := []byte(`{
		"hook_event_name": "stop",
		"conversation_id": "90dd2512",
		"generation_id": "1f2d6703",
		"workspace_roots": ["C:\\programsx\\superbased-observer"],
		"model": "default",
		"input_tokens": 14243,
		"output_tokens": 41,
		"cache_read_tokens": 6747,
		"cache_write_tokens": 0
	}`)
	ev, ok, err := BuildStopTokenEvent(body)
	if err != nil || !ok {
		t.Fatalf("BuildStopTokenEvent: %v ok=%v", err, ok)
	}
	// Windows backslash workspace root must canonicalize to /mnt/c/...
	if ev.ProjectRoot != "/mnt/c/programsx/superbased-observer" {
		t.Errorf("ProjectRoot = %q, want /mnt/c/programsx/superbased-observer (canonicalized from C:\\...)", ev.ProjectRoot)
	}
	// Net non-cached: 14243 - 6747 = 7496.
	if ev.InputTokens != 7496 || ev.CacheReadTokens != 6747 {
		t.Errorf("usage: in=%d cr=%d, want 7496/6747 (net of cached)", ev.InputTokens, ev.CacheReadTokens)
	}
}

// TestNormalizeWorkspaceRoot_CanonicalizesWindowsShapes pins the
// post-F4 project-identity contract on the HOOK path. Cursor emits a
// Windows workspace root in three spellings depending on surface and
// era — the CLI's raw `C:\...`, the IDE's `Uri.fsPath` `/c:/...`, and
// (on a WSL-side install) an already-native POSIX path. F4 made the
// WATCHER path (scan.go resolveProjectRoot) emit canonical
// `/mnt/c/...`; if the hook path leaves `/c:/...` alone, one
// directory becomes two project rows. All Windows spellings must
// converge here.
func TestNormalizeWorkspaceRoot_CanonicalizesWindowsShapes(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("/mnt/<drive> canonicalization is a WSL-daemon-observing-a-Windows-mount behavior")
	}
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"cursor-agent CLI backslash", `C:\programsx\marmutmain`, "/mnt/c/programsx/marmutmain"},
		{"IDE Uri.fsPath lowercase drive", "/c:/programsx/marmutmain", "/mnt/c/programsx/marmutmain"},
		{"IDE Uri.fsPath uppercase drive", "/C:/programsx/marmutmain", "/mnt/c/programsx/marmutmain"},
		{"already canonical", "/mnt/c/programsx/marmutmain", "/mnt/c/programsx/marmutmain"},
		{"file URI", "file:///c:/programsx/marmutmain", "/mnt/c/programsx/marmutmain"},
		// Native WSL-side cursor-agent: untouched.
		{"native linux root", "/home/marmutapp/superbased-observer", "/home/marmutapp/superbased-observer"},
		// A Linux directory that merely starts like a drive letter
		// must never be rewritten.
		{"linux /cache root", "/cache/projects/foo", "/cache/projects/foo"},
		{"empty", "", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := normalizeWorkspaceRoot(c.in); got != c.want {
				t.Errorf("normalizeWorkspaceRoot(%q) = %q, want %q", c.in, got, c.want)
			}
		})
	}
}

// TestNormalizeWorkspaceRoot_HookMatchesWatcher is the cross-path
// convergence assertion stated end-to-end: the hook path's root for a
// Windows workspace must equal the watcher path's root for the same
// workspace. Before the pathnorm `/c:` strip, the left side was
// `/c:/programsx/model_pricing` and the right side (post-F4)
// `/mnt/c/programsx/model_pricing` — the live split reported in
// docs/audits/cursor-windows-capture-diagnosis-2026-08-07.md §2.5.
func TestNormalizeWorkspaceRoot_HookMatchesWatcher(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("/mnt/<drive> canonicalization is a WSL-daemon-observing-a-Windows-mount behavior")
	}
	const workspace = `C:\programsx\model_pricing`
	hookRoot := normalizeWorkspaceRoot("/c:/programsx/model_pricing")
	// The watcher path resolves through the same translate seam once
	// .workspace-trusted supplies the authoritative Windows path.
	watcherRoot := projectRootResolver{}.doTranslate(workspace)
	if hookRoot != watcherRoot {
		t.Fatalf("hook root %q != watcher root %q — project identity is split", hookRoot, watcherRoot)
	}
	if hookRoot != "/mnt/c/programsx/model_pricing" {
		t.Errorf("converged root = %q, want /mnt/c/programsx/model_pricing", hookRoot)
	}
}

func TestBuildStopTranscriptEvents(t *testing.T) {
	dir := t.TempDir()
	transcript := filepath.Join(dir, "session.jsonl")
	body := strings.Join([]string{
		`{"role":"user","message":{"content":[{"type":"text","text":"<user_query>Summarize</user_query>"}]}}`,
		`{"role":"assistant","message":{"content":[{"type":"text","text":"I'll inspect the repo."},{"type":"tool_use","name":"Glob","input":{"target_directory":"d:\\repo","glob_pattern":"*"}},{"type":"tool_use","name":"ReadFile","input":{"path":"d:\\repo\\package.json"}}]}}`,
		`{"role":"assistant","message":{"content":[{"type":"text","text":"Done."}]}}`,
		"",
	}, "\n")
	if err := os.WriteFile(transcript, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}

	stopBody := []byte(`{
		"conversation_id":"c1",
		"generation_id":"g1",
		"workspace_roots":["/repo"],
		"transcript_path":"` + strings.ReplaceAll(transcript, `\`, `\\`) + `"
	}`)
	events, err := BuildStopTranscriptEvents(stopBody, scrub.New(), time.Unix(0, 0).UTC())
	if err != nil {
		t.Fatalf("BuildStopTranscriptEvents: %v", err)
	}
	// Expected after v1.4.49 cursor.assistant_text emission:
	//   [0] cursor.assistant_text — "I'll inspect the repo." (assistant line 1, text part)
	//   [1] Glob                  — search_files
	//   [2] ReadFile              — read_file
	//   [3] cursor.assistant_text — "Done."  (assistant line 2, text part)
	if len(events) != 4 {
		t.Fatalf("event count = %d want 4 (events: %+v)", len(events), events)
	}
	if events[0].RawToolName != "cursor.assistant_text" || events[0].ActionType != models.ActionAssistantMessage {
		t.Fatalf("first event = %+v (want cursor.assistant_text/assistant_message)", events[0])
	}
	if events[0].ToolOutput != "I'll inspect the repo." {
		t.Errorf("first event tool_output = %q, want %q", events[0].ToolOutput, "I'll inspect the repo.")
	}
	if events[1].MessageID != "g1" || events[1].ActionType != models.ActionSearchFiles {
		t.Fatalf("second event = %+v", events[1])
	}
	if events[2].ActionType != models.ActionReadFile || events[2].Target != "d:\\repo\\package.json" {
		t.Fatalf("third event = %+v", events[2])
	}
	if events[3].RawToolName != "cursor.assistant_text" || events[3].ToolOutput != "Done." {
		t.Fatalf("fourth event = %+v (want cursor.assistant_text \"Done.\")", events[3])
	}
}

// TestStripUserQueryWrapper pins the wrapper-strip behavior introduced
// in v1.4.21. Cursor's agent runtime wraps user prompts in
// <user_query>...</user_query> XML before passing them to the model;
// previously this landed verbatim in the DB. Strip when both sides
// are present, leave alone when only one side is — partial-wrapper
// stripping risks damaging real content that mentions the tag.
func TestStripUserQueryWrapper(t *testing.T) {
	cases := map[string]struct {
		in, want string
	}{
		"complete wrapper":             {"<user_query>\nbuild a todo app\n</user_query>", "build a todo app"},
		"complete wrapper no newlines": {"<user_query>x</user_query>", "x"},
		"surrounding whitespace":       {"  <user_query>x</user_query>  ", "x"},
		"unwrapped":                    {"plain text", "plain text"},
		"only opening tag":             {"<user_query>oops", "<user_query>oops"},
		"only closing tag":             {"oops</user_query>", "oops</user_query>"},
		"empty":                        {"", ""},
		"empty wrapped":                {"<user_query></user_query>", ""},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			got := stripUserQueryWrapper(c.in)
			if got != c.want {
				t.Errorf("stripUserQueryWrapper(%q) = %q want %q", c.in, got, c.want)
			}
		})
	}
}

// TestBuildTranscriptUserPromptEvent pins the new transcript-walker
// emission of user_prompt actions. Per-line MessageID format must
// match the live hook path ("user:" + generationID) so dashboards can
// join across the two source paths cleanly.
func TestBuildTranscriptUserPromptEvent(t *testing.T) {
	turn := transcriptTurn{
		User: transcriptUserLine{LineNumber: 7, Text: "<user_query>\nWrite tests\n</user_query>"},
	}
	ev, ok := BuildTranscriptUserPromptEvent(turn, "sess-1", "/repo", "gen-X", "/tmp/x.jsonl", time.Unix(0, 0).UTC(), nil)
	if !ok {
		t.Fatal("expected user_prompt event for non-empty wrapped text")
	}
	if ev.ActionType != models.ActionUserPrompt {
		t.Errorf("action_type: %s", ev.ActionType)
	}
	if ev.Target != "Write tests" {
		t.Errorf("target wrapper not stripped: %q", ev.Target)
	}
	if ev.MessageID != "user:gen-X" {
		t.Errorf("message_id: %q want user:gen-X", ev.MessageID)
	}
	if ev.SessionID != "sess-1" {
		t.Errorf("session_id: %q", ev.SessionID)
	}
	if !strings.HasPrefix(ev.SourceEventID, "gen-X:transcript:L7:user:") {
		t.Errorf("source_event_id prefix: %q", ev.SourceEventID)
	}
	if ev.RawToolName != "user_message" {
		t.Errorf("raw_tool_name: %q", ev.RawToolName)
	}
	// Empty user line returns false.
	emptyTurn := transcriptTurn{User: transcriptUserLine{LineNumber: 1, Text: "<user_query></user_query>"}}
	if _, ok := BuildTranscriptUserPromptEvent(emptyTurn, "s", "/r", "g", "/p", time.Time{}, nil); ok {
		t.Error("expected false for empty wrapper")
	}
}

// TestBuildEvent_StripsUserQueryWrapper pins the live-hook path's
// strip behavior for EventBeforeSubmitPrompt — when Cursor's hook
// payload includes a wrapped prompt, the resulting Target is the
// raw user text only.
func TestBuildEvent_StripsUserQueryWrapper(t *testing.T) {
	body := []byte(`{
		"hook_event_name":"beforeSubmitPrompt",
		"conversation_id":"c1",
		"generation_id":"g1",
		"workspace_roots":["/repo"],
		"prompt":"<user_query>\nWrite tests\n</user_query>"
	}`)
	ev, ok, err := BuildEvent(EventBeforeSubmitPrompt, body, nil)
	if err != nil || !ok {
		t.Fatalf("BuildEvent: ok=%v err=%v", ok, err)
	}
	if ev.Target != "Write tests" {
		t.Errorf("target wrapper not stripped in hook path: %q", ev.Target)
	}
}

// TestCursorTranscriptActionType pins the v1.4.21 normalizer extension
// for tool names observed in real cursor agent transcripts that the
// pre-v1.4.21 classifier silently routed to ActionUnknown. Subagent is
// re-tested in capitalized form to confirm the case-insensitive match.
func TestCursorTranscriptActionType(t *testing.T) {
	cases := map[string]string{
		"ReadLints":     models.ActionReadFile,
		"StrReplace":    models.ActionEditFile,
		"Subagent":      models.ActionSpawnSubagent, // capitalized form lower-cases
		"call_mcp_tool": models.ActionMCPCall,
		"Await":         models.ActionUnknown, // intentional — control-flow primitive
	}
	for name, want := range cases {
		t.Run(name, func(t *testing.T) {
			got := cursorTranscriptActionType(name)
			if got != want {
				t.Errorf("cursorTranscriptActionType(%q) = %s want %s", name, got, want)
			}
		})
	}
}

// TestCursorTranscriptTarget pins target extraction for the same set,
// verifying that MCP calls produce server:tool and edit-shaped tools
// pull the file_path/path/target_file field.
func TestCursorTranscriptTarget(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"ReadLints", `{"path":"x.go"}`, "x.go"},
		{"StrReplace", `{"file_path":"y.go"}`, "y.go"},
		{"call_mcp_tool", `{"server_name":"obs","tool_name":"get_session_summary"}`, "obs:get_session_summary"},
		{"call_mcp_tool", `{"tool":"only_tool"}`, "only_tool"},
	}
	for _, c := range cases {
		got := cursorTranscriptTarget(c.name, []byte(c.in))
		if got != c.want {
			t.Errorf("cursorTranscriptTarget(%s, %s) = %q want %q", c.name, c.in, got, c.want)
		}
	}
}

func TestBuildEvent_RejectsMissingFields(t *testing.T) {
	// Missing conversation_id.
	_, _, err := BuildEvent(EventBeforeShellCommand, []byte(`{"command":"ls"}`), nil)
	if err == nil {
		t.Error("expected error when conversation_id missing")
	}
	// Malformed JSON.
	_, _, err = BuildEvent(EventBeforeShellCommand, []byte(`{not json`), nil)
	if err == nil {
		t.Error("expected parse error")
	}
	// Missing event name.
	_, _, err = BuildEvent("", []byte(`{"conversation_id":"c1"}`), nil)
	if err == nil {
		t.Error("expected error when event name missing")
	}
}

func TestBuildEvent_LongPromptTruncated(t *testing.T) {
	long := strings.Repeat("x", 500)
	body := []byte(`{
		"hook_event_name":"beforeSubmitPrompt",
		"conversation_id":"c1",
		"generation_id":"g1",
		"workspace_roots":["/repo"],
		"prompt":"` + long + `"
	}`)
	ev, ok, _ := BuildEvent(EventBeforeSubmitPrompt, body, nil)
	if !ok || len(ev.Target) != 200 {
		t.Errorf("expected target truncated to 200 chars, got %d", len(ev.Target))
	}
}

func TestBuildEvent_DeterministicEventID(t *testing.T) {
	body := []byte(`{
		"hook_event_name": "beforeShellExecution",
		"conversation_id": "c1",
		"generation_id": "gen-A",
		"workspace_roots": ["/repo"],
		"command": "go build"
	}`)
	a, _, _ := BuildEvent(EventBeforeShellCommand, body, nil)
	b, _, _ := BuildEvent(EventBeforeShellCommand, body, nil)
	if a.SourceEventID != b.SourceEventID {
		t.Errorf("event IDs differ across calls: %s vs %s", a.SourceEventID, b.SourceEventID)
	}
}

// TestBuildEvent_BeforeReadFile pins the audit-C2 closure: Cursor's
// pre-v1.4.45 hook surface had no file-read event, so live freshness/
// redundancy detection systematically undercounted Cursor activity vs
// claudecode. The new beforeReadFile hook produces an ActionReadFile row
// keyed off the same generation_id as sibling tool calls.
func TestBuildEvent_BeforeReadFile(t *testing.T) {
	body := []byte(`{
		"hook_event_name":"beforeReadFile",
		"conversation_id":"c1",
		"generation_id":"g1",
		"workspace_roots":["/repo"],
		"model":"claude-sonnet-4-5",
		"file_path":"internal/handler.go"
	}`)
	ev, ok, err := BuildEvent(EventBeforeReadFile, body, scrub.New())
	if err != nil || !ok {
		t.Fatalf("BuildEvent: %v ok=%v", err, ok)
	}
	if ev.ActionType != models.ActionReadFile {
		t.Errorf("action: %s want read_file", ev.ActionType)
	}
	if ev.Target != "internal/handler.go" {
		t.Errorf("target: %s", ev.Target)
	}
	if ev.RawToolInput != "internal/handler.go" {
		t.Errorf("raw input: %s", ev.RawToolInput)
	}
	if ev.SessionID != "c1" || ev.MessageID != "g1" {
		t.Errorf("session/message: %s/%s", ev.SessionID, ev.MessageID)
	}
	if ev.SourceEventID == "" || !strings.HasPrefix(ev.SourceEventID, "g1:beforeReadFile:") {
		t.Errorf("event id: %s", ev.SourceEventID)
	}
}

func TestBuildEvent_PostToolUseFailure(t *testing.T) {
	body := []byte(`{
		"hook_event_name":"postToolUseFailure",
		"conversation_id":"c1",
		"generation_id":"g1",
		"workspace_roots":["/repo"],
		"model":"claude-sonnet-4-5",
		"tool_name":"shell",
		"tool_use_id":"toolu_xyz",
		"failure_type":"non_zero_exit",
		"error":"command failed: exit 2",
		"duration_ms":1234,
		"input":{"command":"npm test"}
	}`)
	ev, ok, err := BuildEvent(EventPostToolUseFailure, body, scrub.New())
	if err != nil || !ok {
		t.Fatalf("BuildEvent: %v ok=%v", err, ok)
	}
	if ev.ActionType != models.ActionToolFailure {
		t.Errorf("action: %s want tool_failure", ev.ActionType)
	}
	if ev.Success {
		t.Errorf("expected Success=false on tool failure")
	}
	if ev.Target != "shell" {
		t.Errorf("target: %s want shell", ev.Target)
	}
	if ev.RawToolName != "non_zero_exit" {
		t.Errorf("raw_tool_name (failure_type): %s", ev.RawToolName)
	}
	if ev.ErrorMessage != "command failed: exit 2" {
		t.Errorf("error: %s", ev.ErrorMessage)
	}
	if ev.DurationMs != 1234 {
		t.Errorf("duration_ms: %d", ev.DurationMs)
	}
	if !strings.Contains(ev.RawToolInput, "npm test") {
		t.Errorf("raw input lost: %s", ev.RawToolInput)
	}
	// Event ID uses tool_use_id when present.
	if !strings.HasPrefix(ev.SourceEventID, "g1:postToolUseFailure:") {
		t.Errorf("event id prefix: %s", ev.SourceEventID)
	}
}

// TestBuildEvent_SessionStart pins lifecycle-marker emission. Session
// events fire before any generation, so generation_id may be empty;
// the event ID falls back to conversation_id so duplicate inserts of
// the same start event are idempotent.
func TestBuildEvent_SessionStart(t *testing.T) {
	body := []byte(`{
		"hook_event_name":"sessionStart",
		"conversation_id":"c1",
		"workspace_roots":["/repo"],
		"source":"startup"
	}`)
	ev, ok, err := BuildEvent(EventSessionStart, body, nil)
	if err != nil || !ok {
		t.Fatalf("BuildEvent: %v ok=%v", err, ok)
	}
	if ev.ActionType != models.ActionSessionStart {
		t.Errorf("action: %s", ev.ActionType)
	}
	if ev.Target != "startup" {
		t.Errorf("target: %s", ev.Target)
	}
	if ev.SessionID != "c1" {
		t.Errorf("session: %s", ev.SessionID)
	}
	// generation_id missing → event ID derived from conversation_id.
	if !strings.HasPrefix(ev.SourceEventID, "c1:sessionStart") {
		t.Errorf("event id should fall back to conversation_id: %s", ev.SourceEventID)
	}
}

func TestBuildEvent_SessionEnd(t *testing.T) {
	body := []byte(`{
		"hook_event_name":"sessionEnd",
		"conversation_id":"c1",
		"workspace_roots":["/repo"],
		"reason":"clear"
	}`)
	ev, ok, err := BuildEvent(EventSessionEnd, body, nil)
	if err != nil || !ok {
		t.Fatalf("BuildEvent: %v ok=%v", err, ok)
	}
	if ev.ActionType != models.ActionSessionEnd {
		t.Errorf("action: %s", ev.ActionType)
	}
	if ev.Target != "clear" {
		t.Errorf("target: %s", ev.Target)
	}
}

func TestBuildEvent_SubagentStartStop(t *testing.T) {
	startBody := []byte(`{
		"hook_event_name":"subagentStart",
		"conversation_id":"c1",
		"generation_id":"g1",
		"workspace_roots":["/repo"],
		"agent_id":"sub-abc",
		"agent_type":"reviewer"
	}`)
	startEv, ok, err := BuildEvent(EventSubagentStart, startBody, nil)
	if err != nil || !ok {
		t.Fatalf("subagentStart: %v ok=%v", err, ok)
	}
	if startEv.ActionType != models.ActionSubagentStart {
		t.Errorf("start action: %s", startEv.ActionType)
	}
	if startEv.Target != "reviewer" {
		t.Errorf("start target: %s", startEv.Target)
	}
	if !startEv.IsSidechain {
		t.Errorf("subagent rows must carry IsSidechain=true")
	}
	if startEv.MessageID != "sub-abc" {
		t.Errorf("start message_id (agent_id): %s", startEv.MessageID)
	}

	// Stop with the alternate field name (subagent_id) — falls back when
	// agent_id is absent.
	stopBody := []byte(`{
		"hook_event_name":"subagentStop",
		"conversation_id":"c1",
		"generation_id":"g1",
		"workspace_roots":["/repo"],
		"subagent_id":"sub-abc",
		"agent_type":"reviewer"
	}`)
	stopEv, ok, err := BuildEvent(EventSubagentStop, stopBody, nil)
	if err != nil || !ok {
		t.Fatalf("subagentStop: %v ok=%v", err, ok)
	}
	if stopEv.ActionType != models.ActionSubagentStop {
		t.Errorf("stop action: %s", stopEv.ActionType)
	}
	if stopEv.MessageID != "sub-abc" {
		t.Errorf("stop message_id (subagent_id fallback): %s", stopEv.MessageID)
	}
	// Start and stop event IDs must differ on the same agent_id.
	if startEv.SourceEventID == stopEv.SourceEventID {
		t.Errorf("subagent start/stop produced identical event IDs: %s", startEv.SourceEventID)
	}
}

// TestBuildEvent_PreToolUse_CoveredToolsSuppressed pins the Tier 3 dedup:
// when preToolUse fires for a tool already covered by a per-tool before*
// hook (shell, MCP, file edits, file reads, subagent), we drop the row
// to avoid double-counting in the actions table. The per-tool hook is
// canonical for these tools because it carries richer typed payload
// fields.
func TestBuildEvent_PreToolUse_CoveredToolsSuppressed(t *testing.T) {
	covered := []struct {
		toolName string
	}{
		{"Shell"},
		{"Bash"},
		{"call_mcp_tool"},
		{"ApplyPatch"},
		{"EditFile"},
		{"StrReplace"},
		{"Read"},
		{"ReadFile"},
		{"ReadLints"},
		{"Subagent"},
		{"Agent"},
	}
	for _, c := range covered {
		t.Run(c.toolName, func(t *testing.T) {
			body := []byte(`{
				"hook_event_name":"preToolUse",
				"conversation_id":"c1",
				"generation_id":"g1",
				"workspace_roots":["/repo"],
				"tool_name":"` + c.toolName + `",
				"tool_use_id":"toolu_x",
				"tool_input":{}
			}`)
			_, ok, err := BuildEvent(EventPreToolUse, body, nil)
			if err != nil {
				t.Fatalf("BuildEvent error: %v", err)
			}
			if ok {
				t.Errorf("expected (zero, false) for covered tool %q to avoid duplication", c.toolName)
			}
		})
	}
}

// TestBuildEvent_PreToolUse_LongTailToolsRecorded pins the other half of
// the dedup: preToolUse should emit rows for tools the per-tool hooks
// don't cover (Glob, Grep, semanticsearch, WriteFile, etc.). Action type
// flows through cursorTranscriptActionType so the mapping stays in one
// place; target extraction flows through cursorTranscriptTarget for the
// same reason.
func TestBuildEvent_PreToolUse_LongTailToolsRecorded(t *testing.T) {
	cases := []struct {
		name        string
		toolName    string
		toolInput   string
		wantAction  string
		wantTarget  string
		wantRawTool string
	}{
		{
			name:        "Glob",
			toolName:    "Glob",
			toolInput:   `{"glob_pattern":"**/*.go"}`,
			wantAction:  models.ActionSearchFiles,
			wantTarget:  "**/*.go",
			wantRawTool: "Glob",
		},
		{
			name:        "Grep",
			toolName:    "Grep",
			toolInput:   `{"pattern":"TODO"}`,
			wantAction:  models.ActionSearchText,
			wantTarget:  "TODO",
			wantRawTool: "Grep",
		},
		{
			name:        "semanticsearch",
			toolName:    "semanticsearch",
			toolInput:   `{"query":"how does login work"}`,
			wantAction:  models.ActionSearchText,
			wantTarget:  "how does login work",
			wantRawTool: "semanticsearch",
		},
		{
			name:        "WriteFile",
			toolName:    "WriteFile",
			toolInput:   `{"path":"new.go","content":"package main"}`,
			wantAction:  models.ActionWriteFile,
			wantTarget:  "new.go",
			wantRawTool: "WriteFile",
		},
		{
			name:        "unknown future tool",
			toolName:    "FutureTool",
			toolInput:   `{"foo":"bar"}`,
			wantAction:  models.ActionUnknown,
			wantTarget:  "",
			wantRawTool: "FutureTool",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			body := []byte(`{
				"hook_event_name":"preToolUse",
				"conversation_id":"c1",
				"generation_id":"g1",
				"workspace_roots":["/repo"],
				"tool_name":"` + c.toolName + `",
				"tool_use_id":"toolu_a",
				"tool_input":` + c.toolInput + `
			}`)
			ev, ok, err := BuildEvent(EventPreToolUse, body, scrub.New())
			if err != nil || !ok {
				t.Fatalf("BuildEvent: %v ok=%v", err, ok)
			}
			if ev.ActionType != c.wantAction {
				t.Errorf("action: %s want %s", ev.ActionType, c.wantAction)
			}
			if ev.Target != c.wantTarget {
				t.Errorf("target: %q want %q", ev.Target, c.wantTarget)
			}
			if ev.RawToolName != c.wantRawTool {
				t.Errorf("raw_tool_name: %q want %q", ev.RawToolName, c.wantRawTool)
			}
			if ev.RawToolInput == "" {
				t.Errorf("raw_tool_input should carry tool_input JSON, got empty")
			}
			if !strings.HasPrefix(ev.SourceEventID, "g1:preToolUse:") {
				t.Errorf("event id prefix: %s", ev.SourceEventID)
			}
		})
	}
}

// TestBuildEvent_PreToolUse_DistinctIDsForDistinctTools pins that two
// preToolUse events within the same turn (same generation_id) but for
// different tools produce distinct SourceEventIDs — otherwise the
// second insert would collide with the first on the unique index.
func TestBuildEvent_PreToolUse_DistinctIDsForDistinctTools(t *testing.T) {
	bodyA := []byte(`{
		"hook_event_name":"preToolUse","conversation_id":"c1","generation_id":"g1",
		"workspace_roots":["/repo"],"tool_name":"Glob","tool_use_id":"toolu_a",
		"tool_input":{"glob_pattern":"*.go"}
	}`)
	bodyB := []byte(`{
		"hook_event_name":"preToolUse","conversation_id":"c1","generation_id":"g1",
		"workspace_roots":["/repo"],"tool_name":"Grep","tool_use_id":"toolu_b",
		"tool_input":{"pattern":"TODO"}
	}`)
	a, _, _ := BuildEvent(EventPreToolUse, bodyA, nil)
	b, _, _ := BuildEvent(EventPreToolUse, bodyB, nil)
	if a.SourceEventID == b.SourceEventID {
		t.Errorf("expected distinct IDs for distinct tools within one turn, got %s == %s",
			a.SourceEventID, b.SourceEventID)
	}
}

// TestBuildEvent_PostToolUseAndAfterEventsNoRow pins that the three
// paired-after events register correctly but emit no rows in this batch
// (update-in-place to enrich the before* row's outcome metadata is a
// separate follow-up). All three should return (zero, false, nil).
func TestBuildEvent_PostToolUseAndAfterEventsNoRow(t *testing.T) {
	cases := []string{EventPostToolUse, EventAfterShellExecution, EventAfterMCPExecution}
	for _, evt := range cases {
		t.Run(evt, func(t *testing.T) {
			body := []byte(`{
				"hook_event_name":"` + evt + `",
				"conversation_id":"c1",
				"generation_id":"g1",
				"workspace_roots":["/repo"],
				"tool_name":"Shell",
				"tool_use_id":"toolu_x"
			}`)
			_, ok, err := BuildEvent(evt, body, nil)
			if err != nil {
				t.Fatalf("BuildEvent: %v", err)
			}
			if ok {
				t.Errorf("expected (zero, false) for %s — paired-after enrichment is deferred", evt)
			}
		})
	}
}

func TestBuildEvent_PreCompact(t *testing.T) {
	body := []byte(`{
		"hook_event_name":"preCompact",
		"conversation_id":"c1",
		"generation_id":"g1",
		"workspace_roots":["/repo"],
		"trigger":"auto",
		"duration_ms":42
	}`)
	ev, ok, err := BuildEvent(EventPreCompact, body, nil)
	if err != nil || !ok {
		t.Fatalf("BuildEvent: %v ok=%v", err, ok)
	}
	if ev.ActionType != models.ActionContextCompacted {
		t.Errorf("action: %s want context_compacted", ev.ActionType)
	}
	if ev.Target != "auto" {
		t.Errorf("target: %s", ev.Target)
	}
	if ev.DurationMs != 42 {
		t.Errorf("duration_ms: %d", ev.DurationMs)
	}
}

// TestBuildAfterOutcome_PairsWithBeforeShellExecution pins that the
// after-event computes the same source_event_id as the
// beforeShellExecution row would, so store.UpdateActionOutcome
// lands on the matching row. Both events carry `command` and the
// id derives from shortHash(command).
func TestBuildAfterOutcome_PairsWithBeforeShellExecution(t *testing.T) {
	beforeBody := []byte(`{
		"hook_event_name":"beforeShellExecution",
		"conversation_id":"c1","generation_id":"g1",
		"workspace_roots":["/repo"],"command":"go test"
	}`)
	afterBody := []byte(`{
		"hook_event_name":"afterShellExecution",
		"conversation_id":"c1","generation_id":"g1",
		"workspace_roots":["/repo"],"command":"go test",
		"exit_code":1,"error":"FAIL TestFoo","duration_ms":750
	}`)
	before, _, err := BuildEvent(EventBeforeShellCommand, beforeBody, nil)
	if err != nil {
		t.Fatalf("BuildEvent: %v", err)
	}
	out, ok, err := BuildAfterOutcome(EventAfterShellExecution, afterBody)
	if err != nil || !ok {
		t.Fatalf("BuildAfterOutcome: %v ok=%v", err, ok)
	}
	if out.SourceEventID != before.SourceEventID {
		t.Errorf("after id %q != before id %q", out.SourceEventID, before.SourceEventID)
	}
	if out.SourceFile != before.SourceFile {
		t.Errorf("source_file: after=%q before=%q", out.SourceFile, before.SourceFile)
	}
	if out.Success {
		t.Errorf("success=true; exit_code=1 should fail-derive")
	}
	if out.ErrorMessage != "FAIL TestFoo" {
		t.Errorf("error: %q", out.ErrorMessage)
	}
	if out.DurationMs != 750 {
		t.Errorf("duration_ms: %d want 750", out.DurationMs)
	}
}

// TestBuildAfterOutcome_PairsWithBeforeMCPExecution verifies the
// MCP pairing — both events carry server_name + tool_name, the id
// derives from shortHash("server:tool").
func TestBuildAfterOutcome_PairsWithBeforeMCPExecution(t *testing.T) {
	beforeBody := []byte(`{
		"hook_event_name":"beforeMCPExecution",
		"conversation_id":"c1","generation_id":"g1",
		"workspace_roots":["/repo"],"server_name":"observer","tool_name":"get_session_summary",
		"input":{"session_id":"x"}
	}`)
	afterBody := []byte(`{
		"hook_event_name":"afterMCPExecution",
		"conversation_id":"c1","generation_id":"g1",
		"workspace_roots":["/repo"],"server_name":"observer","tool_name":"get_session_summary",
		"success":true,"duration_ms":120
	}`)
	before, _, err := BuildEvent(EventBeforeMCPExecution, beforeBody, nil)
	if err != nil {
		t.Fatalf("BuildEvent: %v", err)
	}
	out, ok, err := BuildAfterOutcome(EventAfterMCPExecution, afterBody)
	if err != nil || !ok {
		t.Fatalf("BuildAfterOutcome: %v ok=%v", err, ok)
	}
	if out.SourceEventID != before.SourceEventID {
		t.Errorf("after id %q != before id %q", out.SourceEventID, before.SourceEventID)
	}
	if !out.Success {
		t.Errorf("success=false; explicit success:true ignored")
	}
	if out.DurationMs != 120 {
		t.Errorf("duration_ms: %d want 120", out.DurationMs)
	}
}

// TestBuildAfterOutcome_PostToolUseRoutesByToolName checks that
// postToolUse correctly routes the pairing key to the matching
// before-event slug based on tool_name (Shell → beforeShellExecution,
// MCP → beforeMCPExecution, long-tail → preToolUse, fileEdit/subagent
// → no pair). Long-tail tool: Glob-style search.
func TestBuildAfterOutcome_PostToolUseRoutesByToolName(t *testing.T) {
	cases := []struct {
		name     string
		toolName string
		wantPair bool
		wantSlug string
	}{
		{"Shell pairs to beforeShellExecution", "Shell", true, EventBeforeShellCommand},
		{"call_mcp_tool pairs to beforeMCPExecution", "call_mcp_tool", true, EventBeforeMCPExecution},
		{"Read pairs to beforeReadFile", "Read", true, EventBeforeReadFile},
		{"Grep pairs to preToolUse (long-tail)", "Grep", true, EventPreToolUse},
		{"EditFile skips (afterFileEdit handles)", "EditFile", false, ""},
		{"Subagent skips (lifecycle, not call)", "Subagent", false, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			body := []byte(`{
				"hook_event_name":"postToolUse",
				"conversation_id":"c1","generation_id":"g1",
				"workspace_roots":["/repo"],
				"tool_name":"` + c.toolName + `",
				"tool_use_id":"tu_42",
				"success":true
			}`)
			out, ok, err := BuildAfterOutcome(EventPostToolUse, body)
			if err != nil {
				t.Fatalf("BuildAfterOutcome: %v", err)
			}
			if ok != c.wantPair {
				t.Errorf("ok=%v want %v", ok, c.wantPair)
			}
			if !c.wantPair {
				return
			}
			// Confirm the slug embedded in the SourceEventID matches.
			if !strings.Contains(out.SourceEventID, c.wantSlug) {
				t.Errorf("SourceEventID=%q want substring %q", out.SourceEventID, c.wantSlug)
			}
		})
	}
}

// TestBuildAfterOutcome_NotAfterEventReturnsFalse pins that
// non-after events route through BuildEvent, not the outcome path.
func TestBuildAfterOutcome_NotAfterEventReturnsFalse(t *testing.T) {
	body := []byte(`{"hook_event_name":"beforeShellExecution","conversation_id":"c","generation_id":"g","command":"x"}`)
	if _, ok, err := BuildAfterOutcome(EventBeforeShellCommand, body); ok || err != nil {
		t.Errorf("ok=%v err=%v want (false, nil) for before event", ok, err)
	}
}

// TestBuildAfterOutcome_PostToolUseDurationSecondsTranslated pins the
// v1.6.23 audit F2 fix: cursor's postToolUse payload sends `duration`
// (float, in seconds) instead of `duration_ms`. BuildAfterOutcome must
// translate seconds → ms so Store.UpdateActionOutcome lands a non-zero
// duration_ms on the matching before-event row. Empirically verified
// from /tmp/cursor-hook-capture/postToolUse-*.json on Cursor 3.4.20.
func TestBuildAfterOutcome_PostToolUseDurationSecondsTranslated(t *testing.T) {
	body := []byte(`{
		"hook_event_name":"postToolUse",
		"conversation_id":"c1","generation_id":"g1",
		"tool_name":"Read","tool_input":{"path":"go.mod"},
		"tool_use_id":"tool_abc",
		"duration":6.332
	}`)
	out, ok, err := BuildAfterOutcome(EventPostToolUse, body)
	if err != nil || !ok {
		t.Fatalf("BuildAfterOutcome: %v ok=%v", err, ok)
	}
	if out.DurationMs != 6332 {
		t.Errorf("duration_ms = %d, want 6332 (6.332s × 1000)", out.DurationMs)
	}
}

// TestBuildAfterOutcome_DurationMsFallback pins the legacy field name
// path: events that genuinely emit `duration_ms` (afterShellExecution
// / afterMCPExecution conventionally) still get the value preserved.
// Only postToolUse triggered the seconds-float field-name surprise.
func TestBuildAfterOutcome_DurationMsFallback(t *testing.T) {
	body := []byte(`{
		"hook_event_name":"afterMCPExecution",
		"conversation_id":"c1","generation_id":"g1",
		"server_name":"observer","tool_name":"get_session_summary",
		"success":true,"duration_ms":120
	}`)
	out, ok, err := BuildAfterOutcome(EventAfterMCPExecution, body)
	if err != nil || !ok {
		t.Fatalf("BuildAfterOutcome: %v ok=%v", err, ok)
	}
	if out.DurationMs != 120 {
		t.Errorf("duration_ms = %d, want 120 (preserved from duration_ms field)", out.DurationMs)
	}
}

// TestBuildAfterOutcome_PostToolUseCapturesOutput pins the v1.6.23
// audit F3 fix: postToolUse.tool_output (the tool's response body)
// now flows through OutcomeUpdate.Output → action_excerpts FTS5 via
// Store.UpdateActionOutcome when the Store has an Indexer attached.
func TestBuildAfterOutcome_PostToolUseCapturesOutput(t *testing.T) {
	body := []byte(`{
		"hook_event_name":"postToolUse",
		"conversation_id":"c1","generation_id":"g1",
		"tool_name":"Read","tool_input":{"path":"go.mod"},
		"tool_use_id":"tool_abc",
		"tool_output":"module github.com/foo\n\ngo 1.22\n",
		"duration":0.5
	}`)
	out, ok, err := BuildAfterOutcome(EventPostToolUse, body)
	if err != nil || !ok {
		t.Fatalf("BuildAfterOutcome: %v ok=%v", err, ok)
	}
	if out.Output != "module github.com/foo\n\ngo 1.22\n" {
		t.Errorf("Output = %q, want full tool_output body", out.Output)
	}
	if out.ToolName != "Read" {
		t.Errorf("ToolName = %q, want \"Read\"", out.ToolName)
	}
	if out.Target != "go.mod" {
		t.Errorf("Target = %q, want \"go.mod\"", out.Target)
	}
}

// TestBuildEvent_BeforeReadFile_CapturesContent pins the v1.6.23
// audit F4 fix: cursor's beforeReadFile payload carries `content`
// (the file body cursor just read). BuildEvent stamps it on
// ev.ToolOutput so the dashboard's tool-output panel surfaces it
// the same way claudecode's Read tool body does. Scrubbed + capped
// at 4000 chars matching the cross-adapter convention.
func TestBuildEvent_BeforeReadFile_CapturesContent(t *testing.T) {
	body := []byte(`{
		"hook_event_name":"beforeReadFile",
		"conversation_id":"c1","generation_id":"g1",
		"workspace_roots":["/repo"],
		"file_path":"go.mod",
		"content":"module github.com/foo\n\ngo 1.22\n"
	}`)
	ev, ok, err := BuildEvent(EventBeforeReadFile, body, nil)
	if err != nil || !ok {
		t.Fatalf("BuildEvent: %v ok=%v", err, ok)
	}
	if ev.ToolOutput != "module github.com/foo\n\ngo 1.22\n" {
		t.Errorf("ToolOutput = %q, want full content body", ev.ToolOutput)
	}
	if ev.Target != "go.mod" {
		t.Errorf("Target = %q, want \"go.mod\"", ev.Target)
	}
}

// TestBuildEvent_BeforeReadFile_CapsAtContentcapDefault pins the
// v1.6.29 cap shift: ToolOutput now flows through
// internal/contentcap.Cap (1 MiB default) instead of the legacy
// 4000-char hard slice. Bodies under the cap pass through verbatim so
// the dashboard's on-demand /api/action/<id>/full_text endpoint can
// serve the operator the actual file contents. Oversized bodies get
// the trailing truncation marker added by contentcap.
func TestBuildEvent_BeforeReadFile_CapsAtContentcapDefault(t *testing.T) {
	t.Run("under cap passes through", func(t *testing.T) {
		long := strings.Repeat("a", 5000)
		body := []byte(`{
			"hook_event_name":"beforeReadFile",
			"conversation_id":"c1","generation_id":"g1",
			"workspace_roots":["/repo"],
			"file_path":"big.go",
			"content":"` + long + `"
		}`)
		ev, ok, err := BuildEvent(EventBeforeReadFile, body, nil)
		if err != nil || !ok {
			t.Fatalf("BuildEvent: %v ok=%v", err, ok)
		}
		if ev.ToolOutput != long {
			t.Errorf("ToolOutput len = %d, want %d (under cap should pass through)", len(ev.ToolOutput), len(long))
		}
	})

	t.Run("over cap is truncated with marker", func(t *testing.T) {
		long := strings.Repeat("a", contentcap.DefaultMaxBytes+1024)
		body := []byte(`{
			"hook_event_name":"beforeReadFile",
			"conversation_id":"c1","generation_id":"g1",
			"workspace_roots":["/repo"],
			"file_path":"big.go",
			"content":"` + long + `"
		}`)
		ev, ok, err := BuildEvent(EventBeforeReadFile, body, nil)
		if err != nil || !ok {
			t.Fatalf("BuildEvent: %v ok=%v", err, ok)
		}
		if !strings.HasPrefix(ev.ToolOutput, strings.Repeat("a", 100)) {
			t.Errorf("ToolOutput should start with the body content")
		}
		if !strings.Contains(ev.ToolOutput, "content truncated at") {
			t.Errorf("ToolOutput should carry contentcap truncation marker, got tail %q", ev.ToolOutput[len(ev.ToolOutput)-80:])
		}
	})
}

// TestBuildAfterOutcome_DerivedSuccess covers the three-way success
// signal collapse: explicit `success` bool wins; falls back to
// `exit_code == 0`; falls back to error-string emptiness.
func TestBuildAfterOutcome_DerivedSuccess(t *testing.T) {
	cases := []struct {
		name string
		body string
		want bool
	}{
		{"explicit success:true wins over exit_code", `{"hook_event_name":"afterShellExecution","conversation_id":"c","generation_id":"g","command":"x","success":true,"exit_code":1}`, true},
		{"exit_code 0 ⇒ success when no explicit", `{"hook_event_name":"afterShellExecution","conversation_id":"c","generation_id":"g","command":"x","exit_code":0}`, true},
		{"exit_code non-zero ⇒ failure", `{"hook_event_name":"afterShellExecution","conversation_id":"c","generation_id":"g","command":"x","exit_code":2}`, false},
		{"empty error fallback ⇒ success", `{"hook_event_name":"afterShellExecution","conversation_id":"c","generation_id":"g","command":"x"}`, true},
		{"non-empty error fallback ⇒ failure", `{"hook_event_name":"afterShellExecution","conversation_id":"c","generation_id":"g","command":"x","error":"boom"}`, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			out, ok, err := BuildAfterOutcome(EventAfterShellExecution, []byte(c.body))
			if err != nil || !ok {
				t.Fatalf("BuildAfterOutcome: %v ok=%v", err, ok)
			}
			if out.Success != c.want {
				t.Errorf("Success=%v want %v", out.Success, c.want)
			}
		})
	}
}

// TestPostToolUseDurationUnitByVersion pins S10-CURSOR review (Codex
// pass 2) finding 4: current builds send postToolUse `duration` in
// MILLISECONDS (grounded 3.17.21-3.21.13); only the version-less 3.4.x
// shape keeps the seconds reading.
func TestPostToolUseDurationUnitByVersion(t *testing.T) {
	cases := []struct {
		version string
		d       float64
		want    int64
	}{
		{"3.20.21", 1401.838, 1401},
		{"3.17.21", 120086.182, 120086},
		{"3.21.13", 0.859, 0},
		{"4.0.1", 250, 250},
		{"3.16.9", 6.332, 6332},
		{"", 6.332, 6332},
		{"garbage", 6.332, 6332},
	}
	for _, tc := range cases {
		if got := postToolUseDurationMs(tc.d, tc.version); got != tc.want {
			t.Errorf("postToolUseDurationMs(%v, %q) = %d, want %d", tc.d, tc.version, got, tc.want)
		}
	}
}

// TestBuildAfterOutcome_ReadPairsWithBeforeReadFile pins Codex pass-2
// finding 5: the Read tool's postToolUse carries its path only in
// tool_input.file_path, and must hash to the SAME id as the
// beforeReadFile row (whose top-level file_path it matches verbatim).
func TestBuildAfterOutcome_ReadPairsWithBeforeReadFile(t *testing.T) {
	before := []byte(`{"hook_event_name":"beforeReadFile","conversation_id":"c1","generation_id":"g1",
		"file_path":"/repo/internal/store/x_test.go","content":"package store","workspace_roots":["/repo"]}`)
	ev, ok, err := BuildEvent(EventBeforeReadFile, before, nil)
	if err != nil || !ok {
		t.Fatalf("BuildEvent: ok=%v err=%v", ok, err)
	}
	post := []byte(`{"hook_event_name":"postToolUse","conversation_id":"c1","generation_id":"g1",
		"tool_name":"Read","tool_input":{"file_path":"/repo/internal/store/x_test.go"},
		"tool_output":"ok","duration":12.5,"cursor_version":"3.20.21","tool_use_id":"call-1"}`)
	out, ok, err := BuildAfterOutcome(EventPostToolUse, post)
	if err != nil || !ok {
		t.Fatalf("BuildAfterOutcome: ok=%v err=%v", ok, err)
	}
	if out.SourceEventID != ev.SourceEventID {
		t.Fatalf("outcome id %q != before-row id %q", out.SourceEventID, ev.SourceEventID)
	}
	if out.DurationMs != 12 {
		t.Fatalf("duration_ms = %d, want 12 (ms on 3.20.21)", out.DurationMs)
	}
}

// TestBuildEventUnmappedEventIsScrubbedAndCapped pins Codex pass-2
// finding 7: an event with no mapping keeps its payload only through
// the scrubber and the content cap, never verbatim.
func TestBuildEventUnmappedEventIsScrubbedAndCapped(t *testing.T) {
	secret := "sk-ant-api03-" + strings.Repeat("A", 90)
	big := strings.Repeat("x", 3*1024*1024)
	body := []byte(`{"hook_event_name":"someFutureEvent","conversation_id":"c1","generation_id":"g1",
		"workspace_roots":["/repo"],"note":"key ` + secret + `","blob":"` + big + `"}`)
	small := []byte(`{"hook_event_name":"someFutureEvent","conversation_id":"c1","generation_id":"g1",
		"workspace_roots":["/repo"],"note":"key ` + secret + `"}`)
	sev, ok, err := BuildEvent("someFutureEvent", small, scrub.New())
	if err != nil || !ok {
		t.Fatalf("BuildEvent: ok=%v err=%v", ok, err)
	}
	if strings.Contains(sev.RawToolInput, secret) || !strings.Contains(sev.RawToolInput, "conversation_id") {
		t.Fatalf("unmapped event not scrubbed field-wise: %q", sev.RawToolInput)
	}
	ev, ok, err := BuildEvent("someFutureEvent", body, scrub.New())
	if err != nil || !ok {
		t.Fatalf("BuildEvent: ok=%v err=%v", ok, err)
	}
	if len(ev.RawToolInput) >= len(body) || len(ev.RawToolInput) > 1024*1024 {
		t.Fatalf("unmapped event payload not capped: %d bytes", len(ev.RawToolInput))
	}
}
