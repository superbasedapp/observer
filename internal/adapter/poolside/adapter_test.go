package poolside

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/adapter"
	"github.com/marmutapp/superbased-observer/internal/models"
)

const fixtureName = "trajectory-standalone_11111111-2222-7333-8444-555555555555.ndjson"

// fixtureRoot lays a testdata fixture out under a temp watch root and
// returns (root, trajectoryPath). Every parse test goes through here so
// the adapter is always exercised with its own under-watch-root
// predicate satisfied, exactly as the watcher would.
func fixtureRoot(t *testing.T, fixture string) (root, trajPath string) {
	t.Helper()
	root = filepath.Join(t.TempDir(), "poolside", "trajectories")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	body, err := os.ReadFile(filepath.Join("..", "..", "..", "testdata", "poolside", fixture))
	if err != nil {
		t.Fatalf("read fixture %s: %v", fixture, err)
	}
	trajPath = filepath.Join(root, fixture)
	if err := os.WriteFile(trajPath, body, 0o600); err != nil {
		t.Fatalf("write log: %v", err)
	}
	return root, trajPath
}

// parseFixture is the common "lay it out, parse it whole" helper.
func parseFixture(t *testing.T) (adapter.ParseResult, string) {
	t.Helper()
	root, trajPath := fixtureRoot(t, fixtureName)
	a := NewWithOptions(nil, root)
	res, err := a.ParseSessionFile(context.Background(), trajPath, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	return res, trajPath
}

func TestName(t *testing.T) {
	if got := New().Name(); got != models.ToolPoolside {
		t.Errorf("Name() = %q, want %q", got, models.ToolPoolside)
	}
}

func TestIsSessionFile(t *testing.T) {
	root := filepath.Join(t.TempDir(), "poolside", "trajectories")
	a := NewWithOptions(nil, root)
	cases := []struct {
		name string
		path string
		want bool
	}{
		{"trajectory file", filepath.Join(root, fixtureName), true},
		{"other basename", filepath.Join(root, "not-a-trajectory.ndjson"), false},
		{"wrong extension", filepath.Join(root, "trajectory-standalone_x.json"), false},
		{"right shape, foreign root", filepath.Join("/tmp/foreign/poolside/trajectories", fixtureName), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := a.IsSessionFile(tc.path); got != tc.want {
				t.Errorf("IsSessionFile(%q) = %v, want %v", tc.path, got, tc.want)
			}
		})
	}
}

func TestWatchPathsAreAbsolute(t *testing.T) {
	for _, p := range New().WatchPaths() {
		if !filepath.IsAbs(p) {
			t.Errorf("watch path %q is not absolute", p)
		}
		if !strings.HasSuffix(filepath.ToSlash(p), "/poolside/trajectories") {
			t.Errorf("watch path %q does not end in poolside/trajectories", p)
		}
	}
}

func TestSessionAndAgentFromPath(t *testing.T) {
	cases := []struct {
		path      string
		wantSess  string
		wantAgent string
	}{
		{"trajectory-standalone_01a06e04-7ef2-7a95-b894-ee1f89c31bf8.ndjson", "01a06e04-7ef2-7a95-b894-ee1f89c31bf8", "standalone"},
		{"trajectory-multi_agent_mode_11111111-2222-3333-4444-555555555555.ndjson", "11111111-2222-3333-4444-555555555555", "multi_agent_mode"},
		{"not-matching.ndjson", "not-matching", ""},
	}
	for _, tc := range cases {
		sess, agent := sessionAndAgentFromPath(tc.path)
		if sess != tc.wantSess || agent != tc.wantAgent {
			t.Errorf("sessionAndAgentFromPath(%q) = (%q,%q), want (%q,%q)", tc.path, sess, agent, tc.wantSess, tc.wantAgent)
		}
	}
}

func TestParseSessionFile_SessionMarkers(t *testing.T) {
	res, _ := parseFixture(t)
	wantSessionID := "11111111-2222-7333-8444-555555555555"

	var start, end *models.ToolEvent
	for i := range res.ToolEvents {
		ev := &res.ToolEvents[i]
		if ev.SessionID != wantSessionID {
			t.Errorf("event %d SessionID = %q, want %q", i, ev.SessionID, wantSessionID)
		}
		switch ev.ActionType {
		case models.ActionSessionStart:
			start = ev
		case models.ActionSessionEnd:
			end = ev
		}
	}
	if start == nil {
		t.Fatal("no session_start event emitted")
	}
	if start.SourceEventID != "session_start:"+wantSessionID {
		t.Errorf("session_start SourceEventID = %q", start.SourceEventID)
	}
	if end == nil {
		t.Fatal("no session_end event emitted")
	}
	if end.Target != "exit_tool_called" {
		t.Errorf("session_end Target = %q, want %q", end.Target, "exit_tool_called")
	}
	wantRoot := filepath.FromSlash("C:/Users/devuser/workspace/demo-project")
	if start.ProjectRoot == "" || filepath.ToSlash(start.ProjectRoot) != filepath.ToSlash(wantRoot) {
		// git.Resolve falls back to the raw cwd when it isn't a git repo,
		// which is the case for this fixture's synthetic path.
		if !strings.Contains(filepath.ToSlash(start.ProjectRoot), "demo-project") {
			t.Errorf("ProjectRoot = %q, want it to contain demo-project", start.ProjectRoot)
		}
	}
}

func TestParseSessionFile_UserPromptAndAssistantMessage(t *testing.T) {
	res, _ := parseFixture(t)
	var prompt, assistant *models.ToolEvent
	for i := range res.ToolEvents {
		ev := &res.ToolEvents[i]
		switch ev.ActionType {
		case models.ActionUserPrompt:
			if prompt == nil {
				prompt = ev
			}
		case models.ActionAssistantMessage:
			if assistant == nil {
				assistant = ev
			}
		}
	}
	if prompt == nil {
		t.Fatal("no user_prompt event emitted")
	}
	if !strings.Contains(prompt.RawToolInput, "Summarize this project") {
		t.Errorf("prompt RawToolInput = %q", prompt.RawToolInput)
	}
	if assistant == nil {
		t.Fatal("no assistant_message event emitted")
	}
	if assistant.Model != "poolside/laguna-s-2.1" {
		t.Errorf("assistant Model = %q", assistant.Model)
	}
	if assistant.PrecedingReasoning == "" {
		t.Error("assistant_message should carry the same step's thought as PrecedingReasoning")
	}
}

// TestParseSessionFile_ToolCallVocabulary asserts every grounded native
// tool name maps to the right normalized action, and that the target /
// content-bytes extraction reads the right argument keys.
func TestParseSessionFile_ToolCallVocabulary(t *testing.T) {
	res, _ := parseFixture(t)
	byRawName := map[string]*models.ToolEvent{}
	for i := range res.ToolEvents {
		ev := &res.ToolEvents[i]
		if ev.SourceEventID == "" || !strings.HasPrefix(ev.SourceEventID, "tool:") {
			continue
		}
		if _, ok := byRawName[ev.RawToolName]; !ok {
			byRawName[ev.RawToolName] = ev
		}
	}
	cases := []struct {
		raw    string
		action string
	}{
		{"read", models.ActionReadFile},
		{"write", models.ActionWriteFile},
		{"edit", models.ActionEditFile},
		{"shell", models.ActionRunCommand},
		{"list_directory_tree", models.ActionSearchFiles},
		{"todo_action", models.ActionTodoUpdate},
		{"exit", models.ActionTaskComplete},
	}
	for _, tc := range cases {
		ev, ok := byRawName[tc.raw]
		if !ok {
			t.Errorf("no tool call event for raw name %q", tc.raw)
			continue
		}
		if ev.ActionType != tc.action {
			t.Errorf("%s: ActionType = %q, want %q", tc.raw, ev.ActionType, tc.action)
		}
	}

	writeEv := byRawName["write"]
	if writeEv.Target == "" || !strings.HasSuffix(filepath.ToSlash(writeEv.Target), "demo.py") {
		t.Errorf("write Target = %q, want it to end in demo.py", writeEv.Target)
	}
	if writeEv.ContentBytes != int64(len("print('hello demo')\n")) {
		t.Errorf("write ContentBytes = %d", writeEv.ContentBytes)
	}
	shellEv := byRawName["shell"]
	if shellEv.Target != "python demo.py" {
		t.Errorf("shell Target = %q", shellEv.Target)
	}
	if shellEv.ContentBytes != int64(len("python demo.py")) {
		t.Errorf("shell ContentBytes = %d", shellEv.ContentBytes)
	}
}

// TestParseSessionFile_ValidationErrorFailsImmediately pins that a
// tool_call.parsed carrying a validation_error is recorded as an
// immediate failure — the call never ran, so no later result is
// expected.
func TestParseSessionFile_ValidationErrorFailsImmediately(t *testing.T) {
	res, _ := parseFixture(t)
	for i := range res.ToolEvents {
		ev := &res.ToolEvents[i]
		if ev.RawToolName == "list_directory_tree" {
			if ev.Success {
				t.Error("list_directory_tree call had a validation_error and must be Success=false")
			}
			if !strings.Contains(ev.ErrorMessage, "not available") {
				t.Errorf("ErrorMessage = %q, want it to mention the validation detail", ev.ErrorMessage)
			}
			return
		}
	}
	t.Fatal("no list_directory_tree event found")
}

// TestParseSessionFile_ShellFailureFromExitCode pins that a shell call's
// non-zero shell_run_tool_result.exit_code flips Success within the SAME
// parse window (both the approval and the result land in this parse).
func TestParseSessionFile_ShellFailureFromExitCode(t *testing.T) {
	res, _ := parseFixture(t)
	var failing *models.ToolEvent
	for i := range res.ToolEvents {
		ev := &res.ToolEvents[i]
		if ev.SourceEventID == "tool:call-shell-1" {
			failing = ev
		}
	}
	if failing == nil {
		t.Fatal("call-shell-1 event not found")
	}
	if failing.Success {
		t.Error("shell call with exit_code=1 must be Success=false")
	}
	if failing.DurationMs != 100 {
		t.Errorf("DurationMs = %d, want 100 (100000000ns)", failing.DurationMs)
	}
	if !strings.Contains(failing.ToolOutput, "exited with code 1") {
		t.Errorf("ToolOutput = %q", failing.ToolOutput)
	}
}

// TestParseSessionFile_DeniedCallFailsWithNoResult pins that a denied
// approval (tool_call.approval.denied=true) marks the call failed even
// though no tool_call.result ever follows it.
func TestParseSessionFile_DeniedCallFailsWithNoResult(t *testing.T) {
	res, _ := parseFixture(t)
	for i := range res.ToolEvents {
		ev := &res.ToolEvents[i]
		if ev.SourceEventID == "tool:call-shell-2" {
			if ev.Success {
				t.Error("denied call must be Success=false")
			}
			if !strings.Contains(ev.ErrorMessage, "denied") {
				t.Errorf("ErrorMessage = %q, want it to mention the denial", ev.ErrorMessage)
			}
			return
		}
	}
	t.Fatal("call-shell-2 event not found")
}

// TestParseSessionFile_TokenNetting pins the GROSS-input netting: turn 2's
// input_tokens (1300) includes cache_read_input_tokens (1050), so
// InputTokens (net) must be 250.
func TestParseSessionFile_TokenNetting(t *testing.T) {
	res, _ := parseFixture(t)
	if len(res.TokenEvents) == 0 {
		t.Fatal("no token events emitted")
	}
	var turn2 *models.TokenEvent
	for i := range res.TokenEvents {
		te := &res.TokenEvents[i]
		if te.CacheReadTokens == 1050 {
			turn2 = te
		}
		if te.Model != "poolside/laguna-s-2.1" {
			t.Errorf("token event %d Model = %q", i, te.Model)
		}
		if te.Source != models.TokenSourceJSONL || te.Reliability != models.ReliabilityApproximate {
			t.Errorf("token event %d Source/Reliability = %q/%q", i, te.Source, te.Reliability)
		}
	}
	if turn2 == nil {
		t.Fatal("no token event with cache_read_input_tokens=1050 found")
	}
	if turn2.InputTokens != 250 {
		t.Errorf("turn2 net InputTokens = %d, want 250 (1300-1050)", turn2.InputTokens)
	}
	if turn2.OutputTokens != 80 {
		t.Errorf("turn2 OutputTokens = %d, want 80", turn2.OutputTokens)
	}
}

// TestParseSessionFile_CrossWindowOutcomeUpdate pins the no-rewind design:
// parsing up to (and including) a tool_call.parsed line in one window,
// then resuming for the approval+result in a SECOND window, must emit an
// OutcomeUpdate rather than silently losing the outcome.
func TestParseSessionFile_CrossWindowOutcomeUpdate(t *testing.T) {
	root, trajPath := fixtureRoot(t, fixtureName)
	a := NewWithOptions(nil, root)

	body, err := os.ReadFile(trajPath)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	// call-write-1's tool_call.parsed line is "ev-0018" — split the file
	// right after that line so its approval+result land in a second
	// parse window with an empty in-memory toolIdx map.
	idx := strings.Index(string(body), `"id": "ev-0019"`)
	if idx < 0 {
		t.Fatal("fixture no longer contains ev-0019 — update the split point")
	}
	// idx points mid-line; back up to the start of that line.
	lineStart := strings.LastIndex(string(body)[:idx], "\n") + 1

	ctx := context.Background()
	first, err := a.ParseSessionFile(ctx, trajPath, 0)
	if err != nil {
		t.Fatalf("first ParseSessionFile: %v", err)
	}
	if int64(lineStart) > first.NewOffset {
		t.Fatalf("test setup: split point %d is past the first window's natural end %d", lineStart, first.NewOffset)
	}

	second, err := a.ParseSessionFile(ctx, trajPath, int64(lineStart))
	if err != nil {
		t.Fatalf("second ParseSessionFile: %v", err)
	}

	// The write call's ToolEvent from the FIRST window must never have
	// been patched (this parse instance forgot it — a fresh Adapter
	// value, matching how the watcher resumes across ticks).
	var found bool
	for _, upd := range second.OutcomeUpdates {
		if upd.SourceEventID == "tool:call-write-1" {
			found = true
			if upd.SuccessKnown {
				t.Error("OutcomeUpdate for call-write-1 should not claim SuccessKnown (write carries no verdict field)")
			}
			if upd.ToolOutput == "" || !strings.Contains(upd.ToolOutput, "Created file") {
				t.Errorf("OutcomeUpdate ToolOutput = %q", upd.ToolOutput)
			}
			if upd.DurationMs != 20 {
				t.Errorf("OutcomeUpdate DurationMs = %d, want 20", upd.DurationMs)
			}
		}
	}
	if !found {
		t.Fatal("no OutcomeUpdate for tool:call-write-1 in the second parse window")
	}
}

func TestParseSessionFile_CacheObservations(t *testing.T) {
	res, _ := parseFixture(t)
	if len(res.CacheObservations) == 0 {
		t.Error("expected at least one CacheTurnObservation")
	}
}

// TestParseSessionFile_MalformedLineWarnsAndContinues feeds a COMPLETE but
// non-JSON line in the middle of an otherwise-good trajectory and asserts
// the parser records a warning and keeps going (the session markers after
// the bad line still land). This exercises the malformed-complete-line
// branch that the partial-line and whole-file tests do not.
func TestParseSessionFile_MalformedLineWarnsAndContinues(t *testing.T) {
	good, err := os.ReadFile(filepath.Join("..", "..", "..", "testdata", "poolside", fixtureName))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	lines := strings.Split(strings.TrimRight(string(good), "\n"), "\n")
	if len(lines) < 2 {
		t.Fatalf("fixture has too few lines (%d)", len(lines))
	}
	// Inject a complete malformed line after the first record.
	injected := append([]string{lines[0], "{ this is not valid json"}, lines[1:]...)
	body := []byte(strings.Join(injected, "\n") + "\n")

	root := filepath.Join(t.TempDir(), "poolside", "trajectories")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	trajPath := filepath.Join(root, fixtureName)
	if err := os.WriteFile(trajPath, body, 0o600); err != nil {
		t.Fatal(err)
	}

	a := NewWithOptions(nil, root)
	res, err := a.ParseSessionFile(context.Background(), trajPath, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}

	var sawMalformed bool
	for _, w := range res.Warnings {
		if strings.Contains(w, "malformed JSON") {
			sawMalformed = true
		}
	}
	if !sawMalformed {
		t.Fatalf("no 'malformed JSON' warning; warnings=%v", res.Warnings)
	}
	// Parse continued past the bad line: the session markers that live in
	// the records AFTER the injection still produced events.
	var sawStart bool
	for i := range res.ToolEvents {
		if res.ToolEvents[i].ActionType == models.ActionSessionStart {
			sawStart = true
		}
	}
	if !sawStart {
		t.Fatal("parse did not continue past the malformed line (no session_start event)")
	}
}

// TestDefaultRootsComposeSinglePoolsideSegment pins the fix for the
// doubled-app-name bug: AppDataRoots already appends appDataSpec.Name
// ("poolside"), so defaultRoots must join only the trajectories subdir.
// Before the fix every root ended in .../poolside/poolside/trajectories,
// a path that never exists, so the daemon watched nothing. Whatever homes
// this host exposes, no root may carry a doubled "poolside/poolside"
// segment and every root must end in "poolside/trajectories".
func TestDefaultRootsComposeSinglePoolsideSegment(t *testing.T) {
	roots := defaultRoots()
	for _, r := range roots {
		s := filepath.ToSlash(r)
		if strings.Contains(s, "/poolside/poolside/") {
			t.Errorf("root has a doubled app segment: %s", r)
		}
		if !strings.HasSuffix(s, "/poolside/trajectories") {
			t.Errorf("root does not end in poolside/trajectories: %s", r)
		}
	}
}
