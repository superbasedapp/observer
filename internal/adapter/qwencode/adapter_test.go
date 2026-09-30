package qwencode

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/tooltax"
)

// newTestAdapter builds an adapter whose single watch root is dir, so the
// synthetic/fixture paths under it pass UnderAnyWatchRoot.
func newTestAdapter(root string) *Adapter {
	return NewWithOptions(nil, root)
}

func TestName(t *testing.T) {
	if got := New().Name(); got != models.ToolQwenCode {
		t.Fatalf("Name() = %q, want %q", got, models.ToolQwenCode)
	}
	if got := New().Name(); got != "qwen-code" {
		t.Fatalf("Name() = %q, want qwen-code", got)
	}
}

func TestIsSessionFile(t *testing.T) {
	root := "/home/u/.qwen/projects"
	a := newTestAdapter(root)
	cases := []struct {
		name string
		path string
		want bool
	}{
		{"canonical chat transcript", "/home/u/.qwen/projects/-tmp-proj/chats/1a2b.jsonl", true},
		{"windows-style separators", `/home/u/.qwen/projects/c--proj/chats/deadbeef.jsonl`, true},
		{"runtime json sidecar rejected", "/home/u/.qwen/projects/-tmp-proj/chats/1a2b.runtime.json", false},
		{"runtime jsonl companion rejected", "/home/u/.qwen/projects/-tmp-proj/chats/1a2b.runtime.jsonl", false},
		{"shape ok but outside watch root", "/other/place/.qwen/projects/x/chats/y.jsonl", false},
		{"under root but wrong shape (no chats)", "/home/u/.qwen/projects/x/y.jsonl", false},
		{"under root but not .qwen", "/home/u/.qwen/projects/../.gemini/chats/y.jsonl", false},
		{"non-jsonl", "/home/u/.qwen/projects/x/chats/y.json", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := a.IsSessionFile(tc.path); got != tc.want {
				t.Fatalf("IsSessionFile(%q) = %v, want %v", tc.path, got, tc.want)
			}
		})
	}
}

// parseFixture places a copy of the named testdata fixture inside a
// watch-rooted chats/ dir so IsSessionFile-style path shape holds, then
// parses it fully.
func parseFixture(t *testing.T, fixture string) ([]models.ToolEvent, []models.TokenEvent, int64) {
	t.Helper()
	src := filepath.Join("..", "..", "..", "testdata", "qwencode", fixture)
	body, err := os.ReadFile(src)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	root := t.TempDir()
	dst := filepath.Join(root, ".qwen", "projects", "-home-dev-proj", "chats", "session.jsonl")
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dst, body, 0o644); err != nil {
		t.Fatal(err)
	}
	a := newTestAdapter(filepath.Join(root, ".qwen", "projects"))
	res, err := a.ParseSessionFile(context.Background(), dst, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	return res.ToolEvents, res.TokenEvents, res.NewOffset
}

func TestParseToolCallSession(t *testing.T) {
	tools, tokens, off := parseFixture(t, "tool-call-session.jsonl")
	if off <= 0 {
		t.Fatalf("offset did not advance: %d", off)
	}

	// Two token events (two api_response records).
	if len(tokens) != 2 {
		t.Fatalf("token events = %d, want 2", len(tokens))
	}

	// GROSS→NET verdict. Turn 1: cached 0 → net input = 17883.
	t1 := tokens[0]
	if t1.InputTokens != 17883 || t1.OutputTokens != 81 || t1.CacheReadTokens != 0 {
		t.Errorf("turn1 tokens = in%d out%d cache%d, want in17883 out81 cache0",
			t1.InputTokens, t1.OutputTokens, t1.CacheReadTokens)
	}
	// Turn 2: input 18049 gross incl. cached 17920 → net input = 129.
	t2 := tokens[1]
	if t2.InputTokens != 129 {
		t.Errorf("turn2 net input = %d, want 129 (18049 gross - 17920 cached)", t2.InputTokens)
	}
	if t2.CacheReadTokens != 17920 {
		t.Errorf("turn2 cache read = %d, want 17920", t2.CacheReadTokens)
	}
	if t2.OutputTokens != 41 {
		t.Errorf("turn2 output = %d, want 41", t2.OutputTokens)
	}
	if t2.Model != "gpt-4o" {
		t.Errorf("turn2 model = %q, want gpt-4o", t2.Model)
	}
	if t2.Source != models.TokenSourceJSONL || t2.Reliability != models.ReliabilityApproximate {
		t.Errorf("token source/reliability = %q/%q", t2.Source, t2.Reliability)
	}
	if t2.MessageID != "chatcmpl-BBB" {
		t.Errorf("token MessageID = %q, want chatcmpl-BBB", t2.MessageID)
	}
	if !strings.HasSuffix(t2.TurnID, "########0") {
		t.Errorf("token TurnID = %q, want prompt_id suffix", t2.TurnID)
	}

	// Tool events: session_start, user_prompt, write_file, run_shell_command,
	// assistant_message.
	byAction := map[string]models.ToolEvent{}
	byRaw := map[string]models.ToolEvent{}
	for _, e := range tools {
		byAction[e.ActionType] = e
		byRaw[e.RawToolName] = e
	}
	for _, want := range []string{
		models.ActionSessionStart, models.ActionUserPrompt,
		models.ActionWriteFile, models.ActionRunCommand, models.ActionAssistantMessage,
	} {
		if _, ok := byAction[want]; !ok {
			t.Errorf("missing action type %q; got %v", want, actionTypes(tools))
		}
	}

	wf := byRaw["write_file"]
	if wf.ActionType != models.ActionWriteFile {
		t.Errorf("write_file mapped to %q", wf.ActionType)
	}
	if !strings.HasSuffix(wf.Target, "greeting.txt") {
		t.Errorf("write_file target = %q, want *greeting.txt", wf.Target)
	}
	if !wf.Success {
		t.Errorf("write_file should be success")
	}
	if wf.DurationMs != 101 {
		t.Errorf("write_file duration = %d, want 101 (from ui_telemetry)", wf.DurationMs)
	}
	if wf.ToolOutput == "" {
		t.Errorf("write_file output not stamped from tool_result")
	}

	sh := byRaw["run_shell_command"]
	if sh.ActionType != models.ActionRunCommand || sh.DurationMs != 353 {
		t.Errorf("run_shell_command action=%q dur=%d", sh.ActionType, sh.DurationMs)
	}

	// Project root resolves from the record cwd (not the dir slug).
	if wf.ProjectRoot != "/home/dev/proj" {
		t.Errorf("project root = %q, want /home/dev/proj", wf.ProjectRoot)
	}
}

func TestParseSimpleSession(t *testing.T) {
	tools, tokens, _ := parseFixture(t, "simple-session.jsonl")
	if len(tokens) != 1 {
		t.Fatalf("token events = %d, want 1", len(tokens))
	}
	tok := tokens[0]
	if tok.ReasoningTokens != 40 {
		t.Errorf("reasoning (thoughts) tokens = %d, want 40", tok.ReasoningTokens)
	}
	if tok.Model != "glm-5.2" {
		t.Errorf("model = %q, want glm-5.2 (never hardcode Qwen)", tok.Model)
	}
	if tok.InputTokens != 9786 {
		t.Errorf("input = %d, want 9786", tok.InputTokens)
	}
	// assistant text + user prompt + session start present.
	var haveAssistant, havePrompt bool
	for _, e := range tools {
		if e.ActionType == models.ActionAssistantMessage {
			haveAssistant = true
			if !strings.HasSuffix(e.RawToolName, ".assistant_text") {
				t.Errorf("assistant raw name = %q", e.RawToolName)
			}
		}
		if e.ActionType == models.ActionUserPrompt {
			havePrompt = true
		}
	}
	if !haveAssistant || !havePrompt {
		t.Errorf("assistant=%v prompt=%v", haveAssistant, havePrompt)
	}
}

func TestParseWindowsSession(t *testing.T) {
	tools, _, _ := parseFixture(t, "windows-session.jsonl")
	var apiErr, slash *models.ToolEvent
	for i := range tools {
		switch tools[i].ActionType {
		case models.ActionAPIError:
			apiErr = &tools[i]
		case models.ActionUserPromptExpansion:
			if tools[i].RawToolName == "qwen-code.slash_command" {
				slash = &tools[i]
			}
		}
	}
	if apiErr == nil {
		t.Fatal("no ActionAPIError emitted")
	}
	if apiErr.Success {
		t.Error("api_error must be Success=false")
	}
	if apiErr.RawToolName != "AuthenticationError" {
		t.Errorf("api_error raw name = %q, want AuthenticationError", apiErr.RawToolName)
	}
	if !strings.Contains(apiErr.ErrorMessage, "401") {
		t.Errorf("api_error message = %q", apiErr.ErrorMessage)
	}
	if slash == nil {
		t.Fatal("slash_command not captured")
	}
	if slash.Target != "/auth" {
		t.Errorf("slash target = %q, want /auth", slash.Target)
	}

	// Windows cwd C:\programsx\regulation must translate for project root.
	for _, e := range tools {
		if e.ProjectRoot == "" {
			continue
		}
		if strings.Contains(e.ProjectRoot, `\`) || strings.HasPrefix(e.ProjectRoot, "C:") {
			t.Errorf("project root not translated: %q", e.ProjectRoot)
		}
		if !strings.Contains(e.ProjectRoot, "regulation") {
			t.Errorf("project root = %q, want a path containing 'regulation'", e.ProjectRoot)
		}
	}
}

func TestMalformedToleranceAndOffset(t *testing.T) {
	tools, _, off := parseFixture(t, "malformed-session.jsonl")
	// Fixture is 4 physical lines (good, garbage, empty, good); the two
	// good records must both parse and the cursor must reach EOF.
	src := filepath.Join("..", "..", "..", "testdata", "qwencode", "malformed-session.jsonl")
	fi, _ := os.Stat(src)
	if off != fi.Size() {
		t.Errorf("offset = %d, want EOF %d", off, fi.Size())
	}
	var prompt, assistant bool
	for _, e := range tools {
		if e.ActionType == models.ActionUserPrompt && e.Target == "first prompt" {
			prompt = true
		}
		if e.ActionType == models.ActionAssistantMessage {
			assistant = true
		}
	}
	if !prompt || !assistant {
		t.Errorf("recovery failed: prompt=%v assistant=%v", prompt, assistant)
	}
}

func TestCursorResumption(t *testing.T) {
	src := filepath.Join("..", "..", "..", "testdata", "qwencode", "tool-call-session.jsonl")
	body, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	dst := filepath.Join(root, ".qwen", "projects", "-home-dev-proj", "chats", "s.jsonl")
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dst, body, 0o644); err != nil {
		t.Fatal(err)
	}
	a := newTestAdapter(filepath.Join(root, ".qwen", "projects"))

	// First pass over only the first N lines' worth of bytes.
	lines := strings.SplitAfter(string(body), "\n")
	var midOffset int64
	for i := 0; i < 4; i++ { // through the assistant functionCall record
		midOffset += int64(len(lines[i]))
	}
	res1, err := a.ParseSessionFile(context.Background(), dst, 0)
	if err != nil {
		t.Fatal(err)
	}
	full := len(res1.TokenEvents) + len(res1.ToolEvents)

	// Resume from a mid-file offset: must not re-emit earlier events, and
	// must still produce the second-turn token event.
	res2, err := a.ParseSessionFile(context.Background(), dst, midOffset)
	if err != nil {
		t.Fatal(err)
	}
	if res2.NewOffset != int64(len(body)) {
		t.Errorf("resume offset = %d, want %d", res2.NewOffset, len(body))
	}
	// The resumed pass sees strictly fewer events than a full parse.
	if got := len(res2.TokenEvents) + len(res2.ToolEvents); got >= full {
		t.Errorf("resume produced %d events, full produced %d — no resumption", got, full)
	}
	// Second-turn token event (cached 17920) is after the mid offset.
	var sawSecond bool
	for _, tk := range res2.TokenEvents {
		if tk.CacheReadTokens == 17920 {
			sawSecond = true
		}
	}
	if !sawSecond {
		t.Errorf("resumed parse missed the second-turn token event")
	}
}

func actionTypes(evs []models.ToolEvent) []string {
	var out []string
	for _, e := range evs {
		out = append(out, e.ActionType)
	}
	return out
}

// TestToolResultCrossTickEmitsOutcomeUpdate pins the parser half of the
// store outcome-update seam. A functionCall and its tool_result record
// are separate JSONL lines; when a poll tick ends between them the call
// row is already persisted optimistically successful and the next parse
// window resumes with an empty pendingCall map. The outcome must leave
// as an ActionOutcomeUpdate keyed by the same "tool:<callId>"
// SourceEventID callEventID produced — the store's action upsert cannot
// flip success / error_message, so a dropped update is a permanent lie.
func TestToolResultCrossTickEmitsOutcomeUpdate(t *testing.T) {
	const (
		userLine = `{"sessionId":"s-xt","cwd":"/home/dev/proj","gitBranch":"main","uuid":"u0","timestamp":"2026-07-09T04:46:34.989Z","type":"user","message":{"role":"user","parts":[{"text":"run the tests"}]}}`
		callLine = `{"sessionId":"s-xt","cwd":"/home/dev/proj","gitBranch":"main","uuid":"u1","parentUuid":"u0","timestamp":"2026-07-09T04:46:42.771Z","type":"assistant","model":"gpt-4o","message":{"role":"model","parts":[{"functionCall":{"id":"call_xt","name":"run_shell_command","args":{"command":"go test ./..."}}}]}}`
	)

	cases := []struct {
		name         string
		resultLine   string
		wantID       string
		wantKnown    bool
		wantOK       bool
		wantErrMsg   bool
		wantNoOutput bool
	}{
		{
			name:       "failed call",
			resultLine: `{"sessionId":"s-xt","cwd":"/home/dev/proj","uuid":"u2","parentUuid":"u1","timestamp":"2026-07-09T04:46:43.000Z","type":"tool_result","message":{"role":"user","parts":[{"functionResponse":{"id":"call_xt","name":"run_shell_command","response":{"output":"--- FAIL: TestFoo\nexit status 1"}}}]},"toolCallResult":{"callId":"call_xt","status":"error","resultDisplay":"--- FAIL: TestFoo"}}`,
			wantID:     "tool:call_xt",
			wantKnown:  true,
			wantOK:     false,
			wantErrMsg: true,
		},
		{
			name:       "successful call",
			resultLine: `{"sessionId":"s-xt","cwd":"/home/dev/proj","uuid":"u2","parentUuid":"u1","timestamp":"2026-07-09T04:46:43.000Z","type":"tool_result","message":{"role":"user","parts":[{"functionResponse":{"id":"call_xt","name":"run_shell_command","response":{"output":"ok 12 tests"}}}]},"toolCallResult":{"callId":"call_xt","status":"success","resultDisplay":"ok 12 tests"}}`,
			wantID:     "tool:call_xt",
			wantKnown:  true,
			wantOK:     true,
		},
		{
			// A functionResponse without a toolCallResult carries no
			// status. In-window that leaves Success untouched; the
			// cross-tick update must say so rather than invent one —
			// the persisted row may already be a telemetry-stamped
			// failure.
			name:       "status-less response carries no verdict",
			resultLine: `{"sessionId":"s-xt","cwd":"/home/dev/proj","uuid":"u2","parentUuid":"u1","timestamp":"2026-07-09T04:46:43.000Z","type":"tool_result","message":{"role":"user","parts":[{"functionResponse":{"id":"call_xt","name":"run_shell_command","response":{"output":"partial output, no status"}}}]}}`,
			wantID:     "tool:call_xt",
			wantKnown:  false,
		},
		{
			name:       "result with no call id is unkeyable and dropped",
			resultLine: `{"sessionId":"s-xt","cwd":"/home/dev/proj","uuid":"u2","parentUuid":"u1","timestamp":"2026-07-09T04:46:43.000Z","type":"tool_result","message":{"role":"user","parts":[{"functionResponse":{"name":"run_shell_command","response":{"output":"orphan"}}}]}}`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			projects := filepath.Join(root, ".qwen", "projects")
			dst := filepath.Join(projects, "-home-dev-proj", "chats", "s.jsonl")
			if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
				t.Fatal(err)
			}
			a := newTestAdapter(projects)

			// Window 1: the transcript ends right after the functionCall.
			if err := os.WriteFile(dst, []byte(userLine+"\n"+callLine+"\n"), 0o644); err != nil {
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
			if err := os.WriteFile(dst, []byte(userLine+"\n"+callLine+"\n"+tc.resultLine+"\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			res2, err := a.ParseSessionFile(context.Background(), dst, res1.NewOffset)
			if err != nil {
				t.Fatalf("second parse: %v", err)
			}
			if tc.wantID == "" {
				if len(res2.OutcomeUpdates) != 0 {
					t.Fatalf("unkeyable result produced %+v, want no updates", res2.OutcomeUpdates)
				}
				return
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
			if up.SourceEventID != tc.wantID {
				t.Errorf("SourceEventID = %q, want %q", up.SourceEventID, tc.wantID)
			}
			if up.SuccessKnown != tc.wantKnown {
				t.Errorf("SuccessKnown = %v, want %v (a status-less response is not a verdict)", up.SuccessKnown, tc.wantKnown)
			}
			if up.Success != tc.wantOK {
				t.Errorf("Success = %v, want %v", up.Success, tc.wantOK)
			}
			if tc.wantErrMsg && up.ErrorMessage == "" {
				t.Error("ErrorMessage empty on a status=error result")
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

// TestMapToolName_VendorGroundedNames pins the qwen-code tool names
// added 2026-09-28 (R2-TOOLMAP). `advisor` is ToolNames.ADVISOR in
// QwenLM/qwen-code packages/core/src/tools/tool-names.ts (Kind.Think).
// One case per new mapping; each must agree with internal/tooltax.
func TestMapToolName_VendorGroundedNames(t *testing.T) {
	cases := []struct{ native, want string }{
		{"advisor", models.ActionHarnessCall},
	}
	for _, tc := range cases {
		if got := mapToolName(tc.native); got != tc.want {
			t.Errorf("mapToolName(%q) = %q, want %q", tc.native, got, tc.want)
		}
		if e, ok := tooltax.Resolve(models.ToolQwenCode, tc.native); !ok || e.Tool != models.ToolQwenCode || e.ActionType != tc.want {
			t.Errorf("tooltax.Resolve(qwen-code, %q) = %+v (ok=%v), want a qwen-code %q row", tc.native, e, ok, tc.want)
		}
	}
}
