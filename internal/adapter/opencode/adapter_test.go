package opencode

import (
	"context"
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"github.com/marmutapp/superbased-observer/internal/adapter/mirrorbase"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
)

func TestParseSessionFile_SQLiteCapturesRichActions(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "opencode.db")
	setupOpenCodeDB(t, path)

	a := NewWithOptions(nil, []string{root})
	res, err := a.ParseSessionFile(context.Background(), path, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	if got := len(res.ToolEvents); got != 3 {
		t.Fatalf("expected 3 events, got %d", got)
	}

	if got := res.ToolEvents[0].ActionType; got != models.ActionUserPrompt {
		t.Fatalf("first event action_type = %q, want %q", got, models.ActionUserPrompt)
	}
	if got := res.ToolEvents[0].Target; got != "Build the app" {
		t.Fatalf("prompt target = %q", got)
	}

	if got := res.ToolEvents[1].ActionType; got != models.ActionRunCommand {
		t.Fatalf("second event action_type = %q, want %q", got, models.ActionRunCommand)
	}
	if res.ToolEvents[1].Success {
		t.Fatalf("expected bash event to be unsuccessful")
	}
	if got := res.ToolEvents[1].Target; got != "npm start" {
		t.Fatalf("command target = %q", got)
	}

	if got := res.ToolEvents[2].ActionType; got != models.ActionTaskComplete {
		t.Fatalf("third event action_type = %q, want %q", got, models.ActionTaskComplete)
	}
}

// TestParseSessionFile_SQLitePopulatesMessageIDAndToolOutputAndDuration
// pins the per-adapter parity with claudecode that landed in v1.4.19:
// every OpenCode event now carries a MessageID grouping (msg_xxx for
// assistant turns, "user:<id>" for prompts), tool events carry the
// scrubbed body of the tool result via ToolOutput, and DurationMs is
// derived from the part's own start/end timestamps. Pre-fix the audit
// flagged all three as silently zero — the source data was right there
// but the adapter discarded it.
func TestParseSessionFile_SQLitePopulatesMessageIDAndToolOutputAndDuration(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "opencode.db")
	setupOpenCodeDB(t, path)

	a := NewWithOptions(nil, []string{root})
	res, err := a.ParseSessionFile(context.Background(), path, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	if got := res.ToolEvents[0].MessageID; got != "user:msg_user" {
		t.Errorf("user prompt MessageID = %q, want user:msg_user", got)
	}
	tool := res.ToolEvents[1]
	if tool.MessageID != "msg_tool" {
		t.Errorf("tool MessageID = %q, want msg_tool (parent message id)", tool.MessageID)
	}
	if tool.ToolOutput != "boom" {
		t.Errorf("tool ToolOutput = %q, want %q (scrubbed State.Output)", tool.ToolOutput, "boom")
	}
	if tool.DurationMs != 300 {
		t.Errorf("tool DurationMs = %d, want 300 (end-start in fixture)", tool.DurationMs)
	}
	if got := res.ToolEvents[2].MessageID; got != "msg_done" {
		t.Errorf("completion MessageID = %q, want msg_done", got)
	}
}

// TestParseSessionFile_SQLiteEmitsTokenEventsForAssistantMessages
// pins OpenCode token-extraction behaviour. Confirmed against
// OpenCode's InfoData zod schema in
// packages/opencode/src/session/message.ts:
//
//	tokens: { input, output, reasoning, cache: { read, write } }
//	cost:   number (USD)
//
// Pre-fix the adapter only extracted role/model/time from the data
// blob; the token + cost fields were silently ignored, which is why
// OpenCode rows landed on the dashboard with Source="jsonl" but no
// numbers attached. This test seeds an assistant message with the
// full token bundle and asserts each field flows through to the
// emitted TokenEvent — Reliability=approximate (not unreliable like
// Claude Code's JSONL, since OpenCode persists the upstream usage
// envelope verbatim).
func TestParseSessionFile_SQLiteEmitsTokenEventsForAssistantMessages(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "opencode.db")
	setupOpenCodeDBWithTokens(t, path)

	a := NewWithOptions(nil, []string{root})
	res, err := a.ParseSessionFile(context.Background(), path, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	if got := len(res.TokenEvents); got != 1 {
		t.Fatalf("expected 1 token event, got %d", got)
	}
	te := res.TokenEvents[0]
	if te.Tool != models.ToolOpenCode {
		t.Errorf("Tool = %q, want %q", te.Tool, models.ToolOpenCode)
	}
	if te.Model != "big-pickle" {
		t.Errorf("Model = %q, want big-pickle", te.Model)
	}
	if te.InputTokens != 1234 {
		t.Errorf("InputTokens = %d, want 1234", te.InputTokens)
	}
	if te.OutputTokens != 567 {
		t.Errorf("OutputTokens = %d, want 567", te.OutputTokens)
	}
	if te.CacheReadTokens != 12345 {
		t.Errorf("CacheReadTokens = %d, want 12345", te.CacheReadTokens)
	}
	if te.CacheCreationTokens != 678 {
		t.Errorf("CacheCreationTokens = %d, want 678", te.CacheCreationTokens)
	}
	if te.ReasoningTokens != 89 {
		t.Errorf("ReasoningTokens = %d, want 89", te.ReasoningTokens)
	}
	if te.EstimatedCostUSD != 0.0532 {
		t.Errorf("EstimatedCostUSD = %v, want 0.0532", te.EstimatedCostUSD)
	}
	if te.Reliability != models.ReliabilityApproximate {
		t.Errorf("Reliability = %q, want %q", te.Reliability, models.ReliabilityApproximate)
	}
	if te.Source != models.TokenSourceJSONL {
		t.Errorf("Source = %q, want %q", te.Source, models.TokenSourceJSONL)
	}
	if te.MessageID != "msg_done" {
		t.Errorf("MessageID = %q, want msg_done (the assistant message id)", te.MessageID)
	}
}

// TestParseSessionFile_SQLiteSkipsZeroTokenAssistantRows pins the
// no-tokens guard — in-progress turns and assistant rows where the
// token bundle is empty across the board don't emit a TokenEvent
// (would otherwise pollute the cost engine with zero rows).
func TestParseSessionFile_SQLiteSkipsZeroTokenAssistantRows(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "opencode.db")
	setupOpenCodeDB(t, path) // seeds assistant rows WITHOUT tokens

	a := NewWithOptions(nil, []string{root})
	res, err := a.ParseSessionFile(context.Background(), path, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	if got := len(res.TokenEvents); got != 0 {
		t.Errorf("expected 0 token events from token-less rows, got %d: %+v", got, res.TokenEvents)
	}
}

// TestParseSessionFile_SubtaskPartEmitsSpawnSubagent pins the
// subtask-part wiring added in v1.4.9. OpenCode's parent message
// emits a `subtask` part to invoke a subagent (Build/Plan/Explore/
// custom). We tag those as ActionSpawnSubagent with target=agent name
// + the subagent's model when set.
func TestParseSessionFile_SubtaskPartEmitsSpawnSubagent(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "opencode.db")
	setupOpenCodeDBWithSubtask(t, path)
	a := NewWithOptions(nil, []string{root})
	res, err := a.ParseSessionFile(context.Background(), path, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	var spawn *models.ToolEvent
	for i := range res.ToolEvents {
		if res.ToolEvents[i].ActionType == models.ActionSpawnSubagent {
			spawn = &res.ToolEvents[i]
			break
		}
	}
	if spawn == nil {
		t.Fatalf("expected a spawn_subagent event from subtask part, got %+v", res.ToolEvents)
	}
	if spawn.Target != "Explore" {
		t.Errorf("Target = %q, want Explore (subagent name)", spawn.Target)
	}
	if spawn.Model != "claude-haiku-4-5" {
		t.Errorf("Model = %q, want claude-haiku-4-5 (subagent's model)", spawn.Model)
	}
	if spawn.RawToolName != "subtask" {
		t.Errorf("RawToolName = %q, want subtask", spawn.RawToolName)
	}
	if spawn.MessageID != "msg_a" {
		t.Errorf("MessageID = %q, want msg_a (parent message id)", spawn.MessageID)
	}
}

// TestParseSessionFile_TodoTableEmitsTodoUpdate pins the todo-table
// wiring. Each row → one ActionTodoUpdate event with target=status.
func TestParseSessionFile_TodoTableEmitsTodoUpdate(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "opencode.db")
	setupOpenCodeDBWithTodos(t, path)
	a := NewWithOptions(nil, []string{root})
	res, err := a.ParseSessionFile(context.Background(), path, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	var todoCount int
	for _, e := range res.ToolEvents {
		if e.ActionType == models.ActionTodoUpdate {
			todoCount++
		}
	}
	if todoCount != 2 {
		t.Errorf("expected 2 todo events, got %d (events=%+v)", todoCount, res.ToolEvents)
	}
}

// TestParseSessionFile_NewToolNamesMappedCorrectly pins the
// mapTool() extension covering webfetch, websearch, task, todoread,
// todowrite, multiedit, and OpenCode's underscore variant `apply_patch`.
// Pre-fix these all fell through to mcp regex or stayed as ActionUnknown.
func TestParseSessionFile_NewToolNamesMappedCorrectly(t *testing.T) {
	cases := []struct {
		tool, want string
	}{
		{"webfetch", models.ActionWebFetch},
		{"websearch", models.ActionWebSearch},
		{"task", models.ActionSpawnSubagent},
		{"agent", models.ActionSpawnSubagent},
		{"todowrite", models.ActionTodoUpdate},
		{"todoread", models.ActionTodoUpdate},
		{"multiedit", models.ActionEditFile},
		{"apply_patch", models.ActionEditFile},
	}
	for _, tc := range cases {
		t.Run(tc.tool, func(t *testing.T) {
			part := toolPartData{Tool: tc.tool}
			at, _, _, _ := mapTool(part)
			if at != tc.want {
				t.Errorf("mapTool(%q): got %q, want %q", tc.tool, at, tc.want)
			}
		})
	}
}

// TestMapTool_VendorGroundedNames pins the 2026-09-28 (R2-TOOLMAP)
// mappings for OpenCode tool ids that used to land in `unknown`. Each
// id is grounded in the OpenCode source (packages/opencode/src/tool/*.ts
// Tool.define(<id>), 1.18.32; codesearch from the pre-#27019 tree) and
// seen in live stores. One case per new mapping.
func TestMapTool_VendorGroundedNames(t *testing.T) {
	cases := []struct {
		name       string
		partJSON   string // a tool part's `data` column, as OpenCode writes it
		wantAction string
		wantTarget string
		wantOK     bool
		wantErr    string
	}{
		{
			name:       "question",
			partJSON:   `{"type":"tool","tool":"question","state":{"status":"completed","title":"Asked 2 questions","input":{"questions":[{"header":"h","question":"q?"}]}}}`,
			wantAction: models.ActionAskUser, wantTarget: "Asked 2 questions", wantOK: true,
		},
		{
			name:       "plan_exit",
			partJSON:   `{"type":"tool","tool":"plan_exit","state":{"status":"completed","title":"Switching to build agent","input":{}}}`,
			wantAction: models.ActionPermissionMode, wantTarget: "Switching to build agent", wantOK: true,
		},
		{
			name:       "skill",
			partJSON:   `{"type":"tool","tool":"skill","state":{"status":"completed","title":"Loaded skill: pdf","input":{"name":"pdf"}}}`,
			wantAction: models.ActionSkillInvoke, wantTarget: "Loaded skill: pdf", wantOK: true,
		},
		{
			name:       "lsp",
			partJSON:   `{"type":"tool","tool":"lsp","state":{"status":"completed","title":"goToDefinition","input":{"operation":"goToDefinition","filePath":"src/a.ts","line":3,"character":5}}}`,
			wantAction: models.ActionSearchText, wantTarget: "src/a.ts", wantOK: true,
		},
		{
			name:       "codesearch",
			partJSON:   `{"type":"tool","tool":"codesearch","state":{"status":"completed","title":"Code search: react useState","input":{"query":"react useState"}}}`,
			wantAction: models.ActionWebSearch, wantTarget: "Code search: react useState", wantOK: true,
		},
		{
			// The pseudo-tool itself "completed", but the model's call
			// failed: Success must be false and Target the attempted tool
			// (live shape, win store 2026-09-27).
			name:       "invalid",
			partJSON:   `{"type":"tool","tool":"invalid","state":{"status":"completed","title":"Invalid Tool","input":{"tool":"task","error":"Model tried to call unavailable tool 'task'."},"output":"The arguments provided to the tool are invalid: Model tried to call unavailable tool 'task'."}}`,
			wantAction: models.ActionToolFailure, wantTarget: "task", wantOK: false,
			wantErr: "Model tried to call unavailable tool 'task'.",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var part toolPartData
			if err := json.Unmarshal([]byte(tc.partJSON), &part); err != nil {
				t.Fatalf("fixture: %v", err)
			}
			at, target, ok, errMsg := mapTool(part)
			if at != tc.wantAction {
				t.Errorf("action = %q, want %q", at, tc.wantAction)
			}
			if target != tc.wantTarget {
				t.Errorf("target = %q, want %q", target, tc.wantTarget)
			}
			if ok != tc.wantOK {
				t.Errorf("success = %v, want %v", ok, tc.wantOK)
			}
			if errMsg != tc.wantErr {
				t.Errorf("errMsg = %q, want %q", errMsg, tc.wantErr)
			}
		})
	}
}

func TestParseSessionFile_SQLiteWatermarkSkipsOldRows(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "opencode.db")
	setupOpenCodeDB(t, path)

	a := NewWithOptions(nil, []string{root})
	res, err := a.ParseSessionFile(context.Background(), path, 3000)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	if len(res.ToolEvents) != 0 {
		t.Fatalf("expected no events, got %d", len(res.ToolEvents))
	}
	if res.NewOffset != 3000 {
		t.Fatalf("NewOffset = %d, want 3000", res.NewOffset)
	}
}

// TestParseSessionFile_AssistantTextEmission pins the new
// opencode.assistant_text emission: assistant-role text parts in the
// `part` table produce ActionTaskComplete rows with the body in
// ToolOutput, NO token/cost fields on the ToolEvent (token data flows
// through the separate TokenEvent path), and MessageID set to the
// parent message ID for cross-event linkage.
func TestParseSessionFile_AssistantTextEmission(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "opencode.db")
	setupOpenCodeDBWithAssistantText(t, path)

	a := NewWithOptions(nil, []string{root})
	res, err := a.ParseSessionFile(context.Background(), path, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}

	// Filter the emitted events to just the assistant_text rows for
	// stable assertions independent of other emitters' ordering.
	var asst []models.ToolEvent
	for _, ev := range res.ToolEvents {
		if ev.RawToolName == "opencode.assistant_text" {
			asst = append(asst, ev)
		}
	}
	if len(asst) != 2 {
		t.Fatalf("opencode.assistant_text rows: got %d want 2 (full events: %+v)", len(asst), res.ToolEvents)
	}

	for i, want := range []string{"First reasoning chunk.", "Second reasoning chunk."} {
		ev := asst[i]
		if ev.ActionType != models.ActionAssistantMessage {
			t.Errorf("asst[%d] action_type = %q, want assistant_message", i, ev.ActionType)
		}
		if ev.Target != want {
			t.Errorf("asst[%d] target = %q, want %q", i, ev.Target, want)
		}
		if ev.ToolOutput != want {
			t.Errorf("asst[%d] tool_output = %q, want %q", i, ev.ToolOutput, want)
		}
		if ev.MessageID != "msg_asst" {
			t.Errorf("asst[%d] message_id = %q, want msg_asst", i, ev.MessageID)
		}
		if ev.Tool != models.ToolOpenCode {
			t.Errorf("asst[%d] tool = %q, want %s", i, ev.Tool, models.ToolOpenCode)
		}
		if !ev.Success {
			t.Errorf("asst[%d] should be success", i)
		}
	}
	if asst[0].SourceEventID == asst[1].SourceEventID {
		t.Errorf("SourceEventIDs must differ across distinct parts: %q vs %q",
			asst[0].SourceEventID, asst[1].SourceEventID)
	}
}

// TestParseSessionFile_VariantStampsEffortLevelOnAssistantRows pins
// F1 from the 2026-05-21 opencode audit. OpenCode CLI sets
// `message.data.variant` to the per-(provider,model) effort selection
// ("low"/"medium"/"high") from ~/.local/state/opencode/model.json on
// every assistant message — verified against a live WSL CLI session
// where the assistant message JSON carried `"variant":"high"`. Pre-fix
// the adapter's messageData struct had no Variant field, so the
// effort was silently dropped from every CLI-origin row. This test
// seeds an assistant message with variant=high and asserts the
// effort lands on Metadata.EffortLevel of every assistant-side
// ToolEvent (completion, tool, assistant_text, subtask, reasoning,
// step_finish) — and stays nil on the user_prompt row which has no
// variant in OpenCode's emit shape.
func TestParseSessionFile_VariantStampsEffortLevelOnAssistantRows(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "opencode.db")
	setupOpenCodeDBWithVariant(t, path)

	a := NewWithOptions(nil, []string{root})
	res, err := a.ParseSessionFile(context.Background(), path, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}

	type want struct {
		raw    string
		effort string // "" means Metadata should be nil
		stop   string // expected Metadata.StopReason ("" = not asserted)
	}
	wantFor := map[string]want{
		// user prompts carry no variant in OpenCode's emit shape.
		"chat.message":            {raw: "chat.message", effort: ""},
		"opencode.assistant_text": {raw: "opencode.assistant_text", effort: "high"},
		// The terminus row stamps the source finish reason into the
		// canonical Metadata.StopReason column alongside the effort.
		"assistant.stop": {raw: "assistant.stop", effort: "high", stop: "stop"},
		"bash":           {raw: "bash", effort: "high"},
		// UPDATED 2026-07-31 (B3 convergence): the `opencode.reasoning`
		// row is gone — reasoning is threaded onto its successor's
		// PrecedingReasoning, never minted as an action of its own — so
		// there is no reasoning row left to carry effort metadata.
		"opencode.step_finish": {raw: "opencode.step_finish", effort: "high"},
	}
	seen := map[string]bool{}
	for _, ev := range res.ToolEvents {
		w, ok := wantFor[ev.RawToolName]
		if !ok {
			continue
		}
		seen[ev.RawToolName] = true
		if w.effort == "" {
			if ev.Metadata != nil {
				t.Errorf("%s row Metadata = %+v, want nil (no variant on user prompts)", ev.RawToolName, ev.Metadata)
			}
			continue
		}
		if ev.Metadata == nil {
			t.Errorf("%s row Metadata = nil, want EffortLevel=%q", ev.RawToolName, w.effort)
			continue
		}
		if ev.Metadata.EffortLevel != w.effort {
			t.Errorf("%s row EffortLevel = %q, want %q", ev.RawToolName, ev.Metadata.EffortLevel, w.effort)
		}
		if w.stop != "" && ev.Metadata.StopReason != w.stop {
			t.Errorf("%s row StopReason = %q, want %q", ev.RawToolName, ev.Metadata.StopReason, w.stop)
		}
	}
	for raw := range wantFor {
		if !seen[raw] {
			t.Errorf("expected an emitted row with RawToolName=%q; got events=%+v", raw, res.ToolEvents)
		}
	}
}

// TestEffortMetadata_TrimAndEmpty pins the helper's contract — only
// non-empty trimmed input produces a non-nil ActionMetadata. Whitespace-
// only variants (defensive — OpenCode shouldn't emit them) return nil
// so action rows don't get a "{}" metadata column for nothing.
func TestEffortMetadata_TrimAndEmpty(t *testing.T) {
	if effortMetadata("") != nil {
		t.Error("empty variant must return nil Metadata")
	}
	if effortMetadata("   ") != nil {
		t.Error("whitespace variant must return nil Metadata")
	}
	if m := effortMetadata("high"); m == nil || m.EffortLevel != "high" {
		t.Errorf("variant=high must return EffortLevel=high; got %+v", m)
	}
}

// TestParseSessionFile_ResolveProjectRootTranslatesForeignCwd pins
// F3 from the 2026-05-21 audit. OpenCode Desktop on Windows records
// path.cwd in Windows convention (e.g. "C:\programsx\..."); pre-fix
// resolveProjectRoot called git.Resolve directly on that string, and
// because filepath.Abs treats it as relative on Linux, the result
// CWD-prefixed onto observer's own tree (memory
// feedback_foreign_path_git_resolve). This test asserts the cwd is
// translated through crossmount.TranslateForeignPath before
// git.Resolve runs — so the projectRoot is "/mnt/c/programsx/..."
// (the WSL-mount equivalent) rather than observer's repo root.
func TestParseSessionFile_ResolveProjectRootTranslatesForeignCwd(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("foreign-cwd translation to /mnt/c is a Linux/WSL-daemon-reading-Windows-mount behavior; on a Windows host a C:\\ path is native and correctly stays untranslated")
	}
	a := NewWithOptions(nil, []string{t.TempDir()})
	cache := map[string]projectGitInfo{}
	got := a.resolveProjectRoot(`C:\programsx\open-code-test`, cache)
	// git.Resolve will fail to find a .git dir under /mnt/c on this
	// host; the fallback path stores the (translated) cwd directly.
	if !strings.HasPrefix(got, "/mnt/") {
		t.Errorf("resolveProjectRoot did not translate foreign path; got %q (want prefix /mnt/)", got)
	}
}

// TestParseSessionFile_ReasoningPartThreadsAndMintsNoRow is the B3
// successor of TestParseSessionFile_ReasoningPartEmitsRow (2026-07-31).
// OpenCode Desktop and the CLI both emit `reasoning`-typed parts
// carrying the model's chain-of-thought (verified 2026-05-21 on a live
// Desktop session: 11 reasoning parts across 11 messages). The adapter
// used to mint an `opencode.reasoning` task_complete row per part; it
// now mints NONE and threads the body onto the successor part's
// PrecedingReasoning instead. This pins all three semantics at once:
// no row, consumed-once (the tool takes the first thought, the text
// part does NOT re-take it), and last-wins (the two thoughts between
// the tool and the text collapse to the newest).
func TestParseSessionFile_ReasoningPartThreadsAndMintsNoRow(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "opencode.db")
	setupOpenCodeDBWithReasoning(t, path)

	a := NewWithOptions(nil, []string{root})
	res, err := a.ParseSessionFile(context.Background(), path, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}

	byRaw := map[string]models.ToolEvent{}
	for _, ev := range res.ToolEvents {
		if ev.RawToolName == "opencode.reasoning" {
			t.Fatalf("opencode.reasoning row minted: %+v", ev)
		}
		byRaw[ev.RawToolName] = ev
	}

	tool, ok := byRaw["bash"]
	if !ok {
		t.Fatalf("no tool row; events=%+v", res.ToolEvents)
	}
	if tool.PrecedingReasoning != "Considering the next step..." {
		t.Errorf("tool PrecedingReasoning = %q, want the reasoning body (it must beat the part title %q)",
			tool.PrecedingReasoning, "Run ls")
	}
	asst, ok := byRaw["opencode.assistant_text"]
	if !ok {
		t.Fatalf("no assistant_text row; events=%+v", res.ToolEvents)
	}
	if asst.PrecedingReasoning != "Second thought, the newer one." {
		t.Errorf("assistant_text PrecedingReasoning = %q, want the LAST reasoning before it", asst.PrecedingReasoning)
	}
}

// TestParseSessionFile_ReasoningThreadsAcrossParseWindow pins the
// widened index window: a poll tick can land between the reasoning part
// and the successor it belongs to. The successor's own batch sees no
// reasoning part at all under the incremental `time_updated > ?` filter,
// so the index deliberately re-reads every part of the messages that
// batch touches.
func TestParseSessionFile_ReasoningThreadsAcrossParseWindow(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "opencode.db")
	setupOpenCodeDBWithReasoning(t, path)

	a := NewWithOptions(nil, []string{root})
	// fromOffset past the reasoning part's time_updated (3500) but
	// before the tool part's (4500).
	res, err := a.ParseSessionFile(context.Background(), path, 4000)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	for _, ev := range res.ToolEvents {
		if ev.RawToolName == "bash" {
			if ev.PrecedingReasoning != "Considering the next step..." {
				t.Errorf("cross-window tool PrecedingReasoning = %q", ev.PrecedingReasoning)
			}
			return
		}
	}
	t.Fatalf("no tool row in the incremental batch; events=%+v", res.ToolEvents)
}

// TestParseSessionFile_StepFinishPartEmitsToolEventOnly pins F5 from
// the audit. OpenCode emits `step-finish` parts per-step within an
// assistant message carrying that step's token + cost slice; summed
// across all step-finishes within a message, the totals equal the
// message-level token bundle. Emitting TokenEvents from step-finish
// would double-count against loadTokenEvents — this test asserts a
// step-finish part produces a ToolEvent but ZERO additional
// TokenEvents (the message-level token bundle remains the single
// source of token truth).
func TestParseSessionFile_StepFinishPartEmitsToolEventOnly(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "opencode.db")
	setupOpenCodeDBWithStepFinish(t, path)

	a := NewWithOptions(nil, []string{root})
	res, err := a.ParseSessionFile(context.Background(), path, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	var steps []models.ToolEvent
	for _, ev := range res.ToolEvents {
		if ev.RawToolName == "opencode.step_finish" {
			steps = append(steps, ev)
		}
	}
	if len(steps) != 1 {
		t.Fatalf("opencode.step_finish rows: got %d want 1 (events=%+v)", len(steps), res.ToolEvents)
	}
	ev := steps[0]
	if ev.Target != "tool-calls" {
		t.Errorf("Target = %q, want tool-calls (finish reason)", ev.Target)
	}
	if !strings.Contains(ev.RawToolInput, `"tokens"`) {
		t.Errorf("RawToolInput must contain the step-finish JSON tokens block; got %q", ev.RawToolInput)
	}
	// Crucial: the step-finish path MUST NOT emit any TokenEvent —
	// message-level loadTokenEvents owns token attribution.
	if len(res.TokenEvents) != 0 {
		t.Errorf("step-finish must not emit TokenEvents (would double-count); got %+v", res.TokenEvents)
	}
}

// TestIsForeignMountPath_OnlyForeignHomes pins the F2 helper's
// contract — only paths under cross-mount-detected non-native homes
// match. Tests inject a fake AllHomes returning one native + one
// foreign home so the assertion runs identically on any host.
func TestIsForeignMountPath_OnlyForeignHomes(t *testing.T) {
	orig := allHomesFunc
	t.Cleanup(func() { allHomesFunc = orig })
	allHomesFunc = func() []crossmount.HomeRoot {
		return []crossmount.HomeRoot{
			{Path: "/home/me", OS: crossmount.OSLinux, Origin: "native"},
			{Path: "/mnt/c/Users/auzy_", OS: crossmount.OSWindows, Origin: "wsl-mnt:auzy_"},
		}
	}
	cases := []struct {
		path string
		want bool
	}{
		{"/home/me/.local/share/opencode/opencode.db", false},
		{"/mnt/c/Users/auzy_/.local/share/opencode/opencode.db", true},
		{"/tmp/something", false},
		{"/mnt/c/Users/other/.local/share/opencode/opencode.db", false},
	}
	for _, tc := range cases {
		if got := isForeignMountPath(tc.path); got != tc.want {
			t.Errorf("isForeignMountPath(%q) = %v, want %v", tc.path, got, tc.want)
		}
	}
}

// TestStageMirrorIfForeign_NativePassThrough pins that native paths
// hit the no-op fast path — no copy, no cache dir created. Critical
// because every parse call goes through this helper; a mistaken
// always-copy would burn 2.3+MB I/O on every native poll.
func TestStageMirrorIfForeign_NativePassThrough(t *testing.T) {
	orig := allHomesFunc
	t.Cleanup(func() { allHomesFunc = orig })
	allHomesFunc = func() []crossmount.HomeRoot {
		return []crossmount.HomeRoot{
			{Path: "/home/me", OS: crossmount.OSLinux, Origin: "native"},
		}
	}
	got, err := stageMirrorIfForeign("/home/me/.local/share/opencode/opencode.db")
	if err != nil {
		t.Fatalf("stageMirrorIfForeign: %v", err)
	}
	if got != "/home/me/.local/share/opencode/opencode.db" {
		t.Errorf("native path got remapped to %q (want passthrough)", got)
	}
}

// TestStageMirrorIfForeign_CopiesTrioAndReusesOnRepeat pins F2's
// happy path — a foreign-mount source triggers a trio copy to a per-
// source cache dir; a second call with no source mtime change skips
// the copy. Uses a fake AllHomes pointing at a tempdir so the test
// runs without depending on /mnt/c.
func TestStageMirrorIfForeign_CopiesTrioAndReusesOnRepeat(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("stageMirrorIfForeign uses os.UserCacheDir, which honors XDG_CACHE_HOME only on Unix; on Windows it returns %LocalAppData% with no env redirect, so the mirror cannot be staged under the test's temp cache root without prod changes")
	}
	srcRoot := t.TempDir()
	cacheRoot := t.TempDir()
	t.Setenv("XDG_CACHE_HOME", cacheRoot)
	orig := allHomesFunc
	t.Cleanup(func() { allHomesFunc = orig })
	allHomesFunc = func() []crossmount.HomeRoot {
		return []crossmount.HomeRoot{
			{Path: "/home/observer", OS: crossmount.OSLinux, Origin: "native"},
			{Path: srcRoot, OS: crossmount.OSWindows, Origin: "wsl-mnt:fake"},
		}
	}
	srcDB := filepath.Join(srcRoot, "opencode.db")
	if err := os.WriteFile(srcDB, []byte("DBv1"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(srcDB+"-wal", []byte("WALv1"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(srcDB+"-shm", []byte("SHMv1"), 0o600); err != nil {
		t.Fatal(err)
	}

	first, err := stageMirrorIfForeign(srcDB)
	if err != nil {
		t.Fatalf("first mirror: %v", err)
	}
	if first == srcDB {
		t.Fatalf("foreign source returned passthrough; want mirror path")
	}
	if !strings.HasPrefix(first, cacheRoot) {
		t.Errorf("mirror path %q must be under cache root %q", first, cacheRoot)
	}
	for _, suffix := range []string{"", "-wal", "-shm"} {
		got, err := os.ReadFile(first + suffix)
		if err != nil {
			t.Fatalf("read mirror sibling %s: %v", suffix, err)
		}
		want := map[string]string{"": "DBv1", "-wal": "WALv1", "-shm": "SHMv1"}[suffix]
		if string(got) != want {
			t.Errorf("mirror %s body = %q, want %q", suffix, got, want)
		}
	}

	// Backdate every source sibling so the mirror is clearly fresher
	// than the source — that's the condition mirrorUpToDate checks.
	// Snapshot the mirror's mtime BEFORE the second call so we can
	// detect a re-copy by observing the mtime move forward.
	past := time.Now().Add(-time.Hour)
	for _, suffix := range []string{"", "-wal", "-shm"} {
		if err := os.Chtimes(srcDB+suffix, past, past); err != nil {
			t.Fatal(err)
		}
	}
	beforeSecond, err := os.Stat(first)
	if err != nil {
		t.Fatal(err)
	}

	second, err := stageMirrorIfForeign(srcDB)
	if err != nil {
		t.Fatalf("second mirror: %v", err)
	}
	if second != first {
		t.Errorf("repeat call returned %q, want %q (same per-source mirror)", second, first)
	}
	afterSecond, err := os.Stat(second)
	if err != nil {
		t.Fatal(err)
	}
	if !afterSecond.ModTime().Equal(beforeSecond.ModTime()) {
		t.Errorf("mirror mtime changed (%v -> %v); repeat call must skip the copy when source is unchanged",
			beforeSecond.ModTime(), afterSecond.ModTime())
	}
}

// TestStageMirrorIfForeign_RespectsProcessBaseOverride pins F1: the
// mirror staging directory is derived from the single-owner
// mirrorbase.Base() seam, so installing a per-process override (the
// one-shot usage report's "nothing written outside a scratch dir"
// contract) redirects the mirror write there instead of the default
// os.UserCacheDir()-derived location.
func TestStageMirrorIfForeign_RespectsProcessBaseOverride(t *testing.T) {
	srcRoot := t.TempDir()
	overrideBase := t.TempDir()
	mirrorbase.SetBaseForProcess(overrideBase)
	t.Cleanup(func() { mirrorbase.SetBaseForProcess("") })

	orig := allHomesFunc
	t.Cleanup(func() { allHomesFunc = orig })
	allHomesFunc = func() []crossmount.HomeRoot {
		return []crossmount.HomeRoot{
			{Path: srcRoot, OS: crossmount.OSWindows, Origin: "wsl-mnt:fake"},
		}
	}
	srcDB := filepath.Join(srcRoot, "opencode.db")
	if err := os.WriteFile(srcDB, []byte("DBv1"), 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := stageMirrorIfForeign(srcDB)
	if err != nil {
		t.Fatalf("stageMirrorIfForeign: %v", err)
	}
	if !strings.HasPrefix(got, overrideBase) {
		t.Errorf("mirror path %q must be under process override base %q, want redirect", got, overrideBase)
	}
	if _, err := os.Stat(got); err != nil {
		t.Errorf("mirrored db not staged at %q: %v", got, err)
	}
}

// TestStageMirrorIfForeign_RefreshesOnSourceWALAdvance pins the WAL-
// triggered refresh — the main .db's mtime can stay stable while the
// WAL advances on every flush, so the mirror must re-copy when the
// WAL is newer than the mirror's WAL.
func TestStageMirrorIfForeign_RefreshesOnSourceWALAdvance(t *testing.T) {
	srcRoot := t.TempDir()
	cacheRoot := t.TempDir()
	t.Setenv("XDG_CACHE_HOME", cacheRoot)
	orig := allHomesFunc
	t.Cleanup(func() { allHomesFunc = orig })
	allHomesFunc = func() []crossmount.HomeRoot {
		return []crossmount.HomeRoot{
			{Path: srcRoot, OS: crossmount.OSWindows, Origin: "wsl-mnt:fake"},
		}
	}
	srcDB := filepath.Join(srcRoot, "opencode.db")
	if err := os.WriteFile(srcDB, []byte("DBv1"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(srcDB+"-wal", []byte("WALv1"), 0o600); err != nil {
		t.Fatal(err)
	}

	first, err := stageMirrorIfForeign(srcDB)
	if err != nil {
		t.Fatalf("first mirror: %v", err)
	}

	// Advance ONLY the WAL — the main .db stays unchanged. Force a
	// distinctly-newer mtime to defeat the same-second tick.
	if err := os.WriteFile(srcDB+"-wal", []byte("WALv1-advanced"), 0o600); err != nil {
		t.Fatal(err)
	}
	future := time.Now().Add(2 * time.Hour)
	if err := os.Chtimes(srcDB+"-wal", future, future); err != nil {
		t.Fatal(err)
	}

	if _, err := stageMirrorIfForeign(srcDB); err != nil {
		t.Fatalf("second mirror: %v", err)
	}
	got, err := os.ReadFile(first + "-wal")
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "WALv1-advanced" {
		t.Errorf("mirror -wal = %q, want %q (refresh must trigger on WAL mtime advance even when main .db is stable)", got, "WALv1-advanced")
	}
}

func setupOpenCodeDBWithVariant(t *testing.T, path string) {
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
		`CREATE TABLE session (id TEXT PRIMARY KEY, directory TEXT NOT NULL, time_updated INTEGER NOT NULL)`,
		`CREATE TABLE message (id TEXT PRIMARY KEY, session_id TEXT NOT NULL, time_created INTEGER NOT NULL, time_updated INTEGER NOT NULL, data TEXT NOT NULL)`,
		`CREATE TABLE part (id TEXT PRIMARY KEY, message_id TEXT NOT NULL, session_id TEXT NOT NULL, time_created INTEGER NOT NULL, time_updated INTEGER NOT NULL, data TEXT NOT NULL)`,
		`INSERT INTO session(id, directory, time_updated) VALUES ('ses_1', '/tmp/oc', 5000)`,
		`INSERT INTO message(id, session_id, time_created, time_updated, data) VALUES
			('msg_user', 'ses_1', 1000, 1001,
			 '{"role":"user","agent":"build","model":{"providerID":"openai","modelID":"gpt-5.4-nano"},"time":{"created":1000}}'),
			('msg_asst', 'ses_1', 2000, 5000,
			 '{"role":"assistant","agent":"build","variant":"high","modelID":"gpt-5.4-nano","providerID":"openai","path":{"cwd":"/tmp/oc"},"time":{"created":2000,"completed":5000},"finish":"stop"}')`,
		`INSERT INTO part(id, message_id, session_id, time_created, time_updated, data) VALUES
			('prt_user_text',  'msg_user', 'ses_1', 1000, 1001, '{"type":"text","text":"Do work"}'),
			('prt_asst_text',  'msg_asst', 'ses_1', 2100, 2200, '{"type":"text","text":"Working on it."}'),
			('prt_tool',       'msg_asst', 'ses_1', 2300, 2400, '{"type":"tool","tool":"bash","callID":"c1","state":{"status":"completed","input":{"command":"ls"},"output":"ok","title":"ls","time":{"start":2300,"end":2400}}}'),
			('prt_subtask',    'msg_asst', 'ses_1', 2500, 2600, '{"type":"subtask","prompt":"plan","description":"plan","agent":"Plan","model":{"providerID":"openai","modelID":"gpt-5.4-nano"},"time":{"created":2500}}'),
			('prt_reasoning',  'msg_asst', 'ses_1', 2700, 2800, '{"type":"reasoning","text":"Thinking step.","time":{"start":2700,"end":2800}}'),
			('prt_step',       'msg_asst', 'ses_1', 2900, 3000, '{"type":"step-finish","reason":"tool-calls","tokens":{"input":10,"output":5,"reasoning":0,"total":15,"cache":{"read":0,"write":0}},"cost":0.0001}')`,
	}
	for _, stmt := range stmts {
		if _, err := db.Exec(stmt); err != nil {
			t.Fatalf("exec %q: %v", stmt, err)
		}
	}
}

func setupOpenCodeDBWithReasoning(t *testing.T, path string) {
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
		`CREATE TABLE session (id TEXT PRIMARY KEY, directory TEXT NOT NULL, time_updated INTEGER NOT NULL)`,
		`CREATE TABLE message (id TEXT PRIMARY KEY, session_id TEXT NOT NULL, time_created INTEGER NOT NULL, time_updated INTEGER NOT NULL, data TEXT NOT NULL)`,
		`CREATE TABLE part (id TEXT PRIMARY KEY, message_id TEXT NOT NULL, session_id TEXT NOT NULL, time_created INTEGER NOT NULL, time_updated INTEGER NOT NULL, data TEXT NOT NULL)`,
		`INSERT INTO session(id, directory, time_updated) VALUES ('ses_1', '/tmp/oc', 7500)`,
		`INSERT INTO message(id, session_id, time_created, time_updated, data) VALUES
			('msg_asst', 'ses_1', 2000, 7500,
			 '{"role":"assistant","agent":"build","modelID":"gpt-5.4-nano","providerID":"openai","path":{"cwd":"/tmp/oc"},"time":{"created":2000,"completed":7500},"finish":"stop"}')`,
		`INSERT INTO part(id, message_id, session_id, time_created, time_updated, data) VALUES
			('prt_reasoning', 'msg_asst', 'ses_1', 3000, 3500, '{"type":"reasoning","text":"Considering the next step...","time":{"start":3000,"end":7500}}'),
			('prt_tool', 'msg_asst', 'ses_1', 4000, 4500, '{"type":"tool","tool":"bash","callID":"c1","state":{"status":"completed","input":{"command":"ls"},"output":"ok","title":"Run ls","time":{"start":4000,"end":4500}}}'),
			('prt_reasoning_2', 'msg_asst', 'ses_1', 5000, 5100, '{"type":"reasoning","text":"First thought, superseded.","time":{"start":5000,"end":5100}}'),
			('prt_reasoning_3', 'msg_asst', 'ses_1', 5500, 5600, '{"type":"reasoning","text":"Second thought, the newer one.","time":{"start":5500,"end":5600}}'),
			('prt_text', 'msg_asst', 'ses_1', 6000, 6100, '{"type":"text","text":"Done."}')`,
	}
	for _, stmt := range stmts {
		if _, err := db.Exec(stmt); err != nil {
			t.Fatalf("exec %q: %v", stmt, err)
		}
	}
}

func setupOpenCodeDBWithStepFinish(t *testing.T, path string) {
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
		`CREATE TABLE session (id TEXT PRIMARY KEY, directory TEXT NOT NULL, time_updated INTEGER NOT NULL)`,
		`CREATE TABLE message (id TEXT PRIMARY KEY, session_id TEXT NOT NULL, time_created INTEGER NOT NULL, time_updated INTEGER NOT NULL, data TEXT NOT NULL)`,
		`CREATE TABLE part (id TEXT PRIMARY KEY, message_id TEXT NOT NULL, session_id TEXT NOT NULL, time_created INTEGER NOT NULL, time_updated INTEGER NOT NULL, data TEXT NOT NULL)`,
		`INSERT INTO session(id, directory, time_updated) VALUES ('ses_1', '/tmp/oc', 3000)`,
		`INSERT INTO message(id, session_id, time_created, time_updated, data) VALUES
			('msg_asst', 'ses_1', 2000, 3000,
			 '{"role":"assistant","agent":"build","modelID":"gpt-5.4-nano","providerID":"openai","path":{"cwd":"/tmp/oc"},"time":{"created":2000,"completed":3000},"finish":"tool-calls"}')`,
		`INSERT INTO part(id, message_id, session_id, time_created, time_updated, data) VALUES
			('prt_step', 'msg_asst', 'ses_1', 2500, 3000, '{"type":"step-finish","reason":"tool-calls","tokens":{"input":7720,"output":199,"reasoning":76,"total":7995,"cache":{"read":0,"write":0}},"cost":0.00188775}')`,
	}
	for _, stmt := range stmts {
		if _, err := db.Exec(stmt); err != nil {
			t.Fatalf("exec %q: %v", stmt, err)
		}
	}
}

func setupOpenCodeDBWithAssistantText(t *testing.T, path string) {
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
		`CREATE TABLE session (id TEXT PRIMARY KEY, directory TEXT NOT NULL, time_updated INTEGER NOT NULL)`,
		`CREATE TABLE message (id TEXT PRIMARY KEY, session_id TEXT NOT NULL, time_created INTEGER NOT NULL, time_updated INTEGER NOT NULL, data TEXT NOT NULL)`,
		`CREATE TABLE part (id TEXT PRIMARY KEY, message_id TEXT NOT NULL, session_id TEXT NOT NULL, time_created INTEGER NOT NULL, time_updated INTEGER NOT NULL, data TEXT NOT NULL)`,
		`INSERT INTO session(id, directory, time_updated) VALUES ('ses_1', '/tmp/oc', 3000)`,
		`INSERT INTO message(id, session_id, time_created, time_updated, data) VALUES
			('msg_asst', 'ses_1', 2000, 2500,
			 '{"role":"assistant","agent":"build","modelID":"big-pickle","providerID":"opencode","path":{"cwd":"/tmp/oc"},"time":{"created":2000,"completed":2500},"finish":"stop"}'),
			('msg_user', 'ses_1', 1000, 1001,
			 '{"role":"user","agent":"build","time":{"created":1000}}')`,
		`INSERT INTO part(id, message_id, session_id, time_created, time_updated, data) VALUES
			('prt_user_text', 'msg_user', 'ses_1', 1000, 1001, '{"type":"text","text":"Run the thing"}'),
			('prt_asst_1', 'msg_asst', 'ses_1', 2100, 2200, '{"type":"text","text":"First reasoning chunk."}'),
			('prt_asst_2', 'msg_asst', 'ses_1', 2300, 2400, '{"type":"text","text":"Second reasoning chunk."}'),
			('prt_asst_empty', 'msg_asst', 'ses_1', 2350, 2400, '{"type":"text","text":"   "}')`,
	}
	for _, stmt := range stmts {
		if _, err := db.Exec(stmt); err != nil {
			t.Fatalf("exec %q: %v", stmt, err)
		}
	}
}

func setupOpenCodeDB(t *testing.T, path string) {
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
		`CREATE TABLE session (
			id TEXT PRIMARY KEY,
			directory TEXT NOT NULL,
			time_updated INTEGER NOT NULL
		)`,
		`CREATE TABLE message (
			id TEXT PRIMARY KEY,
			session_id TEXT NOT NULL,
			time_created INTEGER NOT NULL,
			time_updated INTEGER NOT NULL,
			data TEXT NOT NULL
		)`,
		`CREATE TABLE part (
			id TEXT PRIMARY KEY,
			message_id TEXT NOT NULL,
			session_id TEXT NOT NULL,
			time_created INTEGER NOT NULL,
			time_updated INTEGER NOT NULL,
			data TEXT NOT NULL
		)`,
		`INSERT INTO session(id, directory, time_updated) VALUES
			('ses_1', 'D:\\programsx\\open-code-test', 3000)`,
		`INSERT INTO message(id, session_id, time_created, time_updated, data) VALUES
			('msg_user', 'ses_1', 1000, 1001, '{"role":"user","agent":"build","model":{"providerID":"opencode","modelID":"big-pickle"},"time":{"created":1000}}'),
			('msg_tool', 'ses_1', 2000, 2500, '{"role":"assistant","agent":"build","modelID":"big-pickle","providerID":"opencode","path":{"cwd":"D:\\programsx\\open-code-test"},"time":{"created":2000,"completed":2500},"finish":"tool-calls"}'),
			('msg_done', 'ses_1', 2900, 3000, '{"role":"assistant","agent":"build","modelID":"big-pickle","providerID":"opencode","path":{"cwd":"D:\\programsx\\open-code-test"},"time":{"created":2900,"completed":3000},"finish":"stop"}')`,
		`INSERT INTO part(id, message_id, session_id, time_created, time_updated, data) VALUES
			('prt_prompt', 'msg_user', 'ses_1', 1000, 1001, '{"type":"text","text":"Build the app"}'),
			('prt_tool', 'msg_tool', 'ses_1', 2200, 2500, '{"type":"tool","tool":"bash","callID":"call_1","state":{"status":"completed","input":{"command":"npm start","description":"Run app"},"output":"boom","metadata":{"output":"boom","exit":1,"description":"Run app","truncated":false},"title":"Run app","time":{"start":2200,"end":2500}}}')`,
	}
	for _, stmt := range stmts {
		if _, err := db.Exec(stmt); err != nil {
			t.Fatalf("exec %q: %v", stmt, err)
		}
	}
}

// setupOpenCodeDBWithSubtask seeds a session with one subtask-typed
// part — the parent invoking an Explore subagent on a haiku model.
func setupOpenCodeDBWithSubtask(t *testing.T, path string) {
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
		`CREATE TABLE session (id TEXT PRIMARY KEY, directory TEXT NOT NULL, time_updated INTEGER NOT NULL)`,
		`CREATE TABLE message (id TEXT PRIMARY KEY, session_id TEXT NOT NULL, time_created INTEGER NOT NULL, time_updated INTEGER NOT NULL, data TEXT NOT NULL)`,
		`CREATE TABLE part (id TEXT PRIMARY KEY, message_id TEXT NOT NULL, session_id TEXT NOT NULL, time_created INTEGER NOT NULL, time_updated INTEGER NOT NULL, data TEXT NOT NULL)`,
		`INSERT INTO session(id, directory, time_updated) VALUES ('ses_1', '/tmp/oc', 3000)`,
		`INSERT INTO message(id, session_id, time_created, time_updated, data) VALUES
			('msg_a', 'ses_1', 2900, 3000,
			 '{"role":"assistant","agent":"build","modelID":"big-pickle","providerID":"opencode","path":{"cwd":"/tmp/oc"},"time":{"created":2900,"completed":3000},"finish":"tool-calls"}')`,
		`INSERT INTO part(id, message_id, session_id, time_created, time_updated, data) VALUES
			('prt_subtask', 'msg_a', 'ses_1', 2950, 3000,
			 '{"type":"subtask","prompt":"explore the codebase","description":"map the repo","agent":"Explore","model":{"providerID":"anthropic","modelID":"claude-haiku-4-5"},"time":{"created":2950}}')`,
	}
	for _, stmt := range stmts {
		if _, err := db.Exec(stmt); err != nil {
			t.Fatalf("exec %q: %v", stmt, err)
		}
	}
}

// setupOpenCodeDBWithTodos seeds the todo table with two entries —
// one pending, one completed — to exercise loadTodoEvents.
func setupOpenCodeDBWithTodos(t *testing.T, path string) {
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
		`CREATE TABLE session (id TEXT PRIMARY KEY, directory TEXT NOT NULL, time_updated INTEGER NOT NULL)`,
		`CREATE TABLE message (id TEXT PRIMARY KEY, session_id TEXT NOT NULL, time_created INTEGER NOT NULL, time_updated INTEGER NOT NULL, data TEXT NOT NULL)`,
		`CREATE TABLE part (id TEXT PRIMARY KEY, message_id TEXT NOT NULL, session_id TEXT NOT NULL, time_created INTEGER NOT NULL, time_updated INTEGER NOT NULL, data TEXT NOT NULL)`,
		`CREATE TABLE todo (
			session_id TEXT NOT NULL,
			content TEXT NOT NULL,
			status TEXT NOT NULL,
			priority TEXT NOT NULL,
			position INTEGER NOT NULL,
			time_created INTEGER NOT NULL,
			time_updated INTEGER NOT NULL,
			PRIMARY KEY (session_id, position)
		)`,
		`INSERT INTO session(id, directory, time_updated) VALUES ('ses_1', '/tmp/oc', 3000)`,
		`INSERT INTO todo VALUES
			('ses_1', 'Refactor module X', 'pending',     'high', 0, 1000, 1000),
			('ses_1', 'Run go test',       'completed',   'med',  1, 1100, 1500)`,
	}
	for _, stmt := range stmts {
		if _, err := db.Exec(stmt); err != nil {
			t.Fatalf("exec %q: %v", stmt, err)
		}
	}
}

// setupOpenCodeDBWithTokens seeds a minimal opencode.db with one
// assistant message carrying the full InfoData token bundle (input,
// output, reasoning, cache.read, cache.write, cost). Used by the
// token-event regression test to assert each field flows through.
func setupOpenCodeDBWithTokens(t *testing.T, path string) {
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
		`CREATE TABLE session (id TEXT PRIMARY KEY, directory TEXT NOT NULL, time_updated INTEGER NOT NULL)`,
		`CREATE TABLE message (id TEXT PRIMARY KEY, session_id TEXT NOT NULL, time_created INTEGER NOT NULL, time_updated INTEGER NOT NULL, data TEXT NOT NULL)`,
		`CREATE TABLE part (id TEXT PRIMARY KEY, message_id TEXT NOT NULL, session_id TEXT NOT NULL, time_created INTEGER NOT NULL, time_updated INTEGER NOT NULL, data TEXT NOT NULL)`,
		`INSERT INTO session(id, directory, time_updated) VALUES ('ses_1', '/tmp/oc', 3000)`,
		// Numbers chosen deliberately so each field's drop-through can
		// be asserted independently:
		//   input=1234, output=567, reasoning=89,
		//   cache.read=12345, cache.write=678, cost=0.0532
		`INSERT INTO message(id, session_id, time_created, time_updated, data) VALUES
			('msg_done', 'ses_1', 2900, 3000,
			 '{"role":"assistant","agent":"build","modelID":"big-pickle","providerID":"opencode","path":{"cwd":"/tmp/oc"},"time":{"created":2900,"completed":3000},"finish":"stop","tokens":{"input":1234,"output":567,"reasoning":89,"cache":{"read":12345,"write":678}},"cost":0.0532}')`,
	}
	for _, stmt := range stmts {
		if _, err := db.Exec(stmt); err != nil {
			t.Fatalf("exec %q: %v", stmt, err)
		}
	}
}

// TestLoadSessionLineages pins the session.parent_id → SessionLineage
// emission: linked children carry ParentThreadID + ThreadSource="subagent",
// unlinked/empty-parent rows are skipped, and a pre-parent_id schema
// degrades to "no linkage" instead of failing the parse.
func TestLoadSessionLineages(t *testing.T) {
	tests := []struct {
		name    string
		schema  string // session-table DDL (controls the parent_id column)
		rows    []string
		want    []models.SessionLineage
		wantNil bool
	}{
		{
			name:   "linked children emitted as subagent lineage",
			schema: `CREATE TABLE session (id TEXT PRIMARY KEY, directory TEXT NOT NULL, time_updated INTEGER NOT NULL, parent_id TEXT)`,
			rows: []string{
				`INSERT INTO session(id, directory, time_updated, parent_id) VALUES ('ses_parent', '/tmp/oc', 100, NULL)`,
				`INSERT INTO session(id, directory, time_updated, parent_id) VALUES ('ses_child1', '/tmp/oc', 200, 'ses_parent')`,
				`INSERT INTO session(id, directory, time_updated, parent_id) VALUES ('ses_child2', '/tmp/oc', 300, 'ses_parent')`,
			},
			want: []models.SessionLineage{
				{SessionID: "ses_child1", ParentThreadID: "ses_parent", ThreadSource: "subagent"},
				{SessionID: "ses_child2", ParentThreadID: "ses_parent", ThreadSource: "subagent"},
			},
		},
		{
			name:   "empty parent_id string skipped",
			schema: `CREATE TABLE session (id TEXT PRIMARY KEY, directory TEXT NOT NULL, time_updated INTEGER NOT NULL, parent_id TEXT)`,
			rows: []string{
				`INSERT INTO session(id, directory, time_updated, parent_id) VALUES ('ses_a', '/tmp/oc', 100, '')`,
				`INSERT INTO session(id, directory, time_updated, parent_id) VALUES ('ses_b', '/tmp/oc', 200, 'ses_a')`,
			},
			want: []models.SessionLineage{
				{SessionID: "ses_b", ParentThreadID: "ses_a", ThreadSource: "subagent"},
			},
		},
		{
			name:    "pre-parent_id schema degrades to no linkage",
			schema:  `CREATE TABLE session (id TEXT PRIMARY KEY, directory TEXT NOT NULL, time_updated INTEGER NOT NULL)`,
			rows:    []string{`INSERT INTO session(id, directory, time_updated) VALUES ('ses_1', '/tmp/oc', 100)`},
			wantNil: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			dbPath := filepath.Join(dir, "opencode.db")
			db, err := sql.Open("sqlite", dbPath)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := db.Exec(tt.schema); err != nil {
				t.Fatal(err)
			}
			for _, stmt := range tt.rows {
				if _, err := db.Exec(stmt); err != nil {
					t.Fatalf("exec %q: %v", stmt, err)
				}
			}
			db.Close()

			a := NewWithOptions(nil, []string{dir})
			got, err := a.loadSessionLineages(context.Background(), func() *sql.DB {
				d, err := openReadOnlyDB(dbPath)
				if err != nil {
					t.Fatal(err)
				}
				return d
			}())
			if err != nil {
				t.Fatalf("loadSessionLineages: %v", err)
			}
			if tt.wantNil {
				if got != nil {
					t.Fatalf("want nil lineages, got %v", got)
				}
				return
			}
			if len(got) != len(tt.want) {
				t.Fatalf("got %d lineages, want %d: %+v", len(got), len(tt.want), got)
			}
			for i, w := range tt.want {
				if got[i] != w {
					t.Errorf("lineage[%d] = %+v, want %+v", i, got[i], w)
				}
			}
		})
	}
}
