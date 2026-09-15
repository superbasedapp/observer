package kirocli

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/adapter"
	"github.com/marmutapp/superbased-observer/internal/models"
)

// The PRIMARY IDE fixture is an anonymized derivation of the operator's
// REAL Kiro IDE 1.0.411 session (captured 2026-09-03, Google sign-in,
// the five-step prompt kit). Every payload kind, tool name and arg
// shape below came off that capture — see testdata/kirocli/README.md
// for the derivation rules.
const (
	ideFixtureBucket  = "9f3c1d0b7a4e2856"
	ideFixtureSession = "sess_0a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d"
)

// The SHAPES fixture is the older bundle-derived synthetic one, kept
// because it carries payload shapes the real five-turn capture never
// produced: `tombstone`, `sub_agent_start`, `source:"steer"`,
// ARRAY-shaped `content`, an UNMAPPED tool name, the SYNTHETIC
// interrupted tool_result, and a `session.json` with `effortLevel`.
const (
	ideShapesBucket  = "a1b2c3d4e5f60718"
	ideShapesSession = "sess-ide-shapes-0001"
)

// stageIDEFixture copies the real-derived IDE fixture into a temp
// `.kiro/sessions/<bucket>/<sid>/` tree and returns (sessionsRoot,
// messagesPath). withSessionJSON=false omits the sibling state file so
// the missing-sibling path is exercised.
func stageIDEFixture(t *testing.T, withSessionJSON bool) (string, string) {
	t.Helper()
	return stageIDEFixtureFrom(t, ideFixtureBucket, ideFixtureSession, withSessionJSON)
}

// stageIDEShapesFixture stages the bundle-derived shape-variant fixture.
func stageIDEShapesFixture(t *testing.T, withSessionJSON bool) (string, string) {
	t.Helper()
	return stageIDEFixtureFrom(t, ideShapesBucket, ideShapesSession, withSessionJSON)
}

func stageIDEFixtureFrom(t *testing.T, bucket, session string, withSessionJSON bool) (string, string) {
	t.Helper()
	sessionsRoot := filepath.Join(t.TempDir(), ".kiro", "sessions")
	sessDir := filepath.Join(sessionsRoot, bucket, session)
	if err := os.MkdirAll(sessDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	names := []string{"messages.jsonl"}
	if withSessionJSON {
		names = append(names, "session.json")
	}
	for _, name := range names {
		src := filepath.Join("..", "..", "..", "testdata", "kirocli", "ide", bucket, session, name)
		body, err := os.ReadFile(src)
		if err != nil {
			t.Fatalf("read fixture %s: %v", name, err)
		}
		if err := os.WriteFile(filepath.Join(sessDir, name), body, 0o644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	return sessionsRoot, filepath.Join(sessDir, "messages.jsonl")
}

// TestClassifyLayoutMatrix pins the full path matrix across all three
// layouts — the `cli` bucket, a workspace-hash bucket, the excluded
// IDE siblings, and the sqlite family.
func TestClassifyLayoutMatrix(t *testing.T) {
	cases := []struct {
		name string
		path string
		want layout
	}{
		// Layout 1 — CLI flat bundles.
		{"flat json", "/home/u/.kiro/sessions/cli/abc.json", layoutFlat},
		{"flat jsonl", "/home/u/.kiro/sessions/cli/abc.jsonl", layoutFlat},
		{"flat windows", `C:\Users\u\.kiro\sessions\cli\abc.jsonl`, layoutFlat},
		{"flat history rejected", "/home/u/.kiro/sessions/cli/abc.history", layoutUnknown},
		{"flat lock rejected", "/home/u/.kiro/sessions/cli/abc.lock", layoutUnknown},

		// Layout 3 — Kiro IDE.
		{"ide hash bucket", "/home/u/.kiro/sessions/a1b2c3d4e5f60718/s1/messages.jsonl", layoutIDE},
		{"ide global bucket", "/home/u/.kiro/sessions/global/s1/messages.jsonl", layoutIDE},
		{"ide windows", `C:\Users\u\.kiro\sessions\a1b2c3d4e5f60718\s1\messages.jsonl`, layoutIDE},
		{"ide session.json is a sibling not a trigger", "/home/u/.kiro/sessions/a1b2c3d4e5f60718/s1/session.json", layoutUnknown},
		{"ide snapshots excluded", "/home/u/.kiro/sessions/a1b2c3d4e5f60718/s1/snapshots/snap-1/server.go", layoutUnknown},
		{"ide snapshots messages-named file excluded", "/home/u/.kiro/sessions/a1b2c3d4e5f60718/s1/snapshots/messages.jsonl", layoutUnknown},
		{"ide sub-executions excluded", "/home/u/.kiro/sessions/a1b2c3d4e5f60718/s1/sub-executions/exec-1.jsonl", layoutUnknown},
		{"ide bare bucket file excluded", "/home/u/.kiro/sessions/a1b2c3d4e5f60718/messages.jsonl", layoutUnknown},
		{"cli bucket never classifies as IDE", "/home/u/.kiro/sessions/cli/s1/messages.jsonl", layoutUnknown},

		// Layout 2 — SQLite.
		{"sqlite", "/home/u/.local/share/kiro-cli/data.sqlite3", layoutSQLite},
		{"sqlite wal", "/home/u/.local/share/kiro-cli/data.sqlite3-wal", layoutSQLite},
		{"sqlite shm", "/home/u/.local/share/kiro-cli/data.sqlite3-shm", layoutSQLite},
		{"sqlite windows", `C:\Users\u\AppData\Local\Kiro-Cli\data.sqlite3`, layoutSQLite},
		{"sqlite elsewhere", "/home/u/other/data.sqlite3", layoutUnknown},

		// Neither.
		{"unrelated json", "/home/u/project/session.json", layoutUnknown},
		{"unrelated messages.jsonl", "/home/u/project/messages.jsonl", layoutUnknown},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := classifyLayout(tc.path); got != tc.want {
				t.Errorf("classifyLayout(%q) = %d, want %d", tc.path, got, tc.want)
			}
		})
	}
}

// TestIsSessionFileIDERootGated proves the widened `.kiro/sessions`
// root still root-gates and still accepts the flat bundles.
func TestIsSessionFileIDERootGated(t *testing.T) {
	a := NewWithOptions(nil, "/home/dev/.kiro/sessions", "/home/dev/.local/share/kiro-cli")
	accept := []string{
		"/home/dev/.kiro/sessions/cli/abc.jsonl",
		"/home/dev/.kiro/sessions/cli/abc.json",
		"/home/dev/.kiro/sessions/a1b2c3d4e5f60718/s1/messages.jsonl",
		"/home/dev/.local/share/kiro-cli/data.sqlite3",
	}
	for _, p := range accept {
		if !a.IsSessionFile(p) {
			t.Errorf("IsSessionFile(%q) = false, want true", p)
		}
	}
	reject := []string{
		"/tmp/foreign/.kiro/sessions/a1b2c3d4e5f60718/s1/messages.jsonl", // right shape, wrong root
		"/home/dev/.kiro/sessions/a1b2c3d4e5f60718/s1/session.json",
		"/home/dev/.kiro/sessions/a1b2c3d4e5f60718/s1/snapshots/x.go",
		"/home/dev/.kiro/sessions/a1b2c3d4e5f60718/s1/sub-executions/e1.jsonl",
	}
	for _, p := range reject {
		if a.IsSessionFile(p) {
			t.Errorf("IsSessionFile(%q) = true, want false", p)
		}
	}
}

// TestIDELiveToolVocabulary is the grounded half of the record→row
// table: it walks the REAL five-turn capture and asserts every native
// Kiro IDE tool name lands on its taxonomy action rather than in the
// `unknown` bucket, which is exactly where all ten of them landed on
// the live daemon before this table existed.
func TestIDELiveToolVocabulary(t *testing.T) {
	root, messages := stageIDEFixture(t, true)
	a := NewWithOptions(nil, root)

	res, err := a.ParseSessionFile(context.Background(), messages, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	if len(res.Warnings) != 0 {
		t.Errorf("the real capture must parse without a single warning: %v", res.Warnings)
	}
	if len(res.TokenEvents) != 0 {
		t.Errorf("Kiro IDE persists no token counts; want 0 TokenEvents, got %d", len(res.TokenEvents))
	}

	// Every native tool name the capture contains, and the action it
	// must resolve to. `unknown` may not appear here at all.
	wantTools := map[string]string{
		"read_file":      models.ActionReadFile,
		"fs_write":       models.ActionWriteFile,
		"str_replace":    models.ActionEditFile,
		"delete_file":    models.ActionEditFile,
		"execute_pwsh":   models.ActionRunCommand,
		"list_directory": models.ActionSearchFiles,
		"todo_list":      models.ActionTodoUpdate,
		"tool_approval":  models.ActionPermissionRequest,
	}
	seenTools := map[string]bool{}
	counts := map[string]int{}
	for _, ev := range res.ToolEvents {
		counts[ev.ActionType]++
		if ev.ActionType == models.ActionUnknown {
			t.Errorf("row %q (raw %q) is still `unknown`", ev.SourceEventID, ev.RawToolName)
		}
		if ev.RawToolName == "" {
			continue
		}
		seenTools[ev.RawToolName] = true
		if want, ok := wantTools[ev.RawToolName]; ok && ev.ActionType != want {
			t.Errorf("%s: ActionType = %q, want %q", ev.RawToolName, ev.ActionType, want)
		}
		if ev.Target == "" {
			t.Errorf("row %q (raw %q) has a blank target", ev.SourceEventID, ev.RawToolName)
		}
	}
	for name := range wantTools {
		if !seenTools[name] {
			t.Errorf("the capture no longer exercises %q — fixture drift", name)
		}
	}

	// The per-action-type census of the operator's five-turn run. The
	// pre-fix live daemon recorded `unknown: 10` for the same session.
	wantCounts := map[string]int{
		models.ActionSessionStart:      1,
		models.ActionUserPrompt:        1,
		models.ActionAssistantMessage:  7,
		models.ActionReadFile:          1,
		models.ActionWriteFile:         1,
		models.ActionEditFile:          2, // str_replace + delete_file
		models.ActionRunCommand:        2,
		models.ActionSearchFiles:       1,
		models.ActionTodoUpdate:        4,
		models.ActionPermissionRequest: 4,
	}
	if !reflect.DeepEqual(counts, wantCounts) {
		t.Errorf("action_type census = %v, want %v", counts, wantCounts)
	}

	for _, ev := range res.ToolEvents {
		if ev.Tool != models.ToolKiroCLI {
			t.Errorf("%s: Tool = %q, want %q", ev.SourceEventID, ev.Tool, models.ToolKiroCLI)
		}
		if ev.SessionID != ideFixtureSession {
			t.Errorf("%s: SessionID = %q, want %q", ev.SourceEventID, ev.SessionID, ideFixtureSession)
		}
		if ev.SourceFile != messages {
			t.Errorf("%s: SourceFile = %q, want %q", ev.SourceEventID, ev.SourceFile, messages)
		}
		// `auto` is what Kiro IDE writes for an auto-mode session; the
		// concrete model is resolved server-side and never persisted.
		if ev.Model != "auto" {
			t.Errorf("%s: Model = %q, want \"auto\"", ev.SourceEventID, ev.Model)
		}
		// The live session.json carries NO effortLevel key, so no row
		// may invent one.
		if ev.Metadata != nil {
			t.Errorf("%s: Metadata = %+v, want nil (the live session.json has no effortLevel)",
				ev.SourceEventID, ev.Metadata)
		}
	}
}

// TestIDETodoListSubCommandIsNotAToolName pins the finding that made the
// live capture read as noise: `create` and `complete` are the
// `todo_list` SUB-COMMAND, surfacing as targets only because
// genericToolTarget probes the `command` arg key on an unmapped tool.
// They must now ride an honest todo_update row.
func TestIDETodoListSubCommandIsNotAToolName(t *testing.T) {
	root, messages := stageIDEFixture(t, true)
	a := NewWithOptions(nil, root)
	res, err := a.ParseSessionFile(context.Background(), messages, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	got := map[string]int{}
	for _, ev := range res.ToolEvents {
		if ev.RawToolName == "todo_list" {
			got[ev.Target]++
			if ev.ActionType != models.ActionTodoUpdate {
				t.Errorf("todo_list row %q = %q, want todo_update", ev.SourceEventID, ev.ActionType)
			}
		}
	}
	if !reflect.DeepEqual(got, map[string]int{"create": 1, "complete": 3}) {
		t.Errorf("todo_list sub-commands = %v, want {create:1 complete:3}", got)
	}
}

// TestIDEApprovalOutcomeStamped pins the approval pair: every
// pending_interaction becomes a permission_request row, and its
// interaction_resolved stamps the verdict onto that same row rather
// than emitting a second one.
func TestIDEApprovalOutcomeStamped(t *testing.T) {
	root, messages := stageIDEFixture(t, true)
	a := NewWithOptions(nil, root)
	res, err := a.ParseSessionFile(context.Background(), messages, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	approvals := 0
	for _, ev := range res.ToolEvents {
		if ev.ActionType != models.ActionPermissionRequest {
			continue
		}
		approvals++
		if !strings.HasPrefix(ev.SourceEventID, "perm:") {
			t.Errorf("approval row id %q must carry the perm: prefix", ev.SourceEventID)
		}
		if ev.RawToolName != "tool_approval" {
			t.Errorf("approval RawToolName = %q, want tool_approval", ev.RawToolName)
		}
		// Every approval in the capture was accepted (allow_once).
		if !ev.Success || ev.OutcomePending {
			t.Errorf("approval %q: success=%v pending=%v, want an accepted, resolved row",
				ev.SourceEventID, ev.Success, ev.OutcomePending)
		}
		if ev.RawToolInput == "" {
			t.Errorf("approval %q lost its options array", ev.SourceEventID)
		}
	}
	if approvals != 4 {
		t.Errorf("permission_request rows = %d, want 4", approvals)
	}
	if len(res.OutcomeUpdates) != 0 {
		t.Errorf("every approval resolved in-window; want 0 OutcomeUpdates, got %d", len(res.OutcomeUpdates))
	}
}

// TestIDEInteractionGrantedTable is the outcome rule table, one case per
// row plus the fail-open default.
func TestIDEInteractionGrantedTable(t *testing.T) {
	cases := []struct {
		name    string
		kind    string
		payload idePayload
		want    bool
	}{
		{"allow_once kind", "allow_once", idePayload{Outcome: "selected", SelectedOption: "accept"}, true},
		{"reject_once kind", "reject_once", idePayload{Outcome: "selected", SelectedOption: "reject"}, false},
		{"kind unknown, option id rejects", "", idePayload{Outcome: "selected", SelectedOption: "reject"}, false},
		{"kind unknown, option id accepts", "", idePayload{Outcome: "selected", SelectedOption: "accept"}, true},
		{"cancelled outcome", "", idePayload{Outcome: "cancelled"}, false},
		{"fail-open on an unknown vocabulary", "", idePayload{Outcome: "selected", SelectedOption: "later"}, true},
		{"fail-open on nothing at all", "", idePayload{}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := interactionGranted(tc.kind, tc.payload); got != tc.want {
				t.Errorf("interactionGranted(%q, %+v) = %v, want %v", tc.kind, tc.payload, got, tc.want)
			}
		})
	}
}

// TestIDEPayloadUnion is the record→row table over the SHAPES fixture:
// one row per payload type, asserting exactly what each emits (or that
// it emits nothing). It covers the shapes the real five-turn capture
// never produced.
func TestIDEPayloadUnion(t *testing.T) {
	root, messages := stageIDEShapesFixture(t, true)
	a := NewWithOptions(nil, root)

	res, err := a.ParseSessionFile(context.Background(), messages, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	if len(res.Warnings) != 0 {
		t.Errorf("the grounded payload union must not warn: %v", res.Warnings)
	}
	if len(res.TokenEvents) != 0 {
		t.Errorf("Kiro IDE persists no token counts; want 0 TokenEvents, got %d", len(res.TokenEvents))
	}

	byID := map[string]models.ToolEvent{}
	for _, ev := range res.ToolEvents {
		if _, dup := byID[ev.SourceEventID]; dup {
			t.Errorf("duplicate SourceEventID %q", ev.SourceEventID)
		}
		byID[ev.SourceEventID] = ev
	}

	want := []struct {
		record  string // the payload type / operationType the row comes from
		eventID string
		action  string
		target  string
	}{
		{"session_start", "session_start_sess-ide-shapes-0001_autopilot", models.ActionSessionStart, "autopilot"},
		{"user (string content)", "u-0001", models.ActionUserPrompt, ""},
		{"assistant Say", "a-0002", models.ActionAssistantMessage, "Reading the router."},
		{"tool_call fs_read", "tool:tc-0001", models.ActionReadFile, "/home/<u>/dev/project/server.go"},
		{"tool_call fs_write", "tool:tc-0002", models.ActionWriteFile, "/home/<u>/dev/project/health.go"},
		{"assistant Print", "a-0003", models.ActionAssistantMessage, "Added the /healthz handler."},
		{"assistant Summary", "a-0004", models.ActionContextCompacted, "So far: read the router, added health.go."},
		{"tool_call unmapped", "tool:tc-0003", models.ActionUnknown, "go test ./..."},
		{"user (block content, steer)", "u-0002", models.ActionUserPrompt, "also add a readiness probe"},
	}
	if len(res.ToolEvents) != len(want) {
		t.Fatalf("emitted %d events, want %d: %+v", len(res.ToolEvents), len(want), res.ToolEvents)
	}
	for _, w := range want {
		ev, ok := byID[w.eventID]
		if !ok {
			t.Errorf("%s: no event with SourceEventID %q", w.record, w.eventID)
			continue
		}
		if ev.ActionType != w.action {
			t.Errorf("%s: ActionType = %q, want %q", w.record, ev.ActionType, w.action)
		}
		if w.target != "" && ev.Target != w.target {
			t.Errorf("%s: Target = %q, want %q", w.record, ev.Target, w.target)
		}
		if ev.Tool != models.ToolKiroCLI {
			t.Errorf("%s: Tool = %q, want %q", w.record, ev.Tool, models.ToolKiroCLI)
		}
		if ev.SessionID != ideShapesSession {
			t.Errorf("%s: SessionID = %q, want %q", w.record, ev.SessionID, ideShapesSession)
		}
		if ev.SourceFile != messages {
			t.Errorf("%s: SourceFile = %q, want %q", w.record, ev.SourceFile, messages)
		}
		if ev.Model != "kiro-sonnet-4" {
			t.Errorf("%s: Model = %q, want kiro-sonnet-4", w.record, ev.Model)
		}
		if ev.Metadata == nil || ev.Metadata.EffortLevel != "high" {
			t.Errorf("%s: EffortLevel metadata = %+v, want high", w.record, ev.Metadata)
		}
	}

	// An unmapped tool still carries its raw name.
	if ev := byID["tool:tc-0003"]; ev.RawToolName != "open_cli_terminal" {
		t.Errorf("unmapped tool lost its raw name: %q", ev.RawToolName)
	}

	// No-row record types: nothing anywhere carries their ids.
	for _, noRow := range []string{
		"a-0001",               // assistant Reasoning
		"exec-0001-turn-start", // turn_start
		"exec-0001-turn-end",   // turn_end
		"meta-0001",            // session_metadata
		"evt-0001",             // session_event
		"sub-0001",             // sub_agent_start
		"tomb-0001",            // tombstone
	} {
		if _, ok := byID[noRow]; ok {
			t.Errorf("record %q must emit no row", noRow)
		}
	}
}

// TestIDEUnmappedToolFallsBackToRawName pins the blank-target fix: the
// live `delete_file` shape (`targetFile` + `explanation`) used to land a
// row with an EMPTY target because the probe table did not know the key.
// A tool with NO recognised operand at all now shows its raw name.
func TestIDEUnmappedToolFallsBackToRawName(t *testing.T) {
	sessionsRoot := filepath.Join(t.TempDir(), ".kiro", "sessions")
	dir := filepath.Join(sessionsRoot, "abcdefabcdefabcd", "s-unmapped")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	body := `{"id":"c1","timestamp":"2026-09-03T12:00:00.000Z","payload":{"type":"tool_call","toolCallId":"tc-1","toolName":"some_future_tool","args":{"explanation":"why"}}}` + "\n"
	messages := filepath.Join(dir, "messages.jsonl")
	if err := os.WriteFile(messages, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	a := NewWithOptions(nil, sessionsRoot)
	res, err := a.ParseSessionFile(context.Background(), messages, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	if len(res.ToolEvents) != 1 {
		t.Fatalf("want 1 event, got %d", len(res.ToolEvents))
	}
	ev := res.ToolEvents[0]
	if ev.ActionType != models.ActionUnknown {
		t.Errorf("ActionType = %q, want unknown", ev.ActionType)
	}
	if ev.RawToolName != "some_future_tool" || ev.Target != "some_future_tool" {
		t.Errorf("raw=%q target=%q — an unmapped tool must keep its name in BOTH", ev.RawToolName, ev.Target)
	}
}

// TestIDEReasoningRidesNextEvent asserts an assistant Reasoning record
// emits no row of its own but lands on the next event's
// PrecedingReasoning (and is consumed there, not repeated).
//
// It runs on the SHAPES fixture because the real capture's Reasoning
// bodies are all the literal ellipsis Kiro persists in place of the
// hidden text (see TestIDELiveReasoningIsElided) — real, but useless
// for asserting the carry.
func TestIDEReasoningRidesNextEvent(t *testing.T) {
	root, messages := stageIDEShapesFixture(t, true)
	a := NewWithOptions(nil, root)
	res, err := a.ParseSessionFile(context.Background(), messages, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	var carried, repeats int
	for _, ev := range res.ToolEvents {
		if ev.PrecedingReasoning == "" {
			continue
		}
		carried++
		if ev.SourceEventID != "a-0002" {
			repeats++
		}
		if !strings.Contains(ev.PrecedingReasoning, "server.go") {
			t.Errorf("PrecedingReasoning = %q, want the Reasoning body", ev.PrecedingReasoning)
		}
	}
	if carried != 1 || repeats != 0 {
		t.Errorf("reasoning carried onto %d events (%d wrong ones), want exactly 1 (a-0002)", carried, repeats)
	}
}

// TestIDELiveReasoningIsElided records what the real capture proves
// about Kiro IDE reasoning: the harness writes the ENCRYPTED
// `reasoningSignature` but replaces the body with a literal ellipsis, so
// there is no reasoning prose to capture on this surface — an
// honest-absent, not a parser gap.
func TestIDELiveReasoningIsElided(t *testing.T) {
	root, messages := stageIDEFixture(t, true)
	a := NewWithOptions(nil, root)
	res, err := a.ParseSessionFile(context.Background(), messages, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	for _, ev := range res.ToolEvents {
		if r := ev.PrecedingReasoning; r != "" && r != "..." {
			t.Errorf("%s: PrecedingReasoning = %q, want the elided ellipsis Kiro persists",
				ev.SourceEventID, r)
		}
	}
}

// TestIDEToolResultCorrelation covers both correlation paths: an
// in-window result stamps its row, and the SYNTHETIC interrupted result
// flips success + fills the error message. It runs on the SHAPES
// fixture — the real capture has no interrupted call.
func TestIDEToolResultCorrelation(t *testing.T) {
	root, messages := stageIDEShapesFixture(t, true)
	a := NewWithOptions(nil, root)
	res, err := a.ParseSessionFile(context.Background(), messages, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	byID := map[string]models.ToolEvent{}
	for _, ev := range res.ToolEvents {
		byID[ev.SourceEventID] = ev
	}

	ok := byID["tool:tc-0001"]
	if !ok.Success || ok.DurationMs != 12 || !strings.Contains(ok.ToolOutput, "package main") {
		t.Errorf("successful result not stamped: success=%v dur=%d out=%q", ok.Success, ok.DurationMs, ok.ToolOutput)
	}
	if ok.OutcomePending {
		t.Errorf("tool:tc-0001 saw its result in-window; OutcomePending must be false")
	}

	interrupted := byID["tool:tc-0003"]
	if interrupted.Success {
		t.Errorf("synthetic interrupted result must set Success=false")
	}
	if !strings.Contains(interrupted.ErrorMessage, "session was interrupted") {
		t.Errorf("ErrorMessage = %q, want the interrupted text", interrupted.ErrorMessage)
	}
	if len(res.OutcomeUpdates) != 0 {
		t.Errorf("all results landed in-window; want 0 OutcomeUpdates, got %d", len(res.OutcomeUpdates))
	}
}

// TestIDEToolResultCrossWindow proves a result parsed in a LATER window
// than its call goes out as an ActionOutcomeUpdate whose key the emit
// side can rebuild from the toolCallId alone.
func TestIDEToolResultCrossWindow(t *testing.T) {
	dir := filepath.Join(t.TempDir(), ".kiro", "sessions", "b0b0b0b0b0b0b0b0", "s-split")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	call := `{"id":"act-1","timestamp":"2026-09-02T10:00:00.000Z","payload":{"type":"tool_call","toolCallId":"tc-9","toolName":"execute_bash","args":{"command":"go build ./..."},"status":"running"}}` + "\n"
	result := `{"id":"act-1-result","timestamp":"2026-09-02T10:00:01.000Z","payload":{"type":"tool_result","toolCallId":"tc-9","content":"build failed","success":false,"durationMs":77,"executionId":"e1"}}` + "\n"
	messages := filepath.Join(dir, "messages.jsonl")
	if err := os.WriteFile(messages, []byte(call), 0o644); err != nil {
		t.Fatal(err)
	}
	// Watch root = the `<home>/.kiro/sessions` parent of the bucket dir.
	a := NewWithOptions(nil, filepath.Dir(filepath.Dir(dir)))

	first, err := a.ParseSessionFile(context.Background(), messages, 0)
	if err != nil {
		t.Fatalf("window 1: %v", err)
	}
	if len(first.ToolEvents) != 1 {
		t.Fatalf("window 1 emitted %d events, want 1", len(first.ToolEvents))
	}
	if !first.ToolEvents[0].OutcomePending {
		t.Errorf("a call whose result never arrived in-window must be OutcomePending")
	}
	callKey := first.ToolEvents[0].SourceEventID

	if err := os.WriteFile(messages, []byte(call+result), 0o644); err != nil {
		t.Fatal(err)
	}
	second, err := a.ParseSessionFile(context.Background(), messages, first.NewOffset)
	if err != nil {
		t.Fatalf("window 2: %v", err)
	}
	if len(second.ToolEvents) != 0 {
		t.Errorf("window 2 must re-emit nothing, got %+v", second.ToolEvents)
	}
	if len(second.OutcomeUpdates) != 1 {
		t.Fatalf("window 2 OutcomeUpdates = %d, want 1", len(second.OutcomeUpdates))
	}
	up := second.OutcomeUpdates[0]
	if up.SourceEventID != callKey {
		t.Errorf("OutcomeUpdate key = %q, want the call row's %q", up.SourceEventID, callKey)
	}
	if up.SourceFile != messages {
		t.Errorf("OutcomeUpdate SourceFile = %q, want %q", up.SourceFile, messages)
	}
	if !up.SuccessKnown || up.Success {
		t.Errorf("OutcomeUpdate verdict = (known %v, success %v), want (true, false)", up.SuccessKnown, up.Success)
	}
	if up.DurationMs != 77 {
		t.Errorf("OutcomeUpdate DurationMs = %d, want 77", up.DurationMs)
	}
}

// TestIDETurnIndexSpansWindows is the K1 regression pin: a byte-offset
// tail resumes mid-file, so a window-local turn counter would restart at
// 0 and the third turn would collide with the first. TurnIndex must
// count turns from the START OF THE FILE regardless of where the parse
// window begins.
func TestIDETurnIndexSpansWindows(t *testing.T) {
	dir := filepath.Join(t.TempDir(), ".kiro", "sessions", "c0c0c0c0c0c0c0c0", "s-turns")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	// One line per turn: turn_start brackets it, the `user` record
	// inside it must NOT advance the counter a second time.
	turn := func(n int) string {
		return fmt.Sprintf(
			`{"id":"ts-%d","timestamp":"2026-09-02T10:0%d:00.000Z","payload":{"type":"turn_start"}}`+"\n"+
				`{"id":"u-%d","timestamp":"2026-09-02T10:0%d:01.000Z","payload":{"type":"user","content":{"text":"prompt %d"}}}`+"\n"+
				`{"id":"te-%d","timestamp":"2026-09-02T10:0%d:02.000Z","payload":{"type":"turn_end"}}`+"\n",
			n, n, n, n, n, n, n)
	}
	messages := filepath.Join(dir, "messages.jsonl")
	window1 := turn(0) + turn(1)
	if err := os.WriteFile(messages, []byte(window1), 0o644); err != nil {
		t.Fatal(err)
	}
	a := NewWithOptions(nil, filepath.Dir(filepath.Dir(dir)))

	first, err := a.ParseSessionFile(context.Background(), messages, 0)
	if err != nil {
		t.Fatalf("window 1: %v", err)
	}
	if got := turnIndexes(first); !reflect.DeepEqual(got, []int{0, 1}) {
		t.Fatalf("window 1 TurnIndexes = %v, want [0 1]", got)
	}

	if err := os.WriteFile(messages, []byte(window1+turn(2)), 0o644); err != nil {
		t.Fatal(err)
	}
	second, err := a.ParseSessionFile(context.Background(), messages, first.NewOffset)
	if err != nil {
		t.Fatalf("window 2: %v", err)
	}
	if got := turnIndexes(second); !reflect.DeepEqual(got, []int{2}) {
		t.Fatalf("window 2 TurnIndexes = %v, want [2] (a window-local counter would give [0])", got)
	}

	// And a third window resuming inside the SAME turn must not
	// double-advance: a steer `user` record arriving after the window
	// boundary rides the turn that is already open.
	steer := `{"id":"ts-3","timestamp":"2026-09-02T10:03:00.000Z","payload":{"type":"turn_start"}}` + "\n"
	body := window1 + turn(2) + steer
	if err := os.WriteFile(messages, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	third, err := a.ParseSessionFile(context.Background(), messages, second.NewOffset)
	if err != nil {
		t.Fatalf("window 3: %v", err)
	}
	steerUser := `{"id":"u-3","timestamp":"2026-09-02T10:03:01.000Z","payload":{"type":"user","content":{"text":"steer"}}}` + "\n"
	if err := os.WriteFile(messages, []byte(body+steerUser), 0o644); err != nil {
		t.Fatal(err)
	}
	fourth, err := a.ParseSessionFile(context.Background(), messages, third.NewOffset)
	if err != nil {
		t.Fatalf("window 4: %v", err)
	}
	if got := turnIndexes(fourth); !reflect.DeepEqual(got, []int{3}) {
		t.Fatalf("window 4 TurnIndexes = %v, want [3] — the turn opened by the "+
			"turn_start in window 3, not a fresh one", got)
	}
}

func turnIndexes(res adapter.ParseResult) []int {
	out := make([]int, 0, len(res.ToolEvents))
	for _, ev := range res.ToolEvents {
		out = append(out, ev.TurnIndex)
	}
	return out
}

// TestIDEMissingSessionJSON proves the parse still runs (and still
// stamps the surface) when the sibling state file has not been flushed.
func TestIDEMissingSessionJSON(t *testing.T) {
	root, messages := stageIDEFixture(t, false)
	a := NewWithOptions(nil, root)
	res, err := a.ParseSessionFile(context.Background(), messages, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	if len(res.ToolEvents) == 0 {
		t.Fatalf("want events with no session.json, got none")
	}
	for _, ev := range res.ToolEvents {
		if ev.ProjectRoot != "" {
			t.Errorf("ProjectRoot = %q, want empty with no session.json", ev.ProjectRoot)
		}
		if ev.Model != "" {
			t.Errorf("Model = %q, want empty with no session.json", ev.Model)
		}
		if ev.Metadata != nil {
			t.Errorf("Metadata = %+v, want nil with no effortLevel", ev.Metadata)
		}
		if ev.SessionID != ideFixtureSession {
			t.Errorf("SessionID = %q, want the directory name %q", ev.SessionID, ideFixtureSession)
		}
	}
	if len(res.SessionSurfaces) != 1 {
		t.Fatalf("want 1 surface stamp, got %d", len(res.SessionSurfaces))
	}
}

// TestIDEScrubsUserPrompt pins the scrub pass on the IDE path.
func TestIDEScrubsUserPrompt(t *testing.T) {
	root, messages := stageIDEFixture(t, true)
	a := NewWithOptions(nil, root)
	res, err := a.ParseSessionFile(context.Background(), messages, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	for _, ev := range res.ToolEvents {
		if strings.Contains(ev.Target, "sk-ant-api03-DEADBEEF") {
			t.Fatalf("unscrubbed secret in %s Target: %q", ev.SourceEventID, ev.Target)
		}
		if strings.Contains(ev.RawToolInput, "sk-ant-api03-DEADBEEF") {
			t.Fatalf("unscrubbed secret in %s RawToolInput", ev.SourceEventID)
		}
	}
}

// TestIDECRLFSafe asserts the byte cursor and the decode both survive
// Windows line endings and interspersed blank lines.
func TestIDECRLFSafe(t *testing.T) {
	sessionsRoot := filepath.Join(t.TempDir(), ".kiro", "sessions")
	dir := filepath.Join(sessionsRoot, "c0ffee00c0ffee00", "s-crlf")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	lines := []string{
		`{"id":"u1","timestamp":"2026-09-02T10:00:00.000Z","payload":{"type":"user","content":"hi"}}`,
		``,
		`{"id":"a1","timestamp":"2026-09-02T10:00:01.000Z","payload":{"type":"assistant","content":"yo","operationType":"Say"}}`,
	}
	body := strings.Join(lines, "\r\n") + "\r\n"
	messages := filepath.Join(dir, "messages.jsonl")
	if err := os.WriteFile(messages, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	a := NewWithOptions(nil, sessionsRoot)
	res, err := a.ParseSessionFile(context.Background(), messages, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	if len(res.ToolEvents) != 2 {
		t.Fatalf("CRLF parse produced %d events, want 2; warnings=%v", len(res.ToolEvents), res.Warnings)
	}
	if len(res.Warnings) != 0 {
		t.Errorf("CRLF / blank lines must not warn: %v", res.Warnings)
	}
	if res.NewOffset != int64(len(body)) {
		t.Errorf("NewOffset = %d, want %d (the whole file)", res.NewOffset, len(body))
	}
}

// TestIDEMalformedLineAdvances pins §4.6: warn, advance past the
// garbage, keep parsing.
func TestIDEMalformedLineAdvances(t *testing.T) {
	sessionsRoot := filepath.Join(t.TempDir(), ".kiro", "sessions")
	dir := filepath.Join(sessionsRoot, "deadbeefdeadbeef", "s-bad")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	body := strings.Join([]string{
		`{"id":"u1","timestamp":"2026-09-02T10:00:00.000Z","payload":{"type":"user","content":"hi"}}`,
		`{"id":"broken",`,
		`{"id":"a1","timestamp":"2026-09-02T10:00:02.000Z","payload":{"type":"assistant","content":"yo","operationType":"Say"}}`,
		`{"id":"x1","timestamp":"2026-09-02T10:00:03.000Z","payload":{"type":"brand_new_type"}}`,
	}, "\n") + "\n"
	messages := filepath.Join(dir, "messages.jsonl")
	if err := os.WriteFile(messages, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	a := NewWithOptions(nil, sessionsRoot)
	res, err := a.ParseSessionFile(context.Background(), messages, 0)
	if err != nil {
		t.Fatalf("a malformed line must not fail the parse: %v", err)
	}
	if len(res.ToolEvents) != 2 {
		t.Errorf("want 2 events around the malformed line, got %d", len(res.ToolEvents))
	}
	if len(res.Warnings) != 2 {
		t.Errorf("want 2 warnings (malformed line + unknown payload type), got %v", res.Warnings)
	}
	if res.NewOffset != int64(len(body)) {
		t.Errorf("NewOffset = %d, want %d — the cursor must clear the garbage", res.NewOffset, len(body))
	}
}

// TestIDEPartialTrailingLineDeferred proves a record still being
// written is NOT consumed: the cursor stops before it.
func TestIDEPartialTrailingLineDeferred(t *testing.T) {
	sessionsRoot := filepath.Join(t.TempDir(), ".kiro", "sessions")
	dir := filepath.Join(sessionsRoot, "1234123412341234", "s-partial")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	complete := `{"id":"u1","timestamp":"2026-09-02T10:00:00.000Z","payload":{"type":"user","content":"hi"}}` + "\n"
	partial := `{"id":"a1","timestamp":"2026-09-02T10`
	messages := filepath.Join(dir, "messages.jsonl")
	if err := os.WriteFile(messages, []byte(complete+partial), 0o644); err != nil {
		t.Fatal(err)
	}
	a := NewWithOptions(nil, sessionsRoot)
	res, err := a.ParseSessionFile(context.Background(), messages, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	if res.NewOffset != int64(len(complete)) {
		t.Errorf("NewOffset = %d, want %d (before the partial record)", res.NewOffset, len(complete))
	}
	if len(res.Warnings) != 0 {
		t.Errorf("a partial trailing line is not malformed; want no warning, got %v", res.Warnings)
	}
}

// TestSurfacePerLayout is the surface table: one row per layout.
func TestSurfacePerLayout(t *testing.T) {
	cases := []struct {
		layout      layout
		wantSurface string
		wantHost    string
	}{
		{layoutFlat, models.SurfaceCLI, "kiro-cli"},
		{layoutSQLite, models.SurfaceCLI, "kiro-cli"},
		{layoutIDE, models.SurfaceIDE, "kiro"},
	}
	for _, tc := range cases {
		got := surfaceFor(tc.layout, "s1")
		if got.SessionID != "s1" || got.Surface != tc.wantSurface || got.SurfaceHost != tc.wantHost {
			t.Errorf("surfaceFor(%d) = %+v, want {s1 %s %s}", tc.layout, got, tc.wantSurface, tc.wantHost)
		}
		if !models.KnownSurface(got.Surface) {
			t.Errorf("surfaceFor(%d) emitted an out-of-vocabulary kind %q", tc.layout, got.Surface)
		}
	}
	// Honesty rule: no layout, or no session id ⇒ no stamp.
	if got := surfaceFor(layoutUnknown, "s1"); got != (models.SessionSurface{}) {
		t.Errorf("surfaceFor(layoutUnknown) = %+v, want the zero value", got)
	}
	if got := surfaceFor(layoutIDE, ""); got != (models.SessionSurface{}) {
		t.Errorf("surfaceFor with no session id = %+v, want the zero value", got)
	}
}

// TestIDESurfaceStamped asserts the IDE parse emits exactly one
// ide/kiro stamp for its own session.
func TestIDESurfaceStamped(t *testing.T) {
	root, messages := stageIDEFixture(t, true)
	a := NewWithOptions(nil, root)
	res, err := a.ParseSessionFile(context.Background(), messages, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	if len(res.SessionSurfaces) != 1 {
		t.Fatalf("SessionSurfaces = %+v, want exactly 1", res.SessionSurfaces)
	}
	got := res.SessionSurfaces[0]
	want := models.SessionSurface{SessionID: ideFixtureSession, Surface: models.SurfaceIDE, SurfaceHost: "kiro"}
	if got != want {
		t.Errorf("SessionSurfaces[0] = %+v, want %+v", got, want)
	}
}

// TestFlatSurfaceStamped pins the CLI half of the surface table on the
// real flat-bundle path.
func TestFlatSurfaceStamped(t *testing.T) {
	dir := filepath.Join(t.TempDir(), ".kiro", "sessions", "cli")
	id := "sess-surface"
	copyFixtureBundle(t, "flat-with-metadata", dir, id)
	a := NewWithOptions(nil, filepath.Dir(dir))

	res, err := a.ParseSessionFile(context.Background(), filepath.Join(dir, id+".jsonl"), 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	want := models.SessionSurface{SessionID: id, Surface: models.SurfaceCLI, SurfaceHost: "kiro-cli"}
	if len(res.SessionSurfaces) != 1 || res.SessionSurfaces[0] != want {
		t.Errorf("SessionSurfaces = %+v, want [%+v]", res.SessionSurfaces, want)
	}
}

// TestIDESessionIDDivergenceWarns pins §4.5a: the DIRECTORY name is the
// canonical session id and a session.json `id` that disagrees is
// reported, never adopted.
func TestIDESessionIDDivergenceWarns(t *testing.T) {
	sessionsRoot := filepath.Join(t.TempDir(), ".kiro", "sessions")
	dir := filepath.Join(sessionsRoot, "5555555555555555", "dir-id")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	state := `{"schemaVersion":"1.0","id":"OTHER-ID","workspacePaths":[]}`
	if err := os.WriteFile(filepath.Join(dir, "session.json"), []byte(state), 0o644); err != nil {
		t.Fatal(err)
	}
	line := `{"id":"u1","timestamp":"2026-09-02T10:00:00.000Z","payload":{"type":"user","content":"hi"}}` + "\n"
	messages := filepath.Join(dir, "messages.jsonl")
	if err := os.WriteFile(messages, []byte(line), 0o644); err != nil {
		t.Fatal(err)
	}
	a := NewWithOptions(nil, sessionsRoot)
	res, err := a.ParseSessionFile(context.Background(), messages, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	if len(res.ToolEvents) != 1 || res.ToolEvents[0].SessionID != "dir-id" {
		t.Fatalf("SessionID must stay the directory name, got %+v", res.ToolEvents)
	}
	if len(res.Warnings) != 1 || !strings.Contains(res.Warnings[0], "OTHER-ID") {
		t.Errorf("want a divergence warning naming the session.json id, got %v", res.Warnings)
	}
}

// TestIDECursorSemanticsAreByteOffset confirms the new path resolves to
// the DEFAULT (byte-offset) cursor semantics.
func TestIDECursorSemanticsAreByteOffset(t *testing.T) {
	a := NewWithOptions(nil, "/home/dev/.kiro/sessions")
	got := a.CursorSemanticsFor("/home/dev/.kiro/sessions/a1b2c3d4e5f60718/s1/messages.jsonl")
	if got.Kind != adapter.CursorByteOffset {
		t.Errorf("CursorSemanticsFor(IDE messages.jsonl).Kind = %v, want CursorByteOffset", got.Kind)
	}
}

// TestIDEContentPolymorphism pins the tolerant `content` decode
// (checklist §4.4d) across every observed shape.
func TestIDEContentPolymorphism(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want string
	}{
		{"string", `"hello"`, "hello"},
		{"block array", `[{"type":"text","text":"a"},{"type":"text","text":"b"}]`, "ab"},
		{"block array mixed", `[{"type":"image","text":"skip"},{"type":"text","text":"keep"}]`, "keep"},
		{"single object", `{"type":"text","text":"solo"}`, "solo"},
		{"null", `null`, ""},
		{"number (unhandled shape)", `42`, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var c ideContent
			if err := c.UnmarshalJSON([]byte(tc.raw)); err != nil {
				t.Fatalf("UnmarshalJSON(%s) errored: %v", tc.raw, err)
			}
			if c.Text != tc.want {
				t.Errorf("UnmarshalJSON(%s).Text = %q, want %q", tc.raw, c.Text, tc.want)
			}
		})
	}
}

// TestIDETranscriptRoundTrip proves ReadTranscript resolves an IDE
// session from the widened watch root.
func TestIDETranscriptRoundTrip(t *testing.T) {
	root, _ := stageIDEFixture(t, true)
	a := NewWithOptions(nil, root)
	msgs, err := a.ReadTranscript(context.Background(), models.Session{ID: ideFixtureSession}, nil)
	if err != nil {
		t.Fatalf("ReadTranscript: %v", err)
	}
	if len(msgs) < 2 {
		t.Fatalf("want >=2 transcript messages, got %d", len(msgs))
	}
	if msgs[0].Role != models.TranscriptUser {
		t.Errorf("first message role = %v, want user", msgs[0].Role)
	}
}
