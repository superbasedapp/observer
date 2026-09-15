package taskflow

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fixtureLine mirrors the JSON shape of each testdata/taskflow/*.jsonl
// line — the (tool, raw_tool_name, raw_tool_input, raw_tool_output)
// projection ActionInput needs, minus the session/action/timestamp
// bookkeeping a real actions row carries (filled in with fixed test
// values below, since Decode doesn't inspect them for these fixtures).
type fixtureLine struct {
	Tool          string `json:"tool"`
	RawToolName   string `json:"raw_tool_name"`
	RawToolInput  string `json:"raw_tool_input"`
	RawToolOutput string `json:"raw_tool_output"`
}

// loadFixtureLines reads one testdata/taskflow/<name>.jsonl file.
func loadFixtureLines(t *testing.T, name string) []fixtureLine {
	t.Helper()
	path := filepath.Join("..", "..", "testdata", "taskflow", name)
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer f.Close()

	var lines []fixtureLine
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		raw := strings.TrimSpace(sc.Text())
		if raw == "" {
			continue
		}
		var fl fixtureLine
		if err := json.Unmarshal([]byte(raw), &fl); err != nil {
			t.Fatalf("%s: bad fixture line: %v", path, err)
		}
		lines = append(lines, fl)
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("scan %s: %v", path, err)
	}
	return lines
}

// TestFixtures_ClaudeCode exercises every claude-code fixture line
// (TaskCreate/TaskUpdate/TodoWrite/post_tool_batch), asserting the
// event/item counts §R2.2's decoder table promises for each shape.
func TestFixtures_ClaudeCode(t *testing.T) {
	lines := loadFixtureLines(t, "claudecode.jsonl")
	if len(lines) != 8 {
		t.Fatalf("fixture drifted: got %d lines, want 8 (update the count if the fixture legitimately grew)", len(lines))
	}

	decode := func(fl fixtureLine) []TaskEvent {
		return Decode(ActionInput{
			Tool: fl.Tool, RawToolName: fl.RawToolName, ActionType: actionTypeFor(fl.RawToolName),
			RawToolInput: fl.RawToolInput, RawToolOutput: fl.RawToolOutput,
			SessionID: "fixture-session", ActionID: 1,
		})
	}

	// 0: TaskCreate.
	if ev := decode(lines[0]); len(ev) != 1 || ev[0].Kind != DeltaKind || ev[0].Items[0].Key != "1" {
		t.Errorf("line 0 (TaskCreate) = %+v", ev)
	}
	// 1: TaskUpdate -> in_progress.
	if ev := decode(lines[1]); len(ev) != 1 || ev[0].Items[0].Status != StatusInProgress {
		t.Errorf("line 1 (TaskUpdate in_progress) = %+v", ev)
	}
	// 2: TaskUpdate with owner.
	if ev := decode(lines[2]); len(ev) != 1 || ev[0].Items[0].Owner != "track-gen agent" {
		t.Errorf("line 2 (TaskUpdate owner) = %+v", ev)
	}
	// 3: content-only TaskUpdate (no status).
	if ev := decode(lines[3]); len(ev) != 1 || ev[0].Items[0].StatusKnown {
		t.Errorf("line 3 (content-only TaskUpdate) = %+v", ev)
	}
	// 4: TaskUpdate -> completed.
	if ev := decode(lines[4]); len(ev) != 1 || ev[0].Items[0].Status != StatusCompleted {
		t.Errorf("line 4 (TaskUpdate completed) = %+v", ev)
	}
	// 5: rejected TaskUpdate — decodes, but Failed=true.
	if ev := decode(lines[5]); len(ev) != 1 || !ev[0].Failed {
		t.Errorf("line 5 (rejected TaskUpdate) = %+v, want Failed=true", ev)
	}
	// 6: TodoWrite snapshot, 3 items.
	if ev := decode(lines[6]); len(ev) != 1 || len(ev[0].Items) != 3 || ev[0].Kind != SnapshotKind {
		t.Errorf("line 6 (TodoWrite) = %+v", ev)
	}
	// 7: post_tool_batch — 1 decodable envelope (the Read element is skipped).
	if ev := decode(lines[7]); len(ev) != 1 || ev[0].Items[0].Key != "4" {
		t.Errorf("line 7 (post_tool_batch) = %+v", ev)
	}
}

func TestFixtures_Codex(t *testing.T) {
	lines := loadFixtureLines(t, "codex.jsonl")
	if len(lines) != 3 {
		t.Fatalf("fixture drifted: got %d lines, want 3", len(lines))
	}
	for i, fl := range lines {
		ev := Decode(ActionInput{
			Tool: fl.Tool, RawToolName: fl.RawToolName, ActionType: "todo_update",
			RawToolInput: fl.RawToolInput, SessionID: "fixture-session", ActionID: 1,
		})
		if len(ev) != 1 || len(ev[0].Items) == 0 {
			t.Errorf("codex line %d = %+v", i, ev)
		}
	}
	// Line 2 (Unified Exec) must decode 3 items via the JS-source fallback.
	ev := Decode(ActionInput{
		Tool: "codex", RawToolName: "update_plan", ActionType: "todo_update",
		RawToolInput: lines[2].RawToolInput, SessionID: "s", ActionID: 1,
	})
	if len(ev[0].Items) != 3 {
		t.Errorf("unified exec line = %+v, want 3 items", ev)
	}
}

func TestFixtures_OpenCode(t *testing.T) {
	lines := loadFixtureLines(t, "opencode.jsonl")
	if len(lines) != 2 {
		t.Fatalf("fixture drifted: got %d lines, want 2", len(lines))
	}
	var allTransitions int
	prevState := map[string]*ItemState{}
	for _, fl := range lines {
		ev := Decode(ActionInput{
			Tool: fl.Tool, RawToolName: fl.RawToolName, ActionType: "todo_update",
			RawToolInput: fl.RawToolInput, SessionID: "s", ActionID: 1,
		})
		if len(ev) != 1 || len(ev[0].Items) != 2 {
			t.Fatalf("opencode event = %+v", ev)
		}
		for _, item := range ev[0].Items {
			res := Apply(prevState[item.Key], item, ev[0].Ts)
			st := res.NewState
			prevState[item.Key] = &st
			if res.Transition != nil {
				allTransitions++
			}
		}
	}
	// First call: 2 new items -> 2 transitions. Second call: same
	// content-hash keys, both flip pending->completed -> 2 more.
	if allTransitions != 4 {
		t.Errorf("allTransitions = %d, want 4 (2 creates + 2 completions)", allTransitions)
	}
}

func TestFixtures_GeminiCLI(t *testing.T) {
	lines := loadFixtureLines(t, "gemini-cli.jsonl")
	if len(lines) != 1 {
		t.Fatalf("fixture drifted: got %d lines, want 1", len(lines))
	}
	ev := Decode(ActionInput{
		Tool: lines[0].Tool, RawToolName: lines[0].RawToolName, ActionType: "todo_update",
		RawToolInput: lines[0].RawToolInput, SessionID: "s", ActionID: 1,
	})
	if len(ev) != 1 || len(ev[0].Items) != 3 {
		t.Fatalf("gemini-cli event = %+v", ev)
	}
	wantStatuses := []string{StatusInProgress, StatusPending, StatusBlocked}
	for i, want := range wantStatuses {
		if ev[0].Items[i].Status != want {
			t.Errorf("item %d status = %q, want %q", i, ev[0].Items[i].Status, want)
		}
	}
}

func TestFixtures_KiroCLI(t *testing.T) {
	lines := loadFixtureLines(t, "kirocli.jsonl")
	if len(lines) != 2 {
		t.Fatalf("fixture drifted: got %d lines, want 2", len(lines))
	}
	create := Decode(ActionInput{
		Tool: lines[0].Tool, RawToolName: lines[0].RawToolName, ActionType: "todo_update",
		RawToolInput: lines[0].RawToolInput, SessionID: "s", ActionID: 1,
	})
	if len(create) != 1 || len(create[0].Items) != 3 {
		t.Fatalf("kiro-cli create = %+v", create)
	}
	complete := Decode(ActionInput{
		Tool: lines[1].Tool, RawToolName: lines[1].RawToolName, ActionType: "todo_update",
		RawToolInput: lines[1].RawToolInput, SessionID: "s", ActionID: 2,
	})
	if len(complete) != 1 || complete[0].Items[0].Key != kiroIndexKey("0") {
		t.Fatalf("kiro-cli complete = %+v, want key %q (off-by-one adjusted)", complete, kiroIndexKey("0"))
	}
}

// TestFixtures_Droid exercises droid's TodoWrite: the JSON-array path
// (identical shape to claude-code's legacy TodoWrite) and the
// markdown-string emitTodo fallback (§2.10 — not observed live on the
// grounding box, but the code path exists).
func TestFixtures_Droid(t *testing.T) {
	lines := loadFixtureLines(t, "droid.jsonl")
	if len(lines) != 2 {
		t.Fatalf("fixture drifted: got %d lines, want 2", len(lines))
	}
	jsonArray := Decode(ActionInput{
		Tool: lines[0].Tool, RawToolName: lines[0].RawToolName, ActionType: "todo_update",
		RawToolInput: lines[0].RawToolInput, SessionID: "s", ActionID: 1,
	})
	if len(jsonArray) != 1 || len(jsonArray[0].Items) != 2 || jsonArray[0].Kind != SnapshotKind {
		t.Fatalf("droid JSON-array line = %+v", jsonArray)
	}
	markdown := Decode(ActionInput{
		Tool: lines[1].Tool, RawToolName: lines[1].RawToolName, ActionType: "todo_update",
		RawToolInput: lines[1].RawToolInput, SessionID: "s", ActionID: 2,
	})
	if len(markdown) != 1 || len(markdown[0].Items) != 2 {
		t.Fatalf("droid markdown-fallback line = %+v", markdown)
	}
	if markdown[0].Items[0].Status != StatusCompleted || markdown[0].Items[1].Status != StatusInProgress {
		t.Errorf("droid markdown statuses = %+v", markdown[0].Items)
	}
}

// TestFixtures_Poolside exercises the flat content-addressed Delta
// shape: a multi-line `add` (one content-hash item per line), then
// set_in_progress/complete against the SAME content key.
func TestFixtures_Poolside(t *testing.T) {
	lines := loadFixtureLines(t, "poolside.jsonl")
	if len(lines) != 3 {
		t.Fatalf("fixture drifted: got %d lines, want 3", len(lines))
	}
	add := Decode(ActionInput{
		Tool: lines[0].Tool, RawToolName: lines[0].RawToolName, ActionType: "todo_update",
		RawToolInput: lines[0].RawToolInput, SessionID: "s", ActionID: 1,
	})
	if len(add) != 1 || len(add[0].Items) != 2 || add[0].Items[0].KeyKind != KeyContent {
		t.Fatalf("poolside add line = %+v", add)
	}
	wantKey := ContentKey("Fix the login redirect bug")
	inProgress := Decode(ActionInput{
		Tool: lines[1].Tool, RawToolName: lines[1].RawToolName, ActionType: "todo_update",
		RawToolInput: lines[1].RawToolInput, SessionID: "s", ActionID: 2,
	})
	if len(inProgress) != 1 || inProgress[0].Items[0].Key != wantKey || inProgress[0].Items[0].Status != StatusInProgress {
		t.Fatalf("poolside set_in_progress line = %+v, want key %q", inProgress, wantKey)
	}
	complete := Decode(ActionInput{
		Tool: lines[2].Tool, RawToolName: lines[2].RawToolName, ActionType: "todo_update",
		RawToolInput: lines[2].RawToolInput, SessionID: "s", ActionID: 3,
	})
	if len(complete) != 1 || complete[0].Items[0].Key != wantKey || complete[0].Items[0].Status != StatusCompleted {
		t.Fatalf("poolside complete line = %+v, want key %q", complete, wantKey)
	}
}

// TestFixtures_Copilot exercises the rare KEYED snapshot shape
// (manage_todo_list) — a real per-item id, unlike every other
// Snapshot-kind tool in the table.
func TestFixtures_Copilot(t *testing.T) {
	lines := loadFixtureLines(t, "copilot.jsonl")
	if len(lines) != 2 {
		t.Fatalf("fixture drifted: got %d lines, want 2", len(lines))
	}
	first := Decode(ActionInput{
		Tool: lines[0].Tool, RawToolName: lines[0].RawToolName, ActionType: "todo_update",
		RawToolInput: lines[0].RawToolInput, SessionID: "s", ActionID: 1,
	})
	if len(first) != 1 || len(first[0].Items) != 2 {
		t.Fatalf("copilot line 0 = %+v", first)
	}
	if first[0].Items[0].Key != "1" || first[0].Items[0].KeyKind != KeyNative || first[0].Items[0].Status != StatusInProgress {
		t.Errorf("copilot item 0 = %+v, want native key 1, in_progress", first[0].Items[0])
	}
	if first[0].Items[1].Status != StatusPending {
		t.Errorf("copilot item 1 status = %q, want pending (not-started dialect)", first[0].Items[1].Status)
	}
	second := Decode(ActionInput{
		Tool: lines[1].Tool, RawToolName: lines[1].RawToolName, ActionType: "todo_update",
		RawToolInput: lines[1].RawToolInput, SessionID: "s", ActionID: 2,
	})
	if len(second) != 1 || second[0].Items[0].Status != StatusCompleted {
		t.Errorf("copilot line 1 item 0 = %+v, want completed (done dialect)", second[0].Items[0])
	}
}

// actionTypeFor mirrors the store seam's cheap pre-filter so these
// fixture-driven tests exercise Decode exactly as production calls it.
func actionTypeFor(rawToolName string) string {
	if rawToolName == "post_tool_batch" {
		return "post_tool_batch"
	}
	return "todo_update"
}
