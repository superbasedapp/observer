package taskflow

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/models"
)

func TestDecode_ClaudeCodeTaskCreate(t *testing.T) {
	in := ActionInput{
		Tool:          models.ToolClaudeCode,
		RawToolName:   "TaskCreate",
		ActionType:    "todo_update",
		RawToolInput:  `{"activeForm":"Building blueprint CSS system","description":"desc","subject":"Blueprint direction: CSS design system"}`,
		RawToolOutput: `Task #7 created successfully: Blueprint direction: CSS design system`,
		SessionID:     "sess1",
		ActionID:      1,
		SourceEventID: "toolu_1",
	}
	events := Decode(in)
	if len(events) != 1 {
		t.Fatalf("want 1 event, got %d", len(events))
	}
	ev := events[0]
	if ev.Kind != DeltaKind {
		t.Errorf("kind = %v, want Delta", ev.Kind)
	}
	if len(ev.Items) != 1 {
		t.Fatalf("want 1 item, got %d", len(ev.Items))
	}
	item := ev.Items[0]
	if item.Key != "7" {
		t.Errorf("key = %q, want 7", item.Key)
	}
	if item.KeyKind != KeyNative {
		t.Errorf("keykind = %q", item.KeyKind)
	}
	if item.Status != StatusPending || !item.StatusKnown {
		t.Errorf("status = %q known=%v, want pending/true", item.Status, item.StatusKnown)
	}
	if item.Content != "Blueprint direction: CSS design system" {
		t.Errorf("content = %q", item.Content)
	}
}

func TestDecode_ClaudeCodeTaskCreate_NoOutputMatch(t *testing.T) {
	in := ActionInput{
		Tool:          models.ToolClaudeCode,
		RawToolName:   "TaskCreate",
		ActionType:    "todo_update",
		RawToolInput:  `{"subject":"x"}`,
		RawToolOutput: ``,
	}
	if events := Decode(in); events != nil {
		t.Errorf("want no events without a parseable output id, got %+v", events)
	}
}

func TestDecode_ClaudeCodeTaskUpdate_WithOwner(t *testing.T) {
	in := ActionInput{
		Tool:         models.ToolClaudeCode,
		RawToolName:  "TaskUpdate",
		ActionType:   "todo_update",
		RawToolInput: `{"owner":"track-gen agent","status":"in_progress","taskId":"1"}`,
	}
	events := Decode(in)
	if len(events) != 1 || len(events[0].Items) != 1 {
		t.Fatalf("got %+v", events)
	}
	item := events[0].Items[0]
	if item.Key != "1" || item.Status != StatusInProgress || item.Owner != "track-gen agent" {
		t.Errorf("item = %+v", item)
	}
}

func TestDecode_ClaudeCodeTaskUpdate_ContentOnly(t *testing.T) {
	in := ActionInput{
		Tool:         models.ToolClaudeCode,
		RawToolName:  "TaskUpdate",
		ActionType:   "todo_update",
		RawToolInput: `{"description":"revised text","taskId":"3"}`,
	}
	events := Decode(in)
	item := events[0].Items[0]
	if item.StatusKnown {
		t.Errorf("content-only update must not carry a known status: %+v", item)
	}
	if item.Content != "revised text" {
		t.Errorf("content = %q", item.Content)
	}
}

func TestDecode_ClaudeCodeTaskUpdate_KeyRepair(t *testing.T) {
	// Vendor-documented key-name repair invisible in the stream: id /
	// task_id must resolve the same as taskId (§2.1 finding 4).
	in := ActionInput{
		Tool:         models.ToolClaudeCode,
		RawToolName:  "TaskUpdate",
		ActionType:   "todo_update",
		RawToolInput: `{"status":"completed","task_id":"9"}`,
	}
	events := Decode(in)
	if events[0].Items[0].Key != "9" {
		t.Errorf("key = %q, want 9 (task_id fallback)", events[0].Items[0].Key)
	}
}

func TestDecode_ClaudeCodeTaskUpdate_Failed(t *testing.T) {
	in := ActionInput{
		Tool:          models.ToolClaudeCode,
		RawToolName:   "TaskUpdate",
		ActionType:    "todo_update",
		RawToolInput:  `{"status":"deleted","taskId":"3"}`,
		RawToolOutput: `<tool_use_error>Task not found</tool_use_error>`,
	}
	events := Decode(in)
	if !events[0].Failed {
		t.Errorf("want Failed=true for a rejected update")
	}
}

func TestDecode_TaskStopExcluded(t *testing.T) {
	in := ActionInput{
		Tool:         models.ToolClaudeCode,
		RawToolName:  "TaskStop",
		ActionType:   "todo_update",
		RawToolInput: `{"task_id":"b0nnuonn6"}`,
	}
	if events := Decode(in); events != nil {
		t.Errorf("TaskStop must not decode as a checklist tool: %+v", events)
	}
}

func TestDecode_TodoWriteSnapshot(t *testing.T) {
	in := ActionInput{
		Tool:         models.ToolClaudeCode,
		RawToolName:  "TodoWrite",
		ActionType:   "todo_update",
		RawToolInput: `{"todos":[{"activeForm":"Inspecting","content":"Inspect screenshots","status":"completed"},{"content":"Validate output","status":"in_progress"}]}`,
	}
	events := Decode(in)
	if len(events) != 1 || events[0].Kind != SnapshotKind {
		t.Fatalf("got %+v", events)
	}
	items := events[0].Items
	if len(items) != 2 {
		t.Fatalf("want 2 items, got %d", len(items))
	}
	if items[0].KeyKind != KeyContent || items[0].Key != ContentKey("Inspect screenshots") {
		t.Errorf("item0 key = %+v", items[0])
	}
	if items[1].Status != StatusInProgress {
		t.Errorf("item1 status = %q", items[1].Status)
	}
}

func TestDecode_CodexUpdatePlan_PlainJSON(t *testing.T) {
	in := ActionInput{
		Tool:         models.ToolCodex,
		RawToolName:  "update_plan",
		ActionType:   "todo_update",
		RawToolInput: `{"steps":[{"step":"verify tests","status":"completed"}]}`,
	}
	events := Decode(in)
	if len(events) != 1 || len(events[0].Items) != 1 {
		t.Fatalf("got %+v", events)
	}
	if events[0].Items[0].Content != "verify tests" {
		t.Errorf("content = %q", events[0].Items[0].Content)
	}
}

func TestDecode_CodexUpdatePlan_UnifiedExec(t *testing.T) {
	in := ActionInput{
		Tool:        models.ToolCodex,
		RawToolName: "update_plan",
		ActionType:  "todo_update",
		RawToolInput: `const r = await tools.update_plan({explanation:"...",plan:[
			{step:"Audit existing reviews",status:"completed"},
			{step:"Benchmark current collector",status:"completed"}
		]});`,
	}
	events := Decode(in)
	if len(events) != 1 || len(events[0].Items) != 2 {
		t.Fatalf("got %+v", events)
	}
	if events[0].Items[0].Content != "Audit existing reviews" {
		t.Errorf("content = %q", events[0].Items[0].Content)
	}
}

func TestDecode_OpenInterpreterAliasesCodexShape(t *testing.T) {
	in := ActionInput{
		Tool:         models.ToolOpenInterpreter,
		RawToolName:  "update_plan",
		ActionType:   "todo_update",
		RawToolInput: `{"plan":[{"step":"do it","status":"pending"}]}`,
	}
	events := Decode(in)
	if len(events) != 1 || len(events[0].Items) != 1 {
		t.Fatalf("got %+v", events)
	}
}

func TestDecode_GeminiWriteTodos(t *testing.T) {
	in := ActionInput{
		Tool:         models.ToolGeminiCLI,
		RawToolName:  "write_todos",
		ActionType:   "todo_update",
		RawToolInput: `{"todos":[{"description":"Ship the feature","status":"in_progress"}]}`,
	}
	events := Decode(in)
	if len(events) != 1 || events[0].Items[0].Content != "Ship the feature" {
		t.Fatalf("got %+v", events)
	}
}

func TestDecode_FreebuffAndGeminiSameNameDifferentShape(t *testing.T) {
	// Proof the decoder keys on (tool, name), never name alone (§2.6).
	in := ActionInput{
		Tool:         models.ToolFreebuff,
		RawToolName:  "write_todos",
		ActionType:   "todo_update",
		RawToolInput: `{"todos":[{"id":"1","text":"Do the thing","status":"completed"}]}`,
	}
	events := Decode(in)
	item := events[0].Items[0]
	if item.KeyKind != KeyNative || item.Key != "1" || item.Content != "Do the thing" {
		t.Errorf("freebuff item = %+v, want keyed id=1", item)
	}
}

func TestDecode_CopilotManageTodoList(t *testing.T) {
	in := ActionInput{
		Tool:         models.ToolCopilot,
		RawToolName:  "manage_todo_list",
		ActionType:   "todo_update",
		RawToolInput: `{"todoList":[{"id":1,"title":"Write tests","status":"in-progress"}]}`,
	}
	events := Decode(in)
	item := events[0].Items[0]
	if item.Key != "1" || item.KeyKind != KeyNative || item.Status != StatusInProgress {
		t.Errorf("copilot item = %+v", item)
	}
}

func TestDecode_OpenCodeTodoWrite(t *testing.T) {
	in := ActionInput{
		Tool:         models.ToolOpenCode,
		RawToolName:  "todowrite",
		ActionType:   "todo_update",
		RawToolInput: `{"todos":[{"content":"Draft plan","priority":"high","status":"completed"}]}`,
	}
	events := Decode(in)
	if len(events) != 1 || events[0].Items[0].Content != "Draft plan" {
		t.Fatalf("got %+v", events)
	}
}

func TestDecode_OpenCodeExplodedRowsExcluded(t *testing.T) {
	in := ActionInput{
		Tool:         models.ToolOpenCode,
		RawToolName:  "todo.completed",
		ActionType:   "todo_update",
		RawToolInput: `Draft and self-review full build plan`,
	}
	if events := Decode(in); events != nil {
		t.Errorf("exploded todo.<status> rows must not double-decode: %+v", events)
	}
}

func TestDecode_PoolsideTodoAction_MultiLineAdd(t *testing.T) {
	in := ActionInput{
		Tool:         models.ToolPoolside,
		RawToolName:  "todo_action",
		ActionType:   "todo_update",
		RawToolInput: `{"action":"add","content":"first task\nsecond task"}`,
	}
	events := Decode(in)
	if len(events) != 1 || len(events[0].Items) != 2 {
		t.Fatalf("want 2 split items, got %+v", events)
	}
	if events[0].Items[0].Key == events[0].Items[1].Key {
		t.Errorf("split items must have distinct content-hash keys")
	}
}

func TestDecode_KiroTodoList_CreateThenComplete(t *testing.T) {
	create := ActionInput{
		Tool:         models.ToolKiroCLI,
		RawToolName:  "todo_list",
		ActionType:   "todo_update",
		RawToolInput: `{"command":"create","tasks":{"0":{"task_description":"first"},"1":{"task_description":"second"}}}`,
	}
	events := Decode(create)
	if len(events) != 1 || len(events[0].Items) != 2 {
		t.Fatalf("create: got %+v", events)
	}

	complete := ActionInput{
		Tool:         models.ToolKiroCLI,
		RawToolName:  "todo_list",
		ActionType:   "todo_update",
		RawToolInput: `{"command":"complete","completed_task_ids":{"0":"1"}}`,
	}
	events = Decode(complete)
	if len(events) != 1 || len(events[0].Items) != 1 {
		t.Fatalf("complete: got %+v", events)
	}
	// completed_task_ids value "1" is 1-based → adjusts to 0-based index "0".
	if got, want := events[0].Items[0].Key, kiroIndexKey("0"); got != want {
		t.Errorf("completed key = %q, want %q (off-by-one adjustment)", got, want)
	}
}

// TestDecode_KiroTodoList_CreateOrderIsDeterministic is FIX-5:
// in.Tasks is a JSON object (Go map) — ranging it directly produced a
// nondeterministic item order and left every item's Order at its zero
// value. With enough keys, a bug that ranges a map without sorting
// shows up as flaky test failures across repeated runs; run the same
// decode several times and require BOTH the Order field (parsed from
// the string index) and the resulting item sequence to be identical
// every time.
func TestDecode_KiroTodoList_CreateOrderIsDeterministic(t *testing.T) {
	create := ActionInput{
		Tool:        models.ToolKiroCLI,
		RawToolName: "todo_list",
		ActionType:  "todo_update",
		RawToolInput: `{"command":"create","tasks":{
			"0":{"task_description":"first"},
			"1":{"task_description":"second"},
			"2":{"task_description":"third"},
			"3":{"task_description":"fourth"},
			"4":{"task_description":"fifth"},
			"5":{"task_description":"sixth"},
			"6":{"task_description":"seventh"},
			"7":{"task_description":"eighth"}
		}}`,
	}
	wantContents := []string{"first", "second", "third", "fourth", "fifth", "sixth", "seventh", "eighth"}
	for run := 0; run < 20; run++ {
		events := Decode(create)
		if len(events) != 1 || len(events[0].Items) != 8 {
			t.Fatalf("run %d: got %+v", run, events)
		}
		for i, item := range events[0].Items {
			if item.Order != i {
				t.Errorf("run %d: item %d Order = %d, want %d", run, i, item.Order, i)
			}
			if item.Content != wantContents[i] {
				t.Fatalf("run %d: item order not stable — item %d content = %q, want %q",
					run, i, item.Content, wantContents[i])
			}
		}
	}
}

func TestDecode_DroidJSONPath(t *testing.T) {
	in := ActionInput{
		Tool:         models.ToolDroid,
		RawToolName:  "TodoWrite",
		ActionType:   "todo_update",
		RawToolInput: `{"todos":[{"content":"Fix the build","status":"in_progress"}]}`,
	}
	events := Decode(in)
	if len(events) != 1 || events[0].Items[0].Content != "Fix the build" {
		t.Fatalf("got %+v", events)
	}
}

func TestDecode_DroidMarkdownFallback(t *testing.T) {
	in := ActionInput{
		Tool:         models.ToolDroid,
		RawToolName:  "TodoWrite",
		ActionType:   "todo_update",
		RawToolInput: `{"todos":"1. [completed] Create Hello World Python file\n2. [pending] Write tests"}`,
	}
	events := Decode(in)
	if len(events) != 1 || len(events[0].Items) != 2 {
		t.Fatalf("got %+v", events)
	}
	if events[0].Items[0].Status != StatusCompleted || events[0].Items[1].Status != StatusPending {
		t.Errorf("items = %+v", events[0].Items)
	}
}

func TestDecode_HermesDefensiveProbe(t *testing.T) {
	in := ActionInput{
		Tool:         models.ToolHermes,
		RawToolName:  "todo",
		ActionType:   "todo_update",
		RawToolInput: `{"action":"complete","task":"ship the release"}`,
	}
	events := Decode(in)
	if len(events) != 1 || events[0].Items[0].Content != "ship the release" {
		t.Fatalf("got %+v", events)
	}

	unrecognized := ActionInput{
		Tool:         models.ToolHermes,
		RawToolName:  "todo",
		ActionType:   "todo_update",
		RawToolInput: `{"unrelated":"field"}`,
	}
	if events := Decode(unrecognized); events != nil {
		t.Errorf("unrecognized hermes shape must yield no event, got %+v", events)
	}
}

func TestDecode_PostToolBatch(t *testing.T) {
	in := ActionInput{
		Tool:         models.ToolClaudeCode,
		ActionType:   "post_tool_batch",
		RawToolInput: `[{"tool_name":"TaskUpdate","tool_use_id":"toolu_a","tool_input":{"status":"completed","taskId":"2"},"tool_response":"Updated task #2 status"},{"tool_name":"Read","tool_use_id":"toolu_b","tool_input":{},"tool_response":"..."}]`,
		SessionID:    "sess1",
		ActionID:     42,
	}
	events := Decode(in)
	if len(events) != 1 {
		t.Fatalf("want 1 decodable envelope (Read is not a task tool), got %+v", events)
	}
	if events[0].SourceEventID != "toolu_a" {
		t.Errorf("source event id = %q, want the envelope's own tool_use_id", events[0].SourceEventID)
	}
	if events[0].Items[0].Key != "2" {
		t.Errorf("item = %+v", events[0].Items[0])
	}
}

func TestDecode_UnknownToolYieldsNothing(t *testing.T) {
	in := ActionInput{
		Tool:         "qoder",
		RawToolName:  "TodoWrite",
		ActionType:   "todo_update",
		RawToolInput: `{"todos":[]}`,
	}
	if events := Decode(in); events != nil {
		t.Errorf("unregistered (tool, name) pair must never guess a decode: %+v", events)
	}
}

func TestDecode_TaskCompleteActionTypeNeverDecodes(t *testing.T) {
	// task_complete is a turn-terminus signal, never a checklist event
	// (§1.1) — even if a caller mistakenly routes one through Decode
	// with a todo-shaped raw_tool_name, ActionType alone must not be
	// enough to produce items when the (tool, raw_tool_name) pair isn't
	// registered under it.
	in := ActionInput{
		Tool:         models.ToolCodex,
		RawToolName:  "some_other_tool",
		ActionType:   "task_complete",
		RawToolInput: `{}`,
	}
	if events := Decode(in); events != nil {
		t.Errorf("got %+v", events)
	}
}
