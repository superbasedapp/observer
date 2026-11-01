package taskflow

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/models"
)

// TestDecode_Wave1021 pins one row per decoderTable entry added in the
// 2026-10-21 ten-adapter wave. Payload shapes are the live / fixture /
// vendor-definition shapes named on each table row.
func TestDecode_Wave1021(t *testing.T) {
	type wantItem struct {
		key, kind, content, status string
		known                      bool
	}
	cases := []struct {
		name, tool, raw, in, out string
		kind                     TaskEventKind
		items                    []wantItem
		none                     bool
	}{
		{
			name: "autohand todo_write", tool: models.ToolAutohand, raw: "todo_write",
			in:   `{"tasks":[{"content":"Create hello_world.py","status":"in_progress","activeForm":"Creating"},{"content":"Run it","status":"pending"}]}`,
			kind: SnapshotKind,
			items: []wantItem{
				{ContentKey("Create hello_world.py"), KeyContent, "Create hello_world.py", StatusInProgress, true},
				{ContentKey("Run it"), KeyContent, "Run it", StatusPending, true},
			},
		},
		{
			name: "deepagents write_todos", tool: models.ToolDeepAgentsCode, raw: "write_todos",
			in:    `{"todos":[{"content":"Plan","status":"completed"}]}`,
			kind:  SnapshotKind,
			items: []wantItem{{ContentKey("Plan"), KeyContent, "Plan", StatusCompleted, true}},
		},
		{
			name: "kimchi create_todos keyed", tool: models.ToolKimchi, raw: "create_todos",
			in:    `{"todos":[{"id":1,"content":"Create and run","status":"in_progress","activeForm":"Creating"}]}`,
			kind:  SnapshotKind,
			items: []wantItem{{"1", KeyNative, "Create and run", StatusInProgress, true}},
		},
		{
			name: "kimchi mark_todo delta by id", tool: models.ToolKimchi, raw: "mark_todo",
			in:    `{"id":2,"status":"completed","note":"done"}`,
			kind:  DeltaKind,
			items: []wantItem{{"2", KeyNative, "", StatusCompleted, true}},
		},
		{
			name: "kimchi add_todo id from result", tool: models.ToolKimchi, raw: "add_todo",
			in:    `{"content":"Follow up"}`,
			out:   "Added todo #4 in global.",
			kind:  DeltaKind,
			items: []wantItem{{"4", KeyNative, "Follow up", "", false}},
		},
		{
			name: "kimchi add_todo without result falls back to content", tool: models.ToolKimchi, raw: "add_todo",
			in:    `{"content":"Follow up","status":"pending"}`,
			kind:  DeltaKind,
			items: []wantItem{{ContentKey("Follow up"), KeyContent, "Follow up", StatusPending, true}},
		},
		{
			name: "kimchi clear_todos empty snapshot", tool: models.ToolKimchi, raw: "clear_todos",
			in: `{}`, kind: SnapshotKind, items: []wantItem{},
		},
		{
			name: "ibm-bob update_todo_list checklist", tool: models.ToolIBMBob, raw: "update_todo_list",
			in:   `{"todos":"\n[-] Create hello.py\n[ ] Delete it\n[x] Plan\n"}`,
			kind: SnapshotKind,
			items: []wantItem{
				{ContentKey("Create hello.py"), KeyContent, "Create hello.py", StatusInProgress, true},
				{ContentKey("Delete it"), KeyContent, "Delete it", StatusPending, true},
				{ContentKey("Plan"), KeyContent, "Plan", StatusCompleted, true},
			},
		},
		{
			name: "cortex-code system_todo_write", tool: models.ToolCortexCode, raw: "system_todo_write",
			in:    `{"todos":[{"content":"Query the table","status":"in_progress"}]}`,
			kind:  SnapshotKind,
			items: []wantItem{{ContentKey("Query the table"), KeyContent, "Query the table", StatusInProgress, true}},
		},
		{
			name: "cortex-code task_create is not decoded", tool: models.ToolCortexCode, raw: "task_create",
			in: `{"subject":"x"}`, out: "Task created successfully.\nTask ID: task-ab12\nSubject: x", none: true,
		},
		{
			name: "ibm-bob non-checklist body decodes nothing", tool: models.ToolIBMBob, raw: "update_todo_list",
			in: `{"todos":"just prose"}`, none: true,
		},
		{
			name: "kimchi mark_todo without id decodes nothing", tool: models.ToolKimchi, raw: "mark_todo",
			in: `{"status":"completed"}`, none: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			evs := Decode(ActionInput{
				Tool: tc.tool, RawToolName: tc.raw, ActionType: "todo_update",
				RawToolInput: tc.in, RawToolOutput: tc.out, SessionID: "s", ActionID: 1, SourceEventID: "e",
			})
			if tc.none {
				if len(evs) != 0 {
					t.Fatalf("decoded %+v, want nothing", evs)
				}
				return
			}
			if len(evs) != 1 {
				t.Fatalf("got %d events, want 1", len(evs))
			}
			ev := evs[0]
			if ev.Kind != tc.kind || len(ev.Items) != len(tc.items) {
				t.Fatalf("kind %v items %+v, want kind %v and %d items", ev.Kind, ev.Items, tc.kind, len(tc.items))
			}
			for i, w := range tc.items {
				g := ev.Items[i]
				if g.Key != w.key || g.KeyKind != w.kind || g.Content != w.content || g.Status != w.status || g.StatusKnown != w.known {
					t.Errorf("item %d = %+v, want %+v", i, g, w)
				}
			}
		})
	}
}
