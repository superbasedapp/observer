package taskflow

import "testing"

func TestCursorTodoMergeSemantics(t *testing.T) {
	for _, test := range []struct {
		name, input, output string
		kind                TaskEventKind
		count               int
	}{
		{"replace", `{"merge":false,"todos":[{"id":"a","content":"A","status":"pending"}]}`, "", SnapshotKind, 1},
		{"merge", `{"merge":true,"todos":[{"id":"a","status":"completed"}]}`, "", DeltaKind, 1},
		{"clear", `{"merge":false,"todos":[]}`, "", SnapshotKind, 0},
		{"successful full result", `{"merge":true,"todos":[{"id":"a","status":"completed"}]}`, `{"success":{"todos":[{"id":"a","content":"A","status":"completed"},{"id":"b","content":"B","status":"pending"}]}}`, SnapshotKind, 2},
	} {
		t.Run(test.name, func(t *testing.T) {
			events := Decode(ActionInput{Tool: "cursor", RawToolName: "TodoWrite", RawToolInput: test.input, RawToolOutput: test.output})
			if len(events) != 1 || events[0].Kind != test.kind || len(events[0].Items) != test.count {
				t.Fatalf("events=%+v", events)
			}
			for _, item := range events[0].Items {
				if item.KeyKind != KeyNative {
					t.Fatal("lost native id")
				}
			}
		})
	}
	for _, input := range []string{`{"todos":[{"content":"no id","status":"pending"}]}`, `{"merge":true,"todos":[]}`, `prose only`} {
		if events := Decode(ActionInput{Tool: "cursor", RawToolName: "TodoWrite", RawToolInput: input}); len(events) != 0 {
			t.Fatalf("invalid/no-op input decoded: %s", input)
		}
	}
	if events := Decode(ActionInput{
		Tool: "cursor", RawToolName: "TodoWrite",
		RawToolInput:  `{"merge":true,"todos":[{"id":"a","status":"completed"}]}`,
		RawToolOutput: `{"error":{"error":"rejected"}}`,
	}); len(events) != 0 {
		t.Fatal("failed update changed a checklist")
	}
}
