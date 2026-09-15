package cursor

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/platform/protowire"
	"github.com/marmutapp/superbased-observer/internal/taskflow"
)

func nativeTodoFixture(t *testing.T, step int) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "..", "testdata", "cursor", "native-todos", fmt.Sprintf("step-%d.bin", step)))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestNativeCursorTodosCapture(t *testing.T) {
	dir := t.TempDir()
	storePath := filepath.Join(dir, ".cursor", "chats", "workspace", "probe-session", "store.db")
	blobs := make(map[string][]byte)
	for i := 1; i <= 4; i++ {
		blobs[fmt.Sprintf("step%d", i)] = nativeTodoFixture(t, i)
	}
	writeCursorStoreDB(t, storePath, blobs)
	a := NewWithOptions(nil, filepath.Join(dir, ".cursor")).WithSessionHookChecker(func(context.Context, string) (bool, error) {
		return true, nil // SessionStart must not suppress native tasks.
	})
	result, err := a.ParseSessionFile(context.Background(), storePath, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.ToolEvents) != 4 {
		t.Fatalf("got %d events, want four native todo calls", len(result.ToolEvents))
	}
	previous := int64(0)
	for i, event := range result.ToolEvents {
		if event.ActionType != models.ActionTodoUpdate || event.RawToolName != "TodoWrite" || !event.Success {
			t.Fatalf("incorrect event: %+v", event)
		}
		if event.Timestamp.UnixMilli() <= previous {
			t.Fatal("native completion timestamps are not ordered")
		}
		previous = event.Timestamp.UnixMilli()
		decoded := taskflow.Decode(taskflow.ActionInput{
			Tool: event.Tool, RawToolName: event.RawToolName,
			RawToolInput: event.RawToolInput, RawToolOutput: event.ToolOutput, SourceEventID: event.SourceEventID,
		})
		if len(decoded) != 1 || decoded[0].Kind != taskflow.SnapshotKind || len(decoded[0].Items) != 2 {
			t.Fatalf("step %d failed to decode full native result: %+v", i+1, decoded)
		}
		if i == 3 {
			for _, item := range decoded[0].Items {
				if item.KeyKind != taskflow.KeyNative || item.Status != taskflow.StatusCompleted {
					t.Fatalf("final item: %+v", item)
				}
			}
		}
	}
	if previous != 1788942091951 {
		t.Fatalf("final timestamp %d was not preserved", previous)
	}
	first := result.ToolEvents[0]
	if first.SourceEventID != "tool_b8d4df39-ebb7-4142-b0f8-2a56fd35b07" {
		t.Fatal("native tool call ID was not preserved")
	}
	replay, err := a.ParseSessionFile(context.Background(), storePath, 0)
	if err != nil || replay.ToolEvents[0].SourceEventID != first.SourceEventID {
		t.Fatal("replay changed native event identity")
	}
}

func TestNativeCursorTodosRejectIncompleteOrFailed(t *testing.T) {
	valid := nativeTodoFixture(t, 1)
	step, _ := cursorProto(valid)
	call, _ := cursorProtoChild(step, 2)
	update, _ := cursorProtoChild(call, 9)
	args, _ := cursorProtoBytes(update, 1)
	failedUpdate := protowire.AppendBytesField(nil, 1, args)
	failedUpdate = protowire.AppendBytesField(failedUpdate, 2, protowire.AppendBytesField(nil, 2,
		protowire.AppendBytesField(nil, 1, []byte("rejected"))))
	failedCall := protowire.AppendBytesField(nil, 9, failedUpdate)
	failedCall = protowire.AppendBytesField(failedCall, 57, []byte("failed-call"))
	failedCall = protowire.AppendVarintField(failedCall, 60, 1788942084274)
	for name, data := range map[string][]byte{
		"truncated": valid[:len(valid)-1], "JSON prose": []byte(`{"todos":["do work"]}`),
		"failed": protowire.AppendBytesField(nil, 2, failedCall),
		"missing result and timestamps": protowire.AppendBytesField(nil, 2, protowire.AppendBytesField(nil, 9,
			protowire.AppendBytesField(nil, 1, args))),
	} {
		t.Run(name, func(t *testing.T) {
			if _, ok := decodeCursorTodoCall(data); ok {
				t.Fatal("non-successful execution became a task update")
			}
		})
	}
}

func TestCursorTodoTranscriptDefersToNativeStore(t *testing.T) {
	dir := t.TempDir()
	transcript := filepath.Join(dir, ".cursor", "projects", "workspace", "agent-transcripts", "probe", "probe.jsonl")
	if err := os.MkdirAll(filepath.Dir(transcript), 0o755); err != nil {
		t.Fatal(err)
	}
	body := "{\"role\":\"user\",\"message\":{\"content\":[{\"type\":\"text\",\"text\":\"test\"}]}}\n" +
		`{"role":"assistant","message":{"content":[{"type":"tool_use","name":"TodoWrite","input":{"merge":true,"todos":[{"id":"1","content":"test","status":"completed"}]}}]}}` + "\n"
	if err := os.WriteFile(transcript, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	a := NewWithOptions(nil, filepath.Join(dir, ".cursor"))
	without, err := a.ParseSessionFile(context.Background(), transcript, 0)
	if err != nil || len(without.ToolEvents) != 1 || without.ToolEvents[0].ActionType != models.ActionTodoUpdate {
		t.Fatalf("IDE fallback lost: %+v %v", without, err)
	}
	storePath := filepath.Join(dir, ".cursor", "chats", "workspace", "probe", "store.db")
	writeCursorStoreDB(t, storePath, map[string][]byte{"step": nativeTodoFixture(t, 1)})
	with, err := a.ParseSessionFile(context.Background(), transcript, 0)
	if err != nil || len(with.ToolEvents) != 0 {
		t.Fatalf("duplicate transcript task: %+v %v", with, err)
	}
	if cursorTodoStoreExists(transcript, "another-session") {
		t.Fatal("native store lookup crossed session boundaries")
	}
}
