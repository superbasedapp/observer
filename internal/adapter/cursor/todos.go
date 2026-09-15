package cursor

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/platform/protowire"
)

// The CLI's store.db contains agent.v1.ConversationStep protobuf blobs.
// Verified against CLI 2026.09.08-6caf4ff and the four live fixtures in
// testdata/cursor/native-todos. Only a completed, successful native
// UpdateTodosToolCall is accepted; prose and pending calls cannot create tasks.
type cursorTodoCall struct {
	ID          string
	CompletedMS int64
	Input       string
	Output      string
}

type cursorTodoItem struct {
	ID      string `json:"id"`
	Content string `json:"content"`
	Status  string `json:"status"`
}

type cursorTodoInput struct {
	Todos []cursorTodoItem `json:"todos"`
	Merge bool             `json:"merge"`
}

// cursorProto validates the complete message and keeps only its immediate
// fields. Each known nested message is validated separately before use.
func cursorProto(data []byte) ([]protowire.Field, bool) {
	var fields []protowire.Field
	err := protowire.Walk(data, func(f protowire.Field) error {
		if f.Depth == 0 {
			fields = append(fields, f)
		}
		return nil
	})
	return fields, err == nil
}

func cursorProtoBytes(fields []protowire.Field, num int) ([]byte, bool) {
	for _, f := range fields {
		if f.FieldNumber == num && f.WireType == protowire.WireBytes {
			return f.Bytes, true
		}
	}
	return nil, false
}

func cursorProtoUint(fields []protowire.Field, num int) uint64 {
	for _, f := range fields {
		if f.FieldNumber == num && f.WireType == protowire.WireVarint {
			return f.Varint
		}
	}
	return 0
}

func cursorProtoChild(fields []protowire.Field, num int) ([]protowire.Field, bool) {
	b, ok := cursorProtoBytes(fields, num)
	if !ok {
		return nil, false
	}
	return cursorProto(b)
}

func decodeCursorTodoItems(fields []protowire.Field) ([]cursorTodoItem, bool) {
	items := make([]cursorTodoItem, 0)
	statuses := map[uint64]string{1: "pending", 2: "in_progress", 3: "completed", 4: "cancelled"}
	for _, f := range fields {
		if f.FieldNumber != 1 {
			continue
		}
		if f.WireType != protowire.WireBytes {
			return nil, false
		}
		item, ok := cursorProto(f.Bytes)
		if !ok {
			return nil, false
		}
		id, _ := cursorProtoBytes(item, 1)
		content, _ := cursorProtoBytes(item, 2)
		status, known := statuses[cursorProtoUint(item, 3)]
		if len(id) == 0 || !utf8.Valid(id) || !utf8.Valid(content) || !known {
			return nil, false
		}
		items = append(items, cursorTodoItem{ID: string(id), Content: string(content), Status: status})
	}
	return items, true
}

func decodeCursorTodoCall(data []byte) (cursorTodoCall, bool) {
	step, ok := cursorProto(data)
	if !ok {
		return cursorTodoCall{}, false
	}
	call, ok := cursorProtoChild(step, 2)
	if !ok {
		return cursorTodoCall{}, false
	}
	update, ok := cursorProtoChild(call, 9)
	if !ok {
		return cursorTodoCall{}, false
	}
	id, _ := cursorProtoBytes(call, 57)
	started, completed := cursorProtoUint(call, 59), cursorProtoUint(call, 60)
	// Bound to a valid positive Unix millisecond timestamp (through year 9999).
	if len(id) == 0 || !utf8.Valid(id) || completed == 0 || completed > 253402300799999 || completed < started {
		return cursorTodoCall{}, false
	}
	args, argsOK := cursorProtoChild(update, 1)
	result, resultOK := cursorProtoChild(update, 2)
	if !argsOK || !resultOK {
		return cursorTodoCall{}, false
	}
	if _, failed := cursorProtoBytes(result, 2); failed {
		return cursorTodoCall{}, false
	}
	success, ok := cursorProtoChild(result, 1)
	if !ok {
		return cursorTodoCall{}, false
	}
	inputItems, inputOK := decodeCursorTodoItems(args)
	resultItems, resultOK := decodeCursorTodoItems(success)
	if !inputOK || !resultOK {
		return cursorTodoCall{}, false
	}
	input, _ := json.Marshal(cursorTodoInput{Todos: inputItems, Merge: cursorProtoUint(args, 2) != 0})
	output, _ := json.Marshal(map[string]any{"success": map[string]any{"todos": resultItems}})
	return cursorTodoCall{ID: string(id), CompletedMS: int64(completed), Input: string(input), Output: string(output)}, true
}

func (a *Adapter) todoEvents(calls []cursorTodoCall, sessionID, projectRoot, sourceFile string) []models.ToolEvent {
	sort.SliceStable(calls, func(i, j int) bool {
		if calls[i].CompletedMS != calls[j].CompletedMS {
			return calls[i].CompletedMS < calls[j].CompletedMS
		}
		return calls[i].ID < calls[j].ID
	})
	seen := make(map[string]bool)
	var events []models.ToolEvent
	for _, call := range calls {
		if seen[call.ID] {
			continue
		}
		seen[call.ID] = true
		input, output := call.Input, call.Output
		if a.scrubber != nil {
			input = a.scrubber.RawJSON([]byte(input))
			output = a.scrubber.RawJSON([]byte(output))
		}
		events = append(events, models.ToolEvent{
			Tool: models.ToolCursor, SessionID: sessionID, ProjectRoot: projectRoot,
			SourceFile: sourceFile, SourceEventID: call.ID,
			Timestamp:  time.UnixMilli(call.CompletedMS).UTC(),
			ActionType: models.ActionTodoUpdate, RawToolName: "TodoWrite",
			RawToolInput: input, ToolOutput: output, Success: true,
			Target: fmt.Sprintf("Native todo update %s", call.ID),
		})
	}
	return events
}

// CLI todos have an authoritative result-bearing store. Its transcript
// contains the same calls without IDs, results or timestamps, so replaying
// both would duplicate transitions. IDE transcripts without this sibling
// retain their existing capture path.
func cursorTodoStoreExists(transcriptPath, sessionID string) bool {
	norm := strings.ReplaceAll(transcriptPath, `\`, "/")
	index := strings.Index(strings.ToLower(norm), "/.cursor/")
	if index < 0 {
		return false
	}
	root := norm[:index+len("/.cursor")]
	paths, _ := filepath.Glob(filepath.Join(root, "chats", "*", sessionID, "store.db"))
	return len(paths) != 0
}
