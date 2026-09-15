package taskflow

import "encoding/json"

// Cursor TodoWrite merges by native id when merge=true, otherwise replaces
// the list. The native CLI success payload carries the complete resulting
// list; prefer that authoritative snapshot over the requested input delta.
func cursorTodoSnapshot(rawInput, rawOutput string) (string, bool) {
	var result struct {
		Success json.RawMessage `json:"success"`
	}
	if json.Unmarshal([]byte(rawOutput), &result) == nil && len(result.Success) > 0 && string(result.Success) != "null" {
		return string(result.Success), true
	}
	return rawInput, false
}

func decodeCursorTodo(rawInput, rawOutput string) ([]TaskItem, bool) {
	var request struct {
		Merge bool `json:"merge"`
	}
	if json.Unmarshal([]byte(rawInput), &request) != nil {
		return nil, false
	}
	var result map[string]json.RawMessage
	if json.Unmarshal([]byte(rawOutput), &result) == nil {
		if failure, exists := result["error"]; exists && string(failure) != "null" && string(failure) != `""` {
			return nil, false
		}
	}
	input, _ := cursorTodoSnapshot(rawInput, rawOutput)
	items, ok := decodeGenericSnapshot(snapshotShape{
		containerKeys: []string{"todos"}, contentKeys: []string{"content"}, idKey: "id",
	}, input)
	if !ok {
		return nil, false
	}
	for _, item := range items {
		if item.KeyKind != KeyNative {
			return nil, false
		}
	}
	return items, true
}

func cursorTodoKind(rawInput, rawOutput string) TaskEventKind {
	if _, snapshot := cursorTodoSnapshot(rawInput, rawOutput); snapshot {
		return SnapshotKind
	}
	var input struct {
		Merge bool `json:"merge"`
	}
	if json.Unmarshal([]byte(rawInput), &input) == nil && input.Merge {
		return DeltaKind
	}
	return SnapshotKind
}
