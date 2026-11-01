package taskflow

import (
	"encoding/json"
	"regexp"
	"strings"
)

// Decoders for the 2026-10-21 ten-adapter wave. Each is grounded on a live
// payload or the vendor's own tool definition; the decoderTable rows that
// use them name the grounding.

// decodeKimchiSnapshot handles kimchi `create_todos` / `update_todos`:
// `{"todos":[{"id":1,"content":"…","status":"in_progress","activeForm":"…"}]}`
// (testdata/kimchi/session-wsl.jsonl). The numeric id is the native key
// that mark_todo addresses.
func decodeKimchiSnapshot(rawInput, _ string) ([]TaskItem, bool) {
	return decodeGenericSnapshot(snapshotShape{
		containerKeys: []string{"todos"},
		contentKeys:   []string{"content"},
		idKey:         "id",
	}, rawInput)
}

// decodeKimchiClear handles kimchi `clear_todos` (`{}` or `{"scope":…}`,
// testdata/kimchi/session-wsl.jsonl): an EMPTY snapshot, so the fold
// records every tracked item as vanished.
func decodeKimchiClear(rawInput, _ string) ([]TaskItem, bool) {
	var m map[string]json.RawMessage
	if err := json.Unmarshal([]byte(rawInput), &m); err != nil {
		return nil, false
	}
	return []TaskItem{}, true
}

// decodeKimchiMarkTodo handles kimchi `mark_todo`:
// `{"id":2,"status":"in_progress","activeForm":"…","note":"…"}`
// (testdata/kimchi/session-wsl.jsonl; kimchi.exe MARK_TODO_PARAMETERS:
// id Number, status required). A status-only Delta keyed by the native id.
func decodeKimchiMarkTodo(rawInput, _ string) ([]TaskItem, bool) {
	var m map[string]json.RawMessage
	if err := json.Unmarshal([]byte(rawInput), &m); err != nil {
		return nil, false
	}
	id := stringifyField(m, "id")
	if id == "" {
		return nil, false
	}
	item := TaskItem{Key: id, KeyKind: KeyNative}
	if st := firstStringField(m, []string{"status"}); st != "" {
		item.RawStatus = st
		item.Status = NormalizeStatus(st)
		item.StatusKnown = true
	}
	item.ActiveForm = firstStringField(m, []string{"activeForm"})
	return []TaskItem{item}, true
}

// kimchiAddedIDRe reads the id kimchi assigned to an appended item from the
// tool result text ("Added todo #4 in global."; kimchi.exe executeAddTodo).
var kimchiAddedIDRe = regexp.MustCompile(`Added todo #(\d+)\b`)

// decodeKimchiAddTodo handles kimchi `add_todo`: `{"content":"…",
// "status"?:…, "activeForm"?:…, "note"?:…}` (kimchi.exe
// ADD_TODO_PARAMETERS; no live call yet). The id is assigned by the tool,
// so it is read back from the result; without it the item is keyed by
// content (a later mark_todo by id then cannot join it, which is the
// honest outcome of an id that was never observed).
func decodeKimchiAddTodo(rawInput, rawOutput string) ([]TaskItem, bool) {
	var m map[string]json.RawMessage
	if err := json.Unmarshal([]byte(rawInput), &m); err != nil {
		return nil, false
	}
	content := firstStringField(m, []string{"content"})
	if strings.TrimSpace(content) == "" {
		return nil, false
	}
	item := TaskItem{Content: content, ActiveForm: firstStringField(m, []string{"activeForm"})}
	if st := firstStringField(m, []string{"status"}); st != "" {
		item.RawStatus = st
		item.Status = NormalizeStatus(st)
		item.StatusKnown = true
	}
	if mm := kimchiAddedIDRe.FindStringSubmatch(rawOutput); mm != nil {
		item.Key, item.KeyKind = mm[1], KeyNative
	} else {
		item.Key, item.KeyKind = ContentKey(content), KeyContent
	}
	return []TaskItem{item}, true
}

// rooChecklistRe matches one line of a Roo-family markdown checklist:
// "[ ] pending", "[-] in progress", "[x] done".
var rooChecklistRe = regexp.MustCompile(`^\s*\[([ xX\-~])\]\s*(.+?)\s*$`)

// rooChecklistStatus maps the bracket glyph onto the raw vendor status.
var rooChecklistStatus = map[string]string{
	" ": "pending",
	"-": "in_progress",
	"~": "in_progress",
	"x": "completed",
	"X": "completed",
}

// decodeRooChecklist handles ibm-bob `update_todo_list`:
// `{"todos":"\n[-] Create hello.py\n[ ] Delete it\n"}` (testdata/ibmbob/
// fixture.sql; the tool result's `_meta.todos` confirms the mapping:
// `[-]` → inprogress, `[ ]` → pending). A whole-list Snapshot with no ids.
func decodeRooChecklist(rawInput, _ string) ([]TaskItem, bool) {
	var doc struct {
		Todos string `json:"todos"`
	}
	if err := json.Unmarshal([]byte(rawInput), &doc); err != nil {
		return nil, false
	}
	items := []TaskItem{}
	for _, line := range strings.Split(doc.Todos, "\n") {
		mm := rooChecklistRe.FindStringSubmatch(line)
		if mm == nil {
			continue
		}
		raw := rooChecklistStatus[mm[1]]
		items = append(items, TaskItem{
			Key:         ContentKey(mm[2]),
			KeyKind:     KeyContent,
			Content:     mm[2],
			RawStatus:   raw,
			Status:      NormalizeStatus(raw),
			StatusKnown: true,
			Order:       len(items),
		})
	}
	if len(items) == 0 && strings.TrimSpace(doc.Todos) != "" {
		// A non-empty body with no checklist line is not a cleared list.
		return nil, false
	}
	return items, true
}
