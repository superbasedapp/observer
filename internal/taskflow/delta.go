package taskflow

import (
	"encoding/json"
	"sort"
	"strconv"
	"strings"
)

// decodeTaskCreate handles claude-code/cowork TaskCreate. The taskId is
// NOT in the call's input (§2.1) — it is minted server-side and only
// echoed in the tool's OUTPUT text ("Task #7 created successfully: ...").
// Phase 1 reads that text on both the forward and backfill paths (see
// snapshot.go's taskNumberRe doc comment).
func decodeTaskCreate(rawInput, rawOutput string) ([]TaskItem, bool) {
	id, outputSubject, ok := parseTaskCreateOutput(rawOutput)
	if !ok {
		return nil, false
	}
	var in struct {
		Subject     string `json:"subject"`
		Description string `json:"description"`
		ActiveForm  string `json:"activeForm"`
	}
	_ = json.Unmarshal([]byte(rawInput), &in)
	content := in.Subject
	if content == "" {
		content = in.Description
	}
	if content == "" {
		content = outputSubject
	}
	item := TaskItem{
		Key:         id,
		KeyKind:     KeyNative,
		Content:     content,
		ActiveForm:  in.ActiveForm,
		RawStatus:   StatusPending, // implicit — TaskCreate carries no status field
		Status:      StatusPending,
		StatusKnown: true,
	}
	return []TaskItem{item}, true
}

// taskUpdateInput mirrors the vendor's published TaskUpdateInput
// (§2.1 finding 1), read defensively per the documented (and
// unreflected-in-stream) key-name repair: taskId ?? id ?? task_id,
// activeForm ?? active_form.
type taskUpdateInput struct {
	TaskID      *string `json:"taskId"`
	ID          *string `json:"id"`
	TaskIDSnake *string `json:"task_id"`
	Status      *string `json:"status"`
	Subject     *string `json:"subject"`
	Description *string `json:"description"`
	ActiveForm  *string `json:"activeForm"`
	ActiveSnake *string `json:"active_form"`
	Owner       *string `json:"owner"`
}

func decodeTaskUpdate(rawInput, rawOutput string) ([]TaskItem, bool) {
	var in taskUpdateInput
	if err := json.Unmarshal([]byte(rawInput), &in); err != nil {
		return nil, false
	}
	id := firstNonNil(in.TaskID, in.ID, in.TaskIDSnake)
	if id == "" {
		return nil, false
	}
	item := TaskItem{Key: id, KeyKind: KeyNative}
	if in.Subject != nil {
		item.Content = *in.Subject
	} else if in.Description != nil {
		item.Content = *in.Description
	}
	if in.ActiveForm != nil {
		item.ActiveForm = *in.ActiveForm
	} else if in.ActiveSnake != nil {
		item.ActiveForm = *in.ActiveSnake
	}
	if in.Owner != nil {
		item.Owner = *in.Owner
	}
	if in.Status != nil {
		item.RawStatus = *in.Status
		item.Status = NormalizeStatus(*in.Status)
		item.StatusKnown = true
	}
	return []TaskItem{item}, true
}

func firstNonNil(vals ...*string) string {
	for _, v := range vals {
		if v != nil && *v != "" {
			return *v
		}
	}
	return ""
}

// decodePoolsideTodoAction handles the flat `{action, content}` Delta
// shape with NO container and NO id (§R2.2). `add` may pack MULTIPLE
// items into one newline-separated content string (§R2.6 item 7) — each
// line becomes its own content-addressed item.
func decodePoolsideTodoAction(rawInput, _ string) ([]TaskItem, bool) {
	var in struct {
		Action  string `json:"action"`
		Content string `json:"content"`
	}
	if err := json.Unmarshal([]byte(rawInput), &in); err != nil || in.Content == "" {
		return nil, false
	}
	status := ""
	switch strings.ToLower(strings.TrimSpace(in.Action)) {
	case "add":
		status = StatusPending
	case "set_in_progress":
		status = StatusInProgress
	case "complete":
		status = StatusCompleted
	default:
		return nil, false
	}
	lines := strings.Split(in.Content, "\n")
	items := make([]TaskItem, 0, len(lines))
	for i, line := range lines {
		text := strings.TrimSpace(line)
		if text == "" {
			continue
		}
		items = append(items, TaskItem{
			Key:         ContentKey(text),
			KeyKind:     KeyContent,
			Content:     text,
			RawStatus:   in.Action,
			Status:      status,
			StatusKnown: true,
			Order:       i,
		})
	}
	if len(items) == 0 {
		return nil, false
	}
	return items, true
}

// decodeKiroTodoList handles kiro-cli's index-keyed-OBJECT commands.
// `tasks` (on `create`) is 0-based; `completed_task_ids` VALUES (on
// `complete`) are 1-based back-references into that same numbering
// (§R2.6 item 8's off-by-one trap — kiroCompletedIndex adjusts it).
func decodeKiroTodoList(rawInput, _ string) ([]TaskItem, bool) {
	var in struct {
		Command          string                     `json:"command"`
		Tasks            map[string]json.RawMessage `json:"tasks"`
		CompletedTaskIDs map[string]string          `json:"completed_task_ids"`
	}
	if err := json.Unmarshal([]byte(rawInput), &in); err != nil {
		return nil, false
	}
	switch strings.ToLower(strings.TrimSpace(in.Command)) {
	case "create":
		if len(in.Tasks) == 0 {
			return nil, false
		}
		// in.Tasks is a JSON OBJECT keyed by string index ("0","1",...) —
		// Go's map iteration order is randomized per-run, so ranging it
		// directly (the pre-fix shape) produced a nondeterministic
		// TaskItem slice order on every call, with Order left at its
		// zero value throughout. Parse each key back to its numeric
		// index for Order, then sort — the resulting item order is
		// stable across repeated decodes of the identical payload,
		// matching every OTHER Snapshot-family decoder's guarantee
		// (decodeGenericSnapshot's Order = array position).
		items := make([]TaskItem, 0, len(in.Tasks))
		for idx, raw := range in.Tasks {
			var t struct {
				TaskDescription string `json:"task_description"`
			}
			_ = json.Unmarshal(raw, &t)
			order, _ := strconv.Atoi(strings.TrimSpace(idx)) // non-numeric key -> Order 0, defensive
			items = append(items, TaskItem{
				Key:         kiroIndexKey(idx),
				KeyKind:     KeyNative,
				Content:     t.TaskDescription,
				RawStatus:   StatusPending,
				Status:      StatusPending,
				StatusKnown: true,
				Order:       order,
			})
		}
		sort.Slice(items, func(i, j int) bool { return items[i].Order < items[j].Order })
		return items, true
	case "complete":
		if len(in.CompletedTaskIDs) == 0 {
			return nil, false
		}
		items := make([]TaskItem, 0, len(in.CompletedTaskIDs))
		for _, oneBased := range in.CompletedTaskIDs {
			idx := kiroCompletedIndex(oneBased)
			if idx == "" {
				continue
			}
			items = append(items, TaskItem{
				Key:         kiroIndexKey(idx),
				KeyKind:     KeyNative,
				RawStatus:   "complete",
				Status:      StatusCompleted,
				StatusKnown: true,
			})
		}
		if len(items) == 0 {
			return nil, false
		}
		return items, true
	default:
		return nil, false
	}
}

// decodeHermesTodo is a defensive best-effort probe over hermes' `todo`
// tool — NO fixture and NO live non-empty payload exists to ground the
// shape against (§2.9, §R2.7). It mirrors the adapter's own defensive
// field read (`strKey(m,"action","task")`, parse.go:618) and returns
// ok=false — an uncounted, un-guessed no-op — for anything it cannot
// recognize.
func decodeHermesTodo(rawInput, _ string) ([]TaskItem, bool) {
	var m map[string]json.RawMessage
	if err := json.Unmarshal([]byte(rawInput), &m); err != nil {
		return nil, false
	}
	content := firstStringField(m, []string{"content", "task", "description", "text"})
	if content == "" {
		return nil, false
	}
	rawStatus := firstStringField(m, []string{"status", "action"})
	item := TaskItem{
		Key:       ContentKey(content),
		KeyKind:   KeyContent,
		Content:   content,
		RawStatus: rawStatus,
	}
	if rawStatus != "" {
		item.Status = NormalizeStatus(rawStatus)
		item.StatusKnown = item.Status != ""
	}
	return []TaskItem{item}, true
}
