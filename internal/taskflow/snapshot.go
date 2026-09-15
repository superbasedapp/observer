package taskflow

import (
	"encoding/json"
	"regexp"
	"strconv"
	"strings"
)

// snapshotShape parametrizes the ONE generic whole-list decoder that
// covers every Snapshot-kind tool in §R2.2's table: the container key
// differs (todos / plan / steps / todoList), the per-item content field
// differs (content / description / step / title / text), and three
// tools (copilot, freebuff — plus, defensively, anything else that ever
// grows one) carry a real per-item id where everyone else does not.
type snapshotShape struct {
	// containerKeys are tried in order; the first present wins. Codex's
	// fixture spells the same array "steps" where its live Unified Exec
	// samples spell it "plan" — accept both (§R2.2 grounding note).
	containerKeys []string
	contentKeys   []string
	// idKey, if non-empty, names the per-item id field (number or
	// string in the wire JSON — both are accepted and stringified).
	idKey string
}

func decodeGenericSnapshot(shape snapshotShape, rawInput string) ([]TaskItem, bool) {
	var doc map[string]json.RawMessage
	if err := json.Unmarshal([]byte(rawInput), &doc); err != nil {
		return nil, false
	}
	var arr []json.RawMessage
	for _, ck := range shape.containerKeys {
		raw, ok := doc[ck]
		if !ok {
			continue
		}
		if err := json.Unmarshal(raw, &arr); err == nil {
			break
		}
	}
	if arr == nil {
		return nil, false
	}

	items := make([]TaskItem, 0, len(arr))
	for i, rawItem := range arr {
		var m map[string]json.RawMessage
		if err := json.Unmarshal(rawItem, &m); err != nil {
			continue
		}
		content := firstStringField(m, shape.contentKeys)
		rawStatus := firstStringField(m, []string{"status"})
		item := TaskItem{
			Content:   content,
			RawStatus: rawStatus,
			Order:     i,
		}
		if rawStatus != "" {
			item.Status = NormalizeStatus(rawStatus)
			item.StatusKnown = true
		}
		if af := firstStringField(m, []string{"activeForm", "active_form"}); af != "" {
			item.ActiveForm = af
		}
		if shape.idKey != "" {
			if id := stringifyField(m, shape.idKey); id != "" {
				item.Key = id
				item.KeyKind = KeyNative
			}
		}
		if item.Key == "" {
			item.Key = ContentKey(content)
			item.KeyKind = KeyContent
		}
		items = append(items, item)
	}
	return items, true
}

// firstStringField returns the first present-and-string-typed field
// among candidates, or "".
func firstStringField(m map[string]json.RawMessage, candidates []string) string {
	for _, c := range candidates {
		raw, ok := m[c]
		if !ok {
			continue
		}
		var s string
		if err := json.Unmarshal(raw, &s); err == nil {
			return s
		}
	}
	return ""
}

// stringifyField reads a field that may be wire-encoded as either a
// JSON string or a JSON number (copilot's `id` is a number; freebuff's
// is a string) and returns its string form, or "" if absent/unparsable.
func stringifyField(m map[string]json.RawMessage, key string) string {
	raw, ok := m[key]
	if !ok {
		return ""
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s
	}
	var n json.Number
	if err := json.Unmarshal(raw, &n); err == nil {
		return n.String()
	}
	return ""
}

// codexUnifiedExecRe extracts {step:"...",...,status:"..."} pairs from
// the Unified Exec JS-source encoding of update_plan (§2.2): the SAME
// data arrives as a JS object literal, not JSON, when the call is
// wrapped in a Unified Exec program. Best-effort per the audit's own
// framing ("decode defensively") — only 3 live rows exist on the
// grounding corpus outside opencode's deliberately-bare-string rows.
var codexUnifiedExecRe = regexp.MustCompile(`step\s*:\s*"([^"]*)"[^{}]*?status\s*:\s*"([^"]*)"`)

func decodeCodexUnifiedExec(rawInput string) ([]TaskItem, bool) {
	matches := codexUnifiedExecRe.FindAllStringSubmatch(rawInput, -1)
	if len(matches) == 0 {
		return nil, false
	}
	items := make([]TaskItem, 0, len(matches))
	for i, m := range matches {
		item := TaskItem{
			Content:     m[1],
			RawStatus:   m[2],
			Status:      NormalizeStatus(m[2]),
			StatusKnown: m[2] != "",
			Order:       i,
		}
		item.Key = ContentKey(item.Content)
		item.KeyKind = KeyContent
		items = append(items, item)
	}
	return items, true
}

// droidMarkdownRe matches droid's flattened-markdown TodoWrite line
// shape, "N. [status] text" (§2.10, emitTodo's lossy path).
var droidMarkdownRe = regexp.MustCompile(`(?m)^\s*\d+\.\s*\[(\w+)\]\s*(.+?)\s*$`)

// decodeDroidTodo handles droid's TodoWrite in EITHER wire shape: the
// generic JSON-array path (all 7 live corpus rows, structurally
// identical to claude-code's legacy TodoWrite) and the markdown-string
// `emitTodo` path described in droid's own doc comment (not observed
// live on this box, but the code path exists — §2.10).
func decodeDroidTodo(rawInput string) ([]TaskItem, bool) {
	if items, ok := decodeGenericSnapshot(snapshotShape{
		containerKeys: []string{"todos"},
		contentKeys:   []string{"content"},
	}, rawInput); ok {
		return items, true
	}
	// Fallback: `{"todos": "1. [in_progress] ...\n2. [pending] ..."}`
	var doc struct {
		Todos string `json:"todos"`
	}
	if err := json.Unmarshal([]byte(rawInput), &doc); err != nil || doc.Todos == "" {
		return nil, false
	}
	matches := droidMarkdownRe.FindAllStringSubmatch(doc.Todos, -1)
	if len(matches) == 0 {
		return nil, false
	}
	items := make([]TaskItem, 0, len(matches))
	for i, m := range matches {
		rawStatus := m[1]
		content := strings.TrimSpace(m[2])
		item := TaskItem{
			Content:     content,
			RawStatus:   rawStatus,
			Status:      NormalizeStatus(rawStatus),
			StatusKnown: true,
			Order:       i,
		}
		item.Key = ContentKey(content)
		item.KeyKind = KeyContent
		items = append(items, item)
	}
	return items, true
}

// decodeCodexUpdatePlan tries the plain-JSON `{plan|steps:[...]}` shape
// first, then the Unified Exec JS-source fallback.
func decodeCodexUpdatePlan(rawInput string) ([]TaskItem, bool) {
	if items, ok := decodeGenericSnapshot(snapshotShape{
		containerKeys: []string{"plan", "steps"},
		contentKeys:   []string{"step"},
	}, rawInput); ok {
		return items, true
	}
	return decodeCodexUnifiedExec(rawInput)
}

// taskNumberRe backfills claude-code TaskCreate's server-minted id from
// the tool's OUTPUT text, since the id never appears in the call's own
// input (§2.1). Also used on the forward path (Phase 1 scope: the
// ingest seam re-reads actions.raw_tool_output, the same column both
// the live and backfill paths populate — see docs/task-tracking.md
// "Deviations" for why this trades the contract's `toolUseResult.task.id`
// forward-path recommendation for a single code path).
var taskNumberRe = regexp.MustCompile(`Task #(\d+) created successfully:?\s*(.*)`)

func parseTaskCreateOutput(rawOutput string) (id string, subject string, ok bool) {
	m := taskNumberRe.FindStringSubmatch(rawOutput)
	if m == nil {
		return "", "", false
	}
	return m[1], strings.TrimSpace(m[2]), true
}

// taskUpdateFailureMarkers are substrings in a TaskUpdate/TaskCreate
// tool's raw_tool_output that mean the call was rejected — applying it
// would corrupt the state machine (§R2.6 item 5, 11 live failed rows).
var taskUpdateFailureMarkers = []string{
	"<tool_use_error>",
	"Task not found",
}

func taskCallFailed(rawOutput string) bool {
	for _, marker := range taskUpdateFailureMarkers {
		if strings.Contains(rawOutput, marker) {
			return true
		}
	}
	return false
}

// kiroIndexKey builds the stable key for one kiro-cli todo_list task,
// namespaced so it can never collide with a native taskId from an
// unrelated tool sharing the same session id space (defensive; kiro-cli
// sessions never mix with claude-code's in practice, but the namespace
// costs nothing).
func kiroIndexKey(index string) string { return "kirocli:" + index }

// kiroCompletedIndex converts a completed_task_ids VALUE (1-based, per
// §R2.6 item 8) to the 0-based key the create call minted. Returns ""
// if value is not a small non-negative integer string.
func kiroCompletedIndex(value string) string {
	n, err := strconv.Atoi(strings.TrimSpace(value))
	if err != nil || n < 1 {
		return ""
	}
	return strconv.Itoa(n - 1)
}
