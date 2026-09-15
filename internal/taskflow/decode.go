package taskflow

import (
	"encoding/json"
	"sort"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/models"
)

// itemDecodeFunc turns one call's (raw_tool_input, raw_tool_output)
// into its items. rawOutput is "" for tools that never carry one.
type itemDecodeFunc func(rawInput, rawOutput string) ([]TaskItem, bool)

// failureCheckFunc reports whether a call's own output means the update
// was rejected — see decoderEntry.checkFail.
type failureCheckFunc func(rawOutput string) bool

// decoderEntry is one row of the (tool, raw_tool_name) → shape table
// (§R2.2/§R2.6 item 1: "query by raw_tool_name, never by action_type
// alone"). names are matched case-insensitively after TrimSpace.
type decoderEntry struct {
	tool      string
	names     []string
	kind      TaskEventKind
	kindFor   func(string, string) TaskEventKind
	decode    itemDecodeFunc
	checkFail failureCheckFunc
}

// decoderTable is the COMPLETE registered set (CLAUDE.md #5: data, not
// an if/else ladder). Deliberately ABSENT — by design, not oversight —
// from this table:
//
//   - claude-code TaskStop / TaskOutput / TaskList: background-shell
//     control on a different id namespace, not checklist tools (§2.1
//     finding 5). Their actions.action_type is (mis-)classified
//     todo_update by tooltax, but they carry no entry here, so
//     Decode's per-name lookup naturally excludes them.
//   - opencode/kilo-code-cli/zcode's exploded `todo.<status>` /
//     `todoread` rows: the SAME facts as their sibling `todowrite`
//     call, already captured; decoding both would double-count every
//     transition (§2.3).
//   - cline's `task_progress` parameter: rides on arbitrary tool calls,
//     not a (tool, raw_tool_name) pair — a third shape class this
//     table cannot represent (§2.8). Removed in Cline 4.x; 0 populated
//     instances anywhere. Documented follow-up, not scheduled.
//   - Kiro's file-based `tasks.md` spec workflow and antigravity's
//     unverified `task.md` — file-watch mechanisms, not tool calls.
//   - claude-code `ExitPlanMode` plan documents — prose, not a
//     checklist (orchestrator scope note, 2026-09-07): out of v1.
//   - grok, deepseek, kimi-code, qoder, qwen-code, command-code, muse,
//     mistral-code: zero live rows AND zero fixture payloads anywhere
//     in the corpus (§R2.7) — no grounding to decode against.
var decoderTable = []decoderEntry{
	{
		tool: models.ToolCursor, names: []string{"TodoWrite"}, kind: SnapshotKind,
		decode: decodeCursorTodo, kindFor: cursorTodoKind,
	},
	{
		tool:   models.ToolClaudeCode,
		names:  []string{"TaskCreate"},
		kind:   DeltaKind,
		decode: decodeTaskCreate,
	},
	{
		tool:      models.ToolClaudeCode,
		names:     []string{"TaskUpdate"},
		kind:      DeltaKind,
		decode:    decodeTaskUpdate,
		checkFail: taskCallFailed,
	},
	{
		tool:  models.ToolClaudeCode,
		names: []string{"TodoWrite"},
		kind:  SnapshotKind,
		decode: func(in, _ string) ([]TaskItem, bool) {
			return decodeGenericSnapshot(snapshotShape{
				containerKeys: []string{"todos"},
				contentKeys:   []string{"content"},
			}, in)
		},
	},
	// cowork mirrors claude-code's Task API verbatim (§2.13).
	{tool: models.ToolCowork, names: []string{"TaskCreate"}, kind: DeltaKind, decode: decodeTaskCreate},
	{tool: models.ToolCowork, names: []string{"TaskUpdate"}, kind: DeltaKind, decode: decodeTaskUpdate, checkFail: taskCallFailed},
	{
		tool: models.ToolCowork, names: []string{"TodoWrite"}, kind: SnapshotKind,
		decode: func(in, _ string) ([]TaskItem, bool) {
			return decodeGenericSnapshot(snapshotShape{
				containerKeys: []string{"todos"},
				contentKeys:   []string{"content"},
			}, in)
		},
	},
	// codex update_plan, and its open-interpreter rebadge alias (which
	// carries the identical shape verbatim, §1.1).
	{
		tool: models.ToolCodex, names: []string{"update_plan"}, kind: SnapshotKind,
		decode: func(in, _ string) ([]TaskItem, bool) { return decodeCodexUpdatePlan(in) },
	},
	{
		tool: models.ToolOpenInterpreter, names: []string{"update_plan"}, kind: SnapshotKind,
		decode: func(in, _ string) ([]TaskItem, bool) { return decodeCodexUpdatePlan(in) },
	},
	// gemini-cli write_todos (§2.6 / §R2.1 item 1 — the tooltax row
	// this decoder depends on is added alongside it in
	// internal/tooltax/table.go).
	{
		tool: models.ToolGeminiCLI, names: []string{"write_todos", "writetodos"}, kind: SnapshotKind,
		decode: func(in, _ string) ([]TaskItem, bool) {
			return decodeGenericSnapshot(snapshotShape{
				containerKeys: []string{"todos"},
				contentKeys:   []string{"description"},
			}, in)
		},
	},
	// opencode / kilo-code-cli / zcode: only the raw whole-list call,
	// never the exploded per-item rows (see the table doc comment).
	{
		tool: models.ToolOpenCode, names: []string{"todowrite"}, kind: SnapshotKind,
		decode: func(in, _ string) ([]TaskItem, bool) {
			return decodeGenericSnapshot(snapshotShape{
				containerKeys: []string{"todos"},
				contentKeys:   []string{"content"},
			}, in)
		},
	},
	{
		tool: models.ToolKiloCodeCLI, names: []string{"todowrite"}, kind: SnapshotKind,
		decode: func(in, _ string) ([]TaskItem, bool) {
			return decodeGenericSnapshot(snapshotShape{
				containerKeys: []string{"todos"},
				contentKeys:   []string{"content"},
			}, in)
		},
	},
	{
		tool: models.ToolZcode, names: []string{"todowrite"}, kind: SnapshotKind,
		decode: func(in, _ string) ([]TaskItem, bool) {
			return decodeGenericSnapshot(snapshotShape{
				containerKeys: []string{"todos"},
				contentKeys:   []string{"content"},
			}, in)
		},
	},
	// copilot (VS Code core) manage_todo_list — the rare KEYED snapshot.
	{
		tool: models.ToolCopilot, names: []string{"manage_todo_list", "managetodolist"}, kind: SnapshotKind,
		decode: func(in, _ string) ([]TaskItem, bool) {
			return decodeGenericSnapshot(snapshotShape{
				containerKeys: []string{"todoList"},
				contentKeys:   []string{"title"},
				idKey:         "id",
			}, in)
		},
	},
	// freebuff write_todos — ALSO a keyed snapshot, but a DIFFERENT item
	// shape than gemini-cli's identically-named tool (§2.6 / §R2.2 item
	// 13) — proof the table must key on (tool, name), never name alone.
	{
		tool: models.ToolFreebuff, names: []string{"write_todos", "writetodos"}, kind: SnapshotKind,
		decode: func(in, _ string) ([]TaskItem, bool) {
			return decodeGenericSnapshot(snapshotShape{
				containerKeys: []string{"todos"},
				contentKeys:   []string{"text"},
				idKey:         "id",
			}, in)
		},
	},
	// poolside todo_action — flat, content-addressed Delta.
	{
		tool: models.ToolPoolside, names: []string{"todo_action"}, kind: DeltaKind,
		decode: decodePoolsideTodoAction,
	},
	// kiro-cli todo_list — index-keyed-object Delta.
	{
		tool: models.ToolKiroCLI, names: []string{"todo_list"}, kind: DeltaKind,
		decode: decodeKiroTodoList,
	},
	// droid TodoWrite — JSON array (all live rows) or lossy markdown
	// string (emitTodo path, §2.10).
	{
		tool: models.ToolDroid, names: []string{"TodoWrite"}, kind: SnapshotKind,
		decode: func(in, _ string) ([]TaskItem, bool) { return decodeDroidTodo(in) },
	},
	// hermes todo — defensive best-effort, no grounding (§2.9).
	{
		tool: models.ToolHermes, names: []string{"todo"}, kind: DeltaKind,
		decode: decodeHermesTodo,
	},
}

// decoderIndex is decoderTable rebuilt as a (tool, lower(name)) lookup
// map at init, so Decode is O(1) per action instead of scanning the
// whole table.
var decoderIndex = buildDecoderIndex()

func buildDecoderIndex() map[string]map[string]decoderEntry {
	idx := make(map[string]map[string]decoderEntry, len(decoderTable))
	for _, e := range decoderTable {
		byName, ok := idx[e.tool]
		if !ok {
			byName = make(map[string]decoderEntry)
			idx[e.tool] = byName
		}
		for _, n := range e.names {
			byName[strings.ToLower(strings.TrimSpace(n))] = e
		}
	}
	return idx
}

func lookupDecoder(tool, rawToolName string) (decoderEntry, bool) {
	byName, ok := decoderIndex[tool]
	if !ok {
		return decoderEntry{}, false
	}
	e, ok := byName[strings.ToLower(strings.TrimSpace(rawToolName))]
	return e, ok
}

// RegisteredRawToolNames returns every distinct raw_tool_name
// decoderTable knows about (original casing, deduplicated
// case-insensitively). This is the store seam's substrate for a cheap
// SQL `raw_tool_input LIKE '%<name>%'` pre-filter over post_tool_batch
// rows BEFORE json.Unmarshal — only claude-code/cowork's Task API and
// TodoWrite calls are ever wrapped in a post_tool_batch envelope
// (decoderTable's own doc comment), so this list is deliberately the
// package's single source of truth for "what could possibly be inside
// one" rather than a second, hand-maintained copy at the store layer.
// SQLite's LIKE is case-insensitive for ASCII by default, so callers
// don't need the lowercase form separately.
func RegisteredRawToolNames() []string {
	seen := make(map[string]bool)
	var names []string
	for _, e := range decoderTable {
		for _, n := range e.names {
			key := strings.ToLower(n)
			if seen[key] {
				continue
			}
			seen[key] = true
			names = append(names, n)
		}
	}
	sort.Strings(names)
	return names
}

// ActionInput is the store seam's projection of one actions row — the
// only shape this package reads. It never sees a database row directly
// (CLAUDE.md module boundary #1).
type ActionInput struct {
	Tool          string
	RawToolName   string
	ActionType    string
	RawToolInput  string
	RawToolOutput string
	SessionID     string
	ActionID      int64
	SourceEventID string
	Ts            int64 // Unix nanoseconds — the caller owns time parsing
	// MatchMode is [tasks].match_mode ("" and "exact" are equivalent —
	// the default). See applyMatchMode's doc comment (status.go) for
	// why this is a post-decode recompute rather than a parameter
	// threaded through every decoderTable entry.
	MatchMode string
}

// postToolBatchEnvelope is one element of a claude-code post_tool_batch
// row's raw_tool_input array (§R2.2's `post_tool_batch rows` entry).
type postToolBatchEnvelope struct {
	ToolName     string          `json:"tool_name"`
	ToolUseID    string          `json:"tool_use_id"`
	ToolInput    json.RawMessage `json:"tool_input"`
	ToolResponse json.RawMessage `json:"tool_response"`
}

// Decode turns one action row into zero or more TaskEvents. A
// post_tool_batch row can yield several (one per decodable envelope
// element); every other action_type yields at most one. The caller
// (internal/store/taskflow.go) is expected to pre-filter to
// action_type ∈ {todo_update, task_complete, post_tool_batch} before
// calling — Decode itself is defensive regardless (an unrecognized
// action_type or (tool, raw_tool_name) pair simply yields nothing).
func Decode(in ActionInput) []TaskEvent {
	switch in.ActionType {
	case "post_tool_batch":
		return decodeBatch(in)
	default:
		if ev, ok := decodeOne(in.Tool, in.RawToolName, in.RawToolInput, in.RawToolOutput,
			in.SessionID, in.ActionID, in.SourceEventID, in.Ts, in.MatchMode); ok {
			return []TaskEvent{ev}
		}
		return nil
	}
}

func decodeOne(tool, rawToolName, rawInput, rawOutput, sessionID string, actionID int64, sourceEventID string, ts int64, matchMode string) (TaskEvent, bool) {
	entry, ok := lookupDecoder(tool, rawToolName)
	if !ok {
		return TaskEvent{}, false
	}
	items, ok := entry.decode(rawInput, rawOutput)
	if !ok {
		return TaskEvent{}, false
	}
	if entry.kindFor != nil {
		entry.kind = entry.kindFor(rawInput, rawOutput)
	}
	// A Delta call that produced zero items decoded nothing meaningful
	// (every decodeXxx in delta.go already returns ok=false for that
	// case; this is defensive). A Snapshot call that legitimately
	// rewrote the list down to EMPTY ("clear my todos") is different: it
	// is real information — every previously-tracked item vanished —
	// and must still become a TaskEvent so the store seam's vanish
	// bookkeeping (§R2.3.4, FIX-2) runs. Dropping it here would silently
	// leave an in_progress item's window open forever.
	if len(items) == 0 && entry.kind != SnapshotKind {
		return TaskEvent{}, false
	}
	items = dropEmptyContentItems(items)
	if len(items) == 0 && entry.kind != SnapshotKind {
		// Every item this Delta call carried was a content_hash item
		// with no text at all — nothing to key on, nothing to report.
		return TaskEvent{}, false
	}
	applyMatchMode(items, matchMode)
	ev := TaskEvent{
		Tool:          tool,
		RawToolName:   rawToolName,
		SessionID:     sessionID,
		ActionID:      actionID,
		SourceEventID: sourceEventID,
		Ts:            unixNanoToTime(ts),
		Kind:          entry.kind,
		Items:         items,
	}
	if entry.checkFail != nil && entry.checkFail(rawOutput) {
		ev.Failed = true
	}
	return ev, true
}

// dropEmptyContentItems removes any content_hash item with no text at
// all. A KeyNative item is never dropped, even with empty content — a
// real vendor id can legitimately carry a status-only update (§R2.2's
// content-only-edit sibling). But a content_hash item with Content==""
// has nothing to key on: ContentKey("")/NormalizedContentKey("") both
// hash to the SAME fixed value regardless of which array-element or
// call produced it, so two unrelated empty-content items (e.g. a
// snapshot array element missing its content field entirely) would
// silently collide onto one bogus task_items row instead of being
// reported as what they are — nothing worth tracking.
func dropEmptyContentItems(items []TaskItem) []TaskItem {
	out := items[:0]
	for _, it := range items {
		if it.KeyKind == KeyContent && strings.TrimSpace(it.Content) == "" {
			continue
		}
		out = append(out, it)
	}
	return out
}

func decodeBatch(in ActionInput) []TaskEvent {
	var envelopes []postToolBatchEnvelope
	if err := json.Unmarshal([]byte(in.RawToolInput), &envelopes); err != nil {
		return nil
	}
	var events []TaskEvent
	for _, env := range envelopes {
		if env.ToolName == "" || env.ToolUseID == "" {
			continue
		}
		ev, ok := decodeOne(in.Tool, env.ToolName, rawMessageToString(env.ToolInput),
			rawMessageToString(env.ToolResponse), in.SessionID, in.ActionID, env.ToolUseID, in.Ts, in.MatchMode)
		if !ok {
			continue
		}
		events = append(events, ev)
	}
	return events
}

func rawMessageToString(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	// tool_response inside a post_tool_batch envelope is sometimes a
	// bare JSON string (the text rendering) and sometimes a structured
	// object; either way the decoders below only need the string form
	// they'd have seen on the direct-action path.
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s
	}
	return string(raw)
}
