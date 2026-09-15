package dashboard

import (
	"net/http"
	"sort"
	"strings"
	"unicode"
)

// messageSortDefaultKey is the sort column that reproduces the endpoint's
// historical (pre-sort) behaviour: the chronological ordinal assigned right
// after the authoritative merge sort. Ascending on this key is a no-op
// permutation, so a caller that passes no sort params gets byte-identical
// output to the pre-v1.26 handler.
const messageSortDefaultKey = "seq"

// messageSortField is the flat projection of one /api/session/<id>/messages
// row's sortable values. It exists so the comparator table can live at
// package scope (and be unit-tested) while the wire struct stays a local type
// inside handleSessionMessages — extending the wire struct never forces a
// change here, and vice versa.
//
// The nullable columns are pointers on purpose: "no value" is a distinct
// state from zero and is sunk to the bottom of the table in BOTH directions
// (see messageSortOrder).
type messageSortField struct {
	// Seq is the 1..N chronological ordinal. It is the default sort key AND
	// the final tie-break for every other key, so equal values never jitter
	// between auto-refresh polls.
	Seq            int
	Timestamp      string
	MessageID      string
	Role           string
	Model          string
	Account        string
	AccountUnknown bool
	EffortLevel    string
	Input          int64
	CacheRead      int64
	CacheWrite     int64
	Output         int64
	ElapsedMs      *int64
	TokensPerSec   *float64
	ToolCalls      int
	AICostUSD      float64
	ToolCostUSD    float64
	CostUSD        float64
	// Content mirrors the string the table's Content cell renders (see
	// messageContentSortKey) so sorting matches what the operator reads.
	Content string
}

// messageSortComparator is one row of the sort allow-list: how to order two
// rows by a column, plus how to detect a row that has no value for it.
//
// less must implement a strict weak ordering IGNORING direction and
// nullability; messageSortOrder layers direction, the null-sink and the seq
// tie-break on top. missing may be nil for columns that are never absent.
type messageSortComparator struct {
	less    func(a, b messageSortField) bool
	missing func(f messageSortField) bool
}

// messageSortKeys is the allow-list of sortable columns for
// /api/session/<id>/messages, keyed by the `sort_by` query value. The keys are
// exactly the 17 columns the dashboard's Messages table renders, in table
// order. A key that is not in this table falls back to the default
// (messageSortDefaultKey, ascending) — an unknown column is never an error.
//
// Table-driven by design (CLAUDE.md rule 5): adding a column is one row here
// plus one row in the test table, never a new branch in a conditional ladder.
var messageSortKeys = map[string]messageSortComparator{
	"account": {
		less:    func(a, b messageSortField) bool { return strings.ToLower(a.Account) < strings.ToLower(b.Account) },
		missing: func(f messageSortField) bool { return f.AccountUnknown },
	},
	"seq":       {less: func(a, b messageSortField) bool { return a.Seq < b.Seq }},
	"timestamp": {less: func(a, b messageSortField) bool { return a.Timestamp < b.Timestamp }},
	"message_id": {
		less: func(a, b messageSortField) bool {
			return strings.ToLower(a.MessageID) < strings.ToLower(b.MessageID)
		},
	},
	"role": {less: func(a, b messageSortField) bool { return a.Role < b.Role }},
	"model": {
		less: func(a, b messageSortField) bool {
			return strings.ToLower(a.Model) < strings.ToLower(b.Model)
		},
	},
	"effort_level": {
		less: func(a, b messageSortField) bool {
			return messageEffortRank(a.EffortLevel) < messageEffortRank(b.EffortLevel)
		},
		// An adapter that exposes no effort knob (Anthropic models, copilot,
		// …) leaves the column empty, and that is the MAJORITY value on real
		// data. Treat it as absent — same null-sink as elapsed_ms /
		// tokens_per_sec — so neither direction opens with a screenful of "—".
		missing: func(f messageSortField) bool { return strings.TrimSpace(f.EffortLevel) == "" },
	},
	"input":          {less: func(a, b messageSortField) bool { return a.Input < b.Input }},
	"cache_read":     {less: func(a, b messageSortField) bool { return a.CacheRead < b.CacheRead }},
	"cache_creation": {less: func(a, b messageSortField) bool { return a.CacheWrite < b.CacheWrite }},
	"output":         {less: func(a, b messageSortField) bool { return a.Output < b.Output }},
	"elapsed_ms": {
		less:    func(a, b messageSortField) bool { return *a.ElapsedMs < *b.ElapsedMs },
		missing: func(f messageSortField) bool { return f.ElapsedMs == nil },
	},
	"tokens_per_sec": {
		less:    func(a, b messageSortField) bool { return *a.TokensPerSec < *b.TokensPerSec },
		missing: func(f messageSortField) bool { return f.TokensPerSec == nil },
	},
	"tool_call_count": {less: func(a, b messageSortField) bool { return a.ToolCalls < b.ToolCalls }},
	"ai_cost_usd":     {less: func(a, b messageSortField) bool { return a.AICostUSD < b.AICostUSD }},
	"tool_cost_usd":   {less: func(a, b messageSortField) bool { return a.ToolCostUSD < b.ToolCostUSD }},
	"cost_usd":        {less: func(a, b messageSortField) bool { return a.CostUSD < b.CostUSD }},
	"content": {
		less: func(a, b messageSortField) bool {
			return strings.ToLower(a.Content) < strings.ToLower(b.Content)
		},
	},
}

// messageEffortOrder ranks the reasoning-effort vocabulary so the Effort
// column sorts by intensity rather than alphabetically ("high" < "low" <
// "medium" reads as nonsense to an operator).
//
// Empty is NOT in this table: it is handled as a null-sink by the
// "effort_level" comparator's missing func, so it lands last in BOTH
// directions like every other nullable column.
var messageEffortOrder = map[string]int{
	"none":    1,
	"minimal": 2,
	"low":     3,
	"medium":  4,
	"high":    5,
	"max":     6,
}

// messageEffortRankUnknown ranks an unrecognised NON-EMPTY effort value BELOW
// the known ladder. A value we cannot place is not "more effort than high" —
// putting it above the ladder made the descending sort (the useful direction:
// "show me the expensive turns first") open with unplaceable strings.
const messageEffortRankUnknown = 0

// messageEffortRank maps an effort_level string onto messageEffortOrder,
// returning a sentinel BELOW the known ladder for unrecognised values. Empty
// input never reaches a comparison (it is null-sunk first) but ranks with the
// unknowns for defensiveness.
func messageEffortRank(s string) int {
	if r, ok := messageEffortOrder[strings.ToLower(strings.TrimSpace(s))]; ok {
		return r
	}
	return messageEffortRankUnknown
}

// parseMessagesSortParams reads sort_by / sort_dir off the request, clamping
// sort_by to the messageSortKeys allow-list. An absent or unrecognised sort_by
// resolves to the default (chronological ordinal, ascending) INCLUDING the
// direction, so every legacy caller — and any client that sends garbage — gets
// exactly the historical response. Direction only flips on the literal "desc".
func parseMessagesSortParams(r *http.Request) (sortBy string, desc bool) {
	sortBy = strings.ToLower(strings.TrimSpace(r.URL.Query().Get("sort_by")))
	if _, ok := messageSortKeys[sortBy]; !ok {
		return messageSortDefaultKey, false
	}
	desc = strings.EqualFold(strings.TrimSpace(r.URL.Query().Get("sort_dir")), "desc")
	return sortBy, desc
}

// messageSortIsDefault reports whether a resolved (sortBy, desc) pair is the
// identity permutation — the chronological order the rows already carry.
// Callers use it to skip the reorder entirely on the hot default path.
func messageSortIsDefault(sortBy string, desc bool) bool {
	return sortBy == messageSortDefaultKey && !desc
}

// messageSortOrder returns the permutation of indices into fields that puts
// them in the requested order. It is total and never panics: an unknown
// sortBy falls back to the seq COMPARATOR (chronological order). Note that is
// not the identity permutation — it sorts by Seq, so a caller that passes
// fields already out of chronological order gets them reordered, not returned
// as-is. (The handler always passes chronological input, where the two
// coincide; messageSortIsDefault is what lets it skip the call entirely.)
//
// Three properties the Messages table depends on:
//
//   - Null-sink. A row whose value for the column is absent (elapsed_ms on the
//     last chronological message; tokens_per_sec when there is no output or no
//     timing basis; effort_level for an adapter with no effort knob) sorts
//     LAST in BOTH directions. Flipping direction must not drag the "—" rows
//     to the top of the table.
//   - Stability + seq tie-break. Ties resolve on the chronological ordinal
//     ascending, in both directions, so a 4s auto-refresh poll can never
//     reshuffle equal rows.
//   - Order-independence. The result depends only on the field values, not on
//     the slice's incoming order (the caller always passes chronological
//     order, but the tie-break makes that irrelevant).
func messageSortOrder(fields []messageSortField, sortBy string, desc bool) []int {
	idx := make([]int, len(fields))
	for i := range idx {
		idx[i] = i
	}
	cmp, ok := messageSortKeys[sortBy]
	if !ok {
		cmp = messageSortKeys[messageSortDefaultKey]
	}
	missing := cmp.missing
	if missing == nil {
		missing = func(messageSortField) bool { return false }
	}
	sort.SliceStable(idx, func(x, y int) bool {
		a, b := fields[idx[x]], fields[idx[y]]
		am, bm := missing(a), missing(b)
		switch {
		case am && bm:
			return a.Seq < b.Seq
		case am:
			return false // null sinks: never before a present value
		case bm:
			return true
		}
		switch {
		case cmp.less(a, b):
			return !desc
		case cmp.less(b, a):
			return desc
		default:
			return a.Seq < b.Seq // stable tie-break, direction-independent
		}
	})
	return idx
}

// messageContentActionLabels mirrors the frontend ACTION_REGISTRY labels
// (web/src/lib/actions.ts) so the server can sort the Content column by the
// same string the cell renders. Kept as a plain table; an action_type absent
// here is humanized the same way the frontend's fallback does.
var messageContentActionLabels = map[string]string{
	"read_file":              "Read file",
	"write_file":             "Write file",
	"edit_file":              "Edit file",
	"run_command":            "Run command",
	"search_text":            "Search text",
	"search_files":           "Search files",
	"web_search":             "Web search",
	"web_fetch":              "Web fetch",
	"spawn_subagent":         "Spawn subagent",
	"subagent_start":         "Subagent start",
	"subagent_stop":          "Subagent stop",
	"mcp_call":               "MCP call",
	"user_prompt":            "User prompt",
	"user_prompt_expansion":  "Prompt expansion",
	"ask_user":               "Ask user",
	"system_prompt":          "System prompt",
	"prompt_context":         "Prompt context",
	"task_complete":          "Task complete",
	"permission_request":     "Permission request",
	"permission_denied":      "Permission denied",
	"post_tool_batch":        "Post-tool batch",
	"setup":                  "Setup",
	"instructions_loaded":    "Instructions loaded",
	"config_change":          "Config change",
	"session_start":          "Session start",
	"session_end":            "Session end",
	"notification":           "Notification",
	"cwd_change":             "CWD change",
	"todo_update":            "Todo update",
	"context_compacted":      "Context compacted",
	"rate_limit":             "Rate limit",
	"turn_aborted":           "Turn aborted",
	"tool_failure":           "Tool failure",
	"api_error":              "API error",
	"llm_call":               "Llm Call",
	"assistant_message":      "Assistant Message",
	"unknown":                "Unknown",
	"session_pause":          "Session Pause",
	"prompt_cache_read":      "Prompt Cache Read",
	"model_change":           "Model Change",
	"compaction_reset":       "Compaction Reset",
	"tool_result":            "Tool Result",
	"assistant_reasoning":    "Assistant Reasoning",
	"user_prompt_attachment": "User Prompt Attachment",
}

// messageContentActionLabel returns the human label for an action_type,
// humanizing unknown keys ("foo_bar" → "Foo Bar") exactly like the frontend's
// actionMeta fallback so ordering matches the rendered cell.
func messageContentActionLabel(actionType string) string {
	if actionType == "" {
		return "Unknown"
	}
	if l, ok := messageContentActionLabels[actionType]; ok {
		return l
	}
	words := strings.Split(strings.ReplaceAll(actionType, "_", " "), " ")
	for i, w := range words {
		if w == "" {
			continue
		}
		r := []rune(w)
		r[0] = unicode.ToUpper(r[0])
		words[i] = string(r)
	}
	return strings.Join(words, " ")
}

// messageContentSortKey reproduces the Content cell's rendered text for the
// first tool call of a message: "<action label>" or "<action label> · <target
// truncated to 60>". A message with no tool calls renders "—" and sorts as the
// empty string (it is a real "nothing here" value, not a null-sink case).
//
// Known cosmetic divergence: on ANY MCP-bearing row the cell diverges from
// this key. ContentSnippet (web/src/components/SessionDetailPanel.tsx) does
// tool_calls.find(mcpIdentity) and, on any hit, renders an MCP badge plus that
// call's target — never the action-label string this key builds, not even when
// tool_calls[0] is itself the MCP call. Ordering stays deterministic and
// stable, and MCP rows still group together (they share the "MCP call · …"
// prefix); only the visual label differs on those rows.
func messageContentSortKey(actionType, target string) string {
	label := messageContentActionLabel(actionType)
	if target == "" {
		return label
	}
	return label + " · " + messageTruncate(target, 60)
}

// messageTruncate mirrors the frontend truncate(): at most n runes, with the
// last replaced by an ellipsis when the string is longer.
func messageTruncate(s string, n int) string {
	if s == "" {
		return ""
	}
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n-1]) + "…"
}
