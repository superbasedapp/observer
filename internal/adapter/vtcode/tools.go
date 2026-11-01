package vtcode

import (
	"encoding/json"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/models"
)

// mapVTCodeTool collapses VT Code's tool vocabulary onto the normalized
// action set. The vocabulary is grounded three ways (2026-10-21, 0.180.2):
// live sessions on both OSes (exec_command, code_search), the per-workspace
// `.vtcode/tool-policy.json` the binary writes (apply_patch, exec_command,
// record_decision, search_tools, write_stdin, load_skill, memory,
// start_planning, code_search, web_fetch, web_search, task_tracker,
// request_user_input, list_skills, mcp, load_skill_resource), and the
// trajectory `ordered_wire_tool_names` (exec_command, code_search,
// record_decision, request_user_input). Matching is case-insensitive with
// `_`/`-` stripped. The raw name is preserved on ToolEvent.RawToolName;
// anything else maps to ActionUnknown (the tooltax global `mcp__*` glob
// still catches a provider-qualified MCP name downstream).
func mapVTCodeTool(name string) string {
	key := strings.ToLower(strings.TrimSpace(name))
	key = strings.ReplaceAll(key, "_", "")
	key = strings.ReplaceAll(key, "-", "")
	switch key {
	case "execcommand":
		// Shell command through the active shell profile (the harness
		// stamps an `action:"run"` arg next to `cmd`).
		return models.ActionRunCommand
	case "writestdin":
		// Feeds a live exec_command session — codex write_stdin.
		return models.ActionStdinWrite
	case "applypatch":
		// Freeform patch for edits / adds / moves / deletes — codex.
		return models.ActionEditFile
	case "codesearch":
		// Bounded literal search for definitions / usages / text / paths.
		return models.ActionSearchText
	case "searchtools":
		// Searches the deferred tool catalog.
		return models.ActionToolSearch
	case "webfetch":
		return models.ActionWebFetch
	case "websearch":
		return models.ActionWebSearch
	case "requestuserinput":
		return models.ActionAskUser
	case "tasktracker":
		return models.ActionTodoUpdate
	case "startplanning":
		// Enters planning mode — the plan-mode toggle bucket.
		return models.ActionPermissionMode
	case "loadskill", "loadskillresource":
		return models.ActionSkillInvoke
	case "listskills", "recorddecision", "memory":
		// Harness-owned bookkeeping: enumerate skills, record a decision
		// in the session ledger, read/write the memory store.
		return models.ActionHarnessCall
	case "mcp":
		// The MCP gateway tool (`action: search_tools` / a provider call).
		return models.ActionMCPCall
	default:
		return models.ActionUnknown
	}
}

// argsMap decodes a tool invocation's arguments into a map. Arguments are
// an object on item.completed; a string-typed value (the streaming
// item.updated shape) is decoded as JSON text when it parses. Returns nil
// when there is nothing decodable.
func argsMap(raw json.RawMessage) map[string]any {
	if len(raw) == 0 || string(raw) == "null" {
		return nil
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err == nil {
		return m
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		if json.Unmarshal([]byte(s), &m) == nil {
			return m
		}
	}
	return nil
}

// patchText returns the freeform patch body of an apply_patch call: a bare
// string argument, or the `input` / `patch` key of an object.
func patchText(raw json.RawMessage, m map[string]any) string {
	for _, k := range []string{"input", "patch"} {
		if v, ok := m[k].(string); ok && v != "" {
			return v
		}
	}
	var s string
	if json.Unmarshal(raw, &s) == nil && strings.Contains(s, "*** ") {
		return s
	}
	return ""
}

// toolTarget picks the representative target for a call: the command for
// exec_command, the first file of a patch for apply_patch, the query for
// the search tools, then the common path / url / query keys, falling back
// to the tool name.
func toolTarget(name string, raw json.RawMessage, m map[string]any) string {
	str := func(keys ...string) string {
		for _, k := range keys {
			if v, ok := m[k].(string); ok && strings.TrimSpace(v) != "" {
				return v
			}
		}
		return ""
	}
	var t string
	switch mapVTCodeTool(name) {
	case models.ActionRunCommand:
		t = str("cmd", "command")
	case models.ActionEditFile:
		t = applyPatchTarget(patchText(raw, m))
	case models.ActionStdinWrite:
		t = str("session_id")
	case models.ActionSearchText, models.ActionToolSearch, models.ActionWebSearch:
		t = str("query")
	case models.ActionWebFetch:
		t = str("url")
	}
	if t == "" {
		t = str("path", "file_path", "url", "query", "cmd", "command", "action", "name")
	}
	return firstNonEmpty(t, name)
}

// applyPatchTarget pulls the first changed file path out of the
// Codex-style patch envelope (`*** Add File:` / `*** Update File:` /
// `*** Delete File:` / `*** Move File:` headers). Returns "" when the text
// does not follow that format.
func applyPatchTarget(patch string) string {
	for _, line := range strings.Split(patch, "\n") {
		line = strings.TrimSpace(line)
		rest, ok := strings.CutPrefix(line, "*** ")
		if !ok {
			continue
		}
		for _, header := range []string{"Add File:", "Update File:", "Delete File:", "Move File:"} {
			if p, ok := strings.CutPrefix(rest, header); ok {
				return strings.TrimSpace(p)
			}
		}
	}
	return ""
}

// patchAddedBytes counts the bytes of authored (`+`) lines in a patch
// envelope, for the Output-Composition ContentBytes column. `+++` file
// headers are not content.
func patchAddedBytes(patch string) int64 {
	var n int64
	for _, line := range strings.Split(patch, "\n") {
		if strings.HasPrefix(line, "+") && !strings.HasPrefix(line, "+++") {
			n += int64(len(line) - 1)
		}
	}
	return n
}
