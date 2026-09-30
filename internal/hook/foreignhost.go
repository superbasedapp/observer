package hook

import (
	"encoding/json"

	"github.com/marmutapp/superbased-observer/internal/adapter/cursor"
)

// Another host can run the hook commands a user registered for Claude
// Code. cursor-agent does (grounded against the 2026.08.25 bundle, and the
// 2026.09.18 debug log's `cli.hook.executed` records with
// hookSource "claude-user"): it loads ~/.claude/settings.json (plus the
// project's .claude/settings*.json), maps each Claude event onto its own
// step (UserPromptSubmit -> beforeSubmitPrompt, PreToolUse -> preToolUse,
// PostToolUse -> postToolUse, Stop -> stop, SubagentStop -> subagentStop,
// SessionStart -> sessionStart, SessionEnd -> sessionEnd, PreCompact ->
// preCompact) and runs the command with the SAME stdin payload it gives its
// own hooks: Cursor's field set, `hook_event_name` set to the Cursor step
// name, and `cursor_version` always present. The hookSource label lives
// only in Cursor's own analytics log, never in the payload.
//
// Such a payload reaching the claude-code receiver is not a Claude Code
// event. Observer's cursor receiver already sees the same call through
// Cursor's own hooks.json, so handling it again would evaluate the guard
// twice (and answer in Claude Code's reply dialect, which Cursor partly
// honours), write pidbridge / compaction / account rows under the wrong
// tool, and count nothing Observer does not already have.

// hostProbe is the part of a hook payload the signature table reads.
type hostProbe struct {
	CursorVersion *string `json:"cursor_version"`
	HookEventName string  `json:"hook_event_name"`
}

// cursorSteps are the Cursor step names cursor-agent puts in
// hook_event_name when it runs a Claude Code hook (the targets of its
// Claude-event mapping). Claude Code itself spells every event in
// PascalCase, so none of these can come from Claude Code.
var cursorSteps = map[string]bool{
	cursor.EventBeforeSubmitPrompt: true,
	cursor.EventPreToolUse:         true,
	cursor.EventPostToolUse:        true,
	cursor.EventStop:               true,
	cursor.EventSubagentStop:       true,
	cursor.EventSessionStart:       true,
	cursor.EventSessionEnd:         true,
	cursor.EventPreCompact:         true,
}

// foreignHostSignatures is the ordered signature table: the first row
// whose match holds names the host. Adding a host that runs Claude Code
// hooks is adding a row.
var foreignHostSignatures = []struct {
	host  string
	match func(hostProbe) bool
}{
	{host: "cursor", match: func(p hostProbe) bool { return p.CursorVersion != nil }},
	{host: "cursor", match: func(p hostProbe) bool { return cursorSteps[p.HookEventName] }},
}

// ForeignClaudeHookHost reports the host that sent a payload to a Claude
// Code hook command when that host is NOT Claude Code ("" and false for a
// genuine Claude Code payload, or one that does not decode - the caller
// then proceeds exactly as before).
func ForeignClaudeHookHost(body []byte) (string, bool) {
	var p hostProbe
	if err := json.Unmarshal(body, &p); err != nil {
		return "", false
	}
	for _, row := range foreignHostSignatures {
		if row.match(p) {
			return row.host, true
		}
	}
	return "", false
}
