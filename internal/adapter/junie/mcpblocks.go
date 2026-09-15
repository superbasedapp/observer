package junie

import (
	"encoding/json"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/models"
)

// This file owns Junie's MCP-TOOL lane: the block kinds a Junie run
// emits when its tools are served by an MCP server rather than by the
// agent's own built-in Terminal / FileChanges executors.
//
// # Why the lane exists (grounded 2026-09-03)
//
// The 2026-08-16 Phase-0 capture (testdata/junie/session-260816-…) was
// a Junie run whose file and shell work landed as
// TerminalBlockUpdatedEvent / FileChangesBlockUpdatedEvent. The
// 2026-09-03 capture of the SAME five-turn prompt kit, run through
// IntelliJ IDEA 2026.2 AI Assistant, contains ZERO of either: all eight
// tool calls — list the project, create hello_world.py, run it, patch
// it, run it again, delete it, list again — arrived as
// McpBlockUpdatedEvent, because the IDE serves its own tools to Junie
// over MCP (`idea/…`). Before this file those 42 events were skipped
// silently and the whole run reduced to 3 actions (session start, user
// prompt, result). That is the capture gap this lane closes.
//
// The lane is NOT a second parser: MCP blocks reuse the SAME
// "step:"+stepId SourceEventID, the same stepIdx collapse and the same
// terminal-status semantics as Terminal/FileChanges blocks, so a block
// that recurs (IN_PROGRESS → COMPLETED → the task's completion
// rebroadcast) updates one row in place instead of appending copies.
//
// # Sibling kinds in the same capture
//
//   - ViewFilesBlockUpdatedEvent (6 events / 2 steps) is the agent
//     READING files — the IDE's own "open file" / "get structure"
//     affordances, which do not go through MCP. Mapped here to
//     ActionReadFile.
//   - ToolBlockUpdatedEvent (3 events / 2 steps) is a GENERIC
//     "a tool is running" label carrying only free text ("Open
//     text.iml"). Every occurrence in the capture shares its stepId
//     with a ViewFiles block that says the same thing with structure,
//     so it is deliberately NOT mapped: doing so would either
//     double-count the step or overwrite the specialised row's action
//     type with a generic one. If a future capture shows a
//     ToolBlockUpdatedEvent stepId with no specialised sibling, this is
//     the note to revisit.
//   - `cancelRequest` appears on 7 of the 8 MCP steps and is NOT a
//     cancellation — it is the UI's "cancel this running step" handle,
//     present precisely BECAUSE the step is still running. It is never
//     decoded, and must never be read as a failure signal.
//   - `approvalRequest` (1 occurrence) IS meaningful: it is the
//     permission prompt the IDE raised before the first `idea/…` call,
//     and it becomes its own ActionPermissionRequest row.
//
// # Environment variables
//
// EnvironmentVariablesUpdatedEvent (24 events in the capture) carries
// the operator's entire process environment. It is not decoded, not
// emitted, and not fixtured — see the package doc's off-limits list.

// MCP-lane agentEvent.kind discriminators.
const (
	agentKindMcpBlock       = "McpBlockUpdatedEvent"
	agentKindViewFilesBlock = "ViewFilesBlockUpdatedEvent"
	// agentKindToolBlock is decoded only so the dispatch switch can
	// name it as DELIBERATELY skipped — see the file doc.
	agentKindToolBlock = "ToolBlockUpdatedEvent"
)

// targetKind selects how an [mcpToolRule] pulls the normalized action
// TARGET out of an MCP call's JSON arguments.
type targetKind int

const (
	// targetArg uses the named argument's string value verbatim.
	targetArg targetKind = iota
	// targetPatchFile parses the file path (and the create-vs-modify
	// verb) out of an apply_patch-grammar patch body.
	targetPatchFile
)

// mcpToolRule is one row of [mcpToolRules]: a vendor MCP tool name and
// how to normalize a call to it.
type mcpToolRule struct {
	// ToolName is the verbatim `toolName` the block carries, matched
	// case-insensitively.
	ToolName string
	// ActionType is the normalized models.Action* constant. For a
	// targetPatchFile row it is the DEFAULT, refined per patch verb.
	ActionType string
	// ArgKeys are the JSON keys of `input` to try, in order, for the
	// action target. The first key with a non-empty string value wins.
	ArgKeys []string
	// Target selects the extraction strategy for the chosen value.
	Target targetKind
}

// mcpToolRules is THE table of MCP tool names this adapter normalizes.
// Walked top-down; the first case-insensitive name match wins. Every
// row is grounded on the operator's 2026-09-03 IntelliJ IDEA 2026.2 run
// (the `idea` MCP server the IDE serves to Junie); the vocabulary the
// IDE advertises is much larger (~40 `idea/…` tools), but only names
// actually OBSERVED get a specific row — an unlisted name falls through
// to [mcpFallbackAction] rather than being guessed at.
var mcpToolRules = []mcpToolRule{
	// Listing the project tree. `directoryPath` is "" for the project
	// root (2 of 3 observed calls) — see targetForMCP for what that
	// falls back to.
	{ToolName: "idea/list_directory_tree", ActionType: models.ActionSearchFiles, ArgKeys: []string{"directoryPath"}, Target: targetArg},
	// Creating a file. `overwrite` is carried in the raw input but is
	// not a discriminator: a create-with-overwrite is still a write.
	{ToolName: "idea/create_new_file", ActionType: models.ActionWriteFile, ArgKeys: []string{"pathInProject", "path"}, Target: targetArg},
	// Running a shell command — the same lane the built-in
	// TerminalBlockUpdatedEvent covers on a non-MCP Junie run. The
	// capture's file DELETION arrived here too, as a PowerShell
	// `Remove-Item`: there is no `idea/delete_file` in the observed
	// vocabulary and no delete action type in the normalized set, so a
	// deletion is honestly a run_command.
	{ToolName: "idea/execute_terminal_command", ActionType: models.ActionRunCommand, ArgKeys: []string{"command"}, Target: targetArg},
	// Editing files through the apply_patch grammar.
	{ToolName: "idea/apply_patch", ActionType: models.ActionEditFile, ArgKeys: []string{"patch"}, Target: targetPatchFile},
}

// mcpFallbackAction is what an MCP tool name outside [mcpToolRules]
// normalizes to. It is the honest answer — the call IS an MCP call —
// and the raw vendor name still rides in RawToolName and in Target, so
// a row is never blank and the name is never lost.
const mcpFallbackAction = models.ActionMCPCall

// applyPatchHeaders maps the apply_patch grammar's per-file verbs onto
// the normalized action they really are. Only "Update File" is
// GROUNDED (the single observed patch); the other two are the same
// self-describing grammar and are refined rather than left as the row's
// default edit_file, since a patch that says it ADDS a file is not an
// edit. A header this table does not name leaves the rule's default in
// place.
var applyPatchHeaders = []struct {
	Prefix string
	Action string
}{
	{Prefix: "*** Add File: ", Action: models.ActionWriteFile},
	{Prefix: "*** Update File: ", Action: models.ActionEditFile},
	{Prefix: "*** Delete File: ", Action: models.ActionEditFile},
}

// mcpNormalization is the resolved outcome of one MCP call.
type mcpNormalization struct {
	ActionType string
	Target     string
}

// normalizeMCPCall resolves a block's vendor tool name plus its raw
// `input` JSON into a normalized (action type, target) pair through
// [mcpToolRules]. It never returns an empty Target: an unmatched rule,
// unparseable arguments or an argument present-but-empty all fall back
// to the verbatim tool name.
func normalizeMCPCall(toolName, input string) mcpNormalization {
	name := strings.TrimSpace(toolName)
	out := mcpNormalization{ActionType: mcpFallbackAction, Target: name}
	if name == "" {
		out.Target = models.ToolJunie + ".mcp"
		return out
	}
	for _, r := range mcpToolRules {
		if !strings.EqualFold(name, r.ToolName) {
			continue
		}
		out.ActionType = r.ActionType
		args := decodeMCPArgs(input)
		raw := firstNonEmptyArg(args, r.ArgKeys)
		switch r.Target {
		case targetPatchFile:
			if path, action, ok := parsePatchHeader(raw); ok {
				out.Target = path
				if action != "" {
					out.ActionType = action
				}
			}
		default:
			if raw != "" {
				out.Target = raw
			}
		}
		return out
	}
	return out
}

// decodeMCPArgs decodes an MCP block's `input` — a JSON object rendered
// with a leading newline and four-space indentation — into its
// top-level string fields. A non-object or malformed body yields nil,
// so the caller falls back rather than failing the parse.
func decodeMCPArgs(input string) map[string]string {
	body := strings.TrimSpace(input)
	if !strings.HasPrefix(body, "{") {
		return nil
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal([]byte(body), &raw); err != nil {
		return nil
	}
	out := make(map[string]string, len(raw))
	for k, v := range raw {
		var s string
		if err := json.Unmarshal(v, &s); err == nil {
			out[k] = s
		}
	}
	return out
}

// firstNonEmptyArg returns the first non-empty value among keys.
func firstNonEmptyArg(args map[string]string, keys []string) string {
	for _, k := range keys {
		if v := strings.TrimSpace(args[k]); v != "" {
			return v
		}
	}
	return ""
}

// parsePatchHeader finds the first per-file header of an apply_patch
// body and returns the path it names plus the action that verb implies
// (see [applyPatchHeaders]). ok is false for a body with no recognised
// header, in which case the caller keeps the rule's own default.
func parsePatchHeader(patch string) (path, action string, ok bool) {
	for _, line := range strings.Split(patch, "\n") {
		line = strings.TrimSpace(line)
		for _, h := range applyPatchHeaders {
			if !strings.HasPrefix(line, h.Prefix) {
				continue
			}
			p := strings.TrimSpace(strings.TrimPrefix(line, h.Prefix))
			if p == "" {
				continue
			}
			return p, h.Action, true
		}
	}
	return "", "", false
}
