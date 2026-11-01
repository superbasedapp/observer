package autohand

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/models"
)

// mcpPrefix is the vendor's namespace for MCP-routed tools
// (`mcp__<server>__<tool>`, McpClientManager).
const mcpPrefix = "mcp__"

// browserPrefix namespaces the Chrome-extension bridge tools
// (browser_click, browser_navigate, ...).
const browserPrefix = "browser_"

// message is one conversation.jsonl line.
type message struct {
	Role       string          `json:"role"`
	Content    json.RawMessage `json:"content"`
	Timestamp  string          `json:"timestamp"`
	ToolCalls  []toolCall      `json:"toolCalls"`
	Name       string          `json:"name"`
	ToolCallID string          `json:"tool_call_id"`
	Meta       *messageMeta    `json:"_meta"`
}

// messageMeta is the optional `_meta` envelope. Only the members that change
// how a line is interpreted are decoded; the rest is ignored.
type messageMeta struct {
	// Stream marks a transient streamed tool-output chunk (written only
	// when AUTOHAND_STREAM_TOOL_OUTPUT=1); the final tool message for the
	// call is a separate line without it.
	Stream json.RawMessage `json:"stream"`
	// PeerReferences / PeerContext mark harness-injected "user" lines that
	// carry peer-agent context, not something the human typed.
	PeerReferences json.RawMessage `json:"peerReferences"`
	PeerContext    json.RawMessage `json:"peerContext"`
}

// injected reports whether a user line was written by the harness rather
// than typed by the operator.
func (m *messageMeta) injected() bool {
	return m != nil && (len(m.PeerReferences) > 0 || len(m.PeerContext) > 0)
}

// streamChunk reports whether a tool line is a streamed chunk.
func (m *messageMeta) streamChunk() bool {
	return m != nil && len(m.Stream) > 0 && string(m.Stream) != "null"
}

// toolCall is one entry of an assistant line's toolCalls[].
type toolCall struct {
	ID   string          `json:"id"`
	Tool string          `json:"tool"`
	Args json.RawMessage `json:"args"`
}

// actionMap maps Autohand's native tool names onto normalized action types.
// Names marked (live) were observed in real sessions on both operating
// systems; the rest are the vendor's complete built-in surface read from the
// shipped autohand-cli 0.9.8 tool registry. MCP tools (`mcp__*`) and the
// `browser_*` bridge are classified by prefix in classifyTool. Anything not
// listed (memory, goals, hooks, worktrees, ...) classifies as unknown with
// the raw name preserved.
var actionMap = map[string]string{
	// reads
	"read_file":  models.ActionReadFile, // (live)
	"file_stats": models.ActionReadFile,
	"checksum":   models.ActionReadFile,

	// searches
	"find_grep": models.ActionSearchText,
	"fff_find":  models.ActionSearchFiles, // (live)
	"list_tree": models.ActionSearchFiles, // (live)

	// writes
	"write_file":       models.ActionWriteFile, // (live)
	"append_file":      models.ActionWriteFile,
	"create_directory": models.ActionWriteFile,
	"copy_path":        models.ActionWriteFile,

	// edits (no canonical delete/rename type; zed precedent)
	"search_replace":    models.ActionEditFile, // (live)
	"apply_patch":       models.ActionEditFile,
	"git_apply_patch":   models.ActionEditFile,
	"notebook_edit":     models.ActionEditFile,
	"format_file":       models.ActionEditFile,
	"delete_path":       models.ActionEditFile, // (live)
	"rename_path":       models.ActionEditFile,
	"remove_dependency": models.ActionEditFile,

	// shell
	"run_command":    models.ActionRunCommand, // (live)
	"shell":          models.ActionRunCommand, // (live)
	"custom_command": models.ActionRunCommand,
	"add_dependency": models.ActionRunCommand,
	"auto_commit":    models.ActionRunCommand,

	// web
	"web_search":   models.ActionWebSearch,
	"fetch_url":    models.ActionWebFetch,
	"web_repo":     models.ActionWebFetch,
	"package_info": models.ActionWebFetch,

	// planning / delegation
	"todo_write":            models.ActionTodoUpdate, // (live)
	"create_task":           models.ActionTodoUpdate,
	"task_get":              models.ActionTodoUpdate,
	"task_list":             models.ActionTodoUpdate,
	"task_update":           models.ActionTodoUpdate,
	"task_stop":             models.ActionTodoUpdate,
	"task_output":           models.ActionTodoUpdate,
	"delegate_task":         models.ActionSpawnSubagent,
	"delegate_parallel":     models.ActionSpawnSubagent,
	"add_teammate":          models.ActionSpawnSubagent,
	"ask_followup_question": models.ActionAskUser,
	"skill":                 models.ActionSkillInvoke,
	"tool_search":           models.ActionToolSearch,
	"tools_registry":        models.ActionToolSearch,
	"cron_create":           models.ActionSchedule,
	"cron_delete":           models.ActionSchedule,
	"list_schedules":        models.ActionSchedule,
	"cancel_schedule":       models.ActionSchedule,
}

// gitToolPrefix classifies the vendor's git_* tool family: every member is a
// git invocation run through the harness, i.e. a command, except the patch
// applier mapped explicitly above. git_status — the most common — is the only
// one observed live.
const gitToolPrefix = "git_"

// classifyTool returns the normalized action type for a native tool name.
func classifyTool(name string) string {
	if a, ok := actionMap[name]; ok {
		return a
	}
	switch {
	case strings.HasPrefix(name, mcpPrefix):
		return models.ActionMCPCall
	case strings.HasPrefix(name, browserPrefix):
		return models.ActionBrowserAction
	case strings.HasPrefix(name, gitToolPrefix):
		return models.ActionRunCommand
	}
	return models.ActionUnknown
}

// targetKeys are the argument keys tried, in order, to pick a representative
// target. `path` (file tools), `command` (shell tools), `query` (searches)
// and `url` are live-grounded; the rest cover the registry's other shapes.
var targetKeys = []string{
	"query", "path", "file_path", "from", "command", "url",
	"agent_name", "name", "package_name", "repo", "directory",
}

// targetFromArgs picks the most human-meaningful field of a tool's JSON
// arguments, falling back to the tool name when none is present. For the
// shell tools the optional `args` array is appended to `command` the way the
// vendor joins them.
func targetFromArgs(tool string, args json.RawMessage) string {
	if len(args) == 0 {
		return tool
	}
	var m map[string]any
	if err := json.Unmarshal(args, &m); err != nil {
		return tool
	}
	for _, k := range targetKeys {
		v, ok := m[k].(string)
		if !ok || strings.TrimSpace(v) == "" {
			continue
		}
		if k == "command" {
			if extra, ok := m["args"].([]any); ok {
				for _, e := range extra {
					if s, ok := e.(string); ok && s != "" {
						v += " " + s
					}
				}
			}
		}
		return v
	}
	return tool
}

// authoredBytes returns the byte length of code the model authored in an
// action, read from the untruncated tool arguments: the full body of
// write_file/append_file, the REPLACE side of search_replace blocks, and the
// added lines of a unified diff. Zero for everything else.
func authoredBytes(tool string, args json.RawMessage) int64 {
	if len(args) == 0 {
		return 0
	}
	var in struct {
		Contents string `json:"contents"`
		Blocks   string `json:"blocks"`
		Patch    string `json:"patch"`
	}
	if err := json.Unmarshal(args, &in); err != nil {
		return 0
	}
	switch tool {
	case "write_file", "append_file":
		return int64(len(in.Contents))
	case "search_replace":
		return replaceSideBytes(in.Blocks)
	case "apply_patch", "git_apply_patch":
		return addedLineBytes(in.Patch)
	}
	return 0
}

// replaceSideBytes sums the REPLACE half of SEARCH/REPLACE blocks
// (`<<<<<<< SEARCH ... ======= ... >>>>>>> REPLACE`).
func replaceSideBytes(blocks string) int64 {
	var total int64
	inReplace := false
	for _, line := range strings.Split(blocks, "\n") {
		switch {
		case strings.HasPrefix(line, "=======") && !inReplace:
			inReplace = true
		case strings.HasPrefix(line, ">>>>>>>") && inReplace:
			inReplace = false
		case inReplace:
			total += int64(len(line)) + 1
		}
	}
	return total
}

// addedLineBytes sums the bytes of '+' lines of a unified diff, excluding
// the `+++` file header.
func addedLineBytes(patch string) int64 {
	var total int64
	for _, line := range strings.Split(patch, "\n") {
		if strings.HasPrefix(line, "+") && !strings.HasPrefix(line, "+++") {
			total += int64(len(line))
		}
	}
	return total
}

// ansiPattern matches CSI sequences and OSC strings (window-title writes
// from a Windows console appear in shell tool output).
var ansiPattern = regexp.MustCompile(`\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)`)

// stripANSI removes terminal control sequences from tool output; the diff
// renderings the file tools save are colored with 24-bit escapes.
func stripANSI(s string) string {
	return ansiPattern.ReplaceAllString(s, "")
}

// A tool result carries no explicit success flag: the vendor saves a failed
// call's `result.error` (else its output) as the message content, exactly as
// it saves a successful call's output (autohand-cli 0.9.8,
// `content = result.success ? result.output : result.error ?? ...`). Failure
// is therefore read from the content by the ordered rules below, each
// grounded on the vendor source or a live session.

// failurePrefixes are the fixed failure texts the vendor writes into a tool
// message, for any tool: a non-zero command exit and rejected invocations
// (JCPIIFVL.js AgentToolRuntime), its own pre-tool / permission-request hook
// failures and the default reasons of a hook block (2HZHNXFR.js ToolManager,
// TTIOFY7O.js HookManager; "Pre-tool hook failed." and "Hook timed out after
// 15000ms" seen live 2026-10-21), and the tool manager's aborts and skips.
var failurePrefixes = []string{
	"Command exited with code",
	"Error:",
	"Error running ",
	"Pre-tool hook",
	"Permission-request hook",
	"Hook timed out after",
	"Hook execution aborted",
	"Hook blocked execution",
	"Tool execution aborted.",
	"Tool execution skipped by user.",
	"Tool failed without error message",
	"Updated input for '",
	"Alternative input for '",
}

// toolRefusalPattern is the tool manager's refusal of a call it never ran
// (`Tool '<name>' was denied by the permission policy.`, `... is not
// available ...`).
var toolRefusalPattern = regexp.MustCompile(`^Tool '[^']*' (?:was denied by the permission policy|is not available)`)

// commandHeaderTools are the raw tools every SUCCESSFUL result of which
// starts with the vendor's command header (`$ <description>\n> <command>` or
// `$ <command>`, every success return of the run_command and shell cases in
// JCPIIFVL.js; live on both OSes). Any other content is the error of a call
// that did not run: a pre-tool hook's own block reason (Observer's guard
// reason, live 2026-10-22: `user rule U-901: ...`), a permission refusal or
// a validation error.
var commandHeaderTools = map[string]bool{"shell": true, "run_command": true}

// commandHeader is the prefix of every successful command-tool result.
const commandHeader = "$ "

// failureRules is the ordered failure classification, walked top-down; the
// first matching row decides. tool is the call's raw tool name ("" when
// unknown), text the ANSI-stripped, trimmed result.
var failureRules = []struct {
	name  string
	match func(tool, text string) bool
}{
	{"vendor failure text", func(_, text string) bool {
		for _, p := range failurePrefixes {
			if strings.HasPrefix(text, p) {
				return true
			}
		}
		return false
	}},
	{"tool refusal", func(_, text string) bool { return toolRefusalPattern.MatchString(text) }},
	{"command did not run", func(tool, text string) bool {
		return commandHeaderTools[tool] && !strings.HasPrefix(text, commandHeader)
	}},
}

// outputFailed reports whether a (ANSI-stripped) result of the raw tool reads
// as a failure.
func outputFailed(tool, out string) bool {
	t := strings.TrimSpace(out)
	for _, r := range failureRules {
		if r.match(tool, t) {
			return true
		}
	}
	return false
}

// contentText flattens a message `content` value into plain text. The live
// shape is always a string; an array of {text} blocks is tolerated so a
// future multimodal content does not drop the line.
func contentText(raw json.RawMessage) string {
	if len(raw) == 0 || string(raw) == "null" {
		return ""
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s
	}
	var parts []struct {
		Text string `json:"text"`
	}
	if err := json.Unmarshal(raw, &parts); err == nil {
		var b strings.Builder
		for _, p := range parts {
			if p.Text == "" {
				continue
			}
			if b.Len() > 0 {
				b.WriteByte('\n')
			}
			b.WriteString(p.Text)
		}
		return b.String()
	}
	return ""
}

// parseTime decodes the vendor's RFC3339 millisecond timestamps (UTC).
func parseTime(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC()
		}
	}
	return time.Time{}
}

// messageKey is the stable discriminator for a user/assistant text line:
// the millisecond timestamp plus a short content hash. The transcript has no
// message ids, and a line index would shift if the vendor rewrites the file
// (Session.replaceMessages), so identity is derived from the line itself.
func messageKey(ts time.Time, content string) string {
	sum := sha256.Sum256([]byte(content))
	return strconv.FormatInt(ts.UnixMilli(), 10) + ":" + hex.EncodeToString(sum[:4])
}

// truncate caps a preview string to n bytes without splitting a rune.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	cut := n
	for cut > 0 && cut < len(s) && s[cut]&0xC0 == 0x80 {
		cut--
	}
	return s[:cut]
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
