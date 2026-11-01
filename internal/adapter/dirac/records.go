package dirac

import (
	"encoding/json"
	"strconv"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/models"
)

// rawOp is one line of a Dirac operation log
// (`api_conversation_history.jsonl` and its rotated
// `.archive.<offset>` siblings). Grounded against dirac-cli 0.5.22:
//
//	{"offset":0,"type":"append_message","message":{…}}
//	{"offset":N,"type":"append_user_content","content":{…block…}}
//	{"offset":N,"type":"reset","messages":[{…},…]}
//
// `offset` is a per-task monotonic operation counter (NOT a byte
// offset). `reset` replaces the whole conversation (Dirac's
// overwriteApiConversationHistory: truncation / condensation);
// `append_user_content` appends one content block to the trailing user
// message. Any other `type` is skipped silently (forward-compat).
type rawOp struct {
	Offset   int64           `json:"offset"`
	Type     string          `json:"type"`
	Message  *rawMessage     `json:"message"`
	Messages []rawMessage    `json:"messages"`
	Content  json.RawMessage `json:"content"`
}

// rawMessage is one Anthropic-shaped conversation message as Dirac
// persists it. Assistant messages carry the provider response id
// (`id`, e.g. `resp_…`), `modelInfo` and a per-request `metrics`
// block; user messages carry only role/content/ts. `ts` is Unix
// milliseconds on both.
type rawMessage struct {
	Role      string          `json:"role"`
	Content   json.RawMessage `json:"content"`
	ID        string          `json:"id"`
	Ts        int64           `json:"ts"`
	ModelInfo *rawModelInfo   `json:"modelInfo"`
	Metrics   *rawMetrics     `json:"metrics"`
}

// rawModelInfo is the per-assistant-message model descriptor.
type rawModelInfo struct {
	ModelID    string `json:"modelId"`
	ProviderID string `json:"providerId"`
	Mode       string `json:"mode"`
}

// rawMetrics is the per-assistant-message token block. Its `cached`
// field is Dirac's `cacheWriteTokens + cacheReadTokens` SUM (bundle:
// `cached:(m.cacheWriteTokens??0)+(m.cacheReadTokens??0)`), so it is
// only a fallback — the split lives in ui_messages (usage.go).
type rawMetrics struct {
	Tokens rawMetricTokens `json:"tokens"`
	Cost   float64         `json:"cost"`
}

// rawMetricTokens: prompt = NET input (provider-normalized by Dirac),
// completion = output tokens as the provider reported them, cached =
// cache reads + cache writes.
type rawMetricTokens struct {
	Prompt     int64 `json:"prompt"`
	Completion int64 `json:"completion"`
	Cached     int64 `json:"cached"`
}

func (t rawMetricTokens) isZero() bool {
	return t.Prompt == 0 && t.Completion == 0 && t.Cached == 0
}

// rawBlock is one content block. Only the fields this adapter reads are
// declared; an image block's `source.data` (base64) is never decoded.
type rawBlock struct {
	Type      string          `json:"type"`
	Text      string          `json:"text"`
	Thinking  string          `json:"thinking"`
	ID        string          `json:"id"`
	Name      string          `json:"name"`
	Input     json.RawMessage `json:"input"`
	ToolUseID string          `json:"tool_use_id"`
	Content   json.RawMessage `json:"content"`
	IsError   bool            `json:"is_error"`
	Source    json.RawMessage `json:"source"`
}

// decodeBlocks normalizes a message's `content`, which is either a
// block array or (defensively — every grounded message used the array
// form) a bare string.
func decodeBlocks(raw json.RawMessage) []rawBlock {
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" {
		return nil
	}
	switch trimmed[0] {
	case '[':
		var blocks []rawBlock
		if err := json.Unmarshal(raw, &blocks); err != nil {
			return nil
		}
		return blocks
	case '"':
		var s string
		if err := json.Unmarshal(raw, &s); err != nil {
			return nil
		}
		return []rawBlock{{Type: "text", Text: s}}
	case '{':
		var b rawBlock
		if err := json.Unmarshal(raw, &b); err != nil {
			return nil
		}
		return []rawBlock{b}
	}
	return nil
}

// imageMediaType reads ONLY `source.media_type` off an image block.
func (b rawBlock) imageMediaType() string {
	if len(b.Source) == 0 {
		return ""
	}
	var src struct {
		MediaType string `json:"media_type"`
	}
	if err := json.Unmarshal(b.Source, &src); err != nil {
		return ""
	}
	return src.MediaType
}

// resultText flattens a tool_result `content` (a string, or an array of
// text/image blocks) into text. Image blocks contribute nothing.
func resultText(raw json.RawMessage) string {
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" {
		return ""
	}
	switch trimmed[0] {
	case '"':
		var s string
		_ = json.Unmarshal(raw, &s)
		return s
	case '[':
		var blocks []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		}
		if err := json.Unmarshal(raw, &blocks); err != nil {
			return ""
		}
		parts := make([]string, 0, len(blocks))
		for _, b := range blocks {
			if b.Type == "text" && b.Text != "" {
				parts = append(parts, b.Text)
			}
		}
		return strings.Join(parts, "\n")
	}
	return ""
}

// actionMap is the native tool name → normalized action table. Every
// row is one of the 26 tool specs (`{id:"…",name:"…"}`) in the shipped
// dirac-cli 0.5.22 bundle; `execute_command`, `write_to_file` and
// `respond` were also observed live. `respond` is NOT here: it is
// classified per `operation` by respondAction (its synthesized raw names
// live in respondActions). User-defined tools (`upsert_tool`) have
// arbitrary names and fall through to ActionUnknown.
var actionMap = map[string]string{
	"execute_command":  models.ActionRunCommand,
	"read_file":        models.ActionReadFile,
	"diagnostics_scan": models.ActionReadFile, // linter/syntax diagnostics over files — zed `diagnostics` precedent
	"write_to_file":    models.ActionWriteFile,
	"edit_file":        models.ActionEditFile,
	"edit_ast":         models.ActionEditFile, // AST rename / whole-definition replace
	"inspect_ast":      models.ActionSearchText,
	"search_files":     models.ActionSearchText, // regex content search (cline precedent)
	"list_files":       models.ActionSearchFiles,
	"browser_action":   models.ActionBrowserAction,
	"use_skill":        models.ActionSkillInvoke,
	"list_skills":      models.ActionToolSearch,
	"condense":         models.ActionContextCompacted,
	"new_task":         models.ActionHarnessCall, // replacement task handoff — a new session, not a sub-agent
	"upsert_tool":      models.ActionHarnessCall,
	"use_subagents":    models.ActionSpawnSubagent,
	// Goal-mode contained-task primitives.
	"start_task":               models.ActionSpawnSubagent,
	"verify_goal":              models.ActionSpawnSubagent, // starts an asynchronous verification Task
	"send_task_message":        models.ActionAgentMessage,
	"resolve_task_interaction": models.ActionAgentMessage,
	"cancel_task":              models.ActionAgentControl,
	"list_tasks":               models.ActionAgentControl,
	"read_task_transcript":     models.ActionAgentControl,
	"wait_for_goal_events":     models.ActionSubagentWait,
	"update_goal":              models.ActionHarnessCall,
	"block_goal":               models.ActionHarnessCall,
}

// respondTool is Dirac's single user-facing response tool. Dirac's
// assistant turns carry NO `text` blocks on the grounded providers —
// every user-visible message is a `respond` call whose `operation`
// (progress | complete | plan | question, bundle enum) decides what it
// is.
const respondTool = "respond"

// respondActions maps the synthesized raw tool name `respond.<operation>`
// to the normalized action. One native tool that means four different
// things is resolved at this boundary into four raw names so the
// taxonomy stays a 1:1 table (aider's synthesized-name precedent).
var respondActions = map[string]string{
	"respond.complete": models.ActionTaskComplete,
	"respond.question": models.ActionAskUser,
	"respond.progress": models.ActionAssistantMessage,
	"respond.plan":     models.ActionAssistantMessage,
}

// classifyTool resolves (rawToolName, action, recognised) for one
// tool_use block. `respond` becomes `respond.<operation>`; an unknown
// operation keeps the bare `respond` raw name as an assistant message.
func classifyTool(name string, input json.RawMessage) (string, string, bool) {
	if name == respondTool {
		op := strings.ToLower(strings.TrimSpace(stringField(input, "operation")))
		raw := respondTool + "." + op
		if action, ok := respondActions[raw]; ok {
			return raw, action, true
		}
		return respondTool, models.ActionAssistantMessage, false
	}
	if action, ok := actionMap[name]; ok {
		return name, action, true
	}
	return name, models.ActionUnknown, false
}

// stringField returns input[key] when it is a JSON string.
func stringField(input json.RawMessage, key string) string {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(input, &m); err != nil {
		return ""
	}
	v, ok := m[key]
	if !ok {
		return ""
	}
	var s string
	if err := json.Unmarshal(v, &s); err != nil {
		return ""
	}
	return s
}

// toolInput is the union of the tool-input fields targetFor and
// authoredBytes read. Every field is optional.
type toolInput struct {
	Commands  []string `json:"commands"`
	Script    *string  `json:"script"`
	Paths     []string `json:"paths"`
	Path      string   `json:"path"`
	Content   string   `json:"content"`
	Regex     string   `json:"regex"`
	Symbols   []string `json:"symbols"`
	Action    string   `json:"action"`
	URL       string   `json:"url"`
	SkillName string   `json:"skill_name"`
	TaskTitle string   `json:"task_title"`
	Intent    string   `json:"intent"`
	Operation string   `json:"operation"`
	Text      string   `json:"text"`
	TaskID    string   `json:"task_id"`
	Subagents []struct {
		TaskTitle string `json:"task_title"`
	} `json:"subagents"`
	Files []struct {
		Path  string `json:"path"`
		Edits []struct {
			Text string `json:"text"`
		} `json:"edits"`
	} `json:"files"`
	Targets []struct {
		Path        string `json:"path"`
		Symbol      string `json:"symbol"`
		Replacement string `json:"replacement"`
	} `json:"targets"`
}

// decodeToolInput decodes a tool input tolerantly. `commands` may be a
// single string on a malformed call; that shape is folded in too.
func decodeToolInput(raw json.RawMessage) toolInput {
	var in toolInput
	if err := json.Unmarshal(raw, &in); err == nil {
		return in
	}
	var loose map[string]json.RawMessage
	if err := json.Unmarshal(raw, &loose); err != nil {
		return toolInput{}
	}
	if v, ok := loose["commands"]; ok {
		var s string
		if json.Unmarshal(v, &s) == nil && s != "" {
			in.Commands = []string{s}
		}
	}
	return in
}

// targetFor returns the unscrubbed, un-relativized primary target of a
// call: (target, isPath). The caller scrubs and, for path targets,
// relativizes against the project root.
func targetFor(rawName string, in toolInput) (string, bool) {
	firstPath := func() string {
		if len(in.Paths) > 0 {
			return in.Paths[0]
		}
		return in.Path
	}
	switch {
	case rawName == "execute_command":
		if len(in.Commands) > 0 {
			return strings.Join(in.Commands, " && "), false
		}
		if in.Script != nil {
			return *in.Script, false
		}
	case rawName == "read_file", rawName == "list_files", rawName == "diagnostics_scan":
		return firstPath(), true
	case rawName == "search_files":
		if in.Regex != "" {
			return in.Regex, false
		}
		return firstPath(), true
	case rawName == "inspect_ast":
		if len(in.Symbols) > 0 {
			return in.Symbols[0], false
		}
		return firstPath(), true
	case rawName == "write_to_file":
		return in.Path, true
	case rawName == "edit_file":
		if len(in.Files) > 0 {
			return in.Files[0].Path, true
		}
	case rawName == "edit_ast":
		if len(in.Targets) > 0 {
			return in.Targets[0].Path, true
		}
	case rawName == "browser_action":
		if in.URL != "" {
			return in.Action + " " + in.URL, false
		}
		return in.Action, false
	case rawName == "use_skill":
		return in.SkillName, false
	case rawName == "use_subagents":
		if len(in.Subagents) > 0 {
			return in.Subagents[0].TaskTitle, false
		}
	case rawName == "start_task":
		return in.TaskTitle, false
	case rawName == "new_task":
		return in.Intent, false
	case rawName == "send_task_message", rawName == "cancel_task", rawName == "read_task_transcript", rawName == "resolve_task_interaction":
		return in.TaskID, false
	case strings.HasPrefix(rawName, respondTool):
		return in.Text, false
	}
	return "", false
}

// authoredBytes is the byte length of code the model AUTHORED in a
// write/edit call (§8.5): write_to_file content, the summed edit_file
// replacement texts, and edit_ast replacements for the `replace`
// operation (a `rename` replacement is an identifier, not code).
func authoredBytes(rawName string, in toolInput) int64 {
	switch rawName {
	case "write_to_file":
		return int64(len(in.Content))
	case "edit_file":
		var n int64
		for _, f := range in.Files {
			for _, e := range f.Edits {
				n += int64(len(e.Text))
			}
		}
		return n
	case "edit_ast":
		if in.Operation != "replace" {
			return 0
		}
		var n int64
		for _, t := range in.Targets {
			n += int64(len(t.Replacement))
		}
		return n
	}
	return 0
}

// failureMarkers are the result-text prefixes Dirac's own formatter
// writes for a failed or denied call (bundle: `toolError` → "The tool
// execution failed with the following error:", `toolDenied` → "The user
// denied this operation."). Ordered table, walked top-down.
var failureMarkers = []string{
	"The tool execution failed with the following error:",
	"The user denied this operation.",
}

// commandFailedMarker is the per-command line execute_command writes for
// a non-zero exit ("Command failed with exit code N"); a multi-command
// call fails when any of its commands did.
const commandFailedMarker = "Command failed"

// resultFailed reports whether a tool_result records a failure.
func resultFailed(rawName string, isError bool, text string) bool {
	if isError {
		return true
	}
	trimmed := strings.TrimSpace(text)
	for _, m := range failureMarkers {
		if strings.HasPrefix(trimmed, m) {
			return true
		}
	}
	if rawName != "execute_command" {
		return false
	}
	// The per-command status line follows each "--- Output for" header;
	// match it at a line start so command OUTPUT that merely mentions the
	// phrase does not count.
	for _, line := range strings.Split(text, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), commandFailedMarker) {
			return true
		}
	}
	return false
}

// promptTags are the wrappers Dirac puts around genuine user input
// (bundle list: <task>, <feedback>, <answer>, <user_message>,
// <steering_message>). Everything else under role=user (tool results,
// <environment_details>, "[TASK RESUMPTION]" nudges) is programmatic.
var promptTags = []string{"task", "feedback", "answer", "user_message", "steering_message"}

// extractPrompt returns the user-authored text of one text block, or "".
func extractPrompt(text string) string {
	for _, tag := range promptTags {
		open, closing := "<"+tag+">", "</"+tag+">"
		i := strings.Index(text, open)
		if i < 0 {
			continue
		}
		rest := text[i+len(open):]
		j := strings.Index(rest, closing)
		if j < 0 {
			continue
		}
		if s := strings.TrimSpace(rest[:j]); s != "" {
			return s
		}
	}
	return ""
}

// messageKey is a message's deterministic identity: the provider
// response id for an assistant message, else its millisecond `ts`. Both
// survive a `reset` re-emission of the same message unchanged, so a
// message re-listed by a later reset dedups against its first emission.
func messageKey(m *rawMessage) string {
	if m.ID != "" {
		return m.ID
	}
	return "ts" + strconv.FormatInt(m.Ts, 10)
}

// deniedMarker is the result text Dirac writes when the user refused an
// operation (bundle toolDenied); it is also one of failureMarkers.
const deniedMarker = "The user denied this operation."

// isDenied reports whether a tool_result records a user denial.
func isDenied(text string) bool {
	return strings.HasPrefix(strings.TrimSpace(text), deniedMarker)
}
