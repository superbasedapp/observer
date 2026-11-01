package deepseek

import (
	"encoding/json"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/models"
)

// Event type discriminators this adapter acts on. Every other `type`
// value is either streaming/ephemeral noise or session/config
// informational — see the package doc for the full inventory — and is
// skipped silently so a long session doesn't flood the watcher log.
const (
	evUserMessage      = "user/message"
	evAssistantMessage = "assistant/message"
	evToolCall         = "tool/call"
	evToolResult       = "tool/result"
	evTurnStart        = "turn/start"
	evTurnEnd          = "turn/end"
)

// sourceKindUser is the only data.source.kind value that marks a
// user/message event as genuinely user-authored. Anything else
// (observed: "plugin", e.g. the "@deepseek-ai/dsh-system-prompt"
// sandbox/approval-policy snapshot injector) rides the identical
// envelope shape but is harness-injected context, not a typed prompt —
// see the package doc for why misclassifying it would corrupt
// user_prompt-boundary-dependent surfaces.
const sourceKindUser = "user"

// turnEndCompleted is the only data.reason.kind observed on turn/end in
// live capture. Any other value is treated defensively as an abort,
// mirroring internal/adapter/muse's emitTurnTerminal polarity.
const turnEndCompleted = "completed"

// sessionHeader is the FIRST line of every session log: a
// distinct shape from every other line (no seq/time/data envelope).
type sessionHeader struct {
	Type            string `json:"type"`
	Version         int    `json:"version"`
	ID              string `json:"id"`
	CreatedAt       int64  `json:"createdAt"`
	Cwd             string `json:"cwd"`
	DelegationDepth int    `json:"delegationDepth"`
	AgentPreset     string `json:"agentPreset"`
}

// isHeader reports whether raw looks like the session header line rather
// than a seq/time/data envelope line.
func isHeader(raw []byte) bool {
	var h sessionHeader
	if err := json.Unmarshal(raw, &h); err != nil {
		return false
	}
	return h.Type == "session" && h.ID != ""
}

// rawEnvelope is one seq/time/data JSONL line.
type rawEnvelope struct {
	Type string          `json:"type"`
	Seq  int64           `json:"seq"`
	Time int64           `json:"time"`
	Data json.RawMessage `json:"data"`
}

// userMessageData is `data` on a user/message envelope.
type userMessageData struct {
	Content []contentBlock  `json:"content"`
	Role    string          `json:"role"`
	ID      string          `json:"id"`
	Source  messageSourceEv `json:"source"`
}

// messageSourceEv is the `data.source` object on a user/message event —
// distinct from the richer `data.message.source` object an
// assistant/message carries (see assistantMessageData).
type messageSourceEv struct {
	Kind   string `json:"kind"`
	Plugin string `json:"plugin"`
}

// contentBlock is one entry of a message's `content` array. Only Text and
// the tool-call fields are populated for the block kinds this adapter
// reads (`text`, `tool-call`, `tool-result`).
type contentBlock struct {
	Type string `json:"type"`
	Text string `json:"text"`

	// tool-call block (inside data.message.content on assistant/message)
	ID        string `json:"id"`
	Name      string `json:"name"`
	Arguments string `json:"arguments"`

	// tool-result block (inside data.message.content on tool/result)
	ToolCallID string         `json:"toolCallId"`
	Content    []contentBlock `json:"content"`
	IsError    bool           `json:"isError"`
}

// assistantMessageData is `data` on an assistant/message envelope. Usage
// is a SIBLING of Message, not nested inside it.
type assistantMessageData struct {
	Turn    int             `json:"turn"`
	Step    int             `json:"step"`
	Message assistantMsg    `json:"message"`
	Usage   *assistantUsage `json:"usage"`
}

// assistantMsg is `data.message` on an assistant/message envelope.
type assistantMsg struct {
	Role    string          `json:"role"`
	Content []contentBlock  `json:"content"`
	Source  assistantMsgSrc `json:"source"`
	ID      string          `json:"id"`
}

// assistantMsgSrc is `data.message.source` on an assistant/message
// envelope — the model resolution point.
type assistantMsgSrc struct {
	Kind     string `json:"kind"`
	Provider string `json:"provider"`
	Model    string `json:"model"`
}

// assistantUsage is `data.usage` on an assistant/message envelope.
// InputTokens is already NET of CacheReadTokens — see the package doc.
type assistantUsage struct {
	InputTokens     int64 `json:"inputTokens"`
	OutputTokens    int64 `json:"outputTokens"`
	CacheReadTokens int64 `json:"cacheReadTokens"`
}

// isZero reports whether a usage envelope carries nothing worth
// persisting, so an all-zero envelope never produces a phantom token row.
func (u *assistantUsage) isZero() bool {
	if u == nil {
		return true
	}
	return u.InputTokens == 0 && u.OutputTokens == 0 && u.CacheReadTokens == 0
}

// toolResultData is `data` on a tool/result envelope.
type toolResultData struct {
	Turn    int           `json:"turn"`
	Step    int           `json:"step"`
	Message toolResultMsg `json:"message"`
}

// toolResultMsg is `data.message` on a tool/result envelope.
type toolResultMsg struct {
	Content []contentBlock `json:"content"`
}

// turnEndData is `data` on a turn/end envelope.
type turnEndData struct {
	Turn   int             `json:"turn"`
	Reason turnEndReasonEv `json:"reason"`
}

type turnEndReasonEv struct {
	Kind string `json:"kind"`
}

// toolResultText concatenates the text of every text-shaped nested
// content block inside a tool-result block. A tool-result's own Content
// is the nested `content[].text` array from the live sample.
func toolResultText(block contentBlock) string {
	var parts []string
	for _, c := range block.Content {
		if c.Type == "text" && strings.TrimSpace(c.Text) != "" {
			parts = append(parts, c.Text)
		}
	}
	return strings.Join(parts, "\n")
}

// actionMap translates DeepSeek Harness tool names onto the normalized
// taxonomy. GROUNDED against the confirmed 24-name live inventory (a
// request/header event embeds the full JSON-schema tool-definition set).
// Keys are the raw names verbatim — DeepSeek's tool names are already a
// single stable spelling (snake_case), so no normalizeToolKey-style
// folding is needed the way muse's more varied surface requires.
var actionMap = map[string]string{
	"ask_user_question": models.ActionAskUser,
	"bash":              models.ActionRunCommand,
	// pwsh is DSH's shell tool on Windows (live-observed 2026-08-26 on a
	// /mnt/c/Users/<u>/.dsh Windows session); same run-command bucket as bash.
	"pwsh": models.ActionRunCommand,
	// create_goal / get_goal / update_goal are DSH's own goal-tracking
	// tool trio — they record state back INTO the harness, not workspace
	// state, so harness_call is the honest bucket (same reasoning as
	// muse's submit_reminder_decision).
	"create_goal":    models.ActionHarnessCall,
	"get_goal":       models.ActionHarnessCall,
	"update_goal":    models.ActionHarnessCall,
	"edit":           models.ActionEditFile,
	"exit_plan_mode": models.ActionHarnessCall,
	"glob":           models.ActionSearchFiles,
	"grep":           models.ActionSearchText,
	// interrupt_agent / job_kill / job_list / job_output / list_agents /
	// send_message are multi-agent orchestration control-plane calls —
	// they don't touch the workspace or spawn a NEW agent themselves, so
	// agent_control is the honest bucket, distinct from spawn_subagent.
	"interrupt_agent": models.ActionAgentControl,
	"job_kill":        models.ActionAgentControl,
	"job_list":        models.ActionAgentControl,
	"job_output":      models.ActionAgentControl,
	"list_agents":     models.ActionAgentControl,
	"send_message":    models.ActionAgentMessage,
	// ralph / subagent / subagent_fork / workflow all launch a NEW agent
	// run (ralph = the "run until done" loop pattern; workflow = a
	// predefined multi-step agent recipe).
	"ralph":         models.ActionSpawnSubagent,
	"subagent":      models.ActionSpawnSubagent,
	"subagent_fork": models.ActionSpawnSubagent,
	"workflow":      models.ActionSpawnSubagent,
	"read":          models.ActionReadFile,
	"read_image":    models.ActionReadFile,
	"skill":         models.ActionSkillInvoke,
	"todo_write":    models.ActionTodoUpdate,
	"web_search":    models.ActionWebSearch,
	"write":         models.ActionWriteFile,
}

// mapToolName resolves a raw DeepSeek tool name onto a normalized action
// type, reporting whether the name was recognised. The raw name is always
// preserved on ToolEvent.RawToolName regardless.
func mapToolName(name string) (action string, recognised bool) {
	if a, ok := actionMap[name]; ok {
		return a, true
	}
	return models.ActionUnknown, false
}

// targetKeys are the tool-call argument keys tried, in order, when
// picking a representative target for an action. Grounded against the
// live capture: glob{pattern,path}, read{file_path}, write{file_path,
// content}, bash{command}.
var targetKeys = []string{
	"file_path", "path", "pattern", "command", "cmd", "query", "url",
	"prompt",
}

// decodeArgs unmarshals a tool call's `arguments`, which DeepSeek
// serializes as a JSON STRING containing a JSON object — exactly the
// same double-encoding muse's `args` field uses. Returns nil when the
// value is empty or is not an object.
func decodeArgs(raw string) map[string]any {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		return nil
	}
	return m
}

// targetFromArgs picks a representative target from a decoded argument
// object, falling back to the tool name when no known key is present.
func targetFromArgs(args map[string]any, fallback string) string {
	for _, key := range targetKeys {
		if v, ok := args[key].(string); ok && strings.TrimSpace(v) != "" {
			return v
		}
	}
	return fallback
}

// authoredBytes returns the byte length of the content the model
// authored in a write/edit/run action, read from the untruncated
// arguments. Zero for read-only or unrecognised actions.
func authoredBytes(actionType string, args map[string]any) int64 {
	str := func(k string) int64 {
		v, _ := args[k].(string)
		return int64(len(v))
	}
	switch actionType {
	case models.ActionWriteFile:
		return str("content")
	case models.ActionEditFile:
		return str("new_string") + str("new_text") + str("content")
	case models.ActionRunCommand:
		return str("command")
	default:
		return 0
	}
}

// parseTimestamp decodes a DeepSeek `time`/`createdAt` value — confirmed
// Unix MILLISECONDS throughout. A non-positive value yields the zero
// time.
func parseTimestamp(ms int64) time.Time {
	if ms <= 0 {
		return time.Time{}
	}
	return time.UnixMilli(ms).UTC()
}

// truncate caps a preview string to n bytes.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
