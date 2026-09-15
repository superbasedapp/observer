package poolside

import (
	"encoding/json"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/models"
)

// Record type discriminators (the trajectory's `type` field). Only the
// ones this adapter consumes are named; every other type is a bookkeeping
// marker and is skipped.
const (
	typeSessionStart           = "session.start"
	typeSessionInput           = "session.input"
	typeThoughtEnd             = "thought.end"
	typeAssistantMessageEnd    = "assistant_message.end"
	typeToolCallInferenceStart = "tool_call.inference.start"
	typeToolCallInferenceEnd   = "tool_call.inference.end"
	typeToolCallParsed         = "tool_call.parsed"
	typeToolCallApproval       = "tool_call.approval"
	typeToolCallResult         = "tool_call.result"
	typeSessionExit            = "session.exit"
)

// rawRecord is one JSONL line of a Poolside trajectory. Every line shares
// the same envelope shape: `id` + `step_id` + `timestamp` + `type`, plus
// exactly one nested payload object keyed by `type` with `.` replaced by
// `_`. Only the payload fields this adapter reads are modeled; every
// other line shape decodes with every payload pointer nil and is skipped
// by handle's switch.
type rawRecord struct {
	ID        string `json:"id"`
	StepID    string `json:"step_id"`
	Timestamp string `json:"timestamp"`
	Type      string `json:"type"`

	SessionStart           *sessionStartPayload           `json:"session_start"`
	SessionInput           *sessionInputPayload           `json:"session_input"`
	ThoughtEnd             *thoughtEndPayload             `json:"thought_end"`
	AssistantMessageEnd    *assistantMessageEndPayload    `json:"assistant_message_end"`
	ToolCallInferenceStart *toolCallInferenceStartPayload `json:"tool_call_inference_start"`
	ToolCallInferenceEnd   *toolCallInferenceEndPayload   `json:"tool_call_inference_end"`
	ToolCallParsed         *toolCallParsedPayload         `json:"tool_call_parsed"`
	ToolCallApproval       *toolCallApprovalPayload       `json:"tool_call_approval"`
	ToolCallResult         *toolCallResultPayload         `json:"tool_call_result"`
	SessionExit            *sessionExitPayload            `json:"session_exit"`
}

// sessionStartPayload is `session_start` — the trajectory's first record.
type sessionStartPayload struct {
	WorkingDirectories []string `json:"working_directories"`
}

// sessionInputPayload is `session_input` — one user turn.
type sessionInputPayload struct {
	Prompt string `json:"prompt"`
}

// thoughtEndPayload is `thought_end` — the model's reasoning for the
// current step_id.
type thoughtEndPayload struct {
	Thought string `json:"thought"`
}

// assistantMessageEndPayload is `assistant_message_end` — the visible
// reply for the current step_id.
type assistantMessageEndPayload struct {
	AssistantMessage string `json:"assistant_message"`
}

// toolCallInferenceStartPayload is `tool_call_inference_start` — read
// only for the per-step model id; the full chat_completion_request
// (messages, tools, sampling params) is not modeled.
type toolCallInferenceStartPayload struct {
	ChatCompletionRequest struct {
		Model string `json:"model"`
	} `json:"chat_completion_request"`
}

// toolCallInferenceEndPayload is `tool_call_inference_end` — the per-call
// token usage. See the package doc for the GROSS-input netting evidence.
type toolCallInferenceEndPayload struct {
	InputTokens           int64 `json:"input_tokens"`
	OutputTokens          int64 `json:"output_tokens"`
	CacheWriteInputTokens int64 `json:"cache_write_input_tokens"`
	CacheReadInputTokens  int64 `json:"cache_read_input_tokens"`
}

// isZero reports whether the usage envelope carries nothing worth
// persisting, so an all-zero envelope never produces a phantom token row.
func (u *toolCallInferenceEndPayload) isZero() bool {
	if u == nil {
		return true
	}
	return u.InputTokens == 0 && u.OutputTokens == 0 &&
		u.CacheReadInputTokens == 0 && u.CacheWriteInputTokens == 0
}

// tokenParts is the NET-token view derived from a usage envelope.
type tokenParts struct {
	inputNet  int64
	outputNet int64
	cacheRead int64
	cacheWrit int64
}

// tokenBundle nets a Poolside usage envelope. input_tokens is GROSS and
// INCLUDES cache_read_input_tokens (see the package doc's summed-vs-
// summary-total evidence); there is no reasoning-token field to net out
// of output.
func tokenBundle(u *toolCallInferenceEndPayload) tokenParts {
	if u == nil {
		return tokenParts{}
	}
	netIn := u.InputTokens - u.CacheReadInputTokens
	if netIn < 0 {
		netIn = 0
	}
	return tokenParts{
		inputNet:  netIn,
		outputNet: u.OutputTokens,
		cacheRead: u.CacheReadInputTokens,
		cacheWrit: u.CacheWriteInputTokens,
	}
}

// validationError is `tool_call_parsed.validation_error` — present only
// when the call never ran (e.g. the named tool is not available in this
// build). Its presence is an explicit, immediate failure signal; no
// tool_call.approval or tool_call.result is expected to follow.
type validationError struct {
	Kind   string `json:"kind"`
	Detail string `json:"detail"`
}

// toolCallParsedPayload is `tool_call_parsed` — the tool call itself.
// Args is a genuine JSON OBJECT (unlike muse's stringified args), so no
// second unmarshal is needed to reach the per-tool keys. RawArgs is the
// provider's own serialized copy, used verbatim as RawToolInput when
// present; a synthetic call (the harness-injected `exit`) carries no
// RawArgs at all, so RawToolInput falls back to re-marshaling Args.
type toolCallParsedPayload struct {
	ID              string           `json:"id"`
	Name            string           `json:"name"`
	Args            map[string]any   `json:"args"`
	RawArgs         string           `json:"raw_args"`
	ValidationError *validationError `json:"validation_error"`
	IsSynthetic     bool             `json:"is_synthetic"`
}

// toolCallApprovalPayload is `tool_call_approval` — the user's allow/deny
// verdict on a pending call.
type toolCallApprovalPayload struct {
	ToolCallID string `json:"tool_call_id"`
	Denied     bool   `json:"denied"`
	Reason     string `json:"reason"`
}

// shellToolResult is the ONE typed per-tool result shape that carries an
// explicit pass/fail signal for a shell call: `exit_code`.
type shellToolResult struct {
	ExitCode int `json:"exit_code"`
}

// successResult is the typed shape shared by todo_action and the
// synthetic exit tool's result — both carry an explicit `success` bool.
// read/write/edit results carry NEITHER an exit_code NOR a success field
// (grounded: write_tool_result/edit_tool_result/read_tool_result only
// state path/content-shape facts), so those three tool names stay
// optimistically successful absent a denial.
type successResult struct {
	Success bool `json:"success"`
}

// toolCallResultPayload is `tool_call_result` — the call's outcome.
// Observation is the generic, always-present human-readable summary this
// adapter uses as ToolOutput; the typed `<tool>_tool_result` fields are
// decoded only for the two tool names known to carry an explicit verdict.
type toolCallResultPayload struct {
	ID                    string           `json:"id"`
	ToolName              string           `json:"tool_name"`
	ExecutionLatencyNanos int64            `json:"execution_latency"`
	Observation           string           `json:"observation"`
	ShellResult           *shellToolResult `json:"shell_run_tool_result"`
	TodoActionResult      *successResult   `json:"todo_action_tool_result"`
	ExitResult            *successResult   `json:"exit_tool_result"`
}

// verdict reports whether this result states an explicit pass/fail, and
// what it is. successKnown=false means the result carries no explicit
// verdict (read/write/edit) — the call stays optimistically successful.
func (r *toolCallResultPayload) verdict() (successKnown, success bool) {
	if r == nil {
		return false, false
	}
	switch {
	case r.ShellResult != nil:
		return true, r.ShellResult.ExitCode == 0
	case r.TodoActionResult != nil:
		return true, r.TodoActionResult.Success
	case r.ExitResult != nil:
		return true, r.ExitResult.Success
	default:
		return false, false
	}
}

// sessionExitPayload is `session_exit` — the session's end marker.
type sessionExitPayload struct {
	Reason string `json:"reason"`
}

// actionMap translates Poolside's native tool names onto the normalized
// taxonomy. Every key below is GROUNDED — the complete tool surface
// observed in the 2026-09-05 live capture (a 22-call, single-prompt
// session): read, write, edit, shell, list_directory_tree, todo_action,
// and the harness-injected synthetic completion tool, exit. Unlike most
// adapters this table carries no "defensive" rows: the ACP session/new
// response's own configOptions never enumerated a larger tool surface,
// so there is no evidence of additional native names to guess at. An
// unrecognised name still degrades safely to ActionUnknown via
// mapToolName, never dropped.
var actionMap = map[string]string{
	"read":                models.ActionReadFile,
	"write":               models.ActionWriteFile,
	"edit":                models.ActionEditFile,
	"shell":               models.ActionRunCommand,
	"list_directory_tree": models.ActionSearchFiles,
	"todo_action":         models.ActionTodoUpdate,
	// exit is the harness-injected, IsSynthetic completion signal (the
	// model calls it on purpose the same way cline's attempt_completion
	// or cline-cli's submit_and_exit works) — the ActionTaskComplete
	// contract's "a native completion tool the model called on purpose"
	// branch.
	"exit": models.ActionTaskComplete,
}

// mapToolName resolves a raw Poolside tool name onto a normalized action
// type, reporting whether the name was recognised. An MCP-routed call
// (a `__` separator, the shared convention every adapter's fallback
// checks) maps to ActionMCPCall even though none was observed live.
func mapToolName(name string) (action string, recognised bool) {
	if name == "" {
		return models.ActionUnknown, false
	}
	if a, ok := actionMap[name]; ok {
		return a, true
	}
	if strings.Contains(name, "__") || strings.HasPrefix(name, "mcp") {
		return models.ActionMCPCall, true
	}
	return models.ActionUnknown, false
}

// targetKeys are the tool-call argument keys tried, in order, when
// picking a representative target for an action. All four are GROUNDED
// against the live capture: path (read/write/edit), cmd (shell),
// directoryPath (list_directory_tree), content (todo_action, the todo
// list text itself — the closest thing to a "target" that call has).
var targetKeys = []string{"path", "cmd", "directoryPath", "content"}

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

// authoredBytes returns the byte length of content the model authored in
// a write / edit / shell call, read from the untruncated arguments. Zero
// for read-only or unrecognised actions. All three key names are
// GROUNDED: write{contents}, edit{new_string}, shell{cmd}.
func authoredBytes(actionType string, args map[string]any) int64 {
	str := func(k string) int64 {
		v, _ := args[k].(string)
		return int64(len(v))
	}
	switch actionType {
	case models.ActionWriteFile:
		return str("contents")
	case models.ActionEditFile:
		return str("new_string")
	case models.ActionRunCommand:
		return str("cmd")
	default:
		return 0
	}
}

// rawToolInput returns the tool call's serialized arguments: the
// provider's own raw_args string when present, otherwise a re-marshal of
// the decoded Args object (the synthetic `exit` call carries Args but no
// raw_args).
func rawToolInput(tc *toolCallParsedPayload) string {
	if tc.RawArgs != "" {
		return tc.RawArgs
	}
	if len(tc.Args) == 0 {
		return ""
	}
	buf, err := json.Marshal(tc.Args)
	if err != nil {
		return ""
	}
	return string(buf)
}

// parseTimestamp decodes a trajectory record's ISO-8601 timestamp
// (`2026-09-05T01:33:15.6806478+05:30`). A malformed value yields the
// zero time rather than failing the whole line.
func parseTimestamp(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return time.Time{}
	}
	return t.UTC()
}
