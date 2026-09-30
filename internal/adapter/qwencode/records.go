package qwencode

import (
	"encoding/json"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/models"
)

// rawRecord is one JSONL line of a qwen chat transcript. All record
// `type`s share the Claude-Code envelope; the type-specific bodies
// (message / usageMetadata / systemPayload / toolCallResult) are
// optional pointers so a single struct decodes every shape.
type rawRecord struct {
	UUID           string             `json:"uuid"`
	ParentUUID     *string            `json:"parentUuid"`
	SessionID      string             `json:"sessionId"`
	Timestamp      string             `json:"timestamp"`
	Type           string             `json:"type"`
	Cwd            string             `json:"cwd"`
	Version        string             `json:"version"`
	GitBranch      string             `json:"gitBranch"`
	Model          string             `json:"model"`
	Subtype        string             `json:"subtype"`
	Message        *rawMessage        `json:"message"`
	UsageMetadata  *rawUsage          `json:"usageMetadata"`
	SystemPayload  *rawSystemPayload  `json:"systemPayload"`
	ToolCallResult *rawToolCallResult `json:"toolCallResult"`
}

// rawMessage is the Gemini-shaped message body (role + parts).
type rawMessage struct {
	Role  string    `json:"role"`
	Parts []rawPart `json:"parts"`
}

// rawPart is one content part: text, a functionCall (assistant tool
// request), or a functionResponse (tool result). Exactly one field is
// populated per part.
type rawPart struct {
	Text             string           `json:"text"`
	FunctionCall     *rawFunctionCall `json:"functionCall"`
	FunctionResponse *rawFunctionResp `json:"functionResponse"`
}

// rawFunctionCall is an assistant tool-call request part.
type rawFunctionCall struct {
	ID   string          `json:"id"`
	Name string          `json:"name"`
	Args json.RawMessage `json:"args"`
}

// rawFunctionResp is a tool-result response part.
type rawFunctionResp struct {
	ID       string          `json:"id"`
	Name     string          `json:"name"`
	Response json.RawMessage `json:"response"`
}

// rawUsage is the Gemini-named per-turn usage envelope on assistant
// records. The adapter reads tokens from the ui_telemetry api_response
// records instead (see records.go tokenBundle), but this shape is
// decoded so future consumers can cross-check.
type rawUsage struct {
	PromptTokenCount        int64 `json:"promptTokenCount"`
	CandidatesTokenCount    int64 `json:"candidatesTokenCount"`
	ThoughtsTokenCount      int64 `json:"thoughtsTokenCount"`
	TotalTokenCount         int64 `json:"totalTokenCount"`
	CachedContentTokenCount int64 `json:"cachedContentTokenCount"`
}

// rawToolCallResult is the structured result envelope on tool_result
// records. Status is "success" / "error"; resultDisplay is either a
// plain string or a {fileDiff,fileName,...} object (json.RawMessage so
// both decode).
type rawToolCallResult struct {
	CallID        string          `json:"callId"`
	Status        string          `json:"status"`
	ResultDisplay json.RawMessage `json:"resultDisplay"`
}

// rawSystemPayload is the body of a `type:"system"` record. UIEvent is
// populated for subtype ui_telemetry; Phase/RawCommand for subtype
// slash_command. Other subtypes (attribution_snapshot,
// file_history_snapshot) carry payloads the adapter ignores.
type rawSystemPayload struct {
	UIEvent     *rawUIEvent `json:"uiEvent"`
	Phase       string      `json:"phase"`
	RawCommand  string      `json:"rawCommand"`
	SentToModel bool        `json:"sentToModel"`
}

// rawUIEvent is a ui_telemetry event. The dotted JSON keys
// ("event.name") are decoded verbatim. Fields are a superset across the
// three event.name variants (api_response / tool_call / api_error);
// unused fields on a given variant stay zero.
type rawUIEvent struct {
	Name       string `json:"event.name"`
	Timestamp  string `json:"event.timestamp"`
	Model      string `json:"model"`
	AuthType   string `json:"auth_type"`
	ResponseID string `json:"response_id"`
	PromptID   string `json:"prompt_id"`
	DurationMs int64  `json:"duration_ms"`

	// api_response
	InputTokenCount  int64  `json:"input_token_count"`
	OutputTokenCount int64  `json:"output_token_count"`
	CachedTokenCount int64  `json:"cached_content_token_count"`
	ThoughtsTokens   int64  `json:"thoughts_token_count"`
	TotalTokenCount  int64  `json:"total_token_count"`
	ResponseText     string `json:"response_text"`

	// tool_call
	FunctionName string          `json:"function_name"`
	FunctionArgs json.RawMessage `json:"function_args"`
	Status       string          `json:"status"`
	Success      *bool           `json:"success"`
	Decision     string          `json:"decision"`

	// api_error
	StatusCode   int    `json:"status_code"`
	ErrorMessage string `json:"error_message"`
	ErrorType    string `json:"error_type"`
}

// ui_telemetry event.name values.
const (
	eventAPIResponse = "qwen-code.api_response"
	eventToolCall    = "qwen-code.tool_call"
	eventAPIError    = "qwen-code.api_error"
)

// tokenParts is the net-token view derived from an api_response event.
type tokenParts struct {
	inputNet  int64
	output    int64
	cacheRead int64
	reasoning int64
}

// tokenBundle converts an api_response ui_telemetry event into NET token
// counts. Qwen mirrors OpenAI's GROSS input convention:
// input_token_count INCLUDES cached_content_token_count, and
// total_token_count == input_token_count + output_token_count (verified
// against live turns 2026-07-09: 17883+81==17964 with cached 0;
// 18049+41==18090 with cached 17920 ⊂ input). TokenEvent.InputTokens
// must be NET, so cached is subtracted here and carried in CacheRead.
func tokenBundle(ev *rawUIEvent) tokenParts {
	net := ev.InputTokenCount - ev.CachedTokenCount
	if net < 0 {
		net = 0
	}
	return tokenParts{
		inputNet:  net,
		output:    ev.OutputTokenCount,
		cacheRead: ev.CachedTokenCount,
		reasoning: ev.ThoughtsTokens,
	}
}

// mapToolName collapses qwen's tool vocabulary onto the normalized
// action set. Matching is case-insensitive with `_`/`-` stripped so
// both snake_case (qwen native) and any camelCase variant resolve. The
// raw tool name is preserved separately on ToolEvent.RawToolName; an
// unrecognised name maps to ActionUnknown, and MCP tools (containing
// `__` or an `mcp` prefix) map to ActionMCPCall.
func mapToolName(name string) string {
	key := strings.ToLower(strings.TrimSpace(name))
	key = strings.ReplaceAll(key, "_", "")
	key = strings.ReplaceAll(key, "-", "")
	switch key {
	case "readfile", "read", "readmanyfiles", "viewfile", "view":
		return models.ActionReadFile
	case "writefile", "write", "createfile", "create":
		return models.ActionWriteFile
	case "replace", "edit", "editfile", "applypatch", "patch", "smartedit":
		return models.ActionEditFile
	case "runshellcommand", "shell", "bash", "exec", "execute", "runcommand",
		"powershell", "pwsh", "cmd", "cmdexe":
		return models.ActionRunCommand
	case "searchfilecontent", "grep", "searchtext", "findtext", "ripgrep":
		return models.ActionSearchText
	case "glob", "findfiles", "filesearch", "ls", "listfiles", "listdirectory", "readfolder":
		return models.ActionSearchFiles
	case "googlewebsearch", "websearch", "search":
		return models.ActionWebSearch
	case "webfetch", "fetch", "fetchurl", "fetchwebpage":
		return models.ActionWebFetch
	case "task", "subagent", "spawnagent", "delegate":
		return models.ActionSpawnSubagent
	case "todowrite", "todo", "updateplan":
		return models.ActionTodoUpdate
	case "savememory", "memorize":
		return models.ActionMCPCall // closest existing semantic; no dedicated type
	case "advisor":
		// ToolNames.ADVISOR = 'advisor' (QwenLM/qwen-code
		// packages/core/src/tools/tool-names.ts; tools/advisor.ts,
		// Kind.Think): a one-shot, TOOL-LESS consultation of a separately
		// configured Advisor model whose free-text advice returns to the
		// executor. Not a sub-agent spawn (no tools, no autonomous run) —
		// a host-harness builtin, so harness_call.
		return models.ActionHarnessCall
	default:
		if strings.HasPrefix(key, "mcp") || strings.Contains(name, "__") {
			return models.ActionMCPCall
		}
		return models.ActionUnknown
	}
}

// targetFromArgs picks a representative target from a functionCall's raw
// args JSON. Tries common path/command/query keys, falling back to the
// tool name.
func targetFromArgs(args json.RawMessage, fallback string) string {
	if len(args) == 0 {
		return fallback
	}
	var m map[string]any
	if err := json.Unmarshal(args, &m); err != nil {
		return fallback
	}
	for _, key := range []string{
		"file_path", "filePath", "absolute_path", "absolutePath", "path",
		"file", "command", "query", "url", "pattern", "prompt", "directory",
	} {
		if v, ok := m[key].(string); ok && strings.TrimSpace(v) != "" {
			return v
		}
	}
	return fallback
}

// responseOutput extracts the plain-text output from a functionResponse
// `response` object ({"output": "..."} shape). Returns "" when the shape
// is unexpected.
func responseOutput(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var m struct {
		Output string `json:"output"`
		Error  string `json:"error"`
	}
	if err := json.Unmarshal(raw, &m); err == nil {
		if strings.TrimSpace(m.Output) != "" {
			return m.Output
		}
		if strings.TrimSpace(m.Error) != "" {
			return m.Error
		}
	}
	return string(raw)
}

// parseTimestamp decodes qwen's RFC3339 millisecond timestamps. Returns
// the zero time on an empty or unparseable value.
func parseTimestamp(raw string) time.Time {
	if raw == "" {
		return time.Time{}
	}
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02T15:04:05.000Z"} {
		if t, err := time.Parse(layout, raw); err == nil {
			return t.UTC()
		}
	}
	return time.Time{}
}

// firstText returns the concatenated text parts of a message, trimmed.
func firstText(msg *rawMessage) string {
	if msg == nil {
		return ""
	}
	var b strings.Builder
	for _, p := range msg.Parts {
		if p.Text != "" {
			if b.Len() > 0 {
				b.WriteByte('\n')
			}
			b.WriteString(p.Text)
		}
	}
	return strings.TrimSpace(b.String())
}

// truncate caps a preview string to n bytes.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
