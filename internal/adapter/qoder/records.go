package qoder

import (
	"encoding/json"
	"strconv"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/models"
)

// rawRecord is one JSONL line of a qoder session transcript. Every record
// `type` shares the Claude-Code envelope (uuid / parentUuid / sessionId /
// timestamp / cwd / version / gitBranch / isSidechain); the type-specific
// body lives in the optional message pointer plus toolUseResult. The
// record `type` is one of user / assistant / runtime-config /
// file-history-snapshot / last-prompt (verified against a live v1.0.40
// capture 2026-07-09).
type rawRecord struct {
	Type          string          `json:"type"`
	UUID          string          `json:"uuid"`
	ParentUUID    *string         `json:"parentUuid"`
	SessionID     string          `json:"sessionId"`
	Timestamp     flexTimestamp   `json:"timestamp"`
	Cwd           string          `json:"cwd"`
	Version       string          `json:"version"`
	GitBranch     string          `json:"gitBranch"`
	IsSidechain   bool            `json:"isSidechain"`
	PromptID      string          `json:"promptId"`
	Message       *rawMessage     `json:"message"`
	ToolUseResult json.RawMessage `json:"toolUseResult"`
}

// rawMessage is the Anthropic-shaped message body. ID is the upstream
// message id (`chatcmpl-…`) on assistant records; Model was EMPTY in every
// live capture (qoder resolves the concrete model server-side and never
// writes it locally). Content is polymorphic: a user prompt is a bare
// STRING, while an assistant turn and a tool-result user turn are ARRAYS of
// content blocks — hence json.RawMessage decoded by shape.
type rawMessage struct {
	ID      string          `json:"id"`
	Role    string          `json:"role"`
	Model   string          `json:"model"`
	Content json.RawMessage `json:"content"`
}

// rawBlock is one Anthropic content block. Exactly one variant is
// populated per block, discriminated by Type: text / tool_use (assistant
// tool request) / tool_result (tool response echoed on the next user
// record).
type rawBlock struct {
	Type string `json:"type"`
	// text
	Text string `json:"text"`
	// tool_use
	ID    string          `json:"id"`
	Name  string          `json:"name"`
	Input json.RawMessage `json:"input"`
	// tool_result
	ToolUseID string          `json:"tool_use_id"`
	Content   json.RawMessage `json:"content"`
	IsError   bool            `json:"is_error"`
}

// contentString returns the user-prompt text when message.content is a
// bare JSON string, and "" when it is an array (tool-result / assistant
// shape) or absent.
func (m *rawMessage) contentString() string {
	if m == nil || len(m.Content) == 0 {
		return ""
	}
	var s string
	if err := json.Unmarshal(m.Content, &s); err == nil {
		return strings.TrimSpace(s)
	}
	return ""
}

// contentBlocks returns the content blocks when message.content is a JSON
// array, and nil when it is a bare string or absent.
func (m *rawMessage) contentBlocks() []rawBlock {
	if m == nil || len(m.Content) == 0 {
		return nil
	}
	var blocks []rawBlock
	if err := json.Unmarshal(m.Content, &blocks); err == nil {
		return blocks
	}
	return nil
}

// actionMap translates qoder tool names onto the normalized taxonomy.
// qoder uses the Claude-Code tool vocabulary verbatim (Write / Bash /
// Read / Edit …), so this mirrors the claudecode adapter's map.
var actionMap = map[string]string{
	"Read":            models.ActionReadFile,
	"Write":           models.ActionWriteFile,
	"Edit":            models.ActionEditFile,
	"MultiEdit":       models.ActionEditFile,
	"NotebookEdit":    models.ActionEditFile,
	"SearchReplace":   models.ActionEditFile, // Qoder IDE edit tool (transcript/*.session.execution.jsonl)
	"Bash":            models.ActionRunCommand,
	"PowerShell":      models.ActionRunCommand,
	"powershell":      models.ActionRunCommand,
	"pwsh":            models.ActionRunCommand,
	"cmd":             models.ActionRunCommand,
	"cmd.exe":         models.ActionRunCommand,
	"sh":              models.ActionRunCommand,
	"Grep":            models.ActionSearchText,
	"Glob":            models.ActionSearchFiles,
	"LS":              models.ActionSearchFiles,
	"WebSearch":       models.ActionWebSearch,
	"WebFetch":        models.ActionWebFetch,
	"Fetch":           models.ActionWebFetch,
	"Agent":           models.ActionSpawnSubagent,
	"Task":            models.ActionSpawnSubagent,
	"TodoWrite":       models.ActionTodoUpdate,
	"TaskCreate":      models.ActionTodoUpdate,
	"TaskUpdate":      models.ActionTodoUpdate,
	"AskUserQuestion": models.ActionAskUser,
}

// mapToolName resolves a raw qoder tool name onto a normalized action
// type. An exact match wins; otherwise an MCP-routed call (containing
// `__` or an `mcp` prefix) maps to ActionMCPCall, and everything else
// falls back to ActionUnknown with the raw name preserved on the event.
func mapToolName(name string) string {
	if a, ok := actionMap[name]; ok {
		return a
	}
	lower := strings.ToLower(strings.TrimSpace(name))
	if strings.HasPrefix(lower, "mcp") || strings.Contains(name, "__") {
		return models.ActionMCPCall
	}
	return models.ActionUnknown
}

// targetFromInput picks a representative target from a tool_use `input`
// object, trying common path/command/query keys before the tool name.
func targetFromInput(input json.RawMessage, fallback string) string {
	if len(input) == 0 {
		return fallback
	}
	var m map[string]any
	if err := json.Unmarshal(input, &m); err != nil {
		return fallback
	}
	for _, key := range []string{
		"file_path", "filePath", "absolute_path", "path", "file",
		"command", "query", "url", "pattern", "prompt", "directory",
	} {
		if v, ok := m[key].(string); ok && strings.TrimSpace(v) != "" {
			return v
		}
	}
	return fallback
}

// authoredBytes returns the byte length of the code the model authored in a
// write/edit/run action, read from the untruncated Anthropic-shaped tool
// input. Zero for read-only or unrecognised actions.
func authoredBytes(actionType string, input json.RawMessage) int64 {
	if len(input) == 0 {
		return 0
	}
	var in struct {
		Content string `json:"content"`
		// FileContent is the Qoder IDE's spelling of the Write tool's
		// body (GROUNDED 2026-09-03: the in-editor agent emits
		// `{"file_content": …, "file_path": …}` where the terminal
		// binary emits Claude-Code's `content`). Without it every
		// IDE-authored write reported zero authored bytes.
		FileContent string `json:"file_content"`
		NewString   string `json:"new_string"`
		Command     string `json:"command"`
		Edits       []struct {
			NewString string `json:"new_string"`
		} `json:"edits"`
	}
	if err := json.Unmarshal(input, &in); err != nil {
		return 0
	}
	switch actionType {
	case models.ActionWriteFile:
		if in.Content == "" {
			return int64(len(in.FileContent))
		}
		return int64(len(in.Content))
	case models.ActionEditFile:
		n := int64(len(in.NewString))
		for _, e := range in.Edits {
			n += int64(len(e.NewString))
		}
		return n
	case models.ActionRunCommand:
		return int64(len(in.Command))
	default:
		return 0
	}
}

// toolResultText flattens a tool_result block's `content` into plain text.
// The content is either a bare string ("File created successfully…") or an
// array of `{type:"text",text:…}` blocks; both are handled.
func toolResultText(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s
	}
	var parts []struct {
		Type string `json:"type"`
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
	return string(raw)
}

// rawSegment is one line of a qoder run log under
// logs/sessions/<slug>/<sid>/segments/<ts>-<rand>-p<pid>.jsonl. The token
// fields live in the `data` body of the model.response.completed records
// (Anthropic-NET named); every field was ZERO in live capture. request_id
// / turn_id are top-level.
type rawSegment struct {
	Type      string          `json:"type"`
	Ts        string          `json:"ts"`
	Seq       int64           `json:"seq"`
	RequestID string          `json:"request_id"`
	TurnID    string          `json:"turn_id"`
	Data      json.RawMessage `json:"data"`
}

// segConfig is the body of a session.config.loaded segment record. It
// carries the project root and (server-resolved, usually empty) model.
type segConfig struct {
	ProjectRoot string `json:"project_root"`
	TargetDir   string `json:"target_dir"`
	Model       string `json:"model"`
}

// segResponse is the body of a model.response.completed segment record.
// Input tokens are Anthropic-NET (cache is reported separately, not folded
// into input), matching TokenEvent's contract — no gross-net subtraction.
type segResponse struct {
	RequestIndex        int64  `json:"request_index"`
	Model               string `json:"model"`
	StopReason          string `json:"stop_reason"`
	InputTokens         int64  `json:"input_tokens"`
	OutputTokens        int64  `json:"output_tokens"`
	CacheReadTokens     int64  `json:"cache_read_input_tokens"`
	CacheCreationTokens int64  `json:"cache_creation_input_tokens"`
}

// nonZero reports whether the response carries any token count worth
// persisting. All-zero responses (the only shape seen in live capture —
// usage is resolved server-side and never written locally) are skipped so
// no phantom token rows land.
func (r segResponse) nonZero() bool {
	return r.InputTokens != 0 || r.OutputTokens != 0 ||
		r.CacheReadTokens != 0 || r.CacheCreationTokens != 0
}

// flexTimestamp tolerates qoder's TWO on-disk timestamp encodings: an
// RFC3339 string (Linux captures) and a bare epoch NUMBER on some records
// (observed in a Windows v1.0.40 capture — mixed within one file). It
// unmarshals either shape into its string form so a numeric line no
// longer fails the whole record as malformed JSON.
type flexTimestamp string

// UnmarshalJSON implements json.Unmarshaler.
func (f *flexTimestamp) UnmarshalJSON(b []byte) error {
	if len(b) > 0 && b[0] == '"' {
		var s string
		if err := json.Unmarshal(b, &s); err != nil {
			return err
		}
		*f = flexTimestamp(s)
		return nil
	}
	if string(b) == "null" {
		*f = ""
		return nil
	}
	*f = flexTimestamp(b)
	return nil
}

// parseTimestamp decodes qoder's timestamps: RFC3339 strings (transcript
// records use UTC `…Z`; segment records use a local offset such as
// `+05:30`) or a bare epoch number (milliseconds when ≥13 digits, else
// seconds — the Windows-capture shape). Returns the zero time on an empty
// or unparseable value.
func parseTimestamp[T ~string](raw T) time.Time {
	s := string(raw)
	if s == "" {
		return time.Time{}
	}
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC()
		}
	}
	whole := strings.SplitN(s, ".", 2)[0]
	if n, err := strconv.ParseInt(whole, 10, 64); err == nil && n > 0 {
		if len(whole) >= 13 {
			return time.UnixMilli(n).UTC()
		}
		return time.Unix(n, 0).UTC()
	}
	return time.Time{}
}

// truncate caps a preview string to n bytes.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
