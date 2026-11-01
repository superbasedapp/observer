package kimchi

import (
	"encoding/json"
	"strings"
	"time"
)

// Entry `type` discriminators this adapter consumes. Every other type the
// log carries (`custom`, `custom_message`, `session_info`, `label`,
// `branch_summary`) is skipped silently — see the package doc.
const (
	typeSession          = "session"
	typeMessage          = "message"
	typeModelChange      = "model_change"
	typeThinkingChange   = "thinking_level_change"
	typeCompaction       = "compaction"
	typeCustom           = "custom"
	customSubagentEntry  = "kimchi:subagent-session"
	customPermissionMode = "permission_mode"
)

// Message `role` discriminators (the pi-mono AgentMessage union).
const (
	roleUser              = "user"
	roleAssistant         = "assistant"
	roleToolResult        = "toolResult"
	roleBashExecution     = "bashExecution"
	roleCompactionSummary = "compactionSummary"
)

// Content-part `type` discriminators.
const (
	partText     = "text"
	partThinking = "thinking"
	partToolCall = "toolCall"
	partImage    = "image"
)

// rawLine is the superset of every session-entry shape. Kimchi inherits
// pi-mono's flat envelope (session format version 3): every entry shares
// type / id / parentId / timestamp and differs only in which extra fields
// are populated, so one decode covers the whole vocabulary.
type rawLine struct {
	Type      string `json:"type"`
	ID        string `json:"id"`
	Timestamp string `json:"timestamp"`

	// `session` header. ParentSession is the ABSOLUTE PATH of the
	// transcript this one was forked from or spawned by (never an id).
	Version       int    `json:"version"`
	Cwd           string `json:"cwd"`
	ParentSession string `json:"parentSession"`

	// `model_change`.
	Provider string `json:"provider"`
	ModelID  string `json:"modelId"`

	// `thinking_level_change`.
	ThinkingLevel string `json:"thinkingLevel"`

	// `custom`. Data is kept raw: only the `permission_mode` payload is
	// decoded (permissionData); every other custom payload (context_assembly,
	// llm_response_debug, ...) is never inspected, so a bool, object or
	// oversized `data` can never fail the entry's decode.
	CustomType string          `json:"customType"`
	Data       json.RawMessage `json:"data"`

	// `message`.
	Message *agentMessage `json:"message"`

	// `compaction`.
	Summary      string `json:"summary"`
	TokensBefore int64  `json:"tokensBefore"`
}

// agentMessage is the decoded superset of the AgentMessage union. Every
// role arrives nested under the same `message` field; Role selects which
// fields are populated.
type agentMessage struct {
	Role    string       `json:"role"`
	Content contentParts `json:"content"`

	// assistant.
	API          string `json:"api"`
	Provider     string `json:"provider"`
	Model        string `json:"model"`
	StopReason   string `json:"stopReason"`
	ErrorMessage string `json:"errorMessage"`
	Usage        *usage `json:"usage"`

	// toolResult.
	ToolCallID string       `json:"toolCallId"`
	ToolName   string       `json:"toolName"`
	IsError    bool         `json:"isError"`
	Details    *toolDetails `json:"details"`

	// bashExecution (pi-mono's `!`-prefixed operator shell). ExitCode is
	// undefined while the command still runs, hence the pointer.
	Command   string `json:"command"`
	Output    string `json:"output"`
	ExitCode  *int   `json:"exitCode"`
	Cancelled bool   `json:"cancelled"`

	// compactionSummary.
	Summary string `json:"summary"`

	// Unix MILLISECONDS. On an assistant record this is when the stream
	// STARTED; the envelope timestamp is when the record was appended (the
	// stream's end). See genMs.
	Timestamp int64 `json:"timestamp"`
}

// permissionData is the `custom:permission_mode` payload: the harness's
// permission posture for the session ({"mode":"default","source":"config",
// "initiatedBy":"user"} on every live session). Only Mode is consumed.
type permissionData struct {
	Mode string `json:"mode"`
}

// toolDetails is the per-tool result metadata. Only the bash family's
// elapsedSeconds is consumed; every other tool's details (todo
// snapshots, edit diffs, write line counts) decode to zero values.
type toolDetails struct {
	ElapsedSeconds float64 `json:"elapsedSeconds"`
}

// usage is the per-message token + cost envelope.
//
// Input is NET of the cached prefix and Output INCLUDES Reasoning:
// `totalTokens == input + output + cacheRead + cacheWrite` holds exactly
// on every observed row on both API lanes, with `reasoning` never adding
// to it (WSL row 1: 9932 + 301 = 10233 with reasoning 92). See the
// package doc "Token semantics".
type usage struct {
	Input       int64 `json:"input"`
	Output      int64 `json:"output"`
	CacheRead   int64 `json:"cacheRead"`
	CacheWrite  int64 `json:"cacheWrite"`
	Reasoning   int64 `json:"reasoning"`
	TotalTokens int64 `json:"totalTokens"`
	Cost        struct {
		Total float64 `json:"total"`
	} `json:"cost"`
}

// empty reports whether the envelope carries no token counts at all — the
// shape a provider error leaves behind (the operator's three exhausted-
// credit kimchi-dev turns). Such a turn produces no token row.
func (u *usage) empty() bool {
	if u == nil {
		return true
	}
	return u.Input == 0 && u.Output == 0 && u.CacheRead == 0 && u.CacheWrite == 0 && u.Reasoning == 0
}

// split returns the disjoint (output, reasoning) pair the cost engine
// requires: the envelope's output already contains the reasoning count,
// so it is subtracted (clamped at zero) rather than billed twice.
func (u *usage) split() (output, reasoning int64) {
	reasoning = u.Reasoning
	if reasoning < 0 {
		reasoning = 0
	}
	output = u.Output - reasoning
	if output < 0 {
		output = 0
	}
	return output, reasoning
}

// contentPart is one normalized content block. Image parts carry their
// MimeType; their base64 `data` is never decoded.
type contentPart struct {
	Type      string         `json:"type"`
	Text      string         `json:"text"`
	Thinking  string         `json:"thinking"`
	ID        string         `json:"id"`
	Name      string         `json:"name"`
	Arguments map[string]any `json:"arguments"`
	MimeType  string         `json:"mimeType"`
}

// contentParts tolerates every shape a message's `content` can take
// (checklist §4.4d): pi-mono types UserMessage.content as
// `string | (TextContent | ImageContent)[]`, and a strict slice type would
// fail the WHOLE entry on the string form and drop the prompt line. A
// string becomes one text part, an array decodes as-is, a bare object
// becomes one part and null/absent becomes no parts.
type contentParts []contentPart

// UnmarshalJSON implements json.Unmarshaler.
func (c *contentParts) UnmarshalJSON(b []byte) error {
	trimmed := strings.TrimSpace(string(b))
	if trimmed == "" || trimmed == "null" {
		*c = nil
		return nil
	}
	switch trimmed[0] {
	case '"':
		var s string
		if err := json.Unmarshal(b, &s); err != nil {
			return err
		}
		*c = nil
		if strings.TrimSpace(s) != "" {
			*c = contentParts{{Type: partText, Text: s}}
		}
		return nil
	case '[':
		var parts []contentPart
		if err := json.Unmarshal(b, &parts); err != nil {
			return err
		}
		*c = parts
		return nil
	case '{':
		var one contentPart
		if err := json.Unmarshal(b, &one); err != nil {
			return err
		}
		*c = contentParts{one}
		return nil
	default:
		*c = nil
		return nil
	}
}

// text joins every text part, in order.
func (c contentParts) text() string { return c.join(partText) }

// thinking joins every thinking part, in order. Kimchi carries a whole
// model call in one record with no ordering between a thinking block and
// the tool calls beside it, so the reasoning FANS OUT to every row the
// record produces (the same threading pi and prime-agent use).
func (c contentParts) thinking() string { return c.join(partThinking) }

func (c contentParts) join(kind string) string {
	var parts []string
	for _, p := range c {
		if p.Type != kind {
			continue
		}
		v := p.Text
		if kind == partThinking {
			v = p.Thinking
		}
		if strings.TrimSpace(v) == "" {
			continue
		}
		parts = append(parts, v)
	}
	return strings.TrimSpace(strings.Join(parts, "\n"))
}

// toolCalls returns the record's toolCall parts, in order.
func (c contentParts) toolCalls() []contentPart {
	var out []contentPart
	for _, p := range c {
		if p.Type == partToolCall {
			out = append(out, p)
		}
	}
	return out
}

// epochMillisFloor / epochMillisCeil bound a plausible Unix-millisecond
// timestamp (2001-09-09 .. 2286-11-20) so a unit change yields a zero time
// the caller falls back from instead of a 1970 or year-50000 row.
const (
	epochMillisFloor = int64(1_000_000_000_000)
	epochMillisCeil  = int64(9_999_999_999_999)
)

// parseUnixMillis converts an inner message timestamp. Returns the zero
// time when the value is absent or implausible.
func parseUnixMillis(ms int64) time.Time {
	if ms < epochMillisFloor || ms > epochMillisCeil {
		return time.Time{}
	}
	return time.UnixMilli(ms).UTC()
}

// parseTimestamp converts the entry envelope's ISO-8601 timestamp.
func parseTimestamp(raw string) time.Time {
	if raw == "" {
		return time.Time{}
	}
	if t, err := time.Parse(time.RFC3339Nano, raw); err == nil {
		return t.UTC()
	}
	if t, err := time.Parse(time.RFC3339, raw); err == nil {
		return t.UTC()
	}
	return time.Time{}
}
