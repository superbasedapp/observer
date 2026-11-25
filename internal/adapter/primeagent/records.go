package primeagent

import (
	"encoding/json"
	"strings"
	"time"
)

// Entry `type` discriminators this adapter consumes. Every other
// documented type is skipped silently — see the package doc.
const (
	typeSession        = "session"
	typeMessage        = "message"
	typeModelChange    = "model_change"
	typeCompaction     = "compaction"
	typeChildUsageAttr = "child_usage_attributed"
)

// Message `role` discriminators (the AgentMessage union).
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
)

// rawLine is the superset of every session-entry shape. Prime Agent's
// entries share one flat envelope and differ only in which extra fields
// are populated, so one decode covers the whole vocabulary; the Type
// switch in adapter.go decides which fields are meaningful.
type rawLine struct {
	Type      string `json:"type"`
	ID        string `json:"id"`
	Timestamp string `json:"timestamp"`

	// `session` header.
	Version int      `json:"version"`
	Cwd     string   `json:"cwd"`
	Git     *gitMeta `json:"git"`

	// `model_change`.
	Provider string `json:"provider"`
	ModelID  string `json:"modelId"`

	// `message`.
	Message *agentMessage `json:"message"`

	// `compaction`.
	Summary      string `json:"summary"`
	TokensBefore int64  `json:"tokensBefore"`

	// `child_usage_attributed` (TargetID is also present on `label`,
	// which the type switch never reaches).
	TargetID       string `json:"targetId"`
	AggregateUsage *usage `json:"aggregateUsage"`
}

// gitMeta is the header's repository snapshot. Only Branch is consumed —
// the project root comes from Cwd via git.Resolve, and RepoURL/Commit are
// not columns this adapter owns.
type gitMeta struct {
	RepoURL string `json:"repoUrl"`
	Commit  string `json:"commit"`
	Branch  string `json:"branch"`
}

// agentMessage is the decoded superset of the AgentMessage union. Every
// role arrives nested under the same `message` field; Role selects which
// fields are populated.
type agentMessage struct {
	Role    string       `json:"role"`
	Content contentParts `json:"content"`

	// assistant.
	API           string `json:"api"`
	Provider      string `json:"provider"`
	Model         string `json:"model"`
	ResponseID    string `json:"responseId"`
	ResponseModel string `json:"responseModel"`
	StopReason    string `json:"stopReason"`
	ErrorMessage  string `json:"errorMessage"`
	Usage         *usage `json:"usage"`

	// toolResult.
	ToolCallID string       `json:"toolCallId"`
	ToolName   string       `json:"toolName"`
	IsError    bool         `json:"isError"`
	Details    *toolDetails `json:"details"`

	// bashExecution. ExitCode is undefined while the command is still
	// running, so it is a pointer rather than a zero-valued int.
	Command   string `json:"command"`
	Output    string `json:"output"`
	ExitCode  *int   `json:"exitCode"`
	Cancelled bool   `json:"cancelled"`
	Truncated bool   `json:"truncated"`

	// compactionSummary / branchSummary.
	Summary string `json:"summary"`

	// Unix MILLISECONDS. Overrides the envelope's ISO timestamp when set.
	Timestamp int64 `json:"timestamp"`
}

// toolDetails is the tool-specific result metadata. The shape below is
// the built-in ipython tool's (IpythonToolDetails); a custom tool's
// details decode to zero values, which is harmless because only
// DurationMs is consumed.
type toolDetails struct {
	DurationMs      int64  `json:"durationMs"`
	Status          string `json:"status"`
	Stdout          string `json:"stdout"`
	Stderr          string `json:"stderr"`
	KernelRestarted bool   `json:"kernelRestarted"`
}

// usage is Prime Agent's per-message token + cost envelope.
//
// Input is NET of the cached prefix: `TotalTokens == Input + Output +
// CacheRead + CacheWrite` holds exactly on every observed row, which is
// the checklist §4.4c net signature. Nothing here is re-netted.
type usage struct {
	Input       int64 `json:"input"`
	Output      int64 `json:"output"`
	CacheRead   int64 `json:"cacheRead"`
	CacheWrite  int64 `json:"cacheWrite"`
	TotalTokens int64 `json:"totalTokens"`
	Cost        struct {
		Input      float64 `json:"input"`
		Output     float64 `json:"output"`
		CacheRead  float64 `json:"cacheRead"`
		CacheWrite float64 `json:"cacheWrite"`
		Total      float64 `json:"total"`
	} `json:"cost"`
}

// empty reports whether the envelope carries no token counts at all — the
// shape a provider error (401 / 402) leaves behind. Such a turn produces
// no token row (§4.4b): the counts are observationally vacant, and a zero
// row per failed attempt is noise the cost surfaces then have to filter.
func (u *usage) empty() bool {
	if u == nil {
		return true
	}
	return u.Input == 0 && u.Output == 0 && u.CacheRead == 0 && u.CacheWrite == 0
}

// contentPart is one normalized content block. Image parts decode with an
// empty Text and are ignored by the text/thinking accumulators.
type contentPart struct {
	Type              string         `json:"type"`
	Text              string         `json:"text"`
	Thinking          string         `json:"thinking"`
	ThinkingSignature string         `json:"thinkingSignature"`
	ID                string         `json:"id"`
	Name              string         `json:"name"`
	Arguments         map[string]any `json:"arguments"`
	MimeType          string         `json:"mimeType"`
}

// contentParts tolerates every shape a message's `content` can take.
//
// This is the checklist §4.4d guard and it is load-bearing here, not
// defensive boilerplate: the vendor types UserMessage.content as
// `string | (TextContent | ImageContent)[]` and its own documented
// parsing example uses the bare-string form. A strict `[]contentPart`
// would make json.Unmarshal fail on the WHOLE entry envelope, and the
// parser would drop the user's prompt line entirely — precisely the
// Gemini bug that shipped a dashboard showing prompts with no replies.
//
// Normalisation: a string becomes one text part, an array decodes as-is,
// a bare object becomes one part, and null/absent becomes no parts.
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
		if strings.TrimSpace(s) == "" {
			*c = nil
			return nil
		}
		*c = contentParts{{Type: partText, Text: s}}
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
		// A number or bool is not a shape the schema allows; treat it as
		// absent rather than failing the whole entry.
		*c = nil
		return nil
	}
}

// text joins every text part, in order.
func (c contentParts) text() string {
	return c.join(partText)
}

// thinking joins every thinking part, in order. Prime Agent carries the
// whole turn in one record with no ordering between a thinking block and
// the tool calls beside it, so the reasoning FANS OUT to every event that
// record produces — the same threading pi uses.
func (c contentParts) thinking() string {
	return c.join(partThinking)
}

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
// timestamp (2001-09-09 .. 2286-11-20). parseUnixMillis rejects anything
// outside, so a schema that silently switched to seconds or microseconds
// yields a zero time the caller falls back from — rather than a 1970 or
// year-50000 row nobody notices.
const (
	epochMillisFloor = int64(1_000_000_000_000)
	epochMillisCeil  = int64(9_999_999_999_999)
)

// parseUnixMillis converts the inner message timestamp. Returns the zero
// time when the value is absent or outside the plausible window.
func parseUnixMillis(ms int64) time.Time {
	if ms < epochMillisFloor || ms > epochMillisCeil {
		return time.Time{}
	}
	return time.UnixMilli(ms).UTC()
}
