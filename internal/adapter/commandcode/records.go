package commandcode

import (
	"encoding/json"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/models"
)

// rawLine is one JSONL line of a Command Code transcript. The two record
// shapes (`session` header and `message`) share one struct, discriminated
// by Type; fields absent on a given shape stay zero.
//
// Note that ID means different things per shape: on the session header it
// is the session UUID, on a message line it is a short 8-hex-char
// per-line identifier. Usage and Model sit on the OUTER record, not
// inside Message.
type rawLine struct {
	Type      string      `json:"type"`
	Version   int         `json:"version"`
	ID        string      `json:"id"`
	ParentID  *string     `json:"parentId"`
	Timestamp string      `json:"timestamp"`
	Cwd       string      `json:"cwd"`
	Message   *rawMessage `json:"message"`
	Usage     *rawUsage   `json:"usage"`
	Model     string      `json:"model"`
}

// rawMessage is the Anthropic-shaped message body. Content is decoded as
// json.RawMessage because a bare-string content (the shape the Gemini
// adapter was bitten by) cannot be ruled out from the thin Phase-0
// sample, even though every observed line carried an array.
type rawMessage struct {
	Role    string          `json:"role"`
	Content json.RawMessage `json:"content"`
	Meta    *rawMeta        `json:"meta"`
}

// rawMeta is the per-message metadata envelope. Source is a third
// role-like discriminator ("user" / "model" / "tool") that identifies
// tool results, which arrive wrapped in a role:"user" message per the
// Anthropic Messages API convention. MessageID is a full UUID, distinct
// from the outer line ID.
type rawMeta struct {
	Source    string `json:"source"`
	CreatedAt int64  `json:"createdAt"`
	MessageID string `json:"messageId"`
}

// rawBlock is one content block. Exactly one variant is populated,
// discriminated by Type: text / thinking / tool_use / tool_result.
type rawBlock struct {
	Type string `json:"type"`
	// text
	Text string `json:"text"`
	// thinking / reasoning (defensive — not observed in Phase 0, which
	// only ran a non-reasoning free model)
	Thinking string `json:"thinking"`
	// tool_use
	ID    string          `json:"id"`
	Name  string          `json:"name"`
	Input json.RawMessage `json:"input"`
	// tool_result
	ToolUseID string          `json:"tool_use_id"`
	Content   json.RawMessage `json:"content"`
	IsError   *bool           `json:"is_error"`
}

// rawUsage is the per-assistant-message token envelope. Field names are
// camelCase and unique to this tool. There is no totalTokens field.
// InputTokens is GROSS (includes CacheReadTokens) — see tokenBundle.
// ReasoningTokens is decoded defensively; no reasoning-capable model was
// exercised in the Phase-0 capture, so its presence is unconfirmed.
type rawUsage struct {
	InputTokens      int64   `json:"inputTokens"`
	OutputTokens     int64   `json:"outputTokens"`
	CacheReadTokens  int64   `json:"cacheReadTokens"`
	CacheWriteTokens int64   `json:"cacheWriteTokens"`
	ReasoningTokens  int64   `json:"reasoningTokens"`
	CostUSD          float64 `json:"costUsd"`
}

// sessionMeta is the `<uuid>.meta.json` sidecar. Only Model is consumed
// (as a fallback when a usage record omits its model); TraceIDs are the
// tool's own OpenTelemetry ids and Title is a model-generated string that
// can echo pasted secrets — neither is surfaced.
type sessionMeta struct {
	TraceIDs []string `json:"traceIds"`
	Model    string   `json:"model"`
	Title    string   `json:"title"`
}

// isZero reports whether the usage envelope carries nothing worth
// persisting, so a usage block of all zeros never produces a phantom
// token row.
func (u *rawUsage) isZero() bool {
	if u == nil {
		return true
	}
	return u.InputTokens == 0 && u.OutputTokens == 0 &&
		u.CacheReadTokens == 0 && u.CacheWriteTokens == 0 &&
		u.ReasoningTokens == 0 && u.CostUSD == 0
}

// tokenParts is the NET-token view derived from a usage envelope.
type tokenParts struct {
	inputNet  int64
	output    int64
	cacheRead int64
	cacheWrit int64
	reasoning int64
	costUSD   float64
}

// tokenBundle converts a Command Code usage envelope into NET token
// counts.
//
// `inputTokens` is GROSS: it INCLUDES `cacheReadTokens`. The evidence is
// arithmetic across three live sessions — a turn's cacheReadTokens sits
// within tens of tokens of its inputTokens while inputTokens itself grows
// only slightly turn-over-turn (the textbook prompt-cache replay), and a
// brand-new session's FIRST turn already reports ~7,900 cache-read tokens
// from the cross-session-warm system-prompt prefix. Reading the same
// numbers as NET would imply a ~21k-token prompt jump from one short
// assistant reply. The `chatcmpl-tool-*` tool-call id prefix (an
// OpenAI-Chat-Completions-shaped backend) corroborates it: OpenAI-shaped
// input is gross everywhere else in this repo.
//
// [models.TokenEvent.InputTokens] must be NET, so cache-read is
// subtracted and clamped at zero. `cacheWriteTokens` was zero in every
// sample, so whether it is ALSO folded into inputTokens is unverified —
// it is carried through untouched rather than guessed at.
func tokenBundle(u *rawUsage) tokenParts {
	if u == nil {
		return tokenParts{}
	}
	net := u.InputTokens - u.CacheReadTokens
	if net < 0 {
		net = 0
	}
	return tokenParts{
		inputNet:  net,
		output:    u.OutputTokens,
		cacheRead: u.CacheReadTokens,
		cacheWrit: u.CacheWriteTokens,
		reasoning: u.ReasoningTokens,
		costUSD:   u.CostUSD,
	}
}

// contentBlocks returns the message's content blocks. It tolerates both
// the observed array shape and a bare-string content (which is folded
// into a single synthetic text block) so a role whose content changes
// shape never costs a whole line.
func (m *rawMessage) contentBlocks() []rawBlock {
	if m == nil || len(m.Content) == 0 {
		return nil
	}
	var blocks []rawBlock
	if err := json.Unmarshal(m.Content, &blocks); err == nil {
		return blocks
	}
	var s string
	if err := json.Unmarshal(m.Content, &s); err == nil && strings.TrimSpace(s) != "" {
		return []rawBlock{{Type: "text", Text: s}}
	}
	return nil
}

// actionMap translates Command Code tool names onto the normalized
// taxonomy. Keys are normalized by normalizeToolKey (lower-cased, `_`
// and `-` removed) so both snake_case (the native spelling) and any
// camelCase variant resolve to the same row.
//
// GROUNDED (observed in live capture): read_file, read_directory,
// shell_command — Command Code's only shell/run tool (WP-T6 live probe
// finding B1, 2026-07-31; it previously fell to unknown because the
// name normalizes to "shellcommand", distinct from "runshellcommand").
// Everything else is a DEFENSIVE entry covering the
// conventional OpenAI-compat agent vocabulary — Command Code's slash
// commands (/worktree, /plan, /review, /mcp, /skills) imply a much
// richer runtime tool surface than the two calls the Phase-0 capture
// exercised. An unrecognised name is never dropped: it becomes
// ActionUnknown with the raw name preserved on the event, and the parse
// records a one-shot warning so the gap is visible.
var actionMap = map[string]string{
	// grounded
	"readfile":      models.ActionReadFile,
	"readdirectory": models.ActionSearchFiles,
	"shellcommand":  models.ActionRunCommand,
	// defensive — read
	"read":          models.ActionReadFile,
	"viewfile":      models.ActionReadFile,
	"view":          models.ActionReadFile,
	"readmanyfiles": models.ActionReadFile,
	"listdirectory": models.ActionSearchFiles,
	"listfiles":     models.ActionSearchFiles,
	"listdir":       models.ActionSearchFiles,
	"ls":            models.ActionSearchFiles,
	"glob":          models.ActionSearchFiles,
	"findfiles":     models.ActionSearchFiles,
	// defensive — write / edit
	"writefile":  models.ActionWriteFile,
	"write":      models.ActionWriteFile,
	"createfile": models.ActionWriteFile,
	"editfile":   models.ActionEditFile,
	"edit":       models.ActionEditFile,
	"multiedit":  models.ActionEditFile,
	"applypatch": models.ActionEditFile,
	"patch":      models.ActionEditFile,
	"replace":    models.ActionEditFile,
	// defensive — shell
	"runcommand":      models.ActionRunCommand,
	"runshellcommand": models.ActionRunCommand,
	"shell":           models.ActionRunCommand,
	"bash":            models.ActionRunCommand,
	"exec":            models.ActionRunCommand,
	"execute":         models.ActionRunCommand,
	"terminal":        models.ActionRunCommand,
	"powershell":      models.ActionRunCommand,
	"pwsh":            models.ActionRunCommand,
	// defensive — search
	"grep":              models.ActionSearchText,
	"searchtext":        models.ActionSearchText,
	"searchfilecontent": models.ActionSearchText,
	"ripgrep":           models.ActionSearchText,
	"codesearch":        models.ActionSearchText,
	"searchfiles":       models.ActionSearchFiles,
	// defensive — web
	"websearch": models.ActionWebSearch,
	"webfetch":  models.ActionWebFetch,
	"fetch":     models.ActionWebFetch,
	"fetchurl":  models.ActionWebFetch,
	"readurl":   models.ActionWebFetch,
	// defensive — agents / planning
	"task":                models.ActionSpawnSubagent,
	"agent":               models.ActionSpawnSubagent,
	"spawnagent":          models.ActionSpawnSubagent,
	"subagent":            models.ActionSpawnSubagent,
	"delegate":            models.ActionSpawnSubagent,
	"todowrite":           models.ActionTodoUpdate,
	"todo":                models.ActionTodoUpdate,
	"updateplan":          models.ActionTodoUpdate,
	"updatetodos":         models.ActionTodoUpdate,
	"askuser":             models.ActionAskUser,
	"askuserquestion":     models.ActionAskUser,
	"askfollowupquestion": models.ActionAskUser,
}

// normalizeToolKey lower-cases a raw tool name and strips `_` / `-` /
// whitespace so snake_case, kebab-case and camelCase spellings of the
// same tool collapse to one lookup key.
func normalizeToolKey(name string) string {
	key := strings.ToLower(strings.TrimSpace(name))
	key = strings.ReplaceAll(key, "_", "")
	key = strings.ReplaceAll(key, "-", "")
	return strings.ReplaceAll(key, " ", "")
}

// mapToolName resolves a raw Command Code tool name onto a normalized
// action type, reporting whether the name was recognised. An exact
// (normalized) match wins; an MCP-routed call (`mcp` prefix or a `__`
// separator) maps to ActionMCPCall; everything else falls back to
// ActionUnknown with recognised=false so the caller can warn once. The
// raw name is always preserved on ToolEvent.RawToolName.
func mapToolName(name string) (action string, recognised bool) {
	key := normalizeToolKey(name)
	if key == "" {
		return models.ActionUnknown, false
	}
	if a, ok := actionMap[key]; ok {
		return a, true
	}
	if strings.HasPrefix(key, "mcp") || strings.Contains(name, "__") {
		return models.ActionMCPCall, true
	}
	return models.ActionUnknown, false
}

// targetKeys are the tool_use input keys tried, in order, when picking a
// representative target for an action. `file_path` (read_file) and
// `path` (read_directory) are the grounded ones; the rest cover the
// conventional vocabulary the defensive actionMap rows anticipate.
var targetKeys = []string{
	"file_path", "filePath", "absolute_path", "absolutePath",
	"path", "file", "directory", "dir",
	"command", "cmd", "query", "url", "pattern", "prompt",
}

// targetFromInput picks a representative target from a tool_use `input`
// object, falling back to the tool name when no known key is present or
// the input isn't an object.
func targetFromInput(input json.RawMessage, fallback string) string {
	if len(input) == 0 {
		return fallback
	}
	var m map[string]any
	if err := json.Unmarshal(input, &m); err != nil {
		return fallback
	}
	for _, key := range targetKeys {
		if v, ok := m[key].(string); ok && strings.TrimSpace(v) != "" {
			return v
		}
	}
	return fallback
}

// authoredBytes returns the byte length of the code the model authored in
// a write / edit / run action, read from the untruncated tool input.
// Zero for read-only or unrecognised actions.
//
// The key names are DEFENSIVE: the Phase-0 capture only exercised
// read-only tools, so no write/edit/run input shape is grounded. An
// input that doesn't carry any of these keys simply yields 0 rather
// than a wrong number.
func authoredBytes(actionType string, input json.RawMessage) int64 {
	if len(input) == 0 {
		return 0
	}
	var in struct {
		Content   string `json:"content"`
		NewString string `json:"new_string"`
		NewText   string `json:"new_text"`
		Command   string `json:"command"`
		Edits     []struct {
			NewString string `json:"new_string"`
			NewText   string `json:"new_text"`
		} `json:"edits"`
	}
	if err := json.Unmarshal(input, &in); err != nil {
		return 0
	}
	switch actionType {
	case models.ActionWriteFile:
		return int64(len(in.Content))
	case models.ActionEditFile:
		n := int64(len(in.NewString) + len(in.NewText))
		for _, e := range in.Edits {
			n += int64(len(e.NewString) + len(e.NewText))
		}
		return n
	case models.ActionRunCommand:
		return int64(len(in.Command))
	default:
		return 0
	}
}

// toolResultText flattens a tool_result block's `content` into plain
// text. The observed shape is an array of `{type:"text",text}` blocks; a
// bare string is tolerated too.
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
		if b.Len() > 0 {
			return b.String()
		}
		return ""
	}
	return string(raw)
}

// truncate caps a preview string to n bytes.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
