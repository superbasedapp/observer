package droid

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/models"
)

// Record `type` discriminators observed in droid transcripts.
const (
	typeSessionStart     = "session_start"
	typeMessage          = "message"
	typeAgentTurnOutcome = "agent_turn_outcome"
	typeCompactionState  = "compaction_state"
	typeTodoState        = "todo_state"
)

// message.visibility discriminators. An absent value means a real user
// prompt (or an assistant reply); see the package doc.
const (
	visibilityLLMOnly  = "llm_only"
	visibilityUserOnly = "user_only"
)

// Content-block `type` discriminators inside message.content[].
const (
	blockText       = "text"
	blockThinking   = "thinking"
	blockToolUse    = "tool_use"
	blockToolResult = "tool_result"
)

// rawRecord is one JSONL line of a droid transcript. Every record type
// shares the flat envelope (type / id / timestamp / parentId); the
// type-specific fields below are simply absent on the other shapes, so a
// single struct decodes them all.
type rawRecord struct {
	Type      string `json:"type"`
	ID        string `json:"id"`
	Timestamp string `json:"timestamp"`
	ParentID  string `json:"parentId"`

	// session_start
	Title  string `json:"title"`
	Owner  string `json:"owner"`
	Cwd    string `json:"cwd"`
	HostID string `json:"hostId"`
	// Parent / ForkedAtMessageID mark a Factory Desktop "fork" — the
	// operator branched a NEW session off an existing one at a specific
	// message boundary rather than continuing linearly. Parent is the
	// source session's id; ForkedAtMessageID is a MESSAGE id inside that
	// parent transcript (not a session/thread id), so it has no home on
	// models.SessionLineage and is deliberately not captured — see
	// lineageForHeader.
	Parent            string `json:"parent"`
	ForkedAtMessageID string `json:"forkedAtMessageId"`

	// message
	Message *rawMessage `json:"message"`

	// agent_turn_outcome
	TurnID     string `json:"turnId"`
	Reason     string `json:"reason"`
	ResultKind string `json:"resultKind"`

	// compaction_state
	SummaryText   string `json:"summaryText"`
	SummaryTokens int64  `json:"summaryTokens"`
	SummaryKind   string `json:"summaryKind"`
	RemovedCount  int    `json:"removedCount"`
	AnchorMessage *struct {
		ID    string `json:"id"`
		Index int    `json:"index"`
	} `json:"anchorMessage"`

	// todo_state
	Todos *struct {
		Todos string `json:"todos"`
	} `json:"todos"`
	MessageIndex int `json:"messageIndex"`
}

// rawMessage is the Anthropic-shaped message body. Content is kept raw so
// both the observed array-of-blocks shape and a bare-string fallback
// decode (see decodeBlocks).
type rawMessage struct {
	Role       string          `json:"role"`
	Visibility string          `json:"visibility"`
	Content    json.RawMessage `json:"content"`
	ModelID    string          `json:"modelId"`
	// ReasoningEffort is droid's per-turn effort knob (low|medium|high).
	ReasoningEffort string `json:"reasoningEffort"`
	// UserMessageSource is droid's OWN client-provenance marker on a
	// real user-typed turn (role="user", no visibility). Grounded
	// 2026-09-03 (docs/droid-adapter.md "Factory Desktop"): present as
	// "desktop" on every genuine user prompt a Factory Desktop-composed
	// session sends, absent (the key is missing entirely, never an empty
	// string or a "cli" value) on every CLI-composed prompt — both a
	// fresh CLI session and one resumed via `droid --resume` — and also
	// absent on the tool_result-carrying synthetic user messages a turn
	// emits. See userMessageSourceDesktop in surface.go.
	UserMessageSource string `json:"userMessageSource"`
}

// rawBlock is one entry of message.content[]. Field sets are disjoint per
// block type; unused fields stay zero.
type rawBlock struct {
	Type string `json:"type"`

	// text
	Text string `json:"text"`

	// thinking — Signature carries an ENCRYPTED provider reasoning blob
	// (an OpenAI Responses `rs_...` payload); it is never emitted.
	Thinking          string `json:"thinking"`
	Signature         string `json:"signature"`
	SignatureProvider string `json:"signatureProvider"`
	DurationMs        int64  `json:"durationMs"`

	// tool_use
	ID    string          `json:"id"`
	Name  string          `json:"name"`
	Input json.RawMessage `json:"input"`

	// tool_result
	ToolUseID string          `json:"tool_use_id"`
	IsError   bool            `json:"is_error"`
	Content   json.RawMessage `json:"content"`
}

// decodeBlocks decodes message.content into blocks. The grounded shape is
// an array of typed blocks; a bare string is accepted as a single text
// block for forward-compat with the Anthropic content shorthand. An
// undecodable payload yields nil (the caller skips the message).
func decodeBlocks(raw json.RawMessage) []rawBlock {
	if len(raw) == 0 {
		return nil
	}
	var blocks []rawBlock
	if err := json.Unmarshal(raw, &blocks); err == nil {
		return blocks
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil && strings.TrimSpace(s) != "" {
		return []rawBlock{{Type: blockText, Text: s}}
	}
	return nil
}

// resultText flattens a tool_result block's `content` into plain text.
// The grounded shape is a bare string; an array of {type,text} blocks
// (the Anthropic long form) is also accepted. Anything else falls back to
// the raw JSON so nothing is silently lost.
func resultText(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s
	}
	var blocks []rawBlock
	if err := json.Unmarshal(raw, &blocks); err == nil {
		var b strings.Builder
		for _, blk := range blocks {
			if blk.Text == "" {
				continue
			}
			if b.Len() > 0 {
				b.WriteByte('\n')
			}
			b.WriteString(blk.Text)
		}
		if b.Len() > 0 {
			return b.String()
		}
	}
	return string(raw)
}

// actionMap translates droid's tool vocabulary onto the normalized action
// taxonomy. droid normalizes tool names to a Claude-Code-flavoured
// taxonomy regardless of the underlying provider (confirmed live under an
// OpenAI BYOK model, which would natively emit OpenAI-style function
// names), so the keys here are droid's own names — grounded from the
// per-session tool manifest: Read, Grep, Glob, LS, Execute, ApplyPatch,
// AskUser, Create, Edit, TodoWrite, ExitSpecMode, ToolSearch, FetchUrl,
// WebSearch, GenerateDroid, TaskOutput, TaskStop, Cron*, *Automation.
var actionMap = map[string]string{
	"Read":         models.ActionReadFile,
	"ReadFile":     models.ActionReadFile,
	"Create":       models.ActionWriteFile,
	"Write":        models.ActionWriteFile,
	"Edit":         models.ActionEditFile,
	"MultiEdit":    models.ActionEditFile,
	"ApplyPatch":   models.ActionEditFile,
	"Execute":      models.ActionRunCommand,
	"Bash":         models.ActionRunCommand,
	"Grep":         models.ActionSearchText,
	"Glob":         models.ActionSearchFiles,
	"LS":           models.ActionSearchFiles,
	"WebSearch":    models.ActionWebSearch,
	"FetchUrl":     models.ActionWebFetch,
	"WebFetch":     models.ActionWebFetch,
	"TodoWrite":    models.ActionTodoUpdate,
	"AskUser":      models.ActionAskUser,
	"ExitSpecMode": models.ActionPermissionMode,
	// Task* are droid's BACKGROUND-TASK controls (the tool manifest
	// describes task_id as "the task ID (session id)"), i.e. the
	// mission/worker-session surface — NOT the todo list, which is
	// TodoWrite above.
	"Task":       models.ActionSpawnSubagent,
	"TaskOutput": models.ActionSpawnSubagent,
	"TaskStop":   models.ActionSpawnSubagent,
	// GenerateDroid authors a custom droid definition file.
	"GenerateDroid": models.ActionWriteFile,
	// Cron* / *Automation schedule recurring prompts. There is no
	// scheduling action type; ActionConfigChange is the closest honest
	// bucket (they mutate persisted machine/cloud configuration).
	"CronCreate":        models.ActionConfigChange,
	"CronList":          models.ActionConfigChange,
	"CronDelete":        models.ActionConfigChange,
	"CreateAutomation":  models.ActionConfigChange,
	"ListAutomations":   models.ActionConfigChange,
	"ReadAutomation":    models.ActionConfigChange,
	"EditAutomation":    models.ActionConfigChange,
	"DeleteAutomation":  models.ActionConfigChange,
	"ListAutomationRun": models.ActionConfigChange,
}

// mapToolName resolves a droid tool name onto the normalized action set.
// Lookup is exact-first (droid's names are stable and capitalized), then
// case-insensitive. MCP tools — which droid namespaces with `__`, the
// same convention claude-code and cursor use — map to ActionMCPCall.
// Anything else is ActionUnknown; the raw name survives on
// ToolEvent.RawToolName either way.
func mapToolName(name string) string {
	trimmed := strings.TrimSpace(name)
	if a, ok := actionMap[trimmed]; ok {
		return a
	}
	lower := strings.ToLower(trimmed)
	for k, v := range actionMap {
		if strings.ToLower(k) == lower {
			return v
		}
	}
	if strings.Contains(trimmed, "__") || strings.HasPrefix(lower, "mcp") {
		return models.ActionMCPCall
	}
	return models.ActionUnknown
}

// targetFromInput picks a human-meaningful target from a tool_use input
// object, trying droid's observed argument keys (file_path,
// directory_path, …) before falling back to the tool name.
func targetFromInput(input json.RawMessage, fallback string) string {
	if len(input) == 0 {
		return fallback
	}
	var m map[string]any
	if err := json.Unmarshal(input, &m); err != nil {
		return fallback
	}
	for _, key := range []string{
		"file_path", "filePath", "path", "directory_path", "directoryPath",
		"command", "cmd", "query", "url", "pattern", "task_id", "todos", "prompt",
	} {
		if v, ok := m[key].(string); ok && strings.TrimSpace(v) != "" {
			return v
		}
	}
	return fallback
}

// parseTimestamp decodes droid's RFC3339 millisecond-UTC timestamps
// ("2026-07-28T18:03:10.939Z"). Returns the zero time when absent or
// unparseable — callers substitute the last known record timestamp.
func parseTimestamp(raw string) time.Time {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return time.Time{}
	}
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339} {
		if t, err := time.Parse(layout, raw); err == nil {
			return t.UTC()
		}
	}
	return time.Time{}
}

// contentHash returns a short stable hex digest, used to build the
// content-addressed SourceEventID that collapses droid's per-turn
// repeated context injection into one row per distinct payload.
func contentHash(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])[:16]
}

// truncate caps a preview string to n bytes.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// firstNonEmpty returns the first non-blank string.
func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}
