package muse

import (
	"encoding/json"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/models"
)

// Payload type discriminators. Only the ones this adapter consumes are
// named; every other payload_type is informational and skipped silently.
const (
	ptRuntimeSession  = "runtime.session"
	ptSessionMeta     = "runtime.session.metadata"
	ptSessionOpened   = "session.opened.observed"
	ptWorkspaceBranch = "session.workspace_branch.observed"
	ptSessionEnd      = "session.end"
	ptToolBatchTerm   = "tool_batch.effect.terminal"
	ptRunModel        = "run.model.configured"
)

// runtime.session event kinds this adapter acts on. The Phase-0 capture
// carried 30 distinct kinds; the rest are scheduler / reminder / diagnostic
// bookkeeping with no normalized-action counterpart.
const (
	evStarted        = "started"
	evAssistantMsg   = "assistant_message_committed"
	evToolCalls      = "assistant_tool_calls_committed"
	evToolResults    = "tool_result_batch_committed"
	evModelCompleted = "model_completed"
	evTerminal       = "terminal"
)

// rawRecord is one JSONL line of a Muse session log.
//
// Two line shapes share this struct. An EVENT record carries
// payload_type + payload; a RETAINED-MARKER tombstone carries
// retained_marker + omitted_record and no payload at all (a record that
// was ephemeral and deliberately not durably written). The marker lines
// are recognised so they can be skipped silently instead of being
// reported as malformed.
type rawRecord struct {
	SchemaVersion  int             `json:"schema_version"`
	ID             string          `json:"id"`
	Stream         *streamRef      `json:"stream"`
	Sequence       int64           `json:"sequence"`
	RecordedAt     int64           `json:"recorded_at"`
	RecordType     string          `json:"record_type"`
	Durability     string          `json:"durability"`
	PayloadType    string          `json:"payload_type"`
	Payload        *rawPayload     `json:"payload"`
	RetainedMarker string          `json:"retained_marker"`
	OmittedRecord  json.RawMessage `json:"omitted_record"`
}

// isMarker reports whether the line is a retained-marker tombstone rather
// than an event record.
func (r *rawRecord) isMarker() bool {
	return r.RetainedMarker != "" || len(r.OmittedRecord) > 0
}

// streamRef is the {kind,id} stream pointer every record carries. For a
// session log the kind is "session" and the id is the session UUID; the
// adapter prefers the PATH-derived id (§4.5a) and uses this only to
// cross-check.
type streamRef struct {
	Kind string `json:"kind"`
	ID   string `json:"id"`
}

// rawPayload is the record payload. One struct covers every payload_type
// the adapter reads: `runtime.session` populates Event (+ RunID/TaskID),
// while the observed-record shapes (metadata / session_opened /
// workspace_branch / session_end / tool_batch effect) populate Record.
type rawPayload struct {
	Kind   string        `json:"kind"`
	RunID  string        `json:"run_id"`
	TaskID string        `json:"task_id"`
	Event  *sessionEvent `json:"event"`
	Record *metaRecord   `json:"record"`
}

// sessionEvent is `payload.event` on a runtime.session record. Kind is the
// discriminator; the remaining fields are populated per-kind and stay zero
// otherwise. A single tolerant struct (rather than one type per kind) keeps
// the dispatch table-driven and additive: a new kind that reuses an
// existing field name needs no new type.
type sessionEvent struct {
	Kind string `json:"kind"`

	// started (run level) — the user's prompt, verbatim. Task-level
	// `started` events carry a task_id and no prompt.
	Prompt string `json:"prompt"`

	// model_completed
	Model        string    `json:"model"`
	Usage        *rawUsage `json:"usage"`
	DurationMs   int64     `json:"duration_ms"`
	FinishReason string    `json:"finish_reason"`

	// assistant_message_committed / reasoning_committed
	MessageID  string `json:"message_id"`
	ResponseID string `json:"response_id"`
	Text       string `json:"text"`

	// assistant_tool_calls_committed
	ToolCalls []rawToolCall `json:"tool_calls"`

	// tool_result_batch_committed
	BatchID string          `json:"batch_id"`
	Results []rawToolResult `json:"results"`

	// terminal (run level)
	Terminal       string `json:"terminal"`
	Reason         string `json:"reason"`
	TurnDurationMs int64  `json:"turn_duration_ms"`
}

// rawToolCall is one entry of assistant_tool_calls_committed.tool_calls.
// Args is a JSON STRING (the provider's serialized function arguments), not
// a nested object — it must be unmarshalled a second time to reach the
// per-tool keys.
type rawToolCall struct {
	Name   string `json:"name"`
	CallID string `json:"call_id"`
	ID     string `json:"id"`
	Args   string `json:"args"`
}

// rawToolResult is one entry of tool_result_batch_committed.results. It
// joins back to a rawToolCall on ToolCallID == rawToolCall.CallID.
type rawToolResult struct {
	ToolCallID    string `json:"tool_call_id"`
	ToolCallIndex int    `json:"tool_call_index"`
	Text          string `json:"text"`
}

// rawUsage is model_completed.usage. See the package doc for the gross-vs-
// net analysis: InputTokens INCLUDES CacheReadTokens, and OutputTokens
// INCLUDES ReasoningTokens.
type rawUsage struct {
	InputTokens      int64 `json:"input_tokens"`
	OutputTokens     int64 `json:"output_tokens"`
	CacheReadTokens  int64 `json:"cache_read_tokens"`
	CacheWriteTokens int64 `json:"cache_write_tokens"`
	CachedTokens     int64 `json:"cached_tokens"`
	ReasoningTokens  int64 `json:"reasoning_tokens"`
}

// metaRecord is `payload.record` on the observed-record payload types. As
// with sessionEvent, one tolerant struct covers several shapes.
type metaRecord struct {
	// runtime.session.metadata / session.workspace_branch.observed
	WorkspaceRoot string `json:"workspace_root"`
	ProviderID    string `json:"provider_id"`
	ModelID       string `json:"model_id"`

	// session.opened.observed / session.end
	SessionID  string `json:"session_id"`
	Resume     bool   `json:"resume"`
	ExitReason string `json:"exit_reason"`

	// session.workspace_branch.observed
	Reference *branchRef `json:"reference"`
	VCS       string     `json:"vcs"`
	Commit    string     `json:"commit"`

	// tool_batch.effect.terminal
	CallID   string         `json:"call_id"`
	ToolName string         `json:"tool_name"`
	Outcome  *effectOutcome `json:"outcome"`
}

// branchRef is the workspace_branch record's reference pointer. Kind is
// "branch" for a normal checkout; a detached HEAD reports a different kind,
// which the adapter treats as "no branch" rather than guessing.
type branchRef struct {
	Kind string `json:"kind"`
	Name string `json:"name"`
}

// effectOutcome is tool_batch.effect.terminal.record.outcome — the per-call
// verdict, and the ONLY explicit success signal in the log (the result text
// is free-form per tool).
//
// Two shapes exist on record.outcome across builds. The documented one is
// an object, `{"kind":"completed"}`. A 2026-08-07 live capture also emits a
// BARE STRING, e.g. `"outcome":"error"`, on a `voice.capture.observed`
// record — a payload_type this adapter never dispatches (§ handle), but
// every line is still fully json.Unmarshal'd into rawRecord regardless of
// payload_type, so a strict struct here breaks the WHOLE line and is
// reported as malformed JSON even though nothing downstream would have read
// it. UnmarshalJSON tolerates both shapes so an unrelated record can never
// stall the parse; the string form's value becomes Kind directly, which
// keeps failedOutcomes classifying it correctly if this shape is ever
// reached through tool_batch.effect.terminal too.
type effectOutcome struct {
	Kind string `json:"kind"`
}

// UnmarshalJSON implements json.Unmarshaler.
func (o *effectOutcome) UnmarshalJSON(b []byte) error {
	trimmed := strings.TrimSpace(string(b))
	if trimmed == "" || trimmed == "null" {
		*o = effectOutcome{}
		return nil
	}
	if trimmed[0] == '"' {
		var s string
		if err := json.Unmarshal(b, &s); err != nil {
			return err
		}
		o.Kind = s
		return nil
	}
	type alias effectOutcome
	var a alias
	if err := json.Unmarshal(b, &a); err != nil {
		return err
	}
	*o = effectOutcome(a)
	return nil
}

// failedOutcomes are the outcome kinds treated as a FAILED tool call. Only
// "completed" was observed in the Phase-0 capture, so the polarity is
// deliberately inverted from the obvious one: an UNRECOGNISED outcome kind
// leaves the call optimistically successful rather than inventing a
// failure. Recording a false failure is the worse error — it poisons the
// failure-correlation patterns — so a new outcome kind must be added here
// explicitly before it can mark a row failed.
var failedOutcomes = map[string]bool{
	"failed":    true,
	"error":     true,
	"cancelled": true,
	"canceled":  true,
	"rejected":  true,
	"timed_out": true,
	"timeout":   true,
}

// isZero reports whether a usage envelope carries nothing worth persisting,
// so an all-zero envelope never produces a phantom token row.
func (u *rawUsage) isZero() bool {
	if u == nil {
		return true
	}
	return u.InputTokens == 0 && u.OutputTokens == 0 &&
		u.CacheReadTokens == 0 && u.CacheWriteTokens == 0 &&
		u.CachedTokens == 0 && u.ReasoningTokens == 0
}

// tokenParts is the NET-token view derived from a usage envelope.
type tokenParts struct {
	inputNet  int64
	outputNet int64
	cacheRead int64
	cacheWrit int64
	reasoning int64
}

// tokenBundle converts a Muse usage envelope into the NET counts
// [models.TokenEvent] requires.
//
// Two subtractions, both mandatory (see the package doc for the evidence):
//
//   - input_tokens is GROSS and INCLUDES cache_read_tokens. Without the
//     subtraction the cached prefix is billed at BOTH the input rate and
//     the cache-read rate.
//   - output_tokens is GROSS and INCLUDES reasoning_tokens (the OpenAI
//     Responses convention this backend speaks). cost.ComputeBreakdown
//     bills Reasoning ADDITIVELY at the output rate on top of Output, so
//     Output must carry the NON-reasoning remainder — the identical
//     correction internal/adapter/codex applies.
//
// cached_tokens duplicated cache_read_tokens in every observed row; it is
// used only when cache_read_tokens is absent, never added to it.
func tokenBundle(u *rawUsage) tokenParts {
	if u == nil {
		return tokenParts{}
	}
	cacheRead := u.CacheReadTokens
	if cacheRead == 0 {
		cacheRead = u.CachedTokens
	}
	netIn := u.InputTokens - cacheRead
	if netIn < 0 {
		netIn = 0
	}
	netOut := u.OutputTokens - u.ReasoningTokens
	if netOut < 0 {
		netOut = 0
	}
	return tokenParts{
		inputNet:  netIn,
		outputNet: netOut,
		cacheRead: cacheRead,
		cacheWrit: u.CacheWriteTokens,
		reasoning: u.ReasoningTokens,
	}
}

// actionMap translates Muse tool names onto the normalized taxonomy. Keys
// are normalized by normalizeToolKey (lower-cased, `_`/`-`/space stripped)
// so snake_case (Muse's native spelling) and any camelCase or kebab-case
// variant resolve to the same row.
//
// GROUNDED — observed in the live Phase-0 capture: bash, read_file,
// write_file, edit_file.
//
// GROUNDED — named verbatim in the 0.1.0-R708.1 binary's own strings:
// web_search ("web_search failed with HTTP", "web_search mode"), web_fetch
// ("web_fetch failed:", "failed to build web_fetch HTTP client:"),
// read_skill (alongside "Read one available SKILL.md body as a tool
// result."), and `search` (from the workflow-child guardrail string "child
// tools may only include read_file, search, bash, or web_search"). `search`
// maps to search_text; whether it ALSO does filename discovery is not
// grounded, and the honest cost of being wrong is one row in the wrong
// search bucket, not a dropped event.
//
// Everything else is DEFENSIVE — the conventional agent vocabulary a
// 27-tool surface (model_request_configured reported active_tools#len=27,
// with the names themselves elided by the trace bound) is overwhelmingly
// likely to spell some of. An unrecognised name is never dropped: it
// becomes ActionUnknown with the raw name preserved on the event, and the
// parse records a one-shot warning so the gap is visible.
var actionMap = map[string]string{
	// grounded — live capture
	"bash":      models.ActionRunCommand,
	"readfile":  models.ActionReadFile,
	"writefile": models.ActionWriteFile,
	"editfile":  models.ActionEditFile,
	// grounded — live capture, sub-agent side. `submit_reminder_decision`
	// is the reminder observer's decision-submission tool: it records a
	// verdict back INTO the harness (`{decision,reason,confidence,priority,
	// advisory_text,next_step}`) and touches no workspace state, so
	// harness_call is the honest bucket rather than a fabricated
	// todo/ask-user shape. Found only by the §21 live re-parse — 13 calls
	// across the 15 child logs, and zero in the parent.
	"submitreminderdecision": models.ActionHarnessCall,
	// grounded — binary strings
	"websearch": models.ActionWebSearch,
	"webfetch":  models.ActionWebFetch,
	"readskill": models.ActionSkillInvoke,
	"search":    models.ActionSearchText,
	// defensive — read
	"read":          models.ActionReadFile,
	"viewfile":      models.ActionReadFile,
	"view":          models.ActionReadFile,
	"readmanyfiles": models.ActionReadFile,
	"listdirectory": models.ActionSearchFiles,
	"listdir":       models.ActionSearchFiles,
	"listfiles":     models.ActionSearchFiles,
	"glob":          models.ActionSearchFiles,
	"findfiles":     models.ActionSearchFiles,
	"searchfiles":   models.ActionSearchFiles,
	// defensive — write / edit
	"write":      models.ActionWriteFile,
	"createfile": models.ActionWriteFile,
	"edit":       models.ActionEditFile,
	"multiedit":  models.ActionEditFile,
	"applypatch": models.ActionEditFile,
	"patch":      models.ActionEditFile,
	"replace":    models.ActionEditFile,
	// defensive — shell
	"shell":       models.ActionRunCommand,
	"runcommand":  models.ActionRunCommand,
	"execcommand": models.ActionRunCommand,
	"exec":        models.ActionRunCommand,
	"execute":     models.ActionRunCommand,
	"terminal":    models.ActionRunCommand,
	// defensive — search
	"grep":       models.ActionSearchText,
	"searchtext": models.ActionSearchText,
	"ripgrep":    models.ActionSearchText,
	"codesearch": models.ActionSearchText,
	// defensive — web
	"fetch":    models.ActionWebFetch,
	"fetchurl": models.ActionWebFetch,
	"readurl":  models.ActionWebFetch,
	// defensive — agents / skills / planning
	"task":            models.ActionSpawnSubagent,
	"agent":           models.ActionSpawnSubagent,
	"subagent":        models.ActionSpawnSubagent,
	"spawnagent":      models.ActionSpawnSubagent,
	"delegate":        models.ActionSpawnSubagent,
	"skill":           models.ActionSkillInvoke,
	"useskill":        models.ActionSkillInvoke,
	"todowrite":       models.ActionTodoUpdate,
	"todo":            models.ActionTodoUpdate,
	"updateplan":      models.ActionTodoUpdate,
	"updatetodos":     models.ActionTodoUpdate,
	"askuser":         models.ActionAskUser,
	"askuserquestion": models.ActionAskUser,
}

// normalizeToolKey lower-cases a raw tool name and strips `_` / `-` /
// whitespace so snake_case, kebab-case and camelCase spellings of the same
// tool collapse to one lookup key.
func normalizeToolKey(name string) string {
	key := strings.ToLower(strings.TrimSpace(name))
	key = strings.ReplaceAll(key, "_", "")
	key = strings.ReplaceAll(key, "-", "")
	return strings.ReplaceAll(key, " ", "")
}

// mapToolName resolves a raw Muse tool name onto a normalized action type,
// reporting whether the name was recognised. An exact (normalized) match
// wins; an MCP-routed call (`mcp` prefix or a `__` separator) maps to
// ActionMCPCall; everything else falls back to ActionUnknown with
// recognised=false so the caller can warn once. The raw name is always
// preserved on ToolEvent.RawToolName.
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

// targetKeys are the tool-call argument keys tried, in order, when picking a
// representative target for an action. `path` (read_file / write_file /
// edit_file) and `command` (bash) are the GROUNDED ones — every observed
// call used exactly one of them; the rest cover the vocabulary the
// defensive actionMap rows anticipate.
var targetKeys = []string{
	"path", "file_path", "filePath", "absolute_path", "absolutePath",
	"file", "directory", "dir",
	"command", "cmd", "query", "pattern", "url", "skill", "prompt",
}

// decodeArgs unmarshals a tool call's `args`, which the provider serializes
// as a JSON STRING containing a JSON object. Returns nil when the value is
// empty or is not an object — callers fall back to the tool name.
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

// authoredBytes returns the byte length of the code the model authored in a
// write / edit / run action, read from the untruncated arguments. Zero for
// read-only or unrecognised actions.
//
// All three key names are GROUNDED against the live capture:
// write_file{path,content}, edit_file{path,find,replace}, bash{command,…}.
// The extra edit spellings are defensive aliases for the same slot.
func authoredBytes(actionType string, args map[string]any) int64 {
	str := func(k string) int64 {
		v, _ := args[k].(string)
		return int64(len(v))
	}
	switch actionType {
	case models.ActionWriteFile:
		return str("content")
	case models.ActionEditFile:
		return str("replace") + str("new_string") + str("new_text")
	case models.ActionRunCommand:
		return str("command")
	default:
		return 0
	}
}

// Unit boundaries for parseTimestamp. Muse writes microseconds
// (`recorded_at` is 16 digits); the ladder makes a future unit switch
// impossible to miss silently.
const (
	microsFloor = int64(1e15) // ≥ this many µs ⇒ year 2001+
	millisFloor = int64(1e12) // ≥ this many ms ⇒ year 2001+
)

// parseTimestamp decodes Muse's `recorded_at`. The observed unit is
// MICROSECONDS since the Unix epoch; the magnitude ladder also accepts
// millis and seconds so a schema that changes units degrades to a
// still-correct timestamp rather than silently landing in 1970. A
// non-positive value yields the zero time.
func parseTimestamp(v int64) time.Time {
	switch {
	case v <= 0:
		return time.Time{}
	case v >= microsFloor:
		return time.UnixMicro(v).UTC()
	case v >= millisFloor:
		return time.UnixMilli(v).UTC()
	default:
		return time.Unix(v, 0).UTC()
	}
}

// truncate caps a preview string to n bytes.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
