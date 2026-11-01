package vtcode

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"time"
)

// envelope is one line of a workspace `events.jsonl`: a schema-versioned
// wrapper around one harness event (VT Code's exec-events `ThreadEvent`,
// schema_version "0.18.0" on 0.180.2).
type envelope struct {
	SchemaVersion string    `json:"schema_version"`
	Event         eventBody `json:"event"`
}

// eventBody is the union of every event shape the adapter consumes,
// discriminated by Type. Unused fields stay zero.
//
// Consumed types: thread.started, turn.started, item.started /
// item.updated / item.completed, turn.completed / turn.failed /
// turn.blocked, thread.completed (session end: stop reason, provider
// cost; its usage is the sum of the per-turn usages and is NOT re-read),
// interjected (only its image_count, carried onto the next user prompt —
// the text is raw composer input incl. slash commands, the real prompt
// is turn.started's goal) and permission.resolved (the approval decision).
type eventBody struct {
	Type string `json:"type"`

	// thread.started / thread.completed
	ThreadID string `json:"thread_id"`

	// thread.completed
	Subtype      string   `json:"subtype"`
	OutcomeCode  string   `json:"outcome_code"`
	StopReason   string   `json:"stop_reason"`
	TotalCostUSD *float64 `json:"total_cost_usd"`

	// interjected
	ImageCount int `json:"image_count"`

	// permission.requested / permission.resolved
	ToolName string `json:"tool_name"`
	Decision string `json:"decision"`
	WaitMs   int64  `json:"wait_ms"`

	// turn.started
	Context *turnContext `json:"context"`

	// item.*
	Item *item `json:"item"`

	// turn.completed / turn.failed / turn.blocked
	CompletedAt string `json:"completed_at"`
	Message     string `json:"message"`
	Usage       *usage `json:"usage"`
}

// turnContext is the context block carried by turn.started and by every
// item. actor_id is the session id for the primary agent; origin is
// "user" for a submitted prompt and "continuation" for a harness-driven
// follow-up turn.
type turnContext struct {
	TaskID    string `json:"task_id"`
	TurnID    string `json:"turn_id"`
	ActorID   string `json:"actor_id"`
	Origin    string `json:"origin"`
	Timestamp string `json:"timestamp"`
	Goal      string `json:"goal"`
	Activity  string `json:"activity"`
}

// item is one thread item. Type is one of agent_message, tool_invocation,
// tool_output, reasoning (harness diagnosis text, not model reasoning) or
// harness (snapshot / latency / blocked bookkeeping).
type item struct {
	Context    turnContext     `json:"context"`
	ID         string          `json:"id"`
	Type       string          `json:"type"`
	Text       string          `json:"text"`
	ToolName   string          `json:"tool_name"`
	Arguments  json.RawMessage `json:"arguments"`
	ToolCallID string          `json:"tool_call_id"`
	Status     string          `json:"status"`
	Outcome    string          `json:"outcome"`
	Output     string          `json:"output"`
	ExitCode   *int            `json:"exit_code"`
}

// usage is the per-turn token envelope on turn.completed / turn.failed /
// turn.blocked. It is the SUM over every LLM request in the turn (verified
// against the per-request `prompt_cache_metrics` trajectory records,
// which add up to it exactly). input_tokens is GROSS: it includes
// cached_input_tokens (OpenAI/OpenRouter prompt_tokens convention —
// trajectory records show input_tokens == prompt_tokens and
// total_tokens == prompt_tokens + completion_tokens).
type usage struct {
	InputTokens         int64 `json:"input_tokens"`
	CachedInputTokens   int64 `json:"cached_input_tokens"`
	CacheCreationTokens int64 `json:"cache_creation_tokens"`
	OutputTokens        int64 `json:"output_tokens"`
}

// isZero reports whether every counter is zero (an aborted turn that made
// no request).
func (u *usage) isZero() bool {
	return u == nil || (u.InputTokens == 0 && u.CachedInputTokens == 0 &&
		u.CacheCreationTokens == 0 && u.OutputTokens == 0)
}

// netInput returns the NET non-cached input: input_tokens minus the
// cached subset, floored at zero.
func (u *usage) netInput() int64 {
	if n := u.InputTokens - u.CachedInputTokens; n > 0 {
		return n
	}
	return 0
}

// manifest is the sibling `manifest.json` of a workspace session dir.
// created_at is the session-start timestamp (thread.started carries
// none); status ("completed" once the session ended) gates process
// seeding so a finished session's pid is never offered for attribution.
type manifest struct {
	SessionID string `json:"session_id"`
	CreatedAt string `json:"created_at"`
	Status    string `json:"status"`
}

// parseTime parses VT Code's RFC 3339 timestamps (nanosecond precision,
// `+00:00` offset). The zero time is returned for an empty or unparseable
// value.
func parseTime(s string) time.Time {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}
	}
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return time.Time{}
	}
	return t.UTC()
}

// hashID returns a deterministic 16-hex-char digest of raw, used only for
// records with no native id.
func hashID(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])[:16]
}

// truncate caps a preview string to n bytes.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// firstNonEmpty returns the first argument that is not blank.
func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}
