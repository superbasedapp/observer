package hermes

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/marmutapp/superbased-observer/internal/contentcap"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/scrub"
)

// SourceFileHook is the canonical SourceFile value for events produced
// by the hook path (the Python plugin bridge). Mirrors the convention
// the cursor adapter established with "cursor:hook".
const SourceFileHook = "hermes:hook"

// Event-name constants matching the wire shape the Python plugin
// bridge emits. The bridge maps Hermes's plugin-API hook names to
// these compact identifiers before firing `observer hook hermes
// <event>` as a subprocess.
//
// Token capture goes through EventAPIRequest (the post_api_request
// hook) rather than the originally-planned post_llm_call — confirmed
// against hermes_cli/hooks.py's _DEFAULT_PAYLOADS dict: post_llm_call
// carries no usage payload at all, while post_api_request carries
// usage{input_tokens, output_tokens} plus provider / base_url /
// api_mode / api_duration. See docs/hermes-adapter-plan.md §17.1.F.
const (
	EventToolCall      = "tool_call"      // mapped from post_tool_call
	EventSessionStart  = "session_start"  // mapped from on_session_start
	EventSessionEnd    = "session_end"    // mapped from on_session_end
	EventAPIRequest    = "api_request"    // mapped from post_api_request
	EventSubagentStart = "subagent_start" // mapped from subagent_start
	EventSubagentStop  = "subagent_stop"  // mapped from subagent_stop
)

// hookPayload is the union of fields the Python bridge sends. Unknown
// fields are tolerated; missing fields surface as zero values. The
// shape derives from:
//   - docs/hermes-adapter-plan.md §11.1 (the originally-planned wire
//     shape)
//   - testdata/hermes/plugin-api-source.txt _DEFAULT_PAYLOADS dict
//     (the source-of-truth shape every Hermes-shipping plugin sees)
//   - §17.1.F (the deltas the reality check captured: post_api_request
//     over post_llm_call; args= over arguments=; usage as a sub-dict)
type hookPayload struct {
	Event      string          `json:"event"`
	SessionID  string          `json:"session_id"`
	TaskID     string          `json:"task_id"`
	ToolCallID string          `json:"tool_call_id"`
	ToolName   string          `json:"tool_name"`
	Args       json.RawMessage `json:"args"`
	Result     string          `json:"result"`
	DurationMs int64           `json:"duration_ms"`
	CWD        string          `json:"cwd"`
	Timestamp  float64         `json:"timestamp"`
	Model      string          `json:"model"`
	Source     string          `json:"source"`
	StartedAt  float64         `json:"started_at"`
	EndedAt    float64         `json:"ended_at"`
	// PID/PPID ride only on session_start (additive since the plugin's
	// pid-emitting revision). PID is the long-lived Hermes agent
	// process — the socket opener — which observer's hook receiver
	// seeds into session_pid_bridge for direct process attribution.
	// PPID (the agent's parent shell) is diagnostic only and never
	// seeded. Consumed in cmd/observer/hook.go::seedHermesSessionPidbridge,
	// not by BuildToolEvent/BuildTokenEvent — kept here so this struct
	// stays the single source of truth for the plugin wire shape.
	PID                    int    `json:"pid"`
	PPID                   int    `json:"ppid"`
	EndReason              string `json:"end_reason"`
	TelemetrySchemaVersion string `json:"telemetry_schema_version"`

	// post_api_request fields (token capture).
	Provider     string         `json:"provider"`
	BaseURL      string         `json:"base_url"`
	APIMode      string         `json:"api_mode"`
	APICallCount int64          `json:"api_call_count"`
	APIDuration  float64        `json:"api_duration"`
	FinishReason string         `json:"finish_reason"`
	MessageCount int64          `json:"message_count"`
	Usage        hookUsageBlock `json:"usage"`

	// subagent_start / subagent_stop fields. ChildRole rides on both
	// events per testdata/hermes/plugin-api-source.txt's
	// _DEFAULT_PAYLOADS["subagent_stop"] sample (child_role: None) —
	// captured here so a future bridge revision that populates it on
	// either event needs no struct change.
	ParentSessionID string `json:"parent_session_id"`
	ChildRole       string `json:"child_role"`
	ChildSummary    string `json:"child_summary"`
	ChildStatus     string `json:"child_status"`
}

// hookUsageBlock is the post_api_request usage sub-dict. Field names
// follow the post_api_request payload shape (input_tokens /
// output_tokens / cache_read_tokens / cache_write_tokens /
// reasoning_tokens), matching what Hermes's invoke_hook surfaces to
// plugins from the provider's response envelope.
type hookUsageBlock struct {
	InputTokens         int64 `json:"input_tokens"`
	OutputTokens        int64 `json:"output_tokens"`
	CacheReadTokens     int64 `json:"cache_read_tokens"`
	CacheWriteTokens    int64 `json:"cache_write_tokens"`
	CacheCreationTokens int64 `json:"cache_creation_tokens"`
	ReasoningTokens     int64 `json:"reasoning_tokens"`
}

// BuildToolEvent maps a hermes hook payload to a normalized ToolEvent.
// Returns (event, true, nil) when the payload represents a recordable
// action; (zero, false, nil) when there's nothing to record (e.g. the
// api_request event, which is handled separately by BuildTokenEvent).
//
// Errors indicate malformed input — the caller logs and continues
// (hooks must never break the host tool per spec P1).
//
// SourceEventID composition mirrors the SQLite path's deterministic
// dedup scheme:
//   - tool_call:      <session_id>:<tool_call_id>
//   - session_start:  <session_id>:session_start
//   - session_end:    <session_id>:session_end
//   - subagent_start: <session_id>:subagent_start:<timestamp_ms>
//   - subagent_stop:  <session_id>:subagent_stop:<child_summary_hash>
//
// EventSubagentStart is a real entry in hermes_cli/plugins.py's
// VALID_HOOKS (testdata/hermes/plugin-api-source.txt line 147,
// alongside subagent_stop) but the bundled plugin bridge shipped at
// internal/hook/hermesplugin/__init__.py currently registers only
// subagent_stop — so no live Hermes install fires this event today.
// The case below is forward-compatible groundwork: once the bridge
// registers subagent_start (out of this package's scope), rows land
// correctly with no adapter change. See docs/hermes-adapter.md.
//
// Combined with SourceFile="hermes:hook" these are unique across
// re-fires and across the SQLite path (which uses the absolute DB
// path as SourceFile). A turn captured by both paths would produce
// two rows that don't collide on the UNIQUE index — which is why the
// SQLite path consults the SessionHookChecker and suppresses its
// tool_call + token emissions for hook-covered sessions (the H1
// audit finding; see buildEvents in parse.go).
func BuildToolEvent(eventName string, body []byte, sc *scrub.Scrubber) (models.ToolEvent, bool, error) {
	var raw hookPayload
	if err := json.Unmarshal(body, &raw); err != nil {
		return models.ToolEvent{}, false, fmt.Errorf("hermes.BuildToolEvent: parse: %w", err)
	}
	// CLI-supplied event name wins; some payloads omit the "event"
	// field (the body-only shape).
	if eventName == "" {
		eventName = raw.Event
	}
	if eventName == "" {
		return models.ToolEvent{}, false, errors.New("hermes.BuildToolEvent: event name missing")
	}
	if raw.SessionID == "" {
		return models.ToolEvent{}, false, errors.New("hermes.BuildToolEvent: session_id missing")
	}

	switch eventName {
	case EventToolCall:
		return buildHookToolCall(raw, sc), true, nil
	case EventSessionStart:
		return buildHookSessionStart(raw), true, nil
	case EventSessionEnd:
		return buildHookSessionEnd(raw), true, nil
	case EventSubagentStart:
		return buildHookSubagentStart(raw), true, nil
	case EventSubagentStop:
		return buildHookSubagentStop(raw, sc), true, nil
	case EventAPIRequest:
		// Token-bearing event — handled by BuildTokenEvent. No
		// ToolEvent for these (the model output itself isn't a
		// tool call).
		return models.ToolEvent{}, false, nil
	default:
		// Unknown event names produce a no-op rather than an error
		// so forward-compatible plugins (or older plugin versions)
		// don't crash the hook handler.
		return models.ToolEvent{}, false, nil
	}
}

// BuildTokenEvent maps a hermes post_api_request hook payload to a
// normalized TokenEvent. Returns (zero, false, nil) when the event
// isn't EventAPIRequest or when the usage block is empty (all-zero).
//
// Source=TokenSourceHook, Reliability=ReliabilityApproximate. Per
// §17.1.F: post_api_request carries provider-reported usage from the
// API envelope, which is approximate-but-trustworthy for the major
// providers. Tier 1 accuracy requires the proxy path (deferred).
func BuildTokenEvent(eventName string, body []byte) (models.TokenEvent, bool, error) {
	var raw hookPayload
	if err := json.Unmarshal(body, &raw); err != nil {
		return models.TokenEvent{}, false, fmt.Errorf("hermes.BuildTokenEvent: parse: %w", err)
	}
	if eventName == "" {
		eventName = raw.Event
	}
	if eventName != EventAPIRequest {
		return models.TokenEvent{}, false, nil
	}
	if raw.SessionID == "" {
		return models.TokenEvent{}, false, errors.New("hermes.BuildTokenEvent: session_id missing")
	}
	if raw.Usage.InputTokens == 0 && raw.Usage.OutputTokens == 0 &&
		raw.Usage.CacheReadTokens == 0 && raw.Usage.CacheWriteTokens == 0 &&
		raw.Usage.CacheCreationTokens == 0 && raw.Usage.ReasoningTokens == 0 {
		// No usable token information.
		return models.TokenEvent{}, false, nil
	}

	// CacheCreation: Hermes's wire field name is cache_write_tokens
	// historically, but newer payloads carry cache_creation_tokens.
	// Prefer the newer name when present; fall back to the legacy
	// one. They never both fire today.
	cacheCreation := raw.Usage.CacheCreationTokens
	if cacheCreation == 0 {
		cacheCreation = raw.Usage.CacheWriteTokens
	}

	ev := models.TokenEvent{
		SourceFile:          SourceFileHook,
		SourceEventID:       fmt.Sprintf("%s:api:%d", raw.SessionID, raw.APICallCount),
		SessionID:           raw.SessionID,
		ProjectRoot:         raw.CWD,
		Timestamp:           unixFloatToTime(raw.Timestamp),
		Tool:                models.ToolHermes,
		Model:               stripProviderPrefix(raw.Model),
		InputTokens:         raw.Usage.InputTokens,
		OutputTokens:        raw.Usage.OutputTokens,
		CacheReadTokens:     raw.Usage.CacheReadTokens,
		CacheCreationTokens: cacheCreation,
		ReasoningTokens:     raw.Usage.ReasoningTokens,
		Source:              models.TokenSourceHook,
		Reliability:         models.ReliabilityApproximate,
	}
	// Fall back to a synthetic source event id when api_call_count
	// is missing (older bridge versions or non-CLI surfaces).
	if raw.APICallCount == 0 {
		ev.SourceEventID = fmt.Sprintf("%s:api:t%d", raw.SessionID, int64(raw.Timestamp*1000))
	}
	return ev, true, nil
}

func buildHookToolCall(raw hookPayload, sc *scrub.Scrubber) models.ToolEvent {
	callKey := raw.ToolCallID
	if callKey == "" {
		// Synthetic from timestamp when the bridge omits tool_call_id
		// — shouldn't happen with the current plugin but defensive.
		callKey = fmt.Sprintf("t%d", int64(raw.Timestamp*1000))
	}

	// args is a JSON-shaped sub-document from the bridge (unlike the
	// SQLite path's arguments-as-JSON-string). Serialise back to a
	// canonical string for RawToolInput.
	rawArgs := ""
	if len(raw.Args) > 0 {
		rawArgs = string(raw.Args)
	}
	scrubbedInput := rawArgs
	if sc != nil {
		scrubbedInput = sc.RawJSON(raw.Args)
	}
	scrubbedInput = contentcap.Cap(scrubbedInput, contentcap.DefaultMaxBytes)

	target := extractTarget(raw.ToolName, rawArgs)
	if sc != nil {
		target = sc.String(target)
	}

	evt := models.ToolEvent{
		SourceFile:    SourceFileHook,
		SourceEventID: raw.SessionID + ":" + callKey,
		SessionID:     raw.SessionID,
		ProjectRoot:   raw.CWD,
		Timestamp:     unixFloatToTime(raw.Timestamp),
		Tool:          models.ToolHermes,
		Model:         stripProviderPrefix(raw.Model),
		ActionType:    normalizeToolName(raw.ToolName),
		Target:        target,
		Success:       true,
		DurationMs:    raw.DurationMs,
		RawToolName:   raw.ToolName,
		RawToolInput:  scrubbedInput,
		MessageID:     callKey,
	}

	// Pair the result inline — hooks get the tool result in the same
	// payload (the bridge waits until post_tool_call fires after the
	// tool returns).
	if raw.Result != "" {
		success, errMsg, output := parseToolResult(raw.Result)
		evt.Success = success
		evt.ErrorMessage = errMsg
		if sc != nil {
			// parseToolResult's fallback path (no output/content key
			// found) hands back the WHOLE raw JSON result body, so
			// scrub with RawJSON — not String's line-oriented regexes,
			// which can corrupt JSON structure (MHC-4). RawJSON falls
			// back to the same behavior String had when output is
			// plain text (the extracted-field case), so this is safe
			// either way.
			output = sc.RawJSON([]byte(output))
		}
		evt.ToolOutput = contentcap.Cap(output, contentcap.DefaultMaxBytes)
	}
	return evt
}

func buildHookSessionStart(raw hookPayload) models.ToolEvent {
	ts := unixFloatToTime(raw.StartedAt)
	if ts.IsZero() {
		ts = unixFloatToTime(raw.Timestamp)
	}
	return models.ToolEvent{
		SourceFile:    SourceFileHook,
		SourceEventID: raw.SessionID + ":session_start",
		SessionID:     raw.SessionID,
		ProjectRoot:   raw.CWD,
		Timestamp:     ts,
		Tool:          models.ToolHermes,
		Model:         stripProviderPrefix(raw.Model),
		ActionType:    models.ActionSessionStart,
		Target:        raw.Source,
		Success:       true,
		RawToolName:   "on_session_start",
	}
}

func buildHookSessionEnd(raw hookPayload) models.ToolEvent {
	ts := unixFloatToTime(raw.EndedAt)
	if ts.IsZero() {
		ts = unixFloatToTime(raw.Timestamp)
	}
	return models.ToolEvent{
		SourceFile:    SourceFileHook,
		SourceEventID: raw.SessionID + ":session_end",
		SessionID:     raw.SessionID,
		ProjectRoot:   raw.CWD,
		Timestamp:     ts,
		Tool:          models.ToolHermes,
		Model:         stripProviderPrefix(raw.Model),
		ActionType:    models.ActionSessionEnd,
		Target:        raw.EndReason,
		Success:       true,
		RawToolName:   "on_session_end",
	}
}

// buildHookSubagentStart maps a subagent_start hook payload to a
// normalized ToolEvent, mirroring buildHookSubagentStop. IsSidechain
// is set true — this row marks the child sub-agent's OWN runtime
// bracket starting, distinct from the parent's tool_use that spawned
// it (ActionSpawnSubagent, which stays IsSidechain=false since it
// happens on the parent thread). See models.ActionSubagentStart doc
// comment and the cursor adapter's EventSubagentStart handling for
// the same start/stop bracket convention.
//
// No live payload sample exists for this event yet (absent from
// testdata/hermes/plugin-api-source.txt's _DEFAULT_PAYLOADS, unlike
// subagent_stop) since the bundled bridge doesn't fire it — see the
// BuildToolEvent doc comment. SourceEventID falls back to a
// timestamp-derived key (no child_summary equivalent exists at start
// time to hash).
func buildHookSubagentStart(raw hookPayload) models.ToolEvent {
	return models.ToolEvent{
		SourceFile:    SourceFileHook,
		SourceEventID: fmt.Sprintf("%s:subagent_start:%d", raw.SessionID, int64(raw.Timestamp*1000)),
		SessionID:     raw.SessionID,
		ProjectRoot:   raw.CWD,
		Timestamp:     unixFloatToTime(raw.Timestamp),
		Tool:          models.ToolHermes,
		Model:         stripProviderPrefix(raw.Model),
		ActionType:    models.ActionSubagentStart,
		Target:        raw.ChildRole,
		Success:       true,
		RawToolName:   "subagent_start",
		IsSidechain:   true,
	}
}

func buildHookSubagentStop(raw hookPayload, sc *scrub.Scrubber) models.ToolEvent {
	summary := raw.ChildSummary
	if sc != nil {
		summary = sc.String(summary)
	}
	return models.ToolEvent{
		SourceFile:    SourceFileHook,
		SourceEventID: fmt.Sprintf("%s:subagent_stop:%s", raw.SessionID, shortHash(raw.ChildSummary)),
		SessionID:     raw.SessionID,
		ProjectRoot:   raw.CWD,
		Timestamp:     unixFloatToTime(raw.Timestamp),
		Tool:          models.ToolHermes,
		ActionType:    models.ActionSubagentStop,
		Target:        raw.ChildStatus,
		Success:       raw.ChildStatus == "completed",
		DurationMs:    raw.DurationMs,
		RawToolName:   "subagent_stop",
		RawToolInput:  contentcap.Cap(summary, contentcap.DefaultMaxBytes),
		IsSidechain:   true,
	}
}

// shortHash returns the first 12 hex chars of sha256(s). Used in
// SourceEventID composition where a content-derived discriminator
// avoids collisions across same-shape events within a session.
func shortHash(s string) string {
	if s == "" {
		return "empty"
	}
	// Local copy to avoid pulling crypto/sha256 into the top-level
	// imports just for one helper; inline-equivalent below.
	return hashHex12(s)
}
