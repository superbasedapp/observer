package codex

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/scrub"
)

// Hook event names Codex emits. Codex uses CamelCase event names
// identical to Claude Code's; the registration writes ~/.codex/hooks.json
// with these as keys (see internal/hook/register.go::registerCodex).
const (
	HookEventSessionStart      = "SessionStart"
	HookEventUserPromptSubmit  = "UserPromptSubmit"
	HookEventPreToolUse        = "PreToolUse"
	HookEventPermissionRequest = "PermissionRequest"
	HookEventPostToolUse       = "PostToolUse"
	HookEventStop              = "Stop"
)

// rawHookPayload is the union of fields we read from any Codex hook
// payload. Per the codex 0.129.0 hooks reference at
// docs.codex.com/codex-hooks (mirrored locally in
// tmp/codex-hooks.md), the common envelope is:
//
//	session_id / transcript_path / cwd / hook_event_name / model
//
// Turn-scoped events (PreToolUse, PostToolUse, PermissionRequest,
// UserPromptSubmit, Stop) also carry `turn_id`. The codex docs
// don't list `permission_mode` in the common envelope but real
// captures (2026-05-11 maintainer dogfood) confirmed codex emits
// it on UserPromptSubmit fires at minimum — undocumented but
// real, so we keep parsing it.
//
// Unknown fields are tolerated; missing fields surface as zero
// values. Earlier versions of this struct accepted speculative
// effort.level and collaboration_mode.settings.reasoning_effort
// shapes; both were dropped after the 2026-05-11 capture-first
// procedure confirmed codex hook payloads never carry effort
// (effort lives only in the JSONL turn_context lines, see
// internal/adapter/codex/adapter.go).
type rawHookPayload struct {
	HookEventName  string `json:"hook_event_name"`
	SessionID      string `json:"session_id"`
	TurnID         string `json:"turn_id"`
	TranscriptPath string `json:"transcript_path"`
	Cwd            string `json:"cwd"`
	Model          string `json:"model"`
	PermissionMode string `json:"permission_mode"`
	Source         string `json:"source"`

	// Tool events:
	ToolName     string          `json:"tool_name"`
	ToolUseID    string          `json:"tool_use_id"`
	ToolInput    json.RawMessage `json:"tool_input"`
	ToolResponse string          `json:"tool_response"`

	// User-prompt event:
	Prompt string `json:"prompt"`

	// Stop event:
	StopHookActive       bool   `json:"stop_hook_active"`
	LastAssistantMessage string `json:"last_assistant_message"`
}

// hookEnvelopeMetadata builds an ActionMetadata from the codex hook
// envelope. Returns nil when no fields are set so callers can pass
// it directly to ev.Metadata. Migration 017.
//
// Codex hook payloads carry `permission_mode` (undocumented but
// real, verified 2026-05-11) and DO NOT carry an effort field. The
// JSONL adapter remains the authoritative source for effort_level
// — see internal/adapter/codex/adapter.go's withEffort wrapper.
func hookEnvelopeMetadata(raw rawHookPayload) *models.ActionMetadata {
	m := models.ActionMetadata{
		PermissionMode: raw.PermissionMode,
	}
	if m.IsZero() {
		return nil
	}
	return &m
}

// BuildHookEvent maps a Codex hook payload to a normalized ToolEvent
// when the event represents recordable activity. Returns (zero, false,
// nil) for events with nothing to record (every event currently emits
// a row except Stop, which carries only metadata that the proxy/JSONL
// watcher already captures more accurately).
//
// The caller passes the event name (from CLI or payload), the raw JSON
// body, and a scrubber. Errors indicate malformed input — the caller
// should log and continue (spec §17 row 1) since hooks must never
// break the host.
func BuildHookEvent(eventName string, body []byte, sc *scrub.Scrubber) (models.ToolEvent, bool, error) {
	var raw rawHookPayload
	if err := json.Unmarshal(body, &raw); err != nil {
		return models.ToolEvent{}, false, fmt.Errorf("codex.BuildHookEvent: parse: %w", err)
	}
	if eventName == "" {
		eventName = raw.HookEventName
	}
	if eventName == "" {
		return models.ToolEvent{}, false, errors.New("codex.BuildHookEvent: event name missing")
	}
	if raw.SessionID == "" {
		return models.ToolEvent{}, false, errors.New("codex.BuildHookEvent: session_id missing")
	}

	ts := time.Now().UTC()
	base := models.ToolEvent{
		SourceFile:    "codex:hook",
		SourceEventID: hookSourceEventID(raw, eventName),
		SessionID:     raw.SessionID,
		ProjectRoot:   raw.Cwd,
		Timestamp:     ts,
		Tool:          models.ToolCodex,
		Model:         raw.Model,
		MessageID:     raw.TurnID,
		Metadata:      hookEnvelopeMetadata(raw),
	}

	switch eventName {
	case HookEventSessionStart:
		base.ActionType = models.ActionSessionStart
		base.Target = raw.Source
		base.Success = true
		return base, true, nil

	case HookEventUserPromptSubmit:
		// User-prompt rows: ProjectRoot + SessionID + the prompt body.
		base.ActionType = models.ActionUserPrompt
		if raw.TurnID != "" {
			base.MessageID = "user:" + raw.TurnID
		}
		text := scrubText(sc, raw.Prompt)
		base.RawToolInput = text
		base.Target = previewLine(text, 120)
		base.Success = true
		return base, true, nil

	case HookEventPreToolUse:
		// PreToolUse rows are intentionally not emitted: codex's session
		// JSONL captures the same tool call with full input, and the
		// proxy captures token usage independently. The hook is
		// registered so codex still calls observer (cleaner ack path
		// than letting it fail), but no row is written.
		return models.ToolEvent{}, false, nil

	case HookEventPermissionRequest:
		// Permission flow visibility: not in any other source. Captures
		// which tool requested permission and what the input was, so
		// dashboards can correlate slow turns to permission prompts.
		base.ActionType = models.ActionUnknown
		base.RawToolName = raw.ToolName
		if len(raw.ToolInput) > 0 {
			// tool_input is JSON — scrubJSON (not scrubText/String)
			// so redaction can't corrupt the stored blob (MHC-4).
			base.RawToolInput = scrubJSON(sc, raw.ToolInput)
		}
		base.Target = "permission_request:" + raw.ToolName
		base.Success = true
		return base, true, nil

	case HookEventPostToolUse:
		// As with PreToolUse, the tool call is captured by the JSONL
		// watcher with richer detail. Hook is registered for parity
		// (so future schema additions are cheap) but emits no row.
		return models.ToolEvent{}, false, nil

	case HookEventStop:
		// Stop carries no data the JSONL watcher / proxy don't already
		// capture (model + token usage live on the response stream).
		// Kept registered for symmetry but no row.
		return models.ToolEvent{}, false, nil
	}

	// Unknown event: capture as ActionUnknown so it surfaces on the
	// dashboard rather than silently dropping. Helpful when Codex adds
	// new event names we haven't seen yet.
	base.ActionType = models.ActionUnknown
	base.Target = "codex_hook:" + eventName
	return base, true, nil
}

// hookSourceEventID returns a stable per-event identifier for dedup.
// Pairs (turn_id, event) for tool/turn events; falls back to (session_id,
// event, ts) for session-scoped events that lack a turn id.
func hookSourceEventID(raw rawHookPayload, eventName string) string {
	if raw.ToolUseID != "" {
		return raw.ToolUseID + ":" + eventName
	}
	if raw.TurnID != "" {
		return raw.TurnID + ":" + eventName
	}
	return raw.SessionID + ":" + eventName + ":" + time.Now().UTC().Format(time.RFC3339Nano)
}

func scrubText(sc *scrub.Scrubber, s string) string {
	if sc == nil || s == "" {
		return s
	}
	return sc.String(s)
}

// scrubJSON is scrubText's counterpart for a JSON-shaped payload (e.g.
// tool_input): it scrubs each string value in isolation and
// re-marshals via [scrub.Scrubber.RawJSON], which — unlike
// [scrub.Scrubber.String]'s line-oriented regexes — can never corrupt
// the JSON structure of what gets stored (MHC-4, docs/audits/
// codebase-audit-2026-09-16.md).
func scrubJSON(sc *scrub.Scrubber, raw []byte) string {
	if sc == nil || len(raw) == 0 {
		return string(raw)
	}
	return sc.RawJSON(raw)
}

func previewLine(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max]
}
