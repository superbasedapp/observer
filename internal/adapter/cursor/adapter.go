// Package cursor implements the hook-driven capture path for Cursor.
// Cursor has no structured native session logs — every action is observed
// via a registered hook fired before/after the user's tool calls.
//
// The package exposes a stateless mapper, BuildEvent, that turns a single
// Cursor hook JSON payload into a normalized models.ToolEvent. The hook CLI
// wraps this with config loading, DB insert, and the approval response.
//
// Coverage gap (audit C2): Cursor's public hook surface emits events for
// shell commands, MCP executions, file edits, and prompt submission — but
// there is no event for file reads. As a result, observer's freshness
// tracking and read-redundancy detection systematically undercount Cursor
// activity relative to Claude Code (which captures every Read tool_use).
// Cursor would need to add a beforeFileRead hook in their CLI for this to
// close; in the meantime cross-tool comparisons should treat Cursor as
// having an "edits-only" view of file activity.
//
// See spec §4.3.
package cursor

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/contentcap"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
	"github.com/marmutapp/superbased-observer/internal/scrub"
)

// Hook event names that Cursor passes via `--<event>` flags or the
// `hook_event_name` payload field. Stable strings — used in event IDs.
//
// Tier 1 (the original 5) covers shell, MCP, file edits, prompt submission,
// and stop. Tier 2 (v1.4.45) adds file reads, tool failures,
// session-lifecycle markers, sub-agent fan-out, and pre-compact dispatch.
// Tier 3 (v1.4.45) adds the universal preToolUse + the symmetric
// postToolUse / afterShellExecution / afterMCPExecution observers —
// preToolUse emits rows only for tools the per-tool before* hooks don't
// cover (Glob, Grep, Search, semanticsearch, WriteFile, etc.) so the
// long-tail closes; postToolUse / afterShellExecution / afterMCPExecution
// are registered for parity but emit no rows (the richer "update the
// before* row's Success/ErrorMessage/DurationMs" path needs a new store
// method, deferred). Tier 4 (v1.6.18) adds afterAgentThought and
// afterAgentResponse — see below.
//
// Tier 4 (v1.6.18) — afterAgentThought + afterAgentResponse. The v1.4.45
// docstring rationalized away these two events as "fires on every
// text/thought delta, low marginal value because the JSONL transcript
// walker delivers the same content on stop." Both halves of that
// reasoning were wrong for the builds measured in 2026-05:
//   - On the Cursor 3.4.20 install captured in the 2026-05-21 audit,
//     no agent-transcripts/<conv>.jsonl materialised for the hook's
//     transcript_path, so BuildStopTranscriptEvents had nothing to
//     walk. Do NOT read that as "Cursor stopped writing transcripts":
//     the walker is very much alive on Cursor 3.14.27, where the
//     `.cursor/projects/<slug>/agent-transcripts/<conv>/<conv>.jsonl`
//     files ARE written and are the ONLY thing capturing Windows-IDE
//     Cursor activity today (grounded 2026-08-07, see
//     docs/audits/cursor-windows-capture-diagnosis-2026-08-07.md §1
//     Path A / §2.8). What those files still do NOT carry is usage:
//     every line is `{"message","role"}` — no `usage`, no `model` —
//     which is why tokens remain hook-only. Treat transcript
//     presence as version- and surface-dependent, never as settled.
//   - Captured live payloads show finalized blocks (single text, single
//     duration_ms per thought/response), not per-token deltas. The
//     overhead concern was wrong for the builds measured.
//
// So afterAgentThought is now CAPTURED (it was skipped entirely
// pre-v1.6.18) — though as of the 2026-07-31 B3 convergence it mints no
// row of its own: its finalized thinking-text is stashed and threaded
// onto the next recordable event's PrecedingReasoning (see pending.go
// and the EventAfterAgentThought case below). afterAgentResponse emits a
// cursor.assistant_response row carrying the final assistant prose. Per-
// turn token counts are still sourced from the `stop` event (single
// source of truth — afterAgentResponse's input_tokens/output_tokens
// fields are intentionally not consumed here to avoid double-counting).
// Tab events (beforeTabFileRead, afterTabFileEdit) are still out of
// scope: tab uses a different session model from agent chat with no
// shared correlation keys.
const (
	EventBeforeShellCommand = "beforeShellExecution"
	EventBeforeMCPExecution = "beforeMCPExecution"
	EventAfterFileEdit      = "afterFileEdit"
	EventBeforeSubmitPrompt = "beforeSubmitPrompt"
	EventStop               = "stop"

	// Tier 2 events (v1.4.45):
	EventBeforeReadFile     = "beforeReadFile"
	EventPostToolUseFailure = "postToolUseFailure"
	EventSessionStart       = "sessionStart"
	EventSessionEnd         = "sessionEnd"
	EventSubagentStart      = "subagentStart"
	EventSubagentStop       = "subagentStop"
	EventPreCompact         = "preCompact"

	// Tier 3 events (v1.4.45). preToolUse fills the long-tail-tool gap;
	// the other three are registered but emit no rows (paired-after
	// metadata enrichment deferred until update-in-place lands).
	EventPreToolUse          = "preToolUse"
	EventPostToolUse         = "postToolUse"
	EventAfterShellExecution = "afterShellExecution"
	EventAfterMCPExecution   = "afterMCPExecution"

	// Tier 4 events (v1.6.18) — finalized assistant prose + thinking
	// per turn. See the package-level commentary above for why these
	// were skipped pre-v1.6.18 and what changed.
	EventAfterAgentThought  = "afterAgentThought"
	EventAfterAgentResponse = "afterAgentResponse"
)

// rawHookPayload is the union of fields we read out of any Cursor hook
// payload. Unknown fields are tolerated; missing fields surface as zero
// values. workspace_roots can be a list of strings (older builds) or a list
// of objects with .path (newer builds), so we handle both.
type rawHookPayload struct {
	HookEventName  string          `json:"hook_event_name"`
	ConversationID string          `json:"conversation_id"`
	GenerationID   string          `json:"generation_id"`
	WorkspaceRoots json.RawMessage `json:"workspace_roots"`
	Model          string          `json:"model"`
	Status         string          `json:"status"`
	InputTokens    int64           `json:"input_tokens"`
	OutputTokens   int64           `json:"output_tokens"`
	CacheRead      int64           `json:"cache_read_tokens"`
	CacheWrite     int64           `json:"cache_write_tokens"`
	TranscriptPath string          `json:"transcript_path"`

	// Per-event fields:
	Command  string          `json:"command"`     // beforeShellCommand
	FilePath string          `json:"file_path"`   // afterFileEdit, beforeReadFile
	Prompt   string          `json:"prompt"`      // beforeSubmitPrompt
	ToolName string          `json:"tool_name"`   // beforeMCPExecution, postToolUseFailure
	Server   string          `json:"server_name"` // beforeMCPExecution
	Input    json.RawMessage `json:"input"`       // beforeMCPExecution

	// Tier 2 fields (v1.4.45). Cursor docs don't enumerate every payload
	// field per event; we accept the conventionally-named variants we've
	// observed in the docs reference + sibling tools' payloads, falling
	// back to zero values when missing.
	ToolUseID    string `json:"tool_use_id"`   // postToolUseFailure
	ErrorMessage string `json:"error"`         // postToolUseFailure
	FailureType  string `json:"failure_type"`  // postToolUseFailure
	DurationMs   int64  `json:"duration_ms"`   // postToolUseFailure
	Source       string `json:"source"`        // sessionStart  ("startup"|"resume"|...)
	Reason       string `json:"reason"`        // sessionEnd    ("clear"|"resume"|...)
	AgentID      string `json:"agent_id"`      // subagentStart, subagentStop
	AgentType    string `json:"agent_type"`    // subagentStart, subagentStop
	SubagentID   string `json:"subagent_id"`   // subagentStart, subagentStop (alt name)
	MessageCount int64  `json:"message_count"` // preCompact
	ByteSize     int64  `json:"byte_size"`     // preCompact (best-effort)
	Trigger      string `json:"trigger"`       // preCompact ("auto"|"manual")

	// Tier 3 fields (v1.4.45). preToolUse / postToolUse use tool_input
	// (distinct from beforeMCPExecution's flat `input`) per the cursor
	// docs reference — the universal hooks wrap input under a tool_input
	// key while the per-tool hooks expose individual fields.
	ToolInput json.RawMessage `json:"tool_input"` // preToolUse, postToolUse

	// After-event outcome fields. afterShellExecution,
	// afterMCPExecution, postToolUse all carry the result of the
	// preceding tool call.
	//
	// Field-name choices verified empirically from
	// /tmp/cursor-hook-capture/ on Cursor 3.4.20 (2026-05-21 audit,
	// docs/audits/cursor-audit-2026-05-21.md F2/F3):
	//   - duration: float in SECONDS (NOT duration_ms). 6.332 means
	//     6,332 ms — multiply by 1000 at consumption time. The
	//     long-misnamed DurationMs struct tag below is retained for
	//     events that genuinely emit `duration_ms` (afterAgentThought,
	//     postToolUseFailure per separate empirical pinning).
	//   - tool_output: the body Cursor's tool produced (stdout, file
	//     content, etc.) — typically 70-100 chars per Read but can be
	//     large for shell tools. Surfaced via OutcomeUpdate.Output and
	//     indexed into action_excerpts FTS5 when the cursor hook has
	//     an Indexer wired.
	//   - success / exit_code: still inferred conventionally; empirical
	//     captures didn't include either field, so the conservative
	//     "no field ⇒ derive from error/output" path at deriveAfterSuccess
	//     still applies.
	Success      *bool   `json:"success"`     // after*: explicit success flag (preferred)
	ExitCode     *int    `json:"exit_code"`   // afterShellExecution: 0 ⇒ success
	Output       string  `json:"output"`      // after*: legacy fallback output body (used for derived success)
	ToolOutput   string  `json:"tool_output"` // postToolUse: tool result body (audit F3)
	DurationSecs float64 `json:"duration"`    // postToolUse: duration in seconds (audit F2)
	Content      string  `json:"content"`     // beforeReadFile: file body Cursor just read (audit F4)

	// Tier 4 (v1.6.18) — afterAgentThought / afterAgentResponse. Both
	// events carry the finalized prose for that thought/response in a
	// single `text` field (not per-token deltas, despite the v1.4.45
	// docstring's now-obsolete claim). afterAgentThought additionally
	// carries duration_ms (the rendered "Thought for Ns" timer);
	// afterAgentResponse carries the per-turn token counts (same
	// fields as `stop`, deliberately not consumed here to keep `stop`
	// as the single source of token truth and avoid double-counting).
	Text string `json:"text"` // afterAgentThought, afterAgentResponse
}

// BuildEvent maps a Cursor hook payload to a normalized ToolEvent. The
// caller passes the hook event name (from CLI or payload), the raw JSON
// body, and a scrubber. Returns (event, true) when the payload represents
// a recordable action; (zero, false) when there's nothing to record (the
// `stop` event, which is handled separately as token usage).
//
// Errors indicate malformed input — the caller should log and continue
// (spec §17 row 1) since hooks must never break the host tool.
func BuildEvent(eventName string, body []byte, sc *scrub.Scrubber) (models.ToolEvent, bool, error) {
	var raw rawHookPayload
	if err := json.Unmarshal(body, &raw); err != nil {
		return models.ToolEvent{}, false, fmt.Errorf("cursor.BuildEvent: parse: %w", err)
	}
	// CLI-supplied event name wins; some payloads don't include
	// hook_event_name explicitly.
	if eventName == "" {
		eventName = raw.HookEventName
	}
	if eventName == "" {
		return models.ToolEvent{}, false, errors.New("cursor.BuildEvent: event name missing")
	}
	if eventName == EventStop {
		// Nothing to record — Cursor doesn't pass tool detail on stop.
		return models.ToolEvent{}, false, nil
	}

	projectRoot := decodeWorkspaceRoot(raw.WorkspaceRoots)
	if raw.ConversationID == "" {
		return models.ToolEvent{}, false, errors.New("cursor.BuildEvent: conversation_id missing")
	}

	now := time.Now().UTC()
	ev := models.ToolEvent{
		SourceFile:    "cursor:hook",
		SourceEventID: cursorEventID(raw.GenerationID, eventName, raw),
		SessionID:     raw.ConversationID,
		MessageID:     raw.GenerationID,
		ProjectRoot:   projectRoot,
		Timestamp:     now,
		Model:         raw.Model,
		Tool:          models.ToolCursor,
		Success:       true,
		RawToolName:   eventName,
	}

	switch eventName {
	case EventBeforeShellCommand:
		ev.ActionType = models.ActionRunCommand
		ev.Target = raw.Command
		if sc != nil {
			ev.RawToolInput = sc.String(raw.Command)
		} else {
			ev.RawToolInput = raw.Command
		}
	case EventAfterFileEdit:
		ev.ActionType = models.ActionEditFile
		ev.Target = raw.FilePath
		if sc != nil {
			ev.RawToolInput = sc.String(raw.FilePath)
		} else {
			ev.RawToolInput = raw.FilePath
		}
	case EventBeforeSubmitPrompt:
		ev.ActionType = models.ActionUserPrompt
		ev.MessageID = "user:" + raw.GenerationID
		stripped := stripUserQueryWrapper(raw.Prompt)
		preview := stripped
		if len(preview) > 200 {
			preview = preview[:200]
		}
		ev.Target = preview
		ev.PrecedingReasoning = preview
	case EventBeforeMCPExecution:
		ev.ActionType = models.ActionMCPCall
		ev.Target = strings.TrimSpace(raw.Server + ":" + raw.ToolName)
		if sc != nil {
			ev.RawToolInput = sc.RawJSON(raw.Input)
		} else {
			ev.RawToolInput = string(raw.Input)
		}
	case EventBeforeReadFile:
		// Closes audit C2: Cursor's only file-read signal pre-v1.4.45 was
		// the after-the-fact transcript replay on stop. Live capture of
		// reads finally lets freshness/redundancy detection see the same
		// activity claudecode does.
		//
		// v1.6.23 audit F4: also capture `content` (the file body cursor
		// just read) into ToolOutput so the dashboard's "tool output"
		// surface for cursor Read mirrors what claudecode shows for its
		// Read tool. Scrubbed + capped at 4000 chars matching the
		// afterAgentThought / transcript walker convention. When the
		// hook handler has an Indexer wired the body lands in
		// action_excerpts FTS5 too.
		ev.ActionType = models.ActionReadFile
		ev.Target = raw.FilePath
		if sc != nil {
			ev.RawToolInput = sc.String(raw.FilePath)
		} else {
			ev.RawToolInput = raw.FilePath
		}
		if raw.Content != "" {
			body := raw.Content
			if sc != nil {
				body = sc.String(body)
			}
			ev.ToolOutput = contentcap.Cap(body, contentcap.DefaultMaxBytes)
		}
	case EventPostToolUseFailure:
		ev.ActionType = models.ActionToolFailure
		ev.Success = false
		ev.Target = raw.ToolName
		ev.RawToolName = raw.FailureType
		ev.ErrorMessage = raw.ErrorMessage
		ev.DurationMs = raw.DurationMs
		if len(raw.Input) > 0 {
			if sc != nil {
				ev.RawToolInput = sc.RawJSON(raw.Input)
			} else {
				ev.RawToolInput = string(raw.Input)
			}
		}
	case EventSessionStart:
		ev.ActionType = models.ActionSessionStart
		ev.Target = raw.Source
		ev.Success = true
	case EventSessionEnd:
		ev.ActionType = models.ActionSessionEnd
		ev.Target = raw.Reason
		ev.Success = true
	case EventSubagentStart:
		ev.ActionType = models.ActionSubagentStart
		ev.Target = raw.AgentType
		ev.IsSidechain = true
		// Prefer agent_id; fall back to subagent_id when the docs-shape
		// alternate is in use. MessageID identifies the subagent run.
		if raw.AgentID != "" {
			ev.MessageID = raw.AgentID
		} else if raw.SubagentID != "" {
			ev.MessageID = raw.SubagentID
		}
		ev.Success = true
	case EventSubagentStop:
		ev.ActionType = models.ActionSubagentStop
		ev.Target = raw.AgentType
		ev.IsSidechain = true
		if raw.AgentID != "" {
			ev.MessageID = raw.AgentID
		} else if raw.SubagentID != "" {
			ev.MessageID = raw.SubagentID
		}
		ev.Success = true
	case EventPreCompact:
		ev.ActionType = models.ActionContextCompacted
		ev.Target = raw.Trigger
		ev.DurationMs = raw.DurationMs
		ev.Success = true
	case EventPreToolUse:
		// Universal-tool hook. Suppress rows for tools the per-tool
		// before* hooks already cover (Shell, MCP, FileEdit, ReadFile,
		// Subagent) so the actions table doesn't double-count. Emit
		// rows only for the long-tail tools — Glob, Grep, Search,
		// semanticsearch, WriteFile/CreateFile, plus any future tools
		// the per-tool hooks don't have a category for.
		if coveredByPerToolHook(raw.ToolName) {
			return models.ToolEvent{}, false, nil
		}
		ev.ActionType = cursorTranscriptActionType(raw.ToolName)
		ev.Target = cursorTranscriptTarget(raw.ToolName, raw.ToolInput)
		ev.RawToolName = raw.ToolName
		if len(raw.ToolInput) > 0 {
			if sc != nil {
				ev.RawToolInput = sc.RawJSON(raw.ToolInput)
			} else {
				ev.RawToolInput = string(raw.ToolInput)
			}
		}
	case EventPostToolUse, EventAfterShellExecution, EventAfterMCPExecution:
		// After-events emit no NEW row; instead the dispatcher calls
		// cursor.BuildAfterOutcome → store.UpdateActionOutcome to
		// enrich the matching before-event row's success /
		// error_message / duration_ms in place. Failures are also
		// captured separately via postToolUseFailure (Tier 2) which
		// writes a dedicated tool_failure row — both surfaces carry
		// useful detail (the before-row gets the typed-payload
		// outcome; the failure row carries the structured failure
		// type).
		return models.ToolEvent{}, false, nil
	case EventAfterAgentThought:
		// Finalized assistant thinking block. text is the full prose
		// (no per-token deltas — on the builds captured live, 3.4.20
		// and 3.9.16, Cursor emits one event per finalized thought,
		// not one per fragment; unverified on 3.14.x).
		//
		// REASONING SEMANTICS (B3 convergence, 2026-07-31): this event
		// mints NO row. A thought is not an action; the row it used to
		// emit was a phantom that polluted every action aggregate and
		// carried the text nowhere but its own self-preview (see
		// docs/plans/b3-reasoning-convergence-plan-2026-07-31.md §1).
		// Instead the scrubbed 200-char preview — byte-for-byte the
		// string that used to land in that row's preceding_reasoning
		// column, cap unchanged — is stashed for the conversation and
		// threaded onto the NEXT recordable event of that conversation
		// (see pending.go for the consumed-once / last-wins / user-turn
		// -discard semantics and why cursor needs an on-disk carrier).
		// duration_ms is dropped with the row: it described the thought,
		// and no successor row can honestly claim it.
		//
		// Empty-text events (rare but observed in capture dumps) carry
		// nothing to stash.
		text := strings.TrimSpace(raw.Text)
		if text == "" {
			return models.ToolEvent{}, false, nil
		}
		preview := text
		if sc != nil {
			preview = sc.String(preview)
		}
		if len(preview) > 200 {
			preview = preview[:200]
		}
		stashReasoning(raw.ConversationID, preview)
		return models.ToolEvent{}, false, nil
	case EventAfterAgentResponse:
		// Finalized assistant response prose. Mirrors the transcript
		// walker's cursor.assistant_text emit so a session ingested
		// via the hook path produces the same row shape as one
		// ingested via the (now-unwritten) JSONL walker.
		// input_tokens / output_tokens / cache_read_tokens /
		// cache_write_tokens fields are present on the payload but
		// NOT consumed here — the `stop` event remains the single
		// source of token truth so we don't double-count per
		// generation.
		text := strings.TrimSpace(raw.Text)
		if text == "" {
			return models.ToolEvent{}, false, nil
		}
		ev.ActionType = models.ActionAssistantMessage
		ev.RawToolName = "cursor.assistant_response"
		preview := text
		if sc != nil {
			preview = sc.String(preview)
		}
		body := preview
		if len(preview) > 200 {
			preview = preview[:200]
		}
		ev.Target = preview
		ev.PrecedingReasoning = preview
		ev.ToolOutput = contentcap.Cap(body, contentcap.DefaultMaxBytes)
	default:
		ev.ActionType = models.ActionUnknown
		ev.RawToolInput = string(body)
	}

	// Thread the pending thought (see pending.go) onto this row. The
	// consumer set is a TABLE, not a name ladder: only the events that
	// are genuinely the model's next act can claim a thought. A
	// lifecycle marker (sessionEnd, preCompact, subagentStop) that
	// happened to fire next must not eat it — it would both mis-attribute
	// the reasoning and rob the real successor.
	if reasoningConsumers[eventName] {
		if pending := takeReasoning(raw.ConversationID, ev.SourceEventID); pending != "" {
			// A real thought beats the self-preview afterAgentResponse
			// otherwise writes here (a row echoing its own body into its
			// reasoning column tells a reader nothing).
			ev.PrecedingReasoning = pending
		}
	}
	if eventName == EventBeforeSubmitPrompt {
		// A new user turn ends the previous one — an unclaimed thought
		// from it must not leak forward (grok's emitUserPrompt discard).
		clearReasoning(raw.ConversationID)
	}

	return ev, true, nil
}

// reasoningConsumers is the set of hook events that may claim a pending
// afterAgentThought as their PrecedingReasoning: the model's own next
// act — a tool call it decided on, or the prose it produced. Lifecycle
// and bookkeeping events (sessionStart/End, preCompact, subagent*,
// postToolUseFailure) are deliberately absent; see BuildEvent.
var reasoningConsumers = map[string]bool{
	EventBeforeShellCommand: true,
	EventBeforeMCPExecution: true,
	EventBeforeReadFile:     true,
	EventAfterFileEdit:      true,
	EventPreToolUse:         true,
	EventAfterAgentResponse: true,
}

// OutcomeUpdate is the paired-after-event enrichment payload for the
// matching before-event row in the actions table. Returned by
// BuildAfterOutcome and applied via store.UpdateActionOutcome.
//
// SourceFile + SourceEventID together identify the row to update;
// they are computed using the BEFORE-event's slug and the same hash
// inputs cursorEventID would have used for the matching before-row,
// so the update lands on the correct row even though the after-event
// rides a different hook binding.
type OutcomeUpdate struct {
	SourceFile    string
	SourceEventID string
	Success       bool
	ErrorMessage  string
	DurationMs    int64
	// Output carries the tool's response body (postToolUse.tool_output
	// per the v1.6.23 audit F3 fix). Non-empty Output triggers an
	// action_excerpts FTS5 insert from store.UpdateActionOutcome when
	// the Store has an Indexer attached; empty Output leaves the
	// existing excerpt (if any) untouched.
	Output string
	// ToolName / Target pass through to the indexer so the FTS5 row
	// carries the same tool_name/target columns that batch-Ingest's
	// indexOutputs path would have written. tool_name is the cursor
	// tool that ran (Read, Grep, etc.); target is the file path or
	// command — derived from raw.ToolName/raw.ToolInput so the values
	// match the before-event row's columns.
	ToolName string
	Target   string
}

// BuildAfterOutcome maps a Cursor after-event payload to an
// OutcomeUpdate that the dispatcher applies via
// store.UpdateActionOutcome to enrich the matching before-event row.
//
// Returns (zero, false, nil) for events that aren't paired-after
// observers (any event other than afterShellExecution /
// afterMCPExecution / postToolUse). Returns (zero, false, err) for
// malformed JSON. Returns (update, true, nil) when the payload
// resolves to a valid pairing target — even when the before-row
// hasn't landed yet (the UPDATE will simply touch zero rows).
func BuildAfterOutcome(eventName string, body []byte) (OutcomeUpdate, bool, error) {
	switch eventName {
	case EventAfterShellExecution, EventAfterMCPExecution, EventPostToolUse:
	default:
		return OutcomeUpdate{}, false, nil
	}
	var raw rawHookPayload
	if err := json.Unmarshal(body, &raw); err != nil {
		return OutcomeUpdate{}, false, fmt.Errorf("cursor.BuildAfterOutcome: parse: %w", err)
	}
	if raw.ConversationID == "" {
		return OutcomeUpdate{}, false, errors.New("cursor.BuildAfterOutcome: conversation_id missing")
	}
	beforeName, ok := beforeEventNameFor(eventName, raw)
	if !ok {
		// postToolUse for a covered tool (Shell/MCP/etc) maps to its
		// per-tool before-event; if the tool isn't in coverage and
		// has no tool_use_id we can't pair, so skip.
		return OutcomeUpdate{}, false, nil
	}
	id := cursorEventID(raw.GenerationID, beforeName, raw)
	// Duration: postToolUse sends `duration` (float seconds — audit F2);
	// afterAgentThought / postToolUseFailure use the conventional
	// `duration_ms` (int64). Prefer the seconds variant when present
	// (multiplying to ms); fall back to the legacy field for events
	// that emit it.
	durationMs := raw.DurationMs
	if raw.DurationSecs > 0 {
		durationMs = int64(raw.DurationSecs * 1000)
	}
	return OutcomeUpdate{
		SourceFile:    "cursor:hook",
		SourceEventID: id,
		Success:       deriveAfterSuccess(raw),
		ErrorMessage:  raw.ErrorMessage,
		DurationMs:    durationMs,
		Output:        raw.ToolOutput,
		ToolName:      raw.ToolName,
		Target:        cursorTranscriptTarget(raw.ToolName, raw.ToolInput),
	}, true, nil
}

// beforeEventNameFor maps an after-event name to the before-event
// name it pairs with, so cursorEventID computes the same id for both
// halves. Returns (name, true) on success; (zero, false) when no
// pairing applies (postToolUse for a covered tool already mapped to
// its per-tool before-hook, or the universal preToolUse for a
// long-tail tool — both pair on the universal preToolUse slug).
func beforeEventNameFor(after string, raw rawHookPayload) (string, bool) {
	switch after {
	case EventAfterShellExecution:
		return EventBeforeShellCommand, true
	case EventAfterMCPExecution:
		return EventBeforeMCPExecution, true
	case EventPostToolUse:
		// postToolUse pairs with whichever before-event the tool's
		// preToolUse fires under. If the tool is covered by a
		// per-tool before-hook (Shell, MCP, FileEdit, ReadFile,
		// Subagent), pair on that hook's slug — preToolUse itself
		// emitted no row for those tools (coveredByPerToolHook
		// suppression). Otherwise it's a long-tail tool that
		// preToolUse DID write a row for; pair on the universal
		// preToolUse slug.
		switch strings.ToLower(raw.ToolName) {
		case "shell", "bash", "command":
			return EventBeforeShellCommand, true
		case "call_mcp_tool", "mcp", "mcptool":
			return EventBeforeMCPExecution, true
		case "applypatch", "editfile", "strreplace", "edit":
			// afterFileEdit is the per-tool match; we don't enrich
			// these via postToolUse because cursor delivers the
			// success-only afterFileEdit hook for them already.
			return "", false
		case "read", "readfile", "cat", "readlints":
			return EventBeforeReadFile, true
		case "subagent", "agent":
			// subagentStart/Stop are lifecycle events, not paired
			// success/error around a single tool call. Skip pairing.
			return "", false
		default:
			return EventPreToolUse, true
		}
	}
	return "", false
}

// deriveAfterSuccess collapses the cursor docs' three-way
// success-or-not signal (explicit `success` bool, `exit_code` for
// shell, presence of `error` string) into a single boolean. The
// after-event payload defines outcome whether or not the host
// accepted/rejected the before-event hook.
func deriveAfterSuccess(raw rawHookPayload) bool {
	if raw.Success != nil {
		return *raw.Success
	}
	if raw.ExitCode != nil {
		return *raw.ExitCode == 0
	}
	// Fall back to error-string presence: an after-event that
	// reports a non-empty error is a failure even when the docs'
	// dedicated success flag is missing.
	return raw.ErrorMessage == "" && raw.FailureType == ""
}

// BuildStopTokenEvent maps Cursor's `stop` hook payload to a normalized
// TokenEvent. Retained for Cursor builds that fire `stop`; on the
// builds captured live (3.4.20, 3.9.16) per-generation usage arrived
// on afterAgentResponse instead (see BuildResponseTokenEvent). Both
// share buildTokenEvent and dedup against each other, so registering
// BOTH is the safe posture on an unmeasured build — which 3.14.x
// currently is (docs/audits/cursor-windows-capture-diagnosis-2026-08-07.md
// §2.6, probe P4).
func BuildStopTokenEvent(body []byte) (models.TokenEvent, bool, error) {
	return buildTokenEvent(body)
}

// BuildResponseTokenEvent maps Cursor's `afterAgentResponse` payload to a
// normalized TokenEvent. On the builds captured live (3.4.20 in the
// 2026-05-21 audit, 3.9.16 in the last cursor-stop-debug.jsonl lines)
// `stop` was not observed to fire, while afterAgentResponse carried
// the IDENTICAL per-generation usage fields
// (input_tokens / output_tokens / cache_read_tokens / cache_write_tokens,
// model, generation_id — see TestBuildEvent_AfterAgentResponse), which
// is why this is the PRIMARY cursor token path.
//
// 2026-08-22 LIVE AUDIT (C1 close-out): cursor 3.15.19 stop payloads now
// carry NO usage fields at all — the hook fires, session_id is present,
// and the payload keys are conversation/model/status/transcript_path
// only (15 `no_usage_fields` forensic rows since Aug 19). No other local
// surface carries per-generation tokens either (transcripts, store.db
// blobs, ai-tracking.db all checked). The usage-field extraction below is
// correct and stays ready; the gap is upstream. Do not treat either hook
// as a working token source on 3.15.x.
//
// It shares the (source_file, source_event_id) identity with
// the stop path via buildTokenEvent, so a generation seen on BOTH events
// dedups to a single token_usage row (UNIQUE(source_file, source_event_id)
// + the (tool, session_id, message_id) guard) instead of double-counting.
func BuildResponseTokenEvent(body []byte) (models.TokenEvent, bool, error) {
	return buildTokenEvent(body)
}

// buildTokenEvent is the shared per-generation usage extractor for the
// stop / afterAgentResponse hook payloads (identical usage shape).
// Returns (zero, false, nil) when every usage field is zero — an
// observationally empty turn worth no row.
func buildTokenEvent(body []byte) (models.TokenEvent, bool, error) {
	var raw rawHookPayload
	if err := json.Unmarshal(body, &raw); err != nil {
		return models.TokenEvent{}, false, fmt.Errorf("cursor.buildTokenEvent: parse: %w", err)
	}
	if raw.ConversationID == "" {
		return models.TokenEvent{}, false, errors.New("cursor.buildTokenEvent: conversation_id missing")
	}
	if raw.GenerationID == "" {
		return models.TokenEvent{}, false, errors.New("cursor.buildTokenEvent: generation_id missing")
	}
	if raw.Model == "" {
		return models.TokenEvent{}, false, errors.New("cursor.buildTokenEvent: model missing")
	}
	if raw.InputTokens == 0 && raw.OutputTokens == 0 && raw.CacheRead == 0 && raw.CacheWrite == 0 {
		return models.TokenEvent{}, false, nil
	}

	// Net non-cached input. Cursor's usage payload uses
	// Anthropic-style field NAMES (cache_read_tokens / cache_write_
	// tokens) but populates input_tokens with the OpenAI-style GROSS
	// total — the full prompt count INCLUDING the cached portion.
	// Verified empirically (session 93bcba3c, 2026-05-24): a trivial
	// 2-turn "say hello" conversation reported input_tokens=11615
	// with cache_read_tokens=11490 (99%); 11615 brand-new uncached
	// tokens is impossible for that conversation, so input_tokens is
	// the total prompt and the 11490 cached tokens are a subset.
	// The cost engine's TokenBundle.Input contract is NET non-cached
	// (see internal/intelligence/cost/engine.go), so net at emit time
	// to stop the cached portion being billed at BOTH the full input
	// rate AND the cache_read rate. Clamp at 0 against any anomaly.
	netInput := raw.InputTokens - raw.CacheRead
	if netInput < 0 {
		netInput = 0
	}

	return models.TokenEvent{
		SourceFile:          "cursor:hook",
		SourceEventID:       raw.GenerationID + ":" + EventStop,
		SessionID:           raw.ConversationID,
		MessageID:           raw.GenerationID,
		ProjectRoot:         decodeWorkspaceRoot(raw.WorkspaceRoots),
		Timestamp:           time.Now().UTC(),
		Tool:                models.ToolCursor,
		Model:               raw.Model,
		InputTokens:         netInput,
		OutputTokens:        raw.OutputTokens,
		CacheReadTokens:     raw.CacheRead,
		CacheCreationTokens: raw.CacheWrite,
		Source:              models.TokenSourceHook,
		Reliability:         models.ReliabilityAccurate,
	}, true, nil
}

type transcriptLine struct {
	Role    string `json:"role"`
	Message struct {
		Content []transcriptPart `json:"content"`
	} `json:"message"`
}

type transcriptPart struct {
	Type  string          `json:"type"`
	Text  string          `json:"text"`
	Name  string          `json:"name"`
	Input json.RawMessage `json:"input"`
}

type transcriptAssistantLine struct {
	LineNumber int
	Parts      []transcriptPart
}

// transcriptUserLine captures the user-role line that opens a turn.
// LineNumber is the 1-indexed file offset; Text is the concatenation of
// all text parts (cursor user lines exclusively contain text parts in
// observed corpora). Stored here so the backfill path can emit a
// user_prompt action without re-walking the file.
type transcriptUserLine struct {
	LineNumber int
	Text       string
}

type transcriptTurn struct {
	User      transcriptUserLine
	Assistant []transcriptAssistantLine
}

func BuildStopTranscriptEvents(body []byte, sc *scrub.Scrubber, ts time.Time) ([]models.ToolEvent, error) {
	var raw rawHookPayload
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("cursor.BuildStopTranscriptEvents: parse: %w", err)
	}
	if raw.TranscriptPath == "" || raw.ConversationID == "" || raw.GenerationID == "" {
		return nil, nil
	}
	// Cursor on Windows sends transcript_path as a Windows-style path
	// (e.g. `C:\Users\<u>\.cursor\projects\...\.jsonl`). Running in WSL
	// we need /mnt/c/... to actually open the file. The translator is
	// a no-op when the path is already native (Linux/macOS observer +
	// host-native Cursor) or when running on Windows directly.
	transcriptFS := crossmount.TranslateForeignPath(raw.TranscriptPath)
	turns, err := parseTranscriptTurns(transcriptFS)
	if err != nil {
		return nil, fmt.Errorf("cursor.BuildStopTranscriptEvents: parse transcript: %w", err)
	}
	if len(turns) == 0 {
		return nil, nil
	}
	return buildTranscriptToolEvents(
		turns[len(turns)-1],
		raw.ConversationID,
		decodeWorkspaceRoot(raw.WorkspaceRoots),
		raw.GenerationID,
		transcriptFS,
		ts,
		sc,
	), nil
}

func ParseTranscriptTurns(path string) ([]transcriptTurn, error) { return parseTranscriptTurns(path) }

func parseTranscriptTurns(path string) ([]transcriptTurn, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), 16*1024*1024)

	var turns []transcriptTurn
	var current *transcriptTurn
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var tl transcriptLine
		if err := json.Unmarshal([]byte(line), &tl); err != nil {
			continue
		}
		switch tl.Role {
		case "user":
			var text strings.Builder
			for _, part := range tl.Message.Content {
				if part.Type == "text" && part.Text != "" {
					if text.Len() > 0 {
						text.WriteString("\n")
					}
					text.WriteString(part.Text)
				}
			}
			turns = append(turns, transcriptTurn{
				User: transcriptUserLine{LineNumber: lineNo, Text: text.String()},
			})
			current = &turns[len(turns)-1]
		case "assistant":
			if current == nil {
				turns = append(turns, transcriptTurn{})
				current = &turns[len(turns)-1]
			}
			current.Assistant = append(current.Assistant, transcriptAssistantLine{
				LineNumber: lineNo,
				Parts:      tl.Message.Content,
			})
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return turns, nil
}

// BuildTranscriptToolEvents emits the assistant-text and tool_use rows
// for one transcript turn. Every content-bearing field (Target,
// RawToolInput, PrecedingReasoning, ToolOutput) is scrubbed; a nil sc
// is replaced with a default [scrub.New] scrubber rather than skipping
// the pass, so no caller can land raw transcript text in the DB.
func BuildTranscriptToolEvents(
	turn transcriptTurn,
	sessionID, projectRoot, generationID, sourceFile string,
	ts time.Time,
	sc *scrub.Scrubber,
) []models.ToolEvent {
	return buildTranscriptToolEvents(turn, sessionID, projectRoot, generationID, sourceFile, ts, sc)
}

func buildTranscriptToolEvents(
	turn transcriptTurn,
	sessionID, projectRoot, generationID, sourceFile string,
	ts time.Time,
	sc *scrub.Scrubber,
) []models.ToolEvent {
	// Scrubbing is mandatory on every content-bearing field: a nil
	// scrubber is treated as "caller forgot", never as "opt out", so no
	// call site (live hook or backfill) can land transcript text in the
	// DB unredacted.
	if sc == nil {
		sc = scrub.New()
	}
	var out []models.ToolEvent
	var todoStoreChecked, todoStoreExists bool
	for _, line := range turn.Assistant {
		reasoning := ""
		for partIdx, part := range line.Parts {
			switch part.Type {
			case "text":
				txt := strings.TrimSpace(part.Text)
				if txt != "" {
					// The carried reasoning is scrubbed prose: it is
					// copied into the NEXT tool row's
					// PrecedingReasoning, so it must never hold the
					// raw text.
					reasoning = sc.String(txt)
					// Emit a standalone cursor.assistant_text row matching the
					// cross-adapter convention. The body is sourced from the
					// transcript JSONL the stop-hook handler walks, not from
					// the per-delta `afterAgentResponse` hook (which fires
					// per-token and is intentionally not registered).
					preview := reasoning
					if len(preview) > 200 {
						preview = preview[:200]
					}
					body := contentcap.Cap(reasoning, contentcap.DefaultMaxBytes)
					out = append(out, models.ToolEvent{
						SourceFile:         sourceFile,
						SourceEventID:      fmt.Sprintf("%s:transcript:L%d:P%d:asst:%s", generationID, line.LineNumber, partIdx, shortHash(txt)),
						SessionID:          sessionID,
						MessageID:          generationID,
						ProjectRoot:        projectRoot,
						Timestamp:          ts,
						Tool:               models.ToolCursor,
						ActionType:         models.ActionAssistantMessage,
						Target:             preview,
						Success:            true,
						PrecedingReasoning: preview,
						RawToolName:        "cursor.assistant_text",
						ToolOutput:         body,
					})
				}
			case "tool_use":
				if strings.EqualFold(part.Name, "TodoWrite") {
					if !todoStoreChecked {
						todoStoreExists = cursorTodoStoreExists(sourceFile, sessionID)
						todoStoreChecked = true
					}
					if todoStoreExists {
						continue
					}
				}
				rawInput := sc.RawJSON(part.Input)
				out = append(out, models.ToolEvent{
					SourceFile:         sourceFile,
					SourceEventID:      fmt.Sprintf("%s:transcript:L%d:P%d:%s", generationID, line.LineNumber, partIdx, shortHash(part.Name+":"+string(part.Input))),
					SessionID:          sessionID,
					MessageID:          generationID,
					ProjectRoot:        projectRoot,
					Timestamp:          ts,
					Tool:               models.ToolCursor,
					ActionType:         cursorTranscriptActionType(part.Name),
					Target:             sc.String(cursorTranscriptTarget(part.Name, part.Input)),
					Success:            true,
					PrecedingReasoning: reasoning,
					RawToolName:        part.Name,
					RawToolInput:       rawInput,
				})
			}
		}
	}
	return out
}

// BuildTranscriptUserPromptEvent emits an ActionUserPrompt event for a
// transcript turn's opening user line. Returns (zero, false) when the
// user line carried no text after stripping. The stripUserQueryWrapper
// helper unwraps the `<user_query>...</user_query>` markers Cursor's
// agent runtime injects around the user's prompt so the DB carries the
// user-typed text rather than the wrapped envelope.
//
// generationID is the cursor `generation_id` for this turn (sourced
// from token_usage rows in the backfill path); MessageID on the row
// becomes "user:" + generationID, matching the live hook path's
// MessageID convention so dashboard joins land cleanly.
//
// Both Target and RawToolInput carry the SCRUBBED prompt; a nil sc is
// replaced with a default [scrub.New] scrubber rather than skipping
// the pass.
func BuildTranscriptUserPromptEvent(
	turn transcriptTurn,
	sessionID, projectRoot, generationID, sourceFile string,
	ts time.Time,
	sc *scrub.Scrubber,
) (models.ToolEvent, bool) {
	// A nil scrubber means the caller forgot, never "ship raw": user
	// prompts are the single most secret-dense field Cursor gives us.
	if sc == nil {
		sc = scrub.New()
	}
	stripped := stripUserQueryWrapper(turn.User.Text)
	stripped = strings.TrimSpace(stripped)
	if stripped == "" {
		return models.ToolEvent{}, false
	}
	rawInput := sc.String(stripped)
	preview := rawInput
	if len(preview) > 200 {
		preview = preview[:200]
	}
	return models.ToolEvent{
		SourceFile:         sourceFile,
		SourceEventID:      fmt.Sprintf("%s:transcript:L%d:user:%s", generationID, turn.User.LineNumber, shortHash(stripped)),
		SessionID:          sessionID,
		MessageID:          "user:" + generationID,
		ProjectRoot:        projectRoot,
		Timestamp:          ts,
		Tool:               models.ToolCursor,
		ActionType:         models.ActionUserPrompt,
		Target:             preview,
		Success:            true,
		PrecedingReasoning: preview,
		RawToolName:        "user_message",
		RawToolInput:       rawInput,
	}, true
}

// stripUserQueryWrapper removes a leading `<user_query>` and trailing
// `</user_query>` envelope when both are present (Cursor's agent
// runtime wraps user prompts in this XML before passing them to the
// model). Returns the original string when only one side is present
// or neither — never strips partial wrappers, since that risks
// damaging real user content that happens to mention the tag name.
func stripUserQueryWrapper(s string) string {
	trimmed := strings.TrimSpace(s)
	const open = "<user_query>"
	const close = "</user_query>"
	if !strings.HasPrefix(trimmed, open) || !strings.HasSuffix(trimmed, close) {
		return s
	}
	inner := trimmed[len(open) : len(trimmed)-len(close)]
	return strings.TrimSpace(inner)
}

// coveredByPerToolHook reports whether a tool name fired through the
// universal preToolUse/postToolUse path is already captured by one of
// the per-tool before* hooks (beforeShellExecution, beforeMCPExecution,
// afterFileEdit, beforeReadFile, subagentStart). When true, the
// universal hook should drop the event to avoid double-counting in the
// actions table. Names match cursor's transcript-walker convention
// (lowercased internally).
//
// Dedup-decision pin (handover menu #2, 2026-05-10): we keep the
// per-tool + universal-long-tail-fill model rather than going
// universal-only. Per-tool hooks deliver typed payloads
// (`command`, `server_name`+`tool_name`, `file_path`) that beat
// re-extracting the same fields from `tool_input json.RawMessage`,
// the dedup logic here is small (5 cases), and the after-event
// update-in-place wired in the same batch (Store.UpdateActionOutcome)
// makes the before/after pair enrich a single row rather than emit
// duplicates. See PROGRESS.md "Unreleased — Cursor pre/postToolUse
// dedup decision" for the full rationale.
func coveredByPerToolHook(toolName string) bool {
	switch strings.ToLower(toolName) {
	case "shell", "bash", "command":
		// beforeShellExecution covers.
		return true
	case "call_mcp_tool", "mcp", "mcptool":
		// beforeMCPExecution covers.
		return true
	case "applypatch", "editfile", "strreplace", "edit":
		// afterFileEdit covers (though the timing differs — afterFileEdit
		// fires after success; preToolUse fires before. Trade-off: lose
		// pre-edit visibility for these tools, gain dedup. Accept it for
		// now; revisit if pre-edit gating becomes important).
		return true
	case "read", "readfile", "cat", "readlints":
		// beforeReadFile covers.
		return true
	case "subagent", "agent":
		// subagentStart covers.
		return true
	default:
		return false
	}
}

func cursorTranscriptActionType(name string) string {
	switch strings.ToLower(name) {
	case "glob", "findfiles":
		return models.ActionSearchFiles
	case "grep", "search", "searchfiles":
		return models.ActionSearchText
	case "read", "readfile", "cat", "readlints":
		// "read" is the live-cursor 2026-05 transcript tool name; the
		// older live-hook payload uses readfile. readlints reads
		// diagnostic info for a file — semantically a read, not a
		// separate category, so all three fold into ActionReadFile.
		return models.ActionReadFile
	case "shell", "bash", "command",
		"powershell", "pwsh", "cmd", "cmdexe":
		return models.ActionRunCommand
	case "semanticsearch":
		// Cursor's semantic codebase search; conceptually grep over an
		// embedding index, fold into ActionSearchText.
		return models.ActionSearchText
	case "todowrite":
		return models.ActionTodoUpdate
	case "applypatch", "editfile", "strreplace":
		// strreplace is the cursor in-place string-edit primitive
		// (analogue of claudecode's Edit tool).
		return models.ActionEditFile
	case "writefile", "createfile":
		return models.ActionWriteFile
	case "subagent", "agent":
		return models.ActionSpawnSubagent
	case "call_mcp_tool":
		return models.ActionMCPCall
	case "await":
		// `Await` is a control-flow primitive the agent uses to wait on
		// a long-running tool call. It carries no file/command target,
		// so we don't lift it to a known category — keep as Unknown
		// rather than mis-classifying. Distinguished from genuinely
		// unmapped tools by the RawToolName preserving "Await".
		return models.ActionUnknown
	default:
		return models.ActionUnknown
	}
}

func cursorTranscriptTarget(name string, raw json.RawMessage) string {
	var input map[string]any
	if err := json.Unmarshal(raw, &input); err != nil {
		return ""
	}
	switch strings.ToLower(name) {
	case "glob", "findfiles":
		return firstString(input, "glob_pattern", "pattern", "query")
	case "grep", "search", "searchfiles":
		return firstString(input, "pattern", "query")
	case "read", "readfile", "writefile", "createfile", "editfile", "applypatch", "readlints", "strreplace":
		return firstString(input, "path", "file_path", "target_file")
	case "shell", "bash", "command":
		return firstString(input, "command")
	case "semanticsearch":
		return firstString(input, "query", "pattern")
	case "subagent", "agent":
		return firstString(input, "description", "prompt")
	case "call_mcp_tool":
		// MCP calls carry server + tool name in input. Format match
		// what BuildEvent does for live-hook MCP rows.
		server := firstString(input, "server_name", "server")
		tool := firstString(input, "tool_name", "tool")
		switch {
		case server != "" && tool != "":
			return server + ":" + tool
		case tool != "":
			return tool
		default:
			return server
		}
	default:
		return firstString(input, "path", "pattern", "query", "command")
	}
}

func firstString(m map[string]any, keys ...string) string {
	for _, key := range keys {
		v, ok := m[key]
		if !ok {
			continue
		}
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

// decodeWorkspaceRoot pulls the first workspace path out of either shape.
// Returns "" when the payload doesn't include any roots — the store layer
// will skip events without a project root (spec §20 fallback to cwd doesn't
// apply here because the hook process isn't in the user's cwd).
func decodeWorkspaceRoot(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	// Try []string first.
	var asStrings []string
	if err := json.Unmarshal(raw, &asStrings); err == nil && len(asStrings) > 0 {
		return normalizeWorkspaceRoot(asStrings[0])
	}
	// Then []{path string}.
	var asObjects []struct {
		Path string `json:"path"`
	}
	if err := json.Unmarshal(raw, &asObjects); err == nil && len(asObjects) > 0 {
		return normalizeWorkspaceRoot(asObjects[0].Path)
	}
	return ""
}

// normalizeWorkspaceRoot canonicalizes a Cursor workspace root so it
// matches how the rest of observer represents paths on the host.
//
// Cursor-agent on Windows (the CLI) sends workspace_roots as a raw
// Windows backslash path, e.g. `C:\programsx\superbased-observer`;
// the IDE sends the `Uri.fsPath` spelling `/c:/programsx/...`. Stored
// verbatim neither is stat-able from a WSL observer, and neither
// matches the `/mnt/c/...` form pathnorm produces everywhere else
// (verified against session 90dd2512, 2026-05-24). Route through
// crossmount.TranslateForeignPath (a thin wrapper over
// pathnorm.Normalize) so `C:\...`, `/c:/...` and `file://` URIs all
// canonicalize to `/mnt/c/...`. No-op for already-native Linux paths.
//
// The pre-2026-08-07 rationale here — "leave `/c:/...` alone so
// existing IDE rows don't fragment" — is INVERTED, and was already
// only half-true (it described a pathnorm gap as a deliberate
// choice). Two changes flipped it:
//
//   - F4 (commit 82372dca) made the watcher path emit canonical
//     `/mnt/c/...` roots via resolveProjectRoot (scan.go). Leaving
//     the hook path on `/c:/...` is now precisely what fragments a
//     project: one directory, two project rows.
//   - pathnorm layer 7a now strips the URI fsPath leading slash, so
//     this function converges the hook path onto the watcher's form
//     with no cursor-local special-casing.
//
// Hence NO behaviour change is needed here: the delegation was
// already correct, and inherits the fix. Pinned by
// TestNormalizeWorkspaceRoot_CanonicalizesWindowsShapes.
//
// Historic rows written before this landed keep their `/c:/...`
// roots until a re-parse (`observer scan --force`) — the fix is on
// the write path only, per the "measure by RE-PARSING" rule.
func normalizeWorkspaceRoot(p string) string {
	if p == "" {
		return ""
	}
	return crossmount.TranslateForeignPath(p)
}

// cursorEventID derives a deterministic event ID for idempotent inserts.
// Cursor sends generation_id per turn, but a single turn can fire multiple
// hooks of the same event type (rare but possible) so we mix in payload
// fields that distinguish duplicates within a turn. Session-lifecycle
// events fire before any generation, so we fall back to conversation_id
// when generation_id is empty.
func cursorEventID(generationID, eventName string, raw rawHookPayload) string {
	base := generationID
	if base == "" {
		base = raw.ConversationID
	}
	id := base + ":" + eventName
	switch eventName {
	case EventBeforeShellCommand:
		id += ":" + shortHash(raw.Command)
	case EventAfterFileEdit, EventBeforeReadFile:
		id += ":" + shortHash(raw.FilePath)
	case EventBeforeMCPExecution:
		id += ":" + shortHash(raw.Server+":"+raw.ToolName)
	case EventPostToolUseFailure:
		// tool_use_id is the cleanest discriminator; fall back to
		// (tool_name, error) when missing.
		if raw.ToolUseID != "" {
			id += ":" + shortHash(raw.ToolUseID)
		} else {
			id += ":" + shortHash(raw.ToolName+":"+raw.ErrorMessage)
		}
	case EventSubagentStart, EventSubagentStop:
		agentKey := raw.AgentID
		if agentKey == "" {
			agentKey = raw.SubagentID
		}
		id += ":" + shortHash(agentKey)
	case EventPreToolUse:
		// preToolUse fires for every tool call within a turn; multiple
		// tool calls of different names share the same generation_id.
		// tool_use_id is the cleanest discriminator; fall back to
		// (tool_name, tool_input) when missing.
		if raw.ToolUseID != "" {
			id += ":" + shortHash(raw.ToolUseID)
		} else {
			id += ":" + shortHash(raw.ToolName+":"+string(raw.ToolInput))
		}
	}
	return id
}
