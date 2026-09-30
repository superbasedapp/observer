package hermes

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/contentcap"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
	"github.com/marmutapp/superbased-observer/internal/scrub"
)

// normalizeProjectRoot canonicalises sessions.cwd through the cross-
// mount translator so a Windows-native Hermes install observed from a
// WSL2 observer lands on /mnt/c/... rather than the verbatim C:\...
// form that would fail git.Resolve + filepath.Abs (CWD-prefix-onto-
// observer's-own-repo trap; see [[feedback-foreign-path-git-resolve]]).
// No-op on Linux-native paths and on already-translated /mnt/c/... .
//
// Audit-2026-06-05 finding §4d fix: pre-fix the cwd column was
// captured verbatim, so a hermes session run on the Windows host
// while observer ran in WSL2 attributed every action to the wrong
// project root.
func normalizeProjectRoot(cwd string) string {
	if cwd == "" {
		return ""
	}
	return crossmount.TranslateForeignPath(cwd)
}

// SessionHookChecker is the predicate the SQLite path consults to
// learn whether a session already has hook-emitted rows
// (SourceFile="hermes:hook"). Mirrors cursor's and clinecli's
// SessionHookChecker pattern; wired at the cmd assembly via
// WithSessionHookChecker over store.SessionHasSourceFileRows.
type SessionHookChecker func(ctx context.Context, sessionID string) (bool, error)

// buildEvents converts the row sets returned by scanStateDB into the
// adapter.ParseResult-shaped ToolEvent + TokenEvent slices the
// watcher's store layer consumes.
//
// Behaviour:
//
//   - Tool events: one ToolEvent per element of every assistant
//     message's tool_calls JSON array. Each is paired with the
//     matching role='tool' result message (by tool_call_id) for
//     Success / ErrorMessage / DurationMs / ToolOutput enrichment.
//     Assistant rows with no tool_calls (plain assistant text) are
//     skipped — there's no canonical Action* row for raw assistant
//     text on the SQLite path; the hook path can emit one via
//     post_llm_call when it lands.
//
//   - Token events: one TokenEvent per session that has non-zero
//     aggregate token columns. Source = TokenSourceJSONL, reliability
//     = approximate (per plan §10.8). Re-emit on every scan is safe
//     because the store layer's MAX-upgrade on (source_file,
//     source_event_id) conflict freezes the monotonic-grow guarantee.
//
//   - Cross-path dedup (the H1 audit finding, observed live
//     2026-06-11 as an exact 2× token count on a hook-covered
//     session): when hookCheck reports a session already has
//     hook-emitted rows, the SQLite path suppresses the event
//     classes the hook also emits — tool_call-derived ToolEvents
//     and the session token aggregate (the hook's post_api_request
//     rows are the finer-grained source). Classes only SQLite can
//     see (user_prompt, assistant text, system_prompt) still emit:
//     a wholesale skip à la cursor/clinecli would lose them, since
//     hermes hooks carry no message-text callbacks. On checker
//     error: warn + fall back to emitting (over-count beats silent
//     drop). nil hookCheck = emit everything (backfill paths and
//     hookless installs).
//
//   - Archived sessions (archived=1) are skipped wholesale unless
//     they have new activity — observer's analytics don't want stale
//     historical bookkeeping leaking into the live dashboard. The
//     archive-restore path (operator manually un-archives a session
//     in Hermes) re-surfaces them naturally on the next scan.
//
// Warnings accumulate non-fatal parse hiccups (malformed tool_calls
// JSON, unknown role values, etc.) so the watcher can log them
// without aborting the scan.
//
//nolint:gocyclo // one branch per hermes message role/shape variant by design; complexity tracks the upstream schema's variant count.
func buildEvents(
	ctx context.Context,
	sessions map[string]sessionRow,
	messages []messageRow,
	sourceFile string,
	sc *scrub.Scrubber,
	hookCheck SessionHookChecker,
) (toolEvents []models.ToolEvent, tokenEvents []models.TokenEvent, warnings []string) {
	// Per-session hook-coverage memo: one checker call per session
	// per scan, shared by the per-message and per-session loops.
	hookCovered := map[string]bool{}
	isHooked := func(sid string) bool {
		if v, ok := hookCovered[sid]; ok {
			return v
		}
		v := false
		if hookCheck != nil {
			h, err := hookCheck(ctx, sid)
			if err != nil {
				warnings = append(warnings, fmt.Sprintf("hermes.buildEvents: hookCheck for session %s failed (%v); falling back to SQLite emission", sid, err))
			} else {
				v = h
			}
		}
		hookCovered[sid] = v
		return v
	}
	// Pair tool-call ids to their result messages first so the
	// assistant pass can look up results in O(1).
	resultsByCallID := map[string]messageRow{}
	for _, m := range messages {
		if m.Role == "tool" && m.ToolCallID.Valid && m.ToolCallID.String != "" {
			resultsByCallID[m.ToolCallID.String] = m
		}
	}

	emittedSessions := map[string]struct{}{}
	// Reasoning is never its own action row (B3) — it rides the next
	// event this batch emits. See reasoningThread for the semantics.
	var pending reasoningThread
	for _, m := range messages {
		sess, ok := sessions[m.SessionID]
		if !ok {
			warnings = append(warnings, fmt.Sprintf("hermes.buildEvents: message id=%d references unknown session %q", m.ID, m.SessionID))
			continue
		}
		if sess.Archived == 1 {
			// Skip archived sessions silently — common case, not a
			// warning. The operator un-archive flow re-surfaces them.
			continue
		}
		emittedSessions[sess.ID] = struct{}{}

		switch m.Role {
		case "assistant":
			// Reasoning path — Hermes persists the model's chain-of-
			// thought in messages.reasoning / reasoning_content
			// (schema-v14; both populated identically in the live
			// corpus). B3: it mints NO row of its own; it is held and
			// threaded onto the first event this message produces (a
			// tool call, else the assistant text) as
			// PrecedingReasoning. Capture is NOT hook-gated the way
			// the retired row was — threading adds no row, so there is
			// no hook/SQLite duplicate to suppress.
			if r := strings.TrimSpace(hermesReasoning(m)); r != "" {
				pending.set(sess.ID, r)
			}
			// Tool calls path — emit one ToolEvent per element of the
			// tool_calls JSON. Suppressed for hook-covered sessions:
			// the hook's tool_call events carry the same calls, and
			// the two paths' rows differ on SourceFile so the UNIQUE
			// key can't dedup them (H1).
			if m.ToolCalls.Valid && strings.TrimSpace(m.ToolCalls.String) != "" && !isHooked(sess.ID) {
				calls, err := parseToolCalls(m.ToolCalls.String)
				if err != nil {
					warnings = append(warnings, fmt.Sprintf("hermes.buildEvents: tool_calls JSON for message id=%d: %v", m.ID, err))
				} else {
					for callIdx, call := range calls {
						evt := assistantToolEvent(m, sess, call, callIdx, resultsByCallID, sourceFile, sc)
						if r := pending.take(sess.ID, sc); r != "" {
							evt.PrecedingReasoning = r
						}
						toolEvents = append(toolEvents, evt)
					}
				}
			}
			// Text-response path — every assistant row with content
			// (whether finish_reason='stop' or interleaved between tool
			// calls). Emits a task_complete row carrying the prose so
			// the dashboard's "what did the assistant actually say"
			// surface works on Hermes sessions. Live corpus
			// 20260605_154029_7b8623 has 5 such rows (the final
			// summary plus 4 inline narration rows between tool
			// batches); pre-fix all 5 were invisible to the
			// dashboard.
			if m.Content.Valid && strings.TrimSpace(m.Content.String) != "" {
				evt := assistantTextEvent(m, sess, sourceFile, sc)
				// The message's own reasoning, when no tool call on this
				// message already consumed it.
				if r := pending.take(sess.ID, sc); r != "" {
					evt.PrecedingReasoning = r
				}
				toolEvents = append(toolEvents, evt)
			}
		case "user":
			// User prompt — the operator's typed message. Skipped
			// pre-fix because the original buildEvents only handled
			// tool calls. Live corpus 20260605_154029_7b8623 has 6
			// user rows; all 6 invisible pre-fix.
			//
			// WP-T6 finding H1: Hermes's own verify-on-stop loop (and
			// its codex-ack continuation) inject synthetic follow-ups
			// as role='user' messages, indistinguishable from real
			// input by role alone. isHarnessSyntheticUserMessage
			// detects the grounded "[System: " prefix (see
			// usermessage.go) and skips them — a harness reminder is
			// not developer activity, and counting it as user_prompt
			// would shrink the boundary count internal/predict's
			// fan-out ladder resolves T from.
			// A user turn is a reasoning boundary: thinking left
			// unconsumed by the previous turn is dropped, never stamped
			// onto the new turn's rows.
			pending.clear()
			if m.Content.Valid && strings.TrimSpace(m.Content.String) != "" {
				if isHarnessSyntheticUserMessage(m.Content.String) {
					continue
				}
				toolEvents = append(toolEvents, userPromptEvent(m, sess, sourceFile, sc))
			}
		case "tool":
			// Tool result rows are pair-targets for assistant
			// tool_calls, lifted inline above via resultsByCallID.
			// No standalone row.
		case "system":
			// System messages on the messages table are rare in
			// Hermes (system_prompt lives on sessions.system_prompt
			// instead). When present, skip to avoid clobbering the
			// session-level system_prompt row emitted in the
			// per-session loop below.
		default:
			warnings = append(warnings, fmt.Sprintf("hermes.buildEvents: message id=%d unknown role %q", m.ID, m.Role))
		}
	}

	// Emit session-level rows for every session referenced by the
	// messages batch:
	//   - system_prompt event (lifecycle row carrying the agent's
	//     seed instructions; SourceEventID="sys:<sid>" is stable so
	//     the UNIQUE constraint catches re-emits) — hooks never
	//     carry it, so it emits regardless of hook coverage
	//   - token aggregate row (session-level totals, re-emit-safe
	//     via the store's MAX-upgrade conflict path) — suppressed
	//     for hook-covered sessions, whose per-API-call
	//     post_api_request rows already carry the session's usage;
	//     adding the aggregate on top double-counts every token
	//     (H1, observed live 2026-06-11)
	//   - auxiliary-call rows (session_model_usage, task != '') - one
	//     per (task, model, route). NOT hook-gated: Hermes fires
	//     auxiliary calls through the distinct post_auxiliary_call
	//     plugin event (agent/auxiliary_hooks.py), never
	//     post_api_request, and the observer plugin subscribes only to
	//     the latter, so neither the hook path nor the session
	//     aggregate carries this spend (see auxTokenEvent).
	for sid := range emittedSessions {
		sess := sessions[sid]
		if strings.TrimSpace(sess.SystemPrompt) != "" {
			toolEvents = append(toolEvents, sessionSystemPromptEvent(sess, sourceFile, sc))
		}
		for _, aux := range sess.AuxUsage {
			if ev, ok := auxTokenEvent(sess, aux, sourceFile); ok {
				tokenEvents = append(tokenEvents, ev)
			}
		}
		if sess.InputTokens == 0 && sess.OutputTokens == 0 &&
			sess.CacheReadTokens == 0 && sess.CacheWriteTokens == 0 &&
			sess.ReasoningTokens == 0 {
			continue
		}
		if isHooked(sid) {
			continue
		}
		tokenEvents = append(tokenEvents, sessionTokenEvent(sess, sourceFile))
	}

	return toolEvents, tokenEvents, warnings
}

// auxTokenEvent maps one session_model_usage auxiliary row (vision,
// compression, title_generation, background_review, ...) onto a
// TokenEvent. ok is false for an all-zero row (observationally vacant).
//
// Identity: the SourceEventID folds the table's whole primary key
// (task + model + billing route) so two routes for the same task never
// collide, and it is stable across scans - the counters only grow, so
// the store's MAX-upgrade conflict path keeps the row correct on every
// re-emit. The model is Hermes's own per-call value; an aux call whose
// model Hermes could not resolve is stored as the literal "unknown",
// which this maps to "" (unknown to the cost engine) rather than a
// fabricated model id. Counters are NET input like the session
// aggregate (the same update path writes both), so no cache netting.
func auxTokenEvent(sess sessionRow, aux auxUsageRow, sourceFile string) (models.TokenEvent, bool) {
	if aux.InputTokens == 0 && aux.OutputTokens == 0 && aux.CacheReadTokens == 0 &&
		aux.CacheWriteTokens == 0 && aux.ReasoningTokens == 0 {
		return models.TokenEvent{}, false
	}
	model := stripProviderPrefix(strings.TrimSpace(aux.Model))
	if strings.EqualFold(model, "unknown") {
		model = ""
	}
	ts := unixFloatToTime(sess.StartedAt)
	if aux.LastSeen.Valid {
		if t := unixFloatToTime(aux.LastSeen.Float64); !t.IsZero() {
			ts = t
		}
	}
	cost := aux.ActualCostUSD
	if cost <= 0 {
		cost = aux.EstimatedCostUSD
	}
	if cost < 0 {
		cost = 0
	}
	key := strings.Join([]string{aux.Model, aux.BillingProvider, aux.BillingBaseURL, aux.BillingMode}, "\x1f")
	return models.TokenEvent{
		SourceFile:          sourceFile,
		SourceEventID:       fmt.Sprintf("tk-aux:%s:%s:%s", sess.ID, aux.Task, hashHex12(key)),
		SessionID:           sess.ID,
		ProjectRoot:         normalizeProjectRoot(sess.CWD),
		Timestamp:           ts,
		Tool:                models.ToolHermes,
		Model:               model,
		InputTokens:         aux.InputTokens,
		OutputTokens:        aux.OutputTokens,
		CacheReadTokens:     aux.CacheReadTokens,
		CacheCreationTokens: aux.CacheWriteTokens,
		ReasoningTokens:     aux.ReasoningTokens,
		EstimatedCostUSD:    cost,
		Source:              models.TokenSourceJSONL,
		Reliability:         models.ReliabilityApproximate,
	}, true
}

// userPromptEvent maps a role='user' message into an ActionUserPrompt
// ToolEvent. Hermes's user rows carry the operator's typed message
// in `content`; the dashboard's session-detail view consumes this as
// the "what the user asked" surface for the timeline. Pre-fix
// 2026-06-06 this was skipped because buildEvents only handled tool
// calls, so multi-prompt sessions surfaced as a sequence of tool
// calls with no question to anchor them.
func userPromptEvent(m messageRow, sess sessionRow, sourceFile string, sc *scrub.Scrubber) models.ToolEvent {
	body := m.Content.String
	if sc != nil {
		body = sc.String(body)
	}
	preview := body
	if len(preview) > 200 {
		preview = preview[:200]
	}
	return models.ToolEvent{
		SourceFile:         sourceFile,
		SourceEventID:      fmt.Sprintf("m%d:user", m.ID),
		SessionID:          m.SessionID,
		ProjectRoot:        normalizeProjectRoot(sess.CWD),
		Timestamp:          unixFloatToTime(m.Timestamp),
		Tool:               models.ToolHermes,
		Model:              stripProviderPrefix(sess.Model),
		ActionType:         models.ActionUserPrompt,
		Target:             preview,
		Success:            true,
		PrecedingReasoning: preview,
		RawToolName:        "user_message",
		RawToolInput:       contentcap.Cap(body, contentcap.DefaultMaxBytes),
		MessageID:          fmt.Sprintf("user:hermes-msg-%d", m.ID),
	}
}

// hermesReasoning returns the model's chain-of-thought text for an
// assistant message, preferring reasoning_content and falling back to
// reasoning (both are populated identically in the live corpus, but a
// future Hermes build could carry only one). Empty string when neither
// is present (e.g. tool-result narration with no thinking).
func hermesReasoning(m messageRow) string {
	if m.ReasoningContent.Valid && strings.TrimSpace(m.ReasoningContent.String) != "" {
		return m.ReasoningContent.String
	}
	if m.Reasoning.Valid && strings.TrimSpace(m.Reasoning.String) != "" {
		return m.Reasoning.String
	}
	return ""
}

// reasoningThread holds an assistant message's chain-of-thought until
// the next event consumes it as PrecedingReasoning. Pre-B3 the text
// minted its own ActionTaskComplete row (`hermes.reasoning`) — a phantom
// action for something the model never did.
//
// Semantics (grok-style default adopted by B3):
//
//   - CONSUMED-ONCE: the first successor event (the message's first tool
//     call, else its assistant-text row) takes it and clears it, so one
//     block of thinking is never stamped onto a whole session.
//   - LAST-WINS: an unconsumed body is replaced by a newer one — the
//     nearest thinking is the one that introduced the call.
//   - TURN-BOUNDARY DISCARD: a role='user' message clears it.
//   - SESSION-SCOPED: one hermes state.db holds many sessions and the
//     message scan interleaves them, so reasoning never crosses a
//     session id.
type reasoningThread struct {
	sessionID string
	text      string
}

// set records a reasoning body for a session (last-wins).
func (t *reasoningThread) set(sessionID, body string) {
	t.sessionID, t.text = sessionID, body
}

// clear drops any pending reasoning (turn boundary).
func (t *reasoningThread) clear() { t.sessionID, t.text = "", "" }

// take consumes the pending reasoning for sessionID, or returns "" when
// nothing is pending / it belongs to another session. Scrubbing + the
// 200-char cap happen HERE (at flush) so the preview convention the
// retired `hermes.reasoning` row carried is preserved unchanged.
func (t *reasoningThread) take(sessionID string, sc *scrub.Scrubber) string {
	if t.text == "" || t.sessionID != sessionID {
		return ""
	}
	body := t.text
	if sc != nil {
		body = sc.String(body)
	}
	if len(body) > 200 {
		body = body[:200]
	}
	t.clear()
	return body
}

// assistantTextEvent maps a role='assistant' message with non-empty
// content (the model's prose response — either the final summary
// after a tool sequence or an inline narration row between tool
// batches) into an ActionTaskComplete ToolEvent. Mirrors the cursor
// adapter's cursor.assistant_response shape. Pre-fix 2026-06-06 this
// was skipped, so sessions appeared to end abruptly after the last
// tool call with no visible response.
func assistantTextEvent(m messageRow, sess sessionRow, sourceFile string, sc *scrub.Scrubber) models.ToolEvent {
	body := m.Content.String
	if sc != nil {
		body = sc.String(body)
	}
	preview := body
	if len(preview) > 200 {
		preview = preview[:200]
	}
	ev := models.ToolEvent{
		SourceFile:         sourceFile,
		SourceEventID:      fmt.Sprintf("m%d:asst", m.ID),
		SessionID:          m.SessionID,
		ProjectRoot:        normalizeProjectRoot(sess.CWD),
		Timestamp:          unixFloatToTime(m.Timestamp),
		Tool:               models.ToolHermes,
		Model:              stripProviderPrefix(sess.Model),
		ActionType:         models.ActionAssistantMessage,
		Target:             preview,
		Success:            true,
		PrecedingReasoning: preview,
		RawToolName:        "hermes.assistant_response",
		ToolOutput:         contentcap.Cap(body, contentcap.DefaultMaxBytes),
		MessageID:          fmt.Sprintf("hermes-msg-%d", m.ID),
	}
	// Stamp the per-message terminal reason (messages.finish_reason —
	// OpenAI/OpenRouter-shaped: stop / length / tool_calls / …) into the
	// canonical Metadata.StopReason column, matching opencode/cowork/pi.
	// statedb already scans it; pre-fix it was dropped on the floor.
	if r := strings.TrimSpace(m.FinishReason.String); m.FinishReason.Valid && r != "" {
		ev.Metadata = &models.ActionMetadata{StopReason: r}
	}
	return ev
}

// sessionSystemPromptEvent emits one ActionSystemPrompt row carrying
// the session's seed instructions from sessions.system_prompt. One
// row per session per scan; SourceEventID="sys:<session_id>" is
// stable so the (source_file, source_event_id) UNIQUE constraint
// catches re-emit on subsequent scans. Live corpus
// 20260605_154029_7b8623 has 15,529 chars of system prompt that
// pre-fix was invisible to the dashboard.
func sessionSystemPromptEvent(sess sessionRow, sourceFile string, sc *scrub.Scrubber) models.ToolEvent {
	body := sess.SystemPrompt
	if sc != nil {
		body = sc.String(body)
	}
	preview := body
	if len(preview) > 200 {
		preview = preview[:200]
	}
	return models.ToolEvent{
		SourceFile:    sourceFile,
		SourceEventID: "sys:" + sess.ID,
		SessionID:     sess.ID,
		ProjectRoot:   normalizeProjectRoot(sess.CWD),
		Timestamp:     unixFloatToTime(sess.StartedAt),
		Tool:          models.ToolHermes,
		Model:         stripProviderPrefix(sess.Model),
		ActionType:    models.ActionSystemPrompt,
		Target:        preview,
		Success:       true,
		RawToolName:   "hermes.system_prompt",
		RawToolInput:  contentcap.Cap(body, contentcap.DefaultMaxBytes),
		MessageID:     "sys:" + sess.ID,
	}
}

// assistantToolEvent maps one (assistant message, tool_call) pair into
// a ToolEvent, looking up the matching role='tool' result for
// Success / ErrorMessage / ToolOutput enrichment.
//
// SourceEventID composition: `m<msg_id>:<call_id>` — deterministic
// across re-scans, distinguishes multiple calls per assistant row.
// Falls back to the call index when the wrapper's id field is empty
// (defensive — real fixtures always carry id).
func assistantToolEvent(
	m messageRow,
	sess sessionRow,
	call toolCallWrapper,
	callIdx int,
	resultsByCallID map[string]messageRow,
	sourceFile string,
	sc *scrub.Scrubber,
) models.ToolEvent {
	callKey := call.ID
	if callKey == "" {
		callKey = fmt.Sprintf("idx%d", callIdx)
	}

	rawInput := call.Function.Arguments
	scrubbedInput := rawInput
	if sc != nil {
		scrubbedInput = sc.String(rawInput)
	}
	scrubbedInput = contentcap.Cap(scrubbedInput, contentcap.DefaultMaxBytes)

	target := extractTarget(call.Function.Name, call.Function.Arguments)
	if sc != nil {
		target = sc.String(target)
	}

	evt := models.ToolEvent{
		SourceFile:    sourceFile,
		SourceEventID: fmt.Sprintf("m%d:%s", m.ID, callKey),
		SessionID:     m.SessionID,
		ProjectRoot:   normalizeProjectRoot(sess.CWD),
		Timestamp:     unixFloatToTime(m.Timestamp),
		Tool:          models.ToolHermes,
		Model:         stripProviderPrefix(sess.Model),
		ActionType:    normalizeToolName(call.Function.Name),
		Target:        target,
		Success:       true, // optimistic default; overwritten when the result pairs.
		RawToolName:   call.Function.Name,
		RawToolInput:  scrubbedInput,
		MessageID:     fmt.Sprintf("hermes-msg-%d", m.ID),
	}

	// Pair with the role='tool' result for outcome enrichment.
	if call.ID != "" {
		if r, ok := resultsByCallID[call.ID]; ok {
			pairResult(&evt, r, sc)
		}
	}
	return evt
}

// pairResult mutates a ToolEvent in-place with the paired role='tool'
// result message's outcome fields. Tool result content for Hermes is
// structured JSON (see plan §17.1 C); parseToolResult lifts
// exit_code / error / output cleanly. When the content isn't valid
// JSON (rare; legacy Hermes builds or operator-customised tools) we
// fall back to treating the whole body as output and Success=true.
func pairResult(evt *models.ToolEvent, result messageRow, sc *scrub.Scrubber) {
	if !result.Content.Valid {
		return
	}
	body := result.Content.String

	success, errMsg, output := parseToolResult(body)
	evt.Success = success
	evt.ErrorMessage = errMsg

	if sc != nil {
		output = sc.String(output)
	}
	evt.ToolOutput = contentcap.Cap(output, contentcap.DefaultMaxBytes)

	// DurationMs from the timestamp delta between the assistant
	// message (already on evt.Timestamp) and the tool result.
	if result.Timestamp > 0 && !evt.Timestamp.IsZero() {
		delta := unixFloatToTime(result.Timestamp).Sub(evt.Timestamp).Milliseconds()
		if delta > 0 {
			evt.DurationMs = delta
		}
	}
}

// sessionTokenEvent emits one TokenEvent carrying the session-level
// aggregate counts. Same row gets re-emitted on every scan that
// references this session; the store layer's MAX-upgrade conflict
// path freezes them in place because the aggregates only ever grow.
//
// Timestamp: prefers ended_at when set, else falls back to
// started_at — the row records "as of when do these aggregates
// hold".
func sessionTokenEvent(sess sessionRow, sourceFile string) models.TokenEvent {
	ts := unixFloatToTime(sess.StartedAt)
	if sess.EndedAt.Valid {
		if end := unixFloatToTime(sess.EndedAt.Float64); !end.IsZero() {
			ts = end
		}
	}
	// Hermes computes its own per-session cost (sessions.estimated_cost_usd /
	// actual_cost_usd, cost_source=provider_models_api). Propagate it like
	// the kilo adapter does — prefer the actual (billed) figure when
	// present, else the estimate — rather than discarding it and forcing a
	// recompute. Zero/absent (e.g. free models) leaves cost to the engine.
	cost := 0.0
	if sess.ActualCostUSD.Valid {
		cost = sess.ActualCostUSD.Float64
	} else if sess.EstimatedCostUSD.Valid {
		cost = sess.EstimatedCostUSD.Float64
	}
	return models.TokenEvent{
		SourceFile:          sourceFile,
		SourceEventID:       "tk:" + sess.ID,
		SessionID:           sess.ID,
		ProjectRoot:         normalizeProjectRoot(sess.CWD),
		Timestamp:           ts,
		Tool:                models.ToolHermes,
		Model:               stripProviderPrefix(sess.Model),
		InputTokens:         sess.InputTokens,
		OutputTokens:        sess.OutputTokens,
		CacheReadTokens:     sess.CacheReadTokens,
		CacheCreationTokens: sess.CacheWriteTokens,
		ReasoningTokens:     sess.ReasoningTokens,
		EstimatedCostUSD:    cost,
		Source:              models.TokenSourceJSONL,
		Reliability:         models.ReliabilityApproximate,
	}
}

// extractTarget picks the most informative single-string target field
// out of a tool-call's argument JSON. The per-tool argument shapes
// come from the §17.1 reality check (testdata/hermes/reality-check.txt
// sample rows) — keep this in sync when a new tool grows live
// coverage in the fixture corpus.
//
// Empty result is acceptable: ToolEvent.Target is informational and
// the dashboard tolerates "" for the long-tail tools where no single
// field reads as "the thing this call is about".
func extractTarget(toolName string, rawArgs string) string {
	if rawArgs == "" {
		return ""
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(rawArgs), &m); err != nil {
		return ""
	}

	switch toolName {
	case "read_file", "write_file", "patch", "apply_diff":
		// {path: "..."} for all three (verified live for
		// read_file / write_file / patch in the fixture corpus).
		return strKey(m, "path", "file_path")
	case "terminal":
		return strKey(m, "command")
	case "process":
		return strKey(m, "command", "process_name")
	case "execute_code":
		return strKey(m, "code", "language")
	case "search_files":
		// Live shape: {pattern: "...", target: "files", path: "..."}.
		// Pattern is the most informative single field.
		return strKey(m, "pattern", "query")
	case "web_search":
		return strKey(m, "query")
	case "web_extract":
		// Live shape: {urls: ["..."]} — array even for one URL. Lift
		// the first url string when present; fall back to the bare
		// "url" key if some future Hermes build switches to single-
		// shape.
		if v, ok := m["urls"]; ok {
			if arr, ok := v.([]any); ok && len(arr) > 0 {
				if s, ok := arr[0].(string); ok {
					return s
				}
			}
		}
		return strKey(m, "url")
	case "delegate_task", "mixture_of_agents":
		return strKey(m, "task", "prompt", "description")
	case "todo":
		return strKey(m, "action", "task")
	case "clarify":
		return strKey(m, "question", "prompt")
	case "send_message":
		return strKey(m, "to", "channel", "recipient")
	default:
		// MCP / browser / media / etc. — best-effort: any common
		// "name" / "target" / "id" / "query" / "url" lifts something
		// dashboard-friendly.
		return strKey(m, "url", "query", "path", "name", "target", "id")
	}
}

// strKey returns the first non-empty string value found across keys,
// or "" when none are populated. Lets extractTarget handle the
// keys-might-be-named-differently variants without nested switches.
func strKey(m map[string]any, keys ...string) string {
	for _, k := range keys {
		if v, ok := m[k]; ok {
			if s, ok := v.(string); ok && s != "" {
				return s
			}
		}
	}
	return ""
}

// parseToolResult lifts Success / ErrorMessage / Output out of a
// Hermes tool-result message body. Schema-v14 stores structured JSON
// in messages.content (see §17.1 C):
//
//	terminal:    {"output": "...", "exit_code": 0, "error": null}
//	write_file:  {"bytes_written": 128, "dirs_created": true,
//	              "lint": {...}, "resolved_path": "...",
//	              "files_modified": ["..."]}
//	read_file:   {"content": "...", "lines": N}  (illustrative)
//	patch:       {"applied": true, "diff": "...", ...}
//
// Success precedence: exit_code (0 = success) > error (null = success)
// > applied/ok flags > default true (so unknown shapes don't get
// marked failed). ErrorMessage prefers a non-null error string, then
// stderr-like fields, then nothing.
func parseToolResult(body string) (success bool, errMsg string, output string) {
	success = true
	body = strings.TrimSpace(body)
	if body == "" {
		return
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(body), &m); err != nil {
		// Not JSON — treat the whole body as the tool's output;
		// success defaults true.
		output = body
		return
	}

	// exit_code takes precedence — terminal/process tools surface it
	// canonically. Non-zero ⇒ failure.
	if v, ok := m["exit_code"]; ok {
		switch n := v.(type) {
		case float64:
			if n != 0 {
				success = false
			}
		case int64:
			if n != 0 {
				success = false
			}
		}
	}

	// Explicit error string ⇒ failure (overrides exit_code-derived
	// success when present).
	if v, ok := m["error"]; ok && v != nil {
		if s, ok := v.(string); ok && s != "" {
			success = false
			errMsg = s
		}
	}

	// Fallback failure signals.
	if v, ok := m["applied"]; ok {
		if b, ok := v.(bool); ok && !b {
			success = false
		}
	}

	// Output extraction prefers the canonical "output" key, then
	// "content" (read_file shape), else serialises the whole body
	// for dashboard visibility. Track "saw the key" separately from
	// "key has non-empty value" so an explicit "output": "" doesn't
	// fall through to the whole-body fallback — the tool genuinely
	// emitted empty output (the terminal-permission-error live shape
	// reads exactly this way).
	sawOutputKey := false
	if v, ok := m["output"]; ok {
		sawOutputKey = true
		if s, ok := v.(string); ok {
			output = s
		}
	}
	if !sawOutputKey {
		if v, ok := m["content"]; ok {
			sawOutputKey = true
			if s, ok := v.(string); ok {
				output = s
			}
		}
	}
	if !sawOutputKey {
		output = body
	}
	return
}
