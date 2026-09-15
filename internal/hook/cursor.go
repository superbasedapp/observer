package hook

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/adapter/cursor"
	"github.com/marmutapp/superbased-observer/internal/guard"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/scrub"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// CursorSink is the subset of *store.Store methods needed to record a single
// hook event. Defined as an interface so tests can fake it without a real
// SQLite database.
type CursorSink interface {
	Ingest(ctx context.Context, events []models.ToolEvent, tokens []models.TokenEvent, opts store.IngestOptions) (store.IngestResult, error)
	UpdateActionOutcome(ctx context.Context, sourceFile, sourceEventID string, success bool, errorMessage string, durationMs int64, toolOutput, toolName, target string) (int64, error)
}

// cursorHookBodyLimit (B2, final-fix review) bounds a single Cursor
// hook payload read — raised from the original 2 MiB so a genuinely
// large beforeSubmitPrompt prompt isn't truncated into a guard bypass
// (see HandleCursorEventGuarded's own truncation detection). Every
// other cursor event shares this same read/limit, so it is sized for
// the largest one, not the common case.
const cursorHookBodyLimit = 8 * 1024 * 1024

// HandleCursorEvent reads a Cursor hook payload from stdin, replies on
// stdout immediately so the host tool never waits, then synchronously
// inserts the event into the observer DB with a strict deadline.
//
// The reply goes out FIRST so even if the insert fails or hits the timeout
// the host tool is unblocked. The deadline (default 250ms) caps how long
// the insert can take; spec §14.1 budgets the whole hook at 500ms.
//
// Spec P1: never break the host tool. All error paths log to stderr and
// return without panicking.
func HandleCursorEvent(eventName string, sink CursorSink, sc *scrub.Scrubber, stdin io.Reader, stdout, stderr io.Writer, deadline time.Duration) {
	HandleCursorEventGuarded(eventName, nil, nil, sink, sc, stdin, false, stdout, stderr, deadline)
}

// CursorEvaluator is HandleCursorEventGuarded's view of the guard:
// guard.Evaluator for the pre-execution shell/MCP/file channels, plus
// PromptEvaluator + the ActionVerdictFromPrompt bridge for
// beforeSubmitPrompt (Part B — the prompt-submit intervention hook
// lane). *guard.Guard implements all three; a nil CursorEvaluator
// degrades every channel to the unguarded receiver.
type CursorEvaluator interface {
	guard.Evaluator
	PromptEvaluator
	ActionVerdictFromPrompt(pv guard.PromptVerdict, em guard.Emission, input guard.ActionInput) guard.ActionVerdict
}

// HandleCursorEventGuarded is HandleCursorEvent with the guard seam
// (guard spec §3.2 seam 1, G6): for pre-execution events
// (before-shell / before-mcp / before-read) it evaluates the payload
// BEFORE the reply and emits Cursor's documented permission JSON
// ("allow" | "deny" | "ask" — spec §6.2) instead of the unconditional
// allow. Capture proceeds REGARDLESS of the verdict — a denied
// attempt is still an attempt worth recording — and verdict
// persistence runs last (reply → capture → persist; the reply always
// goes out first per the §6.4 budget; the forensics JSONL row carries
// the verdict either way).
//
// beforeSubmitPrompt (Part B) is special-cased to the shared
// prompt-submit seam BEFORE any of the above: its reply shape is
// {continue,user_message}, NOT the {permission,continue} shape every
// other cursor channel here emits (contract §6.3's wire-shape trap —
// HandleCursorEventGuarded used to encode ONE cursorReply struct for
// every event, which is wrong for this one).
//
// gd nil (or a non-pre-execution event) degrades to exactly the
// unguarded behavior. persist is the same nil-tolerant lazy-DB
// callback shape HandleGuarded takes.
//
// callerBodyTruncated (B2, final-fix review) lets a caller that
// already read+bounded stdin itself (cmd/observer/hook.go's
// handleCursorHook reads once so the same bytes can also feed the
// post-reply pidbridge seed) report that ITS OWN read already hit its
// limit — this function's own internal read below can't rediscover
// that fact once stdin has been re-wrapped as a fixed-size
// bytes.Reader, since a length exactly at the limit is indistinguishable
// from "the payload was exactly that long". A direct caller that hands
// this function the raw, never-pre-truncated stdin (there are none in
// this codebase today, but the exported signature doesn't forbid it)
// passes false and relies entirely on this function's own detection
// below; the two signals are OR'd together either way.
func HandleCursorEventGuarded(eventName string, gd CursorEvaluator, persist func(guard.ActionVerdict), sink CursorSink, sc *scrub.Scrubber, stdin io.Reader, callerBodyTruncated bool, stdout, stderr io.Writer, deadline time.Duration) {
	buf, _ := io.ReadAll(io.LimitReader(stdin, cursorHookBodyLimit+1))
	truncated := callerBodyTruncated
	if int64(len(buf)) > cursorHookBodyLimit {
		buf = buf[:cursorHookBodyLimit]
		truncated = true
	}
	body := bytes.TrimPrefix(buf, []byte{0xEF, 0xBB, 0xBF})

	if eventName == cursor.EventBeforeSubmitPrompt {
		handleCursorPromptSubmit(body, truncated, gd, persist, sink, sc, stdout, stderr, deadline)
		return
	}

	permission := "allow"
	var verdict guard.ActionVerdict
	recordWorthy := false
	if gd != nil {
		if pe, ok := BuildCursorEvent(eventName, body, sc); ok {
			verdict, recordWorthy = gd.EvaluateHook(pe)
			em := guard.ResolveEmission(verdict.Verdict, pe.Caps)
			verdict.Enforced = em.Enforced
			if em.DegradedFrom != "" {
				// Preserve the §6.3 "approved" marker when no §6.2
				// capability degradation applied.
				verdict.DegradedFrom = em.DegradedFrom
			}
			permission = em.Permission
			if recordWorthy {
				action := "approve+flag"
				if permission != "allow" {
					action = "guard:" + permission
				}
				appendHookEventLog(hookEvent{
					Event:        "cursor:" + eventName,
					Bytes:        len(body),
					SessionID:    pe.SessionID,
					Action:       action,
					RuleID:       verdict.Verdict.RuleID,
					Decision:     verdict.Verdict.Decision.String(),
					Severity:     verdict.Verdict.Severity.String(),
					DegradedFrom: em.DegradedFrom,
				})
			}
			if permission != "allow" {
				fmt.Fprintf(stderr, "observer-hook: cursor %s guard %s (%s: %s)\n",
					eventName, permission, verdict.Verdict.RuleID, verdict.Verdict.Reason)
			}
		}
	}

	// Reply first — Cursor tolerates extra fields, so a single response
	// shape covers all event types.
	_ = json.NewEncoder(stdout).Encode(cursorReply{
		Permission: permission,
		Continue:   true,
	})

	processCursorEvent(eventName, body, sink, sc, stderr, deadline)

	if recordWorthy && persist != nil {
		persist(verdict)
	}
}

// handleCursorPromptSubmit routes beforeSubmitPrompt through
// HandlePromptSubmitGuarded (the shared dialect table), then runs the
// SAME post-reply capture (processCursorEvent) every other cursor
// channel gets — a denied prompt is still an attempt worth recording,
// same posture as the shell/MCP/file channels above. gd nil degrades
// to the unguarded reply ({"continue":true}), matching this event's
// documented allow shape.
func handleCursorPromptSubmit(body []byte, bodyTruncated bool, gd CursorEvaluator, persist func(guard.ActionVerdict), sink CursorSink, sc *scrub.Scrubber, stdout, stderr io.Writer, deadline time.Duration) {
	promptPersist := func(pv guard.PromptVerdict, em guard.Emission, sessionID string) {
		if gd == nil || persist == nil {
			return
		}
		persist(gd.ActionVerdictFromPrompt(pv, em, guard.ActionInput{
			SessionID: sessionID, Tool: models.ToolCursor,
			ActionType: models.ActionUserPrompt, Timestamp: time.Now().UTC(),
		}))
	}
	// Cursor's dialect always replies via JSON (blockExitCode is
	// zero — see promptDialects[PromptDialectCursor]), so the
	// returned exitCode is always 0 and there is nothing for this
	// caller to act on; Cursor's own hook process always exits 0.
	handled, after, _ := HandlePromptSubmitGuarded(models.ToolCursor, PromptDialectCursor, cursor.EventBeforeSubmitPrompt, body, bodyTruncated, gd, promptPersist, stdout, stderr)
	if !handled {
		_ = json.NewEncoder(stdout).Encode(promptCursorReply{Continue: true})
	}
	processCursorEvent(cursor.EventBeforeSubmitPrompt, body, sink, sc, stderr, deadline)
	if after != nil {
		after()
	}
}

// processCursorEvent is the post-reply capture half of the cursor
// hook: stop-event token+transcript ingestion, after-event outcome
// enrichment, and before-event row insertion.
func processCursorEvent(eventName string, body []byte, sink CursorSink, sc *scrub.Scrubber, stderr io.Writer, deadline time.Duration) {
	defer recordCursorAccounts(eventName, body, sink, stderr, deadline, time.Now().UTC())

	if eventName == cursor.EventStop {
		tk, ok, err := cursor.BuildStopTokenEvent(body)
		if err != nil {
			// A parse/required-field rejection. Cursor discards hook
			// stderr, so also record a content-safe forensic row to
			// surface a payload-shape change (see cursor_stopdebug.go).
			dumpCursorStopReject(body, "build_error: "+err.Error())
			fmt.Fprintf(stderr, "observer-hook: cursor build %s: %v\n", eventName, err)
			return
		}
		if !ok {
			// Silent reject: every usage field read as zero. The most
			// likely cause of cursor's zero-token regression is a renamed
			// *_tokens field, so capture the raw key set here.
			dumpCursorStopReject(body, "no_usage_fields")
			return
		}
		// Only session_id is required. Cursor's stop payload carries the
		// per-generation usage but its workspace_roots often can't be
		// decoded into a project root — and token_usage attaches by
		// session_id (no project_id column), so the store can still land
		// the row against the already-existing session. Rejecting on empty
		// project_root here is what silently dropped every cursor token row.
		if tk.SessionID == "" {
			dumpCursorStopReject(body, "missing_session_id")
			fmt.Fprintf(stderr, "observer-hook: cursor %s missing session_id\n", eventName)
			return
		}
		// Auto-mode sessions report the placeholder model "default" in the
		// hook body; the real model (e.g. "composer-2.5") only lives in the
		// conversation's store.db turn blobs. Resolve it so token rows get
		// the concrete model the cost engine can price. Gated on the
		// sentinel, so explicit-model sessions pay no store.db I/O.
		if tk.Model == "" || strings.EqualFold(tk.Model, "default") || strings.EqualFold(tk.Model, "auto") {
			if home, err := os.UserHomeDir(); err == nil {
				if m := cursor.ResolveModelFromStore(home, tk.SessionID); m != "" {
					tk.Model = m
				}
			}
		}
		if deadline <= 0 {
			deadline = 250 * time.Millisecond
		}
		events, err := cursor.BuildStopTranscriptEvents(body, sc, tk.Timestamp)
		if err != nil {
			fmt.Fprintf(stderr, "observer-hook: cursor transcript %s: %v\n", eventName, err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), deadline)
		defer cancel()
		if _, err := sink.Ingest(ctx, events, []models.TokenEvent{tk}, store.IngestOptions{}); err != nil {
			if errors.Is(err, context.DeadlineExceeded) {
				fmt.Fprintf(stderr, "observer-hook: cursor %s insert deadline exceeded\n", eventName)
			} else {
				fmt.Fprintf(stderr, "observer-hook: cursor %s insert: %v\n", eventName, err)
			}
		}
		return
	}

	// After-events (afterShellExecution / afterMCPExecution / postToolUse)
	// don't insert a new row — they enrich the matching before-event row's
	// outcome fields in place via Store.UpdateActionOutcome. Dispatch
	// before falling through to BuildEvent so the after-event branch is
	// handled exactly once.
	if outcome, ok, err := cursor.BuildAfterOutcome(eventName, body); err != nil {
		fmt.Fprintf(stderr, "observer-hook: cursor build outcome %s: %v\n", eventName, err)
		return
	} else if ok {
		if deadline <= 0 {
			deadline = 250 * time.Millisecond
		}
		ctx, cancel := context.WithTimeout(context.Background(), deadline)
		defer cancel()
		n, err := sink.UpdateActionOutcome(
			ctx,
			outcome.SourceFile, outcome.SourceEventID,
			outcome.Success, outcome.ErrorMessage, outcome.DurationMs,
			outcome.Output, outcome.ToolName, outcome.Target,
		)
		if err != nil {
			if errors.Is(err, context.DeadlineExceeded) {
				fmt.Fprintf(stderr, "observer-hook: cursor %s outcome update deadline exceeded\n", eventName)
			} else {
				fmt.Fprintf(stderr, "observer-hook: cursor %s outcome update: %v\n", eventName, err)
			}
		} else if n == 0 {
			// Not necessarily an error — the before-row may not have
			// landed yet (rare race) or the pairing key didn't match.
			// Surface in stderr so dogfood can see the rate.
			fmt.Fprintf(stderr, "observer-hook: cursor %s outcome update touched 0 rows (sourceEventID=%s)\n",
				eventName, outcome.SourceEventID)
		}
		return
	}

	ev, ok, err := cursor.BuildEvent(eventName, body, sc)
	if err != nil {
		fmt.Fprintf(stderr, "observer-hook: cursor build %s: %v\n", eventName, err)
		return
	}
	if !ok {
		return
	}
	if ev.ProjectRoot == "" || ev.SessionID == "" {
		fmt.Fprintf(stderr, "observer-hook: cursor %s missing project_root or session_id\n", eventName)
		return
	}

	// Cursor 3.4+ carries per-generation token usage on afterAgentResponse
	// (it no longer fires the `stop` hook that the block above expects), so
	// extract usage here alongside the assistant-message row — otherwise
	// token_usage stays empty for every modern cursor session.
	var toks []models.TokenEvent
	if eventName == cursor.EventAfterAgentResponse {
		toks = cursorResponseTokens(body, stderr)
	}

	if deadline <= 0 {
		deadline = 250 * time.Millisecond
	}
	ctx, cancel := context.WithTimeout(context.Background(), deadline)
	defer cancel()
	if _, err := sink.Ingest(ctx, []models.ToolEvent{ev}, toks, store.IngestOptions{}); err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			fmt.Fprintf(stderr, "observer-hook: cursor %s insert deadline exceeded\n", eventName)
		} else {
			fmt.Fprintf(stderr, "observer-hook: cursor %s insert: %v\n", eventName, err)
		}
		return
	}
}

// cursorResponseTokens extracts the per-generation token usage that Cursor
// 3.4+ carries on the afterAgentResponse hook (it no longer fires the
// `stop` hook the older token path keys on). It mirrors the stop-path
// handling — resolving the placeholder "default"/"auto" model from the
// conversation store.db — and dumps a content-safe forensic row when the
// payload has no usable usage fields, so a field rename surfaces in
// ~/.observer/cursor-stop-debug.jsonl instead of silently yielding zero
// token rows. Returns nil when there's nothing usable; the hook stays
// fail-open.
func cursorResponseTokens(body []byte, stderr io.Writer) []models.TokenEvent {
	tk, ok, err := cursor.BuildResponseTokenEvent(body)
	if err != nil {
		dumpCursorStopReject(body, "afterAgentResponse build_error: "+err.Error())
		fmt.Fprintf(stderr, "observer-hook: cursor afterAgentResponse token build: %v\n", err)
		return nil
	}
	if !ok {
		dumpCursorStopReject(body, "afterAgentResponse no_usage_fields")
		return nil
	}
	if tk.SessionID == "" {
		dumpCursorStopReject(body, "afterAgentResponse missing_session_id")
		return nil
	}
	if tk.Model == "" || strings.EqualFold(tk.Model, "default") || strings.EqualFold(tk.Model, "auto") {
		if home, err := os.UserHomeDir(); err == nil {
			if m := cursor.ResolveModelFromStore(home, tk.SessionID); m != "" {
				tk.Model = m
			}
		}
	}
	return []models.TokenEvent{tk}
}

// cursorReply is the response shape we emit. Cursor accepts both
// "permission" (for tool gating) and "continue" (for prompt gating); extra
// keys are ignored, so a single reply works across all events.
type cursorReply struct {
	Permission string `json:"permission,omitempty"`
	Continue   bool   `json:"continue,omitempty"`
}

// BuildCursorEvent extracts a policy.Event from a Cursor pre-execution
// hook payload, REUSING the adapter's own payload extraction
// (cursor.BuildEvent — spec §6.1: reuse the per-client extraction the
// receivers already do, don't duplicate). ok=false for non-pre-
// execution channels, unparsable payloads, and non-evaluable action
// kinds — the caller then behaves exactly like the unguarded receiver.
//
// Boundary notes:
//   - Capabilities come from the §6.5 conformance matrix lookup
//     (guard.CapabilitiesFor) — the data table is the single source
//     of per-channel truth, not local constants.
//   - Unlike Claude Code's PreToolUse, the cursor payload carries the
//     workspace root, so ProjectRoot is REAL here and the boundary
//     rules (R-150/151, T-502) are active pre-execution.
//   - The adapter extraction scrubs secrets from the target before we
//     see it; rule patterns match command/path STRUCTURE, which
//     scrubbing preserves (a redacted token never changes whether the
//     command is `rm -rf` or the path is under ~/.ssh).
func BuildCursorEvent(eventName string, body []byte, sc *scrub.Scrubber) (policy.Event, bool) {
	caps, known := guard.CapabilitiesFor(models.ToolCursor, "hook:"+eventName)
	if !known || !caps.PreExecution {
		return policy.Event{}, false
	}
	ev, ok, err := cursor.BuildEvent(eventName, body, sc)
	if err != nil || !ok {
		return policy.Event{}, false
	}
	kind, evaluable := guard.ClassifyActionType(ev.ActionType)
	if !evaluable {
		return policy.Event{}, false
	}
	caps.Sandboxed = sandboxedChild()
	return policy.Event{
		Kind:        kind,
		ActionType:  ev.ActionType,
		Tool:        models.ToolCursor,
		Target:      ev.Target,
		ProjectRoot: ev.ProjectRoot,
		SessionID:   ev.SessionID,
		Caps:        caps,
		Now:         time.Now().UTC(),
	}, true
}

// recordCursorAccounts also runs for after-events and stops without usage.
// The guard reply precedes this optional evidence write on every path.
func recordCursorAccounts(eventName string, body []byte, sink CursorSink, stderr io.Writer, deadline time.Duration, at time.Time) {
	observations := cursor.BuildAccountObservations(eventName, body, at)
	if len(observations) == 0 {
		return
	}
	if deadline <= 0 {
		deadline = 250 * time.Millisecond
	}
	ctx, cancel := context.WithTimeout(context.Background(), deadline)
	defer cancel()
	if _, err := sink.Ingest(ctx, nil, nil, store.IngestOptions{ToolAccounts: observations}); err != nil {
		fmt.Fprintf(stderr, "observer-hook: cursor account capture: %v\n", err)
	}
}
