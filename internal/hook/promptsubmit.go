package hook

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/guard"
	"github.com/marmutapp/superbased-observer/internal/policy"
)

// Prompt-submit intervention — the HOOK LANE (Part B of
// docs/plans/prompt-submit-intervention-exploration-2026-09-07.md).
// Phase 1 built the pure evaluation engine (guard.EvaluatePrompt) with
// no caller; this file is the ONE shared handler seam every
// prompt-submit-capable client's hook receiver calls into, table-driven
// on the wire DIALECT (never on tool name — CLAUDE.md rule 3). Several
// tools share one dialect: Codex, Factory Droid, and Qwen Code all
// speak the same top-level `{"decision":"block","reason":…}` legacy
// shape (contract §6.2/§6.5/§6.6), so they share promptDialectBlock
// even though they are three different registry rows.
//
// Contract §10 item 12 (honest degradation): a channel with NO
// user-visible message field must never run ask-once — it would block
// a developer with no explanation and no way to learn a resend
// confirms. That is expressed as CanAsk:false in the conformance row
// (internal/guard/conformance.go), and guard.ResolveEmission already
// degrades Ask→Deny with DegradedFrom="ask" for such a channel — this
// file does not duplicate that logic, it only resolves the WIRE SHAPE
// for whatever Permission ResolveEmission decided.

// PromptEvaluator is HandlePromptSubmitGuarded's view of the guard —
// the prompt-submit counterpart of guard.Evaluator (guard/hook.go).
// *guard.Guard implements it; tests stub it.
type PromptEvaluator interface {
	// BuildPromptFindings runs the typed detectors over prompt text.
	// See guard.Guard.BuildPromptFindings's doc comment for the
	// truncated-return contract (FIX-2).
	BuildPromptFindings(text string) (secrets []policy.SecretFinding, pii []policy.PIIFinding, truncated bool)
	// EvaluatePrompt runs the reconsider-once state machine.
	EvaluatePrompt(ev policy.Event) guard.PromptVerdict
}

// promptReplyOutcome is what a dialect's reply builder needs to shape
// one wire response — resolved AFTER guard.ResolveEmission, so the
// dialect layer never touches policy.Decision or channel capabilities
// directly.
type promptReplyOutcome struct {
	// Blocking is true for a "deny" or "ask" emission (both express as
	// a hard stop on every dialect here — none of the wire shapes this
	// file implements has a genuine third "ask" wire state; Qwen's
	// documented "ask" verb is deliberately NOT used for it, see
	// promptDialectBlock's doc comment).
	Blocking bool
	// Confirmable is true when the stop is one the developer can confirm
	// (re-enter: send it again; confirm: a native dialog), as opposed to a
	// hard block. Only meaningful with Blocking; a dialect whose wire shape
	// has a distinct ask state (the plugin shim) reads it.
	Confirmable bool
	// Reason is the house-style, human-facing message (§7) — never
	// vendor-authored text, never a raw prompt/value.
	Reason string
	// Warn is true when the underlying decision is a non-blocking flag
	// worth surfacing to the developer (mode=warn, or a degrade like
	// FIX-2's truncated-prompt notice) — Blocking is always false when
	// Warn is true.
	Warn bool
	// Redacted is true when the verdict's action is guard.PromptActionRedact:
	// the prompt goes through as Masked (every secret span replaced by its
	// [REDACTED:type] marker). Only a dialect with a redact builder ever
	// sees it; Blocking and Warn are false then.
	Redacted bool
	// Masked is the rewritten prompt text when Redacted.
	Masked string
}

// promptDialect is one row of the table-driven wire-shape dispatch
// (CLAUDE.md rule 5), keyed by DIALECT id, never by tool name (rule
// 3) — registration.go / the caller decides which dialect a given
// TOOL speaks; this table only knows shapes.
type promptDialect struct {
	// extract pulls (prompt, sessionID) out of the raw hook payload.
	// ok=false means the payload isn't recognizable for this dialect —
	// the caller falls through to its normal unguarded reply, exactly
	// like HandleGuarded's behavior for an unrecognized tool shape.
	//
	// fieldMissing (FIX-2, phase-2 review) is true when ok=true but
	// NONE of this dialect's known prompt-field names were present in
	// the raw JSON at all — a vendor schema change, not a developer
	// who genuinely submitted an empty prompt. It must NEVER be
	// silently treated as "prompt scanned, nothing found" — see
	// policy.Event.PromptFieldMissing's doc comment.
	extract func(body []byte) (prompt, sessionID string, ok, fieldMissing bool)
	// decodes, when non-nil, says whether a payload extract answered
	// ok=false for decodes as this dialect's shape after all: a dialect whose
	// extractor also says ok=false for a benign reason (Command Code's input
	// with no text member, Antigravity's model call with no transcript yet)
	// sets it, so PromptPayloadUndecodable fails closed only on a payload
	// that does not decode. nil: every ok=false is a decode failure.
	decodes func(body []byte) bool
	// reply builds the dialect's wire-shaped JSON reply object for one
	// resolved outcome. nil for a dialect whose block signal is a bare
	// process exit code with no structured stdout reply at all
	// (Devin/Cascade — the vendor states show_output does not apply to
	// this event, so nothing is written anywhere).
	reply func(out promptReplyOutcome) any
	// blockExitCode (Part B item 2, the documented long-tail vendors):
	// when non-zero, HandlePromptSubmitGuarded returns this as its
	// exitCode result whenever out.Blocking is true. The CALLER
	// (`observer hook`'s per-tool receiver, cmd/observer/hook.go) is
	// responsible for actually calling os.Exit(exitCode) AFTER
	// recordAfterReply() runs. Zero (Cursor, zcode, commandcode) means
	// "the JSON stdout reply alone is the wire contract; the process
	// always exits 0". Claude Code joined the exit-code set on
	// 2026-09-07 (LIVE CORRECTION — see claudeCodePromptOut): its
	// block is exit 2 with NO stdout reply, Qoder's shape.
	blockExitCode int
	// stderrReason, when true, means a Blocking or Warn outcome's
	// house message is written as plain text to stderr (a Blocking one
	// after the StderrBlockHeader on one line, DEC-1; a Warn one
	// verbatim): Qoder's documented "exit 2 rejects the prompt; stderr
	// is shown to the user" channel (docs.qoder.com/en/cli/hooks).
	// The forensics debug line HandlePromptSubmitGuarded otherwise
	// writes to stderr is suppressed for such a dialect (it goes to
	// appendHookEventLog's file only instead) — that debug line is
	// invisible process stderr for every JSON dialect, but Qoder's own
	// stderr genuinely reaches the developer's terminal, so mixing
	// internal rule-id/severity noise into it would leak debug text
	// into the one channel the vendor renders as the user-facing
	// reason.
	stderrReason bool
	// caps is what this wire shape lets the developer SEE and DO for a
	// prompt finding (guard.PromptSeamCaps), resolved through the one
	// decision x capability table (guard/promptaction.go). Warn is true
	// only where the vendor documents a pass-through notice the
	// DEVELOPER sees: Claude Code and Codex `systemMessage`
	// (code.claude.com/docs/en/hooks, learn.chatgpt.com/docs/hooks,
	// fetched 2026-10-02), Gemini CLI `systemMessage`. Cursor's
	// beforeSubmitPrompt has no non-blocking notice field (cursor.com/
	// docs/agent/hooks, fetched 2026-10-02), and additionalContext /
	// additional_context reach the MODEL, not the developer, so those
	// rows cannot warn: a flag there is recorded and toasted
	// (flag-after).
	caps guard.PromptSeamCaps
	// allowReply is the dialect's own "nothing to say" reply, written
	// when Observer has no verdict to give (no prompt found, guard off,
	// a non-prompt event, a recovered panic): HandlePromptAllow. nil
	// means the host accepts the generic {"decision":"approve"}
	// (HandleApprove). A host whose output schema REJECTS unknown fields
	// must set it: Antigravity CLI accepts only `injectSteps` or an empty
	// object, and logged "unknown field \"decision\"" on every
	// invocation (node 1 live test, 2026-10-03).
	allowReply any
	// oncePerPrompt marks a seam that fires repeatedly for ONE prompt
	// (agy's PreInvocation runs before every model call of a turn): a
	// prompt with findings is judged once, deduped on the pre-send mark
	// the first verdict's persist leaves (guard.PromptAlreadyJudged).
	oncePerPrompt bool
	// redact, when non-nil, builds the dialect's MODIFY reply: the host
	// sends out.Masked to the model instead of what the developer typed
	// (Poolside hook_specific_output.updated_prompt, commandcode
	// {action:"transform"}). A dialect with redact sets caps.Redact; the
	// handler offers it to the decision table only when the guard could
	// mask this prompt completely (guard.Guard.RedactPromptText).
	redact func(out promptReplyOutcome) any
	// silentAllow marks a host that treats ANY non-empty stdout on an allow
	// as text to add to the model context (Kimi Code appends an exit-0
	// hook's stdout to the conversation as a <hook_result> message), so
	// "nothing to say" must be an EMPTY stdout, never a JSON approve.
	silentAllow bool
	// capsProbe, when non-nil, narrows caps for THIS invocation's host
	// (Antigravity CLI: the PreInvocation abort is offered only when the
	// running agy is a version proven to honour it). It runs only for a
	// prompt with something to judge, never on the clean-prompt path.
	capsProbe func(guard.PromptSeamCaps) guard.PromptSeamCaps
	// taintsSession marks a seam whose stop leaves the prompt in the
	// conversation, which the host resends with every later turn (agy's
	// PreInvocation abort). Such a seam first asks whether a prompt was
	// already stopped in this conversation (guard.PromptSessionStopped)
	// and, if so, stops the turn again whatever its own prompt says
	// (guard.TaintedSessionPromptVerdict).
	taintsSession bool
}

// promptSessionStopChecker is the optional evaluator capability a
// taintsSession dialect uses (guard.Guard implements it).
type promptSessionStopChecker interface {
	PromptSessionStopped(tool, sessionID string) (guard.PromptSessionStop, bool)
}

// seamCapsFor returns d's capabilities for this invocation (capsProbe
// applied).
func (d promptDialect) seamCapsFor() guard.PromptSeamCaps {
	if d.capsProbe != nil {
		return d.capsProbe(d.caps)
	}
	return d.caps
}

// taintedSessionVerdict returns the verdict that stops this turn because
// its conversation still carries a stopped prompt (ok=false: not a
// taintsSession dialect, no session, nothing stopped, or a host that cannot
// stop the turn, in which case the turn is judged on its own prompt).
func taintedSessionVerdict(tool string, d promptDialect, ge PromptEvaluator, sessionID string) (guard.PromptVerdict, bool) {
	if !d.taintsSession || sessionID == "" {
		return guard.PromptVerdict{}, false
	}
	c, ok := ge.(promptSessionStopChecker)
	if !ok {
		return guard.PromptVerdict{}, false
	}
	stop, ok := c.PromptSessionStopped(tool, sessionID)
	if !ok {
		return guard.PromptVerdict{}, false
	}
	caps := d.seamCapsFor()
	if !caps.Block {
		return guard.PromptVerdict{}, false
	}
	return guard.TaintedSessionPromptVerdict(stop).WithAction(caps, "hook"), true
}

// repeatSeamNothingNew reports whether a oncePerPrompt seam has nothing
// new to say: the prompt is clean, or a pre-send lane already judged it.
// No DB read unless the prompt has a finding.
func repeatSeamNothingNew(ge PromptEvaluator, sessionID, prompt string, findings int) bool {
	if findings == 0 {
		return true
	}
	c, ok := ge.(promptJudgedChecker)
	return ok && c.PromptAlreadyJudged(sessionID, prompt, time.Now().UTC())
}

// promptJudgedChecker is the optional evaluator capability a
// oncePerPrompt dialect uses (guard.Guard implements it).
type promptJudgedChecker interface {
	PromptAlreadyJudged(sessionID, text string, at time.Time) bool
}

// promptHookStops is the capability every dialect below shares: each can
// stop the prompt with its own block signal, and the reconsider-once
// flow turns that into a re-enter.
var promptHookStops = guard.PromptSeamCaps{Reenter: true, Block: true}

// promptHookWarns adds the documented pass-through notice.
var promptHookWarns = guard.PromptSeamCaps{Warn: true, Reenter: true, Block: true}

// promptPluginShimStops is the OpenCode / Kilo CLI chat.message seam
// through the plugin shim: it stops the prompt (the shim throws, so the
// model is never called; the session id keys resend-to-confirm) and shows a
// notice with the host's TUI toast (a headless run has no TUI, so a warning
// there is seen only on the dashboard). No native confirm exists
// (permission.ask has no trigger site in OpenCode 1.18.31), and no redact is
// offered.
var promptPluginShimStops = guard.PromptSeamCaps{Warn: true, Reenter: true, Block: true}

// promptPluginShimConfirms is the pi `input` seam through the plugin shim:
// a notice (ctx.ui.notify), a native confirm (ctx.ui.confirm; with no UI the
// shim stops the prompt and the developer resends to confirm, so Reenter
// backs it), a hard stop ({action:"handled"}, no request is sent) and a
// rewrite ({action:"transform"}).
var promptPluginShimConfirms = guard.PromptSeamCaps{Warn: true, Confirm: true, Reenter: true, Block: true, Redact: true}

// promptHookStopsOrRedacts is a seam that can stop the prompt AND rewrite
// what the model receives (Poolside updated_prompt, commandcode transform).
var promptHookStopsOrRedacts = guard.PromptSeamCaps{Reenter: true, Block: true, Redact: true}

// jsonHasAnyKey reports whether body decodes as a JSON object carrying
// at least one of the given top-level keys — used by every extractor
// below to distinguish "the vendor renamed/removed this field" (FIX-2)
// from "the field is present with a genuinely empty string value" (a
// developer submitting a blank prompt, which is not schema drift).
func jsonHasAnyKey(body []byte, keys ...string) bool {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(body, &m); err != nil {
		return false
	}
	for _, k := range keys {
		if _, ok := m[k]; ok {
			return true
		}
	}
	return false
}

// promptGenericPayload is the {"prompt":"…","session_id":"…"} shape
// shared by Codex, Droid, Qwen Code, and Gemini CLI (contract §6.2,
// §6.4, §6.5, §6.6) — every vendor except Claude Code (whose field is
// user_prompt) and Cursor (whose session field is conversation_id).
type promptGenericPayload struct {
	Prompt    string `json:"prompt"`
	SessionID string `json:"session_id"`
}

func extractGenericPrompt(body []byte) (prompt, sessionID string, ok, fieldMissing bool) {
	var p promptGenericPayload
	// B1 (phase-3a review): an absent/empty session_id must NOT make
	// this extractor report ok=false — that sent the caller
	// (HandlePromptSubmitGuarded) down the "unrecognized dialect"
	// fallthrough path, which for every real hook receiver means
	// falling through to its normal unguarded HandleApprove reply: a
	// silent, total bypass of prompt-submit scanning triggered by
	// nothing more than a missing identity field. ok now depends only
	// on whether the body parses as this dialect's JSON object shape;
	// an empty sessionID is passed through to the engine, which
	// already fails CLOSED on it (evaluatePromptAskOnce's "no_session"
	// degrade — deny, never allow) rather than being memory-holed here
	// before the engine ever sees the prompt.
	if err := json.Unmarshal(body, &p); err != nil {
		return "", "", false, false
	}
	return p.Prompt, p.SessionID, true, !jsonHasAnyKey(body, "prompt")
}

// promptClaudeCodePayload is Claude Code's UserPromptSubmit input
// shape. The contract (§6.1, code.claude.com/docs/en/hooks fetched
// 2026-09-07) names the field `user_prompt`; this repo's OWN
// pre-existing capture builder (buildClaudeUserPromptSubmitEvent,
// cmd/observer/hook.go) reads `prompt` instead, and its test fixtures
// use that shape too — a genuine, unresolved conflict between two
// grounding sources this build cannot re-verify against a live
// install. Rather than pick one and risk the guard seeing an
// permanently EMPTY prompt (silently never detecting anything — the
// worst failure mode for a security feature), both field names are
// accepted, `user_prompt` preferred when both are present. Flagged for
// a live-capture probe before this ships (see docs/guard-prompt.md's
// hook-lane section).
type promptClaudeCodePayload struct {
	UserPrompt string `json:"user_prompt"`
	Prompt     string `json:"prompt"`
	SessionID  string `json:"session_id"`
}

func extractClaudeCodePrompt(body []byte) (prompt, sessionID string, ok, fieldMissing bool) {
	var p promptClaudeCodePayload
	// B1: same fail-open trap as extractGenericPrompt (see its comment)
	// — an empty session_id must reach the engine's own fail-closed
	// "no_session" degrade, not bounce the caller to HandleApprove.
	if err := json.Unmarshal(body, &p); err != nil {
		return "", "", false, false
	}
	if p.UserPrompt != "" {
		return p.UserPrompt, p.SessionID, true, false
	}
	return p.Prompt, p.SessionID, true, !jsonHasAnyKey(body, "user_prompt", "prompt")
}

// promptCursorPayload is Cursor's beforeSubmitPrompt input shape
// (contract §6.3) — session id is `conversation_id` (the same field
// every other Cursor hook payload carries, cursor.rawHookPayload),
// never `session_id`.
type promptCursorPayload struct {
	Prompt         string `json:"prompt"`
	ConversationID string `json:"conversation_id"`
}

func extractCursorPrompt(body []byte) (prompt, sessionID string, ok, fieldMissing bool) {
	var p promptCursorPayload
	// B1: same fail-open trap (see extractGenericPrompt's comment) —
	// an empty conversation_id must reach the engine's fail-closed
	// "no_session" degrade rather than bounce to HandleApprove.
	if err := json.Unmarshal(body, &p); err != nil {
		return "", "", false, false
	}
	return p.Prompt, p.ConversationID, true, !jsonHasAnyKey(body, "prompt")
}

// claudeCodePromptOut is the UserPromptSubmit hookSpecificOutput
// envelope for the NON-blocking outcomes only. LIVE CORRECTION
// (2026-09-07, operator step-in on Claude Code under both WSL and
// Windows): contract §6.1's `permissionDecision: "deny"` is a
// PreToolUse-only field — Claude Code silently ignores it on
// UserPromptSubmit (three live submissions of a fake `sk-ant-` key
// were logged as blocked by the receiver and still reached the model).
// The vendor's documented block signal for THIS event is process exit
// code 2, whose stderr is the user-visible reason and which erases the
// prompt from context (code.claude.com/docs/en/hooks). So the dialect
// row now carries blockExitCode:2 + stderrReason, exactly like Qoder's
// (whose settings.json schema is byte-identical to Claude Code's), and
// a block writes NOTHING to stdout. The JSON reply is emitted only for
// allow (bare envelope) and warn (`additionalContext`), the two fields
// the docs list for this event.
type claudeCodePromptOut struct {
	HookEventName     string `json:"hookEventName"`
	AdditionalContext string `json:"additionalContext,omitempty"`
}

type claudeCodePromptReply struct {
	// SystemMessage is the documented common field "Warning message
	// shown to the user" (code.claude.com/docs/en/hooks, fetched
	// 2026-10-02): the flag decision's visible warning. additionalContext
	// only reaches the model.
	SystemMessage      string              `json:"systemMessage,omitempty"`
	HookSpecificOutput claudeCodePromptOut `json:"hookSpecificOutput"`
}

// buildClaudeCodePromptReply returns nil on a blocking outcome — the
// block is carried by the exit code + stderr (see the type comment),
// and HandlePromptSubmitGuarded skips the stdout encode for a nil reply.
func buildClaudeCodePromptReply(out promptReplyOutcome) any {
	if out.Blocking {
		return nil
	}
	hso := claudeCodePromptOut{HookEventName: "UserPromptSubmit"}
	reply := claudeCodePromptReply{}
	if out.Warn {
		hso.AdditionalContext = out.Reason
		reply.SystemMessage = out.Reason
	}
	reply.HookSpecificOutput = hso
	return reply
}

// ClaudeCodePromptApproveReply is the modern UserPromptSubmit "allow"
// envelope (claudeCodePromptOut) exported for callers that need to
// reply approve WITHOUT going through the full
// HandlePromptSubmitGuarded pipeline — e.g. cmd/observer/hook.go's
// handleClaudeCodeUserPromptSubmit falls back to this when the guard
// is disabled/errored (!handled), so that fallback path still speaks
// the modern hookSpecificOutput contract Claude Code's own docs
// describe, instead of the legacy bare {"decision":"approve"} shape
// (FIX cluster, item 7a).
func ClaudeCodePromptApproveReply() any {
	return buildClaudeCodePromptReply(promptReplyOutcome{})
}

// promptTopLevelBlockOut is the legacy top-level decision envelope
// Codex, Factory Droid, and Qwen Code all accept (contract §6.2, §6.5,
// §6.6): `{"decision":"block","reason":…}` to interrupt, an optional
// `hookSpecificOutput.additionalContext` for a non-blocking notice.
// "block" (not "deny") is used deliberately: it is the ONE verb every
// vendor in this dialect's own documentation names explicitly for
// this exact event, whereas none of their docs disambiguate a
// separate "deny" semantic at prompt-submit — using the
// vendor-confirmed verb rather than inventing a distinction the docs
// don't draw (contract's own "never a guessed payload" discipline).
type promptTopLevelBlockOut struct {
	// SystemMessage is Codex's "surfaced as a warning in the UI" field
	// (learn.chatgpt.com/docs/hooks, fetched 2026-10-02); Droid and Qwen
	// Code take the same Claude-Code-compatible common field.
	SystemMessage      string                        `json:"systemMessage,omitempty"`
	Decision           string                        `json:"decision,omitempty"`
	Reason             string                        `json:"reason,omitempty"`
	HookSpecificOutput *promptTopLevelHookOutputOnly `json:"hookSpecificOutput,omitempty"`
}

type promptTopLevelHookOutputOnly struct {
	HookEventName     string `json:"hookEventName"`
	AdditionalContext string `json:"additionalContext,omitempty"`
}

func buildPromptTopLevelBlockReply(out promptReplyOutcome) any {
	if out.Blocking {
		return promptTopLevelBlockOut{
			Decision: "block",
			Reason:   out.Reason,
			HookSpecificOutput: &promptTopLevelHookOutputOnly{
				HookEventName: "UserPromptSubmit",
			},
		}
	}
	if out.Warn {
		return promptTopLevelBlockOut{
			SystemMessage: out.Reason,
			HookSpecificOutput: &promptTopLevelHookOutputOnly{
				HookEventName:     "UserPromptSubmit",
				AdditionalContext: out.Reason,
			},
		}
	}
	return promptTopLevelBlockOut{}
}

// promptCursorReply is beforeSubmitPrompt's OWN reply shape (contract
// §6.3's wire-shape trap): `continue` + `user_message`, NOT the
// `permission` field HandleCursorEventGuarded's shared cursorReply
// emits for the shell/MCP/file channels. Cursor's docs state the
// prompt cannot be modified and name no non-blocking notice channel
// for this event, so a warn-mode finding forwards silently
// (Continue:true, no message) rather than guessing a field that
// doesn't exist in the documented schema.
type promptCursorReply struct {
	Continue    bool   `json:"continue"`
	UserMessage string `json:"user_message,omitempty"`
}

func buildCursorPromptReply(out promptReplyOutcome) any {
	if out.Blocking {
		return promptCursorReply{Continue: false, UserMessage: out.Reason}
	}
	return promptCursorReply{Continue: true}
}

// promptGeminiReply is Gemini CLI's BeforeAgent decision shape
// (contract §6.4): `decision:"deny"` blocks and discards the message;
// `systemMessage` is the field the vendor's own docs call
// user-visible in the terminal, and `reason` ALSO renders on a denial
// — set both, per the contract's explicit "set both" resolution of
// the round-1/round-2 discrepancy over whether `reason` is
// user-visible.
type promptGeminiReply struct {
	Decision      string `json:"decision,omitempty"`
	Reason        string `json:"reason,omitempty"`
	SystemMessage string `json:"systemMessage,omitempty"`
}

func buildGeminiPromptReply(out promptReplyOutcome) any {
	if out.Blocking {
		return promptGeminiReply{Decision: "deny", Reason: out.Reason, SystemMessage: out.Reason}
	}
	if out.Warn {
		return promptGeminiReply{SystemMessage: out.Reason}
	}
	return promptGeminiReply{}
}

// --- Part B item 2 (docs/plans/prompt-submit-intervention-exploration-2026-09-07.md
// §2.1b): the documented long-tail vendors. Each wire shape below was
// verified 2026-09-07 by fetching the vendor's own cited docs page
// live (not the contract's own summary alone) — Qoder
// (docs.qoder.com/en/cli/hooks), Poolside (docs.poolside.ai/hooks),
// zcode (zcode.z.ai/en/docs/hooks), Devin Desktop/Cascade
// (docs.devin.ai/desktop/cascade/hooks), commandcode
// (commandcode.ai/docs/mods).

// extractQoderPrompt is Qoder CLI's UserPromptSubmit payload
// (contract §2.1b, docs.qoder.com/en/cli/hooks):
// {"prompt","session_id","cwd","hook_event_name","transcript_path"} —
// the same {prompt, session_id} shape as extractGenericPrompt.
var extractQoderPrompt = extractGenericPrompt

// promptCascadePayload is Windsurf/Devin Desktop Cascade's
// pre_user_prompt payload (docs.devin.ai/desktop/cascade/hooks):
// common fields agent_action_name/trajectory_id/execution_id/
// timestamp/model_name plus an event-specific tool_info.user_prompt.
// NO session_id field is documented for this event at all;
// trajectory_id (the "conversation identifier") is the closest
// functional analog and is used as the reconsider-once scoping key —
// a real field serving the session-scoping role under a different
// name, not a guessed one.
type promptCascadePayload struct {
	TrajectoryID string `json:"trajectory_id"`
	ToolInfo     *struct {
		UserPrompt string `json:"user_prompt"`
	} `json:"tool_info"`
}

func extractCascadePrompt(body []byte) (prompt, sessionID string, ok, fieldMissing bool) {
	var p promptCascadePayload
	// B1: same fail-open trap (see extractGenericPrompt's comment) —
	// an empty trajectory_id must reach the engine's fail-closed
	// "no_session" degrade rather than bounce to HandleApprove.
	if err := json.Unmarshal(body, &p); err != nil {
		return "", "", false, false
	}
	missing := !jsonNestedHasKey(body, "tool_info", "user_prompt")
	if p.ToolInfo != nil {
		return p.ToolInfo.UserPrompt, p.TrajectoryID, true, missing
	}
	return "", p.TrajectoryID, true, missing
}

// jsonNestedHasKey is jsonHasAnyKey's one-level-nested counterpart,
// used by extractCascadePrompt to distinguish "tool_info.user_prompt
// is present but empty" (a developer submitted a blank prompt) from
// "tool_info itself, or user_prompt within it, is absent" (schema
// drift — FIX-2's fieldMissing degrade).
func jsonNestedHasKey(body []byte, outer, inner string) bool {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(body, &m); err != nil {
		return false
	}
	outerRaw, ok := m[outer]
	if !ok {
		return false
	}
	var innerMap map[string]json.RawMessage
	if err := json.Unmarshal(outerRaw, &innerMap); err != nil {
		return false
	}
	_, ok = innerMap[inner]
	return ok
}

// extractCommandCodePrompt is commandcode's Mods SDK transformInput
// payload (commandcode.ai/docs/mods): the hook is registered as
// `cmd.hooks({transformInput({text}) {...}})` — the ONLY documented
// field is `text`; there is NO session/conversation id anywhere in
// the signature. sessionID is therefore always "" here — a genuine
// property of this wire shape, not an extraction bug. The engine's
// own documented state machine (docs/guard-prompt.md "How
// reconsider-once works": "Empty session_id ... fails closed to
// block") applies honestly: every ask-once/redact-mode finding on
// this channel becomes a hard, unconditional block (no resend
// override) until the prompt text itself changes. That is a real,
// disclosed UX cost of this vendor's hook signature, not something
// this build can improve on — see docs/guard-prompt.md's per-vendor
// table. ok requires the "text" key to be present at all: unlike
// every other dialect (which anchors on a separate identity field
// such as session_id), commandcode has no second field to prove a
// genuine invocation, so the presence of its one documented field is
// the only signal available.
func extractCommandCodePrompt(body []byte) (prompt, sessionID string, ok, fieldMissing bool) {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(body, &m); err != nil {
		return "", "", false, false
	}
	raw, hasText := m["text"]
	if !hasText {
		return "", "", false, false
	}
	var text string
	if json.Unmarshal(raw, &text) != nil {
		// A text member that is not a string is not an empty prompt: the
		// guard cannot read it (FU-161, commandCodePromptDecodes).
		return "", "", false, false
	}
	return text, "", true, false
}

// promptQoderReply is intentionally unused: Qoder's block channel is
// a bare process exit code (2) plus a plain-text stderr line — see
// promptDialect.stderrReason and promptDialects[PromptDialectQoder]
// below, which sets reply to nil.

// promptPoolsideReply is Poolside's UserPromptSubmit JSON decision
// shape (docs.poolside.ai/hooks, live-fetched 2026-09-07):
// {"decision":"block","reason":…,"hook_specific_output":{
// "updated_prompt":…,"additional_context":…}}. Poolside ALSO
// documents a bare exit-2 alternative ("exit 2 blocks the event, with
// the text your script wrote to stderr as the reason") — the JSON
// decision form is the PRIMARY signal (symmetric with every other JSON
// dialect), and F3 (phase-3a review) additionally sets
// blockExitCode:2 on this dialect's promptDialects row as a
// fail-closed, defense-in-depth FALLBACK: both the JSON reply AND a
// non-zero exit fire on a block, so a misread of this reconstructed
// JSON shape by a real Poolside build still stops the prompt via the
// documented exit-code alternative. updated_prompt (the genuine
// redact lane) is never populated — redact is not wired on ANY
// channel yet (Phase 1 degrade, matching Claude Code's own
// updatedInput).
type promptPoolsideReply struct {
	Decision           string                        `json:"decision,omitempty"`
	Reason             string                        `json:"reason,omitempty"`
	HookSpecificOutput *promptPoolsideHookOutputOnly `json:"hook_specific_output,omitempty"`
}

type promptPoolsideHookOutputOnly struct {
	AdditionalContext string `json:"additional_context,omitempty"`
}

func buildPoolsidePromptReply(out promptReplyOutcome) any {
	if out.Blocking {
		return promptPoolsideReply{Decision: "block", Reason: out.Reason}
	}
	if out.Warn {
		return promptPoolsideReply{HookSpecificOutput: &promptPoolsideHookOutputOnly{AdditionalContext: out.Reason}}
	}
	return promptPoolsideReply{}
}

// promptZcodeOut is zcode's UserPromptSubmit reply shape
// (zcode.z.ai/en/docs/hooks, live-fetched 2026-09-07):
// {"continue":false,"reason":…,"hookSpecificOutput":{"hookEventName":
// "UserPromptSubmit","additionalContext":…}} — Claude-Code-shaped
// (camelCase hookSpecificOutput, unlike Poolside's snake_case), and
// the vendor states outright it "cannot rewrite the original prompt"
// (no redact lane, unlike Poolside/commandcode). **Contested
// liveness**: zai-org/feedback#32 reports configured hooks may not
// fire on the native agent at all — this dialect/receiver is built
// and tested, but its registration writer is deliberately NOT wired
// into `observer init`/the auto-register loop (HookZcodeJSON,
// AutoWired:false) until that is probed live; see
// internal/integration's zcode row.
type promptZcodeOut struct {
	Continue           bool                   `json:"continue"`
	Reason             string                 `json:"reason,omitempty"`
	HookSpecificOutput *promptZcodeHookOutput `json:"hookSpecificOutput,omitempty"`
}

type promptZcodeHookOutput struct {
	HookEventName     string `json:"hookEventName"`
	AdditionalContext string `json:"additionalContext,omitempty"`
}

func buildZcodePromptReply(out promptReplyOutcome) any {
	if out.Blocking {
		return promptZcodeOut{Continue: false, Reason: out.Reason, HookSpecificOutput: &promptZcodeHookOutput{HookEventName: "UserPromptSubmit"}}
	}
	if out.Warn {
		return promptZcodeOut{Continue: true, HookSpecificOutput: &promptZcodeHookOutput{HookEventName: "UserPromptSubmit", AdditionalContext: out.Reason}}
	}
	return promptZcodeOut{Continue: true}
}

// promptCommandCodeOut is commandcode's Mods SDK transformInput
// return shape (commandcode.ai/docs/mods, live-fetched 2026-09-07):
// "return {action:'transform',text} to rewrite (handlers chain),
// {action:'handled',message?} to consume the prompt entirely, or
// undefined/{action:'continue'} to pass through." `action:'transform'`
// (the genuine redact lane) is never emitted — redact is not wired on
// any channel yet. Non-blocking outcomes emit an explicit
// {"action":"continue"} — undefined can't be JSON-encoded, and the
// vendor's own docs list it as equivalent to that literal object.
type promptCommandCodeOut struct {
	Action  string `json:"action,omitempty"`
	Message string `json:"message,omitempty"`
}

func buildCommandCodePromptReply(out promptReplyOutcome) any {
	if out.Blocking {
		return promptCommandCodeOut{Action: "handled", Message: out.Reason}
	}
	return promptCommandCodeOut{Action: "continue"}
}

// buildPoolsidePromptRedactReply is Poolside's MODIFY reply
// (docs.poolside.ai/hooks, fetched 2026-10-03): exit 0 with
// hook_specific_output.updated_prompt makes the MODEL receive the rewritten
// prompt while the terminal keeps showing what the developer typed;
// additional_context (also honoured on this event) tells the model why the
// value reads as a redaction marker.
func buildPoolsidePromptRedactReply(out promptReplyOutcome) any {
	type poolsideRedactOut struct {
		UpdatedPrompt     string `json:"updated_prompt"`
		AdditionalContext string `json:"additional_context,omitempty"`
	}
	return struct {
		HookSpecificOutput poolsideRedactOut `json:"hook_specific_output"`
	}{poolsideRedactOut{UpdatedPrompt: out.Masked, AdditionalContext: out.Reason}}
}

// buildCommandCodePromptRedactReply is commandcode's Mods SDK transform
// (commandcode.ai/docs/mods, fetched 2026-10-03): {action:'transform',text}
// "rewrites the prompt text that reaches the model" for this model call
// only; the visible record keeps the typed input. The go:embed'd bridge
// (commandcodemod/observer-guard.ts) already returns a transform reply
// verbatim.
func buildCommandCodePromptRedactReply(out promptReplyOutcome) any {
	type commandCodeTransformOut struct {
		Action string `json:"action"`
		Text   string `json:"text"`
	}
	return commandCodeTransformOut{Action: "transform", Text: out.Masked}
}

// Kimi Code's UserPromptSubmit (kimi-code 2.1.1, grounded 2026-10-03 from
// the bundled source of the installed build on demo node 1:
// agent-core-v2 externalHooks runHook.ts / userPrompt.ts; the vendor page
// moonshotai.github.io/kimi-code/en/customization/hooks agrees on the
// envelope). The runner camelCases-to-snake_cases the input, so stdin is
// {"hook_event_name","session_id","session_title","cwd",...,"prompt",
// "is_steer"} - the generic {prompt, session_id} shape. Exit 2 BLOCKS and
// its trimmed stderr becomes the block message, which Kimi appends to the
// conversation as a <hook_result hook_event="UserPromptSubmit"> message
// and dispatches as a HookResult event (the developer sees it in the
// transcript; the model reads it too). On exit 0 a non-empty stdout is
// appended to the model context as another <hook_result>, which is why the
// allow reply is an empty stdout (silentAllow) and why a warning has no
// developer-visible channel here (caps: stop only). A timed-out or crashed
// hook is an allow (Kimi fails open).
//
// T-378 live capture (kimi 2.1.1 on demo node 1, 2026-10-07): "prompt" is
// NOT a string on the wire but the turn's content parts,
// [{"type":"text","text":"..."}]. A string-only decode failed on that body
// and the receiver fell through to its unguarded allow, so a secret in the
// prompt reached the model. Both shapes are read here: the text parts are
// joined with newlines (non-text parts such as images carry no text to
// scan), and a prompt value of any other shape is reported as a missing
// field, never as an empty prompt.
func extractKimiCodePrompt(body []byte) (prompt, sessionID string, ok, fieldMissing bool) {
	var p struct {
		Prompt    json.RawMessage `json:"prompt"`
		SessionID string          `json:"session_id"`
	}
	if err := json.Unmarshal(body, &p); err != nil {
		return "", "", false, false
	}
	text, shapeOK := kimiPromptText(p.Prompt)
	return text, p.SessionID, true, !jsonHasAnyKey(body, "prompt") || !shapeOK
}

// kimiPromptText reads a Kimi Code prompt value: a plain string, or a list
// of content parts whose "text" members are joined with newlines. ok is
// false for any other shape (including null and an absent value).
func kimiPromptText(raw json.RawMessage) (string, bool) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return "", false
	}
	var s string
	if json.Unmarshal(trimmed, &s) == nil {
		return s, true
	}
	var parts []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	}
	if json.Unmarshal(trimmed, &parts) != nil {
		return "", false
	}
	texts := make([]string, 0, len(parts))
	for _, pt := range parts {
		if pt.Text != "" {
			texts = append(texts, pt.Text)
		}
	}
	return strings.Join(texts, "\n"), true
}

// Devin CLI's UserPromptSubmit (docs.devin.ai/cli/extensibility/hooks/
// lifecycle-hooks, fetched 2026-10-03): stdin carries "prompt" and
// "session_id"; the only documented output is
// hookSpecificOutput.additionalContext, which reaches the AGENT's context.
// No block is documented, so the seam can only warn the model (caps:
// warn, indirect) and every finding still toasts.
var extractDevinCLIPrompt = extractGenericPrompt

// devinCLIPromptOut is the hookSpecificOutput envelope Devin CLI documents.
type devinCLIPromptOut struct {
	HookEventName     string `json:"hookEventName"`
	AdditionalContext string `json:"additionalContext,omitempty"`
}

func buildDevinCLIPromptReply(out promptReplyOutcome) any {
	if !out.Warn {
		return struct{}{}
	}
	return struct {
		HookSpecificOutput devinCLIPromptOut `json:"hookSpecificOutput"`
	}{devinCLIPromptOut{HookEventName: "UserPromptSubmit", AdditionalContext: out.Reason}}
}

// Kiro CLI's userPromptSubmit (kiro-cli 2.28.0, live on demo node 1,
// gfiD research 2026-10-15): stdin {hook_event_name, cwd, session_id,
// prompt} (the prompt also in $USER_PROMPT); the hook CANNOT block (exit 1
// and exit 2 both let the prompt through) and an exit-0 stdout is added to
// the MODEL's context only. So the seam warns the model in plain text and
// every finding still toasts; the allow is an empty stdout (any text would
// reach the model).
var extractKiroCLIPrompt = extractGenericPrompt

// plainTextReply is a dialect reply written verbatim as one line of plain
// text (a host that adds stdout to the model context as text, not JSON).
type plainTextReply string

func buildKiroCLIPromptReply(out promptReplyOutcome) any {
	if !out.Warn || out.Reason == "" {
		return nil
	}
	return plainTextReply(out.Reason)
}

// Dialect ids — the channel's WIRE SHAPE, not a tool name. Multiple
// registry tools may share one row (contract §6.7/§9.0).
const (
	// PromptDialectClaudeCode is Claude Code's UserPromptSubmit shape.
	PromptDialectClaudeCode = "claude-code"
	// PromptDialectTopLevelBlock is the legacy {"decision":"block",…}
	// shape shared by Codex, Factory Droid, and Qwen Code.
	PromptDialectTopLevelBlock = "top-level-block"
	// PromptDialectCursor is Cursor's beforeSubmitPrompt shape.
	PromptDialectCursor = "cursor"
	// PromptDialectGemini is Gemini CLI's BeforeAgent shape.
	PromptDialectGemini = "gemini-cli"
	// PromptDialectQoder is Qoder CLI's UserPromptSubmit shape: exit
	// code 2 blocks, plain-text stderr is the user-visible reason (no
	// JSON reply at all).
	PromptDialectQoder = "qoder"
	// PromptDialectPoolside is Poolside's UserPromptSubmit JSON
	// decision shape (snake_case, unlike every Claude-Code-shaped
	// dialect here).
	PromptDialectPoolside = "poolside"
	// PromptDialectZcode is zcode's Claude-Code-shaped UserPromptSubmit
	// continue:false reply.
	PromptDialectZcode = "zcode"
	// PromptDialectCascade is Windsurf/Devin Desktop Cascade's
	// pre_user_prompt shape: exit code 2 blocks, with NO user-visible
	// message channel at all.
	//
	// F2 (phase-3a review) RE-VERIFIED this live on 2026-09-07 by
	// fetching https://docs.devin.ai/desktop/cascade/hooks directly (not
	// relying on the contract's own summary): the page states VERBATIM
	// "The show_output configuration option does not apply to this
	// hook" for pre_user_prompt specifically, and separately "the user
	// can see any hook-generated standard output and standard error in
	// the Cascade UI if show_output is true" for the hooks it DOES
	// apply to. Since show_output is documented as inapplicable to
	// pre_user_prompt, there is no live UI-visible reply channel for
	// this event — the original no-output assumption holds. Blocking
	// itself is confirmed as exit code 2 ("pre-hooks ... can block
	// actions using exit code 2"), matching this dialect's
	// blockExitCode:2/reply:nil row below. No code change results from
	// this re-verification — see promptDialects' PromptDialectCascade
	// row.
	PromptDialectCascade = "cascade"
	// PromptDialectCommandCode is commandcode's Mods SDK transformInput
	// shape — packaged as a TypeScript module, not a shell hook; see
	// internal/hook/hermesplugin's Python-plugin precedent for the
	// analogous non-JSON-config registration model.
	PromptDialectCommandCode = "command-code"
	// PromptDialectAntigravityPreInvocation is Antigravity CLI's
	// PreInvocation hook (promptagy.go): a pre-model-call seam that reads
	// the prompt from the session transcript, warns the developer with an
	// injected userMessage, and blocks by aborting the turn (no message can
	// accompany the abort; the toast carries the reason).
	PromptDialectAntigravityPreInvocation = "antigravity-preinvocation"
	// PromptDialectKimiCode is Kimi Code's UserPromptSubmit shape: exit 2
	// with the reason on stderr blocks; an allow is an EMPTY stdout.
	PromptDialectKimiCode = "kimi-code"
	// PromptDialectDevinCLI is Devin CLI's UserPromptSubmit shape (its own
	// .devin/hooks.v1.json, distinct from Devin Desktop's Cascade
	// pre_user_prompt): context injection only, no block.
	PromptDialectDevinCLI = "devin-cli"
	// PromptDialectKiroCLI is Kiro CLI's userPromptSubmit shape: context
	// injection only (plain-text stdout reaches the model), no block.
	PromptDialectKiroCLI = "kiro-cli"
	// PromptDialectDirac is Dirac's UserPromptSubmit file hook: the prompt
	// under userPromptSubmit.prompt, {cancel: true, errorMessage} cancels the
	// whole task before any model call; the allow is silence.
	PromptDialectDirac = "dirac"
	// PromptDialectAutohand is Autohand's pre-prompt: the prompt is
	// "instruction"; a top-level {decision: block, reason} (exit 0) stops it
	// and the reason is printed to the developer.
	PromptDialectAutohand = "autohand"
)

// Dirac's UserPromptSubmit (dirac-cli 0.5.22, live 2026-10-21 on Windows
// and WSL): stdin {diracVersion, hookName, taskId, workspaceRoots, ...,
// userPromptSubmit: {prompt, attachments?}}. It fires before EVERY API
// request of a task (twice with the initial prompt, then with prompt "" on
// each tool-result turn), so the row is oncePerPrompt (a repeat of an already
// judged prompt replies allow without a second verdict) and an empty prompt
// is simply clean. A block cancels the whole task; a resend is a NEW task
// (a new session id), so no resend-to-confirm is offered: caps are a hard
// stop. The reason goes to stderr, which Dirac echoes into the transcript
// (the model never sees it).
type promptDiracPayload struct {
	TaskID           string `json:"taskId"`
	UserPromptSubmit *struct {
		Prompt *string `json:"prompt"`
	} `json:"userPromptSubmit"`
}

func extractDiracPrompt(body []byte) (prompt, sessionID string, ok, fieldMissing bool) {
	var p promptDiracPayload
	if err := json.Unmarshal(body, &p); err != nil {
		return "", "", false, false
	}
	if p.UserPromptSubmit == nil || p.UserPromptSubmit.Prompt == nil {
		return "", p.TaskID, true, true
	}
	return *p.UserPromptSubmit.Prompt, p.TaskID, true, false
}

// diracPromptReply is Dirac's cancel reply.
type diracPromptReply struct {
	Cancel       bool   `json:"cancel"`
	ErrorMessage string `json:"errorMessage,omitempty"`
}

func buildDiracPromptReply(out promptReplyOutcome) any {
	if !out.Blocking {
		return nil
	}
	return diracPromptReply{Cancel: true, ErrorMessage: out.Reason}
}

// promptDiracStops is Dirac's seam: a hard stop only (see above).
var promptDiracStops = guard.PromptSeamCaps{Block: true}

// Autohand's pre-prompt (autohand-cli 0.9.8, live 2026-10-21 on Windows and
// WSL): stdin {session_id, cwd, hook_event_name, instruction,
// mentioned_files?}. {"decision":"block","reason"} on exit 0 stops the
// prompt before the model and prints the reason to the developer (yellow);
// additionalContext reaches only the model, so there is no developer-visible
// warning. exit 2 would print stderr instead, which carries Observer's own
// diagnostics, so the block is the JSON reply alone.
type promptAutohandPayload struct {
	Instruction string `json:"instruction"`
	SessionID   string `json:"session_id"`
}

func extractAutohandPrompt(body []byte) (prompt, sessionID string, ok, fieldMissing bool) {
	var p promptAutohandPayload
	if err := json.Unmarshal(body, &p); err != nil {
		return "", "", false, false
	}
	return p.Instruction, p.SessionID, true, !jsonHasAnyKey(body, "instruction")
}

func buildAutohandPromptReply(out promptReplyOutcome) any {
	if out.Blocking {
		return topDecisionReply{Decision: "block", Reason: out.Reason}
	}
	return struct{}{}
}

// promptDialects is the dialect table (CLAUDE.md rule 5): exactly the
// VERIFIED wire shapes (contract §6/§2.1b) get a row here. A
// genuinely unverified or contested wire shape (Kimi Code, Kiro,
// Cline, open-interpreter) gets a registry + conformance row marked
// probe_required instead of a guessed entry here — see
// internal/integration's PromptLane field and
// docs/guard-prompt.md's hook-lane table.
// F3 (phase-3a review) added blockExitCode:2 to three more rows below
// as a fail-closed, defense-in-depth FALLBACK: HandlePromptSubmitGuarded
// already writes the JSON reply AND exits non-zero whenever both
// d.reply != nil and d.blockExitCode != 0 (see its own doc comment) —
// so a dialect gets this DUAL signal, not a replacement of the JSON
// form. The idea: if this repo's guessed/reconstructed JSON reply
// shape ever turns out wrong for a given vendor build, the non-zero
// exit is a second, independent block signal that still stops the
// prompt even when the JSON reply is silently ignored.
//
//   - PromptDialectTopLevelBlock (Codex/Factory Droid/Qwen Code): ALL
//     THREE vendors' own docs independently confirm exit-2 blocking
//     for this event (docs/plans/prompt-submit-intervention-exploration-2026-09-07.md
//     §6.2 Codex: "Exit 2 with stderr blocks, stderr becoming the
//     reason"; §6.5 Factory Droid, quoting docs.factory.ai directly:
//     "Exit 2 blocks... Emit both plus exit-2 as a backstop"; §6.6
//     Qwen Code, re-verified live 2026-09-07 at
//     qwenlm.github.io/qwen-code-docs/en/users/features/hooks/:
//     "Command hooks use exit code 2 to signal a blocking error" —
//     this is a SHARED dialect row (one wire shape, three tools), so
//     the fallback applies to all three together rather than needing
//     a per-tool split of an otherwise-identical shape.
//   - PromptDialectGemini: §6.4 "Exit 2 blocks and erases the prompt"
//     (geminicli.com/docs/hooks/reference).
//   - PromptDialectPoolside: already documented in
//     buildPoolsidePromptReply's own doc comment
//     (docs.poolside.ai/hooks, live-fetched 2026-09-07): "exit 2
//     blocks the event, with the text your script wrote to stderr as
//     the reason".
//
// PromptDialectQoder keeps blockExitCode:2 with reply:nil — it is
// EXIT-CODE-ONLY by its own vendor doc (no JSON reply channel exists
// for this event at all), so there is no JSON form to dual-signal
// alongside; adding one would contradict, not reinforce, its
// documented single mechanism. PromptDialectCascade is the same
// exit-code-only shape (no JSON reply, no session_id — see its own
// doc comment). Cursor, zcode, and commandcode are left unchanged:
// outside this review's explicit list, and — for Cursor —
// (Claude Code WAS left unchanged by that review, then moved to
// blockExitCode:2 + stderrReason by the 2026-09-07 live correction
// — its JSON permissionDecision form was ignored on the wire.)
// setting blockExitCode risked interacting with its own
// `HandleCursorEventGuarded` reply path in ways not audited here.
var promptDialects = map[string]promptDialect{
	PromptDialectClaudeCode:    {extract: extractClaudeCodePrompt, reply: buildClaudeCodePromptReply, blockExitCode: 2, stderrReason: true, caps: promptHookWarns},
	PromptDialectTopLevelBlock: {extract: extractGenericPrompt, reply: buildPromptTopLevelBlockReply, blockExitCode: 2, caps: promptHookWarns},
	PromptDialectCursor:        {extract: extractCursorPrompt, reply: buildCursorPromptReply, caps: promptHookStops},
	PromptDialectGemini:        {extract: extractGenericPrompt, reply: buildGeminiPromptReply, blockExitCode: 2, caps: promptHookWarns},
	PromptDialectQoder:         {extract: extractQoderPrompt, reply: nil, blockExitCode: 2, stderrReason: true, caps: promptHookStops},
	PromptDialectPoolside:      {extract: extractGenericPrompt, reply: buildPoolsidePromptReply, redact: buildPoolsidePromptRedactReply, blockExitCode: 2, caps: promptHookStopsOrRedacts},
	PromptDialectZcode:         {extract: extractGenericPrompt, reply: buildZcodePromptReply, caps: promptHookStops},
	PromptDialectCascade:       {extract: extractCascadePrompt, reply: nil, blockExitCode: 2, caps: promptHookStops},
	PromptDialectCommandCode:   {extract: extractCommandCodePrompt, decodes: commandCodePromptDecodes, reply: buildCommandCodePromptReply, redact: buildCommandCodePromptRedactReply, caps: promptHookStopsOrRedacts},
	PromptDialectAntigravityPreInvocation: {
		extract: extractAntigravityPreInvocationPrompt, decodes: antigravityPreInvocationDecodes, reply: buildAntigravityPreInvocationReply,
		caps: promptAgyAbortOrWarns, capsProbe: agyPreInvocationCaps, taintsSession: true,
		oncePerPrompt: true, allowReply: agyPreInvocationReply{},
	},
	// Plugin hosts' prompt seams (through the pluginshim TS shim). The
	// session id makes the resend-to-confirm flow keyable on both. The
	// allow reply is HandleApprove's: the shim treats anything that is not
	// deny / ask / modify as an allow. Caps differ per seam, so each is its
	// own row (data, not a host branch).
	PromptDialectPluginShim:        {extract: extractPluginPrompt, reply: buildPluginPromptReply, caps: promptPluginShimStops},
	PromptDialectPluginShimConfirm: {extract: extractPluginPrompt, reply: buildPluginPromptReply, redact: buildPluginPromptRedactReply, caps: promptPluginShimConfirms},
	PromptDialectKimiCode: {
		extract: extractKimiCodePrompt, reply: nil, blockExitCode: 2, stderrReason: true,
		caps: promptHookStops, silentAllow: true,
	},
	PromptDialectDevinCLI: {
		extract: extractDevinCLIPrompt, reply: buildDevinCLIPromptReply,
		caps: guard.PromptSeamWarnOnly, allowReply: struct{}{},
	},
	// Copilot CLI userPromptSubmitted (promptcopilot.go): handled +
	// responseContent + modifiedPrompt blocks, modifiedPrompt redacts,
	// additionalContext warns the model only; exit codes never block.
	PromptDialectCopilotCLI: {
		extract: extractCopilotCLIPrompt, reply: buildCopilotCLIPromptReply, redact: buildCopilotCLIPromptRedactReply,
		caps: promptCopilotCLICaps, allowReply: promptCopilotCLIReply{},
	},
	// Cline CLI plugin beforeModel (promptclineplugin.go): stop or rewrite.
	PromptDialectClinePlugin: {
		extract: extractClinePluginPrompt, reply: buildClinePluginPromptReply, redact: buildClinePluginPromptRedactReply,
		caps: promptClinePluginCaps,
	},
	PromptDialectKiroCLI: {
		extract: extractKiroCLIPrompt, reply: buildKiroCLIPromptReply,
		caps: guard.PromptSeamWarnOnly, silentAllow: true,
	},
	// 2026-10-21 wave (docs/guard.md "Live grounding: 2026-10-21 wave").
	PromptDialectDirac: {
		extract: extractDiracPrompt, reply: buildDiracPromptReply, stderrReason: true,
		caps: promptDiracStops, silentAllow: true, oncePerPrompt: true,
	},
	PromptDialectAutohand: {
		extract: extractAutohandPrompt, reply: buildAutohandPromptReply,
		caps: promptHookStops, allowReply: struct{}{},
	},
}

// HandlePromptAllow writes dialect's allow reply (promptDialect.allowReply)
// with HandleApprove's forensics, or HandleApprove's own reply for a
// dialect that declares none (or an unknown dialect id). It is the ONE
// fallback every prompt-submit receiver path uses when it has no verdict
// to give, so a host with a strict output schema is never sent a field it
// rejects.
func HandlePromptAllow(dialect, event string, stdin io.Reader, stdout, stderr io.Writer) {
	if d, ok := promptDialects[dialect]; ok && d.silentAllow {
		handleAllow(event, stdin, stdout, stderr, nil)
		return
	}
	if d, ok := promptDialects[dialect]; ok && d.allowReply != nil {
		handleAllow(event, stdin, stdout, stderr, d.allowReply)
		return
	}
	HandleApprove(event, stdin, stdout, stderr)
}

// PromptDialectWritesStdout reports whether dialect's prompt-submit wire
// contract ever writes a stdout reply. False for the exit-code-only
// dialects with a silent allow (Kimi Code): a recovered panic there must
// leave stdout empty. Dialects without a row answer true (the generic
// approve reply).
func PromptDialectWritesStdout(dialect string) bool {
	d, ok := promptDialects[dialect]
	return !ok || !(d.silentAllow && d.reply == nil)
}

// KnownPromptDialect reports whether dialect has a row in the prompt
// dialect table (a binding naming an unknown dialect is not evaluated).
func KnownPromptDialect(dialect string) bool {
	_, ok := promptDialects[dialect]
	return ok
}

// PromptDialectSeamCaps returns dialect's prompt-seam capabilities as its
// row declares them, and probed=true when the row narrows them per
// invocation (capsProbe: the running host must prove it honours the stop,
// otherwise the seam degrades). ok=false for an unknown dialect. Coverage
// surfaces read it (controlcoverage.RuleCoverage); the handler itself uses
// the per-invocation seamCapsFor.
func PromptDialectSeamCaps(dialect string) (caps guard.PromptSeamCaps, probed, ok bool) {
	d, ok := promptDialects[dialect]
	if !ok {
		return guard.PromptSeamCaps{}, false, false
	}
	return d.caps, d.capsProbe != nil, true
}

// promptBlockReasons is FIX-5's table-driven (CLAUDE.md rule 5) map
// from a Blocked+non-Ask verdict's DegradedFrom marker to the honest,
// case-specific suffix appended after pv.Verdict.Reason. The zero key
// ("") is the operator's OWN [guard.prompt].mode="block" choice — the
// only case where "mode=\"block\" has no resend override" is actually
// true; every other key names a DIFFERENT, non-configuration reason
// the prompt blocked unconditionally, and previously all four were
// rendered with the same "you configured mode=block" text regardless
// of which one actually happened.
var promptBlockReasons = map[string]string{
	"": ". Edit it out before sending. mode=\"block\" has no resend override.",
	"unhashable": ". This finding type can't be fingerprinted for a resend override, so it blocks every time; " +
		"edit it out before sending.",
	"no_session": ". No session id was available to track a resend, so this blocks unconditionally; " +
		"edit it out before sending.",
	"store_unwired": ". The reconsider-once store isn't available right now, so this blocks unconditionally " +
		"(fail-closed). Edit it out before sending, or retry once observer is healthy.",
	// "unscanned" (FIX-2's truncated/field-missing degrade under
	// mode=block): the Reason itself is already the complete,
	// self-explanatory message — no generic suffix needed.
	"unscanned": "",
	// guard.DegradedFromTaintedSession: the reason already says why and
	// what to do (start a new conversation).
	guard.DegradedFromTaintedSession: ".",
}

// promptAskStoppedSuffix closes an ask on a seam that could only stop the
// prompt (no confirm, no resend-to-confirm: agy's atomic abort), so the
// developer is not told to resend something that would be stopped again.
const promptAskStoppedSuffix = ". This tool cannot ask before the model call, so the prompt was stopped; " +
	"edit it out and send it in a new conversation."

// promptRemediationDetector picks the ONE detector id to name in the
// in-band "run `observer guard prompt allow <detector> --session <id>`"
// remediation text (F6, phase-3a review) from PromptVerdict.Detectors'
// sorted CSV — the first (alphabetically earliest) type when more than
// one detector drove the interrupt. A copy-pasteable command can only
// name one detector at a time; the appended rule-class clause below
// tells the developer the grant isn't actually limited to just this
// one anyway.
func promptRemediationDetector(csv string) string {
	if i := strings.IndexByte(csv, ','); i >= 0 {
		return csv[:i]
	}
	return csv
}

// promptHouseMessage renders the house-style, human-facing message
// (contract §7) from an already-evaluated PromptVerdict — one style
// across every dialect, never vendor-specific text, never the model's
// audience (contrast guardDenyBody's agent-facing framing,
// internal/proxy/guard.go).
//
// sessionID is the SAME session id the caller extracted from the raw
// hook payload (HandlePromptSubmitGuarded's own `sessionID`) — F6
// (phase-3a review): the ask-once branch below used to emit the
// literal, non-functional placeholder text "observer guard prompt
// allow <detector> --session" (no actual detector id, no actual
// session id, and missing the --session flag's own argument
// entirely). It now interpolates the REAL values so a developer can
// copy-paste a working command, and states plainly that the grant
// covers the whole rule class, not just the one detector named (see
// promptRuleIDForDetector / the `allow` command's own help text,
// cmd/observer/guard_prompt.go — allowing is by RULE, github_pat and
// every other secret-class detector share R-172, credit_card and
// every other PII-class detector share R-190).
func promptHouseMessage(pv guard.PromptVerdict, sessionID string) string {
	reason := pv.Verdict.Reason
	if pv.Action == guard.PromptActionRedact {
		return "observer: " + reason + ". The value was replaced with a [REDACTED] marker before the prompt reached the model."
	}
	switch pv.Outcome {
	case guard.PromptOutcomeBlocked:
		if guard.IsBudgetRule(pv.Verdict.RuleID) {
			// A managed budget stop (T-519): the reason already names the
			// budget, the spend and the request flow. Nothing in the prompt
			// caused it, so no "edit it out" or resend suffix applies.
			return "observer: " + reason
		}
		if pv.Verdict.Decision == policy.DecisionAsk && pv.Action == guard.PromptActionBlock {
			// The seam could not ask (promptaction.go's ask ladder fell
			// through confirm and re-enter to block): no resend story.
			return "observer: " + reason + promptAskStoppedSuffix
		}
		if pv.Verdict.Decision == policy.DecisionAsk {
			detector := promptRemediationDetector(pv.Detectors)
			if detector == "" {
				detector = "<detector>"
			}
			if sessionID == "" {
				sessionID = "<session>"
			}
			if pv.DegradedFrom == "retry_too_fast" {
				// The resend landed inside reconsider_min_delay — most likely
				// the client's own retry, but a fast human gets the same
				// verdict, so tell them what to do (F2, retry-floor review).
				return "observer: " + reason + ". That resend arrived too fast to count as your confirmation. Wait a moment and send it again unchanged to confirm, or edit it out."
			}
			// how names the confirm the seam offers: a native dialog
			// (which falls back to a resend where the host has no UI) or
			// the resend itself.
			how := "Send it again unchanged to confirm, or edit it out. "
			if pv.Action == guard.PromptActionConfirm {
				how = "Confirm to send it anyway, or cancel and edit it out (where no confirm dialog can open, send it again unchanged to confirm). "
			}
			return "observer: " + reason + ". " + how +
				"Run `observer guard prompt allow " + detector + " --session " + sessionID +
				"` to stop asking (this allows every detector in the same rule class, not just " + detector + ")."
		}
		// FIX-5 (phase-2 review): every non-Ask Blocked verdict
		// previously got the SAME "mode=\"block\" has no resend
		// override" suffix even when the actual cause was an
		// unhashable finding, a missing session id, an unwired
		// reconsider store, or an oversize/schema-drift-degraded
		// scan under mode=block — none of which is "you configured
		// mode=block". Branch on the DegradedFrom marker those
		// producers now set (internal/guard/promptguard.go).
		// Sol A2-10: an org-overridable deny tells the developer how to
		// override it (the shared guard rendering), never "edit it out".
		if hint := guard.PromptOverrideHint(pv, sessionID); hint != "" {
			return "observer: " + reason + hint
		}
		suffix, ok := promptBlockReasons[pv.DegradedFrom]
		if !ok {
			suffix = promptBlockReasons[""]
		}
		// Request-grants G4: an org-locked block leads with the request
		// line (rule, link to the prefilled request form, CLI command) so
		// it survives a host or display that shows only the start.
		if hint := guard.PromptRequestAccessHint(pv, sessionID); hint != "" {
			return "observer: " + hint + " Reason: " + reason + suffix
		}
		return "observer: " + reason + suffix
	case guard.PromptOutcomeWarned:
		if pv.OrgCapped {
			return "observer: " + reason + " (sent: your organization set this rule to warn only; see `observer guard prompt status`)."
		}
		return "observer: " + reason + " (forwarded; see `observer guard prompt status`)."
	default:
		return reason
	}
}

// promptRedactor is the optional evaluator capability a redact-capable
// dialect uses (guard.Guard implements it): mask every secret in a prompt
// and confirm the masked text rescans clean.
type promptRedactor interface {
	RedactPromptText(text string) (masked string, ok bool)
}

// promptRedactOffer returns the capabilities the decision table may use
// for this prompt: the dialect's own, with Redact kept only when the
// dialect can rewrite the prompt AND the guard masked it completely (a
// secret-only finding set, a complete scan, a masked text that rescans
// clean). Anything less withdraws Redact, so the table falls back to the
// dialect's other actions rather than forwarding a half-masked prompt.
func promptRedactOffer(d promptDialect, ge PromptEvaluator, prompt string, secrets []policy.SecretFinding, pii []policy.PIIFinding, complete bool) (guard.PromptSeamCaps, string) {
	caps := d.caps
	if !caps.Redact {
		return caps, ""
	}
	caps.Redact = false
	if d.redact == nil || !complete || len(pii) > 0 || len(secrets) == 0 {
		return caps, ""
	}
	r, ok := ge.(promptRedactor)
	if !ok {
		return caps, ""
	}
	masked, ok := r.RedactPromptText(prompt)
	if !ok {
		return caps, ""
	}
	caps.Redact = true
	return caps, masked
}

// HandlePromptSubmitGuarded is the ONE shared prompt-submit hook seam
// (Part B item 1): extract the raw prompt text + session id at the
// boundary via the dialect table, run
// BuildPromptFindings → EvaluatePrompt → guard.ResolveEmission, and
// shape the reply through the dialect's own builder.
//
// tool is the models.ToolXxx id (the conformance-matrix lookup key and
// the Event.Tool/audit stamp); dialect is the WIRE SHAPE key from the
// table above; event is the conformance channel suffix ("hook:" +
// event is the CapabilitiesFor lookup, matching every other channel's
// convention).
//
// Returns handled=false when the dialect is unknown, ge is nil (guard
// not constructed — fail-open, mirrors HandleGuarded), or the payload
// doesn't parse for this dialect — the caller then falls through to
// its normal unguarded reply exactly as it did before this seam
// existed. recordAfterReply mirrors HandleGuarded's reply-then-persist
// contract: nil unless the verdict is record-worthy, and MUST be
// called only AFTER the reply already went out (persist is nil-tolerant
// and invoked at most once).
//
// stderr receives the same forensics line and hook-events.jsonl row
// every other guarded channel writes on a non-allow verdict
// (HandleGuarded / handleCursorPromptSubmit's own logForensics —
// round-2 phase-2-review NIT: prompt blocks previously left no
// crash-window forensics trail at all, unlike every other guarded
// channel) — EXCEPT a stderrReason dialect (Qoder, Claude Code), whose forensics
// line is suppressed from stderr (file-only) because that dialect's
// stderr is the vendor's own user-visible reason channel; see
// promptDialect.stderrReason's doc comment.
//
// exitCode (Part B item 2) is the process exit code the CALLER should
// return via os.Exit AFTER invoking recordAfterReply() — 0 for the
// JSON-only dialects (Cursor, zcode, commandcode: the stdout reply is
// the entire wire contract); non-zero only for a dialect whose
// blockExitCode is set AND the outcome is Blocking (Qoder, Poolside,
// Devin/Cascade, and — since the 2026-09-07 live correction — Claude
// Code; see promptDialect.blockExitCode).
//
// bodyTruncated (B2, final-fix review) is true when the CALLER's own
// stdin read hit its byte limit — the raw payload on the wire was
// longer than what body actually holds (see
// cmd/observer's readHookBodyDetectTruncation). Before this fix, a
// truncated body almost always failed d.extract's json.Unmarshal
// (cut off mid-object), which returned handled=false and sent the
// caller down its normal UNGUARDED fallback reply — a plain approve
// with no scan, no warning, and no audit trail for a payload that,
// past observer's own 2 MiB stdin bound, could carry an unbounded
// secret or PII value with zero guard visibility. bodyTruncated now
// keeps this function IN the guarded path even when extraction fails,
// routing through the same ev.PromptTruncated degrade FIX-2 already
// built for an oversize prompt TEXT (see below) — the caller no
// longer silently bypasses the guard just because the JSON envelope
// around the prompt didn't fit.
//
// A payload this returns handled=false for because it does not decode as
// the dialect's shape (PromptPayloadUndecodable) must fail closed in the
// caller under guard enforcement (FU-161); its unguarded allow is only for
// a guard that is not enforcing.
func HandlePromptSubmitGuarded(
	tool, dialect, event string,
	body []byte,
	bodyTruncated bool,
	ge PromptEvaluator,
	persist func(pv guard.PromptVerdict, em guard.Emission, sessionID string),
	stdout, stderr io.Writer,
) (handled bool, recordAfterReply func(), exitCode int) {
	if ge == nil {
		return false, nil, 0
	}
	d, dialectOK := promptDialects[dialect]
	if !dialectOK {
		return false, nil, 0
	}
	// A leading UTF-8 BOM (a .NET / PowerShell stdin writer's) never makes
	// the payload read as another shape (FU-161).
	body = bytes.TrimPrefix(body, utf8BOM)
	prompt, sessionID, extractOK, fieldMissing := d.extract(body)
	// A conversation that still carries a stopped prompt is stopped again
	// before anything else (taintsSession): the host resends that prompt
	// with this turn whatever the turn's own text is.
	if pv, tainted := taintedSessionVerdict(tool, d, ge, sessionID); tainted {
		return finishPromptVerdict(tool, event, d, body, sessionID, pv, "", persist, stdout, stderr)
	}
	if !extractOK && !bodyTruncated {
		// A genuinely unrecognized/malformed payload, unrelated to
		// observer's own read bound — fall through to the caller's
		// normal unguarded reply, exactly as before this fix.
		return false, nil, 0
	}

	caps, _ := guard.CapabilitiesFor(tool, "hook:"+event)

	// extractOK is false exactly when bodyTruncated forced us past the
	// early return above — prompt/sessionID are then both "" (nothing
	// to scan, no session to key a fingerprint on), so BuildPromptFindings
	// is skipped rather than run over an empty string.
	var secrets []policy.SecretFinding
	var pii []policy.PIIFinding
	scanTruncated := false
	if extractOK {
		secrets, pii, scanTruncated = ge.BuildPromptFindings(prompt)
	}
	if d.oncePerPrompt && extractOK && !scanTruncated &&
		repeatSeamNothingNew(ge, sessionID, prompt, len(secrets)+len(pii)) {
		// The dialect's own nothing-to-say reply (a builder returning nil
		// for it, Dirac's silent allow, writes nothing).
		writePromptReply(d, promptReplyOutcome{}, stdout)
		return true, nil, 0
	}

	ev := policy.Event{
		Kind:        policy.KindUserPrompt,
		Tool:        tool,
		SessionID:   sessionID,
		Caps:        caps,
		Secrets:     secrets,
		PIIFindings: pii,
		// bodyTruncated folds into the same PromptTruncated signal as
		// scanTruncated (BuildPromptFindings' own scrub-level bound) —
		// either one means the guard could not see the whole prompt,
		// and both degrade identically (guard.degradedScanVerdict):
		// warn under every mode except block, hard deny under
		// mode=block. Never silently "scanned clean".
		PromptTruncated:    scanTruncated || bodyTruncated,
		PromptFieldMissing: fieldMissing,
		Now:                time.Now().UTC(),
	}
	// The one decision x capability table (guard/promptaction.go): the
	// dialect row's caps decide what the developer gets for this
	// decision, and the emission reports exactly that. A redact-capable
	// dialect offers Redact only when the guard can mask THIS prompt
	// completely (promptRedactOffer).
	d.caps = d.seamCapsFor()
	seamCaps, masked := promptRedactOffer(d, ge, prompt, secrets, pii, extractOK && !scanTruncated && !bodyTruncated)
	pv := ge.EvaluatePrompt(ev).WithAction(seamCaps, "hook")
	if extractOK {
		// The pre-send mark the post-hoc capture lane dedupes on
		// (guard/posthocprompt.go): carried to the one guard_events
		// writer on the persisted verdict.
		pv.CaptureDigest = guard.PromptPreSendDigest(prompt, pv.RecordWorthy())
	}
	return finishPromptVerdict(tool, event, d, body, sessionID, pv, masked, persist, stdout, stderr)
}

// finishPromptVerdict writes the dialect's reply for a resolved prompt
// verdict, the forensics for a block, and returns HandlePromptSubmitGuarded's
// results (the persist closure for a record-worthy or mark-carrying verdict,
// and the dialect's block exit code).
func finishPromptVerdict(
	tool, event string,
	d promptDialect,
	body []byte,
	sessionID string,
	pv guard.PromptVerdict,
	masked string,
	persist func(pv guard.PromptVerdict, em guard.Emission, sessionID string),
	stdout, stderr io.Writer,
) (handled bool, recordAfterReply func(), exitCode int) {
	em := guard.PromptEmission(pv)
	out := promptOutcomeFor(pv, sessionID, masked)
	writePromptReply(d, out, stdout)
	switch {
	case d.stderrReason && out.Blocking:
		// A block's reason carries the StderrBlockHeader line (DEC-1).
		WriteStderrBlockReason(stderr, out.Reason)
	case d.stderrReason && out.Warn:
		// A warning is not a block: its notice stays verbatim.
		fmt.Fprintln(stderr, out.Reason)
	}
	if out.Blocking && d.blockExitCode != 0 {
		exitCode = d.blockExitCode
	}

	if out.Blocking {
		action := "guard:" + em.Permission
		if !d.stderrReason {
			fmt.Fprintf(stderr, "observer-hook: %s:%s prompt-submit guard %s (%s: %s)\n",
				tool, event, em.Permission, pv.Verdict.RuleID, pv.Verdict.Reason)
		}
		appendHookEventLog(hookEvent{
			Event:        tool + ":" + event,
			Bytes:        len(body),
			SessionID:    sessionID,
			Tool:         tool,
			Action:       action,
			RuleID:       pv.Verdict.RuleID,
			Decision:     pv.Verdict.Decision.String(),
			Severity:     pv.Verdict.Severity.String(),
			DegradedFrom: em.DegradedFrom,
		})
	}

	if !pv.RecordWorthy() {
		if pv.CaptureDigest == "" || sessionID == "" {
			return true, nil, exitCode
		}
		// Nothing to audit, but the stored form of this prompt will carry
		// a typed redaction marker (e.g. an allow-listed fixture): persist
		// a MARK-ONLY verdict (no rule id) so the capture lane does not
		// flag afterwards what this lane deliberately let through.
		// store.PersistGuardVerdicts writes the mark and no guard_events
		// row; MaybeAlert ignores a verdict with no rule id.
	}
	return true, func() {
		if persist != nil {
			persist(pv, em, sessionID)
		}
	}, exitCode
}

// promptOutcomeFor maps a resolved prompt verdict onto the reply outcome
// a dialect builder consumes. masked is carried only on a redact.
func promptOutcomeFor(pv guard.PromptVerdict, sessionID, masked string) promptReplyOutcome {
	out := promptReplyOutcome{
		Blocking:    pv.Action.Stops(),
		Confirmable: pv.Action == guard.PromptActionReenter || pv.Action == guard.PromptActionConfirm,
		Warn:        pv.Action == guard.PromptActionWarn,
		Redacted:    pv.Action == guard.PromptActionRedact,
	}
	if out.Blocking || out.Warn || out.Redacted {
		out.Reason = promptHouseMessage(pv, sessionID)
	}
	if out.Redacted {
		out.Masked = masked
	}
	return out
}

// writePromptReply encodes the dialect's stdout reply for out: the redact
// builder on a redact, the reply builder otherwise. A builder may return
// nil for an outcome its vendor signals WITHOUT a stdout reply (Claude
// Code's exit-2 block); an encoded `null` would be a malformed hook
// reply, so it is skipped.
func writePromptReply(d promptDialect, out promptReplyOutcome, stdout io.Writer) {
	builder := d.reply
	if out.Redacted {
		builder = d.redact
	}
	if builder == nil {
		return
	}
	r := builder(out)
	if text, ok := r.(plainTextReply); ok {
		_, _ = fmt.Fprintln(stdout, string(text))
		return
	}
	if r != nil {
		_ = json.NewEncoder(stdout).Encode(r)
	}
}
