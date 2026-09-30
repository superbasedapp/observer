package cursorusage

import (
	"fmt"
	"strings"
)

// Row identity shared by the writer (internal/adapter/cursor, the
// cursor-agent debug-log reader) and the readers (store seam, doctor). A
// reader matches on these, never on free text.
const (
	// SourceEventTurnPrefix prefixes the SourceEventID of a turn_aborted
	// row recorded from the cursor-agent debug log: a turn that never
	// finished, or finished with an error / cancellation.
	SourceEventTurnPrefix = "cursor-cli-turn:"
	// SourceEventAttemptPrefix prefixes the SourceEventID of an api_error
	// row for one failed cursor-agent request attempt.
	SourceEventAttemptPrefix = "cursor-cli-attempt:"
	// RawToolTurnUnfinished is the RawToolName of a turn that was still
	// running (or retrying) when the cursor-agent process ended.
	RawToolTurnUnfinished = "cursor_cli.turn_unfinished"
	// RawToolTurnFailedPrefix prefixes the RawToolName of a turn whose
	// logged outcome was not success (cursor_cli.turn_error,
	// cursor_cli.turn_cancelled, ...).
	RawToolTurnFailedPrefix = "cursor_cli.turn_"
	// RawToolResponseHook is the RawToolName of an assistant row written
	// from Cursor's afterAgentResponse hook (the live hook and the IDE
	// hooks-log replay share it).
	RawToolResponseHook = "afterAgentResponse"
)

// Evidence is what the store knows about a Cursor session that has no
// token_usage rows. Zero value = nothing recorded.
type Evidence struct {
	// Prompts counts user_prompt rows (beforeSubmitPrompt hook).
	Prompts int
	// ResponseHooks counts assistant rows written from afterAgentResponse.
	ResponseHooks int
	// UnfinishedTurns counts turns still running when the CLI exited.
	UnfinishedTurns int
	// FailedTurns counts turns whose logged outcome was not success.
	FailedTurns int
	// FailedAttempts counts failed request attempts (api_error rows from
	// the cursor-agent debug log), including ones a retry later healed.
	FailedAttempts int
	// LatestTurnDetail is the error_message of the most recent
	// turn_aborted row from the debug log ("" when none). It already
	// names the attempts and which hooks fired.
	LatestTurnDetail string
	// FinishHooks is the registration state of the hooks that carry usage
	// (FinishHookEvents) on the node that captured the session. Tally never
	// sets it: a loader that can read the node's hooks.json fills it in
	// (the doctor, the node dashboard); a reader that cannot (the org
	// drawer) leaves the zero value, HookWiringUnknown, and the note then
	// says what it cannot know instead of guessing.
	FinishHooks HookWiring
}

// FinishHookEvents are the Cursor hook events that carry usage: Cursor fires
// them only when a turn finishes. A loader reports whether all of them are
// registered as Evidence.FinishHooks.
var FinishHookEvents = []string{"stop", RawToolResponseHook}

// HookWiring is whether FinishHookEvents are registered through the
// observer registrar on the capturing node. It changes the REMEDY, never the
// evidence: re-registering is advice only when they are not registered.
type HookWiring int

const (
	// HookWiringUnknown is the zero value: the reader cannot see the
	// node's hooks.json (the org drawer).
	HookWiringUnknown HookWiring = iota
	// HookWiringComplete means every finish hook is registered.
	HookWiringComplete
	// HookWiringIncomplete means at least one finish hook is not
	// registered (or no hooks.json exists).
	HookWiringIncomplete
)

// Reason is the single explanation Classify picks.
type Reason string

// The reasons, in rule-table order.
const (
	ReasonUnfinishedTurn       Reason = "unfinished_turn"
	ReasonFailedTurn           Reason = "failed_turn"
	ReasonResponseWithoutUsage Reason = "response_without_usage"
	ReasonFinishHooksSilent    Reason = "finish_hooks_silent"
	ReasonFinishHooksMissing   Reason = "finish_hooks_unregistered"
	ReasonNoFinishHook         Reason = "no_finish_hook"
	ReasonNoEvidence           Reason = "no_evidence"
)

// noFinishHookLead is the evidence sentence the three no-finish-hook rows
// share; only the cause and remedy differ with the registration state.
func noFinishHookLead(e Evidence) string {
	return fmt.Sprintf("Token usage was not captured for this Cursor session: %s recorded, but neither Cursor's stop nor afterAgentResponse hook arrived and no turn outcome was found in the cursor-agent log.", plural(e.Prompts, "prompt was", "prompts were"))
}

const unknownNotZero = "Input, output, cache counts and cost are unknown, not zero."

// rule is one row of the ordered explanation table: the first row whose
// match holds wins. Adding a cause is adding a row, never a branch.
type rule struct {
	reason Reason
	match  func(Evidence) bool
	note   func(Evidence) string
	remedy string
}

var rules = []rule{
	{
		reason: ReasonUnfinishedTurn,
		match:  func(e Evidence) bool { return e.UnfinishedTurns > 0 },
		note: func(e Evidence) string {
			return joinSentences(
				fmt.Sprintf("Token usage was not captured for this Cursor session: %s never finished, so Cursor never reported the usage.", plural(e.UnfinishedTurns, "turn", "turns")),
				e.LatestTurnDetail,
				unknownNotZero,
			)
		},
		remedy: "let a turn finish (or press Esc to abort it) before quitting cursor-agent - Cursor reports usage only for a finished or aborted turn",
	},
	{
		reason: ReasonFailedTurn,
		match:  func(e Evidence) bool { return e.FailedTurns > 0 },
		note: func(e Evidence) string {
			return joinSentences(
				fmt.Sprintf("Token usage was not captured for this Cursor session: %s ended without a successful outcome and Cursor reported no usage for it.", plural(e.FailedTurns, "turn", "turns")),
				e.LatestTurnDetail,
				unknownNotZero,
			)
		},
		remedy: "the turn failed upstream (see the api_error rows); nothing to change locally",
	},
	{
		reason: ReasonResponseWithoutUsage,
		match:  func(e Evidence) bool { return e.ResponseHooks > 0 },
		note: func(e Evidence) string {
			return joinSentences(
				fmt.Sprintf("Token usage was not captured for this Cursor session: Cursor's afterAgentResponse hook arrived for %s but carried no usage fields, which some Cursor builds omit.", plural(e.ResponseHooks, "response", "responses")),
				unknownNotZero,
			)
		},
		remedy: "update Cursor; this build sends afterAgentResponse without input_tokens / output_tokens",
	},
	{
		// Hooks registered, yet neither fired: the turn most likely never
		// finished. Re-registering would change nothing, so the remedy
		// must not say so (live finding D4, 2026-09-28).
		reason: ReasonFinishHooksSilent,
		match:  func(e Evidence) bool { return e.Prompts > 0 && e.FinishHooks == HookWiringComplete },
		note: func(e Evidence) string {
			return joinSentences(
				noFinishHookLead(e),
				"Both hooks are registered, and Cursor fires them only when a turn finishes, so the turn most likely never finished (cursor-agent or the window was closed mid-answer) or this Cursor build did not fire them.",
				unknownNotZero,
			)
		},
		remedy: "stop and afterAgentResponse are registered, so re-running `observer init --cursor` changes nothing: the turn most likely never finished (let it finish, or press Esc to abort it, before quitting cursor-agent) or Cursor did not fire those hooks",
	},
	{
		reason: ReasonFinishHooksMissing,
		match:  func(e Evidence) bool { return e.Prompts > 0 && e.FinishHooks == HookWiringIncomplete },
		note: func(e Evidence) string {
			return joinSentences(
				noFinishHookLead(e),
				"Cursor's stop and afterAgentResponse hooks are not both registered on this machine; run `observer init --cursor` to register them.",
				unknownNotZero,
			)
		},
		remedy: "run `observer init --cursor` so stop and afterAgentResponse are registered, and keep the daemon running so the cursor-agent debug log is tailed",
	},
	{
		// The reader cannot see the node's hooks.json (the org drawer):
		// say both causes, claim neither.
		reason: ReasonNoFinishHook,
		match:  func(e Evidence) bool { return e.Prompts > 0 },
		note: func(e Evidence) string {
			return joinSentences(
				noFinishHookLead(e),
				"Cursor fires those only when a turn finishes, so the turn most likely never finished; if it did, run `observer doctor cursor` on that machine to check the hook wiring.",
				unknownNotZero,
			)
		},
		remedy: "run `observer doctor cursor` on the capturing machine: if stop and afterAgentResponse are registered the turn most likely never finished, otherwise `observer init --cursor` registers them",
	},
	{
		reason: ReasonNoEvidence,
		match:  func(Evidence) bool { return true },
		note: func(Evidence) string {
			return joinSentences(
				"Token usage was not captured for this Cursor session, and no prompt or turn record says why.",
				unknownNotZero,
			)
		},
		remedy: "run `observer doctor cursor`",
	},
}

// Classify returns the first matching reason.
func Classify(e Evidence) Reason {
	return pick(e).reason
}

// Explain renders the banner text for a Cursor session with no usage.
// contextBudget > 0 appends that the context figure is an estimate.
func Explain(e Evidence, contextBudget int64) string {
	n := pick(e).note(e)
	if contextBudget > 0 {
		n += " The context figure is Cursor's own count of prompt size, not billed usage."
	}
	return n
}

// Remedy returns the operator action for a reason ("" for an unknown one).
func Remedy(r Reason) string {
	for _, row := range rules {
		if row.reason == r {
			return row.remedy
		}
	}
	return ""
}

func pick(e Evidence) rule {
	for _, row := range rules {
		if row.match(e) {
			return row
		}
	}
	return rules[len(rules)-1]
}

func plural(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return fmt.Sprintf("%d %s", n, many)
}

func joinSentences(parts ...string) string {
	var out []string
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if !strings.HasSuffix(p, ".") {
			p += "."
		}
		out = append(out, p)
	}
	return strings.Join(out, " ")
}
