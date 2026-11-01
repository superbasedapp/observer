package guard

import (
	"fmt"

	"github.com/marmutapp/superbased-observer/internal/policy"
)

// Stopped-conversation taint (guard-enforcement fix, 2026-10-15). Some
// prompt seams stop a prompt by aborting the turn, while the host KEEPS the
// stopped prompt in the conversation and resends it with every later turn
// (Antigravity CLI's PreInvocation abort: the USER_INPUT step stays in the
// transcript). Judging only the latest prompt would then let the stopped
// value reach the model on the very next turn. A seam that declares this
// (internal/hook promptDialect.taintsSession) asks PromptSessionStopped
// first and, on a hit, stops every later turn of that conversation with
// TaintedSessionPromptVerdict, telling the developer to start a new one.
//
// The taint is not a new table: it is the guard_events row the first stop
// already wrote (an enforced ask/deny user_prompt verdict for the same tool
// and session), read through the injected lookup, so it lives exactly as
// long as the audit record does.

// PromptSessionStop is the most recent prompt Observer stopped in one
// conversation: the rule that stopped it and that rule's severity (the
// guard_events severity string).
type PromptSessionStop struct {
	RuleID   string
	Severity string
}

// PromptSessionStopLookup returns the prompts a pre-send prompt lane
// already STOPPED (an enforced ask or deny) in sessionID for tool, newest
// first. Wired at composition to store.PromptSessionStops; guard never
// imports store (the ApprovalLookup precedent). A lookup failure returns
// nothing: the turn is then judged on its own prompt, which is the
// pre-taint behaviour, never a new hard stop on an unreadable store.
type PromptSessionStopLookup func(tool, sessionID string) []PromptSessionStop

// SetPromptSessionStopLookup wires the stopped-conversation lookup.
func (g *Guard) SetPromptSessionStopLookup(fn PromptSessionStopLookup) {
	g.promptSessionStop = fn
}

// PromptSessionStopped reports whether a prompt was already stopped in
// sessionID for tool because of its CONTENT, and returns the newest such
// stop. A managed-budget stop and a fail-closed guard error are skipped:
// neither says anything about the prompt the conversation carries, so
// neither taints (the next turn is judged on its own). False without a
// wired lookup or a session id.
func (g *Guard) PromptSessionStopped(tool, sessionID string) (PromptSessionStop, bool) {
	if g.promptSessionStop == nil || sessionID == "" {
		return PromptSessionStop{}, false
	}
	return firstContentStop(g.promptSessionStop(tool, sessionID))
}

// firstContentStop returns the first stop in stops that judged the prompt's
// content (not a budget rule, not a guard error).
func firstContentStop(stops []PromptSessionStop) (PromptSessionStop, bool) {
	for _, s := range stops {
		if s.RuleID != "" && s.RuleID != GuardErrorRuleID && !IsBudgetRule(s.RuleID) {
			return s, true
		}
	}
	return PromptSessionStop{}, false
}

// DegradedFromTaintedSession marks a prompt verdict that stopped a turn
// because its conversation still carries an earlier stopped prompt, not
// because of the turn's own text.
const DegradedFromTaintedSession = "tainted_session"

// taintedSessionReason is the house text for such a stop; %s is the rule
// that stopped the earlier prompt.
const taintedSessionReason = "This conversation still carries a prompt Observer stopped earlier (rule %s), " +
	"and the agent resends the whole conversation with every turn, so every turn of it is stopped. " +
	"Start a new conversation"

// TaintedSessionPromptVerdict is the verdict for a turn of a conversation
// that still carries a stopped prompt: a deny of the rule that stopped it
// (its own severity; high when the stored one does not parse), outcome
// blocked, marked DegradedFromTaintedSession. The caller resolves the seam
// action through WithAction like any other prompt verdict.
func TaintedSessionPromptVerdict(stop PromptSessionStop) PromptVerdict {
	sev, err := policy.ParseSeverity(stop.Severity)
	if err != nil {
		sev = policy.SeverityHigh
	}
	return PromptVerdict{
		Verdict: policy.Verdict{
			RuleID:   stop.RuleID,
			Decision: policy.DecisionDeny,
			Severity: sev,
			Reason:   fmt.Sprintf(taintedSessionReason, stop.RuleID),
			Source:   policy.SourceBuiltin,
		},
		Outcome:      PromptOutcomeBlocked,
		DegradedFrom: DegradedFromTaintedSession,
	}
}
