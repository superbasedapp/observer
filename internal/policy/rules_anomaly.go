package policy

import "strconv"

// Anomaly rules (spec §5.7, §12.2). G12 ships A-610 (stuck-loop
// detection over the guard layer's consecutive-identical-action
// tracker). A-611 (MAD z-score rate anomaly vs per-project baselines)
// and A-612 (first-ever-seen action-type novelty) need the
// per-project baseline plumbing in internal/intelligence and are
// deferred with reason — recorded in the spec §22 tracker, never
// silently stubbed.
//
// Anomaly NEVER denies (§12.2, the F6 principle: statistical signals
// don't get enforcement authority) — A-610 is flag in both modes.

// repeatLoopThreshold is the A-610 consecutive-identical run length
// past which the row fires: the 9th identical action in a row flags.
// The value is deliberately above common legitimate retry counts
// (formatters re-run 2-3×, flaky-test retries 3-5×); a tool that
// legitimately repeats more is tuned via [guard.rules] disable or a
// user rule with repeat_count_gt (§4.4).
const repeatLoopThreshold = 8

// matchRepeatLoop fires exactly once per stuck-loop episode: on the
// CROSSING event (RepeatCount == threshold+1), not on every repeat
// after it — a 50-iteration loop is one finding, not 42. A new
// episode (the run resets, then repeats again) fires again. User
// repeat_count_gt matchers use strict-greater semantics instead and
// re-match each repeat — their decision, documented in the matcher
// reference.
func matchRepeatLoop(ctx *MatchContext) (bool, string) {
	if ctx.Event.RepeatCount != repeatLoopThreshold+1 {
		return false, ""
	}
	return true, "identical " + ctx.Event.ActionType + " repeated " +
		strconv.Itoa(ctx.Event.RepeatCount) + "× consecutively (stuck loop shape)"
}

// matchEvasion is A-613 (D-761, security pillar plan section 5.2): after a
// deny, the agent kept trying the same denied thing in other shapes (the
// JSP-6 live half saw a model reword a denied commit twice in one turn).
// A-610 catches only identical repeats. The guard layer stamps the event
// (Event.EvasionOf, Event.EvasionShapes) on the watcher ingest path; the
// row is inert without the stamp, which is the default.
func matchEvasion(ctx *MatchContext) (bool, string) {
	ev := ctx.Event
	if ev.EvasionOf == "" || ev.EvasionShapes < 1 {
		return false, ""
	}
	return true, "after " + ev.EvasionOf + " refused an action in this session, " +
		strconv.Itoa(ev.EvasionShapes) + " differently shaped attempt(s) hit the same rule"
}

// anomalyRules assembles the shipped §5.7 anomaly rows.
func anomalyRules() []Rule {
	return []Rule{
		{
			ID: "A-610", Category: CategoryAnomaly, Severity: SeverityWarn,
			AppliesTo: []EventKind{KindShellExec, KindFileAccess, KindMCPCall, KindToolCall},
			Match:     matchRepeatLoop,
			Observe:   DecisionFlag, Enforce: DecisionFlag,
			Doc:    "identical tool call repeated consecutively past the stuck-loop threshold",
			Advice: "The agent is likely looping on a failing action; check the session timeline and interrupt the run if it isn't converging.",
		},
		{
			ID: "A-613", Category: CategoryAnomaly, Severity: SeverityHigh,
			AppliesTo: []EventKind{KindShellExec, KindFileAccess, KindMCPCall, KindToolCall},
			Match:     matchEvasion,
			Observe:   DecisionFlag, Enforce: DecisionFlag,
			Doc:    "repeated attempts at a denied action in different shapes (policy evasion, opt-in)",
			Advice: "The agent is trying to get around a guard refusal. Read the refusal it received and the session timeline; stop the run if it does not change course.",
		},
	}
}
