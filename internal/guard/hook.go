package guard

import (
	"time"

	"github.com/marmutapp/superbased-observer/internal/policy"
)

// Hook-path (pre-execution) evaluation seam (guard spec §3.2 seam 1,
// §6). The hook handler builds a policy.Event from the client payload
// at ITS boundary (per-client extraction lives in internal/hook),
// calls EvaluateHook, resolves the client-appropriate emission via
// ResolveEmission, writes the decision to stdout FIRST, and persists
// the verdict afterwards (spec §6.4: reply before persist).
//
// Unlike the watcher seam, the hook path takes NO taint side-effects:
// a pre-execution event hasn't produced results yet (a WebFetch that
// hasn't run has fetched nothing). The watcher marks taint post-hoc
// when results exist; the hook path only CONSUMES the snapshot. Note
// the hook process is short-lived — its tracker is empty, so taint
// rules are effectively watcher-path-only until a shared-state
// channel exists (documented limitation; the daemon-resident proxy
// seam in G9 evaluates with live state).

// Evaluator is the hook handler's view of the guard: one evaluation
// seam, no policy internals (spec §17.2 — hot paths hold only
// Event/Verdict/Capabilities plus this package's plain result types).
// *Guard implements it; hook tests stub it.
type Evaluator interface {
	// EvaluateHook evaluates one pre-execution event. recordWorthy
	// reports whether the verdict should persist (decision >= flag,
	// or a guard_error wrapper verdict).
	EvaluateHook(ev policy.Event) (v ActionVerdict, recordWorthy bool)
}

// EvaluateHook implements Evaluator: stamps the session's taint
// snapshot, evaluates through the Q2 failure wrapper, and shapes the
// result for persistence. The returned ActionVerdict carries no
// ActionID (pre-execution: the action row doesn't exist yet — the
// guard_events anchor stays NULL on this path).
func (g *Guard) EvaluateHook(ev policy.Event) (ActionVerdict, bool) {
	if ev.Now.IsZero() {
		ev.Now = time.Now().UTC()
	}
	ev.Taint = g.taint.Snapshot(ev.SessionID, 0, ev.Now)
	// One snapshot for the evaluate+categorize pair (NIT contract).
	es := g.set.Load()
	verdict, guardErr := g.evaluateWith(es, ev)
	verdict, approved := g.applyApprovals(verdict, &ev)
	av := ActionVerdict{
		Input: ActionInput{
			SessionID:   ev.SessionID,
			ProjectRoot: ev.ProjectRoot,
			Tool:        ev.Tool,
			ActionType:  ev.ActionType,
			Target:      ev.Target,
			Timestamp:   ev.Now,
		},
		Kind:        ev.Kind,
		Category:    g.categoryWith(es, verdict.RuleID),
		Verdict:     verdict,
		TaintOrigin: taintOriginFor(verdict, ev.Taint),
		GuardError:  guardErr != nil,
	}
	g.stampOrgOverride(es, &av)
	if approved {
		// The grant is an audited exception: the row records what the
		// verdict WAS downgraded from (§14.4 exception register).
		av.DegradedFrom = "approved"
	}
	return av, verdict.Decision >= policy.DecisionFlag || guardErr != nil
}

// Emission is the client-facing decision resolved from a verdict +
// channel capabilities (spec §6.2). Permission is the tri-state the
// client protocols speak; DegradedFrom records a capability downgrade
// for the audit row (§6.2: the downgrade is RECORDED, never silent);
// Enforced reports whether the emission actually blocks or defers the
// action (the guard_events.enforced flag).
type Emission struct {
	// Permission is "allow" | "ask" | "deny".
	Permission string
	// DegradedFrom is the verdict decision this emission was
	// downgraded FROM when the channel lacked the capability
	// ("ask" → deny on no-ask clients, "deny"/"ask" → allow on
	// no-block channels). Empty when no degradation applied.
	DegradedFrom string
	// Enforced is true when Permission is ask or deny — the action
	// did not proceed unexamined.
	Enforced bool
	// Reason is the client-facing reason: Verdict.Reason with the
	// Advice appended (spec §4.2 — written FOR THE AGENT, which
	// reads it and self-corrects).
	Reason string
}

// ResolveEmission maps a verdict onto what the channel can actually
// express (spec §6.2 + F5). Pure data-driven capability logic — no
// client names anywhere:
//
//   - allow / flag    → allow (flag-class verdicts record, action
//     proceeds — D2).
//   - ask on CanAsk   → ask (native prompt).
//   - ask, no ask but CanBlock → deny, DegradedFrom=ask (F5: never
//     silently weaker than the verdict on a channel that can block).
//   - ask, no block   → allow, DegradedFrom=ask (post-hoc-only
//     channel: record loudly, can't intervene).
//   - deny on CanBlock → deny.
//   - deny, no block  → allow, DegradedFrom=deny.
//
// The verdict's Decision already encodes mode + per-rule enforcement
// (the engine resolved it); this function only reconciles it with the
// channel — plus the ONE org-granted softening below.
func ResolveEmission(v policy.Verdict, caps policy.Capabilities) Emission {
	reason := v.Reason
	if v.Advice != "" {
		reason += " " + v.Advice
	}
	em := Emission{Permission: "allow", Reason: reason}
	switch emissionDecision(v) {
	case policy.DecisionDeny:
		if caps.CanBlock {
			em.Permission = "deny"
			em.Enforced = true
		} else {
			em.DegradedFrom = policy.DecisionDeny.String()
		}
	case policy.DecisionAsk:
		switch {
		case caps.CanAsk:
			em.Permission = "ask"
			em.Enforced = true
		case caps.CanBlock:
			em.Permission = "deny"
			em.Enforced = true
			em.DegradedFrom = policy.DecisionAsk.String()
		default:
			em.DegradedFrom = policy.DecisionAsk.String()
		}
	case policy.DecisionAllow, policy.DecisionFlag:
		// allow stands.
	}
	return em
}

// emissionDecision is the org-granted-override softening applied
// BEFORE the capability table above (Track B, override.go): a deny on
// a rule the organization marked `overridable` is emitted as an ASK,
// so a channel that can prompt asks the human instead of hard-blocking
// them. Everything downstream is then the EXISTING, already-correct
// ask row of the §6.2 table — on a no-ask/can-block channel (the proxy
// lane, a hook without ask) it degrades right back to deny with
// DegradedFrom="ask", which is what reporting reads.
//
// A hard (non-overridable) deny, and every verdict on a node with no
// org bundle, returns unchanged.
func emissionDecision(v policy.Verdict) policy.Decision {
	if v.Decision == policy.DecisionDeny && v.Overridable {
		return policy.DecisionAsk
	}
	return v.Decision
}
