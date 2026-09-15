package dashboard

import (
	"context"
	"time"
)

// policystop.go is the UX-honesty seam for a dashboard terminal an org-
// managed node's OWN node-intervention loop stopped (a process-control
// policy verdict, e.g. rule B-602 "daily spend accounting is unavailable").
// Without it, an operator's "New Terminal" session just goes to
// EXITED (255) with no explanation — this surfaces the SAME durable audit
// row the daemon already wrote (internal/store.LookupProcessControlStop over
// guard_events, category process_control) on the terminal's exit event and
// its status payload. The dashboard never imports internal/store or
// internal/termsession — cmd supplies a PolicyStopProvider closure, the same
// injected-seam discipline as TerminalStatusProvider.

// PolicyStop is one node-intervention audit verdict, trimmed to what a UI
// surface may show. It deliberately excludes process-identity fields
// (pid/uid/boot_id) and policy/pricing fingerprints — those are
// attribution/forensics metadata, not something to echo to the operator.
type PolicyStop struct {
	// RuleID is the policy rule that fired (e.g. "B-602").
	RuleID string `json:"rule_id"`
	// Decision is the outcome status (e.g. "terminated", "killed",
	// "policy_unavailable"). See DisplayMessage for how this is rendered.
	Decision string `json:"decision"`
	// Reason is the bounded, human-readable explanation the policy verdict
	// carried.
	Reason string `json:"reason"`
	// At is when the audit row was recorded.
	At time.Time `json:"at"`
}

// stoppingDecisions are the Decision values that mean the daemon actually
// terminated the process — as opposed to a decision that merely OBSERVED a
// problem (e.g. "policy_unavailable": the policy check itself could not run,
// so nothing was stopped). Table-driven per CLAUDE.md #5, so a new stopping
// decision is one row, not a new branch.
var stoppingDecisions = map[string]bool{
	"terminated": true,
	"killed":     true,
}

// DisplayMessage renders the honest, decision-aware sentence a UI surface
// should show. It never claims "stopped by organization policy" for a
// decision that did not actually stop the process (e.g.
// "policy_unavailable"), matching the operator ruling that copy must stay
// true to what the daemon actually did.
func (p PolicyStop) DisplayMessage() string {
	if stoppingDecisions[p.Decision] {
		msg := "Stopped by organization policy"
		if p.RuleID != "" {
			msg += " (" + p.RuleID + ")"
		}
		if p.Reason != "" {
			msg += ": " + p.Reason
		}
		return msg
	}
	msg := "Organization policy check failed; process was not stopped by the daemon"
	if p.Reason != "" {
		msg += ": " + p.Reason
	}
	return msg
}

// PolicyStopProvider is the dashboard's seam onto the node-intervention audit
// trail. The nil provider is the disabled state: every consumer treats a nil
// PolicyStopProvider (or a false ok) as "nothing to show", never an error.
type PolicyStopProvider interface {
	// PolicyStopForHandle resolves the newest policy-stop verdict for a
	// terminal run's PTY child, keyed by the handle's OS process identity and
	// launch time. ok is false when no matching audit row exists — including
	// when the handle carries no recorded pid — never a guess.
	PolicyStopForHandle(ctx context.Context, handle string) (PolicyStop, bool)
}

// resolvePolicyStop is the one call site both the exit-frame path
// (bridgeTerminalWS) and the status payload (handleTerminalStatus) use to
// consult the optional seam. A nil provider or a not-found lookup both
// resolve to (zero value, false) — the caller then simply omits policy_stop.
func (s *Server) resolvePolicyStop(ctx context.Context, handle string) (PolicyStop, bool) {
	if s.opts.PolicyStop == nil {
		return PolicyStop{}, false
	}
	return s.opts.PolicyStop.PolicyStopForHandle(ctx, handle)
}
