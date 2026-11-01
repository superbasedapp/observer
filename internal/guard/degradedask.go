package guard

import (
	"fmt"

	"github.com/marmutapp/superbased-observer/internal/policy"
)

// Deny-only hosts and the enforced ask (hook-parity audit section 5.7
// decision table; operator ruling 2026-10-02, decision log D-040; task
// T-052).
//
// The table, for one rule outcome on one seam:
//
//	| Outcome                     | Seam can ask   | Seam is deny-only               | Observe-only seam |
//	|-----------------------------|----------------|---------------------------------|-------------------|
//	| FLAG (and enforce=false)    | allow + record | allow + record                  | record            |
//	| ASK, enforced               | native ask     | DENY WITH A REASON (below)      | record            |
//	| DENY, enforced              | deny           | deny                            | record            |
//
// ResolveEmission already maps an enforced ask on a can-block, cannot-ask
// channel to a deny (DegradedFrom="ask"). What it did not do is say WHY the
// call stopped or how to proceed: the rule's own reason reads like a hard
// block. ExplainDegradedAsk adds the one sentence the ruling requires: the
// call needs the developer's confirmation, this host cannot ask, and here
// is how to give it (approve the rule for this session, then let the agent
// retry the identical call, the tool-call equivalent of re-entering a
// prompt). The approval is the existing section 6.3 register, keyed on
// rule + session (+ project root), which the retried call then hits.

// ConfirmBlockLine renders the leading sentence for a degraded ask. The
// command is printed only when it would work: an approval is scoped to a
// session, so a seam that reported no session id points at the dashboard
// Security page instead (the HumanBlockLine precedent). Hyphens only.
func ConfirmBlockLine(av ActionVerdict, sessionID string) string {
	what, ok := blockedWhatByKind[av.Kind]
	if !ok {
		what = blockedWhatFallback
	}
	rule := av.Verdict.RuleID
	if sessionID != "" {
		return fmt.Sprintf(
			"observer: %s needs your confirmation before %s runs, and this tool cannot ask you, so it was blocked. To allow it, the developer (not the agent) runs `observer guard approve %s --session %s` (or approves it on the Observer dashboard Security page), then lets the agent retry the identical call.",
			rule, what, rule, sessionID)
	}
	return fmt.Sprintf(
		"observer: %s needs your confirmation before %s runs, and this tool cannot ask you, so it was blocked. This tool reported no session id, so the developer (not the agent) approves %s on the Observer dashboard Security page, then lets the agent retry the identical call.",
		rule, what, rule)
}

// ExplainDegradedAsk prepends ConfirmBlockLine to an emission that is an
// enforced ask degraded to a deny because the channel cannot ask. It leaves
// every other emission untouched: a genuine deny, an ask the channel asked
// natively, a non-blocking emission, and an org-overridable or org-locked
// rule (HumanizeEmission already leads those with the org's own sentence).
func ExplainDegradedAsk(em Emission, av ActionVerdict, sessionID string) Emission {
	if !em.Enforced || em.Permission != "deny" || em.DegradedFrom != policy.DecisionAsk.String() {
		return em
	}
	if av.Verdict.RuleID == "" || av.Overridable || av.OrgLocked || av.Verdict.Decision != policy.DecisionAsk {
		return em
	}
	em.Reason = ConfirmBlockLine(av, sessionID) + " " + em.Reason
	return em
}
