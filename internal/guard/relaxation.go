package guard

import "github.com/marmutapp/superbased-observer/internal/policy"

// relaxation.go is the ONE read the agent-run security assessments module
// makes of the guard before it offers to lift a rule for one run
// (docs/plans/security-assessments-module-plan-2026-11-13.md section 13.4). It
// answers from the guard's own gate and the engine's own rule stances, never
// from a second derivation, and it fails CLOSED: anything it cannot read is
// `locked` with the cause `unreadable`, and a decision it cannot read is
// reported as unknown (the caller reads an unknown decision as ask).

// RelaxLock is the org lock on one rule in one project, as applyApprovals
// reads it.
type RelaxLock string

// The relaxation locks.
const (
	// RelaxUntouched: the org layer does not reach the rule here; a local
	// approval applies.
	RelaxUntouched RelaxLock = "untouched"
	// RelaxOverridable: the org layer reaches the rule and marked it
	// overridable, so the guard honours a local approval for it.
	RelaxOverridable RelaxLock = "overridable"
	// RelaxLocked: the org layer locks the rule here (or the answer could not
	// be read); a local approval is inert.
	RelaxLocked RelaxLock = "locked"
)

// RuleRelaxation is the answer of Guard.RuleRelaxation.
type RuleRelaxation struct {
	Lock RelaxLock
	// Cause says why the rule is locked ("named", "project", "managed",
	// "unverifiable", "unresolved", "unreadable"), "" when it is not.
	Cause string
	// Decision is the rule's decision in the running mode for this project
	// (allow, flag, ask, deny): the strictest row of the rule, with the mode,
	// a per-rule enforce and an `enforce = false` cap all folded by the
	// engine's own rule. "" when it could not be read.
	Decision string
	// Known says the project's engine carries the rule (a disabled rule is
	// not there and reads as allow).
	Known bool
}

// unreadableRelaxation is the fail-closed answer.
func unreadableRelaxation() RuleRelaxation {
	return RuleRelaxation{Lock: RelaxLocked, Cause: "unreadable"}
}

// RuleRelaxation answers, for one rule in one project root ("" for none), what
// a local approval can do (the lock, from orgLocksVerdictRule, which also
// locks a rule named by an org project section, combined with the rule's
// Overridable bit exactly as orgLockedVerdict does) and what the rule decides
// now (the project engine's RuleStances: Observe, Enforce, per-rule Enforced
// and EnforceCappedBy, folded by the engine's own ruleDecision).
func (g *Guard) RuleRelaxation(ruleID, projectRoot string) (out RuleRelaxation) {
	if g == nil || ruleID == "" {
		return unreadableRelaxation()
	}
	defer func() {
		if recover() != nil {
			out = unreadableRelaxation()
		}
	}()
	es := g.set.Load()
	if es == nil {
		return unreadableRelaxation()
	}
	eng := es.engineFor(g, projectRoot)
	if eng == nil {
		return unreadableRelaxation()
	}
	stances := eng.RuleStances(ruleID)
	out = RuleRelaxation{Lock: RelaxUntouched, Decision: policy.DecisionAllow.String(), Known: len(stances) > 0}
	strictest, stopping, overridable := policy.DecisionAllow, 0, 0
	for _, s := range stances {
		if s.Decision > strictest {
			strictest = s.Decision
		}
		if s.Decision >= policy.DecisionAsk {
			stopping++
			if s.Overridable {
				overridable++
			}
		}
	}
	out.Decision = strictest.String()
	if !g.orgLocksVerdictRule(es, ruleID, projectRoot) {
		return out
	}
	// The org layer reaches the rule. Overridable only when every row that
	// stops is marked so (a multi-row id grants as a unit only when none of
	// its stopping rows is left locked).
	if stopping > 0 && overridable == stopping {
		out.Lock = RelaxOverridable
		return out
	}
	out.Lock = RelaxLocked
	out.Cause = string(g.orgLockCause(es, ruleID, projectRoot))
	return out
}
