package guard

import "github.com/marmutapp/superbased-observer/internal/policy"

// OrgPromptJudgeRuleID is the guard_events rule id of a verdict from the
// organization's coding-agent prompt judge (P-228, docs/guard.md "Org prompt
// admission judge"). It is not a catalog rule: the org's signed
// planeb.admission body is the policy. Both the daemon's node lane (the
// audit writer) and the hook lane (the reply) use it, so the developer's
// message and the audit row name the same thing.
const OrgPromptJudgeRuleID = "J-801"

// OrgPromptJudgeBlock is the prompt verdict a hook replies with when the
// organization's prompt judge refused the prompt (or, under a strict policy,
// could not answer): a deny the seam then resolves through its own action
// table (WithAction), so a warn-only seam warns rather than pretending it
// blocked. reason is the developer-facing text; it is never persisted by the
// hook (the daemon's audit row is the record).
func OrgPromptJudgeBlock(reason string) PromptVerdict {
	return PromptVerdict{
		Verdict: policy.Verdict{
			Decision: policy.DecisionDeny,
			RuleID:   OrgPromptJudgeRuleID,
			Severity: policy.SeverityHigh,
			Reason:   reason,
			Source:   policy.SourceOrg,
		},
		Outcome: PromptOutcomeBlocked,
	}
}
