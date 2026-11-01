package guard

import (
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/policy"
)

// The project_unknown floor (security plan section 7.11 "Offline launch",
// PR14, Q27; lane sec-p2a; P-052 finding 6).
//
// Where a project bundle reaches the member but the project layer of a root
// is unknown (the signed mapping is past its offline lifetime or missing, the
// mapping is above its cap and the resolve call failed, or a matched
// project's envelope is missing, rejected or unparseable), the org, team and
// member layers still apply, and the org's `[project_audience] unknown`
// decision adds a floor:
//
//	value  | individual node | managed node (or tenancy unresolved)
//	none   | nothing         | nothing
//	ask    | ask             | deny
//
// The floor only raises a verdict (never weaker than what the rules decided,
// PR14), on the hook path only (pre-execution events), for the event kinds
// in projectFloorKinds. A host that cannot ask turns the ask into a deny
// (ResolveEmission, F5), which is the Q27 ruling. It is inert unless the org
// layer in force carries the project audience AND the org set "ask".

// ProjectUnknownRuleID tags a verdict the project_unknown floor raised. Like
// GuardErrorRuleID it is a guard-level id, not a catalog rule.
const ProjectUnknownRuleID = "project_unknown"

// projectFloorKinds are the event kinds the floor applies to, with whether a
// file access counts only when it writes. Reads are left alone: they change
// nothing, and asking on every read would make the floor unusable.
var projectFloorKinds = []struct {
	kind       policy.EventKind
	writesOnly bool
}{
	{kind: policy.KindShellExec},
	{kind: policy.KindMCPCall},
	{kind: policy.KindToolCall},
	{kind: policy.KindFileAccess, writesOnly: true},
}

// projectFloorAppliesTo reports whether ev is of a kind the floor covers.
func projectFloorAppliesTo(ev policy.Event) bool {
	for _, k := range projectFloorKinds {
		if k.kind != ev.Kind {
			continue
		}
		if k.writesOnly {
			switch ev.ActionType {
			case "write_file", "edit_file":
				return true
			default:
				return false
			}
		}
		return true
	}
	return false
}

// projectUnknownFor returns why the root's org project layer is unknown in
// this snapshot ("" when it is known or was never built).
func (es *engineSet) projectUnknownFor(projectRoot string) string {
	if es == nil || projectRoot == "" {
		return ""
	}
	es.pmu.Lock()
	defer es.pmu.Unlock()
	return es.projectUnknown[projectRoot]
}

// orgProjectUnknownDecision is the org layer's project_unknown value
// ("none" when no org layer or no table).
func (es *engineSet) orgProjectUnknownDecision() string {
	if es == nil || es.orgLayer == nil || es.orgLayer.projectUnknown == "" {
		return orgcontract.ProjectUnknownNone
	}
	return es.orgLayer.projectUnknown
}

// projectFloor returns the floor verdict for ev when it applies and is
// stricter than verdict (ok=false otherwise). The snapshot must already have
// evaluated ev (engineFor built the root and recorded its unknown state).
func (g *Guard) projectFloor(es *engineSet, ev policy.Event, verdict policy.Verdict) (policy.Verdict, bool) {
	if !es.orgProjectsInForce() || es.orgProjectUnknownDecision() != orgcontract.ProjectUnknownAsk {
		return policy.Verdict{}, false
	}
	if !ev.Caps.PreExecution || !projectFloorAppliesTo(ev) {
		return policy.Verdict{}, false
	}
	why := es.projectUnknownFor(projectLookupRoot(&ev))
	if why == "" {
		return policy.Verdict{}, false
	}
	decision, where, effect := policy.DecisionAsk, "this node", "needs your approval"
	if g.orgLocksEveryRule() {
		decision, where, effect = policy.DecisionDeny, "this managed node", "is blocked"
	}
	if verdict.Decision >= decision {
		return policy.Verdict{}, false
	}
	return policy.Verdict{
		Decision: decision,
		RuleID:   ProjectUnknownRuleID,
		Severity: policy.SeverityWarn,
		Source:   policy.SourceOrg,
		Reason: "Observer guard: your organization's project policy for this repository cannot be confirmed right now (" + why +
			"), and its project_unknown setting is \"ask\", so on " + where + " this action " + effect + ".",
		Advice: "Reconnect so the org policy can refresh (`observer org status`), or run the agent from a launcher (`observer <tool>`) so the repository is resolved before the session.",
	}, true
}
