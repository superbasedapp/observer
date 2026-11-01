package guard

import (
	"crypto/sha256"
	"encoding/hex"

	"github.com/marmutapp/superbased-observer/internal/policy"
)

// Approvals integration (guard spec §6.3, G8): operator-granted
// scoped exceptions downgrade blocking verdicts so the agent's
// natural retry succeeds. The grants live in guard_approvals (G2);
// the LOOKUP is injected (ApprovalLookup) because guard never imports
// store — cmd composition wires it to store.ApprovalActiveFor.
//
// Cost posture: the lookup only runs for verdicts that would BLOCK
// (ask/deny). Flag/allow verdicts never consult it, so the hook
// latency budget only pays the DB read on the rare blocking path —
// and a blocked call was about to not-happen anyway.

// ApprovalLookup reports whether an active (non-expired) approval
// grant covers the rule for this session/project. projectRootHash is
// the sha256 hex of the project root ("" when unknown). Lookup
// failures must report false (no approval) — fail-safe toward
// enforcement, never toward a silent grant.
type ApprovalLookup func(ruleID, sessionID, projectRootHash string) bool

// SetApprovalLookup wires the grant lookup. Nil disables approvals
// (every blocking verdict enforces). Set once at composition.
func (g *Guard) SetApprovalLookup(fn ApprovalLookup) {
	g.approvals = fn
}

// SessionProjectRootLookup resolves the project root a session belongs
// to ("" when unknown). It exists because the LANES DISAGREE about
// what an event carries (adversarial review P2-7): a hook event names
// its own ProjectRoot, while the proxy's egress/injection/budget
// events are built from a request body that has no path in it at all,
// so a scope='project' grant could never match on the proxy lane no
// matter what the developer approved.
//
// Guard never imports store: the daemon composition wires this to
// store.ProjectRootForSession - THE existing session-to-project
// resolver, the same one the dashboard's approvals POST uses to anchor
// a project-scoped grant from a verdict row's session id. One
// resolver, one answer on both lanes.
type SessionProjectRootLookup func(sessionID string) string

// SetSessionProjectRootLookup wires the session-to-project resolver.
// Nil (a hook process, a CLI-built guard) leaves the behaviour exactly
// as it was: an event with no ProjectRoot simply matches no
// project-scoped grant.
func (g *Guard) SetSessionProjectRootLookup(fn SessionProjectRootLookup) {
	g.projectRootForSession = fn
}

// approvalProjectRootHash is the projectRootHash the grant lookup is
// asked with. The event's own root wins (the hook lane already carries
// it, and resolving again would be a second answer); only an event
// with no root at all - the proxy lane - falls through to the injected
// session resolver, and only on the already-rare blocking path, so no
// allow-path request pays the read.
func (g *Guard) approvalProjectRootHash(ev *policy.Event) string {
	if ev.ProjectRoot != "" {
		return HashProjectRoot(ev.ProjectRoot)
	}
	if g.projectRootForSession == nil || ev.SessionID == "" {
		return ""
	}
	return HashProjectRoot(g.projectRootForSession(ev.SessionID))
}

// applyApprovals is the exception layer: the ordered table of request-
// grants design §3.2, walked top down, first row that decides wins.
//
//	| # | condition                                          | result                                   |
//	|---|----------------------------------------------------|------------------------------------------|
//	| 1 | verdict below ask, or no rule id                   | unchanged                                |
//	| 2 | ORG grant, effect exempt (gate lane only)          | flag, degraded_from=org_grant, grant_id  |
//	| 3 | ORG grant, effect soften, verdict deny             | ask (orggrant.go: when a use is counted) |
//	| 4 | local approval, rule not org-locked                | flag, degraded_from=approved             |
//	| 5 | local approval, rule org-locked                    | unchanged + [org_locked ...]             |
//	| 6 | else                                               | unchanged                                |
//
// The org grant is checked BEFORE the org-lock gate because it is the
// organization speaking, but only a grant issued under the locked-rule
// approval rule reaches a locked rule (the claim filters it, RuleLocked).
// lane is the gate lane the verdict was produced on ("" for a post-hoc or
// observe-only seam, where org grants never apply). Every downgrade is
// RECORDED on the verdict (reason suffix + the outcome's degraded_from
// marker and grant id) - an exception is audited (§14.4 exception
// register), never a silent allow.
//
// ORG-LOCK GATE (Track B, override.go): where the org layer LOCKS a
// rule - always on a managed node, and on an individual node for the
// rules the bundle NAMES - a grant only lands when the organization
// marked the rule `overridable`.
// A pre-existing grant for any other locked rule is INERT - the verdict is
// returned un-downgraded with the fact appended to its reason, so the
// audit row (and, under full-content sharing, the org) shows that a
// local approval was refused rather than silently applied. Un-enrolled
// nodes have no bundle, so nothing here changes for them.
func (g *Guard) applyApprovals(v policy.Verdict, ev *policy.Event, lane string) (policy.Verdict, approvalOutcome) {
	if v.Decision < policy.DecisionAsk || v.RuleID == "" {
		return v, approvalOutcome{}
	}
	// The org layer changes only on a bundle reload, so reading the
	// current snapshot here is stable in practice; the cost is one
	// atomic pointer load on the already-rare blocking path.
	es := g.set.Load()
	locked := orgLockedVerdict(v, g.orgLocksVerdictRule(es, v.RuleID, eventProjectRoot(ev)))
	localApproved := func() bool {
		return g.approvals != nil && g.approvals(v.RuleID, ev.SessionID, g.approvalProjectRootHash(ev))
	}
	gv, out, handled := g.applyOrgGrant(es, v, ev, lane, locked, localApproved)
	if handled {
		return gv, out
	}
	v = gv
	if !localApproved() {
		return v, approvalOutcome{}
	}
	if locked {
		v.Reason += " [org_locked: an org policy locks " + v.RuleID + "; the local approval was ignored]"
		return v, approvalOutcome{}
	}
	v.Decision = policy.DecisionFlag
	v.Reason += " [approved: an operator grant covers this rule for this scope]"
	return v, approvalOutcome{degradedFrom: "approved"}
}

// eventProjectRoot is the root ev's project layer is looked up under (the
// org lock's per-project blast radius reads it), "" for a nil event.
func eventProjectRoot(ev *policy.Event) string {
	return projectLookupRoot(ev)
}

// projectLookupRoot is the root the project layer (engineFor), the per-project
// org lock and the project_unknown floor use for ev: the boundary's derived
// ProjectLookupRoot when it set one (a pre-tool hook whose payload carries
// only cwd), else ProjectRoot. "" for a nil event. Nothing else reads the
// derived root: the rules and the persisted row keep ProjectRoot.
func projectLookupRoot(ev *policy.Event) string {
	if ev == nil {
		return ""
	}
	if ev.ProjectLookupRoot != "" {
		return ev.ProjectLookupRoot
	}
	return ev.ProjectRoot
}

// HashProjectRoot returns the sha256 hex of a project root — the
// guard_approvals.project_root_hash convention (raw paths never land
// in the approvals table, matching the org-wire posture). Empty in,
// empty out.
func HashProjectRoot(root string) string {
	if root == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(root))
	return hex.EncodeToString(sum[:])
}
