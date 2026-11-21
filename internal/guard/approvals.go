package guard

import (
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"strings"

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
// the sha256 hex of the project root ("" when unknown).
//
// A lookup that could not be answered (the DB would not open, the query
// timed out, the table is missing) returns false AND a non-nil error:
// fail-safe toward enforcement, never toward a silent grant, but no
// longer silent either. applyApprovals records the failure on the
// verdict's reason (" [approval lookup failed: ...]", the tool lane's
// counterpart of the prompt lane's store_error marker), so an operator
// who granted the rule can see why it still asked (P-232). "No grant"
// is (false, nil).
type ApprovalLookup func(ruleID, sessionID, projectRootHash string) (bool, error)

// SetApprovalLookup wires the grant lookup. Nil disables approvals
// (every blocking verdict enforces). Set once at composition.
func (g *Guard) SetApprovalLookup(fn ApprovalLookup) {
	g.approvals = fn
}

// ApprovalCover is the covering approval a richer lookup found.
type ApprovalCover struct {
	// Found says an active approval covers the rule for this scope.
	Found bool
	// ID is the approval row id and GrantedBy its grantor ("" when the lookup
	// does not know them). When several rows cover, the narrowest scope wins
	// (session, then project, then global), then the lowest id.
	ID        int64
	GrantedBy string
}

// ApprovalCoverLookup is ApprovalLookup that also says WHICH approval covers
// (plan docs/plans/security-assessments-module-plan-2026-11-13.md section
// 13.7), so a verdict a relaxation changed names it. The error contract is
// ApprovalLookup's: a lookup that could not be answered returns Found false
// and a non-nil error, never a silent grant.
type ApprovalCoverLookup func(ruleID, sessionID, projectRootHash string) (ApprovalCover, error)

// SetApprovalCoverLookup wires the richer grant lookup beside SetApprovalLookup.
// When it is set it is consulted in place of the plain lookup, so exactly one
// read answers the question; nil (the default, and every process that does not
// wire it) leaves the plain lookup and the verdict text exactly as they were.
func (g *Guard) SetApprovalCoverLookup(fn ApprovalCoverLookup) {
	g.approvalCover = fn
}

// SessionProjectRootLookup resolves the project root a session belongs
// to ("" when unknown). It exists because the LANES DISAGREE about
// what an event carries (adversarial review P2-7): a host that names
// its project sets ProjectRoot, a pre-tool hook whose payload carries
// only cwd has the boundary's derived ProjectLookupRoot instead, while
// the proxy's egress/injection/budget events are built from a request
// body that has no path in it at all, so a scope='project' grant could
// never match on the proxy lane no matter what the developer approved.
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

// GrantProject is the project a verdict's grant question is asked under:
// the raw root (node-local, the request form shows it) and its
// HashProjectRoot digest (what a project-scoped grant or approval is
// matched against). Zero value: no project (matches no project grant).
type GrantProject struct {
	Root string
	Hash string
}

// grantProject resolves the project the grant lookup is asked with, an
// ordered table walked top down (P-232):
//
//	| # | the event carries                 | root                                |
//	|---|-----------------------------------|-------------------------------------|
//	| 1 | ProjectRoot (the host named it)   | ProjectRoot                         |
//	| 2 | ProjectLookupRoot (boundary-made) | ProjectLookupRoot                   |
//	| 3 | neither, a session id             | the injected session resolver's     |
//	| 4 | nothing                           | "" (matches no project grant)       |
//
// Row 2 is the Claude Code PreToolUse hook (and every tool gate whose
// payload carries only cwd): ProjectRoot stays empty there by design
// (internal/hook/guarded.go), and the boundary derives the root into
// ProjectLookupRoot with git.FindRoot over the cwd translated the way
// the watcher translates it, which is the spelling projects.root_path
// holds and so the spelling the dashboard hashed when it anchored the
// grant. Before P-232 this row was missing, the hash was always "" on
// that lane, and a project grant never downgraded a hook verdict.
// Row 3 is the proxy lane, and it runs only on the already-rare
// blocking (or recorded) path, so no allow-path request pays the read.
//
// It is the ONE resolver for both uses (GRANT-20): the grant matcher
// (approvalProjectRootHash) and the guard_events writer
// (stampGrantProject -> ActionVerdict.GrantProject ->
// guard_events.project_root / project_root_hash, agent migration 253), so
// a request drafted from the row is scoped to the project the gate will
// match the next call on, not the session's start project.
func (g *Guard) grantProject(ev *policy.Event) GrantProject {
	root := ""
	switch {
	case ev == nil:
	case ev.ProjectRoot != "":
		root = ev.ProjectRoot
	case ev.ProjectLookupRoot != "":
		root = ev.ProjectLookupRoot
	case g.projectRootForSession != nil && ev.SessionID != "":
		root = g.projectRootForSession(ev.SessionID)
	}
	return GrantProject{Root: root, Hash: HashProjectRoot(root)}
}

// approvalProjectRootHash is the projectRootHash the grant lookup is asked
// with: grantProject's digest.
func (g *Guard) approvalProjectRootHash(ev *policy.Event) string {
	return g.grantProject(ev).Hash
}

// stampGrantProject records on a verdict about to be persisted the project
// its grant question was (or would have been) asked under, so the audit row
// carries it (GRANT-20). A verdict below flag that is not a guard error is
// never written, so it is left alone and pays no session read.
func (g *Guard) stampGrantProject(av *ActionVerdict, ev *policy.Event) {
	if av.Verdict.Decision < policy.DecisionFlag && !av.GuardError {
		return
	}
	av.GrantProject = g.grantProject(ev)
}

// approvalLookupFailedNote is the reason suffix a verdict carries when the
// grant lookup could not be answered. The error text is bounded: a reason
// is written for the agent and lands in guard_events.reason.
func approvalLookupFailedNote(err error) string {
	msg := err.Error()
	const maxLen = 160
	if len(msg) > maxLen {
		msg = msg[:maxLen] + "..."
	}
	return " [approval lookup failed: " + msg + "; any grant for this rule was not consulted]"
}

// applyApprovals is the exception layer: the ordered table of request-
// grants design §3.2, walked top down, first row that decides wins.
//
//	| # | condition                                          | result                                   |
//	|---|----------------------------------------------------|------------------------------------------|
//	| 0 | rule asks every use (policy.AsksEveryUse: R-168)   | unchanged: no grant covers it            |
//	| 1 | verdict below ask, or no rule id                   | unchanged                                |
//	| 2 | ORG grant, effect exempt (gate lane only)          | flag, degraded_from=org_grant, grant_id  |
//	| 3 | ORG grant, effect soften, verdict deny             | ask (orggrant.go: when a use is counted) |
//	| 4 | local approval, rule not org-locked                | flag, degraded_from=approved             |
//	| 5 | local approval, rule org-locked                    | unchanged + [org_locked ...]             |
//	| 6 | the lookup failed (error)                          | unchanged + [approval lookup failed ...] |
//	| 7 | else                                               | unchanged                                |
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
	// Row 0 (lane cli-2): a rule that asks on every use is never lifted by
	// a grant, local or org; one yes would otherwise cover every later
	// launch in that scope.
	if policy.AsksEveryUse(v.RuleID) {
		return v, approvalOutcome{}
	}
	// The org layer changes only on a bundle reload, so reading the
	// current snapshot here is stable in practice; the cost is one
	// atomic pointer load on the already-rare blocking path.
	es := g.set.Load()
	locked := orgLockedVerdict(v, g.orgLocksVerdictRule(es, v.RuleID, eventProjectRoot(ev)))
	var lookupErr error
	var cover ApprovalCover
	localApproved := func() bool {
		if g.approvalCover != nil {
			c, err := g.approvalCover(v.RuleID, ev.SessionID, g.approvalProjectRootHash(ev))
			if err != nil {
				lookupErr = err
				return false
			}
			cover = c
			return c.Found
		}
		if g.approvals == nil {
			return false
		}
		ok, err := g.approvals(v.RuleID, ev.SessionID, g.approvalProjectRootHash(ev))
		if err != nil {
			lookupErr = err
			return false
		}
		return ok
	}
	gv, out, handled := g.applyOrgGrant(es, v, ev, lane, locked, localApproved)
	if handled {
		if lookupErr != nil && gv.Decision >= policy.DecisionAsk {
			gv.Reason += approvalLookupFailedNote(lookupErr)
		}
		return gv, out
	}
	v = gv
	if !localApproved() {
		if lookupErr != nil {
			v.Reason += approvalLookupFailedNote(lookupErr)
		}
		return v, approvalOutcome{}
	}
	if locked {
		v.Reason += orgLockedNote(g.orgLockCause(es, v.RuleID, eventProjectRoot(ev)), v.RuleID)
		return v, approvalOutcome{}
	}
	v.Decision = policy.DecisionFlag
	v.Reason += approvedNote(cover)
	return v, approvalOutcome{degradedFrom: "approved"}
}

// approvedNote is the reason suffix of a verdict a local approval lifted. The
// plain lookup names no approval; the richer one (SetApprovalCoverLookup) names
// the covering row and its grantor, so the audit row says which approval
// changed the verdict (plan section 13.7).
func approvedNote(c ApprovalCover) string {
	if c.ID <= 0 {
		return " [approved: an operator grant covers this rule for this scope]"
	}
	who := ""
	if c.GrantedBy != "" {
		who = " (" + sanitizeApprovalGrantor(c.GrantedBy) + ")"
	}
	return " [approved: approval #" + strconv.FormatInt(c.ID, 10) + who + " covers this rule for this scope]"
}

// sanitizeApprovalGrantor bounds and cleans the grantor text a reason carries:
// it is operator-chosen on the dashboard and the CLI, so a bracket or a control
// character must not forge a second note.
func sanitizeApprovalGrantor(s string) string {
	const maxLen = 80
	var b strings.Builder
	for _, r := range s {
		if b.Len() >= maxLen {
			break
		}
		switch {
		case r == '[' || r == ']' || r < 0x20 || r == 0x7f:
			b.WriteByte('_')
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// eventProjectRoot is the root ev's project layer is looked up under (the
// org lock's per-project blast radius reads it), "" for a nil event.
func eventProjectRoot(ev *policy.Event) string {
	return projectLookupRoot(ev)
}

// projectLookupRoot is the root the project layer (engineFor), the per-project
// org lock and the project_unknown floor use for ev: the boundary's derived
// ProjectLookupRoot when it set one (a pre-tool hook whose payload carries
// only cwd), else ProjectRoot. "" for a nil event. The approval lookup
// reads the derived root too (approvalProjectRootHash, row 2); the rules and
// the persisted row keep ProjectRoot.
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
