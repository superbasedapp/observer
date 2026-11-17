package guard

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"time"

	"github.com/marmutapp/superbased-observer/internal/policy"
)

// Org access grants on the guard's decision path (request-grants design
// §3.2, phase G3; docs/access-grants.md).
//
// An org grant is the ORGANIZATION's signed, time-bound exception for one
// developer: "exempt" lifts an enforced ask/deny on the rule it names to
// FLAG (allowed, recorded), "soften" turns an enforced deny into an ask so
// the developer still confirms each call. Guard never imports the grant
// cache: the composition wires OrgGrantClaim to orgclient.ClaimAccessGrant,
// which re-verifies the signed cache on every call (hook process and daemon
// alike) and counts a use with one conditional UPDATE. Every failure there
// is "no grant", so enforcement stands.
//
// Where a grant applies: only on a GATE lane (the tool hook, the prompt
// gate, the proxy request), never on a post-hoc or observe-only seam (the
// watcher, the captured-prompt lane, proxy response inspection): those
// record what already happened, and counting a use there would count the
// same call twice. And never on a budget rule: a budget has its own grant
// type that raises the cap itself (§3.3).
//
// When a use is counted: once per call the grant lets through.
//
//	| effect | channel                         | verdict | use counted          |
//	|--------|---------------------------------|---------|----------------------|
//	| exempt | any gate                        | flag    | yes                  |
//	| soften | can ask natively                | ask     | yes (the ask)        |
//	| soften | deny-only, not yet confirmed    | ask     | no (nothing runs)    |
//	| soften | deny-only, confirmed (approval) | flag    | yes (the retry)      |
//	| soften | prompt gate, first send         | ask     | no (ask-once)        |
//	| soften | prompt gate, confirming re-send | flag    | yes                  |
//
// A native ask counts its use when presented because the developer's answer
// happens inside the vendor's own prompt, which Observer cannot see; counting
// there is the stricter reading.

// Grant lanes (accessgrant.Lane* spelling; pinned by
// TestOrgGrant_VocabularyMatchesAccessGrant).
const (
	OrgGrantLaneTool   = "tool"
	OrgGrantLanePrompt = "prompt"
	OrgGrantLaneProxy  = "proxy"
)

// Grant effects (orgcontract.AccessGrantEffect* spelling).
const (
	OrgGrantEffectExempt = "exempt"
	OrgGrantEffectSoften = "soften"
)

// guard_events.degraded_from markers for a verdict an org grant changed.
// Never a plain allow: the row says which grant and what it was before.
const (
	DegradedFromOrgGrant       = "org_grant"
	DegradedFromOrgGrantSoften = "org_grant_soften"
)

// OrgGrantQuery is the guard's question for one blocking verdict.
type OrgGrantQuery struct {
	RuleID string
	Lane   string
	// CommandClass is "<category>/<event kind>" and OperandHash the sha256
	// of the event target: the same values a guard_events row carries, so a
	// grant requested from a blocked event matches that call again.
	CommandClass    string
	OperandHash     string
	ProjectRootHash string
	// Decision is the verdict the grant would change ("ask" or "deny").
	Decision string
	// RuleLocked is the org lock on this rule on this node (override.go):
	// only a grant issued under the locked-rule approval rule reaches it.
	RuleLocked bool
	// Consume asks the claim to COUNT a use. A false Consume is a peek: it
	// answers whether a grant covers the call without spending anything.
	Consume bool
}

// OrgGrantResult is the claim's answer.
type OrgGrantResult struct {
	OK          bool
	GrantID     int64
	Effect      string
	ExpiresAtNs int64
	// UsesLeft is what remains after this call (-1 unlimited).
	UsesLeft int64
	// LockRefused: a grant matched but the rule is org-locked and the grant
	// was not issued under the locked-rule approval rule.
	LockRefused bool
	// Unverified: the node holds a grant document that no longer verifies.
	Unverified bool
	// ScopeMissID: no grant covered the call, but the node holds an honoured
	// grant for this rule pinned to another lane, command or project.
	ScopeMissID int64
	// Failed is why the question could not be ANSWERED ("" when it was): the
	// grant list could not be read in time, or a use could not be counted.
	// The answer is still "no grant", and the verdict says so.
	Failed string
}

// OrgGrantClaim answers (and, with Consume, counts) one grant question. It
// must never block on the network and must fail toward "no grant".
type OrgGrantClaim func(OrgGrantQuery) OrgGrantResult

// SetOrgGrantClaim wires the org access-grant claim. Nil disables org
// grants (every blocking verdict enforces exactly as before). Set once at
// composition.
func (g *Guard) SetOrgGrantClaim(fn OrgGrantClaim) {
	g.orgGrants = fn
	g.orgGrantSession = nil
}

// OrgGrantSession begins one grant conversation: the questions one verdict
// asks (the peek, then the claim that counts the use) go through the returned
// claim, and done releases whatever the conversation held (a hook process's
// database handle, so the claim does not open the database a second time
// right after the peek). done is called exactly once.
type OrgGrantSession func() (claim OrgGrantClaim, done func())

// SetOrgGrantSession wires the org access-grant claim as a session (the hook
// process): it replaces SetOrgGrantClaim, a lone question (the prompt lane's
// two sends) is a session of its own, and nil disables org grants. Set once
// at composition.
func (g *Guard) SetOrgGrantSession(fn OrgGrantSession) {
	g.orgGrantSession = fn
	g.orgGrants = nil
	if fn != nil {
		g.orgGrants = func(q OrgGrantQuery) OrgGrantResult {
			claim, done := fn()
			defer done()
			return claim(q)
		}
	}
}

// beginOrgGrants opens the conversation one verdict's grant questions share:
// the session's when one is wired, else the plain claim with nothing to
// release.
func (g *Guard) beginOrgGrants() (OrgGrantClaim, func()) {
	if g.orgGrantSession != nil {
		return g.orgGrantSession()
	}
	return g.orgGrants, func() {}
}

// approvalOutcome is what the exception layer (approvals.go) did to a
// verdict, for the audit row.
type approvalOutcome struct {
	// degradedFrom is the guard_events marker ("approved", org_grant,
	// org_grant_soften) or "".
	degradedFrom string
	// grantID is the org grant whose use this call counted.
	grantID int64
	// softenedBy is a soften grant shown to the developer WITHOUT counting a
	// use (a deny-only host before the developer confirmed): it steers the
	// deny text, never the audit row's grant_id, so the org's use count
	// stays a count of calls let through.
	softenedBy int64
}

// stamp writes the outcome onto a freshly built verdict row. It runs after
// stampOrgOverride: a call the ORG let through (or offered to confirm) is
// not "locked by your organization", whatever the bundle says.
func (o approvalOutcome) stamp(av *ActionVerdict) {
	if o.degradedFrom != "" {
		av.DegradedFrom = o.degradedFrom
	}
	av.GrantID = o.grantID
	av.softenedBy = o.softenedBy
	if o.grantID != 0 || o.softenedBy != 0 {
		av.OrgLocked = false
	}
}

// approved reports whether a LOCAL approval downgraded the verdict.
func (o approvalOutcome) approved() bool { return o.degradedFrom == "approved" }

// grantEligible is the gate in front of every org-grant question: a gate
// lane, a blocking verdict, a rule id, and not a budget rule.
func (g *Guard) grantEligible(v policy.Verdict, lane string) bool {
	return g.orgGrants != nil && lane != "" && v.Decision >= policy.DecisionAsk &&
		v.RuleID != "" && !isBudgetRuleID(v.RuleID)
}

// orgGrantQuery builds the query for v on ev from one policy snapshot.
func (g *Guard) orgGrantQuery(es *engineSet, v policy.Verdict, ev *policy.Event, lane string, locked bool) OrgGrantQuery {
	class := ""
	if cat := g.categoryWith(es, v.RuleID); cat != "" || ev.Kind != "" {
		class = cat + "/" + string(ev.Kind)
	}
	return OrgGrantQuery{
		RuleID: v.RuleID, Lane: lane, CommandClass: class, OperandHash: operandHash(ev.Target),
		ProjectRootHash: g.approvalProjectRootHash(ev), Decision: v.Decision.String(), RuleLocked: locked,
	}
}

// operandHash is the guard_events.target_hash convention (sha256 hex of the
// raw target, "" for an empty one).
func operandHash(target string) string {
	if target == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(target))
	return hex.EncodeToString(sum[:])
}

// grantEffect is one row of the effect table: what a claimed grant does to
// a verdict and which marker the row carries.
type grantEffect struct {
	decision policy.Decision
	marker   string
	note     func(r OrgGrantResult) string
}

var grantEffects = map[string]grantEffect{
	OrgGrantEffectExempt: {
		decision: policy.DecisionFlag, marker: DegradedFromOrgGrant,
		note: func(r OrgGrantResult) string {
			return fmt.Sprintf(" [granted: G-%d by your organization%s]", r.GrantID, grantWindowNote(r))
		},
	},
	OrgGrantEffectSoften: {
		decision: policy.DecisionAsk, marker: DegradedFromOrgGrantSoften,
		note: func(r OrgGrantResult) string {
			return fmt.Sprintf(" [softened by G-%d: confirm each call%s]", r.GrantID, grantWindowNote(r))
		},
	},
}

// grantActs is the effect x decision table (accessgrant's effectActs, seen
// from the guard): exempt changes an ask or a deny, soften only a deny.
func grantActs(effect string, d policy.Decision) bool {
	switch effect {
	case OrgGrantEffectExempt:
		return d == policy.DecisionAsk || d == policy.DecisionDeny
	case OrgGrantEffectSoften:
		return d == policy.DecisionDeny
	}
	return false
}

func grantWindowNote(r OrgGrantResult) string {
	s := ""
	if r.ExpiresAtNs > 0 {
		s = " until " + time.Unix(0, r.ExpiresAtNs).UTC().Format("2006-01-02 15:04 UTC")
	}
	if r.UsesLeft >= 0 {
		s += ", " + strconv.FormatInt(r.UsesLeft, 10) + " uses left"
	}
	return s
}

// grantNoteRule is one row of the "no grant applied, and here is why" table,
// walked top down; the first row that holds writes its note.
type grantNoteRule struct {
	holds func(r OrgGrantResult) bool
	note  func(r OrgGrantResult) string
}

// maxGrantFailureLen bounds the failure text a reason carries: a reason is
// written for the agent and lands in guard_events.reason.
const maxGrantFailureLen = 160

var grantNoteRules = []grantNoteRule{
	{
		func(r OrgGrantResult) bool { return r.Failed != "" },
		func(r OrgGrantResult) string {
			msg := r.Failed
			if len(msg) > maxGrantFailureLen {
				msg = msg[:maxGrantFailureLen] + "..."
			}
			return " [org grants: this machine's grant list could not be consulted (" + msg + "), so no grant was applied to this call; if you hold a grant for this rule it is still in force, so retry the call rather than requesting it again]"
		},
	},
	{
		func(r OrgGrantResult) bool { return r.Unverified },
		func(OrgGrantResult) string {
			return " [org grants: this machine's grant list could not be verified, so no grant applies; it refreshes on the next sync]"
		},
	},
	{
		func(r OrgGrantResult) bool { return r.LockRefused },
		func(OrgGrantResult) string {
			return " [org grants: a grant covers this rule but was not issued under the locked-rule approval, so the organization's lock stands]"
		},
	},
	{
		func(r OrgGrantResult) bool { return r.ScopeMissID != 0 },
		func(r OrgGrantResult) string {
			return fmt.Sprintf(" [org grants: G-%d covers this rule only for another project, command or lane, so it does not apply to this call; request access for this one]", r.ScopeMissID)
		},
	},
}

// grantNoteFor is the reason suffix for a grant question that changed
// nothing but is worth telling the developer (and the audit row) about. A
// granted rule that still stops a call always says why here: a silent miss
// is what made a developer ask for the same grant again (operator report
// 2026-11-13).
func grantNoteFor(r OrgGrantResult) string {
	for _, rule := range grantNoteRules {
		if rule.holds(r) {
			return rule.note(r)
		}
	}
	return ""
}

// applyOrgGrant is row 2-3 of the exception table (approvals.go). handled
// is false when no org grant decided the verdict, so the local approval
// rows run next. localApproved is the developer's own approval for this
// rule and scope, which is a soften grant's confirmation on a host that
// cannot ask.
func (g *Guard) applyOrgGrant(es *engineSet, v policy.Verdict, ev *policy.Event, lane string, locked bool, localApproved func() bool) (policy.Verdict, approvalOutcome, bool) {
	if !g.grantEligible(v, lane) {
		return v, approvalOutcome{}, false
	}
	q := g.orgGrantQuery(es, v, ev, lane, locked)
	// One conversation for the peek and the claim: a hook process opens
	// the database once for both (orggrant_wire.go).
	claim, done := g.beginOrgGrants()
	defer done()
	peek := claim(q)
	if !peek.OK || !grantActs(peek.Effect, v.Decision) {
		v.Reason += grantNoteFor(peek)
		return v, approvalOutcome{}, false
	}
	plan := grantPlanFor(peek.Effect, lane, ev.Caps.CanAsk, localApproved)
	if !plan.consume {
		// A soften grant offered on a host that cannot ask: the call is
		// held for the developer's confirmation and nothing is counted.
		out := grantEffects[peek.Effect]
		v.Decision = out.decision
		v.Reason += out.note(peek) + " [confirm, then retry the identical call]"
		return v, approvalOutcome{degradedFrom: out.marker, softenedBy: peek.GrantID}, true
	}
	q.Consume = true
	r := claim(q)
	if !r.OK || !grantActs(r.Effect, v.Decision) {
		// The last use went to another process between the peek and the
		// claim: no grant, enforcement stands.
		v.Reason += grantNoteFor(r)
		return v, approvalOutcome{}, false
	}
	out := grantEffects[r.Effect]
	v.Decision = out.decision
	marker := out.marker
	if plan.confirmed {
		v.Decision = policy.DecisionFlag
		marker = DegradedFromOrgGrant
		v.Reason += fmt.Sprintf(" [confirmed by you under G-%d%s]", r.GrantID, grantWindowNote(r))
	} else {
		v.Reason += out.note(r)
	}
	return v, approvalOutcome{degradedFrom: marker, grantID: r.GrantID}, true
}

// grantPlan says whether a claimed grant counts a use now, and whether the
// call is already confirmed by the developer.
type grantPlan struct {
	consume   bool
	confirmed bool
}

// grantPlanFor is the "use counted" column of the table at the top of this
// file. The prompt gate's soften is handled by the ask-once state machine
// (promptguard.go), so here a prompt-lane soften is never consumed.
func grantPlanFor(effect, lane string, canAsk bool, localApproved func() bool) grantPlan {
	if effect != OrgGrantEffectSoften {
		return grantPlan{consume: true}
	}
	if lane == OrgGrantLanePrompt {
		return grantPlan{}
	}
	if localApproved != nil && localApproved() {
		return grantPlan{consume: true, confirmed: true}
	}
	return grantPlan{consume: canAsk}
}

// promptSoftenGrant peeks for a soften grant covering a prompt-gate DENY
// (mode=block). When one exists, the prompt goes through the ask-once
// confirm instead of a hard block (design §3.2: "A soften grant on a prompt
// DENY yields ASK -> confirm or re-enter").
func (g *Guard) promptSoftenGrant(es *engineSet, v policy.Verdict, ev *policy.Event) (OrgGrantResult, bool) {
	if !g.grantEligible(v, OrgGrantLanePrompt) {
		return OrgGrantResult{}, false
	}
	locked := orgLockedVerdict(v, g.orgLocksVerdictRule(es, v.RuleID, eventProjectRoot(ev)))
	r := g.orgGrants(g.orgGrantQuery(es, v, ev, OrgGrantLanePrompt, locked))
	return r, r.OK && r.Effect == OrgGrantEffectSoften
}

// claimPromptSoftenConfirm counts the use of a soften grant when the
// developer confirmed the prompt by re-sending it. It re-asks with the
// ORIGINAL deny decision (the one the grant softens). ok=false: the grant
// was spent meanwhile, so the confirmation does not stand.
func (g *Guard) claimPromptSoftenConfirm(es *engineSet, deny policy.Verdict, ev *policy.Event) (OrgGrantResult, bool) {
	locked := orgLockedVerdict(deny, g.orgLocksVerdictRule(es, deny.RuleID, eventProjectRoot(ev)))
	q := g.orgGrantQuery(es, deny, ev, OrgGrantLanePrompt, locked)
	q.Consume = true
	r := g.orgGrants(q)
	return r, r.OK && r.Effect == OrgGrantEffectSoften
}
