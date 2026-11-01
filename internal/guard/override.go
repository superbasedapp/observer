package guard

import (
	"fmt"
	"net/url"

	"github.com/marmutapp/superbased-observer/internal/policy"
)

// Org-granted per-rule override (Track B of the org guardrail control
// wave, docs/plans/org-guardrail-control-wave-2026-09-21.md).
//
// The ruling: a guardrail deny may be overridden on a node ONLY if the
// organization marked the rule `overridable` in the policy bundle it
// published; otherwise the block is hard and the developer's own
// approvals register cannot soften it. Two consequences, both resolved
// here so no hot path re-derives them:
//
//   - Overridable - the org said "a developer may take this one".
//     policy.Verdict carries it out of the engine; the emission seam
//     softens the deny into an ask wherever the channel can prompt,
//     and the §6.3 approvals register accepts a scoped grant.
//   - OrgLocked - the org bundle LOCKS this rule here and the org did
//     not mark it overridable. Approvals for it are inert, the deny
//     text says so, and the node dashboard renders it read-only.
//
// How far the lock reaches is a TENANCY question, not a bundle
// question (adversarial review P2-8). CLAUDE.md's posture is
// lowering-only on an individual node and org-authoritative on a
// managed one, so:
//
//	tenancy    | bundle names the rule | rule marked overridable | result
//	-----------|-----------------------|-------------------------|--------------
//	none       | -                     | -                       | inert
//	individual | no                    | -                       | inert (local approvals stand)
//	individual | yes                   | no                      | org-locked
//	individual | yes                   | yes                     | overridable
//	managed    | no                    | -                       | org-locked
//	managed    | yes                   | no                      | org-locked
//	managed    | yes                   | yes                     | overridable
//	unresolved | -                     | no                      | org-locked (conservative)
//
// "unresolved" is a process that did not wire Options.ManagedTenancy
// (a short-lived hook process): it keeps the widest lock rather than
// silently widening what a developer may approve.
//
// With NO org bundle loaded (every individual, un-enrolled node) both
// flags are false everywhere and nothing in this file changes a byte
// of the pre-wave behaviour - guaranteed structurally by orgApplies()
// gating every path below and by Overridable only ever being set from
// an ORG-layer [[override]] row (guard/merge.go).

// SetManagedTenancy wires (or re-wires) the tenancy half of the org
// lock after construction; nil restores the unresolved default. See
// Options.ManagedTenancy for the semantics of each state.
func (g *Guard) SetManagedTenancy(fn func() bool) {
	if fn == nil {
		g.managedTenancy.Store(nil)
		return
	}
	g.managedTenancy.Store(&fn)
}

// orgLocksEveryRule resolves the tenancy half of the lock: true when
// the organization is authoritative over the whole catalog on this
// node (a managed node), false when an org bundle is only a floor over
// the rules it names (an individual node). An UNRESOLVED tenancy
// reports true - the pre-P2-8 answer - so a process that cannot afford
// the lookup never widens local override authority.
func (g *Guard) orgLocksEveryRule() bool {
	fn := g.managedTenancy.Load()
	if fn == nil {
		return true
	}
	return (*fn)()
}

// OrgOverridePosture is the whole org-granted override answer off ONE
// policy snapshot: which rules the org marked overridable, which rules
// the bundle names, and how far the lock reaches on this node.
//
// It is THE one owner of the question. Single-row callers use
// OrgOverrideStatus (which is this type plus a For), and read surfaces
// that annotate MANY rows (the dashboard's guard-event timeline) take
// the posture once and call For per row - never a snapshot load per
// row.
type OrgOverridePosture struct {
	// OrgApplies reports whether an org policy bundle is loaded at
	// all. False = an individual, un-enrolled node, where every other
	// field is empty and the whole mechanism is inert.
	OrgApplies bool
	// LocksEveryRule is the tenancy half (Guard.orgLocksEveryRule):
	// true on a managed node (and on a process with unresolved
	// tenancy), false on an individual node where the bundle only
	// locks the rules it names.
	LocksEveryRule bool
	// Overridable is the set of rule IDs the org bundle marked
	// `overridable = true`.
	Overridable map[string]bool
	// Named is the set of rule IDs the org bundle NAMES at all (an
	// [[override]] target or an org-defined rule). It is the lock's
	// blast radius on an individual node.
	Named map[string]bool
	// Unverifiable reports that the org bundle exists but cannot be
	// verified and no last verified layer stands in for it, on a node where
	// the org's authority reaches every rule (T-844): every rule is locked.
	Unverifiable bool
}

// For answers the per-rule question. Both false means the rule is
// untouched by the org layer on this node: local approvals apply
// exactly as they did before enrolment.
func (p OrgOverridePosture) For(ruleID string) (overridable, orgLocked bool) {
	if ruleID == "" {
		return false, false
	}
	if p.Unverifiable {
		return false, true
	}
	if !p.OrgApplies {
		return false, false
	}
	if p.Overridable[ruleID] {
		return true, false
	}
	return false, p.LocksEveryRule || p.Named[ruleID]
}

// OrgOverridePosture reports the org-granted override posture against
// the LIVE policy snapshot. The zero-ish result (OrgApplies=false) is
// the individual-node case, where the whole mechanism is inert.
func (g *Guard) OrgOverridePosture() OrgOverridePosture {
	es := g.set.Load()
	if !es.orgApplies() {
		return OrgOverridePosture{Unverifiable: g.orgUnverifiable(es)}
	}
	out := OrgOverridePosture{
		OrgApplies:     true,
		LocksEveryRule: g.orgLocksEveryRule(),
		Overridable:    map[string]bool{},
		Named:          es.orgNamedRules,
	}
	for _, info := range es.base().RuleInfos() {
		// Multi-row IDs (R-152's write/read split) grant as a unit:
		// one overridable row makes the public ID overridable.
		if info.Overridable {
			out.Overridable[info.ID] = true
		}
	}
	return out
}

// OrgOverrideStatus reports the org-granted override posture of ONE
// rule ID: overridable when the org bundle marked it so, orgLocked
// when the bundle locks it here and did not. Both false means the org
// layer does not reach this rule on this node (or ruleID is empty).
func (g *Guard) OrgOverrideStatus(ruleID string) (overridable, orgLocked bool) {
	return g.OrgOverridePosture().For(ruleID)
}

// orgLockedVerdict is the pure predicate behind OrgLocked: the org
// layer locks this rule here (orgLocks, resolved by orgLocksRule), the
// verdict names it, and the org did not grant the override.
// Blocking-class only - a flag verdict is not "locked", it never
// blocked anything.
func orgLockedVerdict(v policy.Verdict, orgLocks bool) bool {
	return orgLocks && v.RuleID != "" && !v.Overridable && v.Decision >= policy.DecisionAsk
}

// orgLocksVerdictRule folds the snapshot's blast radius and the
// Guard's tenancy into the one question orgLockedVerdict takes. Kept
// beside it so no caller re-derives the pair.
//
// projectRoot is the event's root ("" on a lane that carries none): inside a
// root whose org project sections loaded, the rules they name are locked on
// an individual node too (audit finding 3). The root's engine is resolved
// first (a cached map read after the evaluation that produced the verdict)
// so its named set is installed.
func (g *Guard) orgLocksVerdictRule(es *engineSet, ruleID, projectRoot string) bool {
	if ruleID == "" {
		return false
	}
	if !es.orgApplies() {
		// T-844: an org bundle that exists but cannot be verified, with no
		// last verified layer to stand in for it, leaves the org's floor
		// UNKNOWN on a node where the org's authority reaches every rule.
		// Every rule is locked then (orglock.go orgUnverifiable): a local
		// approval must not be what turns a broken bundle into an allow.
		return g.orgUnverifiable(es)
	}
	if projectRoot != "" && es.orgProjectsInForce() {
		es.engineFor(g, projectRoot)
	}
	return es.orgLocksRule(ruleID, projectRoot, g.orgLocksEveryRule())
}

// stampOrgOverride stamps the org-override posture onto a freshly
// built verdict row. Called by every seam that constructs an
// ActionVerdict, from the SAME snapshot that produced the verdict (the
// NIT one-snapshot-per-evaluation contract).
func (g *Guard) stampOrgOverride(es *engineSet, av *ActionVerdict) {
	g.stampOrgOverrideAt(es, av, av.Input.ProjectRoot)
}

// stampOrgOverrideAt is stampOrgOverride with the root the project layer was
// looked up under (the hook path's derived root, projectLookupRoot), which
// the persisted row's ProjectRoot does not carry.
func (g *Guard) stampOrgOverrideAt(es *engineSet, av *ActionVerdict, projectRoot string) {
	if av.Verdict.RuleID == "" {
		return
	}
	av.Overridable = av.Verdict.Overridable
	av.OrgLocked = orgLockedVerdict(av.Verdict, g.orgLocksVerdictRule(es, av.Verdict.RuleID, projectRoot))
	av.RequestBase = g.requestBase
}

// blockedWhatByKind names the blocked thing for the human-first line,
// keyed by the normalized EVENT KIND (Module rule 3/5: a data table
// over the policy vocabulary - never a branch on the client, tool or
// adapter name). An unlisted kind falls back to blockedWhatFallback.
var blockedWhatByKind = map[policy.EventKind]string{
	policy.KindShellExec:    "this command",
	policy.KindFileAccess:   "this file access",
	policy.KindConfigChange: "this configuration change",
	policy.KindToolCall:     "this tool call",
	policy.KindMCPCall:      "this MCP call",
	policy.KindAPIRequest:   "this request",
	policy.KindAPIResponse:  "this response",
	policy.KindUserPrompt:   "this prompt",
	policy.KindSessionMeta:  "this action",
}

// blockedWhatFallback is the neutral noun for an unmapped event kind.
const blockedWhatFallback = "this action"

// HumanBlockLine renders the ONE human-first line that leads a blocked
// message under an org bundle (the prompt-guard house style,
// internal/hook/promptsubmit.go::promptHouseMessage): what was
// blocked, and whether the organization allows the developer to take
// it anyway. Empty string when the org layer does not reach this rule
// - which keeps an individual node's deny text byte-identical to the
// pre-wave text.
//
// THE COMMAND IS ONLY PRINTED WHEN IT WOULD WORK (adversarial review
// P2-7). Every approval scope the node can grant is anchored to a
// session or to a project root resolved FROM that session, so a lane
// that reports no session id - the proxy lane whenever the client sets
// no prompt_cache_key / Session-Id and the pidbridge misses - has
// nothing to scope a grant to. Printing `--session <session-id>` there
// hands the developer a command that cannot be completed, so the
// no-session arm points at the node dashboard Security page instead.
//
// Hyphens only, never em-dashes: this string is read by humans in
// terminals, desktop toasts and provider error bodies.
func HumanBlockLine(av ActionVerdict, sessionID string) string {
	if av.Verdict.RuleID == "" || (!av.Overridable && !av.OrgLocked) {
		return ""
	}
	what, ok := blockedWhatByKind[av.Kind]
	if !ok {
		what = blockedWhatFallback
	}
	switch {
	case av.Overridable && sessionID != "":
		return fmt.Sprintf(
			"observer: %s blocked %s. The organization allows an override: the developer (not the agent) runs `observer guard approve %s --session %s`, then the call can be retried.",
			av.Verdict.RuleID, what, av.Verdict.RuleID, sessionID)
	case av.Overridable:
		return fmt.Sprintf(
			"observer: %s blocked %s. The organization allows an override, but this lane reported no session id, so the override cannot be scoped from the command line here; grant it on the Observer dashboard Security page instead.",
			av.Verdict.RuleID, what)
	}
	return requestAccessLine(av.Verdict.RuleID, what)
}

// RequestAccessMaxBytes bounds the org-locked deny line (request-grants G4):
// the node dashboard shows the first 200 bytes of an error body, and every
// vendor reply leads with this line, so the request path must survive a
// host that shows only the start of the reason.
const RequestAccessMaxBytes = 200

// requestAccessVariants is the ordered fallback table for the org-locked
// line: the richest variant that fits RequestAccessMaxBytes wins; the last
// row always fits. The line is read in band by the agent, so it carries no
// URL (WINNODE2 16d: an agent treated the localhost request link as an
// undocumented service and refused to use it, or might try to call it). It
// is an instruction the agent relays to the developer; the link itself is
// offered where a human reads it (the dashboard, the desktop notification,
// RequestAccessLink).
var requestAccessVariants = []func(head, cli string) string{
	func(h, c string) string {
		return h + " Ask your admin: Observer dashboard, Requests page, or run " + c + "."
	},
	func(h, _ string) string {
		return h + " Ask your admin for an exception from the Observer dashboard, Requests page."
	},
	func(h, _ string) string { return h + " Ask your admin for an exception." },
}

// requestAccessLine renders the org-locked block line: what was blocked,
// that the organization locks the rule, and how the developer asks for an
// exception. Hyphens only, US spelling, one line, no URL.
func requestAccessLine(ruleID, what string) string {
	head := fmt.Sprintf("observer: %s blocked %s; your organization locks this rule.", ruleID, what)
	cli := "`observer request access --rule " + ruleID + " \"<reason>\"`"
	var last string
	for _, render := range requestAccessVariants {
		last = render(head, cli)
		if len(last) <= RequestAccessMaxBytes {
			return last
		}
	}
	return last
}

// RequestAccessLink is the node dashboard request form for a verdict the
// developer can ask about, prefilled (it never submits; nothing leaves the
// machine until the developer presses Send, GRANT-8): an org-locked rule's
// access request, or a budget stop's increase request. "" when the
// dashboard origin is unknown or there is nothing to request. Only a human
// reads it (the desktop notification); in-band reasons carry no URL.
func RequestAccessLink(av ActionVerdict) string {
	if av.RequestBase == "" || av.Verdict.RuleID == "" {
		return ""
	}
	switch {
	case av.Category == string(policy.CategoryBudget):
		return av.RequestBase + BudgetIncreaseRequestPath
	case av.OrgLocked:
		link := av.RequestBase + "/requests?rule=" + url.QueryEscape(av.Verdict.RuleID)
		if av.Input.SessionID != "" {
			link += "&session=" + url.QueryEscape(av.Input.SessionID)
		}
		return link
	}
	return ""
}

// SetRequestAccessBase sets the node dashboard origin the org-locked deny
// line links its request form under ("" = the CLI command only). Set once at
// composition; stampOrgOverride copies it onto every verdict.
func (g *Guard) SetRequestAccessBase(base string) {
	g.requestBase = base
}

// HumanizeEmission prepends HumanBlockLine to a BLOCKING emission's
// reason, so the developer reads one plain sentence first and the
// agent-facing reason follows unchanged. A non-blocking emission, or a
// node whose org layer does not reach the rule, is returned untouched.
func HumanizeEmission(em Emission, av ActionVerdict, sessionID string) Emission {
	if !em.Enforced {
		return em
	}
	line := HumanBlockLine(av, sessionID)
	if line == "" {
		return em
	}
	em.Reason = line + " " + em.Reason
	return em
}
