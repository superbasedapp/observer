package guard

import "fmt"

// Where a blocked call's approval is granted (control-coverage audit CG-16).
//
// The block texts used to send every developer to the node dashboard
// Security page. On a managed node that page is hidden by default
// (nodegov.ManagedNavDefaults), and the approvals API it calls is refused
// while it is hidden, so the pointer led nowhere; the no-session arms had no
// command-line alternative at all. The guard does not read governance itself:
// the boundary wires SetApprovalPageHidden, and the verdict carries the
// answer (ActionVerdict.ApprovalPageHidden), so every text below is a pure
// function of the verdict.

// noSessionApproveTTL bounds the node-wide approval the no-session arms offer
// when the Security page is hidden. A call that reported no session id has
// nothing narrower to scope a grant to (the P2-7 rule in HumanBlockLine), so
// the command grants every session on this machine, briefly.
const noSessionApproveTTL = "15m"

// SetApprovalPageHidden wires the lookup that reports whether the dashboard
// Security page is hidden on this machine. Nil (the default) means shown.
func (g *Guard) SetApprovalPageHidden(fn func() bool) {
	if fn == nil {
		g.approvalPageHidden.Store(nil)
		return
	}
	g.approvalPageHidden.Store(&fn)
}

// approvalPageIsHidden asks the wired lookup; false when none is wired.
func (g *Guard) approvalPageIsHidden() bool {
	p := g.approvalPageHidden.Load()
	if p == nil || *p == nil {
		return false
	}
	return (*p)()
}

// sessionApproveAlso is the parenthetical that follows the session-scoped
// approve command: the dashboard alternative, only while the page is shown.
func sessionApproveAlso(av ActionVerdict) string {
	if av.ApprovalPageHidden {
		return ""
	}
	return " (or approves it on the Observer dashboard Security page)"
}

// noSessionApprove is how the developer approves rule when the call carried
// no session id: on the Security page while it is shown, otherwise with a
// short node-wide CLI grant (the only scope a session-less call can match).
func noSessionApprove(av ActionVerdict, rule string) string {
	if av.ApprovalPageHidden {
		return fmt.Sprintf("runs `observer guard approve %s --global --ttl %s` (every session on this machine, for %s)", rule, noSessionApproveTTL, noSessionApproveTTL)
	}
	return fmt.Sprintf("approves %s on the Observer dashboard Security page", rule)
}
