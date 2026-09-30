package guard

import (
	"github.com/marmutapp/superbased-observer/internal/policy"
)

// Agent Access P4 W4d (doc3 §12.6): the node MCP-access seam.
//
// The compiled `tools.mcp_access` node decision table lives in the relay
// (internal/mcprelay/localpdp); guard never imports it. Like MCPPinLookup,
// the daemon composition injects ONE plain-result lookup, and guard stamps
// its answer onto every KindMCPCall event as an MCPFinding BEFORE the rule
// engine runs — so R-306 (server not approved) and R-307 (org grant denies)
// evaluate through the REAL engine, with [guard.rules] disable/overrides,
// approvals, mode and the org lock applying exactly like every other rule.
// Every channel that builds a KindMCPCall event gets the same answer: the
// hook PreToolUse seam (the one pre-execution channel — this is the hook
// deny), the watcher ingest path and the proxy's response inspection.
//
// Honesty rule: a lookup that has NO table loaded reports Known=false and
// stamps nothing — an ungoverned node is not a violation. Lookup failures
// must report Known=false too: fail toward "no finding", never toward a
// fabricated deny.

// MCPAccessVerdict is the plain result the injected lookup returns for one
// MCP call (server + bare tool name).
type MCPAccessVerdict struct {
	// Known is true when a compiled node table was consulted. false =
	// nothing loaded / lookup failed / relay disabled → no finding.
	Known bool
	// Allowed is true when the table's first matching row allows the call.
	Allowed bool
	// OrgDenied distinguishes an explicit org DENY (or an ask this channel
	// cannot honour) from a server the table does not know at all:
	// true → R-307, false (with Allowed=false) → R-306.
	OrgDenied bool
	// Reason is the bounded, content-free detail the verdict reason
	// carries (the matched grant id / "no row matched").
	Reason string
}

// MCPAccessLookup answers one (server, tool) pair. Must be cheap and
// non-blocking: it runs on the hook reply path.
type MCPAccessLookup func(server, tool string) MCPAccessVerdict

// SetMCPAccessLookup wires (or, with nil, removes) the node MCP-access
// lookup. Safe to call after construction and concurrently with
// evaluation: the daemon binds it once the relay's table holder exists,
// which may be after the guard was built.
func (g *Guard) SetMCPAccessLookup(fn MCPAccessLookup) {
	if fn == nil {
		g.mcpAccess.Store(nil)
		return
	}
	g.mcpAccess.Store(&fn)
}

// stampMCPAccess appends the R-306/R-307 finding to a KindMCPCall event
// when the lookup reports a non-allowed, known verdict. Every other kind
// and every inert/allow answer leaves the event untouched.
func (g *Guard) stampMCPAccess(ev *policy.Event) {
	if ev.Kind != policy.KindMCPCall {
		return
	}
	fnp := g.mcpAccess.Load()
	if fnp == nil || *fnp == nil {
		return
	}
	server := policy.MCPServerFromTarget(ev.Target)
	if server == "" {
		return
	}
	v := (*fnp)(server, policy.MCPToolFromTarget(ev.Target))
	if !v.Known || v.Allowed {
		return
	}
	kind := policy.MCPFindingUnapprovedServer
	if v.OrgDenied {
		kind = policy.MCPFindingOrgGrantDenied
	}
	ev.MCPFindings = append(ev.MCPFindings, policy.MCPFinding{
		Kind:   kind,
		Server: server,
		Client: ev.Tool,
		Detail: v.Reason,
	})
}
