package routeattest

import "github.com/marmutapp/superbased-observer/internal/integration"

// AttestAll classifies every tool in the integration registry's closed
// vocabulary (integration.Tools()) and returns exactly one RouteAttestation
// per tool, in sorted-tool order — full coverage by construction, per §3.3.
//
// homeDir and gateways are passed straight through to the config-lane
// inspectors (see internal/proxyroute's Inspect*WithGateways functions);
// traffic is the caller-injected TrafficSource used for tools whose
// config surface can't be read directly. A nil traffic source degrades
// those tools to VerdictUnrouted with an honest reason rather than
// erroring.
//
// Dispatch order per tool:
//  1. Exempt (IsExempt) — no routable surface by design.
//  2. Config — the tool's derived RouteKind (kindOf) has an Inspector in
//     configInspectors that recognizes THIS tool's identity (ok=true).
//  3. Traffic — everything else, via AttestByTraffic.
//
// This is the seam a server-side rollup or the web2 per-node route-
// attestation matrix consumes directly: call once per node/homeDir (or
// once server-side per reporting node, with the node's own homeDir/
// gateways/traffic-window supplied by that layer) and render the returned
// slice — this package performs no aggregation, persistence, or cross-node
// rollup of its own.
func AttestAll(homeDir string, gateways []string, traffic TrafficSource) []RouteAttestation {
	tools := integration.Tools()
	out := make([]RouteAttestation, 0, len(tools))
	for _, tool := range tools {
		row, _ := integration.For(tool)
		out = append(out, attestOne(row, homeDir, gateways, traffic))
	}
	return out
}

// attestOne classifies a single Capability. Split out from AttestAll for
// table-driven testability without needing the full registry.
func attestOne(row integration.Capability, homeDir string, gateways []string, traffic TrafficSource) RouteAttestation {
	kind, _ := kindOf(row)

	if exempt, reason := IsExempt(row); exempt {
		return RouteAttestation{Tool: row.Tool, Kind: kind, Method: MethodExempt, State: VerdictExempt, Reason: reason}
	}

	if kind != "" {
		if insp, found := configInspectors[kind]; found {
			if verdict, reason, ok := insp(row.Tool, homeDir, gateways); ok {
				return RouteAttestation{Tool: row.Tool, Kind: kind, Method: MethodConfig, State: verdict, Reason: reason}
			}
		}
	}

	verdict, reason := AttestByTraffic(row.Tool, traffic)
	return RouteAttestation{Tool: row.Tool, Kind: kind, Method: MethodTraffic, State: verdict, Reason: reason}
}
