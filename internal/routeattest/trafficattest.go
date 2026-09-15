package routeattest

import "fmt"

// TrafficSource supplies the two counts AttestByTraffic needs for a tool,
// over whatever window the caller chooses (e.g. the last N days of
// sessions/api_turns). Implementations live outside this package (the
// store seam) — routeattest stays pure and never touches database/sql
// itself.
type TrafficSource interface {
	// NativeAndProxiedCounts returns, for tool:
	//   - native: count of locally captured session/action activity (hook,
	//     transcript, or SQLite capture — however that tool's adapter
	//     observes it natively), and
	//   - proxied: count of turns that landed through observer's proxy or
	//     an authorized org AI Gateway (api_turns rows / gateway-attributed
	//     turns) for the same tool in the same window.
	NativeAndProxiedCounts(tool string) (native, proxied int)
}

// AttestByTraffic classifies tool's route posture from traffic counts when
// its config surface can't be read directly (RouteLauncher, RouteManual,
// a RouteProviderJSON/RouteVSCodeSettings tool, or a RouteKind shared with
// a tool that has no per-tool config reader — see configattest.go). A nil
// traffic source is treated as "no evidence available" (VerdictUnrouted),
// never fabricated.
//
// Classification:
//   - native > 0 && proxied > 0: VerdictAttestedByTraffic — the tool is
//     active AND its activity is landing through an observed route.
//   - native > 0 && proxied == 0: VerdictBypassSuspect — the tool is
//     active but NONE of it is landing through an observed route; evidence
//     of a possible bypass (not proof — see VerdictBypassSuspect doc).
//   - native == 0: VerdictUnrouted — no native activity in the window, so
//     there is nothing to attest either way.
func AttestByTraffic(tool string, traffic TrafficSource) (Verdict, string) {
	if traffic == nil {
		return VerdictUnrouted, "no traffic source supplied"
	}
	native, proxied := traffic.NativeAndProxiedCounts(tool)
	switch {
	case native > 0 && proxied > 0:
		return VerdictAttestedByTraffic, fmt.Sprintf("native activity (%d) and proxied/gateway turns (%d) both observed in window", native, proxied)
	case native > 0:
		return VerdictBypassSuspect, fmt.Sprintf("native activity (%d) observed with zero proxied/gateway turns — possible bypass", native)
	default:
		return VerdictUnrouted, "no native session activity observed in window"
	}
}
