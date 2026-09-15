package routeattest

import "github.com/marmutapp/superbased-observer/internal/integration"

// Method is HOW a RouteAttestation's State was determined.
type Method string

const (
	// MethodConfig: read directly from the tool's own routing-surface
	// config file (env var or config file) via a grounded, tool-identity-
	// aware Inspector.
	MethodConfig Method = "config"
	// MethodTraffic: no config surface is readable for this tool yet;
	// inferred from a comparison of native session activity against
	// proxied/gateway turn counts (see TrafficSource / AttestByTraffic).
	MethodTraffic Method = "traffic"
	// MethodExempt: the registry marks this tool as having no routable
	// proxy surface at all (RouteStatusNativeExempt or a browser-extension
	// capture hook) — never attested, always shown as exempt.
	MethodExempt Method = "exempt"
)

// Verdict is the classified route posture for one tool.
type Verdict string

const (
	// VerdictRoutedLoopback: config-attested — the tool's routing surface
	// points at an observer loopback proxy.
	VerdictRoutedLoopback Verdict = "routed_loopback"
	// VerdictRoutedOrgGateway: config-attested — the tool's routing surface
	// points at an authorized org AI Gateway endpoint (Plane B dual-mode
	// design §3.2's "authorized non-loopback" case).
	VerdictRoutedOrgGateway Verdict = "routed_org_gateway"
	// VerdictDrifted: config-attested — the tool's routing surface points
	// at a non-loopback host that matches no authorized gateway endpoint. A
	// bypass of the managed route.
	VerdictDrifted Verdict = "drifted"
	// VerdictUnrouted: no route is configured (config-attested absent, or
	// traffic-attested with zero native session activity observed).
	VerdictUnrouted Verdict = "unrouted"
	// VerdictAttestedByTraffic: traffic-attested — native session activity
	// AND proxied/gateway turns were both observed in the window, so the
	// tool is presumed routed even though its config surface can't be read
	// directly.
	VerdictAttestedByTraffic Verdict = "attested_by_traffic"
	// VerdictBypassSuspect: traffic-attested — native session activity was
	// observed with ZERO matching proxied/gateway turns. Evidence of a
	// possible bypass, not proof (a tool that is simply idle in the window
	// reads the same as VerdictUnrouted, not this — this requires observed
	// native activity).
	VerdictBypassSuspect Verdict = "bypass_suspect"
	// VerdictExempt: the tool has no routable proxy surface by design
	// (native-exempt registry row, or browser-extension capture).
	VerdictExempt Verdict = "exempt"
)

// RouteAttestation is one tool's classified route posture: full-coverage-
// by-construction means every tool in integration.Tools() gets exactly one
// of these, never a silent omission.
type RouteAttestation struct {
	// Tool is the registry tool identity (integration.Capability.Tool).
	Tool string
	// Kind is the RouteKind the verdict was dispatched against, derived
	// from the tool's Proxy.Kind (falling back to ProxyProbe.Kind). Empty
	// when the tool carries neither — e.g. a RouteManual tool documented
	// only in registry comments (cline, kilo-code, copilot today) that
	// falls straight to traffic attestation.
	Kind integration.RouteKind
	// Method names how State was determined (config / traffic / exempt).
	Method Method
	// State is the classified verdict.
	State Verdict
	// Reason is a short human-readable explanation of State, safe to show
	// on a dashboard (never carries secrets — config inspectors read only
	// coarse state, per internal/proxyroute's own contract).
	Reason string
}

// IsExempt reports whether cap has no routable proxy surface by design and,
// if so, why. A tool is exempt when the registry marks it
// RouteStatusNativeExempt, OR its Hook mechanism is HookBrowserExtension
// (the *-web browser-capture rows) — checked independently of Routability
// so a future row that ships HookBrowserExtension without also being
// re-classified NativeExempt is still caught, per the design's "attest, not
// gap" mandate. Never derives exemption from a nil Proxy field alone: many
// non-exempt tools (cline, kilo-code, copilot) carry Proxy==nil because
// their route is manual-paste (RouteManual), not because they are exempt —
// those fall to traffic attestation instead.
func IsExempt(cap integration.Capability) (bool, string) {
	if cap.Routability == integration.RouteStatusNativeExempt {
		return true, "registry Routability=native_exempt — no routable proxy surface"
	}
	if cap.Hook.Mechanism == integration.HookBrowserExtension {
		return true, "browser-extension capture (Hook=chrome_native_messaging) — no proxy-route surface by design"
	}
	return false, ""
}

// kindOf derives the RouteKind a capability's config-lane attestation
// should dispatch on: the verified Proxy.Kind if present, else the writer-
// binding ProxyProbe.Kind (an unpromoted probe still names the shape init
// would write), else "" when neither is set (a RouteManual tool documented
// only in comments, or a tool with genuinely no routing surface at all).
func kindOf(cap integration.Capability) (integration.RouteKind, bool) {
	if cap.Proxy != nil && cap.Proxy.Kind != "" {
		return cap.Proxy.Kind, true
	}
	if cap.ProxyProbe != nil && cap.ProxyProbe.Kind != "" {
		return cap.ProxyProbe.Kind, true
	}
	return "", false
}
