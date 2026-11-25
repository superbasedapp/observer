package routeattest

import "github.com/marmutapp/superbased-observer/internal/integration"

// Method is HOW a tool's route attestation was determined. The org route
// matrix (internal/orgserver/rollup/routematrix.go) stamps it on each tool
// cell.
type Method string

const (
	// MethodTraffic: inferred from the tool's observed session traffic,
	// judged per capture surface by AttestSurfaces.
	MethodTraffic Method = "traffic"
	// MethodExempt: the registry marks this tool as having no routable
	// proxy surface at all (RouteStatusNativeExempt or a browser-extension
	// capture hook) — never attested, always shown as exempt.
	MethodExempt Method = "exempt"
)

// IsExempt reports whether cap has no routable proxy surface by design and,
// if so, why. A tool is exempt when the registry marks it
// RouteStatusNativeExempt, OR its Hook mechanism is HookBrowserExtension
// (the *-web browser-capture rows) — checked independently of Routability
// so a future row that ships HookBrowserExtension without also being
// re-classified NativeExempt is still caught, per the design's "attest, not
// gap" mandate. Never derives exemption from a nil Proxy field alone: many
// non-exempt tools (cline, kilo-code, copilot) carry Proxy==nil because
// their route is manual-paste (RouteManual), not because they are exempt —
// those are judged on their traffic instead.
func IsExempt(cap integration.Capability) (bool, string) {
	if cap.Routability == integration.RouteStatusNativeExempt {
		return true, "registry Routability=native_exempt - no routable proxy surface"
	}
	if cap.Hook.Mechanism == integration.HookBrowserExtension {
		return true, "browser-extension capture (Hook=chrome_native_messaging) - no proxy-route surface by design"
	}
	return false, ""
}
