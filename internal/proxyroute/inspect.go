package proxyroute

import (
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/BurntSushi/toml"
)

// inspect.go — read-only route inspectors for the Arc 4 P6b managed-integrity
// probe (plan §9). They report whether a managed node's AI-tool proxy routes
// still point at an observer proxy or have DRIFTED away (repointed at a
// non-loopback host = a bypass of the managed proxy). They never write, and
// they return only a coarse state per tool — never the config value — so the
// caller can build the content-floored managed-integrity wire.
//
// EVIDENCE, not prevention: a developer who owns the machine can edit these
// configs back and forth; this catches the ordinary repoint and feeds the admin
// a signal (§5 MDM gate is the actual lock).

// RouteState classifies one tool's current proxy-route posture.
type RouteState string

const (
	// RouteOurs: the tool points at an observer proxy (any loopback port).
	RouteOurs RouteState = "ours"
	// RouteDrifted: the tool points at a non-loopback host — a bypass of the
	// managed proxy (repointed at a third-party endpoint or direct upstream).
	RouteDrifted RouteState = "drifted"
	// RouteAbsent: no route configured (config or key missing). A tool that was
	// never routed is not drift; it is simply not captured.
	RouteAbsent RouteState = "absent"
	// RouteOrgGateway: the tool points at a published org AI Gateway endpoint
	// (Gateway Mode thin routing, or a node whose managed config points a tool
	// straight at the gateway). A non-loopback host that MATCHES an authorized
	// gateway endpoint is Routed-remote (authorized), NOT drift
	// (docs/plans/plane-b-dual-mode-gateway-rbac-ia-design-2026-08-29.md §3.2).
	// Anything else non-loopback stays RouteDrifted.
	RouteOrgGateway RouteState = "org_gateway"
)

// RouteStatus is one tool's inspected route posture. Tool is the adapter
// identity (e.g. "claude-code", "codex") — not secret.
type RouteStatus struct {
	Tool  string
	State RouteState
}

// classifyBaseURLWithGateways maps a raw base-URL string to a RouteState. An
// empty value is Absent; a loopback observer URL (any port — matching the
// Register* tolerance for a second install on a different port) is Ours; a
// non-loopback host matching any published org-gateway endpoint (§3.2) is
// RouteOrgGateway (authorized); anything else is Drifted. gateways is the
// authorized endpoint list (the org-route primary + fallbacks); nil/empty
// gives the gateway-unaware behavior (every non-loopback host is drift).
func classifyBaseURLWithGateways(raw string, gateways []string) RouteState {
	if raw == "" {
		return RouteAbsent
	}
	if IsObserverBaseURL(raw) {
		return RouteOurs
	}
	if IsOrgGatewayBaseURL(raw, gateways) {
		return RouteOrgGateway
	}
	return RouteDrifted
}

// IsOrgGatewayBaseURL reports whether raw points at one of the authorized org
// AI Gateway endpoints. Match is on scheme+host+port (path ignored) so a tool
// that appends "/v1" to the gateway base still matches. nil/empty gateways ⇒
// never a match.
func IsOrgGatewayBaseURL(raw string, gateways []string) bool {
	if raw == "" || len(gateways) == 0 {
		return false
	}
	target := normalizeRouteHost(raw)
	if target == "" {
		return false
	}
	for _, g := range gateways {
		if normalizeRouteHost(g) == target {
			return true
		}
	}
	return false
}

// normalizeRouteHost reduces a base URL to a lowercase scheme://host[:port]
// key for endpoint equality, dropping any path/query. Returns "" when the
// input has no host.
func normalizeRouteHost(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		return ""
	}
	return strings.ToLower(u.Scheme) + "://" + strings.ToLower(u.Host)
}

// InspectClaudeRoute reads env.ANTHROPIC_BASE_URL from
// <homeDir>/.claude/settings.json (the value RegisterClaudeCode writes) and
// classifies it. A missing file, missing env block, or missing key is Absent.
func InspectClaudeRoute(homeDir string) RouteStatus {
	return InspectClaudeRouteWithGateways(homeDir, nil)
}

// InspectClaudeRouteWithGateways is InspectClaudeRoute with org-gateway
// awareness: a base URL matching an authorized gateway endpoint classifies
// RouteOrgGateway instead of RouteDrifted (§3.2). nil gateways ⇒ identical to
// InspectClaudeRoute.
func InspectClaudeRouteWithGateways(homeDir string, gateways []string) RouteStatus {
	res := RouteStatus{Tool: "claude-code", State: RouteAbsent}
	raw, err := os.ReadFile(filepath.Join(homeDir, ".claude", "settings.json"))
	if err != nil {
		return res
	}
	var settings struct {
		Env map[string]string `json:"env"`
	}
	if err := json.Unmarshal(raw, &settings); err != nil {
		return res
	}
	res.State = classifyBaseURLWithGateways(settings.Env["ANTHROPIC_BASE_URL"], gateways)
	return res
}

// InspectCodexRoute resolves the base_url of the provider that
// <homeDir>/.codex/config.toml's top-level model_provider points at and
// classifies it. No model_provider, no matching provider block, or no base_url
// is Absent; a non-loopback base_url is Drifted.
func InspectCodexRoute(homeDir string) RouteStatus {
	return InspectCodexRouteWithGateways(homeDir, nil)
}

// InspectCodexRouteWithGateways is InspectCodexRoute with org-gateway
// awareness (§3.2). nil gateways ⇒ identical to InspectCodexRoute.
func InspectCodexRouteWithGateways(homeDir string, gateways []string) RouteStatus {
	res := RouteStatus{Tool: "codex", State: RouteAbsent}
	raw, err := os.ReadFile(filepath.Join(homeDir, ".codex", "config.toml"))
	if err != nil {
		return res
	}
	root := map[string]any{}
	if err := toml.Unmarshal(raw, &root); err != nil {
		return res
	}
	mp, _ := root["model_provider"].(string)
	if mp == "" {
		return res
	}
	providers, _ := root["model_providers"].(map[string]any)
	block, _ := providers[mp].(map[string]any)
	base, _ := block["base_url"].(string)
	res.State = classifyBaseURLWithGateways(base, gateways)
	return res
}

// InspectRoutes runs every read-only route inspector for homeDir and returns
// one RouteStatus per tool. The managed-integrity probe counts the Drifted ones.
func InspectRoutes(homeDir string) []RouteStatus {
	return InspectRoutesWithGateways(homeDir, nil)
}

// InspectRoutesWithGateways is InspectRoutes with org-gateway awareness: a
// tool pointed at an authorized gateway endpoint reports RouteOrgGateway
// instead of RouteDrifted (§3.2). nil gateways ⇒ identical to InspectRoutes.
func InspectRoutesWithGateways(homeDir string, gateways []string) []RouteStatus {
	return []RouteStatus{
		InspectClaudeRouteWithGateways(homeDir, gateways),
		InspectCodexRouteWithGateways(homeDir, gateways),
	}
}
