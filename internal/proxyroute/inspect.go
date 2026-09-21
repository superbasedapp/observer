package proxyroute

import (
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/BurntSushi/toml"

	"github.com/marmutapp/superbased-observer/internal/integration"
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
	// RouteAbsent: no route configured — either the tool's config artifact
	// does not exist on this host at all, or it exists and carries no route
	// key. A tool that was never routed is not drift; it is simply not
	// captured. RouteStatus.ArtifactPresent is what tells the two apart, and
	// only the second can ever be read as drift (see DriftedTools).
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
	// Kind is the integration registry's RouteKind for this tool — the
	// capability SHAPE the inspector dispatched on (CLAUDE.md #3). It is
	// carried so a caller can reason about the route MECHANISM without
	// re-deriving it from a tool name.
	Kind integration.RouteKind
	// ArtifactPresent reports whether the tool's own persisted config file
	// EXISTS and was readable on this host — independently of whether a
	// route key was found inside it. It is what makes RouteAbsent legible:
	//
	//   false — the config is not there. The developer does not use this
	//           tool on this machine, so there is no route to have lost.
	//   true  — the config is there and the route key is gone or empty. On a
	//           managed node the organization provisioned that route, so this
	//           is the shape a bypass leaves behind.
	//
	// Without it, "absent" on a managed node meant "drift" for every tool the
	// developer never installed — a Claude-Code-only developer reported four
	// drifted tools the moment the stricter reading shipped.
	ArtifactPresent bool
}

// routeInspector is one row of the read-only inspection table (Track C
// item 2, docs/plans/org-guardrail-control-wave-2026-09-21.md).
//
// The table is keyed by the registry's RouteKind, never by tool name: adding
// a tool is adding a row whose `read` returns that tool's persisted base URL
// plus whether the tool's config artifact exists at all, and the
// classification, the gateway allowance and the drift rule are shared by
// every row.
//
// COVERAGE IS HONEST BY CONSTRUCTION. A row exists exactly when proxyroute
// owns a guarded, grounded WRITER for that tool's persisted route — i.e. when
// there is a file this package knows how to read the route out of. The three
// PERSISTED kinds (env_settings / config_file / provider_json) are the only
// inspectable ones: RouteLauncher exports the base URL at exec time and
// leaves nothing on disk, RouteVSCodeSettings and RouteManual have no writer
// at all, so "absent" for those would mean "we did not look", not "the route
// is gone". routeKindInspectable is the table that states that, and
// TestEveryPersistedRouteKindIsInspectable holds it to the registry.
type routeInspector struct {
	tool string
	kind integration.RouteKind
	// read is TRI-STATE on purpose. It returns the persisted base URL it
	// found and whether the tool's config ARTIFACT exists on this host:
	//
	//   ("", false)   the config file is not there (tool not installed here)
	//   ("", true)    the config file is there, the route key is gone/empty
	//   (url, true)   the config file is there and names this base URL
	//
	// A reader must never collapse the first two: they are the difference
	// between "not routed because there is nothing to route" and "routed
	// once, not any more", and only the second can be drift.
	read func(homeDir string) (baseURL string, artifactPresent bool)
}

// routeKindInspectable maps every RouteKind to whether a persisted artifact
// exists that an inspector could read. A kind absent from this map is treated
// as NOT inspectable (the safe direction: we never claim to have looked).
var routeKindInspectable = map[integration.RouteKind]bool{
	integration.RouteEnvSettings:    true,
	integration.RouteConfigFile:     true,
	integration.RouteProviderJSON:   true,
	integration.RouteLauncher:       false, // env var at exec time; nothing on disk
	integration.RouteVSCodeSettings: false, // no writer; the registry ships a hint string only
	integration.RouteManual:         false, // no writer by definition
}

// routeInspectors is the inspection table. One row per tool whose persisted
// proxy route this package writes, so an inspector and its writer always
// agree about where the value lives.
func routeInspectors() []routeInspector {
	return []routeInspector{
		{tool: "claude-code", kind: integration.RouteEnvSettings, read: readClaudeBaseURL},
		{tool: "codex", kind: integration.RouteConfigFile, read: readCodexBaseURL},
		{tool: "kimi-code", kind: integration.RouteConfigFile, read: readKimiCodeBaseURL},
		{tool: "qwen-code", kind: integration.RouteConfigFile, read: readQwenCodeBaseURL},
		{tool: "crush", kind: integration.RouteProviderJSON, read: readCrushBaseURL},
	}
}

// InspectedTools returns the adapter ids this package can inspect a route
// for, sorted. It is the SOURCE of the managed-integrity `drifted_tools`
// label vocabulary — orgcontract's validator is held to it by a test rather
// than hand-maintained alongside it.
func InspectedTools() []string {
	out := make([]string, 0, len(routeInspectors()))
	for _, ri := range routeInspectors() {
		out = append(out, ri.tool)
	}
	sort.Strings(out)
	return out
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

// readClaudeBaseURL reads env.ANTHROPIC_BASE_URL from
// <homeDir>/.claude/settings.json (the value RegisterClaudeCode writes).
//
// Tri-state per routeInspector.read: an unreadable/absent settings.json is
// ("", false) — Claude Code is not set up on this host. A settings.json that
// IS there but carries no env block, no key, or unparseable JSON is
// ("", true): the tool is configured here and the route is not.
func readClaudeBaseURL(homeDir string) (string, bool) {
	raw, err := os.ReadFile(filepath.Join(homeDir, ".claude", "settings.json"))
	if err != nil {
		return "", false
	}
	var settings struct {
		Env map[string]string `json:"env"`
	}
	if err := json.Unmarshal(raw, &settings); err != nil {
		return "", true
	}
	return settings.Env["ANTHROPIC_BASE_URL"], true
}

// readCodexBaseURL resolves the base_url of the provider that
// <homeDir>/.codex/config.toml's top-level model_provider points at.
//
// Tri-state per routeInspector.read: an absent config.toml is ("", false) —
// Codex is not set up on this host. A config.toml that IS there but names no
// model_provider, no matching provider block, or no base_url is ("", true).
func readCodexBaseURL(homeDir string) (string, bool) {
	raw, err := os.ReadFile(filepath.Join(homeDir, ".codex", "config.toml"))
	if err != nil {
		return "", false
	}
	root := map[string]any{}
	if err := toml.Unmarshal(raw, &root); err != nil {
		return "", true
	}
	mp, _ := root["model_provider"].(string)
	if mp == "" {
		return "", true
	}
	providers, _ := root["model_providers"].(map[string]any)
	block, _ := providers[mp].(map[string]any)
	base, _ := block["base_url"].(string)
	return base, true
}

// readKimiCodeBaseURL reads base_url under [providers.openai] in
// <kimi-home>/config.toml — the key RegisterKimiCode additively writes.
//
// Tri-state per routeInspector.read: an absent config.toml is ("", false).
func readKimiCodeBaseURL(homeDir string) (string, bool) {
	raw, err := os.ReadFile(resolveKimiCodeConfigPath(homeDir))
	if err != nil {
		return "", false
	}
	root := map[string]any{}
	if err := toml.Unmarshal(raw, &root); err != nil {
		return "", true
	}
	providers, _ := root["providers"].(map[string]any)
	openai, _ := providers["openai"].(map[string]any)
	base, _ := openai["base_url"].(string)
	return base, true
}

// readQwenCodeBaseURL reads model.baseUrl from <qwen-home>/settings.json —
// the key RegisterQwenCode rewrites, and (per its own live grounding) the
// only lane that actually decides Qwen Code's host.
//
// Tri-state per routeInspector.read: an absent settings.json is ("", false).
func readQwenCodeBaseURL(homeDir string) (string, bool) {
	raw, err := os.ReadFile(resolveQwenConfigPath(homeDir))
	if err != nil {
		return "", false
	}
	root := map[string]any{}
	if err := json.Unmarshal(raw, &root); err != nil {
		return "", true
	}
	model, _ := root["model"].(map[string]any)
	base, _ := model["baseUrl"].(string)
	return base, true
}

// readCrushBaseURL reads providers.openai.base_url from crush.json — the key
// RegisterCrush additively writes.
//
// Tri-state per routeInspector.read: an absent crush.json is ("", false).
func readCrushBaseURL(homeDir string) (string, bool) {
	raw, err := os.ReadFile(resolveCrushConfigPath(homeDir))
	if err != nil {
		return "", false
	}
	root := map[string]any{}
	if err := json.Unmarshal(raw, &root); err != nil {
		return "", true
	}
	providers, _ := root["providers"].(map[string]any)
	openai, _ := providers["openai"].(map[string]any)
	base, _ := openai["base_url"].(string)
	return base, true
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
	return inspectOne(routeInspector{tool: "claude-code", kind: integration.RouteEnvSettings, read: readClaudeBaseURL}, homeDir, gateways)
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
	return inspectOne(routeInspector{tool: "codex", kind: integration.RouteConfigFile, read: readCodexBaseURL}, homeDir, gateways)
}

// inspectOne runs one table row.
func inspectOne(ri routeInspector, homeDir string, gateways []string) RouteStatus {
	raw, present := ri.read(homeDir)
	return RouteStatus{
		Tool:            ri.tool,
		Kind:            ri.kind,
		State:           classifyBaseURLWithGateways(raw, gateways),
		ArtifactPresent: present,
	}
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
	rows := routeInspectors()
	out := make([]RouteStatus, 0, len(rows))
	for _, ri := range rows {
		out = append(out, inspectOne(ri, homeDir, gateways))
	}
	return out
}

// DriftedTools classifies an inspection into the managed-integrity
// `drifted_tools` label set.
//
// absentIsDrift is the TENANCY-resolved capability flag, not a tool or a
// tenancy name (CLAUDE.md #3): on a managed node where the organization is
// authoritative over some enforcement point
// (govern.Effective.GrantsAnyEnforcement), a tool whose persisted route is
// GONE is drift — the org provisioned that route and its absence is the
// cheapest possible bypass. On an individual node, and on a managed node the
// org only advises, an absent route stays exactly what it always was: a tool
// that is simply not routed (inspect.go's original rule).
//
// absentIsDrift is NOT enough on its own. An absent route only counts when
// the tool's config ARTIFACT is actually present (RouteStatus.ArtifactPresent
// — "the config is here, the route key is not"). A tool the developer never
// installed leaves no artifact, so it is never drift under any tenancy: a
// developer who only uses Claude Code must not report codex, crush, kimi-code
// and qwen-code as four drifted routes and open an integrity_risk finding on
// every node in the fleet the day the stricter reading ships.
//
// Wrong host (RouteDrifted) is drift under BOTH tenancies, unchanged.
func DriftedTools(statuses []RouteStatus, absentIsDrift bool) []string {
	var out []string
	for _, rs := range statuses {
		switch rs.State {
		case RouteDrifted:
			out = append(out, rs.Tool)
		case RouteAbsent:
			if absentIsDrift && rs.ArtifactPresent {
				out = append(out, rs.Tool)
			}
		}
	}
	sort.Strings(out)
	return out
}
