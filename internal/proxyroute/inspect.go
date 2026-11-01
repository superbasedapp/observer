package proxyroute

import (
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/BurntSushi/toml"

	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
	"github.com/marmutapp/superbased-observer/internal/proxyauth"
	"github.com/marmutapp/superbased-observer/internal/routeprov"
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
	// RouteOurs: the tool points at an observer proxy (any loopback port;
	// RouteStatus.Port says which, and the drift reading compares it with
	// the daemon's own listener, T-901).
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
	// RouteUnknown: Observer cannot name the tool's route file on this host,
	// so it did not look. A relocation variable (RouteStatus.UnresolvedBy)
	// holds a relative value the tool reads against its own working
	// directory, or the row has no file on this OS. ArtifactPresent is
	// false and ConfigPath is empty: the vendor default under the home is
	// not what the tool reads, so reading it would report a route the tool
	// never uses (R-188 F6). Never drift, never written by maintenance.
	RouteUnknown RouteState = "unknown"
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
	// ConfigPath is the config file this row reads and its writer writes.
	// It is local to the node: the managed-integrity wire carries only a
	// home-relative label of it, never the path. Empty for RouteUnknown.
	ConfigPath string
	// UnresolvedBy names the relocation variable whose relative value hides
	// the route file (State RouteUnknown), "" otherwise. A variable name,
	// never its value.
	UnresolvedBy string
	// Routability says whether Observer can write this tool's route on this
	// host (HostRoutability). It is evaluated for a row whose route is
	// absent while its config is present, the only shape where it decides
	// anything; the zero value means "not evaluated" and is read on the loud
	// side (an absent route still counts as drift).
	Routability HostRoutability
	// WasRouted reports that the route-provenance file holds a record for
	// this tool and config file: Observer wrote or confirmed this route
	// before. A missing route that WAS routed is a removal, whatever the
	// config now looks like.
	WasRouted bool
	// LaneWritable reports, for a tool pointed at a host other than Observer
	// (State RouteDrifted), that the host is a third-party provider the
	// registry row can carry through a proxy route lane (ProxyRoute.
	// ForeignLane) and a dry run of the lane writer accepts this config. The
	// wrong host is still reported until the managed daemon routes it.
	LaneWritable bool
	// Port is the port a loopback route names (State RouteOurs), its
	// scheme default when the URL names none; 0 for any other state. The
	// drift reading compares it with the daemon's own proxy port (T-901): a
	// loopback route at another port does not reach this proxy and may be a
	// local forwarder around it.
	Port int
	// Lane reports that the route is a third-party-provider route lane
	// (an Observer URL under /up/route-...), not the fixed upstream route.
	Lane bool
	// OrgRouted reports that the route-provenance record for this tool and
	// config file was written by the organization (enrolment or the managed
	// daemon, routeprov.OrgOwned), not by the developer's own `observer
	// init`. An unreadable provenance file reads as OrgRouted, the loud
	// side, like WasRouted.
	OrgRouted bool
	// OrgWrittenExact reports, for a loopback route (State RouteOurs), that
	// Observer provably wrote it (portmove.go, D-745): a readable
	// organization-written provenance record holds exactly this value, and
	// the value is exactly what the tool's writer writes at the route's own
	// port. Unlike OrgRouted it is false on an unreadable provenance file:
	// it licenses a write, so it is never assumed. Route maintenance moves
	// such a route to this daemon's proxy port when the port changed.
	OrgWrittenExact bool
	// ClientAuth reports that a loopback route (State RouteOurs) carries the
	// proxy client token (http://127.0.0.1:<port>/t/<token>..., OSH-R-009).
	// A plain loopback route at the proxy's port is what keeps
	// [proxy].require_client_auth from being enforced (proxyauth.Enforce).
	ClientAuth bool
	// ClientAuthWritable reports that this tool's route writer writes the
	// client token form (the inspection row's clientAuth), so maintenance
	// can move the route between the plain and the token form.
	ClientAuthWritable bool
}

// HostRoutability is whether Observer can write one tool's proxy route on
// this host.
type HostRoutability string

const (
	// RoutabilityUnknown: not evaluated (the zero value).
	RoutabilityUnknown HostRoutability = ""
	// RoutabilityWritable: the registry row allows an unattended route
	// write (routable_now, a persisted kind, no launch gate, no upstream
	// lane) and a dry run of the writer accepts this host's config.
	RoutabilityWritable HostRoutability = "writable"
	// RoutabilityNotRoutable: the registry row offers no route the daemon
	// may write unattended (launcher-only, manual, a gated or lane route, or
	// a tool that is not routable_now).
	RoutabilityNotRoutable HostRoutability = "not_routable"
	// RoutabilityConfigNotCovered: the row is writable in general, but this
	// host's config selects a provider the writer does not route (kimi-code
	// with no [providers.openai] table, a qwen-code settings file with no
	// model.baseUrl, a codex model_provider set to another built-in), so the
	// writer refuses it.
	RoutabilityConfigNotCovered HostRoutability = "config_not_covered"
)

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
	// artifact is the agentconfig FileRow id of the route file. The row
	// owns the file's default path and its relocation rules (surface-gap
	// Wave 4).
	artifact string
	// read is TRI-STATE on purpose. It reads the config file at path and
	// returns the persisted base URL it found and whether the tool's config
	// ARTIFACT exists on this host:
	//
	//   ("", false)   the config file is not there (tool not installed here)
	//   ("", true)    the config file is there, the route key is gone/empty
	//   (url, true)   the config file is there and names this base URL
	//
	// A reader must never collapse the first two: they are the difference
	// between "not routed because there is nothing to route" and "routed
	// once, not any more", and only the second can be drift.
	read func(path string) (baseURL string, artifactPresent bool)
	// clientAuth says the row's writer writes the proxy client token form
	// when its registrar holds a token (RegisterOptions.ClientToken), and
	// rewrites a route of its own between the plain and the token form.
	clientAuth bool
	// path is the config file read and write address, resolved exactly as
	// the writer resolves it (env overrides included). Every row reads the
	// file at this one address, so the inspector and its writer cannot
	// disagree about where the value lives. An error (the writer's own
	// refusal, routeArtifactPath) means the row reads nothing and reports
	// RouteUnknown.
	path func(e inspectEnv) (string, error)
	// write is the guarded writer for this row's route: the same method
	// `observer init` calls, so the managed daemon and init cannot disagree
	// about where or how the route is written.
	write func(r *Registrar) RegistrationResult
	// laneWrite is the third-party-provider lane writer (lane.go), or nil.
	// It is used only when the registry row declares ProxyRoute.ForeignLane.
	laneWrite func(r *Registrar) RegistrationResult
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
//
// Every row names its route file's agentconfig artifact. The Claude Code and
// Codex rows resolve their path through it (artifactRowPath), so a
// relocation rule on the row reaches the inspector, the writer and the
// routability dry run at once. The kimi-code, qwen-code and crush rows
// resolve through their writer's own resolver (kimicode.go, qwencode.go,
// crush.go), handed the inspection's environment; the artifact id
// pins that the writer's default is the row's default
// (TestRouteInspectorArtifactsMatchTheWriters).
func routeInspectors() []routeInspector {
	return []routeInspector{
		{tool: "claude-code", kind: integration.RouteEnvSettings, artifact: claudeSettingsArtifact, read: readClaudeBaseURL, path: artifactRowPath("proxyroute.claude", claudeSettingsArtifact), write: (*Registrar).RegisterClaudeCode, clientAuth: true},
		{tool: "codex", kind: integration.RouteConfigFile, artifact: codexConfigArtifact, read: readCodexBaseURL, path: artifactRowPath("proxyroute.codex", codexConfigArtifact), write: (*Registrar).RegisterCodex, clientAuth: true},
		{tool: "kimi-code", kind: integration.RouteConfigFile, artifact: "kimi-code/user-config", read: readKimiCodeBaseURL, path: func(e inspectEnv) (string, error) { return resolveKimiCodeConfigPath(e.home, e.getenv) }, write: (*Registrar).RegisterKimiCode, laneWrite: (*Registrar).RegisterKimiCodeLane},
		{tool: "qwen-code", kind: integration.RouteConfigFile, artifact: "qwen-code/user-settings", read: readQwenCodeBaseURL, path: func(e inspectEnv) (string, error) { return resolveQwenConfigPath(e.home, e.getenv) }, write: (*Registrar).RegisterQwenCode, laneWrite: (*Registrar).RegisterQwenCodeLane},
		{tool: "crush", kind: integration.RouteProviderJSON, artifact: "crush/user-json", read: readCrushBaseURL, path: func(e inspectEnv) (string, error) { return resolveCrushConfigPath(e.home, e.getenv) }, write: (*Registrar).RegisterCrush},
	}
}

// inspectEnv is the machine one inspection reads: the home and the
// environment that relocates its route files.
type inspectEnv struct {
	home   string
	getenv func(string) string
}

// artifactRowPath is a row path that resolves the agentconfig artifact id
// under the inspected home with the inspection's environment, through the
// writers' own routeArtifactPath.
func artifactRowPath(what, id string) func(e inspectEnv) (string, error) {
	return func(e inspectEnv) (string, error) { return routeArtifactPath(what, id, e.home, e.getenv) }
}

// routeMaintainable reports whether a registry row allows an UNATTENDED
// route write: the tool is routable_now, its VERIFIED route (Proxy, never a
// ProxyProbe) is a persisted kind this package can read back, and the route
// is unconditional (no launch-time credential gate, no /up/<id> lane the
// proxy must be configured for first). A capability-shape question, never a
// tool name (CLAUDE.md #3).
func routeMaintainable(c integration.Capability) bool {
	if c.Routability != integration.RouteStatusRoutableNow || c.Proxy == nil {
		return false
	}
	return routeKindInspectable[c.Proxy.Kind] && c.Proxy.Gate == nil && c.Proxy.Lane == nil
}

// dryRunProxyPort is the port the coverage dry run renders. The question it
// answers ("would the writer route this config?") does not depend on it.
const dryRunProxyPort = 8820

// hostRoutability decides whether Observer can write ri's route on this
// host: the registry row first, then a DRY RUN of the row's own writer (no
// file is written, no provenance recorded), so "covers this config" is the
// writer's answer, never a second copy of its guard rules.
func hostRoutability(ri routeInspector, e inspectEnv) HostRoutability {
	c, _ := integration.For(ri.tool)
	if !routeMaintainable(c) || ri.write == nil {
		return RoutabilityNotRoutable
	}
	dry, err := NewRegistrar(RegisterOptions{ProxyPort: dryRunProxyPort, HomeDir: e.home, DryRun: true, Getenv: e.getenv})
	if err != nil {
		return RoutabilityConfigNotCovered
	}
	res := ri.write(dry)
	if res.Error != nil || res.ConfigMissing || (!res.Added && !res.AlreadySet) {
		return RoutabilityConfigNotCovered
	}
	return RoutabilityWritable
}

// laneCapable reports whether a registry row lets the managed daemon carry
// a third-party provider host through a proxy route lane: an unattended
// route row (routeMaintainable) that also declares ProxyRoute.ForeignLane.
func laneCapable(c integration.Capability) bool {
	return routeMaintainable(c) && c.Proxy.ForeignLane != nil
}

// laneWritable dry-runs ri's lane writer (no file written, no provenance
// recorded) when the row is lane capable.
func laneWritable(ri routeInspector, e inspectEnv) bool {
	c, _ := integration.For(ri.tool)
	if ri.laneWrite == nil || !laneCapable(c) {
		return false
	}
	dry, err := NewRegistrar(RegisterOptions{ProxyPort: dryRunProxyPort, HomeDir: e.home, DryRun: true, Getenv: e.getenv})
	if err != nil {
		return false
	}
	res := ri.laneWrite(dry)
	return res.Error == nil && res.Added && res.LaneID != ""
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

// readClaudeBaseURL reads env.ANTHROPIC_BASE_URL from the Claude Code user
// settings.json at path (the value RegisterClaudeCode writes).
//
// Tri-state per routeInspector.read: an unreadable/absent settings.json is
// ("", false) — Claude Code is not set up on this host. A settings.json that
// IS there but carries no env block, no key, or unparseable JSON is
// ("", true): the tool is configured here and the route is not.
func readClaudeBaseURL(path string) (string, bool) {
	raw, err := os.ReadFile(path)
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

// readCodexBaseURL resolves the base_url of the provider that the Codex
// config.toml at path's top-level model_provider points at.
//
// Tri-state per routeInspector.read: an absent config.toml is ("", false) —
// Codex is not set up on this host. A config.toml that IS there but names no
// model_provider, no matching provider block, or no base_url is ("", true).
func readCodexBaseURL(path string) (string, bool) {
	raw, err := os.ReadFile(path)
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

// readKimiCodeBaseURL reads the base_url Kimi Code actually talks to in
// <kimi-home>/config.toml: the ACTIVE provider's (default_model's alias ->
// its provider) when that provider is OpenAI-compatible (type "openai"), the
// key RegisterKimiCodeLane rewrites; otherwise base_url under
// [providers.openai], the key RegisterKimiCode additively writes.
//
// Tri-state per routeInspector.read: an absent config.toml is ("", false).
func readKimiCodeBaseURL(path string) (string, bool) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", false
	}
	root := map[string]any{}
	if err := toml.Unmarshal(raw, &root); err != nil {
		return "", true
	}
	providers, _ := root["providers"].(map[string]any)
	if alias, _ := root["default_model"].(string); alias != "" {
		models, _ := root["models"].(map[string]any)
		model, _ := models[alias].(map[string]any)
		if name, _ := model["provider"].(string); name != "" {
			if p, _ := providers[name].(map[string]any); p != nil {
				if t, _ := p["type"].(string); strings.TrimSpace(t) == "openai" {
					base, _ := p["base_url"].(string)
					return base, true
				}
			}
		}
	}
	openai, _ := providers["openai"].(map[string]any)
	base, _ := openai["base_url"].(string)
	return base, true
}

// readQwenCodeBaseURL reads model.baseUrl from <qwen-home>/settings.json —
// the key RegisterQwenCode rewrites, and (per its own live grounding) the
// only lane that actually decides Qwen Code's host.
//
// Tri-state per routeInspector.read: an absent settings.json is ("", false).
func readQwenCodeBaseURL(path string) (string, bool) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", false
	}
	root := map[string]any{}
	if err := json.Unmarshal(raw, &root); err != nil {
		return "", true
	}
	model, _ := root["model"].(map[string]any)
	base, _ := model["baseUrl"].(string)
	if strings.TrimSpace(base) == qwenDefaultBaseURL {
		// The stock default host is "not routed yet", not a repoint: it is
		// exactly the value RegisterQwenCode is allowed to replace, so
		// reading it as a wrong host would leave a routable tool reported
		// as redirection evidence and never repaired.
		return "", true
	}
	return base, true
}

// readCrushBaseURL reads providers.openai.base_url from crush.json — the key
// RegisterCrush additively writes.
//
// Tri-state per routeInspector.read: an absent crush.json is ("", false).
func readCrushBaseURL(path string) (string, bool) {
	raw, err := os.ReadFile(path)
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

// InspectClaudeRoute reads env.ANTHROPIC_BASE_URL from the Claude Code user
// settings.json under homeDir (the value RegisterClaudeCode writes) and
// classifies it. A missing file, missing env block, or missing key is Absent.
func InspectClaudeRoute(homeDir string) RouteStatus {
	return InspectClaudeRouteWithGateways(homeDir, nil)
}

// InspectClaudeRouteWithGateways is InspectClaudeRoute with org-gateway
// awareness: a base URL matching an authorized gateway endpoint classifies
// RouteOrgGateway instead of RouteDrifted (§3.2). nil gateways ⇒ identical to
// InspectClaudeRoute.
func InspectClaudeRouteWithGateways(homeDir string, gateways []string) RouteStatus {
	return inspectOne(inspectorFor("claude-code"), newInspectEnv(homeDir, nil), gateways, provenanceView{})
}

// InspectCodexRoute resolves the base_url of the provider that the Codex
// user config.toml's top-level model_provider points at and classifies it.
// No model_provider, no matching provider block, or no base_url is Absent; a
// non-loopback base_url is Drifted.
func InspectCodexRoute(homeDir string) RouteStatus {
	return InspectCodexRouteWithGateways(homeDir, nil)
}

// InspectCodexRouteWithGateways is InspectCodexRoute with org-gateway
// awareness (§3.2). nil gateways ⇒ identical to InspectCodexRoute.
func InspectCodexRouteWithGateways(homeDir string, gateways []string) RouteStatus {
	return inspectOne(inspectorFor("codex"), newInspectEnv(homeDir, nil), gateways, provenanceView{})
}

// newInspectEnv is the inspection machine for homeDir. A nil getenv is the
// one pinned-home rule for a named home (crossmount.HomeEnvAt, R-188 F1), the
// RegisterOptions.Getenv rule for a caller that names its home: the process
// environment when homeDir is this process's own, non-isolated home, and
// none otherwise, so a pinned test or sandbox home resolves every file
// under itself.
func newInspectEnv(homeDir string, getenv func(string) string) inspectEnv {
	return inspectEnv{home: homeDir, getenv: crossmount.HomeEnvAt(homeDir, getenv)}
}

// inspectorFor returns the inspection-table row for tool. Every caller names
// a tool the table holds (the two named inspectors above).
func inspectorFor(tool string) routeInspector {
	for _, ri := range routeInspectors() {
		if ri.tool == tool {
			return ri
		}
	}
	return routeInspector{tool: tool, read: func(string) (string, bool) { return "", false }}
}

// errNoInspectorPath is readAt's error for a row with no path function.
var errNoInspectorPath = errors.New("proxyroute: inspector row has no path")

// readAt runs the row's reader against its resolved path. An error is the
// path's refusal: nothing was read, and the row reports RouteUnknown.
func (ri routeInspector) readAt(e inspectEnv) (path, baseURL string, present bool, err error) {
	if ri.path == nil {
		return "", "", false, errNoInspectorPath
	}
	path, err = ri.path(e)
	if err != nil {
		return "", "", false, err
	}
	baseURL, present = ri.read(path)
	return path, baseURL, present, nil
}

// inspectOne runs one table row. prov is the route-provenance file read once
// by the caller (the zero view holds no records). A row whose route file
// cannot be named reports RouteUnknown and nothing else (R-188 F6).
func inspectOne(ri routeInspector, e inspectEnv, gateways []string, prov provenanceView) RouteStatus {
	path, raw, present, err := ri.readAt(e)
	if err != nil {
		return RouteStatus{Tool: ri.tool, Kind: ri.kind, State: RouteUnknown, UnresolvedBy: unresolvedRelocation(err)}
	}
	rs := RouteStatus{
		Tool:            ri.tool,
		Kind:            ri.kind,
		State:           classifyBaseURLWithGateways(raw, gateways),
		ArtifactPresent: present,
		ConfigPath:      path,
		// The writer's capability, reported on every row so a caller can
		// tell a plain route maintenance will convert from one it cannot.
		ClientAuthWritable: ri.clientAuth,
	}
	rs.WasRouted = prov.wasRouted(ri.tool, rs.ConfigPath)
	rs.OrgRouted = prov.orgRouted(ri.tool, rs.ConfigPath)
	if rs.State == RouteOurs {
		rs.Port = observerURLPort(raw)
		rs.Lane = isLaneURL(raw)
		rs.ClientAuth = proxyauth.HasToken(raw)
		rs.OrgWrittenExact = prov.orgWrittenExact(ri.tool, rs.ConfigPath, raw, rs.Port)
	}
	if rs.State == RouteAbsent && rs.ArtifactPresent {
		rs.Routability = hostRoutability(ri, e)
	}
	if rs.State == RouteDrifted {
		rs.LaneWritable = laneWritable(ri, e)
	}
	return rs
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
	return InspectRoutesWith(homeDir, InspectOptions{Gateways: gateways})
}

// InspectOptions parameterizes InspectRoutesWith.
type InspectOptions struct {
	// Gateways is the authorized org-gateway endpoint list (§3.2); nil gives
	// the gateway-unaware reading.
	Gateways []string
	// Getenv reads the variables that relocate a route file
	// (CLAUDE_CONFIG_DIR, CODEX_HOME and every other rule on the files'
	// agentconfig rows). nil means the process environment when homeDir is
	// this process's own, non-isolated home, and none otherwise
	// (crossmount.HomeEnvAt, R-188 F1), the RegisterOptions.Getenv rule.
	Getenv func(string) string
}

// InspectRoutesWith is InspectRoutes with explicit options.
func InspectRoutesWith(homeDir string, o InspectOptions) []RouteStatus {
	rows := routeInspectors()
	e := newInspectEnv(homeDir, o.Getenv)
	prov := inspectProvenance(homeDir)
	out := make([]RouteStatus, 0, len(rows))
	for _, ri := range rows {
		out = append(out, inspectOne(ri, e, o.Gateways, prov))
	}
	return out
}

// provenanceView is the route-provenance file as the inspection reads it.
type provenanceView struct {
	file *routeprov.File
	// unreadable: the file exists but could not be read or parsed. Every
	// row then reads as WasRouted, the loud side: a damaged record must not
	// turn a removed route into "this config was never routable" (the
	// hook_checksums.json precedent, where a deleted registry is a risk).
	unreadable bool
}

// wasRouted reports whether the view holds a record for tool at path.
func (v provenanceView) wasRouted(tool, path string) bool {
	if v.unreadable {
		return true
	}
	return v.file != nil && path != "" && v.file.Find(tool, path) != nil
}

// orgRouted reports whether the view holds a record for tool at path that
// the organization wrote (routeprov.OrgOwned).
func (v provenanceView) orgRouted(tool, path string) bool {
	if v.unreadable {
		return true
	}
	if v.file == nil || path == "" {
		return false
	}
	rec := v.file.Find(tool, path)
	return rec != nil && routeprov.OrgOwned(rec.Writer)
}

// inspectProvenance reads the route-provenance file a registrar for homeDir
// keeps. An absent file is an empty view.
func inspectProvenance(homeDir string) provenanceView {
	f, err := loadProvenance(filepath.Join(homeDir, ".observer", ProvenanceFileName))
	if err != nil {
		return provenanceView{unreadable: true}
	}
	return provenanceView{file: &f}
}

// DriftMode is how the node's route posture reads its inspected routes for
// the managed-integrity `drifted_tools` label set. It is a capability value
// the boundary resolves from govern.Effective.RoutePosture (cmd/observer
// routeDriftPolicies), never a tool or a tenancy name (CLAUDE.md #3).
type DriftMode string

const (
	// DriftModeOff: nothing is drift. The admin turned route maintenance off
	// (posture release): no route is required, so a tool on its own provider
	// is the setup the admin chose, not a bypass (T-900, RETEST5 F4).
	DriftModeOff DriftMode = "off"
	// DriftModeOrgRoutes: no posture (unset, and the org governs no
	// enforcement point in the API proxy). Nothing is maintained, and the
	// routes the organization wrote earlier are left in place (D-738). Only
	// such a route (RouteStatus.OrgRouted) can drift: gone, at another host,
	// or at another loopback port means the organization's route no longer
	// reaches this proxy. A route the organization never wrote is the
	// developer's own setup.
	DriftModeOrgRoutes DriftMode = "org_routes"
	// DriftModeMaintained: the organization requires routes and the daemon
	// maintains them (posture maintain). Every installed tool whose route
	// does not reach this proxy is drift, unless Observer cannot route it
	// here and never did (UnroutableTools coverage).
	DriftModeMaintained DriftMode = "maintained"
)

// DriftPolicy is the drift reading's input beyond the inspected rows.
type DriftPolicy struct {
	Mode DriftMode
	// ProxyPort is the port the daemon's own proxy listens on. A loopback
	// route at another port does not reach it (a second install, or a local
	// forwarder that could send traffic past the proxy), so it is drift
	// wherever a route is required (T-901). 0: ports are not compared.
	ProxyPort int
	// Selection is the node's component selection, the same one route
	// maintenance acts on. The zero value selects routing and every tool,
	// the pre-T-915 reading.
	Selection Selection
}

// Selection is what the node's component policy selected for managed
// routes, resolved at the cmd boundary from the component state (a
// capability, never a tool name). Route maintenance, the integrity probe and
// `observer doctor` all read the one value, so they cannot disagree.
type Selection struct {
	// RoutingOff reports that the route writer component itself
	// (integration.proxy-route) is not active: inactive by policy, or not in
	// this build at all (the minimal distro). Route maintenance then writes
	// nothing, so no tool's route is drift; the installed tools read as
	// "routing switched off by policy" (RoutingOffTools) instead (T-915,
	// D-771).
	RoutingOff bool
	// Tool reports whether the policy selected one tool (its adapter is
	// active), the filter route maintenance writes with
	// (MaintainOptions.Allow). An installed tool it does not select is never
	// routed by the daemon, so it is never drift: it reads as "installed, not
	// selected by policy" (UnselectedTools) instead (T-915, D-770). Nil
	// selects every tool.
	Tool func(tool string) bool
}

// selects reports whether p's policy selected tool (nil: every tool).
func (p DriftPolicy) selects(tool string) bool {
	return p.Selection.Tool == nil || p.Selection.Tool(tool)
}

// RoutingSwitchedOff reports whether p reads routes at all (not
// DriftModeOff) and the route writer component is not active, so the node
// keeps no routes and the admin sees "routing switched off by policy". Under
// DriftModeOff (the admin turned route maintenance off) nothing changes.
func RoutingSwitchedOff(p DriftPolicy) bool {
	return p.Mode != DriftModeOff && p.Selection.RoutingOff
}

// DriftedTools classifies an inspection into the managed-integrity
// `drifted_tools` label set under policy p (routeVerdictRules).
//
// An absent route only counts when the tool's config ARTIFACT is actually
// present (RouteStatus.ArtifactPresent: "the config is here, the route key is
// not"). A tool the developer never installed leaves no artifact, so it is
// never drift under any mode: a developer who only uses Claude Code must not
// report codex, crush, kimi-code and qwen-code as four drifted routes.
//
// Under DriftModeMaintained an absent route on a present config is drift only
// when Observer could have written it (RouteStatus.Routability is writable,
// so the managed daemon repairs it on its next pass and the drift clears) or
// when Observer DID route it before (RouteStatus.WasRouted: a removal). A
// tool whose route Observer cannot write on this host and never wrote is not
// drift: UnroutableTools reports it as coverage. A wrong host is drift and is
// never overwritten (unless it is a provider the daemon carries through a
// route lane, which keeps that host as the upstream).
//
// A tool the policy did not select (Selection.Tool) is never drift under any
// mode: route maintenance does not route it, so its route is not the
// organization's to keep. UnselectedTools reports it instead (T-915). With
// the route writer component inactive (Selection.RoutingOff) no tool is
// drift: RoutingOffTools reports the installed ones (D-771).
func DriftedTools(statuses []RouteStatus, p DriftPolicy) []string {
	var out []string
	for _, rs := range statuses {
		if routeVerdictFor(rs, p) == verdictDrift {
			out = append(out, rs.Tool)
		}
	}
	sort.Strings(out)
	return out
}

// UnroutableTools lists the tools whose config is on this host, whose route
// is absent, and whose route Observer cannot write here and never wrote. It
// is honest COVERAGE ("installed, not routed, and Observer cannot route it"),
// never integrity drift, under any mode: it always reads the maintained table.
// Wherever routes are read (every mode but DriftModeOff) it also reads p's
// selection, so a tool the policy did not select is UnselectedTools and a
// node with routing switched off is RoutingOffTools, never also unroutable;
// under DriftModeOff the list is what it was before T-915 (the admin turned
// route maintenance off, so nothing about it changes).
func UnroutableTools(statuses []RouteStatus, p DriftPolicy) []string {
	q := DriftPolicy{Mode: DriftModeMaintained}
	if p.Mode != DriftModeOff {
		q.Selection = p.Selection
	}
	return toolsWithVerdict(statuses, q, verdictUnroutable)
}

// RoutingOffTools lists the installed tools (config on this host) of a node
// whose route writer component is not active (Selection.RoutingOff), under
// every mode that reads routes at all. The daemon writes no route there, so
// none of them is drift: the admin sees "routing switched off by policy"
// naming them (T-915, D-771).
func RoutingOffTools(statuses []RouteStatus, p DriftPolicy) []string {
	return toolsWithVerdict(statuses, p, verdictRoutingOff)
}

// UnselectedTools lists the tools whose config is on this host but whose
// adapter the node's policy did not select (Selection.Tool), under
// every mode that reads routes at all (not DriftModeOff). Route maintenance
// never routes such a tool, so it is coverage ("installed, not selected by
// policy"), never drift (T-915, D-770).
func UnselectedTools(statuses []RouteStatus, p DriftPolicy) []string {
	return toolsWithVerdict(statuses, p, verdictUnselected)
}

// InactiveProviderTools lists the tools whose route Observer wrote is in the
// config but whose active provider is another one (RouteInactiveProvider,
// so the statuses must have been through ApplyActiveProvider), under p: the
// managed-integrity `inactive_provider_tools` labels (DEC-7). Never drift;
// nothing under DriftModeOff, with routing switched off, for a tool the
// policy did not select, or (no posture) for a route the organization never
// wrote.
func InactiveProviderTools(statuses []RouteStatus, p DriftPolicy) []string {
	return toolsWithVerdict(statuses, p, verdictInactiveProvider)
}

// toolsWithVerdict returns the sorted tools whose row reads as want under p.
func toolsWithVerdict(statuses []RouteStatus, p DriftPolicy, want routeVerdict) []string {
	var out []string
	for _, rs := range statuses {
		if routeVerdictFor(rs, p) == want {
			out = append(out, rs.Tool)
		}
	}
	sort.Strings(out)
	return out
}

// routeVerdict is what one inspected row means for the integrity probe.
type routeVerdict int

const (
	verdictClear routeVerdict = iota
	verdictDrift
	verdictUnroutable
	verdictUnselected
	verdictRoutingOff
	verdictInactiveProvider
)

// routeVerdictRule is one row of the drift table.
type routeVerdictRule struct {
	match   func(rs RouteStatus, p DriftPolicy) bool
	verdict routeVerdict
}

// otherPort reports a loopback route at a port other than the daemon's own
// proxy listener (p.ProxyPort 0: not compared).
func otherPort(rs RouteStatus, p DriftPolicy) bool {
	return rs.State == RouteOurs && p.ProxyPort > 0 && rs.Port > 0 && rs.Port != p.ProxyPort
}

// routeVerdictRules is the drift table (CLAUDE.md #5), walked top-down; the
// first match wins. One test case per row (TestRouteVerdictRules).
var routeVerdictRules = []routeVerdictRule{
	// Route maintenance is off: nothing is required, nothing is drift.
	{func(_ RouteStatus, p DriftPolicy) bool { return p.Mode == DriftModeOff }, verdictClear},
	// Observer cannot name the route file (a relative relocation variable):
	// it read nothing, so it has nothing to call drift (R-188 F6).
	{func(rs RouteStatus, _ DriftPolicy) bool { return rs.State == RouteUnknown }, verdictClear},
	// Installed, and the route writer component is not active (switched off
	// by policy, or not in this build): the daemon writes no route, so
	// nothing is drift (D-771).
	{func(rs RouteStatus, p DriftPolicy) bool { return rs.ArtifactPresent && p.Selection.RoutingOff }, verdictRoutingOff},
	// Installed, but the policy did not select the tool: route maintenance
	// never routes it, so whatever its route says is not drift (T-915).
	{func(rs RouteStatus, p DriftPolicy) bool { return rs.ArtifactPresent && !p.selects(rs.Tool) }, verdictUnselected},
	// An authorized org gateway is a route the organization published.
	{func(rs RouteStatus, _ DriftPolicy) bool { return rs.State == RouteOrgGateway }, verdictClear},
	// No posture: only a route the organization wrote (and left in place)
	// can drift; anything else is the developer's own setup.
	{func(rs RouteStatus, p DriftPolicy) bool { return p.Mode == DriftModeOrgRoutes && !rs.OrgRouted }, verdictClear},
	// A wrong host is redirection evidence. Never overwritten.
	{func(rs RouteStatus, _ DriftPolicy) bool { return rs.State == RouteDrifted }, verdictDrift},
	// A loopback route at another port than this proxy's listener: it does
	// not reach the proxy (T-901). Never overwritten either.
	{otherPort, verdictDrift},
	// The route is in the file, but the tool's active provider is another
	// one (RouteInactiveProvider, set by ApplyActiveProvider): its turns do
	// not reach the proxy, yet the route the daemon keeps is intact, so a
	// repair would change nothing. Its own reading, never drift (DEC-7).
	// Rows above still win: with maintenance off, routing off or the tool
	// not selected it is not reported, and with no posture only a route the
	// organization wrote is.
	{func(rs RouteStatus, _ DriftPolicy) bool { return rs.State == RouteInactiveProvider }, verdictInactiveProvider},
	// Ours: nothing to say.
	{func(rs RouteStatus, _ DriftPolicy) bool { return rs.State == RouteOurs }, verdictClear},
	// The tool is not installed here: there is no route to have lost.
	{func(rs RouteStatus, _ DriftPolicy) bool { return !rs.ArtifactPresent }, verdictClear},
	// Observer routed it before and it is gone: a removal. Under
	// DriftModeOrgRoutes every row left here is an organization route.
	{func(rs RouteStatus, _ DriftPolicy) bool { return rs.WasRouted }, verdictDrift},
	// Installed, never routed, and Observer cannot write the route here.
	{func(rs RouteStatus, _ DriftPolicy) bool {
		return rs.Routability == RoutabilityNotRoutable || rs.Routability == RoutabilityConfigNotCovered
	}, verdictUnroutable},
	// Writable (or not evaluated, the loud side) and missing: drift until
	// the managed daemon repairs it.
	{func(RouteStatus, DriftPolicy) bool { return true }, verdictDrift},
}

// routeVerdictFor walks routeVerdictRules for one row.
func routeVerdictFor(rs RouteStatus, p DriftPolicy) routeVerdict {
	for _, r := range routeVerdictRules {
		if r.match(rs, p) {
			return r.verdict
		}
	}
	return verdictClear
}

// observerURLPort is the port a loopback observer URL names, its scheme
// default when it names none, 0 when raw is not one.
func observerURLPort(raw string) int {
	if !IsObserverBaseURL(raw) {
		return 0
	}
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return 0
	}
	port := u.Port()
	switch {
	case port != "":
	case u.Scheme == "https":
		port = "443"
	default:
		port = "80"
	}
	n := 0
	for _, c := range port {
		if c < '0' || c > '9' {
			return 0
		}
		n = n*10 + int(c-'0')
		if n > 65535 {
			return 0
		}
	}
	return n
}

// isLaneURL reports an Observer URL that addresses a route lane
// (/up/route-<id>/...), the shape the lane writers write.
func isLaneURL(raw string) bool {
	if !IsObserverBaseURL(raw) {
		return false
	}
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return false
	}
	_, path, _ := proxyauth.SplitPath(u.Path)
	return strings.HasPrefix(path, "/up/"+RouteLanePrefix)
}

// ObserverRoutePorts reports, for every inspected tool whose persisted route
// points at a loopback observer URL, the port that URL names (U9, lane
// FIX-UPGRADE): a route written for :8820 keeps pointing there after
// [proxy].port changes, because Register* treats any loopback route as
// already set. A URL without an explicit port reports its scheme default.
// Read-only, like every inspector.
func ObserverRoutePorts(homeDir string) map[string]int {
	out := map[string]int{}
	e := newInspectEnv(homeDir, nil)
	for _, ri := range routeInspectors() {
		_, raw, _, _ := ri.readAt(e)
		if n := observerURLPort(raw); n > 0 {
			out[ri.tool] = n
		}
	}
	return out
}

// LaneRoutedTools reports the inspected tools whose persisted route is a
// third-party-provider route lane (an Observer URL under /up/route-...).
// Read-only and cheap (no dry run), for `observer doctor`'s per-tool route
// note (T-903).
func LaneRoutedTools(homeDir string) map[string]bool {
	out := map[string]bool{}
	e := newInspectEnv(homeDir, nil)
	for _, ri := range routeInspectors() {
		_, raw, _, _ := ri.readAt(e)
		if isLaneURL(raw) {
			out[ri.tool] = true
		}
	}
	return out
}
