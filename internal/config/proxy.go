package config

// This file holds the config types of [proxy].

// DefaultProxyClientTokenFile is where the proxy client token lives when
// [proxy].client_token_file is unset (OSH-R-009).
const DefaultProxyClientTokenFile = "~/.observer/proxy-client-token" //nolint:gosec // G101: a PATH, not a credential

// ClientAuthWanted reports whether the node writes and accepts the proxy
// client token: either switch turns it on (require implies routes).
func (p ProxyConfig) ClientAuthWanted() bool { return p.ClientAuthRoutes || p.RequireClientAuth }

// ProxyConfig controls the API reverse proxy.
type ProxyConfig struct {
	Enabled           bool   `toml:"enabled"`
	Port              int    `toml:"port"`
	AnthropicUpstream string `toml:"anthropic_upstream"`
	OpenAIUpstream    string `toml:"openai_upstream"`
	ChatGPTUpstream   string `toml:"chatgpt_upstream"`
	GeminiUpstream    string `toml:"gemini_upstream"`
	ForceChatGPTHTTP  bool   `toml:"force_chatgpt_http"`
	// MaintainRoutes is the org-pinned managed route-maintenance switch (lane
	// P1, node.governance key proxy.maintain_routes). It exists so the pin
	// resolves in this build's config; the daemon reads the pinned value live
	// from the governance posture (govern.Effective.RoutePosture) and never
	// reads this local value, which an individual node has no use for.
	MaintainRoutes bool `toml:"maintain_routes"`
	// RequireClientAuth refuses a proxy request whose base URL does not
	// carry the node's client token (OSH-R-009,
	// docs/plans/proxy-client-auth-2026-10-30.md). Default false: every
	// local client is served, as before. Turning it on implies
	// ClientAuthRoutes, and the daemon enforces it only when no route
	// pointed at the proxy is still in the plain form (proxyauth.Enforce),
	// so a live route is never broken. Read at daemon start; follow the
	// restart runbook. A local switch only in this release: no org pin
	// sets it (the start-time hold-off does not yet see every route a
	// managed node can carry; docs/plans/proxy-client-auth-2026-10-30.md).
	RequireClientAuth bool `toml:"require_client_auth"`
	// ClientAuthRoutes makes `observer init`, the managed route writer and
	// the launchers write the client token form of a route
	// (http://127.0.0.1:<port>/t/<token>...) for every tool whose writer
	// supports it, and has the daemon create the token file. Default false.
	// It is the first, non-breaking step of the migration: the proxy keeps
	// serving plain requests until RequireClientAuth is also on.
	ClientAuthRoutes bool `toml:"client_auth_routes"`
	// ClientTokenFile is where the proxy client token lives (32 random
	// bytes, hex, mode 0600, created on first use when ClientAuthRoutes or
	// RequireClientAuth is on). Default ~/.observer/proxy-client-token. A
	// sandboxed run sees it read-only (it is granted the model proxy).
	ClientTokenFile string `toml:"client_token_file"`
	// PrewarmTargets are URLs the proxy fires HEAD against at startup
	// to populate the http.Transport connection pool with warm TLS
	// sessions (V6-3 mitigation). The first real proxy request reuses
	// a pooled connection, saving the TLS handshake cost that pushed
	// codex's inner-pipe TTFB past its ~15s timeout. Defaults set in
	// Default(); empty slice disables pre-warm entirely.
	PrewarmTargets []string `toml:"prewarm_targets"`
	// Upstreams maps a routing id to an upstream base URL, selected
	// per-request via a `/up/<id>/` path prefix (Phase C per-provider
	// upstream selection). A routed tool whose traffic must reach a
	// non-default host — e.g. hermes → OpenRouter — points its base URL at
	// http://127.0.0.1:<port>/up/<id>/v1 and the proxy strips the prefix
	// and forwards to the mapped host. The value is the host root WITHOUT
	// the version suffix (the client's base URL keeps `/v1`), exactly like
	// the fixed upstreams: e.g. openrouter = "https://openrouter.ai/api".
	// Empty/unset → only the fixed three upstreams exist (current
	// behavior; fail-open). Locally authored here; an org may ALSO
	// distribute lane entries via the signed `gateway.providers` policy
	// family (installed through SetLaneTable, never written back into
	// this file) — the two sources merge at the live lane table, and
	// this TOML block remains the node-local layer.
	Upstreams map[string]string `toml:"upstreams"`
	// AgentUpstreams maps a lane id to the upstream host of a local CODING
	// AGENT's own provider (Plane B), selected by the same `/up/<id>/`
	// prefix but kept OUT of the Upstreams lane table: an agent lane only
	// picks the upstream host, the request keeps pid-derived session
	// attribution, gets no hosted-app admission or obs-trace synthesis,
	// and is not part of the gateway.providers lane policy (so a node
	// with only the default agent lane still reports no local lane
	// policy). A same-id [proxy.upstreams] lane wins. Default:
	// OpenCodeZenLane -> https://opencode.ai/zen (OpenCode's built-in Zen
	// provider; `observer opencode` points it here). The loader merges map
	// keys over the default.
	AgentUpstreams map[string]string `toml:"agent_upstreams"`
	// AutoDefaultLane names the Upstreams lane id the virtual `/up/auto/`
	// lane falls back to (gateway config plane spec Phase 2) when the
	// request's top-level model has no `<lane>/` prefix matching a
	// configured lane. Must name a key present in Upstreams when set
	// (validated below); "" means no default — an unresolvable auto
	// request falls through exactly like an unknown /up/<id> today
	// (fixed upstream, warn-once). Like Upstreams, this is the
	// node-local layer; the signed `gateway.providers` policy family can
	// also set the live auto-default via SetLaneTable.
	AutoDefaultLane string `toml:"auto_default_lane"`
	// OrgRoute is the node-local bootstrap for the org-wide AI Gateway
	// route (Phase P5a, docs/plans/plane-b-dual-mode-gateway-rbac-ia-
	// design-2026-08-29.md §2, Sol S7/S8). It mirrors the Upstreams/
	// AutoDefaultLane relationship above: this TOML block seeds
	// Proxy.SetOrgGatewayRoute at startup, and — once wired at the
	// cmd/observer layer — a signed org policy can supersede it hot with
	// no restart, the same two-source-one-live-table pattern already
	// used for [proxy.upstreams]. The zero value (no [proxy.org_route]
	// section) is fully inert: no SetOrgGatewayRoute call is ever made
	// for it, so an existing config gets byte-identical proxy behavior.
	OrgRoute ProxyOrgRouteConfig `toml:"org_route"`
	// AppLanes hardens the [proxy.upstreams] lanes as the machine's LOCAL APP
	// LANE (hosted AI gateway plan L7, L-172): the call path an app built on
	// this machine points its model client at
	// (http://127.0.0.1:<port>/up/<id>). It adds a hard model allow-list per
	// lane, an in-memory budget reservation over the machine's and the org's
	// app caps, and the usage injection for known hosts. It never adds a
	// lane: a lane exists only once the user adds it ([proxy.upstreams],
	// `observer apps lane add`, or the dashboard; decision 8 of L-174).
	AppLanes ProxyAppLanesConfig `toml:"app_lanes"`
}

// App lane budget modes ([proxy.app_lanes] budget).
const (
	// AppLaneBudgetEnforce refuses a lane call (402) when its worst case
	// would pass a hard app cap. The default.
	AppLaneBudgetEnforce = "enforce"
	// AppLaneBudgetObserve keeps the reservation's books and logs a would-be
	// refusal, but forwards the call.
	AppLaneBudgetObserve = "observe"
	// AppLaneBudgetOff turns the lane reservation off.
	AppLaneBudgetOff = "off"
)

// DefaultAppLaneWorstCaseOutputTokens is the output-token ceiling a lane
// call's worst case is reserved at when the request names no max tokens.
const DefaultAppLaneWorstCaseOutputTokens = 4096

// ProxyAppLanesConfig is [proxy.app_lanes]: the local app lane's hardening.
// The zero value (no [proxy.app_lanes] block) keeps the defaults: budget
// enforced, usage injected for known hosts, every model allowed.
type ProxyAppLanesConfig struct {
	// Models is the hard model allow-list per lane id: a lane listed here
	// forwards only a request whose top-level model matches one pattern
	// ('*' matches any run of characters, '/' included). The key "*" is the
	// list for every lane without its own entry. A lane with no list allows
	// every model. A refused model is a 403 model_not_allowed, never
	// forwarded.
	Models map[string][]string `toml:"models"`
	// Budget is the lane reservation's mode: "enforce" (default), "observe"
	// or "off". The reservation is held in memory (the daemon is one
	// process) over the recorded app spend plus every call in flight, and
	// runs whether or not [observability.admission] is enabled. The caps
	// are the machine's per-user caps ([observability.admission.budget],
	// when its enabled is true) and the org's app caps ([guard.budget]
	// from_org; authoritative on a managed machine).
	Budget string `toml:"budget"`
	// IncludeUsage injects stream_options.include_usage into a streaming
	// chat-completions body on a lane whose upstream host is known to
	// accept it (api.openai.com, openrouter.ai), so a stream reports its
	// usage and is priced exactly. Never on the Responses API. Default true.
	IncludeUsage bool `toml:"include_usage"`
	// WorstCaseOutputTokens is the output ceiling a call is reserved at when
	// its body names no max tokens. Default 4096; 0 keeps the default.
	WorstCaseOutputTokens int `toml:"worst_case_output_tokens"`
}

// BudgetMode returns the effective [proxy.app_lanes] budget mode ("" reads
// as enforce).
func (a ProxyAppLanesConfig) BudgetMode() string {
	if a.Budget == "" {
		return AppLaneBudgetEnforce
	}
	return a.Budget
}

// WorstCaseOutput returns the effective worst-case output ceiling.
func (a ProxyAppLanesConfig) WorstCaseOutput() int {
	if a.WorstCaseOutputTokens <= 0 {
		return DefaultAppLaneWorstCaseOutputTokens
	}
	return a.WorstCaseOutputTokens
}

// ProxyOrgRouteConfig is the node-local bootstrap shape for
// Proxy.SetOrgGatewayRoute(mode, primary, fallbacks) — see ProxyConfig.OrgRoute.
type ProxyOrgRouteConfig struct {
	// Mode is fed to SetOrgGatewayRoute verbatim — it must be exactly ""
	// (node mode, the default: org-route stays inert) or "gateway" (all
	// default-lane traffic, per Sol S8's fall-through guard, redirects to
	// Primary). There is deliberately no "node" synonym for the empty
	// string: this field carries the same wire vocabulary
	// SetOrgGatewayRoute already validates, not a separate translation
	// layer that could drift from it.
	Mode string `toml:"mode"`
	// Primary is the AI Gateway base URL. Required when Mode == "gateway";
	// ignored (and must be empty) when Mode == "".
	Primary string `toml:"primary"`
	// Fallbacks lists additional gateway/provider URLs for the fallback
	// ladder (Sol S10). The runtime executor (Luna L16,
	// internal/proxy/gatewayfallback.go) walks primary → each fallback →
	// TerminalPolicy on exhaustion.
	Fallbacks []string `toml:"fallbacks"`
	// TerminalPolicy is the fallback-ladder terminal rung reached after
	// primary + every fallback endpoint is exhausted: "" or "hold" (the
	// fail-closed default), "break_glass" (permission only — the lease rides
	// the enrolment rail), or "direct" (auto-fallback to the developer's
	// direct provider, which requires DirectFallbackCustodyAck). Fed verbatim
	// to Proxy.SetOrgGatewayRouteWithFallback, which validates it.
	TerminalPolicy string `toml:"terminal_policy"`
	// DirectFallbackCustodyAck acknowledges the custody downgrade that
	// TerminalPolicy == "direct" entails. Ignored for other terminals; the
	// proxy setter refuses to honor a "direct" terminal without it.
	DirectFallbackCustodyAck bool `toml:"direct_fallback_custody_ack"`
}

// EditAppLanes applies edit to the [proxy] block of the config file at path
// (the global config when path is empty) and writes the change: the one
// writer `observer apps lane add|remove` and the dashboard's
// POST/DELETE /api/apps/lanes share. It holds the config write lock the
// dashboard's save pipeline holds, validates the edited config, and patches
// only the keys that changed (StructuralPatches + PatchFile, which keeps
// the file's comments and its previous bytes as the backup). It returns the
// config as written.
func EditAppLanes(path string, edit func(p *ProxyConfig) error) (Config, error) {
	resolved, err := ResolveGlobalPath(path)
	if err != nil {
		return Config{}, err
	}
	mu := WriteLock()
	mu.Lock()
	defer mu.Unlock()
	cfg, err := Load(LoadOptions{GlobalPath: resolved})
	if err != nil {
		return Config{}, err
	}
	next := cfg
	next.Proxy.Upstreams = cloneStringMap(cfg.Proxy.Upstreams)
	next.Proxy.AppLanes.Models = cloneModelLists(cfg.Proxy.AppLanes.Models)
	if err := edit(&next.Proxy); err != nil {
		return Config{}, err
	}
	if err := Validate(next); err != nil {
		return Config{}, err
	}
	patches, err := StructuralPatches(cfg, next)
	if err != nil {
		return Config{}, err
	}
	if len(patches) == 0 {
		return next, nil
	}
	if _, err := PatchFile(resolved, next, patches); err != nil {
		return Config{}, err
	}
	return next, nil
}

func cloneStringMap(m map[string]string) map[string]string {
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

func cloneModelLists(m map[string][]string) map[string][]string {
	if m == nil {
		return nil
	}
	out := make(map[string][]string, len(m))
	for k, v := range m {
		out[k] = append([]string(nil), v...)
	}
	return out
}
