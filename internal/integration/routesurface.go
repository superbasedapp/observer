package integration

import (
	"sort"

	"github.com/marmutapp/superbased-observer/internal/models"
)

// routesurface.go is the per-surface route side table (surface-gap arc
// Wave 0.2; docs/plans/surface-gap-wave-0-design-2026-10-25.md section 4;
// the otlpExports precedent). A tool's Routability answers "is this tool
// routable?" once per tool, but a product ships several capture surfaces
// (models.SurfaceCLI, SurfaceIDE, SurfaceDesktop, SurfaceSDK, SurfaceWeb)
// and they do not all honour the same route: Claude Desktop's Code tab, for
// one, ignores the settings-file route the CLI reads. A row here refines the
// tool-level facts for one surface. It is data; consumers ask
// Capability.RouteSurfaceFor and never branch on a tool name.
//
// "Surface" here means the CAPTURE surface (models.Surface*), not the
// intervention process class (InterventionSurfaceClass) and not a vendor
// admin plane (internal/vendorsurface).

// CorrelationMode says whether a proxied turn of one surface can be joined
// back to its transcript session, that is whether api_turns.session_id
// equals sessions.id for that surface. It decides whether "no proxied
// session" can be read as a bypass. The zero value is unknown, never "not
// measurable": an ungrounded row must not be judged as either.
type CorrelationMode string

const (
	// CorrelationUnknown: not grounded yet. Traffic verdicts for the
	// surface stay "unknown measurability".
	CorrelationUnknown CorrelationMode = ""
	// CorrelationRequestID: a request header or body field carries the
	// session id the transcript uses (the proxy's resolveAPITurnSessionID).
	CorrelationRequestID CorrelationMode = "request_id"
	// CorrelationProcessBridge: the proxy's process-bridge fallback resolves
	// the session id from the calling process.
	CorrelationProcessBridge CorrelationMode = "process_bridge"
	// CorrelationUnavailable: grounded negative, the surface's proxied turns
	// cannot be joined to its sessions.
	CorrelationUnavailable CorrelationMode = "unavailable"
)

// correlationModes is the closed CorrelationMode set.
var correlationModes = map[CorrelationMode]bool{
	CorrelationUnknown:       true,
	CorrelationRequestID:     true,
	CorrelationProcessBridge: true,
	CorrelationUnavailable:   true,
}

// Known reports whether m is one of the declared CorrelationMode values.
func (m CorrelationMode) Known() bool { return correlationModes[m] }

// Measurable reports whether a session group of a surface with this mode
// can be judged by its proxied-session count.
func (m CorrelationMode) Measurable() bool {
	return m == CorrelationRequestID || m == CorrelationProcessBridge
}

// JoinsEveryTurn reports whether every proxied turn of a surface with this
// mode carries its session id, so a partly proxied window is evidence that
// some sessions bypassed the proxy. Only request_id does: the process
// bridge misses the first turns before its row lands and every turn of a
// one-shot run, so a partly joined window is expected there and only a
// window with no joined session reads as a bypass.
func (m CorrelationMode) JoinsEveryTurn() bool { return m == CorrelationRequestID }

// SurfaceRoute is one capture surface's route facts for one tool.
type SurfaceRoute struct {
	// Kind is a models.Surface* kind (models.KnownSurface).
	Kind string
	// Host refines Kind with a lowercase host token, the same token the
	// adapter stamps in sessions.surface_host ("claude-desktop",
	// "jetbrains", ...). "" = every host of Kind. A declared host must ship
	// on the org wire verbatim (tests/invariant/routesurface_hosts_test.go).
	Host string
	// Routability is the surface's own RouteStatus. The zero value inherits
	// Capability.Routability (EffectiveRoutability), so a row that only
	// declares correlation changes no routability claim.
	Routability RouteStatus
	// CorrelationMode says whether the surface's proxied turns join back to
	// its sessions.
	CorrelationMode CorrelationMode
	// Note explains the row for people.
	Note string
	// Grounding names the evidence ("repo: <path>", "doc: <url>",
	// "live: <date> <what>"). Required whenever Routability or
	// CorrelationMode is not the zero value.
	Grounding string
	// LiveCheck names the pending live check(s) of the gap review (section
	// 6, "LC7") that would ground a fact this row leaves unknown. A routed
	// surface (effective routable_now) may leave CorrelationMode unknown
	// only when it names one (TestProxiedToolsDeclareCorrelation).
	LiveCheck string
	// Unstamped says that a session of this tool with no surface stamp
	// (sessions.surface = '') is judged by this row. Set only on a tool
	// whose adapter stamps no surface at all, so every session it writes
	// is unstamped and this row is the only surface its route reaches. A
	// tool whose adapter stamps several surfaces sets it on no row: there
	// an unstamped session (an agent older than server migration 139, or a
	// vendor token the adapter does not map) could be any surface, so it
	// stays "unknown surface" and never blocks. At most one row per tool.
	Unstamped bool
	// NoProducer says that no adapter stamps this (Kind, Host) yet, so no
	// node can hold a session of the surface (AW-48, arc-lead ruling
	// 2026-10-28). The tool-level route proof counts only surfaces that
	// produce sessions: on a node it skips every surface with no observed
	// session, and in a registry-only view (docs, generated coverage, the
	// org's tool-wide fallback) it skips exactly the NoProducer rows, which
	// have zero sessions on every node by construction. Either way the
	// skipped surface is named "no sessions observed", never dropped
	// silently. Clear it in the commit that makes an adapter stamp the
	// surface. Requires a Host (the surface is named by its host token).
	NoProducer bool
}

// SurfaceMatch says how RouteSurfaceFor answered.
type SurfaceMatch string

const (
	// SurfaceMatchExact: a row declared this exact (Kind, Host).
	SurfaceMatchExact SurfaceMatch = "exact"
	// SurfaceMatchKind: a row declared (Kind, "") for every host of Kind.
	SurfaceMatchKind SurfaceMatch = "kind"
	// SurfaceMatchTool: no row; the answer is the tool-level fallback.
	SurfaceMatchTool SurfaceMatch = "tool"
)

// surfaceMatchRules is the ordered lookup table RouteSurfaceFor walks:
// the first rule whose predicate holds wins.
var surfaceMatchRules = []struct {
	match SurfaceMatch
	hit   func(row SurfaceRoute, kind, host string) bool
}{
	{SurfaceMatchExact, func(row SurfaceRoute, kind, host string) bool {
		return row.Kind == kind && row.Host != "" && row.Host == host
	}},
	{SurfaceMatchKind, func(row SurfaceRoute, kind, _ string) bool {
		return row.Kind == kind && row.Host == ""
	}},
}

// RouteSurfaceFor returns the route facts that apply to one capture surface
// of c, and how they were found. With no matching row it returns the
// tool-level fallback: Routability from c, CorrelationMode unknown.
func (c Capability) RouteSurfaceFor(kind, host string) (SurfaceRoute, SurfaceMatch) {
	if kind != "" {
		for _, rule := range surfaceMatchRules {
			for _, row := range c.RouteSurfaces {
				if rule.hit(row, kind, host) {
					return row, rule.match
				}
			}
		}
	}
	return SurfaceRoute{Kind: kind, Host: host, Routability: c.Routability}, SurfaceMatchTool
}

// EffectiveRoutability is the surface's RouteStatus: its own when set, else
// the tool's.
func (r SurfaceRoute) EffectiveRoutability(c Capability) RouteStatus {
	if r.Routability != RouteStatusUnknown {
		return r.Routability
	}
	return c.Routability
}

// UnstampedSurface returns the row an unstamped session of c is judged
// by (SurfaceRoute.Unstamped), and false when c declares none.
func (c Capability) UnstampedSurface() (SurfaceRoute, bool) {
	for _, row := range c.RouteSurfaces {
		if row.Unstamped {
			return row, true
		}
	}
	return SurfaceRoute{}, false
}

// RouteStatuses returns the closed RouteStatus vocabulary, the zero value
// first. Consumers that label a status (observer adapters, the parity
// generator, website/track-gen) test that every value has a label.
func RouteStatuses() []RouteStatus {
	return []RouteStatus{
		RouteStatusUnknown,
		RouteStatusRoutableNow,
		RouteStatusAfterUpstream,
		RouteStatusAfterBridge,
		RouteStatusProbeRequired,
		RouteStatusNativeExempt,
		RouteStatusSettingsIgnored,
	}
}

// routeSurfaces is the ONE owner of the RouteSurfaces column, keyed by
// registry tool. A tool absent here has no per-surface facts, and every
// surface of it reads the tool-level fallback.
//
// Every tool whose capability routes through the proxy (Proxy != nil)
// declares the surface its route reaches with a known CorrelationMode
// (surface-gap Wave 3, gate strength; TestProxiedToolsDeclareCorrelation),
// grounded in the proxy's session resolution (internal/proxy
// resolveAPITurnSessionID):
//
//   - request_id: the request body or a header carries the transcript's
//     session id. Only Claude Code (metadata.user_id) and Codex
//     (prompt_cache_key, then the Session-Id header fan-out) do.
//   - process_bridge: nothing in the request names the session, so the
//     turn joins only through the SessionResolver (internal/pidbridge): a
//     session_pid_bridge row written by a SessionStart hook walk, an
//     adapter's own pid seed, a launcher's launch seed once the daemon
//     sweep binds it to an ingested session, or a dashboard terminal seed.
//     It is LINUX ONLY (resolve_other.go is a stub), the first turns before
//     the row lands and every turn of a one-shot run stay unjoined, and
//     nothing backfills them, so a partly joined window is expected and
//     only a window with no joined session reads as a bypass
//     (routeattest: SurfaceVerdict.ObservedBypass). That is the same
//     evidence the pre-arc tool-level gate used. Note also that the
//     resolver still runs on a built-in agent lane (grok, hermes): only a
//     hosted-app lane refuses it (proxy.go, TestProxy_AgentLaneKeepsCodingAgentSession).
var routeSurfaces = map[string][]SurfaceRoute{
	"claude-code": {
		{
			Kind: models.SurfaceIDE, Host: xcodeHost, Routability: RouteStatusSettingsIgnored, NoProducer: true,
			Note:      "Claude Agent in Xcode uses CodingAssistant/ClaudeAgentConfig as its CLAUDE_CONFIG_DIR and never reads ~/.claude, so the ~/.claude/settings.json route Observer writes never reaches it; only a route written into that home could (a separate, unbuilt writer). The claude-code adapter captures that home on macOS and stamps its sessions ide/xcode (FU-150); NoProducer stays set until the arc lead rules how a macOS-only producer counts in the registry view (AW-48).",
			Grounding: "live: 2026-10-28 MAC-1 read (Xcode 26.6 17F113, macOS 26.2): ClaudeAgentConfig holds .claude.json, policy-limits.json, remote-settings.json and no settings.json; no ~/.claude hook call from its Bash calls",
			LiveCheck: "LCR-89",
		},
		{
			Kind: models.SurfaceCLI, CorrelationMode: CorrelationRequestID,
			Note:      "The CLI's Messages request carries its session id (metadata.user_id, X-Session-Id), which the proxy lands on api_turns.session_id.",
			Grounding: "repo: internal/proxy/proxy.go resolveAPITurnSessionID (Anthropic branch)",
		},
		{
			Kind: models.SurfaceIDE, Routability: RouteStatusProbeRequired,
			Note:      "The VS Code and JetBrains extensions run Claude Code itself, which reads the settings route, but the IDE's own environment or workspace claudeCode.environmentVariables may outrank it, so the route is not proven there.",
			Grounding: "audit: surface-settings-precedence-gap-review-2026-10-25.md IDE-3 (doc: https://code.claude.com/docs/en/settings-reference, a launch-env value beats a settings env value)",
			LiveCheck: "LC3",
		},
		{
			Kind: models.SurfaceDesktop, Routability: RouteStatusSettingsIgnored,
			Note:      "Claude Desktop's Code tab sets its own ANTHROPIC_BASE_URL under a Claude account login, and Claude Code ignores a settings env value the launch environment already sets, so the settings route never reaches it; only the desktop's gateway setting could.",
			Grounding: "doc: https://code.claude.com/docs/en/settings-reference and https://code.claude.com/docs/en/desktop (re-fetched for gap review CC-1, grounded locally 2026-10-24)",
			LiveCheck: "LC2",
		},
		{
			Kind: models.SurfaceSDK, Routability: RouteStatusProbeRequired,
			Note:      "An Agent SDK or claude -p embedding can drop user settings (settingSources) or replace the environment (the SDK env option), so the settings route is unproven there.",
			Grounding: "doc: https://code.claude.com/docs/en/agent-sdk/typescript and cli-reference (gap review CC-3)",
			LiveCheck: "LC4, LC5",
		},
	},
	"codex": {
		{
			Kind: models.SurfaceIDE, Host: xcodeHost, Routability: RouteStatusSettingsIgnored, NoProducer: true,
			Note:      "Codex in Xcode runs from its own CODEX_HOME (~/Library/Developer/Xcode/CodingAssistant/codex), which has no config.toml, so the ~/.codex/config.toml route Observer writes never reaches it; only a provider written into that home could (a separate, unbuilt writer). The codex adapter captures that home on macOS and stamps its sessions ide/xcode (FU-150), so on a node the surface counts toward Codex's route proof once a session of it is observed; NoProducer stays set until the arc lead rules how a macOS-only producer counts in the registry view (AW-48).",
			Grounding: "live: 2026-10-28 MAC-1 read (Xcode 26.6 17F113, macOS 26.2): codex/ holds sessions/, logs_2.sqlite, rules/xcode.rules and no config.toml; no ~/.codex hook call during four Xcode Codex sessions",
			LiveCheck: "LCR-90",
		},
		{
			Kind: models.SurfaceCLI, CorrelationMode: CorrelationRequestID,
			Note:      "The CLI's Responses request carries prompt_cache_key, the session's UUID, with a Session-Id header fan-out when the body drops it.",
			Grounding: "repo: internal/proxy/provider.go extractOpenAISessionID, internal/proxy/proxy.go resolveAPITurnSessionID (OpenAI branch)",
		},
		{
			Kind: models.SurfaceIDE, Routability: RouteStatusRoutableNow,
			Note:      "The VS Code and JetBrains-embedded Codex cores read the same config.toml route and were routed live; whether their requests carry the session id the rollout uses is not checked.",
			Grounding: "live: 2026-09-07 prompt-guard sweep, Desktop / VS Code / JetBrains cores proxy-only (docs/plans/adapter-coverage-parity-plan-2026-06-26.md codex prompt row)",
			LiveCheck: "LC7",
		},
		{
			Kind: models.SurfaceDesktop, Routability: RouteStatusRoutableNow,
			Note:      "Codex Desktop reads the same config.toml route and was routed live; whether its requests carry the session id the rollout uses is not checked.",
			Grounding: "live: 2026-09-07 prompt-guard sweep, Desktop / VS Code / JetBrains cores proxy-only (docs/plans/adapter-coverage-parity-plan-2026-06-26.md codex prompt row)",
			LiveCheck: "LC7",
		},
	},
	"copilot-cli": {
		processBridgeCLI("observer copilot-cli writes a launch seed (launch.go); the sessionStart hook does not seed the bridge. Only BYOK sessions route at all (ProxyRoute.PromptScope).", false),
	},
	"cline-cli": {
		processBridgeCLI("The adapter seeds the bridge from sessions.db's own pid column, and observer cline-cli writes a launch seed.", false),
	},
	"opencode":  {processBridgeCLI("observer opencode writes a launch seed; the plugin's session.created event does not seed the bridge, and opencode sets prompt_cache_key only for some providers (unverified).", true)},
	"hermes":    {processBridgeCLI("The Hermes plugin's SessionStart seeds the bridge with its own pid, and observer hermes writes a launch seed. The /up/openrouter lane is a built-in agent lane, where the resolver still runs.", true)},
	"pi":        {processBridgeCLI("observer pi writes a launch seed; no hook seeds the bridge.", true)},
	"qwen-code": {processBridgeCLI("The lifecycle SessionStart hook walk and the adapter's runtime.json seed write the bridge, and observer qwen writes a launch seed.", true)},
	"aider":     {processBridgeCLI("observer aider writes a launch seed; aider has no session id of its own on the wire.", true)},
	"gemini-cli": {
		processBridgeCLI("observer gemini writes a launch seed; the proxy extracts no session id from a Gemini generateContent request at all.", true),
		{
			Kind: models.SurfaceIDE, Routability: RouteStatusProbeRequired,
			Note: "The Gemini route is launcher env only (GOOGLE_GEMINI_BASE_URL), so it never reaches an IDE-hosted Gemini: Gemini Code Assist agent mode in VS Code writes the same ~/.gemini/tmp chats but has no base-URL key, and an ACP host (JetBrains, Zed) spawns gemini with its own environment. " +
				"Only a host env writer (Zed agent_servers env, JetBrains acp.json env; D8, not built) could carry it. The adapter stamps no surface, so these sessions are judged by the CLI row.",
			Grounding: "audit: docs/audits/vendor-surface-inventory-2026-10-25.md sections 2.3, 3.3 and 5 (Code Assist agent mode, the registry gemini entry); gap review S-1, S-4",
			LiveCheck: "LC27, LC28",
		},
	},
	"grok":  {processBridgeCLI("observer grok --proxy writes a launch seed, and the Claude settings replay's SessionStart walk seeds it when Observer's Claude Code hooks are registered. The grok lane is a built-in agent lane, where the resolver still runs.", true)},
	"crush": {processBridgeCLI("observer crush writes a launch seed; a bare crush run, routed by crush.json alone, seeds nothing, so its turns never join.", true)},
	"goose": {
		processBridgeCLI("observer goose --proxy writes a launch seed; no hook seeds the bridge.", true),
		{
			Kind: models.SurfaceIDE, Routability: RouteStatusProbeRequired,
			Note: "Goose for VS Code (block.vscode-goose, experimental) talks ACP to a goose CLI it spawns itself and reads the CLI's config.yaml, so the observer goose launcher route never reaches it; only a provider host in config.yaml could. " +
				"Whether its sessions land in sessions.db, and with what client marker, is not grounded; the adapter stamps no surface, so they are judged by the CLI row.",
			Grounding: "doc: https://raw.githubusercontent.com/block/vscode-goose/main/package.json and block/goose documentation/docs/experimental/vs-code-extension.md (re-fetched 2026-10-25, inventory section 2.2)",
			LiveCheck: "LCR-62",
		},
	},
	"prime-agent": {processBridgeCLI("observer prime-agent writes a launch seed; no hook seeds the bridge.", true)},
	"kimi-code":   {processBridgeCLI("observer kimi writes a launch seed; a bare kimi run, routed by config.toml alone, seeds nothing, so its turns never join.", true)},
	"kilo-code-cli": {
		{
			Kind: models.SurfaceIDE, Routability: RouteStatusProbeRequired,
			Note: "Kilo Code 7.x for VS Code embeds the Kilo runtime and Kilo Code for JetBrains v7 downloads the pinned Kilo CLI; both read the same kilo.jsonc as the CLI, so a custom provider baseURL there would reach them too. " +
				"No writer exists and no routed turn was seen from any of the three.",
			Grounding: "doc: https://raw.githubusercontent.com/Kilo-Org/kilocode/main/packages/kilo-docs/pages/getting-started/settings/index.md and code-with-ai/platforms/jetbrains.md (re-fetched 2026-10-25, inventory section 2.4; gap review IDE-9, CLI-9)",
			LiveCheck: "LC16, LC24",
		},
	},
}

// processBridgeCLI is the CLI row of a proxied tool whose turns join only
// through the process bridge (see routeSurfaces). seeds names the tool's
// bridge writers; unstamped is true for an adapter that stamps no surface.
func processBridgeCLI(seeds string, unstamped bool) SurfaceRoute {
	note := "No session id in the request: a turn joins its session only through the Linux process bridge, which misses the first turns and one-shot runs. " + seeds
	if unstamped {
		note += " The adapter stamps no surface, so every session is judged by this row."
	}
	return SurfaceRoute{
		Kind: models.SurfaceCLI, CorrelationMode: CorrelationProcessBridge, Unstamped: unstamped,
		Note:      note,
		Grounding: "repo: internal/proxy/proxy.go resolveAPITurnSessionID (no body or header id for this wire), internal/pidbridge resolve_linux.go / resolve_other.go, cmd/observer/launchseed.go; live: docs/handovers/session-parking-2026-08-22-runtime-verify-opencode-lineage.md (launch seed to bridge to api_turns proven on grok; first turns and one-shot runs unjoined)",
	}
}

// init folds the RouteSurfaces column into the registry rows. A key with no
// registry row is a table error caught by TestRouteSurfacesAreRegistryRows.
func init() {
	for tool, rows := range routeSurfaces {
		if c, ok := registry[tool]; ok {
			c.RouteSurfaces = append([]SurfaceRoute(nil), rows...)
			registry[tool] = c
		}
	}
}

// RouteSurfaceHosts returns every non-empty Host declared in the
// RouteSurfaces column, sorted and de-duplicated. The org-wire drift guard
// reads it; the wire allowlist is never derived from it.
func RouteSurfaceHosts() []string { return routeSurfaceHostsOf(routeSurfaces) }

// routeSurfaceHostsOf is RouteSurfaceHosts over any table (tests pass their
// own).
func routeSurfaceHostsOf(table map[string][]SurfaceRoute) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, rows := range table {
		for _, r := range rows {
			if r.Host != "" && !seen[r.Host] {
				seen[r.Host] = true
				out = append(out, r.Host)
			}
		}
	}
	sort.Strings(out)
	return out
}
