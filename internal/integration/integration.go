package integration

import (
	"sort"

	"github.com/marmutapp/superbased-observer/internal/platform/winshim"
)

// ProxyLane is one `/up/<id>/` proxy lane a route depends on.
type ProxyLane struct {
	// ID is the lane id (the `<id>` path segment).
	ID string
	// DefaultUpstream is the GROUNDED host root (no version suffix; the
	// client's base URL carries it) the proxy uses for this lane when
	// neither [proxy.upstreams] nor [proxy.agent_upstreams] names the id.
	// "" = no built-in default: the operator must configure the lane.
	DefaultUpstream string
}

// RouteKind names HOW a proxy route is applied — the capability shape the
// init proxy-route step dispatches on (CLAUDE.md #3), distinguishing a
// persisted config write from an ephemeral launcher env var.
type RouteKind string

const (
	// RouteLauncher: the base-URL env var is exported at exec time by the
	// `observer <x>` launcher; there is NO persisted per-tool config file to
	// write (opencode). routeSupported is false for these — the launcher,
	// not init, applies the route.
	RouteLauncher RouteKind = "launcher"
	// RouteEnvSettings: the base-URL env var is persisted into the client's
	// own settings file (claude-code → ~/.claude/settings.json "env").
	RouteEnvSettings RouteKind = "env_settings"
	// RouteConfigFile: the base URL is written into the client's config file
	// under a vendor-specific key (codex → ~/.codex/config.toml
	// openai_base_url).
	RouteConfigFile RouteKind = "config_file"
	// RouteProviderJSON: the base URL is written into a provider entry in a
	// JSON config the tool reads (openclaw/pi models.json baseUrl). Declared
	// in Phase 0; its writer lands in Phase B (gated on a live probe).
	RouteProviderJSON RouteKind = "provider_json"
	// RouteVSCodeSettings: the base URL is written into a VS Code extension's
	// settings (cline/roo/kilo "OpenAI Compatible" Base URL). Declared in
	// Phase 0; writer lands in Phase B.
	RouteVSCodeSettings RouteKind = "vscode_settings"
	// RouteManual: observer cannot safely auto-edit the client, so the
	// `observer <tool> --setup` launcher PRINTS the base-URL settings for the
	// operator to paste (copilot VS Code BYOK). The ProxyRoute carries
	// the URL to print; init never auto-writes these (routeSupported excludes
	// them). Declared in Phase 0; consumed in Phase B.
	RouteManual RouteKind = "manual_instructions"
)

// RouteStatus is the surface-specific routability bucket for an adapter —
// the honest answer to "is this tool's model traffic routable through the
// observer proxy?", INDEPENDENT of whether observer auto-applies the route
// today (that is the Proxy field: non-nil ⇒ observer drives a route now).
//
// It retires the old "permanently impossible" framing (operator directive
// 2026-06-26): native hosted/proprietary traffic is exempt, but a tool's
// BYOK / custom-base-URL surface is frequently routable. Buckets mirror
// docs/audits/notes-on-proxy.md and are grounded against adapter code +
// the live 2026-06-26 8-tool run. The zero value (RouteStatusUnknown) means
// "not yet classified", never "impossible".
type RouteStatus string

const (
	// RouteStatusUnknown: not yet classified against a surface.
	RouteStatusUnknown RouteStatus = ""
	// RouteStatusRoutableNow: an OpenAI/Anthropic-shaped base-URL knob exists
	// that observer can drive. The Proxy field shows whether observer applies
	// it today (claude-code/codex/opencode) or whether the writer is still
	// pending (cline/kilo VS Code surface — knob exists, Phase-B writer).
	RouteStatusRoutableNow RouteStatus = "routable_now"
	// RouteStatusAfterUpstream: routable only after the proxy gains
	// per-provider upstream selection (hermes → OpenRouter; Phase C).
	RouteStatusAfterUpstream RouteStatus = "after_upstream"
	// RouteStatusAfterBridge: routable only after a request/response protocol
	// bridge (gemini-cli generateContent; Phase E).
	RouteStatusAfterBridge RouteStatus = "after_bridge"
	// RouteStatusProbeRequired: a BYOK / custom-base-URL path is documented
	// but unconfirmed on a live install — confirm with a live turn before
	// flipping the Proxy field on (cline-cli, openclaw, pi,
	// copilot-cli/VS Code BYOK, cowork third-party gateway).
	RouteStatusProbeRequired RouteStatus = "probe_required"
	// RouteStatusNativeExempt: no routable surface found — the tool talks
	// only to its own backend with no base-URL knob (antigravity, kilo-cli
	// per the live 2026-06-26 finding, cowork's local microVM path), or its
	// only knob is relayed through the vendor's servers and so cannot reach
	// a loopback proxy (cursor's BYOK "OpenAI Base URL"). A
	// grounded negative, not "permanently impossible": a future version or a
	// new BYOK surface can reclassify it.
	RouteStatusNativeExempt RouteStatus = "native_exempt"
	// RouteStatusSettingsIgnored: a SURFACE row value (SurfaceRoute), never
	// a tool-level one. The tool's route lives in a settings file the CLI
	// reads, and this surface grounded-ly ignores it, so the route Observer
	// writes never reaches it (Claude Desktop's Code tab under a Claude
	// account login sets its own ANTHROPIC_BASE_URL, and Claude Code ignores
	// a settings env value the launch environment already sets; gap review
	// CC-1a). Not exempt: the surface's traffic bypasses the proxy and is
	// reported as such, but it never blocks Gateway Mode, because nothing
	// Observer writes today can route it. A different knob on the surface
	// (a desktop gateway setting) is a separate, unbuilt writer.
	RouteStatusSettingsIgnored RouteStatus = "settings_ignored"
)

// ClientAuthCarrier names how a routed tool can carry the node proxy's
// client token (OSH-R-009, docs/plans/proxy-client-auth-2026-10-30.md). The
// zero value means "not grounded", never "impossible".
type ClientAuthCarrier string

const (
	// ClientAuthNone: no grounded way to carry the token (the zero value).
	ClientAuthNone ClientAuthCarrier = ""
	// ClientAuthPathToken: the tool keeps a path on its base URL, so the
	// token rides as the first path segment
	// (http://127.0.0.1:<port>/t/<token>/v1). Declared only where the row's
	// own grounded route already carries a path through to the request: a
	// Suffix with a path, a lane, the codex writer's /v1, or Claude Code's
	// documented gateway path (also the Windows relay's /r/claude-code).
	ClientAuthPathToken ClientAuthCarrier = "path_token"
)

// ProxyRoute describes how a proxy-routable adapter is pointed at the
// observer proxy. Most adapters are captured by the watcher/hooks and are
// NOT proxy-routable (they talk only to their vendor's own backend, with
// no base-URL knob) — those carry a nil Proxy on their Capability, which
// is data, not a missing feature.
type ProxyRoute struct {
	// Kind is how the route is applied (persisted config write vs launcher
	// env var). init only writes config for the persisted kinds.
	Kind RouteKind
	// ClientAuth says how the tool can carry the proxy client token
	// (ClientAuthCarrier). Zero = not grounded: a node with this tool routed
	// in the plain form keeps [proxy].require_client_auth unenforced.
	ClientAuth ClientAuthCarrier
	// EnvVar is the base-URL env var that routes the tool at the proxy
	// (e.g. ANTHROPIC_BASE_URL, OPENAI_BASE_URL), or "" when the tool
	// routes via a config file instead (see Note).
	EnvVar string
	// Suffix is appended to the proxy URL: "/v1" for OpenAI-compatible
	// endpoints, "" for Anthropic's ANTHROPIC_BASE_URL.
	Suffix string
	// Launcher is the `observer <x>` command that wires the routing.
	Launcher string
	// LaunchFlag, when non-empty, is the opt-in launcher argument that turns
	// this launcher route on (grok and goose: "--proxy"). A bare `observer
	// <verb>` without it launches the product UNROUTED, so a wrapped form
	// that runs the bare verb (WrappedCommandFor, the shell-wrap shims) must
	// not claim the route. "" = the launcher routes by default.
	LaunchFlag string
	// Note documents config-file-routed tools (EnvVar == ""), where the
	// base URL lives in a config file rather than an env var.
	Note string
	// Lane is the proxy `/up/<id>/` lane this route addresses, for a tool
	// whose traffic must reach a NON-default host. Nil = the route rides
	// the proxy's fixed upstreams and needs no lane. Since Sol A5-02 an
	// unresolvable lane is refused (HTTP 502) rather than forwarded to a
	// fixed provider, so a launcher checks Lane before it routes.
	Lane *ProxyLane
	// PromptScope says which of the tool's turns the route actually
	// carries when that is not every turn (e.g. only one provider entry of
	// several). Coverage surfaces print it beside the proxy seam. "" = the
	// route carries every turn of a routed session.
	PromptScope string
	// CrossOSBridge mirrors HookSpec.CrossOSBridge for the proxy route: this
	// persisted route's config file can ALSO be written into a foreign
	// Windows home from a WSL daemon — the `<tool>-windows` virtual-target
	// convention. When true, the `<tool>-windows` target resolves the
	// Windows-side config path through crossmount and writes the base-URL
	// route (env settings / config file) pointing at the WSL proxy's
	// localhost-forwarded port, so a Windows-installed claude/codex routes
	// through the WSL proxy. A capability FLAG, not a tool branch
	// (CLAUDE.md #3); meaningful only for the persisted RouteKinds
	// (RouteEnvSettings / RouteConfigFile).
	CrossOSBridge bool
	// Proof states whether APPLYING this route establishes which backend the
	// invocation actually reaches. The zero value (RouteProofUnproven) is the
	// safe answer for every tool whose effective provider is chosen by an
	// ambient variable, a profile, or a config merge the launcher does not
	// own. See RouteProof.
	Proof RouteProof
	// SelectorArguments are the grounded, PRODUCT-SPECIFIC argv keys that can
	// outrank this route (a model, provider, credential or settings selector
	// this vendor honours over its own base-URL knob). The cross-vendor
	// spellings stay with the launch boundary that owns the generic scan; a
	// row lists only what that generic set misses. Keys only — the scan
	// compares the token before any '=' — and never a value.
	SelectorArguments []string
	// Gate, when non-nil, says the route is CONDITIONAL: the vendor lane the
	// launcher points at the proxy only works with the developer's own
	// provider credential (and possibly an explicit model), and without it the
	// product runs on its own sign-in, which no base URL can route. A gated
	// launcher applies the route only when EvaluateRouteGate says so and
	// otherwise launches the product UNROUTED, saying why. Nil = the route
	// applies to every launch. See RouteGate.
	Gate *RouteGate
	// Setting names, for people, the setting a persisted route writes into
	// the tool's config, when the EnvVar does not already name it (a
	// config-file route under vendor keys). Leaving an organization says
	// "Removes <setting> from <file>" from it (RouteSetting, T-495). "" =
	// the EnvVar names it, or no grounded name.
	Setting string
	// ProviderOverrides lists the tool's BUILT-IN providers and, for each,
	// the proxy path that can stand in for its base URL (or why none can).
	// A launcher whose route rides one provider entry of several writes the
	// covered rows on a managed node so a mid-session provider switch stays
	// on the proxy (T-035, PROVIDER-SWITCH-1). Nil = the route carries every
	// turn already, or the tool has no overridable built-in providers.
	ProviderOverrides []ProviderOverride
	// ForeignLane, when non-nil, says this persisted route can ALSO carry a
	// third-party OpenAI-compatible provider the developer configured (a host
	// other than the route's fixed upstream) through a proxy `/up/<id>/` lane
	// whose upstream is that same host, so the traffic still reaches the
	// provider the developer chose. Only the managed daemon's route
	// maintenance writes it (lane P1). Nil = the route only carries the fixed
	// upstream, and a third-party host on it is never rewritten.
	ForeignLane *ForeignProviderLane
	// ConfigContentEnv names an environment variable whose value is a
	// configuration document the tool merges over its own config files
	// (opencode's OPENCODE_CONFIG_CONTENT). The launcher puts the route
	// there too, so a project config file cannot shadow it, and the
	// effective-layer evaluator reads it (from the injected environment
	// only) as the config_content layer (surface-gap CLI-2, CLI-3). "" =
	// no such variable.
	ConfigContentEnv string
	// DotenvOverride, when non-nil, says the tool loads .env files itself
	// and lets them override its launch environment, so a base-URL
	// variable in one of them shadows the launcher route (aider's
	// load_dotenv(override=True), CLI-7). Nil = no such loading.
	DotenvOverride *DotenvOverride
	// LiveGate, when set, switches this route's writer off until the named
	// live check passes (DEC-12, livegate.go): init, the dashboard and route
	// maintenance refuse to run it and doctor says "built, waiting on live
	// check <id>". Zero = the writer runs as its callers decide.
	LiveGate LiveGate
	// SharesCredentialFile declares the D-268 / D-270 credential-file
	// exception for this route's writer (surface-gap FU-33, D9), mirroring
	// MCPTarget.SharesCredentialFile: the file the writer read-modify-writes
	// also holds plaintext credentials, so only a row carrying this flag may
	// write it, and the writer then follows the probe-writer credential-file
	// rules (internal/proxyroute probe_write.go): only the route keys
	// change, every other byte stays, the mode is kept, no backup is left,
	// and no error quotes the file. Pinned by tests/invariant
	// TestRouteWritersIntoCredentialFilesAreDeclared.
	SharesCredentialFile bool
	// CredentialFileReason names the file and the credential it holds, for
	// a route with SharesCredentialFile set. Empty otherwise.
	CredentialFileReason string
	// PersistedDefault, when non-nil, declares a writer that makes this
	// route the tool's PERSISTED default, so a bare binary (no launcher)
	// uses it too (surface-gap CLI-1a): it selects the provider entry the
	// launcher writes as the default provider, or persists the base URL the
	// launcher would inject. Nil = only the launcher applies the route.
	PersistedDefault *PersistedDefault
}

// PersistedDefault is a route's default-provider writer
// (ProxyRoute.PersistedDefault).
type PersistedDefault struct {
	// Note names the file and the key the writer sets, and what it
	// requires to be there first.
	Note string
	// LiveGate switches the writer off until its live check passes
	// (DEC-12). Every default-provider writer is gated on LC25 until the
	// vendor keys that select the default provider are grounded live.
	LiveGate LiveGate
}

// ForeignProviderLane describes a route's third-party-provider lane writer
// (ProxyRoute.ForeignLane).
type ForeignProviderLane struct {
	// LiveVerified is true once a live turn through the lane landed an
	// api_turns row on a real install. False = written by the managed
	// daemon but still awaiting that confirmation (the honest state).
	LiveVerified bool
	// Note grounds the writer: which key it rewrites and what it keeps.
	Note string
}

// Capability is one adapter's row in the registry: everything observer
// knows, as DATA, about how this tool can integrate with the proxy / hooks
// / MCP / native-console / token capture. Consumers gate on the SHAPE of
// the field they need (Proxy != nil, Hook.Mechanism != HookNone, MCP != nil
// …), never on Tool name (CLAUDE.md rule #3). A zero-value Capability is
// safe to pass around: every field reads as "no grounded capability".
//
// Population status (2026-06-26): Proxy seeded Phase 0; Hook / MCP / Native
// / TokenTier filled by the capability-discovery spike, code-grounded with
// honest zero values where a cell could not be grounded (see capability.go).
// Consumers (init, register, doctor) are wired phase-by-phase; the fields
// are inert data until then.
type Capability struct {
	Tool  string
	Proxy *ProxyRoute
	// ProxyProbe records the config-lane WRITER BINDING (a RouteKind, plus
	// the writer's Note) for a tool whose GUARDED, ADDITIVE proxy-route
	// writer EXISTS in internal/proxyroute. It names HOW `observer init`
	// writes the route: init dispatches its probe-route step on
	// ProxyProbe.Kind (never a tool-name branch) and derives the eligible
	// SET from this field, not a hand-list.
	//
	// ProxyProbe PERSISTS after promotion. Proxy and ProxyProbe answer two
	// different questions: Proxy records the live-verified route observer
	// DRIVES; ProxyProbe records how init WRITES it. The writer remains
	// init's apply mechanism on any machine where the tool's config is not
	// yet routed — a live-verified route on the operator's box does not
	// pre-write the config on a fresh install, so init still needs the
	// binding to lay it down. So a promoted tool carries BOTH: a non-nil
	// Proxy (verified) and a non-nil ProxyProbe (the writer that applies it).
	//
	// An UN-promoted probe (Proxy nil, Routability probe_required) is the
	// "writer ready, promotion pending a live api_turns confirmation" state
	// the docs mandate ("flip the matrix cell ONLY after live verification").
	// A nil ProxyProbe means "no config-lane writer" (the common case). Never
	// fabricate a verified Proxy from a ProxyProbe.
	ProxyProbe *ProxyRoute
	// Routability is the surface-specific bucket (RouteStatus): whether the
	// tool is routable at all, independent of whether observer drives a route
	// today (Proxy). A row can have Proxy==nil yet Routability != exempt — the
	// surface exists but observer's writer/upstream support is still pending.
	Routability RouteStatus
	Hook        HookSpec
	MCP         *MCPTarget
	Native      NativeRails
	// RouteSurfaces refines Routability per capture surface (CLI, IDE,
	// desktop, SDK, web; models.Surface*) and says whether a proxied turn
	// of that surface can be joined back to its session. Owned by the
	// routeSurfaces table in routesurface.go; nil = no per-surface facts,
	// and every lookup falls back to the tool-level fields
	// (Capability.RouteSurfaceFor).
	RouteSurfaces []SurfaceRoute
	// OTLP declares the tool's own OpenTelemetry export (where it is sent
	// from, how to enable it, whether internal/otlpvendor maps it). Owned
	// by the otlpExports table in otlpexport.go; zero value = none grounded.
	OTLP OTLPExport
	// StatusLine declares the tool's own status-line command (where it is
	// set, its payload shape, whether Observer writes it). Owned by the
	// statusLines table in statusline.go; zero value = none grounded.
	StatusLine StatusLineSpec
	// Enterprise is the tool's vendor enterprise-plane answer: the vendor
	// surface catalog rows that cover it, a parent it inherits from, or an
	// honest none (enterprise vendor API plan 4.2). Owned by the
	// enterpriseAnswers table in enterprise_table.go; the only authored tool to
	// surface relation (invariant I2).
	Enterprise EnterpriseAnswer
	TokenTier  TokenTier
	// Limit records an AUDITED negative finding for the 5h/weekly usage-
	// limit gauge (docs/cost-predictor.md; LimitCapability's doc comment).
	// Zero value = not audited, falls through to the existing proxy/
	// transcript ladder unchanged. Populated only for a tool where a live
	// investigation found NO possible local source — see the "cursor" and
	// "grokbot" rows for the grounded examples.
	Limit LimitCapability
	// Handoff is the session-handoff row: transcript readability (Phase 0
	// P0.1, live-grounded 2026-07-03 on a 328-session corpus) + grounded
	// delivery lanes. Zero value = actions-only carry + file delivery, the
	// honest floor.
	Handoff HandoffCapability
	// Attach, when non-nil, declares the tool is attachable: `observer
	// <Subcommand> --attach` hands its PTY to the daemon so the dashboard
	// can join the live session as a second seat (session-attach design
	// §2.3, T2). Nil = not attachable (bare launch only). Populated only
	// for tools with a wired attachable launcher; the row must also be
	// Launchable (pinned by registry_coverage_test.go).
	Attach *AttachSpec
	// Resume declares how a CLOSED session is reopened (session-attach
	// design §2.3, T3). Zero value (ResumeNone) = no grounded native
	// resume; the dashboard offers the shipped handoff-fork resume when the
	// tool is launchable, else a disabled affordance. A ResumeNative row is
	// declared only after the native-resume argv is verified live.
	Resume ResumeSpec
	// Binary, when non-nil, declares how the `observer <x>` launcher resolves
	// the tool's executable across OSes plus the grounded one-click install
	// hints (BinaryResolveSpec). Nil = no grounded resolution row (the honest
	// floor). Populated for every launchable tool (Handoff.Launch != nil),
	// pinned by registry_coverage_test.go. Consumers (the toolresolve ladder,
	// the dashboard install endpoint, the doctor) dispatch on the SHAPE of
	// this field, never on tool name (CLAUDE.md #3).
	Binary *BinaryResolveSpec
	// InstallSignals are the extra evidence that the tool is installed on
	// this machine before its own config home exists (installsignal.go,
	// WINNODE item 5): a VS Code-family extension directory, or this row's
	// own Binary resolving. Auto-wiring (`observer enroll`, `observer init`
	// with no tool flag) treats a row whose signal holds as installed. Empty
	// keeps the config-home probe alone.
	InstallSignals []InstallSignal
	// AuthEnv lists the environment-variable NAMES (never values) a tool reads
	// its provider credentials from at runtime. The attach client forwards the
	// caller's values for these keys claude-style — presence-forwarded (an
	// absent key is skipped, a present-but-empty `KEY=` forwarded verbatim),
	// layered last so launchChildEnv's inherited daemon env loses to them
	// (last-wins) — so a shell-exported-only key (never written to any config
	// file) reaches the daemon-spawned child exactly as it would a bare launch,
	// which inherits the caller's os.Environ() directly. A zero value means "no
	// grounded credential-env" — the tool authenticates via a config file,
	// OAuth, or a keychain, OR its env surface is unverified — never a
	// fabricated key. NAMES ONLY: TestAuthEnvWellFormed enforces that no value
	// leaks in (no `=`, no whitespace, not OBSERVER_-prefixed, not a launcher-
	// closure-owned routing/profile key, no intra-row duplicate), and
	// TestAuthEnvImpliesAttachable pins that only an attachable row carries keys
	// (a bare-only tool has no attach socket to forward across).
	AuthEnv []string
	// Model declares how a model can be selected at fresh-launch time (the
	// dashboard New Terminal model picker, B5): zero value (ModelNone) = "no
	// grounded seed-time model mechanism" — a valid final answer, never a
	// TODO, and the picker stays hidden for that row. A populated ModelSpec
	// is delivered via ModelLaunch at the boundary (args/env appended to the
	// observer launcher's invocation), so no consumer branches on tool name
	// (CLAUDE.md #3).
	Model ModelSpec
	// Vocabulary declares whether this adapter's NATIVE TOOL NAMES live in
	// the canonical cross-adapter taxonomy table (internal/tooltax) — the
	// WP-T3 teeth of the tool-taxonomy plan. A zero value is "not declared"
	// and fails registry_coverage_test.go's
	// TestVocabularyDeclaredForEveryAdapter, so a NEW adapter cannot ship a
	// private action-type map that drifts from the table. InTaxonomy false
	// is legal ONLY with a Note explaining the honest zero (the five
	// browser-chat `*-web` rows capture chat turns, not tool calls).
	Vocabulary Vocabulary
	// Sandbox declares the HOME-RELATIVE state a tool needs at its real
	// path inside a B9 filesystem sandbox (SandboxSpec). Zero value = "no
	// grounded sandbox row, tool is not sandbox-launchable" — a valid
	// answer for a Launchable row only when SandboxSpec.Note explains the
	// honest zero (pinned by TestSandboxDeclaredForEveryLaunchableAdapter).
	// v1 grounds only claude-code; every other launchable tool carries the
	// Note fallback (plan amendment A3, ledger G21).
	Sandbox SandboxSpec
	// Headless, when non-nil, declares a live-verified headless one-shot
	// contract (prompt on argv → parseable final answer) that the Agent
	// Arena drives. Nil = no grounded one-shot form — the honest floor;
	// populated only after a real drive proves the argv, pinned to the
	// exact grounded set by registry coverage tests.
	Headless *HeadlessSpec
	// Lifecycle is the product's vendor-support status under the harness
	// lifecycle policy (docs/harness-lifecycle-policy.md; lifecycle.go).
	// Zero value = active. A deprecated or dead row keeps capturing (rows
	// are never deleted) but is excluded from every ADVERTISING surface —
	// picker / launch / guided install / init targets — through the one
	// predicate Lifecycle.Advertised() (TerminalLaunchable, Advertised),
	// pinned by TestUnadvertisedRowsAreNeverDispatched.
	Lifecycle Lifecycle
	// LifecycleNote is REQUIRED (non-empty) whenever Lifecycle is not
	// active: the vendor-grounded reason + date + URL the flip was made
	// on (pinned by TestLifecycleNotesGrounded). Optional on an active row
	// (an alias / name-collision caveat the docs should carry).
	LifecycleNote string
	// GUI, when non-nil, declares that this adapter's OWN product is an IDE
	// or desktop app the dashboard can install + launch DETACHED (no PTY)
	// with Observer's routing wrap injected (gui.go, docs/plans/
	// ide-desktop-launch-plan-2026-09-03.md). Nil = the product has no GUI
	// surface of its own, or it has one that is not yet grounded — see the
	// row comment. Editor HOSTS with no adapter row of their own (VS Code,
	// JetBrains IDEs, Zed) live in the guiHosts table instead; both feed
	// the single GUILaunchables() accessor the dashboard dispatches on.
	GUI *GUILaunchSpec
	// PromptLane declares the tool's prompt-submit intervention
	// mechanism (docs/plans/prompt-submit-intervention-exploration-2026-09-07.md
	// Part B). Zero value (PromptLaneNone) = no grounded capability —
	// the honest default for most rows. See internal/integration's
	// PromptLane doc comment for the full vocabulary.
	PromptLane PromptLane
}

// registry is the capability table, keyed by the adapter's canonical tool
// name (matching adapter.Adapter.Name() and the EnabledAdapters list). It
// covers every registered adapter (pinned by registry_coverage_test.go); the doctor (and the matrix)
// render from it. Every cell is code-grounded — a zero value means "no
// grounded capability" (genuinely unsupported OR pending a discovery spike
// against a live install), distinguished by the per-row comment, never a
// fabricated capability. An absent tool resolves via For to a zero-value
// Capability that still echoes the Tool name.
var registry = map[string]Capability{
	// Full-capability flagships: proxy + hook + MCP + all native rails.
	"claude-code": {
		Tool:       "claude-code",
		PromptLane: PromptLaneHook,
		// The VS Code extension alone (no `claude` on PATH, no ~/.claude
		// before its first session) reads the same ~/.claude settings and
		// hooks (Windows Server 2025 demo, 2026-10-28: `observer init
		// --claude-code` wired it, 24 hooks, while auto-detect saw nothing).
		InstallSignals: []InstallSignal{{Kind: InstallSignalEditorExtension, ExtensionID: "anthropic.claude-code"}},
		Vocabulary:     Vocabulary{InTaxonomy: true},
		// ANTHROPIC_BASE_URL is the route for the first-party Anthropic
		// provider. Claude Code also has provider selectors
		// (CLAUDE_CODE_USE_ANTHROPIC_AWS / _BEDROCK / _FOUNDRY / _MANTLE /
		// _VERTEX, the table in providerselectors.go); a session with one of
		// them set goes to that provider instead and is not proxy-proven
		// (surface-gap CC-10).
		Proxy: &ProxyRoute{
			ClientAuth:           ClientAuthPathToken,
			SharesCredentialFile: true, CredentialFileReason: routeCredClaudeCode,
			Kind: RouteEnvSettings, EnvVar: "ANTHROPIC_BASE_URL", Suffix: "",
			Launcher: "observer claude", CrossOSBridge: true, Proof: RouteProofLauncherRoute,
			// OBS-4: the route is per surface (routeSurfaces): proven for the
			// CLI, ignored by Claude Desktop's Code tab, unproven in the IDE
			// extensions and Agent SDK embeddings.
			PromptScope: "Only Claude Code CLI sessions are proven to go through the proxy; Claude Desktop's Code tab ignores the settings route, and the IDE extensions and Agent SDK embeddings can override it, so their prompts are judged by the hooks or flagged after send.",
		},
		Routability: RouteStatusRoutableNow,
		Hook:        HookSpec{Mechanism: HookClaudeSettings, CrossOSBridge: true, AutoWired: true, Bindings: hookBindingsClaudeCode, HooksShareCredentialFile: true, CredentialFileReason: credFileClaudeCode},
		// Remote grounded 2026-09-24 against code.claude.com/docs/en/mcp:
		// `{"type":"http"|"sse","url":…,"headers":{…}}` — a url WITHOUT a
		// type is a configuration ERROR Claude Code skips, so the writer
		// always emits `type`. Written by internal/mcp's shared JSON remote
		// writer (W4a).
		// WindowsStdio grounded live 2026-10-20 on native Windows 11 (lane
		// NPXMCP, T-923) with a throwaway stdio server and an isolated
		// CLAUDE_CONFIG_DIR: the Node build 1.0.51 failed both a bare `npx`
		// and `npx.cmd` (spawn ENOENT) and started `cmd /c npx`; the native
		// build 2.1.304 started all three. `cmd /c` is the one form every
		// tested build starts, and it is the wrapper Anthropic's MCP docs
		// told native Windows users to use.
		MCP: &MCPTarget{Format: MCPServersJSON, PathHint: ".claude.json", Implemented: true, SharesCredentialFile: true, CredentialFileReason: mcpCredClaudeCode, WindowsStdio: winshim.LaunchCmdShell, Remote: &MCPRemoteTarget{
			Transports:   []MCPRemoteTransport{MCPRemoteStreamableHTTP, MCPRemoteSSE},
			Headers:      true,
			TransportKey: "type",
			Spelling:     map[MCPRemoteTransport]string{MCPRemoteStreamableHTTP: "http", MCPRemoteSSE: "sse"},
			Implemented:  true,
			Note:         "code.claude.com/docs/en/mcp 2026-09-24: type http|sse + url + headers; url without type is skipped as a config error",
		}},
		Native:    NativeRails{A: true, B: true, C: true},
		TokenTier: TokenTier{Best: "proxy", ReasoningDisjoint: true, GenerationTiming: GenTimingTranscript},
		// P0.1 FULL: ~/.claude/projects/<slug>/<sid>.jsonl; reader derives
		// the path by session-id glob (hook-fed rows carry a sentinel).
		Handoff: HandoffCapability{Transcript: TranscriptFull, Inject: []InjectKind{InjectFile, InjectMCP, InjectHook, InjectPrompt}, Launch: &LaunchSpec{Subcommand: "claude"}},
		// Binary resolution + grounded installs. Unix launcher resolves
		// "claude"; the npm shim + the official curl installer are both
		// grounded (npm @anthropic-ai/claude-code; claude.ai/install.sh).
		Binary: &BinaryResolveSpec{
			Names: BinaryNames{
				Unix:    []string{"claude"},
				Windows: []string{"claude.exe", "claude.cmd", "claude"},
			},
			ProbeDirs: []ProbeDir{
				{OS: ProbeUnix, Rel: ".claude/local"},
				{OS: ProbeUnix, Rel: ".local/bin"},
				// grounded 2026-09-02: bootstrap.ps1 installs the native
				// binary under %USERPROFILE%\.local\bin, mirroring the Unix
				// layout (code.claude.com/docs/en/setup uninstall section).
				{OS: ProbeWindows, Rel: ".local/bin"},
			},
			// Minimum host runtime, grounded 2026-10-04 from the npm registry
			// (`npm view <pkg> engines`): @anthropic-ai/claude-code 2.1.289 declares engines.node.
			Runtime: &RuntimeRequirement{Runtime: RuntimeNode, MinVersion: "22.0.0", Product: "Claude Code", Source: "npm registry engines.node, @anthropic-ai/claude-code 2.1.289, read 2026-10-04"},
			Installs: []InstallHint{
				{OS: "", Channel: "npm", Argv: []string{"npm", "install", "-g", "@anthropic-ai/claude-code"}, Display: "npm install -g @anthropic-ai/claude-code"},
				{OS: "linux", Channel: "script", Argv: []string{"bash", "-lc", "curl -fsSL https://claude.ai/install.sh | bash"}, Display: "curl -fsSL https://claude.ai/install.sh | bash", Requires: []string{"curl"}},
				{OS: "darwin", Channel: "script", Argv: []string{"bash", "-lc", "curl -fsSL https://claude.ai/install.sh | bash"}, Display: "curl -fsSL https://claude.ai/install.sh | bash", Requires: []string{"curl"}},
				// grounded 2026-09-02: bootstrap.ps1 (claude.ai/install.ps1)
				// downloads the platform .exe and execs `& $binaryPath
				// install`; the winget manifest (Anthropic.ClaudeCode,
				// InstallerType: portable, Commands: [claude]) is the
				// package-manager alternative.
				{OS: "windows", Channel: "script", Argv: []string{"powershell", "-Command", "irm https://claude.ai/install.ps1 | iex"}, Display: "irm https://claude.ai/install.ps1 | iex"},
				{OS: "windows", Channel: "winget", Argv: []string{"winget", "install", "Anthropic.ClaudeCode"}, Display: "winget install Anthropic.ClaudeCode"},
			},
		},
		// Attachable: `observer claude --attach` hands the PTY to the daemon
		// (session-attach v1 scope).
		Attach: &AttachSpec{Subcommand: "claude"},
		// Credential env forwarded across the attach socket. Grounded:
		// cmd/observer/claude.go prepareClaudeEnv honors a preset
		// ANTHROPIC_AUTH_TOKEN (docs/proxy-wrappers.md); ANTHROPIC_API_KEY is
		// claude-code's standard key env. NAMES only — the caller's values ride
		// the socket so a shell-exported key reaches the daemon-spawned child.
		AuthEnv: []string{"ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN"},
		// Native resume GROUNDED (session-attach design Phase 3, decision #6:
		// claude-code first). Verified live 2026-07-19 against the installed
		// CLI: `claude --help` lists `-r, --resume [value]` — "Resume a
		// conversation by session ID" (also `-c, --continue` for the most
		// recent). Observer's sessions.id IS claude's native JSONL sessionId
		// (adapter recon), so `claude --resume <sessions.id>` reattaches the
		// REAL transcript. IDMechanism "flag:--resume"; the `observer claude`
		// launcher exposes a uniform `--resume <id>` flag that maps to it.
		Resume: ResumeSpec{Kind: ResumeNative, Subcommand: "claude", IDMechanism: "flag:--resume"},
		// Model picker (B5). Grounded live 2026-08-08: `claude --help` lists
		// `--model <model>` — "Provide an alias for the latest model (e.g.
		// 'fable', 'opus', or 'sonnet') or a model's full name (e.g.
		// 'claude-fable-5')". The `observer claude` launcher is
		// DisableFlagParsing + launcherArgsOrDone (B6), so a forwarded
		// `--model <value>` reaches the claude binary unmodified.
		// Catalog: Anthropic only. ANTHROPIC_BASE_URL is the whole route
		// (above) and every model id the CLI accepts is a Claude alias or a
		// full Claude model name (the --help text quoted above).
		Model: ModelSpec{
			Kind: ModelArg, Flag: "--model", Known: []string{"opus", "sonnet", "fable"},
			Catalog: ModelCatalog{Kind: ModelCatalogVendor, Providers: []string{"anthropic"}},
		},
		// Sandbox filesystem-isolation row (B9). GROUNDED: the tool's own
		// state lives at ~/.claude (settings/hooks/projects transcripts),
		// ~/.claude.json + ~/.claude.json.backup (trust/onboarding/MCP
		// config); ~/.local/share/claude holds the versioned install and is
		// read-only from the sandbox's perspective.
		Sandbox: SandboxSpec{
			NeedsWin32k: true,
			ProviderEnv: []string{"ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "CLAUDE_CONFIG_DIR"},
			StateRW:     []string{".claude", ".claude.json", ".claude.json.backup"},
			StateRO:     []string{".local/share/claude"},
			// settings.json carries the hooks observer registers
			// (internal/hook/register.go registerClaudeCode).
			ProtectRO: []string{".claude/settings.json"},
			// Windows 11 Pro rerun 2026-10-25, D3: Claude Code reads
			// $CLAUDE_CONFIG_DIR/.claude.json when the variable is set,
			// else ~/.claude.json; a first start shows the onboarding
			// screens (they call api.anthropic.com and platform.claude.com
			// directly, which the box refuses, and the tool exits 1), and
			// with hasCompletedOnboarding true it starts without them.
			// Sign-in seeding (lane BOXSIGNIN): the vendor's credential
			// management docs name the file on Linux and Windows and the
			// keychain on macOS.
			SignIn: &SandboxSignIn{
				Files: []string{".claude/.credentials.json"}, KeychainOn: []string{"darwin"}, Artifacts: []string{"claude-code/credentials"},
				Grounding: "code.claude.com/docs/en/authentication, Credential management (read 2026-10-27): on Linux ~/.claude/.credentials.json (mode 0600), on Windows .claude/.credentials.json under %USERPROFILE%, on macOS the encrypted macOS Keychain (a file only when the Keychain rejects the write); CLAUDE_CONFIG_DIR moves the file",
				DocURL:    "https://code.claude.com/docs/en/authentication",
			},
			ConfigHome: &SandboxConfigHome{
				Env: "CLAUDE_CONFIG_DIR", Dir: ".claude", StateFile: ".claude.json", RelocatedStateFile: ".claude.json",
				OnboardedKey: "hasCompletedOnboarding", SeedKeys: []string{"hasCompletedOnboarding", "theme"},
				Grounding: "Windows 11 Pro rerun 2026-10-25 D3 debug logs (raw win8b-diag-debug2/3): exit 1 at showSetupScreens without the flag, a running session with it",
			},
			// A call that ran has a tool_result block (keyed by the call's
			// tool_use_id) in a user line; PreToolUse names the same id.
			// An errored result is not counted (an interrupted or refused
			// call may never have reached the gate).
			GateDrift: TranscriptGateSpec{
				PayloadCallID: "tool_use_id",
				Ran: []TranscriptBlockRule{{
					LineKey: "type", LineValue: "user", Path: []string{"message", "content"},
					BlockKey: "type", BlockValue: "tool_result", IDKey: "tool_use_id", SkipIfTrue: "is_error",
				}},
				// The call is a tool_use block (keyed by id) in an
				// assistant line; every line carries an RFC 3339
				// timestamp, which a resumed or forked session's copied
				// history keeps.
				Called: []TranscriptBlockRule{{
					LineKey: "type", LineValue: "assistant", Path: []string{"message", "content"},
					BlockKey: "type", BlockValue: "tool_use", IDKey: "id",
				}},
				TimestampKey: "timestamp",
				Grounding:    "testdata/claudecode/multi-tool-turn.jsonl (tool_use id == tool_result tool_use_id) and the PreToolUse payload's tool_use_id (internal/hook/toolaccount.go)",
			},
		},
		// Headless one-shot, grounded by the live benchmark drives
		// (cmd/observer/benchmark_driver.go claudeCodeDriver): `claude -p
		// <prompt> --output-format json` prints a result JSON envelope on
		// stdout. Arena arena runner reuses the same argv shape.
		//
		// Permission lanes (OSH-R-005): bypass is the benchmark drive's
		// --dangerously-skip-permissions; edit is acceptEdits (file edits
		// inside the working directory run, anything else asks, and under -p
		// an ask is a denial, askhost.go); read_only is the default mode with
		// the writing and network tools disallowed. An explicit
		// --permission-mode also overrides a defaultMode the copied
		// settings.json may carry.
		Headless: &HeadlessSpec{
			PromptFlag: "-p",
			OutputArgs: []string{"--output-format", "json"},
			Result:     HeadlessResultStdoutJSON,
			Permissions: map[HeadlessPermLane][]string{
				HeadlessPermBypass: {"--dangerously-skip-permissions"},
				HeadlessPermEdit:   {"--permission-mode", "acceptEdits"},
				HeadlessPermReadOnly: {
					"--permission-mode", "default",
					"--disallowedTools", "Bash,Edit,Write,MultiEdit,NotebookEdit,WebFetch,WebSearch",
				},
			},
		},
	},
	"codex": {
		Tool:       "codex",
		PromptLane: PromptLaneHook,
		Vocabulary: Vocabulary{InTaxonomy: true},
		// The config file the launcher writes is the route; the launcher also
		// refuses to claim it when the invocation supplies its own config
		// override, so an un-overridden launch reaches the Observer proxy.
		Proxy: &ProxyRoute{
			ClientAuth:           ClientAuthPathToken,
			SharesCredentialFile: true, CredentialFileReason: routeCredCodex,
			Kind: RouteConfigFile, EnvVar: "", Launcher: "observer codex",
			Note:          "codex routes through ~/.codex/config.toml (model_provider=openai-observer base_url, or openai_base_url for the built-in openai provider; not an env var); a selected provider that resolves its own endpoint (amazon-bedrock, SigV4 to AWS) bypasses the proxy - `observer doctor codex` reports it",
			CrossOSBridge: true, Proof: RouteProofLauncherRoute,
			Setting: "the Observer model provider (model_provider and [model_providers.openai-observer])",
		},
		Routability: RouteStatusRoutableNow,
		// CrossOSBridge grounded 2026-09-02 (IDE-surface remediation T2):
		// hook.registerCodexWindows writes the wsl.exe bridge into the
		// Windows-side ~/.codex/hooks.json exactly like the claude-code and
		// cursor targets, so init/start's hookSupported() may auto-wire the
		// `codex-windows` target.
		// PromptShadowsTranscript (T-563): the UserPromptSubmit row and the
		// rollout's user_message / item_completed UserMessage row record the
		// same prompt; session messages keep the rollout row.
		Hook: HookSpec{Mechanism: HookCodexConfig, CrossOSBridge: true, AutoWired: true, Bindings: hookBindingsCodex, HooksShareCredentialFile: true, CredentialFileReason: credFileCodex, PromptShadowsTranscript: true},
		// Remote grounded 2026-09-24 against the Codex config reference
		// (learn.chatgpt.com/docs/config-file/config-reference, the
		// developers.openai.com redirect) + docs/plans/native-console-codex-
		// findings-2026-06-16.md: `[mcp_servers.<id>] url = …` designates a
		// Streamable HTTP server (no transport/type key — url-vs-command is
		// the discriminator), `http_headers` = static headers,
		// `bearer_token_env_var`/`env_http_headers` = secret-by-reference
		// (never written by the relay writer). No SSE spelling exists.
		// WindowsStdio grounded 2026-10-20 (lane NPXMCP, T-923): codex-rs
		// spawns an MCP command with Rust's std Command (no shell, no
		// %PATHEXT%); rmcp-client/src/program_resolver.rs (openai/codex PR
		// #3828, commit f828cd2897, first in rust-v0.59.0) resolves a bare
		// name through PATHEXT on Windows. Live on native Windows 11 with an
		// isolated CODEX_HOME: 0.58.0 failed a bare `npx` ("program not
		// found") and started `npx.cmd` and `cmd /c npx`; 0.163.0 started
		// all three. `npx.cmd` is the form every tested build starts.
		MCP: &MCPTarget{Format: MCPCodexTOML, PathHint: ".codex/config.toml", Implemented: true, SharesCredentialFile: true, CredentialFileReason: mcpCredCodex, WindowsStdio: winshim.LaunchCmdExtension, Remote: &MCPRemoteTarget{
			Transports:  []MCPRemoteTransport{MCPRemoteStreamableHTTP},
			Headers:     true,
			Implemented: true,
			Note:        "codex config reference 2026-09-24: url (streamable HTTP only, no type key) + http_headers; bearer_token_env_var/env_http_headers never emitted (no secret in config)",
		}},
		Native:    NativeRails{A: true, B: true, C: true, Note: "Rail A (usage-export) config-gated on live keys"},
		TokenTier: TokenTier{Best: "proxy", ReasoningDisjoint: true, GenerationTiming: GenTimingTranscript},
		// P0.1 FULL: rollout JSONL (event_msg text lane + function_call
		// pairing); reader derives the path by session-id glob.
		Handoff: HandoffCapability{Transcript: TranscriptFull, Inject: []InjectKind{InjectFile, InjectMCP, InjectPrompt}, Launch: &LaunchSpec{Subcommand: "codex"}},
		// Binary resolution + grounded installs. Unix launcher resolves
		// "codex"; npm @openai/codex (any OS) + brew on macOS.
		Binary: &BinaryResolveSpec{
			Names: BinaryNames{
				Unix:    []string{"codex"},
				Windows: []string{"codex.exe", "codex.cmd", "codex"},
			},
			// grounded 2026-09-02: the native/winget install lands
			// codex.exe under %LOCALAPPDATA%\Programs\OpenAI\Codex\bin
			// (CODEX_INSTALL_DIR override); releases live under
			// %USERPROFILE%\.codex\packages\standalone\releases.
			ProbeDirs: []ProbeDir{
				{OS: ProbeWindows, Rel: "AppData/Local/Programs/OpenAI/Codex/bin"},
			},
			// Minimum host runtime, grounded 2026-10-04 from the npm registry
			// (`npm view <pkg> engines`): @openai/codex 0.160.0 declares engines.node.
			Runtime: &RuntimeRequirement{Runtime: RuntimeNode, MinVersion: "16", Product: "Codex CLI", Source: "npm registry engines.node, @openai/codex 0.160.0, read 2026-10-04"},
			Installs: []InstallHint{
				{OS: "", Channel: "npm", Argv: []string{"npm", "install", "-g", "@openai/codex"}, Display: "npm install -g @openai/codex"},
				// DI-10 fix: codex is a brew CASK (formulae.brew.sh/cask/codex),
				// not a formula — the bare `brew install codex` name collides.
				{OS: "darwin", Channel: "brew", Argv: []string{"brew", "install", "--cask", "codex"}, Display: "brew install --cask codex"},
				// grounded 2026-09-02: releases.openai.com/codex/install.ps1
				// (302 from chatgpt.com/codex/install.ps1), vendor form uses
				// -ExecutionPolicy ByPass. No winget id exists.
				// T-034j (2026-10-07, script re-read): install.ps1's one
				// Read-Host ("Start Codex now?", plus the replace / conflict
				// questions) blocks in a ConPTY; CODEX_NON_INTERACTIVE=1
				// answers every one "no" without asking.
				{OS: "windows", Channel: "script", Argv: []string{"powershell", "-ExecutionPolicy", "ByPass", "-c", "$env:CODEX_NON_INTERACTIVE='1'; irm https://chatgpt.com/codex/install.ps1 | iex"}, Display: "$env:CODEX_NON_INTERACTIVE='1'; irm https://chatgpt.com/codex/install.ps1 | iex"},
			},
		},
		// Attachable: `observer codex --attach` hands the PTY to the daemon
		// (session-attach v1 scope).
		Attach: &AttachSpec{Subcommand: "codex"},
		// Credential env forwarded across the attach socket. Grounded:
		// cmd/observer/codex.go's sk-/JWT auth paths read OPENAI_API_KEY.
		AuthEnv: []string{"OPENAI_API_KEY"},
		// Native resume GROUNDED (session-attach design Phase 3, decision #6:
		// codex first). Verified live 2026-07-19 against the installed CLI:
		// `codex resume [SESSION_ID] [PROMPT]` — "Resume a previous interactive
		// session … Session id (UUID) or session name … use --last to pick the
		// most recent". Observer's sessions.id IS codex's native session_id
		// (adapter recon), so `codex resume <sessions.id>` reattaches the REAL
		// session. The global `-c openai_base_url` override is honored BEFORE
		// the `resume` subcommand (verified: `codex -c … resume --help` parses
		// clean), so proxy routing composes. IDMechanism "subcommand:resume";
		// the `observer codex` launcher exposes a uniform `--resume <id>` flag
		// that maps to the `resume <id>` subcommand.
		Resume: ResumeSpec{Kind: ResumeNative, Subcommand: "codex", IDMechanism: "subcommand:resume"},
		// Model picker (B5). Grounded live 2026-08-08: `codex --help` lists
		// `-m, --model <MODEL>` — "Model the agent should use" (also
		// reachable via `-c model="o3"`, the example shown in help). The
		// `observer codex` launcher is DisableFlagParsing + launcherArgsOrDone
		// (B6), so a forwarded `--model <value>` reaches the codex binary
		// unmodified.
		// Catalog: OpenAI. The route above is the openai provider's base URL;
		// a config.toml model_provider that resolves its own endpoint is the
		// documented bypass, not a second catalogue this row can enumerate.
		Model: ModelSpec{
			Kind: ModelArg, Flag: "--model", Known: []string{"o3"},
			Catalog: ModelCatalog{Kind: ModelCatalogVendor, Providers: []string{"openai"}},
		},
		// Sandbox filesystem-isolation row (B9). GROUNDED against the adapter's
		// own roots (internal/adapter/codex/adapter.go WatchPaths → <home>/.codex/
		// sessions) plus the CLI's config/auth siblings: ~/.codex holds config.toml,
		// auth.json, history.jsonl and the rollout transcripts. The WHOLE dir is
		// bound rw — config.toml carries plaintext provider keys, and the sandbox
		// deliberately does not hide the operator's own credentials from the tool
		// they just launched; the boundary is about the rest of $HOME and the rest
		// of the filesystem, not about this tool's own state.
		// hooks.json = register.go codexHooksFile; config.toml carries
		// mcp_servers (internal/mcp/locate) and the hooks feature flag.
		// SignIn (lane BOXSIGNIN): the Codex auth docs name auth.json under
		// CODEX_HOME (default ~/.codex) for the file store; the keyring and
		// auto stores keep it in the OS credential store, where no file
		// exists and nothing is copied (config.toml, which says which, is
		// never read: it holds provider keys).
		Sandbox: SandboxSpec{
			NeedsWin32k: true, ProviderEnv: []string{"OPENAI_API_KEY", "CODEX_HOME"}, StateRW: []string{".codex"}, ProtectRO: []string{".codex/hooks.json", ".codex/config.toml"},
			SignIn: &SandboxSignIn{
				Files:     []string{".codex/auth.json"},
				Artifacts: []string{"codex/auth"}, MayUseKeychain: true,
				Grounding: "learn.chatgpt.com/docs/auth (the developers.openai.com/codex/auth redirect, read 2026-10-27): Codex caches login details in a plaintext file at ~/.codex/auth.json or in the OS credential store; cli_auth_credentials_store file keeps auth.json under CODEX_HOME (default ~/.codex), keyring and auto use the OS store",
				DocURL:    "https://developers.openai.com/codex/auth",
			},
		},
		// Headless one-shot, grounded by the live benchmark drives
		// (cmd/observer/benchmark_driver.go codexDriver): `codex exec
		// <prompt> --json -o <file>` writes the final message to the -o
		// file and thread ids to stdout JSON.
		//
		// Permission lanes (OSH-R-005): codex exec runs inside its own
		// sandbox, so edit is -s workspace-write (the benchmark drive's
		// shape) and read_only is -s read-only. No bypass lane: codex's
		// --dangerously-bypass-approvals-and-sandbox is never driven.
		Headless: &HeadlessSpec{
			Lead:       []string{"exec"},
			OutputArgs: []string{"--json"},
			Result:     HeadlessResultOutputFile,
			ResultFlag: "-o",
			Permissions: map[HeadlessPermLane][]string{
				HeadlessPermEdit:     {"--skip-git-repo-check", "-s", "workspace-write"},
				HeadlessPermReadOnly: {"--skip-git-repo-check", "-s", "read-only"},
			},
		},
	},

	// Proxy-routable CLI (OpenAI-compatible base URL via launcher).
	// LIVE-VERIFIED 2026-06-27: `observer opencode -- run …` routed a
	// gpt-5.4-nano turn through the proxy (api_turns grew).
	"opencode": {
		Tool:       "opencode",
		Vocabulary: Vocabulary{InTaxonomy: true},
		// FIX-7 (phase-2 review): no prompt-submit hook exists for
		// OpenCode (its chat.message plugin hook is a REDACT-only
		// lane per §2.2 of the contract, and even that is unbuilt),
		// but it is already proxy-routed today — the proxy lane is
		// its only realistic path to prompt-submit intervention.
		PromptLane: PromptLaneProxyOnly,
		// OPENAI_BASE_URL is the route AND the provider selection: the
		// launcher's injected environment names the openai-compatible provider
		// opencode then uses, and the live 2026-06-27 verification above ran
		// through exactly that injection. OpenCode's built-in Zen provider
		// ("opencode", e.g. big-pickle) ignores OPENAI_BASE_URL; since
		// 2026-10-02 the launcher also routes it through
		// OPENCODE_CONFIG_CONTENT onto the proxy's `opencode-zen` agent lane
		// (demo node 1: a Zen session had bypassed the proxy and with it
		// the only prompt lane OpenCode has).
		Proxy: &ProxyRoute{
			ClientAuth: ClientAuthPathToken,
			Kind:       RouteLauncher, EnvVar: "OPENAI_BASE_URL", Suffix: "/v1",
			Launcher: "observer opencode", Proof: RouteProofLauncherRoute,
			// CLI-2: a project opencode.json provider.openai.options.baseURL
			// beats OPENAI_BASE_URL, so since Wave 4 the launcher also puts
			// the openai route in OPENCODE_CONFIG_CONTENT, which opencode
			// merges over every file but the managed one. That is what keeps
			// RouteProofLauncherRoute honest; a caller-set
			// OPENCODE_CONFIG_CONTENT leaves the proof unproven.
			ConfigContentEnv: "OPENCODE_CONFIG_CONTENT",
		},
		Routability: RouteStatusRoutableNow,
		Hook:        HookSpec{Mechanism: HookPluginShimTS, AutoWired: true, Bindings: hookBindingsOpenCode}, // plugin shim (Lane D)
		// OpenCode hosts MCP under its own "mcp" object in
		// ~/.config/opencode/opencode.json (live-grounded 2026-06-26 against
		// the operator's install: {"type":"local","command":[…],"enabled"}),
		// written globally by registerOpenCodeJSON.
		// Remote grounded 2026-09-24 against opencode.ai/docs/mcp-servers:
		// `{"type":"remote","url":…,"enabled":true,"headers":{…}}` — the
		// typed-remote sibling of the local shape above; transport is
		// inferred from the url. Written by registerOpenCodeRemote (W4a).
		MCP: &MCPTarget{Format: MCPOpenCodeJSON, PathHint: ".config/opencode/opencode.json", Implemented: true, SharesCredentialFile: true, CredentialFileReason: mcpCredOpenCode, Remote: &MCPRemoteTarget{
			Transports:  []MCPRemoteTransport{MCPRemoteStreamableHTTP, MCPRemoteSSE},
			Headers:     true,
			Flags:       map[string]bool{"enabled": true},
			Implemented: true,
			Note:        "opencode.ai/docs/mcp-servers 2026-09-24: type remote + url + enabled + headers; transport inferred from url",
		}},
		Native:    NativeRails{},
		TokenTier: TokenTier{Best: "sqlite", ReportsCost: true},
		// P0.1 FULL: opencode.db message+part tables (reader = P2 tranche);
		// OpenCode 2.x session_message read the same way (opencode/v2.go).
		Handoff: HandoffCapability{Transcript: TranscriptFull, Inject: []InjectKind{InjectFile, InjectMCP, InjectPrompt}, Launch: &LaunchSpec{Subcommand: "opencode"}},
		// Attach grounded 2026-07-24 (attach-all-launchers); PTY handoff only
		// — no prompt seeding, token capture path unchanged.
		Attach: &AttachSpec{Subcommand: "opencode"},
		// Native resume GROUNDED, live-verified 2026-07-24: `opencode --session
		// <id>` reattaches the real session; id is the raw observer SessionID
		// (`ses_…`). The `observer opencode` launcher maps `--resume <id>` to it.
		Resume: ResumeSpec{Kind: ResumeNative, Subcommand: "opencode", IDMechanism: "flag:--session"},
		// AuthEnv zero: opencode's primary auth is its `opencode auth` file
		// store; per-provider env keys (OPENAI_API_KEY / ANTHROPIC_API_KEY / …)
		// are candidates but unverified as the effective runtime source here.
		// Binary resolution + grounded installs. Unix launcher resolves
		// "opencode"; npm opencode-ai@latest (any OS) + the official curl
		// installer on linux/darwin. Its own bin dir (.opencode/bin) is a
		// per-tool extra on both OSes.
		Binary: &BinaryResolveSpec{
			// npm JS bin: Windows install lays down a `.cmd` shim (+
			// .ps1/POSIX-shell forms), never an `.exe` — see the
			// command-code row's Binary comment for the long-form
			// rationale.
			Names: BinaryNames{
				Unix:    []string{"opencode"},
				Windows: []string{"opencode.cmd", "opencode"},
			},
			ProbeDirs: []ProbeDir{
				{OS: ProbeUnix, Rel: ".opencode/bin"},
				{OS: ProbeWindows, Rel: ".opencode/bin"},
			},
			Installs: []InstallHint{
				{OS: "", Channel: "npm", Argv: []string{"npm", "install", "-g", "opencode-ai@latest"}, Display: "npm install -g opencode-ai@latest"},
				{OS: "linux", Channel: "script", Argv: []string{"bash", "-lc", "curl -fsSL https://opencode.ai/install | bash"}, Display: "curl -fsSL https://opencode.ai/install | bash", Requires: []string{"curl", "tar"}},
				{OS: "darwin", Channel: "script", Argv: []string{"bash", "-lc", "curl -fsSL https://opencode.ai/install | bash"}, Display: "curl -fsSL https://opencode.ai/install | bash", Requires: []string{"curl", "unzip"}},
				// grounded 2026-09-02: opencode.ai/docs lists scoop (Scoop
				// main bucket) alongside npm for Windows. The choco listing
				// (author SST = the vendor org) publishes a stale 0.11.1
				// vs. npm's 1.18.26 — deliberately not adopted.
				{OS: "windows", Channel: "scoop", Argv: []string{"scoop", "install", "opencode"}, Display: "scoop install opencode"},
			},
		},
		// Model picker (B5). Grounded live 2026-08-08: `opencode --help`
		// lists `-m, --model  model to use in the format of provider/model`.
		// The `observer opencode` launcher is DisableFlagParsing +
		// launcherArgsOrDone (B6), so a forwarded `--model <value>` reaches
		// the opencode binary unmodified. Catalog: open (provider/model ids
		// for any configured provider), so a picker offers models this node
		// has used rather than a catalogue it cannot prove keys for.
		Model: ModelSpec{Kind: ModelArg, Flag: "--model", Catalog: ModelCatalog{
			Kind: ModelCatalogOpen,
			Note: "Arena routes opencode through OpenRouter, so a model must be an openrouter/<vendor>/<model> id",
		}},
		// Headless one-shot, LIVE-GROUNDED 2026-08-22 (arena headless-drive
		// arc): `opencode run <prompt> --format json` streams NDJSON events
		// (step_start/text/step_finish), each carrying sessionID; the last
		// text part is the answer. A real drive created oc.txt and replied
		// DONE. Default formatted output also works but carries no ids. The
		// routed Arena lane pins the provider to openrouter/* because the
		// process-local OPENCODE_CONFIG_CONTENT override points that provider
		// at Observer's named OpenRouter upstream. stealth/ox-alpha was
		// confirmed at zero prompt/completion price in OpenRouter's live
		// catalog on 2026-08-24.
		Headless: &HeadlessSpec{
			Lead:              []string{"run"},
			OutputArgs:        []string{"--format", "json"},
			Result:            HeadlessResultOpenCodeEvents,
			ProxyModelPrefix:  "openrouter/",
			ProxyDefaultModel: "openrouter/stealth/ox-alpha",
			// opencode run asks nothing: its default permission set lets
			// every tool run, with no flag to say so. That is a bypass with
			// no tokens (OSH-R-005); no other lane is grounded.
			Permissions: map[HeadlessPermLane][]string{HeadlessPermBypass: {}},
		},
		// Sandbox filesystem-isolation row (B9). GROUNDED against
		// internal/adapter/opencode/adapter.go defaultRoots (~/.opencode and
		// ~/.local/share/opencode) plus the XDG config dir the guard dialect
		// compiler already writes (~/.config/opencode/opencode.json — see
		// cmd/observer/guardcompile.go). auth.json lives in the data dir, so the
		// whole state tree is bound rw: the tool needs its own credentials.
		Sandbox: SandboxSpec{
			StateRW: []string{".local/share/opencode", ".config/opencode", ".opencode"},
			// macOS (live user install 2026-10-29, D-MU6): opencode also
			// writes its XDG state dir (prompt history, model memory) and
			// failed under Seatbelt without it, and its XDG cache dir
			// (~/.cache/opencode/bin, re-check 2026-10-29: EEXIST on mkdir
			// in the blinded home, N2). Linux is not grounded yet.
			StateRWByOS: map[string][]string{"darwin": {".local/state/opencode", ".cache/opencode"}},
			// opencode.json carries the MCP servers (internal/mcp/locate).
			ProtectRO: []string{".config/opencode/opencode.json"},
		},
		// GUI launch row (plan §2.2): OpenCode Desktop writes the SAME
		// opencode.db this row's watcher reads (inventory §2.12,
		// VERIFIED-LIVE via a drafts.sqlite session-id join) — the cleanest
		// desktop case.
		GUI: &GUILaunchSpec{
			ID:      "opencode-desktop",
			Label:   "OpenCode Desktop",
			Surface: "desktop",
			Binary: BinaryResolveSpec{
				Names: BinaryNames{
					Windows: []string{"OpenCode.exe"},
				},
				ProbeDirs: []ProbeDir{
					{OS: ProbeWindows, Rel: "AppData/Local/Programs/@opencode-aidesktop"},
				},
				Installs: []InstallHint{
					{OS: "windows", Channel: "winget", Argv: []string{"winget", "install", "--id", "SST.OpenCodeDesktop", "-e", "--source", "winget"}, Display: "winget install --id SST.OpenCodeDesktop -e --source winget"},
					{OS: "darwin", Channel: "brew", Argv: []string{"brew", "install", "--cask", "opencode-desktop"}, Display: "brew install --cask opencode-desktop"},
				},
				InstallNote: "no grounded Linux channel argv: the vendor ships .deb and .rpm artifacts " +
					"(opencode.ai/download) and which applies depends on the distro, so no single command is " +
					"offered.",
			},
			// PATH walk disabled: a bun-compiled `opencode.exe` CLI can sit
			// on PATH and would match "OpenCode.exe" case-insensitively on
			// Windows — that would spawn the TUI detached with no PTY.
			ProbeOnly:      true,
			DarwinApp:      "OpenCode",
			ProjectDirArgv: false,
			Wrap: WrapSpec{
				Kind: WrapChildEnv,
				Env: []WrapEnvVar{
					{Name: "OPENAI_BASE_URL", Suffix: "/v1"},
				},
				ColdStartOnly: true,
				Reason: "child_env, NOT config_write, and the plan §2.2 sketch said the opposite - here is " +
					"why. WrapConfigWrite's contract is that an EXISTING config-lane writer applies the route, " +
					"but internal/proxyroute has no opencode registrar (claude/codex/crush/kimi/qwen only) and " +
					"this row carries no ProxyProbe, so naming one would point the operator at a writer that " +
					"does not exist. What IS grounded and live-verified for opencode is the launcher lane in " +
					"this row's Proxy above: `observer opencode` exports OPENAI_BASE_URL=<proxy>/v1, and the " +
					"desktop app embeds the same core. Injecting it on a cold start is the honest best effort; " +
					"whether the Electron shell honours the env var (rather than only the per-provider baseURL " +
					"in ~/.config/opencode/opencode.json, inventory §4.1) is NOT verified - treat a launch " +
					"that produces no api_turns row as the config lane winning.",
			},
			Hosts:    []string{"opencode"},
			Grounded: true,
			Note: "Windows layout grounded on this box 2026-09-03: " +
				"%LOCALAPPDATA%\\Programs\\@opencode-aidesktop\\OpenCode.exe, with NO bin\\ dir - hence " +
				"ProjectDirArgv=false. macOS bundle \"OpenCode.app\" grounded from the Homebrew cask " +
				"`opencode-desktop`; winget id `SST.OpenCodeDesktop` grounded from a live " +
				"`winget search --exact` the same day (note the sibling `SST.opencode`, which is the CLI).",
		},
	},

	// IDE/extension adapters that talk only to their own backend → no proxy
	// route (Proxy=nil is DATA, not a missing feature). Hooks/MCP per tool.
	"cursor": {
		Tool:       "cursor",
		PromptLane: PromptLaneHook,
		Vocabulary: Vocabulary{InTaxonomy: true},
		// Surface-split (2026-06-26): the NATIVE Cursor backend has no base-URL
		// knob. RECLASSIFIED native_exempt 2026-10-25 (surface-gap arc IDE-4,
		// lane w2-c): the one BYOK knob, the custom "OpenAI Base URL", cannot
		// reach a loopback proxy, because Cursor relays even BYOK requests
		// through its own servers ("all requests are routed through Cursor's
		// servers", cursor.com/docs/settings/api-keys), which cannot reach
		// 127.0.0.1 on the developer's machine. cursor-agent documents no
		// base-URL knob either. Only a publicly reachable org gateway could
		// sit behind that knob, which is an org-plane design question, not a
		// node route. Proxy stays nil.
		Proxy:       nil,
		Routability: RouteStatusNativeExempt,
		Hook:        HookSpec{Mechanism: HookCursor, CrossOSBridge: true, AutoWired: true, Bindings: hookBindingsCursor},
		// Remote grounded 2026-09-24 against cursor.com/docs/context/mcp:
		// `{"url":…,"headers":{…}}` — NO type key on a remote entry (type is
		// only used for `"stdio"`); Cursor auto-detects Streamable HTTP vs
		// SSE from the endpoint. Written by the shared JSON remote writer.
		MCP: &MCPTarget{Format: MCPServersJSON, PathHint: ".cursor/mcp.json", Implemented: true, SharesCredentialFile: true, CredentialFileReason: mcpCredCursor, Remote: &MCPRemoteTarget{
			Transports:  []MCPRemoteTransport{MCPRemoteStreamableHTTP, MCPRemoteSSE},
			Headers:     true,
			Implemented: true,
			Note:        "cursor.com/docs/context/mcp 2026-09-24: url + headers, no type key on remote entries (transport auto-detected)",
		}},
		Native: NativeRails{}, // business admin/usage API not yet investigated (Phase-4 ledger).
		// Auto-mode "default" model is now resolved from store.db turn blobs
		// (providerOptions.cursor.modelName) at hook time — see
		// cursor.ResolveModelFromStore. Tokens still depend on the stop hook
		// firing (the transcript carries no usage).
		//
		// C1 CLOSED AS UPSTREAM-REGRESSION (2026-08-22 live audit): cursor
		// 3.15.19 stop payloads carry NO usage fields at all (verified via
		// ~/.observer/cursor-stop-debug.jsonl `no_usage_fields` rows — hooks
		// fire, session_id present, payload keys are conversation/model/
		// status/transcript_path only), and no local surface carries
		// per-generation tokens anymore: agent-transcripts JSONLs have none,
		// chats/<ws>/<conv>/store.db blobs are message content only, and
		// ai-tracking/ai-code-tracking.db tracks code hashes, not spend.
		// The ff8ebc12 guard fix stands ready if usage returns. Since
		// 0c791f59e (2026-09-09, merged 2026-09-10) the CLI's own structured
		// `agent_cli.turn.outcome` log records are captured too
		// (cli_usage.go): they carry per-turn counters (input already net of
		// both cache buckets) even when headless runs emit neither stop nor
		// afterAgentResponse; a retried turn keeps the final attempt only, so
		// totals are a lower bound and are labelled as such.
		//
		// CORRECTED 2026-09-23 (S10-CURSOR, live-grounded on 3.17.21 /
		// 3.20.21 / 3.21.13): IDE stop AND afterAgentResponse payloads DO
		// carry per-request usage again (input_tokens GROSS incl. cache
		// read, output, cache_read, cache_write). Session 8be96a3f's
		// 2,783,511 / 21,724 / 2,529,792 reached the hook and was LOST to
		// the hook's ingest deadline (tokens were written after actions +
		// FTS). Fixed by the token-first write (internal/hook/cursor.go) and
		// backstopped by the IDE hooks output-log replay
		// (internal/adapter/cursor/hookslog.go): Cursor writes every hook
		// INPUT payload to <userData>/logs/*/window*/output_*/cursor.hooks*.log,
		// which the watcher replays under the live hook's own identity.
		// Cloud Agents (bc-… ids) carry no usage in any local hook.
		// Re-grounded 2026-10-05 on Cursor 3.23.12: a Cloud Agent fires only
		// sessionStart and afterAgentThought locally (no stop, no
		// afterAgentResponse, no tool hooks; the turns run in Cursor's
		// remote VM), and state.vscdb keeps it under bcCachedDetails:<id>
		// as protobuf with no usage either. The adapter now captures the
		// session and one step row per thought (internal/adapter/cursor/
		// cloudagent.go); tokens and model cost stay honestly absent, so
		// the Gap text below is unchanged.
		//
		// 2026-09-27 (tracker item 17, grounded on node-1 + the 2026.09.18 /
		// 2026.09.26 cursor-agent bundles): the INTERACTIVE CLI reports usage
		// only on stop + afterAgentResponse (gross input incl. BOTH cache
		// buckets - now netted by both), its turn-outcome log record carries
		// no tokens, and a turn that is still retrying when the user quits
		// runs neither hook - no local usage exists for it. The adapter now
		// records such turns from the debug log as turn_aborted / api_error
		// evidence rows (cli_turns.go) so the session page and
		// `observer doctor cursor` (cursor.usage) say why usage is unknown.
		TokenTier: TokenTier{Best: "hook", Gap: "IDE usage rides the stop/afterAgentResponse hook payload (replayed from Cursor's own hooks output log when the live write is lost; the watcher tails that log, so a log first seen with more than max_file_bytes unread needs `observer backfill --cursor-hook-usage`, and the log only covers Cursor's last ~10 IDE launches); interactive CLI usage rides the same two hooks, which run only when a turn finishes, so a turn quit mid-retry or killed has no local usage (recorded as turn_aborted evidence, never zero); CLI headless usage comes from agent_cli.turn.outcome log records (final attempt only, so a lower bound); Cloud Agents (bc-… ids) expose no local usage at all"},
		// Limit AUDITED 2026-09-22: `cursor-agent about|status --format
		// json` (live-run) return only email/subscriptionTier/auth state —
		// no numeric usage/quota field. `~/.cursor/cli-config.json` and
		// `agent-cli-state.json` carry no usage data either, and
		// `cursor-agent --help` lists no usage/limits/quota subcommand.
		// Cursor traffic never touches the observer proxy (Proxy is nil
		// above), so the proxy-header half of the gauge can never fire
		// either — the vendor's own dashboard (cursor.com/settings) is the
		// only place this number exists.
		Limit: LimitCapability{
			Source: LimitSourceNoneRemote,
			Note:   "Cursor's usage-based limits are visible only in the Cursor dashboard (cursor.com/settings) - cursor-agent's own CLI (about/status/--help) and every local config file carry no usage/quota field, and Cursor traffic never routes through the observer proxy.",
		},
		// P0.1 FULL (CLI): ~/.cursor/projects/<slug>/agent-transcripts/
		// <sid>/<sid>.jsonl, Anthropic-shaped; NOT referenced by DB
		// source_file (sentinel) — derive by session id. IDE state.vscdb
		// unmeasured on this corpus. Reader = P2 tranche.
		Handoff: HandoffCapability{Transcript: TranscriptFull, Inject: []InjectKind{InjectFile, InjectMCP, InjectPrompt}, Launch: &LaunchSpec{Subcommand: "cursor"}, Note: "CLI grounded; IDE surface unmeasured"},
		// Attach grounded 2026-07-24 (attach-all-launchers); PTY handoff only
		// — no prompt seeding, token capture path unchanged.
		Attach: &AttachSpec{Subcommand: "cursor"},
		// Resume LIVE-CONFIRMED 2026-07-25 (the 2026-07-24 auth block is gone —
		// operator logged in, `cursor-agent status` → "Logged in as …").
		// `cursor-agent --help` lists `--resume [chatId]  Select a session to
		// resume`, and the chatId is our stored SessionID VERBATIM: the on-disk
		// chat dirs ~/.cursor/chats/<hash>/<chatId>/ are named with the exact
		// sessions.id values our adapter stores, so NO id transform is needed.
		// SPELLING (operator-corrected 2026-07-25): pass it JOINED as
		// `--resume=<chatId>`, not space-separated. The flag takes an OPTIONAL
		// value (`[chatId]`, help reports `default: false`), so the `=` form is
		// the unambiguous spelling; the space form relies on the parser electing
		// to consume the next token instead of leaving the flag bare and letting
		// the id fall through as a positional. resume_launcher.go's "cursor" row
		// therefore sets joined:true.
		// CONTENT-LEVEL PROOF: `cursor-agent --resume=<id> -p …` run against a
		// chat this session never wrote to, asked to quote the conversation's
		// first user message, answered with that message verbatim — the prior
		// transcript really is loaded, not merely a chat re-opened. Structural
		// proof alongside it: createdAtMs + title preserved, store.db grew,
		// no new chat dir; CONTROL — the same command WITHOUT --resume created
		// a new chat dir. Caveat (honest, non-blocking): the call is flaky over
		// this network — `RetriableError: WritableIterable is closed` against
		// agentn.global.api5.cursor.sh, typically clearing within 1–3 attempts,
		// on BOTH argv forms and on non-resume calls too. That is TRANSPORT
		// flakiness, not a broken resume mechanism; retry before concluding.
		Resume: ResumeSpec{Kind: ResumeNative, Subcommand: "cursor", IDMechanism: "flag:--resume"},
		// AuthEnv zero: cursor-agent authenticates via OAuth by default;
		// CURSOR_API_KEY is upstream-plausible but ungrounded as the runtime
		// key env, so no key is declared (never fabricate one).
		// Binary resolution + grounded install. Unix launcher resolves
		// "cursor-agent"; the installer drops versioned binaries under
		// .local/share/cursor-agent/versions/*. Official installer script
		// (cursor.com/docs/cli/installation). Windows hint is EXECUTABLE by
		// a native-Windows daemon (ConPTY, since 2026-07-04); post-install
		// detection needs Names.Windows (grounded 2026-09-02).
		//
		// Windows spellings GROUNDED 2026-09-02 by reading the installer
		// source (`$agentPath = "$env:LOCALAPPDATA\cursor-agent"`, a
		// `cursor-agent*` copy + `agent.*` alias block) and range-reading
		// the ZIP central directory of
		// downloads.cursor.com/lab/2026.08.31-4057e58/windows/x64/
		// agent-cli-package.zip: root entries are cursor-agent.cmd,
		// cursor-agent.ps1, node.exe, rg.exe, crepectl.exe,
		// cursorsandbox.exe — NO cursor-agent.exe exists, so the agent.exe
		// alias branch never fires. ARM64 zip not read (assumed identical).
		Binary: &BinaryResolveSpec{
			Names: BinaryNames{
				Unix:    []string{"cursor-agent", "agent"},
				Windows: []string{"cursor-agent.cmd", "agent.cmd"},
			},
			ProbeDirs: []ProbeDir{
				{OS: ProbeUnix, Rel: ".local/bin"},
				{OS: ProbeUnix, Rel: ".local/share/cursor-agent/versions/*"},
				{OS: ProbeWindows, Rel: "AppData/Local/cursor-agent"},
			},
			Installs: []InstallHint{
				{OS: "linux", Channel: "script", Argv: []string{"bash", "-lc", "curl https://cursor.com/install -fsS | bash"}, Display: "curl https://cursor.com/install -fsS | bash", Requires: []string{"curl", "tar"}},
				{OS: "darwin", Channel: "script", Argv: []string{"bash", "-lc", "curl https://cursor.com/install -fsS | bash"}, Display: "curl https://cursor.com/install -fsS | bash", Requires: []string{"curl", "tar"}},
				{OS: "windows", Channel: "script", Argv: []string{"powershell", "-Command", "irm 'https://cursor.com/install?win32=true' | iex"}, Display: "irm 'https://cursor.com/install?win32=true' | iex"},
			},
		},
		// Model picker (B5). Grounded live 2026-08-08: `cursor-agent --help`
		// lists `--model <model>  Model to use (e.g., gpt-5,
		// sonnet-4-thinking). Parameterized models accept quoted bracket
		// overrides, e.g. 'claude-opus-4-8[context=1m,effort=high,
		// fast=false]'`. The `observer cursor` launcher is
		// DisableFlagParsing + launcherArgsOrDone (B6), so a forwarded
		// `--model <value>` reaches the cursor-agent binary unmodified.
		Model: ModelSpec{Kind: ModelArg, Flag: "--model", Known: []string{"gpt-5", "sonnet-4-thinking"}},
		// Sandbox filesystem-isolation row (B9). Not grounded in v1 (plan
		// amendment A3) — only claude-code has a verified state-dir bind
		// list; every other launchable tool carries the honest zero note
		// until a per-tool probe grounds its StateRW/StateRO paths.
		Sandbox: SandboxSpec{Note: "state dirs not yet grounded - not sandbox-launchable"},
		// GUI launch row (plan §2.2). Cursor IS an IDE, so the spec rides
		// its own registry row rather than the guiHosts table.
		GUI: &GUILaunchSpec{
			ID:      "cursor-ide",
			Label:   "Cursor",
			Surface: "ide",
			Binary: BinaryResolveSpec{
				// The Electron exe, not the `resources\app\bin\cursor.cmd`
				// PATH shim (a .cmd would allocate a console). No collision
				// with this row's CLI Names above (`cursor-agent`/`agent`).
				Names: BinaryNames{
					Unix:    []string{"cursor"},
					Windows: []string{"Cursor.exe"},
				},
				ProbeDirs: []ProbeDir{
					{OS: ProbeWindows, Rel: "AppData/Local/Programs/cursor"},
				},
				Installs: []InstallHint{
					{OS: "windows", Channel: "winget", Argv: []string{"winget", "install", "--id", "Anysphere.Cursor", "-e", "--source", "winget"}, Display: "winget install --id Anysphere.Cursor -e --source winget"},
					{OS: "darwin", Channel: "brew", Argv: []string{"brew", "install", "--cask", "cursor"}, Display: "brew install --cask cursor"},
				},
				InstallNote: "no grounded Linux channel: Cursor ships an AppImage/deb download page, not a " +
					"scriptable one-liner (cursor.com/downloads).",
			},
			DarwinApp:      "Cursor",
			ProjectDirArgv: true,
			Wrap: WrapSpec{
				Kind: WrapNone,
				Reason: "the in-IDE agent's backend is hard-wired to Cursor's own service - no base-URL env " +
					"var exists. The one BYOK knob (\"OpenAI Base URL\") cannot point at a loopback proxy: " +
					"Cursor relays even BYOK requests through its own servers (cursor.com/docs/settings/api-keys), " +
					"which cannot reach 127.0.0.1, so this row's Routability is native_exempt (surface-gap IDE-4). " +
					"Launch yes, wrap no; capture rides the agent-transcripts + store.db watcher path.",
			},
			Hosts:    []string{"cursor"},
			Grounded: true,
			Note: "Windows layout grounded on this box 2026-09-03: " +
				"%LOCALAPPDATA%\\Programs\\cursor\\Cursor.exe (+ resources\\app\\bin\\{cursor,cursor.cmd}, which " +
				"grounds `cursor <dir>`). macOS bundle \"Cursor.app\" grounded from the Homebrew cask `cursor`; " +
				"winget id `Anysphere.Cursor` grounded from a live `winget search --exact` against the official " +
				"winget source the same day - the inventory rates Anysphere's vendor blessing of that package " +
				"LOW, so treat it as a grounded id, not a vendor-endorsed channel.",
		},
	},
	"cline": {
		Tool:       "cline",
		PromptLane: PromptLaneProbeRequired,
		Vocabulary: Vocabulary{InTaxonomy: true},
		// Cline itself is ACTIVE. The note records the DEAD product this
		// row also services: internal/adapter/cline watches Roo Code's
		// globalStorage ids alongside saoudrizwan.claude-dev
		// (roovscode.roo-cline, roovscode.roo-code,
		// rooveterinaryinc.roo-cline, rooveterinaryinc.roo-code,
		// rooveterinaryinc.roo-code-nightly — see roots.go
		// clineExtensions) and retags those rows Tool="roo-code" PER FILE
		// (adapter.go toolFromPath). Roo Code shut down 2026-04-21 and its
		// repo/extension were archived 2026-05-15; capture keeps running
		// (lifecycle never gates capture) but nothing is advertised for
		// it. There is NO roo-code registry row BY DESIGN — every cell
		// would be zero or copied from this one (IDE-20 /
		// registryRowlessTaxonomyTools); its lifecycle lives in
		// productLifecycles["roo-code"] instead.
		LifecycleNote: "also services the DEAD Roo Code retag identity: internal/adapter/cline watches the " +
			"roovscode.roo-cline / roovscode.roo-code / rooveterinaryinc.roo-cline / " +
			"rooveterinaryinc.roo-code / rooveterinaryinc.roo-code-nightly globalStorage ids and retags " +
			"those rows Tool=\"roo-code\" per file. No roo-code registry row exists by design (every cell " +
			"would be zero or copied) - see productLifecycles[\"roo-code\"] for that product's lifecycle. " +
			"Cline itself is active.",
		// VS Code extension → backend. Current builds (cline/cline main,
		// re-fetched 2026-10-25, surface-gap lane w2-d) resolve each
		// provider's base URL from ~/.cline/data/globalState.json
		// <provider>BaseUrl (CLINE_DATA_DIR > CLINE_DIR), which beats
		// providers.json (resolveBaseUrl). The 2026-06-27 grounding (VS Code
		// state.vscdb only, a manual paste) predates that store.
		// proxyroute.RegisterCline writes the active provider's member as a
		// probe writer (OpenAI Compatible and Anthropic only; a foreign
		// endpoint, an unroutable provider or split Act/Plan endpoints are
		// refused). The extension reads globalState.json once at start and
		// rewrites its whole copy on every state change, so the route applies
		// at its next start. Proxy stays nil and the row probe_required until a
		// live routed turn lands an api_turns row (IDE-8; the old
		// routable_now with no writer was an overclaim).
		Proxy: nil,
		ProxyProbe: &ProxyRoute{
			SharesCredentialFile: true, CredentialFileReason: routeCredCline,
			Kind:    RouteConfigFile,
			Setting: "openAiBaseUrl",
			Note:    "proxyroute.RegisterCline sets the active provider's base-URL member (openAiBaseUrl or anthropicBaseUrl) in ~/.cline/data/globalState.json (CLINE_DATA_DIR > CLINE_DIR); never a key; applies at the extension's next start; credential-adjacent file, probe-writer rules (D9)",
		},
		Routability: RouteStatusProbeRequired,
		// T-342 (2026-10-04): the ~/.cline/hooks tool-gate registration lives
		// on the cline-cli row (the CLI reads that directory, live); whether
		// this extension does is unconfirmed, so its bindings are vendor-only.
		Hook: HookSpec{Mechanism: HookNone, Bindings: hookBindingsCline},
		// Current Cline builds (the VS Code extension, the Cline CLI and Cline
		// for JetBrains) read ONE shared MCP file,
		// ~/.cline/data/settings/cline_mcp_settings.json, relocated by
		// CLINE_MCP_SETTINGS_PATH > CLINE_DATA_DIR > CLINE_DIR (agentconfig
		// cline/mcp-settings). The old VS Code globalStorage copy
		// (saoudrizwan.claude-dev/settings/cline_mcp_settings.json,
		// cline/mcp-settings-legacy) is migrated once and never re-read
		// (cline/cline main, 2026-10-25, lane w2-d). Observer writes the
		// shared file natively (locate "cline") and cross-OS into the Windows
		// home from a WSL daemon via the cline-windows wsl.exe bridge
		// (CrossOSBridge); unregister also removes an entry an older build
		// left in the legacy file. Standard {"mcpServers":{…}} shape.
		// Remote grounded 2026-09-24 against docs.cline.bot/mcp/configuring-
		// mcp-servers: `{"type":"streamableHttp"|"sse","url":…,"headers":{…},
		// "disabled":false,"autoApprove":[]}` — an OMITTED type defaults to
		// the legacy sse transport, so the writer always emits it. autoApprove
		// is left unset (its absence = no auto-approval, the safe default).
		// Same writer natively AND through the cline-windows bridge path.
		MCP: &MCPTarget{Format: MCPServersJSON, PathHint: ".cline/data/settings/cline_mcp_settings.json", Implemented: true, SharesCredentialFile: true, CredentialFileReason: mcpCredCline, CrossOSBridge: true, Remote: &MCPRemoteTarget{
			Transports:   []MCPRemoteTransport{MCPRemoteStreamableHTTP, MCPRemoteSSE},
			Headers:      true,
			TransportKey: "type",
			Spelling:     map[MCPRemoteTransport]string{MCPRemoteStreamableHTTP: "streamableHttp", MCPRemoteSSE: "sse"},
			Flags:        map[string]bool{"disabled": false},
			Implemented:  true,
			Note:         "docs.cline.bot 2026-09-24: type streamableHttp|sse (omitted = legacy sse) + url + headers + disabled; autoApprove left unset",
		}},
		Native:    NativeRails{},
		TokenTier: TokenTier{Best: "transcript"}, // per-message metrics + modelInfo; full.
		// P0.1 FULL: tasks/<id>/api_conversation_history.json, Anthropic-
		// shaped (reader = P2 tranche).
		Handoff: HandoffCapability{Transcript: TranscriptFull, Inject: []InjectKind{InjectFile, InjectMCP}},
		// Sandbox filesystem-isolation row (B9). Honest zero: the agent runs
		// inside its host IDE's process tree, which observer never spawns, so
		// there is no launch to wrap in a filesystem boundary.
		Sandbox: SandboxSpec{Note: "not sandbox-launchable: the agent runs inside its host IDE, which observer does not spawn"},
	},
	"copilot": {
		Tool:       "copilot",
		Vocabulary: Vocabulary{InTaxonomy: true},
		// VS Code extension → GitHub-hosted backend (native traffic exempt),
		// but VS Code's custom-endpoint / BYOK model support MAY route — probe
		// before flipping. Native hosted + inline completions stay exempt.
		Proxy:       nil,
		Routability: RouteStatusProbeRequired,
		Hook:        HookSpec{Mechanism: HookNone, Bindings: hookBindingsCopilot},
		MCP:         nil,
		Native:      NativeRails{A: true, B: true, C: true, Note: "rails partial; identity = GitHub login, cost seat/account-level"},
		TokenTier:   TokenTier{Best: "events_jsonl", Gap: "no cache tier", OutputOnlyShadow: true, GenerationTiming: GenTimingNative}, // legacy OTel llm_request span dur only
		// P0.1 PARTIAL: chatSessions/<id>.jsonl is a key-path PATCH LOG
		// (kind:0 init + kind:1/2 patches) — content present but needs a
		// replay reader (deferred tranche).
		Handoff: HandoffCapability{Transcript: TranscriptPartial, Inject: []InjectKind{InjectFile}, Note: "patch-log replay reader not built"},
		// Sandbox filesystem-isolation row (B9). Honest zero: the agent runs
		// inside its host IDE's process tree, which observer never spawns, so
		// there is no launch to wrap in a filesystem boundary.
		Sandbox: SandboxSpec{Note: "not sandbox-launchable: the agent runs inside its host IDE, which observer does not spawn"},
	},
	"copilot-cli": {
		Tool:       "copilot-cli",
		Vocabulary: Vocabulary{InTaxonomy: true},
		// Guard-fix lane B (live 2026-10-15, copilot 1.0.96): the
		// userPromptSubmitted COMMAND hook blocks ({handled:true,
		// responseContent} plus modifiedPrompt, zero model requests),
		// redacts (modifiedPrompt) and warns the model (additionalContext),
		// superseding FIX-7's reading of the docs ("cannot reject a
		// prompt"; "command hooks have their output dropped"). Observer
		// writes it beside preToolUse; the proxy lane still covers BYOK
		// sessions as well.
		PromptLane: PromptLaneHook,
		// BYOK path: COPILOT_PROVIDER_BASE_URL/_TYPE/_API_KEY + COPILOT_MODEL →
		// OpenAI-compatible endpoint (GitHub Docs); native GitHub-hosted
		// routing stays exempt.
		// LIVE-VERIFIED 2026-06-27: `observer copilot-cli` (launcher sets
		// COPILOT_PROVIDER_BASE_URL=<proxy>/v1 + _TYPE=openai) with the
		// operator's COPILOT_PROVIDER_API_KEY + --model gpt-4o routed a real
		// turn through the proxy (api_turns provider=openai, gpt-4o-2024-08-06)
		// AND was compressed (4 tools-trim compression_events). The launcher
		// NEVER sets the key — that's the operator's BYOK env. Proxy is the
		// launcher route (mirrors opencode); init does not auto-write it.
		// The BYOK lane is proven by the launcher because it injects the
		// provider TYPE alongside the base URL; the argv keys below are the
		// grounded ways an invocation can pick a different backend anyway.
		Proxy: &ProxyRoute{
			ClientAuth: ClientAuthPathToken,
			Kind:       RouteLauncher, EnvVar: "COPILOT_PROVIDER_BASE_URL", Suffix: "/v1",
			Launcher: "observer copilot-cli", Proof: RouteProofLauncherRoute,
			SelectorArguments: []string{
				"--provider-type", "--provider_type", "--provider-base-url",
				"--provider_base_url", "--backend", "--auth-type", "--auth_type",
			},
			// CONDITIONAL route (fix/copilot-cli-unrouted-launch, 2026-10-04).
			// Grounded against `copilot help providers` / `copilot help
			// environment` on Copilot CLI 1.0.91: COPILOT_PROVIDER_BASE_URL
			// alone switches Copilot into BYOK mode ("GitHub authentication is
			// not required"), so a GitHub-subscription session cannot ride a
			// custom base URL at all, and BYOK refuses to start without a model
			// ("A model is required for BYOK. Set COPILOT_MODEL,
			// COPILOT_PROVIDER_MODEL_ID, or --model."). Credential sources per
			// the same help: API_KEY, API_KEY_COMMAND, BEARER_TOKEN (the key is
			// optional only for local providers, which the proxy does not
			// front). Live 2026-10-04 on demo node 1: the ungated launcher made
			// a signed-in subscription user's Copilot exit with "BYOK providers
			// require an explicit model".
			//
			// Provider type (pass-2 review C156-19): the route is the proxy's
			// OpenAI-compatible endpoint (`<proxy>/v1`, COPILOT_PROVIDER_TYPE
			// set to openai by the launcher). A developer who chose another
			// type (anthropic, azure, ...) holds that provider's key, and
			// routing it would hand that key to the OpenAI lane, so such a
			// launch stays unrouted on the developer's own provider settings.
			Gate: &RouteGate{
				CredentialEnv:         []string{"COPILOT_PROVIDER_API_KEY", "COPILOT_PROVIDER_API_KEY_COMMAND", "COPILOT_PROVIDER_BEARER_TOKEN"},
				ModelEnv:              []string{"COPILOT_MODEL", "COPILOT_PROVIDER_MODEL_ID"},
				ModelArguments:        []string{"--model"},
				UnroutedBecause:       "Copilot is using your GitHub sign-in",
				ProviderTypeEnv:       "COPILOT_PROVIDER_TYPE",
				RoutableProviderTypes: []string{"openai"},
				ProviderTypeArguments: []string{"--provider-type", "--provider_type"},
			},
			PromptScope: "Only BYOK sessions (your own COPILOT_PROVIDER_API_KEY plus a model) go through the proxy; a session on your GitHub Copilot sign-in cannot be routed and launches unrouted, captured from Copilot's own session files.",
		},
		Routability: RouteStatusRoutableNow,
		// CrossOSBridge: true - internal/hook's copilot-cli-windows target
		// (live check 2026-10-20: a WSL daemon never wired the Windows
		// Copilot CLI, so its tool gate did not exist there).
		Hook:   HookSpec{Mechanism: HookCopilotCLIHooks, CrossOSBridge: true, AutoWired: true, Bindings: hookBindingsCopilotCLI},
		MCP:    nil,
		Native: NativeRails{}, // shares Copilot's GitHub governance but no separate node rail grounded.
		// Captures cache read + creation and nets input (log.go). Live
		// 2026-06-26 grounding: session.shutdown carries the FULL
		// session-aggregate input/cache/cost WITHOUT --log-level debug
		// (modelMetrics.<model>.usage); debug only adds PER-TURN input/cache
		// attribution (plain turns are output-only). The "no cache tier" the
		// audit attributed here was VS Code copilot's, not the CLI's.
		TokenTier: TokenTier{Best: "events_jsonl", Gap: "per-turn input/cache attribution needs --log-level debug (session-aggregate captured without it)", OutputOnlyShadow: true},
		// P0.1 FULL: ~/.copilot/session-store.db turns(user_message,
		// assistant_response) (reader = P2 tranche).
		Handoff: HandoffCapability{Transcript: TranscriptFull, Inject: []InjectKind{InjectFile, InjectPrompt}, Launch: &LaunchSpec{Subcommand: "copilot-cli"}},
		// Attach grounded 2026-07-24 (attach-all-launchers); PTY handoff only
		// — no prompt seeding, token capture path unchanged.
		Attach: &AttachSpec{Subcommand: "copilot-cli"},
		// Native resume GROUNDED, live-verified 2026-07-24: `copilot
		// --session-id <id>` reattaches the real session; id is a raw uuid. The
		// `observer copilot-cli` launcher maps `--resume <id>` to it.
		Resume: ResumeSpec{Kind: ResumeNative, Subcommand: "copilot-cli", IDMechanism: "flag:--session-id"},
		// Credential env forwarded across the attach socket. COPILOT_PROVIDER_API_KEY
		// is the BYOK model-provider key (repo-grounded in copilotcli.go — the
		// COPILOT_PROVIDER_* BYOK lane). The other three are the upstream-
		// documented GitHub-auth precedence chain (docs.github.com,
		// "Authenticating GitHub Copilot CLI"): COPILOT_GITHUB_TOKEN > GH_TOKEN
		// > GITHUB_TOKEN, and an env value silently overrides stored OAuth — so
		// forwarding the caller's value preserves the profile a bare launch
		// would use. NAMES only. The two BYOK alternates
		// (COPILOT_PROVIDER_API_KEY_COMMAND, COPILOT_PROVIDER_BEARER_TOKEN) are
		// grounded in `copilot help environment` (CLI 1.0.91).
		AuthEnv: []string{"COPILOT_PROVIDER_API_KEY", "COPILOT_PROVIDER_API_KEY_COMMAND", "COPILOT_PROVIDER_BEARER_TOKEN", "COPILOT_GITHUB_TOKEN", "GH_TOKEN", "GITHUB_TOKEN"},
		// Binary resolution + grounded installs. Unix launcher resolves
		// "copilot"; npm @github/copilot (any OS) + the cask/script/winget
		// channels (docs.github.com copilot-cli install).
		Binary: &BinaryResolveSpec{
			// npm JS launcher gives Windows a `.cmd` shim; the winget
			// portable install ALSO grounds a `.exe` alias
			// (NestedInstallerFiles: copilot.exe) in
			// %LOCALAPPDATA%\Microsoft\WinGet\Links — grounded 2026-09-02
			// against the winget manifest (GitHub.Copilot v1.0.82,
			// Commands: [copilot]).
			Names: BinaryNames{
				Unix:    []string{"copilot"},
				Windows: []string{"copilot.exe", "copilot.cmd", "copilot"},
			},
			Installs: []InstallHint{
				{OS: "", Channel: "npm", Argv: []string{"npm", "install", "-g", "@github/copilot"}, Display: "npm install -g @github/copilot"},
				{OS: "darwin", Channel: "brew", Argv: []string{"brew", "install", "--cask", "copilot-cli"}, Display: "brew install --cask copilot-cli"},
				{OS: "linux", Channel: "brew", Argv: []string{"brew", "install", "--cask", "copilot-cli"}, Display: "brew install --cask copilot-cli"},
				{OS: "linux", Channel: "script", Argv: []string{"bash", "-lc", "curl -fsSL https://gh.io/copilot-install | bash"}, Display: "curl -fsSL https://gh.io/copilot-install | bash", Requires: []string{"curl", "tar"}},
				{OS: "darwin", Channel: "script", Argv: []string{"bash", "-lc", "curl -fsSL https://gh.io/copilot-install | bash"}, Display: "curl -fsSL https://gh.io/copilot-install | bash", Requires: []string{"curl", "tar"}},
				{OS: "windows", Channel: "winget", Argv: []string{"winget", "install", "GitHub.Copilot"}, Display: "winget install GitHub.Copilot"},
			},
		},
		// Model picker (B5). The `observer copilot-cli` launcher OWNS its
		// own `--model` cobra flag (cmd/observer/copilotcli.go) and
		// translates it to COPILOT_MODEL in the child env — it is NOT
		// forwarded verbatim to the wrapped `copilot` binary's own `--model`
		// flag. `copilot help environment` (CLI 1.0.91) documents
		// COPILOT_MODEL as the general agent model ("Can be overridden by the
		// --model command line option"), so it selects a GitHub-hosted model
		// on an unrouted subscription launch and the BYOK wire model on a
		// routed one. ModelArg is still the correct delivery shape from the
		// dashboard's perspective: the picker appends `--model <value>` to
		// the launcher's argv, to a flag the launcher itself consumes. Known
		// left empty: the valid values differ by lane (GitHub-hosted catalog
		// vs the BYOK provider's own), so no example is fabricated here.
		Model: ModelSpec{Kind: ModelArg, Flag: "--model"},
		// Sandbox filesystem-isolation row (B9). GROUNDED against
		// internal/adapter/copilotcli/paths.go candidateRoots (<home>/.copilot/
		// session-state and <home>/.copilot/logs). ~/.copilot is the CLI's whole
		// state dir and is bound rw as one dir; it holds this tool's own GitHub
		// auth state.
		// macOS (live user install 2026-10-29, D-MU6): the CLI also writes
		// ~/Library/Caches/copilot and failed under Seatbelt without it.
		Sandbox: SandboxSpec{ProviderEnv: []string{"COPILOT_PROVIDER_API_KEY", "COPILOT_PROVIDER_API_KEY_COMMAND", "COPILOT_PROVIDER_BEARER_TOKEN", "COPILOT_GITHUB_TOKEN", "GH_TOKEN", "GITHUB_TOKEN"}, StateRW: []string{".copilot"}, StateRWByOS: map[string][]string{"darwin": {"Library/Caches/copilot"}}},
	},
	"kilo-code": {
		Tool:       "kilo-code",
		Vocabulary: Vocabulary{InTaxonomy: true},
		// Legacy IDE extension (Kilo Code < 7, wraps cline). Its "OpenAI
		// Compatible" base URL lives in live VS Code globalState
		// (state.vscdb), which Observer never writes, and the manual-paste
		// hint it once cited (proxyroute.VSCodeBaseURLHint) has no caller
		// (gap review IDE-8). Kilo Code 7.x is a different product shape: it
		// embeds the Kilo runtime, shares ~/.config/kilo/kilo.jsonc with the
		// CLI and Kilo Code for JetBrains v7, and its sessions land in
		// kilo.db, so they belong to the kilo-code-cli row (gap review IDE-9,
		// inventory 2026-10-25 section 2.4). So this row describes only the
		// legacy extension, and its route claim is probe_required, not
		// routable_now: a knob exists, no writer reaches it and no routed
		// turn was ever seen. Whether 7.x loads the global plugin shim is
		// live check LC16.
		Proxy:       nil,
		Routability: RouteStatusProbeRequired,
		Hook:        HookSpec{Mechanism: HookNone, Bindings: kiloBindings(false)},
		MCP:         nil,
		Native:      NativeRails{},
		TokenTier:   TokenTier{Best: "sqlite"}, // inherits cline's full per-message capture.
		// Handoff zero value: no kilo-code (legacy) sessions on this node
		// during Phase 0 — expected FULL via the cline task-dir format, but
		// unmeasured, so the row stays the honest actions-only floor until
		// live data grounds it.
		Handoff: HandoffCapability{},
		// Sandbox filesystem-isolation row (B9). Honest zero: the agent runs
		// inside its host IDE's process tree, which observer never spawns, so
		// there is no launch to wrap in a filesystem boundary.
		Sandbox: SandboxSpec{Note: "not sandbox-launchable: the agent runs inside its host IDE, which observer does not spawn"},
	},
	"kilo-code-cli": {
		Tool:       "kilo-code-cli",
		Vocabulary: Vocabulary{InTaxonomy: true},
		// probe_required (gap review CLI-9, surface-gap lane w8-registry,
		// 2026-10-28). The live 2026-06-26 finding stands for the env: the
		// CLI reads no base-URL variable and talks to the api.kilo.ai gateway
		// by default (docs/kilo-code-adapter.md). But Kilo now documents a
		// custom OpenAI-compatible provider, provider.<id>.options.baseURL in
		// kilo.jsonc (Kilo-Org/kilocode packages/kilo-docs/pages/ai-providers/
		// openai-compatible.md, re-fetched 2026-10-25, inventory X8), and the
		// generated catalogue carries that key, so native_exempt was stale.
		// No writer exists and no routed turn was seen: whether a request
		// through that provider reaches the proxy is live check LC24. The
		// same kilo.jsonc is read by Kilo Code 7.x for VS Code and Kilo Code
		// for JetBrains v7 (IDE-9); routeSurfaces carries that IDE row.
		Proxy:       nil,
		Routability: RouteStatusProbeRequired,
		Hook:        HookSpec{Mechanism: HookPluginShimTS, AutoWired: true, Bindings: kiloBindings(true)}, // plugin shim (Lane D)
		MCP:         nil,
		Native:      NativeRails{},
		// Per-message tokens NET (Anthropic-shape, verified). kilo-auto/* has
		// explicit pricing aliases; stealth/* gateway models price via the
		// cost engine's provider-segment strip (stealth/claude-sonnet-4.6 →
		// claude-sonnet-4.6). cachetrack shape rule now covers stealth/claude
		// explicitly (Anthropic-shape) alongside kilo-auto.
		TokenTier: TokenTier{Best: "sqlite", ReportsCost: true},
		// P0.1 FULL: kilo.db message+part tables (reader = P2 tranche).
		Handoff: HandoffCapability{Transcript: TranscriptFull, Inject: []InjectKind{InjectFile, InjectPrompt}, Launch: &LaunchSpec{Subcommand: "kilo"}},
		// Attach grounded 2026-07-24 (attach-all-launchers); PTY handoff only
		// — no prompt seeding, token capture path unchanged.
		Attach: &AttachSpec{Subcommand: "kilo"},
		// Native resume GROUNDED, live-verified 2026-07-24: `kilo --session <id>`
		// (OpenCode-fork surface) reattaches the real session; id is raw. The
		// `observer kilo` launcher maps `--resume <id>` to it.
		Resume: ResumeSpec{Kind: ResumeNative, Subcommand: "kilo", IDMechanism: "flag:--session"},
		// AuthEnv zero: KILO_API_KEY appears in Kilo docs, but the CLI's
		// env-read of it is ungrounded (it talks to the api.kilo.ai gateway
		// directly); no key declared until a live read is grounded.
		// Binary resolution + grounded installs. Unix launcher resolves
		// "kilo"; npm @kilocode/cli (any OS) + the script/brew channels
		// (kilo.ai/docs/cli). Windows shim grounded at
		// %APPDATA%\npm\kilo.cmd (docs/kilo-code-adapter.md).
		Binary: &BinaryResolveSpec{
			// npm JS bin: Windows install lays down a `.cmd` shim (+
			// .ps1/POSIX-shell forms), never an `.exe` — see the
			// command-code row's Binary comment for the long-form
			// rationale. `kilocode` is a second real bin key for the SAME
			// binary (npm scratch-install bin map: {kilo: ./bin/kilo,
			// kilocode: ./bin/kilo}, grounded 2026-09-02).
			Names: BinaryNames{
				Unix:    []string{"kilo", "kilocode"},
				Windows: []string{"kilo.cmd", "kilo", "kilocode.cmd", "kilocode"},
			},
			// grounded 2026-09-02: the vendor's script channel (Git-Bash
			// runnable, MINGW*/MSYS*/CYGWIN* branch) installs into
			// $HOME/.kilo/bin on both OSes.
			ProbeDirs: []ProbeDir{
				{OS: ProbeUnix, Rel: ".kilo/bin"},
				{OS: ProbeWindows, Rel: ".kilo/bin"},
			},
			Installs: []InstallHint{
				{OS: "", Channel: "npm", Argv: []string{"npm", "install", "-g", "@kilocode/cli"}, Display: "npm install -g @kilocode/cli"},
				{OS: "linux", Channel: "script", Argv: []string{"bash", "-lc", "curl -fsSL https://kilo.ai/cli/install | bash"}, Display: "curl -fsSL https://kilo.ai/cli/install | bash", Requires: []string{"curl", "tar"}},
				{OS: "darwin", Channel: "script", Argv: []string{"bash", "-lc", "curl -fsSL https://kilo.ai/cli/install | bash"}, Display: "curl -fsSL https://kilo.ai/cli/install | bash", Requires: []string{"curl", "unzip"}},
				{OS: "darwin", Channel: "brew", Argv: []string{"brew", "install", "Kilo-Org/tap/kilo"}, Display: "brew install Kilo-Org/tap/kilo"},
			},
		},
		// Sandbox filesystem-isolation row (B9). GROUNDED against
		// internal/adapter/kilocode/adapter.go defaultCLIRoots
		// (<home>/.local/share/kilo — the same XDG layout on Linux, macOS and
		// Windows) plus the config dir the plugin install uses
		// (~/.config/kilo/kilo.jsonc, docs/plans/kilocode-adapter-plan-2026-06-06.md
		// §"Where does it persist session data?"). Both bound rw.
		Sandbox: SandboxSpec{
			StateRW: []string{".local/share/kilo", ".config/kilo"},
		},
	},

	// CLI adapters captured via watcher/SQLite (+ opt-in receivers).
	"cline-cli": {
		Tool:       "cline-cli",
		Vocabulary: Vocabulary{InTaxonomy: true},
		// Guard-fix lane B (live 2026-10-15, cline 3.0.68): the file
		// UserPromptSubmit hook is detached and never fired for the
		// initial prompt, but the Cline Plugin API's beforeModel is awaited
		// before every model call and can stop the turn or rewrite the
		// messages. Observer's plugin (internal/hook/pluginshim "cline"
		// shape) is that prompt gate: block and redact, no developer-visible
		// warning or resend message (a stop reason is shown nowhere).
		PromptLane: PromptLaneHook,
		// ROUTABLE via the openai-compatible provider's persisted baseUrl —
		// VERIFIED LIVE 2026-06-27. The NATIVE `openai` provider hardcodes
		// api.openai.com and ignores OPENAI_BASE_URL (confirmed: `-P openai -k …`
		// succeeded but bypassed the proxy), so the old env launcher was inert.
		// But cline's `openai-compatible` provider reads an explicit
		// `settings.baseUrl` from ~/.cline/data/settings/providers.json (cline
		// auth `-b/--baseurl`). The `observer cline-cli` launcher now writes that
		// baseUrl → the proxy (preserving the api key, NEVER writing one) and
		// execs `cline -P openai-compatible`. A live turn landed a real api_turn
		// (provider=openai, gpt-4o-2024-08-06, HTTP 200). RouteProviderJSON; the
		// operator supplies the key once via `cline auth openai-compatible -k …`.
		// (docs/proxy-routing-blockers.md)
		// T-208: the launcher selects that provider with `-P` and re-reads
		// its persisted baseUrl right before cline starts, so applying the
		// route settles the invocation's backend (RouteProofLauncherRoute);
		// a forwarded `-P` / `--provider` of the operator's own takes the
		// proof away for that invocation.
		Proxy: &ProxyRoute{
			ClientAuth:           ClientAuthPathToken,
			SharesCredentialFile: true, CredentialFileReason: routeCredClineCLI,
			Kind: RouteProviderJSON, EnvVar: "", Suffix: "/v1", Launcher: "observer cline-cli",
			Note:              "routes via the openai-compatible provider's settings.baseUrl in ~/.cline/data/settings/providers.json; launcher writes baseUrl, never a key",
			Proof:             RouteProofLauncherRoute,
			SelectorArguments: []string{"-P"},
		},
		Routability: RouteStatusRoutableNow,
		// Guard-fix lane B (2026-10-15): Observer writes the guard PLUGIN
		// ($CLINE_DIR/plugins/superbased-observer-guard.js: beforeModel
		// prompt gate + beforeTool per-call gate) and replaces the T-342
		// ~/.cline/hooks/PreToolUse gate script with a no-op keep-alive; the
		// lifecycle and tool-result bindings stay the hooks.jsonl tailer
		// (clinecli/hook.go), which a hook file in that directory keeps on.
		Hook: HookSpec{Mechanism: HookClineHookFiles, AutoWired: true, Bindings: hookBindingsClineCLI},
		// MCP: nil means "served by the cline row's writer", not "not
		// capable". The Cline CLI reads the same shared
		// ~/.cline/data/settings/cline_mcp_settings.json the cline row's
		// MCPTarget writes (cline/cline main, 2026-10-25, lane w2-d), so one
		// writer fills it for every Cline client; a second target here would
		// be a second writer of one file (CLAUDE.md #4). `cline mcp
		// install|add` is the vendor's own command path.
		MCP:       nil,
		Native:    NativeRails{},
		TokenTier: TokenTier{Best: "sqlite", ReportsCost: true}, // sessions.db + per-session messages.json; full.
		// P0.1 FULL: <id>.messages.json, Anthropic-shaped (reader = P2
		// tranche).
		Handoff: HandoffCapability{Transcript: TranscriptFull, Inject: []InjectKind{InjectFile, InjectPrompt}, Launch: &LaunchSpec{Subcommand: "cline-cli"}},
		// Attach grounded 2026-07-24 (attach-all-launchers); PTY handoff only
		// — no prompt seeding, token capture path unchanged.
		Attach: &AttachSpec{Subcommand: "cline-cli"},
		// Native resume GROUNDED, live-verified 2026-07-24: `cline --id <id>`
		// reattaches the real session; id is raw (e.g. `1782548283719_prf8j`).
		// The `observer cline-cli` launcher maps `--resume <id>` to it.
		Resume: ResumeSpec{Kind: ResumeNative, Subcommand: "cline-cli", IDMechanism: "flag:--id"},
		// GUI launch row: the standalone Cline DESKTOP app (Electron IDE,
		// grounded on this box 2026-09-20). DISTINCT from the cline-cli
		// terminal (this row's adapter) and the `cline` VS Code extension:
		// it is a plain UNPACKAGED exe at %LOCALAPPDATA%\Cline\cline-app.exe
		// (Electron GUI + a code-sidecar.exe backend + a Cline.lnk Start
		// Menu shortcut) — NOT a packaged MSIX/AUMID app. It writes the
		// SAME ~/.cline/data sessions.db with source='desktop', which the
		// clinecli adapter already stamps surface=desktop /
		// surface_host=cline-desktop (internal/adapter/clinecli/surface.go)
		// — capture is free; this row is launch-only. It rides cline-cli's
		// lifecycle and its sessions (Hosts=["cline-cli"]).
		GUI: &GUILaunchSpec{
			ID:      "cline-desktop",
			Label:   "Cline",
			Surface: "desktop",
			Binary: BinaryResolveSpec{
				// Plain Electron exe; no collision with this row's CLI Names
				// above (`cline`/`cline.cmd`), but ProbeOnly below resolves it
				// through the install dir only (factory-desktop precedent).
				Names: BinaryNames{
					Windows: []string{"cline-app.exe"},
				},
				ProbeDirs: []ProbeDir{
					{OS: ProbeWindows, Rel: "AppData/Local/Cline"},
				},
				// Conservative InstallNote (no invented URL): the standalone
				// desktop download channel is not grounded from a repo doc or
				// an existing row, so name the app without guessing a URL
				// (honesty rule; required because this grounded row ships no
				// Installs — TestGUIInstallHintsUseClosedVocabulary).
				InstallNote: "no grounded install channel: the standalone Cline desktop app has no verified " +
					"winget/brew id and no repo-grounded download URL, so no install command is offered; once " +
					"installed it launches from %LOCALAPPDATA%\\Cline\\cline-app.exe.",
			},
			// PATH walk disabled: resolve through the ProbeDirs only, the
			// desktop convention here (factory-desktop / zcode-desktop).
			ProbeOnly:      true,
			ProjectDirArgv: false,
			Wrap: WrapSpec{
				Kind: WrapNone,
				Reason: "the standalone desktop app routes through Cline's OWN hosted gateway (the cline-free " +
					"provider), not the openai-compatible baseUrl in ~/.cline/data/settings/providers.json that " +
					"the `observer cline-cli` launcher rewrites; a detached GUI launch cannot re-point that " +
					"account/gateway selection, so there is nothing to inject. Launch yes, wrap no.",
			},
			Hosts:    []string{"cline-cli"},
			Grounded: true,
			// Windows-only: the exe spelling was grounded live on this Windows
			// box 2026-09-20. No macOS .app bundle name or Linux path is
			// grounded, so DarwinApp is left empty and no Unix spelling is
			// fabricated (factory-desktop precedent — a desktop app is not
			// required to ship everywhere).
			Note: "Windows layout grounded on this box 2026-09-20: %LOCALAPPDATA%\\Cline\\cline-app.exe " +
				"(Electron GUI) alongside a code-sidecar.exe backend and a Cline.lnk shortcut. macOS/Linux " +
				"spellings NOT grounded - Windows-only for now. Sessions land in ~/.cline/data with " +
				"source='desktop', captured by the clinecli adapter (surface_host=cline-desktop).",
		},
		// AuthEnv zero: cline-cli reads provider keys from its providers.json
		// file store (`cline auth … -k`), not an env var — file auth, no
		// grounded credential-env to forward.
		// Binary resolution + grounded install. Unix launcher resolves
		// "cline"; npm-distributed `cline` 3.x (docs/clinecli-adapter.md).
		Binary: &BinaryResolveSpec{
			// npm JS bin: Windows install lays down a `.cmd` shim (+
			// .ps1/POSIX-shell forms), never an `.exe` — see the
			// command-code row's Binary comment for the long-form
			// rationale.
			Names: BinaryNames{
				Unix:    []string{"cline"},
				Windows: []string{"cline.cmd", "cline"},
			},
			Installs: []InstallHint{
				{OS: "", Channel: "npm", Argv: []string{"npm", "install", "-g", "cline"}, Display: "npm install -g cline"},
			},
		},
		// Model picker (B5). Grounded live 2026-08-08: `cline --help` lists
		// `-m, --model <model-id>  Model to use for the session with the
		// selected provider`. The `observer cline-cli` launcher is
		// DisableFlagParsing + launcherArgsOrDone (B6), so a forwarded
		// `--model <value>` reaches the cline binary unmodified.
		Model: ModelSpec{Kind: ModelArg, Flag: "--model"},
		// Sandbox filesystem-isolation row (B9). GROUNDED against
		// internal/adapter/clinecli/roots.go defaultRoots (<home>/.cline, or
		// $CLINE_DIR). ~/.cline holds data/db/sessions.db, the per-session
		// transcripts and providers.json/secrets.json — bound rw as one dir,
		// because the tool needs its own provider credentials to run.
		Sandbox: SandboxSpec{StateRW: []string{".cline"}},
	},
	"hermes": {
		Tool:       "hermes",
		Vocabulary: Vocabulary{InTaxonomy: true},
		// FIX-7 (phase-2 review): Hermes' pre_llm_call hook is
		// injection-only per the vendor's own docs ("the clean
		// user-message content remains unchanged", contract §2.3) —
		// it has a prompt-submit event but genuinely CANNOT block or
		// redact. The proxy lane (already routed today) is Hermes'
		// only realistic path to prompt-submit intervention.
		PromptLane: PromptLaneProxyOnly,
		// Proxy BLOCKED at the proxy-upstream layer, not a writer gap (live-
		// grounded 2026-06-26). Hermes' only base-URL knob is model.base_url
		// in ~/.hermes/config.yaml, live-set to https://openrouter.ai/api/v1
		// (OpenAI-shaped via OpenRouter). The observer proxy forwards ALL
		// OpenAI-shaped traffic to a single fixed upstream (proxy.go
		// upstreamForPath → openaiURL, default api.openai.com) with no
		// OpenRouter target and no per-request upstream selection. Pointing
		// hermes at the proxy would misroute its OpenRouter-bound traffic to
		// api.openai.com (wrong host/key/models) and break the session. The
		// YAML writer is trivial; making hermes routable needs proxy
		// per-provider upstream routing (a hot-path change), so this stays
		// nil until that lands. (docs/hermes-adapter.md)
		//
		// UPDATE — Phase C shipped + LIVE-VERIFIED 2026-06-27: the /up/<id>
		// seam + [proxy.upstreams] openrouter route hermes' OpenRouter traffic;
		// the since-deleted proxyroute.RegisterHermes (superseded by Approach
		// B below) rewrote model.base_url →
		// http://127.0.0.1:<port>/up/openrouter/api/v1. A live `hermes -z` turn
		// routed to OpenRouter (confirmed via OpenRouter-specific responses)
		// and landed an api_turns row as provider=openai with the OpenRouter
		// model name (tokens were 0 only because the free tier was rate-limited
		// — error responses carry no usage; the parse path is covered by the
		// proxy e2e test).
		// ROUTING MECHANISM VERIFIED LIVE 2026-06-27. hermes' NAMED providers
		// (openrouter, nous) hardcode their endpoint via `base_url = base_url or
		// CONST` and IGNORE model.base_url — so `-z`/`chat` under provider:
		// openrouter bypass the proxy. BUT the built-in `custom` provider DOES
		// honor model.base_url (loopback-trusted). Setting model.provider: custom
		// + model.base_url: <proxy>/up/openrouter/api/v1 + an OpenRouter key
		// routed a live `hermes chat` turn through the proxy (api_turn
		// provider=openai, nvidia/nemotron-…:free, HTTP 200).
		// SECRET-FREE AUTO-WRITER SHIPPED + LIVE-VERIFIED 2026-06-27 (Approach
		// B): hermes' top-level `--provider` flag accepts a name from the
		// config's `providers:` section, and a user-config provider entry
		// resolves its key via `key_env` (the env var NAME — providers.py
		// resolve_user_provider). The `observer hermes` launcher
		// (cmd/observer/hermes.go) ADDITIVELY writes a `providers.observer`
		// entry {base_url: <proxy>/up/<upstream>/api/v1, key_env:
		// OPENROUTER_API_KEY, transport: openai_chat} — touching ONLY that
		// entry, so the operator's top-level model block is preserved — then
		// execs `hermes --provider observer`. NEVER writes a key (key_env is
		// the env-var name; the operator exports the credential). Two live
		// turns confirmed it: the key_env config probe AND the launcher's own
		// write each landed an api_turns row (provider=openai,
		// nvidia/nemotron-…:free, ~16.7k input). RouteProviderJSON; init does
		// NOT auto-write it (the launcher does), and routing needs a matching
		// [proxy.upstreams] entry (default `openrouter`). NB: hermes'
		// auxiliary/moa providers (provider: auto) make separate calls that
		// don't follow the override. (docs/proxy-routing-blockers.md)
		// The openrouter lane is the live-verified host root above
		// (docs/proxy-routing.md, docs/hermes-adapter.md); built in so the
		// default --upstream resolves without a [proxy.upstreams] entry.
		Proxy: &ProxyRoute{ClientAuth: ClientAuthPathToken, Kind: RouteProviderJSON, EnvVar: "", Suffix: "/up/openrouter/api/v1", Launcher: "observer hermes", Note: "routes via a user-config `observer` provider (providers: section) in ~/.hermes/config.yaml with key_env (secret-free); launcher writes the provider additively, never a key; the default openrouter lane is built in (a [proxy.upstreams] openrouter entry overrides it); another --upstream needs its own [proxy.upstreams] entry", Lane: &ProxyLane{ID: "openrouter", DefaultUpstream: "https://openrouter.ai"}, SharesCredentialFile: true, CredentialFileReason: routeCredHermes, PersistedDefault: &PersistedDefault{
			Note:     "CLI-1a: proxyroute.RegisterDefaultProvider(hermes) sets model.provider = observer in ~/.hermes/config.yaml once the launcher's providers.observer entry is there, so a bare hermes routes; YAML member edit, never a key",
			LiveGate: "LC25",
		}},
		Routability: RouteStatusRoutableNow,
		Hook:        HookSpec{Mechanism: HookHermesPlugin, AutoWired: true, Bindings: hookBindingsHermes, HooksShareCredentialFile: true, CredentialFileReason: credFileHermes}, // embedded plugin via `observer init --hermes`.
		// Remote grounded 2026-09-24 against hermes-agent.nousresearch.com/
		// docs/user-guide/features/mcp: `mcp_servers.<name>: {url: …,
		// headers: {…}}` (transport inferred; `auth: oauth` optional). The
		// stdio target above is Implemented because internal/hook's
		// RegisterHermesMCP (`observer init --hermes`) writes it — but that
		// writer has NO remote variant and internal/mcp/locate carries no
		// hermes row, so the Registrar cannot project a remote entry today:
		// Remote.Implemented=false (honest zero, doc3 §12.1 R8.24.u — doc3
		// does NOT claim hermes remote projection until a locate row + a
		// YAML remote writer land).
		MCP: &MCPTarget{Format: MCPHermesYAML, PathHint: ".hermes/config.yaml", Implemented: true, SharesCredentialFile: true, CredentialFileReason: mcpCredHermes, Remote: &MCPRemoteTarget{
			Transports:  []MCPRemoteTransport{MCPRemoteStreamableHTTP, MCPRemoteSSE},
			Headers:     true,
			Implemented: false,
			Note:        "hermes docs 2026-09-24: url + headers (transport inferred); NO writer - internal/hook's YAML writer is stdio-only and locate has no hermes row",
		}},
		Native:    NativeRails{},
		TokenTier: TokenTier{Best: "sqlite", GenerationTiming: GenTimingNative, ReportsCost: true}, // post_api_request token rows; full. api_duration (float s) -> gen_ms.
		// P0.1 FULL: state.db messages(role, content, tool_calls) active=1
		// (reader = P2 tranche).
		// No InjectPrompt lane: hermes' TUI (`--tui` / HERMES_TUI=1) takes NO
		// initial-message flag (its only prompt entry points — `-z/--oneshot`,
		// `chat -q` — are headless one-shots that answer and exit; upstream
		// gap, NousResearch/hermes-agent Issue #19675). So it is launchable
		// only in DocAssisted mode: write the doc + open `hermes --tui`.
		Handoff: HandoffCapability{Transcript: TranscriptFull, Inject: []InjectKind{InjectFile, InjectMCP}, Launch: &LaunchSpec{Subcommand: "hermes", Mode: LaunchDocAssisted}, Note: "TUI has no initial-prompt seed (upstream gap); launch writes the handover doc + opens hermes --tui"},
		// Attach grounded 2026-07-24 (attach-all-launchers); PTY handoff only
		// — no prompt seeding, token capture path unchanged. DocAssisted only
		// gates --continue-from seeding (incompatible with attach); plain attach
		// opens the TUI seedless.
		Attach: &AttachSpec{Subcommand: "hermes"},
		// Native resume GROUNDED, live-verified 2026-07-24: `hermes --resume
		// <id>` reattaches the real session; id is raw (`20260627_132748_325fea`
		// shape). Composes with the config.yaml provider route (the launcher
		// prepends `--provider observer`). The `observer hermes` launcher maps
		// `--resume <id>` to it.
		Resume: ResumeSpec{Kind: ResumeNative, Subcommand: "hermes", IDMechanism: "flag:--resume"},
		// Credential env forwarded across the attach socket. Grounded:
		// hermes.go hermesDefaultKeyEnv (OPENROUTER_API_KEY) — the default
		// key_env the observer provider resolves at runtime. A NON-default
		// `--key-env NAME` is dynamic and handled at the launcher call site
		// (hermes.go sets authEnvExtra to that NAME); the registry row carries
		// only the static default.
		AuthEnv: []string{"OPENROUTER_API_KEY"},
		// Binary resolution + grounded install. Unix launcher resolves
		// "hermes"; its bundled node prefix (.hermes/node/bin) + .hermes/bin
		// are per-tool extras (the off-PATH hermes-bundled npm prefix from
		// the opencode-WSL incident). Official install script
		// (github.com/NousResearch/hermes-agent README; no official pip
		// path). Windows hint is EXECUTABLE by a native-Windows daemon
		// (ConPTY, since 2026-07-04); post-install detection needs
		// Names.Windows (grounded 2026-09-02).
		//
		// Windows spellings GROUNDED 2026-09-02 by reading the installer
		// (`$HermesHome = $env:LOCALAPPDATA\hermes`,
		// Install-HermesCommandLaunchers emits ONE of hermes.exe/hermes.cmd
		// per install depending on whether the uv venv is relocatable) and
		// `where.exe hermes` on this box, which resolved to the legacy
		// venv\Scripts layout.
		Binary: &BinaryResolveSpec{
			Names: BinaryNames{
				Unix:    []string{"hermes"},
				Windows: []string{"hermes.exe", "hermes.cmd"},
			},
			ProbeDirs: []ProbeDir{
				{OS: ProbeUnix, Rel: ".hermes/bin"},
				{OS: ProbeUnix, Rel: ".hermes/node/bin"},
				{OS: ProbeUnix, Rel: ".local/bin"},
				{OS: ProbeWindows, Rel: "AppData/Local/hermes/bin"},
				// Legacy layout — what this box has (live `where.exe hermes`
				// grounding); the installer actively removes these from PATH
				// on newer installs but the dir can still be resolved off-PATH.
				{OS: ProbeWindows, Rel: "AppData/Local/hermes/hermes-agent/venv/Scripts"},
			},
			Installs: []InstallHint{
				// T-034j (2026-10-07, script re-read): both installers end in
				// `hermes setup` (a wizard) and `hermes gateway install`,
				// which read /dev/tty / the console, so the guided install
				// sat in the wizard. --non-interactive / -NonInteractive skip
				// both stages (and the libatomic sudo cache). install.ps1 has
				// no env alternative, so it runs through the vendor's
				// documented scriptblock form, which accepts the switch.
				{OS: "linux", Channel: "script", Argv: []string{"bash", "-lc", "curl -fsSL https://hermes-agent.nousresearch.com/install.sh | bash -s -- --non-interactive"}, Display: "curl -fsSL https://hermes-agent.nousresearch.com/install.sh | bash -s -- --non-interactive", Requires: []string{"curl", "git"}},
				{OS: "darwin", Channel: "script", Argv: []string{"bash", "-lc", "curl -fsSL https://hermes-agent.nousresearch.com/install.sh | bash -s -- --non-interactive"}, Display: "curl -fsSL https://hermes-agent.nousresearch.com/install.sh | bash -s -- --non-interactive", Requires: []string{"curl", "git"}},
				{OS: "windows", Channel: "script", Argv: []string{"powershell", "-Command", "& ([scriptblock]::Create((irm https://hermes-agent.nousresearch.com/install.ps1))) -NonInteractive"}, Display: "& ([scriptblock]::Create((irm https://hermes-agent.nousresearch.com/install.ps1))) -NonInteractive"},
			},
		},
		// Model picker (B5). Grounded live 2026-08-08: `hermes --help` lists
		// `-m MODEL, --model MODEL  Model override for this invocation (e.g.
		// anthropic/claude-sonnet-4.6) … Also settable via
		// HERMES_INFERENCE_MODEL env var`. VERIFIED against
		// cmd/observer/hermes.go's own OpenRouter-routing table
		// (hermesRouteRules, "model-supplied" row): when
		// hermesHasModelArg(scanArgs) is true — i.e. the caller supplied a
		// non-blank `--model`/`-m` — the launcher injects `--provider
		// observer` ALONGSIDE it and leaves the caller's model flag
		// untouched; it never rewrites or drops it. So a dashboard-supplied
		// `--model <value>` is RESPECTED, not clobbered (no conflict to flag).
		Model: ModelSpec{Kind: ModelArg, Flag: "--model", Known: []string{"anthropic/claude-sonnet-4.6"}},
		// Sandbox filesystem-isolation row (B9). GROUNDED against
		// internal/adapter/hermes/roots.go defaultRoots (<home>/.hermes on
		// linux+darwin, or $HERMES_HOME). ~/.hermes holds the schema-v14 SQLite
		// store and the OpenRouter credentials the agent needs — bound rw as one
		// dir.
		// plugins/ is auto-discovered Python (internal/hook/hermesplugin).
		Sandbox: SandboxSpec{ProviderEnv: []string{"OPENROUTER_API_KEY"}, StateRW: []string{".hermes"}, ProtectRODirs: []string{".hermes/plugins"}},
		// GUI launch row (plan §2.2): Hermes Desktop shares ~/.hermes with
		// this row's CLI ("one agent, one memory, every surface"). UNVERIFIED
		// layout ⇒ Grounded=false, empty Binary, never launchable.
		GUI: &GUILaunchSpec{
			ID:             "hermes-desktop",
			Label:          "Hermes Desktop",
			Surface:        "desktop",
			ProjectDirArgv: false,
			Wrap: WrapSpec{
				Kind:       WrapConfigWrite,
				ConfigTool: "hermes",
				Reason: "Hermes reads its base URL from a persisted config file, never the environment: " +
					"this row's verified Proxy above routes via a user-config `observer` provider in " +
					"~/.hermes/config.yaml (written additively by the `observer hermes` launcher, never a " +
					"key), and Desktop shares that same ~/.hermes. So a route already applied to the CLI " +
					"applies to Desktop too - the GUI launch itself writes nothing and records " +
					"wrap_applied=false naming that writer. Carry the CLI's known bug forward: an " +
					"OpenRouter-catalog-matching model name can silently override an explicit custom " +
					"base_url (upstream #39753).",
			},
			Hosts:    []string{"hermes"},
			Grounded: false,
			Note: "UNVERIFIED on the grounding box (2026-09-03): %LOCALAPPDATA%\\hermes exists but is the " +
				"CLI's DATA dir (HERMES_HOME - config.yaml, auth.json, bin\\), and " +
				"%LOCALAPPDATA%\\com.nousresearch.hermes.setup contains only an EBWebView profile left by an " +
				"installer - neither grounds a desktop executable. No Homebrew cask `hermes` and no winget " +
				"package (both checked live the same day). The vendor documents a `hermes desktop` verb " +
				"(inventory §2.12) which would make this nearly free once someone grounds one install. " +
				"Grounded=false ⇒ empty Binary, never launchable, listed for the record.",
		},
	},
	"cowork": {
		Tool:       "cowork",
		Vocabulary: Vocabulary{InTaxonomy: true},
		// The LOCAL-observer path is native-exempt: the microVM sandbox can't
		// reach 127.0.0.1:8820, app JS is ACL-locked, and the only base-URL
		// levers are machine-wide (docs/cowork-adapter.md). A third-party
		// remote inference gateway is a SEPARATE (non-local) surface that may
		// be configurable — out of observer's local-proxy scope, so probe it
		// before any claim. Bucketed probe-required to reflect that surface.
		Proxy:       nil,
		Routability: RouteStatusProbeRequired,
		Hook:        HookSpec{Mechanism: HookNone, Note: hookNoteCowork},
		MCP:         nil,
		Native:      NativeRails{},
		TokenTier:   TokenTier{Best: "transcript", Gap: "capture depth un-audited", GenerationTiming: GenTimingNative}, // result.duration_api_ms, single-model results only
		// P0.1 FULL: audit.jsonl user/assistant records (Windows
		// cross-mount; reader = P2 tranche).
		Handoff: HandoffCapability{Transcript: TranscriptFull, Inject: []InjectKind{InjectFile}},
		// GUI launch row (plan §2.2): Claude Desktop. It is the only row in
		// the table with no launchable executable path at all on Windows —
		// an MSIX package launched by AUMID.
		GUI: &GUILaunchSpec{
			ID:      "claude-desktop",
			Label:   "Claude Desktop",
			Surface: "desktop",
			Binary: BinaryResolveSpec{
				// Names.Windows deliberately EMPTY: the MSIX payload lives
				// under %ProgramFiles%\WindowsApps, which is ACL-locked and
				// must not be exec'd directly. AppsFolderAUMID is the launch
				// path; WindowsNote carries the honest zero.
				WindowsNote: "Claude Desktop installs as an MSIX package with no exe alias on PATH; it is " +
					"launched via `explorer.exe shell:AppsFolder\\Claude_pzs8sxrjxfjjc!Claude` " +
					"(AppsFolderAUMID), never by executable path.",
				Installs: []InstallHint{
					{OS: "windows", Channel: "winget", Argv: []string{"winget", "install", "--id", "Anthropic.Claude", "-e", "--source", "winget"}, Display: "winget install --id Anthropic.Claude -e --source winget"},
					{OS: "darwin", Channel: "brew", Argv: []string{"brew", "install", "--cask", "claude"}, Display: "brew install --cask claude"},
				},
				InstallNote: "no Linux channel: Anthropic ships Claude Desktop for Windows and macOS only " +
					"(claude.ai/download).",
				UserInstallHint: "Claude Desktop is available for Windows and macOS only.",
			},
			// PATH walk disabled: `claude.exe` on PATH is the Claude Code
			// CLI, an entirely different product (gui.go's ProbeOnly doc
			// names this exact collision).
			ProbeOnly:       true,
			AppsFolderAUMID: "Claude_pzs8sxrjxfjjc!Claude",
			DarwinApp:       "Claude",
			ProjectDirArgv:  false,
			Wrap: WrapSpec{
				Kind: WrapNone,
				Reason: "two independent reasons, either sufficient. (1) Claude Desktop reads base-URL / " +
					"proxy / mTLS settings ONLY from managed settings and ~/.claude/settings.json - never from " +
					"repo-local config, and no process env var is documented (inventory §4.2). (2) An " +
					"AppsFolder launch goes through explorer.exe, so the child inherits explorer's " +
					"environment, not the daemon's: a child_env wrap could not reach it even if a var existed " +
					"(gui.go AppsFolderAUMID doc; pinned by TestGUIAppsFolderRowsAreWrapNone).",
			},
			// cowork is this row's own adapter (the Cowork code-session
			// store); claude-code is listed because Claude Desktop's
			// Claude Code lane writes the same ~/.claude/projects transcripts
			// that adapter reads.
			Hosts:    []string{"cowork", "claude-code"},
			Grounded: true,
			Note: "Windows identity grounded on this box 2026-09-03 via Get-AppxPackage: " +
				"PackageFullName Claude_1.44121.4.0_x64__pzs8sxrjxfjjc, PackageFamilyName " +
				"Claude_pzs8sxrjxfjjc, and the manifest's single Application Id \"Claude\" - so the AUMID is " +
				"Claude_pzs8sxrjxfjjc!Claude (the family suffix is the publisher hash and is stable across " +
				"versions). macOS bundle \"Claude.app\" grounded from the Homebrew cask `claude`; winget id " +
				"`Anthropic.Claude` grounded from a live `winget search --exact` the same day.",
		},
		// Sandbox filesystem-isolation row (B9). Honest zero: a GUI desktop app
		// with no launcher verb — nothing observer spawns, so nothing to wrap.
		Sandbox: SandboxSpec{Note: "not sandbox-launchable: a GUI desktop app with no launcher verb, so there is no observer-spawned process to isolate"},
	},
	"gemini-cli": {
		Tool:       "gemini-cli",
		PromptLane: PromptLaneHook,
		// Lifecycle stays ACTIVE: Google retired Gemini CLI / GCA only for the individual and
		// AI Pro/Ultra tiers on 2026-06-18 (Standard/Enterprise unchanged) — see the rowless
		// "gemini-code-assist-individuals" product entry in lifecycle.go.
		LifecycleNote: "Individual / AI Pro / AI Ultra tiers retired by Google on 2026-06-18 in favour of Antigravity (agy); Standard/Enterprise still served - https://developers.google.com/gemini-code-assist/docs/deprecations/code-assist-individuals",
		Vocabulary:    Vocabulary{InTaxonomy: true},
		// Phase E SHIPPED + LIVE-VERIFIED 2026-06-27: the proxy bridges Google
		// generateContent (providerForPath → ProviderGoogle, the
		// generativelanguage upstream, parseGeminiResponse/parseGeminiStream
		// usageMetadata) and `observer gemini` sets GOOGLE_GEMINI_BASE_URL (no
		// /v1 suffix — the CLI appends the /v1beta path). A live `observer
		// gemini -- -p …` turn produced google api_turns rows (gemini-3.5-flash
		// 11092/132) with accurate token capture.
		//
		// CONDITIONAL route (T-345, 2026-10-04). Grounded against the
		// installed @google/gemini-cli 0.62.0 bundle on demo node 1
		// (bundle/chunk-2DHAEQE2.js): createContentGenerator sends the
		// "oauth-personal" (sign in with Google) and
		// "compute-default-credentials" auth types to the Code Assist server
		// at CODE_ASSIST_ENDPOINT (default https://cloudcode-pa.googleapis.com)
		// and NEVER reads GOOGLE_GEMINI_BASE_URL; only "gemini-api-key" and
		// "gateway" honour it ("vertex-ai" reads GOOGLE_VERTEX_BASE_URL). The
		// auth type is the saved settings choice (security.auth.selectedType)
		// first, else getAuthTypeFromEnv: GOOGLE_GENAI_USE_GCA=true -> Google
		// sign-in, GOOGLE_GENAI_USE_VERTEXAI=true -> Vertex,
		// GOOGLE_GEMINI_BASE_URL set -> "gateway", GEMINI_API_KEY -> key.
		// So setting the base URL with no key on a fresh install selects
		// "gateway" with an EMPTY key instead of offering Google sign-in.
		// Gate: route only when GEMINI_API_KEY is in the launch environment;
		// a key kept only in a .env file Gemini loads itself is invisible to
		// the launcher (unrouted, and the notice says how to route it), and a
		// saved Google sign-in with a key exported is named by RoutedCaveat.
		Proxy: &ProxyRoute{
			Kind: RouteLauncher, EnvVar: "GOOGLE_GEMINI_BASE_URL", Suffix: "", Launcher: "observer gemini",
			Gate: &RouteGate{
				CredentialEnv:   []string{"GEMINI_API_KEY"},
				UnroutedBecause: "Gemini CLI has no GEMINI_API_KEY in this environment, so it uses your Google sign-in (or Vertex AI), which talks to Google directly",
				RoutedCaveat:    "if Gemini CLI is set to sign in with Google or to use Vertex AI (/auth, GOOGLE_GENAI_USE_GCA or GOOGLE_GENAI_USE_VERTEXAI), it ignores this and talks to Google directly",
				// CLI-6 (surface-gap review): the saved sign-in mode
				// (security.auth.selectedType, which /auth writes) and an
				// administrator's enforcedType decide the host before
				// GOOGLE_GEMINI_BASE_URL is read; a .env in a trusted folder
				// can flip it with GOOGLE_GENAI_USE_GCA / _VERTEXAI. Key
				// presence only (google-gemini/gemini-cli
				// packages/cli/src/config/settings.ts).
				AuthSettingKeys: []AuthSettingKey{
					{File: "gemini-cli/user-settings", Key: "security.auth.selectedType"},
					{File: "gemini-cli/project-settings", Key: "security.auth.selectedType"},
					{File: "gemini-cli/system-settings", Key: "security.auth.selectedType"},
					{File: "gemini-cli/system-settings", Key: "security.auth.enforcedType"},
				},
				DotenvKeys:  []string{"GOOGLE_GENAI_USE_GCA", "GOOGLE_GENAI_USE_VERTEXAI"},
				DotenvFiles: []string{"<project>/.gemini/.env", "<project>/.env", "~/.gemini/.env", "~/.env"},
			},
			PromptScope: "Only Gemini API-key sessions (GEMINI_API_KEY exported where you launch) go through the proxy; a session signed in with Google, or on Vertex AI, talks to Google directly and is captured from Gemini's own session files.",
		},
		Routability: RouteStatusRoutableNow,
		// Part B item 1: the prompt-submit hook lane (BeforeAgent),
		// registered by registerGenericSettingsHooks into
		// ~/.gemini/settings.json's "hooks" block — the SAME
		// Claude-Code-shaped structure HookClaudeSettings uses. This
		// is DISTINCT from (and does not replace) the "future
		// receiver lane" note below about the FULL CC-shaped
		// lifecycle hook system (PreToolUse/PostToolUse/…) Gemini CLI
		// also exposes — only BeforeAgent has a wired receiver today.
		// CrossOSBridge: true — internal/hook's gemini-cli-windows target
		// (registerGeminiCLIWindows) wraps the command in the wsl.exe
		// bridge, mirroring claude-code/cursor/codex's own bridges.
		Hook:      HookSpec{Mechanism: HookGeminiSettings, CrossOSBridge: true, AutoWired: true, Bindings: hookBindingsGeminiCLI},
		MCP:       nil,
		Native:    NativeRails{},                   // Google Cloud usage API not yet investigated (Phase-4 ledger).
		TokenTier: TokenTier{Best: "events_jsonl"}, // gross-input netting fixed (tokenEventFor nets cached); no known gap.
		// P0.1 FULL: ~/.gemini/tmp/<proj>/chats/session-*.jsonl user/gemini
		// records (reader = P2 tranche).
		Handoff: HandoffCapability{Transcript: TranscriptFull, Inject: []InjectKind{InjectFile, InjectPrompt}, Launch: &LaunchSpec{Subcommand: "gemini"}},
		// Attach grounded 2026-07-24 (attach-all-launchers); PTY handoff only
		// — no prompt seeding, token capture path unchanged.
		Attach: &AttachSpec{Subcommand: "gemini"},
		// Native resume GROUNDED, live-verified 2026-07-24 (v0.49.0): `gemini
		// --resume <uuid>` honors a full session UUID (help documents only
		// index/latest; older-UUID disambiguation confirmed live). Each resume
		// writes a continuation .jsonl carrying the SAME sessionId (native
		// checkpointing — not a new logical session). The `observer gemini`
		// launcher maps `--resume <id>` to it.
		Resume: ResumeSpec{Kind: ResumeNative, Subcommand: "gemini", IDMechanism: "flag:--resume"},
		// Credential env forwarded across the attach socket. Upstream-verified
		// at geminicli.com/docs/get-started/authentication: GEMINI_API_KEY =
		// AI-Studio mode key, GOOGLE_API_KEY = Vertex express-mode key (mode-
		// specific, NOT a precedence pair); GOOGLE_APPLICATION_CREDENTIALS =
		// Vertex service-account JSON path; the project var is checked
		// GOOGLE_CLOUD_PROJECT then GOOGLE_CLOUD_PROJECT_ID; GOOGLE_CLOUD_LOCATION
		// is required for Vertex. NAMES only.
		AuthEnv: []string{"GEMINI_API_KEY", "GOOGLE_API_KEY", "GOOGLE_APPLICATION_CREDENTIALS", "GOOGLE_CLOUD_PROJECT", "GOOGLE_CLOUD_PROJECT_ID", "GOOGLE_CLOUD_LOCATION"},
		// Binary resolution + grounded install. Unix launcher resolves
		// "gemini"; npm @google/gemini-cli (any OS).
		Binary: &BinaryResolveSpec{
			// npm JS bin: Windows install lays down a `.cmd` shim (+
			// .ps1/POSIX-shell forms), never an `.exe` — see the
			// command-code row's Binary comment for the long-form
			// rationale.
			Names: BinaryNames{
				Unix:    []string{"gemini"},
				Windows: []string{"gemini.cmd", "gemini"},
			},
			// Minimum host runtime, grounded 2026-10-04 from the npm registry
			// (`npm view <pkg> engines`): @google/gemini-cli 0.62.0 declares engines.node.
			Runtime: &RuntimeRequirement{Runtime: RuntimeNode, MinVersion: "20", Product: "Gemini CLI", Source: "npm registry engines.node, @google/gemini-cli 0.62.0, read 2026-10-04"},
			Installs: []InstallHint{
				{OS: "", Channel: "npm", Argv: []string{"npm", "install", "-g", "@google/gemini-cli"}, Display: "npm install -g @google/gemini-cli"},
			},
		},
		// Model picker (B5). Grounded live 2026-08-08: `gemini --help` lists
		// `-m, --model  Model  [string]`. The `observer gemini` launcher is
		// DisableFlagParsing + launcherArgsOrDone (B6), so a forwarded
		// `--model <value>` reaches the gemini binary unmodified.
		Model: ModelSpec{Kind: ModelArg, Flag: "--model"},
		// Sandbox filesystem-isolation row (B9). GROUNDED against
		// internal/adapter/gemini/adapter.go defaultRoots (<home>/.gemini/tmp) —
		// ~/.gemini is the whole CLI state dir (settings, oauth creds, per-project
		// tmp/ chats). Bound rw as one dir; it holds this tool's own credentials.
		// macOS (live user install 2026-10-29, D-MU6): gemini-cli runs
		// /bin/ps at start and exits when it is refused in the Seatbelt box.
		// /bin/ps is setuid root: letting it run would hand the box a root
		// program that lists every process of every user with their command
		// lines, which the profile's same-sandbox process-info rule exists to
		// prevent, so the box is not widened and the limitation is recorded.
		Sandbox: SandboxSpec{
			NeedsWin32k: true, ProviderEnv: []string{"GEMINI_API_KEY", "GOOGLE_API_KEY", "GOOGLE_APPLICATION_CREDENTIALS", "GOOGLE_CLOUD_PROJECT", "GOOGLE_CLOUD_PROJECT_ID", "GOOGLE_CLOUD_LOCATION"}, StateRW: []string{".gemini"}, ProtectRO: []string{".gemini/settings.json"},
			OSNotes: map[string]string{"darwin": "gemini-cli runs /bin/ps (setuid root) at start; a Seatbelt box refuses it, so gemini-cli exits in a macOS Seatbelt box; run it with another driver or unsandboxed"},
		},
	},
	"openclaw": {
		Tool:       "openclaw",
		Vocabulary: Vocabulary{InTaxonomy: true},
		// Live-grounded 2026-06-26 (this WSL install): OpenClaw's bundled
		// `openai` plugin reads OPENAI_BASE_URL / OPENAI_API_BASE
		// (plugin-runtime-deps/.../extensions/openai), and the operator's
		// default model is on the `openai` provider — so the `observer
		// openclaw` launcher's env redirect routes real traffic. NOT a
		// models.json writer (no such file/key exists here; openclaw.json has
		// no provider baseUrl). The `openai-codex` provider is OAuth, env-
		// immune. Proxy stays nil until a live turn confirms api_turns (the
		// app also fronts calls with its own local gateway on :18789).
		// Verification attempt 2026-06-27: the `observer openclaw` launcher
		// correctly injects OPENAI_BASE_URL, but this install's `openai`
		// provider has no API key (only openai-codex OAuth is configured), so
		// a routed openai/* turn can't authenticate here — the launcher is
		// sound; the install lacks OpenAI-compatible credentials to confirm.
		// CONFIG MECHANISM FOUND but RUNTIME STALLS (re-tested 2026-06-27). The
		// correct route is a config provider, NOT env: add
		// models.providers.<id> {baseUrl: <proxy>/v1, api: "openai-completions",
		// models:[…]} AND allow-list "<id>/<model>" in agents.defaults.models
		// (the "not allowed for agent main" blocker). That config is now
		// schema-valid (drop the unrecognized `timeoutSeconds`). HOWEVER a
		// routed `--local` turn STILL STALLS with no api_turn. Source review
		// (2026-06-27, openclaw v2026.4.24) CORRECTED the cause: it is NOT the
		// model-catalog load (offline — pi-SDK ModelRegistry, no network), it's
		// the openai-codex provider's UNBOUNDED fetch (chatgpt.com backend, 0
		// AbortSignal), which fires even when codex isn't primary because the
		// pi-SDK harness discovers a live codex OAuth token in the AGENT-DIR
		// auth store (~/.openclaw/agents/main/agent/auth-profiles.json), distinct
		// from openclaw.json. BOTH fallbacks were TESTED 2026-06-27: config-only
		// (observer primary, codex left in place) AND the operator-authorized
		// credential-step (codex dropped from config + the agent-dir auth store
		// moved aside so no live token is discoverable; restored byte-identical
		// after). BOTH STILL STALLED with no api_turn — so neutralizing codex is
		// necessary-but-NOT-sufficient; an unidentified eager call in openclaw's
		// `--local` startup hangs BEFORE the inference reaches the proxy. A
		// confirmed RUNTIME-BLOCK, closed as a grounded negative; observer drives
		// no route and must not auto-disable a user's OAuth credential to force
		// one. (docs/proxy-routing-blockers.md)
		Proxy:       nil,
		Routability: RouteStatusProbeRequired,
		Hook:        HookSpec{Mechanism: HookPluginShimTS, Bindings: hookBindingsOpenClaw}, // shim renders; no grounded install location (Lane D)
		MCP:         nil,
		Native:      NativeRails{},
		TokenTier:   TokenTier{Best: "transcript"}, // <id>.jsonl message.usage covers EVERY call (accurate; re-grounded 2026-07-31 — byte-identical to the trajectory's lastCallUsage where they overlap); *.trajectory.jsonl model.completed is a one-row-per-run SUBSET that only fills gateway-injected usage-zero turns. The runs.sqlite task path genuinely has no token columns.
		// P0.1 FULL: agents/main/sessions/<sid>.jsonl message records
		// (content present despite gateway-zeroed tokens; reader = P2
		// tranche).
		// Seeded via `openclaw chat --message "<handover>"` (chat ≡ tui
		// --local). The `--continue-from` launch runs NON-PROXIED to sidestep
		// the known `--local` proxy-routing stall (project_openclaw_runtime_
		// block); token capture stays on the trajectory adapter, so seeding is
		// orthogonal to capture.
		Handoff: HandoffCapability{Transcript: TranscriptFull, Inject: []InjectKind{InjectFile, InjectPrompt}, Launch: &LaunchSpec{Subcommand: "openclaw"}, Note: "seeded via chat --message; --continue-from launches non-proxied to avoid the --local proxy stall"},
		// Attach grounded 2026-07-24 (attach-all-launchers); PTY handoff only
		// — no prompt seeding, token capture path unchanged.
		Attach: &AttachSpec{Subcommand: "openclaw"},
		// Resume stays ResumeNone (2026-07-24): no non-interactive resume surface
		// — the only entry is the picker-only `sessions` command, and the
		// documented runtime-block (project_openclaw_runtime_block) prevents
		// probing a resume argv. The dashboard offers the handoff-fork resume.
		// AuthEnv zero: openclaw authenticates via OAuth tokens in its
		// agent-dir auth store (auth-profiles.json); no grounded runtime key
		// env to forward.
		// Binary resolution + grounded installs. Unix launcher resolves
		// "openclaw"; the vendor script is primary (docs.openclaw.ai/install),
		// npm is an alternate (needs `openclaw onboard --install-daemon`
		// after, so script leads).
		Binary: &BinaryResolveSpec{
			// npm JS bin: Windows install lays down a `.cmd` shim (+
			// .ps1/POSIX-shell forms), never an `.exe` — see the
			// command-code row's Binary comment for the long-form
			// rationale.
			Names: BinaryNames{
				Unix:    []string{"openclaw"},
				Windows: []string{"openclaw.cmd", "openclaw"},
			},
			// grounded 2026-09-02: git-source/dev installs land under
			// .local/bin — optional, the primary channel is the script
			// below.
			ProbeDirs: []ProbeDir{
				{OS: ProbeWindows, Rel: ".local/bin"},
			},
			// Minimum host runtime, grounded 2026-10-04 from the npm registry
			// (`npm view <pkg> engines`): openclaw 2026.9.8 (">=24.16.0<25||>=26.1.0"; the 25.x hole is not modelled) declares engines.node.
			Runtime: &RuntimeRequirement{Runtime: RuntimeNode, MinVersion: "24.16.0", Range: ">=24.16.0 <25 || >=26.1.0", Product: "OpenClaw", Source: "npm registry engines.node, openclaw 2026.9.8, read 2026-10-04"},
			Installs: []InstallHint{
				// T-034j (2026-10-07, script re-read): install.sh runs
				// `openclaw onboard` after `exec </dev/tty` and asks y/N and
				// menu questions; --no-onboard skips onboarding and
				// --no-prompt disables every prompt (a missing Node then
				// fails with instructions instead of asking). install.ps1
				// reads OPENCLAW_NO_ONBOARD=1 (exactly "1") and has no other
				// prompt.
				{OS: "linux", Channel: "script", Argv: []string{"bash", "-lc", "curl -fsSL https://openclaw.ai/install.sh | bash -s -- --no-onboard --no-prompt"}, Display: "curl -fsSL https://openclaw.ai/install.sh | bash -s -- --no-onboard --no-prompt", Requires: []string{"curl"}},
				{OS: "darwin", Channel: "script", Argv: []string{"bash", "-lc", "curl -fsSL https://openclaw.ai/install.sh | bash -s -- --no-onboard --no-prompt"}, Display: "curl -fsSL https://openclaw.ai/install.sh | bash -s -- --no-onboard --no-prompt", Requires: []string{"curl"}},
				// grounded 2026-09-02: openclaw.ai/install.ps1 installs Node
				// (winget → choco → scoop → portable) then npm-installs
				// itself; the CMD form here mirrors the vendor's Unix
				// script shape for a native-Windows daemon.
				{OS: "windows", Channel: "script", Argv: []string{"powershell", "-Command", "$env:OPENCLAW_NO_ONBOARD='1'; iwr -useb https://openclaw.ai/install.ps1 | iex"}, Display: "$env:OPENCLAW_NO_ONBOARD='1'; iwr -useb https://openclaw.ai/install.ps1 | iex"},
				// DI-12 fix: openclaw's own install.ps1
				// (Get-NpmLifecycleAllowArgument) passes
				// --allow-scripts=openclaw on a modern npm so the postinstall
				// step (which drops the openclaw.cmd shim) actually runs; a
				// bare `npm install -g` silently skips it on npm >= 11.16.
				{OS: "", Channel: "npm", Argv: []string{"npm", "install", "-g", "--allow-scripts=openclaw", "openclaw@latest"}, Display: "npm install -g --allow-scripts=openclaw openclaw@latest"},
			},
		},
		// Model picker (B5): explicit ModelNone. `openclaw --help` and its
		// `chat`/`tui` subcommand surfaces confirm no `--model` flag anywhere
		// on the launch path (model selection lives entirely in the
		// interactive `openclaw models` picker / config, not an argv flag) —
		// the same grounded negative documented on Resume above.
		Model: ModelSpec{Kind: ModelNone},
		// Sandbox filesystem-isolation row (B9). GROUNDED against
		// internal/adapter/openclaw/adapter.go defaultRoots (<home>/.openclaw/tasks
		// and <home>/.openclaw/agents). ~/.openclaw is the whole state dir
		// (sessions.json, per-agent sqlite stores, auth) and is bound rw as one
		// dir.
		Sandbox: SandboxSpec{NeedsWin32k: true, StateRW: []string{".openclaw"}},
		// GUI launch row (plan §2.2): the OpenClaw desktop companion. It is
		// Gateway-scoped, not project-scoped — there is no project argv and
		// no per-workspace launch semantics.
		GUI: &GUILaunchSpec{
			ID:      "openclaw-hub",
			Label:   "OpenClaw Hub",
			Surface: "desktop",
			Binary: BinaryResolveSpec{
				// Names.Windows deliberately EMPTY (see WindowsNote); a
				// Names.Unix entry would collide with this row's CLI
				// (`openclaw`) above, so none is declared either.
				WindowsNote: "the Windows Hub installer's layout is unverified: it is not installed on the " +
					"grounding box (2026-09-03), no winget package exists, and the Hub provisions its own " +
					"`OpenClawGateway` WSL distro - %LOCALAPPDATA%\\OpenClawTray\\ is state/logs, not a " +
					"grounded executable path (inventory §2.12).",
				Installs: []InstallHint{
					{OS: "darwin", Channel: "brew", Argv: []string{"brew", "install", "--cask", "openclaw"}, Display: "brew install --cask openclaw"},
				},
				InstallNote: "macOS only: no winget package (checked live 2026-09-03); on Linux the CLI's " +
					"own install script in this row's Binary above is the surface, not a desktop app.",
			},
			DarwinApp:      "OpenClaw",
			ProjectDirArgv: false,
			Wrap: WrapSpec{
				Kind: WrapNone,
				Reason: "config-write is the ONLY route OpenClaw honours - ANTHROPIC_BASE_URL explicitly " +
					"does not work (upstream #56679) and a pre-existing auth-profiles.json can silently " +
					"bypass a configured baseUrl - but this row carries NEITHER a verified Proxy nor a " +
					"ProxyProbe writer binding (Routability is probe_required and internal/proxyroute has no " +
					"openclaw registrar), so a config_write ConfigTool here would name a writer that does not " +
					"exist. Honest zero until a registrar for ~/.openclaw/openclaw.json " +
					"models.providers.*.baseUrl lands; then this becomes config_write, and the route needs a " +
					"post-launch verification that it actually took (inventory §4.2).",
			},
			Hosts:    []string{"openclaw"},
			Grounded: true,
			Note: "Grounded from the macOS side ONLY: the Homebrew cask `openclaw` (name \"OpenClaw\", " +
				"homepage openclaw.ai) installs \"OpenClaw.app\", read from the cask API 2026-09-03. Whether " +
				"that bundle is the menu-bar companion the inventory §2.12 describes or a different desktop " +
				"shell was NOT separately verified. Windows Hub layout unverified - Names.Windows empty. " +
				"Gateway-scoped, so ProjectDirArgv=false by design, and the Hub's own WSL Gateway is a " +
				"documented double-counting risk (a distinct OPENCLAW_HOME).",
		},
	},
	"pi": {
		Tool:       "pi",
		Vocabulary: Vocabulary{InTaxonomy: true},
		// FIX-7 (phase-2 review): pi's before_provider_payload hook is
		// REDACT-capable but explicitly cannot block ("Cannot: Block
		// the turn or cancel it" — contract §2.2) and no writer exists
		// for it yet; the proxy lane (already routed today) is the
		// only real coverage.
		PromptLane: PromptLaneProxyOnly,
		// ROUTABLE via a custom provider in ~/.pi/agent/models.json — VERIFIED
		// LIVE 2026-06-27. pi's BUILT-IN providers ignore OPENAI_BASE_URL
		// (a dead-port base URL still reached api.openai.com; both env and the
		// default provider bypass the proxy), but pi's documented custom-
		// provider mechanism (docs/models.md) accepts an explicit `baseUrl`.
		// The `observer pi` launcher (cmd/observer/pi.go) idempotently writes an
		// "observer" provider {baseUrl: <proxy>/v1, api: openai-completions,
		// apiKey: "OPENAI_API_KEY" (the env-var NAME — no secret on disk)} and
		// execs `pi --provider observer`. A live turn landed real api_turns
		// rows (provider=openai, gpt-4o-2024-08-06, HTTP 200) — routing
		// confirmed. RouteProviderJSON because the route is a JSON config write,
		// not an env var; init does NOT auto-write it (the launcher does).
		// COMPRESSION CAVEAT: pi is on the proxy's OpenAI compression path, but
		// pi pre-processes files LOCALLY and sends minimal tool_results (an 87KB
		// read produced a 239-token request), so conversation compression rarely
		// has a large tool-output to compress on a typical pi turn — no
		// compression_event captured despite genuine attempts. Routing works;
		// the compression benefit is small by pi's architecture, not a gate.
		// (docs/proxy-routing-blockers.md)
		Proxy: &ProxyRoute{
			ClientAuth:           ClientAuthPathToken,
			SharesCredentialFile: true, CredentialFileReason: routeCredPi,
			PersistedDefault: &PersistedDefault{
				Note:     "CLI-1a: proxyroute.RegisterDefaultProvider(pi) sets defaultProvider = observer in ~/.pi/agent/settings.json once the launcher's observer provider is in models.json, so a bare pi routes; member edit, never a key; defaultModel must name a model of that provider (part of the live check)",
				LiveGate: "LC25",
			},
			Kind: RouteProviderJSON, EnvVar: "", Suffix: "/v1", Launcher: "observer pi", Note: "routes via ~/.pi/agent/models.json custom 'observer' provider baseUrl (not an env var); launcher writes it, never a key",
			// Demo node 1, 2026-10-02: a pi session on another provider
			// (baseten) never reached the proxy.
			PromptScope:       "Only turns sent to the \"observer\" provider the launcher writes go through the proxy, plus, on a managed node, every built-in provider the launcher can point at a proxy lane for the session; a switch to a built-in provider with no proxy lane (Bedrock, Azure, Vertex, Cloudflare, Mistral, the ChatGPT sign-in, GitHub Copilot, OpenCode) or to your own custom provider bypasses it and is flagged after send.",
			ProviderOverrides: joinProviderOverrides(piFamilyProviderOverrides, piOnlyProviderOverrides),
		},
		Routability: RouteStatusRoutableNow,
		Hook:        HookSpec{Mechanism: HookPluginShimTS, AutoWired: true, Bindings: hookBindingsPi}, // plugin shim (Lane D)
		MCP:         nil,
		Native:      NativeRails{},
		TokenTier:   TokenTier{Best: "transcript", Gap: "capture depth un-audited", ReportsCost: true},
		// P0.1 FULL: sessions/<slug>/<ts>_<id>.jsonl message records
		// (reader = P2 tranche).
		Handoff: HandoffCapability{Transcript: TranscriptFull, Inject: []InjectKind{InjectFile, InjectPrompt}, Launch: &LaunchSpec{Subcommand: "pi"}},
		// Attach grounded 2026-07-24 (attach-all-launchers); PTY handoff only
		// — no prompt seeding, token capture path unchanged.
		Attach: &AttachSpec{Subcommand: "pi"},
		// Native resume GROUNDED, live-verified 2026-07-24: `pi --session <id>`
		// reattaches the real session (accepts full or partial uuid; the
		// launcher passes the full id). The `observer pi` launcher maps
		// `--resume <id>` to it.
		Resume: ResumeSpec{Kind: ResumeNative, Subcommand: "pi", IDMechanism: "flag:--session"},
		// Credential env forwarded across the attach socket. Grounded: pi.go
		// writes the "observer" provider with apiKey = the env-var NAME
		// OPENAI_API_KEY (no secret on disk — pi resolves it from the env at
		// runtime), so that IS the key env the caller exports. NAMES only.
		AuthEnv: []string{"OPENAI_API_KEY"},
		// Binary resolution + grounded installs. Unix launcher resolves
		// "pi"; npm @earendil-works/pi-coding-agent (earendil-works/pi,
		// pi.dev — NOT Inflection) + the official install script.
		Binary: &BinaryResolveSpec{
			// npm JS bin: Windows install lays down a `.cmd` shim (+
			// .ps1/POSIX-shell forms), never an `.exe` — see the
			// command-code row's Binary comment for the long-form
			// rationale.
			Names: BinaryNames{
				Unix:    []string{"pi"},
				Windows: []string{"pi.cmd", "pi"},
			},
			// grounded 2026-09-02: pi.dev/install.ps1 lands
			// %USERPROFILE%\.pi\agent\bin\{pi.cmd,pi.ps1,pi} (a private
			// Node 22 install, separate from any system Node); the Unix
			// script lands the analogous ~/.pi/agent/bin/pi.
			ProbeDirs: []ProbeDir{
				{OS: ProbeUnix, Rel: ".pi/agent/bin"},
				{OS: ProbeWindows, Rel: ".pi/agent/bin"},
			},
			// Minimum host runtime, grounded 2026-10-04 from the npm registry
			// (`npm view <pkg> engines`): @earendil-works/pi-coding-agent 1.0.2 declares engines.node.
			Runtime: &RuntimeRequirement{Runtime: RuntimeNode, MinVersion: "22.19.0", Product: "pi", Source: "npm registry engines.node, @earendil-works/pi-coding-agent 1.0.2, read 2026-10-04"},
			Installs: []InstallHint{
				{OS: "", Channel: "npm", Argv: []string{"npm", "install", "-g", "--ignore-scripts", "@earendil-works/pi-coding-agent"}, Display: "npm install -g --ignore-scripts @earendil-works/pi-coding-agent"},
				{OS: "linux", Channel: "script", Argv: []string{"bash", "-lc", "curl -fsSL https://pi.dev/install.sh | sh"}, Display: "curl -fsSL https://pi.dev/install.sh | sh", Requires: []string{"curl"}},
				{OS: "darwin", Channel: "script", Argv: []string{"bash", "-lc", "curl -fsSL https://pi.dev/install.sh | sh"}, Display: "curl -fsSL https://pi.dev/install.sh | sh", Requires: []string{"curl"}},
				{OS: "windows", Channel: "script", Argv: []string{"powershell", "-Command", "irm https://pi.dev/install.ps1 | iex"}, Display: "irm https://pi.dev/install.ps1 | iex"},
			},
		},
		// Model picker (B5). Grounded live 2026-08-08: `pi --help` lists
		// `--model <pattern>  Model pattern or ID (supports "provider/id" and
		// optional ":<thinking>")`, with help examples `pi --model
		// openai/gpt-4o "…"` and `pi --model sonnet:high "…"`. The
		// `observer pi` launcher is DisableFlagParsing + launcherArgsOrDone
		// (B6), so a forwarded `--model <value>` reaches the pi binary
		// unmodified.
		Model: ModelSpec{Kind: ModelArg, Flag: "--model", Known: []string{"openai/gpt-4o", "sonnet:high"}},
		// Sandbox filesystem-isolation row (B9). GROUNDED against
		// internal/adapter/pi/adapter.go defaultRoots (<home>/.pi/agent/sessions).
		// ~/.pi is the CLI's whole state dir and is bound rw as one dir.
		Sandbox: SandboxSpec{NeedsWin32k: true, ProviderEnv: []string{"OPENAI_API_KEY"}, StateRW: []string{".pi"}},
	},
	"antigravity": {
		Tool:       "antigravity",
		Vocabulary: Vocabulary{InTaxonomy: true},
		// No base-URL / custom-provider knob found (decrypt-gated, own
		// backend). A grounded negative — reclassify if Google documents a
		// gateway knob.
		Proxy:       nil,
		Routability: RouteStatusNativeExempt,
		Hook:        HookSpec{Mechanism: HookNone, Bindings: hookBindingsAntigravity},
		MCP:         nil,
		Native:      NativeRails{}, // Google Cloud usage API not yet investigated (Phase-4 ledger).
		// Desktop CAPTURE (text + tool actions + model + surface) comes
		// from the IDE's PLAINTEXT brain/<uuid>/.system_generated/logs/
		// transcript.jsonl since 2026-09-03 (internal/adapter/antigravity/
		// transcript.go). Desktop TOKENS: REAL per-generation usage + model
		// id whenever an agy backend wrote the conversation — the VS Code
		// extension (Google.google-antigravity, bundled agy) writes a
		// plaintext conversations/<uuid>.db into the desktop tree with the
		// CLI's exact schema (clidb.go, live-grounded 2026-09-03) — and
		// ABSENT for the standalone IDE build, which wrote only the
		// encrypted .pb + the transcript that day (no usage anywhere; the
		// .pb cipher stays parked, IDE-12). RE-GROUNDED 2026-10-28 (the
		// Windows demo node, WINNODE2 item 9): the standalone Antigravity
		// IDE 2.6.0 (bundled agy 1.4.9) writes conversations/<uuid>.db too,
		// and Observer captured real per-turn tokens, cache reads and the
		// model for every IDE session, so only pre-2.6 IDE builds keep the
		// .pb-only store.
		TokenTier: TokenTier{Best: "sqlite", Gap: "pre-2.6 standalone-IDE builds write only the encrypted .pb + transcript.jsonl, so their conversations carry no usage; IDE 2.6+ (bundled agy, live 2026-10-28) writes conversations/<uuid>.db with real tokens", SynthesizedTimestamps: true},
		// Desktop transcript.jsonl is readable plaintext → text + actions
		// present; tokens only for agy-backed (.db) conversations → partial.
		Handoff: HandoffCapability{Transcript: TranscriptPartial, Inject: []InjectKind{InjectFile}, Note: "desktop transcript.jsonl plaintext (text + actions); tokens whenever an agy .db exists (VS Code extension, standalone IDE 2.6+), absent for pre-2.6 standalone IDE builds"},
		// Active row, but the lifecycle context is worth carrying: this is
		// Google's SUCCESSOR family after the 2026-06-18 retirement of
		// Gemini CLI + Gemini Code Assist for individual / AI Pro / AI Ultra
		// tiers (the gemini-cli row is DEPRECATED on that event). Nine
		// surfaces share the harness — desktop IDE (this row's store),
		// Antigravity 2.0 dashboard, agy CLI (antigravity-cli row), VS Code /
		// Visual Studio / JetBrains / Zed / Xcode integrations, Python SDK —
		// only the IDE + CLI stores are grounded; see
		// docs/audits/antigravity-family-surfaces-2026-09-03.md.
		LifecycleNote: "Google's successor family after the 2026-06-18 individual-tier retirement of Gemini CLI / " +
			"Gemini Code Assist (https://developers.googleblog.com/an-important-update-transitioning-gemini-cli-to-antigravity-cli/); " +
			"this row = the desktop IDE store, docs/audits/antigravity-family-surfaces-2026-09-03.md = the family.",
		// GUI launch row (plan §2.2). Launch is buildable; capture of the
		// IDE's conversations lands through the plaintext transcript.jsonl
		// (tokens excepted — see TokenTier).
		GUI: &GUILaunchSpec{
			ID:      "antigravity-ide",
			Label:   "Antigravity",
			Surface: "ide",
			Binary: BinaryResolveSpec{
				Names: BinaryNames{
					Windows: []string{"Antigravity.exe"},
				},
				ProbeDirs: []ProbeDir{
					{OS: ProbeWindows, Rel: "AppData/Local/Programs/antigravity"},
				},
				Installs: []InstallHint{
					{OS: "windows", Channel: "winget", Argv: []string{"winget", "install", "--id", "Google.Antigravity", "-e", "--source", "winget"}, Display: "winget install --id Google.Antigravity -e --source winget"},
					// MAC-4 (docs/handovers/surface-gap-mac4-report.md): the
					// cask `antigravity` now installs the separate Antigravity 2
					// agent app; the IDE is the cask `antigravity-ide`.
					{OS: "darwin", Channel: "brew", Argv: []string{"brew", "install", "--cask", "antigravity-ide"}, Display: "brew install --cask antigravity-ide"},
				},
				InstallNote: "no grounded Linux channel: antigravity.google ships a direct download, not a " +
					"scriptable one-liner.",
			},
			DarwinApp: "Antigravity IDE",
			// FALSE, grounded negative on Windows: unlike every other VS Code
			// fork on this box (Kiro, Qoder, Windsurf, Cursor), the antigravity
			// install dir has NO bin\ directory at all — no `antigravity`
			// shim, so no grounded `<app> <dir>` argv form. Assuming one
			// from the fork lineage would be a fabricated capability. The
			// macOS IDE DOES ship a shim (Contents/Resources/app/bin/
			// antigravity-ide, linked by the cask as antigravity-ide and
			// agy-ide; MAC-4), but its `<shim> <dir>` form was not run, and
			// the flag is one value for every OS, so it stays false.
			ProjectDirArgv: false,
			Wrap: WrapSpec{
				Kind: WrapNone,
				Reason: "no base-URL knob found for the IDE (this row's Routability is native_exempt; the " +
					"sibling `agy` CLI documents GOOGLE_GEMINI_BASE_URL but the antigravity-cli row records " +
					"that as an UNVERIFIED contradiction, inventory §2.3). Launch yes, wrap no; capture " +
					"rides the IDE's plaintext brain/<uuid>/.system_generated/logs/transcript.jsonl " +
					"(text + tool actions + model + surface); tokens from conversations/<uuid>.db on IDE " +
					"2.6+ (live 2026-10-28), absent on older builds (the .pb cipher stays parked).",
			},
			Hosts:    []string{"antigravity"},
			Grounded: true,
			Note: "Windows layout grounded on this box 2026-09-03: " +
				"%LOCALAPPDATA%\\Programs\\antigravity\\Antigravity.exe - and NO bin\\ dir, hence " +
				"ProjectDirArgv=false and no unix shim name (the inventory left both \"to ground\"). macOS " +
				"bundle \"Antigravity IDE.app\" (bundle id com.google.antigravity-ide, 2.6.0) and its cask " +
				"`antigravity-ide` grounded on the MAC-4 macOS run 2026-10-27; the cask `antigravity` now installs " +
				"the separate Antigravity 2 agent app (com.google.antigravity). winget id " +
				"`Google.Antigravity` grounded from a live `winget search --exact` the same day. This row is " +
				"the IDE; the `agy` CLI is the separate antigravity-cli registry row.",
		},
		// Sandbox filesystem-isolation row (B9). Honest zero: a GUI desktop app
		// with no launcher verb — nothing observer spawns, so nothing to wrap.
		Sandbox: SandboxSpec{Note: "not sandbox-launchable: a GUI desktop app with no launcher verb, so there is no observer-spawned process to isolate"},
	},
	"antigravity-cli": {
		Tool:       "antigravity-cli",
		Vocabulary: Vocabulary{InTaxonomy: true},
		// A fresh install puts agy.exe in %LOCALAPPDATA%\agy\bin (Binary's
		// probe dir) and only the registry user Path; ~/.gemini appears at
		// the first run (Windows Server 2025 demo, 2026-10-28).
		InstallSignals: []InstallSignal{{Kind: InstallSignalBinary}},
		// Active; lifecycle context as on the antigravity row — agy is the
		// named successor of Gemini CLI for individual tiers (retired
		// 2026-06-18). No `agy login` subcommand exists: first interactive
		// run opens a browser OAuth flow (OS keyring); BYOK = GEMINI_API_KEY
		// + modelProvider:"gemini" in ~/.gemini/antigravity-cli/settings.json.
		LifecycleNote: "Google's successor to Gemini CLI after the 2026-06-18 individual-tier retirement " +
			"(https://developers.googleblog.com/an-important-update-transitioning-gemini-cli-to-antigravity-cli/); " +
			"family inventory: docs/audits/antigravity-family-surfaces-2026-09-03.md.",
		// Two auth modes (audit P2, 2026-10-02). Google sign-in (the
		// default; demo node 1) has no base-URL knob and is not
		// proxy-routable. API-key mode (settings.json modelProvider
		// "gemini" + GEMINI_API_KEY) honours GOOGLE_GEMINI_BASE_URL per
		// the vendor install doc (antigravity.google/docs/cli/install),
		// which `observer antigravity-cli` now sets in that mode onto the
		// proxy's Gemini generateContent lane. API-key mode routing is
		// proven to a LOOPBACK (agy 1.3.5, demo node 1, 2026-10-15: every
		// request, the title request included, went to
		// GOOGLE_GEMINI_BASE_URL), but no api_turns row has landed through
		// :8820 yet, so Proxy stays nil (flip only after a live api_turns
		// row) and Routability says probe_required. Sign-in mode routing is
		// unproven.
		Proxy:       nil,
		Routability: RouteStatusProbeRequired,
		// Prompt coverage acts before the MAIN model call (PromptWarnOnly:
		// the prompt has already left the machine in agy's title request,
		// which no hook sees). The PreInvocation hook (audit P1,
		// 2026-10-02) was retired by the node 1 live test of agy 1.2.16
		// (2026-10-03: the transcript held the prompt only after the
		// reply), restored by T-476 after agy 1.3.0 (node 1, 2026-10-06)
		// wrote the USER_INPUT step before invocationNum 0, and since the
		// guard-enforcement fix (agy 1.3.5, 2026-10-15) it warns the
		// developer (an injected userMessage) and BLOCKS by aborting the
		// turn ({"injectSteps":[{}]}, an undocumented error path, offered
		// only to agy >= 1.3.5), tainting the conversation because agy
		// resends the stopped prompt with every later turn. A prompt rule is
		// still flagged after send by the capture lane. The mechanism also
		// registers the PreToolUse tool gate (hook-parity Lane A6; an ask is
		// agy's native force_ask under an interactive agy).
		Hook:   HookSpec{Mechanism: HookAntigravityJSON, AutoWired: true, PromptWarnOnly: true, Bindings: hookBindingsAntigravityCLI},
		MCP:    nil,
		Native: NativeRails{},
		// CLI (agy) writes plaintext-protobuf SQLite .db — parsed directly (clidb.go).
		TokenTier: TokenTier{Best: "sqlite"},
		// CLI (agy) plaintext .db readable; seeds agy -i.
		Handoff: HandoffCapability{
			Transcript: TranscriptPartial,
			Inject:     []InjectKind{InjectFile, InjectPrompt},
			Launch:     &LaunchSpec{Subcommand: "antigravity-cli"},
			Note:       "CLI (agy) .db readable + -i seed",
		},
		// Attach grounded 2026-07-24 (attach-all-launchers); PTY handoff only
		// — no prompt seeding, token capture path unchanged.
		Attach: &AttachSpec{Subcommand: "antigravity-cli"},
		// Native resume GROUNDED, live-verified 2026-07-24 (structural: id echo +
		// no new .db; space form accepted): `agy --conversation <UUID>`
		// reattaches the real session; id is a raw uuid. The `observer
		// antigravity-cli` launcher maps `--resume <id>` to it.
		Resume: ResumeSpec{Kind: ResumeNative, Subcommand: "antigravity-cli", IDMechanism: "flag:--conversation"},
		// AuthEnv zero: the agy CLI authenticates via Google OAuth, not a key
		// env — no grounded credential-env to forward.
		// Binary resolution + grounded install. Unix launcher resolves "agy"
		// (the agy CLI); official install script (antigravity.google/docs/
		// cli/install). Windows hint is EXECUTABLE by a native-Windows
		// daemon (ConPTY, since 2026-07-04); post-install detection needs
		// Names.Windows (grounded 2026-09-02).
		//
		// Windows spelling GROUNDED 2026-09-02 by reading the installer
		// (`$TARGET_DIR = Join-Path $env:LOCALAPPDATA "agy\bin"`,
		// `$binaryPath = … "agy.exe"`) and `where.exe agy` on this box.
		Binary: &BinaryResolveSpec{
			Names: BinaryNames{
				Unix:    []string{"agy"},
				Windows: []string{"agy.exe"},
			},
			ProbeDirs: []ProbeDir{
				{OS: ProbeUnix, Rel: ".local/bin"},
				{OS: ProbeWindows, Rel: "AppData/Local/agy/bin"},
			},
			Installs: []InstallHint{
				{OS: "linux", Channel: "script", Argv: []string{"bash", "-lc", "curl -fsSL https://antigravity.google/cli/install.sh | bash"}, Display: "curl -fsSL https://antigravity.google/cli/install.sh | bash", Requires: []string{"curl", "tar"}},
				{OS: "darwin", Channel: "script", Argv: []string{"bash", "-lc", "curl -fsSL https://antigravity.google/cli/install.sh | bash"}, Display: "curl -fsSL https://antigravity.google/cli/install.sh | bash", Requires: []string{"curl", "tar"}},
				{OS: "windows", Channel: "script", Argv: []string{"powershell", "-Command", "irm https://antigravity.google/cli/install.ps1 | iex"}, Display: "irm https://antigravity.google/cli/install.ps1 | iex"},
			},
		},
		// Model picker (B5). Grounded live 2026-08-08: `agy --help` lists a
		// top-level `--model  Model for the current CLI session`. VERIFIED
		// cmd/observer/antigravity.go execs the real `agy` CLI (`return
		// runSeedOnlyLaunch("agy", bin, args, continueDir)`) and is
		// DisableFlagParsing + launcherArgsOrDone (B6), so a forwarded
		// `--model <value>` reaches the agy binary unmodified. (The sibling
		// "antigravity" row above is the decrypt-gated desktop app — it has
		// no Handoff.Launch at all, so it gets no Model row; only this CLI
		// row is launchable.)
		Model: ModelSpec{Kind: ModelArg, Flag: "--model"},
		// Sandbox filesystem-isolation row (B9). Not grounded in v1 (plan
		// amendment A3) — only claude-code has a verified state-dir bind
		// list; every other launchable tool carries the honest zero note
		// until a per-tool probe grounds its StateRW/StateRO paths.
		Sandbox: SandboxSpec{Note: "state dirs not yet grounded - not sandbox-launchable"},
	},
	"qwen-code": {
		Tool:       "qwen-code",
		PromptLane: PromptLaneHook,
		Vocabulary: Vocabulary{InTaxonomy: true},
		// Live-captured 2026-07-09 (WSL + Windows): CC-shaped JSONL under
		// ~/.qwen/projects/<slug>/chats/.
		//
		// ROUTE LANE — PROMOTED, LIVE-VERIFIED 2026-07-09 (operator-approved
		// probe). Qwen Code resolves the active model by the (id, baseUrl) pair,
		// so rewriting model.baseUrl ALONE was insufficient: the first probe
		// (2026-07-09) set model.baseUrl → the proxy but left no matching
		// modelProviders entry, and `qwen -p` warned "no longer matches any
		// provider for model 'gpt-4o' … using the first id match
		// ('https://api.openai.com/v1')" and went DIRECT, no api_turns row.
		// The follow-up writer now ALSO retargets every openai-lane
		// modelProviders entry on the known default host to the proxy URL
		// (carrying each entry's id + envKey untouched — the operator's real
		// OpenAI key still forwards). With that, model.name=gpt-4o resolves to
		// (id=gpt-4o, baseUrl=http://127.0.0.1:8820/v1) and `qwen -p "reply with
		// the word ok"` routed through the proxy and landed api_turns rows
		// (id 23728-23730, provider=openai, model gpt-4o-2024-08-06, HTTP 200).
		// The OPENAI_BASE_URL env knob stays inert; the config lane is the
		// working route. Proxy now drives it; init applies it via the
		// RegisterQwenCode writer (dispatched on Kind).
		Proxy: &ProxyRoute{
			ClientAuth:           ClientAuthPathToken,
			SharesCredentialFile: true, CredentialFileReason: routeCredQwenCode,
			Kind:     RouteConfigFile,
			EnvVar:   "",
			Suffix:   "/v1",
			Launcher: "observer qwen",
			Note:     "routes via model.baseUrl + a matching modelProviders openai entry in ~/.qwen/settings.json (proxyroute.RegisterQwenCode, retargets the openai-default provider, keeps id + envKey); implicit host was api.openai.com so the fixed OpenAI upstream applies. Live-verified 2026-07-09 (api_turns 23728-23730, gpt-4o-2024-08-06)",
			ForeignLane: &ForeignProviderLane{
				LiveVerified: true,
				Note:         "the managed daemon can route a model.baseUrl at a third-party https host (OpenRouter, ...) through a proxy /up/<id> lane, keeping that host as the lane upstream and retargeting the modelProviders entries on it (proxyroute.RegisterQwenCodeLane). Live-verified 2026-10-18 on demo node 1 (RETEST5 F3): one qwen prompt through the route-openrouter-ai lane landed 2 api_turns rows whose request ids carry OpenRouter's gen- prefix (api_turns has no lane column, so the lane itself is proven by the config URL, the proxy's lane set and the rows existing at all)",
			},
		},
		// ProxyProbe PERSISTS after promotion: it is the config-lane WRITER
		// BINDING init uses to apply the (now verified) route on a machine whose
		// ~/.qwen/settings.json is not yet routed. Proxy above is the verified
		// route; this is how init writes it.
		ProxyProbe: &ProxyRoute{
			SharesCredentialFile: true, CredentialFileReason: routeCredQwenCode,
			Kind:     RouteConfigFile,
			Launcher: "observer qwen",
			Note:     "proxyroute.RegisterQwenCode rewrites model.baseUrl AND retargets the matching openai-lane modelProviders entry in ~/.qwen/settings.json (from the known default only; keeps id + envKey; .bak)",
		},
		Routability: RouteStatusRoutableNow,
		// Upstream ships a full CC-shaped lifecycle hook system
		// (PreToolUse/PostToolUse/… in settings.json) — a future receiver
		// lane beyond UserPromptSubmit, which IS wired (Part B item 1):
		// registerGenericSettingsHooks registers it into
		// ~/.qwen/settings.json's "hooks" block, the same shape
		// HookClaudeSettings uses.
		// CrossOSBridge: true — internal/hook's qwen-code-windows target
		// (registerQwenCodeWindows) wraps the command in the wsl.exe
		// bridge, mirroring claude-code/cursor/codex's own bridges.
		Hook: HookSpec{Mechanism: HookQwenSettings, CrossOSBridge: true, AutoWired: true, Bindings: hookBindingsQwenCode, HooksShareCredentialFile: true, CredentialFileReason: credFileQwenCode},
		// MCP client exists (Gemini lineage, mcpServers in settings.json),
		// but settings.json embeds plaintext provider keys — an MCP writer
		// needs a guarded additive write path before this can be grounded.
		MCP:    nil,
		Native: NativeRails{},
		// ui_telemetry in-transcript records: gross input netted against
		// cached (OpenAI convention, live-evidenced), thoughts → Reasoning.
		TokenTier: TokenTier{Best: "transcript", Gap: "no cache-creation tier; counts approximate (self-reported telemetry records)"},
		// Records carry complete prompts/responses/tool bodies; `qwen -i`
		// seed verified live 2026-07-09; launched non-proxied by
		// `observer qwen` (the base-URL lane stays unprobed).
		Handoff: HandoffCapability{
			Transcript: TranscriptFull,
			Inject:     []InjectKind{InjectFile, InjectPrompt},
			Launch:     &LaunchSpec{Subcommand: "qwen"},
			Note:       "-i/--prompt-interactive seed verified live",
		},
		// Attach grounded 2026-07-24 (attach-all-launchers); PTY handoff only
		// — no prompt seeding, token capture path unchanged.
		Attach: &AttachSpec{Subcommand: "qwen"},
		// Native resume GROUNDED, live-verified 2026-07-24: `qwen --resume <id>`
		// reattaches the real session; id is raw. The `observer qwen` launcher
		// maps `--resume <id>` to it.
		Resume: ResumeSpec{Kind: ResumeNative, Subcommand: "qwen", IDMechanism: "flag:--resume"},
		// AuthEnv zero: qwen-code keys live inside settings.json
		// (modelProviders[].apiKey / envKey), a file store — no grounded
		// top-level runtime key env to forward.
		// Binary resolution + grounded installs. Unix launcher resolves
		// "qwen"; npm @qwen-code/qwen-code@latest (any OS) + the standalone
		// install script + brew (QwenLM/qwen-code + official docs).
		Binary: &BinaryResolveSpec{
			// npm JS bin: Windows install lays down a `.cmd` shim (+
			// .ps1/POSIX-shell forms), never an `.exe` — see the
			// command-code row's Binary comment for the long-form
			// rationale.
			Names: BinaryNames{
				Unix:    []string{"qwen"},
				Windows: []string{"qwen.cmd", "qwen"},
			},
			// grounded 2026-09-02: the standalone installer (a .ps1 thin
			// shim downloading + running install-qwen-standalone.bat)
			// lands the command at %LOCALAPPDATA%\qwen-code\bin\qwen.cmd,
			// bundling its own Node under qwen-code\node\node.exe.
			ProbeDirs: []ProbeDir{
				{OS: ProbeWindows, Rel: "AppData/Local/qwen-code/bin"},
			},
			// Minimum host runtime, grounded 2026-10-04 from the npm registry
			// (`npm view <pkg> engines`): @qwen-code/qwen-code 0.24.7 declares engines.node.
			Runtime: &RuntimeRequirement{Runtime: RuntimeNode, MinVersion: "22.0.0", Product: "Qwen Code", Source: "npm registry engines.node, @qwen-code/qwen-code 0.24.7, read 2026-10-04"},
			Installs: []InstallHint{
				{OS: "", Channel: "npm", Argv: []string{"npm", "install", "-g", "@qwen-code/qwen-code@latest"}, Display: "npm install -g @qwen-code/qwen-code@latest"},
				{OS: "linux", Channel: "script", Argv: []string{"bash", "-lc", "curl -fsSL https://qwen-code-assets.oss-cn-hangzhou.aliyuncs.com/installation/install-qwen-standalone.sh | bash"}, Display: "curl -fsSL https://qwen-code-assets.oss-cn-hangzhou.aliyuncs.com/installation/install-qwen-standalone.sh | bash", Requires: []string{"curl"}},
				{OS: "darwin", Channel: "script", Argv: []string{"bash", "-lc", "curl -fsSL https://qwen-code-assets.oss-cn-hangzhou.aliyuncs.com/installation/install-qwen-standalone.sh | bash"}, Display: "curl -fsSL https://qwen-code-assets.oss-cn-hangzhou.aliyuncs.com/installation/install-qwen-standalone.sh | bash", Requires: []string{"curl"}},
				{OS: "darwin", Channel: "brew", Argv: []string{"brew", "install", "qwen-code"}, Display: "brew install qwen-code"},
				{OS: "windows", Channel: "script", Argv: []string{"powershell", "-Command", "irm https://qwen-code-assets.oss-cn-hangzhou.aliyuncs.com/installation/install-qwen-standalone.ps1 | iex"}, Display: "irm https://qwen-code-assets.oss-cn-hangzhou.aliyuncs.com/installation/install-qwen-standalone.ps1 | iex"},
			},
		},
		// Model picker (B5). Grounded live 2026-08-08: `qwen --help` lists
		// `-m, --model  Model  [string]`. The `observer qwen` launcher is
		// DisableFlagParsing + launcherArgsOrDone (B6), so a forwarded
		// `--model <value>` reaches the qwen binary unmodified.
		Model: ModelSpec{Kind: ModelArg, Flag: "--model"},
		// Sandbox filesystem-isolation row (B9). GROUNDED against
		// internal/adapter/qwencode/adapter.go defaultRoots (<home>/.qwen/projects,
		// or $QWEN_HOME). ~/.qwen is the CLI's whole state dir (settings, oauth
		// creds, per-project transcripts) and is bound rw as one dir.
		Sandbox: SandboxSpec{NeedsWin32k: true, StateRW: []string{".qwen"}, ProtectRO: []string{".qwen/settings.json"}},
	},
	"kiro-cli": {
		Tool: "kiro-cli",
		// The userPromptSubmit probe is settled (gfiD research, kiro-cli
		// 2.28.0 live on demo node 1, 2026-10-15): the hook cannot block
		// (exit 1 and exit 2 both let the prompt through), so the seam only
		// warns the model (PromptWarnOnly) and the lane is not "hook".
		Vocabulary: Vocabulary{InTaxonomy: true},
		// SigV4-signed AWS endpoints (CodeWhisperer lineage); no base-URL /
		// BYOK surface exists on a live install — grounded negative.
		Proxy:       nil,
		Routability: RouteStatusNativeExempt,
		// Agent-JSON hooks (HookKiroAgentJSON): Observer's own agent, the
		// same entries merged into the user's global agents, and the CLI V3
		// standalone hooks file. `observer init` only until Observer's own
		// writer has a live run (the bindings are vendor-research grounded).
		Hook: HookSpec{Mechanism: HookKiroAgentJSON, AutoWired: true, PromptWarnOnly: true, Bindings: hookBindingsKiroCLI},
		// ~/.kiro/settings/mcp.json is the documented MCP surface; absent on
		// this install, shape unconfirmed — no writer until grounded.
		MCP:    nil,
		Native: NativeRails{},
		// Mode-dependent dual store (flat bundles + conversations_v2 sqlite);
		// local token counts were structurally 0/null in every capture.
		TokenTier: TokenTier{Best: "transcript", Gap: "no proxy tier (SigV4); local token counts 0/null in practice - credit metering only, not stored as tokens"},
		// Both layouts re-readable (adapter implements ReadTranscript);
		// `kiro-cli chat "<seed>"` positional seed verified live 2026-07-09;
		// launched non-proxied by `observer kiro` (SigV4 — nothing to route).
		Handoff: HandoffCapability{
			Transcript: TranscriptFull,
			Inject:     []InjectKind{InjectFile, InjectPrompt},
			Launch:     &LaunchSpec{Subcommand: "kiro"},
			Note:       "chat positional seed verified live; dual-store reader",
		},
		// Attach grounded 2026-07-24 (attach-all-launchers); PTY handoff only
		// — no prompt seeding, token capture path unchanged.
		Attach: &AttachSpec{Subcommand: "kiro"},
		// Native resume GROUNDED, live-verified 2026-07-24: `kiro-cli chat
		// --resume-id <id>` — the resume flag lives on the `chat` SUBCOMMAND. The
		// `observer kiro` launcher maps `--resume <id>` to it (composes the chat
		// subcommand + --resume-id).
		Resume: ResumeSpec{Kind: ResumeNative, Subcommand: "kiro", IDMechanism: "flag:--resume-id"},
		// AuthEnv zero — DELIBERATE exclusion: kiro-cli uses the AWS credential
		// chain (SigV4). Forwarding the AWS_* family (AWS_ACCESS_KEY_ID /
		// AWS_SECRET_ACCESS_KEY / AWS_SESSION_TOKEN / AWS_PROFILE / …) is a much
		// larger blast radius than a single provider key, so it is deferred, not
		// declared here.
		// Binary resolution + grounded install. Unix launcher resolves
		// "kiro-cli"; official install script (kiro.dev/docs/cli/
		// installation). Homebrew is explicitly NOT supported per vendor
		// docs. Windows hint is EXECUTABLE by a native-Windows daemon
		// (ConPTY, since 2026-07-04); post-install detection needs
		// Names.Windows (grounded 2026-09-02).
		//
		// Windows spelling GROUNDED 2026-09-02 against the MSI's own File
		// table (kiro-cli.exe / MainExecutable) and Directory table
		// (LocalAppDataFolder → Kiro-Cli): the installer lands a single
		// file at %LOCALAPPDATA%\Kiro-Cli\kiro-cli.exe, per-user, no
		// elevation. The installer's OWN printed "installed to C:\Program
		// Files\Kiro-Cli\" message is stale/wrong relative to the MSI
		// tables — both dirs are probed honestly rather than trusting one
		// source over the other; `where.exe kiro-cli` on this box: not
		// installed (unconfirmed live, MSI-table-grounded).
		Binary: &BinaryResolveSpec{
			Names: BinaryNames{
				Unix:    []string{"kiro-cli"},
				Windows: []string{"kiro-cli.exe"},
			},
			ProbeDirs: []ProbeDir{
				{OS: ProbeUnix, Rel: ".local/bin"},
				{OS: ProbeWindows, Rel: "AppData/Local/Kiro-Cli"},
				{OS: ProbeWindows, Rel: "Kiro-Cli", EnvRoot: "ProgramFiles"},
			},
			Installs: []InstallHint{
				{OS: "linux", Channel: "script", Argv: []string{"bash", "-lc", "curl -fsSL https://cli.kiro.dev/install | bash"}, Display: "curl -fsSL https://cli.kiro.dev/install | bash", Requires: []string{"curl", "unzip", "sha256sum"}},
				{OS: "darwin", Channel: "script", Argv: []string{"bash", "-lc", "curl -fsSL https://cli.kiro.dev/install | bash"}, Display: "curl -fsSL https://cli.kiro.dev/install | bash", Requires: []string{"curl", "shasum"}},
				{OS: "windows", Channel: "script", Argv: []string{"powershell", "-Command", "irm 'https://cli.kiro.dev/install.ps1' | iex"}, Display: "irm 'https://cli.kiro.dev/install.ps1' | iex"},
			},
		},
		// Model picker (B5). Grounded live 2026-08-08: `kiro-cli --model` does
		// not exist at the top level (`kiro-cli --help` has no --model row);
		// `kiro-cli chat --help` lists `--model <MODEL>  Current model to
		// use` — the flag exists ONLY on the `chat` subcommand, mirroring the
		// resume reality above (`kiroContinueSubcommand = "chat"` in
		// cmd/observer/kiro.go, ensureLeadingSubcommand). Lead: ["chat"]
		// composes the same leading subcommand.
		Model: ModelSpec{Kind: ModelArg, Flag: "--model", Lead: []string{"chat"}},
		// Sandbox filesystem-isolation row (B9). GROUNDED against
		// internal/adapter/kirocli/roots.go: sessionsSubpath (<home>/.kiro/sessions)
		// and sqliteDataSubdir (<home>/.local/share/kiro-cli on non-Windows). Both
		// bound rw; ~/.kiro also carries the AWS Kiro credential + crew state the
		// CLI itself needs.
		Sandbox: SandboxSpec{
			StateRW: []string{".kiro", ".local/share/kiro-cli"},
		},
		// GUI launch row (plan §2.2): the Kiro IDE is the same product line
		// as this row's CLI and shares ~/.kiro, so the spec rides here.
		GUI: &GUILaunchSpec{
			ID:      "kiro-ide",
			Label:   "Kiro",
			Surface: "ide",
			Binary: BinaryResolveSpec{
				// No collision with this row's CLI Names above: the CLI is
				// `kiro-cli`/`kiro-cli.exe`, the IDE shim is `kiro`.
				Names: BinaryNames{
					Unix:    []string{"kiro"},
					Windows: []string{"Kiro.exe"},
				},
				ProbeDirs: []ProbeDir{
					{OS: ProbeWindows, Rel: "AppData/Local/Programs/Kiro"},
				},
				Installs: []InstallHint{
					{OS: "windows", Channel: "winget", Argv: []string{"winget", "install", "--id", "Amazon.Kiro", "-e", "--source", "winget"}, Display: "winget install --id Amazon.Kiro -e --source winget"},
					{OS: "darwin", Channel: "brew", Argv: []string{"brew", "install", "--cask", "kiro"}, Display: "brew install --cask kiro"},
				},
				InstallNote: "no grounded Linux channel: kiro.dev/downloads offers a deb/AppImage download, " +
					"not a scriptable one-liner. (Distinct from the Kiro CLI's own cli.kiro.dev/install script " +
					"in this row's Binary above - that installs the CLI, not the IDE.)",
			},
			DarwinApp:      "Kiro",
			ProjectDirArgv: true,
			Wrap: WrapSpec{
				Kind: WrapNone,
				Reason: "AWS ships no BYOK / base-URL surface for Kiro at all - four open vendor issues, and " +
					"a third-party `kiro-gateway` proxy exists precisely because of the gap (inventory §2.8 / " +
					"§4.2; this row's Routability is native_exempt). Launch yes, wrap no; capture rides " +
					"~/.kiro/sessions.",
			},
			Hosts:    []string{"kiro-cli"},
			Grounded: true,
			Note: "Windows layout grounded on this box 2026-09-03: " +
				"%LOCALAPPDATA%\\Programs\\Kiro\\Kiro.exe (+ bin\\{kiro,kiro.cmd}, which grounds both the unix " +
				"shim stem and `kiro <dir>` - the inventory left the IDE binary name \"to ground\"). macOS " +
				"bundle \"Kiro.app\" grounded from the Homebrew cask `kiro`; winget id `Amazon.Kiro` grounded " +
				"from a live `winget search --exact` the same day.",
		},
	},
	"grok": {
		Tool:       "grok",
		Vocabulary: Vocabulary{InTaxonomy: true},
		// FIX-7 (phase-2 review): Grok Build's UserPromptSubmit hook
		// has a prompt-submit event but cannot block — the vendor's
		// own docs name PreToolUse "the only blocking event" (contract
		// §2.3) and the documented base payload doesn't even carry a
		// prompt field. The proxy lane (already routed today, opt-in
		// --proxy) is Grok's only realistic path to prompt-submit
		// intervention.
		PromptLane: PromptLaneProxyOnly,
		// LIVE-VERIFIED 2026-07-09: grok's CLI chat proxy base URL is
		// overridable via the GROK_CLI_CHAT_PROXY_BASE_URL env var (the env
		// form of the `grok agent --cli-chat-proxy-base-url` flag; the
		// top-level `grok` rejects that flag as an argument, but DOES honor the
		// env var with `-p/--single`). Setting
		// GROK_CLI_CHAT_PROXY_BASE_URL=http://127.0.0.1:8820/up/grok/v1 routed a
		// live `grok -p` turn through the /up/grok upstream ([proxy.upstreams]
		// grok = https://cli-chat-proxy.grok.com): grok fetched models from
		// /up/grok/v1/models and its OpenAI-Responses turn landed an api_turns
		// row (id 23025, provider=openai, model grok-4.5, 11394/29 tokens,
		// HTTP 200). The per-model base_url is https://cli-chat-proxy.grok.com/v1
		// (api_backend:"responses") — so the /v1 belongs in the override.
		// Routable now, and `observer grok` (2026-08-21) gained an opt-in
		// `--proxy` flag that injects GROK_CLI_CHAT_PROXY_BASE_URL at this
		// exact /up/grok/v1 upstream. The launcher stays non-proxied by
		// DEFAULT (routing is opt-in, not automatic). PROMOTED 2026-08-21:
		// a live `observer grok --proxy -p` turn landed api_turns through
		// the flag (provider=openai, model grok-4.6-build, 12155/24 tokens,
		// HTTP 200) — the checklist §10.1f bar.
		Proxy: &ProxyRoute{
			ClientAuth: ClientAuthPathToken,
			Kind:       RouteLauncher,
			EnvVar:     "GROK_CLI_CHAT_PROXY_BASE_URL",
			Suffix:     "/up/grok/v1",
			Launcher:   "observer grok --proxy",
			LaunchFlag: "--proxy",
			Note:       "Opt-in via the --proxy launcher flag; routes at the grok lane (cli-chat-proxy.grok.com, built in; a [proxy.upstreams] grok entry overrides it), not the default lane.",
			// The live-verified lane above (api_turns 23025, then the
			// launcher's own turn 2026-08-21): host root, the /v1 rides the
			// client's base URL. Built in so `--proxy` never depends on a
			// hand-written [proxy.upstreams] entry (Sol A5-02 follow-up).
			Lane: &ProxyLane{ID: "grok", DefaultUpstream: "https://cli-chat-proxy.grok.com"},
		},
		Routability: RouteStatusRoutableNow,
		// updates.jsonl shows hook_execution records (ACP pre_tool_use fired
		// live) — a real upstream hook system, but no observer receiver is
		// wired; honest none.
		Hook: HookSpec{Mechanism: HookGrokHooksJSON, AutoWired: true, Bindings: hookBindingsGrok},
		// events.jsonl shows an MCP client connecting (mcp_server_connected,
		// 25 tools), but no grounded config-writer surface — nil until then.
		MCP:    nil,
		Native: NativeRails{},
		// Global ~/.grok/logs/unified.jsonl inference_done lines carry
		// {prompt, cached_prompt, completion, reasoning} tokens WITH a `sid`
		// correlation key (no timestamp heuristics). prompt is GROSS
		// (cached ⊂ prompt, live-proven) — the adapter nets it.
		TokenTier: TokenTier{Best: "transcript", Gap: "no cache-creation split; session-bundle counts are cumulative-only (unified.jsonl is the split source)"},
		// chat_history.jsonl re-readable (ReadTranscript); positional seed
		// (`grok "<seed>"`) verified live 2026-07-09 → `observer grok`.
		Handoff: HandoffCapability{
			Transcript: TranscriptFull,
			Inject:     []InjectKind{InjectFile, InjectPrompt},
			Launch:     &LaunchSpec{Subcommand: "grok"},
			Note:       "positional seed verified live; tool-exec capture still owed (plan-agent default)",
		},
		// Attach grounded 2026-07-24 (attach-all-launchers); PTY handoff only
		// — no prompt seeding, token capture path unchanged.
		Attach: &AttachSpec{Subcommand: "grok"},
		// Native resume GROUNDED, live-verified 2026-07-24: `grok --resume <id>`
		// reattaches the real session; id is raw. The `observer grok` launcher
		// maps `--resume <id>` to it.
		Resume: ResumeSpec{Kind: ResumeNative, Subcommand: "grok", IDMechanism: "flag:--resume"},
		// Credential env forwarded across the attach socket. Upstream-verified
		// (docs.x.ai/build/overview): XAI_API_KEY is grok's documented
		// headless / non-browser auth key. NAMES only.
		AuthEnv: []string{"XAI_API_KEY"},
		// Binary resolution + grounded installs. Unix launcher resolves
		// "grok"; npm @xai-official/grok (any OS) + the official install
		// script (docs.x.ai/build/overview).
		Binary: &BinaryResolveSpec{
			// npm JS bin: Windows install lays down a `.cmd` shim (+
			// .ps1/POSIX-shell forms), never an `.exe` — see the
			// command-code row's Binary comment for the long-form
			// rationale.
			// grounded 2026-09-02: x.ai/cli/install.ps1 places grok.exe at
			// %USERPROFILE%\.grok\bin\grok.exe (the script also drops an
			// agent.exe alias to the same binary, not adopted here — see
			// the ProbeDirs note below).
			Names: BinaryNames{
				Unix:    []string{"grok"},
				Windows: []string{"grok.exe", "grok.cmd", "grok"},
			},
			ProbeDirs: []ProbeDir{
				{OS: ProbeUnix, Rel: ".grok/bin"},
				{OS: ProbeWindows, Rel: ".grok/bin"},
			},
			// Minimum host runtime, grounded 2026-10-04 from the npm registry
			// (`npm view <pkg> engines`): @xai-official/grok 1.0.46 declares engines.node.
			Runtime: &RuntimeRequirement{Runtime: RuntimeNode, MinVersion: "20", Product: "Grok CLI", Source: "npm registry engines.node, @xai-official/grok 1.0.46, read 2026-10-04"},
			Installs: []InstallHint{
				{OS: "", Channel: "npm", Argv: []string{"npm", "install", "-g", "@xai-official/grok"}, Display: "npm install -g @xai-official/grok"},
				{OS: "linux", Channel: "script", Argv: []string{"bash", "-lc", "curl -fsSL https://x.ai/cli/install.sh | bash"}, Display: "curl -fsSL https://x.ai/cli/install.sh | bash", Requires: []string{"curl"}},
				{OS: "darwin", Channel: "script", Argv: []string{"bash", "-lc", "curl -fsSL https://x.ai/cli/install.sh | bash"}, Display: "curl -fsSL https://x.ai/cli/install.sh | bash", Requires: []string{"curl"}},
				{OS: "windows", Channel: "script", Argv: []string{"powershell", "-Command", "irm https://x.ai/cli/install.ps1 | iex"}, Display: "irm https://x.ai/cli/install.ps1 | iex"},
			},
		},
		// Model picker (B5). Grounded live 2026-08-08: `grok --help` lists
		// `-m, --model <MODEL>  Model ID to use`. The `observer grok` launcher
		// is DisableFlagParsing + launcherArgsOrDone (B6), so a forwarded
		// `--model <value>` reaches the grok binary unmodified. Catalog: xAI
		// (the CLI fetches its model list from grok's own chat proxy, above).
		Model: ModelSpec{Kind: ModelArg, Flag: "--model", Catalog: ModelCatalog{Kind: ModelCatalogVendor, Providers: []string{"xai"}}},
		// Headless one-shot, LIVE-GROUNDED 2026-08-22 (arena headless-drive
		// arc): `grok -p <prompt> --output-format json --always-approve`
		// prints a single JSON envelope keyed text/sessionId/usage/
		// total_cost_usd (claude-shaped but different keys). A real drive
		// created answer.txt and replied DONE; a second drive returned
		// sessionId + full usage without any proxy lane.
		Headless: &HeadlessSpec{
			PromptFlag: "-p",
			OutputArgs: []string{"--output-format", "json"},
			Result:     HeadlessResultGrokJSON,
			// --always-approve is the grounded drive's bypass (OSH-R-005);
			// no lane that keeps grok's own checks on has been driven.
			Permissions: map[HeadlessPermLane][]string{HeadlessPermBypass: {"--always-approve"}},
		},
		// Sandbox filesystem-isolation row (B9). GROUNDED against
		// internal/adapter/grok/adapter.go defaultRoots (<home>/.grok/sessions and
		// <home>/.grok/logs). ~/.grok is bound rw as one dir.
		Sandbox: SandboxSpec{NeedsWin32k: true, ProviderEnv: []string{"XAI_API_KEY"}, StateRW: []string{".grok"}},
	},
	"kimi-code": {
		Tool: "kimi-code",
		// PromptLaneHook since T-378: the UserPromptSubmit gate blocked a
		// fake-token prompt live (kimi 2.1.1, demo node 1, 2026-10-07).
		PromptLane: PromptLaneHook,
		Vocabulary: Vocabulary{InTaxonomy: true},
		// Live wire traces show an openai-compat endpoint (provider:openai,
		// gpt-4o) configured in ~/.kimi-code/config.toml — a NEVER-READ file
		// (plaintext API key). The [providers.openai] block carries an
		// OpenAI-shaped sk-proj key and NO base_url, so its implicit default
		// host is api.openai.com — the fixed OpenAI upstream the proxy routes
		// to.
		// PROMOTED — LIVE-VERIFIED 2026-07-09 (operator-approved probe): the
		// guarded, ADDITIVE writer proxyroute.RegisterKimiCode added base_url =
		// http://127.0.0.1:8820/v1 under [providers.openai] (.bak +
		// refuse-foreign + never a key), then `kimi -p "…"` (default_model
		// openai/gpt-4o) routed through the proxy and landed an api_turns row
		// (id 23075, provider=openai, model gpt-4o-2024-08-06, 11181/2 tokens,
		// HTTP 200). Proxy now drives the config-lane route; init applies it via
		// the RegisterKimiCode writer (dispatched on Kind).
		Proxy: &ProxyRoute{
			ClientAuth:           ClientAuthPathToken,
			SharesCredentialFile: true, CredentialFileReason: routeCredKimiCode,
			Kind:     RouteConfigFile,
			EnvVar:   "",
			Suffix:   "/v1",
			Launcher: "observer kimi",
			Note:     "routes via base_url under [providers.openai] in ~/.kimi-code/config.toml (proxyroute.RegisterKimiCode, additive, never a key); implicit host was api.openai.com so the fixed OpenAI upstream applies. Live-verified 2026-07-09 (api_turns 23075, gpt-4o-2024-08-06)",
			ForeignLane: &ForeignProviderLane{
				LiveVerified: true,
				Note:         "the managed daemon can route the ACTIVE provider entry (default_model's provider, type openai, e.g. [providers.baseten]) at a third-party https host through a proxy /up/<id> lane, keeping that host as the lane upstream (proxyroute.RegisterKimiCodeLane). Live-verified 2026-10-18 on demo node 1 (RETEST5 F3): `kimi -p` through the route-inference-baseten-co lane landed 1 api_turns row with a Baseten chatcmpl request id (api_turns has no lane column, so the lane itself is proven by the config URL, the proxy's lane set and the row existing at all)",
			},
		},
		// ProxyProbe PERSISTS after promotion: it is the config-lane WRITER
		// BINDING init uses to apply the (now verified) route on a machine
		// whose ~/.kimi-code/config.toml is not yet routed. Proxy above is
		// the verified route; this is how init writes it.
		ProxyProbe: &ProxyRoute{
			SharesCredentialFile: true, CredentialFileReason: routeCredKimiCode,
			Kind:     RouteConfigFile,
			Launcher: "observer kimi",
			Note:     "proxyroute.RegisterKimiCode adds base_url under [providers.openai] in ~/.kimi-code/config.toml (additive, never a key)",
		},
		Routability: RouteStatusRoutableNow,
		// T-378 (D-270): the [[hooks]] tables of ~/.kimi-code/config.toml,
		// written by the credential-file writer (internal/hook
		// register_kimi.go). Both registered bindings went live on demo node
		// 1 (2026-10-07), so `observer start` auto-registers it through the
		// live gate (autoRegisterLiveGate) as well as `observer init`.
		Hook: HookSpec{
			Mechanism: HookKimiCodeTOML, AutoWired: true, Bindings: hookBindingsKimiCode,
			HooksShareCredentialFile: true, CredentialFileReason: credFileKimiCode,
		},
		// MCP client exists (mcp__* names in tools.set_active_tools), but the
		// only config surface is the never-read config.toml — no writer until
		// a guarded additive path is grounded.
		MCP:    nil,
		Native: NativeRails{},
		// wire.jsonl usage.record events: {inputOther (already NET of cache),
		// output, inputCacheRead, inputCacheCreation}. No reasoning split.
		TokenTier: TokenTier{Best: "transcript", Gap: "no reasoning split; counts self-reported (wire-trace usage.record)"},
		// wire.jsonl folds prompts/assistant text/tool bodies (ReadTranscript
		// on both lanes), but there is NO seed lane — `-p` prints and exits,
		// the TUI takes no initial-prompt flag (live-verified 2026-07-09) —
		// so the launch is DocAssisted (hermes precedent): `observer kimi
		// --continue-from` writes the doc + opens the TUI.
		Handoff: HandoffCapability{
			Transcript: TranscriptFull,
			Inject:     []InjectKind{InjectFile},
			Launch:     &LaunchSpec{Subcommand: "kimi", Mode: LaunchDocAssisted},
			Note:       "no seed lane (-p prints+exits; TUI seedless) - doc-assisted launch",
		},
		// Attach grounded 2026-07-24 (attach-all-launchers); PTY handoff only
		// — no prompt seeding, token capture path unchanged. DocAssisted only
		// gates --continue-from seeding (incompatible with attach); plain attach
		// opens the TUI seedless.
		Attach: &AttachSpec{Subcommand: "kimi"},
		// Native resume GROUNDED, live-verified 2026-07-24: `kimi --session <id>`
		// (short `-S`) reattaches the real session, but the id MUST be the
		// PREFIXED form `session_<uuid>` — a bare uuid HARD-FAILS. Our adapter
		// already stores the SessionID in exactly that prefixed form (the
		// `session_<uuid>` directory component — internal/adapter/kimicode/
		// paths.go::sessionIDFromPath), so the `observer kimi` launcher's
		// ensure-prefix transform is idempotent (a stored id passes through). The
		// launcher maps `--resume <id>` to it.
		Resume: ResumeSpec{Kind: ResumeNative, Subcommand: "kimi", IDMechanism: "flag:--session"},
		// AuthEnv zero: kimi-code reads its key from [providers.*] in
		// ~/.kimi-code/config.toml — file auth, no grounded runtime key env.
		// Binary resolution + grounded installs. Unix launcher resolves
		// "kimi". Grounded 2026-08-07 against Moonshot AI's own getting-
		// started page (moonshotai.github.io/kimi-code/en/guides/
		// getting-started.html) — npm `@moonshot-ai/kimi-code` (registry-
		// confirmed: registry.npmjs.org/@moonshot-ai/kimi-code returns 200
		// with published versions) + the official install script, whose
		// body was fetched live and self-identifies as the "kimi-code
		// installer for macOS and Linux" (cdn.kimi.com, redirected from the
		// documented code.kimi.com URL) + its Windows PowerShell twin.
		Binary: &BinaryResolveSpec{
			// npm JS bin: Windows install lays down a `.cmd` shim (+
			// .ps1/POSIX-shell forms), never an `.exe` — see the
			// command-code row's Binary comment for the long-form
			// rationale.
			// grounded 2026-09-02: the install.ps1 (302 from
			// code.kimi.com to cdn.kimi.com) places kimi.exe at
			// %USERPROFILE%\.kimi-code\bin\kimi.exe (SHA256-verified),
			// renaming a legacy uv-installed `kimi` stub to
			// kimi-legacy.exe out of the way.
			Names: BinaryNames{
				Unix:    []string{"kimi"},
				Windows: []string{"kimi.exe", "kimi.cmd", "kimi"},
			},
			ProbeDirs: []ProbeDir{
				{OS: ProbeUnix, Rel: ".kimi-code/bin"},
				{OS: ProbeWindows, Rel: ".kimi-code/bin"},
			},
			// Minimum host runtime, grounded 2026-10-04 from the npm registry
			// (`npm view <pkg> engines`): @moonshot-ai/kimi-code 2.1.1 declares engines.node.
			Runtime: &RuntimeRequirement{Runtime: RuntimeNode, MinVersion: "22.19.0", Product: "Kimi Code", Source: "npm registry engines.node, @moonshot-ai/kimi-code 2.1.1, read 2026-10-04"},
			Installs: []InstallHint{
				{OS: "", Channel: "npm", Argv: []string{"npm", "install", "-g", "@moonshot-ai/kimi-code"}, Display: "npm install -g @moonshot-ai/kimi-code"},
				{OS: "linux", Channel: "script", Argv: []string{"bash", "-lc", "curl -fsSL https://code.kimi.com/kimi-code/install.sh | bash"}, Display: "curl -fsSL https://code.kimi.com/kimi-code/install.sh | bash", Requires: []string{"curl", "tar", "shasum|sha256sum"}},
				{OS: "darwin", Channel: "script", Argv: []string{"bash", "-lc", "curl -fsSL https://code.kimi.com/kimi-code/install.sh | bash"}, Display: "curl -fsSL https://code.kimi.com/kimi-code/install.sh | bash", Requires: []string{"curl", "tar", "shasum|sha256sum"}},
				{OS: "windows", Channel: "script", Argv: []string{"powershell", "-Command", "irm https://code.kimi.com/kimi-code/install.ps1 | iex"}, Display: "irm https://code.kimi.com/kimi-code/install.ps1 | iex"},
			},
		},
		// Model picker (B5). Grounded live 2026-08-08: `kimi --help` lists
		// `-m, --model <model>  LLM model alias to use for this invocation.
		// Defaults to default_model in config.toml`, on the top-level
		// command (not subcommand-gated, unlike Resume's --session). The
		// `observer kimi` launcher is DisableFlagParsing + launcherArgsOrDone
		// (B6), so a forwarded `--model <value>` reaches the kimi binary
		// unmodified.
		Model: ModelSpec{Kind: ModelArg, Flag: "--model"},
		// Sandbox filesystem-isolation row (B9). GROUNDED against
		// internal/adapter/kimicode/adapter.go defaultRoots (<home>/.kimi-code/
		// sessions, or $KIMI_CODE_HOME) — the same layout on Linux, macOS and
		// Windows. ~/.kimi-code also holds config.toml (the openai-compat provider
		// credentials the adapter NEVER reads but kimi itself needs), so the whole
		// dir is bound rw.
		Sandbox: SandboxSpec{NeedsWin32k: true, StateRW: []string{".kimi-code"}},
	},
	"crush": {
		Tool:       "crush",
		Vocabulary: Vocabulary{InTaxonomy: true},
		// FIX-7 (phase-2 review): Crush documents exactly one hook,
		// PreToolUse ("Crush currently supports just one hook… with
		// plans to support the full gamut", contract §2.4) — no
		// prompt-submit event at all. The proxy lane (already routed
		// today) is Crush's only path to prompt-submit intervention.
		PromptLane: PromptLaneProxyOnly,
		// Crush providers support custom base_url incl. an `anthropic` type —
		// a real proxy lane. The provider config lives in crush.json alongside
		// literal API keys (never-read/never-write file); providers.openai
		// carried an OpenAI-shaped sk-proj key and NO base_url, so its implicit
		// default host is api.openai.com — the fixed OpenAI upstream.
		// PROMOTED — LIVE-VERIFIED 2026-07-09 (operator-approved probe): the
		// guarded, ADDITIVE writer proxyroute.RegisterCrush set
		// providers.openai.base_url = http://127.0.0.1:8820/v1 (.bak +
		// refuse-foreign + never a key) in the live Windows-side config
		// (/mnt/c/Users/.../AppData/Local/crush/crush.json, via CRUSH_CONFIG —
		// the Linux crush binary ignores CRUSH_CONFIG and has no config here).
		// Since surface-gap S-17 (lane w2-g) the route writer resolves the
		// file the way Crush does, $CRUSH_GLOBAL_CONFIG/crush.json, and no
		// longer reads CRUSH_CONFIG, which Crush itself never read.
		// A `crush run` turn driven from the Windows crush.cmd reached WSL's
		// :8820 over localhost forwarding and landed api_turns rows (id 23081
		// gpt-5.4-mini 6613/20 + id 23080 gpt-5.4-nano title call,
		// provider=openai, HTTP 200). Proxy now drives the config-lane route;
		// init applies it via the RegisterCrush writer (dispatched on Kind).
		Proxy: &ProxyRoute{
			ClientAuth:           ClientAuthPathToken,
			SharesCredentialFile: true, CredentialFileReason: routeCredCrush,
			Kind:   RouteProviderJSON,
			EnvVar: "",
			Suffix: "/v1",
			Note:   "routes via providers.openai.base_url in crush.json (proxyroute.RegisterCrush, additive, never a key); implicit host was api.openai.com so the fixed OpenAI upstream applies; no observer launcher (init/writer applies it). Live-verified 2026-07-09 via the Windows crush.cmd → WSL :8820 (api_turns 23081/23080)",
		},
		// ProxyProbe PERSISTS after promotion: it is the config-lane WRITER
		// BINDING init uses to apply the (now verified) route on a machine
		// whose crush.json is not yet routed. Proxy above is the verified
		// route; this is how init writes it.
		ProxyProbe: &ProxyRoute{
			SharesCredentialFile: true, CredentialFileReason: routeCredCrush,
			Kind: RouteProviderJSON,
			Note: "proxyroute.RegisterCrush sets providers.openai.base_url in crush.json (additive, never a key)",
		},
		Routability: RouteStatusRoutableNow,
		Hook:        HookSpec{Mechanism: HookCrushJSON, AutoWired: true, Bindings: hookBindingsCrush, HooksShareCredentialFile: true, CredentialFileReason: credFileCrush},
		// MCP client exists, but its config also lives in crush.json — same
		// guarded-write constraint as the proxy lane.
		MCP:    nil,
		Native: NativeRails{},
		// Project-local .crush/crush.db; ONE session-level row. The
		// pre-computed cost is session-cumulative, but Crush OVERWRITES
		// prompt/completion_tokens with the last step's usage, so the
		// adapter reports tokens only for a one-step session
		// (docs/crush-adapter.md, corrected 2026-09-27).
		TokenTier: TokenTier{Best: "sqlite", Gap: "session-level only: the cost is cumulative, but token counts are reported only for one-step sessions; no cache/reasoning breakdown", SessionCumulative: true, ReportsCost: true},
		// messages.parts carry full text/reasoning/tool bodies; NO seed lane
		// (upstream charmbracelet/crush#1791, still OPEN 2026-10-03: the root
		// command accepts positional args but ignores them, per
		// internal/cmd/root.go). So the launch is DOC-ASSISTED (2026-10-03,
		// terminal-picker coverage): `observer crush`, which already ensured
		// the crush.json route before every launch, now also writes the
		// handover doc for --continue-from and opens the TUI in the source
		// project. Native resume (`crush -s/--session <id>`, root.go) is
		// vendor-source grounded but NOT live-verified, so Resume stays zero.
		Handoff: HandoffCapability{
			Transcript: TranscriptFull,
			Inject:     []InjectKind{InjectFile},
			Launch:     &LaunchSpec{Subcommand: "crush", Mode: LaunchDocAssisted},
			Note:       "no interactive-seed lane (upstream #1791): launch writes the handover doc and opens the crush TUI",
		},
		Attach: &AttachSpec{Subcommand: "crush"},
		// Binary resolution + grounded installs (2026-10-03, from the
		// github.com/charmbracelet/crush README "Installation" section):
		// npm `@charmland/crush` (every OS), the vendor's own Homebrew tap
		// formula `charmbracelet/tap/crush` (crush is NOT in homebrew-core:
		// formulae.brew.sh/api/formula/crush.json 404s), and winget
		// `charmbracelet.crush`. Scoop needs a `scoop bucket add charm ...`
		// first (two commands, not one argv) and the apt/yay/nix/pkg
		// channels are distro-specific, so none of those is offered. There
		// is no curl|sh script. Windows: winget lays down crush.exe; a global
		// npm install writes the crush.cmd shim. The tap formula is offered
		// on macOS only: an OS-specific hint outranks the any-OS npm hint in
		// the guided-install plan, and Homebrew is rarely present on Linux,
		// so Linux falls through to npm.
		Binary: &BinaryResolveSpec{
			Names: BinaryNames{
				Unix:    []string{"crush"},
				Windows: []string{"crush.exe", "crush.cmd"},
			},
			Installs: []InstallHint{
				{OS: "", Channel: "npm", Argv: []string{"npm", "install", "-g", "@charmland/crush"}, Display: "npm install -g @charmland/crush"},
				{OS: "darwin", Channel: "brew", Argv: []string{"brew", "install", "charmbracelet/tap/crush"}, Display: "brew install charmbracelet/tap/crush"},
				{OS: "windows", Channel: "winget", Argv: []string{"winget", "install", "--id", "charmbracelet.crush", "-e", "--source", "winget"}, Display: "winget install --id charmbracelet.crush -e --source winget"},
			},
		},
		// Sandbox filesystem-isolation row (B9). GROUNDED against
		// internal/adapter/crush/discover.go stateDirsForHome
		// (<home>/.local/share/crush) plus the global config
		// ($HOME/.config/crush/crush.json, plugins/crush/README.md). The
		// project-local <repo>/.crush store needs no row: it lives inside the
		// workspace, which the sandbox already binds rw.
		Sandbox: SandboxSpec{
			StateRW: []string{".config/crush", ".local/share/crush"},
		},
	},
	"devin": {
		Tool: "devin",
		// FIX-7 (phase-2 review) promoted this from
		// PromptLaneProbeRequired; Part B item 2 (phase-3a, 2026-09-07)
		// wired it after re-fetching docs.devin.ai/desktop/cascade/hooks
		// live: Windsurf/Devin Desktop Cascade's pre_user_prompt exit 2
		// blocks, and the vendor is explicit that show_output does NOT
		// apply to this event — no user-visible message channel at all
		// (no JSON reply either), so ask-once degrades to a hard block
		// per the conformance row (CanBlock:true, CanAsk:false). No
		// session_id field is documented for this event; trajectory_id
		// (the conversation identifier) is used as the reconsider-once
		// scoping key instead. Registered at ~/.codeium/windsurf/hooks.json
		// (HookCascadeJSON) — its OWN shape ({"hooks":{"pre_user_prompt":
		// [{"command":…,"powershell":…}]}}), distinct from every other
		// hooks.json writer in this repo.
		PromptLane: PromptLaneHook,
		Vocabulary: Vocabulary{InTaxonomy: true},
		// Devin is ACTIVE. The note records the DEPRECATED NAME this row
		// answers to: Cognition renamed Windsurf to Devin Desktop on
		// 2026-06-02, and the Windsurf name survives as an install-path /
		// shim alias only — see productLifecycles["windsurf"], which is
		// the lifecycle carrier for the alias (Adapter: "devin").
		LifecycleNote: "answers to the DEPRECATED name \"windsurf\": Cognition renamed Windsurf to Devin Desktop " +
			"on 2026-06-02 and folded the IDE and the agent into one install, so the Windsurf name is an " +
			"alias (install path + `windsurf` shim), not a separate product. See " +
			"productLifecycles[\"windsurf\"] (deprecated, serviced by this row). Devin itself is active.",
		// No base-URL override exists — the CLI talks to Cognition's own
		// Windsurf backend (only an HTTP-proxy setting). No observer-routed
		// turn is possible today.
		Proxy:       nil,
		Routability: RouteStatusNativeExempt,
		// `.devin/hooks.v1.json` is explicitly Claude-Code-compatible but
		// UNWIRED in the shipped Devin CLI (live 3000.1.27) — that surface
		// stays honest-none. The mechanism below targets a DIFFERENT,
		// now-grounded surface instead: Devin Desktop (Cascade)'s own
		// pre_user_prompt hooks.json, distinct from the CLI's unwired file.
		// The Cascade hook file is the Devin Desktop / Windsurf surface.
		// The devin CLI reads its own Claude-shaped hooks from
		// ~/.config/devin/config.json (vendor docs, 2026-10-02), which no
		// writer registers yet: on demo node 1 a devin CLI prompt went
		// through unseen (prompt-guard audit, node 1 findings).
		Hook: HookSpec{
			Mechanism: HookCascadeJSON, AutoWired: true,
			PromptScope: "Devin Desktop / Windsurf only (Cascade pre_user_prompt). Devin CLI sessions have no registered prompt hook, so the rule flags them after send.",
			Bindings:    hookBindingsDevin,
		},
		// MCP client only (reads .devin/ config). The registration format IS
		// now grounded (`.devin-plugin/plugin.json` + root `mcp_config.json`,
		// coverage wave A 2026-07-31 — see plugins/devin/); distribution is
		// the plugins channel, and no `observer init` writer is built, so the
		// capability stays nil.
		MCP:    nil,
		Native: NativeRails{},
		// Per-message metadata.metrics in sessions.db (input/output/cache
		// fields + ttft). CORRECTED 2026-09-03 against a live, signed-in
		// Devin Desktop 2.3.15 run: cache_read_tokens IS populated, and
		// input_tokens is NET of it (input + cache_read == the node's own
		// num_tokens_preceding), so no netting is needed. cache_creation
		// is still null in every captured row.
		TokenTier: TokenTier{Best: "sqlite", Gap: "cache_creation null in all captured rows; no reasoning-token split (thinking folded into output)", GenerationTiming: GenTimingNative}, // metrics.total_time_ms
		// ReadTranscript re-walks the message_nodes main chain (DB lane).
		// Positional seed contract operator-verified on a real TTY 2026-07-09
		// (`devin -- "<prompt>"`, clap last-only positional after the `--`
		// separator) → `observer devin`.
		Handoff: HandoffCapability{
			Transcript: TranscriptFull,
			Inject:     []InjectKind{InjectFile, InjectPrompt},
			Launch:     &LaunchSpec{Subcommand: "devin"},
			Note:       "positional seed contract operator-verified on a real TTY 2026-07-09 (`devin -- \"<prompt>\"`, clap last-only positional after the `--` separator); launcher `observer devin` seed-only/non-proxied (native_exempt, no base-URL knob)",
		},
		// Attach grounded 2026-07-24 (attach-all-launchers); PTY handoff only
		// — no prompt seeding, token capture path unchanged.
		Attach: &AttachSpec{Subcommand: "devin"},
		// Native resume GROUNDED, live-verified 2026-07-24: `devin --resume <id>`
		// reattaches the real session; id is a human MNEMONIC (e.g.
		// `noon-quince`) — the sessions.db primary key == our SessionID. The
		// `observer devin` launcher maps `--resume <id>` to it.
		Resume: ResumeSpec{Kind: ResumeNative, Subcommand: "devin", IDMechanism: "flag:--resume"},
		// AuthEnv zero: devin talks to Cognition's own backend with no grounded
		// key env (file/OAuth auth) — no credential-env to forward.
		// Binary resolution + grounded install. Unix launcher resolves
		// "devin"; official install script (devin.ai/cli). CORRECTED
		// 2026-09-02 — a Windows channel DOES exist: docs.devin.ai/cli
		// documents `irm https://static.devin.ai/cli/setup.ps1 | iex`
		// verbatim (incl. "Do not run this in Git Bash or CMD"), and the
		// winget manifest CognitionAI.DevinCLI is vendor-published
		// (NestedInstallerType: portable, depends on Git.Git) — the prior
		// "third-party, not shipped" note was wrong.
		Binary: &BinaryResolveSpec{
			Names: BinaryNames{
				Unix:    []string{"devin"},
				Windows: []string{"devin.exe"},
			},
			ProbeDirs: []ProbeDir{
				{OS: ProbeUnix, Rel: ".local/bin"},
				// setup.ps1: $EntryExe = …\devin\cli\bin\devin.exe.
				{OS: ProbeWindows, Rel: "AppData/Local/devin/cli/bin"},
			},
			Installs: []InstallHint{
				{OS: "linux", Channel: "script", Argv: []string{"bash", "-lc", "curl -fsSL https://cli.devin.ai/install.sh | bash"}, Display: "curl -fsSL https://cli.devin.ai/install.sh | bash", Requires: []string{"curl", "tar", "sha256sum|shasum"}},
				{OS: "darwin", Channel: "script", Argv: []string{"bash", "-lc", "curl -fsSL https://cli.devin.ai/install.sh | bash"}, Display: "curl -fsSL https://cli.devin.ai/install.sh | bash", Requires: []string{"curl", "tar", "sha256sum|shasum"}},
				{OS: "windows", Channel: "script", Argv: []string{"powershell", "-Command", "irm https://static.devin.ai/cli/setup.ps1 | iex"}, Display: "irm https://static.devin.ai/cli/setup.ps1 | iex"},
				{OS: "windows", Channel: "winget", Argv: []string{"winget", "install", "--id", "CognitionAI.DevinCLI", "-e", "--source", "winget"}, Display: "winget install --id CognitionAI.DevinCLI -e --source winget"},
			},
		},
		// Model picker (B5). Grounded live 2026-08-08: `devin --help` lists
		// `--model <MODEL>  Model to use (e.g. "claude-sonnet-4",
		// "claude-opus-4.6", "opus", "codex") [env: DEVIN_MODEL=]`. The
		// `observer devin` launcher is DisableFlagParsing + launcherArgsOrDone
		// (B6), so a forwarded `--model <value>` reaches the devin binary
		// unmodified.
		Model: ModelSpec{Kind: ModelArg, Flag: "--model", Known: []string{"claude-sonnet-4", "claude-opus-4.6", "opus", "codex"}},
		// Sandbox filesystem-isolation row (B9). Not grounded in v1 (plan
		// amendment A3) — only claude-code has a verified state-dir bind
		// list; every other launchable tool carries the honest zero note
		// until a per-tool probe grounds its StateRW/StateRO paths.
		Sandbox: SandboxSpec{Note: "state dirs not yet grounded - not sandbox-launchable"},
		// GUI launch row (plan §2.2): Devin Desktop is the rebranded
		// Windsurf IDE and shares ~/.devin with this row's CLI. See
		// productLifecycles["windsurf"] for the deprecated alias.
		GUI: &GUILaunchSpec{
			ID:      "devin-desktop",
			Label:   "Devin Desktop (Windsurf)",
			Surface: "ide",
			Binary: BinaryResolveSpec{
				// No collision with this row's CLI Names above (`devin`).
				Names: BinaryNames{
					Unix:    []string{"windsurf", "devin-desktop"},
					Windows: []string{"Windsurf.exe"},
				},
				ProbeDirs: []ProbeDir{
					{OS: ProbeWindows, Rel: "AppData/Local/Programs/Windsurf"},
				},
				Installs: []InstallHint{
					{OS: "darwin", Channel: "brew", Argv: []string{"brew", "install", "--cask", "devin-desktop"}, Display: "brew install --cask devin-desktop"},
				},
				InstallNote: "no Windows or Linux channel offered on purpose. A winget package " +
					"`Codeium.Windsurf` exists (grounded live 2026-09-03) but it carries the DEPRECATED " +
					"Windsurf identity under the pre-rename vendor name, and whether it tracks post-rename " +
					"Devin Desktop builds was not verified - advertising it could install the sunset product " +
					"(docs/harness-lifecycle-policy.md). Use the vendor download at devin.ai/desktop.",
			},
			DarwinApp:      "Devin",
			ProjectDirArgv: true,
			Wrap: WrapSpec{
				Kind: WrapNone,
				Reason: "no DEVIN_BASE_URL or any documented base-URL knob for the desktop lane (this row's " +
					"Routability is native_exempt; inventory §2.10 / §4.2). Launch yes, wrap no; the bundled " +
					"devin.exe lane writes the CLI store this row's watcher already reads - CORRECTED " +
					"and VERIFIED LIVE 2026-09-03: the store is %APPDATA%\\Devin\\cli\\sessions.db (the " +
					"same NTFS directory as the CLI's %APPDATA%\\devin\\cli, schema-identical at " +
					"refinery version 16), NOT ~/.devin, which holds only argv.json + extensions. No root " +
					"widening was needed; the live daemon captured the desktop run through the existing " +
					"root. Sessions the desktop opens are stamped surface ide/devin-desktop from " +
					"sessions.metadata.client_meta[\"cognition.ai/requestingTabId\"], and Devin's own " +
					"hidden=1 summary-agent sessions are marked ThreadSource=subagent. See " +
					"docs/devin-adapter.md \"Devin Desktop\".",
			},
			Hosts:    []string{"devin"},
			Grounded: true,
			Note: "Windows layout grounded on this box 2026-09-03: the install dir STILL carries the " +
				"deprecated Windsurf name - %LOCALAPPDATA%\\Programs\\Windsurf\\Windsurf.exe (+ " +
				"bin\\{windsurf,windsurf.cmd}), NOT the `Devin.exe` the inventory §4.1 sketch guessed. macOS " +
				"is the opposite: the Homebrew cask `devin-desktop` (name \"Devin Desktop\", homepage " +
				"devin.ai/desktop) installs \"Devin.app\", so DarwinApp is \"Devin\". Names.Unix carries both " +
				"the grounded `windsurf` shim stem and the vendor-documented `devin-desktop` shell command " +
				"(docs.devin.ai/desktop via inventory §2.10); neither was verified on a unix host.",
		},
	},
	"qoder": {
		Tool: "qoder",
		// FIX-7 (phase-2 review): promoted from PromptLaneProbeRequired.
		// Qoder's UserPromptSubmit wire shape is fully documented
		// (docs.qoder.com/en/cli/hooks: `prompt` field, exit-2 block,
		// reason/stderr shown to the developer) — the contract's §2.1b
		// long-tail sweep VERIFIED it. Part B item 2 (phase-3a,
		// 2026-09-07) wired the dialect, receiver, and registration
		// writer after re-fetching docs.qoder.com/en/cli/hooks live: the
		// UserPromptSubmit hook's config schema
		// ({"hooks":{"UserPromptSubmit":[{"matcher":…,"hooks":[{"type":
		// "command","command":…,"timeout":…}]}]}}) is byte-identical to
		// Claude Code's own settings.json shape, so registerGenericSettingsHooks
		// (already generalized off registerClaudeCode for Gemini CLI/Qwen
		// Code) is reused, pointed at ~/.qoder/settings.json.
		PromptLane: PromptLaneHook,
		Vocabulary: Vocabulary{InTaxonomy: true},
		// Hardcoded api.qoder.com, PAT auth, NO base-URL knob — token
		// capture is proxy-tier or nothing, and there is no proxy lane.
		Proxy:       nil,
		Routability: RouteStatusNativeExempt,
		// `qodercli hooks` manage-command (a DIFFERENT, still-ungrounded
		// CC-lineage hook envelope) remains honest-none; the
		// UserPromptSubmit hook targeted here is a SEPARATE, now-verified
		// mechanism — a config-file "hooks" block in settings.json, not
		// that manage-command's own runtime registration.
		// CrossOSBridge: true — internal/hook's qoder-windows target
		// (registerQoderWindows) wraps the command in the wsl.exe
		// bridge, mirroring claude-code/cursor/codex's own bridges.
		Hook: HookSpec{Mechanism: HookQoderJSON, CrossOSBridge: true, AutoWired: true, Bindings: hookBindingsQoder},
		// MCP client exists (`qodercli mcp`, --mcp-config). The bundling
		// format IS now grounded (`.qoder-plugin/plugin.json` + dotted
		// `.mcp.json`, validated by `qodercli plugins validate` — coverage
		// wave A 2026-07-31, see plugins/qoder/); distribution is the plugins
		// channel, and no `observer init` writer is built, so the capability
		// stays nil.
		MCP:    nil,
		Native: NativeRails{},
		// Local stores carry NEITHER model (empty string) NOR tokens
		// (structurally zero even with healthy auth — live-disproven
		// auth-refresh hypothesis 2026-07-09); usage is server-side only.
		// The segment parse is zero-guarded so future counts would flow.
		TokenTier: TokenTier{Best: "none", Gap: "usage server-side only - local logs carry zero tokens and no model; no base-URL knob"},
		// CC-shaped transcript folds prompts/text/tool bodies (ReadTranscript
		// both lanes); `-i/--prompt-interactive <text>` seed verified live →
		// `observer qoder --continue-from` (non-proxied).
		Handoff: HandoffCapability{
			Transcript: TranscriptFull,
			Inject:     []InjectKind{InjectFile, InjectPrompt},
			Launch:     &LaunchSpec{Subcommand: "qoder"},
			Note:       "seeds via -i flag value (binary is `qodercli`)",
		},
		// Attach grounded 2026-07-24 (attach-all-launchers); PTY handoff only
		// — no prompt seeding, token capture path unchanged.
		Attach: &AttachSpec{Subcommand: "qoder"},
		// Native resume GROUNDED, live-verified 2026-07-24: `qodercli --resume
		// <id>` reattaches the real session; id is a raw uuid (binary is
		// `qodercli`). The `observer qoder` launcher maps `--resume <id>` to it.
		Resume: ResumeSpec{Kind: ResumeNative, Subcommand: "qoder", IDMechanism: "flag:--resume"},
		// AuthEnv zero: qoder uses PAT auth to api.qoder.com (file store), no
		// grounded runtime key env to forward.
		// Binary resolution + grounded installs. Unix launcher resolves
		// "qodercli" (the binary is qodercli, not qoder); npm
		// @qoder-ai/qodercli (any OS) + the official install script
		// (qoder.com/cli + npm).
		Binary: &BinaryResolveSpec{
			// npm JS bin: Windows install lays down a `.cmd` shim (+
			// .ps1/POSIX-shell forms), never an `.exe` — see the
			// command-code row's Binary comment for the long-form
			// rationale.
			// grounded 2026-09-02: the script channel's own comment
			// ("curl-bash installed versions at ~/.qoder/bin/ remain
			// preferred") plus docs.qoder.com/cli symmetry ground the same
			// %USERPROFILE%\.qoder\bin\qodercli.exe on Windows (.exe
			// inferred for the native script channel; npm still lands the
			// .cmd shim).
			Names: BinaryNames{
				Unix:    []string{"qodercli"},
				Windows: []string{"qodercli.exe", "qodercli.cmd", "qodercli"},
			},
			ProbeDirs: []ProbeDir{
				{OS: ProbeUnix, Rel: ".qoder/bin"},
				{OS: ProbeWindows, Rel: ".qoder/bin"},
			},
			// Minimum host runtime, grounded 2026-10-04 from the npm registry
			// (`npm view <pkg> engines`): @qoder-ai/qodercli 1.1.65 declares engines.node.
			Runtime: &RuntimeRequirement{Runtime: RuntimeNode, MinVersion: "20.0.0", Product: "Qoder CLI", Source: "npm registry engines.node, @qoder-ai/qodercli 1.1.65, read 2026-10-04"},
			Installs: []InstallHint{
				{OS: "", Channel: "npm", Argv: []string{"npm", "install", "-g", "@qoder-ai/qodercli"}, Display: "npm install -g @qoder-ai/qodercli"},
				{OS: "linux", Channel: "script", Argv: []string{"bash", "-lc", "curl -fsSL https://qoder.com/install | bash"}, Display: "curl -fsSL https://qoder.com/install | bash", Requires: []string{"curl", "tar"}},
				{OS: "darwin", Channel: "script", Argv: []string{"bash", "-lc", "curl -fsSL https://qoder.com/install | bash"}, Display: "curl -fsSL https://qoder.com/install | bash", Requires: []string{"curl", "tar"}},
				{OS: "windows", Channel: "script", Argv: []string{"powershell", "-Command", "irm https://qoder.com/install.ps1 | iex"}, Display: "irm https://qoder.com/install.ps1 | iex"},
			},
		},
		// Model picker (B5). Grounded live 2026-08-08: `qodercli --help`
		// lists `-m, --model <model>  Model for the current session`. The
		// `observer qoder` launcher is DisableFlagParsing + launcherArgsOrDone
		// (B6), so a forwarded `--model <value>` reaches the qodercli binary
		// unmodified.
		Model: ModelSpec{Kind: ModelArg, Flag: "--model"},
		// Sandbox filesystem-isolation row (B9). GROUNDED against
		// internal/adapter/qoder/adapter.go defaultRoots (<home>/.qoder/projects
		// and <home>/.qoder/logs/sessions). ~/.qoder is the CLI's whole state dir
		// — including the credential tables the adapter NEVER reads — and is
		// bound rw as one dir.
		Sandbox: SandboxSpec{NeedsWin32k: true, StateRW: []string{".qoder"}, ProtectRO: []string{".qoder/settings.json"}},
		// GUI launch row (plan §2.2). Launch is buildable today; CAPTURE for
		// the IDE is not — its store schema is unknown (inventory §2.13,
		// §3.1 #15) — so this row installs and launches honestly without
		// claiming the IDE's sessions are ingested.
		GUI: &GUILaunchSpec{
			ID:      "qoder-ide",
			Label:   "Qoder IDE",
			Surface: "ide",
			Binary: BinaryResolveSpec{
				// No collision with this row's CLI Names above (`qodercli`).
				Names: BinaryNames{
					Unix:    []string{"qoder"},
					Windows: []string{"Qoder IDE.exe"},
				},
				ProbeDirs: []ProbeDir{
					{OS: ProbeWindows, Rel: "AppData/Local/Programs/Qoder IDE"},
				},
				Installs: []InstallHint{
					{OS: "windows", Channel: "winget", Argv: []string{"winget", "install", "--id", "Alibaba.Qoder", "-e", "--source", "winget"}, Display: "winget install --id Alibaba.Qoder -e --source winget"},
				},
				InstallNote: "no grounded macOS or Linux channel: there is no Homebrew cask `qoder` " +
					"(formulae.brew.sh 404 on 2026-09-03) and the vendor ships a direct download " +
					"(qoder.com/download).",
			},
			// DarwinApp deliberately EMPTY: no cask and no macOS install to
			// read, so the .app bundle name is not grounded. A guess here
			// would be a fabricated capability (gui.go honesty rule).
			ProjectDirArgv: true,
			Wrap: WrapSpec{
				Kind: WrapNone,
				Reason: "no confirmed base-URL surface for the IDE (this row's Routability is native_exempt; " +
					"inventory §2.13 flags the CLI's /cli/network doc page as a possible contradiction but the " +
					"setting name was never extracted). Launch yes, wrap no.",
			},
			Hosts:    []string{"qoder"},
			Grounded: true,
			Note: "Windows layout grounded on this box 2026-09-03: %LOCALAPPDATA%\\Programs\\Qoder " +
				"IDE\\Qoder IDE.exe (+ bin\\{qoder,qoder.cmd} - and, betraying the VS Code fork lineage, " +
				"bin\\{code,code.cmd} too), which grounds both the unix shim stem and `qoder <dir>`. macOS " +
				"bundle name NOT grounded (no cask) - DarwinApp left empty rather than guessed. The IDE's " +
				"sessions ARE captured (batch-3 T4, 2026-09-03): the IDE writes " +
				"~/.qoder/projects/<slug>/transcript/<task>.session.execution.jsonl into the same tree the " +
				"CLI uses, which the qoder adapter ingests and stamps ide/qoder; its " +
				"%APPDATA%\\Qoder\\SharedClientCache\\cache\\db\\local.db (sqlite-vec vec0 tables, plain " +
				"chat tables empty live) is assessed and NOT read. The separate Qoder Work desktop app is " +
				"the `qoder-work` host row.",
		},
	},
	"aider": {
		Tool:       "aider",
		Vocabulary: Vocabulary{InTaxonomy: true},
		// FIX-7 (phase-2 review): Aider's --lint-cmd/--git-commit-verify
		// hooks act on GENERATED CODE, not prompts (contract §2.4) — no
		// prompt-submit event exists at all. The proxy lane (already
		// routed today) is Aider's only path to prompt-submit
		// intervention.
		PromptLane: PromptLaneProxyOnly,
		// Aider honors OPENAI_API_BASE (LiteLLM-shaped) — a real base-URL
		// surface, LIVE-GROUNDED 2026-07-09: a probe with
		// OPENAI_API_BASE=http://127.0.0.1:8820/v1 (aider --message …
		// --model gpt-4o-mini) landed an api_turns row (provider openai,
		// model gpt-4o-mini-2024-07-18). The knob is proven routable, and a
		// minimal `observer aider` launcher injects OPENAI_API_BASE.
		// PROMOTED 2026-08-21: a live `observer aider` turn landed an
		// api_turns row through the launcher path itself (id 166805,
		// provider openai, model gpt-4o-mini-2024-07-18) with a valid key —
		// checklist §10.1f met. (An earlier 401 row, 166747, proved the
		// wire; the keyed run's usage fields read 0/0 in api_turns while
		// aider itself reported 665/1 — a capture-parse gap on this shape
		// worth a follow-up, not a routing doubt.)
		// Proof stays UNPROVEN: OPENAI_API_BASE routes the OpenAI-compatible
		// lane only, and Aider's own model/provider selectors below can send
		// the same run to Anthropic or Bedrock with that variable still set.
		Proxy: &ProxyRoute{
			ClientAuth: ClientAuthPathToken,
			Kind:       RouteLauncher, EnvVar: "OPENAI_API_BASE", Suffix: "/v1",
			Launcher: "observer aider",
			// CLI-7: aider calls load_dotenv(override=True) over these files
			// (and --env-file), so a base-URL variable in one beats the
			// launcher's OPENAI_API_BASE; `openai-api-base` in a
			// .aider.conf.yml beats both (the agentconfig family
			// aider/openai-api-base). The launcher checks key presence.
			DotenvOverride: &DotenvOverride{
				Files:         []string{"~/.aider/oauth-keys.env", "~/.env", "<project>/.env"},
				Keys:          []string{"OPENAI_API_BASE", "AIDER_OPENAI_API_BASE"},
				FileArguments: []string{"--env-file"},
				Grounding:     "Aider-AI/aider aider/main.py load_dotenv_files (override=True; oauth-keys.env, ~/.env, <git root>/.env, ./.env, --env-file); surface-gap review CLI-7",
			},
			SelectorArguments: []string{
				"-m", "--model", "--env-file", "--model-settings-file",
				"--openai-api-base", "--openai-api-type", "--api-type",
				"--anthropic-api-version", "--anthropic-api-key",
				"--openai-api-key", "--api-key",
			},
		},
		Routability: RouteStatusRoutableNow,
		// No pre/post-tool hook surface exists.
		Hook: HookSpec{Mechanism: HookNone, Note: hookNoteAider},
		// Not an MCP client host observer writes into.
		MCP:    nil,
		Native: NativeRails{},
		// Tokens exist only as prose lines in the Markdown transcript
		// ("Tokens: 10.0k sent, ..."), format_tokens-ROUNDED; `sent` is
		// GROSS → the adapter nets it against the cache-hit clause. Aider's
		// own per-message Cost is carried as EstimatedCostUSD.
		TokenTier: TokenTier{Best: "transcript", Gap: "prose-only rounded counts (unreliable precision); no reasoning split; no per-turn timestamps", SynthesizedTimestamps: true, ReportsCost: true},
		// The per-repo .aider.chat.history.md is fully re-readable, but
		// there is NO seed lane: --message runs one turn and exits, the
		// REPL takes no preload flag. `observer aider` (2026-08-21) started as
		// a minimal exec+env-inject launcher; on 2026-10-03 (terminal-picker
		// coverage) it gained the DOC-ASSISTED --continue-from lane (handover
		// doc written, REPL opened in the source project) and the shared
		// attach gate, so the New Terminal picker lists it. aider.chat's
		// options page documents `--read FILE` and `--load FILE` as
		// REPL-preserving preloads; neither is wired as a seed (not
		// live-verified). No native resume (aider has no session-id surface;
		// `--restore-chat-history` replays the per-repo history, not a
		// chosen session).
		Handoff: HandoffCapability{
			Transcript: TranscriptFull,
			Inject:     []InjectKind{InjectFile},
			Launch:     &LaunchSpec{Subcommand: "aider", Mode: LaunchDocAssisted},
			Note:       "no interactive-seed lane (--message exits after the turn): launch writes the handover doc and opens the aider REPL",
		},
		Attach: &AttachSpec{Subcommand: "aider"},
		// Headless one-shot, LIVE-GROUNDED 2026-08-22 (arena headless-drive
		// arc): `aider --yes --no-auto-commits --message <prompt>` runs the
		// turn non-interactively and prints the reply + "Tokens: N sent, M
		// received. Cost: $X" prose to stdout. A real drive created ai.txt
		// (kiwi) end-to-end. CAVEAT (live arena run headless-20260823-02):
		// aider only edits files explicitly added to its chat — a prompt
		// that names the file is NOT enough; it wrote a .gitignore instead.
		// Arena supplies explicitly selected project-relative files as
		// positional argv; naming a path only in prompt prose is insufficient.
		// NOTE: aider needs OPENAI_API_KEY WITHOUT the literal quotes .env
		// carries (operator-shell gotcha); with a bare key it drives clean.
		// No session-id surface exists. A live Arena run must prove process
		// attribution binds the routed api_turn to the candidate; if it does
		// not, the candidate rollup stays honestly zero.
		//
		// Model: `--model <id>` is grounded by the 2026-07-09 live probe quoted
		// on the Proxy row (`aider --message … --model gpt-4o-mini` landed an
		// api_turns row as gpt-4o-mini-2024-07-18). Consumers: the Arena's
		// headless drive and, since aider became launchable (2026-10-03), the
		// New Terminal model picker (forwarded to `observer aider`). Catalog:
		// open (LiteLLM ids for any provider) - and only the OpenAI-compatible
		// lane is routed, which the Note says.
		Model: ModelSpec{Kind: ModelArg, Flag: "--model", Catalog: ModelCatalog{
			Kind: ModelCatalogOpen,
			Note: "Arena routes only aider's OpenAI-compatible lane through Observer; a model on another provider runs direct and its tokens are not captured",
		}},
		Headless: &HeadlessSpec{
			PromptFlag:  "--message",
			OutputArgs:  []string{"--no-auto-commits"},
			Result:      HeadlessResultStdoutText,
			ContextMode: HeadlessContextPositional,
			// --yes answers every confirmation, shell commands included: the
			// grounded drive's bypass (OSH-R-005). No other lane is driven.
			Permissions: map[HeadlessPermLane][]string{HeadlessPermBypass: {"--yes"}},
		},
		// Binary resolution + grounded install. Unix launcher resolves
		// "aider"; official install is the aider.chat uv-based script
		// (installs Python 3.12 if needed). Windows GROUNDED 2026-09-02:
		// install.ps1 (astral's cargo-dist uv installer, re-hosted, with
		// one appended `uv tool install --force --python python3.12
		// --with pip aider-chat@latest` line) lands
		// %USERPROFILE%\.local\bin\aider.exe alongside uv.exe/uvx.exe.
		Binary: &BinaryResolveSpec{
			Names: BinaryNames{
				Unix:    []string{"aider"},
				Windows: []string{"aider.exe"},
			},
			ProbeDirs: []ProbeDir{
				{OS: ProbeWindows, Rel: ".local/bin"},
			},
			Installs: []InstallHint{
				{OS: "linux", Channel: "script", Argv: []string{"sh", "-lc", "curl https://aider.chat/install.sh | sh"}, Display: "curl https://aider.chat/install.sh | sh", Requires: []string{"curl", "tar"}},
				{OS: "darwin", Channel: "script", Argv: []string{"sh", "-lc", "curl https://aider.chat/install.sh | sh"}, Display: "curl https://aider.chat/install.sh | sh", Requires: []string{"curl", "tar"}},
				{OS: "windows", Channel: "script", Argv: []string{"powershell", "-ExecutionPolicy", "ByPass", "-c", "irm https://aider.chat/install.ps1 | iex"}, Display: "irm https://aider.chat/install.ps1 | iex"},
			},
		},
		// Sandbox filesystem-isolation row (B9). GROUNDED against
		// internal/adapter/aider/doc.go: the transcripts are PROJECT-local
		// (<repo>/.aider.chat.history.md), which the sandbox already binds rw
		// as the workspace, and the only home-relative state is ~/.aider
		// (analytics.json / installs.json / the model-price cache).
		Sandbox: SandboxSpec{StateRW: []string{".aider"}},
	},
	"deepseek": {
		Tool: "deepseek",
		// 24 native tool names GROUNDED against a live request/header event
		// that embeds the full JSON-schema tool-definition set (see
		// internal/adapter/deepseek/records.go actionMap + the tooltax
		// deepSeekRows it mirrors). Literal names only, no defensive
		// synonyms — DeepSeek Harness's names are already a single stable
		// snake_case spelling.
		Vocabulary: Vocabulary{InTaxonomy: true},
		// DeepSeek Harness (`npx @deepseek-ai/dsh web`) is a web-only local
		// GUI (http://127.0.0.1:3080, no separate terminal/TUI mode) with
		// no proxy launcher. Surface-gap S-16 (2026-10-25): the vendor config
		// catalogue documents a provider baseURL (plugin
		// @deepseek-ai/dsh-llm-pi-ai, providers.<id>.baseURL, in the profile
		// cordis.yml), a base-URL knob, so the row is probe_required (was
		// native_exempt). No writer: the key's placement inside the profile
		// YAML is itself unverified (catalog_deepseek.go), and no routed turn
		// has been seen.
		Proxy:       nil,
		Routability: RouteStatusProbeRequired,
		// No pre/post-tool hook surface is documented; none registered.
		Hook: HookSpec{Mechanism: HookPluginShimTS, Bindings: hookBindingsDeepSeek}, // shim renders; no grounded install location (Lane D)
		// Not an MCP client host observer writes into.
		MCP:    nil,
		Native: NativeRails{},
		// data.usage on every assistant/message envelope carries
		// {inputTokens,outputTokens,cacheReadTokens?}, PER-STEP (not
		// cumulative), inputTokens already NET of cacheReadTokens
		// (confirmed live: a row with inputTokens < cacheReadTokens). No
		// cache-write field exists. Sub-agent token rollup is UNGROUNDED —
		// see the package doc's "Known gaps" section.
		TokenTier: TokenTier{
			Best: "events_jsonl",
			Gap:  "no cache-write field; sub-agent token rollup ungrounded; no cost field in the on-disk store (rows always $0)",
		},
		// the session[.v<N>].jsonl.zstd log is fully re-readable (whole-file rewrite on
		// every flush, re-decoded in full by ParseSessionFile), but there
		// is no launcher in this adapter's scope (web-only GUI, no CLI
		// seed lane) — file-lane carry only.
		Handoff: HandoffCapability{
			Transcript: TranscriptFull,
			Inject:     []InjectKind{InjectFile},
			Note:       "web-only GUI tool; no launcher, no interactive-seed lane in this adapter's scope",
		},
		// Sandbox filesystem-isolation row (B9). Honest zero: this row's data
		// arrives from the browser-capture extension, not from a process observer
		// spawns, so there is nothing to wrap in a filesystem boundary.
		Sandbox: SandboxSpec{Note: "not sandbox-launchable: captured from the vendor's WEB surface through the browser extension, so there is no observer-spawned local process to isolate"},
	},
	"goose": {
		Tool:       "goose",
		Vocabulary: Vocabulary{InTaxonomy: true},
		// FIX-7 (phase-2 review): Goose's UserPromptSubmit is
		// explicitly observation-only per the vendor's own docs — only
		// PreToolUse and Stop support denial (contract §2.3). The
		// proxy lane (already routed today, opt-in --proxy) is Goose's
		// only realistic path to prompt-submit intervention.
		PromptLane: PromptLaneProxyOnly,
		// Goose reads OPENAI_HOST (NOT OPENAI_BASE_URL; host ROOT — goose
		// appends /v1) plus per-provider host settings in config.yaml — a
		// real override surface, LIVE-GROUNDED 2026-07-09: a probe on the
		// openai provider (--provider openai + OPENAI_HOST=http://127.0.0.1:8820,
		// --model gpt-4o-mini, keyring disabled so the env key is used)
		// landed api_turns rows (provider openai, model gpt-4o-mini-2024-07-18,
		// real usage). The knob is proven routable; `observer goose`
		// (2026-08-21) gained an opt-in `--proxy` flag that injects
		// OPENAI_HOST, but stays NON-PROXIED by DEFAULT — unconditionally
		// setting OPENAI_HOST would redirect an operator's already-configured
		// provider (the live config here defaulted to openrouter). Proxy
		// stays nil until a live turn lands an api_turns row through the flag
		// itself (the cline/kilo VS-Code "routable_now, writer-pending"
		// pattern). PROMOTED 2026-08-21 (second attempt): the first re-probe
		// failed because the operator shell exports
		// OPENAI_HOST=https://api.openai.com globally, and the launcher's
		// user-values-win rule let it override the injection — with
		// OPENAI_HOST unset, a live `observer goose --proxy run` turn landed
		// api_turns rows through the route (ids 167714-5, provider openai,
		// model gpt-4o-mini; 401 upstream on a throwaway key = wire proven).
		// OPERATOR NOTE: unset your ambient OPENAI_HOST (shell profile) when
		// using `observer goose --proxy`, or accept that yours wins.
		Proxy: &ProxyRoute{Kind: RouteLauncher, EnvVar: "OPENAI_HOST", Suffix: "", Launcher: "observer goose --proxy", LaunchFlag: "--proxy", Note: "Opt-in --proxy flag injects OPENAI_HOST at the proxy ROOT (goose appends /v1). Requires GOOSE_PROVIDER=openai (or another OPENAI_HOST-honoring provider); an ambient OPENAI_HOST in the operator env wins over the injection by design.", SharesCredentialFile: true, CredentialFileReason: routeCredGoose, PersistedDefault: &PersistedDefault{
			Note:     "CLI-1a: proxyroute.RegisterDefaultProvider(goose) persists OPENAI_HOST = proxy root in ~/.config/goose/config.yaml when the active provider is openai (active_provider or GOOSE_PROVIDER), so a bare goose routes; YAML member edit, never a key",
			LiveGate: "LC25",
		}},
		Routability: RouteStatusRoutableNow,
		// No pre/post-tool hook surface exists (extensions are MCP servers,
		// not hooks).
		Hook: HookSpec{Mechanism: HookGoosePlugin, AutoWired: true, Bindings: hookBindingsGoose},
		// Goose IS an MCP client — extensions in config.yaml are MCP
		// servers, a future additive-registration candidate — but no
		// guarded write path into config.yaml is grounded; no writer.
		MCP:    nil,
		Native: NativeRails{},
		// sessions.db carries the richest session-level token columns of
		// the 2026-07 wave (incl. accumulated_* + accumulated_cost), but
		// messages.tokens was NULL in every 1.41.0 capture — no per-message
		// split. input_tokens is GROSS (cache_read ⊂ input, single-turn
		// proof) → the adapter nets it. Token-EMPTY sessions persist on
		// provider errors.
		TokenTier: TokenTier{Best: "sqlite", Gap: "session-level counts only (messages.tokens null in all captures); no reasoning split; cache_write null on OpenAI", SessionCumulative: true, ReportsCost: true},
		// messages.content_json re-readable (ReadTranscript, DB lane);
		// `goose run -t "<seed>" -s` seed-then-interactive verified live
		// 2026-07-09 (keyed run) → `observer goose`.
		Handoff: HandoffCapability{
			Transcript: TranscriptFull,
			Inject:     []InjectKind{InjectFile, InjectPrompt},
			Launch:     &LaunchSpec{Subcommand: "goose"},
			Note:       "seeds via `run -t <seed> -s` (seed-then-interactive verified live)",
		},
		// Attach grounded 2026-07-24 (attach-all-launchers); PTY handoff only
		// — no prompt seeding, token capture path unchanged.
		Attach: &AttachSpec{Subcommand: "goose"},
		// Native resume GROUNDED, live-verified 2026-07-24: `goose session
		// --resume --session-id <RAW>` reattaches the real session under the
		// `session` SUBCOMMAND. Observer stores the SCOPED id `<id>@<hash8>`
		// (scopedSessionID, internal/adapter/goose/parse.go), so the `observer
		// goose` launcher STRIPS everything from the first `@` before composing
		// the native argv. It maps `--resume <id>` to it.
		Resume: ResumeSpec{Kind: ResumeNative, Subcommand: "goose", IDMechanism: "flag:--session-id"},
		// AuthEnv zero: goose resolves provider keys from its keyring / config.yaml
		// by default (per-provider env keys exist but are not the grounded runtime
		// source here) — file auth, no key declared.
		// Binary resolution + grounded installs. Unix launcher resolves
		// "goose"; its installer drops the binary under .local/bin (a
		// per-tool extra). Official install script + brew (repo moved
		// block/goose → aaif-goose/goose, Linux Foundation AAIF, Dec 2025 —
		// goose-docs.ai installation page).
		//
		// Windows GROUNDED 2026-09-02: the .ps1 ($OUT_FILE = "goose.exe",
		// GOOSE_BIN_DIR = $env:USERPROFILE\.local\bin) lands
		// %USERPROFILE%\.local\bin\goose.exe but does NOT edit PATH
		// ("Warning: goose installed, but … is not in your PATH") — so
		// post-install detection depends entirely on the ProbeDir. The
		// Git-Bash `.sh` channel's own MSYS branch
		// (DEFAULT_BIN_DIR="$USERPROFILE/goose") lands in a DIFFERENT
		// dir, so both are probed. The vendor documents only the
		// branch-tip raw URL for download_cli.ps1 — the release-asset
		// URL (…/releases/download/stable/download_cli.ps1) 404s as of
		// 2026-09-02. CONFIGURE=false keeps the install non-interactive
		// (skips `goose configure`) in the PTY. Windows ARM64 is
		// refused by the vendor script (exit 1); no winget id exists.
		//
		// RE-GROUNDED 2026-10-02 (after a failed guided install on a Linux
		// node): the curl|bash URL, the brew formula `block-goose-cli`
		// (1.52.0) and the raw download_cli.ps1 URL are still exactly what
		// https://goose-docs.ai/docs/getting-started/installation documents,
		// and `stable` + v1.52.0 both carry goose-x86_64-unknown-linux-gnu
		// .tar.bz2. The failure was NOT this hint: download_cli.sh downloads
		// the archive into the CURRENT directory, and the setup PTY
		// inherited the daemon's cwd "/" (curl exit 23, hidden by -s, then a
		// misleading "Failed to download from fallback url"). Setup PTYs now
		// start in the operator's home (cmd/observer setupWorkDir).
		//
		// FIXED 2026-10-03 (demo node 1): the unix curl|bash hint lacked the
		// CONFIGURE=false the Windows hint already carries, so after a
		// successful download download_cli.sh ran an interactive `goose
		// configure` in the setup PTY. That PTY never exited, so the guided
		// install record stayed "installing" (the ledger settles on PTY exit,
		// correctly). `| CONFIGURE=false bash` sets it for the piped script.
		Binary: &BinaryResolveSpec{
			Names: BinaryNames{
				Unix:    []string{"goose"},
				Windows: []string{"goose.exe"},
			},
			ProbeDirs: []ProbeDir{
				{OS: ProbeUnix, Rel: ".local/bin"},
				{OS: ProbeWindows, Rel: ".local/bin"},
				{OS: ProbeWindows, Rel: "goose"},
			},
			Installs: []InstallHint{
				{OS: "linux", Channel: "script", Argv: []string{"bash", "-lc", "curl -fsSL https://github.com/aaif-goose/goose/releases/download/stable/download_cli.sh | CONFIGURE=false bash"}, Display: "curl -fsSL https://github.com/aaif-goose/goose/releases/download/stable/download_cli.sh | CONFIGURE=false bash", Requires: []string{"curl", "tar", "bzip2"}},
				{OS: "darwin", Channel: "script", Argv: []string{"bash", "-lc", "curl -fsSL https://github.com/aaif-goose/goose/releases/download/stable/download_cli.sh | CONFIGURE=false bash"}, Display: "curl -fsSL https://github.com/aaif-goose/goose/releases/download/stable/download_cli.sh | CONFIGURE=false bash", Requires: []string{"curl", "tar"}},
				{OS: "darwin", Channel: "brew", Argv: []string{"brew", "install", "block-goose-cli"}, Display: "brew install block-goose-cli"},
				{OS: "linux", Channel: "brew", Argv: []string{"brew", "install", "block-goose-cli"}, Display: "brew install block-goose-cli"},
				{
					OS:      "windows",
					Channel: "script",
					Argv: []string{
						"powershell",
						"-ExecutionPolicy",
						"Bypass",
						"-Command",
						`$env:CONFIGURE='false'; Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/aaif-goose/goose/main/download_cli.ps1' -OutFile "$env:TEMP\download_cli.ps1"; & "$env:TEMP\download_cli.ps1"`,
					},
					Display: `$env:CONFIGURE='false'; Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/aaif-goose/goose/main/download_cli.ps1' -OutFile "$env:TEMP\download_cli.ps1"; & "$env:TEMP\download_cli.ps1"`,
				},
			},
		},
		// Model picker (B5): ModelEnv, GOOSE_MODEL. Grounded live 2026-08-08:
		// top-level `goose --help` / `goose session --help` (the default
		// fresh-launch interactive lane) carry NO --model flag; only `goose
		// run --help` does — "Override the GOOSE_MODEL environment variable
		// for this run. The model must be supported by the specified
		// provider" — confirming GOOSE_MODEL as the tool's OWN recognized
		// env var (the run flag is documented sugar for exporting it). Since
		// the dashboard's default fresh launch is the interactive lane
		// (bare `goose` / `goose session`, not headless `goose run`) where
		// no argv flag is reachable, env delivery is the only grounded
		// seed-time mechanism.
		Model: ModelSpec{Kind: ModelEnv, EnvVar: "GOOSE_MODEL"},
		// Sandbox filesystem-isolation row (B9). GROUNDED against
		// internal/adapter/goose/store.go storeSubdir (<home>/.local/share/goose/
		// sessions) plus the config dir docs/goose-adapter.md names
		// (~/.config/goose/config.yaml + secrets.yaml). Both bound rw: the
		// adapter NEVER reads secrets.yaml, but goose itself must.
		Sandbox: SandboxSpec{
			StateRW: []string{".config/goose", ".local/share/goose"},
			// macOS (live user install 2026-10-29, D-MU6): goose writes its
			// logs under the XDG state dir and failed under Seatbelt without it.
			StateRWByOS: map[string][]string{"darwin": {".local/state/goose"}},
		},
		// GUI launch row (plan §2.2): Goose Desktop shares this row's
		// sessions.db (inventory §2.11). NOT installed on this box, so the
		// row is grounded from the macOS side only.
		GUI: &GUILaunchSpec{
			ID:      "goose-desktop",
			Label:   "Goose Desktop",
			Surface: "desktop",
			Binary: BinaryResolveSpec{
				// Names.Windows deliberately EMPTY (honest zero, see
				// WindowsNote); Names.Unix likewise — `goose` on PATH is
				// this row's CLI, a different binary from the desktop app.
				WindowsNote: "Goose Desktop is not installed on the grounding box (2026-09-03) and the " +
					"vendor ships a zip whose extracted layout was not verified, so no Windows executable " +
					"spelling or probe dir is declared rather than guessing " +
					"%LOCALAPPDATA%\\Programs\\Goose.",
				Installs: []InstallHint{
					{OS: "darwin", Channel: "brew", Argv: []string{"brew", "install", "--cask", "block-goose"}, Display: "brew install --cask block-goose"},
				},
				InstallNote: "macOS only. The vendor also publishes a Windows zip and Linux deb/rpm/flatpak " +
					"(inventory §4.1) but none has a grounded one-liner; note the winget package `Pressly.Goose` " +
					"is the unrelated SQL migration tool and must never be offered here.",
			},
			DarwinApp:      "Goose",
			ProjectDirArgv: false,
			Wrap: WrapSpec{
				Kind: WrapChildEnv,
				Env: []WrapEnvVar{
					{Name: "OPENAI_HOST", Suffix: ""},
				},
				ColdStartOnly: true,
				Reason: "OPENAI_HOST at the proxy ROOT (goose appends /v1) is the SAME knob this row's " +
					"opt-in `observer goose --proxy` launcher lane uses, and the vendor says Desktop shares " +
					"the CLI's config surface (inventory §2.11) - but the env lane is verified for the CLI " +
					"only, NOT for the desktop app. Same caveats as the CLI: it needs GOOSE_PROVIDER=openai " +
					"(or another OPENAI_HOST-honouring provider), and an ambient OPENAI_HOST in the operator's " +
					"environment wins over the injection by design.",
			},
			Hosts:    []string{"goose"},
			Grounded: true,
			Note: "Grounded from the macOS side ONLY: bundle \"Goose.app\" and the cask token `block-goose` " +
				"read from the Homebrew cask API on 2026-09-03. Goose Desktop is NOT installed on the " +
				"Windows grounding box, so its Windows layout is unverified and Names.Windows is empty - " +
				"the row is launchable on macOS and will preflight as unresolved on Windows until someone " +
				"grounds the zip layout.",
		},
	},

	// Browser-chatbot rail (Phase 1 = ChatGPT only). Captured by the opt-in
	// MV3 browser extension's native-messaging bridge, NOT a coding CLI or a
	// watcher/SQLite adapter — so there is no local session file, no proxy
	// leg, and no server-side usage field. The other planned *-web sites
	// (claude-web / perplexity-web / gemini-web / copilot-web) join in
	// Phase 2. See docs/plans/browser-extension-and-m365-copilot-proposal-
	// 2026-07-10.md + internal/adapter/browserchat.
	"chatgpt-web": {
		Tool:       "chatgpt-web",
		Vocabulary: Vocabulary{Note: "no native tool vocabulary: the MV3 browser-capture lane records ChatGPT prompt/answer turns from the chat UI, never tool calls, so tooltax carries no rows for it"},
		// The real browser makes the real request; observer only OBSERVES a
		// captured turn relayed by the extension. There is no base-URL knob
		// to route (routing would re-originate TLS and risk flagging the
		// user's own account) — natively exempt, a grounded negative.
		Proxy:       nil,
		Routability: RouteStatusNativeExempt,
		// The extension attaches via the native-messaging bridge (the
		// browser launches `observer browser hook`), not an AI-tool config
		// file. AutoWired is true as of Phase 2: `observer init`'s 4th
		// consent step writes the per-browser native-messaging host manifest
		// (extensionSupported → browserhost.Registrar), so the doctor
		// honestly reports the rail as auto-wired.
		Hook:   HookSpec{Mechanism: HookBrowserExtension, AutoWired: true, Bindings: browserBindings()},
		MCP:    nil,
		Native: NativeRails{}, // no vendor admin/usage API for the consumer web app.
		// Tokens are ALWAYS estimated: no target UI returns authoritative
		// counts, so the extension estimates client-side (gpt-tokenizer) and
		// the server may recompute a chars/4 heuristic — either way
		// TokenSourceEstimated + ReliabilityUnreliable.
		TokenTier: TokenTier{Best: "browser_extension", Gap: "no server-side usage field; estimated only"},
		// Handoff zero value: the browser rail has no re-readable on-disk
		// transcript (the turn lives only in the browser), so it stays the
		// honest actions-only floor with the universal file lane. Not
		// launchable in-terminal.
		Handoff: HandoffCapability{},
		// Sandbox filesystem-isolation row (B9). Honest zero: this row's data
		// arrives from the browser-capture extension, not from a process observer
		// spawns, so there is nothing to wrap in a filesystem boundary.
		Sandbox: SandboxSpec{Note: "not sandbox-launchable: captured from the vendor's WEB surface through the browser extension, so there is no observer-spawned local process to isolate"},
	},
	// Claude.ai browser web app (SSE content_block_delta). Same rail shape
	// as chatgpt-web — the only differences are DATA (host, default model,
	// tokenizer family) in internal/adapter/browserchat.siteRules.
	"claude-web": {
		Tool:        "claude-web",
		Vocabulary:  Vocabulary{Note: "no native tool vocabulary: browser-captured Claude.ai chat turns only (no tool-call surface in the DOM/WS capture)"},
		Proxy:       nil,
		Routability: RouteStatusNativeExempt,
		Hook:        HookSpec{Mechanism: HookBrowserExtension, AutoWired: true, Bindings: browserBindings()},
		MCP:         nil,
		Native:      NativeRails{},
		TokenTier:   TokenTier{Best: "browser_extension", Gap: "no server-side usage field; estimated only (Anthropic tokenizer is documented-inaccurate for Claude 3+)"},
		Handoff:     HandoffCapability{},
		// Sandbox filesystem-isolation row (B9). Honest zero: this row's data
		// arrives from the browser-capture extension, not from a process observer
		// spawns, so there is nothing to wrap in a filesystem boundary.
		Sandbox: SandboxSpec{Note: "not sandbox-launchable: captured from the vendor's WEB surface through the browser extension, so there is no observer-spawned local process to isolate"},
	},
	// Perplexity browser web app (SSE /rest/sse/perplexity_ask — NOT the
	// Comet automation WebSocket).
	"perplexity-web": {
		Tool:        "perplexity-web",
		Vocabulary:  Vocabulary{Note: "no native tool vocabulary: browser-captured Perplexity chat turns only"},
		Proxy:       nil,
		Routability: RouteStatusNativeExempt,
		Hook:        HookSpec{Mechanism: HookBrowserExtension, AutoWired: true, Bindings: browserBindings()},
		MCP:         nil,
		Native:      NativeRails{},
		TokenTier:   TokenTier{Best: "browser_extension", Gap: "no server-side usage field; estimated only (no light client tokenizer - chars/4 heuristic)"},
		Handoff:     HandoffCapability{},
		// Sandbox filesystem-isolation row (B9). Honest zero: this row's data
		// arrives from the browser-capture extension, not from a process observer
		// spawns, so there is nothing to wrap in a filesystem boundary.
		Sandbox: SandboxSpec{Note: "not sandbox-launchable: captured from the vendor's WEB surface through the browser extension, so there is no observer-spawned local process to isolate"},
	},
	// Gemini browser web app (BatchExecute RPC — the hardest transport). The
	// extension parser is BEST-EFFORT / incomplete (proposal §3.4); the Gap
	// says so plainly so the honesty is visible in the doctor.
	"gemini-web": {
		Tool:        "gemini-web",
		Vocabulary:  Vocabulary{Note: "no native tool vocabulary: browser-captured Gemini chat turns only (BatchExecute best-effort)"},
		Proxy:       nil,
		Routability: RouteStatusNativeExempt,
		Hook:        HookSpec{Mechanism: HookBrowserExtension, AutoWired: true, Bindings: browserBindings()},
		MCP:         nil,
		Native:      NativeRails{},
		TokenTier:   TokenTier{Best: "browser_extension", Gap: "no server-side usage field; estimated only; BatchExecute RPC parser is best-effort/incomplete (highest-maintenance site)"},
		Handoff:     HandoffCapability{},
		// Sandbox filesystem-isolation row (B9). Honest zero: this row's data
		// arrives from the browser-capture extension, not from a process observer
		// spawns, so there is nothing to wrap in a filesystem boundary.
		Sandbox: SandboxSpec{Note: "not sandbox-launchable: captured from the vendor's WEB surface through the browser extension, so there is no observer-spawned local process to isolate"},
	},
	// Consumer Copilot browser web app (copilot.microsoft.com — WebSocket
	// frames). NOT GitHub Copilot (see "copilot"/"copilot-cli") and NOT
	// enterprise M365 Copilot (a separate org-tier connector, out of the
	// browser rail).
	"copilot-web": {
		Tool:        "copilot-web",
		Vocabulary:  Vocabulary{Note: "no native tool vocabulary: browser-captured consumer-Copilot chat turns only (WebSocket capture, cf_clearance-gated)"},
		Proxy:       nil,
		Routability: RouteStatusNativeExempt,
		Hook:        HookSpec{Mechanism: HookBrowserExtension, AutoWired: true, Bindings: browserBindings()},
		MCP:         nil,
		Native:      NativeRails{},
		TokenTier:   TokenTier{Best: "browser_extension", Gap: "no server-side usage field; estimated only; WebSocket-frame parser (cf_clearance-gated)"},
		Handoff:     HandoffCapability{},
		// Sandbox filesystem-isolation row (B9). Honest zero: this row's data
		// arrives from the browser-capture extension, not from a process observer
		// spawns, so there is nothing to wrap in a filesystem boundary.
		Sandbox: SandboxSpec{Note: "not sandbox-launchable: captured from the vendor's WEB surface through the browser extension, so there is no observer-spawned local process to isolate"},
	},
	// Factory AI's "droid" CLI (docs/plans/factory-droid-adapter-plan-2026-07-29.md).
	// Phase-0 research only — no adapter package yet (Phase A wiring row).
	"droid": {
		Tool:       "droid",
		PromptLane: PromptLaneHook,
		Vocabulary: Vocabulary{InTaxonomy: true},
		// No live-verified route today; BYOK custom models call the
		// underlying provider directly (the only near-routable_now
		// candidate) but that's unverified — no live turn through :8820.
		Proxy:       nil,
		Routability: RouteStatusProbeRequired,
		// No hook SUBCOMMAND in `droid --help`, but the prompt-submit
		// hook IS a config-file registration (Part B item 1) —
		// ~/.factory/hooks.json, the same {"hooks":{<event>:[{matcher,
		// hooks}]}} shape HookCodexConfig's hooks.json uses.
		// CrossOSBridge: true — internal/hook's droid-windows target
		// (registerFactoryDroidWindows) wraps the command in the
		// wsl.exe bridge, mirroring claude-code/cursor/codex's own
		// bridges.
		Hook: HookSpec{Mechanism: HookFactoryJSON, CrossOSBridge: true, AutoWired: true, Bindings: hookBindingsDroid},
		// ~/.factory/mcp.json reuses claude-code/cursor's {"mcpServers":{}}
		// shape (format confirmed live via a zero-cost `droid mcp add`/
		// `remove` probe). A writer now exists (internal/mcp/register.go's
		// generic registerJSONMCP, via the internal/mcp/locate row) so this
		// is Implemented — parking §3.4.
		// Remote grounded 2026-09-24 against docs.factory.ai/cli/configuration/
		// mcp + the 2026-07-29 live `droid mcp add … --type http` probe (which
		// wrote `{"url":…,"disabled":false,"type":"http"}`): `type` http|sse
		// + url + headers + disabled. Written by the shared JSON remote writer.
		MCP: &MCPTarget{Format: MCPServersJSON, PathHint: ".factory/mcp.json", Implemented: true, SharesCredentialFile: true, CredentialFileReason: mcpCredDroid, Remote: &MCPRemoteTarget{
			Transports:   []MCPRemoteTransport{MCPRemoteStreamableHTTP, MCPRemoteSSE},
			Headers:      true,
			TransportKey: "type",
			Spelling:     map[MCPRemoteTransport]string{MCPRemoteStreamableHTTP: "http", MCPRemoteSSE: "sse"},
			Flags:        map[string]bool{"disabled": false},
			Implemented:  true,
			Note:         "docs.factory.ai 2026-09-24 + live probe 2026-07-29: type http|sse + url + headers + disabled:false",
		}},
		Native: NativeRails{},
		// Sidecar <uuid>.settings.json carries session-level cumulative
		// tokens only — no per-message token field in the JSONL itself.
		TokenTier: TokenTier{Best: "jsonl", Gap: "no per-message tokens; no proxy path verified; Factory-hosted built-in-model wire shape entirely unconfirmed (no active subscription in this corpus)", SessionCumulative: true},
		Handoff: HandoffCapability{
			Transcript: TranscriptFull,
			Inject:     []InjectKind{InjectFile, InjectPrompt},
			// Seed contract grounded 2026-07-29 against `droid --help`
			// (v0.181.0): `Usage: droid [options] [command] [prompt...]`
			// with the worked example `droid "review app.tsx"   Start with
			// an initial prompt` — the initial prompt is a bare positional
			// on the DEFAULT (TUI) command, so the launcher appends the
			// handover as the TRAILING positional after any forwarded
			// flags. `droid exec [prompt]` is the headless one-shot ("Run
			// non-interactively (for scripts/automation)") and is rejected
			// under --continue-from rather than silently seeded.
			Launch: &LaunchSpec{Subcommand: "droid", Mode: LaunchSeeded},
		},
		// Attachable: `observer droid --attach` hands the PTY to the daemon.
		Attach: &AttachSpec{Subcommand: "droid"},
		// Native resume: `droid --resume=<sessionId>`. Grounded 2026-07-29
		// zero-spend on the live install: `-r, --resume [sessionId]` is a
		// commander.js OPTIONAL-value option, so the JOINED `=` spelling is
		// the unambiguous form (the cursor precedent); a REAL uuid from
		// ~/.factory/sessions reopened that session's TUI (no model call,
		// transcript mtime unchanged) while a bogus uuid exited silently —
		// the two outcomes discriminate, so the flag really consumes the
		// value. The id IS our stored SessionID verbatim: the transcript is
		// `<uuid>.jsonl` and its `session_start` line carries the same
		// `"id"` (internal/adapter/droid/adapter.go), so no transform.
		Resume: ResumeSpec{Kind: ResumeNative, Subcommand: "droid", IDMechanism: "flag:--resume"},
		// GUI launch row: Factory Desktop (batch-3 T3, 2026-09-03). The
		// Electron app bundles its OWN droid.exe and writes the SAME
		// ~/.factory/sessions store this row's adapter reads — capture is
		// free; desktop-composed prompts carry message.userMessageSource
		// == "desktop", which is the grounded desktop/factory-desktop stamp.
		GUI: &GUILaunchSpec{
			ID:      "factory-desktop",
			Label:   "Factory Desktop",
			Surface: "desktop",
			Binary: BinaryResolveSpec{
				Names: BinaryNames{
					// The Squirrel stub at the install root relaunches the
					// current app-<ver>\factory-desktop.exe.
					Windows: []string{"factory-desktop.exe"},
				},
				ProbeDirs: []ProbeDir{
					{OS: ProbeWindows, Rel: "AppData/Local/Factory"},
				},
				InstallNote: "no grounded macOS or Linux channel: no Homebrew cask and no winget package found " +
					"(checked 2026-09-03); the vendor ships a direct download (factory.ai/news/factory-desktop).",
			},
			ProbeOnly:      true,
			ProjectDirArgv: false,
			Wrap: WrapSpec{
				Kind: WrapNone,
				Reason: "probe_required and no writer: droid's BYOK route is the customModels array in " +
					"~/.factory/settings.json (a file Observer never reads - plaintext keys) and this row " +
					"carries neither a verified Proxy nor a ProxyProbe binding; the desktop reuses the " +
					"bundled droid's provider config, so there is nothing to wrap. Launch yes, wrap no.",
			},
			Hosts:    []string{"droid"},
			Grounded: true,
			Note: "Windows layout grounded on this box 2026-09-03: %LOCALAPPDATA%\\Factory\\factory-desktop.exe " +
				"(Squirrel stub) → app-0.168.0\\factory-desktop.exe (Electron) bundling " +
				"app-0.168.0\\resources\\bin\\droid.exe. macOS bundle NOT grounded - DarwinApp left empty. " +
				"Sessions land in ~/.factory/sessions/<slug>/<uuid>.jsonl exactly like the CLI's; " +
				"cloudSessionSync defaults TRUE on the vendor side (mirrors to Factory's backend).",
		},
		Binary: &BinaryResolveSpec{
			Names: BinaryNames{
				Unix:    []string{"droid"},
				Windows: []string{"droid.exe", "droid.cmd", "droid"},
			},
			// ~/.local/bin is where the live install landed (2026-07-29).
			// The ~/.factory/bin unix entry was DROPPED 2026-09-02:
			// operator-verified 2026-07-29, but re-checked absent on this
			// WSL box 2026-09-02 and no current vendor script references
			// it — a stale probe dir. Windows GROUNDED 2026-09-02: the
			// installer (`$binaryName = "droid.exe"`, `$userBin =
			// Join-Path $env:USERPROFILE "bin"`) lands
			// %USERPROFILE%\bin\droid.exe, not ~/.factory/bin.
			ProbeDirs: []ProbeDir{
				{OS: ProbeUnix, Rel: ".local/bin"},
				{OS: ProbeWindows, Rel: "bin"},
			},
			// Officially documented channels only. The macOS/Linux line is
			// the installer script's OWN documented usage (fetched
			// 2026-07-29, its first comment reads
			// `# Usage: curl -fsSL https://app.factory.ai/cli | sh`). The
			// npm package name `droid` is registry-confirmed as Factory's
			// own (repo github.com/Factory-AI/factory, directory apps/cli,
			// bin {"droid":"bin/droid"}); it carries OS "" so it is also
			// the Windows answer.
			//
			// Windows script hint ADDED 2026-09-02 (operator decision):
			// the vendor's OWN documented Windows form
			// (app.factory.ai/cli/windows) is a THREE-step, optionally
			// cookie-authenticated flow (`curl.exe -b 'session=…' … -o
			// install.ps1` → `powershell -ExecutionPolicy Bypass -File
			// install.ps1` → `del`), not a one-liner. The `irm … | iex`
			// hint below fetches the SAME URL through observer's own
			// piped-execution convention (no session cookie) — it is
			// observer's construction, not a literal vendor one-liner;
			// noted honestly rather than mis-attributed.
			// Minimum host runtime, grounded 2026-10-04 from the npm registry
			// (`npm view <pkg> engines`): droid 0.233.0 declares engines.node.
			Runtime: &RuntimeRequirement{Runtime: RuntimeNode, MinVersion: "20.0.0", Product: "Droid", Source: "npm registry engines.node, droid 0.233.0, read 2026-10-04"},
			Installs: []InstallHint{
				{OS: "linux", Channel: "script", Argv: []string{"bash", "-lc", "curl -fsSL https://app.factory.ai/cli | sh"}, Display: "curl -fsSL https://app.factory.ai/cli | sh", Requires: []string{"curl"}},
				{OS: "darwin", Channel: "script", Argv: []string{"bash", "-lc", "curl -fsSL https://app.factory.ai/cli | sh"}, Display: "curl -fsSL https://app.factory.ai/cli | sh", Requires: []string{"curl"}},
				{OS: "windows", Channel: "script", Argv: []string{"powershell", "-Command", "irm https://app.factory.ai/cli/windows | iex"}, Display: "irm https://app.factory.ai/cli/windows | iex"},
				{OS: "", Channel: "npm", Argv: []string{"npm", "install", "-g", "droid"}, Display: "npm install -g droid"},
			},
		},
		// Model picker (B5): explicit ModelNone, not an oversight. Grounded
		// live 2026-08-08: `droid --help` (the default interactive TUI
		// launch this registry's Launch.Subcommand drives) lists no
		// model-related flag at all; `-m, --model <id>` exists ONLY under
		// `droid exec --help` (the headless one-shot lane, a different
		// entry point observer does not seed through). No grounded
		// seed-time mechanism on the interactive lane ⇒ the honest floor.
		Model: ModelSpec{Kind: ModelNone},
		// Sandbox filesystem-isolation row (B9). GROUNDED against
		// internal/adapter/droid/adapter.go defaultRoots (<home>/.factory/
		// sessions). ~/.factory is Factory's whole state dir (sessions, per-session
		// settings sidecars, auth) and is bound rw as one dir.
		Sandbox: SandboxSpec{NeedsWin32k: true, StateRW: []string{".factory"}, ProtectRO: []string{".factory/hooks.json", ".factory/mcp.json"}},
	},
	// Rebadged OpenAI Codex CLI Rust build, installed under
	// ~/.openinterpreter (docs/plans/openinterpreter-adapter-plan-2026-07-29.md).
	// Phase-0 research only — no adapter package yet (Phase A wiring row);
	// the eventual implementation is expected to retag internal/adapter/codex
	// (antigravity/antigravity-cli pattern), not a fresh package.
	"open-interpreter": {
		Tool:       "open-interpreter",
		PromptLane: PromptLaneProbeRequired,
		Vocabulary: Vocabulary{InTaxonomy: true},
		// This row (the vendor's current Rust/codex-based rewrite) is
		// ACTIVE. The note records the COMMAND-NAME COLLISION with the
		// dead legacy Python line (pip `open-interpreter`), which also
		// answers to `interpreter` — see
		// productLifecycles["open-interpreter-python"]. This adapter is
		// path-keyed (~/.openinterpreter/sessions via INTERPRETER_HOME)
		// and never reads the Python line's data; any detector keyed on
		// the command NAME must disambiguate by binary path / version.
		LifecycleNote: "COMMAND-NAME COLLISION: the DEAD legacy Python line (pip `open-interpreter`, see " +
			"productLifecycles[\"open-interpreter-python\"]) answers to the same `interpreter` command. " +
			"This row is the vendor's current Rust rewrite and is active; capture is path-keyed " +
			"(~/.openinterpreter/sessions via INTERPRETER_HOME), never command-name-keyed, and the " +
			"install hints below deliberately exclude the pip channel.",
		// config schema present (base_url/wire_api strings confirmed in
		// the binary) but not live-verified on this fork.
		Proxy: nil,
		// OI-1 (D16): the writer is built (proxyroute memberroute.go), the
		// same [model_providers.openai-observer] provider Codex's writer
		// adds, surgically, in the CLI's user config.toml (INTERPRETER_HOME),
		// a file that holds plaintext provider keys. Switched off until live
		// check LC11 shows the route honoured.
		ProxyProbe: &ProxyRoute{
			Kind:                 RouteConfigFile,
			Suffix:               "/v1",
			Setting:              "model_provider and [model_providers.openai-observer]",
			Note:                 "proxyroute.RegisterMemberRoute(open-interpreter) adds [model_providers.openai-observer] (base_url = proxy /v1, wire_api responses) and sets model_provider in ~/.openinterpreter/config.toml (INTERPRETER_HOME); member edits only, never a key; refuses a reserved [model_providers.openai] or another selected provider",
			LiveGate:             "LC11",
			SharesCredentialFile: true, CredentialFileReason: routeCredOpenInterpreter,
		},
		Routability: RouteStatusProbeRequired,
		// Codex's hook mechanism (HookCodexConfig) may port, but this
		// fork's config.toml has no [hooks] observed live — unverified.
		Hook: HookSpec{Mechanism: HookOpenInterpreterHooks, AutoWired: true, Bindings: hookBindingsOpenInterpreter},
		// [mcp_servers] TOML table almost certainly matches codex's format,
		// but MCP must be nil here: no writer exists yet (TestMCPTargets
		// requires nil for every tool without a grounded implemented
		// writer) — the format finding is preserved in the plan doc for
		// the Phase-B/C adapter build.
		MCP:    nil,
		Native: NativeRails{},
		// Rollout JSONL byte-identical to codex's; token_count event GROSS
		// input, nets the same way — Tier 2 until proxy routability
		// confirmed.
		TokenTier: TokenTier{Best: "jsonl", Gap: "no proxy path verified on this fork; hook mechanism unconfirmed", ReasoningDisjoint: true, GenerationTiming: GenTimingTranscript},
		// GUI launch row: the Interpreter DESKTOP app (batch-3 T5,
		// 2026-09-03). Two stores under one adapter: the CLI's
		// ~/.openinterpreter/sessions (INTERPRETER_HOME) and the desktop
		// app's embedded <userData>/interpreter/codex-home/sessions
		// (Windows grounded: %APPDATA%\interpreter; macOS/Linux rungs are
		// the Electron convention, UNVERIFIED). Both are codex-shaped
		// rollouts parsed by codex.NewOpenInterpreter(); the desktop's own
		// originator `codex_ui` stamps desktop/open-interpreter.
		GUI: &GUILaunchSpec{
			ID:      "open-interpreter-desktop",
			Label:   "Interpreter",
			Surface: "desktop",
			Binary: BinaryResolveSpec{
				Names: BinaryNames{
					Windows: []string{"Interpreter.exe"},
				},
				ProbeDirs: []ProbeDir{
					// Per-machine Program Files install, NOT the Squirrel
					// per-user layout its updater dir suggests.
					{OS: ProbeWindows, Rel: "Interpreter", EnvRoot: "ProgramFiles"},
				},
				InstallNote: "no grounded macOS or Linux channel: no Homebrew cask and no winget package found " +
					"(checked 2026-09-03); the vendor ships a direct download (openinterpreter.com/docs/desktop; " +
					"no account needed).",
			},
			// PATH walk disabled: the CLI answers to `interpreter` /
			// `interpreter.exe`, which resolves case-insensitively against
			// Interpreter.exe on Windows. Probe dirs only.
			ProbeOnly:      true,
			ProjectDirArgv: false,
			Wrap: WrapSpec{
				Kind: WrapNone,
				Reason: "the desktop's provider base URLs live per profile in its own codex-home/config.toml " +
					"(alongside plaintext API keys - a file Observer never reads); the row's ProxyProbe writer " +
					"targets the CLI's user config.toml instead and is switched off until live check LC11, " +
					"so config_write would name no writer for the desktop. Launch yes, wrap no.",
			},
			Hosts:    []string{"open-interpreter"},
			Grounded: true,
			Note: "Windows layout grounded on this box 2026-09-03: %ProgramFiles%\\Interpreter\\Interpreter.exe " +
				"(the updater payload sits at %LOCALAPPDATA%\\interpreter-updater\\installer.exe). macOS " +
				"bundle NOT grounded - DarwinApp left empty. Sessions: %APPDATA%\\interpreter\\codex-home\\" +
				"sessions\\YYYY\\MM\\DD\\rollout-*.jsonl, ingested by this row's adapter (tool id " +
				"open-interpreter, surface desktop/open-interpreter).",
		},
		Handoff: HandoffCapability{
			Transcript: TranscriptFull,
			Inject:     []InjectKind{InjectFile, InjectPrompt},
			// Seed contract grounded 2026-07-29 against THIS fork's own
			// help (not codex's): `interpreter --help` prints
			// `Usage: interpreter [OPTIONS] [PROMPT]` and
			// `Arguments: [PROMPT]  Optional user prompt to start the
			// session` — the codex trailing-positional shape. A live
			// zero-spend parse smoke confirmed the argv is accepted
			// (`interpreter "seed text"` reaches the TTY gate — "stdin is
			// not a terminal" — while an unknown token is rejected by clap
			// with "unexpected argument", so acceptance discriminates).
			Launch: &LaunchSpec{Subcommand: "open-interpreter", Mode: LaunchSeeded},
		},
		// Attachable: `observer open-interpreter --attach`.
		Attach: &AttachSpec{Subcommand: "open-interpreter"},
		// Native resume: `interpreter resume <SESSION_ID>` — the codex
		// subcommand shape, grounded 2026-07-29 on `interpreter resume
		// --help`: `Usage: interpreter resume [OPTIONS] [SESSION_ID]
		// [PROMPT]`, `[SESSION_ID]  Session id (UUID) or session name`. A
		// live zero-spend smoke accepted the argv (reached the TTY gate)
		// while clap rejects an unknown token, so acceptance is real. The
		// id is our stored SessionID verbatim: the rollout's `session_meta`
		// carries the same UUID the codex parser adopts as SessionID.
		Resume: ResumeSpec{Kind: ResumeNative, Subcommand: "open-interpreter", IDMechanism: "subcommand:resume"},
		Binary: &BinaryResolveSpec{
			Names: BinaryNames{Unix: []string{"interpreter"}, Windows: []string{"interpreter.exe"}},
			// Live install layout (2026-07-29): ~/.local/bin/interpreter is
			// a symlink into the standalone package's own bin dir. Windows
			// GROUNDED 2026-09-02: install.ps1's own
			// $defaultVisibleBinDir = Join-Path $env:LOCALAPPDATA
			// "Programs\Open Interpreter\bin" (a junction into the
			// versioned store).
			ProbeDirs: []ProbeDir{
				{OS: ProbeUnix, Rel: ".local/bin"},
				{OS: ProbeUnix, Rel: ".openinterpreter/packages/standalone/current/bin"},
				{OS: ProbeWindows, Rel: "AppData/Local/Programs/Open Interpreter/bin"},
			},
			// Officially documented channels (openinterpreter.com
			// /docs/terminal/install): the shell installer only — the docs
			// list no npm or Homebrew channel. NOTE: `pip install
			// open-interpreter` is the UNRELATED Python project of the same
			// name and must never be offered here.
			Installs: []InstallHint{
				// T-034j (2026-10-07, script re-read): both scripts end with
				// "Start ... now?" (a y/N read through /dev/tty or Read-Host);
				// OPEN_INTERPRETER_NONINTERACTIVE=1 answers it "no" without
				// asking (their only prompt).
				{OS: "linux", Channel: "script", Argv: []string{"bash", "-lc", "curl -fsSL https://www.openinterpreter.com/install | OPEN_INTERPRETER_NONINTERACTIVE=1 sh"}, Display: "curl -fsSL https://www.openinterpreter.com/install | OPEN_INTERPRETER_NONINTERACTIVE=1 sh", Requires: []string{"curl", "tar"}},
				{OS: "darwin", Channel: "script", Argv: []string{"bash", "-lc", "curl -fsSL https://www.openinterpreter.com/install | OPEN_INTERPRETER_NONINTERACTIVE=1 sh"}, Display: "curl -fsSL https://www.openinterpreter.com/install | OPEN_INTERPRETER_NONINTERACTIVE=1 sh", Requires: []string{"curl", "tar"}},
				{OS: "windows", Channel: "script", Argv: []string{"powershell", "-Command", "$env:OPEN_INTERPRETER_NONINTERACTIVE='1'; irm https://www.openinterpreter.com/install.ps1 | iex"}, Display: "$env:OPEN_INTERPRETER_NONINTERACTIVE='1'; irm https://www.openinterpreter.com/install.ps1 | iex"},
			},
		},
		// Model picker (B5). This fork is a rebadged codex build
		// (internal/adapter/codex's codex.NewOpenInterpreter() retag,
		// CLAUDE.md); its own `interpreter --help` was grounded live
		// 2026-08-08 and lists `-m, --model <MODEL>` identically to
		// codex's own flag — long form used per convention. The
		// `observer open-interpreter` launcher is DisableFlagParsing +
		// launcherArgsOrDone (B6), so a forwarded `--model <value>`
		// reaches the interpreter binary unmodified.
		Model: ModelSpec{Kind: ModelArg, Flag: "--model"},
		// Sandbox filesystem-isolation row (B9). GROUNDED against
		// internal/adapter/codex/openinterpreter.go homeDirName (".openinterpreter"
		// — the rebadged Codex CLI's own home, <home>/.openinterpreter/sessions).
		// That dir's config*.toml holds plaintext provider keys, which the adapter
		// never reads and the tool always needs, so the whole dir is bound rw.
		Sandbox: SandboxSpec{StateRW: []string{".openinterpreter"}},
	},
	// commandcode.ai's npm CLI (docs/plans/commandcode-adapter-plan-2026-07-29.md).
	// Phase-0 research only — no adapter package yet (Phase A wiring row).
	"command-code": {
		Tool: "command-code",
		// FIX-7 (phase-2 review): promoted from PromptLaneProbeRequired.
		// commandcode's prompt-submit lane is a documented Mods SDK
		// module (commandcode.ai/docs/mods): `transformInput`,
		// `{text}` input, `action:'handled'` info row, and a genuine
		// redact lane via `action:'transform'` — a different
		// PACKAGING (a Mods-SDK module, not a shell hook) than every
		// other row here. Part B item 2 (phase-3a, 2026-09-07) wired it
		// after re-fetching commandcode.ai/docs/mods live: mods are
		// no-build TypeScript files (jiti-compiled at load time) loaded
		// from ~/.commandcode/mods/*.ts, registered via
		// `cmd.hooks({transformInput({text}){...}})`. The emitter is a
		// go:embed'd .ts template (the hermesplugin precedent — an
		// embedded, non-JSON-config registration model) that shells out
		// to `observer hook command-code transformInput`, mirroring
		// every other dialect's argv shape. The ONE documented input
		// field is `text` — no session/conversation id anywhere in the
		// signature, so ask-once/redact findings here fail closed to a
		// hard, unconditional block (the engine's own documented
		// empty-session-id rule; see internal/hook/promptsubmit.go's
		// extractCommandCodePrompt). `action:'transform'` (the genuine
		// redact lane) stays unpopulated — not wired on any channel yet.
		PromptLane: PromptLaneHook,
		Vocabulary: Vocabulary{InTaxonomy: true},
		// COMMANDCODE_API_URL / COMMAND_CODE_API_KEY / COMMANDCODE_API_ENV
		// point at Command Code's OWN closed gateway. Surface-gap S-16
		// (2026-10-25, https://commandcode.ai/docs/byok): BYOK
		// ~/.commandcode/providers.json provider.<id>.baseURL takes
		// openai-completions, openai-responses and anthropic-messages
		// endpoints, a real base-URL knob, so the row is probe_required (was
		// after_bridge). No writer yet: no routed turn has been seen, and
		// which provider entry a session uses is not grounded.
		Proxy:       nil,
		Routability: RouteStatusProbeRequired,
		// CrossOSBridge: true — internal/hook's command-code-windows
		// target (registerCommandCodeWindows) bakes the wsl.exe bridge
		// into the go:embed'd TS mod's own runtime (resolveExec()),
		// mirroring claude-code/cursor/codex's own bridges.
		Hook: HookSpec{Mechanism: HookCommandCodeMod, CrossOSBridge: true, AutoWired: true, Bindings: hookBindingsCommandCode},
		// ~/.commandcode/mcp.json reuses claude-code/cursor/droid's
		// {"mcpServers":{}} shape, grounded 2026-07-29 from the npm
		// package's cli.mjs getUserMcpConfigPath + bundled reference/mcp.md.
		// A writer already exists (internal/mcp/register.go's generic
		// registerJSONMCP, via the internal/mcp/locate row) so this is
		// Implemented, not a new writer.
		// Remote grounded 2026-09-24 against commandcode.ai/docs/mcp:
		// `{"transport":"http","enabled":true,"url":…,"headers":{…}}` — the
		// transport key is `transport` (not `type`), only "http" (Streamable
		// HTTP) is documented for remote, no SSE spelling. `${VAR}` values
		// resolve at runtime and OAuth tokens live in mcp-tokens.json, so the
		// relay writer never needs (and never writes) a secret here.
		MCP: &MCPTarget{Format: MCPServersJSON, PathHint: ".commandcode/mcp.json", Implemented: true, SharesCredentialFile: true, CredentialFileReason: mcpCredCommandCode, Remote: &MCPRemoteTarget{
			Transports:   []MCPRemoteTransport{MCPRemoteStreamableHTTP},
			Headers:      true,
			TransportKey: "transport",
			Spelling:     map[MCPRemoteTransport]string{MCPRemoteStreamableHTTP: "http"},
			Flags:        map[string]bool{"enabled": true},
			Implemented:  true,
			Note:         "commandcode.ai/docs/mcp 2026-09-24: transport http (streamable HTTP only) + enabled + url + headers",
		}},
		Native: NativeRails{},
		// Per-assistant-message usage envelope (inputTokens/outputTokens/
		// cacheReadTokens/cacheWriteTokens/costUsd); inputTokens almost
		// certainly GROSS (high confidence, not proxy-confirmed).
		TokenTier: TokenTier{Best: "jsonl", Gap: "no Tier-1 proxy path; costUsd trusted as-is for open-weight models with no observer pricing table", ReportsCost: true},
		Handoff: HandoffCapability{
			Transcript: TranscriptFull,
			Inject:     []InjectKind{InjectFile, InjectPrompt},
			// Seed contract grounded 2026-07-29 against `commandcode
			// --help` (v1.4.5), whose Options block states the two default-
			// command forms verbatim: `commandcode   Start interactive
			// session` and `commandcode "message"   Start with initial
			// message` — a bare positional on the default TUI command, so
			// the launcher appends the handover as the TRAILING positional.
			// `-p, --print [query]` is the headless one-shot ("Run in
			// non-interactive mode, output response and exit") and is a
			// declared conflict.
			Launch: &LaunchSpec{Subcommand: "command-code", Mode: LaunchSeeded},
		},
		// Attachable: `observer command-code --attach`.
		Attach: &AttachSpec{Subcommand: "command-code"},
		// Native resume: `commandcode --session <id>`. Grounded 2026-07-29
		// on `commandcode --help`: `--session <path|id>   Resume a session
		// by transcript path (.jsonl) or a unique session-id prefix`. This
		// is the REQUIRED-value spelling, so the plain two-token form is
		// unambiguous — deliberately preferred over `-r, --resume [name]`,
		// which is an OPTIONAL-value option (the shape that forced cursor's
		// joined `=` workaround) and resolves names as well as ids. The id
		// is our stored SessionID verbatim (sessionIDFromPath: the
		// `<uuid>.jsonl` basename under ~/.commandcode/projects/<enc-cwd>/).
		Resume: ResumeSpec{Kind: ResumeNative, Subcommand: "command-code", IDMechanism: "flag:--session"},
		Binary: &BinaryResolveSpec{
			// The npm package installs FOUR bin aliases for one binary
			// (`cmd`, `cmdc`, `command-code`, `commandcode` — registry-
			// confirmed). Only the two unambiguous spellings are listed:
			// `cmd`/`cmdc` are omitted deliberately (on Windows `cmd`
			// resolves to the system shell — a shadowing hazard, the same
			// exclusion internal/processobs already makes).
			//
			// Windows spellings are the npm SHIM forms, not `.exe`. The
			// package's bins are JavaScript entry points, so a global npm
			// install writes `<name>.cmd` (+ a `.ps1` and a bare POSIX-shell
			// shim for Git Bash/MSYS) into the npm prefix — it never
			// produces a `<name>.exe`. Both aliases get the same pair, which
			// also fixes an asymmetry: `command-code` previously claimed
			// only a `.cmd` while `commandcode` claimed three forms.
			// `.ps1` is left out on purpose: toolresolve stats a candidate
			// and then EXECS it, and a PowerShell script is not directly
			// executable. Resolution order is not load-bearing here —
			// toolresolve.orderNamesByPathExt re-sorts Windows candidates by
			// the operator's own PATHEXT.
			Names: BinaryNames{
				Unix:    []string{"commandcode", "command-code"},
				Windows: []string{"commandcode.cmd", "commandcode", "command-code.cmd", "command-code"},
			},
			// Official channel: the npm package `command-code` (registry-
			// confirmed name/description/bins). No script or brew channel
			// is documented.
			// Minimum host runtime, grounded 2026-10-04 from the npm registry
			// (`npm view <pkg> engines`): command-code 1.74.1 declares engines.node.
			Runtime: &RuntimeRequirement{Runtime: RuntimeNode, MinVersion: "22", Product: "Command Code", Source: "npm registry engines.node, command-code 1.74.1, read 2026-10-04"},
			Installs: []InstallHint{
				{OS: "", Channel: "npm", Argv: []string{"npm", "install", "-g", "command-code"}, Display: "npm install -g command-code"},
			},
		},
		// Model picker (B5). Grounded live 2026-08-08: `commandcode --help`
		// lists `-m, --model <model>` — "Run on a specific model this
		// session" — long form used per convention. The
		// `observer command-code` launcher is DisableFlagParsing +
		// launcherArgsOrDone (B6), so a forwarded `--model <value>`
		// reaches the commandcode binary unmodified.
		Model: ModelSpec{Kind: ModelArg, Flag: "--model"},
		// Sandbox filesystem-isolation row (B9). GROUNDED against
		// internal/adapter/commandcode/adapter.go defaultRoots
		// (<home>/.commandcode/projects). ~/.commandcode is the CLI's whole state
		// dir (per-project transcripts + config.json) and is bound rw as one dir.
		// mods/ is jiti-loaded TypeScript (register.go HookCommandCodeMod).
		Sandbox: SandboxSpec{NeedsWin32k: true, StateRW: []string{".commandcode"}, ProtectRO: []string{".commandcode/mcp.json"}, ProtectRODirs: []string{".commandcode/mods"}},
	},
	// Meta's Muse Code CLI (docs/muse-adapter.md). Phase-0 grounded
	// 2026-08-06 against a live `Muse Code 0.1.0 (0.1.0-R708.1)` install on
	// Linux x86_64 (session log + config files + the shipped binary's own
	// string table). Every cell below is either observed in that install or
	// an explicit zero.
	"muse": {
		Tool: "muse",
		// 8 grounded native tool names in internal/tooltax (4 from the live
		// capture: bash / read_file / write_file / edit_file; 4 named
		// verbatim in the binary: web_search / web_fetch / read_skill /
		// search) plus the conventional defensive vocabulary.
		Vocabulary: Vocabulary{
			InTaxonomy: true,
			Note: "27 tools were active in the Phase-0 run but the log's " +
				"model_request_configured trace elides the names " +
				"(active_tools:[\"<string>\"], #len=27), so the tail of the " +
				"surface is defensive rather than observed",
		},
		// Model traffic goes to https://api.meta.ai/v1, whose base URL is
		// MINTED BY THE LOGIN FLOW ("mint response missing api_key or
		// base_url" / "unrecognized Model API base URL from login; using the
		// default") and authenticated with a Model API key. TBH_AUTH_BASE_URL
		// and TBH_MINT_BASE_URL steer only the auth + mint endpoints, NOT
		// model traffic, so neither is a route knob. settings.json does carry
		// an endpoint/transport block with `proxy` and mTLS fields plus a
		// `destination` discriminator ("destination=external is direct-only:
		// proxy/mTLS fields do not apply") — a real surface whose schema is
		// NOT grounded and which has never been driven live. That is exactly
		// probe_required: a documented-in-binary BYOK-ish path, unconfirmed on
		// a live install. Proxy stays nil until a live turn lands an api_turns
		// row (checklist §10.1f). Surface-gap S-16: `muse --help` lists a
		// --base-url flag, contradicting AP-036's "not grounded"; whether it
		// exists and routes is live check LC35, and no launcher flag is
		// written until it passes.
		Proxy:       nil,
		Routability: RouteStatusProbeRequired,
		// The binary carries a Claude-Code-derived hook vocabulary in
		// settings.json — user_prompt_submit / pre_tool_use /
		// permission_request / post_tool_use / pre_llm_call / post_llm_call /
		// pre_compact / post_compact / subagent_start / subagent_stop, with
		// matcher-group diagnostics ("hook matcher group must declare
		// `hooks`") and explicit Claude-compat rejections (D99 "Claude
		// `command` plus `args` argv execution is not implemented yet"). But
		// the on-disk matcher schema is not grounded and observer ships no
		// receiver, so the honest value is None: a mechanism named here would
		// make init claim a registration it cannot write.
		Hook: HookSpec{Mechanism: HookMuseSettings, AutoWired: true, Bindings: hookBindingsMuse},
		// Muse is an MCP client (settings.json carries a server block with
		// transport/command/env/framing/url/headers + stdio |
		// streamable_http, and the binary reports "MCP tool name collision
		// for `…`"), but that shape is its OWN, not the shared
		// {"mcpServers":{…}} object any existing writer emits. No writer, no
		// grounded PathHint → nil rather than a fabricated target.
		MCP:    nil,
		Native: NativeRails{},
		// Tier-2 transcript capture only. model_completed.usage carries
		// input/output/cache_read/cache_write/cached/reasoning; both gross
		// fields are netted at emit time. No proxy lane ⇒ no Tier-1, and
		// observer ships no pricing entry for Muse models because Meta
		// publishes no per-token rate card for the subscription.
		TokenTier: TokenTier{
			Best: "transcript",
			Gap: "no Tier-1 proxy path (login-minted base URL); no pricing " +
				"entry for muse-* models, so cost rows resolve as unknown",
			// model_completed usage is DUAL-netted (output excludes
			// reasoning) and model_completed.duration_ms is the call's own
			// duration (S10-SPEED).
			ReasoningDisjoint: true,
			GenerationTiming:  GenTimingNative,
		},
		// The log re-reads in full (prompts, assistant text, tool bodies) so
		// a completed session is a usable handoff source. No Launch: the
		// interactive-seed contract has NOT been grounded — the checklist
		// requires reading the tool's own --help, and this session was
		// forbidden from invoking the CLI at all. InjectFile is the
		// universal floor and is all that is claimed.
		// Launcher GROUNDED 2026-08-06 against a live `muse --help` /
		// `muse resume --help` / `muse exec --help` read (this session was
		// permitted to invoke the CLI, unlike Phase 0). `Usage: muse
		// [OPTIONS] [PROMPT]` seeds the interactive session as a bare
		// trailing positional (LaunchSeeded); `cmd/observer/muse.go` is the
		// wired launcher.
		Handoff: HandoffCapability{
			Transcript: TranscriptFull,
			Inject:     []InjectKind{InjectFile, InjectPrompt},
			Launch:     &LaunchSpec{Subcommand: "muse"},
		},
		// Attach grounded 2026-08-06 (attach-all-launchers); PTY handoff
		// only — no prompt seeding, token capture path unchanged. muse is
		// launched non-proxied (Proxy stays nil above), so the attach spec
		// forwards no proxy env.
		Attach: &AttachSpec{Subcommand: "muse"},
		// Native resume GROUNDED off `muse resume --help`: `Usage: muse
		// resume` / `muse resume --last` / `muse resume <session-uuid>` —
		// a SUBCOMMAND whose positional argument is the session uuid. The
		// id is our stored SessionID verbatim (muse's own directory-name
		// uuid — internal/adapter/muse's sessionIDFromPath), so no
		// transform. Argv construction verified via
		// cmd/observer/resume_launcher_test.go, not a live resume (no paid
		// turn was run).
		Resume: ResumeSpec{Kind: ResumeNative, Subcommand: "muse", IDMechanism: "subcommand:resume"},
		// Binary: Names.Unix populated (required for a launchable tool).
		// Installs GROUNDED 2026-08-07: the self-updating ~/.local/bin/muse
		// launcher itself is behind auth.meta.com device login (still true,
		// per docs/muse-adapter.md), but Meta separately publishes an
		// unauthenticated bootstrap script at dev.meta.ai — fetched live
		// here, its body is a real bash script (`command_name="muse"`,
		// installs into `${MUSE_INSTALL_DIR:-$HOME/.local/bin}`, pulls
		// `https://api.meta.ai/muse-launcher.sh`) that matches this
		// registry's own grounded knowledge of the install layout exactly,
		// and two independent outlets (9to5mac's launch coverage; a
		// layer3labs how-to citing Meta's own product page) quote the same
		// command. No Windows build exists (docs/muse-adapter.md), so
		// linux/darwin only — Names.Windows stays nil.
		Binary: &BinaryResolveSpec{
			Names: BinaryNames{Unix: []string{"muse"}},
			Installs: []InstallHint{
				{OS: "linux", Channel: "script", Argv: []string{"bash", "-lc", "curl -fsSL https://dev.meta.ai/install.sh | bash"}, Display: "curl -fsSL https://dev.meta.ai/install.sh | bash", Requires: []string{"curl"}},
				{OS: "darwin", Channel: "script", Argv: []string{"bash", "-lc", "curl -fsSL https://dev.meta.ai/install.sh | bash"}, Display: "curl -fsSL https://dev.meta.ai/install.sh | bash", Requires: []string{"curl"}},
			},
			// Honest-zero carriers (2026-09-02): Names.Windows stays nil
			// AND no Windows InstallHint exists — GROUNDED against
			// muse-launcher.sh's own detect_platform() (dies on any
			// uname -s other than Darwin/Linux) and Meta's developer blog
			// ("Install Muse Code in macOS or Linux with a single
			// command"). WSL2 works because uname -s reports Linux there.
			WindowsNote:     "macOS/Linux only per vendor (muse-launcher.sh detect_platform dies on any uname -s other than Darwin/Linux); runs under WSL2 because uname -s = Linux there",
			InstallNote:     "no Windows install channel - install inside WSL2 and run the observer daemon there",
			UserInstallHint: "Muse runs on macOS and Linux only. On Windows, install it inside WSL and run SuperBased there.",
		},
		// Model picker (B5). Grounded live 2026-08-08: `muse --help` lists
		// `--model <MODEL>` — "Model id for non-echo providers" — under
		// the default (interactive) usage line, not a subcommand-gated
		// flag. The `observer muse` launcher is DisableFlagParsing +
		// launcherArgsOrDone (B6), so a forwarded `--model <value>`
		// reaches the muse binary unmodified. No Known values: muse's
		// login-minted model catalog was never grounded live (Proxy above
		// stays nil for the same reason), so none is fabricated here.
		Model: ModelSpec{Kind: ModelArg, Flag: "--model"},
		// Sandbox filesystem-isolation row (B9). GROUNDED against
		// internal/adapter/muse/adapter.go defaultRoots
		// ($XDG_DATA_HOME|<home>/.local/share/muse/sessions) plus the config dir
		// the package doc names ($XDG_CONFIG_HOME|~/.config/muse — auth.json and
		// trust.json, both NEVER read by the adapter and both required by muse
		// itself). Both bound rw.
		Sandbox: SandboxSpec{
			StateRW: []string{".config/muse", ".local/share/muse"},
		},
	},
	"prime-agent": {
		Tool: "prime-agent",
		// FIX-7 (phase-2 review): no prompt-submit hook mechanism has
		// been found for Prime Agent CLI at all (PrimeIntellect-ai/
		// prime-agent#872, contract §2.4). The proxy lane (already
		// routed today) is its only path to prompt-submit
		// intervention.
		PromptLane: PromptLaneProxyOnly,
		// Prime Agent is deliberately a ONE-TOOL agent: "Available
		// built-in tools: `ipython`" (README) — the model drives a
		// persistent Python kernel for everything. `bash` and `edit` are
		// the two other built-in names docs/extensions.md says an
		// extension may override. All three carry tooltax rows; the rest
		// of the classifier is the conventional defensive vocabulary.
		Vocabulary: Vocabulary{
			InTaxonomy: true,
			Note: "the native surface is a single built-in tool (`ipython`); " +
				"skills are Python-backed and run INSIDE that kernel, and MCP " +
				"servers are reached from Python as `integration.<tool>(…)`, so " +
				"neither adds an LLM-visible tool name",
		},
		// ROUTABLE surface, route NOT DRIVEN YET. `~/.prime/agent/
		// models.json` accepts a custom provider with an explicit `baseUrl`
		// and `"api":"openai-completions"` (vendor docs/models.md: "Add
		// custom providers and models (Ollama, vLLM, LM Studio, proxies)
		// via ~/.prime/agent/models.json"), and `prime-agent --provider
		// <name>` selects it (confirmed in --help). That is structurally
		// the SAME RouteProviderJSON route cmd/observer/pi.go already
		// drives for pi — unsurprising, since prime-agent is a hard fork of
		// the same pi-mono upstream and inherited the file schema.
		//
		// `prime-agent --provider observer`. PROMOTED 2026-08-21: a live
		// `observer prime-agent --provider observer --model gpt-4o-mini -p`
		// turn landed api_turns rows through the proxy with REAL usage
		// captured (id 166806, provider openai, gpt-4o-mini, 4119/2 tokens,
		// valid key) — checklist §10.1f fully met.
		Proxy: &ProxyRoute{
			ClientAuth:           ClientAuthPathToken,
			SharesCredentialFile: true, CredentialFileReason: routeCredPrimeAgent,
			PersistedDefault: &PersistedDefault{
				Note:     "CLI-1a: proxyroute.RegisterDefaultProvider(prime-agent) sets defaultProvider = observer in ~/.prime/agent/settings.json once the launcher's observer provider is in models.json, so a bare prime-agent routes; member edit, never a key; defaultModel must name a model of that provider (part of the live check)",
				LiveGate: "LC25",
			},
			Kind: RouteLauncher, EnvVar: "", Suffix: "/v1", Launcher: "observer prime-agent", Note: "Routes via the 'observer' provider entry the launcher writes into ~/.prime/agent/models.json (baseUrl = proxy /v1); exec with --provider observer.",
			// Demo node 1, 2026-10-02: the session started on the observer
			// provider (2 proxied turns), then switched to openrouter, and
			// the secret-bearing prompt went there directly.
			PromptScope:       "Only turns sent to the \"observer\" provider the launcher writes go through the proxy, plus, on a managed node, every built-in provider the launcher can point at a proxy lane for the session; a switch to a built-in provider with no proxy lane (Bedrock, Azure, Vertex, Cloudflare, Mistral, the ChatGPT sign-in, GitHub Copilot, OpenCode) or to your own custom provider bypasses it and is flagged after send.",
			ProviderOverrides: joinProviderOverrides(piFamilyProviderOverrides, primeAgentOnlyProviderOverrides),
		},
		Routability: RouteStatusRoutableNow,
		// Prime Agent's extension points are TypeScript EXTENSIONS
		// (-e/--extension, pi.registerTool / lifecycle callbacks), not a
		// settings.json hook-command vocabulary observer can register into.
		// Observer ships no receiver → None rather than a mechanism init
		// cannot write.
		Hook: HookSpec{Mechanism: HookNone, Bindings: hookBindingsPrimeAgent},
		// Prime Agent IS an MCP client, but its servers are configured
		// through the TUI's /login → "MCP Connections" flow with
		// credentials in auth.json, and are called from inside the Python
		// kernel. That is not the shared {"mcpServers":{…}} object any
		// existing writer emits, and no grounded on-disk path was
		// established → nil rather than a fabricated target.
		MCP:    nil,
		Native: NativeRails{},
		// Tier-2 transcript only (no proxy lane driven yet). usage carries
		// input/output/cacheRead/cacheWrite + a provider-reported cost
		// breakdown; `input` is already NET (totalTokens == input + output
		// + cacheRead + cacheWrite holds exactly on every observed row), so
		// nothing is re-netted.
		TokenTier: TokenTier{
			Best: "transcript",
			Gap: "no reasoning-token count in the usage envelope on either " +
				"API lane (thinking TEXT is captured, the count is not " +
				"published); no pricing entries for the prime-inference / " +
				"openrouter model ids seen, so cost rows resolve as unknown " +
				"apart from the provider-reported usage.cost.total",
			ReportsCost: true,
		},
		// The log re-reads in full — prompts, assistant text, thinking
		// blocks, tool bodies and shell output — so a completed session is
		// a usable handoff source.
		//
		// Launcher GROUNDED 2026-08-06 against a live `prime-agent --help`
		// read (this session was permitted to invoke the CLI). `Usage:
		// prime-agent [options] [@files...] [message...]` seeds the
		// interactive session as a trailing positional (LaunchSeeded);
		// `cmd/observer/prime-agent.go` is the wired launcher (also drives
		// the RouteProviderJSON route structurally — see Proxy above,
		// which stays nil pending a live-verified turn).
		Handoff: HandoffCapability{
			Transcript: TranscriptFull,
			Inject:     []InjectKind{InjectFile, InjectPrompt},
			Launch:     &LaunchSpec{Subcommand: "prime-agent"},
		},
		// Attach grounded 2026-08-06 (attach-all-launchers); PTY handoff
		// only — no prompt seeding, token capture path unchanged.
		Attach: &AttachSpec{Subcommand: "prime-agent"},
		// Native resume GROUNDED off `prime-agent --help`: `-r, --resume
		// <path|id>` is a REQUIRED-value flag (angle brackets) taking the
		// session UUID this adapter already keys on (the `<uuid>.jsonl`
		// filename stem), so no transform. Argv construction verified via
		// cmd/observer/resume_launcher_test.go, not a live resume (no
		// paid turn was run).
		Resume: ResumeSpec{Kind: ResumeNative, Subcommand: "prime-agent", IDMechanism: "flag:--resume"},
		// Binary: Names.Unix populated (required for a launchable tool).
		// CORRECTED 2026-08-07: the prior row here claimed an `npm install
		// -g prime-agent` channel on the strength of `npm ls -g` showing
		// the live install as `prime-agent@0.7.0` — but that reflects HOW
		// the vendor installer lays the package down locally, not a public
		// registry entry. `registry.npmjs.org/prime-agent` returns 404 (no
		// such package has ever been published), reproduced live via both
		// `npm view prime-agent` and a direct registry GET on 2026-08-07 —
		// so the old hint would 404 for any operator who ran it. The
		// project's actual, grounded public channel is the installer script
		// named in its own README (github.com/PrimeIntellect-ai/prime-agent)
		// and in docs/plans/prime-agent-adapter-plan-2026-08-06.md: it
		// downloads a versioned release, verifies its SHA-256 checksum, and
		// installs the `prime-agent` command. No Windows build is
		// documented (README leads with Linux/macOS) → Names.Windows stays
		// nil.
		// Windows GROUNDED 2026-09-02: the npm package itself carries no
		// `os` restriction (tarball v0.9.1 package.json bin
		// {prime-agent: dist/bundle/cli.js}), but the package is NOT
		// published to the public npm registry (see the CORRECTED
		// 2026-08-07 comment above). No npm channel is declared here
		// (TestGuidedInstallGapClosed pins that).
		// T-037 (2026-10-07, script re-read): the Windows GUIDED install is
		// withdrawn. The vendor install.sh has no Windows branch (every
		// `uname -s` case knows only Darwin and Linux; no MINGW / MSYS /
		// CYGWIN), so on Windows it falls back to an existing Node.js + npm,
		// and its Node-path confirmation always prompts. Spawned by the
		// dashboard as `bash -lc` it would also pick whichever bash.exe is
		// first on PATH, often the WSL launcher in System32, installing into
		// WSL instead of Windows. The Windows spelling stays in Names so a
		// manual install from Git Bash still resolves; the dashboard shows
		// InstallNote / UserInstallHint instead of a guided command.
		// T-034j (same re-read): the unix script asks "Install Prime Agent
		// v...?" and whether to set up the Python kernel runtime through
		// /dev/tty, which a PTY provides, so the guided install sat at the
		// prompt. PRIME_AGENT_INSTALLER_NONINTERACTIVE=1 skips the first and
		// PRIME_AGENT_BOOTSTRAP_KERNEL_ON_INSTALL=1 answers the second
		// (yes: ipython is Prime Agent's only tool). The env sits on the
		// interpreter side of the pipe so the piped script sees it.
		Binary: &BinaryResolveSpec{
			Names: BinaryNames{
				Unix:    []string{"prime-agent"},
				Windows: []string{"prime-agent.cmd", "prime-agent"},
			},
			Installs: []InstallHint{
				{OS: "linux", Channel: "script", Argv: []string{"bash", "-lc", "curl -fsSL https://app.primeintellect.ai/prime-agent/install.sh | PRIME_AGENT_INSTALLER_NONINTERACTIVE=1 PRIME_AGENT_BOOTSTRAP_KERNEL_ON_INSTALL=1 sh"}, Display: "curl -fsSL https://app.primeintellect.ai/prime-agent/install.sh | PRIME_AGENT_INSTALLER_NONINTERACTIVE=1 PRIME_AGENT_BOOTSTRAP_KERNEL_ON_INSTALL=1 sh", Requires: []string{"curl"}},
				{OS: "darwin", Channel: "script", Argv: []string{"bash", "-lc", "curl -fsSL https://app.primeintellect.ai/prime-agent/install.sh | PRIME_AGENT_INSTALLER_NONINTERACTIVE=1 PRIME_AGENT_BOOTSTRAP_KERNEL_ON_INSTALL=1 sh"}, Display: "curl -fsSL https://app.primeintellect.ai/prime-agent/install.sh | PRIME_AGENT_INSTALLER_NONINTERACTIVE=1 PRIME_AGENT_BOOTSTRAP_KERNEL_ON_INSTALL=1 sh", Requires: []string{"curl"}},
			},
			WindowsNote:     "vendor: requires a bash shell on Windows (Git for Windows is sufficient); the install and the runtime both need bash - never PowerShell/CMD",
			InstallNote:     "no guided Windows install (T-037, 2026-10-07): the vendor install.sh has no Windows branch (uname cases are Darwin and Linux only), falls back to a pre-installed Node.js + npm and always prompts on that path, and a dashboard-spawned bash may be the WSL launcher; install by hand from Git Bash",
			UserInstallHint: "Prime Agent's installer supports Linux and macOS; on Windows, install it yourself from Git Bash with Node.js and npm already installed.",
		},
		// Model picker (B5). Grounded live 2026-08-08: `prime-agent --help`
		// lists a "Model options:" block with `--model <id>` — "Select a
		// model" — under the default (interactive) usage line. The
		// `observer prime-agent` launcher is DisableFlagParsing +
		// launcherArgsOrDone (B6), so a forwarded `--model <value>` reaches
		// the prime-agent binary unmodified.
		Model: ModelSpec{Kind: ModelArg, Flag: "--model"},
		// Sandbox filesystem-isolation row (B9). GROUNDED against
		// internal/adapter/primeagent/adapter.go defaultRoots (<home>/.prime/agent/
		// sessions). ~/.prime also holds auth.json and the daemon-worker state the
		// adapter never reads; the whole dir is bound rw because the CLI needs
		// it.
		Sandbox: SandboxSpec{StateRW: []string{".prime"}},
	},
	// JetBrains Junie (docs/junie-adapter.md). Phase-0 grounded 2026-08-17
	// against two real hello-world-scale sessions captured on the
	// operator's own WSL2 Ubuntu install. Three surfaces share one
	// ${JUNIE_HOME:-~/.junie}/sessions store: the IDE plugin (now inside
	// JetBrains AI Assistant), the standalone `junie` CLI (a terminal TUI,
	// live-captured 2026-09-07) and its `/local` mode. The CLI is what
	// `observer junie` launches (2026-10-03, terminal-picker coverage).
	"junie": {
		Tool: "junie",
		// Junie's events.jsonl is event-sourced: every record is a fixed
		// TYPED envelope/block kind (TerminalBlockUpdatedEvent,
		// FileChangesBlockUpdatedEvent, ResultBlockUpdatedEvent, …), not an
		// LLM-invoked tool NAME the model chose among several options — so
		// there is nothing for internal/tooltax to carry a row for. This is
		// the same honest-zero shape as the browser-chat *-web rows, for a
		// different reason (structural block kinds vs. no tool-call surface
		// at all).
		// Junie's own block kinds (Terminal/FileChanges/ViewFiles/Result)
		// are structural, not tool names — but a Junie run hosted inside
		// the JetBrains IDE calls the IDE's built-in `idea` MCP server tools
		// through McpBlockUpdatedEvent, and THOSE are real tool names
		// (grounded live 2026-09-03, batch-3 T6): internal/tooltax carries
		// the four exercised rows, the rest fall through to mcp_call.
		Vocabulary: Vocabulary{InTaxonomy: true, Note: "typed block kinds are structural; the tool names in the taxonomy are the JetBrains `idea/*` MCP server tools an IDE-hosted run calls"},
		// No observer route is driven. The CLI does document endpoint knobs
		// (2026-10-03): JUNIE_LITELLM_URL ("Base URL of your LiteLLM proxy",
		// junie.jetbrains.com/docs/environment-variables.html), custom model
		// profiles in $JUNIE_HOME/models/*.json carrying `baseUrl` + `apiType`
		// (docs/custom-llm-models.html) and config.json `proxies` entries
		// selected with --provider (docs/custom-proxies.html). None is the
		// default JetBrains-account lane and none has a live api_turns proof,
		// so this stays probe_required rather than a fabricated route.
		Proxy:       nil,
		Routability: RouteStatusProbeRequired,
		Hook:        HookSpec{Mechanism: HookJunieConfig, AutoWired: true, Bindings: hookBindingsJunie, HooksShareCredentialFile: true, CredentialFileReason: credFileJunie},
		MCP:         nil,
		Native:      NativeRails{},
		// Per-call model + cost + token counts come straight off
		// LlmResponseMetadataEvent.modelUsage[] in events.jsonl — no cache
		// tier is stated (CacheInputTokens/CacheCreateTokens both observed
		// zero in the Phase-0 capture, so nothing to report as a gap yet).
		TokenTier: TokenTier{Best: "events_jsonl", ReportsCost: true},
		// events.jsonl reconstructs the full turn (verbatim prompt, agent
		// narration, terminal/file/result blocks) — a genuinely re-readable
		// transcript, same tier as cline's api_conversation_history.json.
		//
		// Launch (2026-10-03, terminal-picker coverage): the standalone CLI
		// runs as an interactive TUI by default and `observer junie` starts it
		// in a PTY. DOC-ASSISTED, not Seeded: junie.jetbrains.com/docs/
		// parameters.html documents `--prompt` ("Start interactive mode with
		// an initial prompt already submitted"), but that seed lane has no
		// live verification yet, and a positional argument or `--task` runs
		// HEADLESS and exits, so the launcher writes the handover doc and
		// opens the TUI. Native resume (`--resume --session-id <id>`, same
		// page) is documented but not live-verified either: Resume stays
		// zero and the dashboard offers the handoff-fork resume instead.
		Handoff: HandoffCapability{
			Transcript: TranscriptFull,
			Inject:     []InjectKind{InjectFile},
			Launch:     &LaunchSpec{Subcommand: "junie", Mode: LaunchDocAssisted},
			Note:       "documented --prompt seed not live-verified: launch writes the handover doc and opens the junie TUI",
		},
		Attach: &AttachSpec{Subcommand: "junie"},
		// Credential env NAMES (never values), grounded 2026-10-03 against
		// junie.jetbrains.com/docs/environment-variables.html: the
		// usage-billed JUNIE_API_KEY plus the Junie-prefixed BYOK keys. The
		// plain ANTHROPIC_API_KEY / OPENAI_API_KEY spellings are not
		// documented for Junie, so they are not listed.
		AuthEnv: []string{
			"JUNIE_API_KEY", "JUNIE_ANTHROPIC_API_KEY", "JUNIE_OPENAI_API_KEY",
			"JUNIE_GOOGLE_API_KEY", "JUNIE_GROK_API_KEY", "JUNIE_OPENROUTER_API_KEY",
			"JUNIE_META_API_KEY",
		},
		// Binary resolution + grounded installs (2026-10-03,
		// junie.jetbrains.com/docs/junie-cli.html + github.com/JetBrains/junie
		// README + the install scripts themselves). install.sh needs curl
		// plus unzip on Linux / ditto on macOS (it exits naming each when
		// missing) and writes a bash SHIM at ~/.local/bin/junie that execs the
		// versioned native binary under ~/.local/share/junie/versions/<v>/.
		// install.ps1 uses PowerShell built-ins only and puts a junie.bat shim
		// in %USERPROFILE%\.local\bin (added to the user PATH). npm
		// `@jetbrains/junie` (registry.npmjs.org, Node >= 20) writes the usual
		// junie.cmd shim on Windows. The README's Homebrew route is a
		// third-party-tap two-step (`brew tap jetbrains-junie/junie` then
		// `brew install junie`), so it is not offered as one argv.
		Binary: &BinaryResolveSpec{
			Names: BinaryNames{
				Unix:    []string{"junie"},
				Windows: []string{"junie.bat", "junie.cmd"},
			},
			ProbeDirs: []ProbeDir{
				{OS: ProbeWindows, Rel: ".local/bin"},
			},
			// Minimum host runtime, grounded 2026-10-04 from the npm registry
			// (`npm view <pkg> engines`): @jetbrains/junie 3110.7.0 declares engines.node.
			Runtime: &RuntimeRequirement{Runtime: RuntimeNode, MinVersion: "20", Product: "Junie CLI", Source: "npm registry engines.node, @jetbrains/junie 3110.7.0, read 2026-10-04"},
			Installs: []InstallHint{
				{OS: "linux", Channel: "script", Argv: []string{"bash", "-lc", "curl -fsSL https://junie.jetbrains.com/install.sh | bash"}, Display: "curl -fsSL https://junie.jetbrains.com/install.sh | bash", Requires: []string{"curl", "unzip"}},
				{OS: "darwin", Channel: "script", Argv: []string{"bash", "-lc", "curl -fsSL https://junie.jetbrains.com/install.sh | bash"}, Display: "curl -fsSL https://junie.jetbrains.com/install.sh | bash", Requires: []string{"curl", "ditto"}},
				{OS: "windows", Channel: "script", Argv: []string{"powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", "iex (irm 'https://junie.jetbrains.com/install.ps1')"}, Display: "iex (irm 'https://junie.jetbrains.com/install.ps1')"},
				{OS: "", Channel: "npm", Argv: []string{"npm", "install", "-g", "@jetbrains/junie"}, Display: "npm install -g @jetbrains/junie"},
			},
		},
		// Sandbox filesystem-isolation row (B9) for the CLI surface. GROUNDED
		// against internal/adapter/junie/adapter.go defaultRoots (the
		// ~/.junie/sessions store; ~/.junie also holds allowlist.json and the
		// custom models/ dir the CLI reads) plus the versioned native install
		// the ~/.local/bin/junie shim execs, which the CLI only reads. The
		// IDE-plugin surface is still never spawned by observer.
		Sandbox: SandboxSpec{
			NeedsWin32k: true,
			ProviderEnv: []string{"JUNIE_API_KEY", "JUNIE_ANTHROPIC_API_KEY", "JUNIE_OPENAI_API_KEY", "JUNIE_GOOGLE_API_KEY", "JUNIE_GROK_API_KEY", "JUNIE_OPENROUTER_API_KEY", "JUNIE_META_API_KEY"},
			StateRW:     []string{".junie"},
			StateRO:     []string{".local/share/junie"},
		},
	},
	// Poolside (docs/poolside-adapter.md). Phase-0 grounded 2026-09-05
	// against a live JetBrains IDEA 2026.2.2 run on Windows, where Poolside
	// ran as a JetBrains AI Assistant ACP agent (`acp.registry.poolside`).
	// Poolside ALSO ships a standalone terminal CLI, `pool`
	// (docs.poolside.ai/cli/install.md + cli/cli-reference.md, read
	// 2026-10-03: "pool starts an interactive session by default"; the ACP
	// agent is `pool acp`), which `observer pool` launches (2026-10-03,
	// terminal-picker coverage).
	"poolside": {
		Tool: "poolside",
		// FIX-7 (phase-2 review) promoted this from
		// PromptLaneProbeRequired; Part B item 2 (phase-3a, 2026-09-07)
		// wired it after re-fetching docs.poolside.ai/hooks live:
		// UserPromptSubmit registers in settings.yaml (the SAME file
		// this row's own pool.api_url already comes from) as
		// {"hooks":{"UserPromptSubmit":[{"name":…,"matcher":"*",
		// "command":…}]}}. The reply is snake_case JSON — {"decision":
		// "block","reason":…,"hook_specific_output":{"updated_prompt",
		// "additional_context"}} — used here over the vendor's
		// documented exit-2 alternative because it needs no new
		// exit-code plumbing beyond what Qoder/Cascade already require.
		// updated_prompt (the genuine redact lane) stays unpopulated —
		// not wired on any channel yet.
		PromptLane: PromptLaneHook,
		// 7 grounded native tool names (read/write/edit/shell/
		// list_directory_tree/todo_action/exit) — the COMPLETE tool
		// surface a live 22-call, single-prompt session exercised; no
		// defensive rows exist because the ACP session/new response's own
		// configOptions never enumerated a larger surface than what was
		// actually called.
		Vocabulary: Vocabulary{InTaxonomy: true},
		// Model traffic goes to https://inference.poolside.ai per
		// ~/.config/poolside/settings.yaml's pool.api_url. The standalone CLI
		// documents POOLSIDE_STANDALONE_BASE_URL (a custom OpenAI-compatible
		// endpoint, docs.poolside.ai/cli/install.md, 2026-10-03), but that is
		// an alternative-provider mode, not a pass-through of the Poolside
		// platform lane, and no routed turn has been observed, so this stays
		// probe_required rather than a fabricated route.
		Proxy: nil,
		// S-16 (D9): the writer is built (proxyroute memberroute.go):
		// pool.api_url at the proxy's /up/poolside/ lane, whose upstream is
		// the same hosted inference host. settings.yaml holds web_search
		// api_key and agent_servers credentials. Switched off until live
		// check LCR-1 (proposed: does pool.api_url at the proxy route the
		// agent's traffic, and in which protocol).
		ProxyProbe: &ProxyRoute{
			Kind:                 RouteConfigFile,
			Suffix:               "/up/poolside/v1",
			Setting:              "pool.api_url",
			Note:                 "proxyroute.RegisterMemberRoute(poolside) adds pool.api_url = proxy /up/poolside/v1 to ~/.config/poolside/settings.yaml (personal file only); YAML member edit, never a key; refuses a non-observer api_url",
			Lane:                 &ProxyLane{ID: "poolside", DefaultUpstream: "https://inference.poolside.ai"},
			LiveGate:             "LCR-1",
			SharesCredentialFile: true, CredentialFileReason: credFilePoolside,
		},
		Routability: RouteStatusProbeRequired,
		// No hook mechanism is documented or grounded for the JetBrains
		// ACP agent surface specifically; the mechanism below targets
		// the SEPARATE standalone `pool` CLI's own hooks system
		// (settings.yaml — see the PromptLane comment above), which
		// applies whenever that standalone binary is installed
		// regardless of whether the ACP-embedded surface this row's
		// OWN capture adapter reads is in use.
		// CrossOSBridge: true — internal/hook's poolside-windows target
		// (registerPoolsideWindows) wraps the command in the wsl.exe
		// bridge, mirroring claude-code/cursor/codex's own bridges.
		Hook: HookSpec{Mechanism: HookPoolsideYAML, CrossOSBridge: true, AutoWired: true, Bindings: hookBindingsPoolside, HooksShareCredentialFile: true, CredentialFileReason: credFilePoolside},
		// Poolside is itself an MCP CLIENT inside the ACP session (the
		// JetBrains host hands it the IDE's own `idea` MCP server), not a
		// target any existing {"mcpServers":{…}}-shaped writer could
		// register into.
		MCP:    nil,
		Native: NativeRails{},
		// Tier-2 transcript capture only. tool_call.inference.end states
		// input/output/cache_read/cache_write per call — richer than most
		// Tier-2 sources, though still not a proxy intercept. No pricing
		// entry exists for poolside/laguna-* models (a brand-new,
		// non-mainstream vendor), so cost rows resolve as unknown.
		TokenTier: TokenTier{
			Best: "trajectory_ndjson",
			Gap:  "no Tier-1 proxy path (IDE-driven, no base-URL knob); no pricing entry for poolside/laguna-* models",
			// tool_call.inference.start -> .end, same parse window only.
			GenerationTiming: GenTimingNative,
		},
		// The trajectory re-reads in full (prompts, reasoning, assistant
		// text, every tool call + outcome) — a genuinely re-readable
		// transcript.
		//
		// Launch (2026-10-03): `observer pool` starts the standalone `pool`
		// TUI in a PTY. DOC-ASSISTED: cli-reference.md documents
		// `-q/--prompt-queue` ("Queue a prompt to send after the interactive
		// session... finish initializing") as the interactive seed, but it is
		// not live-verified, so the launcher writes the handover doc and opens
		// the TUI. Native resume (`-r/--resume [id]`) is documented but not
		// live-verified, so Resume stays zero. Capture (T-706, demo node 1,
		// 2026-10-08): a standalone Linux `pool` run writes the same
		// trajectory format under ~/.local/state/poolside/trajectories, which
		// the adapter watches next to the Windows ACP store
		// (%LOCALAPPDATA%\poolside); macOS stays an unverified expectation.
		Handoff: HandoffCapability{
			Transcript: TranscriptFull,
			Inject:     []InjectKind{InjectFile},
			Launch:     &LaunchSpec{Subcommand: "pool", Mode: LaunchDocAssisted},
			Note:       "documented -q seed not live-verified: launch writes the handover doc and opens the pool TUI; standalone-CLI capture is grounded on Linux (~/.local/state/poolside) and the Windows ACP store, not yet on macOS",
		},
		Attach: &AttachSpec{Subcommand: "pool"},
		// Credential env NAME (never a value): POOLSIDE_API_KEY, the
		// documented non-interactive alternative to `pool login`
		// (docs.poolside.ai/cli/install.md, 2026-10-03).
		AuthEnv: []string{"POOLSIDE_API_KEY"},
		// Binary resolution + grounded installs (2026-10-03,
		// docs.poolside.ai/cli/install.md and the install.sh it serves):
		// install.sh needs curl (or wget) to download and tar to extract, and
		// MOVES the native `pool` binary to ${XDG_BIN_HOME:-~/.local/bin}
		// (the checksum tools are optional); the Windows installer (marked
		// beta by the vendor) puts pool.exe in
		// %LOCALAPPDATA%\Programs\pool\bin. No npm, brew or winget channel is
		// documented.
		Binary: &BinaryResolveSpec{
			Names: BinaryNames{
				Unix:    []string{"pool"},
				Windows: []string{"pool.exe"},
			},
			ProbeDirs: []ProbeDir{
				{OS: ProbeWindows, Rel: "AppData/Local/Programs/pool/bin"},
			},
			Installs: []InstallHint{
				{OS: "linux", Channel: "script", Argv: []string{"sh", "-lc", "curl -fsSL https://downloads.poolside.ai/pool/install.sh | sh"}, Display: "curl -fsSL https://downloads.poolside.ai/pool/install.sh | sh", Requires: []string{"curl", "tar"}},
				{OS: "darwin", Channel: "script", Argv: []string{"sh", "-lc", "curl -fsSL https://downloads.poolside.ai/pool/install.sh | sh"}, Display: "curl -fsSL https://downloads.poolside.ai/pool/install.sh | sh", Requires: []string{"curl", "tar"}},
				{OS: "windows", Channel: "script", Argv: []string{"powershell", "-ExecutionPolicy", "ByPass", "-c", "irm https://downloads.poolside.ai/pool/install.ps1 | iex"}, Display: "irm https://downloads.poolside.ai/pool/install.ps1 | iex"},
			},
		},
		// Sandbox filesystem-isolation row (B9). Honest zero: the Linux state
		// dirs are now known (T-706, node 1, 2026-10-08: ~/.config/poolside,
		// ~/.local/state/poolside, ~/.local/share/poolside), but no sandboxed
		// pool launch has been built or run, so a profile would be untested.
		Sandbox: SandboxSpec{Note: "Linux state dirs known (~/.config/poolside, ~/.local/state/poolside, ~/.local/share/poolside) but no sandboxed pool launch has been tested - not sandbox-launchable"},
	},
	// zcode (Z.AI's OpenCode fork, docs/zcode-adapter.md). Phase-0 grounded
	// 2026-08-18: a structural transposition of the opencode adapter with
	// one difference — per-call tokens come from zcode's own `model_usage`
	// SQLite table (OpenCode's message.data.tokens bundle is zeroed).
	"zcode": {
		Tool: "zcode",
		// FIX-7 (phase-2 review) promoted this from
		// PromptLaneProbeRequired. Part B item 2 (phase-3a, 2026-09-07)
		// built and TESTED the dialect + receiver after re-fetching
		// zcode.z.ai/en/docs/hooks live (continue:false, camelCase
		// hookSpecificOutput, ~/.zcode/cli/config.json registration
		// schema) — PromptLaneHook is honest because
		// `observer hook zcode UserPromptSubmit` genuinely evaluates
		// and can block, exactly like every other PromptLaneHook row.
		// What's genuinely still open is a LIVENESS question
		// (zai-org/feedback#32 claims configured hooks may not fire at
		// all on the native agent), so the REGISTRATION WRITER is
		// deliberately NOT built/auto-wired (Hook.AutoWired stays
		// false, mirroring cline-cli's HookClineCLIJSONL precedent) —
		// `observer doctor --probe-hook zcode` (Part B item 3) is what
		// would confirm liveness before a writer is worth building.
		PromptLane: PromptLaneHook,
		// 10 native tool names grounded off mapTool (internal/adapter/zcode/
		// adapter.go:1105-1156), OpenCode-derived short-name aliases, plus
		// the step_finish harness marker (WP-T4 family). The default case's
		// `strings.Contains(part.Tool, "mcp")` heuristic stays adapter-
		// private per the globalGlobRows precedent (a guess, not an
		// identity).
		Vocabulary: Vocabulary{InTaxonomy: true},
		// zcode authenticates model access via Z.AI OAuth (`zcode login`)
		// and exposes no OpenAI-style base-URL env knob (`zcode --help`,
		// zcode 0.16.3). Surface-gap S-16 (2026-10-25,
		// https://zcode.z.ai/en/docs/configuration): the desktop's model
		// providers in ~/.zcode/v2/config.json carry
		// provider.<id>.options.baseURL beside a plaintext apiKey. No writer:
		// which provider id a session uses is not grounded, and no routed
		// turn has been seen.
		Proxy:       nil,
		Routability: RouteStatusProbeRequired,
		// AutoWired since hook-parity Lane A4 (2026-10-03): the writer
		// registers the PreToolUse tool gate and the UserPromptSubmit prompt
		// gate (and sets hooks.enabled). zai-org/feedback#841 (open,
		// v3.14.3) reports PreToolUse firing for main-session tool calls
		// while UserPromptSubmit never fired, so prompt coverage stays
		// unproven (see the PromptLane comment above). Doc-grounded: `observer init` writes it,
		// `observer start` does not (not live).
		Hook: HookSpec{Mechanism: HookZcodeJSON, AutoWired: true, Bindings: hookBindingsZcode, HooksShareCredentialFile: true, CredentialFileReason: credFileZcode},
		// config.json carries an `mcp` object, but its shape is zcode's own
		// and no writer emits it.
		MCP:    nil,
		Native: NativeRails{},
		// Per-call model/cache/token counts come off the model_usage table
		// (one row per call; netInput = input_tokens - cache_read, the
		// codebase-wide GROSS-input convention) — the same full per-call
		// tier opencode's own sqlite capture carries.
		TokenTier: TokenTier{Best: "sqlite"},
		// db.sqlite reconstructs the full turn (messages + parts), the same
		// tier opencode carries. Launcher `observer zcode`: --continue-from
		// seeds a distilled handover via zcode's `--prompt` flag
		// (LaunchSeeded).
		Handoff: HandoffCapability{
			Transcript: TranscriptFull,
			Inject:     []InjectKind{InjectFile, InjectPrompt},
			Launch:     &LaunchSpec{Subcommand: "zcode"},
		},
		// Attach grounded 2026-08-24 (attach-all-launchers); PTY handoff
		// only — no prompt seeding, token capture path unchanged.
		Attach: &AttachSpec{Subcommand: "zcode"},
		// Native resume GROUNDED off `zcode --help` (0.16.3): `--resume
		// <sessionId>` is a REQUIRED-value flag taking zcode's own
		// `sess_<uuid>` verbatim (the id this adapter already keys on), so
		// no transform.
		Resume: ResumeSpec{Kind: ResumeNative, Subcommand: "zcode", IDMechanism: "flag:--resume"},
		// Binary: install CORRECTED 2026-09-02 (DI-11). The prior
		// `zcode-app-cli` npm hints were UNOFFICIAL: that package's
		// maintainer (kingsword09 <kingsword09@gmail.com>, repo
		// kingsword09/zcode-cli) is unaffiliated with Z.AI. Z.AI's own
		// docs (zcode.z.ai/en/docs/install, v3.10.2) ship a DESKTOP GUI
		// installer only ("Double-click it and follow the setup
		// wizard") — no official CLI install channel exists, so
		// Installs is deliberately empty with an honest InstallNote
		// rather than a fabricated command.
		Binary: &BinaryResolveSpec{
			Names:           BinaryNames{Unix: []string{"zcode"}, Windows: []string{"zcode.exe"}},
			WindowsNote:     "zcode.exe is bundled by the Z.ai desktop app; there is no CLI install channel",
			InstallNote:     "Z.ai ships a desktop installer only (zcode.z.ai/en/docs/install); the npm package zcode-app-cli is unaffiliated - no grounded CLI channel",
			UserInstallHint: "ZCode comes with the Z.ai desktop app. Install that app to get it.",
		},
		// `zcode --help` (0.16.3) exposes no top-level --model flag, so no
		// ModelArg is claimed.
		Model: ModelSpec{Kind: ModelNone},
		// Sandbox filesystem-isolation row (B9). Not grounded — only
		// claude-code has a verified state-dir bind list.
		// Sandbox filesystem-isolation row (B9). GROUNDED against
		// internal/adapter/zcode/adapter.go defaultRoots (<home>/.zcode/cli/db —
		// the OpenCode-fork SQLite store). ~/.zcode is bound rw as one dir; it
		// holds the Z.AI credentials the fork authenticates with.
		Sandbox: SandboxSpec{StateRW: []string{".zcode"}},
		// GUI launch row (plan §2.2): ZCode Desktop is the Electron ADE
		// that BUNDLES this row's zcode CLI runtime and shares its
		// ~/.zcode/cli/db/db.sqlite store.
		GUI: &GUILaunchSpec{
			ID:      "zcode-desktop",
			Label:   "ZCode",
			Surface: "desktop",
			Binary: BinaryResolveSpec{
				Names: BinaryNames{
					Windows: []string{"ZCode.exe"},
				},
				ProbeDirs: []ProbeDir{
					{OS: ProbeWindows, Rel: "AppData/Local/Programs/ZCode"},
				},
				Installs: []InstallHint{
					{OS: "windows", Channel: "winget", Argv: []string{"winget", "install", "--id", "ZhipuAI.ZCode", "-e", "--source", "winget"}, Display: "winget install --id ZhipuAI.ZCode -e --source winget"},
					{OS: "darwin", Channel: "brew", Argv: []string{"brew", "install", "--cask", "zcode"}, Display: "brew install --cask zcode"},
				},
				InstallNote: "no grounded Linux channel: zcode.z.ai/en/docs/install ships a direct download.",
			},
			// PATH walk disabled: this row's own CLI Names above are
			// `zcode`/`zcode.exe`, and on Windows that shim resolves
			// case-insensitively against "ZCode.exe" — a PATH hit would
			// spawn the CLI, not the desktop app. Probe dirs only.
			ProbeOnly:      true,
			DarwinApp:      "ZCode",
			ProjectDirArgv: false,
			Wrap: WrapSpec{
				Kind: WrapNone,
				Reason: "probe_required, and no writer exists to make it config_write: the base URL lives in " +
					"~/.zcode/cli/config.json (plus a separate app-level HTTP proxy under Settings → General → " +
					"Network that needs a restart), and this registry row carries NEITHER a verified Proxy nor " +
					"a ProxyProbe writer binding - internal/proxyroute has registrars for claude/codex/crush/" +
					"kimi/qwen only. Naming a config_write ConfigTool here would point the operator at a " +
					"writer that does not exist (inventory §4.1). Revisit when a zcode registrar lands.",
			},
			Hosts:    []string{"zcode"},
			Grounded: true,
			Note: "Windows layout grounded on this box 2026-09-03: " +
				"%LOCALAPPDATA%\\Programs\\ZCode\\ZCode.exe, with NO bin\\ dir - hence ProjectDirArgv=false " +
				"(the inventory left the argv form \"to ground\"). macOS bundle \"ZCode.app\" grounded from the " +
				"Homebrew cask `zcode` (homepage zcode.z.ai); winget id `ZhipuAI.ZCode` grounded from a live " +
				"`winget search --exact` the same day, which also confirms the inventory §4.1 citation.",
		},
	},
	// Mistral Code (`vibe`, docs/mistral-code-adapter.md). Phase-0 grounded
	// 2026-08-18.
	"mistral-code": {
		Tool: "mistral-code",
		// 11 native tool names grounded off mapVibeTool (internal/adapter/
		// mistralcode/adapter.go:350-378), vibe's own snake_case OpenAI-
		// function-name vocabulary (grounded live off meta.json
		// tools_available).
		Vocabulary: Vocabulary{InTaxonomy: true},
		// vibe authenticates to the Mistral API via an API key; its
		// vibe_base_url/provider api_base override has never been driven
		// live through the proxy, so routing it there would be a guess.
		Proxy:       nil,
		Routability: RouteStatusProbeRequired,
		Hook:        HookSpec{Mechanism: HookVibeHooksTOML, AutoWired: true, Bindings: hookBindingsMistralCode},
		// config.mcp_servers exists but no writer emits vibe's shape.
		MCP:    nil,
		Native: NativeRails{},
		// Tokens are SESSION-LEVEL from meta.json/stats (session_prompt_
		// tokens GROSS incl. cached, session_completion_tokens,
		// session_cached_tokens, session_cost) — no per-message usage
		// field. The adapter emits one session-level token event per
		// session (netInput = session_prompt_tokens - session_cached_
		// tokens), MAX-upgraded as the session grows. vibe 2.25+'s unified
		// store carries the same SESSION-cumulative shape in the projection
		// envelope's tokenUsage (GROSS inputTokens netted vs
		// cachedInputTokens) but no cost field (unified.go).
		TokenTier: TokenTier{Best: "session_meta", Gap: "no per-message usage field; one session-level token row, MAX-upgraded as the session grows", SessionCumulative: true, SynthesizedTimestamps: true, ReportsCost: true},
		// messages.jsonl reconstructs the full turn (prompt, tool calls +
		// results). Launcher `observer vibe`: --continue-from seeds a
		// distilled handover as vibe's bare positional [PROMPT]
		// (LaunchSeeded).
		Handoff: HandoffCapability{
			Transcript: TranscriptFull,
			Inject:     []InjectKind{InjectFile, InjectPrompt},
			Launch:     &LaunchSpec{Subcommand: "vibe"},
		},
		// Attach grounded 2026-08-24 (attach-all-launchers); PTY handoff
		// only — no prompt seeding, token capture path unchanged.
		Attach: &AttachSpec{Subcommand: "vibe"},
		// Native resume operator-verified (WSL + Windows, space form):
		// `--resume <8hex>` is a REQUIRED-value flag taking the session
		// dir's 8-hex suffix verbatim (the id this adapter already keys
		// on), so no transform.
		Resume: ResumeSpec{Kind: ResumeNative, Subcommand: "vibe", IDMechanism: "flag:--resume"},
		// Binary: install grounded 2026-08-18 (docs.mistral.ai;
		// github.com/mistralai/mistral-vibe). uv-tool console script; on
		// Windows it lands at %USERPROFILE%\.local\bin\vibe.exe.
		Binary: &BinaryResolveSpec{
			Names: BinaryNames{Unix: []string{"vibe"}, Windows: []string{"vibe.exe"}},
			// grounded 2026-09-02: uv's tool bin dir resolution
			// (docs.astral.sh/uv/reference/storage) lands on
			// ~/.local/bin (XDG_BIN_HOME / XDG_DATA_HOME fallback) on
			// every OS including Windows (%USERPROFILE%\.local\bin).
			ProbeDirs: []ProbeDir{
				{OS: ProbeUnix, Rel: ".local/bin"},
				{OS: ProbeWindows, Rel: ".local/bin"},
			},
			Installs: []InstallHint{
				{OS: "linux", Channel: "uv", Argv: []string{"uv", "tool", "install", "mistral-vibe"}, Display: "uv tool install mistral-vibe"},
				{OS: "darwin", Channel: "uv", Argv: []string{"uv", "tool", "install", "mistral-vibe"}, Display: "uv tool install mistral-vibe"},
				{OS: "windows", Channel: "uv", Argv: []string{"uv", "tool", "install", "mistral-vibe"}, Display: "uv tool install mistral-vibe"},
				// grounded 2026-09-02: docs.mistral.ai's vibe install page
				// documents this curl|bash form as the pip-alternative-free
				// recommendation alongside uv on Linux/macOS.
				{OS: "linux", Channel: "script", Argv: []string{"bash", "-lc", "curl -LsSf https://mistral.ai/vibe/install.sh | bash"}, Display: "curl -LsSf https://mistral.ai/vibe/install.sh | bash", Requires: []string{"curl"}},
				{OS: "darwin", Channel: "script", Argv: []string{"bash", "-lc", "curl -LsSf https://mistral.ai/vibe/install.sh | bash"}, Display: "curl -LsSf https://mistral.ai/vibe/install.sh | bash", Requires: []string{"curl"}},
			},
		},
		// `vibe --help` exposes no --model flag (model comes from
		// config.models/--agent), so no ModelArg is claimed.
		Model: ModelSpec{Kind: ModelNone},
		// Sandbox filesystem-isolation row (B9). Not grounded — only
		// claude-code has a verified state-dir bind list.
		// Sandbox filesystem-isolation row (B9). GROUNDED against
		// internal/adapter/mistralcode/adapter.go defaultRoots: the `vibe` CLI's
		// <home>/.vibe/logs/session (or $VIBE_HOME) and the Continue-fork IDE
		// store's <home>/.mistralcode/sessions. Both roots' parents are bound rw.
		Sandbox: SandboxSpec{
			StateRW: []string{".vibe", ".mistralcode"},
		},
	},
	// Freebuff (CodebuffAI; the Manicode -> Codebuff -> Freebuff lineage,
	// docs/freebuff-adapter.md). Phase-0 grounded 2026-08-18. The first
	// launchable adapter with NO token tier at all — an honest upstream
	// ceiling, not a gap in the adapter.
	"freebuff": {
		Tool: "freebuff",
		// 9 native tool names grounded off mapFreebuffTool (internal/
		// adapter/freebuff/adapter.go, mapFreebuffTool), freebuff's own snake_case
		// vocabulary with several Claude-Code-style aliases. The
		// structural block-type discriminator "agent" (alongside "text"/
		// "tool") is NOT a tool name and is deliberately excluded — same
		// honest-zero reasoning as junie's typed block kinds.
		Vocabulary: Vocabulary{InTaxonomy: true},
		// freebuff authenticates to the CodebuffAI backend (`freebuff
		// login`). Surface-gap S-16 (2026-10-25, vendor sdk/src/byok.ts): a
		// BYOK openai-compatible connection in
		// ~/.config/freebuff/byok/connections.json (FREEBUFF_BYOK_CONFIG_DIR,
		// shared by CLI and Desktop; http allowed on loopback only) carries a
		// base URL, and settings.byokConnection selects it. No writer: the
		// connection entry's shape is not grounded, and no routed turn has
		// been seen.
		Proxy:       nil,
		Routability: RouteStatusProbeRequired,
		Hook:        HookSpec{Mechanism: HookNone, Note: hookNoteFreebuf},
		MCP:         nil,
		Native:      NativeRails{},
		// Freebuff records NO billable token accounting at all.
		// run-state.json carries a running contextTokenCount, but that is a
		// context-window size, not usage — the adapter emits sessions +
		// actions only, zero TokenEvents. The first launchable adapter with
		// a "none" tier: a genuine upstream gap, surfaced honestly.
		// Two layouts, two truths (batch-3 T2, 2026-09-03): the CLI chats
		// store has no billable usage anywhere (run-state.json's
		// contextTokenCount is a context-window size); the DESKTOP store
		// (~/.config/freebuff-desktop/projects/*/desktop-v2.db,
		// messages.metrics_json.usage) carries real per-turn input /
		// cached-input / output. Best names the better of the two.
		TokenTier: TokenTier{Best: "sqlite", Gap: "desktop layout only - the CLI chats store has no billable usage field; the launchable CLI surface still records sessions + actions without tokens", SynthesizedTimestamps: true, ReportsCost: true},
		// chat-messages.json reconstructs the full turn (prompt, reasoning,
		// tool calls + results). NO --continue-from seed lane: freebuff
		// exposes no positional prompt or one-shot flag to seed
		// (Handoff.Inject is InjectFile only; Launch.Mode=LaunchDocAssisted
		// is the hermes/kimi precedent — the launcher writes the handover
		// doc and opens the TUI, seeding no prompt).
		Handoff: HandoffCapability{
			Transcript: TranscriptFull,
			Inject:     []InjectKind{InjectFile},
			Launch:     &LaunchSpec{Subcommand: "freebuff", Mode: LaunchDocAssisted},
		},
		// Attach grounded 2026-08-24 (attach-all-launchers); PTY handoff
		// only.
		Attach: &AttachSpec{Subcommand: "freebuff"},
		// Native resume grounded off `freebuff --help` (2026-08-18):
		// `--continue [conversation-id]` is a commander.js OPTIONAL-value
		// flag, so the joined `=` spelling is the unambiguous form (the
		// cursor/droid shape). The id is the chat dir's RFC3339 name
		// verbatim (the id this adapter already keys on), so no transform.
		Resume: ResumeSpec{Kind: ResumeNative, Subcommand: "freebuff", IDMechanism: "flag:--continue"},
		// Binary: install grounded 2026-08-18 (npm `freebuff`, every OS).
		// Windows spelling CORRECTED 2026-09-02: the npm package's bin key
		// (`{freebuff: index.js}`) is a JS launcher, so a global npm
		// install writes the shim trio (`freebuff.cmd` + bare + `.ps1`),
		// never a `freebuff.exe` directly on PATH — the prior
		// `freebuff.exe`-only spelling was DEAD (no ProbeDir pointed
		// where it actually lands). The launcher then downloads a
		// Bun-compiled native binary to ~/.config/manicode/freebuff(.exe)
		// and spawns it — that binary is never itself on PATH.
		Binary: &BinaryResolveSpec{
			Names: BinaryNames{Unix: []string{"freebuff"}, Windows: []string{"freebuff.cmd", "freebuff", "freebuff.exe"}},
			ProbeDirs: []ProbeDir{
				{OS: ProbeUnix, Rel: ".config/manicode"},
				{OS: ProbeWindows, Rel: ".config/manicode"},
			},
			// Minimum host runtime, grounded 2026-10-04 from the npm registry
			// (`npm view <pkg> engines`): freebuff 0.2.13 declares engines.node.
			Runtime: &RuntimeRequirement{Runtime: RuntimeNode, MinVersion: "16", Product: "Freebuff", Source: "npm registry engines.node, freebuff 0.2.13, read 2026-10-04"},
			Installs: []InstallHint{
				{OS: "linux", Channel: "npm", Argv: []string{"npm", "install", "-g", "freebuff"}, Display: "npm install -g freebuff"},
				{OS: "darwin", Channel: "npm", Argv: []string{"npm", "install", "-g", "freebuff"}, Display: "npm install -g freebuff"},
				{OS: "windows", Channel: "npm", Argv: []string{"npm", "install", "-g", "freebuff"}, Display: "npm install -g freebuff"},
			},
		},
		// `freebuff --help` (2026-08-18) exposes only `login` and
		// `--continue` — no --model flag, so no ModelArg is claimed.
		Model: ModelSpec{Kind: ModelNone},
		// Sandbox filesystem-isolation row (B9). Not grounded — only
		// claude-code has a verified state-dir bind list.
		Sandbox: SandboxSpec{Note: "state dirs not yet grounded - not sandbox-launchable"},
		// GUI launch row (plan §2.2): Freebuff Desktop. Grounded on the
		// operator's live Windows install 2026-09-03 (batch-3 T2); the
		// desktop keeps its OWN store (~/.config/freebuff-desktop/projects/
		// <name>-<uuid>/desktop-v2.db), captured by this row's adapter as a
		// second layout with REAL per-turn usage.
		GUI: &GUILaunchSpec{
			ID:      "freebuff-desktop",
			Label:   "Freebuff Desktop",
			Surface: "desktop",
			Binary: BinaryResolveSpec{
				Names: BinaryNames{
					Windows: []string{"Freebuff.exe"},
				},
				ProbeDirs: []ProbeDir{
					// The per-user Electron install dir is the npm-scoped
					// package id `@codebuff/freebuff-desktop` with the slash
					// flattened.
					{OS: ProbeWindows, Rel: "AppData/Local/Programs/@codebufffreebuff-desktop"},
				},
				InstallNote: "no grounded macOS or Linux channel: there is no Homebrew cask `freebuff` and no " +
					"winget package (both checked live 2026-09-03); the vendor ships a direct download " +
					"(freebuff.com/desktop).",
			},
			// PATH walk disabled: the CLI shim `freebuff` resolves
			// case-insensitively against Freebuff.exe on Windows — a PATH hit
			// would spawn the CLI, not the desktop app. Probe dirs only.
			ProbeOnly:      true,
			ProjectDirArgv: false,
			Wrap: WrapSpec{
				Kind: WrapNone,
				Reason: "no BYOK and no base-URL surface: Freebuff runs its own hosted model pool with no " +
					"API key on the free tier (this row's Routability is probe_required only because the " +
					"question is open, not because a knob was found; inventory §2.13 / §4.1). Launch yes, " +
					"wrap no.",
			},
			Hosts:    []string{"freebuff"},
			Grounded: true,
			Note: "Windows layout grounded on this box 2026-09-03: " +
				"%LOCALAPPDATA%\\Programs\\@codebufffreebuff-desktop\\Freebuff.exe (Electron; uninstaller " +
				"`Uninstall Freebuff.exe` beside it; no bin\\ shim, hence ProjectDirArgv=false). macOS bundle " +
				"NOT grounded (no cask, no install to read) - DarwinApp left empty rather than guessed. The " +
				"inventory's open question is SETTLED: the desktop does NOT share ~/.config/manicode with the " +
				"CLI (that dir never appeared); it writes its own desktop-v2.db per project, which the " +
				"freebuff adapter now ingests (sessions, actions, real usage), stamped desktop/freebuff-desktop.",
		},
	},
	// Grok Bot DESKTOP app (xAI; Electron, productName "Grok Bot", internal
	// package "sand", built on Anysphere/Cursor's agent stack). NOT the
	// "grok" row above, which is the Grok CLI.
	//
	// Every cell below is a GROUNDED NEGATIVE rather than a pending
	// discovery: Phase 0 (2026-08-28) read a live 0.28.0 Windows install and
	// its shipped app.asar. The defining fact is that the agent executes in
	// a REMOTE sandbox VM ("the box") — the desktop is a thin replicated
	// client — so most integration surfaces do not exist to be wired.
	"grokbot": {
		Tool: "grokbot",
		// No native tool vocabulary to declare: `tool-call` transcript
		// entries carry only name/status/summary (arguments and results
		// stay on the box), and no live tool-call entry has been captured
		// yet, so the adapter maps them to ActionUnknown + RawToolName
		// rather than guessing a taxonomy.
		Vocabulary: Vocabulary{Note: "no native tool vocabulary grounded: tool-call entries carry name/status/summary only (args/results execute server-side in the remote box); none observed live yet"},
		// No base-URL surface of any kind. Inference happens server-side;
		// the desktop never emits a model request we could intercept, so
		// this is exempt, not merely un-probed.
		Proxy:       nil,
		Routability: RouteStatusNativeExempt,
		Hook:        HookSpec{Mechanism: HookNone, Note: hookNoteGrokbot},
		// settings.json has an `mcpBoxServers` array, but that is OUTBOUND
		// — MCP servers the REMOTE BOX connects out to. It is not a client
		// config we can register an observer stdio server into, so this is
		// nil rather than an MCPTarget.
		MCP:    nil,
		Native: NativeRails{},
		// No usage envelope, no model name, no cost anywhere in the local
		// store — a structural consequence of remote execution, not a
		// parsing gap. The "grok-4.5"/"grok-4.6" strings on disk live only
		// in sand-statsig-bootstrap.json as feature-flag config
		// (upgradeModelId / effort_first_compact_model_ids); they record no
		// session's actual model, so reading one would be fabrication.
		TokenTier: TokenTier{Best: "none", Gap: "no usage/model/cost data exists locally: the agent runs in a remote sandbox and the desktop store holds transcript text only; the grok-4.x strings on disk are Statsig feature-flag config, not per-session model attribution"},
		// Limit AUDITED 2026-09-22, same investigation as TokenTier above:
		// every sand-client-persistence blob filename decoded (base32 →
		// dotted key) and every slice's content inspected — zero
		// structured plan/tier/quota/usage/limit/billing/credit/
		// subscription fields anywhere. Same structural cause as the
		// TokenTier gap: the agent runs in a remote sandbox, so there is
		// no local process to ever carry this data. Note text is kept in
		// sync with internal/adapter/grokbot.NoLimitSource — see that
		// package for the fuller investigation record; not imported here
		// to keep this registry free of internal-package dependencies
		// (internal/integration currently imports nothing but "sort").
		Limit: LimitCapability{
			Source: LimitSourceNoneStructural,
			Note:   "Grok Bot runs its agent in a remote sandbox - no local file or process on this machine carries usage/quota data. Check the Grok Bot app's own account panel.",
		},
		// Transcript is fully re-readable (the whole conversation lives in
		// one plaintext-JSON blob). No Launch: a GUI desktop app has no
		// `observer <verb> --continue-from` argv contract, so it is
		// correctly absent from the fresh-launch picker and InjectFile
		// stays the honest floor.
		Handoff: HandoffCapability{
			Transcript: TranscriptFull,
			Inject:     []InjectKind{InjectFile},
		},
		// Not launchable ⇒ not attachable, no native resume, no binary
		// resolution row, no seed-time model mechanism. All grounded
		// negatives following from "it is a GUI app, not a CLI".
		Attach: nil,
		Resume: ResumeSpec{},
		Binary: nil,
		Model:  ModelSpec{Kind: ModelNone},
		Sandbox: SandboxSpec{
			Note: "not sandbox-launchable: a GUI desktop app with no launcher verb, so there is no observer-spawned process to isolate",
		},
		// GUI launch row (plan §2.2): Grok Bot IS a desktop app — this row
		// has no CLI at all, so the GUI spec is its only launch surface.
		GUI: &GUILaunchSpec{
			ID:      "grokbot-desktop",
			Label:   "Grok Bot",
			Surface: "desktop",
			Binary: BinaryResolveSpec{
				WindowsNote: "Grok Bot is not installed on the grounding box (2026-09-03) and there is no " +
					"winget package, so its Windows install layout is unverified and no executable spelling " +
					"or probe dir is declared rather than guessing %LOCALAPPDATA%\\Programs\\Grok Bot.",
				Installs: []InstallHint{
					{OS: "darwin", Channel: "brew", Argv: []string{"brew", "install", "--cask", "grok-bot"}, Display: "brew install --cask grok-bot"},
				},
				InstallNote: "macOS only: no winget package exists (checked live 2026-09-03) and the Linux " +
					"artifacts docs.x.ai lists (.deb/.rpm/AppImage) have no grounded one-liner.",
			},
			DarwinApp:      "Grok Bot",
			ProjectDirArgv: false,
			Wrap: WrapSpec{
				Kind: WrapNone,
				Reason: "there is no local request to route: Grok Bot is a thin client and inference runs in " +
					"a remote sandbox VM (this row's Routability is native_exempt; inventory §2.13 / §4.2). " +
					"That is also why this row captures sessions + actions only, with tokens/model/cost/cwd " +
					"honestly absent.",
			},
			Hosts:    []string{"grokbot"},
			Grounded: true,
			Note: "Grounded from the macOS side ONLY: the Homebrew cask `grok-bot` (name \"Grok Bot\", " +
				"homepage x.ai/bot) installs \"Grok Bot.app\", read from the cask API 2026-09-03. Windows " +
				"layout unverified (not installed here, no winget package) - Names.Windows empty. This also " +
				"partially settles the OS-matrix DISCREPANCY the inventory §2.13 carries (CLAUDE.md says " +
				"Windows+macOS; docs.x.ai also lists Linux): macOS is now confirmed, Windows and Linux are " +
				"still second-hand.",
		},
	},
	"kiro-crew": {
		Tool: "kiro-crew",
		// Crew logs a tool call under its OWN three-token vocabulary
		// (read / edit / execute) in meta.kind, not the kiro-cli tool name
		// it drove. Declared in internal/tooltax as kiroCrewRows.
		Vocabulary: Vocabulary{InTaxonomy: true},
		// No base-URL surface. Kiro is hard-wired to AWS SigV4 endpoints
		// (the same grounded negative kiro-cli carries); the local Gateway
		// on :5476 is Crew's own control plane, not a model endpoint we
		// could point elsewhere. Exempt, not merely un-probed.
		Proxy:       nil,
		Routability: RouteStatusNativeExempt,
		// `~/.kiro/crew/hooks.json` exists but is `{"hooks": []}` with no
		// documented command contract — nothing to register into.
		Hook: HookSpec{Mechanism: HookNone, Bindings: hookBindingsKiroCrew},
		// Crew DOES have an MCP surface: `~/.kiro/crew/mcp.json`, standard
		// `mcpServers` shape (the grounding box's copy even carries three
		// disabled observer entries a human added by hand). It is nil here
		// deliberately: wiring an MCP target means owning idempotent writes
		// into a vendor config whose merge semantics have not been
		// grounded, which is a separate ticket. Recorded, not fabricated.
		MCP:    nil,
		Native: NativeRails{},
		// NO tokens anywhere. The Crew transcript carries no usage field of
		// any kind, and the kiro-cli session Crew drives reports
		// input/output_token_count structurally 0 while billing in CREDITS
		// (meta.turn_stats.credits = 1.2768 on the grounded capture, the
		// sum of kiro-cli's per-call metering to 4dp). Credits are not
		// tokens and are deliberately dropped, as they are for kiro-cli.
		// context_snapshots.json's `used_tokens` is a context-WINDOW
		// occupancy reading, not billable usage, and is not read.
		TokenTier: TokenTier{Best: "none", Gap: "no billable token data exists: the Crew transcript has no usage envelope and the kiro-cli session it drives reports 0/0 with billing in credits (metering_usage / turn_stats.credits), which this repo does not treat as tokens"},
		// The transcript is fully re-readable (one JSONL per chat tab, and
		// the adapter re-reads it whole every tick anyway). No Launch: a
		// GUI desktop app has no `observer <verb> --continue-from` argv
		// contract, so InjectFile is the honest floor.
		Handoff: HandoffCapability{
			Transcript: TranscriptFull,
			Inject:     []InjectKind{InjectFile},
		},
		// Not launchable as a terminal verb ⇒ not attachable, no native
		// resume, no binary resolution row, no seed-time model mechanism.
		// Model is ModelNone because Crew's metadata `model` field is
		// structurally empty — agent_model_state.json records
		// `{"kirocrew": {"model_managed": true}}`, i.e. Crew delegates the
		// choice to the driven agent and never writes one on the chat.
		Attach: nil,
		Resume: ResumeSpec{},
		Binary: nil,
		Model:  ModelSpec{Kind: ModelNone},
		Sandbox: SandboxSpec{
			Note: "not sandbox-launchable: a GUI desktop app with no launcher verb, so there is no observer-spawned process to isolate",
		},
		// GUI launch row: Kiro Crew IS a desktop app, so this is its only
		// launch surface.
		GUI: &GUILaunchSpec{
			ID:      "kiro-crew-desktop",
			Label:   "Kiro Crew",
			Surface: "desktop",
			Binary: BinaryResolveSpec{
				Names: BinaryNames{Windows: []string{"KiroCrew.exe"}},
				ProbeDirs: []ProbeDir{
					// Grounded live 2026-09-03: C:\Program Files\KiroCrew\
					// KiroCrew.exe. NOT %LOCALAPPDATA%\Programs like Kiro
					// IDE — %LOCALAPPDATA%\kirocrew-desktop-updater holds
					// only the updater's installer.exe, and
					// %APPDATA%\kirocrew-desktop is Electron userData.
					{OS: ProbeWindows, EnvRoot: "ProgramFiles", Rel: "KiroCrew"},
				},
				InstallNote: "no grounded one-click channel: the vendor ships a download.crew.kiro.dev " +
					"installer (this box's install came from it) and there is no winget package or Homebrew " +
					"cask for Kiro Crew as of 2026-09-03, so no InstallHint is declared rather than guessing one.",
			},
			// Bare launch only: Crew's agents are workspace-bound through
			// its own folders.json / recent_projects.json, not through argv.
			ProjectDirArgv: false,
			Wrap: WrapSpec{
				Kind: WrapNone,
				Reason: "Kiro hard-wired: AWS ships no BYOK / base-URL surface for Kiro at all (this row's " +
					"Routability is native_exempt, the same grounded negative kiro-cli carries), so there is " +
					"nothing to inject. Launch yes, wrap no; capture rides ~/.kiro/sessions (kiro-cli owns a " +
					"Crew-driven conversation) and ~/.kiro/crew/sessions.",
			},
			// Crew drives kiro-cli, so a Crew launch produces kiro-cli
			// sessions as well as its own transcripts.
			Hosts:    []string{"kiro-crew", "kiro-cli"},
			Grounded: true,
			Note: "Windows layout grounded on the step-in box 2026-09-03: C:\\Program Files\\KiroCrew\\" +
				"KiroCrew.exe, Start-Menu shortcut C:\\ProgramData\\...\\KiroCrew.lnk. macOS/Linux layouts " +
				"are NOT grounded (not installed here, no cask/package found), so Names.Unix and DarwinApp " +
				"are empty rather than guessed.",
		},
	},
	// Zed's own native coding agent (docs/zed-adapter.md). Grounded live
	// 2026-09-06 against the operator's own prompt-kit run — the
	// Claude-ACP-in-Zed integration path did not persist a usable local
	// store, so this row is the built-in agent's own threads.db.
	"zed": {
		Tool: "zed",
		// 7 grounded native tool names (read_file/write_file/edit_file/
		// list_directory/find_path/terminal/delete_path) — the COMPLETE
		// surface a live multi-call session exercised; no defensive rows.
		Vocabulary: Vocabulary{InTaxonomy: true},
		// Zed's built-in agent talks to zed.dev, Zed's own managed model
		// gateway. No BYOK / base-URL override is grounded (Zed's
		// documented `language_models` settings cover BYO-provider
		// entries, but the captured session used Zed's own hosted
		// provider, which is not user-overridable) — probe_required, not
		// a fabricated route.
		Proxy:       nil,
		Routability: RouteStatusProbeRequired,
		Hook:        HookSpec{Mechanism: HookNone, Note: hookNoteZed},
		// CORRECTED 2026-10-25 (surface-gap arc S-12, lane w2-c): Zed DOES
		// document an MCP surface, the "context_servers" object in its
		// settings.json (zed.dev/docs/ai/mcp; the agentconfig catalogue maps
		// it, catalog_zed.go), and offers those servers to the ACP agents it
		// hosts. Linux and macOS read ~/.config/zed/settings.json, Windows
		// %APPDATA%\Zed\settings.json. Observer has no writer for it yet
		// (part of S-1), so the target is a candidate, never written.
		MCP:    &MCPTarget{Format: MCPZedContextServers, PathHint: ".config/zed/settings.json", Implemented: false},
		Native: NativeRails{},
		// Per-request tokens come straight off request_token_usage in the
		// decompressed thread JSON — a SQLite-store capture tier, same
		// bucket as zcode/kilo-code-cli. No cache-creation field exists in
		// the envelope, and no pricing entry exists for zed.dev's
		// gpt-5.6-luna (a closed, non-mainstream backend), so cost rows
		// resolve as unknown rather than a fabricated price.
		TokenTier: TokenTier{Best: "sqlite", Gap: "no pricing entry for zed.dev/gpt-5.6-luna", SynthesizedTimestamps: true},
		// The thread re-reads in full (every user/agent message, tool
		// call + outcome) — a genuinely re-readable transcript. No PTY
		// Launch/Attach/Resume/Binary: Zed IS the editor, and its
		// built-in agent has no separate `observer zed` CLI/TUI process
		// to start. The editor itself is a detached GUI launch row (GUI
		// below, D-177), the same shape as cursor-ide / kiro-ide.
		Handoff: HandoffCapability{Transcript: TranscriptFull, Inject: []InjectKind{InjectFile}},
		// Sandbox filesystem-isolation row (B9). Honest zero: the agent is built
		// into the Zed editor, which is only ever launched DETACHED (the GUI row
		// below, no PTY), so there is no terminal launch to wrap in a filesystem
		// boundary.
		Sandbox: SandboxSpec{Note: "not sandbox-launchable: the agent is built into the Zed editor itself, which observer only launches as a detached GUI app"},
		// GUI launch row (D-177, operator-approved 2026-10-03; T-037c).
		// Grounded 2026-10-04 from the vendor's own install sources, NOT a
		// live install (Zed is not installed on the grounding box):
		//   - zed.dev/docs/installation: `brew install --cask zed`,
		//     `curl -f https://zed.dev/install.sh | sh`,
		//     `winget install -e --id ZedIndustries.Zed`.
		//   - formulae.brew.sh/api/cask/zed.json (1.22.0): app "Zed.app",
		//     binary Zed.app/Contents/MacOS/cli linked as `zed`.
		//   - zed.dev/install.sh linux(): unpacks to ~/.local/zed.app, links
		//     ~/.local/zed.app/bin/zed to ~/.local/bin/zed, and the .desktop
		//     entry's Exec= is that same bin/zed (the vendor's own GUI launch
		//     command). Script needs curl (the pipe) and tar.
		//   - crates/zed/resources/windows/zed.iss: DefaultDirName =
		//     {autopf}\{#AppName} with PrivilegesRequired=lowest, so a
		//     per-user install lands in %LOCALAPPDATA%\Programs\Zed and an
		//     elevated one in %ProgramFiles%\Zed; Zed.exe at the root, the
		//     CLI as bin\zed.exe (script/bundle-windows.ps1 moves cli.exe to
		//     bin\zed.exe; AppName "Zed" for the stable channel), and the
		//     default-on addtopath task puts {app}\bin on the user PATH.
		//   - winget-pkgs ZedIndustries.Zed 1.22.0 installer manifest: inno,
		//     Scope machine, DefaultInstallLocation %ProgramFiles%\Zed.
		//   - crates/zed/src/main.rs Args.paths_or_urls: the app takes
		//     paths positionally, so a project dir is an argv.
		GUI: &GUILaunchSpec{
			ID:      "zed-ide",
			Label:   "Zed",
			Surface: "ide",
			Binary: BinaryResolveSpec{
				// Windows: the REAL app Zed.exe, never the bin\zed.exe CLI.
				// Unix: bin/zed under the install.sh layout, which is the
				// command the vendor's .desktop entry runs.
				Names: BinaryNames{
					Unix:    []string{"zed"},
					Windows: []string{"Zed.exe"},
				},
				ProbeDirs: []ProbeDir{
					// install.sh layout (Linux). Harmless on macOS, where
					// install.sh puts the app in /Applications instead and the
					// DarwinApp bundle probe resolves it.
					{OS: ProbeUnix, Rel: ".local/zed.app/bin"},
					// Per-user (non-elevated) install from the download page.
					{OS: ProbeWindows, Rel: "AppData/Local/Programs/Zed"},
					// Elevated install, which is what winget's machine scope
					// does (manifest DefaultInstallLocation).
					{OS: ProbeWindows, Rel: "Zed", EnvRoot: "ProgramFiles"},
				},
				Installs: []InstallHint{
					{OS: "windows", Channel: "winget", Argv: []string{"winget", "install", "--id", "ZedIndustries.Zed", "-e", "--source", "winget"}, Display: "winget install --id ZedIndustries.Zed -e --source winget"},
					{OS: "darwin", Channel: "brew", Argv: []string{"brew", "install", "--cask", "zed"}, Display: "brew install --cask zed"},
					{OS: "linux", Channel: "script", Argv: []string{"bash", "-lc", "curl -f https://zed.dev/install.sh | sh"}, Display: "curl -f https://zed.dev/install.sh | sh", Requires: []string{"curl", "tar"}},
				},
			},
			// PATH walk disabled: the installer's default-on addtopath task
			// puts {app}\bin on PATH, and its zed.exe (the CLI) matches the
			// Zed.exe spelling case-insensitively, so a PATH hit would launch
			// the CLI instead of the app (the qoder-work precedent). Every
			// grounded vendor layout is a probe dir above, and macOS resolves
			// through the DarwinApp bundle.
			ProbeOnly:      true,
			DarwinApp:      "Zed",
			ProjectDirArgv: true,
			Wrap: WrapSpec{
				Kind: WrapNone,
				Reason: "no environment knob: Zed reads provider API KEYS from the environment " +
					"(ANTHROPIC_API_KEY, OPENAI_API_KEY) but a provider base URL only from " +
					"language_models.<provider>.api_url in its own settings.json " +
					"(zed.dev/docs/ai/use-api-access), which Observer never writes, and the captured " +
					"native agent runs on zed.dev's hosted provider (registry row: probe_required). " +
					"Launch yes, wrap no.",
			},
			// Only the native agent: the Claude-ACP-in-Zed path did not persist
			// a usable local store on the grounding host (docs/zed-adapter.md),
			// so no ACP agent is claimed as hosted here.
			Hosts:    []string{"zed"},
			Grounded: true,
			Note: "Grounded 2026-10-04 from vendor install sources, not a live install: Windows " +
				"%LOCALAPPDATA%\\Programs\\Zed\\Zed.exe (per-user) or %ProgramFiles%\\Zed\\Zed.exe (elevated, " +
				"winget machine scope) from zed.iss + the winget manifest; macOS bundle \"Zed.app\" from the " +
				"Homebrew cask `zed`; Linux ~/.local/zed.app/bin/zed from zed.dev/install.sh. Third-party " +
				"Linux packages (Flathub, distro repos) are not probed: Zed's own docs say they often rename " +
				"the binary to zedit or zeditor, so no single spelling is grounded.",
		},
	},
	// --- 2026-10-21 capture-only wave -----------------------------------
	// Ten CLI agents grounded 2026-10-21 (WSL Ubuntu + Windows 11). Each is
	// a watcher-path capture adapter ONLY: no `observer <tool>` launcher, no
	// hook writer or receiver, no MCP writer and no proxy route was built,
	// so Launch / Attach / Resume / Model stay zero and every hook binding
	// is vendor-only. The launcher facts each vendor's --help grounds are
	// recorded in the row comments for the follow-up that builds one.
	// Status line, native OTLP and plan/limit sources were audited
	// 2026-10-22: the StatusLine column (statusline.go), the OTLP column
	// (otlpexport.go), and for plans the per-tool findings in
	// docs/plans/native-console-wave-2026-10-21-phase0.md (no internal/planlimits
	// source was added: every plan endpoint found is undocumented and was
	// never answered live).

	// autohand (Autohand Code CLI, docs/autohand-adapter.md). Phase-0 grounded
	// 2026-10-21 on WSL + Windows, autohand-cli 0.9.8.
	"autohand": {
		Tool: "autohand",
		// pre-prompt is a prompt gate grounded live 2026-10-21 (the autohand
		// prompt dialect reads "instruction"); registered by `observer init`
		// only (device sync, see the Hook row).
		PromptLane: PromptLaneHook,
		Vocabulary: Vocabulary{InTaxonomy: true},
		// Base-URL knobs exist but none was routed live: config.json
		// <provider>.baseUrl for 17 providers + customProviders,
		// AUTOHAND_PROVIDER, AUTOHAND_AI_BASE_URL / AUTOHAND_AI_API_KEY (the
		// hosted `autohandai` provider: fantail at https://api.autohand.ai/v1,
		// openai-completions shape). Cheapest first probe: a launcher
		// exporting AUTOHAND_AI_BASE_URL. Flip only after a LIVE turn lands
		// an api_turns row (checklist 10.1f).
		Proxy:       nil,
		Routability: RouteStatusProbeRequired,
		// hooks.hooks[] of ~/.autohand/config.json, the file that also holds
		// provider keys and the account token (credential-file exception).
		// No cross-OS bridge: Autohand's device sync mirrors the hooks key
		// between devices (the binding note), so a Windows-side bridge
		// command would reach the other OS.
		Hook: HookSpec{
			Mechanism: HookAutohandConfig, AutoWired: true, Bindings: hookBindingsAutohand,
			HooksShareCredentialFile: true, CredentialFileReason: credFileAutohand,
		},
		// config.json -> mcp.servers[] is an ARRAY of {name, transport:
		// stdio|sse|http, command|url, ...} (`autohand mcp add|remove|list`).
		// Not MCPServersJSON's {"mcpServers":{}} map and no writer emits it.
		MCP:    nil,
		Native: NativeRails{},
		// Session-cumulative usage in metadata.json; promptTokens GROSS of
		// cache read+write (netted at emit); completion includes reasoning.
		TokenTier: TokenTier{Best: "jsonl", Gap: "session-cumulative only (no per-turn rows or cache observation); totals are a lower bound once tokenUsageStatus is \"unavailable\"", SessionCumulative: true},
		// Transcript is full. No observer launcher. Native resume GROUNDED
		// (`autohand resume <id|title|prefix|path>` takes the stored id
		// verbatim); when a launcher lands:
		//   Resume: ResumeSpec{Kind: ResumeNative, Subcommand: "autohand", IDMechanism: "subcommand:resume"},
		//   Model: ModelSpec{Kind: ModelArg, Flag: "--model"} (autohand --help 0.9.8).
		Handoff: HandoffCapability{
			Transcript: TranscriptFull, Inject: []InjectKind{InjectFile},
			Note: "no `observer autohand` launcher yet; native resume is `autohand resume <id>`",
		},
		Binary: &BinaryResolveSpec{
			// The npm package installs four bin aliases for one entry point
			// (autohand, autohand-code, agent, ah); `agent` and `ah` are too
			// generic to resolve safely and are omitted (the command-code
			// cmd/cmdc exclusion precedent). Windows npm shims are
			// <name>.cmd; the vendor's native build is
			// %LOCALAPPDATA%\autohand\autohand.exe.
			Names: BinaryNames{
				Unix:    []string{"autohand", "autohand-code"},
				Windows: []string{"autohand.exe", "autohand.cmd", "autohand", "autohand-code.cmd", "autohand-code"},
			},
			Runtime: &RuntimeRequirement{Runtime: RuntimeNode, MinVersion: "22", Product: "Autohand Code", Source: "autohand-cli 0.9.8 package.json engines.node >=22.0.0 (npm install only; the native build bundles its runtime), read 2026-10-21"},
			Installs: []InstallHint{
				{OS: "", Channel: "npm", Argv: []string{"npm", "install", "-g", "autohand-cli"}, Display: "npm install -g autohand-cli"},
			},
			InstallNote: "operator-verified 2026-10-21: the vendor curl / irm installers failed on this box, npm worked on both WSL and Windows",
		},
		Model:   ModelSpec{Kind: ModelNone},
		Sandbox: SandboxSpec{Note: "not sandbox-launchable: no observer launcher for autohand; ~/.autohand holds config.json secrets"},
	},
	// IBM Bob Shell (docs/ibmbob-adapter.md). Grounded 2026-10-21 against
	// bobshell 2.0.6 on WSL + Windows live installs.
	"ibm-bob": {
		Tool: "ibm-bob",
		// Claude-Code-shaped UserPromptSubmit, exit 2 + stderr blocks (live
		// 2026-10-21, the claude-code prompt dialect).
		PromptLane: PromptLaneHook,
		// 19 built-in tool ids grounded from the 2.0.6 tool classes and the
		// user message's availableTools (4 observed live).
		Vocabulary: Vocabulary{InTaxonomy: true},
		// Inference goes to IBM's own gateway https://api.us-east.bob.ibm.com
		// (/inference/v1/chat/completions, OpenAI-chat shaped + `credits`),
		// overridable via BOB_GATEWAY_URL or the hidden --gateway-url flag.
		// The same base also serves /admin/v1 (profile/auth), so a route
		// needs an /up/<id> upstream that passes those through. Not
		// live-verified.
		Proxy:       nil,
		Routability: RouteStatusProbeRequired,
		// The "hooks" key of ~/.bob/settings/settings.json, which does NOT
		// hold credentials (those live in auth-secrets.json). Windows Bob runs
		// hooks under cmd.exe, so the WSL bridge is a plain wsl.exe prefix.
		Hook: HookSpec{Mechanism: HookIBMBobSettings, CrossOSBridge: true, AutoWired: true, Bindings: hookBindingsIBMBob},
		// ~/.bob/settings/mcp.json: {"mcpServers":{name:{type:"stdio",...}}}.
		// `type` is a REQUIRED discriminator, so the generic writer must be
		// checked to emit "type":"stdio" before this is flipped Implemented.
		// Grounded shape, no writer: stays nil until one exists (the
		// MCP row is non-nil only for an implemented writer).
		MCP:    nil,
		Native: NativeRails{},
		TokenTier: TokenTier{
			Best: "none",
			Gap:  "the vendor strips input/output/cache/reasoning before persisting; on disk only per-call spend {cost (Bobcoins, not USD), contextTokens (input+output unsplit)} survives, which cannot be priced, so no token rows and no Tier-2 cache observation",
		},
		// bob.db is fully re-readable. When a launcher lands:
		//   Resume: ResumeSpec{Kind: ResumeNative, Subcommand: "ibm-bob", IDMechanism: "flag:--resume"}
		// (`-r, --resume [task-id]`, an OPTIONAL-value flag). `bob --help`
		// exposes no model flag (the model is a server-side tier).
		Handoff: HandoffCapability{
			Transcript: TranscriptFull,
			Inject:     []InjectKind{InjectFile},
			Note:       "no `observer ibm-bob` launcher yet; native resume is `bob --resume <task-id>` (or `bob chat --resume <task-id>`), id = tasks.id = our SessionID verbatim",
		},
		Binary: &BinaryResolveSpec{
			// npm global install: Unix bin `bob`; Windows npm shims bob.cmd /
			// bob (no .exe). .ps1 is excluded (not directly execable).
			Names: BinaryNames{
				Unix:    []string{"bob"},
				Windows: []string{"bob.cmd", "bob"},
			},
			Runtime: &RuntimeRequirement{Runtime: RuntimeNode, MinVersion: "22", Product: "IBM Bob Shell", Source: "bobshell 2.0.6 package.json engines.node, read 2026-10-21"},
			Installs: []InstallHint{
				{OS: "linux", Channel: "script", Argv: []string{"bash", "-lc", "curl -fsSL https://bob.ibm.com/download/bobshell.sh | bash"}, Display: "curl -fsSL https://bob.ibm.com/download/bobshell.sh | bash", Requires: []string{"curl"}},
				{OS: "darwin", Channel: "script", Argv: []string{"bash", "-lc", "curl -fsSL https://bob.ibm.com/download/bobshell.sh | bash"}, Display: "curl -fsSL https://bob.ibm.com/download/bobshell.sh | bash", Requires: []string{"curl"}},
				{OS: "windows", Channel: "script", Argv: []string{"powershell", "-ExecutionPolicy", "Bypass", "-Command", "iwr https://bob.ibm.com/download/bobshell.ps1 -OutFile $env:TMP\\bob.ps1; & $env:TMP\\bob.ps1"}, Display: "powershell -ep Bypass \"iwr https://bob.ibm.com/download/bobshell.ps1 -OutFile $env:TMP\\bob.ps1; &$env:TMP\\bob.ps1\""},
			},
			InstallNote: "the installer runs a global npm install of `bobshell` with whichever npm is first on PATH. darwin is the same shell script, not separately grounded.",
		},
		Model:   ModelSpec{Kind: ModelNone},
		Sandbox: SandboxSpec{Note: "not sandbox-launchable: no observer launcher verb for bob yet"},
		// GUI row (FU-148, vendor docs only, no live check): IBM Bob IDE is a
		// desktop IDE beside Bob Shell. bob.ibm.com/docs/ide/getting-started/
		// install (fetched 2026-10-29): "macOS, Linux, or Windows", a .pkg on
		// macOS and an .exe installer on Windows, opened "from your
		// applications menu or desktop shortcut"; bob.ibm.com/download lists
		// the IDE builds. No executable or bundle name is documented, so the
		// row is ungrounded: listed, never launchable.
		GUI: &GUILaunchSpec{
			ID:      "bob-ide",
			Label:   "IBM Bob IDE",
			Surface: "ide",
			Wrap: WrapSpec{
				Reason: "not grounded: no base-URL setting of the IDE has been checked (coding surface bob-ide, LCR-75)",
			},
			Hosts:    []string{"ibm-bob"},
			Grounded: false,
			Note: "Vendor docs only (bob.ibm.com/docs/ide/getting-started/install, 2026-10-29): a desktop IDE for " +
				"macOS (.pkg), Windows (.exe) and Linux. The executable and bundle names are not documented and " +
				"no install was read, so the row is not launchable; the LCR-75 grounding run gives the path.",
		},
	},
	// Snowflake Cortex Code (`cortex`, docs/cortexcode-adapter.md). Phase-0
	// grounded 2026-10-21 against v1.2.18 on WSL Ubuntu and Windows 11.
	"cortex-code": {
		Tool: "cortex-code",
		// 20 native names (bash/write/edit live; the rest off the v1.2.18
		// bundle's native->Claude hook-name table and the live cron system
		// reminder). sql_execute stays unknown on purpose.
		Vocabulary: Vocabulary{InTaxonomy: true},
		// UserPromptSubmit reaches the claude-code receiver through the
		// Claude Code settings replay and is judged as cortex-code.
		PromptLane: PromptLaneHook,
		// Inference is Snowflake's Cortex REST threads API on the account
		// host (https://<account>.snowflakecomputing.com/api/v2/cortex/
		// threads/<id>), the same host that carries auth and SQL. No
		// Anthropic/OpenAI base-URL knob: routing needs a Snowflake-shaped
		// provider lane.
		Proxy:       nil,
		Routability: RouteStatusAfterBridge,
		// Cortex RUNS Claude Code's ~/.claude/settings.json hooks; the
		// claude-code receiver recognises its payload (transcript_path under
		// ~/.snowflake/cortex/conversations) and gates it as cortex-code
		// (internal/hook foreignhost.go, operator ruling 2026-10-21). That is
		// the live path today. Surface-gap W-2a: Observer's own writer for
		// Cortex's hooks.json (`observer hook cortex-code <event>` commands,
		// FU-141: while it is registered the Claude settings replay of the
		// same call answers neutral) is built, CLI only, and switched off
		// until live check LC18 (does Cortex run that file). The Cortex Code IDE runs
		// neither file (LC18 partial, 2026-10-26; W-7 records it ungated).
		Hook: HookSpec{Mechanism: HookCortexHooksJSON, AutoWired: true, Bindings: hookBindingsCortexCode, LiveGate: "LC18"},
		// Cortex loads ~/.claude.json mcpServers plus its own user mcp.json
		// managed by `cortex mcp add`; no writer targets the latter.
		MCP:    nil,
		Native: NativeRails{},
		TokenTier: TokenTier{
			Best:              "session_meta",
			Gap:               "no per-message usage: one session-cumulative row per model from conversations/<id>.json, MAX-upgraded; no per-turn cache observation; billed in Snowflake credits, so cost is a list-price estimate; token_usage is a process-wide per-model running total written when cortex quits (bundle-read): a parent likely includes in-process subagent spend, and a second session in the same process (/new, resume) may inherit earlier totals",
			SessionCumulative: true,
		},
		// history.jsonl re-reads the full turn. When a launcher lands:
		//   Resume: ResumeSpec{Kind: ResumeNative, Subcommand: "cortex", IDMechanism: "flag:--resume"}
		//   Model: ModelSpec{Kind: ModelArg, Flag: "--model"} (`-m, --model`)
		// and the positional [message] is the interactive seed.
		Handoff: HandoffCapability{
			Transcript: TranscriptFull,
			Inject:     []InjectKind{InjectFile},
			Note:       "no observer launcher yet; native resume `cortex --resume <id>` grounded, positional [message] seed not live-verified",
		},
		Binary: &BinaryResolveSpec{
			Names: BinaryNames{
				Unix:    []string{"cortex"},
				Windows: []string{"cortex.cmd", "cortex.exe"},
			},
			ProbeDirs: []ProbeDir{
				{OS: ProbeUnix, Rel: ".local/bin"},
				{OS: ProbeWindows, Rel: "AppData/Local/cortex/bin"},
			},
			Installs: []InstallHint{
				{OS: "linux", Channel: "script", Argv: []string{"sh", "-lc", "curl -LsS https://ai.snowflake.com/static/cc-scripts/install.sh | sh"}, Display: "curl -LsS https://ai.snowflake.com/static/cc-scripts/install.sh | sh", Requires: []string{"curl"}},
				{OS: "windows", Channel: "script", Argv: []string{"powershell", "-ExecutionPolicy", "ByPass", "-c", "irm https://ai.snowflake.com/static/cc-scripts/install.ps1 | iex"}, Display: "irm https://ai.snowflake.com/static/cc-scripts/install.ps1 | iex"},
			},
			InstallNote: "macOS not grounded: the same install.sh is expected to work but was not run",
		},
		Model:   ModelSpec{Kind: ModelNone},
		Sandbox: SandboxSpec{Note: "not sandbox-launchable: no observer launcher; state lives in ~/.snowflake (connections.toml credentials + cortex/)"},
		// GUI row (FU-148, vendor docs only, no live check): Cortex Code
		// Desktop. docs.snowflake.com/en/user-guide/cortex-code/
		// cortex-code-desktop/index (fetched 2026-10-29): "a native
		// macOS/Windows desktop application", "Available for macOS and
		// Windows". No executable or bundle name is documented, so the row is
		// ungrounded: listed, never launchable.
		GUI: &GUILaunchSpec{
			ID:      "cortex-code-desktop",
			Label:   "Cortex Code Desktop",
			Surface: "desktop",
			Wrap: WrapSpec{
				Reason: "cortex-code is after_bridge: inference is Snowflake's Cortex REST API on the account host, with no Anthropic or OpenAI base-URL knob to inject",
			},
			Hosts:    []string{"cortex-code"},
			Grounded: false,
			Note: "Vendor docs only (docs.snowflake.com Cortex Code Desktop page, 2026-10-29): a native desktop app " +
				"for macOS and Windows. The executable and bundle names are not documented and no install was " +
				"read, so the row is not launchable; the LC18 grounding run gives the path.",
		},
	},
	// Tencent CodeBuddy Code (docs/codebuddy-adapter.md). Grounded
	// 2026-10-21 against v2.171.0 on WSL + Windows; the operator could not
	// log in, so the store shape is real but tool/token lines are grounded
	// on the vendor bundle only.
	"codebuddy": {
		Tool: "codebuddy",
		// 41 native names from the CLI's built-in tool enum (bundle
		// 2.171.0), Claude-Code-compatible spellings; none observed in a
		// real transcript yet.
		Vocabulary: Vocabulary{
			InTaxonomy: true,
			Note:       "tool names grounded on the vendor bundle's built-in tool enum; Read/Bash/Edit live",
		},
		// Claude-Code-compatible UserPromptSubmit; decision block + exit 2
		// blocked live 2026-10-21 (the top-level-block dialect).
		PromptLane: PromptLaneHook,
		// CODEBUDDY_BASE_URL overrides the model endpoint; the CLI then
		// POSTs <base>/v2/chat/completions (OpenAI chat-completions shape)
		// to CodeBuddy's OWN authenticated gateway. Never driven live.
		Proxy:       nil,
		Routability: RouteStatusProbeRequired,
		// The "hooks" key of ~/.codebuddy/settings.json. Its Claude-shaped
		// env block can carry CODEBUDDY_API_KEY (credential-file exception).
		// Windows runs hooks under Git Bash (the bridge is gitBashWrapper).
		Hook: HookSpec{
			Mechanism: HookCodeBuddySettings, CrossOSBridge: true, AutoWired: true, Bindings: hookBindingsCodeBuddy,
			HooksShareCredentialFile: true, CredentialFileReason: credFileCodeBuddy,
			WindowsRunner: windowsRunnerCodeBuddy,
		},
		// `codebuddy mcp add -s local|project|user`; {"mcpServers":{}} shape;
		// user scope ~/.codebuddy/.mcp.json. No writer.
		MCP:    nil,
		Native: NativeRails{},
		TokenTier: TokenTier{
			Best: "jsonl",
			Gap:  "usage shape live (hook-probe mock model, numbers unproven); no cost field; sub-agent transcripts not ingested",
			// The vendor log's agent.model_call.completed duration_ms.
			GenerationTiming: GenTimingNative,
		},
		// When a launcher lands: Resume ResumeNative "flag:--resume" joined
		// (`codebuddy --resume=<id>`) and Model ModelArg "--model".
		Handoff: HandoffCapability{
			Transcript: TranscriptFull,
			Inject:     []InjectKind{InjectFile},
			Note:       "no observer launcher yet; native resume is `codebuddy --resume=<id>` (optional-value flag, joined form)",
		},
		Binary: &BinaryResolveSpec{
			// npm package bins: codebuddy / cbc / codebuddy-code (one entry
			// point). `cbc` omitted as too short/ambiguous. Windows forms are
			// the npm .cmd shims (no .exe exists).
			Names: BinaryNames{
				Unix:    []string{"codebuddy", "codebuddy-code"},
				Windows: []string{"codebuddy.cmd", "codebuddy", "codebuddy-code.cmd", "codebuddy-code"},
			},
			Installs: []InstallHint{
				{OS: "", Channel: "npm", Argv: []string{"npm", "install", "-g", "@tencent-ai/codebuddy-code"}, Display: "npm install -g @tencent-ai/codebuddy-code"},
			},
		},
		Model:   ModelSpec{Kind: ModelNone},
		Sandbox: SandboxSpec{Note: "not sandbox-launchable: no observer launcher for codebuddy; ~/.codebuddy holds settings.json and MCP config"},
		// GUI row (FU-148, vendor docs only, no live check): the CodeBuddy
		// IDE, one of the product's three forms beside the plugin and the CLI.
		// Tencent Cloud's getting-started guide (tencentcloud.com/document/
		// product/1256/77266 and 77277, fetched 2026-10-29) lists "Windows,
		// macOS, Linux", a download from the CodeBuddy site, a drag into
		// Applications on macOS and a per-user installer on Windows. No
		// executable or bundle name is documented, so the row is ungrounded:
		// listed, never launchable.
		GUI: &GUILaunchSpec{
			ID:      "codebuddy-ide",
			Label:   "CodeBuddy IDE",
			Surface: "ide",
			Wrap: WrapSpec{
				Reason: "not grounded: no base-URL setting of the IDE has been checked (coding surface codebuddy-ide, LCR-76)",
			},
			Hosts:    []string{"codebuddy"},
			Grounded: false,
			Note: "Vendor docs only (Tencent Cloud CodeBuddy getting-started guide, 2026-10-29): an IDE for Windows, " +
				"macOS and Linux. The executable and bundle names are not documented and no install was read, so the " +
				"row is not launchable; the LCR-76 grounding run gives the path.",
		},
	},
	// Deep Agents Code (`dcode`, docs/deepagents-adapter.md). Phase-0
	// grounded 2026-10-21 against deepagents-code 0.1.87 (WSL live session).
	"deepagents-code": {
		Tool: "deepagents-code",
		// Hooks v2 UserPromptSubmit: exit 2 / decision block blocked live
		// 2026-10-21 (the claude-code prompt dialect).
		PromptLane: PromptLaneHook,
		// 15 native tool names grounded off mapTool: the SDK FsToolName set
		// plus the harness tools. MCP tools are exported as <server>_<tool>
		// with NO marker, so they stay unknown.
		Vocabulary: Vocabulary{InTaxonomy: true},
		// Upstream is whatever LangChain provider the user picked
		// (OpenRouter live). Per provider the base URL resolves from
		// config.toml [models.providers.<p>] base_url, then the provider env
		// var with DEEPAGENTS_CODE_<VAR> beating <VAR>. Read from source,
		// never live-verified; no single route fits every provider.
		Proxy:       nil,
		Routability: RouteStatusProbeRequired,
		// Hooks v2 (Claude-compatible), the user-level
		// ~/.deepagents/hooks.json ($DEEPAGENTS_HOME); Windows dcode runs
		// hooks under cmd.exe.
		Hook: HookSpec{Mechanism: HookDeepAgentsJSON, CrossOSBridge: true, AutoWired: true, Bindings: hookBindingsDeepAgents},
		// ~/.deepagents/.mcp.json {"mcpServers": {...}}: the shared JSON
		// shape; no writer wired.
		MCP:    nil,
		Native: NativeRails{},
		TokenTier: TokenTier{
			Best: "sqlite",
			Gap:  "thread-naming and /btw spend is one cumulative row with no model (attributed to the thread's last model); sub-agent calls carry no GenMs and no Tier-2 observation",
			// Both ends of each model call are in the checkpoint stream.
			GenerationTiming: GenTimingNative,
			// output = output - reasoning, reasoning carried separately
			// (internal/adapter/deepagents doc.go).
			ReasoningDisjoint: true,
			// response_metadata.cost (OpenRouter-reported dollars) rides as
			// EstimatedCostUSD (internal/adapter/deepagents/parse.go).
			ReportsCost: true,
		},
		// No launcher in v1. Grounded for that follow-up: `dcode -r [ID]`
		// (IDMechanism "flag:-r" / --resume), `-M, --model MODEL`,
		// `-m/--message` seeds an initial prompt.
		Handoff: HandoffCapability{
			Transcript: TranscriptFull,
			Inject:     []InjectKind{InjectFile},
			Note:       "no launcher in this adapter's v1 scope; resume would be `dcode -r <thread_id>`",
		},
		Binary: &BinaryResolveSpec{
			Names: BinaryNames{
				Unix:    []string{"dcode", "deepagents-code"},
				Windows: []string{"dcode.exe", "deepagents-code.exe"},
			},
			// `uv tool install` puts the bins in ~/.local/bin on both OSes.
			ProbeDirs: []ProbeDir{
				{OS: ProbeUnix, Rel: ".local/bin"},
				{OS: ProbeWindows, Rel: ".local/bin"},
			},
			Installs: []InstallHint{
				{OS: "linux", Channel: "script", Argv: []string{"bash", "-lc", "curl -LsSf https://langch.in/dcode | bash"}, Display: "curl -LsSf https://langch.in/dcode | bash", Requires: []string{"curl"}},
				{OS: "darwin", Channel: "script", Argv: []string{"bash", "-lc", "curl -LsSf https://langch.in/dcode | bash"}, Display: "curl -LsSf https://langch.in/dcode | bash", Requires: []string{"curl"}},
			},
			InstallNote: "operator-grounded: the same `curl -LsSf https://langch.in/dcode | bash` run from Git Bash on Windows 11 installed dcode.exe via `uv tool install`; no PowerShell variant was observed, so no windows InstallHint is claimed. dcode's self-update is broken on Windows (see docs/deepagents-adapter.md)",
		},
		Model:   ModelSpec{Kind: ModelNone},
		Sandbox: SandboxSpec{Note: "not sandbox-launchable: no observer launcher for dcode; ~/.deepagents holds the store, config.toml and auth.json / chatgpt-auth.json credentials"},
	},
	// DimCode (`dim` / `dimcode`, npm dimcode; docs/dimcode-adapter.md).
	// Capture-only v1, grounded 2026-10-21 on dimcode 0.5.21 (WSL Ubuntu +
	// Windows 11, one real session each).
	"dimcode": {
		Tool: "dimcode",
		// hooks.json UserPromptSubmit: exit 2 + stderr blocked live
		// 2026-10-21 (the kimi-code prompt dialect). No trust step.
		PromptLane: PromptLaneHook,
		// 20 native tool names: live = todowrite/write/edit/exec, the rest
		// from the tool registry in the vendor binary. MCP/dynamic tool
		// names are not grounded and land as unknown.
		Vocabulary: Vocabulary{InTaxonomy: true},
		// The base URL is per provider (`dim provider update <id>
		// --base-url <url>`, persisted with credentials). Surface-gap S-16
		// (2026-10-25, https://dimcode.dev/docs/config) corrects "no global
		// env knob": OPENAI_BASE_URL / DIMCODE_OPENAI_BASE_URL,
		// DIMCODE_ANTHROPIC_BASE_URL and DIMCODE_GEMINI_BASE_URL exist and
		// the runtime env overrides saved files. No launcher yet. No route
		// driven live (the live provider was OpenRouter).
		Proxy:       nil,
		Routability: RouteStatusProbeRequired,
		// Claude-Code-style ~/.dimcode/v2/hooks.json. There is NO trust step
		// (live 2026-10-21; `dim hooks` only manages a disable list).
		// Windows dim runs hooks under cmd.exe.
		Hook: HookSpec{Mechanism: HookDimCodeJSON, CrossOSBridge: true, AutoWired: true, Bindings: hookBindingsDimCode},
		// <home>/mcp.json, {"mcpServers":{...}}; the file does not exist on
		// either grounding box, so no writer is claimed.
		MCP:    nil,
		Native: NativeRails{},
		TokenTier: TokenTier{
			Best: "sqlite",
			Gap:  "tokens are per-run totals (usage_run_stats), one row per user prompt, plus standalone ledger calls; no per-call or per-turn cache split",
			// reasoning is never stamped (completionTokens includes it and
			// bills through OutputTokens), which counts as disjoint.
			ReasoningDisjoint: true,
			// The vendor cost rides as EstimatedCostUSD only when its quality
			// is "exact" (internal/adapter/dimcode/tokens.go exactCost).
			ReportsCost: true,
		},
		// Resume grounded (`dim --session <id>`, `dim exec resume <id>`)
		// but no `observer dimcode` launcher exists.
		Handoff: HandoffCapability{
			Transcript: TranscriptFull,
			Inject:     []InjectKind{InjectFile},
			Note:       "no `observer dimcode` launcher yet; native resume is `dim --session <id>`",
		},
		Binary: &BinaryResolveSpec{
			// npm global shims; the real executable is a platform binary
			// the node wrapper spawns, not on PATH itself.
			Names: BinaryNames{
				Unix:    []string{"dim", "dimcode"},
				Windows: []string{"dim.cmd", "dimcode.cmd", "dim", "dimcode"},
			},
			Installs: []InstallHint{
				{OS: "", Channel: "npm", Argv: []string{"npm", "install", "-g", "dimcode@latest"}, Display: "npm install -g dimcode@latest", Requires: []string{"npm"}},
			},
		},
		Model:   ModelSpec{Kind: ModelNone},
		Sandbox: SandboxSpec{Note: "not sandbox-launchable: no sandboxed dim launch has been built or run; ~/.dimcode holds the store and provider credentials under v2/"},
	},
	// Dirac CLI (docs/dirac-adapter.md). Phase-0 grounded 2026-10-21
	// against dirac-cli 0.5.22 on Windows 11 + WSL Ubuntu and the shipped
	// bundle.
	"dirac": {
		Tool:       "dirac",
		Vocabulary: Vocabulary{InTaxonomy: true},
		// UserPromptSubmit is awaited before the model call and its cancel
		// stops it (live 2026-10-21, the dirac prompt dialect).
		PromptLane: PromptLaneHook,
		// Base-URL surface EXISTS: DIRAC_PROVIDER + DIRAC_BASE_URL (README +
		// bundle) for openai / anthropic / gemini / litellm / ..., and
		// OPENAI_API_BASE. The operator's openai-codex (ChatGPT subscription)
		// provider has NO base-URL key. Not live-verified, so Proxy stays nil
		// (cline row precedent: routable_now with no writer).
		Proxy:       nil,
		Routability: RouteStatusRoutableNow,
		// Nine legacy Cline-lineage file-per-event hooks; Observer writes
		// the PreToolUse and UserPromptSubmit files in ~/.dirac/Hooks
		// (<Event>.ps1 on Windows, where the WSL bridge is a PowerShell
		// `& wsl.exe` line).
		Hook: HookSpec{
			Mechanism: HookDiracHookFiles, CrossOSBridge: true, AutoWired: true, Bindings: hookBindingsDirac,
			WindowsRunner: windowsRunnerDirac,
		},
		// No MCP client config file and no MCP tool in 0.5.22.
		MCP:    nil,
		Native: NativeRails{},
		TokenTier: TokenTier{
			Best: "events_jsonl",
			Gap:  "reasoning stamped only for providers with a grounded output/reasoning relation (OpenAI family netted, Gemini disjoint); input netting verified for openai-codex only; no Tier-1 proxy path",
			// The adapter carries Dirac's own per-call cost.
			ReportsCost:       true,
			ReasoningDisjoint: true,
			// Both ends of each model call are in the task events.
			GenerationTiming: GenTimingNative,
		},
		// When a launcher lands: `dirac --taskId <id>` resumes (a new
		// "flag:--taskId" mechanism), `-m, --model <model>`.
		Handoff: HandoffCapability{
			Transcript: TranscriptFull,
			Inject:     []InjectKind{InjectFile},
			Note:       "no `observer dirac` launcher yet; `dirac \"<prompt>\"` (positional) seeds a task and `dirac --taskId <id>` / `-T` resumes (grounded from --help 0.5.22)",
		},
		Binary: &BinaryResolveSpec{
			// npm JS bin: `.cmd` shim on Windows, never an .exe.
			Names: BinaryNames{
				Unix:    []string{"dirac"},
				Windows: []string{"dirac.cmd", "dirac"},
			},
			Runtime: &RuntimeRequirement{Runtime: RuntimeNode, MinVersion: "22.13.0", Range: ">=22.13.0 <25.0.0", Product: "Dirac CLI", Source: "dirac-cli 0.5.22 package.json engines.node >=22.13.0 <25.0.0, read 2026-10-21"},
			Installs: []InstallHint{
				{OS: "", Channel: "npm", Argv: []string{"npm", "install", "-g", "dirac-cli"}, Display: "npm install -g dirac-cli"},
			},
		},
		Model:   ModelSpec{Kind: ModelNone},
		Sandbox: SandboxSpec{Note: "not sandbox-launchable: no observer launcher for dirac yet; ~/.dirac holds data/ (tasks, secrets.json) and the Hooks dir"},
	},
	// Kimchi (Cast AI, docs/kimchi-adapter.md). Phase-0 grounded 2026-10-21
	// against kimchi 1.17.0 on WSL2 Ubuntu + Windows 11 and the installed
	// bundle. pi-mono derivative, own parser.
	"kimchi": {
		Tool: "kimchi",
		// The Claude-dialect UserPromptSubmit is project-scoped natively; it
		// reaches Observer only through the claude-code-hook-adapter replay
		// (default off), routed by the claude-code receiver.
		PromptLane: PromptLaneHook,
		// 25 tool names registered live + mcp / skill / ask_user from the
		// bundle's tool tables; DAP debug_* and ferment lifecycle verbs
		// deliberately unmapped.
		Vocabulary: Vocabulary{InTaxonomy: true},
		// ROUTABLE surface, route NOT DRIVEN: harness/models.json accepts
		// pi-mono custom providers and the default kimchi-dev provider's
		// baseUrl is overridable by env KIMCHI_BASE_URL. Neither
		// live-verified; a non-default host needs a /up/<id> upstream.
		Proxy:       nil,
		Routability: RouteStatusProbeRequired,
		// Native command hooks exist only in <project>/.kimchi/hooks.json.
		// Observer writes the one user-level hook Kimchi runs, the bash
		// pre-gate script (HookKimchiBashHook, Linux / macOS). A default-OFF
		// extensions.claude-code-hook-adapter makes kimchi run
		// ~/.claude/settings.json hooks; the claude-code receiver routes
		// those payloads to kimchi (internal/hook foreignhost.go).
		Hook: HookSpec{Mechanism: HookKimchiBashHook, AutoWired: true, Bindings: hookBindingsKimchi},
		// MCP client exists but no user-level file/schema grounded on disk.
		MCP:    nil,
		Native: NativeRails{},
		TokenTier: TokenTier{
			Best: "transcript",
			Gap: "per-call usage is NET input + output incl. reasoning (split at the boundary) + cacheRead/cacheWrite + " +
				"provider cost; reconciles exactly with the vendor's cache_summary cumulative. No pricing entry for " +
				"kimchi-dev/gemma-4-31b; the openai-codex lane's cost is a list-price estimate of a ChatGPT subscription",
			ReportsCost: true,
			// output is netted of reasoning at the boundary (84 live usage
			// rows), and both ends of the model call's stream are in the
			// record (GenBasisNative).
			ReasoningDisjoint: true,
			GenerationTiming:  GenTimingNative,
		},
		// No `observer kimchi` launcher. Grounded for it: `kimchi --session
		// <id>` / `--resume <id>`, positional prompt seeding, `--model`.
		Handoff: HandoffCapability{
			Transcript: TranscriptFull,
			Inject:     []InjectKind{InjectFile},
			Note:       "no `observer kimchi` launcher yet; native resume is `kimchi --session <id>`",
		},
		Binary: &BinaryResolveSpec{
			Names: BinaryNames{Unix: []string{"kimchi"}, Windows: []string{"kimchi.exe"}},
			ProbeDirs: []ProbeDir{
				{OS: ProbeUnix, Rel: ".local/bin"},
				{OS: ProbeWindows, Rel: "AppData/Local/Kimchi/bin"},
			},
			Installs: []InstallHint{
				{OS: "linux", Channel: "script", Argv: []string{"bash", "-lc", "curl -fsSL https://github.com/getkimchi/kimchi/releases/latest/download/install.sh | bash"}, Display: "curl -fsSL https://github.com/getkimchi/kimchi/releases/latest/download/install.sh | bash", Requires: []string{"curl"}},
				{OS: "darwin", Channel: "script", Argv: []string{"bash", "-lc", "curl -fsSL https://github.com/getkimchi/kimchi/releases/latest/download/install.sh | bash"}, Display: "curl -fsSL https://github.com/getkimchi/kimchi/releases/latest/download/install.sh | bash", Requires: []string{"curl"}},
				{OS: "windows", Channel: "script", Argv: []string{"powershell", "-Command", "irm https://github.com/getkimchi/kimchi/releases/latest/download/install.ps1 | iex"}, Display: "irm https://github.com/getkimchi/kimchi/releases/latest/download/install.ps1 | iex"},
			},
			InstallNote: "operator-run on WSL (install.sh) and Windows (install.ps1) 2026-10-21; darwin reuses install.sh (not run on macOS); scripts' prompt behaviour under a PTY not verified",
		},
		Model:   ModelSpec{Kind: ModelNone},
		Sandbox: SandboxSpec{Note: "not sandbox-launchable: no observer launcher for kimchi; ~/.config/kimchi holds config.json / auth.json / models.json keys"},
	},
	// Stakpak (`stakpak`, docs/stakpak-adapter.md). Phase-0 grounded
	// 2026-10-21 on stakpak 0.3.88, WSL Ubuntu + Windows 11.
	"stakpak": {
		Tool: "stakpak",
		// 8 live-seen native tool names + 5 binary-string names, off mapTool.
		// The `stakpak__` tool-server namespace is stripped by the adapter.
		Vocabulary: Vocabulary{InTaxonomy: true},
		// No base-URL env knob: the model provider is a
		// [profiles.<p>.providers.<name>] block in ~/.stakpak/config.toml,
		// the same file that holds the profile api_key. Not live-probed.
		Proxy: nil,
		// S-22 (D9): the writer is built (proxyroute memberroute.go): the
		// default profile's openai provider api_endpoint, a member edit in a
		// file holding the profile api_key. Switched off until live check
		// LC37 shows a profile api_endpoint at the proxy routes traffic (and
		// which profile a bare run picks).
		ProxyProbe: &ProxyRoute{
			Kind:                 RouteConfigFile,
			Suffix:               "/v1",
			Setting:              "[profiles.default.providers.openai] api_endpoint",
			Note:                 "proxyroute.RegisterMemberRoute(stakpak) adds api_endpoint = proxy /v1 to an existing [profiles.default.providers.openai] in ~/.stakpak/config.toml; member edit only, never the api_key; the profile a run without --profile / STAKPAK_PROFILE uses is not grounded",
			LiveGate:             "LC37",
			SharesCredentialFile: true, CredentialFileReason: routeCredStakpak,
		},
		Routability: RouteStatusProbeRequired,
		Hook:        HookSpec{Mechanism: HookNone, Note: hookNoteStakpak},
		// `stakpak mcp add|remove|list` manages ~/.stakpak/mcp.toml or
		// mcp.json (names from the binary; on-disk format never observed).
		MCP:    nil,
		Native: NativeRails{},
		// local.db: per-call usage on the assistant message. No cache split,
		// no model recorded anywhere in the store.
		TokenTier: TokenTier{Best: "sqlite", Gap: "no model recorded in the store (cost not estimated); no cache tokens (cachetrack Tier-2 not fed); keyed Stakpak-account profiles keep sessions server-side"},
		// When a launcher lands: `stakpak -s <session-uuid>` (flag:--session),
		// `--model <MODEL>`, positional [PROMPT] seed.
		Handoff: HandoffCapability{
			Transcript: TranscriptFull,
			Inject:     []InjectKind{InjectFile},
			Note:       "no `observer stakpak` launcher yet; native resume is `stakpak -s <session-uuid>`",
		},
		Binary: &BinaryResolveSpec{
			Names: BinaryNames{
				Unix:    []string{"stakpak"},
				Windows: []string{"stakpak.exe"},
			},
			// install.sh lands ~/.local/bin/stakpak(.exe), often off PATH
			// on Windows.
			ProbeDirs: []ProbeDir{
				{OS: ProbeUnix, Rel: ".local/bin"},
				{OS: ProbeWindows, Rel: ".local/bin"},
			},
			Installs: []InstallHint{
				{OS: "linux", Channel: "script", Argv: []string{"bash", "-lc", "curl -sSL https://stakpak.dev/install.sh | sh"}, Display: "curl -sSL https://stakpak.dev/install.sh | sh", Requires: []string{"curl"}},
				{OS: "darwin", Channel: "script", Argv: []string{"bash", "-lc", "curl -sSL https://stakpak.dev/install.sh | sh"}, Display: "curl -sSL https://stakpak.dev/install.sh | sh", Requires: []string{"curl"}},
				{OS: "windows", Channel: "script", Argv: []string{"bash", "-lc", "curl -sSL https://stakpak.dev/install.sh | sh"}, Display: "curl -sSL https://stakpak.dev/install.sh | sh (run from Git Bash)", Requires: []string{"bash", "curl"}},
			},
		},
		Model:   ModelSpec{Kind: ModelNone},
		Sandbox: SandboxSpec{Note: "not sandbox-launchable: no observer launcher for stakpak; ~/.stakpak holds the store and config.toml (api_key)"},
	},
	// VT Code (docs/vtcode-adapter.md). Grounded 2026-10-21 against
	// vtcode-core 0.180.2 on WSL Ubuntu + Windows 11 (operator sessions via
	// OpenRouter).
	"vtcode": {
		Tool:       "vtcode",
		Vocabulary: Vocabulary{InTaxonomy: true},
		// UserPromptSubmit blocks before the model call (live 2026-10-21,
		// TUI sessions only; exec runs fire no hook).
		PromptLane: PromptLaneHook,
		// Base-URL knobs exist but no live turn has been routed:
		// OPENROUTER_BASE_URL / OPENAI_BASE_URL / ANTHROPIC_BASE_URL / ...
		// and vtcode.toml provider_overrides.<p>.base_url. Candidate route
		// when verified: RouteLauncher, EnvVar "OPENROUTER_BASE_URL", Suffix
		// "/up/openrouter/api/v1".
		Proxy:       nil,
		Routability: RouteStatusProbeRequired,
		// [[hooks.lifecycle.<event>]] in the user-level vtcode.toml (live
		// 2026-10-21; interactive TUI sessions only). Windows runs hooks
		// under Git for Windows' sh, so the bridge is gitBashWrapper.
		Hook: HookSpec{
			Mechanism: HookVTCodeTOML, CrossOSBridge: true, AutoWired: true, Bindings: hookBindingsVTCode,
			// Every hook command runs as `sh -c <command>`; Git for Windows
			// puts only Git\cmd (no sh.exe) on PATH, and a spawn failure
			// fails OPEN (live 2026-10-24, docs/vtcode-adapter.md "Hooks").
			WindowsHookShell: HookShellRequirement{
				Shell:      "sh",
				ProvidedBy: "Git Bash",
				Fix:        `add C:\Program Files\Git\bin to the Windows PATH`,
				Grounding:  `vtcode-core 0.180.2 crates/codegen/vtcode-core/src/hooks/lifecycle/engine.rs: Command::new("sh"); "failed to spawn lifecycle hook" observed on Windows 11 2026-10-24`,
			},
		},
		// vtcode.toml [[mcp.providers]]: no observer MCPFormat matches.
		MCP:    nil,
		Native: NativeRails{},
		TokenTier: TokenTier{
			Best: "events_jsonl",
			Gap:  "one usage row per TURN by design (per-request trajectory rows would double-count against re-parses); GenMs = sum of the requests' elapsed_ms when they cover the turn; per-request implicit-cache Tier-2 observations; model from the trajectory, else the archive's session-start model; no reasoning split; archive-only sessions (deleted workspace) carry no tokens",
			// GenMs is the sum of the turn's requests' elapsed_ms.
			GenerationTiming: GenTimingNative,
		},
		// When a launcher lands: Resume ResumeNative "flag:--resume" and
		// Model ModelArg "--model".
		Handoff: HandoffCapability{
			Transcript: TranscriptFull,
			Inject:     []InjectKind{InjectFile},
			Note:       "capture-only adapter: no observer launcher yet (vtcode --resume <id>, --model <id>, --provider <p> are grounded from --help)",
		},
		Binary: &BinaryResolveSpec{
			Names: BinaryNames{
				Unix:    []string{"vtcode"},
				Windows: []string{"vtcode.exe", "vtcode"},
			},
			// Both vendor installers land ~/.local/bin/vtcode(.exe).
			ProbeDirs: []ProbeDir{
				{OS: ProbeUnix, Rel: ".local/bin"},
				{OS: ProbeWindows, Rel: ".local/bin"},
			},
			Installs: []InstallHint{
				{OS: "linux", Channel: "script", Argv: []string{"bash", "-lc", "curl -fsSL https://raw.githubusercontent.com/vinhnx/VTCode/main/scripts/install.sh | bash"}, Display: "curl -fsSL https://raw.githubusercontent.com/vinhnx/VTCode/main/scripts/install.sh | bash", Requires: []string{"curl"}},
				{OS: "windows", Channel: "script", Argv: []string{"powershell", "-Command", "irm https://raw.githubusercontent.com/vinhnx/VTCode/main/scripts/install.ps1 | iex"}, Display: "irm https://raw.githubusercontent.com/vinhnx/VTCode/main/scripts/install.ps1 | iex"},
			},
			InstallNote: "macOS not run: install.sh is the vendor's documented Unix path but was only operator-run on Linux",
		},
		Model:   ModelSpec{Kind: ModelNone},
		Sandbox: SandboxSpec{Note: "not sandbox-launchable: no observer launcher (capture-only)"},
	},
}

// RegistryVersion is the version of the adapter capability registry's
// closed tool vocabulary. It is bumped whenever a tool is ADDED or REMOVED
// (a change to the set Tools() returns), so a consumer that ships the tool
// vocabulary on a wire — e.g. the G25 aggregate rail — can stamp which
// vocabulary it was built against (design §3.2, finding #24). It versions
// the tool NAME set only, not the content of every capability cell.
// Kept honest by TestRegistryVersionMovesWithVocabulary
// (registry_version_test.go): the test pins (RegistryVersion, len(Tools()))
// as a golden pair, so adding/removing a tool without bumping this constant
// fails loudly. Bumped 1 → 2 on 2026-08-25 (adapter-parity audit): the
// constant had sat at 1 through ~24 tool additions, leaving the G25
// ConsentRegistryChanged gate inert. Bumped 2 → 3 on 2026-08-28 (grokbot,
// the Grok Bot desktop app, joined the vocabulary). Bumped 3 -> 4 on
// 2026-09-03 (kiro-crew, AWS Kiro Crew, joined the vocabulary). Bumped
// 4 -> 5 on 2026-09-05 (poolside joined the vocabulary). Bumped 5 -> 6
// on 2026-09-06 (zed, Zed's own native coding agent, joined the
// vocabulary). Bumped 6 -> 7 on 2026-10-21 (the capture-only wave:
// autohand, ibm-bob, cortex-code, codebuddy, deepagents-code, dimcode,
// dirac, kimchi, stakpak and vtcode joined the vocabulary).
const RegistryVersion = 7

// Tools returns every registered tool name, sorted. It is the canonical,
// closed tool vocabulary (NOT config.EnabledAdapters, which is a
// user-configured watch list — finding #24). Consumers that need a stable
// allow-list of known tool names source it here.
func Tools() []string {
	out := make([]string, 0, len(registry))
	for tool := range registry {
		out = append(out, tool)
	}
	sort.Strings(out)
	return out
}

// DefaultLaneUpstreams is the lane id -> grounded host root table of every
// registry row's built-in proxy lane (ProxyRoute.Lane.DefaultUpstream, and
// the lanes its covered ProviderOverrides address). The daemon layers it
// UNDER [proxy.agent_upstreams] (and the proxy prefers a same-id
// [proxy.upstreams] lane over both), so configuration always wins.
func DefaultLaneUpstreams() map[string]string {
	out := map[string]string{}
	for _, c := range registry {
		if c.Proxy == nil {
			continue
		}
		if c.Proxy.Lane != nil && c.Proxy.Lane.DefaultUpstream != "" {
			out[c.Proxy.Lane.ID] = c.Proxy.Lane.DefaultUpstream
		}
		for _, o := range c.Proxy.ProviderOverrides {
			if o.Covered() && o.Lane != nil && o.Lane.DefaultUpstream != "" {
				out[o.Lane.ID] = o.Lane.DefaultUpstream
			}
		}
	}
	return out
}

// ProviderOverridesFor returns the built-in provider table of tool's proxy
// route (nil when the tool has none). The slice is a copy.
func ProviderOverridesFor(tool string) []ProviderOverride {
	c, ok := registry[tool]
	if !ok || c.Proxy == nil || len(c.Proxy.ProviderOverrides) == 0 {
		return nil
	}
	return append([]ProviderOverride(nil), c.Proxy.ProviderOverrides...)
}

// For returns the registered Capability for a tool. ok is false when the
// tool has no registry row yet (resolve as "no known integration
// capabilities"); the returned Capability still carries the Tool name so
// callers can use it safely.
func For(tool string) (Capability, bool) {
	c, ok := registry[tool]
	if !ok {
		return Capability{Tool: tool}, false
	}
	return c, true
}

// Capabilities returns every registered Capability. Order is not
// guaranteed; callers that need determinism should sort by Tool.
func Capabilities() []Capability {
	out := make([]Capability, 0, len(registry))
	for _, c := range registry {
		out = append(out, c)
	}
	return out
}

// TranscriptTimedTools returns, sorted and de-duplicated, every tool whose
// registry row declares GenerationTiming == GenTimingTranscript: the tools
// whose token rows may receive their generation duration (token_usage.
// gen_ms) in a LATER parse than the one that first inserted them. The org
// push holds such a row back briefly (store.PushSettle) so its first push
// carries the stamp - the org ingest is insert-only.
func TranscriptTimedTools() []string {
	seen := map[string]bool{}
	for _, c := range registry {
		if c.TokenTier.GenerationTiming == GenTimingTranscript {
			seen[c.Tool] = true
		}
	}
	out := make([]string, 0, len(seen))
	for t := range seen {
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}

// ToolForLaunchSubcommand resolves an `observer <verb>` launcher verb (the
// Handoff.Launch.Subcommand a dashboard-handoff terminal_run row stores as its
// tool label) back to the canonical registry tool key (== sessions.tool).
// ok=false for an unknown or empty verb.
func ToolForLaunchSubcommand(sub string) (string, bool) {
	if sub == "" {
		return "", false
	}
	// Walk tool keys in sorted order so that IF a future row ever collides
	// on verb (registry_coverage_test.go pins that none do today), the
	// resolution is still deterministic — first match by tool-key order —
	// rather than depending on Go's randomized map iteration.
	for _, tool := range Tools() {
		if launch := registry[tool].Handoff.Launch; launch != nil && launch.Subcommand == sub {
			return tool, true
		}
	}
	return "", false
}
