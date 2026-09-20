package integration

import "sort"

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
	// operator to paste (cursor/copilot VS Code BYOK). The ProxyRoute carries
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
	// flipping the Proxy field on (cline-cli, openclaw, pi, cursor-BYOK,
	// copilot-cli/VS Code BYOK, cowork third-party gateway).
	RouteStatusProbeRequired RouteStatus = "probe_required"
	// RouteStatusNativeExempt: no routable surface found — the tool talks
	// only to its own backend with no base-URL knob (antigravity, kilo-cli
	// per the live 2026-06-26 finding, cowork's local microVM path). A
	// grounded negative, not "permanently impossible": a future version or a
	// new BYOK surface can reclassify it.
	RouteStatusNativeExempt RouteStatus = "native_exempt"
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
	// EnvVar is the base-URL env var that routes the tool at the proxy
	// (e.g. ANTHROPIC_BASE_URL, OPENAI_BASE_URL), or "" when the tool
	// routes via a config file instead (see Note).
	EnvVar string
	// Suffix is appended to the proxy URL: "/v1" for OpenAI-compatible
	// endpoints, "" for Anthropic's ANTHROPIC_BASE_URL.
	Suffix string
	// Launcher is the `observer <x>` command that wires the routing.
	Launcher string
	// Note documents config-file-routed tools (EnvVar == ""), where the
	// base URL lives in a config file rather than an env var.
	Note string
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
	TokenTier   TokenTier
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
		Vocabulary: Vocabulary{InTaxonomy: true},
		// ANTHROPIC_BASE_URL is the whole route: the Anthropic client has no
		// second provider selector to fall back to, so an invocation that
		// carries the injected base URL reaches the Observer proxy.
		Proxy: &ProxyRoute{
			Kind: RouteEnvSettings, EnvVar: "ANTHROPIC_BASE_URL", Suffix: "",
			Launcher: "observer claude", CrossOSBridge: true, Proof: RouteProofLauncherRoute,
		},
		Routability: RouteStatusRoutableNow,
		Hook:        HookSpec{Mechanism: HookClaudeSettings, CrossOSBridge: true, AutoWired: true},
		MCP:         &MCPTarget{Format: MCPServersJSON, PathHint: ".claude.json", Implemented: true},
		Native:      NativeRails{A: true, B: true, C: true},
		TokenTier:   TokenTier{Best: "proxy"},
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
			Installs: []InstallHint{
				{OS: "", Channel: "npm", Argv: []string{"npm", "install", "-g", "@anthropic-ai/claude-code"}, Display: "npm install -g @anthropic-ai/claude-code"},
				{OS: "linux", Channel: "script", Argv: []string{"bash", "-lc", "curl -fsSL https://claude.ai/install.sh | bash"}, Display: "curl -fsSL https://claude.ai/install.sh | bash"},
				{OS: "darwin", Channel: "script", Argv: []string{"bash", "-lc", "curl -fsSL https://claude.ai/install.sh | bash"}, Display: "curl -fsSL https://claude.ai/install.sh | bash"},
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
		Model: ModelSpec{Kind: ModelArg, Flag: "--model", Known: []string{"opus", "sonnet", "fable"}},
		// Sandbox filesystem-isolation row (B9). GROUNDED: the tool's own
		// state lives at ~/.claude (settings/hooks/projects transcripts),
		// ~/.claude.json + ~/.claude.json.backup (trust/onboarding/MCP
		// config); ~/.local/share/claude holds the versioned install and is
		// read-only from the sandbox's perspective.
		Sandbox: SandboxSpec{
			StateRW: []string{".claude", ".claude.json", ".claude.json.backup"},
			StateRO: []string{".local/share/claude"},
		},
		// Headless one-shot, grounded by the live benchmark drives
		// (cmd/observer/benchmark_driver.go claudeCodeDriver): `claude -p
		// <prompt> --output-format json` prints a result JSON envelope on
		// stdout. Arena arena runner reuses the same argv shape.
		Headless: &HeadlessSpec{
			PromptFlag: "-p",
			OutputArgs: []string{"--output-format", "json"},
			Result:     HeadlessResultStdoutJSON,
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
			Kind: RouteConfigFile, EnvVar: "", Launcher: "observer codex",
			Note:          "codex routes through ~/.codex/config.toml openai_base_url (not an env var)",
			CrossOSBridge: true, Proof: RouteProofLauncherRoute,
		},
		Routability: RouteStatusRoutableNow,
		// CrossOSBridge grounded 2026-09-02 (IDE-surface remediation T2):
		// hook.registerCodexWindows writes the wsl.exe bridge into the
		// Windows-side ~/.codex/hooks.json exactly like the claude-code and
		// cursor targets, so init/start's hookSupported() may auto-wire the
		// `codex-windows` target.
		Hook:      HookSpec{Mechanism: HookCodexConfig, CrossOSBridge: true, AutoWired: true},
		MCP:       &MCPTarget{Format: MCPCodexTOML, PathHint: ".codex/config.toml", Implemented: true},
		Native:    NativeRails{A: true, B: true, C: true, Note: "Rail A (usage-export) config-gated on live keys"},
		TokenTier: TokenTier{Best: "proxy"},
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
			Installs: []InstallHint{
				{OS: "", Channel: "npm", Argv: []string{"npm", "install", "-g", "@openai/codex"}, Display: "npm install -g @openai/codex"},
				// DI-10 fix: codex is a brew CASK (formulae.brew.sh/cask/codex),
				// not a formula — the bare `brew install codex` name collides.
				{OS: "darwin", Channel: "brew", Argv: []string{"brew", "install", "--cask", "codex"}, Display: "brew install --cask codex"},
				// grounded 2026-09-02: releases.openai.com/codex/install.ps1
				// (302 from chatgpt.com/codex/install.ps1), vendor form uses
				// -ExecutionPolicy ByPass. No winget id exists.
				{OS: "windows", Channel: "script", Argv: []string{"powershell", "-ExecutionPolicy", "ByPass", "-c", "irm https://chatgpt.com/codex/install.ps1 | iex"}, Display: "irm https://chatgpt.com/codex/install.ps1 | iex"},
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
		Model: ModelSpec{Kind: ModelArg, Flag: "--model", Known: []string{"o3"}},
		// Sandbox filesystem-isolation row (B9). GROUNDED against the adapter's
		// own roots (internal/adapter/codex/adapter.go WatchPaths → <home>/.codex/
		// sessions) plus the CLI's config/auth siblings: ~/.codex holds config.toml,
		// auth.json, history.jsonl and the rollout transcripts. The WHOLE dir is
		// bound rw — config.toml carries plaintext provider keys, and the sandbox
		// deliberately does not hide the operator's own credentials from the tool
		// they just launched; the boundary is about the rest of $HOME and the rest
		// of the filesystem, not about this tool's own state.
		Sandbox: SandboxSpec{StateRW: []string{".codex"}},
		// Headless one-shot, grounded by the live benchmark drives
		// (cmd/observer/benchmark_driver.go codexDriver): `codex exec
		// <prompt> --json -o <file>` writes the final message to the -o
		// file and thread ids to stdout JSON.
		Headless: &HeadlessSpec{
			Lead:       []string{"exec"},
			OutputArgs: []string{"--json"},
			Result:     HeadlessResultOutputFile,
			ResultFlag: "-o",
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
		// through exactly that injection.
		Proxy: &ProxyRoute{
			Kind: RouteLauncher, EnvVar: "OPENAI_BASE_URL", Suffix: "/v1",
			Launcher: "observer opencode", Proof: RouteProofLauncherRoute,
		},
		Routability: RouteStatusRoutableNow,
		Hook:        HookSpec{Mechanism: HookNone},
		// OpenCode hosts MCP under its own "mcp" object in
		// ~/.config/opencode/opencode.json (live-grounded 2026-06-26 against
		// the operator's install: {"type":"local","command":[…],"enabled"}),
		// written globally by registerOpenCodeJSON.
		MCP:       &MCPTarget{Format: MCPOpenCodeJSON, PathHint: ".config/opencode/opencode.json", Implemented: true},
		Native:    NativeRails{},
		TokenTier: TokenTier{Best: "sqlite"},
		// P0.1 FULL: opencode.db message+part tables (reader = P2 tranche).
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
				{OS: "linux", Channel: "script", Argv: []string{"bash", "-lc", "curl -fsSL https://opencode.ai/install | bash"}, Display: "curl -fsSL https://opencode.ai/install | bash"},
				{OS: "darwin", Channel: "script", Argv: []string{"bash", "-lc", "curl -fsSL https://opencode.ai/install | bash"}, Display: "curl -fsSL https://opencode.ai/install | bash"},
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
		// the opencode binary unmodified.
		Model: ModelSpec{Kind: ModelArg, Flag: "--model"},
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
		},
		// Sandbox filesystem-isolation row (B9). GROUNDED against
		// internal/adapter/opencode/adapter.go defaultRoots (~/.opencode and
		// ~/.local/share/opencode) plus the XDG config dir the guard dialect
		// compiler already writes (~/.config/opencode/opencode.json — see
		// cmd/observer/guardcompile.go). auth.json lives in the data dir, so the
		// whole state tree is bound rw: the tool needs its own credentials.
		Sandbox: SandboxSpec{
			StateRW: []string{".local/share/opencode", ".config/opencode", ".opencode"},
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
				Reason: "child_env, NOT config_write, and the plan §2.2 sketch said the opposite — here is " +
					"why. WrapConfigWrite's contract is that an EXISTING config-lane writer applies the route, " +
					"but internal/proxyroute has no opencode registrar (claude/codex/crush/kimi/qwen only) and " +
					"this row carries no ProxyProbe, so naming one would point the operator at a writer that " +
					"does not exist. What IS grounded and live-verified for opencode is the launcher lane in " +
					"this row's Proxy above: `observer opencode` exports OPENAI_BASE_URL=<proxy>/v1, and the " +
					"desktop app embeds the same core. Injecting it on a cold start is the honest best effort; " +
					"whether the Electron shell honours the env var (rather than only the per-provider baseURL " +
					"in ~/.config/opencode/opencode.json, inventory §4.1) is NOT verified — treat a launch " +
					"that produces no api_turns row as the config lane winning.",
			},
			Hosts:    []string{"opencode"},
			Grounded: true,
			Note: "Windows layout grounded on this box 2026-09-03: " +
				"%LOCALAPPDATA%\\Programs\\@opencode-aidesktop\\OpenCode.exe, with NO bin\\ dir — hence " +
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
		// knob (exempt), but Cursor's custom "OpenAI Base URL" / BYOK model
		// setting MAY route through observer — unconfirmed on a live install,
		// so probe before flipping Proxy on. Proxy stays nil (observer drives
		// no route today); the surface is recorded in Routability, not faked.
		Proxy:       nil,
		Routability: RouteStatusProbeRequired,
		Hook:        HookSpec{Mechanism: HookCursor, CrossOSBridge: true, AutoWired: true},
		MCP:         &MCPTarget{Format: MCPServersJSON, PathHint: ".cursor/mcp.json", Implemented: true},
		Native:      NativeRails{}, // business admin/usage API not yet investigated (Phase-4 ledger).
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
		TokenTier: TokenTier{Best: "sqlite", Gap: "IDE builds since 3.15.x drop usage from stop payloads; per-turn usage comes from afterAgentResponse where it fires and, for the CLI, from its agent_cli.turn.outcome log records (final attempt only, so a lower bound)"},
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
				{OS: "linux", Channel: "script", Argv: []string{"bash", "-lc", "curl https://cursor.com/install -fsS | bash"}, Display: "curl https://cursor.com/install -fsS | bash"},
				{OS: "darwin", Channel: "script", Argv: []string{"bash", "-lc", "curl https://cursor.com/install -fsS | bash"}, Display: "curl https://cursor.com/install -fsS | bash"},
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
		Sandbox: SandboxSpec{Note: "state dirs not yet grounded — not sandbox-launchable"},
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
				Reason: "the in-IDE agent's backend is hard-wired to Cursor's own service — no base-URL env " +
					"var exists. The one BYOK knob (\"OpenAI Base URL\") is a VS Code setting persisted in the " +
					"live `state.vscdb`, which Observer will not write; it is a manual paste, which is why this " +
					"row's Routability is probe_required with RouteManual rather than a driven route " +
					"(inventory §2.5 / §4.2). Launch yes, wrap no; capture rides the agent-transcripts + " +
					"store.db watcher path.",
			},
			Hosts:    []string{"cursor"},
			Grounded: true,
			Note: "Windows layout grounded on this box 2026-09-03: " +
				"%LOCALAPPDATA%\\Programs\\cursor\\Cursor.exe (+ resources\\app\\bin\\{cursor,cursor.cmd}, which " +
				"grounds `cursor <dir>`). macOS bundle \"Cursor.app\" grounded from the Homebrew cask `cursor`; " +
				"winget id `Anysphere.Cursor` grounded from a live `winget search --exact` against the official " +
				"winget source the same day — the inventory rates Anysphere's vendor blessing of that package " +
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
			"would be zero or copied) — see productLifecycles[\"roo-code\"] for that product's lifecycle. " +
			"Cline itself is active.",
		// VS Code extension → backend. The "OpenAI Compatible" Base URL surface
		// is routable, but it is a MANUAL-PASTE route, not an auto-writer:
		// live-grounded 2026-06-27, Cline stores its provider/base-URL config
		// in VS Code's globalState (state.vscdb) + SecretStorage, NOT a JSON
		// file (the globalStorage settings dir holds only cline_mcp_settings
		// .json; the claude-dev globalState key held only welcomeViewCompleted,
		// no openAiBaseUrl anywhere). Writing state.vscdb while VS Code runs is
		// unsafe — its in-memory cache overwrites external writes on exit. So
		// the route is `observer`-printed instructions to paste into the
		// extension UI (RouteManual), surfaced via proxyroute.VSCodeBaseURLHint.
		Proxy:       nil,
		Routability: RouteStatusRoutableNow,
		Hook:        HookSpec{Mechanism: HookNone},
		// Cline (saoudrizwan.claude-dev) hosts MCP in VS Code globalStorage
		// cline_mcp_settings.json (standard {"mcpServers":{…}} shape, live-
		// confirmed 2026-06-26: {"mcpServers":{}}). Written natively on the
		// daemon OS (locate "cline") AND cross-OS into a Windows VS Code from
		// a WSL daemon via the cline-windows wsl.exe bridge (CrossOSBridge).
		MCP:       &MCPTarget{Format: MCPServersJSON, PathHint: "<vscode>/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json", Implemented: true, CrossOSBridge: true},
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
		Hook:        HookSpec{Mechanism: HookNone},
		MCP:         nil,
		Native:      NativeRails{A: true, B: true, C: true, Note: "rails partial; identity = GitHub login, cost seat/account-level"},
		TokenTier:   TokenTier{Best: "events_jsonl", Gap: "no cache tier"},
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
		// FIX-7 (phase-2 review): Copilot CLI/SDK's userPromptSubmitted
		// is REDACT-capable but explicitly cannot block ("This hook
		// cannot reject a prompt or enforce policy" — GitHub docs,
		// contract §2.2) and no writer exists for it yet; the proxy
		// lane (already routed today) is the only real coverage.
		PromptLane: PromptLaneProxyOnly,
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
			Kind: RouteLauncher, EnvVar: "COPILOT_PROVIDER_BASE_URL", Suffix: "/v1",
			Launcher: "observer copilot-cli", Proof: RouteProofLauncherRoute,
			SelectorArguments: []string{
				"--provider-type", "--provider_type", "--provider-base-url",
				"--provider_base_url", "--backend", "--auth-type", "--auth_type",
			},
		},
		Routability: RouteStatusRoutableNow,
		Hook:        HookSpec{Mechanism: HookNone},
		MCP:         nil,
		Native:      NativeRails{}, // shares Copilot's GitHub governance but no separate node rail grounded.
		// Captures cache read + creation and nets input (log.go). Live
		// 2026-06-26 grounding: session.shutdown carries the FULL
		// session-aggregate input/cache/cost WITHOUT --log-level debug
		// (modelMetrics.<model>.usage); debug only adds PER-TURN input/cache
		// attribution (plain turns are output-only). The "no cache tier" the
		// audit attributed here was VS Code copilot's, not the CLI's.
		TokenTier: TokenTier{Best: "events_jsonl", Gap: "per-turn input/cache attribution needs --log-level debug (session-aggregate captured without it)"},
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
		// would use. NAMES only.
		AuthEnv: []string{"COPILOT_PROVIDER_API_KEY", "COPILOT_GITHUB_TOKEN", "GH_TOKEN", "GITHUB_TOKEN"},
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
				{OS: "linux", Channel: "script", Argv: []string{"bash", "-lc", "curl -fsSL https://gh.io/copilot-install | bash"}, Display: "curl -fsSL https://gh.io/copilot-install | bash"},
				{OS: "darwin", Channel: "script", Argv: []string{"bash", "-lc", "curl -fsSL https://gh.io/copilot-install | bash"}, Display: "curl -fsSL https://gh.io/copilot-install | bash"},
				{OS: "windows", Channel: "winget", Argv: []string{"winget", "install", "GitHub.Copilot"}, Display: "winget install GitHub.Copilot"},
			},
		},
		// Model picker (B5). The `observer copilot-cli` launcher OWNS its
		// own `--model` cobra flag (cmd/observer/copilotcli.go) and
		// translates it to COPILOT_MODEL in the child env for the BYOK
		// provider — it is NOT forwarded verbatim to the wrapped `copilot`
		// binary's own `--model` flag (which picks among GitHub-hosted
		// models, e.g. `copilot --model gpt-5.4`). ModelArg is still the
		// correct delivery shape from the dashboard's perspective: the
		// picker still appends `--model <value>` to the launcher's argv,
		// just to a flag the launcher itself consumes rather than passes
		// through. Known left empty: COPILOT_MODEL values are BYOK-provider-
		// specific (operator's own upstream catalog), not the GitHub-hosted
		// `copilot --model` values (e.g. gpt-5.4) that this row's flag does
		// NOT select — no example was grounded for the BYOK lane, so none
		// is fabricated here.
		Model: ModelSpec{Kind: ModelArg, Flag: "--model"},
		// Sandbox filesystem-isolation row (B9). GROUNDED against
		// internal/adapter/copilotcli/paths.go candidateRoots (<home>/.copilot/
		// session-state and <home>/.copilot/logs). ~/.copilot is the CLI's whole
		// state dir and is bound rw as one dir; it holds this tool's own GitHub
		// auth state.
		Sandbox: SandboxSpec{StateRW: []string{".copilot"}},
	},
	"kilo-code": {
		Tool:       "kilo-code",
		Vocabulary: Vocabulary{InTaxonomy: true},
		// Legacy IDE extension (wraps cline). Same "OpenAI Compatible" Base URL
		// surface as cline VS Code, and the same MANUAL-PASTE reality: the
		// base URL lives in live VS Code globalState (state.vscdb), not a
		// writable JSON, so the route is operator-pasted instructions
		// (RouteManual / proxyroute.VSCodeBaseURLHint), not an auto-writer.
		Proxy:       nil,
		Routability: RouteStatusRoutableNow,
		Hook:        HookSpec{Mechanism: HookNone},
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
		// Native-exempt per the live 2026-06-26 finding: @kilocode/cli has no
		// base-URL env handling and talks to the api.kilo.ai gateway directly
		// (docs/kilo-code-adapter.md). A grounded negative, not "permanently
		// impossible" — a future @kilocode/cli custom-provider knob would
		// reclassify it; a re-probe is optional/low-priority.
		Proxy:       nil,
		Routability: RouteStatusNativeExempt,
		Hook:        HookSpec{Mechanism: HookNone},
		MCP:         nil,
		Native:      NativeRails{},
		// Per-message tokens NET (Anthropic-shape, verified). kilo-auto/* has
		// explicit pricing aliases; stealth/* gateway models price via the
		// cost engine's provider-segment strip (stealth/claude-sonnet-4.6 →
		// claude-sonnet-4.6). cachetrack shape rule now covers stealth/claude
		// explicitly (Anthropic-shape) alongside kilo-auto.
		TokenTier: TokenTier{Best: "sqlite"},
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
				{OS: "linux", Channel: "script", Argv: []string{"bash", "-lc", "curl -fsSL https://kilo.ai/cli/install | bash"}, Display: "curl -fsSL https://kilo.ai/cli/install | bash"},
				{OS: "darwin", Channel: "script", Argv: []string{"bash", "-lc", "curl -fsSL https://kilo.ai/cli/install | bash"}, Display: "curl -fsSL https://kilo.ai/cli/install | bash"},
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
		// FIX-7 (phase-2 review): no prompt-submit hook lane for
		// cline-cli — it is already proxy-routed today, which is its
		// only realistic path to prompt-submit intervention (Cline's
		// UserPromptSubmit hook exists for the VS Code extension, a
		// DIFFERENT tool row, `cline`, with its own POSIX-only
		// registration caveat).
		PromptLane: PromptLaneProxyOnly,
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
		Proxy:       &ProxyRoute{Kind: RouteProviderJSON, EnvVar: "", Suffix: "/v1", Launcher: "observer cline-cli", Note: "routes via the openai-compatible provider's settings.baseUrl in ~/.cline/data/settings/providers.json; launcher writes baseUrl, never a key"},
		Routability: RouteStatusRoutableNow,
		Hook:        HookSpec{Mechanism: HookClineCLIJSONL, AutoWired: false}, // receiver exists (clinecli/hook.go); the live hooks.jsonl is lifecycle-only (no token payload) → stays a tailer, not auto-wired.
		// MCP: nil here means "no WRITER", not "not capable" — re-grounded
		// 2026-08-01 against cline 3.0.48. There is still NO
		// cline_mcp_settings.json on the live install (the settings dir holds
		// only providers.json + cli-notices.json), but Cline CLI IS
		// MCP-capable via a command: `cline mcp install|add <name>
		// [targetArgs...] --transport stdio --yes`. MCPTarget cannot express
		// that today — every MCPFormat names a FILE and PathHint assumes one —
		// so wiring it needs a command-mediated MCPFormat plus a writer in
		// internal/mcp, not a row edit. Left nil deliberately rather than
		// fabricating a target we cannot write (docs/clinecli-adapter.md).
		MCP:       nil,
		Native:    NativeRails{},
		TokenTier: TokenTier{Best: "sqlite"}, // sessions.db + per-session messages.json; full.
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
				"spellings NOT grounded — Windows-only for now. Sessions land in ~/.cline/data with " +
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
		Proxy:       &ProxyRoute{Kind: RouteProviderJSON, EnvVar: "", Suffix: "/up/openrouter/api/v1", Launcher: "observer hermes", Note: "routes via a user-config `observer` provider (providers: section) in ~/.hermes/config.yaml with key_env (secret-free); launcher writes the provider additively, never a key; needs a matching [proxy.upstreams] upstream (default openrouter)"},
		Routability: RouteStatusRoutableNow,
		Hook:        HookSpec{Mechanism: HookHermesPlugin, AutoWired: true}, // embedded plugin via `observer init --hermes`.
		MCP:         &MCPTarget{Format: MCPHermesYAML, PathHint: ".hermes/config.yaml", Implemented: true},
		Native:      NativeRails{},
		TokenTier:   TokenTier{Best: "sqlite"}, // post_api_request token rows; full.
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
				{OS: "linux", Channel: "script", Argv: []string{"bash", "-lc", "curl -fsSL https://hermes-agent.nousresearch.com/install.sh | bash"}, Display: "curl -fsSL https://hermes-agent.nousresearch.com/install.sh | bash"},
				{OS: "darwin", Channel: "script", Argv: []string{"bash", "-lc", "curl -fsSL https://hermes-agent.nousresearch.com/install.sh | bash"}, Display: "curl -fsSL https://hermes-agent.nousresearch.com/install.sh | bash"},
				{OS: "windows", Channel: "script", Argv: []string{"powershell", "-Command", "iex (irm https://hermes-agent.nousresearch.com/install.ps1)"}, Display: "iex (irm https://hermes-agent.nousresearch.com/install.ps1)"},
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
		Sandbox: SandboxSpec{StateRW: []string{".hermes"}},
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
					"applies to Desktop too — the GUI launch itself writes nothing and records " +
					"wrap_applied=false naming that writer. Carry the CLI's known bug forward: an " +
					"OpenRouter-catalog-matching model name can silently override an explicit custom " +
					"base_url (upstream #39753).",
			},
			Hosts:    []string{"hermes"},
			Grounded: false,
			Note: "UNVERIFIED on the grounding box (2026-09-03): %LOCALAPPDATA%\\hermes exists but is the " +
				"CLI's DATA dir (HERMES_HOME — config.yaml, auth.json, bin\\), and " +
				"%LOCALAPPDATA%\\com.nousresearch.hermes.setup contains only an EBWebView profile left by an " +
				"installer — neither grounds a desktop executable. No Homebrew cask `hermes` and no winget " +
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
		Hook:        HookSpec{Mechanism: HookNone},
		MCP:         nil,
		Native:      NativeRails{},
		TokenTier:   TokenTier{Best: "transcript", Gap: "capture depth un-audited"},
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
					"proxy / mTLS settings ONLY from managed settings and ~/.claude/settings.json — never from " +
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
				"Claude_pzs8sxrjxfjjc, and the manifest's single Application Id \"Claude\" — so the AUMID is " +
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
		LifecycleNote: "Individual / AI Pro / AI Ultra tiers retired by Google on 2026-06-18 in favour of Antigravity (agy); Standard/Enterprise still served — https://developers.google.com/gemini-code-assist/docs/deprecations/code-assist-individuals",
		Vocabulary:    Vocabulary{InTaxonomy: true},
		// Phase E SHIPPED + LIVE-VERIFIED 2026-06-27: the proxy bridges Google
		// generateContent (providerForPath → ProviderGoogle, the
		// generativelanguage upstream, parseGeminiResponse/parseGeminiStream
		// usageMetadata) and `observer gemini` sets GOOGLE_GEMINI_BASE_URL (no
		// /v1 suffix — the CLI appends the /v1beta path). A live `observer
		// gemini -- -p …` turn produced google api_turns rows (gemini-3.5-flash
		// 11092/132) with accurate token capture.
		Proxy:       &ProxyRoute{Kind: RouteLauncher, EnvVar: "GOOGLE_GEMINI_BASE_URL", Suffix: "", Launcher: "observer gemini"},
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
		Hook:      HookSpec{Mechanism: HookGeminiSettings, CrossOSBridge: true, AutoWired: true, PromptLaneOnly: true},
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
		Sandbox: SandboxSpec{StateRW: []string{".gemini"}},
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
		Hook:        HookSpec{Mechanism: HookNone},
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
			Installs: []InstallHint{
				{OS: "linux", Channel: "script", Argv: []string{"bash", "-lc", "curl -fsSL https://openclaw.ai/install.sh | bash"}, Display: "curl -fsSL https://openclaw.ai/install.sh | bash"},
				{OS: "darwin", Channel: "script", Argv: []string{"bash", "-lc", "curl -fsSL https://openclaw.ai/install.sh | bash"}, Display: "curl -fsSL https://openclaw.ai/install.sh | bash"},
				// grounded 2026-09-02: openclaw.ai/install.ps1 installs Node
				// (winget → choco → scoop → portable) then npm-installs
				// itself; the CMD form here mirrors the vendor's Unix
				// script shape for a native-Windows daemon.
				{OS: "windows", Channel: "script", Argv: []string{"powershell", "-Command", "iwr -useb https://openclaw.ai/install.ps1 | iex"}, Display: "iwr -useb https://openclaw.ai/install.ps1 | iex"},
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
		Sandbox: SandboxSpec{StateRW: []string{".openclaw"}},
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
					"`OpenClawGateway` WSL distro — %LOCALAPPDATA%\\OpenClawTray\\ is state/logs, not a " +
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
				Reason: "config-write is the ONLY route OpenClaw honours — ANTHROPIC_BASE_URL explicitly " +
					"does not work (upstream #56679) and a pre-existing auth-profiles.json can silently " +
					"bypass a configured baseUrl — but this row carries NEITHER a verified Proxy nor a " +
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
				"shell was NOT separately verified. Windows Hub layout unverified — Names.Windows empty. " +
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
		Proxy:       &ProxyRoute{Kind: RouteProviderJSON, EnvVar: "", Suffix: "/v1", Launcher: "observer pi", Note: "routes via ~/.pi/agent/models.json custom 'observer' provider baseUrl (not an env var); launcher writes it, never a key"},
		Routability: RouteStatusRoutableNow,
		Hook:        HookSpec{Mechanism: HookNone},
		MCP:         nil,
		Native:      NativeRails{},
		TokenTier:   TokenTier{Best: "transcript", Gap: "capture depth un-audited"},
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
			Installs: []InstallHint{
				{OS: "", Channel: "npm", Argv: []string{"npm", "install", "-g", "--ignore-scripts", "@earendil-works/pi-coding-agent"}, Display: "npm install -g --ignore-scripts @earendil-works/pi-coding-agent"},
				{OS: "linux", Channel: "script", Argv: []string{"bash", "-lc", "curl -fsSL https://pi.dev/install.sh | sh"}, Display: "curl -fsSL https://pi.dev/install.sh | sh"},
				{OS: "darwin", Channel: "script", Argv: []string{"bash", "-lc", "curl -fsSL https://pi.dev/install.sh | sh"}, Display: "curl -fsSL https://pi.dev/install.sh | sh"},
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
		Sandbox: SandboxSpec{StateRW: []string{".pi"}},
	},
	"antigravity": {
		Tool:       "antigravity",
		Vocabulary: Vocabulary{InTaxonomy: true},
		// No base-URL / custom-provider knob found (decrypt-gated, own
		// backend). A grounded negative — reclassify if Google documents a
		// gateway knob.
		Proxy:       nil,
		Routability: RouteStatusNativeExempt,
		Hook:        HookSpec{Mechanism: HookNone},
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
		// .pb cipher stays parked, IDE-12).
		TokenTier: TokenTier{Best: "sqlite", Gap: "standalone-IDE conversations (no .db) carry no usage: transcript.jsonl has none, .pb still decrypt-gated"},
		// Desktop transcript.jsonl is readable plaintext → text + actions
		// present; tokens only for agy-backed (.db) conversations → partial.
		Handoff: HandoffCapability{Transcript: TranscriptPartial, Inject: []InjectKind{InjectFile}, Note: "desktop transcript.jsonl plaintext (text + actions); tokens only when an agy .db exists (VS Code extension), absent for the standalone IDE"},
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
					{OS: "darwin", Channel: "brew", Argv: []string{"brew", "install", "--cask", "antigravity"}, Display: "brew install --cask antigravity"},
				},
				InstallNote: "no grounded Linux channel: antigravity.google ships a direct download, not a " +
					"scriptable one-liner.",
			},
			DarwinApp: "Antigravity",
			// FALSE, grounded negative: unlike every other VS Code fork on
			// this box (Kiro, Qoder, Windsurf, Cursor), the antigravity
			// install dir has NO bin\ directory at all — no `antigravity`
			// shim, so no grounded `<app> <dir>` argv form. Assuming one
			// from the fork lineage would be a fabricated capability.
			ProjectDirArgv: false,
			Wrap: WrapSpec{
				Kind: WrapNone,
				Reason: "no base-URL knob found for the IDE (this row's Routability is native_exempt; the " +
					"sibling `agy` CLI documents GOOGLE_GEMINI_BASE_URL but the antigravity-cli row records " +
					"that as an UNVERIFIED contradiction, inventory §2.3). Launch yes, wrap no; capture " +
					"rides the IDE's plaintext brain/<uuid>/.system_generated/logs/transcript.jsonl " +
					"(text + tool actions + model + surface; tokens absent — the .pb cipher stays parked).",
			},
			Hosts:    []string{"antigravity"},
			Grounded: true,
			Note: "Windows layout grounded on this box 2026-09-03: " +
				"%LOCALAPPDATA%\\Programs\\antigravity\\Antigravity.exe — and NO bin\\ dir, hence " +
				"ProjectDirArgv=false and no unix shim name (the inventory left both \"to ground\"). macOS " +
				"bundle \"Antigravity.app\" grounded from the Homebrew cask `antigravity`; winget id " +
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
		// Active; lifecycle context as on the antigravity row — agy is the
		// named successor of Gemini CLI for individual tiers (retired
		// 2026-06-18). No `agy login` subcommand exists: first interactive
		// run opens a browser OAuth flow (OS keyring); BYOK = GEMINI_API_KEY
		// + modelProvider:"gemini" in ~/.gemini/antigravity-cli/settings.json.
		LifecycleNote: "Google's successor to Gemini CLI after the 2026-06-18 individual-tier retirement " +
			"(https://developers.googleblog.com/an-important-update-transitioning-gemini-cli-to-antigravity-cli/); " +
			"family inventory: docs/audits/antigravity-family-surfaces-2026-09-03.md.",
		// agy CLI itself is non-proxied (runs locally).
		Proxy:       nil,
		Routability: RouteStatusNativeExempt,
		Hook:        HookSpec{Mechanism: HookNone},
		MCP:         nil,
		Native:      NativeRails{},
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
				{OS: "linux", Channel: "script", Argv: []string{"bash", "-lc", "curl -fsSL https://antigravity.google/cli/install.sh | bash"}, Display: "curl -fsSL https://antigravity.google/cli/install.sh | bash"},
				{OS: "darwin", Channel: "script", Argv: []string{"bash", "-lc", "curl -fsSL https://antigravity.google/cli/install.sh | bash"}, Display: "curl -fsSL https://antigravity.google/cli/install.sh | bash"},
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
		Sandbox: SandboxSpec{Note: "state dirs not yet grounded — not sandbox-launchable"},
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
			Kind:     RouteConfigFile,
			EnvVar:   "",
			Suffix:   "/v1",
			Launcher: "observer qwen",
			Note:     "routes via model.baseUrl + a matching modelProviders openai entry in ~/.qwen/settings.json (proxyroute.RegisterQwenCode, retargets the openai-default provider, keeps id + envKey); implicit host was api.openai.com so the fixed OpenAI upstream applies. Live-verified 2026-07-09 (api_turns 23728-23730, gpt-4o-2024-08-06)",
		},
		// ProxyProbe PERSISTS after promotion: it is the config-lane WRITER
		// BINDING init uses to apply the (now verified) route on a machine whose
		// ~/.qwen/settings.json is not yet routed. Proxy above is the verified
		// route; this is how init writes it.
		ProxyProbe: &ProxyRoute{
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
		Hook: HookSpec{Mechanism: HookQwenSettings, CrossOSBridge: true, AutoWired: true, PromptLaneOnly: true},
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
			Installs: []InstallHint{
				{OS: "", Channel: "npm", Argv: []string{"npm", "install", "-g", "@qwen-code/qwen-code@latest"}, Display: "npm install -g @qwen-code/qwen-code@latest"},
				{OS: "linux", Channel: "script", Argv: []string{"bash", "-lc", "curl -fsSL https://qwen-code-assets.oss-cn-hangzhou.aliyuncs.com/installation/install-qwen-standalone.sh | bash"}, Display: "curl -fsSL https://qwen-code-assets.oss-cn-hangzhou.aliyuncs.com/installation/install-qwen-standalone.sh | bash"},
				{OS: "darwin", Channel: "script", Argv: []string{"bash", "-lc", "curl -fsSL https://qwen-code-assets.oss-cn-hangzhou.aliyuncs.com/installation/install-qwen-standalone.sh | bash"}, Display: "curl -fsSL https://qwen-code-assets.oss-cn-hangzhou.aliyuncs.com/installation/install-qwen-standalone.sh | bash"},
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
		Sandbox: SandboxSpec{StateRW: []string{".qwen"}},
	},
	"kiro-cli": {
		Tool:       "kiro-cli",
		PromptLane: PromptLaneProbeRequired,
		Vocabulary: Vocabulary{InTaxonomy: true},
		// SigV4-signed AWS endpoints (CodeWhisperer lineage); no base-URL /
		// BYOK surface exists on a live install — grounded negative.
		Proxy:       nil,
		Routability: RouteStatusNativeExempt,
		// Kiro has first-class agent hooks (~/.kiro/hooks) upstream, but no
		// observer receiver is wired — honest none.
		Hook: HookSpec{Mechanism: HookNone},
		// ~/.kiro/settings/mcp.json is the documented MCP surface; absent on
		// this install, shape unconfirmed — no writer until grounded.
		MCP:    nil,
		Native: NativeRails{},
		// Mode-dependent dual store (flat bundles + conversations_v2 sqlite);
		// local token counts were structurally 0/null in every capture.
		TokenTier: TokenTier{Best: "transcript", Gap: "no proxy tier (SigV4); local token counts 0/null in practice — credit metering only, not stored as tokens"},
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
				{OS: "linux", Channel: "script", Argv: []string{"bash", "-lc", "curl -fsSL https://cli.kiro.dev/install | bash"}, Display: "curl -fsSL https://cli.kiro.dev/install | bash"},
				{OS: "darwin", Channel: "script", Argv: []string{"bash", "-lc", "curl -fsSL https://cli.kiro.dev/install | bash"}, Display: "curl -fsSL https://cli.kiro.dev/install | bash"},
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
					"in this row's Binary above — that installs the CLI, not the IDE.)",
			},
			DarwinApp:      "Kiro",
			ProjectDirArgv: true,
			Wrap: WrapSpec{
				Kind: WrapNone,
				Reason: "AWS ships no BYOK / base-URL surface for Kiro at all — four open vendor issues, and " +
					"a third-party `kiro-gateway` proxy exists precisely because of the gap (inventory §2.8 / " +
					"§4.2; this row's Routability is native_exempt). Launch yes, wrap no; capture rides " +
					"~/.kiro/sessions.",
			},
			Hosts:    []string{"kiro-cli"},
			Grounded: true,
			Note: "Windows layout grounded on this box 2026-09-03: " +
				"%LOCALAPPDATA%\\Programs\\Kiro\\Kiro.exe (+ bin\\{kiro,kiro.cmd}, which grounds both the unix " +
				"shim stem and `kiro <dir>` — the inventory left the IDE binary name \"to ground\"). macOS " +
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
			Kind:     RouteLauncher,
			EnvVar:   "GROK_CLI_CHAT_PROXY_BASE_URL",
			Suffix:   "/up/grok/v1",
			Launcher: "observer grok --proxy",
			Note:     "Opt-in via the --proxy launcher flag; routes at the [proxy.upstreams] grok upstream (cli-chat-proxy.grok.com), not the default lane.",
		},
		Routability: RouteStatusRoutableNow,
		// updates.jsonl shows hook_execution records (ACP pre_tool_use fired
		// live) — a real upstream hook system, but no observer receiver is
		// wired; honest none.
		Hook: HookSpec{Mechanism: HookNone},
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
			Installs: []InstallHint{
				{OS: "", Channel: "npm", Argv: []string{"npm", "install", "-g", "@xai-official/grok"}, Display: "npm install -g @xai-official/grok"},
				{OS: "linux", Channel: "script", Argv: []string{"bash", "-lc", "curl -fsSL https://x.ai/cli/install.sh | bash"}, Display: "curl -fsSL https://x.ai/cli/install.sh | bash"},
				{OS: "darwin", Channel: "script", Argv: []string{"bash", "-lc", "curl -fsSL https://x.ai/cli/install.sh | bash"}, Display: "curl -fsSL https://x.ai/cli/install.sh | bash"},
				{OS: "windows", Channel: "script", Argv: []string{"powershell", "-Command", "irm https://x.ai/cli/install.ps1 | iex"}, Display: "irm https://x.ai/cli/install.ps1 | iex"},
			},
		},
		// Model picker (B5). Grounded live 2026-08-08: `grok --help` lists
		// `-m, --model <MODEL>  Model ID to use`. The `observer grok` launcher
		// is DisableFlagParsing + launcherArgsOrDone (B6), so a forwarded
		// `--model <value>` reaches the grok binary unmodified.
		Model: ModelSpec{Kind: ModelArg, Flag: "--model"},
		// Headless one-shot, LIVE-GROUNDED 2026-08-22 (arena headless-drive
		// arc): `grok -p <prompt> --output-format json --always-approve`
		// prints a single JSON envelope keyed text/sessionId/usage/
		// total_cost_usd (claude-shaped but different keys). A real drive
		// created answer.txt and replied DONE; a second drive returned
		// sessionId + full usage without any proxy lane.
		Headless: &HeadlessSpec{
			PromptFlag: "-p",
			OutputArgs: []string{"--output-format", "json", "--always-approve"},
			Result:     HeadlessResultGrokJSON,
		},
		// Sandbox filesystem-isolation row (B9). GROUNDED against
		// internal/adapter/grok/adapter.go defaultRoots (<home>/.grok/sessions and
		// <home>/.grok/logs). ~/.grok is bound rw as one dir.
		Sandbox: SandboxSpec{StateRW: []string{".grok"}},
	},
	"kimi-code": {
		Tool:       "kimi-code",
		PromptLane: PromptLaneProbeRequired,
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
			Kind:     RouteConfigFile,
			EnvVar:   "",
			Suffix:   "/v1",
			Launcher: "observer kimi",
			Note:     "routes via base_url under [providers.openai] in ~/.kimi-code/config.toml (proxyroute.RegisterKimiCode, additive, never a key); implicit host was api.openai.com so the fixed OpenAI upstream applies. Live-verified 2026-07-09 (api_turns 23075, gpt-4o-2024-08-06)",
		},
		// ProxyProbe PERSISTS after promotion: it is the config-lane WRITER
		// BINDING init uses to apply the (now verified) route on a machine
		// whose ~/.kimi-code/config.toml is not yet routed. Proxy above is
		// the verified route; this is how init writes it.
		ProxyProbe: &ProxyRoute{
			Kind:     RouteConfigFile,
			Launcher: "observer kimi",
			Note:     "proxyroute.RegisterKimiCode adds base_url under [providers.openai] in ~/.kimi-code/config.toml (additive, never a key)",
		},
		Routability: RouteStatusRoutableNow,
		// No hook surface observed on the live install — honest none.
		Hook: HookSpec{Mechanism: HookNone},
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
			Note:       "no seed lane (-p prints+exits; TUI seedless) — doc-assisted launch",
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
			Installs: []InstallHint{
				{OS: "", Channel: "npm", Argv: []string{"npm", "install", "-g", "@moonshot-ai/kimi-code"}, Display: "npm install -g @moonshot-ai/kimi-code"},
				{OS: "linux", Channel: "script", Argv: []string{"bash", "-lc", "curl -fsSL https://code.kimi.com/kimi-code/install.sh | bash"}, Display: "curl -fsSL https://code.kimi.com/kimi-code/install.sh | bash"},
				{OS: "darwin", Channel: "script", Argv: []string{"bash", "-lc", "curl -fsSL https://code.kimi.com/kimi-code/install.sh | bash"}, Display: "curl -fsSL https://code.kimi.com/kimi-code/install.sh | bash"},
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
		Sandbox: SandboxSpec{StateRW: []string{".kimi-code"}},
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
		// A `crush run` turn driven from the Windows crush.cmd reached WSL's
		// :8820 over localhost forwarding and landed api_turns rows (id 23081
		// gpt-5.4-mini 6613/20 + id 23080 gpt-5.4-nano title call,
		// provider=openai, HTTP 200). Proxy now drives the config-lane route;
		// init applies it via the RegisterCrush writer (dispatched on Kind).
		Proxy: &ProxyRoute{
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
			Kind: RouteProviderJSON,
			Note: "proxyroute.RegisterCrush sets providers.openai.base_url in crush.json (additive, never a key)",
		},
		Routability: RouteStatusRoutableNow,
		Hook:        HookSpec{Mechanism: HookNone},
		// MCP client exists, but its config also lives in crush.json — same
		// guarded-write constraint as the proxy lane.
		MCP:    nil,
		Native: NativeRails{},
		// Project-local .crush/crush.db; tokens + pre-computed cost are
		// session-cumulative (no per-message split).
		TokenTier: TokenTier{Best: "sqlite", Gap: "session-cumulative counts only (no per-message split, no cache/reasoning breakdown)"},
		// messages.parts carry full text/reasoning/tool bodies; NO seed lane
		// (upstream charmbracelet/crush#1791) — file-lane carry only.
		Handoff: HandoffCapability{
			Transcript: TranscriptFull,
			Inject:     []InjectKind{InjectFile},
			Note:       "no interactive-seed lane (upstream #1791)",
		},
		// Sandbox filesystem-isolation row (B9). GROUNDED against
		// internal/adapter/crush/discover.go stateDirsForHome
		// (<home>/.local/share/crush) plus the global config
		// ($HOME/.config/crush/crush.json, plugins/crush/README.md). The
		// project-local <repo>/.crush store needs no row — it lives inside the
		// workspace, which the sandbox already binds rw. Declared even though
		// crush has no launcher verb today (Handoff.Launch is nil).
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
		Hook: HookSpec{Mechanism: HookCascadeJSON, AutoWired: true, PromptLaneOnly: true},
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
		TokenTier: TokenTier{Best: "sqlite", Gap: "cache_creation null in all captured rows; no reasoning-token split (thinking folded into output)"},
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
				{OS: "linux", Channel: "script", Argv: []string{"bash", "-lc", "curl -fsSL https://cli.devin.ai/install.sh | bash"}, Display: "curl -fsSL https://cli.devin.ai/install.sh | bash"},
				{OS: "darwin", Channel: "script", Argv: []string{"bash", "-lc", "curl -fsSL https://cli.devin.ai/install.sh | bash"}, Display: "curl -fsSL https://cli.devin.ai/install.sh | bash"},
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
		Sandbox: SandboxSpec{Note: "state dirs not yet grounded — not sandbox-launchable"},
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
					"Devin Desktop builds was not verified — advertising it could install the sunset product " +
					"(docs/harness-lifecycle-policy.md). Use the vendor download at devin.ai/desktop.",
			},
			DarwinApp:      "Devin",
			ProjectDirArgv: true,
			Wrap: WrapSpec{
				Kind: WrapNone,
				Reason: "no DEVIN_BASE_URL or any documented base-URL knob for the desktop lane (this row's " +
					"Routability is native_exempt; inventory §2.10 / §4.2). Launch yes, wrap no; the bundled " +
					"devin.exe lane writes the CLI store this row's watcher already reads — CORRECTED " +
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
				"deprecated Windsurf name — %LOCALAPPDATA%\\Programs\\Windsurf\\Windsurf.exe (+ " +
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
		Hook: HookSpec{Mechanism: HookQoderJSON, CrossOSBridge: true, AutoWired: true, PromptLaneOnly: true},
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
		TokenTier: TokenTier{Best: "none", Gap: "usage server-side only — local logs carry zero tokens and no model; no base-URL knob"},
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
			Installs: []InstallHint{
				{OS: "", Channel: "npm", Argv: []string{"npm", "install", "-g", "@qoder-ai/qodercli"}, Display: "npm install -g @qoder-ai/qodercli"},
				{OS: "linux", Channel: "script", Argv: []string{"bash", "-lc", "curl -fsSL https://qoder.com/install | bash"}, Display: "curl -fsSL https://qoder.com/install | bash"},
				{OS: "darwin", Channel: "script", Argv: []string{"bash", "-lc", "curl -fsSL https://qoder.com/install | bash"}, Display: "curl -fsSL https://qoder.com/install | bash"},
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
		Sandbox: SandboxSpec{StateRW: []string{".qoder"}},
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
				"IDE\\Qoder IDE.exe (+ bin\\{qoder,qoder.cmd} — and, betraying the VS Code fork lineage, " +
				"bin\\{code,code.cmd} too), which grounds both the unix shim stem and `qoder <dir>`. macOS " +
				"bundle name NOT grounded (no cask) — DarwinApp left empty rather than guessed. The IDE's " +
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
			Kind: RouteLauncher, EnvVar: "OPENAI_API_BASE", Suffix: "/v1",
			Launcher: "observer aider",
			SelectorArguments: []string{
				"-m", "--model", "--env-file", "--model-settings-file",
				"--openai-api-base", "--openai-api-type", "--api-type",
				"--anthropic-api-version", "--anthropic-api-key",
				"--openai-api-key", "--api-key",
			},
		},
		Routability: RouteStatusRoutableNow,
		// No pre/post-tool hook surface exists.
		Hook: HookSpec{Mechanism: HookNone},
		// Not an MCP client host observer writes into.
		MCP:    nil,
		Native: NativeRails{},
		// Tokens exist only as prose lines in the Markdown transcript
		// ("Tokens: 10.0k sent, ..."), format_tokens-ROUNDED; `sent` is
		// GROSS → the adapter nets it against the cache-hit clause. Aider's
		// own per-message Cost is carried as EstimatedCostUSD.
		TokenTier: TokenTier{Best: "transcript", Gap: "prose-only rounded counts (unreliable precision); no reasoning split; no per-turn timestamps"},
		// The per-repo .aider.chat.history.md is fully re-readable, but
		// there is NO seed lane: --message runs one turn and exits, the
		// REPL takes no preload flag — file-lane carry only. `observer aider`
		// (2026-08-21) is a minimal exec+env-inject launcher only — no
		// --continue-from/--attach/--resume wiring, so no Launch/Attach/
		// Resume block below.
		Handoff: HandoffCapability{
			Transcript: TranscriptFull,
			Inject:     []InjectKind{InjectFile},
			Note:       "no interactive-seed lane (--message exits after the turn)",
		},
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
		Headless: &HeadlessSpec{
			PromptFlag:  "--message",
			OutputArgs:  []string{"--yes", "--no-auto-commits"},
			Result:      HeadlessResultStdoutText,
			ContextMode: HeadlessContextPositional,
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
				{OS: "linux", Channel: "script", Argv: []string{"sh", "-lc", "curl https://aider.chat/install.sh | sh"}, Display: "curl https://aider.chat/install.sh | sh"},
				{OS: "darwin", Channel: "script", Argv: []string{"sh", "-lc", "curl https://aider.chat/install.sh | sh"}, Display: "curl https://aider.chat/install.sh | sh"},
				{OS: "windows", Channel: "script", Argv: []string{"powershell", "-ExecutionPolicy", "ByPass", "-c", "irm https://aider.chat/install.ps1 | iex"}, Display: "irm https://aider.chat/install.ps1 | iex"},
			},
		},
		// Sandbox filesystem-isolation row (B9). GROUNDED against
		// internal/adapter/aider/doc.go: the transcripts are PROJECT-local
		// (<repo>/.aider.chat.history.md), which the sandbox already binds rw
		// as the workspace, and the only home-relative state is ~/.aider
		// (analytics.json / installs.json / the model-price cache). Rows are
		// declared for every adapter, not only the launchable ones — aider has
		// no launcher verb today (Handoff.Launch is nil), so this row is data
		// waiting for one.
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
		// no documented BYOK / custom-base-URL surface. This adapter's
		// scope is deliberately usage-capture only (no proxy launcher work
		// was performed), so this is the honest default bucket rather than
		// a confirmed negative — reclassify if a base-URL knob surfaces.
		Proxy:       nil,
		Routability: RouteStatusNativeExempt,
		// No pre/post-tool hook surface is documented; none registered.
		Hook: HookSpec{Mechanism: HookNone},
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
		// session.jsonl.zstd is fully re-readable (whole-file rewrite on
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
		Proxy:       &ProxyRoute{Kind: RouteLauncher, EnvVar: "OPENAI_HOST", Suffix: "", Launcher: "observer goose --proxy", Note: "Opt-in --proxy flag injects OPENAI_HOST at the proxy ROOT (goose appends /v1). Requires GOOSE_PROVIDER=openai (or another OPENAI_HOST-honoring provider); an ambient OPENAI_HOST in the operator env wins over the injection by design."},
		Routability: RouteStatusRoutableNow,
		// No pre/post-tool hook surface exists (extensions are MCP servers,
		// not hooks).
		Hook: HookSpec{Mechanism: HookNone},
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
		TokenTier: TokenTier{Best: "sqlite", Gap: "session-level counts only (messages.tokens null in all captures); no reasoning split; cache_write null on OpenAI"},
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
				{OS: "linux", Channel: "script", Argv: []string{"bash", "-lc", "curl -fsSL https://github.com/aaif-goose/goose/releases/download/stable/download_cli.sh | bash"}, Display: "curl -fsSL https://github.com/aaif-goose/goose/releases/download/stable/download_cli.sh | bash"},
				{OS: "darwin", Channel: "script", Argv: []string{"bash", "-lc", "curl -fsSL https://github.com/aaif-goose/goose/releases/download/stable/download_cli.sh | bash"}, Display: "curl -fsSL https://github.com/aaif-goose/goose/releases/download/stable/download_cli.sh | bash"},
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
					"the CLI's config surface (inventory §2.11) — but the env lane is verified for the CLI " +
					"only, NOT for the desktop app. Same caveats as the CLI: it needs GOOSE_PROVIDER=openai " +
					"(or another OPENAI_HOST-honouring provider), and an ambient OPENAI_HOST in the operator's " +
					"environment wins over the injection by design.",
			},
			Hosts:    []string{"goose"},
			Grounded: true,
			Note: "Grounded from the macOS side ONLY: bundle \"Goose.app\" and the cask token `block-goose` " +
				"read from the Homebrew cask API on 2026-09-03. Goose Desktop is NOT installed on the " +
				"Windows grounding box, so its Windows layout is unverified and Names.Windows is empty — " +
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
		Hook:   HookSpec{Mechanism: HookBrowserExtension, AutoWired: true},
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
		Hook:        HookSpec{Mechanism: HookBrowserExtension, AutoWired: true},
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
		Hook:        HookSpec{Mechanism: HookBrowserExtension, AutoWired: true},
		MCP:         nil,
		Native:      NativeRails{},
		TokenTier:   TokenTier{Best: "browser_extension", Gap: "no server-side usage field; estimated only (no light client tokenizer — chars/4 heuristic)"},
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
		Hook:        HookSpec{Mechanism: HookBrowserExtension, AutoWired: true},
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
		Hook:        HookSpec{Mechanism: HookBrowserExtension, AutoWired: true},
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
		Hook: HookSpec{Mechanism: HookFactoryJSON, CrossOSBridge: true, AutoWired: true, PromptLaneOnly: true},
		// ~/.factory/mcp.json reuses claude-code/cursor's {"mcpServers":{}}
		// shape (format confirmed live via a zero-cost `droid mcp add`/
		// `remove` probe). A writer now exists (internal/mcp/register.go's
		// generic registerJSONMCP, via the internal/mcp/locate row) so this
		// is Implemented — parking §3.4.
		MCP:    &MCPTarget{Format: MCPServersJSON, PathHint: ".factory/mcp.json", Implemented: true},
		Native: NativeRails{},
		// Sidecar <uuid>.settings.json carries session-level cumulative
		// tokens only — no per-message token field in the JSONL itself.
		TokenTier: TokenTier{Best: "jsonl", Gap: "no per-message tokens; no proxy path verified; Factory-hosted built-in-model wire shape entirely unconfirmed (no active subscription in this corpus)"},
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
					"~/.factory/settings.json (a file Observer never reads — plaintext keys) and this row " +
					"carries neither a verified Proxy nor a ProxyProbe binding; the desktop reuses the " +
					"bundled droid's provider config, so there is nothing to wrap. Launch yes, wrap no.",
			},
			Hosts:    []string{"droid"},
			Grounded: true,
			Note: "Windows layout grounded on this box 2026-09-03: %LOCALAPPDATA%\\Factory\\factory-desktop.exe " +
				"(Squirrel stub) → app-0.168.0\\factory-desktop.exe (Electron) bundling " +
				"app-0.168.0\\resources\\bin\\droid.exe. macOS bundle NOT grounded — DarwinApp left empty. " +
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
			Installs: []InstallHint{
				{OS: "linux", Channel: "script", Argv: []string{"bash", "-lc", "curl -fsSL https://app.factory.ai/cli | sh"}, Display: "curl -fsSL https://app.factory.ai/cli | sh"},
				{OS: "darwin", Channel: "script", Argv: []string{"bash", "-lc", "curl -fsSL https://app.factory.ai/cli | sh"}, Display: "curl -fsSL https://app.factory.ai/cli | sh"},
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
		Sandbox: SandboxSpec{StateRW: []string{".factory"}},
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
		Proxy:       nil,
		Routability: RouteStatusProbeRequired,
		// Codex's hook mechanism (HookCodexConfig) may port, but this
		// fork's config.toml has no [hooks] observed live — unverified.
		Hook: HookSpec{Mechanism: HookNone},
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
		TokenTier: TokenTier{Best: "jsonl", Gap: "no proxy path verified on this fork; hook mechanism unconfirmed"},
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
					"(alongside plaintext API keys — a file Observer never reads), and this row carries " +
					"neither a verified Proxy nor a ProxyProbe writer binding, so config_write would name a " +
					"writer that does not exist. Launch yes, wrap no.",
			},
			Hosts:    []string{"open-interpreter"},
			Grounded: true,
			Note: "Windows layout grounded on this box 2026-09-03: %ProgramFiles%\\Interpreter\\Interpreter.exe " +
				"(the updater payload sits at %LOCALAPPDATA%\\interpreter-updater\\installer.exe). macOS " +
				"bundle NOT grounded — DarwinApp left empty. Sessions: %APPDATA%\\interpreter\\codex-home\\" +
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
				{OS: "linux", Channel: "script", Argv: []string{"bash", "-lc", "curl -fsSL https://www.openinterpreter.com/install | sh"}, Display: "curl -fsSL https://www.openinterpreter.com/install | sh"},
				{OS: "darwin", Channel: "script", Argv: []string{"bash", "-lc", "curl -fsSL https://www.openinterpreter.com/install | sh"}, Display: "curl -fsSL https://www.openinterpreter.com/install | sh"},
				{OS: "windows", Channel: "script", Argv: []string{"powershell", "-Command", "irm https://www.openinterpreter.com/install.ps1 | iex"}, Display: "irm https://www.openinterpreter.com/install.ps1 | iex"},
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
		// point at Command Code's OWN closed gateway (not a BYOK
		// Anthropic/OpenAI-shaped endpoint) — a knob exists but it isn't
		// routable_now-shaped, so after_bridge rather than native_exempt.
		Proxy:       nil,
		Routability: RouteStatusAfterBridge,
		// CrossOSBridge: true — internal/hook's command-code-windows
		// target (registerCommandCodeWindows) bakes the wsl.exe bridge
		// into the go:embed'd TS mod's own runtime (resolveExec()),
		// mirroring claude-code/cursor/codex's own bridges.
		Hook: HookSpec{Mechanism: HookCommandCodeMod, CrossOSBridge: true, AutoWired: true, PromptLaneOnly: true},
		// ~/.commandcode/mcp.json reuses claude-code/cursor/droid's
		// {"mcpServers":{}} shape, grounded 2026-07-29 from the npm
		// package's cli.mjs getUserMcpConfigPath + bundled reference/mcp.md.
		// A writer already exists (internal/mcp/register.go's generic
		// registerJSONMCP, via the internal/mcp/locate row) so this is
		// Implemented, not a new writer.
		MCP:    &MCPTarget{Format: MCPServersJSON, PathHint: ".commandcode/mcp.json", Implemented: true},
		Native: NativeRails{},
		// Per-assistant-message usage envelope (inputTokens/outputTokens/
		// cacheReadTokens/cacheWriteTokens/costUsd); inputTokens almost
		// certainly GROSS (high confidence, not proxy-confirmed).
		TokenTier: TokenTier{Best: "jsonl", Gap: "no Tier-1 proxy path; costUsd trusted as-is for open-weight models with no observer pricing table"},
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
		Sandbox: SandboxSpec{StateRW: []string{".commandcode"}},
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
		// row (checklist §10.1f).
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
		Hook: HookSpec{Mechanism: HookNone},
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
				{OS: "linux", Channel: "script", Argv: []string{"bash", "-lc", "curl -fsSL https://dev.meta.ai/install.sh | bash"}, Display: "curl -fsSL https://dev.meta.ai/install.sh | bash"},
				{OS: "darwin", Channel: "script", Argv: []string{"bash", "-lc", "curl -fsSL https://dev.meta.ai/install.sh | bash"}, Display: "curl -fsSL https://dev.meta.ai/install.sh | bash"},
			},
			// Honest-zero carriers (2026-09-02): Names.Windows stays nil
			// AND no Windows InstallHint exists — GROUNDED against
			// muse-launcher.sh's own detect_platform() (dies on any
			// uname -s other than Darwin/Linux) and Meta's developer blog
			// ("Install Muse Code in macOS or Linux with a single
			// command"). WSL2 works because uname -s reports Linux there.
			WindowsNote: "macOS/Linux only per vendor (muse-launcher.sh detect_platform dies on any uname -s other than Darwin/Linux); runs under WSL2 because uname -s = Linux there",
			InstallNote: "no Windows install channel — install inside WSL2 and run the observer daemon there",
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
		Proxy:       &ProxyRoute{Kind: RouteLauncher, EnvVar: "", Suffix: "/v1", Launcher: "observer prime-agent", Note: "Routes via the 'observer' provider entry the launcher writes into ~/.prime/agent/models.json (baseUrl = proxy /v1); exec with --provider observer."},
		Routability: RouteStatusRoutableNow,
		// Prime Agent's extension points are TypeScript EXTENSIONS
		// (-e/--extension, pi.registerTool / lifecycle callbacks), not a
		// settings.json hook-command vocabulary observer can register into.
		// Observer ships no receiver → None rather than a mechanism init
		// cannot write.
		Hook: HookSpec{Mechanism: HookNone},
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
		// 2026-08-07 comment above) — so a Windows spelling is grounded
		// through the SAME vendor install script the Unix rows use,
		// runnable only under a bash shell (Git for Windows is
		// sufficient per vendor docs/windows.md). No npm channel is
		// declared here (TestGuidedInstallGapClosed pins that).
		Binary: &BinaryResolveSpec{
			Names: BinaryNames{
				Unix:    []string{"prime-agent"},
				Windows: []string{"prime-agent.cmd", "prime-agent"},
			},
			Installs: []InstallHint{
				{OS: "linux", Channel: "script", Argv: []string{"bash", "-lc", "curl -fsSL https://app.primeintellect.ai/prime-agent/install.sh | sh"}, Display: "curl -fsSL https://app.primeintellect.ai/prime-agent/install.sh | sh"},
				{OS: "darwin", Channel: "script", Argv: []string{"bash", "-lc", "curl -fsSL https://app.primeintellect.ai/prime-agent/install.sh | sh"}, Display: "curl -fsSL https://app.primeintellect.ai/prime-agent/install.sh | sh"},
				{OS: "windows", Channel: "script", Argv: []string{"bash", "-lc", "curl -fsSL https://app.primeintellect.ai/prime-agent/install.sh | sh"}, Display: "curl -fsSL https://app.primeintellect.ai/prime-agent/install.sh | sh"},
			},
			WindowsNote: "vendor: requires a bash shell on Windows (Git for Windows is sufficient); the install and the runtime both need bash — never PowerShell/CMD",
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
	// operator's own WSL2 Ubuntu install (Junie runs as a TUI embedded in
	// a JetBrains IDE, not a standalone CLI observer can launch/attach).
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
		// No base-URL knob has been grounded (only ~/.junie/settings.json's
		// non-credential model/provider fields were read, per the task's
		// off-limits list) — honest "not yet investigated", not a proven
		// negative.
		Proxy:       nil,
		Routability: RouteStatusProbeRequired,
		Hook:        HookSpec{Mechanism: HookNone},
		MCP:         nil,
		Native:      NativeRails{},
		// Per-call model + cost + token counts come straight off
		// LlmResponseMetadataEvent.modelUsage[] in events.jsonl — no cache
		// tier is stated (CacheInputTokens/CacheCreateTokens both observed
		// zero in the Phase-0 capture, so nothing to report as a gap yet).
		TokenTier: TokenTier{Best: "events_jsonl"},
		// events.jsonl reconstructs the full turn (verbatim prompt, agent
		// narration, terminal/file/result blocks) — a genuinely re-readable
		// transcript, same tier as cline's api_conversation_history.json.
		// No InjectPrompt: Junie is IDE-embedded with no verified
		// interactive-seed/launch contract, so Handoff.Launch stays nil
		// (not launchable in-terminal) and cmd/observer/continuefrom.go has
		// no "junie" case.
		Handoff: HandoffCapability{Transcript: TranscriptFull, Inject: []InjectKind{InjectFile}},
		// Sandbox filesystem-isolation row (B9). Honest zero: the agent runs
		// inside its host IDE's process tree, which observer never spawns, so
		// there is no launch to wrap in a filesystem boundary.
		Sandbox: SandboxSpec{Note: "not sandbox-launchable: the agent runs inside its host IDE, which observer does not spawn"},
	},
	// Poolside (docs/poolside-adapter.md). Phase-0 grounded 2026-09-05
	// against a live JetBrains IDEA 2026.2.2 run on Windows — Poolside
	// ships today ONLY as a JetBrains AI Assistant ACP agent
	// (`acp.registry.poolside`), the same IDE-embedded shape as Junie: no
	// standalone CLI/TUI process for `observer poolside` to launch.
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
		// ~/.config/poolside/settings.yaml's pool.api_url. The agent is
		// IDE-driven (no independent launch), so no base-URL override
		// flag or env var could be grounded — probe_required, not a
		// fabricated route.
		Proxy:       nil,
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
		Hook: HookSpec{Mechanism: HookPoolsideYAML, CrossOSBridge: true, AutoWired: true, PromptLaneOnly: true},
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
		},
		// The trajectory re-reads in full (prompts, reasoning, assistant
		// text, every tool call + outcome) — a genuinely re-readable
		// transcript. No Launch/Attach/Resume: there is no standalone
		// process — matches Junie's JetBrains-embedded precedent exactly.
		Handoff: HandoffCapability{Transcript: TranscriptFull, Inject: []InjectKind{InjectFile}},
		// Sandbox filesystem-isolation row (B9). Honest zero: the agent runs
		// inside its host IDE's process tree, which observer never spawns, so
		// there is no launch to wrap in a filesystem boundary.
		Sandbox: SandboxSpec{Note: "not sandbox-launchable: the agent runs inside its host IDE, which observer does not spawn"},
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
		// zcode 0.16.3) — routing it through the proxy would be a guess.
		Proxy:       nil,
		Routability: RouteStatusProbeRequired,
		// AutoWired:false — see the PromptLane comment above: the
		// receiver/dialect exist and are tested, but registration is
		// gated on the zai-org/feedback#32 liveness question.
		Hook: HookSpec{Mechanism: HookZcodeJSON, AutoWired: false, PromptLaneOnly: true},
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
			Names:       BinaryNames{Unix: []string{"zcode"}, Windows: []string{"zcode.exe"}},
			WindowsNote: "zcode.exe is bundled by the Z.ai desktop app; there is no CLI install channel",
			InstallNote: "Z.ai ships a desktop installer only (zcode.z.ai/en/docs/install); the npm package zcode-app-cli is unaffiliated — no grounded CLI channel",
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
					"a ProxyProbe writer binding — internal/proxyroute has registrars for claude/codex/crush/" +
					"kimi/qwen only. Naming a config_write ConfigTool here would point the operator at a " +
					"writer that does not exist (inventory §4.1). Revisit when a zcode registrar lands.",
			},
			Hosts:    []string{"zcode"},
			Grounded: true,
			Note: "Windows layout grounded on this box 2026-09-03: " +
				"%LOCALAPPDATA%\\Programs\\ZCode\\ZCode.exe, with NO bin\\ dir — hence ProjectDirArgv=false " +
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
		Hook:        HookSpec{Mechanism: HookNone},
		// config.mcp_servers exists but no writer emits vibe's shape.
		MCP:    nil,
		Native: NativeRails{},
		// Tokens are SESSION-LEVEL from meta.json/stats (session_prompt_
		// tokens GROSS incl. cached, session_completion_tokens,
		// session_cached_tokens, session_cost) — no per-message usage
		// field. The adapter emits one session-level token event per
		// session (netInput = session_prompt_tokens - session_cached_
		// tokens), MAX-upgraded as the session grows.
		TokenTier: TokenTier{Best: "session_meta", Gap: "no per-message usage field; one session-level token row, MAX-upgraded as the session grows"},
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
				{OS: "linux", Channel: "script", Argv: []string{"bash", "-lc", "curl -LsSf https://mistral.ai/vibe/install.sh | bash"}, Display: "curl -LsSf https://mistral.ai/vibe/install.sh | bash"},
				{OS: "darwin", Channel: "script", Argv: []string{"bash", "-lc", "curl -LsSf https://mistral.ai/vibe/install.sh | bash"}, Display: "curl -LsSf https://mistral.ai/vibe/install.sh | bash"},
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
		// login`) with no grounded base-URL override — routing it through
		// the proxy would be a guess.
		Proxy:       nil,
		Routability: RouteStatusProbeRequired,
		Hook:        HookSpec{Mechanism: HookNone},
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
		TokenTier: TokenTier{Best: "sqlite", Gap: "desktop layout only — the CLI chats store has no billable usage field; the launchable CLI surface still records sessions + actions without tokens"},
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
		Sandbox: SandboxSpec{Note: "state dirs not yet grounded — not sandbox-launchable"},
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
				"NOT grounded (no cask, no install to read) — DarwinApp left empty rather than guessed. The " +
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
		Hook:        HookSpec{Mechanism: HookNone},
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
				"layout unverified (not installed here, no winget package) — Names.Windows empty. This also " +
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
		Hook: HookSpec{Mechanism: HookNone},
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
		Hook:        HookSpec{Mechanism: HookNone},
		// No {"mcpServers":{…}}-shaped (or any other known-format) MCP
		// config surface has been grounded for Zed's own settings.json.
		MCP:    nil,
		Native: NativeRails{},
		// Per-request tokens come straight off request_token_usage in the
		// decompressed thread JSON — a SQLite-store capture tier, same
		// bucket as zcode/kilo-code-cli. No cache-creation field exists in
		// the envelope, and no pricing entry exists for zed.dev's
		// gpt-5.6-luna (a closed, non-mainstream backend), so cost rows
		// resolve as unknown rather than a fabricated price.
		TokenTier: TokenTier{Best: "sqlite", Gap: "no pricing entry for zed.dev/gpt-5.6-luna"},
		// The thread re-reads in full (every user/agent message, tool
		// call + outcome) — a genuinely re-readable transcript. No
		// Launch/Attach/Resume/Binary: Zed IS the editor, and its
		// built-in agent has no separate `observer zed` CLI/TUI process
		// to start — this is capture-only, the same shape as junie and
		// poolside.
		Handoff: HandoffCapability{Transcript: TranscriptFull, Inject: []InjectKind{InjectFile}},
		// Sandbox filesystem-isolation row (B9). Honest zero: the agent is built
		// into the Zed editor, which observer never spawns, so there is no launch
		// to wrap in a filesystem boundary.
		Sandbox: SandboxSpec{Note: "not sandbox-launchable: the agent is built into the Zed editor itself, which observer does not spawn"},
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
// vocabulary).
const RegistryVersion = 6

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
