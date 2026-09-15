package integration

// This file holds the Phase-0-discovery capability vocabulary added on top
// of the proxy-route seed in integration.go. Every type here is DATA: a
// named-constant enum or a small value struct. No behaviour, no I/O — the
// writers that consume these (cmd/observer init, internal/hook register,
// the MCP registrar, the cross-adapter doctor) live at the boundary and
// dispatch on the capability SHAPE, never on tool name (CLAUDE.md rule #3).
//
// Honesty convention (operator directive, 2026-06-26): cells are sourced
// from in-repo adapter code + docs. A ZERO value means "no grounded
// capability" — which is EITHER genuinely unsupported (e.g. cursor talks
// only to its own backend → no proxy route) OR pending a capability-
// discovery spike against a live install. The two are distinguished by the
// per-adapter comments in the registry, not by a magic value: we do NOT
// fabricate a capability we could not ground.

// HookMechanism names how observer hooks attach to a tool's own config, or
// HookNone for the watcher/SQLite-only adapters (the majority). Each
// non-None value maps to exactly one format-writer that Phase 2 will
// dispatch to from a Capabilities() walk, replacing the hardcoded
// switch in internal/hook/register.go.
type HookMechanism string

const (
	// HookNone: captured via the watcher (+ SQLite backfill) only; no hook
	// config is written into the tool. This is the honest default for most
	// adapters, not a missing feature.
	HookNone HookMechanism = ""
	// HookClaudeSettings: Claude Code's ~/.claude/settings.json "hooks"
	// block (registerClaudeCode). Carries the Windows wsl.exe bridge
	// variant — see CrossOSBridge on HookSpec.
	HookClaudeSettings HookMechanism = "claude_settings_json"
	// HookCursor: Cursor's hooks config (registerCursor).
	HookCursor HookMechanism = "cursor_hooks"
	// HookCodexConfig: Codex's ~/.codex/config.toml [features].hooks
	// (registerCodex); verified flag name is [features].hooks, NOT
	// codex_hooks (project_codex_hook_envelope memory).
	HookCodexConfig HookMechanism = "codex_config_toml"
	// HookHermesPlugin: Hermes' embedded Python plugin written under
	// ~/.hermes plus the plugins.enabled allow-list entry (RegisterHermes
	// + RegisterHermesPluginEnabled). A genuinely per-vendor format.
	HookHermesPlugin HookMechanism = "hermes_embedded_plugin"
	// HookClineCLIJSONL: Cline CLI's opt-in hooks.jsonl tail. The receiver
	// code exists (internal/adapter/clinecli/hook.go) but is NOT yet
	// auto-wired by init — one of the two "receiver exists, not wired"
	// items the 2026-06-26 review names; Phase 2 closes it.
	HookClineCLIJSONL HookMechanism = "cline_cli_hooks_jsonl"
	// HookBrowserExtension: the opt-in MV3 browser extension's
	// native-messaging bridge. The browser launches a stdio host that
	// invokes `observer browser hook <event>` with a captured-turn
	// payload on STDIN (cmd/observer/browser.go → internal/adapter/
	// browserchat), mirroring the CLI hook path. Its "config" is the
	// per-browser native-messaging host manifest that `observer init`
	// installs, NOT an AI-tool config file — so this mechanism's format
	// writer targets the browser's NativeMessagingHosts dir, a small
	// per-browser lookup table (Chrome/Edge/Brave: same shape, different
	// dirs). Declared here in Phase 1; the manifest writer + the init 4th
	// consent step land in Phase 2 (browser-extension proposal §10.2).
	HookBrowserExtension HookMechanism = "chrome_native_messaging"
	// HookGeminiSettings (Part B item 1): Gemini CLI's ~/.gemini/settings.json
	// "hooks" block — the SAME Claude-Code-shaped
	// {"hooks":{<event>:[{"hooks":[{"type":"command","command":…}]}]}}
	// structure as HookClaudeSettings, registered by
	// registerGenericSettingsHooks with a SINGLE event (BeforeAgent —
	// the prompt-submit hook lane is the only reason this mechanism
	// exists; Gemini CLI has no other hook this repo captures).
	HookGeminiSettings HookMechanism = "gemini_settings_json"
	// HookQwenSettings (Part B item 1): Qwen Code's ~/.qwen/settings.json
	// "hooks" block — same shape and machinery as HookGeminiSettings,
	// single event (UserPromptSubmit).
	HookQwenSettings HookMechanism = "qwen_settings_json"
	// HookFactoryJSON (Part B item 1): Factory Droid's
	// ~/.factory/hooks.json — the SAME shape as HookCodexConfig's
	// hooks.json (a dedicated {"hooks":{<event>:[{"matcher":…,"hooks":[…]}]}}
	// file, not a shared settings.json), single event (UserPromptSubmit).
	// Reuses codexHooksConfig/readCodexHooks/writeCodexHooks directly.
	HookFactoryJSON HookMechanism = "factory_hooks_json"
	// HookQoderJSON (Part B item 2, phase-3a): Qoder CLI's
	// ~/.qoder/settings.json "hooks" block — byte-identical shape to
	// HookClaudeSettings/HookGeminiSettings/HookQwenSettings, so
	// registration reuses registerGenericSettingsHooks directly.
	HookQoderJSON HookMechanism = "qoder_settings_json"
	// HookPoolsideYAML (Part B item 2, phase-3a): the standalone `pool`
	// CLI's ~/.config/poolside/settings.yaml "hooks" block — a genuinely
	// new FORMAT (YAML, not JSON) for this repo's hook writers, using
	// the internal/hook readYAMLMap/writeYAMLMap helpers already built
	// for Hermes' config.yaml.
	HookPoolsideYAML HookMechanism = "poolside_settings_yaml"
	// HookZcodeJSON (Part B item 2, phase-3a): zcode's
	// ~/.zcode/cli/config.json "hooks.events" block — its own shape,
	// distinct from every other JSON hooks writer. Deliberately never
	// auto-registered (AutoWired:false on the registry row) pending a
	// liveness probe (zai-org/feedback#32) — the receiver exists and is
	// tested, but no `register*` writer function exists for this
	// mechanism at all yet.
	HookZcodeJSON HookMechanism = "zcode_config_json"
	// HookCascadeJSON (Part B item 2, phase-3a): Windsurf/Devin Desktop
	// Cascade's ~/.codeium/windsurf/hooks.json — its OWN shape
	// ({"hooks":{"pre_user_prompt":[{"command":…,"powershell":…}]}}),
	// distinct from every other hooks.json writer (a flat command list,
	// no matcher/type fields, a separate powershell command variant for
	// Windows).
	HookCascadeJSON HookMechanism = "cascade_hooks_json"
	// HookCommandCodeMod (Part B item 2, phase-3a): commandcode's Mods
	// SDK — NOT a shell-hook config file at all. Registration writes a
	// go:embed'd TypeScript module to
	// ~/.commandcode/mods/observer-guard.ts (jiti-compiled at load
	// time, no build step) that shells out to
	// `observer hook command-code transformInput`, mirroring the
	// hermesplugin precedent (an embedded, non-JSON-config bridge) more
	// than any of this repo's other hooks.json/settings.json writers.
	HookCommandCodeMod HookMechanism = "commandcode_mods_ts"
)

// HookSpec describes a tool's hook-registration capability. A zero-value
// HookSpec (Mechanism == HookNone) means watcher/SQLite-only. CrossOSBridge
// records that the tool, when registered from a foreign OS (Windows AI tool
// + WSL daemon), must register a `wsl.exe -d <distro> -- <observer> hook …`
// bridge so the hook executes in the daemon's OS-context (CLAUDE.md hook-
// registration note). It is a CAPABILITY FLAG, not a tool branch.
type HookSpec struct {
	Mechanism     HookMechanism
	CrossOSBridge bool
	// AutoWired is false for a mechanism whose receiver exists but init does
	// not yet register it (cline-cli today). Lets the doctor report "capable
	// but not auto-wired" honestly instead of claiming coverage.
	AutoWired bool
	// PromptLaneOnly is true for a mechanism whose ENTIRE hook surface is
	// the prompt-submit event — the Part B item 1/2 long-tail vendors
	// (Gemini CLI, Qwen Code, Factory Droid, Qoder, Poolside, zcode,
	// Windsurf/Devin Desktop Cascade, commandcode), each registered via a
	// SINGLE event because their tool has no OTHER hook this repo
	// captures (see each mechanism's own doc comment above). false for a
	// mechanism that ALSO carries non-prompt-submit value on its own
	// (Claude Code's 21 lifecycle events, Cursor's 18, Codex's session
	// events) — auto-registering THOSE stays worthwhile even with
	// [guard.prompt] off, since the developer still gets session/tool-call
	// capture out of the same registration.
	//
	// B4 (phase-3a review): autoRegisterHooks (cmd/observer/start.go)
	// gates a PromptLaneOnly mechanism on [guard.prompt].enabled &&
	// hook_lane — writing a vendor config file whose only content is a
	// hook the operator's own config says never to evaluate was dead
	// weight at best and a surprise entry in someone's settings.json at
	// worst. This is a MECHANISM-level flag, not a tool-name list
	// (CLAUDE.md rule 3): a future prompt-submit-only vendor gets the
	// same gate automatically by setting this true on its own row.
	PromptLaneOnly bool
}

// EnforcementChannel classifies HOW an org guard policy can actually STOP a
// dangerous action on this adapter — the honest answer to "what lever does
// enforcement have here?", independent of whether guard is currently in
// enforce mode (that is internal/policy.Mode) and independent of whether the
// lever is available on THIS box right now (see EffectiveEnforcement, which
// degrades EnforceSandbox on a platform without bwrap). Buckets are ordered
// by enforcement strength; the zero value (EnforcementUnknown) is never
// returned by the classifier below — every row lands in exactly one
// non-zero bucket, mirroring the RouteStatus honesty convention.
type EnforcementChannel string

const (
	// EnforcementUnknown: not yet classified. Never produced by
	// (Capability).EnforcementChannel(); reserved for callers that need a
	// zero value before a row is looked up.
	EnforcementUnknown EnforcementChannel = ""
	// EnforceHookBlock: the tool's own hook mechanism supports a genuine
	// blocking reply (a non-zero/deny verdict the vendor's own tool honors
	// BEFORE the dangerous action runs), and observer's receiver is wired to
	// send one. Strongest channel: the action never executes.
	EnforceHookBlock EnforcementChannel = "hook_block"
	// EnforceSandbox: no blocking hook exists (or the mechanism is
	// structurally fire-and-forget/post-hoc), but the tool is launchable via
	// `observer <x>` — so a guard policy in enforce mode can require the
	// launch go through the internal/sandbox bwrap filesystem sandbox
	// (Linux/WSL2 only), containing the blast radius instead of preventing
	// the call. Degrades to EnforceRecordedAcceptance when the platform
	// can't actually provide a sandbox (see EffectiveEnforcement).
	EnforceSandbox EnforcementChannel = "sandbox_enforce"
	// EnforceOrgDisallow: neither a blocking hook nor a launcher exists, but
	// the tool's model traffic is one observer proxy-routes (Proxy != nil)
	// — so the only lever is refusing to route it at all (or the launcher
	// refusing to start it, for the org-disallow node-side honor path).
	EnforceOrgDisallow EnforcementChannel = "org_disallow"
	// EnforceRecordedAcceptance: no grounded lever exists at all (no
	// blocking hook, no launcher, no proxy route) — e.g. the *-web browser-
	// capture rows, or a native/IDE-extension surface observer only
	// observes. The only honest posture is a dated acknowledgment that the
	// org accepted the risk of allowing this tool, surfaced in the matrix.
	EnforceRecordedAcceptance EnforcementChannel = "recorded_acceptance"
)

// blockingHookMechanisms is the grounded set of hook mechanisms verified
// (survey 2026-08-30, grep against internal/hook + each adapter's hook
// receiver) to support a genuine deny reply, i.e. the vendor tool itself
// aborts the dangerous action when observer's hook replies non-approve:
//
//   - HookClaudeSettings: Claude Code PreToolUse — a non-zero exit / deny
//     JSON reply blocks (internal/hook/guarded.go::HandleGuarded, the
//     reference implementation; cmd/observer/hook.go::handleClaudeCodePreTool
//     replies BEFORE the lazy DB persist).
//   - HookCursor: Cursor's parallel guarded path
//     (internal/hook/cursor.go::BuildCursorEvent + HandleCursorEventGuarded).
//
// Every other mechanism was checked and found NOT blocking-capable, each for
// a distinct grounded reason (not merely "not yet wired"):
//
//   - HookCodexConfig: internal/hook/codex.go::HandleCodexEvent replies `{}`
//     on stdout UNCONDITIONALLY and FIRST, before the event is even parsed
//     — genuinely fire-and-forget today. Codex's own PermissionRequest hook
//     class may support a deny in principle, but observer has no vendor-
//     verified reply schema for it (docs/codex-hook-capture.md's
//     capture-first discipline: do not fabricate a schema, prove it live).
//   - HookHermesPlugin: internal/hook/hermesplugin's embedded plugin hard-
//     documents "absent / slow / mis-configured MUST NEVER block the host
//     Hermes" — a design invariant, not an omission.
//   - HookClineCLIJSONL: a post-hoc TAIL of hooks.jsonl, read AFTER the
//     logged action already completed — structurally incapable of blocking.
//   - HookBrowserExtension: the native-messaging chat-capture bridge has no
//     local dangerous-tool-call surface to gate at all.
//
// A future vendor-verified deny schema is the only honest way to grow this
// set — never add a mechanism here without live confirmation.
var blockingHookMechanisms = map[HookMechanism]bool{
	HookClaudeSettings: true,
	HookCursor:         true,
}

// EnforcementChannel returns the grounded bucket for how an org guard policy
// can stop a dangerous action on this adapter, walked as an ordered ladder
// (table-driven, CLAUDE.md rule #5 — not a tool-name switch):
//
//  1. a wired, blocking-capable hook mechanism -> EnforceHookBlock
//  2. else a launchable tool (Handoff.Launch != nil) -> EnforceSandbox
//  3. else a proxy-routable tool (Proxy != nil)      -> EnforceOrgDisallow
//  4. else                                            -> EnforceRecordedAcceptance
//
// This is computed, not stored, so it can never drift from the underlying
// grounded fields (mirrors HandoffCapability.Launchable()'s existing
// computed-property idiom) — a future edit to Hook/Handoff/Proxy
// automatically reclassifies correctly. The registry golden test pins the
// resulting bucket per adapter so a silent reclassification is loud.
func (c Capability) EnforcementChannel() EnforcementChannel {
	if blockingHookMechanisms[c.Hook.Mechanism] {
		return EnforceHookBlock
	}
	if c.Handoff.Launchable() {
		return EnforceSandbox
	}
	if c.Proxy != nil {
		return EnforceOrgDisallow
	}
	return EnforceRecordedAcceptance
}

// EffectiveEnforcement is EnforcementChannel() degraded for the current
// platform: EnforceSandbox is only a real lever where internal/sandbox can
// actually build a bwrap sandbox (Linux/WSL2 with a working userns; see
// sandbox.Probe). sandboxAvailable should come from that probe's Verdict ==
// VerdictAvailable at the call site (cmd/observer). Never upgrades a
// channel, never fails — the honest floor when sandboxing isn't available
// is the same recorded-acceptance posture as a tool with no lever at all.
func (c Capability) EffectiveEnforcement(sandboxAvailable bool) EnforcementChannel {
	ch := c.EnforcementChannel()
	if ch == EnforceSandbox && !sandboxAvailable {
		return EnforceRecordedAcceptance
	}
	return ch
}

// BudgetAdmissionChannel names a pre-model-request enforcement point that can
// enforce an Observer-managed hard budget. It is intentionally separate from
// EnforcementChannel: a blocking tool hook or filesystem sandbox does not
// control provider spend.
type BudgetAdmissionChannel string

const (
	// BudgetAdmissionNone is the safe zero value: Observer has no verified
	// pre-model-request budget blocker for this capability row.
	BudgetAdmissionNone BudgetAdmissionChannel = ""
	// BudgetAdmissionObserverProxy means the tool has a live-verified Proxy
	// route and can be admitted when this invocation proves it uses that route.
	BudgetAdmissionObserverProxy BudgetAdmissionChannel = "observer_proxy"
)

// BudgetAdmissionChannel returns the capability's verified budget enforcement
// point. ProxyProbe, hooks, handoff launchability, and sandboxing are excluded:
// none of them proves that this invocation's model request can be denied for a
// spent budget.
func (c Capability) BudgetAdmissionChannel() BudgetAdmissionChannel {
	if c.Proxy != nil {
		return BudgetAdmissionObserverProxy
	}
	return BudgetAdmissionNone
}

// MCPFormat names the on-disk shape a client uses to store MCP server
// config. Phase 1 reuses ONE writer per format across every client that
// shares it (the agnostic win): the JSON {"mcpServers":{…}} object is
// near-universal; codex and hermes are the two per-vendor exceptions.
type MCPFormat string

const (
	// MCPServersJSON: the shared {"mcpServers": {…}} JSON object used by
	// Claude Code (~/.claude.json) and Cursor (~/.cursor/mcp.json), and the
	// likely shape for several other clients pending Phase-1 confirmation.
	MCPServersJSON MCPFormat = "mcp_servers_json"
	// MCPCodexTOML: Codex's [mcp_servers] table in ~/.codex/config.toml.
	MCPCodexTOML MCPFormat = "codex_config_toml"
	// MCPHermesYAML: Hermes' mcp_servers map in ~/.hermes/config.yaml.
	MCPHermesYAML MCPFormat = "hermes_config_yaml"
	// MCPOpenCodeJSON: OpenCode's own "mcp" object in
	// ~/.config/opencode/opencode.json — typed local-command servers
	// ({"type":"local","command":[…],"enabled":true}), NOT the shared
	// {"mcpServers":{…}} shape. Has its own writer (registerOpenCodeJSON).
	MCPOpenCodeJSON MCPFormat = "opencode_json"
)

// MCPTarget records where/how a client stores MCP server config. A nil
// *MCPTarget on a Capability means "no grounded MCP target" (the client
// has no MCP support, OR support is unconfirmed pending Phase-1 discovery —
// see the per-adapter registry comment). Implemented distinguishes the
// clients observer can write TODAY (a registrar/init writer exists) from
// any future Phase-1 candidate added as a data row before its writer.
type MCPTarget struct {
	Format MCPFormat
	// PathHint documents the config location relative to the user's home
	// (e.g. ".claude.json", ".cursor/mcp.json") for the doctor/matrix; the
	// authoritative path resolution stays in internal/mcp/locate.
	PathHint string
	// Implemented is true when init/the MCP registrar can write this target
	// now (claude-code, cursor, codex, hermes). false marks a client we
	// have grounded as MCP-capable but not yet wired a writer for.
	Implemented bool
	// CrossOSBridge marks a client whose MCP config can ALSO be written from
	// a foreign-OS daemon via a `wsl.exe -d <distro> -- <linux-bin>` bridge
	// command (mirrors HookSpec.CrossOSBridge). When true, the `<tool>-
	// windows` virtual target resolves the Windows-side config path through
	// crossmount and writes the bridge command, so a Windows VS Code client
	// (e.g. Cline) can reach a WSL-resident observer MCP server over stdio.
	// A capability FLAG, not a tool branch (CLAUDE.md #3).
	CrossOSBridge bool
}

// NativeRails is the three-rail native-console telemetry bitset
// (docs/native-console-integration-template.md). Most adapters are small
// vendors with no admin/usage API → every field false (enrollment-only,
// correct, not a hole). Phase 4 keeps this as a LEDGER only; no new vendor
// poller is built this work-stream (operator decision 2026-06-26).
type NativeRails struct {
	// A = native node telemetry (usage-export / OTel).
	A bool
	// B = managed-config distribution (managed-settings / MDM).
	B bool
	// C = org analytics API (server-side poller).
	C bool
	// Note documents gating/partial status (e.g. codex Rail A config-gated,
	// copilot rails partial).
	Note string
}

// Any reports whether at least one native-console rail exists for the tool.
func (n NativeRails) Any() bool { return n.A || n.B || n.C }

// TranscriptTier records whether a completed session's full message
// content is re-readable from the tool's own on-disk files at handoff
// time — the session-handoff Phase 0 P0.1 classification
// (docs/plans/session-handoff-phase0-findings-2026-07-03.md), live-
// grounded 2026-07-03 on a 328-session corpus. The zero value is the
// honest floor: action-derived facts only.
type TranscriptTier string

const (
	// TranscriptActionsOnly: no grounded full-content transcript — the
	// handoff degrades to the metadata carry mode. Zero value.
	TranscriptActionsOnly TranscriptTier = ""
	// TranscriptPartial: content exists on disk but needs work or gating
	// to reconstruct (copilot's patch-log replay; antigravity's
	// CLI-readable / desktop-encrypted split).
	TranscriptPartial TranscriptTier = "partial"
	// TranscriptFull: the full message stream is re-readable now.
	TranscriptFull TranscriptTier = "full"
)

// InjectKind names a handoff delivery lane (plan §10). Dispatch is on
// this shape, never on tool name.
type InjectKind string

const (
	// InjectFile writes HANDOFF-<shortid>.md at the project root — the
	// universal floor every adapter supports.
	InjectFile InjectKind = "file"
	// InjectMCP serves the handover through the continue_session MCP tool
	// (P2; requires an Implemented MCP target).
	InjectMCP InjectKind = "mcp"
	// InjectHook arms a SessionStart additionalContext delivery (P3;
	// hook-lane budget 8KB per Phase 0 D-P0.2).
	InjectHook InjectKind = "hook"
	// InjectPrompt prepends the handover via the tool's `observer <x>`
	// launcher (P3).
	InjectPrompt InjectKind = "prompt"
)

// LaunchMode names HOW a launchable tool receives the handover when started
// in the embedded web terminal. It is a capability of the tool's CLI, not a
// tool-name branch (CLAUDE.md #3).
type LaunchMode int

const (
	// LaunchSeeded (zero value): the launcher injects the handover as the
	// tool's first interactive prompt via its promptInjection descriptor
	// (leading/trailing positional or a flag value). Requires the tool to
	// declare the InjectPrompt lane. The common case — every tool with a
	// grounded interactive-seed contract.
	LaunchSeeded LaunchMode = iota
	// LaunchDocAssisted: the tool's interactive TUI has NO initial-prompt
	// seed (e.g. hermes' `--tui` takes no message — an upstream gap), so the
	// launcher writes the handover doc (file lane) + prints a pointer, then
	// opens the interactive TUI for the user to reference/paste. An honest
	// fallback for TUIs that cannot be auto-seeded; it does NOT declare the
	// InjectPrompt lane (nothing is injected).
	LaunchDocAssisted
)

// LaunchSpec declares that a tool can be started IN-PROCESS from the
// dashboard's embedded web terminal (docs/session-handoff.md launch
// section). Subcommand is the `observer <x>` launcher verb the dashboard
// spawns in a PTY with `--continue-from <id>` — the launcher's stdio is
// wired to the PTY so the tool renders straight into the browser. It is
// present ONLY for tools whose launcher has a grounded, verified continue
// contract (a Seeded interactive-prompt seed, OR a DocAssisted TUI open); a
// non-nil Launch is the single capability the dashboard dispatches on
// (CLAUDE.md #3 — never a tool-name branch). A nil *LaunchSpec means "not
// launchable in-terminal" (the honest floor: the tool can still be handed
// off via file/MCP/hook).
type LaunchSpec struct {
	// Subcommand is the observer launcher verb (e.g. "claude", "codex",
	// "gemini", "pi"). It must match cmd/observer's continueFromLauncher
	// wiring — the registry_coverage_test pins the two can never drift.
	Subcommand string
	// Mode is how the handover reaches the launched tool. Zero value =
	// LaunchSeeded (prompt injection). LaunchDocAssisted marks a tool whose
	// TUI cannot be auto-seeded (doc written + TUI opened).
	Mode LaunchMode
}

// HandoffCapability is an adapter's session-handoff row: transcript
// readability plus the delivery lanes grounded for it. A zero value means
// actions-only carry with file delivery (the floor), never a fabricated
// capability.
type HandoffCapability struct {
	Transcript TranscriptTier
	Inject     []InjectKind
	// Launch, when non-nil, declares the tool is startable in the
	// dashboard's embedded web terminal (a LaunchSpec carrying the
	// `observer <x>` launcher verb). Nil = not launchable in-terminal.
	// Populated only for launchers with a verified --continue-from
	// contract (claude-code, codex, gemini-cli, pi).
	Launch *LaunchSpec
	// Note documents gating/partial status.
	Note string
}

// Launchable reports whether the tool can be started in the dashboard's
// embedded web terminal (a grounded LaunchSpec is present). Dashboard and
// coverage tests dispatch on this shape, never on tool name.
func (h HandoffCapability) Launchable() bool { return h.Launch != nil }

// Lanes returns the grounded delivery lanes, always including the
// universal file lane.
func (h HandoffCapability) Lanes() []InjectKind {
	for _, k := range h.Inject {
		if k == InjectFile {
			return h.Inject
		}
	}
	return append([]InjectKind{InjectFile}, h.Inject...)
}

// TokenTier records the best available token/cost capture tier for a tool
// plus any honest known gap. It is the ledger Phase 5 measures shrinkage
// against; the cost ENGINE (cost.ComputeBreakdown) is already agnostic, so
// only this capture/parse layer is per-adapter.
type TokenTier struct {
	// Best names the strongest capture source: "proxy" (api_turns wall-clock
	// + exact usage), "debug_log", "events_jsonl", "sqlite", "transcript",
	// "proto" (decrypt-gated). "none" = AUDITED and no local token source
	// exists (e.g. qoder's server-side-only usage — distinct from "",
	// which means the audit itself hasn't happened).
	Best string
	// Gap is a short honest description of a known hole ("" = no known gap):
	// e.g. "no cache tier", "model often blank", "decrypt-gated",
	// "sparse task tokens", "OpenAI-gross net-vs-cached fix pending".
	Gap string
}

// AttachSpec declares that `observer <Subcommand> --attach` can hand the
// tool's PTY to the daemon so a second seat (the dashboard) can view and
// drive the SAME live session (session-attach design §2.3, T2). A non-nil
// *AttachSpec means "attachable"; a nil value is the honest floor: the tool
// can only be launched bare, which is not retrofittable onto an already-
// running child. Subcommand MUST match a wired `observer <x>` launcher —
// the registry_coverage_test pins that an Attach row is also Launchable,
// and the cmd-side sync test pins the verb against the actual launcher.
// This mirrors HandoffCapability.Launch *LaunchSpec: a single capability
// the attach policy / dashboard "Jump in" affordance dispatch on by SHAPE
// (non-nil), never on tool name (CLAUDE.md #3).
type AttachSpec struct {
	// Subcommand is the observer launcher verb the daemon spawns in an
	// attachable PTY (e.g. "claude", "codex"). It must match cmd/observer's
	// launcher wiring.
	Subcommand string
}

// ResumeKind names HOW a CLOSED session is reopened (session-attach design
// §2.3, T3). Consumers dispatch on this shape, never on tool name.
type ResumeKind string

const (
	// ResumeNone (zero value): no grounded native-resume contract. The
	// honest floor — a closed session on such a tool falls back to the
	// shipped handoff-fork resume (`--continue-from`) when the tool is
	// launchable, or shows a disabled Resume affordance otherwise.
	ResumeNone ResumeKind = ""
	// ResumeNative: the tool reopens its ACTUAL prior conversation via its
	// own resume mechanism (claude `--resume <id>`, codex `resume <id>`),
	// reattaching the real transcript — NOT a distilled fork. Declared ONLY
	// after the native-resume argv is verified live (the grounding rule,
	// mirroring how LaunchSpec was populated incrementally).
	ResumeNative ResumeKind = "native"
	// ResumeFork: the distilled handoff-fork resume (`--continue-from`),
	// already shipped. It creates a NEW session seeded from a priced
	// handover doc — the honest fallback for tools with no native resume.
	ResumeFork ResumeKind = "handoff"
)

// HeadlessResultKind names WHERE a headless one-shot run's final answer
// lands, so the arena runner extracts it without branching on tool identity.
type HeadlessResultKind string

const (
	// HeadlessResultNone (zero value): no grounded extraction contract.
	HeadlessResultNone HeadlessResultKind = ""
	// HeadlessResultStdoutJSON: the tool prints a machine-readable JSON
	// envelope on stdout whose shape the runner parses (claude-code's
	// `--output-format json` result object).
	HeadlessResultStdoutJSON HeadlessResultKind = "stdout_json"
	// HeadlessResultOutputFile: the tool writes its final message to a file
	// named by an -o-style flag (codex exec's `-o <file>`).
	HeadlessResultOutputFile HeadlessResultKind = "output_file"
	// HeadlessResultGrokJSON: grok's `-p … --output-format json` prints a
	// single JSON object keyed text/sessionId/usage/total_cost_usd —
	// claude-shaped but with different keys (live-verified 2026-08-22).
	HeadlessResultGrokJSON HeadlessResultKind = "grok_json"
	// HeadlessResultOpenCodeEvents: opencode run --format json streams
	// NDJSON events (step_start/text/step_finish), each carrying sessionID;
	// the final answer is the last `text` part (live-verified 2026-08-22).
	HeadlessResultOpenCodeEvents HeadlessResultKind = "opencode_events"
	// HeadlessResultStdoutText: the tool's stdout IS the answer channel —
	// plain text, no envelope (aider --message; live-verified 2026-08-22).
	HeadlessResultStdoutText HeadlessResultKind = "stdout_text"
)

// HeadlessContextMode declares how a headless harness receives operator-
// selected project files as explicit argv context. The zero value means the
// harness discovers files from the prompt/workspace without extra arguments.
type HeadlessContextMode string

const (
	// HeadlessContextNone leaves context-file argv untouched.
	HeadlessContextNone HeadlessContextMode = ""
	// HeadlessContextPositional appends project-relative context files as bare
	// positional arguments (aider's `aider [files...] --message ...` contract).
	HeadlessContextPositional HeadlessContextMode = "positional"
)

// HeadlessSpec declares that a tool has a GROUNDED headless one-shot form:
// prompt in on argv, final answer out somewhere parseable, no interactive
// TUI involved. It is the capability the Agent Arena dispatches on (plan:
// docs/plans/agent-arena-terminal-multi-harness-2026-08-22.md §3). A nil
// Headless means "no live-verified one-shot contract" — the honest floor;
// rows are populated only after a real drive proves the argv (same
// grounding rule as LaunchSpec). Composition is declarative so the runner
// builds exact args without a tool-name branch (CLAUDE.md #3).
type HeadlessSpec struct {
	// Lead is the leading argv tokens before the prompt, typically a
	// subcommand (codex: ["exec"]). Usually nil.
	Lead []string
	// PromptFlag is the flag that introduces the prompt value ("-p" for
	// claude-code); empty when the prompt is a bare positional after Lead.
	PromptFlag string
	// OutputArgs are extra argv required for machine-readable output
	// (claude-code: ["--output-format", "json"]).
	OutputArgs []string
	// Result names where the final answer is extracted from.
	Result HeadlessResultKind
	// ResultFlag is the flag naming the output file when Result ==
	// HeadlessResultOutputFile ("-o" for codex).
	ResultFlag string
	// ContextMode declares how optional run-level context files land on argv.
	// Only live-grounded modes are populated; zero means no explicit delivery.
	ContextMode HeadlessContextMode
	// ProxyModelPrefix constrains model selection when the arena supplies a
	// proxy URL. Some tools expose both a proprietary hosted provider and an
	// OpenAI-compatible provider, while their base-URL env only affects the
	// latter (OpenCode: OPENAI_BASE_URL applies to openai/*). Empty means the
	// proxy route is provider-agnostic.
	ProxyModelPrefix string
	// ProxyDefaultModel is selected when ProxyModelPrefix is non-empty and the
	// operator leaves the candidate model blank. It must include that prefix
	// and must be grounded by a live routed drive.
	ProxyDefaultModel string
}

// ResumeSpec declares the native-resume contract for a tool. It is
// meaningful only when Kind == ResumeNative; a zero value (Kind ==
// ResumeNone) means "no grounded native resume" — never a fabricated
// capability. It mirrors the LaunchSpec descriptor discipline: the
// launcher verb plus how the prior session id is passed on the command
// line, so the resume-command composer at the boundary builds the exact
// argv without a tool-name branch (CLAUDE.md #3).
type ResumeSpec struct {
	// Kind names the resume mechanism (native / fork / none).
	Kind ResumeKind
	// Subcommand is the observer launcher verb that carries native resume
	// (e.g. "claude", "codex"). Non-empty when Kind == ResumeNative.
	Subcommand string
	// IDMechanism names how the prior session id is passed, from a fixed
	// vocabulary: "flag:--resume" | "positional" | "subcommand:resume" | "".
	// Non-empty when Kind == ResumeNative.
	IDMechanism string
}

// ModelKind names HOW a model is selected at fresh-launch time (the
// dashboard New Terminal model picker, B5). Consumers dispatch on this
// shape, never on tool name (CLAUDE.md #3).
type ModelKind string

const (
	// ModelNone (zero value): no grounded seed-time model-selection
	// mechanism. The honest floor — never a fabricated capability; a tool
	// with ModelNone gets no picker.
	ModelNone ModelKind = ""
	// ModelArg: the model is delivered as an argv token appended to the
	// observer launcher's args — Lead... (if any) + Flag + value — which
	// the launcher's B6 flag-passthrough (DisableFlagParsing +
	// launcherArgsOrDone) forwards to the wrapped tool unmodified.
	ModelArg ModelKind = "arg"
	// ModelEnv: the model is delivered as EnvVar=value in the child
	// process environment, for tools whose model selection has no argv
	// flag reachable from the launcher's default (interactive) entry
	// point.
	ModelEnv ModelKind = "env"
)

// ModelSpec declares the seed-time model-selection contract for a tool. It
// is meaningful only when Kind != ModelNone; a zero value (Kind ==
// ModelNone) means "no grounded seed-time model mechanism" — never a
// fabricated capability. It mirrors the ResumeSpec descriptor discipline:
// grounded delivery data, not a tool-name branch, so the boundary composer
// (ModelLaunch) builds the exact args/env without consumers ever switching
// on tool identity (CLAUDE.md #3).
type ModelSpec struct {
	// Kind names the delivery mechanism (arg / env / none).
	Kind ModelKind
	// Flag is the argv flag used when Kind == ModelArg (almost always
	// "--model"; ModelLaunch defaults to "--model" when empty).
	Flag string
	// Lead is leading argv tokens required before Flag, e.g. kiro-cli's
	// ["chat"] (its --model flag exists only on the chat subcommand).
	// Usually nil. Meaningful for both ModelArg and ModelEnv (a tool may
	// need a leading subcommand even when the model rides in the
	// environment).
	Lead []string
	// EnvVar is the environment variable name used when Kind == ModelEnv
	// (e.g. "GOOSE_MODEL"). Non-empty when Kind == ModelEnv.
	EnvVar string
	// Known lists grounded known-good model values (from --help examples
	// or docs) offered in addition to local history in the picker. May be
	// empty — an empty Known list is honest when no example was grounded,
	// never a reason to fabricate one.
	Known []string
}

// BinaryNames lists the executable spellings a launcher looks for, split by
// host OS. Unix carries the plain binary name(s) resolved on a Linux/macOS
// PATH (usually one, e.g. "claude"); Windows carries the LAUNCHABLE shim
// spellings an npm-style install lays down, in PATHEXT-resolution order
// (`x.exe`/`x.cmd`/`x`). A `.ps1` is intentionally NOT listed: it cannot be
// launched by exec.Command / CreateProcess (a PowerShell script is not an
// executable image), so it is not a candidate. A nil/empty Windows slice is
// the honest floor: "no grounded Windows
// spelling" — it does NOT mean the tool is Linux-only, only that we have not
// confirmed how it installs on Windows, so the cross-OS resolver has nothing
// to try. Unix is required for every launchable tool (pinned by the coverage
// test); a zero-value BinaryNames carries no grounded resolution.
type BinaryNames struct {
	Unix    []string
	Windows []string
}

// ProbeOS names which host OS a ProbeDir applies to — the resolver only walks
// a probe dir whose OS matches the home it is scanning (a native probe dir on
// the daemon OS, or a foreign Windows home reached over crossmount).
type ProbeOS string

const (
	// ProbeUnix: the dir is HOME-relative under a Linux/macOS home.
	ProbeUnix ProbeOS = "unix"
	// ProbeWindows: the dir is HOME-relative under a Windows user profile
	// (reached over crossmount from a WSL daemon, or native on a Windows
	// daemon).
	ProbeWindows ProbeOS = "windows"
	// ProbeDarwin: the dir belongs under a macOS home (or, with Abs, at a
	// macOS absolute location such as /Applications). A darwin daemon walks
	// BOTH ProbeUnix and ProbeDarwin dirs — the former is the shared
	// Unix-flavored table, the latter the macOS-only extras (app bundles,
	// ~/Applications) that would be dead weight on Linux. Added for the GUI
	// launch rows (docs/plans/ide-desktop-launch-plan-2026-09-03.md §2.3).
	ProbeDarwin ProbeOS = "darwin"
)

// ProbeDir is a single per-tool EXTRA directory the resolver scans for the
// tool's binary when it is not first on PATH. Rel is HOME-RELATIVE (never
// absolute) and may contain ONE `*` glob segment (e.g.
// ".local/share/cursor-agent/versions/*") which the resolver expands. OS
// gates which home the dir belongs under. The zero value carries no probe
// dir.
type ProbeDir struct {
	OS  ProbeOS
	Rel string
	// EnvRoot, when non-empty, names an environment variable whose value
	// replaces HOME as the root of Rel (e.g. "ProgramFiles" for a probe dir
	// under %ProgramFiles%, rather than the user's home). Empty means
	// HOME-relative (the common case). The resolver skips the dir entirely
	// when the named variable is unset — a Windows-only concept in practice
	// (grounded 2026-09-02: kiro-cli's installer prints an install location
	// under Program Files that the MSI's own Directory table contradicts —
	// probing both honestly needs a non-HOME root on one of the two dirs).
	EnvRoot string
	// Abs marks Rel as an ABSOLUTE path the resolver walks verbatim — no HOME
	// join, no EnvRoot expansion (e.g.
	// "/Applications/Visual Studio Code.app/Contents/MacOS" for a macOS GUI
	// row). It is mutually exclusive with EnvRoot; when both are set Abs wins
	// and EnvRoot is ignored. The zero value keeps the HOME-relative default
	// every existing row relies on.
	Abs bool
}

// InstallHint is a single grounded, one-click install command for a tool on a
// given OS + channel. Argv is a COMPILE-TIME CONSTANT the dashboard install
// endpoint spawns VERBATIM in a visible PTY — it is NEVER interpolated with
// request data (the request contributes only a registry map key; argv
// injection surface is zero by construction). Display is the human-readable
// command surfaced to the operator PRE-CONSENT (shown before the click that
// runs Argv); it is prose for the doctor/dashboard, not what is executed.
//
// The honesty rule is strict (operator directive, 2026-07-23): a tool ships
// an InstallHint ONLY when its official install channel has been grounded. A
// tool with no grounded channel carries an EMPTY Installs slice — the
// doctor/dashboard then render "no grounded install command — see vendor
// docs", never a fabricated command.
type InstallHint struct {
	// OS scopes the hint: "linux" | "darwin" | "windows" | "" (any OS).
	OS string
	// Channel names the install method, a CLOSED vocabulary (pinned by
	// TestInstallHintChannelIsClosedVocabulary): "npm" | "script" | "brew" |
	// "winget" | "uv" | "scoop". "choco" is deliberately NOT in the
	// vocabulary — the one candidate row found (opencode) is a stale
	// third-party publish (0.11.1 vs. npm's 1.18.26), so it was never
	// adopted (2026-09-02 research).
	Channel string
	// Argv is the compile-time-constant command spawned verbatim (never
	// interpolated with request data).
	Argv []string
	// Display is the human-readable command surfaced pre-consent.
	Display string
}

// BinaryResolveSpec is a tool's grounded binary-resolution row: the executable
// spellings to look for, the per-tool EXTRA probe dirs to scan, and the
// grounded install hints. A nil *BinaryResolveSpec on a Capability means "no
// grounded resolution row" (the honest floor); a non-nil spec always carries
// at least Names.Unix (pinned by the coverage test).
//
// COMMON probe dirs are NOT listed here: the ~/.local/bin, npm/volta/pnpm/bun
// prefixes, and nvm/node version dirs shared across tools live in
// internal/toolresolve, walked for every tool. ProbeDirs on this spec carries
// ONLY the per-tool EXTRAS (e.g. cursor's versions/* dir, hermes' .hermes/bin)
// that the common ladder would miss.
type BinaryResolveSpec struct {
	Names     BinaryNames
	ProbeDirs []ProbeDir
	Installs  []InstallHint
	// WindowsNote is the honest-zero carrier for Names.Windows: REQUIRED
	// (non-empty) whenever Names.Windows is empty on a launchable row — it
	// states the grounded REASON there is no Windows spelling (e.g. muse:
	// no Windows build exists per the vendor), never a placeholder. Rendered
	// by the dashboard install_note surface and `observer doctor`
	// (2026-09-02 dashboard-install-gap-remediation research, §1.7).
	WindowsNote string
	// InstallNote is the honest-zero carrier for Installs: REQUIRED
	// (non-empty) whenever no InstallHint in Installs matches an OS the
	// tool is launchable on (an empty Installs slice, or one that only
	// covers a subset of OSes) — it states the grounded reason (e.g.
	// zcode: desktop-installer-only, no CLI channel exists). Never
	// fabricates a channel to fill the gap. Rendered alongside
	// WindowsNote.
	InstallNote string
}

// Vocabulary is an adapter's NATIVE TOOL VOCABULARY row: whether the
// canonical cross-adapter taxonomy table (internal/tooltax) carries
// tool-specific rows for this adapter, so the raw tool names it captures
// resolve to a canonical action type + category instead of falling into
// `unknown`. It is the WP-T3 teeth of
// docs/plans/tool-taxonomy-standardization-plan-2026-07-31.md: the same
// enforcement that pins Binary / Handoff / Routability today, applied to
// the taxonomy.
//
// It is DECLARED here and CROSS-CHECKED against the real table by
// TestVocabularyDeclaredForEveryAdapter (registry_coverage_test.go, which
// lives in the external test package and can therefore import both).
// Declaring rather than computing is deliberate on two counts: the
// registry is the ONE place a new adapter is forced to state its
// cross-cutting capabilities, and the pure integration package keeps its
// stdlib-only import set (no dependency on tooltax).
//
// Honesty rule, same as every other cell: the ZERO value is "not
// declared" and FAILS the coverage test. A row says exactly one of two
// things:
//
//   - InTaxonomy true — internal/tooltax carries rows for this tool. The
//     test verifies the rows actually exist, so a new adapter that adds a
//     registry row without adding its native names to the table goes red.
//   - InTaxonomy false WITH a non-empty Note — the adapter's capture
//     genuinely has NO native tool names to canonicalize. The five
//     browser-chat `*-web` rows are this case: the MV3 extension captures
//     prompt/answer turns out of a chat UI, never tool calls, so there is
//     no vocabulary and fabricating one would be a lie. The test verifies
//     tooltax carries no rows for such a tool either.
type Vocabulary struct {
	// InTaxonomy is true when internal/tooltax carries tool-specific rows
	// for this adapter's native tool names.
	InTaxonomy bool
	// Note documents an honest zero (why this adapter has no native tool
	// vocabulary at all) or a partial-coverage caveat. REQUIRED when
	// InTaxonomy is false; optional otherwise.
	Note string
}

// SandboxSpec declares the HOME-RELATIVE state a tool needs at its REAL
// path inside a filesystem sandbox (B9 sandboxed terminals,
// docs/plans/b9-sandboxed-terminals-implementation-plan-2026-08-08.md §2).
// The sandbox tmpfs-blinds the user's home and punches back exactly this
// state, nothing else — auth, config and transcripts stay writable while
// every other tool's credentials and every other repo stay hidden. Every
// entry is HOME-RELATIVE (never absolute) and is validated well-formed by
// TestSandboxPathsWellFormed (registry_coverage_test.go): no absolute path,
// no `..` segment, no leading `-`, no NUL/whitespace/control byte, and
// never `.` or `""`.
//
// The zero value (StateRW, StateRO and Note all empty) means "no grounded
// sandbox row" — the tool is NOT sandbox-launchable. That is a valid final
// answer for a launchable tool ONLY when Note explains the honest zero
// (TestSandboxDeclaredForEveryLaunchableAdapter enforces this); it is never
// silently left blank. v1 grounds only claude-code (plan amendment A3); all
// other launchable tools carry the Note fallback until a per-tool probe
// grounds their state-dir list (ledger G21).
type SandboxSpec struct {
	// StateRW lists dirs/files the tool must WRITE at runtime: auth,
	// config, transcripts. Bound rw (bind-try) inside the sandbox.
	StateRW []string
	// StateRO lists dirs the tool only READS: versioned installs, shared
	// caches. Bound read-only (ro-bind-try) inside the sandbox.
	StateRO []string
	// Note is REQUIRED when both StateRW and StateRO are empty (the
	// honest zero) — it must say why the row is unmapped, never left
	// silently blank.
	Note string
}

// Declared reports whether the vocabulary cell has been filled in at all.
// A row that is neither in the taxonomy nor carries an honest-zero note is
// undeclared, which is the state registry_coverage_test.go rejects.
//
// Declared() deliberately accepts ANY non-empty Note — a data type cannot
// judge whether a sentence is true. The truth of an honest zero is checked
// where the evidence lives, against the adapter's SOURCE:
// TestHonestZeroVocabularyHasNoClassifier walks the adapter package and
// fails the row if it ships a name-based action classifier after all. Do
// not try to move that judgement in here.
func (v Vocabulary) Declared() bool { return v.InTaxonomy || v.Note != "" }

// PromptLane names the prompt-submit intervention mechanism a tool
// speaks (docs/plans/prompt-submit-intervention-exploration-2026-09-07.md
// Part B) — a MECHANISM-shaped field, never a tool-name branch
// (CLAUDE.md rule 3): `observer doctor`/`observer adapters`/init all
// dispatch on this, not on the tool string. The zero value
// (PromptLaneNone, "") is the honest default for the ~30 rows with no
// grounded prompt-submit capability at all (no hook, or a hook that
// carries no documented deny semantics) — most adapters, not a hole.
type PromptLane string

const (
	// PromptLaneNone: no grounded prompt-submit intervention capability
	// (no hook event, or one with no documented block/deny semantics).
	// Zero value.
	PromptLaneNone PromptLane = ""
	// PromptLaneHook: a VERIFIED hook dialect exists and
	// internal/hook/promptsubmit.go has a wired builder for it — see
	// the matching internal/guard/conformance.go row (CanBlock: true)
	// for the exact capabilities.
	PromptLaneHook PromptLane = "hook"
	// PromptLaneProxyOnly: no prompt-submit hook exists, but the tool
	// is already proxy-routed (Capability.Proxy != nil), so the PROXY
	// LANE (internal/guard/proxyguard.go's scanPrompt, composed onto
	// the real request path by cmd/observer/guardwire.go +
	// cmd/observer/proxy.go — built and wired, not a future phase) is
	// this tool's only path to prompt-submit intervention.
	PromptLaneProxyOnly PromptLane = "proxy_only"
	// PromptLaneProbeRequired: the vendor's own docs describe a
	// prompt-submit block mechanism, but the exact wire shape is
	// UNVERIFIED or contested by the vendor's own issue tracker — a
	// conformance row exists with zero Capabilities (or, where the
	// vendor's lack of a message channel is itself documented,
	// CanAsk:false) rather than a guessed payload. `observer doctor
	// --probe-hook` is what promotes this to PromptLaneHook.
	PromptLaneProbeRequired PromptLane = "probe_required"
	// PromptLaneDocumented existed briefly (FIX-7, phase-2 review) for
	// a vendor whose docs fully described the prompt-submit wire shape
	// but Observer had not yet built a dialect builder/receiver for it.
	// REMOVED (F9, phase-3a review): Part B item 2 (phase-3a,
	// 2026-09-07) built and tested dialects/receivers for every vendor
	// that constant covered (Qoder, Poolside, zcode, commandcode,
	// Devin) and promoted all five to PromptLaneHook — real
	// conformance rows now exist for each (internal/guard/
	// conformance.go). No registry row ever set this value again after
	// that promotion, so it was dead vocabulary: declared, with one
	// unreachable switch case (cmd/observer/adapters.go's promptCell),
	// and the test asserting that case's output
	// (TestRenderAdapterMatrixCoversEveryAdapter) was actually passing
	// on an unrelated coincidental substring match, not a live render
	// of this case at all. zcode's own remaining "not auto-wired"
	// nuance (a tested receiver with no registration writer, pending
	// the zai-org/feedback#32 liveness question) is fully and
	// correctly represented today by Hook.AutoWired:false alone — see
	// HookZcodeJSON's own row and cmd/observer/adapters.go's hookCell
	// ("+manual" suffix) / `observer guard prompt status` / runProbeHook,
	// all three of which already read Hook.AutoWired directly as their
	// one shared source of truth. Introducing a second field that must
	// be kept in sync with Hook.AutoWired==false would have been a NEW
	// drift risk, not a fix.
)
