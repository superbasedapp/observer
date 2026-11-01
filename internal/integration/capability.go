package integration

import "github.com/marmutapp/superbased-observer/internal/platform/winshim"

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
	// HookAntigravityJSON (audit P1, 2026-10-02): Antigravity CLI's
	// ~/.gemini/config/hooks.json, a map of hook NAME -> event lists
	// (antigravity.google/docs/hooks). Observer owns one hook name and
	// registers PreToolUse (the tool gate) and PreInvocation, a
	// pre-model-call prompt seam: agy hooks never receive the prompt text,
	// so the receiver reads it from the transcript, warns the developer and
	// can abort the turn before the main model call (HookSpec.PromptWarnOnly
	// records that the prompt has already left the machine by then).
	HookAntigravityJSON HookMechanism = "antigravity_hooks_json"
	// The hook-parity Lane A6 tool-gate mechanisms (2026-10-03), one per
	// vendor config FORMAT. Each registers the vendor's pre-tool event only
	// (internal/hook register_jsonhooks.go / register_vibe_cline.go):
	//
	//   - HookGrokHooksJSON: Grok Build loads every ~/.grok/hooks/*.json;
	//     Observer owns superbased-observer.json there.
	//   - HookCopilotCLIHooks: Copilot CLI loads every ~/.copilot/hooks/*.json
	//     (version 1, flat preToolUse handlers whose command is "bash").
	//   - HookVibeHooksTOML: Mistral vibe's ~/.vibe/hooks.toml [[hooks]].
	//   - HookGoosePlugin: Goose's Open Plugins directory
	//     ~/.agents/plugins/superbased-observer (plugin.json + hooks/hooks.json).
	//   - HookClineHookFiles: the Cline SDK's file-per-event hooks directory
	//     (~/.cline/hooks/PreToolUse, an executable).
	//   - HookJunieConfig: the "hooks" key of Junie CLI's ~/.junie/config.json.
	//   - HookCrushJSON: the "hooks" key of ~/.config/crush/crush.json.
	//   - HookOpenInterpreterHooks: Open Interpreter's Codex-shaped
	//     ~/.openinterpreter/hooks.json.
	HookGrokHooksJSON        HookMechanism = "grok_hooks_json"
	HookCopilotCLIHooks      HookMechanism = "copilot_cli_hooks_json"
	HookVibeHooksTOML        HookMechanism = "vibe_hooks_toml"
	HookGoosePlugin          HookMechanism = "goose_open_plugin"
	HookClineHookFiles       HookMechanism = "cline_hook_files"
	HookJunieConfig          HookMechanism = "junie_config_json"
	HookCrushJSON            HookMechanism = "crush_json"
	HookOpenInterpreterHooks HookMechanism = "open_interpreter_hooks_json"
	// HookMuseSettings (T-479, 2026-10-06): the "hooks" key of Muse Code's
	// user settings, ~/.config/muse/settings.json (Claude-shaped matcher
	// groups beside "schema_version": 1). Muse 1.4.3 on demo node 1 ran a
	// hook from that block with no trust step; it refuses a flat array
	// ("hooks must be an object") and ignores an untrusted project's
	// .muse/hooks.json.
	HookMuseSettings HookMechanism = "muse_settings_json"
	// HookKimiCodeTOML (T-378, 2026-10-07): the [[hooks]] array of tables in
	// Kimi Code's ~/.kimi-code/config.toml ($KIMI_CODE_HOME/config.toml),
	// {event, matcher, command, timeout} per table (any other field fails
	// the vendor's load). The same file can hold a plaintext provider
	// api_key, so the writer runs under the D-268 / D-270 credential-file
	// exception: it edits only Observer's own [[hooks]] tables, line by
	// line, and never reads a value out of the file.
	HookKimiCodeTOML HookMechanism = "kimi_code_config_toml"
	// HookKiroAgentJSON (guard-enforcement fix gfiD, 2026-10-15): Kiro
	// CLI 2.x reads hooks ONLY from the "hooks" object of the agent in use
	// (~/.kiro/agents/<name>.json; camelCase events, flat {command,
	// matcher?, timeout_ms} entries). Observer writes its own agent
	// ~/.kiro/agents/superbased-observer.json, makes it chat.defaultAgent
	// in ~/.kiro/settings/cli.json only when no default is set, merges the
	// same entries into every other global agent JSON, and writes the CLI
	// V3 standalone ~/.kiro/hooks/superbased-observer.json (PascalCase
	// triggers) that 2.28 does not read yet. The V3 file invokes Observer
	// with the PascalCase event, which the receiver folds onto the
	// binding's camelCase native event.
	HookKiroAgentJSON HookMechanism = "kiro_agent_json"
	// HookPluginShimTS (hook-parity Lane D, 2026-10-03): the ONE embedded
	// TypeScript plugin shim (internal/hook/pluginshim) placed into an
	// in-process plugin host's plugin directory (OpenCode, Kilo CLI, pi;
	// OpenClaw and DeepSeek Harness render the same shim but have no
	// grounded install location). The shim forwards the subscribed events
	// (this row's Registered bindings) to `observer hook <tool> <event>` in
	// the plugin dialect and maps the reply onto the host's own contract.
	HookPluginShimTS HookMechanism = "plugin_shim_ts"
	// The 2026-10-21 wave writers (internal/hook register_wave1021.go), one
	// per vendor config FORMAT, each grounded by a live hook probe on WSL
	// Ubuntu and Windows 11 (docs/guard.md "Live grounding: 2026-10-21
	// wave"):
	//
	//   - HookIBMBobSettings: the "hooks" key of IBM Bob's user settings,
	//     ~/.bob/settings/settings.json (Claude-shaped matcher groups; user
	//     hooks need no folder trust; disableGlobalHooks is honoured).
	//   - HookCodeBuddySettings: the "hooks" key of CodeBuddy Code's
	//     ~/.codebuddy/settings.json (Claude-shaped; Windows runs hooks under
	//     Git Bash).
	//   - HookDeepAgentsJSON: Deep Agents Code's user-level hooks file
	//     ~/.deepagents/hooks.json ($DEEPAGENTS_HOME); the project file is
	//     trust-gated and never written.
	//   - HookDimCodeJSON: DimCode's ~/.dimcode/v2/hooks.json
	//     ($DIMCODE_HOME, with v2 appended unless it already ends in v2);
	//     an unknown event name makes the whole file
	//     unloadable, so only supported names are written.
	//   - HookDiracHookFiles: Dirac's file-per-event hooks directory
	//     ~/.dirac/Hooks (an executable per event; <Event>.ps1 on Windows).
	//   - HookAutohandConfig: the hooks.hooks[] ARRAY of Autohand's
	//     ~/.autohand/config.json, a file that also holds provider keys and
	//     the account token (credential-file exception).
	//   - HookVTCodeTOML: VT Code's user-level vtcode.toml
	//     [[hooks.lifecycle.<event>]] tables (edited line by line).
	//   - HookKimchiBashHook: Kimchi's user-level bash pre-gate directory
	//     ~/.config/kimchi/harness/hooks/bash/ (a script per hook; the only
	//     user-level hook Kimchi runs, bash tool only).
	HookIBMBobSettings    HookMechanism = "ibm_bob_settings_json"
	HookCodeBuddySettings HookMechanism = "codebuddy_settings_json"
	HookDeepAgentsJSON    HookMechanism = "deepagents_hooks_json"
	HookDimCodeJSON       HookMechanism = "dimcode_hooks_json"
	HookDiracHookFiles    HookMechanism = "dirac_hook_files"
	HookAutohandConfig    HookMechanism = "autohand_config_json"
	HookVTCodeTOML        HookMechanism = "vtcode_config_toml"
	HookKimchiBashHook    HookMechanism = "kimchi_bash_hook"
	// HookCortexHooksJSON is Cortex Code's own global hooks file,
	// ~/.snowflake/cortex/hooks.json ({"hooks": {...}}, the settings shape;
	// CORTEX_HOME / SNOWFLAKE_HOME relocate it), which Cortex merges with
	// Claude Code's settings hooks (surface-gap W-2a). Its writer
	// (internal/hook register_cortex.go) writes Observer's Claude Code
	// commands there and is switched off until live check LC18.
	HookCortexHooksJSON HookMechanism = "cortex_hooks_json"
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
	//
	// Since hook-parity Lane A every one of those long-tail rows also wires
	// a pre-tool gate, so none is prompt-only any more and the flag is false
	// on all of them (TestPromptLaneOnlyMatchesWiredBindings keeps it equal
	// to HookSpec.WiredPromptOnly). The registration decision itself is the
	// capability-shaped HookSpec.WantsRegistration (hook-parity Lane C2).
	PromptLaneOnly bool
	// PromptWarnOnly is true for a prompt seam that runs before the MAIN
	// model call but after the prompt has already left the machine
	// (Antigravity CLI PreInvocation: agy's title request carrying the
	// prompt is sent before any hook). It is not a pre-send seam in the
	// controlcoverage sense, whatever its dialect can do there: agy's seam
	// warns the developer and, since the 2026-10-15 guard-enforcement fix,
	// can also abort the main model call (the dialect row's caps, not this
	// flag, say so). Coverage surfaces report it as "warns before the model
	// call", the floor it always reaches.
	PromptWarnOnly bool
	// PromptShadowsTranscript is true when the tool's prompt-submit hook
	// writes a user_prompt row ("<tool>:hook" source_file) for a prompt the
	// tool's own transcript ALSO records for the same turn. Session messages
	// (internal/sessionmsg, node and org alike) then fold the hook row onto
	// the transcript row, which is canonical, so one typed prompt is one
	// user message (T-563). False for a hook that is the ONLY record of the
	// prompt. Grounded for codex (UserPromptSubmit row beside the rollout's
	// user_message / item_completed UserMessage row).
	PromptShadowsTranscript bool
	// PromptScope names the surfaces the prompt hook covers when it does
	// NOT cover every surface the tool's sessions come from ("" = every
	// surface). Coverage surfaces show it beside the hook seam so an
	// admin is not told a prompt rule acts before send on a surface
	// whose prompts it never sees.
	PromptScope string
	// Surfaces says, per capture surface, whether the hooks Observer
	// registers run there (CLI yes, Codex Desktop no, ...). Owned by the
	// hookSurfaces table in hooksurface.go; nil = no per-surface facts, and
	// the tool-level fields answer (HookSpec.SurfaceFor).
	Surfaces []HookSurface
	// Bindings lists the tool's hook surface event by event (hookcaps.go):
	// every native event the vendor provides, the capability it maps to,
	// and whether Observer registers and wires it today. Additive: every
	// field above keeps its meaning; Mechanism still selects the FORMAT
	// writer.
	Bindings []HookBinding
	// Note is the honest-zero reason for a row whose vendor surface offers
	// no hook Observer could bind at all (Bindings empty): tools run on
	// hosted VMs, only static permission rules, post-hoc command options,
	// hooks that do not fire, an observe-only SDK. Empty on every row that
	// declares bindings.
	Note string
	// HooksShareCredentialFile declares the D-268 exception: the vendor
	// keeps its hook config in a file that also holds plaintext
	// credentials (a provider API key, a bearer token), so registering a
	// hook means a read-modify-write of a credential-bearing file. Only a
	// row carrying this flag may do that, and its writer then runs under
	// the credential-file rules in internal/hook/credentialfile.go: it
	// changes only the span Observer owns (the hooks subtree, or Hermes's
	// plugins list), keeps every other key's bytes or values, keeps
	// the file's mode, writes atomically, refuses a file it cannot parse,
	// withholds parse details from every error, and records only a digest
	// of the hooks subtree in hook_checksums.json, never a whole-file
	// hash. It is a capability flag, not a tool branch: the writers ask it
	// of the row.
	HooksShareCredentialFile bool
	// CredentialFileReason names the file and the credential it holds for
	// a row with HooksShareCredentialFile set (the grounding of the
	// exception). Empty otherwise.
	CredentialFileReason string
	// LiveGate, when set, switches this row's hook writer off until the
	// named live check passes (DEC-12, livegate.go): `observer start`,
	// `observer init` and the dashboard refuse to run it, the writer itself
	// refuses, and doctor says "built, waiting on live check <id>". Zero =
	// not gated.
	LiveGate LiveGate
	// WindowsHookShell declares that the host's Windows hook runner spawns
	// every hook command through a shell it resolves BY NAME on the Windows
	// PATH (windowshookshell.go). When that shell is missing the host cannot
	// run any hook, Observer's included. Zero value: no such requirement is
	// grounded (the runner is cmd.exe, PowerShell, a script interpreter it
	// locates itself, or not grounded at all). Registration and `observer
	// doctor` warn, never block, when the shell does not resolve.
	WindowsHookShell HookShellRequirement
	// WindowsRunner declares a precondition of the host's Windows hook
	// runner that is not a shell on PATH: an interpreter the host locates
	// itself (Git Bash), or a script runner the PowerShell execution policy
	// can refuse (windowshookshell.go). The doctor checks it, never blocks
	// on it. Zero value (Kind empty): none grounded. A row carries at most
	// one of WindowsHookShell and WindowsRunner.
	WindowsRunner WindowsHookRunner
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
	// EnforceHookBlock: the tool's own hook supports a genuine blocking
	// reply (a deny verdict the vendor's own tool honors BEFORE the
	// dangerous action runs), observer's receiver is wired to send one, and
	// a live test on a real install proved the deny holds
	// (HookSpec.LiveBlockingToolGate). Strongest channel: the action never
	// executes.
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

// LiveBlockingToolGate reports whether the spec carries a tool gate that
// stops a dangerous call before it runs, proven on a real install: some
// binding is a tool_gate that Observer wires today, whose reply can express
// a deny, and whose grounding is a recorded live test (T-340, the per-binding
// successor of the mechanism-level set that listed only Claude Code and
// Cursor). A doc-, fixture- or inference-grounded gate does not count, even
// when it is wired: the vendor tool honouring the deny is exactly the fact a
// live test establishes. The answer follows the binding rows, never a tool
// or mechanism name, so a binding that goes live reclassifies its row.
func (h HookSpec) LiveBlockingToolGate() bool {
	for _, b := range h.Bindings {
		if b.Cap == HookCapToolGate && b.Wired && b.Grounding.Kind == GroundingLive && b.HasDecision(HookDecisionDeny) {
			return true
		}
	}
	return false
}

// EnforcementChannel returns the grounded bucket for how an org guard policy
// can stop a dangerous action on this adapter, walked as an ordered ladder
// (table-driven, CLAUDE.md rule #5 — not a tool-name switch):
//
//  1. a live-verified blocking tool gate (Hook.LiveBlockingToolGate)
//     -> EnforceHookBlock
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
	if c.Hook.LiveBlockingToolGate() {
		return EnforceHookBlock
	}
	return c.channelWithoutHook()
}

// channelWithoutHook is the ladder below hook_block: the lever a tool falls
// back to when no blocking hook stands in front of its tool calls.
func (c Capability) channelWithoutHook() EnforcementChannel {
	if c.Handoff.Launchable() {
		return EnforceSandbox
	}
	if c.Proxy != nil {
		return EnforceOrgDisallow
	}
	return EnforceRecordedAcceptance
}

// NodeEnforcement is the channel that actually holds on THIS node, and the
// one a launch decision must use. The registry's hook_block says the tool CAN
// block through its tool-gate hook; it holds here only while that hook is
// registered and current (toolGateCurrent, from the node's own hook
// registration state). A hook that is missing, stale, untrusted or switched
// off blocks nothing, so the tool falls back to the channel it would have
// with no hook at all (normally sandbox_enforce), which is then degraded for
// the platform exactly as EffectiveEnforcement does. A caller that cannot
// tell passes false: an unverified hook never stands in for the sandbox.
func (c Capability) NodeEnforcement(toolGateCurrent, sandboxAvailable bool) EnforcementChannel {
	return c.EffectiveEnforcementUnder(toolGateCurrent, sandboxAvailable, EnforceRecordedAcceptance)
}

// EffectiveEnforcement is EnforcementChannel() degraded for the current
// platform: EnforceSandbox is only a real lever where internal/sandbox can
// actually build a bwrap sandbox (Linux/WSL2 with a working userns; see
// sandbox.Probe). sandboxAvailable should come from that probe's Verdict ==
// VerdictAvailable at the call site (cmd/observer). Never upgrades a
// channel, never fails — the honest floor when sandboxing isn't available
// is the same recorded-acceptance posture as a tool with no lever at all.
// It is capability-level: it assumes a hook_block tool's hook is in place,
// so a launch decision uses NodeEnforcement instead.
func (c Capability) EffectiveEnforcement(sandboxAvailable bool) EnforcementChannel {
	return c.EffectiveEnforcementUnder(true, sandboxAvailable, EnforceRecordedAcceptance)
}

// EffectiveEnforcementUnder is the per-node channel (NodeEnforcement) with
// the organization's choice of what a missing sandbox degrades to (D-178,
// operator ruling 2026-10-04: org-configurable, default
// recorded_acceptance). toolGateCurrent is the node's own tool-gate state
// (D-262): a hook_block tool whose gate hook is not registered and current
// here falls through to the channel it would have with no hook, and from
// there to the org's fallback when no sandbox is available. noSandbox is
// EnforceRecordedAcceptance or EnforceOrgDisallow; org_disallow is honoured
// only for a tool whose model traffic Observer proxy-routes (Proxy != nil),
// the same precondition the static ladder puts on that bucket, so a tool with
// no proxy lever still degrades to recorded_acceptance. Any other noSandbox
// value is treated as recorded_acceptance (never an upgrade).
func (c Capability) EffectiveEnforcementUnder(toolGateCurrent, sandboxAvailable bool, noSandbox EnforcementChannel) EnforcementChannel {
	ch := c.EnforcementChannel()
	if ch == EnforceHookBlock && !toolGateCurrent {
		ch = c.channelWithoutHook()
	}
	if ch != EnforceSandbox || sandboxAvailable {
		return ch
	}
	if noSandbox == EnforceOrgDisallow && c.Proxy != nil {
		return EnforceOrgDisallow
	}
	return EnforceRecordedAcceptance
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

// BudgetHookStop names where an exhausted managed hard budget stops a
// direct-provider session of this tool through its OWN hooks (T-519, D-332):
// the prompt-submit seam, the pre-tool seam, both, or neither. It is separate
// from BudgetAdmissionChannel, which names the pre-request chokepoint Observer
// controls (the proxy): a hook stop is the vendor honouring a deny reply, so
// it bites at the NEXT prompt or tool call, not on the model request already
// in flight, and only while the hook is registered and current on the node.
type BudgetHookStop string

const (
	// BudgetHookStopNone: no wired pre-send hook can deny; an exhausted
	// budget is flagged after send (D-031) unless the proxy or the process
	// controller stops the session.
	BudgetHookStopNone BudgetHookStop = ""
	// BudgetHookStopPrompt: the prompt-submit seam denies the next prompt.
	BudgetHookStopPrompt BudgetHookStop = "prompt"
	// BudgetHookStopTool: the pre-tool seam denies the next tool call.
	BudgetHookStopTool BudgetHookStop = "tool"
	// BudgetHookStopPromptAndTool: both seams deny.
	BudgetHookStopPromptAndTool BudgetHookStop = "prompt+tool"
)

// BudgetHookStop is computed from the hook bindings, never stored and never a
// tool-name switch (CLAUDE.md #3): a WIRED prompt_gate binding whose reply can
// express a deny is the prompt seam, a WIRED tool_gate binding whose reply can
// express a deny is the pre-tool seam. The grounding of each binding (live,
// doc, fixture) is the gate columns' to report; this answers only "is there a
// seam Observer answers today".
func (c Capability) BudgetHookStop() BudgetHookStop {
	prompt, tool := false, false
	for _, b := range c.Hook.Bindings {
		if !b.Wired || !b.HasDecision(HookDecisionDeny) {
			continue
		}
		switch b.Cap {
		case HookCapPromptGate:
			prompt = true
		case HookCapToolGate:
			tool = true
		}
	}
	switch {
	case prompt && tool:
		return BudgetHookStopPromptAndTool
	case prompt:
		return BudgetHookStopPrompt
	case tool:
		return BudgetHookStopTool
	default:
		return BudgetHookStopNone
	}
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
	// MCPZedContextServers: Zed's "context_servers" object in its JSONC
	// settings.json ({"<name>": {command, args, env}} or {url}), which Zed
	// also offers to the ACP agents it hosts (zed.dev/docs/ai/mcp). Not the
	// shared {"mcpServers":{…}} shape; no Observer writer yet (S-12).
	MCPZedContextServers MCPFormat = "zed_context_servers"
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
	// Remote describes the client's grounded REMOTE (url-addressed) MCP
	// server shape — what the Agent Access relay projects into the client's
	// config (doc3 §12.1: `{type:"http", url:"http://127.0.0.1:8820/mcp/
	// <vserver>"}` in loopback mode, never a secret). nil = no grounded
	// remote target (the honesty rule: zero value = no capability, never a
	// fabricated writer). The per-format writers in internal/mcp dispatch
	// on THIS row's spelling table, never on the tool name (CLAUDE.md #3).
	Remote *MCPRemoteTarget
	// SharesCredentialFile declares the D-268/D-270 credential-file
	// exception for this client's MCP config file (review T-384): the file
	// can hold plaintext credentials (a sibling server's env block or
	// headers, provider keys), so writing observer's entry is a
	// read-modify-write of a credential-bearing file. Only a row carrying
	// this flag may be written by internal/mcp's registrar (and Hermes'
	// MCP writer in internal/hook), and the write then follows the
	// internal/credfile rules: only the MCP subtree changes, every other
	// member keeps its bytes and position, the mode is kept, and no
	// whole-file hash and no value from the file is stored or surfaced.
	SharesCredentialFile bool
	// CredentialFileReason names the credential the file can hold, for a
	// row with SharesCredentialFile set. Empty otherwise.
	CredentialFileReason string
	// WindowsStdio is how this client starts a stdio MCP server command on
	// native Windows, which decides the form an entry that launches an npm
	// shim (`npx`, `npm`) must take there (internal/platform/winshim.
	// StdioLaunch). The zero value winshim.LaunchAsIs means "not grounded":
	// the command is written as given. Only a writer that emits a bare npm
	// shim reads it today (the managed-settings MCP pins); the registrar's
	// own entries launch an absolute observer binary or a wsl.exe bridge,
	// which every spawner starts. Grounding (source + date) lives in the
	// row comment.
	WindowsStdio winshim.Launch
}

// MCPRemoteTransport is the client-agnostic transport vocabulary for a
// remote MCP server. Each client spells these differently on disk
// (claude-code/droid "http", cline "streamableHttp", command-code
// `transport:"http"`, cursor/codex/opencode/hermes infer from the url) —
// the MCPRemoteTarget.Spelling table owns the per-client spelling so the
// writer never branches on tool name.
type MCPRemoteTransport string

const (
	// MCPRemoteStreamableHTTP is MCP's current Streamable HTTP transport.
	MCPRemoteStreamableHTTP MCPRemoteTransport = "streamable_http"
	// MCPRemoteSSE is the legacy HTTP+SSE transport.
	MCPRemoteSSE MCPRemoteTransport = "sse"
)

// MCPRemoteTarget is the grounded remote-server shape of one client's MCP
// config (Agent Access W4a). Every field is DATA read off the vendor's own
// config docs or a live install (the grounding date + source live in the
// registry row comment); the writer in internal/mcp turns it into the
// on-disk entry. Fields that are absent for a client (no transport key, no
// flags) are simply zero — the writer omits them.
type MCPRemoteTarget struct {
	// Transports lists the transports the client's config grounds, in the
	// client's own preference order. A transport absent here is refused by
	// the writer (e.g. codex and command-code ground Streamable HTTP only).
	Transports []MCPRemoteTransport
	// Headers is true when the client honours a per-server request-header
	// map in config. The relay still injects Authorization itself; this only
	// says the client CAN carry static headers (e.g. a vserver hint).
	Headers bool
	// TransportKey is the entry field that carries the transport ("type" for
	// claude-code/cline/droid, "transport" for command-code). Empty means the
	// client infers the transport from the url and the writer emits none.
	TransportKey string
	// Spelling maps each grounded transport to the client's on-disk spelling
	// under TransportKey (e.g. streamable_http → "http" vs "streamableHttp").
	// Ignored when TransportKey is empty.
	Spelling map[MCPRemoteTransport]string
	// Flags are static boolean fields the client's own tooling writes on a
	// remote entry (`disabled:false` for droid/cline, `enabled:true` for
	// command-code). Emitted verbatim; nil for clients that write none.
	Flags map[string]bool
	// Implemented is true when internal/mcp's Registrar can project this
	// target TODAY (RegisterRemote has a writer for the parent Format AND a
	// locate row resolves the file). false = grounded-capable, no writer
	// (hermes: its YAML writer lives in internal/hook's init path and has no
	// remote variant, and locate carries no hermes row).
	Implemented bool
	// Note documents the grounding (source + date) and any caveat.
	Note string
}

// Supports reports whether transport is one the client's config grounds.
func (m *MCPRemoteTarget) Supports(transport MCPRemoteTransport) bool {
	if m == nil {
		return false
	}
	for _, t := range m.Transports {
		if t == transport {
			return true
		}
	}
	return false
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
	// "hook" (vendor-reported per-request usage on a hook payload),
	// "proto" (decrypt-gated). "none" = AUDITED and no local token source
	// exists (e.g. qoder's server-side-only usage — distinct from "",
	// which means the audit itself hasn't happened).
	Best string
	// Gap is a short honest description of a known hole ("" = no known gap):
	// e.g. "no cache tier", "model often blank", "decrypt-gated",
	// "sparse task tokens", "OpenAI-gross net-vs-cached fix pending".
	Gap string
	// OutputOnlyShadow is true when the adapter emits, beside a FULL usage
	// row for a turn, a second OUTPUT-ONLY token_usage row for the same
	// turn (input == 0, cache == 0, output identical) - the Copilot family's
	// streaming-completion echo. Every consumer that must not double-count
	// (the process cost engine, the node session-detail messages path, the
	// org message rollup) dispatches on THIS flag and pairs shadow rows
	// one-to-one with their full row by output count; none of them names
	// the tool (CLAUDE.md "branch on capabilities, never on source
	// identity"). Audited 2026-09-22 (Sol reviews R9 / P7).
	OutputOnlyShadow bool
	// SessionCumulative is true when the adapter's JSONL token row is a
	// RUNNING TOTAL for the whole session (one row, MAX-upgraded as the
	// session grows) rather than a per-call delta — droid, goose, crush,
	// mistral-code. internal/sessionmsg's session-cumulative
	// reconciliation (reconcileCumulative) dispatches on THIS flag
	// (combined with the adapter's own "tokens:"-prefixed turn id) to
	// decide whether a JSONL row must be resolved winner-take-all against
	// that session's proxy rows rather than turn-deduped individually. A
	// tool whose rows merely happen to share the "tokens:" id prefix
	// convention without being session-cumulative (aider — per-exchange,
	// "tokens:<chat-key>:<seq>") leaves this false and falls through to
	// the ordinary per-turn dedup pass instead (2026-09-22 rework finding
	// #8 — capability, not a bare id-prefix sniff, decides the routing).
	SessionCumulative bool
	// ReasoningDisjoint is true when this adapter's token_usage
	// output_tokens and reasoning_tokens are AUDITED disjoint (reasoning
	// netted out of output, or reasoning never stamped), so a row's
	// generated tokens are Output + Reasoning. False = unaudited: the
	// Tok/s numerator (internal/sessionmsg Speed) counts Output only, so
	// an adapter whose output already includes reasoning is never
	// double-counted. S10-SPEED, 2026-09-23.
	ReasoningDisjoint bool
	// GenerationTiming names where a per-call GENERATION DURATION comes
	// from on this adapter's token rows (token_usage.gen_ms / gen_basis,
	// agent migration 136): GenTimingNative (the tool's own store records the call's
	// duration or start+end), GenTimingTranscript (derived from transcript
	// record order, stamped only when provable in-window), GenTimingNone
	// (audited: no duration exists) or "" (unaudited). Declarative data
	// pinned by registry_coverage_test.go: the Tok/s math reads the per-row
	// duration, never this field. The one consumer is the org push's settle
	// holdback (TranscriptTimedTools): a transcript-timed row can be stamped
	// AFTER its first insert, so it is briefly held back from the push.
	GenerationTiming string
	// SynthesizedTimestamps is true when the adapter FABRICATES per-row
	// timestamps (base + index steps, interpolation, one repeated session
	// stamp) because the store has no real per-message clock. Such an
	// adapter may never declare GenTimingTranscript (pinned by
	// registry_coverage_test.go): a 1 ms synthetic step would read as a
	// million tokens per second.
	SynthesizedTimestamps bool
	// ReportsCost is true when the adapter records the TOOL'S OWN stated cost
	// for a call in token_usage.estimated_cost_usd (a vendor gateway's billed
	// figure, the harness's per-message cost field) rather than leaving it at
	// 0 for Observer's cost engine to price. A non-zero stored cost from such
	// an adapter is authoritative capture data: the opt-in stored-cost
	// re-price (internal/reprice, gap PRICE-REPRICE-1) never overwrites it,
	// on the node or on the org's copy. The zero value is the grounded claim
	// "this adapter never stores a cost of its own", kept honest by
	// registry_reportscost_test.go, which pins the set of adapter packages
	// that assign EstimatedCostUSD against the set of rows flagged here.
	ReportsCost bool
}

// GenerationTiming values (TokenTier.GenerationTiming).
const (
	GenTimingNone       = "none"
	GenTimingNative     = "native"
	GenTimingTranscript = "transcript"
)

// LimitSourceKind names how a tool's OWN subscription-window / rate-limit
// state (docs/cost-predictor.md's 5h/weekly gauge) could ever surface
// LOCALLY, mirroring TokenTier's convention: "" = not yet audited (the
// honest floor), a non-empty value = audited and the answer is a
// permanent negative. This field never records a POSITIVE capability — a
// working source is discovered structurally, by the proxy-header
// snapshot or the transcript fallback in
// internal/intelligence/dashboard/predict.go::loadLimitGauge actually
// producing a window, never by a registry flag. Only a non-empty Source
// short-circuits that ladder.
type LimitSourceKind string

const (
	// LimitSourceUnaudited (zero value): not yet audited for a local
	// limit signal. Falls through to loadLimitGauge's existing proxy-
	// snapshot / transcript-fallback / needs-proxy ladder UNCHANGED —
	// this is the correct default for nearly every row: an unaudited
	// Anthropic-family tool must keep showing "needs proxy", never
	// silently render "not visible" with no real investigation behind it.
	LimitSourceUnaudited LimitSourceKind = ""
	// LimitSourceNoneRemote: a limit/quota genuinely exists but is visible
	// ONLY in the vendor's own hosted dashboard or account API — nothing
	// local (config file, CLI subcommand, IPC surface) exposes it.
	LimitSourceNoneRemote LimitSourceKind = "none_remote"
	// LimitSourceNoneStructural: no local signal can exist even in
	// principle, because the tool's inference never runs on this machine
	// (e.g. a remote-sandbox execution model).
	LimitSourceNoneStructural LimitSourceKind = "none_structural"
)

// LimitCapability records an AUDITED negative finding for the 5h/weekly
// usage-limit gauge. A zero value means "not audited" and MUST NOT be
// read as "no source" — only a non-empty Source short-circuits
// loadLimitGauge's ladder with Note as the operator-facing reason. Note
// is REQUIRED (non-empty) whenever Source != LimitSourceUnaudited
// (registry_coverage_test.go TestLimitCapabilityHonesty pins this).
type LimitCapability struct {
	Source LimitSourceKind
	Note   string
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

// HeadlessPermLane names one way an unattended headless drive handles the
// harness's OWN permission prompts (OSH-R-005). Nobody is at the keyboard
// during a drive, so every lane is a standing answer to "may the agent do
// this without asking": the lanes differ in how much the harness itself
// still refuses. The Agent Arena picks the lane per drive (internal/arena
// permlane.go); a registry row only says what each lane is on argv.
type HeadlessPermLane string

const (
	// HeadlessPermBypass turns the harness's own permission checks off
	// entirely (claude-code --dangerously-skip-permissions, grok
	// --always-approve, aider --yes). A row whose headless mode runs every
	// tool unasked with no flag at all declares this lane with no tokens,
	// because that is what it is. Driven only where the operator's own
	// config allows it and a managed node's org policy does not forbid it.
	HeadlessPermBypass HeadlessPermLane = "bypass"
	// HeadlessPermEdit keeps the harness's own checks on while letting the
	// agent edit inside its working directory without asking
	// (claude-code --permission-mode acceptEdits, codex -s workspace-write).
	// Anything else the harness would ask about is refused headless.
	HeadlessPermEdit HeadlessPermLane = "edit"
	// HeadlessPermReadOnly lets the agent read and answer, nothing else
	// (codex -s read-only). The lane the Arena judge runs in: the judge
	// reads a patch from its prompt and needs no tools.
	HeadlessPermReadOnly HeadlessPermLane = "read_only"
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
	// Permissions maps each GROUNDED permission lane to the argv tokens that
	// select it, placed after Lead and before the prompt. A lane absent from
	// the map is not grounded for the tool and is never guessed; a lane
	// present with no tokens is grounded and needs none. Nil means no lane
	// is grounded, which leaves the harness undrivable unattended.
	Permissions map[HeadlessPermLane][]string
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
	// Catalog declares WHICH models this tool can be pointed at, so a model
	// picker (the Arena's judge/candidate pickers) offers the tool's own
	// provider's models instead of a free-text box. Zero value = no grounded
	// catalogue statement; consumers then offer only the tool's own history.
	Catalog ModelCatalog
}

// ModelCatalogKind names the shape of the model catalogue a tool draws on.
// Consumers dispatch on this shape, never on tool name (CLAUDE.md #3).
type ModelCatalogKind string

const (
	// ModelCatalogNone (zero value): no grounded statement about which
	// models the tool serves. The honest floor.
	ModelCatalogNone ModelCatalogKind = ""
	// ModelCatalogVendor: the tool is locked to one vendor's models (Claude
	// Code -> Anthropic, Codex -> OpenAI). Providers names the provider
	// families; a picker offers that family's catalogue models.
	ModelCatalogVendor ModelCatalogKind = "vendor"
	// ModelCatalogOpen: bring-your-own-model. The tool accepts many
	// providers' ids, so no catalogue can say which ones this machine has
	// keys for; a picker offers only the models this node has actually used.
	ModelCatalogOpen ModelCatalogKind = "open"
)

// ModelCatalog is the per-tool catalogue declaration (see ModelSpec.Catalog).
type ModelCatalog struct {
	// Kind is the catalogue shape.
	Kind ModelCatalogKind
	// Providers lists the provider families ("anthropic", "openai", "xai",
	// "google") a ModelCatalogVendor tool serves. Empty for the other kinds.
	Providers []string
	// Note is optional operator-facing copy about a caveat of selecting a
	// model for this tool (e.g. which models the proxy lane can capture).
	Note string
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
	// TestInstallHintsUseClosedVocabularies): "npm" | "script" | "brew" |
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
	// Requires lists the HOST programs this command needs on PATH beyond its
	// own argv[0] (which the dashboard already resolves): the `curl` a
	// curl|bash pipeline fetches with, and every program the vendor script
	// itself hard-requires (kiro-cli's script exits "Missing required
	// dependencies: unzip" on Linux; goose's extracts a .tar.bz2 with tar +
	// bzip2). An entry may list alternatives separated by "|"
	// ("sha256sum|shasum": either one satisfies it). The guided install checks
	// these BEFORE spawning and, when one is missing, refuses with the
	// package-manager command that fixes it (internal/toolinstall
	// PrereqRemedy) instead of letting the vendor script fail. Same honesty
	// rule as the hint itself: list only what was read in the vendor's
	// current script (every Unix script hint was read for this on
	// 2026-10-03; re-read the script whenever its hint changes, and note
	// that Windows irm|iex hints run on PowerShell built-ins and carry
	// none); a program the script
	// needs only on some other path (e.g. xz when it must also download
	// Node.js) is NOT listed, so a guess never blocks an install. Empty =
	// nothing grounded beyond argv[0].
	Requires []string
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
	// UserInstallHint is OPTIONAL user-facing copy for the same gap: one
	// short plain sentence an end user can act on ("available for Windows
	// and macOS only"), shown by the dashboard when there is no guided
	// install. WindowsNote / InstallNote are engineering records (sources,
	// dates, rejected channels) and are not rendered to users; set this only
	// when the gap carries a fact worth telling them. Empty = say nothing
	// beyond the generic sentence. Pinned plain by user_install_hint_test.go.
	UserInstallHint string
	// Runtime is the tool's grounded MINIMUM HOST RUNTIME: the interpreter
	// version its code needs when it runs on the host's own interpreter (an
	// npm install, whose `#!/usr/bin/env node` shim runs on whatever node the
	// launch's PATH resolves first). nil = unknown, the honest zero: nothing
	// is checked. Set ONLY from the vendor's published metadata (the npm
	// package's engines.node), with the source and date in Source; pinned by
	// TestRuntimeRequirementsGrounded. The guided install refuses an install
	// channel that runs on the host runtime (internal/toolinstall
	// ChannelHostRuntime) when the host's version is older, and every
	// launcher refuses a resolved shim whose interpreter is older, both with
	// the same plain sentence, before the tool can crash at startup. At
	// launch, an installed npm package's OWN engines.node (its package.json
	// beside the resolved shim target) takes precedence when it parses to a
	// floor, since it is exact for the version on disk; this value is the
	// fallback, and the only input for the guided install.
	Runtime *RuntimeRequirement
}

// RuntimeNode is the Node.js runtime in RuntimeRequirement.Runtime's closed
// vocabulary (internal/toolinstall's runtime table carries one row per value:
// display name, program spelling per OS, install guidance per host family).
const RuntimeNode = "node"

// RuntimeRequirement is one grounded minimum-runtime fact (see
// BinaryResolveSpec.Runtime). Every field is data; nothing here is executed.
type RuntimeRequirement struct {
	// Runtime names the interpreter, a CLOSED vocabulary: RuntimeNode.
	Runtime string
	// MinVersion is the lowest acceptable version, dotted numeric ("20",
	// "22.19.0"), copied from the vendor's own range. The floor alone is what
	// blocks: the check may under-block, never over-block.
	MinVersion string
	// Range is the vendor's whole engines range when it has a hole the floor
	// cannot express (openclaw's ">=24.16.0 <25 || >=26.1.0"); "" otherwise.
	// A version above the floor but outside Range is reported
	// (outside_range), never blocked (review M3-18).
	Range string
	// Product is the tool's product name for the user-facing sentence
	// ("Gemini CLI needs Node.js 20 or newer.").
	Product string
	// Source records where MinVersion was read and when (engineering record,
	// not rendered to users).
	Source string
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
	// StateRWByOS adds, per GOOS value, state the tool writes only on that
	// OS (a cache under ~/Library on macOS), or that was grounded on that
	// OS alone. Same path rules as StateRW. ForOS folds the row for one OS
	// into StateRW; nil adds nothing (macOS live install 2026-10-29,
	// D-MU6).
	StateRWByOS map[string][]string
	// OSNotes records, per GOOS value, a known limitation of the tool inside
	// a box on that OS that the row cannot fix (a program the profile
	// deliberately refuses). Shown with the launch and in
	// docs/sandboxed-terminals.md; it never makes a tool unlaunchable.
	OSNotes map[string]string
	// ProtectRO lists HOME-relative files/dirs INSIDE a StateRW entry that
	// a later UNSANDBOXED session of the tool executes: hook config, MCP
	// server config, auto-discovered plugins/mods. The sandbox re-binds
	// them read-only after the rw binds (security ledger SR27-SBX-1), so a
	// sandboxed agent cannot plant a command its next unsandboxed run
	// executes. Grounded from the files observer's own hook/MCP registrars
	// write (internal/hook/register.go, internal/mcp/locate, the hermes
	// plugin writer) - never guessed. A file the tool rewrites on every run
	// (e.g. claude-code's .claude.json, which also carries user MCP
	// servers) cannot be listed without breaking the tool; that residual is
	// documented in docs/sandboxed-terminals.md. Empty for a tool whose
	// executed config observer has not grounded. Entries here are FILES;
	// directories go in ProtectRODirs. The distinction only matters when the
	// path does not exist at launch: the sandbox then creates a read-only
	// placeholder of that shape so the sandboxed process cannot create it
	// (SR27-SBX-2).
	ProtectRO []string
	// ProtectRODirs is ProtectRO for directories (auto-discovered plugin or
	// mod dirs). Same rules: HOME-relative, strictly inside a StateRW entry.
	ProtectRODirs []string
	// Note is REQUIRED when both StateRW and StateRO are empty (the
	// honest zero) — it must say why the row is unmapped, never left
	// silently blank.
	Note string
	// GateDrift is how a sandboxed run's transcript is compared with the
	// gate events its capture relay saw (sandbox plan v2 section 5.2 (2)).
	// The zero value means no grounded comparison: the run is not checked
	// this way (its hook registration is still verified).
	GateDrift TranscriptGateSpec
	// ConfigHome, when set, is where the tool keeps its config and
	// first-run state: a sandboxed launch of a tool whose first run was
	// never finished is refused, and a run whose home has no config folder
	// gets a run-local writable one seeded with non-secret state (Windows 11
	// Pro rerun 2026-10-25, D3). Nil means no grounded config home.
	ConfigHome *SandboxConfigHome
	// SignIn, when set, names the tool's sign-in files (sandboxsignin.go,
	// lane BOXSIGNIN): a run whose tool state is projected may get a copy
	// of them, only with the user's consent for the tool. Nil means no
	// grounded sign-in file (seeding is refused for the tool).
	SignIn *SandboxSignIn
	// ProviderEnv lists the environment-variable NAMES (never values) of
	// the tool's own provider settings that a sandboxed run may receive
	// from the launching environment: its credential variables (every
	// AuthEnv name, pinned by TestSandboxProviderEnvCoversAuthEnv) and its
	// own config-location variables. Every backend builds the box's
	// environment from an allow-list (internal/sandboxenv): the OS table,
	// these names, the user's [terminal.sandbox].pass_env and Observer's own
	// variables, nothing else (WINFIX2 audit finding 1, ledger
	// SBX-WIN-ENV-1). Empty means the box gets no provider variable of the
	// tool from the environment (a tool that signs in through its own state
	// files needs none).
	ProviderEnv []string
	// NeedsWin32k says the tool's own program needs user32.dll, so a
	// Windows mxc-process box runs it with MXC's Win32k system-call
	// mitigation dropped (the document's ui.disable false). Without it the
	// mitigation is kept and a program that imports user32.dll fails to
	// start with STATUS_DLL_INIT_FAILED (Windows 11 Pro rerun 2026-10-25,
	// D1). Decided from the PE import tables of the tool's launch binaries
	// (WINFIX2 audit finding 4, read 2026-10-25 on Windows 11 26200):
	// node.exe (20.19.1 and the Program Files install) imports USER32.dll
	// statically, the native claude.exe delay-loads it and Claude Code's
	// Bash tool runs Git Bash, whose bash.exe imports it; codex.exe imports
	// it. Every row whose launcher runs on node is marked
	// (TestSandboxNeedsWin32kGrounded); every other row keeps the mitigation.
	NeedsWin32k bool
}

// ForOS returns s with StateRWByOS[goos] appended to StateRW (no
// duplicates) and the OS-keyed tables dropped, for a backend that runs on
// goos. The receiver is not changed.
func (s SandboxSpec) ForOS(goos string) SandboxSpec {
	out := s
	out.StateRW = append([]string(nil), s.StateRW...)
	for _, p := range s.StateRWByOS[goos] {
		dup := false
		for _, q := range out.StateRW {
			if q == p {
				dup = true
				break
			}
		}
		if !dup {
			out.StateRW = append(out.StateRW, p)
		}
	}
	out.StateRWByOS = nil
	out.OSNotes = nil
	return out
}

// OSNote returns the row's limitation note for goos ("" for none).
func (s SandboxSpec) OSNote(goos string) string { return s.OSNotes[goos] }

// TranscriptGateSpec declares, for one tool, how its transcript shows the
// tool calls that ran and how its gate event names the call (sandbox plan v2
// section 5.2 (2), lane sbx-p2d): a call the transcript shows as run whose
// gate event the relay never saw is drift. Which hook events are gate events
// is not repeated here: it is the tool's HookCapToolGate binding.
type TranscriptGateSpec struct {
	// PayloadCallID is the top-level gate payload key that carries the
	// tool call's id.
	PayloadCallID string
	// Ran selects, from one JSONL transcript line, the ids of tool calls
	// that ran; any matching rule yields ids.
	Ran []TranscriptBlockRule
	// Called selects, from one line, the ids of tool calls the agent made
	// (the call itself, before its result). A transcript read from its
	// start counts a result with no timestamp only when its call was read
	// in the same transcript, so copied history never counts.
	Called []TranscriptBlockRule
	// TimestampKey is the top-level line key holding the line's RFC 3339
	// time ("" when the transcript has none). A transcript read from its
	// start counts a timestamped result only when it is newer than the run.
	TimestampKey string
	// Grounding names the evidence the rules were read from.
	Grounding string
}

// Compared reports whether the spec declares a comparison at all.
func (s TranscriptGateSpec) Compared() bool { return s.PayloadCallID != "" && len(s.Ran) > 0 }

// TranscriptBlockRule selects call ids from one JSON transcript line: the
// line's top-level LineKey must equal LineValue, Path walks object keys to
// a block or an array of blocks, and each block whose BlockKey equals
// BlockValue yields its IDKey, unless the block's SkipIfTrue key is true (a
// result that says the call failed or never ran: it is not counted, so an
// interrupted call is never drift).
type TranscriptBlockRule struct {
	LineKey, LineValue   string
	Path                 []string
	BlockKey, BlockValue string
	IDKey                string
	SkipIfTrue           string
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
