package hook

import "github.com/marmutapp/superbased-observer/internal/integration"

// registryMechanisms is the closed set of hook mechanisms Registry.Register
// (and Unregister) has a format writer for. It is the ONE owner of that fact:
// `observer init` / `observer uninstall` (cmd/observer hookRegistryWrites) and
// the dashboard's Connected-tools hooks probe both read it through
// RegistryWrites, so the probe can never claim a state for a mechanism the
// registry cannot write, and a new writer is one row here
// (TestRegistryWritesMatchesDispatch keeps the table equal to the dispatch).
//
// Not listed, on purpose: HookNone (watcher-only), HookHermesPlugin (written
// by `observer init --hermes`, runHermesInit), HookClineCLIJSONL (a log
// tailer, no config entry) and HookBrowserExtension (the extension's
// native-messaging host).
var registryMechanisms = map[integration.HookMechanism]bool{
	integration.HookClaudeSettings: true,
	integration.HookCursor:         true,
	integration.HookCodexConfig:    true,
	integration.HookGeminiSettings: true,
	integration.HookQwenSettings:   true,
	integration.HookFactoryJSON:    true,
	// Part B item 2 (phase-3a): the documented long-tail vendors.
	integration.HookQoderJSON:       true,
	integration.HookPoolsideYAML:    true,
	integration.HookCascadeJSON:     true,
	integration.HookCommandCodeMod:  true,
	integration.HookAntigravityJSON: true,
	// Hook-parity Lane A4-A6: the tool-gate-only mechanisms.
	integration.HookGrokHooksJSON:        true,
	integration.HookCopilotCLIHooks:      true,
	integration.HookVibeHooksTOML:        true,
	integration.HookGoosePlugin:          true,
	integration.HookClineHookFiles:       true,
	integration.HookJunieConfig:          true,
	integration.HookCrushJSON:            true,
	integration.HookOpenInterpreterHooks: true,
	integration.HookZcodeJSON:            true,
	// T-479: Muse Code's user settings.json hooks block.
	integration.HookMuseSettings: true,
	// T-378: Kimi Code's config.toml [[hooks]] tables (credential-file exception).
	integration.HookKimiCodeTOML: true,
	// gfiD (2026-10-15): Kiro CLI's agent JSON hooks + the V3 standalone file.
	integration.HookKiroAgentJSON: true,
	// Hook-parity Lane D: the one embedded plugin shim.
	integration.HookPluginShimTS: true,
	// The 2026-10-21 wave (register_wave1021*.go).
	integration.HookIBMBobSettings:    true,
	integration.HookCodeBuddySettings: true,
	integration.HookDeepAgentsJSON:    true,
	integration.HookDimCodeJSON:       true,
	integration.HookDiracHookFiles:    true,
	integration.HookAutohandConfig:    true,
	integration.HookVTCodeTOML:        true,
	integration.HookKimchiBashHook:    true,
	// Surface-gap W-2a: Cortex Code's own hooks.json (register_cortex.go),
	// switched off until live check LC18.
	integration.HookCortexHooksJSON: true,
}

// RegistryWrites reports whether Registry.Register has a writer for the hook
// mechanism m. It says nothing about whether a given tool should be written
// (auto-wiring, lifecycle and cross-OS bridging are the caller's capability
// checks); it only answers "is there a writer for this format".
func RegistryWrites(m integration.HookMechanism) bool { return registryMechanisms[m] }
