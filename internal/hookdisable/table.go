package hookdisable

// groundingConfigSurface is the audit most rows are grounded in.
const groundingConfigSurface = "docs/audits/adapter-config-surface-2026-10-03.md"

// groundingSurfaceGap is the surface-gap review the 2026-10-25 rows come
// from; groundingLocationMatrix is its per-vendor location matrix.
const (
	groundingSurfaceGap     = "docs/audits/surface-settings-precedence-gap-review-2026-10-25.md"
	groundingLocationMatrix = "docs/audits/surface-settings-location-matrix-2026-10-25.md"
)

// claudeUserReplayHosts is every tool on which Observer stops observing
// when Claude Code's user (or managed) hook settings are switched off:
// Claude Code itself plus the hosts that run ~/.claude/settings.json hooks.
// cursor-agent and Grok Build are live-grounded on node 1 2026-10-03; Devin
// CLI and DeepSeek Harness per the config-surface audit finding 5 (Devin's
// read_config_from.claude defaults to true; DeepSeek's dsh-hooks-claude-code
// plugin runs the settings file its configPath names, vendor source
// 0.2.1-rc.3, surface-gap S-20); Cortex Code live-grounded 2026-10-21;
// Kimchi's claude-code-hook-adapter (default off) honours disableAllHooks
// (location matrix part 7). Copilot CLI and VS Code Copilot are NOT here: they
// read only a repository's .claude/settings(.local).json (surface-gap S-8),
// so they are on the project rows only.
//
// Every host internal/hook's foreign-host signature table recognises must be
// on this list or the project list below (internal/hook
// TestForeignHostToolsAreHookDisableReplayHosts); devin stays here without a
// signature row (no payload field tells it from Claude Code yet, surface-gap
// S-10 / S-20). Copilot's VS Code local agent IS the Copilot CLI runtime (live
// check 12, 2026-10-26), so copilot-cli covers it; whether VS Code also runs
// the user ~/.claude/settings.json hooks (chat.useClaudeHooks) is live check
// 12b, so neither copilot id joins this user list yet.
var claudeUserReplayHosts = []string{"claude-code", "cortex-code", "cursor", "deepseek", "devin", "grok", "kimchi"}

// ClaudeUserReplayHosts returns a copy of the tools Claude Code's user (and
// managed) hook-off switches silence: Claude Code plus the hosts that replay
// its user hook settings.
func ClaudeUserReplayHosts() []string {
	return append([]string(nil), claudeUserReplayHosts...)
}

// claudeProjectReplayHosts is the same set for a project's
// .claude/settings(.local).json, which Copilot CLI and the VS Code Copilot
// harness read too (config-surface audit finding 5; S-8).
var claudeProjectReplayHosts = []string{"claude-code", "copilot", "copilot-cli", "cortex-code", "cursor", "deepseek", "devin", "grok", "kimchi"}

// ClaudeProjectReplayHosts returns a copy of the tools a project's Claude
// Code hook-off switches silence.
func ClaudeProjectReplayHosts() []string {
	return append([]string(nil), claudeProjectReplayHosts...)
}

// claudeManagedSettingsFile is the agentconfig FileRow of Claude Code's
// managed settings file (C:\Program Files\ClaudeCode on Windows; the
// caller resolves it, with its managed-settings.d drop-ins, CC-5).
const claudeManagedSettingsFile = "claude-code/managed-settings"

// factorySystemSettingsFile is the agentconfig FileRow of Factory's org
// system settings file.
const factorySystemSettingsFile = "droid/system-settings"

// Switches is the ordered table (one test row each).
//
// Project-scope rows exist only where the vendor documents the switch in a
// project file. Deliberately absent (T-910 grounding pass, 2026-10-19):
// VS Code Copilot's chat.useHooks (a flat VS Code setting; whether a
// workspace .vscode/settings.json may turn it off is unverified, and no row
// covers it at user scope either), Gemini CLI's hooksConfig.disabled (a list
// of hook names, not an on/off switch), Codex's [features] hooks (TOML, and
// unverified in a project .codex/config.toml), and Antigravity's
// .agents/hooks.json per-set enabled flag (unverified that it can reach a
// user-level hook set).
//
// Deliberately absent from the 2026-10-25 surface-gap pass (lane w2-e):
// switches that live in no file (DimCode --no-hooks / DIM_DISABLE_HOOKS,
// Cortex --setting-sources, Command Code --safe-mode, Factory --settings,
// Autohand --bare: W-3b, Wave 5 reconciliation); CodeBuddy's
// CODEBUDDY_DISABLE_EXTENDED_PLUGIN_HOOKS (it names plugin hooks, and
// Observer's are settings hooks); Vibe's same-name project hook (no
// catalogue row for the project hooks.toml) and goose plugins.<name>
// .enabled (YAML, no grounded entry form); Kimchi's org FORCE_OFF lock
// (server-side; the org-policy cache shape is not grounded); Gemini CLI's
// hooksConfig.disabled (Observer's hook entries carry no name to match);
// Copilot policy.d and the VS Code chat policies (Wave 6); Cline
// hooksEnabled (S-6).
//
// Since Wave 4 (lane w4-layers) a user row names its agentconfig FileRow
// (File), which the caller resolves with the row's relocation rules
// (CODEBUDDY_CONFIG_DIR, SNOWFLAKE_HOME, CORTEX_HOME, AUTOHAND_HOME,
// DIMCODE_HOME, DIRAC_DIR, CLAUDE_CONFIG_DIR; FU-38); rows whose file has no
// catalogue row (goose settings.json) still read the default home. Layer
// precedence between rows (a project false over a user true, Factory's
// most-local-wins defaults) is the effective-layer evaluator's
// (internal/agentconfig EvaluateLayers): Detect reports every switch that is
// set, the evaluator says which one the tool obeys.
var Switches = []Switch{
	{
		ID: "claude.disableAllHooks", Scope: ScopeUser, File: "claude-code/user-settings", HomeRel: ".claude/settings.json",
		Key: "disableAllHooks", Off: true, Tools: claudeUserReplayHosts,
		Effect:    "every Claude Code hook is off, including the hosts that replay Claude Code's user hook settings",
		Grounding: groundingConfigSurface + " (claude-code V18; finding 5); " + groundingSurfaceGap + " (S-8: Copilot reads only the repository files; W-3: cortex-code, kimchi)",
	},
	{
		ID: "claude.managed.disableAllHooks", Scope: ScopeManaged, ManagedFile: claudeManagedSettingsFile,
		Key: "disableAllHooks", Off: true, Tools: claudeUserReplayHosts,
		Effect:    "the managed policy turns every Claude Code hook off",
		Grounding: groundingConfigSurface + " (claude-code V18 managed scope; finding 6); " + groundingSurfaceGap + " (CC-5: the file and its drop-ins)",
	},
	{
		ID: "claude.managed.allowManagedHooksOnly", Scope: ScopeManaged, ManagedFile: claudeManagedSettingsFile,
		Key: "allowManagedHooksOnly", Off: true, Tools: claudeUserReplayHosts,
		Effect:    "the managed policy runs only managed hooks, so Observer's user-level hooks never run",
		Grounding: groundingConfigSurface + " (claude-code V18 managed allowManagedHooksOnly; finding 6); " + groundingSurfaceGap + " (CC-5)",
	},
	// Copilot CLI's disableAllHooks (FU-159) is a write-guard-only row in
	// every scope: Copilot CLI 1.0.105 kept running ~/.copilot/hooks with the
	// key true in ~/.copilot/settings.json and in the repo
	// .github/copilot/settings.json (Windows rig run 2026-10-29, also seen on
	// macOS), so no reader claims it turns hooks off, but R-162 / R-163 still
	// refuse an agent write that sets it (~/.copilot/config.json and later
	// versions are unverified, and the refusal costs nothing).
	{
		ID: "copilot-cli.disableAllHooks", Scope: ScopeUser, File: "copilot-cli/user-settings", HomeRel: ".copilot/settings.json",
		Key: "disableAllHooks", Off: true, Tools: []string{"copilot-cli"}, WriteGuardOnly: true,
		Effect:    "not honoured by Copilot CLI 1.0.105 for hooks (live 2026-10-29); writes still guarded",
		Grounding: groundingConfigSurface + " (copilot-cli V18); docs/handovers/surface-gap-windows-rig-run-2026-10-29.md (FU-159)",
	},
	{
		ID: "qwen.disableAllHooks", Scope: ScopeUser, File: "qwen-code/user-settings", HomeRel: ".qwen/settings.json",
		Key: "disableAllHooks", Off: true, Tools: []string{"qwen-code"},
		Effect:    "every Qwen Code hook is off",
		Grounding: groundingConfigSurface + " (qwen-code V18)",
	},
	{
		ID: "gemini.hooksConfig.enabled", Scope: ScopeUser, File: "gemini-cli/user-settings", HomeRel: ".gemini/settings.json",
		Key: "hooksConfig.enabled", Off: false, Tools: []string{"gemini-cli"},
		Effect:    "the Gemini CLI hook system is disabled",
		Grounding: groundingConfigSurface + " (gemini-cli V18; finding 6)",
	},
	{
		ID: "factory.hooksDisabled", Scope: ScopeUser, File: "droid/user-settings", HomeRel: ".factory/settings.json",
		Key: "hooksDisabled", Off: true, Tools: []string{"droid"},
		Effect:    "every Factory Droid hook is off",
		Grounding: groundingConfigSurface + " (droid; finding 6)",
	},
	{
		ID: "factory.userlocal.hooksDisabled", Scope: ScopeUser, File: "droid/user-local-settings", HomeRel: ".factory/settings.local.json",
		Key: "hooksDisabled", Off: true, Tools: []string{"droid"},
		Effect:    "every Factory Droid hook is off (user settings.local.json, which merges over settings.json)",
		Grounding: groundingConfigSurface + " (droid settings files: user-local merges on top; doc-grounded, not live-verified)",
	},
	// Factory's org layers (S-15, decision D17: a cached vendor policy file
	// may be read for doctor rows, never a credential). hooksDisabled is a
	// session default (most-local wins, so a user or project false can
	// override the org value); allowManagedHooksOnly is a hard control.
	{
		ID: "factory.managed.hooksDisabled", Scope: ScopeManaged, ManagedFile: factorySystemSettingsFile,
		Key: "hooksDisabled", Off: true, Tools: []string{"droid"},
		Effect:    "the org system settings turn every Factory Droid hook off, unless a user, project or folder settings file sets hooksDisabled false",
		Grounding: groundingLocationMatrix + " (Factory: org system file; session defaults, most-local wins); doc-grounded, not live-verified",
	},
	{
		ID: "factory.managed.allowManagedHooksOnly", Scope: ScopeManaged, ManagedFile: factorySystemSettingsFile,
		Key: "allowManagedHooksOnly", Off: true, Tools: []string{"droid"},
		Effect:    "the org system settings run only managed hooks, so Observer's user-level Factory Droid hooks never run",
		Grounding: groundingLocationMatrix + " (Factory: org system file, a hard control; CLI-5); doc-grounded, not live-verified",
	},
	{
		ID: "factory.orgcache.hooksDisabled", Scope: ScopeUser, File: "droid/org-managed-settings-cache", HomeRel: ".factory/org-managed-settings.cache.json",
		Key: "managedSettings.hooksDisabled", Off: true, Tools: []string{"droid"},
		Effect:    "the cached org policy from the Factory org endpoint turns every Factory Droid hook off, unless a user, project or folder settings file sets hooksDisabled false",
		Grounding: groundingLocationMatrix + " (Factory: org endpoint cache, live-grounded managedSettings.* shape); the hooksDisabled member under managedSettings is inferred, not live-verified",
	},
	{
		ID: "factory.orgcache.allowManagedHooksOnly", Scope: ScopeUser, File: "droid/org-managed-settings-cache", HomeRel: ".factory/org-managed-settings.cache.json",
		Key: "managedSettings.allowManagedHooksOnly", Off: true, Tools: []string{"droid"},
		Effect:    "the cached org policy from the Factory org endpoint runs only managed hooks, so Observer's user-level Factory Droid hooks never run",
		Grounding: groundingLocationMatrix + " (Factory: org endpoint cache carries the system file's keys); the member under managedSettings is inferred, not live-verified",
	},
	// CodeBuddy (W-3a): disableAllHooks in every settings scope.
	{
		ID: "codebuddy.disableAllHooks", Scope: ScopeUser, File: "codebuddy/user-settings", HomeRel: ".codebuddy/settings.json",
		Key: "disableAllHooks", Off: true, Tools: []string{"codebuddy"},
		Effect:    "every CodeBuddy Code hook is off",
		Grounding: groundingSurfaceGap + " (W-3a); https://www.codebuddy.cn/docs/cli/settings",
	},
	{
		ID: "codebuddy.userlocal.disableAllHooks", Scope: ScopeUser, File: "codebuddy/user-local-settings", HomeRel: ".codebuddy/settings.local.json",
		Key: "disableAllHooks", Off: true, Tools: []string{"codebuddy"},
		Effect:    "every CodeBuddy Code hook is off (user settings.local.json)",
		Grounding: groundingLocationMatrix + " (CodeBuddy user settings.json + settings.local.json); https://www.codebuddy.cn/docs/cli/settings",
	},
	// IBM Bob (W-3a): disableGlobalHooks, honoured until now only at
	// registration (internal/hook ibmBobSkip).
	{
		ID: "ibm-bob.disableGlobalHooks", Scope: ScopeUser, File: "ibm-bob/user-settings", HomeRel: ".bob/settings/settings.json",
		Key: "disableGlobalHooks", Off: true, Tools: []string{"ibm-bob"},
		Effect:    "IBM Bob runs no global hook, so Observer's user-level hooks never run",
		Grounding: groundingSurfaceGap + " (W-3a); docs/ibmbob-adapter.md (disableGlobalHooks turns the global hooks off)",
	},
	// Autohand (W-3a, decision D16): config.json also holds provider keys,
	// so only its hooks member is decoded.
	{
		ID: "autohand.hooks.enabled", Scope: ScopeUser, File: "autohand/user-config", HomeRel: ".autohand/config.json",
		Key: "hooks.enabled", Off: false, Tools: []string{"autohand"},
		Effect:    "the Autohand Code hook system is disabled",
		Grounding: groundingSurfaceGap + " (W-3a, D16 member-only read); https://docs.autohand.ai/docs-md/working-with-autohand-code/hooks.md",
	},
	// Cortex Code (W-3a).
	{
		ID: "cortex.disableAllHooks", Scope: ScopeUser, File: "cortex-code/user-settings", HomeRel: ".snowflake/cortex/settings.json",
		Key: "disableAllHooks", Off: true, Tools: []string{"cortex-code"},
		Effect:    "every Cortex Code hook is off",
		Grounding: groundingSurfaceGap + " (W-3a); https://docs.snowflake.com/en/user-guide/cortex-code/settings",
	},
	{
		ID: "cortex.hooks.disableAllHooks", Scope: ScopeUser, File: "cortex-code/user-hooks", HomeRel: ".snowflake/cortex/hooks.json",
		Key: "disableAllHooks", Off: true, Tools: []string{"cortex-code"},
		Effect:    "every Cortex Code hook is off (the global hooks.json)",
		Grounding: groundingSurfaceGap + " (W-3a); https://docs.snowflake.com/en/user-guide/cortex-code/cortex-code-desktop/hooks",
	},
	{
		ID: "cortex.home.disableAllHooks", Scope: ScopeUser, File: "cortex-code/home-settings", HomeRel: ".cortex/settings.json",
		Key: "disableAllHooks", Off: true, Tools: []string{"cortex-code"},
		Effect:    "every Cortex Code hook is off (~/.cortex/settings.json)",
		Grounding: groundingSurfaceGap + " (W-3a)",
	},
	// Dirac (W-3a): globalState.json holds provider settings, never
	// secrets (those are in secrets.json beside it, never opened).
	{
		ID: "dirac.hooksEnabled", Scope: ScopeUser, File: "dirac/global-state", HomeRel: ".dirac/data/globalState.json",
		Key: "hooksEnabled", Off: false, Tools: []string{"dirac"},
		Effect:    "the Dirac hook system is disabled",
		Grounding: groundingSurfaceGap + " (W-3a); " + groundingLocationMatrix + " (Dirac data settings, source-grounded state-keys.ts)",
	},
	// DimCode (W-3a, decision D5): `dim hooks disable` writes the hash of a
	// hook entry to a deny list; the list is read for membership only.
	{
		ID: "dimcode.hooks-disabled", Scope: ScopeUser, File: "dimcode/hooks-disabled", HomeRel: ".dimcode/v2/hooks-disabled.json",
		DenyList: denyDimCode, DenyHooksRel: ".dimcode/v2/hooks.json", DenyHooksFile: "dimcode/user-hooks",
		Key: "disabled", Tools: []string{"dimcode"},
		Effect:    "DimCode's hook deny list (`dim hooks disable`) names one or more of Observer's DimCode hooks, so DimCode skips them",
		Grounding: groundingSurfaceGap + " (W-3a, D5 hash-only membership read); hash and file shape read from the dimcode 0.5.21 bundle (agent/src/hooks/command/disabled.ts)",
	},
	// Command Code (S-18): mods.disableAll turns every mod off, Observer's
	// mod included.
	{
		ID: "command-code.mods.disableAll", Scope: ScopeUser, File: "command-code/user-settings", HomeRel: ".commandcode/settings.json",
		Key: "mods.disableAll", Off: true, Tools: []string{"command-code"},
		Effect:    "every Command Code mod is off, including Observer's mod (its session bridge, and the tool gate when the mod carries it)",
		Grounding: groundingSurfaceGap + " (S-18); https://commandcode.ai/docs/mods",
	},
	// goose (S-18): disabledPlugins lists plugins by name, in a settings
	// file under .config on every OS.
	{
		ID: "goose.disabledPlugins", Scope: ScopeUser, HomeRel: ".config/goose/settings.json",
		Key: "disabledPlugins", Contains: "superbased-observer", Tools: []string{"goose"},
		Effect:    "goose's disabledPlugins names Observer's plugin, so its hooks never run",
		Grounding: groundingLocationMatrix + " (goose discovery.rs user_settings_path); the bare plugin-name entry form is not live-verified, so another spelling is a missed finding, never a false one",
	},
	// Junie (S-13): the variable stops Junie loading its default config
	// locations, ~/.junie/config.json among them, which holds Observer's
	// hooks.
	{
		ID: "junie.JUNIE_CONFIG_DEFAULT_LOCATIONS", Scope: ScopeEnv,
		Key: "JUNIE_CONFIG_DEFAULT_LOCATIONS", EnvOff: "false", Tools: []string{"junie"},
		Effect:    "Junie skips its default config files, ~/.junie/config.json with Observer's hooks among them (read from this process's environment; a value set only in another shell is not seen)",
		Grounding: groundingSurfaceGap + " (S-13); https://junie.jetbrains.com/docs/environment-variables.html",
	},
	// Devin (S-10): read_config_from.claude=false stops Devin CLI replaying
	// Claude Code's hooks; Observer's own Devin hooks in config.json keep
	// running, hence ReplayOnly.
	{
		ID: "devin.read_config_from.claude", Scope: ScopeUser, File: "devin/user-config", HomeRel: ".config/devin/config.json",
		HomeRelOS: map[string]string{"windows": "AppData/Roaming/devin/config.json"},
		Key:       "read_config_from.claude", Off: false, Tools: []string{"devin"}, ReplayOnly: true,
		Effect:    "Devin CLI stops reading Claude Code's settings, so the Claude Code hooks Observer registers do not run in Devin; Observer's own Devin hooks are unaffected",
		Grounding: groundingSurfaceGap + " (S-10); https://docs.devin.ai/cli/reference/configuration/config-file",
	},
	// Wave 4 (lane w4-layers, CLI-5): the system (managed) layers of
	// Gemini CLI and Qwen Code, read for the same switch as the user file.
	{
		ID: "gemini.system.hooksConfig.enabled", Scope: ScopeManaged, ManagedFile: "gemini-cli/system-settings",
		Key: "hooksConfig.enabled", Off: false, Tools: []string{"gemini-cli"},
		Effect:    "the Gemini CLI system settings disable the hook system for every user of this machine",
		Grounding: groundingSurfaceGap + " (CLI-5: system layers); https://geminicli.com/docs/reference/configuration (system settings override user and workspace)",
	},
	{
		ID: "qwen.system.disableAllHooks", Scope: ScopeManaged, ManagedFile: "qwen-code/system-settings",
		Key: "disableAllHooks", Off: true, Tools: []string{"qwen-code"},
		Effect:    "the Qwen Code system settings turn every Qwen Code hook off for every user of this machine",
		Grounding: groundingSurfaceGap + " (CLI-5: system layers); " + groundingConfigSurface + " (qwen-code V18: system settings override)",
	},
	// Qwen Code's safe and bare modes skip hooks (CLI-5); the truthy
	// spellings are the common ones, not live-verified (live check 21).
	{
		ID: "qwen.QWEN_CODE_SAFE_MODE", Scope: ScopeEnv, Key: "QWEN_CODE_SAFE_MODE", EnvTruthy: true, Tools: []string{"qwen-code"},
		Effect:    "Qwen Code runs in safe mode and skips hooks, Observer's included (read from this process's environment)",
		Grounding: groundingSurfaceGap + " (CLI-5: --safe-mode / QWEN_CODE_SAFE_MODE); truthy spellings not live-verified",
	},
	{
		ID: "qwen.QWEN_CODE_SIMPLE", Scope: ScopeEnv, Key: "QWEN_CODE_SIMPLE", EnvTruthy: true, Tools: []string{"qwen-code"},
		Effect:    "Qwen Code runs bare (--bare) and skips hooks, Observer's included (read from this process's environment)",
		Grounding: groundingSurfaceGap + " (CLI-5: --bare / QWEN_CODE_SIMPLE); truthy spellings not live-verified",
	},
	// Command Code (S-18, FU-38): mods.disabled names a mod by its file name
	// without .ts; Observer's mod is observer-guard.ts. A disable in any
	// settings file wins.
	{
		ID: "command-code.mods.disabled", Scope: ScopeUser, File: "command-code/user-settings", HomeRel: ".commandcode/settings.json",
		Key: "mods.disabled", Contains: "observer-guard", Tools: []string{"command-code"},
		Effect:    "Command Code's mods.disabled names Observer's mod (observer-guard), so it never loads",
		Grounding: groundingSurfaceGap + " (S-18); https://commandcode.ai/docs/mods (mods.disabled: bare mod names, any settings file)",
	},
	// Kimchi (FU-51): `kimchi resources disable hooks.bash` writes
	// resources["hooks.bash"] = false into the harness settings; the org
	// FORCE_OFF lock lives server-side and is not read.
	{
		ID: "kimchi.resources.hooks.bash", Scope: ScopeUser, File: "kimchi/harness-settings", HomeRel: ".config/kimchi/harness/settings.json",
		Key: "resources.hooks.bash", KeyPath: []string{"resources", "hooks.bash"}, Off: false, Tools: []string{"kimchi"},
		Effect:    "Kimchi's hooks.bash resource is disabled, so Observer's bash pre-gate does not run",
		Grounding: groundingSurfaceGap + " (S-18, FU-51); getkimchi/kimchi src/resources/store.ts (setResourceOverride writes resources[id] = enabled into the harness settings.json; an org FORCE_ON / FORCE_OFF beats it)",
	},
	// Project scope (T-910, D-761). Claude Code reads disableAllHooks from
	// every settings scope (claude-code V18 "settings.json any scope"; the
	// schema text says user and project disableAllHooks yield only to a
	// managed one), and finding 5 names .claude/settings*.json as the files
	// the replay hosts read, so these rows silence the same hosts.
	{
		ID: "claude.project.disableAllHooks", Scope: ScopeProject, ProjectRel: ".claude/settings.json",
		Key: "disableAllHooks", Off: true, Tools: claudeProjectReplayHosts,
		Effect:    "the project's Claude Code settings turn every Claude Code hook off in this project, including the hosts that replay Claude Code's hook settings",
		Grounding: groundingConfigSurface + " (claude-code V18 any scope; finding 5)",
	},
	{
		ID: "claude.local.disableAllHooks", Scope: ScopeProject, ProjectRel: ".claude/settings.local.json",
		Key: "disableAllHooks", Off: true, Tools: claudeProjectReplayHosts,
		Effect:    "the project's local Claude Code settings (settings.local.json, usually not committed) turn every Claude Code hook off in this project, including the hosts that replay Claude Code's hook settings",
		Grounding: groundingConfigSurface + " (claude-code V18 any scope; finding 5)",
	},
	// Copilot CLI's repo and local files whitelist disableAllHooks; write
	// guard only (FU-159, the user-scope note above).
	{
		ID: "copilot-cli.project.disableAllHooks", Scope: ScopeProject, ProjectRel: ".github/copilot/settings.json",
		Key: "disableAllHooks", Off: true, Tools: []string{"copilot-cli"}, WriteGuardOnly: true,
		Effect:    "not honoured by Copilot CLI 1.0.105 for hooks (live 2026-10-29); writes still guarded",
		Grounding: groundingConfigSurface + " (copilot-cli settings files: repo whitelist includes disableAllHooks); docs/handovers/surface-gap-windows-rig-run-2026-10-29.md (FU-159)",
	},
	{
		ID: "copilot-cli.local.disableAllHooks", Scope: ScopeProject, ProjectRel: ".github/copilot/settings.local.json",
		Key: "disableAllHooks", Off: true, Tools: []string{"copilot-cli"}, WriteGuardOnly: true,
		Effect:    "not honoured by Copilot CLI 1.0.105 for hooks (live 2026-10-29); writes still guarded (the local file was not tested live)",
		Grounding: groundingConfigSurface + " (copilot-cli settings files: local whitelist includes disableAllHooks)",
	},
	{
		ID: "qwen.project.disableAllHooks", Scope: ScopeProject, ProjectRel: ".qwen/settings.json",
		Key: "disableAllHooks", Off: true, Tools: []string{"qwen-code"},
		Effect:    "the project's Qwen Code settings turn every Qwen Code hook off in this project",
		Grounding: groundingConfigSurface + " (qwen-code V18: settings.json user/workspace/system)",
	},
	{
		ID: "gemini.project.hooksConfig.enabled", Scope: ScopeProject, ProjectRel: ".gemini/settings.json",
		Key: "hooksConfig.enabled", Off: false, Tools: []string{"gemini-cli"},
		Effect:    "the project's Gemini CLI settings disable the hook system in this project",
		Grounding: groundingConfigSurface + " (gemini-cli V18; the schema puts no scope limit on hooksConfig and workspace settings load in a trusted folder)",
	},
	{
		ID: "factory.project.hooksDisabled", Scope: ScopeProject, ProjectRel: ".factory/settings.json",
		Key: "hooksDisabled", Off: true, Tools: []string{"droid"},
		Effect:    "the project's Factory settings turn every Factory Droid hook off in this project",
		Grounding: groundingConfigSurface + " (droid settings files: session defaults most-local wins; doc-grounded, not live-verified)",
	},
	{
		ID: "factory.local.hooksDisabled", Scope: ScopeProject, ProjectRel: ".factory/settings.local.json",
		Key: "hooksDisabled", Off: true, Tools: []string{"droid"},
		Effect:    "the project's local Factory settings turn every Factory Droid hook off in this project",
		Grounding: groundingConfigSurface + " (droid settings files: *.local.json merges on top of its level; doc-grounded, not live-verified)",
	},
	{
		ID: "codebuddy.project.disableAllHooks", Scope: ScopeProject, ProjectRel: ".codebuddy/settings.json",
		Key: "disableAllHooks", Off: true, Tools: []string{"codebuddy"},
		Effect:    "the project's CodeBuddy settings turn every CodeBuddy Code hook off in this project",
		Grounding: groundingSurfaceGap + " (W-3a: project scope); https://www.codebuddy.cn/docs/cli/settings",
	},
	{
		ID: "codebuddy.local.disableAllHooks", Scope: ScopeProject, ProjectRel: ".codebuddy/settings.local.json",
		Key: "disableAllHooks", Off: true, Tools: []string{"codebuddy"},
		Effect:    "the project's local CodeBuddy settings turn every CodeBuddy Code hook off in this project",
		Grounding: groundingSurfaceGap + " (W-3a: project-local scope); https://www.codebuddy.cn/docs/cli/settings",
	},
	{
		ID: "goose.project.disabledPlugins", Scope: ScopeProject, ProjectRel: ".config/goose/settings.json",
		Key: "disabledPlugins", Contains: "superbased-observer", Tools: []string{"goose"},
		Effect:    "the project's goose settings name Observer's plugin in disabledPlugins, so its hooks never run in this project",
		Grounding: groundingLocationMatrix + " (goose discovery.rs project settings); entry form not live-verified",
	},
	{
		ID: "goose.local.disabledPlugins", Scope: ScopeProject, ProjectRel: ".config/goose/settings.local.json",
		Key: "disabledPlugins", Contains: "superbased-observer", Tools: []string{"goose"},
		Effect:    "the project's local goose settings name Observer's plugin in disabledPlugins, so its hooks never run in this project",
		Grounding: groundingLocationMatrix + " (goose discovery.rs project settings.local.json); entry form not live-verified",
	},
	{
		ID: "devin.project.read_config_from.claude", Scope: ScopeProject, ProjectRel: ".devin/config.json",
		Key: "read_config_from.claude", Off: false, Tools: []string{"devin"}, ReplayOnly: true,
		Effect:    "the project's Devin config stops Devin CLI reading Claude Code's settings in this project, so the Claude Code hooks Observer registers do not run there; Observer's own Devin hooks are unaffected",
		Grounding: groundingSurfaceGap + " (S-10); the project file accepts read_config_from (agentconfig devin/project-config)",
	},
	{
		ID: "devin.local.read_config_from.claude", Scope: ScopeProject, ProjectRel: ".devin/config.local.json",
		Key: "read_config_from.claude", Off: false, Tools: []string{"devin"}, ReplayOnly: true,
		Effect:    "the project's local Devin config stops Devin CLI reading Claude Code's settings in this project, so the Claude Code hooks Observer registers do not run there; Observer's own Devin hooks are unaffected",
		Grounding: groundingSurfaceGap + " (S-10); agentconfig devin/project-local-config",
	},
	// Command Code's project and project-local settings (S-18).
	{
		ID: "command-code.project.mods.disableAll", Scope: ScopeProject, ProjectRel: ".commandcode/settings.json",
		Key: "mods.disableAll", Off: true, Tools: []string{"command-code"},
		Effect:    "the project's Command Code settings turn every mod off in this project, including Observer's mod",
		Grounding: groundingSurfaceGap + " (S-18); https://commandcode.ai/docs/mods (mods.disableAll in any settings file)",
	},
	{
		ID: "command-code.local.mods.disableAll", Scope: ScopeProject, ProjectRel: ".commandcode/settings.local.json",
		Key: "mods.disableAll", Off: true, Tools: []string{"command-code"},
		Effect:    "the project's local Command Code settings turn every mod off in this project, including Observer's mod",
		Grounding: groundingSurfaceGap + " (S-18); https://commandcode.ai/docs/mods",
	},
	{
		ID: "command-code.project.mods.disabled", Scope: ScopeProject, ProjectRel: ".commandcode/settings.json",
		Key: "mods.disabled", Contains: "observer-guard", Tools: []string{"command-code"},
		Effect:    "the project's Command Code settings name Observer's mod in mods.disabled (`cmd mods disable` writes here by default), so it never loads in this project",
		Grounding: groundingSurfaceGap + " (S-18); https://commandcode.ai/docs/mods",
	},
	{
		ID: "command-code.local.mods.disabled", Scope: ScopeProject, ProjectRel: ".commandcode/settings.local.json",
		Key: "mods.disabled", Contains: "observer-guard", Tools: []string{"command-code"},
		Effect:    "the project's local Command Code settings name Observer's mod in mods.disabled, so it never loads in this project",
		Grounding: groundingSurfaceGap + " (S-18); https://commandcode.ai/docs/mods",
	},
	// VT Code (W-6, FU-51): use_root_config = true in a workspace file drops
	// the system and user layers, Observer's user-level hook groups with them.
	{
		ID: "vtcode.workspace.use_root_config", Scope: ScopeProject, ProjectRel: ".vtcode/vtcode.toml", Format: FormatTOML,
		Key: "workspace.use_root_config", Off: true, Tools: []string{"vtcode"},
		Effect:    "the project's VT Code workspace file sets use_root_config, which drops the user layer and Observer's hook groups with it in this project",
		Grounding: groundingSurfaceGap + " (W-6, FU-51); vinhnx/vtcode docs/config/CONFIGURATION_PRECEDENCE.md (live check 19 owed)",
	},
	{
		ID: "vtcode.root.use_root_config", Scope: ScopeProject, ProjectRel: "vtcode.toml", Format: FormatTOML,
		Key: "workspace.use_root_config", Off: true, Tools: []string{"vtcode"},
		Effect:    "the project's root vtcode.toml sets use_root_config, which drops the user layer and Observer's hook groups with it in this project",
		Grounding: groundingSurfaceGap + " (W-6, FU-51); vinhnx/vtcode docs/config/CONFIGURATION_PRECEDENCE.md (live check 19 owed)",
	},
}
