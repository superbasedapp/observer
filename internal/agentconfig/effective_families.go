package agentconfig

// effectiveFamilies is the ONE owner of the tools' own setting-family rules
// (surface-gap Wave 0.5 seeded claude-code/env; Wave 4 lane w4-layers added
// the rest with their observation producer, effective_layers.go, and the
// I/O boundary, internal/agentconfigsvc.EffectiveLayers).
//
// A family names only files that exist as catalogue rows of its tool and
// shape: a layer the catalogue lacks (VS Code profile settings, Vibe's
// project hooks.toml, crush's system and data-dir files, the .crush.json
// spelling) is not observed, and the gap is recorded in the lane report
// rather than guessed here. Every family's classes come from its
// classifier (familyClassifiers); TestFamiliesWellFormed pins both.
var effectiveFamilies = append([]Family{
	{
		// Claude Code's env block: managed > --settings > local > project >
		// user, merged per variable; and any variable the launch
		// environment already sets ignores every settings file. This is
		// why a desktop session that sets ANTHROPIC_BASE_URL itself never
		// sees a settings-file route. Only the route variable is observed:
		// the env block also carries credentials, which are never
		// classified.
		ID: "claude-code/env", Tool: "claude-code", Shape: "claude-code/settings",
		Key: KeyPath{"env"}, Policy: PolicyMapMerge, Members: []string{"ANTHROPIC_BASE_URL"},
		Classes:      urlClasses,
		RuntimeRanks: map[RuntimeLayer]int{RuntimeCLIFlag: 50, RuntimeLaunchEnv: 1000},
		Override:     []RuntimeLayer{RuntimeLaunchEnv},
		Concern:      ConcernRoute, ObserverClass: classLoopback,
		Grounding: Grounding{
			Kind: GroundDoc, Date: "2026-10-25",
			Source: "https://code.claude.com/docs/en/settings-reference (a settings-file env value is ignored for a variable the launch environment sets); https://code.claude.com/docs/en/settings (precedence); surface-gap review CC-1, CC-4",
		},
		Note: "Classes: loopback = Observer's local proxy, vendor_host = the vendor's own API host, other_host = any other URL, value = a non-URL value.",
	},
	{
		// CC-4 / CLI-5: disableAllHooks in any scope; a project file beats the
		// user file and only a managed one beats a project file.
		ID: "claude-code/disableAllHooks", Tool: "claude-code", Shape: "claude-code/settings",
		Key: KeyPath{"disableAllHooks"}, Policy: PolicyHighestWins, Classes: switchClasses,
		RuntimeRanks: map[RuntimeLayer]int{RuntimeCLIFlag: 50},
		Concern:      ConcernHooksOff, ObserverClass: classOn, OffClass: classOff,
		Grounding: Grounding{
			Kind: GroundDoc, Date: "2026-10-25",
			Source: "https://code.claude.com/docs/en/settings (precedence; disableAllHooks); https://code.claude.com/docs/en/hooks; surface-gap review CC-4",
		},
	},
	// No copilot-cli/disableAllHooks family (FU-159): Copilot CLI 1.0.105
	// did not honour it for hooks (live 2026-10-29), so classifying it as a
	// hooks-off switch would report a silencing that does not happen.
	{
		ID: "qwen-code/disableAllHooks", Tool: "qwen-code", Shape: "qwen-code/settings",
		Key: KeyPath{"disableAllHooks"}, Policy: PolicyHighestWins, Classes: switchClasses,
		Concern: ConcernHooksOff, ObserverClass: classOn, OffClass: classOff,
		Grounding: Grounding{
			Kind: GroundDoc, Date: "2026-10-25",
			Source: "docs/audits/adapter-config-surface-2026-10-03.md (qwen-code V18: system-defaults < user < workspace < system); surface-gap review CLI-5 (live check 21 owed)",
		},
	},
	{
		ID: "gemini-cli/hooksConfig.enabled", Tool: "gemini-cli", Shape: "gemini-cli/settings",
		Key: KeyPath{"hooksConfig", "enabled"}, Policy: PolicyHighestWins, Classes: switchClasses,
		Concern: ConcernHooksOff, ObserverClass: classOn, OffClass: classOff,
		Grounding: Grounding{
			Kind: GroundDoc, Date: "2026-10-25",
			Source: "https://geminicli.com/docs/reference/configuration (system-defaults < user < workspace < system; hooksConfig); surface-gap review CLI-5 (live check 21 owed)",
		},
		Note: "enabled=false is classified off, enabled=true on.",
	},
	{
		// Factory's hooksDisabled is a session default: the most local file
		// wins, so the org system file (precedence 100 for its hard
		// controls) ranks below every user and project file for this key.
		ID: "droid/hooksDisabled", Tool: "droid", Shape: "droid/settings",
		Key: KeyPath{"hooksDisabled"}, Policy: PolicyHighestWins, Classes: switchClasses,
		FileRanks: map[string]int{"droid/system-settings": 5},
		Concern:   ConcernHooksOff, ObserverClass: classOn, OffClass: classOff,
		Grounding: Grounding{
			Kind: GroundDoc, Date: "2026-10-25",
			Source: "docs/audits/surface-settings-location-matrix-2026-10-25.md (Factory: session defaults, most-local wins; allowManagedHooksOnly is the hard control); FU-38",
		},
	},
	{
		ID: "codebuddy/disableAllHooks", Tool: "codebuddy", Shape: "codebuddy/settings",
		Key: KeyPath{"disableAllHooks"}, Policy: PolicyHighestWins, Classes: switchClasses,
		Concern: ConcernHooksOff, ObserverClass: classOn, OffClass: classOff,
		Grounding: Grounding{
			Kind: GroundDoc, Date: "2026-10-25",
			Source: "https://www.codebuddy.cn/docs/cli/settings (user < user local < project < project local < managed); surface-gap review W-3a",
		},
	},
	{
		// Command Code: a disable in any settings file wins (deny_wins).
		ID: "command-code/mods.disableAll", Tool: "command-code", Shape: "command-code/settings",
		Key: KeyPath{"mods", "disableAll"}, Policy: PolicyDenyWins, Classes: switchClasses, DenyClass: classOff,
		Concern: ConcernHooksOff, ObserverClass: classOn, OffClass: classOff,
		Grounding: Grounding{
			Kind: GroundDoc, Date: "2026-10-26",
			Source: "https://commandcode.ai/docs/mods (mods.disableAll in any settings file; a disable wins); surface-gap review S-18",
		},
	},
	{
		ID: "command-code/mods.disabled", Tool: "command-code", Shape: "command-code/settings",
		Key: KeyPath{"mods", "disabled"}, Policy: PolicyDenyWins, Classes: switchClasses, DenyClass: classOff,
		Concern: ConcernHooksOff, ObserverClass: classOn, OffClass: classOff,
		Grounding: Grounding{
			Kind: GroundDoc, Date: "2026-10-26",
			Source: "https://commandcode.ai/docs/mods (mods.disabled lists mod names without .ts, in the user, project and project local settings; an entry in any keeps the mod off); FU-38",
		},
		Note: "off = the list names Observer's mod (observer-guard); on = a list without it.",
	},
	// --- routes (CLI-2, OBS-9)
	{
		ID: "qwen-code/model.baseUrl", Tool: "qwen-code", Shape: "qwen-code/settings",
		Key: KeyPath{"model", "baseUrl"}, Policy: PolicyHighestWins, Classes: urlClasses,
		Concern: ConcernRoute, ObserverClass: classLoopback,
		Grounding: Grounding{
			Kind: GroundDoc, Date: "2026-10-25",
			Source: "QwenLM/qwen-code docs/cli/configuration settings.md (project .qwen/settings.json beats user); surface-gap review CLI-2",
		},
	},
	{
		ID: "crush/providers.openai.base_url", Tool: "crush", Shape: "crush/config-json",
		Key: KeyPath{"providers", "openai", "base_url"}, Policy: PolicyHighestWins, Classes: urlClasses,
		Concern: ConcernRoute, ObserverClass: classLoopback,
		Grounding: Grounding{
			Kind: GroundDoc, Date: "2026-10-25",
			Source: "charmbracelet/crush internal/config/load.go (project crush.json beats the global file); surface-gap review CLI-2 (live check 22 owed)",
		},
		Note: "The project .crush.json spelling, the data-dir crush.json and /etc/crush/crush.json have no catalogue row, so they are not observed.",
	},
	{
		// opencode: a config-file baseURL beats OPENAI_BASE_URL (the AI SDK's
		// loadOptionalSetting gives the setting first), and
		// OPENCODE_CONFIG_CONTENT is merged over every file but the managed
		// one. The launcher puts Observer's route in OPENCODE_CONFIG_CONTENT
		// so a project file cannot shadow it.
		ID: "opencode/provider.openai.options.baseURL", Tool: "opencode", Shape: "opencode/config",
		Key: KeyPath{"provider", "openai", "options", "baseURL"}, Policy: PolicyHighestWins, Classes: urlClasses,
		RuntimeRanks: map[RuntimeLayer]int{RuntimeLaunchEnv: 1, RuntimeConfigContent: 90},
		Concern:      ConcernRoute, ObserverClass: classLoopback,
		Grounding: Grounding{
			Kind: GroundDoc, Date: "2026-10-25",
			Source: "https://opencode.ai/docs/config (precedence: global < project < OPENCODE_CONFIG_CONTENT < managed); Vercel AI SDK loadOptionalSetting (setting before env); surface-gap review CLI-2, CLI-3",
		},
		Note: "launch_env is OPENAI_BASE_URL, config_content is OPENCODE_CONFIG_CONTENT; both are read from the injected environment only.",
	},
	{
		// aider: launch env < the .env files it loads with override=True <
		// openai-api-base in .aider.conf.yml (which aider writes back into
		// OPENAI_API_BASE after parsing).
		ID: "aider/openai-api-base", Tool: "aider", Shape: "aider/conf",
		Key: KeyPath{"openai-api-base"}, Policy: PolicyHighestWins, Classes: urlClasses,
		RuntimeRanks: map[RuntimeLayer]int{RuntimeLaunchEnv: 5, RuntimeDotenv: 10},
		Concern:      ConcernRoute, ObserverClass: classLoopback,
		Grounding: Grounding{
			Kind: GroundDoc, Date: "2026-10-25",
			Source: "Aider-AI/aider aider/main.py (load_dotenv override=True over ~/.env, <git root>/.env, ./.env; args.openai_api_base rewrites OPENAI_API_BASE); surface-gap review CLI-7",
		},
	},
	// --- the active provider (CLI-3)
	{
		ID: "crush/models.large.provider", Tool: "crush", Shape: "crush/config-json",
		Key: KeyPath{"models", "large", "provider"}, Policy: PolicyHighestWins, Classes: providerClasses,
		Concern: ConcernProvider, ObserverClass: classRouted,
		Grounding: Grounding{
			Kind: GroundDoc, Date: "2026-10-25",
			Source: "charmbracelet/crush internal/config (models.large.provider selects the provider the large model talks to); surface-gap review CLI-3",
		},
		Note: "routed = openai, the provider Observer's crush route writes.",
	},
	{
		ID: "qwen-code/security.auth.selectedType", Tool: "qwen-code", Shape: "qwen-code/settings",
		Key: KeyPath{"security", "auth", "selectedType"}, Policy: PolicyHighestWins, Classes: providerClasses,
		Concern: ConcernProvider, ObserverClass: classRouted,
		Grounding: Grounding{
			Kind: GroundDoc, Date: "2026-10-25",
			Source: "QwenLM/qwen-code settings.md (security.auth.selectedType: openai, qwen-oauth, ...); surface-gap review CLI-3 (whether qwen-oauth honours model.baseUrl is live check 21)",
		},
		Note: "routed = openai; unverified = qwen-oauth (live check 21); other = any other type.",
	},
	// --- sign-in modes that pin the vendor host (CLI-6)
	{
		ID: "gemini-cli/security.auth.selectedType", Tool: "gemini-cli", Shape: "gemini-cli/settings",
		Key: KeyPath{"security", "auth", "selectedType"}, Policy: PolicyHighestWins, Classes: authClasses,
		Concern: ConcernAuth, ObserverClass: classAPIKey,
		Grounding: Grounding{
			Kind: GroundDoc, Date: "2026-10-25",
			Source: "google-gemini/gemini-cli packages/cli/src/config/settings.ts (security.auth.selectedType); integration.go gemini-cli row (Google sign-in and Code Assist ignore GOOGLE_GEMINI_BASE_URL); surface-gap review CLI-6",
		},
	},
	{
		ID: "gemini-cli/security.auth.enforcedType", Tool: "gemini-cli", Shape: "gemini-cli/settings",
		Key: KeyPath{"security", "auth", "enforcedType"}, Policy: PolicyHighestWins, Classes: authClasses,
		Concern: ConcernAuth, ObserverClass: classAPIKey,
		Grounding: Grounding{
			Kind: GroundDoc, Date: "2026-10-25",
			Source: "google-gemini/gemini-cli settings.ts (security.auth.enforcedType, set by an administrator in the system file); surface-gap review CLI-6",
		},
	},
	// --- VT Code (W-6): arrays replace, use_root_config drops layers
	{
		ID: "vtcode/workspace.use_root_config", Tool: "vtcode", Shape: "vtcode/config",
		Key: KeyPath{"workspace", "use_root_config"}, Policy: PolicyHighestWins, Classes: switchClasses,
		Concern: ConcernLayerDrop, OffClass: classOn, DropScopes: []Scope{ScopeSystem, ScopeUser},
		Grounding: Grounding{
			Kind: GroundSchema, Date: "2026-10-25",
			Source: "vinhnx/vtcode docs/config/CONFIGURATION_PRECEDENCE.md and vtcode-config layers.rs (use_root_config drops the system and user layers); surface-gap review W-6 (live check 19 owed)",
		},
		Note: "on = use_root_config true.",
	},
	vtcodeHookFamily("pre_tool_use"),
	vtcodeHookFamily("user_prompt_submit"),
	// --- Stakpak MCP (S-22): first file wins, whole
	{
		ID: "stakpak/mcp", Tool: "stakpak", Shape: "stakpak/mcp",
		Key: KeyPath{DocumentKey}, Policy: PolicyFirstFileWins, Classes: []string{classPresent},
		Concern: ConcernMCP,
		Grounding: Grounding{
			Kind: GroundDoc, Date: "2026-10-25",
			Source: "docs/audits/surface-settings-location-matrix-2026-10-25.md Part 7 (Stakpak resolves MCP configuration first-file-wins, not merged); surface-gap review S-22",
		},
		Note: "The search order is the catalogue's precedence, highest first: only that file is read.",
	},
	// --- IDE-3: VS Code hands Claude Code its environment
	{
		ID: "copilot/claudeCode.environmentVariables", Tool: "copilot", Shape: "copilot/vscode-settings",
		Key: KeyPath{"claudeCode.environmentVariables"}, Policy: PolicyArrayReplace, Classes: append([]string{classUnset}, urlClasses...),
		Concern: ConcernIDERoute, ObserverClass: classLoopback,
		Grounding: Grounding{
			Kind: GroundDoc, Date: "2026-10-25",
			Source: "https://code.claude.com/docs/en/vs-code (claudeCode.environmentVariables, user and workspace scope); VS Code settings precedence (workspace replaces user); surface-gap review IDE-3 (whether it beats ~/.claude/settings.json env is live check 3)",
		},
		Note: "VS Code settings rows are catalogued under copilot (one owner of the VS Code settings files). The class is ANTHROPIC_BASE_URL's in the array; unset = no such entry. Profile settings files have no catalogue row.",
	},
}, ibmBobPolicyFamilies()...)

// ibmBobPolicyFamilies is one family per IBM Bob policy key the catalogue
// records (the ibm-bob/policy SettingRows), FU-105: Bob reads its policy
// through CFPreferences on macOS, so the user's own com.ibm.bob domain
// (RuntimeUserPrefs) feeds the same key as the MDM plists
// (RuntimeManagedPrefs) and the Linux /etc/bob/policy.json row. On Windows
// (FU-115) the HKCU policy key is RuntimeUserPrefs and the HKLM key
// RuntimeManagedPrefs. Any
// user-set key is a ConcernUserPolicy finding, whichever source wins: the
// user domain cannot be locked against the user. Both runtime trees are read
// by internal/hook (PolicyDomainLayers), key names only.
func ibmBobPolicyFamilies() []Family {
	var out []Family
	for _, r := range ibmBobSettings {
		if r.FileID != bobPolicy || len(r.Path) != 1 {
			continue
		}
		// FU-206: EnforcedHooks' Windows precedence is live-grounded (the
		// FU-177 GUI run); every other key's is not verified live.
		windows := "which one Bob applies when both set a key is not verified live."
		if r.Path[0] == "EnforcedHooks" {
			windows = "Bob 2.3.0 takes EnforcedHooks from HKLM whenever HKLM sets it, even as {}, and reads HKCU only when HKLM has no value (FU-177 Windows GUI run, 2026-10-30, docs/handovers/surface-gap-windows-fu177-run-2026-10-29.md section 3)."
		}
		out = append(out, Family{
			ID: "ibm-bob/policy." + r.Path[0], Tool: "ibm-bob", Shape: bobPolicy,
			Key: KeyPath{r.Path[0]}, Policy: PolicyHighestWins, Classes: []string{classSet},
			RuntimeRanks: map[RuntimeLayer]int{RuntimeUserPrefs: 10, RuntimeManagedPrefs: 1000},
			Concern:      ConcernUserPolicy,
			Grounding: Grounding{
				Kind: GroundLive, Date: "2026-10-27",
				Source: "docs/handovers/surface-gap-mac4-report.md item 4 (Bob Shell 2.0.6 vscode-policy-watcher on macOS returned a `defaults write com.ibm.bob` value as policy, scripts/bob6.sh); docs/handovers/surface-gap-windows-rig-run-2026-10-29.md (FU-115: Bob 2.2.3 on Windows applies EnforcedHooks from HKCU as well as HKLM); bob.ibm.com group-policies page; CFPreferences forced-value precedence",
			},
			Note: "macOS: managed_prefs = /Library/Managed Preferences[/<user>]/com.ibm.bob.plist (root-owned only); user_prefs = ~/Library/Preferences/com.ibm.bob.plist. A managed value is expected to beat a user one (CFPreferences forced precedence), not verified live on Bob. " +
				"Windows: managed_prefs = HKLM\\SOFTWARE\\Policies\\IBM\\Bob; user_prefs = HKCU\\Software\\Policies\\IBM\\Bob (user-writable where the user can write HKCU\\Software\\Policies); " + windows,
		})
	}
	return out
}

// vtcodeHookFamily is VT Code's [[hooks.lifecycle.<event>]] array: the
// highest layer that defines it wins whole, so an empty one drops Observer's
// group.
func vtcodeHookFamily(event string) Family {
	return Family{
		ID: "vtcode/hooks.lifecycle." + event, Tool: "vtcode", Shape: "vtcode/config",
		Key: KeyPath{"hooks", "lifecycle", event}, Policy: PolicyArrayReplace, Classes: hookArrayClasses,
		Concern: ConcernHookArray, ObserverClass: classWithObserver,
		Grounding: Grounding{
			Kind: GroundSchema, Date: "2026-10-25",
			Source: "vinhnx/vtcode vtcode-config 0.141.12 layers.rs, merge.rs (arrays are replaced, not merged); surface-gap review W-6 (live check 19 owed on 0.180.2)",
		},
	}
}

// Families returns the effective-layer families (a copy).
func Families() []Family { return append([]Family(nil), effectiveFamilies...) }

// FamilyByID returns one family.
func FamilyByID(id string) (Family, bool) {
	for _, f := range effectiveFamilies {
		if f.ID == id {
			return f, true
		}
	}
	return Family{}, false
}
