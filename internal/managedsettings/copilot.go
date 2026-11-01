package managedsettings

// GitHub Copilot's managed layers (T-434): two products, two layers.
//
//   - Copilot in VS Code: VS Code enterprise POLICIES. A policy value
//     overrides the setting at every level and greys it out. The policy is
//     keyed by POLICY NAME, not by the setting id, so the layer renames each
//     setting through PolicyKeys (only settings with a documented policy).
//     Linux reads /etc/vscode/policy.json (VS Code 1.106+), Windows the ADMX
//     registry key, macOS a configuration profile.
//   - Copilot CLI: managed-settings.json plus MDM (com.github.copilot,
//     HKLM\SOFTWARE\Policies\GitHubCopilot), whose MDM values are flat
//     DOTTED key names holding string (JSON text) values. Mostly a baseline:
//     only some keys lock (PerSetting).
//
// GitHub.com org and enterprise Copilot policies are server-side and have no
// node file: they stay a link-out (plan section 6.2).

const (
	refVSCodePolicies    = "https://code.visualstudio.com/docs/enterprise/policies"
	refCopilotCLIDeploy  = "https://docs.github.com/en/copilot/how-tos/administer-copilot/manage-for-enterprise/use-managed-settings/deploy-managed-settings"
	refCopilotCLIManaged = "https://docs.github.com/en/enterprise-cloud@latest/copilot/reference/enterprise-administrators/enterprise-managed-settings"
)

// copilotPolicyNames maps a Copilot (VS Code) catalogue setting to its VS
// Code policy name, from the policy reference fetched 2026-10-06. A setting
// whose policy value type differs from the setting's (chat.mcp.access is a
// string policy over a boolean row; chat.agent.sandbox.enabled is a boolean
// policy over an on / off row), a policy-only setting the org policy cannot
// author (chat.defaultModel) and a second setting sharing one policy
// (chat.agentHost.claudeAgent.enabled) are left out on purpose: lever B
// still applies them.
var copilotPolicyNames = map[string]string{
	`copilot/"chat.agent.enabled"`:                         "ChatAgentMode",
	`copilot/"chat.extensionTools.enabled"`:                "ChatAgentExtensionTools",
	`copilot/"chat.tools.global.autoApprove"`:              "ChatToolsAutoApprove",
	`copilot/"chat.tools.eligibleForAutoApproval"`:         "ChatToolsEligibleForAutoApproval",
	`copilot/"chat.tools.terminal.enableAutoApprove"`:      "ChatToolsTerminalEnableAutoApprove",
	`copilot/"chat.agent.networkFilter"`:                   "ChatAgentNetworkFilter",
	`copilot/"chat.plugins.enabled"`:                       "ChatPluginsEnabled",
	`copilot/"github.copilot.chat.claudeAgent.enabled"`:    "Claude3PIntegration",
	`copilot/"chat.agentHost.codexAgent.enabled"`:          "Codex3PIntegration",
	`copilot/"github.copilot.nextEditSuggestions.enabled"`: "CopilotNextEditSuggestions",
	`copilot/"github.copilot.chat.otel.enabled"`:           "CopilotOtelEnabled",
	`copilot/"github.copilot.chat.otel.otlpEndpoint"`:      "CopilotOtelEndpoint",
	`copilot/"extensions.allowed"`:                         "AllowedExtensions",
	`copilot/"telemetry.telemetryLevel"`:                   "TelemetryLevel",
	`copilot/"telemetry.feedback.enabled"`:                 "EnableFeedback",
	`copilot/"update.mode"`:                                "UpdateMode",
}

var copilotLayers = []Layer{
	{
		FileID: "copilot/policy", Modes: enforced, Strength: StrengthTamperProof, PolicyKeys: copilotPolicyNames,
		Profile:  &ProfileChannel{Domain: "com.microsoft.VSCode", Mode: ProfileKeysScalarJSON},
		Registry: &RegistryChannel{Key: `SOFTWARE\Policies\Microsoft\VSCode`, Mode: RegistryValues},
		Sources:  []string{refVSCodePolicies}, Verified: false,
		Note: "VS Code policies override the setting at every level and grey it out. The Linux policy.json and the Windows key are documented; " +
			"the per-value registry types (a boolean as a DWORD) and the macOS profile domain com.microsoft.VSCode (VS Code's bundle id) are " +
			"inferred: the ADMX and the .mobileconfig template shipped inside VS Code are the reference, so check one machine first.",
	},
	{
		FileID: "copilot-cli/managed-settings", Modes: enforced, Strength: StrengthDefaultOnly,
		PerSetting: map[string]Strength{
			"copilot-cli/permissions.disableBypassPermissionsMode": StrengthTamperProof,
			"copilot-cli/autoTier":                                 StrengthTamperProof,
			"copilot-cli/shellShortcut":                            StrengthTamperProof,
			"copilot-cli/enabledPlugins":                           StrengthTamperProof,
			"copilot-cli/sandbox.":                                 StrengthRestrictOnly,
		},
		Profile:  &ProfileChannel{Domain: "com.github.copilot", Mode: ProfileDottedStrings},
		Registry: &RegistryChannel{Key: `SOFTWARE\Policies\GitHubCopilot`, Mode: RegistryDottedStrings},
		Sources:  []string{refCopilotCLIDeploy, refCopilotCLIManaged}, Verified: true,
		Note: "Copilot CLI managed settings are mostly a baseline below the user's settings: the bypass-permissions switch, autoTier, the shell " +
			"shortcut and enabled plugins lock; sandbox settings only restrict (most restrictive across sources); a model is a default the user " +
			"can change per conversation. MDM values are flat dotted names holding strings (JSON text for lists and objects); the same " +
			"com.github.copilot / GitHubCopilot policy also reaches Copilot in VS Code. POSIX files must be root-owned, not group- or " +
			"world-writable, and not a symlink. Hooks are not a managed key: Copilot CLI 1.0.105 ignored disableAllHooks there (MAC-6, FU-196), as " +
			"GitHub's key list (re-fetched 2026-10-30) has no hooks entry, so this layer cannot turn a node's hooks off.",
	},
}
