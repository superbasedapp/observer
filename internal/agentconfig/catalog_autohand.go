package agentconfig

// Autohand Code CLI (npm autohand-cli), doc-authored (surface-gap lane
// w4-catalog). Sources: location matrix Part 7 section 1 (vendor
// src/constants.ts, src/config.ts, docs/config-reference.md and the hooks
// page) and docs/autohand-adapter.md.
//
// THE CREDENTIAL RULE (D9): the user config file holds provider API keys,
// auth.token and api.companySecret beside the settings, so it is PrivNever:
// its rows come from the vendor docs and source only and nothing in this
// package reads it. Observer's hook writer splices only the hooks member
// under the declared credential-file exception (D-268,
// integration credFileAutohand); internal/hookdisable reads only
// hooks.enabled (D16).
const (
	autohandConfigRef = "https://raw.githubusercontent.com/autohandai/code-cli/main/src/config.ts"
	autohandConstRef  = "https://raw.githubusercontent.com/autohandai/code-cli/main/src/constants.ts"
	autohandRefDoc    = "https://raw.githubusercontent.com/autohandai/code-cli/main/docs/config-reference.md"
	autohandHooksRef  = "https://docs.autohand.ai/docs-md/working-with-autohand-code/hooks.md"
	autohandSyncRef   = "https://raw.githubusercontent.com/autohandai/code-cli/main/src/sync/SyncService.ts"
	autohandShape     = "autohand/config"
)

var autohandFiles = []FileRow{
	{
		ID: "autohand/user-config", Tool: "autohand", Shape: autohandShape, Kind: KindSettings, Scope: ScopeUser,
		Paths: samePath("~/.autohand/config.json"), Format: FormatJSON, Precedence: 20, WriteNeeds: PrivNever,
		Grounding: waveSource(autohandConfigRef),
		Note: "Holds provider API keys, auth.token and api.companySecret: never read by anything here; rows come from vendor docs and source only. " +
			"Search order (first match wins, two is an error): --config, AUTOHAND_CONFIG, then $AUTOHAND_HOME/config.toml, config.yaml, config.yml, config.json; " +
			"only the json spelling is catalogued. Settings Sync replaces the whole file except auth and mcp when the cloud copy is newer (SyncService.ts). " +
			"Observer's hook writer splices only hooks.hooks[] (credential-file exception D-268).",
	},
	{
		ID: "autohand/project-config", Tool: "autohand", Shape: autohandShape, Kind: KindSettings, Scope: ScopeProjectShared,
		Paths: samePath("<project>/.autohand/config.json"), Format: FormatJSON, Precedence: 30, WriteNeeds: PrivUser,
		Grounding: waveDoc(autohandRefDoc),
		Note: "Project overlay (config.ts loadProjectConfigOverlay): only hooks and mcp are kept, both trust-gated (trust in $AUTOHAND_HOME/trusted-workspaces.json). " +
			"Its entries are APPENDED to the user lists; a same-id entry replaces the user one. config.toml / config.yaml / config.yml are also read.",
	},
	{
		ID: "autohand/project-local", Tool: "autohand", Shape: autohandShape, Kind: KindSettings, Scope: ScopeProjectLocal,
		Paths: samePath("<project>/.autohand/settings.local.json"), Format: FormatJSON, Precedence: 40, WriteNeeds: PrivUser,
		Grounding: waveSource(autohandConfigRef),
		Note: "Workspace settings (config.ts mergeWorkspaceSettings): provider, model, hooks, mcp, permissions and more, above the project overlay. " +
			"Whether it may carry a provider key like the user file is unverified. Precedence above it: environment variables, then --profile, then --set (one run).",
	},
	{
		ID: "autohand/trusted-workspaces", Tool: "autohand", Shape: "autohand/trusted-workspaces", Kind: KindToolState, Scope: ScopeUser,
		Paths: samePath("~/.autohand/trusted-workspaces.json"), Format: FormatJSON, Precedence: 0, WriteNeeds: PrivNever,
		Grounding: waveDoc(autohandRefDoc), Note: "Workspace trust the CLI records; shown, never form-edited.",
	},
}

var autohandSettings = waveRows("autohand", autohandShape, autohandConfigRef, []SettingRow{
	{
		Path: KeyPath{"provider"}, Type: TypeString, Scopes: []Scope{ScopeUser, ScopeProjectLocal},
		Desc: "Active provider (autohandai, openrouter, anthropic, openai, ollama, ...). AUTOHAND_PROVIDER overrides it per process.",
	},
	{Path: KeyPath{"model"}, Type: TypeString, Scopes: []Scope{ScopeUser, ScopeProjectLocal}, Desc: "Model id for the active provider."},
	{
		Path: KeyPath{"autohandai", "baseUrl"}, Type: TypeString, Scopes: []Scope{ScopeUser, ScopeProjectLocal}, Danger: DangerConfirm,
		Desc: "Base URL of the hosted autohandai provider.", Source: "docs/autohand-adapter.md (Integration findings)",
		Note: "AUTOHAND_AI_BASE_URL overrides it for one run. A base URL redirects inference.",
	},
	{
		Path: KeyPath{"openrouter", "baseUrl"}, Type: TypeString, Scopes: []Scope{ScopeUser, ScopeProjectLocal}, Danger: DangerConfirm,
		Desc: "Base URL of the openrouter provider block.", Source: "docs/autohand-adapter.md (Integration findings)",
		Note: "Every provider block takes a baseUrl (anthropic, openai, ollama, llamacpp, mlx, llmgateway, azure, zai, sakana, vertexai, xai, cerebras, nvidia, deepseek, bedrock).",
	},
	{
		Path: KeyPath{"customProviders"}, Type: TypeObject, Scopes: []Scope{ScopeUser, ScopeProjectLocal}, Danger: DangerConfirm,
		Desc: "Custom providers by id, each with a baseUrl.", Note: "A base URL redirects inference.",
	},
	{
		Path: KeyPath{"api", "baseUrl"}, Type: TypeString, Scopes: []Scope{ScopeUser}, Danger: DangerConfirm,
		Desc: "Autohand control-plane API base URL.", Note: "AUTOHAND_API_URL overrides it. Control plane, not inference (docs/autohand-adapter.md).",
	},
	{
		Path: KeyPath{"api", "companySecret"}, Type: TypeString, Scopes: []Scope{ScopeUser}, Secret: true,
		Desc: "Company secret for the Autohand API.", Source: "internal/integration/credentialfile.go (credFileAutohand, hook probe 2026-10-21)",
		Note: "A plaintext credential.",
	},
	{
		Path: KeyPath{"auth"}, Type: TypeObject, Scopes: []Scope{ScopeUser}, Secret: true, Owner: OwnerToolState,
		Desc: "Sign-in state, auth.token included.", Source: "internal/integration/credentialfile.go (credFileAutohand, hook probe 2026-10-21)",
		Note: "A plaintext credential; Settings Sync never replaces it.",
	},
	{
		Path: KeyPath{"hooks", "enabled"}, Type: TypeBool, Source: autohandHooksRef,
		Desc: "Run the hook system.", Danger: DangerRefuseWhileIntegrated,
		Note: "false switches Observer's hooks off; the internal/hookdisable row autohand.hooks.enabled reads only this member (D16). --bare skips ambient hooks for one run.",
	},
	{
		Path: KeyPath{"hooks", "hooks"}, Type: TypeObject, Source: autohandHooksRef,
		Desc: "Hook list: [{event, command, description, enabled, timeout (ms), matcher, filter, async}]; exit code 2 blocks.",
		Note: "An ARRAY, not a map. Observer's pre-tool and pre-prompt entries live here (internal/hook/register_wave1021_config.go); workspace entries are appended, a same-id one replaces the user one.",
	},
	{
		Path: KeyPath{"mcp", "enabled"}, Type: TypeBool, Desc: "Use MCP servers.", Source: autohandRefDoc,
	},
	{
		Path: KeyPath{"mcp", "servers"}, Type: TypeObject, Source: "docs/autohand-adapter.md (Integration findings)",
		Desc: "MCP server list: [{name, transport: stdio | sse | http, command | url, ...}] (an array, not the mcpServers map).",
		Note: "Managed with `autohand mcp add|remove`; --mcp-config <path> loads another file (merge vs replace unverified). Settings Sync keeps it.",
	},
	{
		Path: KeyPath{"permissions"}, Type: TypeObject, Scopes: []Scope{ScopeUser, ScopeProjectLocal}, Danger: DangerConfirm,
		Desc: "Tool permission settings.", Verified: VerifiedUnverified,
		Note: "Named by the matrix for settings.local.json (config.ts mergeWorkspaceSettings); the inner keys are not grounded.",
	},
})

var autohandCatalog = toolCatalog{
	Tool: "autohand",
	VerifiedAgainst: "autohand-cli main src/config.ts, src/constants.ts, src/sync/SyncService.ts, docs/config-reference.md and docs.autohand.ai hooks page " +
		"(location matrix Part 7 section 1, 2026-10-25) plus docs/autohand-adapter.md (0.9.8, live 2026-10-22); the user config file is never read.",
	Files: autohandFiles,
	Extra: autohandSettings,
}
