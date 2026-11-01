package agentconfig

// Tencent CodeBuddy Code CLI (`codebuddy` / `cbc`), doc-authored
// (surface-gap lane w4-catalog). Sources: location matrix Part 7 section 4
// (codebuddy.cn cli settings, hooks, env-vars, mcp, models and permissions
// pages, the 2.175.0 changelog) and docs/codebuddy-adapter.md.
//
// Precedence (settings page): CLI args, then settings.local.json, then the
// project .codebuddy/settings.json, then the user file. The permissions page
// orders it flag/session > user > policy > project > local instead: the
// vendor docs disagree, and the numbers below follow the settings page.
// Hooks merge across scopes and are snapshotted at session start.
// models.json holds per-model apiKey values, so it is PrivNever.
const (
	codebuddySettingsRef = "https://www.codebuddy.cn/docs/cli/settings"
	codebuddyHooksRef    = "https://www.codebuddy.cn/docs/cli/hooks"
	codebuddyEnvRef      = "https://www.codebuddy.cn/docs/cli/env-vars"
	codebuddyMCPRef      = "https://www.codebuddy.cn/docs/cli/mcp"
	codebuddyModelsRef   = "https://www.codebuddy.cn/docs/cli/models"
	codebuddySettings    = "codebuddy/settings"
	codebuddyMCP         = "codebuddy/mcp"
	codebuddyModels      = "codebuddy/models"
)

var codebuddyFiles = []FileRow{
	{
		ID: "codebuddy/user-settings", Tool: "codebuddy", Shape: codebuddySettings, Kind: KindSettings, Scope: ScopeUser,
		Paths: samePath("~/.codebuddy/settings.json"), Format: FormatJSON, Precedence: 20, WriteNeeds: PrivUser,
		Grounding: waveDoc(codebuddySettingsRef),
		Note: "Claude Code's settings schema: its env block can carry CODEBUDDY_API_KEY (credential-file exception D-268, integration credFileCodeBuddy). " +
			"Observer's hook writer splices only the hooks member (internal/hook/register_wave1021.go) and does not follow CODEBUDDY_CONFIG_DIR yet (review W-4). " +
			"On Windows CodeBuddy runs hooks through Git Bash (CODEBUDDY_CODE_GIT_BASH_PATH) and errors without it.",
	},
	{
		ID: "codebuddy/user-local-settings", Tool: "codebuddy", Shape: codebuddySettings, Kind: KindSettings, Scope: ScopeUser,
		Paths: samePath("~/.codebuddy/settings.local.json"), Format: FormatJSON, Precedence: 25, WriteNeeds: PrivUser,
		Grounding: matrixE("section 4"), Note: "User-level local overlay beside settings.json (its rank against the user file is inferred from the project pair).",
	},
	{
		ID: "codebuddy/project-settings", Tool: "codebuddy", Shape: codebuddySettings, Kind: KindSettings, Scope: ScopeProjectShared,
		Paths: samePath("<project>/.codebuddy/settings.json"), Format: FormatJSON, Precedence: 30, WriteNeeds: PrivUser,
		Grounding: waveDoc(codebuddySettingsRef), Note: "--setting-sources can drop a layer for one run.",
	},
	{
		ID: "codebuddy/project-local-settings", Tool: "codebuddy", Shape: codebuddySettings, Kind: KindSettings, Scope: ScopeProjectLocal,
		Paths: samePath("<project>/.codebuddy/settings.local.json"), Format: FormatJSON, Precedence: 40, WriteNeeds: PrivUser,
		Grounding: waveDoc(codebuddySettingsRef),
	},
	{
		ID: "codebuddy/managed-dir", Tool: "codebuddy", Shape: codebuddySettings, Kind: KindSettings, Scope: ScopeManaged,
		Paths: OSPaths{Linux: "/etc/codebuddy/"}, Format: FormatJSON, Precedence: 100, WriteNeeds: PrivAdminRoot,
		Grounding: waveDoc("https://www.codebuddy.cn/docs/cli/permissions"),
		Note: "Managed DIRECTORY; the file name inside it is unverified, and so are the macOS and Windows locations (a 2.36.3 %appdata% expansion fix hints at Windows). " +
			"policySettings is \"in-process, not on disk\"; policy hooks run first and their deny ends the chain.",
	},
	{
		ID: "codebuddy/user-mcp", Tool: "codebuddy", Shape: codebuddyMCP, Kind: KindMCP, Scope: ScopeUser,
		Paths: samePath("~/.codebuddy/.mcp.json"), Format: FormatJSON, Precedence: 22, WriteNeeds: PrivUser,
		Grounding: waveDoc(codebuddyMCPRef),
		Note:      "User MCP is FIRST FILE FOUND WINS, no merge: ~/.codebuddy/.mcp.json, then ~/.codebuddy/mcp.json, then ~/.codebuddy.json. Observer writes no entry (AP-120).",
	},
	{
		ID: "codebuddy/user-mcp-alt", Tool: "codebuddy", Shape: codebuddyMCP, Kind: KindMCP, Scope: ScopeUser,
		Paths: samePath("~/.codebuddy/mcp.json"), Format: FormatJSON, Precedence: 21, WriteNeeds: PrivUser,
		Grounding: waveDoc(codebuddyMCPRef), Note: "Read only when ~/.codebuddy/.mcp.json is absent (also the stream-json mode file).",
	},
	{
		ID: "codebuddy/global-config", Tool: "codebuddy", Shape: "codebuddy/global-config", Kind: KindToolState, Scope: ScopeUser,
		Paths: samePath("~/.codebuddy.json"), Format: FormatJSON, Precedence: 20, WriteNeeds: PrivNever,
		Grounding: waveDoc(codebuddyMCPRef),
		Note: "Claude's ~/.claude.json analog: local-scope MCP servers per project (projects.<path>) and the last user MCP fallback. " +
			"CODEBUDDY_CONFIG_DIR moves it too since 2.125.4, which no anchored rule can express (it sits beside, not under, ~/.codebuddy). Shown, never form-edited.",
	},
	{
		ID: "codebuddy/project-mcp", Tool: "codebuddy", Shape: codebuddyMCP, Kind: KindMCP, Scope: ScopeProjectShared,
		Paths: samePath("<project>/.mcp.json"), Format: FormatJSON, Precedence: 30, WriteNeeds: PrivUser,
		Grounding: waveDoc(codebuddyMCPRef), Note: "Project servers need approval (enableAllProjectMcpServers / enabledMcpjsonServers).",
	},
	{
		ID: "codebuddy/user-models", Tool: "codebuddy", Shape: codebuddyModels, Kind: KindSettings, Scope: ScopeUser,
		Paths: samePath("~/.codebuddy/models.json"), Format: FormatJSON, Precedence: 20, WriteNeeds: PrivNever,
		Grounding: waveDoc(codebuddyModelsRef), Note: "Per-model url and a plaintext apiKey: never read or written here; rows come from the vendor docs only.",
	},
	{
		ID: "codebuddy/project-models", Tool: "codebuddy", Shape: codebuddyModels, Kind: KindSettings, Scope: ScopeProjectShared,
		Paths: samePath("<project>/.codebuddy/models.json"), Format: FormatJSON, Precedence: 30, WriteNeeds: PrivNever,
		Grounding: waveDoc(codebuddyModelsRef), Note: "The project file wins over the user one. May carry an apiKey like the user file: never read or written here.",
	},
}

var codebuddySettingsRows = waveRows("codebuddy", codebuddySettings, codebuddySettingsRef, []SettingRow{
	{
		Path: KeyPath{"hooks"}, Type: TypeObject, Source: codebuddyHooksRef,
		Desc: "Claude-Code-compatible hook groups by event (command / prompt / agent / http types).",
		Note: "Observer's PreToolUse and UserPromptSubmit entries live in the user file; groups merge across scopes and are snapshotted at session start.",
	},
	{
		Path: KeyPath{"disableAllHooks"}, Type: TypeBool, Desc: "Turn every hook off.", Danger: DangerRefuseWhileIntegrated,
		Note: "true in any scope stops Observer's hooks (internal/hookdisable codebuddy.* rows).",
	},
	{
		Path: KeyPath{"allowUntrustedFrontmatterHooks"}, Type: TypeBool, Source: codebuddyHooksRef, Danger: DangerConfirm,
		Desc: "Run hooks declared in untrusted skill / agent front matter.",
	},
	{
		Path: KeyPath{"endpoint"}, Type: TypeString, Danger: DangerConfirm, Desc: "Model endpoint override.",
		Note: "CODEBUDDY_BASE_URL overrides the endpoint from the environment. A base URL redirects inference.",
	},
	{Path: KeyPath{"model"}, Type: TypeString, Desc: "Default model."},
	{
		Path: KeyPath{"env"}, Type: TypeStringMap, Danger: DangerConfirm, Desc: "Environment variables for the session.",
		Note: "Can carry CODEBUDDY_BASE_URL (a route) and CODEBUDDY_API_KEY (a credential).",
	},
	{
		Path: KeyPath{"env", "CODEBUDDY_API_KEY"}, Type: TypeString, Secret: true, Source: codebuddyEnvRef,
		Desc: "CodeBuddy API key.", Note: "A plaintext credential when set here; prefer the shell environment.",
	},
	{
		Path: KeyPath{"env", "CODEBUDDY_BASE_URL"}, Type: TypeString, Source: codebuddyEnvRef, Danger: DangerConfirm,
		Desc: "Model endpoint base URL.", Note: "The proxy probe confirmed the CLI honours it (docs/codebuddy-adapter.md section 7); no route is written.",
	},
	{
		Path: KeyPath{"enableAllProjectMcpServers"}, Type: TypeBool, Danger: DangerConfirm,
		Desc: "Approve every server in the project .mcp.json.", Note: "Project servers run commands at session start.",
	},
	{Path: KeyPath{"enabledMcpjsonServers"}, Type: TypeStringList, Desc: "Project .mcp.json servers approved by name."},
	{Path: KeyPath{"disabledMcpjsonServers"}, Type: TypeStringList, Desc: "Project .mcp.json servers rejected by name."},
	{
		Path: KeyPath{"trustedDirectories"}, Type: TypeStringList, Scopes: []Scope{ScopeUser}, Source: "docs/codebuddy-adapter.md section 2",
		Desc: "Directories CodeBuddy trusts.", Verified: VerifiedUnverified, Note: "Key named by the adapter doc's store table, not the vendor settings page.",
	},
	{
		Path: KeyPath{"mcpServers"}, FileID: codebuddyMCP, Type: TypeMCPMap, Source: codebuddyMCPRef,
		Desc: "MCP servers by name (a flat map is accepted too); stdio / sse / http transports.", Note: "env and headers may hold credentials.",
	},
	{
		Path: KeyPath{"models"}, FileID: codebuddyModels, Type: TypeObject, Source: codebuddyModelsRef, Danger: DangerConfirm,
		Desc: "Custom models, each with a url (the full /chat/completions URL) and an apiKey.", Note: "The file is never read; apiKey is a plaintext credential.",
	},
})

var codebuddyCatalog = toolCatalog{
	Tool: "codebuddy",
	VerifiedAgainst: "codebuddy.cn cli settings, hooks, env-vars, mcp, models and permissions pages and the @tencent-ai/codebuddy-code 2.175.0 changelog " +
		"(location matrix Part 7 section 4, 2026-10-25) plus docs/codebuddy-adapter.md (2.171.0); no settings value was read.",
	Files: codebuddyFiles,
	Extra: codebuddySettingsRows,
}
