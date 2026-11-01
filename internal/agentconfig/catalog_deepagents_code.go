package agentconfig

// LangChain Deep Agents Code (`dcode`), doc-authored (surface-gap lane
// w4-catalog). Sources: location matrix Part 7 section 5
// (docs.langchain.com deepagents code configuration, config-file, hooks and
// mcp-tools pages) and docs/deepagents-adapter.md (0.1.87).
//
// General precedence, high to low: managed_config.toml, a
// DEEPAGENTS_CODE_* variable, the canonical variable, ~/.deepagents/
// config.toml, the built-in default. Hooks: project > user > plugin, every
// matching hook runs and decisions combine deny > ask > allow (a project
// allow cannot override Observer's deny). MCP, low to high: user .mcp.json,
// .deepagents/.mcp.json, root .mcp.json, --mcp-config. The .state auth
// files hold credentials and are never read.
const (
	deepAgentsConfigRef = "https://docs.langchain.com/oss/python/deepagents/code/config-file.md"
	deepAgentsManagedRf = "https://docs.langchain.com/oss/python/deepagents/code/configuration.md"
	deepAgentsHooksRef  = "https://docs.langchain.com/oss/javascript/deepagents/code/hooks.md"
	deepAgentsMCPRef    = "https://docs.langchain.com/oss/javascript/deepagents/code/mcp-tools.md"
	deepAgentsConfig    = "deepagents-code/config"
	deepAgentsHooks     = "deepagents-code/hooks"
	deepAgentsMCP       = "deepagents-code/mcp"
)

var deepAgentsFiles = []FileRow{
	{
		ID: "deepagents-code/user-config", Tool: "deepagents-code", Shape: deepAgentsConfig, Kind: KindSettings, Scope: ScopeUser,
		Paths: samePath("~/.deepagents/config.toml"), Format: FormatTOML, Precedence: 20, WriteNeeds: PrivUser,
		Grounding: waveDoc(deepAgentsConfigRef),
		Note: "DEEPAGENTS_HOME relocates ~/.deepagents (absolute or ~/-prefixed, shell env only; relocate.go). Ranks below every environment variable. " +
			"The adapter doc says [models.providers.*] may hold endpoints and keys; no literal key slot is documented (base_url_env names a variable), so it is not declared a credential file.",
	},
	{
		ID: "deepagents-code/managed-config", Tool: "deepagents-code", Shape: deepAgentsConfig, Kind: KindSettings, Scope: ScopeManaged,
		Paths: OSPaths{
			Linux:   "/etc/dcode/managed_config.toml",
			Darwin:  "/Library/Application Support/dcode/managed_config.toml",
			Windows: `%ProgramData%\dcode\managed_config.toml`,
		},
		Format: FormatTOML, Precedence: 100, WriteNeeds: PrivAdminRoot, Grounding: waveDoc(deepAgentsManagedRf),
		Note: "Fixed path (the Windows ProgramData folder is resolved through the registry). An optional remote [managed_config] source = https://... replaces the local file. " +
			"Same sections as config.toml; no hooks or MCP keys documented. Observer's lever A renders enforced org settings into it (managedsettings layer row, surface-gap S-19).",
	},
	{
		ID: "deepagents-code/user-hooks", Tool: "deepagents-code", Shape: deepAgentsHooks, Kind: KindHooks, Scope: ScopeUser,
		Paths: samePath("~/.deepagents/hooks.json"), Format: FormatJSON, Precedence: 20, WriteNeeds: PrivUser,
		Grounding: waveDoc(deepAgentsHooksRef),
		Note:      "Observer's hook writer adds its groups here (internal/hook/register_wave1021.go); it honours only an ABSOLUTE DEEPAGENTS_HOME (matrix item 12). No kill switch is documented.",
	},
	{
		ID: "deepagents-code/project-hooks", Tool: "deepagents-code", Shape: deepAgentsHooks, Kind: KindHooks, Scope: ScopeProjectShared,
		Paths: samePath("<project>/.deepagents/hooks.json"), Format: FormatJSON, Precedence: 30, WriteNeeds: PrivUser,
		Grounding: waveDoc(deepAgentsHooksRef), Note: "Trust-gated (~/.deepagents/.state/hooks_trust.json, --trust-project-hooks).",
	},
	{
		ID: "deepagents-code/user-mcp", Tool: "deepagents-code", Shape: deepAgentsMCP, Kind: KindMCP, Scope: ScopeUser,
		Paths: samePath("~/.deepagents/.mcp.json"), Format: FormatJSON, Precedence: 20, WriteNeeds: PrivUser,
		Grounding: waveDoc(deepAgentsMCPRef), Note: "Lowest MCP layer; --mcp-config is highest and --no-mcp turns MCP off. Observer writes no entry (AP-120).",
	},
	{
		ID: "deepagents-code/project-mcp", Tool: "deepagents-code", Shape: deepAgentsMCP, Kind: KindMCP, Scope: ScopeProjectShared,
		Paths: samePath("<project>/.deepagents/.mcp.json"), Format: FormatJSON, Precedence: 30, WriteNeeds: PrivUser,
		Grounding: waveDoc(deepAgentsMCPRef), Note: "Project servers are default-deny until approved.",
	},
	{
		ID: "deepagents-code/project-root-mcp", Tool: "deepagents-code", Shape: deepAgentsMCP, Kind: KindMCP, Scope: ScopeProjectShared,
		Paths: samePath("<project>/.mcp.json"), Format: FormatJSON, Precedence: 35, WriteNeeds: PrivUser,
		Grounding: waveDoc(deepAgentsMCPRef), Note: "Above .deepagents/.mcp.json; default-deny until approved.",
	},
	{
		ID: "deepagents-code/auth", Tool: "deepagents-code", Shape: "deepagents-code/auth", Kind: KindToolState, Scope: ScopeUser,
		Paths: samePath("~/.deepagents/.state/auth.json"), Format: FormatJSON, Precedence: 0, WriteNeeds: PrivNever,
		Grounding: waveAdapterDoc("docs/deepagents-adapter.md (.deepagents tree, Off-limits files)"),
		Note:      "Stored provider credentials and endpoints (plus chatgpt-auth.json beside it on Windows): never read or written.",
	},
	{
		ID: "deepagents-code/hooks-trust", Tool: "deepagents-code", Shape: "deepagents-code/hooks-trust", Kind: KindToolState, Scope: ScopeUser,
		Paths: samePath("~/.deepagents/.state/hooks_trust.json"), Format: FormatJSON, Precedence: 0, WriteNeeds: PrivNever,
		Grounding: waveDoc(deepAgentsHooksRef), Note: "Project hook trust dcode records; shown, never form-edited.",
	},
}

var deepAgentsSettings = waveRows("deepagents-code", deepAgentsConfig, deepAgentsConfigRef, []SettingRow{
	{
		Path: KeyPath{"models", "providers"}, Type: TypeObject, Danger: DangerConfirm,
		Desc: "Provider tables [models.providers.<p>] with base_url and base_url_env.",
		Note: "A base URL redirects inference. DEEPAGENTS_CODE_<X>_BASE_URL beats the canonical variable (OPENAI_BASE_URL, ANTHROPIC_BASE_URL, ...), both beat this file. " +
			"The managed file can set it too (by inference, matrix section 5).",
	},
	{
		Path: KeyPath{"models", "allowed"}, Type: TypeStringList, Source: deepAgentsManagedRf,
		Desc: "Exact model allow-list.", Note: "Documented for the managed file, where it is enforced over env and the user config.",
	},
	{Path: KeyPath{"mcp", "enabled_project_server_approvals"}, Type: TypeStringList, Desc: "Project MCP servers approved by name."},
	{Path: KeyPath{"mcp", "disabled_project_servers"}, Type: TypeStringList, Desc: "Project MCP servers turned off by name."},
	{
		Path: KeyPath{"update", "auto_update"}, Type: TypeBool, Source: "docs/deepagents-adapter.md (Windows install)", Verified: VerifiedUnverified,
		Desc: "Self-update.", Note: "Named by the adapter doc's Windows workaround (DEEPAGENTS_CODE_AUTO_UPDATE=0 is the env twin); not quoted from the vendor page.",
	},
	{
		Path: KeyPath{"hooks"}, FileID: deepAgentsHooks, Type: TypeObject, Source: deepAgentsHooksRef,
		Desc: "Hook groups by event: {Event: [{matcher, hooks: [{type: command, command, timeout, statusMessage}]}]}; async handlers are rejected.",
		Note: "Observer's PreToolUse and UserPromptSubmit groups live in the user file. A legacy list-shaped document is migrated by dcode on its next run.",
	},
	{
		Path: KeyPath{"mcpServers"}, FileID: deepAgentsMCP, Type: TypeMCPMap, Source: deepAgentsMCPRef,
		Desc: "MCP servers by name: {command, args, env} | {url, headers}; per-server allowedTools / disabledTools; ${VAR} expansion.",
		Note: "env and headers may hold credentials (${VAR} is the reference form).",
	},
})

var deepAgentsCodeCatalog = toolCatalog{
	Tool: "deepagents-code",
	VerifiedAgainst: "docs.langchain.com deepagents code configuration, config-file, hooks and mcp-tools pages (location matrix Part 7 section 5, 2026-10-25) " +
		"plus docs/deepagents-adapter.md (0.1.87); no settings value was read.",
	Files: deepAgentsFiles,
	Extra: deepAgentsSettings,
}
