package agentconfig

// Snowflake Cortex Code (CLI `cortex`, Desktop, VS Code / ACP),
// doc-authored (surface-gap lane w4-catalog). Sources: location matrix
// Part 7 section 3 (docs.snowflake.com cortex-code settings, managed
// settings, extensibility and Desktop hooks pages) and
// docs/cortexcode-adapter.md (v1.2.18 bundle).
//
// Settings precedence, high to low: managed settings.*, profile
// settingsOverrides, project, managed defaults.*, user, built-in. Hooks
// merge across local .cortex|.claude/settings.local.json, project
// .cortex|.claude/settings.json, the user's ~/.claude/settings.json and the
// global hooks.json. The Claude files belong to the claude-code catalogue
// (Cortex reads them; they are not declared again here, so they are never
// evidence that Cortex is installed). The Snowflake connection files hold
// credentials and are never read.
const (
	cortexSettingsRef = "https://docs.snowflake.com/en/user-guide/cortex-code/settings"
	cortexManagedRef  = "https://docs.snowflake.com/en/user-guide/cortex-code/managed-settings"
	cortexHooksRef    = "https://docs.snowflake.com/en/user-guide/cortex-code/cortex-code-desktop/hooks"
	cortexExtRef      = "https://docs.snowflake.com/en/user-guide/cortex-code/extensibility"
	cortexSettings    = "cortex-code/settings"
	cortexMCP         = "cortex-code/mcp"
	cortexManaged     = "cortex-code/managed"
)

var cortexCodeFiles = []FileRow{
	{
		ID: "cortex-code/user-settings", Tool: "cortex-code", Shape: cortexSettings, Kind: KindSettings, Scope: ScopeUser,
		Paths: samePath("~/.snowflake/cortex/settings.json"), Format: FormatJSON, Precedence: 20, WriteNeeds: PrivUser,
		Grounding: waveDoc(cortexSettingsRef),
		Note: "The --config default. Lowest file layer: project files and the managed defaults.* section rank above it. " +
			"--setting-sources can drop the user layer for one run. CORTEX_HOME / SNOWFLAKE_HOME relocate it (relocate.go).",
	},
	{
		ID: "cortex-code/user-hooks", Tool: "cortex-code", Shape: cortexSettings, Kind: KindHooks, Scope: ScopeUser,
		Paths: samePath("~/.snowflake/cortex/hooks.json"), Format: FormatJSON, Precedence: 10, WriteNeeds: PrivUser,
		Grounding: waveDoc(cortexHooksRef),
		Note:      "Global hooks file {\"hooks\": {...}} (the settings shape's hooks and disableAllHooks keys), merged with every other hook source (\"shared with CoCo CLI\"). Observer writes nothing here yet (review W-2 fix a).",
	},
	{
		ID: "cortex-code/home-settings", Tool: "cortex-code", Shape: cortexSettings, Kind: KindSettings, Scope: ScopeUser,
		Paths: samePath("~/.cortex/settings.json"), Format: FormatJSON, Precedence: 20, WriteNeeds: PrivUser,
		Grounding: Grounding{Kind: GroundSource, Source: wave1021Review + " W-3a (Cortex disableAllHooks sources)", Date: wave1021Date},
		Note:      "Named by the gap review as a hook source (the internal/hookdisable row cortex.home.disableAllHooks); not in the vendor docs, so its place in the order is unverified.",
	},
	{
		ID: "cortex-code/project-settings", Tool: "cortex-code", Shape: cortexSettings, Kind: KindSettings, Scope: ScopeProjectShared,
		Paths: samePath("<project>/.cortex/settings.json"), Format: FormatJSON, Precedence: 30, WriteNeeds: PrivUser,
		Grounding: waveDoc(cortexExtRef), Note: "<project>/.claude/settings.json is read the same way (a claude-code file).",
	},
	{
		ID: "cortex-code/project-local-settings", Tool: "cortex-code", Shape: cortexSettings, Kind: KindSettings, Scope: ScopeProjectLocal,
		Paths: samePath("<project>/.cortex/settings.local.json"), Format: FormatJSON, Precedence: 40, WriteNeeds: PrivUser,
		Grounding: waveDoc(cortexExtRef), Note: "Highest hook layer; <project>/.claude/settings.local.json is read the same way.",
	},
	{
		ID: "cortex-code/user-mcp", Tool: "cortex-code", Shape: cortexMCP, Kind: KindMCP, Scope: ScopeUser,
		Paths: samePath("~/.snowflake/cortex/mcp.json"), Format: FormatJSON, Precedence: 20, WriteNeeds: PrivUser,
		Grounding: waveDoc(cortexSettingsRef),
		Note: "`cortex mcp add|list|remove`; --mcp-config takes another file; the managed files.mcpFile can name it. Cortex ALSO loads ~/.claude.json's servers " +
			"(live log), which is where Observer's claude-code MCP registration reaches it.",
	},
	{
		ID: "cortex-code/managed-settings", Tool: "cortex-code", Shape: cortexManaged, Kind: KindSettings, Scope: ScopeManaged,
		Paths: OSPaths{
			Linux:   "/etc/cortex/managed-settings.json",
			Darwin:  "/Library/Application Support/Cortex/managed-settings.json",
			Windows: `%ProgramData%\Cortex\managed-settings.json`,
		},
		Format: FormatJSON, Precedence: 100, WriteNeeds: PrivAdminRoot, Grounding: waveDoc(cortexManagedRef),
		Note: "settings.* beat every layer; defaults.* rank below project and above user. No hooks key and no base-URL key. " +
			"Observer emits it as an MDM artifact (internal/managedsettings/cortex.go, files.mcpFile and the banner), never writes it.",
	},
	{
		ID: "cortex-code/permissions", Tool: "cortex-code", Shape: "cortex-code/permissions", Kind: KindToolState, Scope: ScopeUser,
		Paths: samePath("~/.snowflake/cortex/permissions.json"), Format: FormatJSON, Precedence: 0, WriteNeeds: PrivNever,
		Grounding: waveAdapterDoc("docs/cortexcode-adapter.md section 2"),
		Note:      "The adapter doc calls it the per-directory permission cache; the matrix names allow / deny / onlyAllow / defaultMode in it. Never read or written here.",
	},
	{
		ID: "cortex-code/connections", Tool: "cortex-code", Shape: "cortex-code/connections", Kind: KindToolState, Scope: ScopeUser,
		Paths: samePath("~/.snowflake/connections.toml"), Format: FormatTOML, Precedence: 0, WriteNeeds: PrivNever, Borrowed: true,
		Grounding: waveAdapterDoc("docs/cortexcode-adapter.md section 2"),
		Note:      "Snowflake connection credentials, shared with the Snowflake CLI (so never install evidence): never read or written. -c picks a connection.",
	},
	{
		ID: "cortex-code/snowflake-config", Tool: "cortex-code", Shape: "cortex-code/connections", Kind: KindToolState, Scope: ScopeUser,
		Paths: samePath("~/.snowflake/config.toml"), Format: FormatTOML, Precedence: 0, WriteNeeds: PrivNever, Borrowed: true,
		Grounding: waveDoc(cortexSettingsRef),
		Note:      "The vendor's name for the connections file (the adapter doc says connections.toml; both may exist). Credentials, shared with the Snowflake CLI: never read or written.",
	},
	{
		ID: "cortex-code/credential-cache", Tool: "cortex-code", Shape: "cortex-code/credential-cache", Kind: KindToolState, Scope: ScopeUser,
		Paths: samePath("~/.snowflake/cortex/cache/credential_cache/credential_cache_v1.json"), Format: FormatJSON, Precedence: 0, WriteNeeds: PrivNever,
		Grounding: waveAdapterDoc("docs/cortexcode-adapter.md section 2"), Note: "Cached auth: never read or written.",
	},
}

var cortexCodeSettings = waveRows("cortex-code", cortexSettings, cortexSettingsRef, []SettingRow{
	{
		Path: KeyPath{"hooks"}, Type: TypeObject, Source: cortexHooksRef,
		Desc: "Claude-Code-shaped hook groups by event; every source (settings.json, hooks.json, project and local files) merges.",
		Note: "Observer writes no Cortex-owned hook file yet: its gate reaches Cortex through the claude-code writer's ~/.claude/settings.json (rerouted by internal/hook/foreignhost.go).",
	},
	{
		Path: KeyPath{"disableAllHooks"}, Type: TypeBool, Source: wave1021Review + " W-3a", Danger: DangerRefuseWhileIntegrated, Verified: VerifiedUnverified,
		Desc: "Turn every hook off.", Note: "true in any hook source turns every hook off, Observer's included (internal/hookdisable cortex.* rows). Key named by the gap review, not quoted from the vendor pages.",
	},
	{
		Path: KeyPath{"mcpServers"}, FileID: cortexMCP, Type: TypeMCPMap,
		Desc: "MCP servers by name (the --mcp-config shape {\"mcpServers\": {...}}).", Note: "env and headers may hold credentials.",
	},
	// --- managed-settings.json
	{
		Path: KeyPath{"permissions", "onlyAllow"}, FileID: cortexManaged, Type: TypeStringList, Source: cortexManagedRef,
		Desc: "Allow-list of tool patterns (incl. mcp(...) patterns); anything else is denied.",
	},
	{Path: KeyPath{"permissions", "deny"}, FileID: cortexManaged, Type: TypeStringList, Source: cortexManagedRef, Desc: "Denied tool patterns (incl. mcp(...))."},
	{
		Path: KeyPath{"files", "mcpFile"}, FileID: cortexManaged, Type: TypeString, Source: cortexManagedRef,
		Desc: "Path of the MCP config file Cortex loads.", Note: "Observer's generator emits it (internal/managedsettings/cortex.go).",
	},
	{Path: KeyPath{"files", "connectionsFile"}, FileID: cortexManaged, Type: TypeString, Source: cortexManagedRef, Desc: "Path of the Snowflake connections file."},
	{Path: KeyPath{"tenant", "allowedAccounts"}, FileID: cortexManaged, Type: TypeStringList, Source: cortexManagedRef, Desc: "Snowflake accounts Cortex may use."},
})

var cortexCodeCatalog = toolCatalog{
	Tool: "cortex-code",
	VerifiedAgainst: "docs.snowflake.com cortex-code settings, managed-settings, extensibility and Desktop hooks pages (location matrix Part 7 section 3, 2026-10-25) " +
		"plus docs/cortexcode-adapter.md (v1.2.18 bundle); no settings value was read.",
	Files: cortexCodeFiles,
	Extra: cortexCodeSettings,
}
