package agentconfig

// Kiro CLI catalogue. Sources: kiro.dev/docs/reference/settings (re-fetched
// 2026-10-04 for the full cli.json key table), kiro.dev/docs/configuration,
// custom-agents configuration reference, enterprise/governance/permissions,
// cli/v3/hooks-migration, audit section 5 "kiro-cli"; repo
// docs/kiro-cli-adapter.md. Kiro was NOT installed on demo node 1, so every
// row is doc-grounded.
const (
	kiroCLIRef      = "https://kiro.dev/docs/reference/settings/"
	kiroCLIConfRef  = "https://kiro.dev/docs/configuration/"
	kiroCLIPermsRef = "https://kiro.dev/docs/enterprise/governance/permissions.md"
	kiroCLIHooksRef = "https://kiro.dev/docs/cli/v3/hooks-migration/"
	kiroCLISettings = "kiro-cli/cli"
	kiroCLIMCP      = "kiro-cli/mcp"
	kiroCLIPerms    = "kiro-cli/permissions"
	kiroCLIHooks    = "kiro-cli/hooks"
	kiroCLIClassic  = "Applies to the classic UI only."
)

// kiroCLIMCPShape: mcpServers.<name> {command, args, env, timeout}; the
// audit grounds local servers only, so remote transports are refused.
var kiroCLIMCPShape = MCPShape{EnvKey: "env", TypeNames: map[string]string{"stdio": ""}}

var kiroCLICatalog = toolCatalog{
	Tool:            "kiro-cli",
	VerifiedAgainst: "vendor docs fetched 2026-10-03 (audit section 5) and the settings reference re-fetched 2026-10-04; not installed on node 1, no live keys",
	Files: []FileRow{
		{
			ID: "kiro-cli/user-cli", Tool: "kiro-cli", Shape: kiroCLISettings, Kind: KindSettings, Scope: ScopeUser,
			Paths: samePath("~/.kiro/settings/cli.json"), Format: FormatJSON, Precedence: 20, WriteNeeds: PrivUser, Grounding: doc(kiroCLIRef),
			Note: "CLI-only; kiro-cli settings <key> <value> edits it. A workspace .kiro/settings/cli.json overrides it per project (kiro-cli/project-cli). " +
				"KIRO_HOME relocates ~/.kiro (Windows %USERPROFILE%\\.kiro) when it is an absolute path that is not the root, the home directory or an ancestor of it.",
		},
		{
			// surface-gap S-11 (NEW-4): the settings reference documents a
			// workspace file that overrides the global one. Its own shape, so
			// the user-file rows (some keys are global-only, and the reference
			// does not say which) never become writable at project scope.
			ID: "kiro-cli/project-cli", Tool: "kiro-cli", Shape: "kiro-cli/cli-workspace", Kind: KindSettings, Scope: ScopeProjectShared,
			Paths: samePath("<project>/.kiro/settings/cli.json"), Format: FormatJSON, Precedence: 30, WriteNeeds: PrivUser, Grounding: doc(kiroCLIRef),
			Note: "Workspace settings: override the global cli.json in this project's terminal UI sessions; some keys are global-only. " +
				"A workspace chat.defaultAgent replaces the default agent Observer sets, so that project's sessions run without Observer's 2.x agent hooks " +
				"unless the named agent carries them (Observer merges its hooks into every global agent JSON, not workspace ones).",
		},
		{
			ID: "kiro-cli/user-mcp", Tool: "kiro-cli", Shape: kiroCLIMCP, Kind: KindMCP, Scope: ScopeUser,
			Paths: samePath("~/.kiro/settings/mcp.json"), Format: FormatJSON, Precedence: 20, WriteNeeds: PrivUser, Grounding: doc(kiroCLIConfRef),
		},
		{
			ID: "kiro-cli/project-mcp", Tool: "kiro-cli", Shape: kiroCLIMCP, Kind: KindMCP, Scope: ScopeProjectShared,
			Paths: samePath("<project>/.kiro/settings/mcp.json"), Format: FormatJSON, Precedence: 30, WriteNeeds: PrivUser, Grounding: doc(kiroCLIConfRef),
		},
		{
			ID: "kiro-cli/user-permissions", Tool: "kiro-cli", Shape: kiroCLIPerms, Kind: KindPermissions, Scope: ScopeUser,
			Paths: samePath("~/.kiro/settings/permissions.yaml"), Format: FormatYAML, Precedence: 20, WriteNeeds: PrivUser,
			Grounding: Grounding{Kind: GroundAdapterDoc, Source: "docs/kiro-cli-adapter.md", Date: auditDate},
			Note:      "Deny overrides: deny > ask > allow across every scope; a permissive rule never overrides a restrictive one.",
		},
		{
			ID: "kiro-cli/workspace-permissions", Tool: "kiro-cli", Shape: kiroCLIPerms, Kind: KindPermissions, Scope: ScopeProjectLocal,
			Paths: samePath("~/.kiro/workspace-roots/"), Format: FormatYAML, Precedence: 30, WriteNeeds: PrivUser,
			Grounding: Grounding{Kind: GroundAdapterDoc, Source: "docs/kiro-cli-adapter.md", Date: auditDate},
			Note:      "Per-workspace permissions.yaml under ~/.kiro/workspace-roots/<hash>/ (kept outside the repo, so a cloned repo cannot inject rules).",
		},
		{
			ID: "kiro-cli/managed-settings", Tool: "kiro-cli", Shape: kiroCLIPerms, Kind: KindPermissions, Scope: ScopeManaged,
			Paths: OSPaths{
				Linux:   "/etc/kiro/managed-settings.json",
				Darwin:  "/Library/Application Support/Kiro/managed-settings.json",
				Windows: `C:\ProgramData\Kiro\managed-settings.json`,
			},
			Format: FormatJSON, Precedence: 100, WriteNeeds: PrivAdminRoot, Grounding: doc(kiroCLIPermsRef),
			Note: "OS-protected, MDM-deployable; effects deny / ask only (cannot grant); applies to the IDE and the CLI; an invalid file fails CLOSED (every tool call denied). " +
				"The Kiro console (model allow-list, MCP registry, web tools) is server-side.",
		},
		{
			ID: "kiro-cli/user-hooks", Tool: "kiro-cli", Shape: kiroCLIHooks, Kind: KindHooks, Scope: ScopeUser,
			Paths: samePath("~/.kiro/hooks/"), Format: FormatJSON, Precedence: 20, WriteNeeds: PrivUser, Grounding: doc(kiroCLIHooksRef),
			Note: "v3 hook files (*.json); 2.x hooks lived in agent JSON (kiro-cli agent migrate converts). Kiro Crew fires project hooks too.",
		},
		{
			ID: "kiro-cli/project-hooks", Tool: "kiro-cli", Shape: kiroCLIHooks, Kind: KindHooks, Scope: ScopeProjectShared,
			Paths: samePath("<project>/.kiro/hooks/"), Format: FormatJSON, Precedence: 30, WriteNeeds: PrivUser, Grounding: doc(kiroCLIHooksRef),
			Note: "Shared with Kiro Crew: one project hook fires under both.",
		},
	},
	Extra: []SettingRow{
		// --- model, thinking, compaction
		{
			ID: "kiro-cli/chat.defaultModel", Tool: "kiro-cli", FileID: kiroCLISettings, Path: KeyPath{"chat", "defaultModel"}, Type: TypeString,
			Desc: "Default model for conversations.", Source: kiroCLIRef, Verified: VerifiedDoc, Owner: OwnerUser,
			Note: "An agent's own model and the Kiro console default can override it.",
		},
		{
			ID: "kiro-cli/chat.defaultAgent", Tool: "kiro-cli", FileID: kiroCLISettings, Path: KeyPath{"chat", "defaultAgent"}, Type: TypeString,
			Desc: "Default agent configuration.", Source: kiroCLIRef, Verified: VerifiedDoc, Owner: OwnerUser,
		},
		{
			ID: "kiro-cli/chat.modelDefaults", Tool: "kiro-cli", FileID: kiroCLISettings, Path: KeyPath{"chat", "modelDefaults"}, Type: TypeObject,
			Desc: "Per-model default settings.", Source: kiroCLIRef, Verified: VerifiedDoc, Owner: OwnerUser,
		},
		{
			ID: "kiro-cli/chat.enableThinking", Tool: "kiro-cli", FileID: kiroCLISettings, Path: KeyPath{"chat", "enableThinking"}, Type: TypeBool,
			Desc: "Enable the thinking tool for complex reasoning.", Source: kiroCLIRef, Verified: VerifiedDoc, Owner: OwnerUser,
			Note: "A switch, not an effort level; a CLI effort key is UNVERIFIED (audit V5).",
		},
		{
			ID: "kiro-cli/chat.showThinking", Tool: "kiro-cli", FileID: kiroCLISettings, Path: KeyPath{"chat", "showThinking"}, Type: TypeBool, Default: "true",
			Desc: "Show reasoning blocks.", Source: kiroCLIRef, Verified: VerifiedDoc, Owner: OwnerUser,
		},
		{
			ID: "kiro-cli/chat.disableAutoCompaction", Tool: "kiro-cli", FileID: kiroCLISettings, Path: KeyPath{"chat", "disableAutoCompaction"}, Type: TypeBool,
			Desc: "Turn automatic conversation summarisation off.", Source: kiroCLIRef, Verified: VerifiedDoc, Owner: OwnerUser,
		},
		{
			ID: "kiro-cli/compaction.excludeMessages", Tool: "kiro-cli", FileID: kiroCLISettings, Path: KeyPath{"compaction", "excludeMessages"}, Type: TypeInt,
			Desc: "Minimum message pairs kept through compaction.", Source: kiroCLIRef, Verified: VerifiedDoc, Owner: OwnerUser,
		},
		{
			ID: "kiro-cli/compaction.excludeContextWindowPercent", Tool: "kiro-cli", FileID: kiroCLISettings, Path: KeyPath{"compaction", "excludeContextWindowPercent"},
			Type: TypeInt, Min: f64(0), Max: f64(100), Desc: "Minimum percent of the context window kept through compaction.", Source: kiroCLIRef,
			Verified: VerifiedDoc, Owner: OwnerUser, Note: "A retention floor, not a trigger threshold.",
		},
		// --- trust and tools
		{
			ID: "kiro-cli/chat.disableGranularTrust", Tool: "kiro-cli", FileID: kiroCLISettings, Path: KeyPath{"chat", "disableGranularTrust"}, Type: TypeBool,
			Desc: "Drop the tiered trust options from tool approvals.", Source: kiroCLIRef, Verified: VerifiedDoc, Owner: OwnerUser, Danger: DangerConfirm,
			Note: "true collapses approvals to all-or-nothing trust.",
		},
		{
			ID: "kiro-cli/chat.enableTodoList", Tool: "kiro-cli", FileID: kiroCLISettings, Path: KeyPath{"chat", "enableTodoList"}, Type: TypeBool,
			Desc: "Enable the todo list.", Source: kiroCLIRef, Verified: VerifiedDoc, Owner: OwnerUser,
		},
		{
			ID: "kiro-cli/chat.enableKnowledge", Tool: "kiro-cli", FileID: kiroCLISettings, Path: KeyPath{"chat", "enableKnowledge"}, Type: TypeBool,
			Desc: "Enable the knowledge base.", Source: kiroCLIRef, Verified: VerifiedDoc, Owner: OwnerUser,
		},
		{
			ID: "kiro-cli/chat.enableWorkflows", Tool: "kiro-cli", FileID: kiroCLISettings, Path: KeyPath{"chat", "enableWorkflows"}, Type: TypeBool,
			Desc: "Enable declarative workflows.", Source: kiroCLIRef, Verified: VerifiedDoc, Owner: OwnerUser,
		},
		{
			ID: "kiro-cli/chat.enableMainAgentSubagentTool", Tool: "kiro-cli", FileID: kiroCLISettings, Path: KeyPath{"chat", "enableMainAgentSubagentTool"},
			Type: TypeBool, Default: "true", Desc: "Keep main-chat subagent delegation when workflows are on.", Source: kiroCLIRef, Verified: VerifiedDoc, Owner: OwnerUser,
		},
		{
			ID: "kiro-cli/chat.enableCheckpoint", Tool: "kiro-cli", FileID: kiroCLISettings, Path: KeyPath{"chat", "enableCheckpoint"}, Type: TypeBool,
			Desc: "Enable checkpoints.", Source: kiroCLIRef, Verified: VerifiedDoc, Owner: OwnerUser, Note: kiroCLIClassic,
		},
		{
			ID: "kiro-cli/chat.enableDelegate", Tool: "kiro-cli", FileID: kiroCLISettings, Path: KeyPath{"chat", "enableDelegate"}, Type: TypeBool,
			Desc: "Enable the delegate tool.", Source: kiroCLIRef, Verified: VerifiedDoc, Owner: OwnerUser, Note: kiroCLIClassic,
		},
		{
			ID: "kiro-cli/chat.enableTangentMode", Tool: "kiro-cli", FileID: kiroCLISettings, Path: KeyPath{"chat", "enableTangentMode"}, Type: TypeBool,
			Desc: "Enable tangent mode.", Source: kiroCLIRef, Verified: VerifiedDoc, Owner: OwnerUser, Note: kiroCLIClassic,
		},
		{
			ID: "kiro-cli/toolSearch.enabled", Tool: "kiro-cli", FileID: kiroCLISettings, Path: KeyPath{"toolSearch", "enabled"}, Type: TypeBool, Default: "false",
			Desc: "Discover MCP tools on demand instead of loading every spec.", Source: kiroCLIRef, Verified: VerifiedDoc, Owner: OwnerUser,
		},
		{
			ID: "kiro-cli/toolSearch.minPct", Tool: "kiro-cli", FileID: kiroCLISettings, Path: KeyPath{"toolSearch", "minPct"}, Type: TypeInt,
			Min: f64(0), Max: f64(100), Default: "5", Desc: "Activate tool search when MCP specs exceed this percent of the context.",
			Source: kiroCLIRef, Verified: VerifiedDoc, Owner: OwnerUser,
		},
		{
			ID: "kiro-cli/toolSearch.minTokens", Tool: "kiro-cli", FileID: kiroCLISettings, Path: KeyPath{"toolSearch", "minTokens"}, Type: TypeInt,
			Default: "50000", Desc: "Activate tool search when MCP specs exceed this many tokens.", Source: kiroCLIRef, Verified: VerifiedDoc, Owner: OwnerUser,
		},
		{
			ID: "kiro-cli/mcp.initTimeout", Tool: "kiro-cli", FileID: kiroCLISettings, Path: KeyPath{"mcp", "initTimeout"}, Type: TypeInt, Default: "5000",
			Desc: "MCP server start-up timeout in milliseconds.", Source: kiroCLIRef, Verified: VerifiedDoc, Owner: OwnerUser,
		},
		{
			ID: "kiro-cli/mcp.noInteractiveTimeout", Tool: "kiro-cli", FileID: kiroCLISettings, Path: KeyPath{"mcp", "noInteractiveTimeout"}, Type: TypeInt,
			Default: "30000", Desc: "MCP start-up timeout for non-interactive runs, in milliseconds.", Source: kiroCLIRef, Verified: VerifiedDoc, Owner: OwnerUser,
		},
		{
			ID: "kiro-cli/mcp.loadedBefore", Tool: "kiro-cli", FileID: kiroCLISettings, Path: KeyPath{"mcp", "loadedBefore"}, Type: TypeBool,
			Desc: "Tracks whether MCP servers were loaded before.", Source: kiroCLIRef, Verified: VerifiedDoc, Owner: OwnerToolState,
			Note: "Maintained by kiro-cli.",
		},
		// --- timeouts
		{
			ID: "kiro-cli/api.timeout", Tool: "kiro-cli", FileID: kiroCLISettings, Path: KeyPath{"api", "timeout"}, Type: TypeInt, Default: "3600",
			Desc: "Overall timeout of a streaming response, in seconds.", Source: kiroCLIRef, Verified: VerifiedDoc, Owner: OwnerUser,
		},
		{
			ID: "kiro-cli/api.streamIdleSoftTimeout", Tool: "kiro-cli", FileID: kiroCLISettings, Path: KeyPath{"api", "streamIdleSoftTimeout"}, Type: TypeInt,
			Default: "60", Desc: "Silent seconds before a stall warning.", Source: kiroCLIRef, Verified: VerifiedDoc, Owner: OwnerUser,
		},
		{
			ID: "kiro-cli/api.streamIdleHardTimeout", Tool: "kiro-cli", FileID: kiroCLISettings, Path: KeyPath{"api", "streamIdleHardTimeout"}, Type: TypeInt,
			Default: "300", Desc: "Silent seconds before the request is cancelled.", Source: kiroCLIRef, Verified: VerifiedDoc, Owner: OwnerUser,
		},
		{
			ID: "kiro-cli/api.subagentTimeout", Tool: "kiro-cli", FileID: kiroCLISettings, Path: KeyPath{"api", "subagentTimeout"}, Type: TypeInt,
			Default: "3600", Desc: "Idle seconds before a subagent times out.", Source: kiroCLIRef, Verified: VerifiedDoc, Owner: OwnerUser,
		},
		// --- telemetry, update
		{
			ID: "kiro-cli/telemetry.enabled", Tool: "kiro-cli", FileID: kiroCLISettings, Path: KeyPath{"telemetry", "enabled"}, Type: TypeBool,
			Desc: "Collect telemetry.", Source: kiroCLIRef, Verified: VerifiedDoc, Owner: OwnerUser,
		},
		{
			ID: "kiro-cli/telemetryClientId", Tool: "kiro-cli", FileID: kiroCLISettings, Path: KeyPath{"telemetryClientId"}, Type: TypeString,
			Desc: "Client identifier for telemetry.", Source: kiroCLIRef, Verified: VerifiedDoc, Owner: OwnerToolState, Note: "Generated by kiro-cli.",
		},
		{
			ID: "kiro-cli/app.disableAutoupdates", Tool: "kiro-cli", FileID: kiroCLISettings, Path: KeyPath{"app", "disableAutoupdates"}, Type: TypeBool,
			Desc: "Turn background auto-updates off.", Source: kiroCLIRef, Verified: VerifiedDoc, Owner: OwnerUser,
		},
		// --- UI
		{
			ID: "kiro-cli/chat.ui", Tool: "kiro-cli", FileID: kiroCLISettings, Path: KeyPath{"chat", "ui"}, Type: TypeEnum,
			Enum: []string{"tui", "classic"}, Default: `"tui"`, Desc: "Terminal UI implementation.", Source: kiroCLIRef, Verified: VerifiedDoc, Owner: OwnerUser,
		},
		{
			ID: "kiro-cli/chat.uiMode", Tool: "kiro-cli", FileID: kiroCLISettings, Path: KeyPath{"chat", "uiMode"}, Type: TypeString,
			Desc: "UI variant.", Source: kiroCLIRef, Verified: VerifiedDoc, Owner: OwnerUser, Note: "A UI variant, not a colour theme.",
		},
		{
			ID: "kiro-cli/chat.outputStyle", Tool: "kiro-cli", FileID: kiroCLISettings, Path: KeyPath{"chat", "outputStyle"}, Type: TypeString,
			Desc: "v3 response style.", Source: kiroCLIRef, Verified: VerifiedDoc, Owner: OwnerUser,
		},
		{
			ID: "kiro-cli/chat.historyMode", Tool: "kiro-cli", FileID: kiroCLISettings, Path: KeyPath{"chat", "historyMode"}, Type: TypeEnum,
			Enum: []string{"session", "global"}, Default: `"session"`, Desc: "Prompt history per session or shared.", Source: kiroCLIRef, Verified: VerifiedDoc, Owner: OwnerUser,
		},
		{
			ID: "kiro-cli/chat.sessionDashboard.scope", Tool: "kiro-cli", FileID: kiroCLISettings, Path: KeyPath{"chat", "sessionDashboard", "scope"}, Type: TypeEnum,
			Enum: []string{"current", "all"}, Default: `"current"`, Desc: "Sessions listed in the v3 dashboard.", Source: kiroCLIRef, Verified: VerifiedDoc, Owner: OwnerUser,
		},
		{
			ID: "kiro-cli/chat.greeting.enabled", Tool: "kiro-cli", FileID: kiroCLISettings, Path: KeyPath{"chat", "greeting", "enabled"}, Type: TypeBool,
			Desc: "Show the greeting at chat start.", Source: kiroCLIRef, Verified: VerifiedDoc, Owner: OwnerUser,
		},
		{
			ID: "kiro-cli/chat.enableNotifications", Tool: "kiro-cli", FileID: kiroCLISettings, Path: KeyPath{"chat", "enableNotifications"}, Type: TypeBool,
			Desc: "Desktop notifications.", Source: kiroCLIRef, Verified: VerifiedDoc, Owner: OwnerUser,
		},
		{
			ID: "kiro-cli/chat.notificationMethod", Tool: "kiro-cli", FileID: kiroCLISettings, Path: KeyPath{"chat", "notificationMethod"}, Type: TypeEnum,
			Enum: []string{"auto", "bel", "osc9"}, Desc: "How notifications are sent.", Source: kiroCLIRef, Verified: VerifiedDoc, Owner: OwnerUser,
		},
		{
			ID: "kiro-cli/chat.enablePromptHints", Tool: "kiro-cli", FileID: kiroCLISettings, Path: KeyPath{"chat", "enablePromptHints"}, Type: TypeBool, Default: "true",
			Desc: "Startup tips and shortcuts.", Source: kiroCLIRef, Verified: VerifiedDoc, Owner: OwnerUser,
		},
		{
			ID: "kiro-cli/chat.autoExpandToolOutput", Tool: "kiro-cli", FileID: kiroCLISettings, Path: KeyPath{"chat", "autoExpandToolOutput"}, Type: TypeBool,
			Desc: "Expand tool output instead of collapsed previews.", Source: kiroCLIRef, Verified: VerifiedDoc, Owner: OwnerUser,
		},
		{
			ID: "kiro-cli/chat.disableWrap", Tool: "kiro-cli", FileID: kiroCLISettings, Path: KeyPath{"chat", "disableWrap"}, Type: TypeBool,
			Desc: "Print output without hard line breaks.", Source: kiroCLIRef, Verified: VerifiedDoc, Owner: OwnerUser,
		},
		{
			ID: "kiro-cli/chat.allowAnimations", Tool: "kiro-cli", FileID: kiroCLISettings, Path: KeyPath{"chat", "allowAnimations"}, Type: TypeBool, Default: "true",
			Desc: "Animated spinners and shimmers.", Source: kiroCLIRef, Verified: VerifiedDoc, Owner: OwnerUser,
		},
		{
			ID: "kiro-cli/chat.preserveScrollback", Tool: "kiro-cli", FileID: kiroCLISettings, Path: KeyPath{"chat", "preserveScrollback"}, Type: TypeBool, Default: "true",
			Desc: "Keep terminal history when the interface redraws.", Source: kiroCLIRef, Verified: VerifiedDoc, Owner: OwnerUser,
		},
		{
			ID: "kiro-cli/chat.diffTool", Tool: "kiro-cli", FileID: kiroCLISettings, Path: KeyPath{"chat", "diffTool"}, Type: TypeString,
			Desc: "External diff tool.", Source: kiroCLIRef, Verified: VerifiedDoc, Owner: OwnerUser, Note: kiroCLIClassic,
		},
		{
			ID: "kiro-cli/chat.editMode", Tool: "kiro-cli", FileID: kiroCLISettings, Path: KeyPath{"chat", "editMode"}, Type: TypeBool,
			Desc: "Vi edit mode.", Source: kiroCLIRef, Verified: VerifiedDoc, Owner: OwnerUser, Note: kiroCLIClassic,
		},
		{
			ID: "kiro-cli/chat.keybindings.quit", Tool: "kiro-cli", FileID: kiroCLISettings, Path: KeyPath{"chat", "keybindings", "quit"}, Type: TypeString,
			Default: `"ctrl+c"`, Desc: "Key that exits the chat.", Source: kiroCLIRef, Verified: VerifiedDoc, Owner: OwnerUser,
		},
		{
			ID: "kiro-cli/knowledge.maxFiles", Tool: "kiro-cli", FileID: kiroCLISettings, Path: KeyPath{"knowledge", "maxFiles"}, Type: TypeInt,
			Desc: "Maximum files the knowledge base indexes.", Source: kiroCLIRef, Verified: VerifiedDoc, Owner: OwnerUser,
		},
		{
			ID: "kiro-cli/knowledge.defaultExcludePatterns", Tool: "kiro-cli", FileID: kiroCLISettings, Path: KeyPath{"knowledge", "defaultExcludePatterns"},
			Type: TypeStringList, Desc: "File patterns the knowledge base skips.", Source: kiroCLIRef, Verified: VerifiedDoc, Owner: OwnerUser,
		},
		// --- mcp.json
		{
			ID: "kiro-cli/mcpServers", Tool: "kiro-cli", FileID: kiroCLIMCP, Path: KeyPath{"mcpServers"}, Type: TypeMCPMap,
			Desc: "MCP servers: command, args, env, timeout.", Source: kiroCLIConfRef, Verified: VerifiedDoc, Owner: OwnerUser,
			Note: "An agent can drop these servers with includeMcpJson: false in its agent JSON.",
		},
		// --- permissions (permissions.yaml and managed-settings.json)
		{
			ID: "kiro-cli/rules", Tool: "kiro-cli", FileID: kiroCLIPerms, Path: KeyPath{"rules"}, Type: TypeObject,
			Desc:   "Permission rules {capability, effect, match, exclude}; capability shell | fs_read | fs_write | web_fetch | web_search | mcp, effect allow | ask | deny.",
			Source: kiroCLIPermsRef, Verified: VerifiedDoc, Owner: OwnerUser, Danger: DangerConfirm,
			Note: "effect: allow with match [\"*\"] runs everything unasked; the managed file accepts only deny and ask. 2.x toolsSettings.shell.allowedCommands is deprecated in favour of these rules.",
		},
		// --- hooks (v3 files)
		{
			ID: "kiro-cli/version", Tool: "kiro-cli", FileID: kiroCLIHooks, Path: KeyPath{"version"}, Type: TypeString, Default: `"v1"`,
			Desc: "Hook file format version.", Source: kiroCLIHooksRef, Verified: VerifiedDoc, Owner: OwnerUser,
		},
		{
			ID: "kiro-cli/hooks", Tool: "kiro-cli", FileID: kiroCLIHooks, Path: KeyPath{"hooks"}, Type: TypeObject,
			Desc:   "Hooks {name, trigger, matcher, action {type command, command}, timeout, enabled}; triggers SessionStart, UserPromptSubmit, PreToolUse, PostToolUse, PostFileSave, PostFileCreate, Stop.",
			Source: kiroCLIHooksRef, Verified: VerifiedDoc, Owner: OwnerUser, Note: "enabled: false on an Observer hook switches it off.",
		},
	},
	Map: []MapRow{
		{Key: KeyModel, Tool: "kiro-cli", Settings: []string{"kiro-cli/chat.defaultModel"}, Transform: TransformModelAlias, Source: kiroCLIRef},
		{Key: KeyTelemetryOff, Tool: "kiro-cli", Settings: []string{"kiro-cli/telemetry.enabled"}, Transform: TransformBoolInvert, Source: kiroCLIRef},
		{Key: KeyAutoUpdate, Tool: "kiro-cli", Settings: []string{"kiro-cli/app.disableAutoupdates"}, Transform: TransformBoolInvert, Source: kiroCLIRef},
		{
			Key: KeyMCPServers, Tool: "kiro-cli", Settings: []string{"kiro-cli/mcpServers"}, Transform: TransformMCPShape,
			Params: TransformParams{MCP: kiroCLIMCPShape}, Lossy: true, Source: kiroCLIConfRef,
			Note: "Local servers only (remote transports are not grounded). " + mcpLossyNote,
		},
	},
}
