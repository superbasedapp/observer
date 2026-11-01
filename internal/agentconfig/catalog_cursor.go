package agentconfig

// Cursor (phase P2, doc-authored). Two surfaces under one tool id: the
// cursor-agent CLI (cli-config.json, user-writable JSON that also carries
// auth state and server caches) and the IDE (a VS Code fork whose AI
// settings live in its SQLite state.vscdb, which is never read or written:
// it also holds auth state, so it gets no Files row at all). Sources: audit
// docs/audits/adapter-config-surface-2026-10-03.md section 5 "cursor" and
// the vendor pages below, re-fetched 2026-10-04.

const (
	cursorCLIRef      = "https://cursor.com/docs/cli/reference/configuration"
	cursorPermRef     = "https://cursor.com/docs/cli/reference/permissions"
	cursorHooksRef    = "https://cursor.com/docs/hooks"
	cursorMCPRef      = "https://cursor.com/docs/context/mcp"
	cursorPermsJSONRf = "https://cursor.com/docs/reference/permissions"
	cursorDeployRef   = "https://cursor.com/docs/enterprise/deployment-patterns"
	cursorVSCodeFAQ   = "https://code.visualstudio.com/docs/supporting/faq"
	cursorLiveRef     = "docs/audits/adapter-config-surface-2026-10-03.md section 5 cursor + section 6 (node 1 live key names, 2026-10-03)"
	cursorLiveNote    = "Key name seen live on node 1 (2026-10-03); the probe recorded names and types only."
)

// cursorCLIUserOnly: cli-config.json keys the project cli.json does not
// accept (it carries permissions only).
var cursorCLIUserOnly = []Scope{ScopeUser}

var cursorFiles = []FileRow{
	{
		ID: "cursor/user-cli-config", Tool: "cursor", Shape: "cursor/cli-config", Kind: KindSettings, Scope: ScopeUser,
		Paths: samePath("~/.cursor/cli-config.json"), Format: FormatJSON, Precedence: 20, WriteNeeds: PrivUser,
		Grounding: live("~/.cursor/cli-config.json carries approvalMode, model, sandbox, permissions beside authInfo and server caches"),
		Note:      "cursor-agent CLI config. CURSOR_CONFIG_DIR relocates it; on Linux/BSD $XDG_CONFIG_HOME/cursor/cli-config.json is used when set. The file mixes user keys with auth state and server caches: only the user-owned rows are editable.",
	},
	{
		ID: "cursor/project-cli-config", Tool: "cursor", Shape: "cursor/cli-config", Kind: KindSettings, Scope: ScopeProjectShared,
		Paths: samePath("<project>/.cursor/cli.json"), Format: FormatJSON, Precedence: 30, WriteNeeds: PrivUser,
		Grounding: doc(cursorCLIRef), Note: "Project CLI config: permissions only.",
	},
	{
		ID: "cursor/user-hooks", Tool: "cursor", Shape: "cursor/hooks", Kind: KindHooks, Scope: ScopeUser,
		Paths: samePath("~/.cursor/hooks.json"), Format: FormatJSON, Precedence: 20, WriteNeeds: PrivUser,
		Grounding: live("~/.cursor/hooks.json carries 18 Observer-registered events"),
		Note:      "Lowest hook layer (user < project < team < enterprise); all layers merge, and a deny from any layer wins over ask and allow.",
	},
	{
		ID: "cursor/project-hooks", Tool: "cursor", Shape: "cursor/hooks", Kind: KindHooks, Scope: ScopeProjectShared,
		Paths: samePath("<project>/.cursor/hooks.json"), Format: FormatJSON, Precedence: 30, WriteNeeds: PrivUser,
		Grounding: doc(cursorHooksRef), Note: "Loaded for trusted workspaces; scripts run from the project root.",
	},
	{
		ID: "cursor/enterprise-hooks", Tool: "cursor", Shape: "cursor/hooks", Kind: KindHooks, Scope: ScopeManaged,
		Paths: OSPaths{
			Linux:   "/etc/cursor/hooks.json",
			Darwin:  "/Library/Application Support/Cursor/hooks.json",
			Windows: `C:\ProgramData\Cursor\hooks.json`,
		},
		Format: FormatJSON, Precedence: 100, WriteNeeds: PrivAdminRoot, Grounding: doc(cursorHooksRef),
		Note: "Enterprise (MDM-deployed) hooks, the highest layer. Team hooks from the cloud dashboard sit between project and enterprise; cursor-agent caches them in cursor/team-hooks.",
	},
	{
		// FU-108 (MAC-4): the cursor-agent bundle's hook loader joins this
		// file beside the enterprise, user and project ones. It is the
		// server's team hooks as cursor-agent last fetched them, so it is
		// read-only evidence, never an edit target. A layer evaluator would
		// pick it up through its shape; no Cursor hooks family exists yet,
		// and nothing in it can remove Observer's user-level entries (the
		// layers merge), so no Observer reader consumes it.
		ID: "cursor/team-hooks", Tool: "cursor", Shape: "cursor/hooks", Kind: KindHooks, Scope: ScopeUser,
		Paths: samePath("~/.cursor/managed/active-team-hooks/hooks.json"), Format: FormatJSON, Precedence: 50, WriteNeeds: PrivNever,
		Grounding: mac4Source("cursor-agent 2026.10.22-27dcf5f bundle: the hooks loader that joins the enterprise /Library/Application Support/Cursor/hooks.json also reads ~/.cursor/managed/active-team-hooks/hooks.json"),
		Note: "Team hooks from the cloud dashboard, cached by cursor-agent (server-managed state): shown read-only, never written. Sits between project and enterprise. " +
			"Read from the macOS bundle; the same home-relative join is assumed on Linux and Windows (not live-checked), and whether CURSOR_CONFIG_DIR moves it is unverified, so it carries no relocation rule.",
	},
	{
		ID: "cursor/user-mcp", Tool: "cursor", Shape: "cursor/mcp", Kind: KindMCP, Scope: ScopeUser,
		Paths: samePath("~/.cursor/mcp.json"), Format: FormatJSON, Precedence: 20, WriteNeeds: PrivUser,
		Grounding: live("~/.cursor/mcp.json present"), Note: "Global MCP servers (IDE and CLI).",
	},
	{
		ID: "cursor/project-mcp", Tool: "cursor", Shape: "cursor/mcp", Kind: KindMCP, Scope: ScopeProjectShared,
		Paths: samePath("<project>/.cursor/mcp.json"), Format: FormatJSON, Precedence: 30, WriteNeeds: PrivUser,
		Grounding: doc(cursorMCPRef),
	},
	{
		ID: "cursor/user-permissions", Tool: "cursor", Shape: "cursor/permissions", Kind: KindPermissions, Scope: ScopeUser,
		Paths: samePath("~/.cursor/permissions.json"), Format: FormatJSONC, Precedence: 20, WriteNeeds: PrivUser,
		Grounding: doc(cursorPermsJSONRf),
		Note:      "IDE allowlists. A key present here replaces the matching in-app allowlist and makes it read-only in the settings UI; the team dashboard still wins. MDM can deploy this file.",
	},
	{
		ID: "cursor/project-permissions", Tool: "cursor", Shape: "cursor/permissions", Kind: KindPermissions, Scope: ScopeProjectShared,
		Paths: samePath("<project>/.cursor/permissions.json"), Format: FormatJSONC, Precedence: 30, WriteNeeds: PrivUser,
		Grounding: doc(cursorPermsJSONRf),
		Note:      "Arrays concatenate with the user file (neither replaces the other). A forum report (forum.cursor.com/t/163614) says some builds do not load the project file.",
	},
	{
		ID: "cursor/policy", Tool: "cursor", Shape: "cursor/policy", Kind: KindSettings, Scope: ScopeManaged,
		Paths: OSPaths{Linux: "~/.cursor/policy.json"}, Format: FormatJSON, Precedence: 100, WriteNeeds: PrivAdminRoot,
		Grounding: doc(cursorDeployRef),
		Note:      "Linux IDE policy file (Cursor 2.0+), keys are policy names. The location is user-writable, so it is lever B: Observer treats it as admin-authored and never writes it as the user. macOS uses a configuration profile (bundle id com.todesktop.230313mzl4w4u92) and Windows Group Policy ADMX/ADML; neither is a file.",
	},
	{
		ID: "cursor/ide-user-settings", Tool: "cursor", Shape: "cursor/ide-settings", Kind: KindSettings, Scope: ScopeUser,
		Paths: OSPaths{
			Linux:   "~/.config/Cursor/User/settings.json",
			Darwin:  "~/Library/Application Support/Cursor/User/settings.json",
			Windows: `%APPDATA%\Cursor\User\settings.json`,
		},
		Format: FormatVSCodeSettings, Precedence: 20, WriteNeeds: PrivUser,
		Grounding: doc("https://cursor.com/docs/cli/reference/configuration"),
		Note:      "IDE (VS Code fork) settings. Most AI settings (model, auto-run mode, BYOK keys and base URL) live in User/globalStorage/state.vscdb, a SQLite store that also holds auth state: it is never read or written and has no row here.",
	},
	{
		ID: "cursor/ide-workspace-settings", Tool: "cursor", Shape: "cursor/ide-settings", Kind: KindSettings, Scope: ScopeProjectShared,
		Paths: samePath("<project>/.vscode/settings.json"), Format: FormatVSCodeSettings, Precedence: 30, WriteNeeds: PrivUser,
		Grounding: doc("https://cursor.com/docs/cli/reference/configuration"),
		Note:      "Shared with every VS Code-family editor that opens the folder.",
	},
}

// cursorRows fills Tool, ID (Tool + "/" + Path), and the user owner / doc
// verification defaults.
func cursorRows(rows []SettingRow) []SettingRow {
	for i := range rows {
		r := &rows[i]
		r.Tool = "cursor"
		r.ID = r.Tool + "/" + r.Path.String()
		if r.Owner == "" {
			r.Owner = OwnerUser
		}
		if r.Verified == "" {
			r.Verified = VerifiedDoc
		}
	}
	return rows
}

var cursorSettings = cursorRows([]SettingRow{
	// --- cli-config.json / .cursor/cli.json
	{
		FileID: "cursor/cli-config", Path: KeyPath{"version"}, Scopes: cursorCLIUserOnly, Type: TypeInt, Enum: []string{"1"},
		Desc: "Config schema version (required).", Source: cursorCLIRef, Owner: OwnerToolState,
	},
	{FileID: "cursor/cli-config", Path: KeyPath{"editor", "vimMode"}, Scopes: cursorCLIUserOnly, Type: TypeBool, Default: "false", Desc: "Vim keybindings in the CLI composer.", Source: cursorCLIRef},
	{
		FileID: "cursor/cli-config", Path: KeyPath{"permissions", "allow"}, Type: TypeRuleList, Default: "[]",
		Desc: "Permission tokens that run without asking: Shell(cmd), Read(glob), Write(glob), WebFetch(domain), Mcp(server:tool).", Source: cursorPermRef,
		Verified: VerifiedLive, Danger: DangerConfirm, Note: "Dangerous: broad tokens such as Shell(*), Write(**) or WebFetch(*). " + cursorLiveNote,
	},
	{
		FileID: "cursor/cli-config", Path: KeyPath{"permissions", "deny"}, Type: TypeRuleList, Default: "[]",
		Desc: "Permission tokens that never run; deny wins over allow.", Source: cursorPermRef, Verified: VerifiedLive, Note: cursorLiveNote,
	},
	{FileID: "cursor/cli-config", Path: KeyPath{"channel"}, Scopes: cursorCLIUserOnly, Type: TypeString, Desc: "CLI release channel.", Source: cursorCLIRef},
	{
		FileID: "cursor/cli-config", Path: KeyPath{"model"}, Scopes: cursorCLIUserOnly, Type: TypeObject,
		Desc: "Selected model settings (an object).", Source: cursorCLIRef, Verified: VerifiedLive,
		Note: "Live sub-keys: modelId, displayModelId, aliases, maxMode. " + cursorLiveNote,
	},
	{
		FileID: "cursor/cli-config", Path: KeyPath{"model", "modelId"}, Scopes: cursorCLIUserOnly, Type: TypeString,
		Desc: "Model id the CLI starts with.", Source: cursorLiveRef, Verified: VerifiedLive, Note: cursorLiveNote,
	},
	{
		FileID: "cursor/cli-config", Path: KeyPath{"model", "displayModelId"}, Scopes: cursorCLIUserOnly, Type: TypeString,
		Desc: "Display id the CLI stores beside modelId.", Source: cursorLiveRef, Verified: VerifiedLive, Owner: OwnerToolState,
		Note: "Written by the CLI's model picker. " + cursorLiveNote,
	},
	{
		FileID: "cursor/cli-config", Path: KeyPath{"model", "aliases"}, Scopes: cursorCLIUserOnly, Type: TypeObject,
		Desc: "Model aliases the CLI stores with the selection.", Source: cursorLiveRef, Verified: VerifiedLive, Owner: OwnerToolState,
		Note: "Value shape not recorded by the probe. " + cursorLiveNote,
	},
	{
		FileID: "cursor/cli-config", Path: KeyPath{"model", "maxMode"}, Scopes: cursorCLIUserOnly, Type: TypeBool,
		Desc: "Max mode for the selected model.", Source: cursorLiveRef, Verified: VerifiedLive, Note: cursorLiveNote,
	},
	{
		FileID: "cursor/cli-config", Path: KeyPath{"selectedModel", "modelId"}, Scopes: cursorCLIUserOnly, Type: TypeString,
		Desc: "Model id the CLI's picker last selected.", Source: cursorLiveRef, Verified: VerifiedLive, Owner: OwnerToolState,
		Note: "Not on the vendor reference. " + cursorLiveNote,
	},
	{
		FileID: "cursor/cli-config", Path: KeyPath{"exploreSubagentModel"}, Scopes: cursorCLIUserOnly, Type: TypeObject,
		Desc: "Model the explore subagent uses.", Source: cursorLiveRef, Verified: VerifiedLive,
		Note: "Not on the vendor reference; value shape not recorded by the probe. " + cursorLiveNote,
	},
	{FileID: "cursor/cli-config", Path: KeyPath{"maxMode"}, Scopes: cursorCLIUserOnly, Type: TypeBool, Desc: "Persisted max mode preference.", Source: cursorCLIRef},
	{
		FileID: "cursor/cli-config", Path: KeyPath{"hasChangedDefaultModel"}, Scopes: cursorCLIUserOnly, Type: TypeBool,
		Desc: "CLI-managed flag recording a model override.", Source: cursorCLIRef, Owner: OwnerToolState,
	},
	{FileID: "cursor/cli-config", Path: KeyPath{"notifications"}, Scopes: cursorCLIUserOnly, Type: TypeBool, Desc: "Terminal notification when the agent finishes.", Source: cursorCLIRef},
	{FileID: "cursor/cli-config", Path: KeyPath{"hints"}, Scopes: cursorCLIUserOnly, Type: TypeBool, Desc: "Show CLI hints while the agent works.", Source: cursorCLIRef},
	{FileID: "cursor/cli-config", Path: KeyPath{"rewind"}, Scopes: cursorCLIUserOnly, Type: TypeBool, Desc: "Enable the /rewind command.", Source: cursorCLIRef},
	{FileID: "cursor/cli-config", Path: KeyPath{"suggestNextPrompt"}, Scopes: cursorCLIUserOnly, Type: TypeBool, Desc: "Suggest follow-up prompts.", Source: cursorCLIRef},
	{FileID: "cursor/cli-config", Path: KeyPath{"display", "showLineNumbers"}, Scopes: cursorCLIUserOnly, Type: TypeBool, Desc: "Line numbers in code blocks.", Source: cursorCLIRef},
	{FileID: "cursor/cli-config", Path: KeyPath{"display", "showThinkingBlocks"}, Scopes: cursorCLIUserOnly, Type: TypeBool, Desc: "Render thinking blocks.", Source: cursorCLIRef},
	{FileID: "cursor/cli-config", Path: KeyPath{"display", "showStatusIndicators"}, Scopes: cursorCLIUserOnly, Type: TypeBool, Desc: "Status indicators in the terminal title.", Source: cursorCLIRef},
	{FileID: "cursor/cli-config", Path: KeyPath{"display", "showStatusLineRunningTime"}, Scopes: cursorCLIUserOnly, Type: TypeBool, Desc: "Elapsed time in the status line.", Source: cursorCLIRef},
	{
		FileID: "cursor/cli-config", Path: KeyPath{"approvalMode"}, Scopes: cursorCLIUserOnly, Type: TypeEnum,
		Enum: []string{"allowlist", "auto-review", "unrestricted"}, Desc: "How the CLI approves agent actions.", Source: cursorCLIRef,
		Verified: VerifiedLive, Danger: DangerConfirm, Note: "Dangerous: \"unrestricted\" (same as --force / --yolo). " + cursorLiveNote,
	},
	{
		FileID: "cursor/cli-config", Path: KeyPath{"sandbox", "mode"}, Scopes: cursorCLIUserOnly, Type: TypeString,
		Desc: "Sandbox mode override.", Source: cursorCLIRef, Verified: VerifiedLive, Danger: DangerConfirm,
		Note: "The vendor reference names no values; a disabled sandbox is dangerous. " + cursorLiveNote,
	},
	{
		FileID: "cursor/cli-config", Path: KeyPath{"sandbox", "networkAccess"}, Scopes: cursorCLIUserOnly, Type: TypeString,
		Desc: "Sandbox network access setting.", Source: cursorCLIRef, Verified: VerifiedLive, Danger: DangerConfirm,
		Note: "The vendor reference names no values; open network access is dangerous. " + cursorLiveNote,
	},
	{FileID: "cursor/cli-config", Path: KeyPath{"network", "useHttp1ForAgent"}, Scopes: cursorCLIUserOnly, Type: TypeBool, Default: "false", Desc: "Use HTTP/1.1 for agent connections.", Source: cursorCLIRef},
	{
		FileID: "cursor/cli-config", Path: KeyPath{"attribution", "attributeCommitsToAgent"}, Scopes: cursorCLIUserOnly, Type: TypeBool, Default: "true",
		Desc: "Add \"Made with Cursor\" to commits.", Source: cursorCLIRef, Verified: VerifiedLive, Note: cursorLiveNote,
	},
	{
		FileID: "cursor/cli-config", Path: KeyPath{"attribution", "attributePRsToAgent"}, Scopes: cursorCLIUserOnly, Type: TypeBool, Default: "true",
		Desc: "Add \"Made with Cursor\" to pull requests.", Source: cursorCLIRef, Verified: VerifiedLive, Note: cursorLiveNote,
	},
	{
		FileID: "cursor/cli-config", Path: KeyPath{"privacyCache", "privacyMode"}, Scopes: cursorCLIUserOnly, Type: TypeObject,
		Desc: "Cached privacy mode from the account or team.", Source: cursorLiveRef, Verified: VerifiedLive, Owner: OwnerServerCache,
		Note: "Privacy mode itself is set in the UI or enforced by the team dashboard. " + cursorLiveNote,
	},
	{
		FileID: "cursor/cli-config", Path: KeyPath{"authInfo"}, Scopes: cursorCLIUserOnly, Type: TypeObject,
		Desc: "CLI sign-in state.", Source: cursorLiveRef, Verified: VerifiedLive, Owner: OwnerToolState, Secret: true,
		Note: "Auth state: never read, shown or written by value. " + cursorLiveNote,
	},
	{
		FileID: "cursor/cli-config", Path: KeyPath{"serverConfigCache"}, Scopes: cursorCLIUserOnly, Type: TypeObject,
		Desc: "Server-delivered configuration cache.", Source: cursorLiveRef, Verified: VerifiedLive, Owner: OwnerServerCache, Note: cursorLiveNote,
	},
	{
		FileID: "cursor/cli-config", Path: KeyPath{"autoReviewAvailabilityCache"}, Scopes: cursorCLIUserOnly, Type: TypeObject,
		Desc: "Cached auto-review availability.", Source: cursorLiveRef, Verified: VerifiedLive, Owner: OwnerServerCache, Note: cursorLiveNote,
	},

	// --- hooks.json (user / project / enterprise)
	{
		FileID: "cursor/hooks", Path: KeyPath{"hooks"}, Type: TypeObject,
		Desc:   "Hook commands keyed by event (sessionStart, preToolUse, beforeShellExecution, stop and others); each entry has command, type, timeout, matcher, loop_limit, failClosed.",
		Source: cursorHooksRef,
		Note: "Observer's own hook entries in ~/.cursor/hooks.json are an owned span: the editor locks those entries only. " +
			"The file also carries a top-level version (1); it has no row because a row id is tool + key path and cli-config.json owns cursor/version.",
	},

	// --- mcp.json
	{
		FileID: "cursor/mcp", Path: KeyPath{"mcpServers"}, Type: TypeMCPMap,
		Desc: "MCP servers by name: {type: stdio, command, args, env, envFile} or {url, headers, auth}.", Source: cursorMCPRef,
		Note: "Observer's \"observer\" entry in ~/.cursor/mcp.json is an owned span. auth may hold an OAuth client secret: the secret posture applies.",
	},

	// --- permissions.json
	{
		FileID: "cursor/permissions", Path: KeyPath{"terminalAllowlist"}, Type: TypeStringList,
		Desc: "Terminal command prefixes that run without approval.", Source: cursorPermsJSONRf, Danger: DangerConfirm,
		Note: "Dangerous: [\"*\"] or other broad prefixes; an allowlist also disables auto-review for matching calls.",
	},
	{
		FileID: "cursor/permissions", Path: KeyPath{"mcpAllowlist"}, Type: TypeStringList,
		Desc: "MCP tools (server:tool, globs allowed) that run without approval.", Source: cursorPermsJSONRf, Danger: DangerConfirm,
		Note: "Dangerous: \"*:*\" (every tool of every server).",
	},
	{FileID: "cursor/permissions", Path: KeyPath{"autoRun"}, Type: TypeObject, Desc: "Steering hints for the auto-review classifier.", Source: cursorPermsJSONRf},
	{
		FileID: "cursor/permissions", Path: KeyPath{"autoRun", "allow_instructions"}, Type: TypeStringList,
		Desc: "Natural-language hints for calls auto-review should allow.", Source: cursorPermsJSONRf, Note: "Steering only, not enforcement; no effect outside auto-review mode.",
	},
	{
		FileID: "cursor/permissions", Path: KeyPath{"autoRun", "block_instructions"}, Type: TypeStringList,
		Desc: "Natural-language hints for calls auto-review should block.", Source: cursorPermsJSONRf,
	},

	// --- policy.json (Linux IDE policy)
	{FileID: "cursor/policy", Path: KeyPath{"AllowedExtensions"}, Type: TypeString, Desc: "JSON object of allowed publishers or extension ids.", Source: cursorDeployRef},
	{FileID: "cursor/policy", Path: KeyPath{"AllowedTeamId"}, Type: TypeString, Desc: "Comma-separated team ids allowed to sign in.", Source: cursorDeployRef},
	{
		FileID: "cursor/policy", Path: KeyPath{"ExtensionGalleryServiceUrl"}, Type: TypeString, Desc: "Custom extension marketplace endpoint.",
		Source: cursorDeployRef, Danger: DangerConfirm, Note: "Redirects extension installs to another host.",
	},
	{FileID: "cursor/policy", Path: KeyPath{"NetworkDisableHttp2"}, Type: TypeBool, Desc: "Disable HTTP/2.", Source: cursorDeployRef},
	{
		FileID: "cursor/policy", Path: KeyPath{"UpdateMode"}, Type: TypeEnum, Enum: []string{"none", "manual", "start", "default", "silentlyApplyOnQuit"},
		Desc: "IDE update mode, locked for the user.", Source: cursorDeployRef,
	},
	{
		FileID: "cursor/policy", Path: KeyPath{"WorkspaceTrustEnabled"}, Type: TypeBool, Desc: "Workspace trust on or off.", Source: cursorDeployRef,
		Danger: DangerConfirm, Note: "Dangerous: false loads project hooks and rules from untrusted repositories.",
	},

	// --- IDE settings.json (VS Code keys)
	{
		FileID: "cursor/ide-settings", Path: KeyPath{"update.mode"}, Scopes: []Scope{ScopeUser}, Type: TypeEnum,
		Enum: []string{"none", "manual", "start", "default"}, Default: "\"default\"",
		Desc: "IDE update mode.", Source: cursorVSCodeFAQ, Note: "VS Code key; policy UpdateMode locks it (cursor/policy).",
	},
	{
		FileID: "cursor/ide-settings", Path: KeyPath{"workbench.colorTheme"}, Type: TypeString, Desc: "Color theme name.",
		Source: "https://code.visualstudio.com/docs/configure/themes", Note: "VS Code key; the audit names it for Cursor V16.",
	},
})

// cursorMCPShape: mcpServers.<name> with an explicit "type": "stdio" for
// local servers. Remote entries carry url (and headers / auth) with no type
// in the vendor docs, so the canonical remote transports are refused rather
// than guessed.
var cursorMCPShape = MCPShape{
	EnvKey: "env", TypeKey: "type", StdioTypeExplicit: true,
	TypeNames: map[string]string{"stdio": "stdio"},
}

var cursorMap = []MapRow{
	{
		Key: KeyModel, Tool: "cursor", Settings: []string{"cursor/model.modelId"}, Transform: TransformModelAlias, Source: cursorLiveRef,
		Note: "CLI only (the IDE model lives in state.vscdb). The CLI also stores displayModelId beside it.",
	},
	{
		Key: KeyMCPServers, Tool: "cursor", Settings: []string{"cursor/mcpServers"}, Transform: TransformMCPShape,
		Params: TransformParams{MCP: cursorMCPShape}, Lossy: true, Source: cursorMCPRef,
		Note: "Local servers only: remote (http / sse) servers are refused because the docs give remote entries no type. " + mcpLossyNote,
	},
	{
		Key: KeyAutoUpdate, Tool: "cursor", Settings: []string{"cursor/\"update.mode\""}, Transform: TransformEnumMap,
		Params: TransformParams{Enum: []EnumPair{{true, []any{"default"}}, {false, []any{"none"}}}}, Source: cursorVSCodeFAQ,
		Note: "IDE only. manual and start have no canonical form.",
	},
}

var cursorCatalog = toolCatalog{
	Tool: "cursor",
	VerifiedAgainst: "cursor.com CLI configuration / permissions / hooks / MCP / permissions.json / deployment-patterns pages fetched 2026-10-04 " +
		"(audit section 5); node 1 live key names 2026-10-03 for approvalMode, model.*, selectedModel.modelId, exploreSubagentModel, " +
		"sandbox.*, permissions.*, attribution.*, privacyCache.privacyMode and the auth / cache keys. IDE AI settings in state.vscdb are not catalogued (never read).",
	Files: cursorFiles,
	Extra: cursorSettings,
	Map:   cursorMap,
}
