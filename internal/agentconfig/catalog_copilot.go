package agentconfig

// GitHub Copilot in VS Code (phase P2, doc-authored). Its settings are VS
// Code settings (one dotted key = ONE KeyPath segment) in the user and
// workspace settings.json; VS Code policies lock a subset. Sources: audit
// docs/audits/adapter-config-surface-2026-10-03.md section 5 "copilot" and
// the VS Code pages below, re-fetched 2026-10-04.

const (
	copilotRef       = "https://code.visualstudio.com/docs/copilot/reference/copilot-settings"
	copilotPolicyRef = "https://code.visualstudio.com/docs/enterprise/policies"
	copilotMCPRef    = "https://code.visualstudio.com/docs/copilot/customization/mcp-servers"
	copilotTelemRef  = "https://code.visualstudio.com/docs/configure/telemetry"
	copilotFAQRef    = "https://code.visualstudio.com/docs/supporting/faq"
	copilotThemeRef  = "https://code.visualstudio.com/docs/configure/themes"
	copilotPolicyNt  = "Policy-backed: /etc/vscode/policy.json (Linux), the Windows registry or a macOS profile locks it."
	copilotVSMCPRef  = "https://learn.microsoft.com/en-us/visualstudio/ide/mcp-servers"
)

// copilotNoPolicy: an ordinary setting with no VS Code policy behind it.
var copilotNoPolicy = []Scope{ScopeUser, ScopeProjectShared}

var copilotFiles = []FileRow{
	{
		ID: "copilot/user-settings", Tool: "copilot", Shape: "copilot/vscode-settings", Kind: KindSettings, Scope: ScopeUser,
		Paths: samePath("<vscode>/User/settings.json"), Format: FormatVSCodeSettings, Precedence: 20, WriteNeeds: PrivUser,
		Grounding: doc(copilotRef),
		Note: "<vscode> is the VS Code user data dir: Linux ~/.config/Code, macOS ~/Library/Application Support/Code, Windows %APPDATA%\\Code " +
			"(Insiders: Code - Insiders; profiles under User/profiles/<id>/). Observer's copilot setup already edits this file JSONC-preserving.",
	},
	{
		ID: "copilot/workspace-settings", Tool: "copilot", Shape: "copilot/vscode-settings", Kind: KindSettings, Scope: ScopeProjectShared,
		Paths: samePath("<project>/.vscode/settings.json"), Format: FormatVSCodeSettings, Precedence: 30, WriteNeeds: PrivUser,
		Grounding: doc(copilotRef), Note: "Multi-root *.code-workspace files carry the same keys in a settings block.",
	},
	{
		ID: "copilot/policy", Tool: "copilot", Shape: "copilot/vscode-settings", Kind: KindSettings, Scope: ScopeManaged,
		Paths: OSPaths{Linux: "/etc/vscode/policy.json"}, Format: FormatJSON, Precedence: 100, WriteNeeds: PrivAdminRoot,
		Grounding: doc(copilotPolicyRef),
		Note: "Linux policy file (VS Code 1.106+), keyed by setting id; a policy greys the setting out. Windows uses the registry " +
			"(Software\\Policies\\Microsoft\\VSCode, ADMX) and macOS a .mobileconfig profile: neither is a file. Policies with no setting id " +
			"(ChatAllowedMcpServers, ChatDeniedMcpServers, McpGalleryServiceUrl, ChatStrictPluginOnlyCustomization) have no row.",
	},
	{
		ID: "copilot/workspace-mcp", Tool: "copilot", Shape: "copilot/mcp", Kind: KindMCP, Scope: ScopeProjectShared,
		Paths: samePath("<project>/.vscode/mcp.json"), Format: FormatJSONC, Precedence: 30, WriteNeeds: PrivUser,
		Grounding: doc(copilotMCPRef),
		Note: "Workspace MCP servers (key servers). The user-profile mcp.json is opened through \"MCP: Open User Configuration\" (path not stated by the docs); " +
			"the portable .mcp.json and ~/.copilot/mcp-config.json use mcpServers.",
	},
	{
		ID: "copilot/visual-studio-user-mcp", Tool: "copilot", Shape: "copilot/visual-studio-mcp", Kind: KindMCP, Scope: ScopeUser,
		Paths: OSPaths{Windows: `%USERPROFILE%\.mcp.json`}, Format: FormatJSON, Precedence: 20, WriteNeeds: PrivNever,
		Grounding: doc(copilotVSMCPRef),
		Note: "Visual Studio 2022 / 2026 (and SSMS 22): the user-global MCP file, read first of five (then <sln>\\.vs\\mcp.json, <sln>\\.mcp.json, <sln>\\.vscode\\mcp.json, <sln>\\.cursor\\mcp.json); key servers. " +
			"Its own shape, so no VS Code Copilot setting (servers included) ever resolves to it, and PrivNever for every catalogue writer: " +
			"only Observer's MCP writer for it (target visual-studio, surface-gap S-3) targets it, built and switched off until live check LCR-68.",
	},
}

func copilotRows(rows []SettingRow) []SettingRow {
	for i := range rows {
		r := &rows[i]
		r.Tool = "copilot"
		r.ID = r.Tool + "/" + r.Path.String()
		if r.FileID == "" {
			r.FileID = "copilot/vscode-settings"
		}
		if r.Owner == "" {
			r.Owner = OwnerUser
		}
		if r.Verified == "" {
			r.Verified = VerifiedDoc
		}
		if r.Source == "" {
			r.Source = copilotRef
		}
	}
	return rows
}

func copilotKey(k string) KeyPath { return KeyPath{k} }

var copilotSettings = copilotRows([]SettingRow{
	// --- approvals and auto-approve
	{
		Path: copilotKey("chat.tools.global.autoApprove"), Type: TypeBool, Default: "false",
		Desc: "Approve every tool call without asking.", Danger: DangerConfirm,
		Note: "Dangerous: true disables critical security protections (\"YOLO\"). " + copilotPolicyNt + " (ChatToolsAutoApprove)",
	},
	{
		Path: copilotKey("chat.tools.terminal.autoApprove"), Scopes: copilotNoPolicy, Type: TypeObject,
		Desc: "Terminal commands (or /regex/flags) mapped to true (auto-approve) or false (always ask).", Danger: DangerConfirm,
		Note: "Dangerous: entries set true for broad commands or regexes. The default sets rm, rmdir, del, kill, curl, wget, eval, chmod, chown to false; false means always ask, not a hard deny.",
	},
	{
		Path: copilotKey("chat.tools.terminal.enableAutoApprove"), Type: TypeBool, Default: "true",
		Desc: "Enable automatic approval of terminal commands.", Danger: DangerConfirm,
		Note: copilotPolicyNt + " (ChatToolsTerminalEnableAutoApprove)",
	},
	{
		Path: copilotKey("chat.tools.edits.autoApprove"), Scopes: copilotNoPolicy, Type: TypeObject, Default: "{}",
		Desc: "File globs mapped to whether edits apply without approval.", Danger: DangerConfirm, Note: "Dangerous: broad globs set true.",
	},
	{
		Path: copilotKey("chat.tools.urls.autoApprove"), Scopes: copilotNoPolicy, Type: TypeObject, Default: "[]",
		Desc: "URL requests and responses approved without asking.", Danger: DangerConfirm, Note: "Dangerous: broad URL patterns.",
	},
	{
		Path: copilotKey("chat.tools.eligibleForAutoApproval"), Type: TypeObject, Desc: "Which tools may be auto-approved at all.",
		Source: copilotPolicyRef, Note: copilotPolicyNt + " (ChatToolsEligibleForAutoApproval)",
	},
	{
		Path: copilotKey("chat.agent.enabled"), Type: TypeBool, Default: "true", Desc: "Allow agent mode (VS Code 1.99+).",
		Note: copilotPolicyNt + " (ChatAgentMode)",
	},
	{Path: copilotKey("chat.agent.maxRequests"), Scopes: copilotNoPolicy, Type: TypeInt, Default: "25", Desc: "Maximum requests the agent makes before asking to continue."},
	{Path: copilotKey("chat.checkpoints.enabled"), Scopes: copilotNoPolicy, Type: TypeBool, Default: "true", Desc: "Chat checkpoints."},
	{Path: copilotKey("chat.extensionTools.enabled"), Type: TypeBool, Desc: "Allow tools contributed by extensions.", Source: copilotPolicyRef, Note: copilotPolicyNt + " (ChatAgentExtensionTools)"},

	// --- sandbox and network
	{
		Path: copilotKey("chat.agent.sandbox.enabled"), Type: TypeEnum, Enum: []string{"off", "on"}, Default: "\"off\"",
		Desc: "Sandbox agent terminal commands on macOS, Linux and WSL2.", Danger: DangerConfirm,
		Note: "Dangerous: \"off\". The audit recorded a bool; the 2026-10-04 reference page lists off / on. " + copilotPolicyNt + " (ChatAgentSandboxEnabled)",
	},
	{
		Path: copilotKey("chat.agent.sandbox.enabledWindows"), Scopes: copilotNoPolicy, Type: TypeEnum, Enum: []string{"off", "on"}, Default: "\"off\"",
		Desc: "Sandbox agent terminal commands on Windows.", Danger: DangerConfirm, Note: "Dangerous: \"off\".",
	},
	{
		Path: copilotKey("chat.agent.sandbox.allowNetwork"), Scopes: copilotNoPolicy, Type: TypeBool, Default: "true",
		Desc: "Unrestricted network access inside the sandbox.", Danger: DangerConfirm, Note: "Dangerous: true.",
	},
	{
		Path: copilotKey("chat.agent.sandbox.allowUnsandboxedCommands"), Scopes: copilotNoPolicy, Type: TypeBool, Default: "true",
		Desc: "Allow a command to run outside the sandbox after confirmation.", Danger: DangerConfirm,
	},
	{Path: copilotKey("chat.agent.sandbox.fileSystem.linux"), Scopes: copilotNoPolicy, Type: TypeObject, Default: "{}", Desc: "Sandbox file system rules on Linux."},
	{Path: copilotKey("chat.agent.sandbox.fileSystem.mac"), Scopes: copilotNoPolicy, Type: TypeObject, Default: "{}", Desc: "Sandbox file system rules on macOS."},
	{Path: copilotKey("chat.agent.sandbox.fileSystem.windows"), Scopes: copilotNoPolicy, Type: TypeObject, Default: "{}", Desc: "Sandbox file system rules on Windows."},
	{
		Path: copilotKey("chat.agent.networkFilter"), Type: TypeBool, Default: "false", Desc: "Filter agent network access by domain.",
		Note: copilotPolicyNt + " (ChatAgentNetworkFilter)",
	},

	// --- models
	{
		Path: copilotKey("chat.defaultModel"), Scopes: []Scope{ScopeManaged}, Type: TypeString, Desc: "Default chat model.",
		Source: copilotPolicyRef, Note: "Policy only (ChatDefaultModel): no user-level default model setting is documented.",
	},
	{Path: copilotKey("chat.utilityModel"), Scopes: copilotNoPolicy, Type: TypeString, Default: "\"Default\"", Desc: "Model for built-in utility flows."},
	{Path: copilotKey("chat.utilitySmallModel"), Scopes: copilotNoPolicy, Type: TypeString, Default: "\"Default\"", Desc: "Model for fast, lightweight utility flows."},
	{
		Path: copilotKey("chat.byokUtilityModelDefault"), Scopes: copilotNoPolicy, Type: TypeString, Default: "\"GitHub Copilot\"",
		Desc: "Model BYOK utility flows use when the main agent model is BYOK.",
	},
	{
		Path: copilotKey("github.copilot.chat.customOAIModels"), Scopes: copilotNoPolicy, Type: TypeObject, Default: "[]",
		Desc: "Custom OpenAI-compatible chat models (an array).", Deprecated: true, Danger: DangerConfirm,
		Note: "Dangerous: a custom endpoint routes chat traffic to another host. Keys are entered through the UI (secret storage), never here.",
	},
	{Path: copilotKey("chat.agentHost.byokModels.enabled"), Scopes: copilotNoPolicy, Type: TypeBool, Default: "false", Desc: "BYOK model bridge for agent-host sessions (experimental)."},
	{
		Path: copilotKey("chat.agent.thinkingStyle"), Scopes: copilotNoPolicy, Type: TypeEnum, Enum: []string{"collapsed", "collapsedPreview", "fixedScrolling"},
		Default: "\"fixedScrolling\"", Desc: "How thinking is rendered in chat (display only, not effort).",
	},
	{Path: copilotKey("github.copilot.chat.agent.thinkingTool"), Scopes: copilotNoPolicy, Type: TypeBool, Default: "false", Desc: "Enable the thinking tool for agents."},
	{
		Path: copilotKey("github.copilot.enable"), Scopes: copilotNoPolicy, Type: TypeObject,
		Desc: "Inline suggestions per language id (\"*\" for all).",
	},
	{
		Path: copilotKey("github.copilot.nextEditSuggestions.enabled"), Type: TypeBool, Default: "true", Desc: "Next edit suggestions.",
		Note: copilotPolicyNt + " (CopilotNextEditSuggestions)",
	},

	// --- MCP
	{
		Path: copilotKey("chat.mcp.access"), Type: TypeBool, Default: "true", Desc: "Which MCP servers may be used.", Danger: DangerConfirm,
		Note: "Dangerous: turning access off drops every MCP server. " + copilotPolicyNt + " (ChatMCP)",
	},
	{Path: copilotKey("chat.mcp.autostart"), Scopes: copilotNoPolicy, Type: TypeString, Default: "\"newAndOutdated\"", Desc: "Which MCP servers start automatically."},
	{Path: copilotKey("chat.mcp.discovery.enabled"), Scopes: copilotNoPolicy, Type: TypeBool, Default: "false", Desc: "Discover MCP configuration from other tools."},
	{Path: copilotKey("chat.mcp.apps.enabled"), Scopes: copilotNoPolicy, Type: TypeBool, Default: "true", Desc: "MCP Apps rich UIs."},
	{
		FileID: "copilot/mcp", Path: KeyPath{"servers"}, Type: TypeMCPMap,
		Desc: "MCP servers by name: {type: stdio | http | sse, command, args, env, envFile, cwd, url, headers}.", Source: copilotMCPRef,
		Note: "The key is servers, not mcpServers.",
	},

	// --- hooks and instructions
	{
		Path: copilotKey("chat.useHooks"), Scopes: copilotNoPolicy, Type: TypeBool, Default: "true", Desc: "Run hooks for the Local harness.",
		Danger: DangerRefuseWhileIntegrated, Note: "Refused while integrated: false stops every hook, including Observer's Claude hooks that Copilot replays from ~/.claude/settings.json.",
	},
	{Path: copilotKey("chat.hookFilesLocations"), Scopes: copilotNoPolicy, Type: TypeObject, Default: "{}", Desc: "Extra hook file locations for the Local harness."},
	{
		Path: copilotKey("chat.useAgentsMdFile"), Scopes: copilotNoPolicy, Type: TypeBool, Default: "true", Desc: "Use AGENTS.md files as chat context.",
		Danger: DangerConfirm, Note: "false stops AGENTS.md instructions (including org instruction blocks) from loading.",
	},
	{Path: copilotKey("chat.useNestedAgentsMdFiles"), Scopes: copilotNoPolicy, Type: TypeBool, Default: "false", Desc: "Also use AGENTS.md files in subfolders."},
	{
		Path: copilotKey("chat.useClaudeMdFile"), Scopes: copilotNoPolicy, Type: TypeBool, Default: "true", Desc: "Use CLAUDE.md files as always-on instructions.",
		Danger: DangerConfirm, Note: "false stops CLAUDE.md instructions from loading.",
	},
	{
		Path: copilotKey("github.copilot.chat.codeGeneration.useInstructionFiles"), Scopes: copilotNoPolicy, Type: TypeBool, Default: "true",
		Desc: "Add .github/copilot-instructions.md to requests.",
	},
	{
		Path: copilotKey("github.copilot.chat.organizationInstructions.enabled"), Scopes: copilotNoPolicy, Type: TypeBool, Default: "true",
		Desc: "Discover GitHub organization-level custom instructions.",
	},
	{
		Path: copilotKey("chat.instructionsFilesLocations"), Scopes: copilotNoPolicy, Type: TypeObject, Deprecated: true,
		Desc: "Extra instruction file locations for the Local agent.", Note: "Agent-host sessions ignore it.",
	},
	{
		Path: copilotKey("chat.promptFilesLocations"), Scopes: copilotNoPolicy, Type: TypeObject, Default: "{\".github/prompts\":true}", Deprecated: true,
		Desc: "Prompt file locations for the Local agent.",
	},
	{Path: copilotKey("chat.agentSkillsLocations"), Scopes: copilotNoPolicy, Type: TypeObject, Deprecated: true, Desc: "Agent skill locations for the Local agent."},
	{Path: copilotKey("chat.useAgentSkills"), Scopes: copilotNoPolicy, Type: TypeBool, Default: "true", Desc: "Agent skills support."},

	// --- third-party agents and plugins (policy-backed)
	{Path: copilotKey("chat.plugins.enabled"), Type: TypeBool, Desc: "Chat plugins.", Source: copilotPolicyRef, Note: copilotPolicyNt + " (ChatPluginsEnabled)"},
	{
		Path: copilotKey("github.copilot.chat.claudeAgent.enabled"), Type: TypeBool, Desc: "Claude third-party agent integration.",
		Source: copilotPolicyRef, Note: copilotPolicyNt + " (Claude3PIntegration)",
	},
	{
		Path: copilotKey("chat.agentHost.claudeAgent.enabled"), Type: TypeBool, Desc: "Claude agent in agent-host sessions.",
		Source: copilotPolicyRef, Note: copilotPolicyNt + " (Claude3PIntegration)",
	},
	{
		Path: copilotKey("chat.agentHost.codexAgent.enabled"), Type: TypeBool, Desc: "Codex agent in agent-host sessions.",
		Source: copilotPolicyRef, Note: copilotPolicyNt + " (Codex3PIntegration)",
	},
	{
		Path: copilotKey("extensions.allowed"), Type: TypeObject, Desc: "Extensions allowed to install.", Source: copilotPolicyRef,
		Note: copilotPolicyNt + " (AllowedExtensions). VS Code-wide.",
	},

	// --- telemetry and OpenTelemetry
	{
		Path: copilotKey("telemetry.telemetryLevel"), Scopes: []Scope{ScopeUser, ScopeManaged}, Type: TypeEnum, Enum: []string{"all", "error", "crash", "off"},
		Desc: "VS Code telemetry level (VS Code-wide).", Source: copilotTelemRef,
		Note: copilotPolicyNt + " (TelemetryLevel). The telemetry page calls it a user setting.",
	},
	{
		Path: copilotKey("telemetry.feedback.enabled"), Type: TypeBool, Desc: "Feedback mechanisms (VS Code-wide).",
		Source: copilotPolicyRef, Note: copilotPolicyNt + " (EnableFeedback)",
	},
	{
		Path: copilotKey("github.copilot.chat.otel.enabled"), Type: TypeBool, Default: "false", Desc: "Emit OpenTelemetry from Copilot Chat.",
		Note: copilotPolicyNt + " (CopilotOtelEnabled)",
	},
	{Path: copilotKey("github.copilot.chat.otel.exporterType"), Scopes: copilotNoPolicy, Type: TypeString, Default: "\"otlp-http\"", Desc: "OpenTelemetry exporter type."},
	{
		Path: copilotKey("github.copilot.chat.otel.otlpEndpoint"), Type: TypeString, Desc: "OTLP endpoint for Copilot Chat telemetry.",
		Source: copilotPolicyRef, Note: copilotPolicyNt + " (CopilotOtelEndpoint)",
	},
	{
		Path: copilotKey("github.copilot.chat.otel.captureContent"), Scopes: copilotNoPolicy, Type: TypeBool, Default: "false",
		Desc: "Capture full prompt and response content in telemetry.",
	},
	{
		Path: copilotKey("github.copilot.chat.otel.captureIdentity"), Scopes: copilotNoPolicy, Type: TypeBool, Default: "false",
		Desc: "Capture authenticated account details in telemetry.",
	},
	{Path: copilotKey("chat.agentHost.otel.enabled"), Type: TypeBool, Desc: "OpenTelemetry for agent-host sessions.", Source: copilotPolicyRef, Note: copilotPolicyNt + " (CopilotOtelEnabled)"},
	{
		Path: copilotKey("chat.agentHost.otel.otlpEndpoint"), Type: TypeString, Desc: "OTLP endpoint for agent-host sessions.",
		Source: copilotPolicyRef, Note: copilotPolicyNt + " (CopilotOtelEndpoint)",
	},

	// --- updates and theme (VS Code-wide)
	{
		Path: copilotKey("update.mode"), Scopes: []Scope{ScopeUser, ScopeManaged}, Type: TypeEnum, Enum: []string{"none", "manual", "start", "default"},
		Default: "\"default\"", Desc: "VS Code update mode (VS Code-wide).", Source: copilotFAQRef,
		Note: copilotPolicyNt + " (UpdateMode). An application-level setting: not read from workspace settings.",
	},
	{
		Path: copilotKey("extensions.autoUpdate"), Scopes: []Scope{ScopeUser}, Type: TypeString, Desc: "Extension auto-update (VS Code-wide; covers the Copilot extension).",
		Source: copilotFAQRef, Note: "The FAQ turns it off with the value off; the exact value set is not on the page.",
	},
	{Path: copilotKey("workbench.colorTheme"), Scopes: copilotNoPolicy, Type: TypeString, Desc: "Color theme name (VS Code-wide).", Source: copilotThemeRef},
})

// copilotMCPShape: .vscode/mcp.json servers.<name> with an explicit type.
var copilotMCPShape = MCPShape{
	EnvKey: "env", TypeKey: "type", StdioTypeExplicit: true,
	TypeNames: map[string]string{"stdio": "stdio", "http": "http", "sse": "sse"},
	URLKeys:   map[string]string{"http": "url", "sse": "url"},
}

var copilotMap = []MapRow{
	{
		Key: KeyTelemetryOff, Tool: "copilot", Settings: []string{"copilot/\"telemetry.telemetryLevel\""}, Transform: TransformEnumMap,
		Params: TransformParams{Enum: []EnumPair{{true, []any{"off"}}, {false, []any{"all"}}}}, Source: copilotTelemRef,
		Note: "VS Code-wide. error and crash have no canonical form.",
	},
	{
		Key: KeyAutoUpdate, Tool: "copilot", Settings: []string{"copilot/\"update.mode\""}, Transform: TransformEnumMap,
		Params: TransformParams{Enum: []EnumPair{{true, []any{"default"}}, {false, []any{"none"}}}}, Source: copilotFAQRef,
		Note: "Updates VS Code itself; manual and start have no canonical form. Extension updates are extensions.autoUpdate.",
	},
	{
		Key: KeySandboxMode, Tool: "copilot", Settings: []string{"copilot/\"chat.agent.sandbox.enabled\""}, Transform: TransformEnumMap,
		Params: TransformParams{Enum: []EnumPair{{"workspace_write", []any{"on"}}, {"off", []any{"off"}}}}, Source: copilotRef,
		Note: "macOS / Linux / WSL2 sandbox; Windows has chat.agent.sandbox.enabledWindows. read_only is refused.",
	},
	{
		Key: KeyMCPServers, Tool: "copilot", Settings: []string{"copilot/servers"}, Transform: TransformMCPShape,
		Params: TransformParams{MCP: copilotMCPShape}, Lossy: true, Source: copilotMCPRef, Note: mcpLossyNote,
	},
}

var copilotCatalog = toolCatalog{
	Tool: "copilot",
	VerifiedAgainst: "VS Code Copilot settings reference, enterprise policies, MCP servers, telemetry and FAQ pages fetched 2026-10-04 " +
		"(audit section 5); no live install on node 1. GitHub.com org / enterprise Copilot policies are server-side and have no node file.",
	Files: copilotFiles,
	Extra: copilotSettings,
	Map:   copilotMap,
}
