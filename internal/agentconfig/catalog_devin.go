package agentconfig

// Devin (phase P2, doc-authored). Two surfaces under one tool id: the Devin
// CLI (JSONC config.json at user / project / project-local scope, an
// admin system.json, dedicated mcp_config.json files) and Devin Desktop
// (the renamed Windsurf VS Code fork) whose in-IDE agent Cascade has its own
// hooks.json under ~/.codeium/windsurf and reads its MCP servers from the
// CLI's mcp_config.json (docs.devin.ai/desktop/cascade/mcp, 2026-10-25).
// Observer registers its Cascade hooks in ~/.codeium/windsurf/hooks.json.
// Sources: audit docs/audits/adapter-config-surface-2026-10-03.md section 5 "devin" and the
// docs.devin.ai pages below, re-fetched 2026-10-04.

const (
	devinConfigRef = "https://docs.devin.ai/cli/reference/configuration/config-file.md"
	devinSystemRef = "https://docs.devin.ai/cli/enterprise/system-config.md"
	devinPermRef   = "https://docs.devin.ai/cli/reference/permissions.md"
	devinHooksRef  = "https://docs.devin.ai/desktop/cascade/hooks"
	devinCLIHooks  = "https://docs.devin.ai/cli/extensibility/hooks/overview.md"
	// devinCascadeMCP is the Cascade MCP page (surface-gap S-10, 2026-10-25):
	// %APPDATA%\devin\mcp_config.json, else $XDG_CONFIG_HOME/devin or
	// ~/.config/devin.
	devinCascadeMCP = "https://docs.devin.ai/desktop/cascade/mcp"
	devinLiveRef    = "docs/audits/adapter-config-surface-2026-10-03.md section 5 devin + section 6 (node 1 live key names, 2026-10-03)"
	devinLiveNote   = "Key name seen live in ~/.config/devin/config.json on node 1 (2026-10-03)."
)

var (
	devinUser        = []Scope{ScopeUser}
	devinUserProject = []Scope{ScopeUser, ScopeProjectShared, ScopeProjectLocal}
	devinUserSystem  = []Scope{ScopeUser, ScopeManaged}
	devinSystemOnly  = []Scope{ScopeManaged}
)

var devinFiles = []FileRow{
	{
		ID: "devin/user-config", Tool: "devin", Shape: "devin/config", Kind: KindSettings, Scope: ScopeUser,
		Paths:  OSPaths{Linux: "~/.config/devin/config.json", Darwin: "~/.config/devin/config.json", Windows: `%APPDATA%\devin\config.json`},
		Format: FormatJSONC, Precedence: 20, WriteNeeds: PrivUser,
		Grounding: live("~/.config/devin/config.json carries devin.org_id, shell.setup_complete, theme_mode, version"),
		Note:      "Devin CLI user config. A hooks key (Claude Code-shaped) is also accepted here; it is not catalogued separately because the Cascade hooks file owns the hooks row.",
	},
	{
		ID: "devin/project-config", Tool: "devin", Shape: "devin/config", Kind: KindSettings, Scope: ScopeProjectShared,
		Paths: samePath("<project>/.devin/config.json"), Format: FormatJSONC, Precedence: 30, WriteNeeds: PrivUser,
		Grounding: doc(devinConfigRef), Note: "Committed. Accepts only permissions, read_config_from and hooks.",
	},
	{
		ID: "devin/project-local-config", Tool: "devin", Shape: "devin/config", Kind: KindSettings, Scope: ScopeProjectLocal,
		Paths: samePath("<project>/.devin/config.local.json"), Format: FormatJSONC, Precedence: 40, WriteNeeds: PrivUser, Gitignored: true,
		Grounding: doc(devinConfigRef), Note: "Gitignored personal overrides; same keys as the project file.",
	},
	{
		ID: "devin/system-config", Tool: "devin", Shape: "devin/config", Kind: KindSettings, Scope: ScopeManaged,
		Paths: OSPaths{
			Linux:   "/etc/devin/system.json",
			Darwin:  "/Library/Application Support/Devin/system.json",
			Windows: `C:\ProgramData\Devin\system.json`,
		},
		Format: FormatJSON, Precedence: 100, WriteNeeds: PrivAdminRoot, Grounding: doc(devinSystemRef),
		Note: "Admin-only. Accepts enterprise_host, account_id and proxy; a proxy section here makes the CLI refuse to start while the user config also sets one. " +
			"Server-side Team Settings (model allowlist, MCP, terminal permissions, sandbox enforcement) have no local file.",
	},
	{
		ID: "devin/user-mcp", Tool: "devin", Shape: "devin/mcp", Kind: KindMCP, Scope: ScopeUser,
		Paths:  OSPaths{Linux: "~/.config/devin/mcp_config.json", Darwin: "~/.config/devin/mcp_config.json", Windows: `%APPDATA%\devin\mcp_config.json`},
		Format: FormatJSON, Precedence: 20, WriteNeeds: PrivUser, Grounding: doc(devinCascadeMCP),
		Note: "Dedicated MCP file since v3000.3 (older config.json mcpServers are migrated on startup). Devin Desktop reads the same file for both " +
			"its agents: Cascade's MCP servers live here, and the default Devin Local agent uses the CLI's config. Linux and macOS honour " +
			"$XDG_CONFIG_HOME/devin/mcp_config.json.",
	},
	{
		ID: "devin/project-mcp", Tool: "devin", Shape: "devin/mcp", Kind: KindMCP, Scope: ScopeProjectShared,
		Paths: samePath("<project>/.devin/mcp_config.json"), Format: FormatJSON, Precedence: 30, WriteNeeds: PrivUser,
		Grounding: doc(devinConfigRef),
	},
	{
		ID: "devin/project-local-mcp", Tool: "devin", Shape: "devin/mcp", Kind: KindMCP, Scope: ScopeProjectLocal,
		Paths: samePath("<project>/.devin/mcp_config.local.json"), Format: FormatJSON, Precedence: 40, WriteNeeds: PrivUser,
		Grounding: doc(devinConfigRef),
	},
	{
		ID: "devin/project-hooks-v1", Tool: "devin", Shape: "devin/hooks-v1", Kind: KindHooks, Scope: ScopeProjectShared,
		Paths: samePath("<project>/.devin/hooks.v1.json"), Format: FormatJSON, Precedence: 30, WriteNeeds: PrivUser,
		Grounding: doc(devinCLIHooks),
		Note:      "CLI hooks: the whole file is the hooks object (raw editor only). Repo docs/devin-adapter.md found it unwired in the shipped CLI (2026-09-03); re-ground before relying on it.",
	},
	{
		ID: "devin/cascade-user-hooks", Tool: "devin", Shape: "devin/cascade-hooks", Kind: KindHooks, Scope: ScopeUser,
		Paths: samePath("~/.codeium/windsurf/hooks.json"), Format: FormatJSON, Precedence: 20, WriteNeeds: PrivUser,
		Grounding: doc(devinHooksRef),
		Note:      "Devin Desktop (Cascade) user hooks; Observer registers its hooks here. Not present on node 1 (2026-10-03). System, user and workspace hooks all merge.",
	},
	{
		ID: "devin/cascade-jetbrains-hooks", Tool: "devin", Shape: "devin/cascade-hooks", Kind: KindHooks, Scope: ScopeUser,
		Paths: samePath("~/.codeium/hooks.json"), Format: FormatJSON, Precedence: 20, WriteNeeds: PrivUser,
		Grounding: doc(devinHooksRef), Note: "Cascade in the JetBrains plugin.",
	},
	{
		ID: "devin/cascade-workspace-hooks", Tool: "devin", Shape: "devin/cascade-hooks", Kind: KindHooks, Scope: ScopeProjectShared,
		Paths: samePath("<project>/.devin/hooks.json"), Format: FormatJSON, Precedence: 30, WriteNeeds: PrivUser,
		Grounding: doc(devinHooksRef), Note: "Legacy fallback .windsurf/hooks.json is read only when this file is absent or empty.",
	},
	{
		ID: "devin/cascade-system-hooks", Tool: "devin", Shape: "devin/cascade-hooks", Kind: KindHooks, Scope: ScopeSystem,
		Paths: OSPaths{
			Linux:   "/etc/devin/hooks.json",
			Darwin:  "/Library/Application Support/Devin/hooks.json",
			Windows: `C:\ProgramData\Devin\hooks.json`,
		},
		Format: FormatJSON, Precedence: 10, WriteNeeds: PrivAdminRoot, Grounding: doc(devinHooksRef),
		Note: "Runs first (system, then user, then workspace; cloud dashboard hooks before all). Legacy Windsurf directories are the fallback. " +
			"The three system roots (and their legacy Windsurf twins) are in the shipped Devin Desktop language server and CLI binaries (MAC-4, " + mac4Report + "); " +
			"the hooks.json join inside them was not exercised (it needs a sign-in), so the file name stays doc-grounded.",
	},
	// No separate Cascade MCP row: docs.devin.ai/desktop/cascade/mcp now puts
	// Cascade's MCP servers in the Devin CLI's own mcp_config.json
	// (devin/user-mcp), and the legacy ~/.codeium/windsurf/mcp_config.json
	// row it replaced was never re-grounded (surface-gap S-10, NEW-1).
	{
		ID: "devin/desktop-settings", Tool: "devin", Shape: "devin/desktop-settings", Kind: KindSettings, Scope: ScopeUser,
		Paths: OSPaths{
			Darwin:  "~/Library/Application Support/Devin/User/settings.json",
			Windows: `%APPDATA%\Devin\User\settings.json`,
		},
		Format: FormatVSCodeSettings, Precedence: 20, WriteNeeds: PrivUser,
		Grounding: mac4Live("Devin Desktop 3.11.228 (bundle com.exafunction.windsurf, product nameShort Devin) created ~/Library/Application Support/Devin/User/ on first launch"),
		Note: "Devin Desktop (VS Code fork) settings. The macOS dir is live-grounded by MAC-4; settings.json itself appears only once a setting is changed (the VS Code layout). " +
			"The Windows path is repo-grounded (docs.devin.ai/llms.txt); Linux ~/.config/Devin is UNVERIFIED, so it has no path. Cascade keys (auto-execution, Turbo) not catalogued.",
	},
}

func devinRows(rows []SettingRow) []SettingRow {
	for i := range rows {
		r := &rows[i]
		r.Tool = "devin"
		r.ID = r.Tool + "/" + r.Path.String()
		if r.FileID == "" {
			r.FileID = "devin/config"
		}
		if r.Owner == "" {
			r.Owner = OwnerUser
		}
		if r.Verified == "" {
			r.Verified = VerifiedDoc
		}
		if r.Source == "" {
			r.Source = devinConfigRef
		}
	}
	return rows
}

var devinSettings = devinRows([]SettingRow{
	// --- user config only
	{Path: KeyPath{"agent", "model"}, Scopes: devinUser, Type: TypeString, Default: "\"swe-1-6-fast\"", Desc: "Default model for new sessions.", Note: "The org model allowlist is server-side."},
	{Path: KeyPath{"agent", "show_history_on_continue"}, Scopes: devinUser, Type: TypeBool, Default: "true", Desc: "Show prior messages when resuming."},
	{
		Path: KeyPath{"theme_mode"}, Scopes: devinUser, Type: TypeEnum, Enum: []string{"light", "dark", "terminal-dark", "terminal-light", "nocolor"},
		Default: "null", Desc: "UI appearance (null = automatic).", Verified: VerifiedLive, Note: devinLiveNote,
	},
	{Path: KeyPath{"show_path"}, Scopes: devinUser, Type: TypeBool, Default: "false", Desc: "Show the working directory in the input border."},
	{Path: KeyPath{"unicode_mode"}, Scopes: devinUser, Type: TypeEnum, Enum: []string{"auto", "unicode", "ascii"}, Default: "\"auto\"", Desc: "Character rendering."},
	{Path: KeyPath{"show_hints"}, Scopes: devinUser, Type: TypeBool, Default: "true", Desc: "Feature tips between turns."},
	{Path: KeyPath{"include_gitignored_files"}, Scopes: devinUser, Type: TypeBool, Default: "false", Desc: "Offer gitignored files in @ completion."},
	{Path: KeyPath{"respect_gitignore"}, Scopes: devinUser, Type: TypeBool, Default: "false", Desc: "Block tool access to gitignored paths."},
	{Path: KeyPath{"attribution"}, Scopes: devinUser, Type: TypeBool, Default: "true", Desc: "Devin attribution on commits and PRs."},
	{Path: KeyPath{"subagents_enabled"}, Scopes: devinUser, Type: TypeBool, Default: "true", Desc: "Let the agent delegate to subagents."},
	{Path: KeyPath{"keymap"}, Scopes: devinUser, Type: TypeObject, Default: "{}", Desc: "Keyboard shortcut overrides by context."},
	{Path: KeyPath{"auto_update"}, Scopes: devinUser, Type: TypeBool, Default: "true", Desc: "Install new releases in the background (macOS / Linux)."},
	{Path: KeyPath{"notify"}, Scopes: devinUser, Type: TypeEnum, Enum: []string{"never", "smart", "always"}, Default: "\"smart\"", Desc: "Notifications."},
	{
		Path: KeyPath{"sandbox", "allowed_domains"}, Scopes: devinUser, Type: TypeStringList, Default: "[]", Desc: "Sandbox network allowlist (active with --sandbox).",
	},
	{Path: KeyPath{"sandbox", "denied_domains"}, Scopes: devinUser, Type: TypeStringList, Default: "[]", Desc: "Sandbox network denylist (wins over the allowlist)."},
	{
		Path: KeyPath{"sandbox", "network_mode"}, Scopes: devinUser, Type: TypeEnum, Enum: []string{"full", "limited"}, Default: "\"full\"",
		Desc: "Sandbox network mode.", Danger: DangerConfirm, Note: "\"full\" leaves sandbox network access unfiltered.",
	},

	// --- user + system.json
	{
		Path: KeyPath{"proxy", "mode"}, Scopes: devinUserSystem, Type: TypeEnum, Enum: []string{"system", "manual", "off"}, Default: "\"system\"",
		Desc: "HTTP egress proxy strategy (not a provider base URL).", Source: devinSystemRef, Danger: DangerConfirm,
		Note: "A system.json proxy wins; the CLI refuses to start while the user config also sets one.",
	},
	{
		Path: KeyPath{"proxy", "url"}, Scopes: devinUserSystem, Type: TypeString, Default: "null", Desc: "Proxy URL (required for manual mode).",
		Source: devinSystemRef, Danger: DangerConfirm, Note: "Routes CLI traffic through another host.",
	},
	{Path: KeyPath{"proxy", "no_proxy"}, Scopes: devinUserSystem, Type: TypeString, Default: "null", Desc: "Comma-separated bypass domains (NO_PROXY syntax).", Source: devinSystemRef},
	{Path: KeyPath{"enterprise_host"}, Scopes: devinSystemOnly, Type: TypeString, Desc: "Enterprise host URL for authentication.", Source: devinSystemRef},
	{Path: KeyPath{"account_id"}, Scopes: devinSystemOnly, Type: TypeString, Desc: "Account the CLI must authenticate to.", Source: devinSystemRef},

	// --- user + project + project-local
	{
		Path: KeyPath{"permissions", "allow"}, Scopes: devinUserProject, Type: TypeRuleList, Default: "[]", Source: devinPermRef,
		Desc:   "Rules that run without asking: Read(glob), Write(glob), Exec(prefix), Fetch(pattern), bare read / edit / grep / glob / exec, mcp__server__tool.",
		Danger: DangerConfirm, Note: "Dangerous: broad rules such as exec, Exec(*) or mcp__*.",
	},
	{Path: KeyPath{"permissions", "deny"}, Scopes: devinUserProject, Type: TypeRuleList, Default: "[]", Source: devinPermRef, Desc: "Rules that never run; deny always wins."},
	{Path: KeyPath{"permissions", "ask"}, Scopes: devinUserProject, Type: TypeRuleList, Default: "[]", Source: devinPermRef, Desc: "Rules that always ask."},
	{Path: KeyPath{"read_config_from", "agents_standard"}, Scopes: devinUserProject, Type: TypeBool, Default: "true", Desc: "Import AGENTS.md, AGENT.md, .windsurfrules (null = true)."},
	{Path: KeyPath{"read_config_from", "cursor"}, Scopes: devinUserProject, Type: TypeBool, Default: "true", Desc: "Import Cursor rules and MCP servers."},
	{Path: KeyPath{"read_config_from", "windsurf"}, Scopes: devinUserProject, Type: TypeBool, Default: "true", Desc: "Import Windsurf rules, skills and MCP."},
	{
		Path: KeyPath{"read_config_from", "claude"}, Scopes: devinUserProject, Type: TypeBool, Default: "true", Desc: "Import Claude Code rules, skills, commands and hooks.",
		Danger: DangerConfirm, Note: "false stops Claude-format hooks (including Observer's Claude hooks) firing inside Devin; true replays them there.",
	},
	{Path: KeyPath{"read_config_from", "copilot"}, Scopes: devinUserProject, Type: TypeBool, Default: "true", Desc: "Import GitHub Copilot skills."},
	{Path: KeyPath{"read_config_from", "opencode"}, Scopes: devinUserProject, Type: TypeBool, Default: "true", Desc: "Import OpenCode MCP servers."},
	{Path: KeyPath{"read_config_from", "zed"}, Scopes: devinUserProject, Type: TypeBool, Default: "true", Desc: "Import Zed MCP servers."},

	// --- live-only, machine-written
	{
		Path: KeyPath{"devin", "org_id"}, Scopes: devinUser, Type: TypeString, Desc: "Organization the CLI is signed in to.", Source: devinLiveRef,
		Verified: VerifiedLive, Owner: OwnerToolState, Note: "Written at sign-in; not on the vendor reference. " + devinLiveNote,
	},
	{
		Path: KeyPath{"shell", "setup_complete"}, Scopes: devinUser, Type: TypeBool, Desc: "Shell integration setup done.", Source: devinLiveRef,
		Verified: VerifiedLive, Owner: OwnerToolState, Note: "Not on the vendor reference. " + devinLiveNote,
	},
	{
		Path: KeyPath{"version"}, Scopes: devinUser, Type: TypeInt, Desc: "Config file version.", Source: devinLiveRef,
		Verified: VerifiedLive, Owner: OwnerToolState, Note: "Not on the vendor reference; type not recorded. " + devinLiveNote,
	},

	// --- MCP and Cascade hooks
	{
		FileID: "devin/mcp", Path: KeyPath{"mcpServers"}, Type: TypeMCPMap,
		Desc: "MCP servers by name: {command, args, env} or {url, transport: http}.",
	},
	{
		FileID: "devin/cascade-hooks", Path: KeyPath{"hooks"}, Type: TypeObject, Source: devinHooksRef,
		Desc: "Cascade hooks keyed by event (pre_read_code, pre_run_command, pre_user_prompt, post_cascade_response and others); each entry has command, powershell, show_output, working_directory.",
		Note: "Observer's own entries in ~/.codeium/windsurf/hooks.json are an owned span: the editor locks those entries only.",
	},
})

// devinRuleGrammar: the bare tool names. A scoped rule uses a different
// spelling (Exec(prefix), Read(glob), Write(glob), Fetch(pattern)) and a
// bare capitalised form is invalid, so canonical patterns are refused.
var devinRuleGrammar = RuleGrammar{
	"shell": {Name: "exec", Style: RuleBare},
	"read":  {Name: "read", Style: RuleBare},
	"edit":  {Name: "edit", Style: RuleBare},
}

// devinMCPShape: {command, args, env} locally; {url, transport: "http"}
// remotely.
var devinMCPShape = MCPShape{
	EnvKey: "env", TypeKey: "transport",
	TypeNames: map[string]string{"stdio": "", "http": "http"},
	URLKeys:   map[string]string{"http": "url"},
}

var devinMap = []MapRow{
	{Key: KeyModel, Tool: "devin", Settings: []string{"devin/agent.model"}, Transform: TransformModelAlias, Source: devinConfigRef},
	{Key: KeyAutoUpdate, Tool: "devin", Settings: []string{"devin/auto_update"}, Transform: TransformIdentity, Source: devinConfigRef},
	{
		Key: KeyTheme, Tool: "devin", Settings: []string{"devin/theme_mode"}, Transform: TransformEnumMap,
		Params: TransformParams{Enum: []EnumPair{{"light", []any{"light"}}, {"dark", []any{"dark"}}}}, Source: devinConfigRef,
		Note: "terminal-dark, terminal-light and nocolor stay tool-specific.",
	},
	{
		Key: KeyAllowedTools, Tool: "devin", Settings: []string{"devin/permissions.allow"}, Transform: TransformRuleTranslate,
		Params: TransformParams{Grammar: devinRuleGrammar}, Source: devinPermRef,
		Note: "Whole-tool rules only (shell, read, edit); patterns, write, fetch and mcp are refused.",
	},
	{
		Key: KeyDeniedTools, Tool: "devin", Settings: []string{"devin/permissions.deny"}, Transform: TransformRuleTranslate,
		Params: TransformParams{Grammar: devinRuleGrammar}, Source: devinPermRef,
		Note: "Whole-tool rules only (shell, read, edit); patterns, write, fetch and mcp are refused.",
	},
	{
		Key: KeyMCPServers, Tool: "devin", Settings: []string{"devin/mcpServers"}, Transform: TransformMCPShape,
		Params: TransformParams{MCP: devinMCPShape}, Lossy: true, Source: devinConfigRef, Note: "CLI MCP files. " + mcpLossyNote,
	},
}

var devinCatalog = toolCatalog{
	Tool: "devin",
	VerifiedAgainst: "docs.devin.ai config-file, system-config, permissions and Cascade hooks pages fetched 2026-10-04 (audit section 5); node 1 live " +
		"key names 2026-10-03 for theme_mode, devin.org_id, shell.setup_complete and version (Devin CLI on Linux).",
	Files: devinFiles,
	Extra: devinSettings,
	Map:   devinMap,
}
