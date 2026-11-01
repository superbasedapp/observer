package agentconfig

// Cline, the VS Code extension saoudrizwan.claude-dev (phase P2,
// doc-authored). The extension contributes NO VS Code settings.json keys:
// its settings are internal state the extension writes itself (the
// globalState.json store of current builds; VS Code's own state.vscdb /
// SecretStorage on older builds, which is never read and has no row). Only
// the MCP settings file is a user-editable config. Org settings arrive as a
// server-side remote configuration (app.cline.bot) with no local file.
// Sources: audit docs/audits/adapter-config-surface-2026-10-03.md section 5
// "cline" and the vendor source below, re-fetched 2026-10-04.

const (
	clineStateRef = "https://raw.githubusercontent.com/cline/cline/main/apps/vscode/src/shared/storage/state-keys.ts"
	clineConfigRf = "https://docs.cline.bot/getting-started/config.md"
	clineAudit    = "docs/audits/adapter-config-surface-2026-10-03.md section 5 cline (vendor source + docs.cline.bot, 2026-10-03)"
	clineStateNt  = "Extension-managed state (set through the Cline UI); the editor never writes it."

	clineMCPSharedRf = "https://raw.githubusercontent.com/cline/cline/main/apps/vscode/src/sdk/SdkController.ts (McpHub settings dir, L331-345, fetched 2026-10-25)"
	clineMCPLegacyRf = "https://raw.githubusercontent.com/cline/cline/main/apps/vscode/src/hosts/vscode/mcp-settings-legacy-migration.ts (getLegacyMcpSettingsSources, fetched 2026-10-25)"
)

var clineFiles = []FileRow{
	{
		ID: "cline/mcp-settings", Tool: "cline", Shape: "cline/mcp-settings", Kind: KindMCP, Scope: ScopeUser,
		Paths: samePath("~/.cline/data/settings/cline_mcp_settings.json"), Format: FormatJSON,
		Precedence: 20, WriteNeeds: PrivUser, Grounding: source(clineMCPSharedRf),
		Note: "The MCP file current builds read (McpHub on resolveDefaultMcpSettingsPath), shared with the Cline CLI and Cline for JetBrains " +
			"(the same file as cline-cli/mcp-settings). CLINE_MCP_SETTINGS_PATH, CLINE_DATA_DIR and CLINE_DIR relocate it (relocate.go).",
	},
	{
		ID: "cline/mcp-settings-legacy", Tool: "cline", Shape: "cline/mcp-settings", Kind: KindMCP, Scope: ScopeUser,
		Paths: samePath("<vscode>/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json"), Format: FormatJSON,
		Precedence: 10, WriteNeeds: PrivUser, Grounding: source(clineMCPLegacyRf),
		Note: "<vscode> is the VS Code user data dir: Linux ~/.config/Code, macOS ~/Library/Application Support/Code, Windows %APPDATA%\\Code. " +
			"Legacy: current builds copy its servers into the shared file once (mcp-settings-legacy-migration.ts) and never read it again. " +
			"Observer no longer writes it; an unregister removes the observer entry an older build left here.",
	},
	{
		ID: "cline/global-state", Tool: "cline", Shape: "cline/global-state", Kind: KindToolState, Scope: ScopeUser,
		Paths: samePath("~/.cline/data/globalState.json"), Format: FormatJSON, Precedence: 0, WriteNeeds: PrivNever,
		Grounding: source("https://raw.githubusercontent.com/cline/cline/main/apps/vscode/src/core/storage/disk.ts"),
		Note:      "Cline's settings store on current builds (CLINE_DIR / CLINE_DATA_DIR relocate ~/.cline/data). Written by the extension; shown, never form-edited.",
	},
	{
		ID: "cline/workspace-state", Tool: "cline", Shape: "cline/workspace-state", Kind: KindToolState, Scope: ScopeUser,
		Paths: samePath("~/.cline/data/workspaces/"), Format: FormatJSON, Precedence: 0, WriteNeeds: PrivNever,
		Grounding: source("https://raw.githubusercontent.com/cline/cline/main/apps/vscode/src/core/storage/disk.ts"),
		Note:      "Per-workspace state: workspaces/<hash>/workspaceState.json (per-rule toggles and similar). Written by the extension.",
	},
	{
		ID: "cline/secrets", Tool: "cline", Shape: "cline/secrets", Kind: KindToolState, Scope: ScopeUser,
		Paths: samePath("~/.cline/data/secrets.json"), Format: FormatJSON, Precedence: 0, WriteNeeds: PrivNever,
		Grounding: source("https://raw.githubusercontent.com/cline/cline/main/apps/vscode/src/core/storage/disk.ts"),
		Note:      "Provider API keys (mode 0600): never read or written.",
	},
}

func clineRows(rows []SettingRow) []SettingRow {
	for i := range rows {
		r := &rows[i]
		r.Tool = "cline"
		r.ID = r.Tool + "/" + r.Path.String()
		if r.FileID == "" {
			r.FileID = "cline/global-state"
		}
		if r.Owner == "" {
			r.Owner = OwnerToolState
		}
		if r.Verified == "" {
			r.Verified = VerifiedDoc
		}
		if r.Source == "" {
			r.Source = clineStateRef
		}
		if r.Owner == OwnerToolState && r.Note == "" {
			r.Note = clineStateNt
		}
	}
	return rows
}

var clineSettings = clineRows([]SettingRow{
	{
		FileID: "cline/mcp-settings", Path: KeyPath{"mcpServers"}, Type: TypeMCPMap, Owner: OwnerUser, Source: clineConfigRf,
		Desc: "MCP servers by name: {command, args, env, disabled, alwaysAllow, type, url}.",
		Note: "Observer's \"observer\" entry is an owned span. alwaysAllow lists auto-approve that server's tools.",
	},

	// --- models (globalState)
	{Path: KeyPath{"actModeApiProvider"}, Type: TypeString, Desc: "Provider used in Act mode."},
	{Path: KeyPath{"planModeApiProvider"}, Type: TypeString, Desc: "Provider used in Plan mode."},
	{Path: KeyPath{"actModeApiModelId"}, Type: TypeString, Desc: "Model id used in Act mode."},
	{Path: KeyPath{"planModeApiModelId"}, Type: TypeString, Desc: "Model id used in Plan mode."},
	{Path: KeyPath{"planActSeparateModelsSetting"}, Type: TypeBool, Default: "false", Desc: "Use separate models for Plan and Act."},
	{Path: KeyPath{"actModeReasoningEffort"}, Type: TypeString, Desc: "Reasoning effort in Act mode (values not enumerated in the source)."},
	{Path: KeyPath{"planModeReasoningEffort"}, Type: TypeString, Desc: "Reasoning effort in Plan mode."},
	{Path: KeyPath{"actModeThinkingBudgetTokens"}, Type: TypeInt, Desc: "Thinking token budget in Act mode."},
	{Path: KeyPath{"planModeThinkingBudgetTokens"}, Type: TypeInt, Desc: "Thinking token budget in Plan mode."},
	{Path: KeyPath{"mode"}, Type: TypeEnum, Enum: []string{"plan", "act"}, Default: "\"act\"", Desc: "Current Plan / Act mode."},

	// --- approvals, hooks, telemetry
	{
		Path: KeyPath{"autoApprovalSettings"}, Type: TypeObject,
		Desc:   "Auto-approve toggles: read / edit project or all files, execute safe or all commands, browser, MCP, notifications.",
		Danger: DangerConfirm, Note: clineStateNt + " Dangerous: execute-all-commands, edit-all-files or MCP auto-approve on.",
	},
	{
		Path: KeyPath{"yoloModeToggled"}, Type: TypeBool, Desc: "YOLO mode (approve everything).", Source: clineAudit, Verified: VerifiedUnverified,
		Danger: DangerConfirm, Note: clineStateNt + " UNVERIFIED key name in the audit; not in state-keys.ts on main (2026-10-04). An org can forbid it (remote yoloModeAllowed: false).",
	},
	{
		Path: KeyPath{"hooksEnabled"}, Type: TypeBool, Default: "true", Desc: "Run Cline hooks.",
		Danger: DangerRefuseWhileIntegrated, Note: clineStateNt + " false switches the hook path off.",
	},
	{
		Path: KeyPath{"telemetrySetting"}, Type: TypeString, Default: "\"unset\"", Desc: "Telemetry setting (enabled / disabled / unset per the audit).",
		Note: clineStateNt + " Users can disable telemetry even when the org enables it.",
	},
	{Path: KeyPath{"useAutoCondense"}, Type: TypeBool, Default: "true", Desc: "Auto-condense the conversation as context fills."},
	{Path: KeyPath{"enableCheckpointsSetting"}, Type: TypeBool, Default: "true", Desc: "Workspace checkpoints."},
	{Path: KeyPath{"mcpMarketplaceEnabled"}, Type: TypeBool, Default: "true", Desc: "MCP marketplace."},
	{Path: KeyPath{"mcpDisplayMode"}, Type: TypeString, Desc: "How MCP responses are displayed."},
	{Path: KeyPath{"shellIntegrationTimeout"}, Type: TypeInt, Default: "4000", Desc: "Shell integration timeout in milliseconds."},
	{Path: KeyPath{"terminalReuseEnabled"}, Type: TypeBool, Default: "true", Desc: "Reuse terminals."},
	{Path: KeyPath{"preferredLanguage"}, Type: TypeString, Default: "\"English\"", Desc: "Response language."},
	{Path: KeyPath{"browserSettings"}, Type: TypeObject, Desc: "Browser tool settings."},
	{Path: KeyPath{"focusChainSettings"}, Type: TypeObject, Desc: "Focus chain (task list) settings."},

	// --- provider base URLs (route overrides)
	{Path: KeyPath{"openAiBaseUrl"}, Type: TypeString, Desc: "OpenAI-compatible provider base URL.", Danger: DangerConfirm, Note: clineStateNt + " Base URL override."},
	{Path: KeyPath{"anthropicBaseUrl"}, Type: TypeString, Desc: "Anthropic provider base URL.", Danger: DangerConfirm, Note: clineStateNt + " Base URL override."},
	{Path: KeyPath{"geminiBaseUrl"}, Type: TypeString, Desc: "Gemini provider base URL.", Danger: DangerConfirm, Note: clineStateNt + " Base URL override."},
	{Path: KeyPath{"liteLlmBaseUrl"}, Type: TypeString, Desc: "LiteLLM base URL.", Danger: DangerConfirm, Note: clineStateNt + " Base URL override."},
	{Path: KeyPath{"ollamaBaseUrl"}, Type: TypeString, Desc: "Ollama base URL.", Danger: DangerConfirm, Note: clineStateNt + " Base URL override."},
	{Path: KeyPath{"lmStudioBaseUrl"}, Type: TypeString, Desc: "LM Studio base URL.", Danger: DangerConfirm, Note: clineStateNt + " Base URL override."},
	{Path: KeyPath{"requestyBaseUrl"}, Type: TypeString, Desc: "Requesty base URL.", Danger: DangerConfirm, Note: clineStateNt + " Base URL override."},
})

// clineMCPShape: mcpServers.<name> {command, args, env}. Cline's remote
// entries carry a type whose spellings the docs do not settle, so remote
// transports are refused rather than guessed (shared with cline-cli).
var clineMCPShape = MCPShape{EnvKey: "env", TypeNames: map[string]string{"stdio": ""}}

var clineMap = []MapRow{
	{
		Key: KeyMCPServers, Tool: "cline", Settings: []string{"cline/mcpServers"}, Transform: TransformMCPShape,
		Params: TransformParams{MCP: clineMCPShape}, Lossy: true, Source: clineConfigRf,
		Note: "Local servers only; remote servers are refused. disabled and alwaysAllow are not carried. " + mcpLossyNote,
	},
}

var clineCatalog = toolCatalog{
	Tool: "cline",
	VerifiedAgainst: "cline/cline main state-keys.ts and docs.cline.bot fetched 2026-10-04 (audit section 5, extension v4.1.22 on main); no live install " +
		"on node 1. Settings are extension-managed state (read-only rows); the org remote configuration is server-side and has no local file.",
	Files: clineFiles,
	Extra: clineSettings,
	Map:   clineMap,
}
