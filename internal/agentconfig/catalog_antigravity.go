package agentconfig

// Google Antigravity desktop (Antigravity 2.0 agent manager and the VS
// Code-fork IDE) doc-authored catalogue. Sources: antigravity.google docs
// (settings, agent-settings, mcp, hooks, enterprise) fetched 2026-10-04 and
// audit section 5 "antigravity". The desktop's own agent settings (permission
// preset, terminal execution, sandbox, telemetry) are set through the Settings
// UI and their on-disk file is not documented, so they have no rows. The
// shared ~/.gemini/config/hooks.json is catalogued once, under
// antigravity-cli, where Observer's hook span lives.
const (
	antigravityMCPRef        = "https://antigravity.google/docs/mcp"
	antigravityEnterpriseRef = "https://antigravity.google/docs/enterprise"
	antigravityVSCodeRef     = "https://code.visualstudio.com/docs/getstarted/settings"
)

// antigravityRow fills the tool, owner, verification and id of one row.
func antigravityRow(r SettingRow) SettingRow {
	r.Tool = "antigravity"
	if r.Owner == "" {
		r.Owner = OwnerUser
	}
	if r.Verified == "" {
		r.Verified = VerifiedDoc
	}
	r.ID = r.Tool + "/" + r.Path.String()
	return r
}

// antigravityMCPShape is the shared mcp_config.json entry shape (stdio
// command / args / env, remote serverUrl).
var antigravityMCPShape = MCPShape{
	EnvKey: "env", TypeNames: map[string]string{"stdio": "", "http": ""},
	URLKeys: map[string]string{"http": "serverUrl"},
}

var antigravityCatalog = toolCatalog{
	Tool: "antigravity",
	VerifiedAgainst: "antigravity.google docs fetched 2026-10-04 (mcp, hooks, enterprise, settings, agent-settings; audit section 5 antigravity). " +
		"The editor-layer User/settings.json rows are inferred from the VS Code fork layout (UNVERIFIED); the agent settings file is undocumented.",
	Files: []FileRow{
		{
			ID: "antigravity/user-editor-settings", Tool: "antigravity", Shape: "antigravity/editor-settings", Kind: KindSettings, Scope: ScopeUser,
			Paths: OSPaths{
				Linux:   "~/.config/Antigravity/User/settings.json",
				Darwin:  "~/Library/Application Support/Antigravity IDE/User/settings.json",
				Windows: `%APPDATA%\Antigravity\User\settings.json`,
			},
			Format: FormatVSCodeSettings, Precedence: 20, WriteNeeds: PrivUser,
			Grounding: mac4Live("Antigravity IDE 2.6.0 (/Applications/Antigravity IDE.app, product nameShort \"Antigravity IDE\") created ~/Library/Application Support/Antigravity IDE/User/; " +
				"~/Library/Application Support/Antigravity is the separate Antigravity 2 agent app's dir, with no User/ layout"),
			Note: "The macOS dir is live-grounded by MAC-4 (the IDE's own product name; older IDE builds named it Antigravity, which the adapter's state.vscdb lookup still tries). " +
				"The Linux and Windows dirs and the settings.json file name are INFERRED from the VS Code fork layout beside the grounded state.vscdb; whether a current " +
				"IDE build on those OSes also moved to an \"Antigravity IDE\" dir is not checked. Not live-checked for agent keys.",
		},
		{
			ID: "antigravity/user-mcp", Tool: "antigravity", Shape: "antigravity/mcp", Kind: KindMCP, Scope: ScopeUser,
			Paths: samePath("~/.gemini/config/mcp_config.json"), Format: FormatJSON, Precedence: 20, WriteNeeds: PrivUser,
			Grounding: doc(antigravityMCPRef), Note: "Shared with the agy CLI (also catalogued as antigravity-cli/user-mcp); the IDE's View raw config opens it.",
		},
		{
			ID: "antigravity/project-mcp", Tool: "antigravity", Shape: "antigravity/mcp", Kind: KindMCP, Scope: ScopeProjectShared,
			Paths: samePath("<project>/.agents/mcp_config.json"), Format: FormatJSON, Precedence: 30, WriteNeeds: PrivUser,
			Grounding: doc(antigravityMCPRef), Note: "Shared with the agy CLI.",
		},
		{
			ID: "antigravity/user-config", Tool: "antigravity", Shape: "antigravity/config", Kind: KindSettings, Scope: ScopeUser,
			Paths: samePath("~/.gemini/config/config.json"), Format: FormatJSON, Precedence: 20, WriteNeeds: PrivUser,
			Grounding: doc(antigravityEnterpriseRef), Note: "Holds userSettings.enableAdc for Antigravity 2.0 and the IDE (the CLI uses AGY_ADC_AUTH instead).",
		},
		{
			ID: "antigravity/mcp-oauth-tokens", Tool: "antigravity", Shape: "antigravity/mcp-oauth-tokens", Kind: KindToolState, Scope: ScopeUser,
			Paths: samePath("~/.gemini/antigravity/mcp_oauth_tokens.json"), Format: FormatJSON, Precedence: 20, WriteNeeds: PrivNever,
			Grounding: doc(antigravityMCPRef), Note: "MCP OAuth access tokens, refreshed by the app: never read, never written.",
		},
	},
	Extra: []SettingRow{
		antigravityRow(SettingRow{
			Path: KeyPath{"mcpServers"}, FileID: "antigravity/mcp", Type: TypeMCPMap, Source: antigravityMCPRef,
			Desc: "MCP servers by name: command, args, env, cwd, serverUrl, headers, authProviderType, oauth, disabled, disabledTools.",
			Note: "Remote servers use serverUrl. disabled: true or disabledTools silences a server; headers and oauth.clientSecret may hold credentials.",
		}),
		antigravityRow(SettingRow{
			Path: KeyPath{"userSettings", "enableAdc"}, FileID: "antigravity/config", Type: TypeBool, Source: antigravityEnterpriseRef,
			Desc: "Authenticate with Google Application Default Credentials.",
		}),
		antigravityRow(SettingRow{
			Path: KeyPath{"update.mode"}, FileID: "antigravity/editor-settings", Type: TypeString, Source: antigravityVSCodeRef, Verified: VerifiedUnverified,
			Desc: "VS Code update mode inherited by the fork.", Note: "UNVERIFIED for Antigravity (audit V15: inferred from the VS Code fork).",
		}),
		antigravityRow(SettingRow{
			Path: KeyPath{"workbench.colorTheme"}, FileID: "antigravity/editor-settings", Type: TypeString, Source: antigravityVSCodeRef, Verified: VerifiedUnverified,
			Desc: "Editor color theme inherited by the fork.", Note: "UNVERIFIED for Antigravity (audit V16: inferred from the VS Code fork).",
		}),
	},
	Map: []MapRow{
		{
			Key: KeyMCPServers, Tool: "antigravity", Settings: []string{"antigravity/mcpServers"}, Transform: TransformMCPShape,
			Params: TransformParams{MCP: antigravityMCPShape}, Lossy: true, Source: antigravityMCPRef,
			Note: "SSE is refused (serverUrl does not distinguish it on write). " + mcpLossyNote,
		},
	},
}
