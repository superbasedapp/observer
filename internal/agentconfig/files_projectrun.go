package agentconfig

// projectRunFiles are project files a repository can ship that make an
// agent run code or load a server without the user asking, which the
// catalogue did not list before the JSP-7 spike (security pillar plan
// section 5.1, revision 2.4 change (c); write-up
// docs/plans/spikes/JSP-7-repository-trust-2026-10.md, "Catalog coverage").
// They are ordinary Files rows: the config editor lists them and the
// repository trust path table (TrustPaths) reads them. Shapes are their own
// (no setting rows map onto them yet), so no settings view changes.
var projectRunFiles = []FileRow{
	{
		ID: "codex/project-hooks", Tool: "codex", Shape: "codex/project-hooks", Kind: KindHooks, Scope: ScopeProjectShared,
		Paths: samePath("<project>/.codex/hooks.json"), Format: FormatJSON, Precedence: 30, WriteNeeds: PrivUser,
		Grounding: Grounding{Kind: GroundLive, Source: "JSP-6 live half: codex exec 0.144.4 ran a project .codex/hooks.json only with the project and the hook trusted", Date: "2026-10-20"},
		Note:      "Ignored unless the project is trusted, and each hook runs only after the user trusts its hash (internal/codextrust).",
	},
	{
		ID: "copilot-cli/project-hooks", Tool: "copilot-cli", Shape: "copilot-cli/project-hooks", Kind: KindHooks, Scope: ScopeProjectShared,
		Paths: samePath("<project>/.github/hooks/"), Format: FormatJSON, Precedence: 30, WriteNeeds: PrivUser,
		Grounding: Grounding{Kind: GroundSource, Source: "JSP-6 live half: the installed @github/copilot 1.0.80 bundle loads repository hooks through loadDeferredRepoHooks", Date: "2026-10-20"},
		Note:      "A directory of *.json hook files. Loaded later in the session (server and resume paths), so a -p run skipped them on 2026-10-20.",
	},
	{
		ID: "opencode/project-dir-config", Tool: "opencode", Shape: "opencode/project-dir-config", Kind: KindSettings, Scope: ScopeProjectShared,
		Paths: samePath("<project>/.opencode/opencode.json"), Format: FormatJSONC, SchemaURL: "https://opencode.ai/config.json",
		Precedence: 30, WriteNeeds: PrivUser, Grounding: doc("https://opencode.ai/docs/config/"),
		Note: "The project config directory's own config file (seen in sst/opencode by the JSP-7 spike).",
	},
	{
		ID: "opencode/project-dir-config-jsonc", Tool: "opencode", Shape: "opencode/project-dir-config", Kind: KindSettings, Scope: ScopeProjectShared,
		Paths: samePath("<project>/.opencode/opencode.jsonc"), Format: FormatJSONC, SchemaURL: "https://opencode.ai/config.json",
		Precedence: 30, WriteNeeds: PrivUser, Grounding: doc("https://opencode.ai/docs/config/"),
		Note: "The JSONC spelling of the project config directory's config file.",
	},
	{
		ID: "opencode/project-plugin", Tool: "opencode", Shape: "opencode/project-plugin", Kind: KindHooks, Scope: ScopeProjectShared,
		Paths: samePath("<project>/.opencode/plugin/"), Format: FormatScript, Precedence: 30, WriteNeeds: PrivUser,
		Grounding: Grounding{Kind: GroundLive, Source: "JSP-6 live half: an OpenCode-lineage plugin in a project plugin directory ran its tool hooks", Date: "2026-10-20"},
		Note:      "TypeScript or JavaScript plugins OpenCode loads and runs in its own process: raw text only.",
	},
	{
		ID: "opencode/project-plugins", Tool: "opencode", Shape: "opencode/project-plugin", Kind: KindHooks, Scope: ScopeProjectShared,
		Paths: samePath("<project>/.opencode/plugins/"), Format: FormatScript, Precedence: 30, WriteNeeds: PrivUser,
		Grounding: Grounding{Kind: GroundSource, Source: "JSP-7 wide-net walk: sst/opencode ships .opencode/plugins", Date: "2026-10-20"},
		Note:      "The plural spelling of the plugin directory.",
	},
	{
		ID: "opencode/project-tool", Tool: "opencode", Shape: "opencode/project-tool", Kind: KindHooks, Scope: ScopeProjectShared,
		Paths: samePath("<project>/.opencode/tool/"), Format: FormatScript, Precedence: 30, WriteNeeds: PrivUser,
		Grounding: Grounding{Kind: GroundSource, Source: "JSP-7 wide-net walk: sst/opencode and Kilo-Org/kilocode ship .opencode/tool/*.ts", Date: "2026-10-20"},
		Note:      "Custom tools: code the agent loads and runs when it calls the tool. Listed as hooks because the kind vocabulary has no plugin kind.",
	},
	{
		ID: "kilo-code-cli/project-plugin", Tool: "kilo-code-cli", Shape: "kilo-code-cli/project-plugin", Kind: KindHooks, Scope: ScopeProjectShared,
		Paths: samePath("<project>/.kilo/plugin/"), Format: FormatScript, Precedence: 30, WriteNeeds: PrivUser,
		Grounding: Grounding{Kind: GroundLive, Source: "JSP-6 live half: Kilo CLI 7.3.54 ran a project .kilo/plugin plugin's tool.execute hooks", Date: "2026-10-20"},
		Note:      "Kilo's OpenCode-lineage plugin directory: raw text only.",
	},
	{
		ID: "kilo-code/project-mcp", Tool: "kilo-code", Shape: "kilo-code/project-mcp", Kind: KindMCP, Scope: ScopeProjectShared,
		Paths: samePath("<project>/.kilocode/mcp.json"), Format: FormatJSON, Precedence: 30, WriteNeeds: PrivUser,
		Grounding: Grounding{Kind: GroundSource, Source: "JSP-7 wide-net walk: Kilo-Org/kilocode packages/kilo-docs/.kilocode/mcp.json", Date: "2026-10-20"},
		Note:      "The pre-7 extension's project MCP server file (the Roo Code lineage shape).",
	},
	{
		ID: "gemini-cli/project-env", Tool: "gemini-cli", Shape: "gemini-cli/project-env", Kind: KindToolState, Scope: ScopeProjectShared,
		Paths: samePath("<project>/.gemini/.env"), Format: FormatScript, Precedence: 30, WriteNeeds: PrivNever,
		Grounding: doc("https://raw.githubusercontent.com/google-gemini/gemini-cli/main/docs/reference/configuration.md"),
		Note:      "A dotenv file Gemini CLI loads into its environment: never shown or edited. The repository trust check reads only its variable names and judges a few of their values in memory.",
	},
}
