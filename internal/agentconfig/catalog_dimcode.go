package agentconfig

// DimCode (`dim`; TUI, `dim exec`, `dim acp`), doc-authored (surface-gap
// lane w4-catalog). Sources: location matrix Part 7 section 6
// (dimcode.dev/docs config and cli pages) and docs/dimcode-adapter.md
// (the vendor binary's bundled source, 0.5.21). Every file sits in the
// store home ~/.dimcode/v2 ($DIMCODE_HOME, with v2 appended unless the value
// already ends in v2). providers.json and auth.json hold credentials and are
// never read; the provider base URL lives there and in the dimcode.sqlite
// providers table, so it has no row. The route levers that need no file are
// environment variables (OPENAI_BASE_URL / DIMCODE_OPENAI_BASE_URL,
// DIMCODE_ANTHROPIC_BASE_URL, DIMCODE_GEMINI_BASE_URL, which override the
// saved files at runtime). Desktop (0.9.8) settings and any managed layer
// are unverified.
const (
	dimcodeConfigRef = "https://dimcode.dev/docs/config"
	dimcodeHooksRef  = "docs/dimcode-adapter.md (Hooks, from the 0.5.21 bundle; live 2026-10-21)"
	dimcodeHooks     = "dimcode/hooks"
	dimcodeMCP       = "dimcode/mcp"
)

var dimcodeFiles = []FileRow{
	{
		ID: "dimcode/user-config", Tool: "dimcode", Shape: "dimcode/config", Kind: KindSettings, Scope: ScopeUser,
		Paths: samePath("~/.dimcode/v2/config.json"), Format: FormatJSON, Precedence: 20, WriteNeeds: PrivUser,
		Grounding: waveAdapterDoc("docs/dimcode-adapter.md (Store layout)"),
		Note:      "Global config; its keys are not grounded, so it has no rows. DIMCODE_HOME relocates the store home (relocate.go).",
	},
	{
		ID: "dimcode/user-hooks", Tool: "dimcode", Shape: dimcodeHooks, Kind: KindHooks, Scope: ScopeUser,
		Paths: samePath("~/.dimcode/v2/hooks.json"), Format: FormatJSON, Precedence: 20, WriteNeeds: PrivUser,
		Grounding: waveAdapterDoc("docs/dimcode-adapter.md (Hooks, proxy, MCP)"),
		Note: "Observer's hook writer adds its groups here (internal/hook/register_wave1021.go). An unknown event name voids the WHOLE file. " +
			"There is no trust gate; --no-hooks and DIM_DISABLE_HOOKS switch hooks off for a run. The vendor docs do not document hook paths (bundle-grounded).",
	},
	{
		ID: "dimcode/project-hooks", Tool: "dimcode", Shape: dimcodeHooks, Kind: KindHooks, Scope: ScopeProjectShared,
		Paths: samePath("<project>/.dimcode/hooks.json"), Format: FormatJSON, Precedence: 30, WriteNeeds: PrivUser,
		Grounding: waveAdapterDoc("docs/dimcode-adapter.md (Hooks, proxy, MCP)"),
		Note:      "Bundle-grounded; how it combines with the user file is unverified.",
	},
	{
		ID: "dimcode/hooks-disabled", Tool: "dimcode", Shape: "dimcode/hooks-disabled", Kind: KindToolState, Scope: ScopeUser,
		Paths: samePath("~/.dimcode/v2/hooks-disabled.json"), Format: FormatJSON, Precedence: 0, WriteNeeds: PrivNever,
		Grounding: waveAdapterDoc("docs/dimcode-adapter.md (Off-limits files)"),
		Note:      "`dim hooks disable` deny list keyed by a hook's command hash. Read for membership of Observer's own hashes only (internal/hookdisable dimcode.hooks-disabled, D5); never form-edited.",
	},
	{
		ID: "dimcode/user-mcp", Tool: "dimcode", Shape: dimcodeMCP, Kind: KindMCP, Scope: ScopeUser,
		Paths: samePath("~/.dimcode/v2/mcp.json"), Format: FormatJSON, Precedence: 20, WriteNeeds: PrivUser,
		Grounding: waveDoc(dimcodeConfigRef), Note: "`dim mcp add|add-json|remove|toggle`; absent on both grounding hosts. Observer writes no entry (AP-120).",
	},
	{
		ID: "dimcode/project-mcp", Tool: "dimcode", Shape: dimcodeMCP, Kind: KindMCP, Scope: ScopeProjectShared,
		Paths: samePath("<project>/.mcp.json"), Format: FormatJSON, Precedence: 30, WriteNeeds: PrivUser,
		Grounding: waveDoc(dimcodeConfigRef),
	},
	{
		ID: "dimcode/providers", Tool: "dimcode", Shape: "dimcode/providers", Kind: KindToolState, Scope: ScopeUser,
		Paths: samePath("~/.dimcode/v2/providers.json"), Format: FormatJSON, Precedence: 0, WriteNeeds: PrivNever,
		Grounding: waveAdapterDoc("docs/dimcode-adapter.md (Off-limits files)"),
		Note: "Provider credentials and base URLs (the npm README names this file; the docs say providers live in dimcode.sqlite): never read or written. " +
			"`dim provider update <id> --base-url` is the vendor's writer.",
	},
	{
		ID: "dimcode/project-providers", Tool: "dimcode", Shape: "dimcode/providers", Kind: KindToolState, Scope: ScopeProjectShared,
		Paths: samePath("<project>/.dimcode/providers.json"), Format: FormatJSON, Precedence: 0, WriteNeeds: PrivNever,
		Grounding: waveAdapterDoc("docs/dimcode-adapter.md (Hooks, proxy, MCP)"), Note: "Project providers file: may hold credentials, never read or written.",
	},
	{
		ID: "dimcode/auth", Tool: "dimcode", Shape: "dimcode/auth", Kind: KindToolState, Scope: ScopeUser,
		Paths: samePath("~/.dimcode/v2/auth.json"), Format: FormatJSON, Precedence: 0, WriteNeeds: PrivNever,
		Grounding: waveAdapterDoc("docs/dimcode-adapter.md (Off-limits files)"), Note: "Login state: never read or written.",
	},
}

var dimcodeSettings = waveRows("dimcode", dimcodeHooks, dimcodeHooksRef, []SettingRow{
	{
		Path: KeyPath{"hooks"}, Type: TypeObject,
		Desc: "Claude-Code-style command hook groups by event (SessionStart, SubagentStart, PreToolUse, PermissionRequest, PostToolUse, PreCompact, PostCompact, UserPromptSubmit, SubagentStop, Stop).",
		Note: "Exit code 2 or continue:false blocks; other failures fail open. Observer's PreToolUse and UserPromptSubmit groups live in the user file; `dim hooks disable` can silence one by hash.",
	},
	{
		Path: KeyPath{"mcpServers"}, FileID: dimcodeMCP, Type: TypeMCPMap, Source: dimcodeConfigRef,
		Desc: "MCP servers by name.", Verified: VerifiedUnverified,
		Note: "The entry shape is vendor-code-grounded, not live (no file on either host). env may hold credentials.",
	},
})

var dimcodeCatalog = toolCatalog{
	Tool: "dimcode",
	VerifiedAgainst: "dimcode.dev/docs config and cli pages (location matrix Part 7 section 6, 2026-10-25) plus docs/dimcode-adapter.md " +
		"(0.5.21 bundle, hooks live 2026-10-21); config.json keys and the Desktop app are not grounded.",
	Files: dimcodeFiles,
	Extra: dimcodeSettings,
}
