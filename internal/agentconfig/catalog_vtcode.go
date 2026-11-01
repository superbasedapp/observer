package agentconfig

// VT Code (`vtcode`; TUI, `exec`, `acp`), doc-authored (surface-gap lane
// w4-catalog). Sources: location matrix Part 7 section 10 (vinhnx/vtcode
// main crates/common/vtcode-commons/src/vtcode_paths.rs,
// docs/config/CONFIGURATION_PRECEDENCE.md, vtcode-config hooks.rs, mcp.rs
// and loader/manager.rs) and docs/vtcode-adapter.md.
//
// Layers, low to high: system (Unix only), user (the legacy ~/.vtcode file,
// then the canonical file), project profile, workspace .vtcode/vtcode.toml,
// workspace root vtcode.toml, an explicit --config / VTCODE_CONFIG_PATH
// (which replaces the workspace files), runtime -c k=v. Tables deep-merge
// and ARRAYS ARE REPLACED: any higher-layer [[hooks.lifecycle.<event>]]
// drops Observer's user-level group (review W-6), and
// [workspace] use_root_config = true drops the system and user layers
// entirely. The auth/ directories are never read.
const (
	vtcodePathsRef = "https://raw.githubusercontent.com/vinhnx/vtcode/main/crates/common/vtcode-commons/src/vtcode_paths.rs"
	vtcodePrecRef  = "https://raw.githubusercontent.com/vinhnx/vtcode/main/docs/config/CONFIGURATION_PRECEDENCE.md"
	vtcodeHooksRef = "https://raw.githubusercontent.com/vinhnx/vtcode/main/crates/codegen/vtcode-config/src/hooks.rs"
	vtcodeMCPRef   = "https://raw.githubusercontent.com/vinhnx/vtcode/main/crates/codegen/vtcode-config/src/mcp.rs"
	vtcodeLoadRef  = "https://raw.githubusercontent.com/vinhnx/vtcode/main/crates/codegen/vtcode-config/src/loader/manager.rs"
	vtcodeConfig   = "vtcode/config"
	vtcodeKeyNote  = "Provider overrides can hold key material (docs/vtcode-adapter.md Off-limits); the editor shows a credential by presence only."
)

var vtcodeFiles = []FileRow{
	{
		ID: "vtcode/system-config", Tool: "vtcode", Shape: vtcodeConfig, Kind: KindSettings, Scope: ScopeSystem,
		Paths: OSPaths{Linux: "/etc/vtcode/vtcode.toml", Darwin: "/etc/vtcode/vtcode.toml"}, Format: FormatTOML, Precedence: 10, WriteNeeds: PrivAdminRoot,
		Grounding: waveSource(vtcodePathsRef),
		Note:      "Unix only (an empty list on Windows); on Linux $XDG_CONFIG_DIRS/*/vtcode/vtcode.toml follow it. It cannot lock hooks: arrays are replaced and use_root_config drops it.",
	},
	{
		ID: "vtcode/user-legacy", Tool: "vtcode", Shape: vtcodeConfig, Kind: KindSettings, Scope: ScopeUser,
		Paths: samePath("~/.vtcode/vtcode.toml"), Format: FormatTOML, Precedence: 15, WriteNeeds: PrivUser,
		Grounding: waveSource(vtcodePathsRef),
		Note:      "Legacy user file, read before the canonical one. VTCODE_HOME moves this legacy root only (relocate.go). The Windows spelling is unverified. " + vtcodeKeyNote,
	},
	{
		ID: "vtcode/user-config", Tool: "vtcode", Shape: vtcodeConfig, Kind: KindSettings, Scope: ScopeUser,
		Paths: OSPaths{
			Linux:   "$XDG_CONFIG_HOME/vtcode/vtcode.toml",
			Darwin:  "~/Library/Application Support/com.vinhnx.vtcode/vtcode.toml",
			Windows: `%APPDATA%\vinhnx\vtcode\config\vtcode.toml`,
		},
		Format: FormatTOML, Precedence: 20, WriteNeeds: PrivUser, Grounding: waveSource(vtcodePathsRef),
		Note: "Canonical user file: Linux uses $XDG_CONFIG_HOME only when it is absolute (else ~/.config); macOS is dirs::data_local_dir (XDG ignored); " +
			"Windows dirs::data_dir. VTCODE_CONFIG (an absolute dir) beats every OS default (relocate.go). " +
			"Observer's hook writer adds its groups here (internal/hook/register_wave1021_config.go) but hard-codes ~/.config/vtcode on Linux, ignores VTCODE_CONFIG " +
			"and skips macOS (matrix items 8 and 9). " + vtcodeKeyNote,
	},
	{
		ID: "vtcode/project-profile", Tool: "vtcode", Shape: vtcodeConfig, Kind: KindSettings, Scope: ScopeProjectShared,
		Paths: samePath("<project>/.vtcode/projects/*/config/vtcode.toml"), Format: FormatTOML, Precedence: 30, WriteNeeds: PrivUser,
		Grounding: waveSource(vtcodeLoadRef),
		Note:      "One per project name (.vtcode-project selects it). Hooks here need digest-bound approval.",
	},
	{
		ID: "vtcode/workspace-config", Tool: "vtcode", Shape: vtcodeConfig, Kind: KindSettings, Scope: ScopeProjectShared,
		Paths: samePath("<project>/.vtcode/vtcode.toml"), Format: FormatTOML, Precedence: 35, WriteNeeds: PrivUser,
		Grounding: waveDoc(vtcodePrecRef), Note: "Hooks need approval; its arrays replace the user arrays (review W-6).",
	},
	{
		ID: "vtcode/workspace-root-config", Tool: "vtcode", Shape: vtcodeConfig, Kind: KindSettings, Scope: ScopeProjectShared,
		Paths: samePath("<project>/vtcode.toml"), Format: FormatTOML, Precedence: 40, WriteNeeds: PrivUser,
		Grounding: waveDoc(vtcodePrecRef),
		Note:      "Highest file layer unless --config / VTCODE_CONFIG_PATH names an explicit file, which replaces both workspace files.",
	},
	{
		ID: "vtcode/user-auth", Tool: "vtcode", Shape: "vtcode/auth", Kind: KindToolState, Scope: ScopeUser,
		Paths: OSPaths{Linux: "~/.config/vtcode/auth/", Windows: `%APPDATA%\vinhnx\vtcode\config\auth\`}, Format: FormatJSON, Precedence: 0, WriteNeeds: PrivNever,
		Grounding: waveAdapterDoc("docs/vtcode-adapter.md (Off-limits)"), Note: "Provider / OAuth credentials: never read or written. The macOS location is unverified.",
	},
}

var vtcodeSettings = waveRows("vtcode", vtcodeConfig, vtcodePrecRef, []SettingRow{
	{
		Path: KeyPath{"hooks", "lifecycle"}, Type: TypeObject, Source: vtcodeHooksRef,
		Desc: "Lifecycle hooks: [[hooks.lifecycle.<event>]] tables {matcher, hooks = [{type = \"command\", command, timeout_seconds}]} for session_start, session_end, " +
			"user_prompt_submit, pre_tool_use, post_tool_use, permission_request, pre_compact, stop, subagent_start, subagent_stop, notification.",
		Note: "No enable switch; user hooks need no approval, repository-layer hooks do. Commands run as sh -c (Windows needs sh.exe on PATH). " +
			"An array in a higher layer REPLACES the user array, so it drops Observer's group.",
	},
	{
		Path: KeyPath{"hooks", "lifecycle", "pre_tool_use"}, Type: TypeObject, Source: vtcodeHooksRef,
		Desc: "pre_tool_use groups.", Note: "Observer's tool-gate group lives here in the user file.",
	},
	{
		Path: KeyPath{"hooks", "lifecycle", "user_prompt_submit"}, Type: TypeObject, Source: vtcodeHooksRef,
		Desc: "user_prompt_submit groups.", Note: "Observer's prompt-gate group lives here in the user file.",
	},
	{
		Path: KeyPath{"workspace", "use_root_config"}, Type: TypeBool, Scopes: []Scope{ScopeProjectShared}, Danger: DangerRefuseWhileIntegrated,
		Desc: "Keep only the workspace root file plus runtime overrides.", Note: "true drops the system and user layers, Observer's user-level hooks included (matrix item 10).",
	},
	{
		Path: KeyPath{"provider_overrides"}, Type: TypeObject, Scopes: []Scope{ScopeSystem, ScopeUser}, Danger: DangerConfirm,
		Desc: "[provider_overrides.<p>] tables with base_url.", Source: "docs/vtcode-adapter.md (Proxy, hooks, MCP; CONFIG_FIELD_REFERENCE.md)",
		Note: "User / system layers only (repository layers may not set them). A base URL redirects inference; OPENAI_BASE_URL, ANTHROPIC_BASE_URL, OPENROUTER_BASE_URL and ~30 more do it from the environment.",
	},
	{
		Path: KeyPath{"custom_providers"}, Type: TypeObject, Scopes: []Scope{ScopeSystem, ScopeUser}, Danger: DangerConfirm,
		Desc: "[[custom_providers]] tables with base_url.", Source: "docs/vtcode-adapter.md (Proxy, hooks, MCP; CONFIG_FIELD_REFERENCE.md)",
		Note: "User / system layers only.",
	},
	{Path: KeyPath{"mcp", "enabled"}, Type: TypeBool, Source: vtcodeMCPRef, Desc: "Use MCP servers."},
	{
		Path: KeyPath{"mcp", "providers"}, Type: TypeObject, Source: vtcodeMCPRef,
		Desc: "[[mcp.providers]] tables {name, command, args, enabled} (stdio) or endpoint (HTTP); `vtcode mcp add|remove`.",
		Note: "An array of tables, which no Observer MCP writer format matches (no MCP target).",
	},
	{Path: KeyPath{"mcp", "allowlist", "enforce"}, Type: TypeBool, Source: vtcodeMCPRef, Desc: "Enforce the MCP allow-list."},
	{Path: KeyPath{"mcp", "requirements", "allowed_stdio_commands"}, Type: TypeStringList, Source: vtcodeMCPRef, Desc: "stdio commands MCP servers may run."},
	{Path: KeyPath{"mcp", "requirements", "allowed_http_endpoints"}, Type: TypeStringList, Source: vtcodeMCPRef, Desc: "HTTP endpoints MCP servers may use."},
})

var vtcodeCatalog = toolCatalog{
	Tool: "vtcode",
	VerifiedAgainst: "vinhnx/vtcode main vtcode_paths.rs, CONFIGURATION_PRECEDENCE.md, vtcode-config hooks.rs, mcp.rs, loader/manager.rs " +
		"(location matrix Part 7 section 10, 2026-10-25) plus docs/vtcode-adapter.md (0.180.2 install); no settings value was read.",
	Files: vtcodeFiles,
	Extra: vtcodeSettings,
}
