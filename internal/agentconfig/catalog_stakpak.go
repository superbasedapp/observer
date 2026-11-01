package agentconfig

// Stakpak (`stakpak`, Rust; ACP `stakpak acp`), doc-authored (surface-gap
// lane w4-catalog). Sources: location matrix Part 7 section 9
// (stakpak/agent main cli/src/config/{profile,app}.rs,
// libs/shared/src/paths.rs, libs/mcp/config/src/lib.rs,
// libs/agent-core/src/hooks.rs) and docs/stakpak-adapter.md.
//
// config.toml holds each profile's api_key beside the settings, so it is
// PrivNever with doc-only rows. The ACTIVE profile is chosen per run by
// --profile or STAKPAK_PROFILE; [profiles.all] is inherited by every
// profile. What a run with neither picks is not grounded. There is no
// STAKPAK_HOME; --config moves the file for one run (an ACP reload drops
// it). MCP is FIRST FILE FOUND WINS, no merge: ./mcp.toml, ./mcp.json,
// ./.stakpak/mcp.*, ~/.stakpak/mcp.toml, ~/.stakpak/mcp.json (the
// precedence numbers below encode that order). No user-configurable hooks
// and no managed layer were found.
const (
	stakpakProfileRef = "https://raw.githubusercontent.com/stakpak/agent/main/cli/src/config/profile.rs"
	stakpakAppRef     = "https://raw.githubusercontent.com/stakpak/agent/main/cli/src/config/app.rs"
	stakpakMCPRef     = "https://raw.githubusercontent.com/stakpak/agent/main/libs/mcp/config/src/lib.rs"
	stakpakConfig     = "stakpak/config"
	stakpakMCP        = "stakpak/mcp"
)

var stakpakFiles = []FileRow{
	{
		ID: "stakpak/user-config", Tool: "stakpak", Shape: stakpakConfig, Kind: KindSettings, Scope: ScopeUser,
		Paths: samePath("~/.stakpak/config.toml"), Format: FormatTOML, Precedence: 20, WriteNeeds: PrivNever,
		Grounding: waveSource(stakpakProfileRef),
		Note: "Profiles with their api_key and provider auth: never read by anything here; rows come from vendor source only (Windows: the Known-Folder profile, %USERPROFILE%). " +
			"A route writer would edit this secret-bearing file (a Wave 6 probe behind D9).",
	},
	{
		ID: "stakpak/auth", Tool: "stakpak", Shape: "stakpak/auth", Kind: KindToolState, Scope: ScopeUser,
		Paths: samePath("~/.stakpak/auth.toml"), Format: FormatTOML, Precedence: 0, WriteNeeds: PrivNever,
		Grounding: waveAdapterDoc("docs/stakpak-adapter.md (Where data lives)"), Note: "OAuth / provider credentials: never read or written.",
	},
	{
		ID: "stakpak/project-mcp-toml", Tool: "stakpak", Shape: stakpakMCP, Kind: KindMCP, Scope: ScopeProjectShared,
		Paths: samePath("<project>/mcp.toml"), Format: FormatTOML, Precedence: 50, WriteNeeds: PrivUser,
		Grounding: waveSource(stakpakMCPRef), Note: "First in the search (relative to the working directory); when present no other MCP file is read.",
	},
	{
		ID: "stakpak/project-mcp-json", Tool: "stakpak", Shape: stakpakMCP, Kind: KindMCP, Scope: ScopeProjectShared,
		Paths: samePath("<project>/mcp.json"), Format: FormatJSON, Precedence: 45, WriteNeeds: PrivUser,
		Grounding: waveSource(stakpakMCPRef),
	},
	{
		ID: "stakpak/project-dot-mcp-toml", Tool: "stakpak", Shape: stakpakMCP, Kind: KindMCP, Scope: ScopeProjectShared,
		Paths: samePath("<project>/.stakpak/mcp.toml"), Format: FormatTOML, Precedence: 41, WriteNeeds: PrivUser,
		Grounding: waveSource(stakpakMCPRef), Note: "The matrix writes ./.stakpak/mcp.*; the toml-before-json order inside it follows the home pair and is unverified.",
	},
	{
		ID: "stakpak/project-dot-mcp-json", Tool: "stakpak", Shape: stakpakMCP, Kind: KindMCP, Scope: ScopeProjectShared,
		Paths: samePath("<project>/.stakpak/mcp.json"), Format: FormatJSON, Precedence: 40, WriteNeeds: PrivUser,
		Grounding: waveSource(stakpakMCPRef),
	},
	{
		ID: "stakpak/user-mcp-toml", Tool: "stakpak", Shape: stakpakMCP, Kind: KindMCP, Scope: ScopeUser,
		Paths: samePath("~/.stakpak/mcp.toml"), Format: FormatTOML, Precedence: 21, WriteNeeds: PrivUser,
		Grounding: waveSource(stakpakMCPRef),
		Note:      "`stakpak mcp add|remove|enable|disable` manage the servers; --config-file names another file. Observer writes no entry (AP-120).",
	},
	{
		ID: "stakpak/user-mcp-json", Tool: "stakpak", Shape: stakpakMCP, Kind: KindMCP, Scope: ScopeUser,
		Paths: samePath("~/.stakpak/mcp.json"), Format: FormatJSON, Precedence: 20, WriteNeeds: PrivUser,
		Grounding: waveSource(stakpakMCPRef), Note: "Last in the search.",
	},
	{
		ID: "stakpak/project-auto-approve", Tool: "stakpak", Shape: "stakpak/auto-approve", Kind: KindToolState, Scope: ScopeProjectShared,
		Paths: samePath("<project>/.stakpak/session/auto_approve.json"), Format: FormatJSON, Precedence: 0, WriteNeeds: PrivNever,
		Grounding: waveAdapterDoc("docs/stakpak-adapter.md (Where data lives)"), Note: "Per-project approval state Stakpak records; shown, never form-edited.",
	},
}

var stakpakSettings = waveRows("stakpak", stakpakConfig, stakpakProfileRef, []SettingRow{
	{
		Path: KeyPath{"profiles"}, Type: TypeObject, Danger: DangerConfirm,
		Desc: "Profiles by name: [profiles.<p>] {api_endpoint, provider, api_key, model, allowed_tools, auto_approve, warden} and " +
			"[profiles.<p>.providers.<n>] {type, api_endpoint, ...}.",
		Note: "The file is never read. api_key is a plaintext credential; an api_endpoint redirects traffic; auto_approve skips confirmations. " +
			"The run's profile comes from --profile or STAKPAK_PROFILE (the no-flag default is not grounded).",
	},
	{
		Path: KeyPath{"profiles", "all"}, Type: TypeObject, Desc: "Settings every profile inherits.",
		Note: "The file is never read; a key here applies under whichever profile is active.",
	},
	{
		Path: KeyPath{"mcpServers"}, FileID: stakpakMCP, Type: TypeMCPMap, Source: stakpakMCPRef,
		Desc: "MCP servers by name: {command, args, env, disabled} | {url, headers}; no allow / deny list.",
		Note: "env and headers may hold credentials. STAKPAK_API_ENDPOINT (" + stakpakAppRef + ") moves only the Stakpak API, not a provider.",
	},
})

var stakpakCatalog = toolCatalog{
	Tool: "stakpak",
	VerifiedAgainst: "stakpak/agent main cli/src/config/profile.rs, app.rs, libs/shared/src/paths.rs, libs/mcp/config/src/lib.rs, libs/agent-core/src/hooks.rs " +
		"(location matrix Part 7 section 9, 2026-10-25) plus docs/stakpak-adapter.md; config.toml is never read.",
	Files: stakpakFiles,
	Extra: stakpakSettings,
}
