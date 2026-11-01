package agentconfig

// Cast AI Kimchi (`kimchi`, a pi-mono derivative), doc-authored
// (surface-gap lane w4-catalog). Sources: location matrix Part 7 section 8
// (getkimchi/kimchi master src/config.ts, src/entry.ts,
// src/api/org-settings.ts, docs/hooks.md, docs/project-trust.md,
// docs/mcp-project-overrides.md) and docs/kimchi-adapter.md.
//
// The base is os.homedir()/.config/kimchi on every OS (Windows
// %USERPROFILE%\.config\kimchi, not %APPDATA%). entry.ts sets
// KIMCHI_CODING_AGENT_DIR and PI_CODING_AGENT_DIR unconditionally to the
// harness dir, so neither variable relocates it (declared as
// does-not-move in relocate.go). The account config.json holds the API
// key, harness/models.json per-provider apiKey values and harness/auth.json
// OAuth state: the first two are PrivNever with doc-only rows, the last has
// none. Resource-enable precedence: org lock (FORCE_ON / FORCE_OFF), local
// settings.json resources, KIMCHI_ENABLE_RESOURCES, org soft default, the
// definition default.
const (
	kimchiConfigRef  = "https://cdn.jsdelivr.net/gh/getkimchi/kimchi@master/src/config.ts"
	kimchiEntryRef   = "https://cdn.jsdelivr.net/gh/getkimchi/kimchi@master/src/entry.ts"
	kimchiHooksRef   = "https://cdn.jsdelivr.net/gh/getkimchi/kimchi@master/docs/hooks.md"
	kimchiTrustRef   = "https://cdn.jsdelivr.net/gh/getkimchi/kimchi@master/docs/project-trust.md"
	kimchiMCPRef     = "https://cdn.jsdelivr.net/gh/getkimchi/kimchi@master/docs/mcp-project-overrides.md"
	kimchiAdapterRef = "docs/kimchi-adapter.md (Storage layout)"
	kimchiConfig     = "kimchi/config"
	kimchiHarness    = "kimchi/harness-settings"
	kimchiModels     = "kimchi/models"
	kimchiHooks      = "kimchi/hooks"
	kimchiMCP        = "kimchi/mcp"
)

var kimchiFiles = []FileRow{
	{
		ID: "kimchi/account-config", Tool: "kimchi", Shape: kimchiConfig, Kind: KindSettings, Scope: ScopeUser,
		Paths: samePath("~/.config/kimchi/config.json"), Format: FormatJSON, Precedence: 20, WriteNeeds: PrivNever,
		Grounding: waveSource(kimchiConfigRef),
		Note:      "Holds the API key beside deviceId, telemetry and onboarding state: never read by anything here; rows come from vendor source only. No relocation variable.",
	},
	{
		ID: "kimchi/project-config", Tool: "kimchi", Shape: kimchiConfig, Kind: KindSettings, Scope: ScopeProjectShared,
		Paths: samePath("<project>/.kimchi/config.json"), Format: FormatJSON, Precedence: 30, WriteNeeds: PrivUser,
		Grounding: waveDoc(kimchiTrustRef), Note: "Trust-gated (harness/agent/trust.json). Whether it may carry an API key like the account file is unverified.",
	},
	{
		ID: "kimchi/org-policy", Tool: "kimchi", Shape: "kimchi/org-policy", Kind: KindToolState, Scope: ScopeUser,
		Paths: samePath("~/.config/kimchi/org-policy.json"), Format: FormatJSON, Precedence: 0, WriteNeeds: PrivNever,
		Grounding: waveAdapterDoc(kimchiAdapterRef),
		Note:      "Org id and key fingerprint; the org settings themselves are server-side (organizations/{org}/settings:resolve, which can FORCE_OFF hooks.bash). Never read or written.",
	},
	{
		ID: "kimchi/harness-settings", Tool: "kimchi", Shape: kimchiHarness, Kind: KindSettings, Scope: ScopeUser,
		Paths: samePath("~/.config/kimchi/harness/settings.json"), Format: FormatJSON, Precedence: 20, WriteNeeds: PrivUser,
		Grounding: waveAdapterDoc(kimchiAdapterRef),
		Note:      "Harness settings (resources, defaultProjectTrust, defaultProvider / defaultModel, retry, theme). KIMCHI_CODING_AGENT_DIR does not move it (entry.ts overrides it).",
	},
	{
		ID: "kimchi/harness-models", Tool: "kimchi", Shape: kimchiModels, Kind: KindSettings, Scope: ScopeUser,
		Paths: samePath("~/.config/kimchi/harness/models.json"), Format: FormatJSON, Precedence: 20, WriteNeeds: PrivNever,
		Grounding: waveAdapterDoc(kimchiAdapterRef),
		Note:      "Providers with baseUrl, api, a plaintext apiKey and the model list (regenerated for kimchi-dev): never read or written here.",
	},
	{
		ID: "kimchi/harness-auth", Tool: "kimchi", Shape: "kimchi/harness-auth", Kind: KindToolState, Scope: ScopeUser,
		Paths: samePath("~/.config/kimchi/harness/auth.json"), Format: FormatJSON, Precedence: 0, WriteNeeds: PrivNever,
		Grounding: waveAdapterDoc(kimchiAdapterRef), Note: "Per-provider OAuth state and keys: never read or written.",
	},
	{
		ID: "kimchi/harness-trust", Tool: "kimchi", Shape: "kimchi/harness-trust", Kind: KindToolState, Scope: ScopeUser,
		Paths: samePath("~/.config/kimchi/harness/agent/trust.json"), Format: FormatJSON, Precedence: 0, WriteNeeds: PrivNever,
		Grounding: waveDoc(kimchiTrustRef), Note: "Project trust Kimchi records; shown, never form-edited.",
	},
	{
		ID: "kimchi/harness-bash-hooks", Tool: "kimchi", Shape: "kimchi/bash-hooks", Kind: KindHooks, Scope: ScopeUser,
		Paths: samePath("~/.config/kimchi/harness/hooks/bash/"), Format: FormatScript, Precedence: 20, WriteNeeds: PrivUser,
		Grounding: waveDoc(kimchiHooksRef),
		Note: "Global bash pre-gate scripts (`bash <file>`; which bash on Windows is unverified), on by default; the hooks.bash resource turns them off. " +
			"Observer's dedicated superbased-observer.sh lives here on Linux / macOS (internal/hook/register_wave1021.go); it follows a user-exported " +
			"KIMCHI_CODING_AGENT_DIR that Kimchi itself overrides (matrix item 4).",
	},
	{
		ID: "kimchi/project-bash-hooks", Tool: "kimchi", Shape: "kimchi/bash-hooks", Kind: KindHooks, Scope: ScopeProjectShared,
		Paths: samePath("<project>/.kimchi/hooks/bash/"), Format: FormatScript, Precedence: 30, WriteNeeds: PrivUser,
		Grounding: waveDoc(kimchiTrustRef), Note: "Project bash hooks: off by default and trust-gated.",
	},
	{
		ID: "kimchi/project-hooks", Tool: "kimchi", Shape: kimchiHooks, Kind: KindHooks, Scope: ScopeProjectShared,
		Paths: samePath("<project>/.kimchi/hooks.json"), Format: FormatJSON, Precedence: 30, WriteNeeds: PrivUser,
		Grounding: waveDoc(kimchiTrustRef), Note: "Claude-Code-dialect event hooks are PROJECT-ONLY (no user-global file) and trust-gated.",
	},
	{
		ID: "kimchi/project-local-hooks", Tool: "kimchi", Shape: kimchiHooks, Kind: KindHooks, Scope: ScopeProjectLocal,
		Paths: samePath("<project>/.kimchi/hooks.local.json"), Format: FormatJSON, Precedence: 40, WriteNeeds: PrivUser,
		Grounding: waveDoc(kimchiTrustRef),
	},
	{
		ID: "kimchi/harness-mcp", Tool: "kimchi", Shape: kimchiMCP, Kind: KindMCP, Scope: ScopeUser,
		Paths: samePath("~/.config/kimchi/harness/mcp.json"), Format: FormatJSON, Precedence: 20, WriteNeeds: PrivUser,
		Grounding: waveDoc(kimchiMCPRef), Note: "User MCP, authoritative over ~/.config/mcp/mcp.json. Observer writes no entry (AP-120).",
	},
	{
		ID: "kimchi/shared-mcp", Tool: "kimchi", Shape: kimchiMCP, Kind: KindMCP, Scope: ScopeUser,
		Paths: samePath("~/.config/mcp/mcp.json"), Format: FormatJSON, Precedence: 10, WriteNeeds: PrivUser, Borrowed: true,
		Grounding: waveDoc(kimchiMCPRef), Note: "A tool-agnostic MCP file Kimchi reads below its own (never evidence Kimchi is installed).",
	},
	{
		ID: "kimchi/project-mcp", Tool: "kimchi", Shape: kimchiMCP, Kind: KindMCP, Scope: ScopeProjectShared,
		Paths: samePath("<project>/.kimchi/mcp.json"), Format: FormatJSON, Precedence: 30, WriteNeeds: PrivUser,
		Grounding: waveDoc(kimchiMCPRef), Note: "Trust-gated project overrides.",
	},
}

var kimchiSettings = waveRows("kimchi", kimchiConfig, kimchiConfigRef, []SettingRow{
	{
		Path: KeyPath{"llmEndpoint"}, Type: TypeString, Danger: DangerConfirm,
		Desc: "Inference endpoint.", Note: "KIMCHI_BASE_URL beats the project file, which beats the account file, which beats the region default. A base URL redirects inference.",
	},
	{
		Path: KeyPath{"apiKey"}, Type: TypeString, Scopes: []Scope{ScopeUser}, Secret: true, Source: "docs/kimchi-adapter.md (Storage layout)",
		Desc: "Kimchi API key.", Note: "A plaintext credential.",
	},
	// --- harness/settings.json
	{
		Path: KeyPath{"resources"}, FileID: kimchiHarness, Type: TypeObject, Source: kimchiHooksRef, Danger: DangerRefuseWhileIntegrated,
		Desc: "Resource enable map (hooks.bash, extensions.claude-code-hook-adapter, ...); `kimchi resources enable|disable` writes it.",
		Note: "Disabling hooks.bash turns Observer's pre-gate off; the org can lock a resource FORCE_ON / FORCE_OFF over this map. " +
			"The member shape is not grounded, so internal/hookdisable has no row for it yet.",
	},
	{Path: KeyPath{"defaultProjectTrust"}, FileID: kimchiHarness, Type: TypeString, Source: kimchiTrustRef, Desc: "Trust decision for projects not yet recorded."},
	{Path: KeyPath{"defaultProvider"}, FileID: kimchiHarness, Type: TypeString, Source: kimchiAdapterRef, Desc: "Default provider."},
	{Path: KeyPath{"defaultModel"}, FileID: kimchiHarness, Type: TypeString, Source: kimchiAdapterRef, Desc: "Default model."},
	{Path: KeyPath{"theme"}, FileID: kimchiHarness, Type: TypeString, Source: kimchiAdapterRef, Desc: "Terminal UI theme."},
	{
		Path: KeyPath{"lastChangelogVersion"}, FileID: kimchiHarness, Type: TypeString, Source: kimchiAdapterRef, Owner: OwnerToolState,
		Desc: "Last version whose changelog was shown.", Note: "Written by Kimchi; the adapter reads it as the install-level tool version.",
	},
	// --- harness/models.json
	{
		Path: KeyPath{"providers"}, FileID: kimchiModels, Type: TypeObject, Source: kimchiAdapterRef, Danger: DangerConfirm,
		Desc: "Providers by id: {baseUrl, api, apiKey, models}; accepts pi-mono custom providers.",
		Note: "The file is never read; apiKey is a plaintext credential and baseUrl redirects inference (providers.kimchi-dev.baseUrl is the kimchi-dev lane).",
	},
	// --- hooks / mcp
	{
		Path: KeyPath{"hooks"}, FileID: kimchiHooks, Type: TypeObject, Source: kimchiHooksRef,
		Desc: "Claude-Code-dialect hook groups by event (PreToolUse, PostToolUse, PostToolUseFailure, PostToolBatch, SessionStart, PreCompact, PostCompact, UserPromptSubmit, Stop, ...).",
		Note: "Project-only; Observer writes none (AP-117).",
	},
	{
		Path: KeyPath{"mcpServers"}, FileID: kimchiMCP, Type: TypeMCPMap, Source: kimchiMCPRef, Verified: VerifiedUnverified,
		Desc: "MCP servers by name.", Note: "The top-level key and entry shape are not grounded on disk (docs/kimchi-adapter.md); env and headers may hold credentials.",
	},
})

var kimchiCatalog = toolCatalog{
	Tool: "kimchi",
	VerifiedAgainst: "getkimchi/kimchi master src/config.ts, src/entry.ts, src/api/org-settings.ts, docs/hooks.md, docs/project-trust.md, docs/mcp-project-overrides.md " +
		"(location matrix Part 7 section 8, 2026-10-25) plus docs/kimchi-adapter.md; config.json and models.json are never read.",
	Files: kimchiFiles,
	Extra: kimchiSettings,
}
