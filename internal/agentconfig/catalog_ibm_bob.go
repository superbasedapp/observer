package agentconfig

// IBM Bob (Bob Shell `bob` and Bob IDE), doc-authored (surface-gap lane
// w4-catalog). Sources: location matrix Part 7 section 2 (bob.ibm.com shell
// configuration, lifecycle hooks, MCP and group-policies pages) and
// docs/ibmbob-adapter.md (Bob Shell 2.0.6 bundle). Credentials live in
// auth-secrets.json, which is never read and has no rows.
const (
	bobConfigRef = "https://bob.ibm.com/docs/shell/configuration/configuring"
	bobHooksRef  = "https://bob.ibm.com/docs/ide/configuration/lifecycle-hooks"
	bobMCPRef    = "https://bob.ibm.com/docs/shell/configuration/mcp/mcp-bobshell"
	bobPolicyRef = "https://bob.ibm.com/docs/ide/security/group-policies"
	bobBundleRef = "docs/ibmbob-adapter.md (Bob Shell 2.0.6 bundle)"
	bobSettings  = "ibm-bob/settings"
	bobMCP       = "ibm-bob/mcp"
	bobPolicy    = "ibm-bob/policy"
)

var ibmBobFiles = []FileRow{
	{
		ID: "ibm-bob/user-settings", Tool: "ibm-bob", Shape: bobSettings, Kind: KindSettings, Scope: ScopeUser,
		Paths: samePath("~/.bob/settings/settings.json"), Format: FormatJSON, Precedence: 20, WriteNeeds: PrivUser,
		Grounding: waveDoc(bobConfigRef),
		Note: "Under the home on Windows too (%USERPROFILE%\\.bob, not %APPDATA%); no relocation variable is documented. " +
			"Observer's hook writer adds its entries under hooks (internal/hook/register_wave1021.go); global hooks always run, workspace hooks merge on top.",
	},
	{
		ID: "ibm-bob/workspace-settings", Tool: "ibm-bob", Shape: bobSettings, Kind: KindSettings, Scope: ScopeProjectShared,
		Paths: samePath("<project>/.bob/settings.json"), Format: FormatJSON, Precedence: 30, WriteNeeds: PrivUser,
		Grounding: waveDoc(bobHooksRef),
		Note:      "Workspace hooks merge over the global ones. The bundle reads them only for a trusted workspace (~/.bob/trustedFolders.json) with workspace hooks enabled; the docs do not say so.",
	},
	{
		ID: "ibm-bob/user-mcp", Tool: "ibm-bob", Shape: bobMCP, Kind: KindMCP, Scope: ScopeUser,
		Paths: samePath("~/.bob/settings/mcp.json"), Format: FormatJSON, Precedence: 20, WriteNeeds: PrivUser,
		Grounding: waveDoc(bobMCPRef), Note: "Managed by `bob mcp add|add-json|remove`; Observer writes no entry here (AP-120).",
	},
	{
		ID: "ibm-bob/workspace-mcp", Tool: "ibm-bob", Shape: bobMCP, Kind: KindMCP, Scope: ScopeProjectShared,
		Paths: samePath("<project>/.bob/mcp.json"), Format: FormatJSON, Precedence: 30, WriteNeeds: PrivUser,
		Grounding: waveDoc("https://bob.ibm.com/docs/ide/configuration/mcp/mcp-in-bob"), Note: "A project server with the same name overrides the global one.",
	},
	{
		ID: "ibm-bob/policy", Tool: "ibm-bob", Shape: bobPolicy, Kind: KindSettings, Scope: ScopeManaged,
		Paths: OSPaths{Linux: "/etc/bob/policy.json"}, Format: FormatJSON, Precedence: 100, WriteNeeds: PrivAdminRoot,
		Grounding: waveDoc(bobPolicyRef),
		Note: "One flat policy object that beats workspace, user and defaults and locks the setting. Windows: the registry key Software\\Policies\\IBM\\Bob " +
			"(HKLM, and HKCU through the User Configuration ADMX); macOS: the com.ibm.bob managed-preferences domain " +
			"(/Library/Managed Preferences/[<user>/]com.ibm.bob.plist). Neither is a file this table can name. Observer emits it as an MDM artifact " +
			"(internal/managedsettings/bob.go), never writes it; its stand-down check reads Linux root-owned only, Windows HKLM only. " +
			"Bob 2.2.3 on Windows also applies EnforcedHooks from the HKCU key (FU-115, live 2026-10-29): Observer reads that key by key name as untrusted, " +
			"report-only (user-set, user-level, never machine-enforced; finding user_policy_override), never for stand-down. " +
			"Bob's macOS watcher also applies the user's own com.ibm.bob domain (~/Library/Preferences/com.ibm.bob.plist, `defaults write`) as policy (MAC-4 item 4): " +
			"Observer reads it by key name as untrusted, report-only (the ibm-bob/policy.* effective-layer families, finding user_policy_override), never for stand-down.",
	},
	{
		ID: "ibm-bob/auth-secrets", Tool: "ibm-bob", Shape: "ibm-bob/auth-secrets", Kind: KindToolState, Scope: ScopeUser,
		Paths: samePath("~/.bob/settings/auth-secrets.json"), Format: FormatJSON, Precedence: 0, WriteNeeds: PrivNever,
		Grounding: waveAdapterDoc("docs/ibmbob-adapter.md (Off-limits)"), Note: "Credentials: never read, copied or written.",
	},
	{
		ID: "ibm-bob/trusted-folders", Tool: "ibm-bob", Shape: "ibm-bob/trusted-folders", Kind: KindToolState, Scope: ScopeUser,
		Paths: samePath("~/.bob/trustedFolders.json"), Format: FormatJSON, Precedence: 0, WriteNeeds: PrivNever,
		Grounding: waveAdapterDoc("docs/ibmbob-adapter.md (Hooks, Off-limits)"), Note: "Workspace trust Bob records; shown, never form-edited.",
	},
}

var ibmBobSettings = waveRows("ibm-bob", bobSettings, bobConfigRef, []SettingRow{
	{
		Path: KeyPath{"hooks"}, Type: TypeObject, Source: bobHooksRef,
		Desc: "Claude-Code-shaped hook groups by event (SessionStart, UserPromptSubmit, PreCompact, PostCompact, PreToolUse, PostToolUse, Stop): " +
			"[{matcher, hooks: [{type: command, command, timeout, disabled} | {type: http, url, headers, allowedEnvVars, timeout}]}].",
		Note: "Observer's PreToolUse and UserPromptSubmit entries live here. The IDE runs commands with sh -c / cmd /c, a 10 s default timeout, and ignores PreToolUse stdout (only exit 2 blocks).",
	},
	{
		Path: KeyPath{"disableGlobalHooks"}, Type: TypeBool, Scopes: []Scope{ScopeUser}, Source: bobBundleRef, Verified: VerifiedUnverified,
		Desc: "Turn the global (user) hooks off.", Danger: DangerRefuseWhileIntegrated,
		Note: "Bundle-grounded, not in the vendor docs. true stops Observer's user-level hooks; the internal/hookdisable row ibm-bob.disableGlobalHooks reads it. Policy EnforcedHooks still run.",
	},
	{
		Path: KeyPath{"telemetry", "enabled"}, Type: TypeBool, Default: "true", Scopes: []Scope{ScopeUser},
		Desc: "Bob's own telemetry (Bobalytics).", Danger: DangerConfirm,
		Note: "false also stops the OTLP export to Observer when the policy sets OtelConfiguration (bundle 2.0.6). `observer init --ibm-bob-disable-vendor-telemetry` " +
			"writes false on opt-in (internal/hook/ibmbob_telemetry.go) and hands the key back on --uninstall.",
	},
	{
		Path: KeyPath{"mcpServers"}, FileID: bobMCP, Type: TypeMCPMap, Source: bobMCPRef,
		Desc: "MCP servers by name: {type: stdio, command, args, env, cwd} | {type: streamable-http | sse, url, headers}; disabled, alwaysAllow.",
		Note: "type is REQUIRED (unlike Claude Code's optional stdio type). headers and env may hold credentials.",
	},
	// --- policy (managed)
	{
		Path: KeyPath{"EnforcedHooks"}, FileID: bobPolicy, Type: TypeString, Source: bobPolicyRef,
		Desc: "Hook groups as a JSON STRING, keyed by event; they run before the user's hooks and the user cannot override them.",
		Note: "Bob's schema is strict: one bad part voids the whole value. Observer's generator emits its hooks here by default (`observer org emit-managed-settings --provider ibm-bob`).",
	},
	{
		Path: KeyPath{"GatewayUrl"}, FileID: bobPolicy, Type: TypeString, Source: bobPolicyRef, Danger: DangerConfirm,
		Desc: "Locked inference gateway URL.", Note: "Overrides a BOB_GATEWAY_URL route. Observer's generator does not emit it (no Bob route is grounded yet) and its README says to keep an org value; the doctor names a deployed one (surface-gap S-19).",
	},
	{
		Path: KeyPath{"DisabledAutoApprovalGroups"}, FileID: bobPolicy, Type: TypeStringList, Source: bobPolicyRef,
		Desc: "Auto-approval groups the policy turns off (incl. mcp).",
	},
	{Path: KeyPath{"UpdateMode"}, FileID: bobPolicy, Type: TypeString, Source: bobPolicyRef, Desc: "Update channel policy."},
	{
		Path: KeyPath{"EnableTelemetry"}, FileID: bobPolicy, Type: TypeBool, Source: bobBundleRef,
		Desc: "Policy twin of telemetry.enabled.", Note: "Read from the 2.0.6 bundle; false also stops the OtelConfiguration export.",
	},
	{
		Path: KeyPath{"OtelConfiguration"}, FileID: bobPolicy, Type: TypeString, Source: bobBundleRef,
		Desc: "OpenTelemetry export settings.", Note: "Read from the 2.0.6 bundle; Observer's generator emits it for its own OTLP receiver.",
	},
})

var ibmBobCatalog = toolCatalog{
	Tool: "ibm-bob",
	VerifiedAgainst: "bob.ibm.com shell configuration, lifecycle hooks, MCP and group-policies pages (location matrix Part 7 section 2, 2026-10-25) " +
		"plus docs/ibmbob-adapter.md (Bob Shell 2.0.6 bundle); no settings value was read.",
	Files: ibmBobFiles,
	Extra: ibmBobSettings,
}
