package agentconfig

// GitHub Copilot CLI (phase P2, doc-authored). JSONC settings under
// ~/.copilot (COPILOT_HOME relocates it), repo and local files under
// .github/copilot, and an MDM managed-settings file that acts as a
// BASELINE (most keys stay user-overridable). Sources: audit
// docs/audits/adapter-config-surface-2026-10-03.md section 5 "copilot-cli"
// and the GitHub docs pages below, re-fetched 2026-10-04.

const (
	copilotCLIRef     = "https://docs.github.com/en/copilot/reference/copilot-cli-reference/cli-config-dir-reference"
	copilotCLIMgdRef  = "https://docs.github.com/en/copilot/reference/enterprise-administrators/enterprise-managed-settings"
	copilotCLICfgMgd  = "https://docs.github.com/en/copilot/how-tos/administer-copilot/manage-for-enterprise/manage-agents/configure-enterprise-managed-settings"
	copilotCLIMCPRef  = "https://docs.github.com/en/copilot/how-tos/copilot-cli/customize-copilot/add-mcp-servers"
	copilotCLIAudit   = "docs/audits/adapter-config-surface-2026-10-03.md section 5 copilot-cli (GitHub Copilot CLI docs, 2026-10-03)"
	copilotCLIUnverNt = "Named by the 2026-10-03 audit from GitHub's Copilot CLI docs; not found on the pages re-fetched 2026-10-04."
)

// Scope sets. The audit records that repo / local files honour only a
// whitelist (model, effortLevel, contextTier, deniedUrls, disabledMcpServers,
// disabledSkills, disableAllHooks, hooks, enabledPlugins, includeCoAuthoredBy,
// respectGitignore); the managed file accepts only the managed key set.
var (
	copilotCLIUser        = []Scope{ScopeUser}
	copilotCLIUserRepo    = []Scope{ScopeUser, ScopeProjectShared, ScopeProjectLocal}
	copilotCLIUserManaged = []Scope{ScopeUser, ScopeManaged}
	copilotCLIManaged     = []Scope{ScopeManaged}
)

var copilotCLIFiles = []FileRow{
	{
		ID: "copilot-cli/managed-settings", Tool: "copilot-cli", Shape: "copilot-cli/settings", Kind: KindSettings, Scope: ScopeManaged,
		Paths: OSPaths{
			Linux:   "/etc/github-copilot/managed-settings.json",
			Darwin:  "/Library/Application Support/GitHubCopilot/managed-settings.json",
			Windows: `%ProgramFiles%\GitHubCopilot\managed-settings.json`,
		},
		Format: FormatJSON, Precedence: 15, WriteNeeds: PrivAdminRoot, Grounding: doc(copilotCLIMgdRef),
		Note: "MDM baseline: applied below user settings, except permissions.disableBypassPermissionsMode \"disable\", managed permission rules, " +
			"sandbox (a floor), a locked autoTier and shellShortcut, which win. POSIX files must be root-owned, not symlinks, not world-writable. " +
			"Also the macOS plist domain com.github.copilot and HKLM\\SOFTWARE\\Policies\\GitHubCopilot; server-managed settings fill gaps. " +
			"Only the documented managed keys apply here; hooks and disableAllHooks are not among them (GitHub's managed-settings reference and deploy guide, re-fetched 2026-10-30), " +
			"and Copilot CLI 1.0.105 ignored disableAllHooks in a root-owned /Library/Application Support/GitHubCopilot/managed-settings.json (MAC-6, 2026-10-30, FU-196): Observer's hooks still ran. " +
			"So this file cannot switch Copilot CLI hooks off; it says nothing against the file itself, which the CLI opens on Linux (T-547 strace).",
	},
	{
		ID: "copilot-cli/user-settings", Tool: "copilot-cli", Shape: "copilot-cli/settings", Kind: KindSettings, Scope: ScopeUser,
		Paths: samePath("~/.copilot/settings.json"), Format: FormatJSONC, Precedence: 20, WriteNeeds: PrivUser,
		Grounding: doc(copilotCLIRef), Note: "COPILOT_HOME relocates ~/.copilot. Not yet written on node 1 (2026-10-03).",
	},
	{
		ID: "copilot-cli/repo-settings", Tool: "copilot-cli", Shape: "copilot-cli/settings", Kind: KindSettings, Scope: ScopeProjectShared,
		Paths: samePath("<project>/.github/copilot/settings.json"), Format: FormatJSONC, Precedence: 30, WriteNeeds: PrivUser,
		Grounding: doc(copilotCLIRef),
		Note: "Per the audit only a whitelist applies here (model / effortLevel / contextTier only in a trusted cwd; deny lists union-add; " +
			"respectGitignore tighten-only); the 2026-10-04 reference table lists User, Repo, Local for every key. The CLI also reads the " +
			"cross-tool subset of .claude/settings(.local).json.",
	},
	{
		ID: "copilot-cli/local-settings", Tool: "copilot-cli", Shape: "copilot-cli/settings", Kind: KindSettings, Scope: ScopeProjectLocal,
		Paths: samePath("<project>/.github/copilot/settings.local.json"), Format: FormatJSONC, Precedence: 40, WriteNeeds: PrivUser,
		Grounding: doc(copilotCLIRef), Note: "Same key whitelist as the repo file.",
	},
	{
		ID: "copilot-cli/user-mcp", Tool: "copilot-cli", Shape: "copilot-cli/mcp", Kind: KindMCP, Scope: ScopeUser,
		Paths: samePath("~/.copilot/mcp-config.json"), Format: FormatJSON, Precedence: 20, WriteNeeds: PrivUser,
		Grounding: doc(copilotCLIMCPRef),
	},
	{
		ID: "copilot-cli/project-mcp", Tool: "copilot-cli", Shape: "copilot-cli/mcp", Kind: KindMCP, Scope: ScopeProjectShared,
		Paths: samePath("<project>/.mcp.json"), Format: FormatJSON, Precedence: 30, WriteNeeds: PrivUser,
		Grounding: doc(copilotCLIRef), Note: "Wins over the user file on a name clash. The same file is Claude Code's project MCP file.",
	},
	{
		ID: "copilot-cli/project-github-mcp", Tool: "copilot-cli", Shape: "copilot-cli/mcp", Kind: KindMCP, Scope: ScopeProjectShared,
		Paths: samePath("<project>/.github/mcp.json"), Format: FormatJSON, Precedence: 30, WriteNeeds: PrivUser,
		Grounding: doc(copilotCLIRef), Note: "Wins over the user file on a name clash.",
	},
	{
		ID: "copilot-cli/providers", Tool: "copilot-cli", Shape: "copilot-cli/providers", Kind: KindSettings, Scope: ScopeUser,
		Paths: samePath("~/.copilot/providers.json"), Format: FormatJSON, Precedence: 20, WriteNeeds: PrivNever,
		Grounding: doc(copilotCLIRef),
		Note: "BYOK provider and model registry (COPILOT_PROVIDERS_CONFIG relocates it). Never written: it may carry provider credentials. " +
			"Observer's copilot-cli launcher routes through the COPILOT_PROVIDER_BASE_URL environment variable, not this file.",
	},
	{
		ID: "copilot-cli/lsp-config", Tool: "copilot-cli", Shape: "copilot-cli/lsp-config", Kind: KindSettings, Scope: ScopeUser,
		Paths: samePath("~/.copilot/lsp-config.json"), Format: FormatJSON, Precedence: 20, WriteNeeds: PrivUser,
		Grounding: doc(copilotCLIRef), Note: "User-level LSP server definitions; keys not catalogued (raw editor only).",
	},
	{
		ID: "copilot-cli/app-state", Tool: "copilot-cli", Shape: "copilot-cli/app-state", Kind: KindToolState, Scope: ScopeUser,
		Paths: samePath("~/.copilot/config.json"), Format: FormatJSON, Precedence: 0, WriteNeeds: PrivNever,
		Grounding: live("~/.copilot/config.json present (auth state, not opened)"),
		Note:      "Automatically managed: authentication, plugin state, internal data. Never read or written.",
	},
	{
		ID: "copilot-cli/permissions-state", Tool: "copilot-cli", Shape: "copilot-cli/permissions-state", Kind: KindToolState, Scope: ScopeUser,
		Paths: samePath("~/.copilot/permissions-config.json"), Format: FormatJSON, Precedence: 0, WriteNeeds: PrivNever,
		Grounding: doc(copilotCLIRef), Note: "Saved tool and directory approvals per project, written by the CLI.",
	},
}

func copilotCLIRows(rows []SettingRow) []SettingRow {
	for i := range rows {
		r := &rows[i]
		r.Tool = "copilot-cli"
		r.ID = r.Tool + "/" + r.Path.String()
		if r.FileID == "" {
			r.FileID = "copilot-cli/settings"
		}
		if r.Owner == "" {
			r.Owner = OwnerUser
		}
		if r.Verified == "" {
			r.Verified = VerifiedDoc
		}
		if r.Source == "" {
			r.Source = copilotCLIRef
		}
	}
	return rows
}

var copilotCLISettings = copilotCLIRows([]SettingRow{
	// --- model and reasoning
	{
		Path: KeyPath{"model"}, Type: TypeString, Desc: "Model to use; \"auto\" lets Auto routing choose.",
		Note: "Repo / local values apply only when the cwd is trusted; .github/allowed_models.txt may restrict the choice. Managed may wrap it as {\"overridable\": ...}.",
	},
	{
		Path: KeyPath{"autoTier"}, Scopes: copilotCLIUserManaged, Type: TypeEnum, Enum: []string{"efficiency", "balance", "intelligence"},
		Desc: "Default Auto routing tier for sessions on model auto.",
		Note: "A bare managed string locks the tier; {\"overridable\": TIER} sets a default. The managed page also lists \"unmanaged\".",
	},
	{
		Path: KeyPath{"effortLevel"}, Type: TypeEnum, Enum: []string{"low", "medium", "high", "xhigh"}, Default: "\"medium\"",
		Desc: "Reasoning effort for extended thinking.",
	},
	{
		Path: KeyPath{"contextTier"}, Type: TypeEnum, Enum: []string{"default", "long_context"}, Desc: "Context tier (a tier, not a token count).",
		Source: copilotCLIAudit, Verified: VerifiedUnverified, Note: copilotCLIUnverNt,
	},
	{
		Path: KeyPath{"continueOnAutoMode"}, Scopes: copilotCLIUser, Type: TypeBool, Default: "false",
		Desc: "Switch to auto mode automatically when rate-limited.", Danger: DangerConfirm, Note: "Dangerous: true.",
	},
	{
		Path: KeyPath{"stayInAutopilot"}, Scopes: copilotCLIUser, Type: TypeBool, Desc: "Keep autopilot on across turns.",
		Source: copilotCLIAudit, Verified: VerifiedUnverified, Danger: DangerConfirm, Note: copilotCLIUnverNt,
	},
	{
		Path: KeyPath{"subagents"}, Scopes: copilotCLIUser, Type: TypeObject,
		Desc:   "Subagent settings: agents.<name>.model (+ modelPolicy preferred / required), disabledSubagents.",
		Source: copilotCLIAudit, Verified: VerifiedUnverified, Note: copilotCLIUnverNt,
	},

	// --- permissions (managed rules; user-side approvals live in permissions-config.json)
	{
		Path: KeyPath{"permissions", "disableBypassPermissionsMode"}, Scopes: copilotCLIUserManaged, Type: TypeEnum, Enum: []string{"disable", "allow-auto-only"},
		Desc: "Suppress or restrict the allow-all permission flags.", Danger: DangerConfirm,
		Note: "Dangerous: unset leaves --allow-all / --yolo available. A managed \"disable\" always wins.",
	},
	{
		Path: KeyPath{"permissions", "allow"}, Scopes: copilotCLIManaged, Type: TypeRuleList, Source: copilotCLIMgdRef,
		Desc:   "Managed rules that run without a prompt: Shell(...) / Bash(...) / PowerShell(...), Read(...), Edit(...) / Write(...), Domain(...).",
		Danger: DangerConfirm, Note: "Dangerous: broad rules.",
	},
	{Path: KeyPath{"permissions", "ask"}, Scopes: copilotCLIManaged, Type: TypeRuleList, Source: copilotCLIMgdRef, Desc: "Managed rules that always need a fresh approval."},
	{
		Path: KeyPath{"permissions", "deny"}, Scopes: copilotCLIManaged, Type: TypeRuleList, Source: copilotCLIMgdRef,
		Desc: "Managed rules that never run; deny beats ask beats allow.",
	},
	{
		Path: KeyPath{"allowedUrls"}, Scopes: copilotCLIUser, Type: TypeStringList, Default: "[]", Desc: "URLs or domains fetched without asking.",
		Danger: DangerConfirm, Note: "Dangerous: broad wildcards.",
	},
	{Path: KeyPath{"deniedUrls"}, Scopes: copilotCLIUserRepo, Type: TypeStringList, Default: "[]", Desc: "URLs or domains always denied (wins over allowedUrls)."},
	{Path: KeyPath{"askUser"}, Scopes: copilotCLIUser, Type: TypeBool, Default: "true", Desc: "Let the agent ask clarifying questions."},

	// --- sandbox (managed values are a floor)
	{
		Path: KeyPath{"sandbox", "enabled"}, Scopes: copilotCLIUserManaged, Type: TypeBool, Default: "false",
		Desc: "Run commands and servers in the sandbox.", Danger: DangerConfirm, Note: "Dangerous: false.",
	},
	{
		Path: KeyPath{"sandbox", "allowBypass"}, Scopes: copilotCLIUserManaged, Type: TypeBool, Default: "true",
		Desc: "Let a sandboxed command request a bypass.", Danger: DangerConfirm, Note: "Dangerous: true.",
	},
	{Path: KeyPath{"sandbox", "failIfUnavailable"}, Scopes: copilotCLIManaged, Type: TypeBool, Desc: "Fail when the sandbox is unavailable (admin-only)."},
	{Path: KeyPath{"sandbox", "auth", "git"}, Scopes: copilotCLIUserManaged, Type: TypeBool, Default: "true", Desc: "Inject Git credentials into the sandbox."},
	{Path: KeyPath{"sandbox", "auth", "gh"}, Scopes: copilotCLIUserManaged, Type: TypeBool, Default: "true", Desc: "Inject GitHub CLI credentials into the sandbox."},
	{
		Path: KeyPath{"sandbox", "userPolicy", "network", "allowLocalNetwork"}, Scopes: copilotCLIUserManaged, Type: TypeBool, Default: "true",
		Desc: "Local network access inside the sandbox.",
	},
	{
		Path: KeyPath{"sandbox", "userPolicy", "network", "allowedHosts"}, Scopes: copilotCLIUserManaged, Type: TypeStringList, Default: "[]",
		Desc: "Hosts the sandbox may reach.", Danger: DangerConfirm, Note: "Dangerous: [\"*\"].",
	},
	{Path: KeyPath{"sandbox", "userPolicy", "network", "blockedHosts"}, Scopes: copilotCLIUserManaged, Type: TypeStringList, Default: "[]", Desc: "Hosts the sandbox may not reach."},
	{
		Path: KeyPath{"sandbox", "userPolicy", "network", "proxy"}, Scopes: copilotCLIUserManaged, Type: TypeObject,
		Desc: "HTTP proxy for sandbox traffic: {url, username, password}.", Secret: true, Note: "Carries a proxy password: the secret posture applies.",
	},
	{Path: KeyPath{"sandbox", "userPolicy", "deniedPaths"}, Scopes: copilotCLIUserManaged, Type: TypeStringList, Default: "[]", Desc: "Absolute paths the sandbox may not access."},

	// --- MCP, plugins, skills
	{
		FileID: "copilot-cli/mcp", Path: KeyPath{"mcpServers"}, Type: TypeMCPMap, Source: copilotCLIMCPRef,
		Desc: "MCP servers by name: {type: local | stdio | http | sse, command, args, env, url, headers, tools}.",
	},
	{
		Path: KeyPath{"disabledMcpServers"}, Scopes: copilotCLIUserRepo, Type: TypeStringList, Default: "[]", Desc: "Configured MCP servers that are not started.",
		Danger: DangerConfirm, Note: "Naming a server Observer depends on stops it.",
	},
	{Path: KeyPath{"enabledMcpServers"}, Scopes: copilotCLIUser, Type: TypeStringList, Default: "[]", Desc: "Built-in MCP servers to enable."},
	{
		Path: KeyPath{"allowedMcpServers"}, Scopes: copilotCLIManaged, Type: TypeObject, Source: copilotCLIMgdRef,
		Desc: "Managed allowlist of MCP servers (an array matched by serverUrl, serverCommand or serverName).",
	},
	{
		Path: KeyPath{"deniedMcpServers"}, Scopes: copilotCLIManaged, Type: TypeObject, Source: copilotCLIMgdRef,
		Desc: "Managed denylist of MCP servers (an array); deny always wins.", Danger: DangerConfirm, Note: "Naming a server Observer depends on blocks it.",
	},
	{Path: KeyPath{"enabledPlugins"}, Type: TypeObject, Default: "{}", Desc: "Plugin specs mapped to true / false (declarative install)."},
	{Path: KeyPath{"extraKnownMarketplaces"}, Scopes: copilotCLIUserManaged, Type: TypeObject, Default: "{}", Desc: "Additional plugin marketplaces."},
	{Path: KeyPath{"strictKnownMarketplaces"}, Scopes: copilotCLIManaged, Type: TypeObject, Source: copilotCLIMgdRef, Desc: "Restrict plugins to the listed marketplaces (an array)."},
	{Path: KeyPath{"disabledSkills"}, Scopes: copilotCLIUserRepo, Type: TypeStringList, Default: "[]", Desc: "Skills discovered but not loaded."},
	{Path: KeyPath{"ignoredSkillsLocations"}, Scopes: copilotCLIUser, Type: TypeStringList, Default: "[]", Desc: "Skill directories excluded from discovery."},
	{
		Path: KeyPath{"skillDirectories"}, Scopes: copilotCLIUser, Type: TypeStringList, Desc: "Extra skill directories.",
		Source: copilotCLIAudit, Verified: VerifiedUnverified, Note: copilotCLIUnverNt,
	},
	{Path: KeyPath{"dynamicRetrieval"}, Scopes: copilotCLIUser, Type: TypeObject, Desc: "Per-category embeddings retrieval ({skills: bool})."},
	{Path: KeyPath{"customAgents", "defaultLocalOnly"}, Scopes: copilotCLIUser, Type: TypeBool, Default: "false", Desc: "Use only local custom agents."},
	{Path: KeyPath{"builtInAgents", "rubberDuck"}, Scopes: copilotCLIUser, Type: TypeBool, Default: "true", Desc: "Rubber-duck feedback agent."},
	{Path: KeyPath{"builtInAgents", "rubberDuckAutoInvoke"}, Scopes: copilotCLIUser, Type: TypeBool, Default: "false", Desc: "Proactive rubber-duck invocation."},
	{Path: KeyPath{"connectors"}, Scopes: copilotCLIUser, Type: TypeBool, Default: "true", Desc: "Copilot Connectors when available."},

	// --- hooks
	{
		Path: KeyPath{"hooks"}, Scopes: copilotCLIUserRepo, Type: TypeObject, Desc: "Inline hook definitions keyed by event (camelCase or PascalCase names).",
		Note: "Repo hooks merge with user hooks.",
	},
	{
		// FU-159: listed in the repo and user settings whitelists, but on
		// Copilot CLI 1.0.105 true in ~/.copilot/settings.json or the repo
		// .github/copilot/settings.json left ~/.copilot/hooks running
		// (Windows rig run 2026-10-29; also seen on macOS, Mac round 5 A7).
		// So nothing here claims it stops Observer's hooks: no editor
		// refusal and no effective-layer family; its internal/hookdisable
		// rows are write-guard-only (R-162 / R-163 still refuse an agent
		// write that sets it, nothing reports it as turning hooks off).
		Path: KeyPath{"disableAllHooks"}, Scopes: copilotCLIUserRepo, Type: TypeBool, Default: "false", Desc: "Documented as disabling every hook (repo and user).",
		Verified: VerifiedUnverified,
		Note:     "Not honoured by Copilot CLI 1.0.105 for hooks (live 2026-10-29): with true in ~/.copilot/settings.json or the repo .github/copilot/settings.json, the hooks in ~/.copilot/hooks (Observer's included) still ran; ~/.copilot/config.json was not tested. Not a managed key either: true in a root-owned managed-settings.json was ignored by 1.0.105 on macOS (MAC-6, FU-196), matching GitHub's managed key list, which has no hooks key. A .claude/settings.json disableAllHooks is Claude Code's own switch, which the Copilot CLI runtime reads for a repository's Claude hooks.",
	},

	// --- updates, telemetry-adjacent, remote
	{Path: KeyPath{"autoUpdate"}, Scopes: copilotCLIUser, Type: TypeBool, Default: "true", Desc: "Download CLI and plugin updates automatically."},
	{Path: KeyPath{"autoUpdatesChannel"}, Scopes: copilotCLIUser, Type: TypeEnum, Enum: []string{"stable", "prerelease"}, Default: "\"stable\"", Desc: "Update channel."},
	{
		Path: KeyPath{"remote"}, Scopes: copilotCLIUser, Type: TypeEnum, Enum: []string{"on", "off"}, Default: "\"on\"",
		Desc: "Session syncing and remote access.", Danger: DangerConfirm, Note: "\"on\" syncs sessions off the device.",
	},
	{Path: KeyPath{"remoteExport"}, Scopes: copilotCLIUser, Type: TypeBool, Default: "true", Desc: "Export sessions remotely when available."},
	{Path: KeyPath{"remoteControl"}, Scopes: copilotCLIManaged, Type: TypeObject, Source: copilotCLIMgdRef, Desc: "Restrict remote session control."},
	{Path: KeyPath{"telemetry"}, Scopes: copilotCLIManaged, Type: TypeObject, Source: copilotCLIMgdRef, Desc: "OpenTelemetry export configuration."},
	{Path: KeyPath{"features", "computerUse"}, Scopes: copilotCLIManaged, Type: TypeBool, Source: copilotCLIMgdRef, Desc: "Computer use capability."},
	{
		Path: KeyPath{"policyHelper"}, Scopes: copilotCLIManaged, Type: TypeObject, Source: copilotCLICfgMgd,
		Desc: "Executable that supplies the lowest managed layer: {path, args, timeoutMs, refreshIntervalMs}.", Danger: DangerConfirm,
		Note: "Runs an arbitrary executable.",
	},
	{Path: KeyPath{"shellShortcut"}, Scopes: copilotCLIUserManaged, Type: TypeBool, Source: copilotCLICfgMgd, Desc: "The $ interactive shell shortcut; a managed value always wins."},
	{
		Path: KeyPath{"forceLoginOrgs"}, Scopes: copilotCLIManaged, Type: TypeStringList, Desc: "Organizations the user must sign in to.",
		Source: copilotCLIAudit, Verified: VerifiedUnverified, Note: copilotCLIUnverNt,
	},
	{
		Path: KeyPath{"forceRemoteSettingsRefresh"}, Scopes: copilotCLIManaged, Type: TypeBool, Desc: "Force a server-managed settings refresh.",
		Source: copilotCLIAudit, Verified: VerifiedUnverified, Note: copilotCLIUnverNt,
	},
	{Path: KeyPath{"proxyUrl"}, Scopes: copilotCLIUser, Type: TypeString, Desc: "HTTP(S) proxy URL (HTTP_PROXY / HTTPS_PROXY override it); not a provider base URL."},
	{Path: KeyPath{"proxyKerberosServicePrincipal"}, Scopes: copilotCLIUser, Type: TypeString, Desc: "Kerberos SPN for proxy authentication."},
	{
		Path: KeyPath{"streamerMode"}, Scopes: copilotCLIUser, Type: TypeBool, Desc: "Hide sensitive details on screen.",
		Source: copilotCLIAudit, Verified: VerifiedUnverified, Note: copilotCLIUnverNt,
	},

	// --- shell, git, UI
	{Path: KeyPath{"bashEnv"}, Scopes: copilotCLIUser, Type: TypeBool, Default: "false", Desc: "BASH_ENV support for bash shells (the only env-like knob)."},
	{Path: KeyPath{"powershellFlags"}, Scopes: copilotCLIUser, Type: TypeStringList, Default: "[\"-NoProfile\",\"-NoLogo\"]", Desc: "Flags passed to PowerShell (Windows)."},
	{Path: KeyPath{"includeCoAuthoredBy"}, Scopes: copilotCLIUserRepo, Type: TypeBool, Default: "true", Desc: "Add a Co-authored-by trailer to commits."},
	{Path: KeyPath{"mergeStrategy"}, Scopes: copilotCLIUser, Type: TypeEnum, Enum: []string{"rebase", "merge"}, Desc: "Conflict resolution strategy for PR fixes."},
	{Path: KeyPath{"respectGitignore"}, Scopes: copilotCLIUserRepo, Type: TypeBool, Default: "true", Desc: "Exclude gitignored files from the mention picker.", Note: "Repo / local may only tighten it."},
	{Path: KeyPath{"companyAnnouncements"}, Scopes: copilotCLIUser, Type: TypeStringList, Default: "[]", Desc: "Messages shown at random on startup."},
	{Path: KeyPath{"experimental"}, Scopes: copilotCLIUser, Type: TypeBool, Default: "false", Desc: "Experimental features."},
	{
		Path: KeyPath{"logLevel"}, Scopes: copilotCLIUser, Type: TypeEnum, Enum: []string{"none", "error", "warning", "info", "debug", "all", "default"},
		Default: "\"default\"", Desc: "Logging verbosity.",
	},
	{
		Path: KeyPath{"theme"}, Scopes: copilotCLIUser, Type: TypeString, Enum: []string{"default", "github", "dim", "high-contrast", "colorblind"},
		Desc: "Visual theme.", Source: copilotCLIAudit, Note: "Value set from the audit; the 2026-10-04 table says only \"theme names\".",
	},
	{
		Path: KeyPath{"colorMode"}, Scopes: copilotCLIUser, Type: TypeEnum, Enum: []string{"default", "github", "dim", "high-contrast", "colorblind"},
		Default: "\"github\"", Desc: "Deprecated alias of theme.", Deprecated: true,
	},
	{Path: KeyPath{"banner"}, Scopes: copilotCLIUser, Type: TypeEnum, Enum: []string{"always", "once", "never"}, Default: "\"once\"", Desc: "Animated banner frequency."},
	{Path: KeyPath{"beep"}, Scopes: copilotCLIUser, Type: TypeBool, Default: "true", Desc: "Beep when attention is needed."},
	{Path: KeyPath{"beepOnSchedule"}, Scopes: copilotCLIUser, Type: TypeBool, Default: "true", Desc: "Beep when a scheduled run finishes."},
	{Path: KeyPath{"commandHistoryMaxSize"}, Scopes: copilotCLIUser, Type: TypeInt, Min: f64(1), Max: f64(1000), Default: "50", Desc: "Recent commands kept in history."},
	{Path: KeyPath{"compactPaste"}, Scopes: copilotCLIUser, Type: TypeBool, Default: "true", Desc: "Collapse large pastes into compact tokens."},
	{Path: KeyPath{"copyOnSelect"}, Scopes: copilotCLIUser, Type: TypeBool, Desc: "Copy mouse-selected text (default true on macOS, false elsewhere)."},
	{Path: KeyPath{"editorMode"}, Scopes: copilotCLIUser, Type: TypeEnum, Enum: []string{"normal", "vim"}, Default: "\"normal\"", Desc: "Composer editing mode."},
	{Path: KeyPath{"footer"}, Scopes: copilotCLIUser, Type: TypeObject, Desc: "Status line items (showModelEffort, showDirectory, showBranch and other booleans)."},
	{Path: KeyPath{"ide", "autoConnect"}, Scopes: copilotCLIUser, Type: TypeBool, Default: "true", Desc: "Connect to the IDE on startup."},
	{Path: KeyPath{"ide", "openDiffOnEdit"}, Scopes: copilotCLIUser, Type: TypeBool, Default: "true", Desc: "Open edit diffs in the IDE for approval."},
	{Path: KeyPath{"keepAlive"}, Scopes: copilotCLIUser, Type: TypeEnum, Enum: []string{"on", "off", "busy"}, Default: "\"off\"", Desc: "Prevent system sleep while the CLI runs."},
	{Path: KeyPath{"mouse"}, Scopes: copilotCLIUser, Type: TypeBool, Default: "true", Desc: "Mouse support."},
	{Path: KeyPath{"pinnedPrompts"}, Scopes: copilotCLIUser, Type: TypeBool, Default: "true", Desc: "Pin the current prompt below the top bar."},
	{Path: KeyPath{"renderHexColors"}, Scopes: copilotCLIUser, Type: TypeBool, Default: "true", Desc: "Show hex colors as swatches."},
	{Path: KeyPath{"renderMarkdown"}, Scopes: copilotCLIUser, Type: TypeBool, Default: "true", Desc: "Render Markdown in terminal output."},

	// --- providers.json (never written)
	{
		FileID: "copilot-cli/providers", Path: KeyPath{"providers"}, Type: TypeObject,
		Desc: "BYOK providers (an array); each entry may set a base URL.", Danger: DangerConfirm,
		Note: "Dangerous: a provider base URL reroutes traffic around Observer. The file is never written by the editor.",
	},
	{FileID: "copilot-cli/providers", Path: KeyPath{"models"}, Type: TypeObject, Desc: "BYOK model registry."},

	// --- auto-managed state
	{
		FileID: "copilot-cli/app-state", Path: KeyPath{"storeTokenPlaintext"}, Type: TypeBool, Owner: OwnerToolState,
		Desc: "Store the auth token in plaintext instead of the keychain.", Source: copilotCLIAudit, Verified: VerifiedUnverified, Danger: DangerConfirm,
		Note: "Dangerous: true. " + copilotCLIUnverNt,
	},
	{
		FileID: "copilot-cli/permissions-state", Path: KeyPath{"locations"}, Type: TypeObject, Owner: OwnerToolState,
		Desc: "Saved approvals per absolute path: tool_approvals (commands, read, write, mcp) and allowed_directories.", Source: copilotCLIAudit,
	},
})

// copilotCLIMCPShape: mcpServers.<name> with an explicit type. The CLI also
// accepts "local" for a stdio server; it reads back as tool-specific.
var copilotCLIMCPShape = MCPShape{
	EnvKey: "env", TypeKey: "type", StdioTypeExplicit: true,
	TypeNames: map[string]string{"stdio": "stdio", "http": "http", "sse": "sse"},
	URLKeys:   map[string]string{"http": "url", "sse": "url"},
}

var copilotCLIMap = []MapRow{
	{Key: KeyModel, Tool: "copilot-cli", Settings: []string{"copilot-cli/model"}, Transform: TransformModelAlias, Source: copilotCLIRef},
	{
		Key: KeyReasoningEffort, Tool: "copilot-cli", Settings: []string{"copilot-cli/effortLevel"}, Transform: TransformEnumMap,
		Params: TransformParams{Enum: []EnumPair{{"low", []any{"low"}}, {"medium", []any{"medium"}}, {"high", []any{"high"}}, {"xhigh", []any{"xhigh"}}}},
		Source: copilotCLIRef, Note: "none, minimal and max are refused.",
	},
	{Key: KeyAutoUpdate, Tool: "copilot-cli", Settings: []string{"copilot-cli/autoUpdate"}, Transform: TransformIdentity, Source: copilotCLIRef},
	{
		Key: KeySandboxMode, Tool: "copilot-cli", Settings: []string{"copilot-cli/sandbox.enabled"}, Transform: TransformEnumMap,
		Params: TransformParams{Enum: []EnumPair{{"workspace_write", []any{true}}, {"off", []any{false}}}}, Source: copilotCLIRef,
		Note: "read_only is refused. A managed sandbox is a floor the user cannot relax.",
	},
	{
		Key: KeyMCPServers, Tool: "copilot-cli", Settings: []string{"copilot-cli/mcpServers"}, Transform: TransformMCPShape,
		Params: TransformParams{MCP: copilotCLIMCPShape}, Lossy: true, Source: copilotCLIMCPRef,
		Note: "An entry typed \"local\" reads back as tool-specific; tools and headers are not carried. " + mcpLossyNote,
	},
}

var copilotCLICatalog = toolCatalog{
	Tool: "copilot-cli",
	VerifiedAgainst: "GitHub Copilot CLI config-dir reference, enterprise managed settings and MCP pages fetched 2026-10-04 (audit section 5); " +
		"node 1 (2026-10-03) had only ~/.copilot/config.json (auth state, not opened), no settings.json.",
	Files: copilotCLIFiles,
	Extra: copilotCLISettings,
	Map:   copilotCLIMap,
}
