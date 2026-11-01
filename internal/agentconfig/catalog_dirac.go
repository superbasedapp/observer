package agentconfig

// Dirac (Cline fork; CLI `dirac`, `--acp`, VS Code extension
// dirac-run.dirac), doc-authored (surface-gap lane w4-catalog). Sources:
// location matrix Part 7 section 7 (dirac-run/dirac master
// src/shared/storage/{storage-context,state-keys}.ts,
// src/core/storage/{paths,directoryEnsurers,hooksStorage,
// remoteConfigCache}.ts, src/core/hooks/HookLaunchConfig.ts and
// cli/man/dirac.1.md) and docs/dirac-adapter.md.
//
// Like Cline, settings are extension / CLI managed state in
// globalState.json (read-only rows here); provider keys sit in secrets.json
// beside it, which is never read. Hooks are file-per-event executables, not
// a config key: the search order is --hooks-dir (root command only), then
// the global ~/.dirac/Hooks, then each workspace root's .diracrules/hooks.
// No MCP client config was found (likely none, not proven).
const (
	diracStateRef   = "https://raw.githubusercontent.com/dirac-run/dirac/master/src/shared/storage/state-keys.ts"
	diracStorageRef = "https://raw.githubusercontent.com/dirac-run/dirac/master/src/shared/storage/storage-context.ts"
	diracPathsRef   = "https://raw.githubusercontent.com/dirac-run/dirac/master/src/core/storage/paths.ts"
	diracHooksRef   = "https://raw.githubusercontent.com/dirac-run/dirac/master/src/core/storage/hooksStorage.ts"
	diracRemoteRef  = "https://raw.githubusercontent.com/dirac-run/dirac/master/src/core/storage/remoteConfigCache.ts"
	diracStateNote  = "Dirac-managed state (set through the Dirac UI or `dirac auth`); the editor never writes it."
	diracState      = "dirac/global-state"
)

var diracFiles = []FileRow{
	{
		ID: "dirac/global-state", Tool: "dirac", Shape: diracState, Kind: KindToolState, Scope: ScopeUser,
		Paths: samePath("~/.dirac/data/globalState.json"), Format: FormatJSON, Precedence: 0, WriteNeeds: PrivNever,
		Grounding: waveSource(diracStorageRef),
		Note: "Provider, model, base-URL and hook settings (Windows C:\\Users\\<u>\\.dirac, not %APPDATA%). DIRAC_DIR (or --config for one run) relocates it; " +
			"DIRAC_DATA_DIR moves only the CLI data and log location (relocate.go). Shown, never form-edited.",
	},
	{
		ID: "dirac/secrets", Tool: "dirac", Shape: "dirac/secrets", Kind: KindToolState, Scope: ScopeUser,
		Paths: samePath("~/.dirac/data/secrets.json"), Format: FormatJSON, Precedence: 0, WriteNeeds: PrivNever,
		Grounding: waveAdapterDoc("docs/dirac-adapter.md (Store layout)"),
		Note:      "Provider API keys and the ChatGPT subscription OAuth tokens (mode 0600): never read or written.",
	},
	{
		ID: "dirac/workspace-state", Tool: "dirac", Shape: "dirac/workspace-state", Kind: KindToolState, Scope: ScopeUser,
		Paths: samePath("~/.dirac/data/workspaces/"), Format: FormatJSON, Precedence: 0, WriteNeeds: PrivNever,
		Grounding: waveSource(diracStorageRef), Note: "Per-workspace state (workspaces/<hash>/). Written by Dirac.",
	},
	{
		ID: "dirac/remote-config-cache", Tool: "dirac", Shape: "dirac/remote-config-cache", Kind: KindToolState, Scope: ScopeUser,
		Paths: samePath("~/.dirac/data/cache/"), Format: FormatJSON, Precedence: 0, WriteNeeds: PrivNever,
		Grounding: waveSource(diracRemoteRef),
		Note:      "Org remote config cache (remote_config_<orgId>.json); opt out with optOutOfRemoteConfig. Whether it can set hooksEnabled is unverified.",
	},
	{
		ID: "dirac/global-hooks", Tool: "dirac", Shape: "dirac/global-hooks", Kind: KindHooks, Scope: ScopeUser,
		Paths: samePath("~/.dirac/Hooks/"), Format: FormatScript, Precedence: 20, WriteNeeds: PrivUser,
		Grounding: waveSource(diracPathsRef),
		Note: "One executable per event (<Event>; <Event>.ps1 on Windows, run by powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -File). " +
			"Built on the OS home alone (getDiracHomePath): DIRAC_DIR does NOT move it (source-grounded, live check 32 open). " +
			"Observer's PreToolUse and UserPromptSubmit scripts live here (internal/hook/register_wave1021.go); a user's own scripts are theirs.",
	},
	{
		ID: "dirac/workspace-hooks", Tool: "dirac", Shape: "dirac/global-hooks", Kind: KindHooks, Scope: ScopeProjectShared,
		Paths: samePath("<project>/.diracrules/hooks/"), Format: FormatScript, Precedence: 30, WriteNeeds: PrivUser,
		Grounding: waveSource(diracHooksRef), Note: "Each workspace root's hooks, scanned after the global folder; --hooks-dir adds one more for the root command.",
	},
}

func diracStateRows(rows []SettingRow) []SettingRow {
	rows = waveRows("dirac", diracState, diracStateRef, rows)
	for i := range rows {
		r := &rows[i]
		if r.Owner == OwnerUser {
			r.Owner = OwnerToolState
		}
		if r.Note == "" {
			r.Note = diracStateNote
		}
	}
	return rows
}

var diracSettings = diracStateRows([]SettingRow{
	{
		Path: KeyPath{"hooksEnabled"}, Type: TypeBool, Default: "true", Desc: "Run Dirac hooks.", Danger: DangerRefuseWhileIntegrated,
		Note: diracStateNote + " false switches Observer's hook scripts off (internal/hookdisable row dirac.hooksEnabled).",
	},
	{Path: KeyPath{"actModeApiProvider"}, Type: TypeString, Desc: "Provider used in Act mode.", Note: diracStateNote + " DIRAC_PROVIDER picks it from the environment."},
	{
		Path: KeyPath{"openAiBaseUrl"}, Type: TypeString, Desc: "OpenAI-compatible provider base URL.", Danger: DangerConfirm,
		Note: diracStateNote + " Base URL override; `dirac auth --provider ... --baseurl ...` persists it, DIRAC_BASE_URL and OPENAI_API_BASE set it from the environment.",
	},
	{Path: KeyPath{"anthropicBaseUrl"}, Type: TypeString, Desc: "Anthropic provider base URL.", Danger: DangerConfirm, Note: diracStateNote + " Base URL override."},
	{Path: KeyPath{"geminiBaseUrl"}, Type: TypeString, Desc: "Gemini provider base URL.", Danger: DangerConfirm, Note: diracStateNote + " Base URL override."},
	{Path: KeyPath{"liteLlmBaseUrl"}, Type: TypeString, Desc: "LiteLLM base URL.", Danger: DangerConfirm, Note: diracStateNote + " Base URL override."},
	{
		Path: KeyPath{"optOutOfRemoteConfig"}, Type: TypeBool, Source: diracRemoteRef,
		Desc: "Opt out of the organization's remote configuration.",
	},
})

var diracCatalog = toolCatalog{
	Tool: "dirac",
	VerifiedAgainst: "dirac-run/dirac master storage-context.ts, state-keys.ts, paths.ts, directoryEnsurers.ts, hooksStorage.ts, remoteConfigCache.ts and cli/man/dirac.1.md " +
		"(location matrix Part 7 section 7, 2026-10-25) plus docs/dirac-adapter.md (0.5.22); settings are Dirac-managed state (read-only rows).",
	Files: diracFiles,
	Extra: diracSettings,
}
