package agentconfig

import (
	"sort"
	"strings"
	"sync"

	"github.com/marmutapp/superbased-observer/internal/guidance"
)

// Grounding shorthands. Vendor facts were fetched 2026-10-03 (audit
// docs/audits/adapter-config-surface-2026-10-03.md section 5, which cites
// every URL); "node 1" is the read-only live probe of audit section 6.
const auditDate = "2026-10-03"

func doc(url string) Grounding { return Grounding{Kind: GroundDoc, Source: url, Date: auditDate} }
func live(what string) Grounding {
	return Grounding{Kind: GroundLive, Source: "node 1: " + what, Date: auditDate}
}

func source(url string) Grounding { return Grounding{Kind: GroundSource, Source: url, Date: auditDate} }

// xcodeMAC1Live grounds an Xcode agent home on the 2026-10-28 MAC-1 read.
func xcodeMAC1Live(what string) Grounding {
	return Grounding{Kind: GroundLive, Source: "MAC-1 read (macOS 26.2, Xcode 26.6 17F113 beside 26.4.1 17E202): " + what, Date: "2026-10-28"}
}

// xcodeRound5bLive grounds an Xcode agent home on Mac round 5b (2026-10-28,
// the operator's Xcode 26.6 run; docs/handovers/surface-gap-mac-ide-round-2026-10-27.md).
func xcodeRound5bLive(what string) Grounding {
	return Grounding{Kind: GroundLive, Source: "Mac round 5b (macOS 26.2, Xcode 26.6): " + what, Date: "2026-10-28"}
}

// settingsFiles is the settings-kind part of the Files table: the tools
// with a schema-generated catalogue (phase P1). The doc-authored tools of
// phase P2 append their own rows here.
var settingsFiles = []FileRow{
	// --- Claude Code (code.claude.com/docs/en/settings, settings-reference,
	// managed-settings). Settings files are strict JSON (the settings page
	// and settings-example page both say comments are not accepted).
	{
		ID: "claude-code/user-settings", Tool: "claude-code", Shape: "claude-code/settings", Kind: KindSettings, Scope: ScopeUser,
		Paths: samePath("~/.claude/settings.json"), Format: FormatJSON, SchemaURL: "https://json.schemastore.org/claude-code-settings.json",
		Precedence: 20, WriteNeeds: PrivUser, Grounding: live("~/.claude/settings.json carries hooks + theme"),
		Note: "CLAUDE_CONFIG_DIR relocates ~/.claude.",
	},
	{
		ID: "claude-code/project-settings", Tool: "claude-code", Shape: "claude-code/settings", Kind: KindSettings, Scope: ScopeProjectShared,
		Paths: samePath("<project>/.claude/settings.json"), Format: FormatJSON, SchemaURL: "https://json.schemastore.org/claude-code-settings.json",
		Precedence: 30, WriteNeeds: PrivUser, Grounding: doc("https://code.claude.com/docs/en/settings"),
	},
	{
		ID: "claude-code/project-local-settings", Tool: "claude-code", Shape: "claude-code/settings", Kind: KindSettings, Scope: ScopeProjectLocal,
		Paths: samePath("<project>/.claude/settings.local.json"), Format: FormatJSON, SchemaURL: "https://json.schemastore.org/claude-code-settings.json",
		Precedence: 40, WriteNeeds: PrivUser, Gitignored: true, Grounding: doc("https://code.claude.com/docs/en/settings"),
	},
	{
		ID: "claude-code/managed-settings", Tool: "claude-code", Shape: "claude-code/settings", Kind: KindSettings, Scope: ScopeManaged,
		Paths: OSPaths{
			Linux:   "/etc/claude-code/managed-settings.json",
			Darwin:  "/Library/Application Support/ClaudeCode/managed-settings.json",
			Windows: `C:\Program Files\ClaudeCode\managed-settings.json`,
		},
		Format: FormatJSON, SchemaURL: "https://json.schemastore.org/claude-code-settings.json",
		Precedence: 100, WriteNeeds: PrivAdminRoot, DropInDir: "managed-settings.d", Grounding: doc("https://code.claude.com/docs/en/managed-settings"),
		Note: "Plus managed-settings.d/*.json (merged) and the MDM / registry sources; /etc/claude-code is reported user-writable on WSL, so it is not a lock there.",
	},
	{
		ID: "claude-code/global-config", Tool: "claude-code", Shape: "claude-code/global-config", Kind: KindToolState, Scope: ScopeUser,
		Paths: samePath("~/.claude.json"), Format: FormatJSON, Precedence: 20, WriteNeeds: PrivNever,
		Grounding: live("~/.claude.json carries autoUpdates beside large server caches"),
		Note:      "Mostly server caches (cachedGrowthBookFeatures, cachedExperimentData) plus user / local MCP servers: shown, never form-edited. CLAUDE_CONFIG_DIR moves it to $CLAUDE_CONFIG_DIR/.claude.json.",
	},
	{
		// Lane BOXSIGNIN: the sign-in file sign-in seeding copies (with
		// consent) into a projected sandbox; Observer never reads it
		// otherwise and never edits it.
		ID: "claude-code/credentials", Tool: "claude-code", Shape: "claude-code/credentials", Kind: KindToolState, Scope: ScopeUser,
		Paths: samePath("~/.claude/.credentials.json"), Format: FormatJSON, Precedence: 0, WriteNeeds: PrivNever,
		Grounding: doc("https://code.claude.com/docs/en/authentication"),
		Note:      "Credential store (Linux and Windows; the macOS Keychain on a Mac): never edited; copied only by consented sign-in seeding. CLAUDE_CONFIG_DIR moves it.",
	},
	{
		// Surface-gap S-2 (lane w8-registry, 2026-10-28): the CLAUDE_CONFIG_DIR
		// of the Claude Code Xcode 26.3+ bundles (Agents/claude/<version>).
		// A tool-state DIRECTORY row of its own shape, so no effective-layer
		// evaluator reads it as a layer of the CLI's settings: Xcode's Claude
		// never reads ~/.claude, and the CLI never reads this. PrivNever: no
		// catalogue writer (the settings editor, a fan-out) touches it; the one
		// writer is the hook target claude-code-xcode (internal/hook
		// register_xcode.go; LCR-89 passed 2026-10-28), which adds
		// settings.json inside it.
		ID: "claude-code/xcode-agent-home", Tool: "claude-code", Shape: "claude-code/xcode-agent-home", Kind: KindToolState, Scope: ScopeUser,
		Paths: OSPaths{Darwin: "~/Library/Developer/Xcode/CodingAssistant/ClaudeAgentConfig/"}, Format: FormatJSON, Precedence: 0, WriteNeeds: PrivNever,
		Grounding: xcodeMAC1Live("ClaudeAgentConfig/ holds .claude.json, policy-limits.json, remote-settings.json, projects/, sessions/, session-env/, shell-snapshots/, backups/, debug/ and no settings.json"),
		Note: "Xcode's own Claude config home (macOS): its .claude.json (rewritten atomically by Xcode's Claude) and transcripts under projects/. " +
			"Xcode ships no settings.json here, so no ~/.claude hook or route reaches Xcode's Claude. Observer's hook writer for this home (target claude-code-xcode) adds its hooks in settings.json here, only when this folder exists; live check LCR-89 passed on 2026-10-28 (Xcode 26.6 ran the hooks and kept the file byte for byte). The claude-code adapter reads the transcripts under projects/ (FU-150).",
	},
	{
		ID: "claude-code/project-mcp", Tool: "claude-code", Shape: "claude-code/mcp", Kind: KindMCP, Scope: ScopeProjectShared,
		Paths: samePath("<project>/.mcp.json"), Format: FormatJSON, Precedence: 30, WriteNeeds: PrivUser,
		Grounding: doc("https://code.claude.com/docs/en/settings"),
	},

	// --- Codex (learn.chatgpt.com/docs/config-file/config-reference,
	// managed-configuration). Precedence: project > user > system; the
	// managed defaults file overrides user config at startup.
	{
		ID: "codex/system-config", Tool: "codex", Shape: "codex/config", Kind: KindSettings, Scope: ScopeSystem,
		Paths:      OSPaths{Linux: "/etc/codex/config.toml", Darwin: "/etc/codex/config.toml", Windows: `%ProgramData%\OpenAI\Codex\config.toml`},
		Format:     FormatTOML,
		SchemaURL:  "https://raw.githubusercontent.com/openai/codex/main/codex-rs/core/config.schema.json",
		Precedence: 10, WriteNeeds: PrivAdminRoot, Grounding: doc("https://learn.chatgpt.com/docs/config-file/config-reference"),
		// The Windows path is from vendor source (codex-rs/config/src/loader/mod.rs,
		// system_config_toml_file: %ProgramData%\OpenAI\Codex\config.toml, C:\ProgramData
		// when unset), surface-gap review S-7.
	},
	{
		ID: "codex/user-config", Tool: "codex", Shape: "codex/config", Kind: KindSettings, Scope: ScopeUser,
		Paths: samePath("~/.codex/config.toml"), Format: FormatTOML,
		SchemaURL:  "https://raw.githubusercontent.com/openai/codex/main/codex-rs/core/config.schema.json",
		Precedence: 20, WriteNeeds: PrivUser, Grounding: live("~/.codex/config.toml carries model, model_reasoning_effort, projects, tui"),
		Note: "CODEX_HOME relocates ~/.codex.",
	},
	{
		// Lane BOXSIGNIN: Codex's file sign-in store.
		ID: "codex/auth", Tool: "codex", Shape: "codex/auth", Kind: KindToolState, Scope: ScopeUser,
		Paths: samePath("~/.codex/auth.json"), Format: FormatJSON, Precedence: 0, WriteNeeds: PrivNever,
		Grounding: doc("https://developers.openai.com/codex/auth"),
		Note:      "Credential store (cli_auth_credentials_store file; keyring and auto use the OS store): never edited; copied only by consented sign-in seeding. CODEX_HOME moves it.",
	},
	{
		ID: "codex/project-config", Tool: "codex", Shape: "codex/config", Kind: KindSettings, Scope: ScopeProjectShared,
		Paths: samePath("<project>/.codex/config.toml"), Format: FormatTOML,
		SchemaURL:  "https://raw.githubusercontent.com/openai/codex/main/codex-rs/core/config.schema.json",
		Precedence: 30, WriteNeeds: PrivUser, Grounding: doc("https://learn.chatgpt.com/docs/config-file/config-reference"),
		Note: "Read only when the project is trusted (projects.<path>.trust_level = \"trusted\").",
	},
	{
		ID: "codex/managed-config", Tool: "codex", Shape: "codex/config", Kind: KindSettings, Scope: ScopeManaged,
		Paths:  OSPaths{Linux: "/etc/codex/managed_config.toml", Darwin: "/etc/codex/managed_config.toml", Windows: "~/.codex/managed_config.toml"},
		Format: FormatTOML, SchemaURL: "https://raw.githubusercontent.com/openai/codex/main/codex-rs/core/config.schema.json",
		Precedence: 50, WriteNeeds: PrivAdminRoot,
		Grounding: doc("https://learn.chatgpt.com/docs/enterprise/managed-configuration"),
		Note:      "Managed DEFAULTS (reset each launch). The Windows path is user-writable: lever B there, not a lock.",
	},
	{
		ID: "codex/requirements", Tool: "codex", Shape: "codex/requirements", Kind: KindPermissions, Scope: ScopeManaged,
		Paths:  OSPaths{Linux: "/etc/codex/requirements.toml", Darwin: "/etc/codex/requirements.toml", Windows: `%ProgramData%\OpenAI\Codex\requirements.toml`},
		Format: FormatTOML, Precedence: 100, WriteNeeds: PrivAdminRoot,
		Grounding: doc("https://learn.chatgpt.com/docs/enterprise/managed-configuration"),
		Note:      "Enforced constraints (allowed_approval_policies, allowed_sandbox_modes, ...); its rows land with the lever A phase (P8).",
	},
	{
		// Surface-gap S-2: the CODEX_HOME of the Codex Xcode bundles
		// (Agents/XcodeVersions/<build>/codex). Not ~/.codex. PrivNever:
		// no catalogue writer touches it; the one writer is the hook target
		// codex-xcode (internal/hook register_xcode.go; LCR-90 passed
		// 2026-10-28), which adds hooks.json and config.toml inside it.
		ID: "codex/xcode-agent-home", Tool: "codex", Shape: "codex/xcode-agent-home", Kind: KindToolState, Scope: ScopeUser,
		Paths: OSPaths{Darwin: "~/Library/Developer/Xcode/CodingAssistant/codex/"}, Format: FormatTOML, Precedence: 0, WriteNeeds: PrivNever,
		Grounding: xcodeMAC1Live("codex/ holds installation_id, cache/, logs_2.sqlite, memories_1.sqlite, plugins/, rules/xcode.rules, sessions/YYYY/MM/rollout-*.jsonl, shell_snapshots/, models_cache.json and no config.toml or hooks.json"),
		Note: "Xcode's own Codex home (macOS): rollouts under sessions/. Xcode ships no hooks.json and writes its own config.toml, so no ~/.codex hook or route reaches Xcode's Codex; " +
			"Observer's hook writer for this home (target codex-xcode) adds hooks.json, the config.toml [features] hooks switch and the trust records here, only when this folder exists; live check LCR-90 passed on 2026-10-28 (Xcode 26.6 ran the hooks with no trust prompt, rewrites config.toml at every session start and keeps those lines). The codex adapter reads the rollouts under sessions/ (FU-150).",
	},
	{
		ID: "codex/user-hooks", Tool: "codex", Shape: "codex/hooks", Kind: KindHooks, Scope: ScopeUser,
		Paths: samePath("~/.codex/hooks.json"), Format: FormatJSON, Precedence: 20, WriteNeeds: PrivUser,
		Grounding: doc("https://learn.chatgpt.com/docs/config-file/config-reference"),
		Note:      "Observer hook registration writes this file (hook-parity Lane 0 owns it).",
	},

	// --- Open Interpreter (openinterpreter.com/docs/terminal/config-reference;
	// repo docs/openinterpreter-adapter.md). Codex-shaped config.
	{
		ID: "open-interpreter/user-config", Tool: "open-interpreter", Shape: "open-interpreter/config", Kind: KindSettings, Scope: ScopeUser,
		Paths: samePath("~/.openinterpreter/config.toml"), Format: FormatTOML,
		SchemaURL:  "https://raw.githubusercontent.com/openai/codex/main/codex-rs/core/config.schema.json",
		Precedence: 20, WriteNeeds: PrivUser, Grounding: doc("https://www.openinterpreter.com/docs/terminal/config-reference"),
		Note: "INTERPRETER_HOME relocates ~/.openinterpreter.",
	},
	{
		ID: "open-interpreter/project-config", Tool: "open-interpreter", Shape: "open-interpreter/config", Kind: KindSettings, Scope: ScopeProjectShared,
		Paths: samePath("<project>/.openinterpreter/config.toml"), Format: FormatTOML,
		SchemaURL:  "https://raw.githubusercontent.com/openai/codex/main/codex-rs/core/config.schema.json",
		Precedence: 30, WriteNeeds: PrivUser, Grounding: doc("https://www.openinterpreter.com/docs/terminal/config-reference"),
		Note: "Read only when the project is trusted.",
	},
	{
		ID: "open-interpreter/desktop-config", Tool: "open-interpreter", Shape: "open-interpreter/desktop-config", Kind: KindToolState, Scope: ScopeUser,
		Paths: OSPaths{Windows: `%APPDATA%\interpreter\codex-home\config.toml`}, Format: FormatTOML,
		Precedence: 20, WriteNeeds: PrivNever, Grounding: Grounding{Kind: GroundAdapterDoc, Source: "docs/openinterpreter-adapter.md", Date: "2026-09-03"},
		Note: "The desktop app's config holds PLAINTEXT provider API keys: never read, never written. macOS / Linux desktop roots unverified.",
	},

	// --- Gemini CLI (github.com/google-gemini/gemini-cli docs/reference/
	// configuration.md). The settings loader strips comments
	// (packages/cli/src/config/settings.ts: stripJsonComments), so JSONC.
	{
		ID: "gemini-cli/system-defaults", Tool: "gemini-cli", Shape: "gemini-cli/settings", Kind: KindSettings, Scope: ScopeSystem,
		Paths: OSPaths{
			Linux:   "/etc/gemini-cli/system-defaults.json",
			Darwin:  "/Library/Application Support/GeminiCli/system-defaults.json",
			Windows: `C:\ProgramData\gemini-cli\system-defaults.json`,
		},
		Format: FormatJSONC, SchemaURL: "https://raw.githubusercontent.com/google-gemini/gemini-cli/main/schemas/settings.schema.json",
		Precedence: 10, WriteNeeds: PrivAdminRoot, Grounding: doc("https://raw.githubusercontent.com/google-gemini/gemini-cli/main/docs/reference/configuration.md"),
	},
	{
		ID: "gemini-cli/user-settings", Tool: "gemini-cli", Shape: "gemini-cli/settings", Kind: KindSettings, Scope: ScopeUser,
		Paths: samePath("~/.gemini/settings.json"), Format: FormatJSONC,
		SchemaURL:  "https://raw.githubusercontent.com/google-gemini/gemini-cli/main/schemas/settings.schema.json",
		Precedence: 20, WriteNeeds: PrivUser, Grounding: source("https://raw.githubusercontent.com/google-gemini/gemini-cli/main/packages/cli/src/config/settings.ts"),
		Note: "GEMINI_CLI_HOME relocates ~/.gemini.",
	},
	{
		// Surface-gap S-2 and FU-160: the Gemini CLI home of the Gemini agent
		// Xcode 26.6 bundles (CodingAssistant/Agents/gemini). Apple's page
		// (https://developer.apple.com/documentation/xcode/extending-and-customizing-agents)
		// names CodingAssistant/gemini; Mac round 5b found the home in its
		// .gemini folder. Not ~/.gemini, and not moved by GEMINI_CLI_HOME
		// (that is the CLI's own home). A tool-state DIRECTORY row of its own
		// shape, so no effective-layer evaluator reads it as a layer of the
		// CLI's settings. PrivNever: no catalogue writer touches it; the one
		// writer is the hook target gemini-cli-xcode (internal/hook
		// register_xcode.go), switched off on LCR-91's finding (FU-195).
		ID: "gemini-cli/xcode-agent-home", Tool: "gemini-cli", Shape: "gemini-cli/xcode-agent-home", Kind: KindToolState, Scope: ScopeUser,
		Paths: OSPaths{Darwin: "~/Library/Developer/Xcode/CodingAssistant/gemini/.gemini/"}, Format: FormatJSONC, Precedence: 0, WriteNeeds: PrivNever,
		Grounding: xcodeRound5bLive("CodingAssistant/gemini/.gemini holds settings.json, GEMINI.md, projects.json, history/ and tmp/; Xcode's Gemini ran a shell call with Observer's ~/.gemini registration in place and no hook reached it"),
		Note: "Xcode's own Gemini CLI home (macOS, Xcode 26.6+), written by Xcode's bundled Gemini CLI: settings.json, GEMINI.md, projects.json, history/, tmp/. " +
			"No ~/.gemini hook or route reaches Xcode's Gemini. The gemini-cli adapter reads the chats under tmp/<project>/chats/ and the project records beside them (FU-160). " +
			"Observer's hook writer for this home (target gemini-cli-xcode) would add its hooks to settings.json here, only when this folder exists; it is built and switched off: live check LCR-91 (MAC-6) found Xcode's Gemini runs BeforeAgent but not BeforeTool, so a tool gate there cannot block a shell call.",
	},
	{
		ID: "gemini-cli/project-settings", Tool: "gemini-cli", Shape: "gemini-cli/settings", Kind: KindSettings, Scope: ScopeProjectShared,
		Paths: samePath("<project>/.gemini/settings.json"), Format: FormatJSONC,
		SchemaURL:  "https://raw.githubusercontent.com/google-gemini/gemini-cli/main/schemas/settings.schema.json",
		Precedence: 30, WriteNeeds: PrivUser, Grounding: doc("https://raw.githubusercontent.com/google-gemini/gemini-cli/main/docs/reference/configuration.md"),
		Note: "Gated by folder trust.",
	},
	{
		ID: "gemini-cli/system-settings", Tool: "gemini-cli", Shape: "gemini-cli/settings", Kind: KindSettings, Scope: ScopeManaged,
		Paths: OSPaths{
			Linux:   "/etc/gemini-cli/settings.json",
			Darwin:  "/Library/Application Support/GeminiCli/settings.json",
			Windows: `C:\ProgramData\gemini-cli\settings.json`,
		},
		Format: FormatJSONC, SchemaURL: "https://raw.githubusercontent.com/google-gemini/gemini-cli/main/schemas/settings.schema.json",
		Precedence: 100, WriteNeeds: PrivAdminRoot, Grounding: doc("https://raw.githubusercontent.com/google-gemini/gemini-cli/main/docs/cli/enterprise.md"),
		Note: "GEMINI_CLI_SYSTEM_SETTINGS_PATH is user-settable, so this is a lock only with a wrapper.",
	},

	// --- OpenCode (opencode.ai/docs/config). JSON or JSONC; merged.
	{
		ID: "opencode/user-config", Tool: "opencode", Shape: "opencode/config", Kind: KindSettings, Scope: ScopeUser,
		Paths: samePath("~/.config/opencode/opencode.json"), Format: FormatJSONC, SchemaURL: "https://opencode.ai/config.json",
		Precedence: 20, WriteNeeds: PrivUser, Grounding: live("~/.config/opencode/opencode.json carries $schema, mcp, provider, small_model"),
		Note: "opencode.jsonc is also read; the Windows path is the same XDG layout (inferred, not live-checked).",
	},
	{
		// FU-103 (MAC-4): OPENCODE_CONFIG_DIR adds this file to the chain
		// rather than moving the global one; the docs load it after the
		// global file and the .opencode directories, so it ranks above the
		// project file and below OPENCODE_CONFIG_CONTENT and managed.
		ID: "opencode/config-dir-config", Tool: "opencode", Shape: "opencode/config", Kind: KindSettings, Scope: ScopeUser,
		Paths: samePath("$OPENCODE_CONFIG_DIR/opencode.json"), Format: FormatJSONC, SchemaURL: "https://opencode.ai/config.json",
		Precedence: 35, WriteNeeds: PrivUser,
		Grounding: mac4Live("opencode 1.19.4 loaded $OPENCODE_CONFIG_DIR/opencode.json beside ~/.config/opencode/opencode.json (both MCP servers listed)"),
		Note: "Read only while OPENCODE_CONFIG_DIR names an absolute directory (the row resolves to env_unset otherwise). That it is loaded is live-grounded; " +
			"its rank (after global and .opencode, before OPENCODE_CONFIG_CONTENT) is from https://opencode.ai/docs/config. The directory may also hold agents, commands and plugins, which have no row.",
	},
	{
		ID: "opencode/project-config", Tool: "opencode", Shape: "opencode/config", Kind: KindSettings, Scope: ScopeProjectShared,
		Paths: samePath("<project>/opencode.json"), Format: FormatJSONC, SchemaURL: "https://opencode.ai/config.json",
		Precedence: 30, WriteNeeds: PrivUser, Grounding: doc("https://opencode.ai/docs/config/"),
	},
	{
		ID: "opencode/managed-config", Tool: "opencode", Shape: "opencode/config", Kind: KindSettings, Scope: ScopeManaged,
		Paths: OSPaths{
			Linux:   "/etc/opencode/opencode.json",
			Darwin:  "/Library/Application Support/opencode/opencode.json",
			Windows: `%ProgramData%\opencode\opencode.json`,
		},
		Format: FormatJSONC, SchemaURL: "https://opencode.ai/config.json",
		Precedence: 100, WriteNeeds: PrivAdminRoot, Grounding: doc("https://opencode.ai/docs/enterprise/"),
	},
	{
		ID: "opencode/user-tui", Tool: "opencode", Shape: "opencode/tui", Kind: KindSettings, Scope: ScopeUser,
		Paths: samePath("~/.config/opencode/tui.json"), Format: FormatJSONC, SchemaURL: "https://opencode.ai/tui.json",
		Precedence: 20, WriteNeeds: PrivUser, Grounding: doc("https://opencode.ai/docs/config/"),
		Note: "TUI settings (theme); its schema is not pinned yet, so it has no catalogue rows.",
	},

	// --- Kilo Code 7.x and the Kilo CLI share one OpenCode-lineage config
	// (kilo.ai/docs; source packages/opencode/src/config/{paths,managed}.ts).
	{
		ID: "kilo-code-cli/user-config", Tool: "kilo-code-cli", Shape: "kilo-code-cli/config", Kind: KindSettings, Scope: ScopeUser,
		Paths: samePath("~/.config/kilo/kilo.jsonc"), Format: FormatJSONC, SchemaURL: "https://app.kilo.ai/config.json",
		Precedence: 20, WriteNeeds: PrivUser, Grounding: live("~/.config/kilo/kilo.jsonc holds only $schema"),
		Note: "config.json, kilo.json, opencode.json(c) in the same dir are also read; the XDG path is used on Windows too " +
			"(C:\\Users\\<username>\\.config\\kilo\\kilo.jsonc). Read by every Kilo client: the CLI, Kilo Code 7.x for VS Code and " +
			"Kilo Code for JetBrains v7 (gap review IDE-9). A custom provider's provider.<id>.options.baseURL is the route lever (CLI-9, LC24).",
	},
	{
		ID: "kilo-code-cli/project-config", Tool: "kilo-code-cli", Shape: "kilo-code-cli/config", Kind: KindSettings, Scope: ScopeProjectShared,
		Paths: samePath("<project>/kilo.jsonc"), Format: FormatJSONC, SchemaURL: "https://app.kilo.ai/config.json",
		Precedence: 30, WriteNeeds: PrivUser, Grounding: doc("https://kilo.ai/docs/contributing/architecture/config-schema"),
	},
	{
		// Gap review IDE-9 (lane w8-registry, 2026-10-28): Kilo's settings
		// page names <project>/.kilo/kilo.jsonc beside <project>/kilo.jsonc
		// and says the .kilo dir wins; Kilo no longer falls back to
		// .opencode config dirs.
		ID: "kilo-code-cli/project-dir-config", Tool: "kilo-code-cli", Shape: "kilo-code-cli/config", Kind: KindSettings, Scope: ScopeProjectShared,
		Paths: samePath("<project>/.kilo/kilo.jsonc"), Format: FormatJSONC, SchemaURL: "https://app.kilo.ai/config.json",
		Precedence: 35, WriteNeeds: PrivUser,
		Grounding: Grounding{Kind: GroundDoc, Source: "https://raw.githubusercontent.com/Kilo-Org/kilocode/main/packages/kilo-docs/pages/getting-started/settings/index.md", Date: "2026-10-25"},
		Note:      "Wins over <project>/kilo.jsonc. Shared by the CLI and the 7.x VS Code and JetBrains clients.",
	},
	{
		ID: "kilo-code-cli/managed-dir", Tool: "kilo-code-cli", Shape: "kilo-code-cli/config", Kind: KindSettings, Scope: ScopeManaged,
		Paths:  OSPaths{Linux: "/etc/kilo/", Darwin: "/Library/Application Support/kilo/", Windows: `%ProgramData%\kilo\`},
		Format: FormatJSONC, SchemaURL: "https://app.kilo.ai/config.json",
		Precedence: 100, WriteNeeds: PrivAdminRoot, Grounding: source("https://raw.githubusercontent.com/Kilo-Org/kilocode/main/packages/opencode/src/config/managed.ts"),
		Note: "Managed config DIRECTORY; the file name inside it is unverified.",
	},
	{
		ID: "kilo-code/user-config", Tool: "kilo-code", Shape: "kilo-code/config", Kind: KindSettings, Scope: ScopeUser,
		Paths: samePath("~/.config/kilo/kilo.jsonc"), Format: FormatJSONC, SchemaURL: "https://app.kilo.ai/config.json",
		Precedence: 20, WriteNeeds: PrivUser, Grounding: doc("https://kilo.ai/docs/llms.txt"),
		Note: "Kilo Code 7.x shares the Kilo CLI config file; the pre-7 extension keeps its settings in VS Code state (read-only, D-110).",
	},
	{
		ID: "kilo-code/project-config", Tool: "kilo-code", Shape: "kilo-code/config", Kind: KindSettings, Scope: ScopeProjectShared,
		Paths: samePath("<project>/kilo.jsonc"), Format: FormatJSONC, SchemaURL: "https://app.kilo.ai/config.json",
		Precedence: 30, WriteNeeds: PrivUser, Grounding: doc("https://kilo.ai/docs/llms.txt"),
	},

	// --- Crush (github.com/charmbracelet/crush README + docs/config).
	// crush.json is the legacy format (the schema covers it); crushrc is a
	// shell script, raw text only.
	{
		ID: "crush/user-json", Tool: "crush", Shape: "crush/config-json", Kind: KindSettings, Scope: ScopeUser,
		Paths: samePath("~/.config/crush/crush.json"), Format: FormatJSON, SchemaURL: "https://charm.land/crush.json",
		Precedence: 20, WriteNeeds: PrivUser, Grounding: doc("https://raw.githubusercontent.com/charmbracelet/crush/main/docs/config/README.md"),
		Note: "Legacy format (\"deprecated, still supported\"); $XDG_CONFIG_HOME / CRUSH_GLOBAL_CONFIG relocate it.",
	},
	{
		ID: "crush/project-json", Tool: "crush", Shape: "crush/config-json", Kind: KindSettings, Scope: ScopeProjectShared,
		Paths: samePath("<project>/crush.json"), Format: FormatJSON, SchemaURL: "https://charm.land/crush.json",
		Precedence: 30, WriteNeeds: PrivUser, Grounding: doc("https://raw.githubusercontent.com/charmbracelet/crush/main/README.md"),
		Note: "<project>/.crush.json takes priority over crush.json.",
	},
	{
		ID: "crush/user-crushrc", Tool: "crush", Shape: "crush/crushrc", Kind: KindSettings, Scope: ScopeUser,
		Paths: samePath("~/.config/crush/crushrc"), Format: FormatCrushrc,
		Precedence: 25, WriteNeeds: PrivUser, Grounding: doc("https://raw.githubusercontent.com/charmbracelet/crush/main/docs/config/README.md"),
		Note: "A shell script of crush commands: raw editor only, no form. Overrides crush.json in the same directory.",
	},
	{
		ID: "crush/project-crushrc", Tool: "crush", Shape: "crush/crushrc", Kind: KindSettings, Scope: ScopeProjectShared,
		Paths: samePath("<project>/.crushrc"), Format: FormatCrushrc,
		Precedence: 45, WriteNeeds: PrivUser, Grounding: doc("https://raw.githubusercontent.com/charmbracelet/crush/main/docs/config/README.md"),
		Note: "Highest-priority project file (then ./crushrc). $(...) runs at load: trusted code.",
	},
	{
		ID: "crush/state", Tool: "crush", Shape: "crush/state", Kind: KindToolState, Scope: ScopeUser,
		Paths:  OSPaths{Linux: "~/.local/share/crush/crush.json", Darwin: "~/.local/share/crush/crush.json", Windows: `%LOCALAPPDATA%\crush\crush.json`},
		Format: FormatJSON, Precedence: 0, WriteNeeds: PrivNever, Grounding: doc("https://raw.githubusercontent.com/charmbracelet/crush/main/README.md"),
		Note: "Machine-owned state, not config.",
	},
}

// Files returns the whole Files table: the declared settings rows plus the
// instruction / rule / skill / agent / command rows derived from
// internal/guidance (the one owner of instruction globs). Sorted by id.
//
// The table is compiled once per process (T-399): every input is a static
// table, so rebuilding and re-sorting it on every UserFileFor /
// ProjectFileFor call (the doc generator and the org lint call those per
// catalogue row) only burned time. Files returns a copy so a caller can never
// change the compiled table; FileRow holds no slice or map, so the copy is
// complete. Package-internal readers walk filesTable() without copying.
func Files() []FileRow {
	return append([]FileRow(nil), filesTable()...)
}

var (
	filesOnce     sync.Once
	filesCompiled []FileRow
)

// filesTable is the compiled Files table, shared and read-only: callers in
// this package must not modify it.
func filesTable() []FileRow {
	filesOnce.Do(func() { filesCompiled = compileFiles() })
	return filesCompiled
}

// compileFiles assembles and sorts the Files table.
func compileFiles() []FileRow {
	out := append([]FileRow(nil), settingsFiles...)
	out = append(out, projectRunFiles...)
	for _, tc := range toolCatalogs {
		out = append(out, tc.Files...)
	}
	out = append(out, guidanceFiles()...)
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// guidanceKind maps guidance's vocabulary onto FileKind. guidance
// "config" rows (settings.json, opencode.json) are NOT derived: settings
// files are declared above with their full metadata.
var guidanceKind = map[guidance.Kind]FileKind{
	guidance.KindInstructions: KindInstructions,
	guidance.KindSkill:        KindSkill,
	guidance.KindAgent:        KindAgent,
	guidance.KindCommand:      KindCommand,
	guidance.KindRule:         KindRule,
}

var guidanceFormat = map[string]Format{
	guidance.FrontmatterNone: FormatMarkdown,
	guidance.FrontmatterYAML: FormatMarkdown,
	guidance.FrontmatterMDC:  FormatMDC,
	guidance.FrontmatterJSON: FormatJSON,
}

func guidanceFiles() []FileRow {
	var out []FileRow
	seen := map[string]bool{}
	for _, r := range guidance.Rules() {
		kind, ok := guidanceKind[r.Kind]
		if !ok {
			continue
		}
		scope, path, prec := ScopeProjectShared, "<project>/"+r.Glob, 30
		switch {
		case r.Scope == guidance.ScopeUser:
			scope, path, prec = ScopeUser, r.Glob, 20
		case r.Personal:
			// A per-developer overlay the vendor keeps out of git
			// (CLAUDE.local.md): in the project tree, never shared.
			scope, prec = ScopeProjectLocal, 40
		}
		id := r.Tool + "/" + string(kind) + ":" + r.Glob
		if seen[id] {
			continue
		}
		seen[id] = true
		format := guidanceFormat[r.Frontmatter]
		if format == "" {
			format = FormatMarkdown
		}
		if strings.HasSuffix(r.Glob, ".toml") {
			// A TOML command file (Gemini CLI) carries no front matter.
			format = FormatTOML
		}
		out = append(out, FileRow{
			ID: id, Tool: r.Tool, Shape: id, Kind: kind, Scope: scope,
			Paths: samePath(path), Format: format, Precedence: prec, WriteNeeds: PrivUser,
			Gitignored: r.Personal,
			Borrowed:   r.Borrowed,
			Grounding:  Grounding{Kind: GroundAdapterDoc, Source: "internal/guidance/rules.go"},
			Note:       strings.TrimSpace(r.Note),
		})
	}
	return out
}
