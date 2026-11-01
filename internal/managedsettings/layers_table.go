package managedsettings

import (
	"fmt"

	"github.com/marmutapp/superbased-observer/internal/agentconfig"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
)

// The managed-layer table (lever A, plan section 6.2, phase P8). One row
// per vendor-managed file Observer renders; the catalogue owns the paths and
// the key shape. Every row was re-grounded against the vendor's own pages on
// 2026-10-06 (Sources); a row that could not be confirmed says so (Verified
// false) and its README tells the admin to test on one machine first.
//
// Tamper-proof needs two things: the vendor ENFORCES the value over the
// developer's own files, and the place it reads is writable only by an
// administrator. Where either half is missing the row says so: a user-
// writable path is Weak on that OS, a user-settable environment variable
// that relocates the file makes the row StrengthBypassable, a layer the
// vendor only uses as a default is StrengthDefaultOnly.

var (
	enforced = []string{orgcontract.AgentConfigModeEnforced}
	defaults = []string{orgcontract.AgentConfigModeDefault}
)

const (
	refClaudeManaged  = "https://code.claude.com/docs/en/managed-settings"
	refClaudeSettings = "https://code.claude.com/docs/en/settings"
	refCodexManaged   = "https://learn.chatgpt.com/docs/enterprise/managed-configuration"
	refCodexConfig    = "https://learn.chatgpt.com/docs/config-file/config-reference"
	refGeminiEnt      = "https://raw.githubusercontent.com/google-gemini/gemini-cli/main/docs/cli/enterprise.md"
	refGeminiConfig   = "https://raw.githubusercontent.com/google-gemini/gemini-cli/main/docs/reference/configuration.md"
	refQwenSettings   = "https://raw.githubusercontent.com/QwenLM/qwen-code/main/docs/users/configuration/settings.md"
	refOpencodeConfig = "https://opencode.ai/docs/config/"
	refOpencodeSrc    = "https://raw.githubusercontent.com/anomalyco/opencode/dev/packages/opencode/src/config/managed.ts"
	refKiloManaged    = "https://raw.githubusercontent.com/Kilo-Org/kilocode/main/packages/opencode/src/config/managed.ts"
	refKiloConfig     = "https://raw.githubusercontent.com/Kilo-Org/kilocode/main/packages/opencode/src/kilocode/config/config.ts"
	refDevinSystem    = "https://docs.devin.ai/cli/enterprise/system-config"
	refFactoryOrg     = "https://docs.factory.com/enterprise/hierarchical-settings-and-org-control"
	refKiroPerms      = "https://kiro.dev/docs/enterprise/governance/permissions/"
	refGrokEnterprise = "https://docs.x.ai/build/enterprise"
	refGrokSettings   = "https://docs.x.ai/build/settings"
	refCoworkConfig   = "https://claude.com/docs/third-party/claude-desktop/configuration"
	refCoworkSupport  = "https://support.claude.com/en/articles/12622667-enterprise-configuration"
	refCursorDeploy   = "https://cursor.com/docs/enterprise/deployment-patterns"
	refDeepAgentsMgd  = "https://docs.langchain.com/oss/python/deepagents/code/configuration.md"
)

// Layers returns the managed-layer table.
func Layers() []Layer {
	out := append([]Layer(nil), layerRows...)
	out = append(out, copilotLayers...)
	return out
}

var layerRows = []Layer{
	// --- Claude Code: one managed document, three admin channels. The tool
	// uses the FIRST admin source that has any policy key (remote, then the
	// MDM plist or HKLM value, then the file), so a machine gets ONE channel.
	{
		FileID: "claude-code/managed-settings", Modes: enforced, Strength: StrengthTamperProof,
		Profile:  &ProfileChannel{Domain: "com.anthropic.claudecode", Mode: ProfileKeysNative},
		Registry: &RegistryChannel{Key: `SOFTWARE\Policies\ClaudeCode`, Mode: RegistryJSONValue, Value: "Settings"},
		Sources:  []string{refClaudeManaged, refClaudeSettings}, Verified: true,
		Note: "Claude Code reads the first administrator source that has any policy key (server-managed, then the macOS profile or the HKLM Settings value, " +
			"then the file): deploy one channel per machine, merged with any managed settings you already ship, or the other one is ignored. " +
			"A malformed document stops Claude Code from starting. On WSL /etc/claude-code is user-writable (tamper-evident there unless " +
			"wslInheritsWindowsSettings points it at the Windows policy). The proxy route disables claude.ai console-managed settings (D-114), so a " +
			"proxy-routed fleet needs this file or MDM layer.",
	},

	// --- Codex: managed DEFAULTS re-applied at launch (managed_config.toml,
	// MDM config_toml_base64) and ENFORCED requirements (requirements.toml,
	// MDM requirements_toml_base64) whose keys are constraints, filled from
	// the derived rules below. The system config.toml is the default layer.
	{
		FileID: "codex/system-config", Modes: defaults, Strength: StrengthDefaultOnly, Header: true,
		Sources: []string{refCodexConfig}, Verified: false,
		Note: "Codex's system config.toml (/etc/codex on Linux and macOS, %ProgramData%\\OpenAI\\Codex on Windows) is below the user's " +
			"config.toml: a default only. The paths are from Codex's config loader source (re-grounded 2026-10-25).",
	},
	{
		FileID: "codex/managed-config", Modes: enforced, Strength: StrengthLaunchReset, Header: true,
		Weak:    map[string]string{"windows": `Codex reads managed_config.toml from the user's own ~/.codex on Windows, which the user can edit.`},
		Profile: &ProfileChannel{Domain: "com.openai.codex", Mode: ProfileBase64File, Key: "config_toml_base64"},
		Sources: []string{refCodexManaged}, Verified: true,
		Note: "Managed defaults Codex re-applies at every launch over the user's config.toml; a developer can change a value inside one session. " +
			"The real lock is requirements.toml (allowed approval policies, sandbox and web search modes).",
	},
	{
		FileID: "codex/requirements", Modes: enforced, Strength: StrengthTamperProof, Header: true,
		PolicyKeys: map[string]string{},
		Profile:    &ProfileChannel{Domain: "com.openai.codex", Mode: ProfileBase64File, Key: "requirements_toml_base64"},
		Sources:    []string{refCodexManaged}, Verified: true,
		Note: "Enforced constraints: Codex refuses a conflicting user value and tells the user. Observer derives them from the enforced " +
			"approval_policy, sandbox_mode, web_search and approvals_reviewer values. Codex has no Windows registry channel; on Windows lock " +
			"%ProgramData%\\OpenAI\\Codex with the icacls step. Both Codex profiles use the com.openai.codex domain with different keys.",
	},

	// --- Gemini CLI and Qwen Code (gemini-cli lineage): the system
	// settings.json overrides user and project files, but environment
	// variables, CLI flags and a user-set *_SYSTEM_SETTINGS_PATH win.
	{
		FileID: "gemini-cli/system-settings", Modes: enforced, Strength: StrengthBypassable,
		Sources: []string{refGeminiEnt, refGeminiConfig}, Verified: true,
		Note: "Overrides the user's and the project's settings.json, but a user can point GEMINI_CLI_SYSTEM_SETTINGS_PATH elsewhere and environment " +
			"variables and CLI flags still win (the vendor recommends a wrapper script). No MDM profile or registry channel.",
	},
	{
		FileID: "gemini-cli/system-defaults", Modes: defaults, Strength: StrengthDefaultOnly,
		Sources: []string{refGeminiConfig}, Verified: true,
		Note: "The lowest settings layer: a default the developer's own settings override.",
	},
	{
		FileID: "qwen-code/system-settings", Modes: enforced, Strength: StrengthBypassable,
		Sources: []string{refQwenSettings}, Verified: true,
		Note: "Overrides the user's and the project's settings.json, but a user can point QWEN_CODE_SYSTEM_SETTINGS_PATH elsewhere and environment " +
			"variables and CLI flags still win. No MDM profile or registry channel.",
	},
	{
		FileID: "qwen-code/system-defaults", Modes: defaults, Strength: StrengthDefaultOnly,
		Sources: []string{refQwenSettings}, Verified: true,
		Note: "The lowest settings layer: a default the developer's own settings override.",
	},

	// --- OpenCode and Kilo (OpenCode lineage): a managed config directory
	// any user can relocate with a test environment variable, plus a macOS
	// managed-preferences domain they cannot (loaded last, overrides all).
	{
		FileID: "opencode/managed-config", Modes: enforced, Strength: StrengthBypassable,
		ChannelStrength: map[Channel]Strength{ChannelProfile: StrengthTamperProof},
		Profile:         &ProfileChannel{Domain: "ai.opencode.managed", Mode: ProfileKeysNative},
		Sources:         []string{refOpencodeConfig, refOpencodeSrc}, Verified: true,
		Note: "Managed config cannot be overridden by user or project config, but OPENCODE_TEST_MANAGED_CONFIG_DIR (and on Windows a user-set " +
			"ProgramData) relocates the directory; the macOS profile is not relocatable. Kilo reads the same ai.opencode.managed domain, so one " +
			"profile configures both tools.",
	},
	{
		FileID: "kilo-code-cli/managed-dir", AlsoShapes: []string{"kilo-code/config"}, FileName: "kilo.jsonc",
		Modes: enforced, Strength: StrengthBypassable,
		ChannelStrength: map[Channel]Strength{ChannelProfile: StrengthTamperProof},
		Profile:         &ProfileChannel{Domain: "ai.opencode.managed", Mode: ProfileKeysNative},
		Sources:         []string{refKiloManaged, refKiloConfig}, Verified: true,
		Note: "Kilo Code and the Kilo CLI read one managed directory (kilo.jsonc, kilo.json, opencode.jsonc or opencode.json). " +
			"KILO_TEST_MANAGED_CONFIG_DIR (and on Windows a user-set ProgramData) relocates it; the macOS profile (still the ai.opencode.managed " +
			"domain, shared with OpenCode) is not relocatable.",
	},

	// --- Devin CLI: system.json locks host, account and proxy only.
	{
		FileID: "devin/system-config", Modes: enforced, Strength: StrengthTamperProof,
		Sources: []string{refDevinSystem}, Verified: true,
		Note: "system.json pins the enterprise host, the account and the proxy (the proxy block is the only key the org policy can set). " +
			"The path cannot be redirected, but a malformed file is treated as absent (fails open). Permission rules are Devin Team Settings, " +
			"server-side.",
	},

	// --- Factory Droid: the org-level file; hard controls cannot be
	// weakened, session defaults (model, effort, autonomy, mode) stay
	// defaults the most local value overrides.
	{
		FileID: "droid/system-settings", Modes: enforced, Strength: StrengthTamperProof,
		PerSetting: map[string]Strength{
			"droid/model":                   StrengthDefaultOnly,
			"droid/reasoningEffort":         StrengthDefaultOnly,
			"droid/sessionDefaultSettings.": StrengthDefaultOnly,
		},
		Sources: []string{refFactoryOrg}, Verified: true,
		Note: "The authoritative org level when present: hard controls cannot be weakened, scalars are first-wins, lists union. Session defaults " +
			"(model, reasoning effort, autonomy level, interaction mode) remain defaults. A malformed file resolves to an EMPTY policy (fails open).",
	},

	// --- Kiro: managed deny / ask rules (restrict only); a malformed or
	// granting file fails CLOSED and denies every tool call, so the layer
	// refuses an allow rule before it is ever rendered.
	{
		FileID: "kiro-cli/managed-settings", Modes: enforced, Strength: StrengthRestrictOnly, Check: kiroRestrictOnly,
		Sources: []string{refKiroPerms}, Verified: false,
		Note: "Rules may only deny or ask; a malformed file denies every tool call (fails closed), so Observer refuses an allow rule here. " +
			"The macOS path is confirmed; the Linux and Windows paths come from the catalogue and were not rendered on the vendor page. " +
			"Restart Kiro after deploying.",
	},

	// --- Grok: /etc/grok/managed_config.toml is defaults; requirements.toml
	// pins (fail closed, beat config, env and remote settings).
	{
		FileID: "grok/system-managed-config", Modes: defaults, Strength: StrengthDefaultOnly, Header: true,
		Sources: []string{refGrokEnterprise, refGrokSettings}, Verified: true,
		Note: "Managed defaults below the user's config.toml (Linux and macOS; no Windows path is documented).",
	},
	{
		FileID: "grok/system-requirements", Modes: enforced, Strength: StrengthTamperProof, Header: true,
		PolicyKeys: map[string]string{},
		Sources:    []string{refGrokEnterprise}, Verified: true,
		Note: "Pins that beat config.toml, environment variables and remote settings (Linux and macOS; no Windows path is documented). " +
			"Observer pins the sandbox profile from an enforced sandbox.profile.",
	},

	// --- LangChain Deep Agents Code (dcode): managed_config.toml outranks
	// every environment variable and the user's config.toml (surface-gap
	// S-19). A remote [managed_config] source can replace it.
	{
		FileID: "deepagents-code/managed-config", Modes: enforced, Strength: StrengthTamperProof, Header: true,
		Weak: map[string]string{"windows": `A standard user can create %ProgramData%\dcode before an administrator does; ` +
			`create it and lock it (administrators write, users read) before deploying.`},
		Sources: []string{refDeepAgentsMgd}, Verified: false,
		Note: "dcode applies managed_config.toml over every environment variable and the user's config.toml ([models] allowed is the documented " +
			"lock). The file is replaced by a remote source when it sets [managed_config] source = https://...; no hooks or MCP keys are " +
			"documented. Doc-grounded from the location matrix (2026-10-25), not re-fetched: test on one machine first.",
	},

	// --- Claude Desktop (cowork): flat policy keys, every MDM value a
	// string. The org policy authors these as device-management-only keys.
	{
		FileID: "cowork/managed-policy", Modes: enforced, Strength: StrengthTamperProof,
		Profile:  &ProfileChannel{Domain: "com.anthropic.claudefordesktop", Mode: ProfileKeysStrings},
		Registry: &RegistryChannel{Key: `SOFTWARE\Policies\Claude`, Mode: RegistryStrings},
		Sources:  []string{refCoworkConfig, refCoworkSupport}, Verified: true,
		Note: "Claude Desktop re-checks its policy every configRecheckIntervalMinutes (10 by default). App-behavior keys (auto-update, relaunch, " +
			"proxy) coexist with local values. HKCU is ignored once the HKLM key exists. Linux: root-owned, not group- or world-writable, no symlink.",
	},

	// --- Cursor: IDE policy keys. Linux reads ~/.cursor/policy.json, which
	// the user owns; the macOS profile is the lock. The Windows registry
	// path of the ADMX is not documented, so there is no .reg here.
	{
		FileID: "cursor/policy", Modes: enforced, Strength: StrengthTamperProof,
		Weak:    map[string]string{"linux": "Cursor reads ~/.cursor/policy.json from the user's home, which the user can edit."},
		Profile: &ProfileChannel{Domain: "com.todesktop.230313mzl4w4u92", Mode: ProfileKeysNative},
		Sources: []string{refCursorDeploy}, Verified: true,
		Note: "Policy keys lock the IDE setting at every level. The production bundle id is the profile domain (nightly: co.anysphere.cursor.nightly). " +
			"Windows uses the ADMX shipped with Cursor; its registry path is not documented, so deploy the ADMX through Group Policy.",
	},
}

// kiroRestrictOnly refuses a Kiro managed rule list that grants anything:
// the managed file accepts only deny and ask, and fails closed otherwise.
func kiroRestrictOnly(_ string, v any) error {
	list, ok := v.([]any)
	if !ok {
		return fmt.Errorf("rules must be a list")
	}
	for i, x := range list {
		rule, ok := x.(map[string]any)
		if !ok {
			return fmt.Errorf("rule %d is not an object", i+1)
		}
		switch rule["effect"] {
		case "deny", "ask":
		default:
			return fmt.Errorf("rule %d has effect %v: the managed file allows only deny and ask", i+1, rule["effect"])
		}
	}
	return nil
}

// derivedRules are the constraints an enforced setting implies in an
// enforcement file (Codex requirements, Grok requirements).
func derivedRules() []Derived {
	return []Derived{
		{
			Name: "allowed_approval_policies", From: "codex/approval_policy", Mode: orgcontract.AgentConfigModeEnforced, To: "codex/requirements",
			Path: agentconfig.KeyPath{"allowed_approval_policies"}, Transform: oneOf(),
		},
		{
			Name: "allowed_sandbox_modes", From: "codex/sandbox_mode", Mode: orgcontract.AgentConfigModeEnforced, To: "codex/requirements",
			Path: agentconfig.KeyPath{"allowed_sandbox_modes"}, Transform: oneOf("read-only", "workspace-write", "danger-full-access"),
		},
		{
			Name: "allowed_web_search_modes", From: "codex/web_search", Mode: orgcontract.AgentConfigModeEnforced, To: "codex/requirements",
			Path: agentconfig.KeyPath{"allowed_web_search_modes"}, Transform: webSearchModes,
		},
		{
			Name: "allowed_approvals_reviewers", From: "codex/approvals_reviewer", Mode: orgcontract.AgentConfigModeEnforced, To: "codex/requirements",
			Path: agentconfig.KeyPath{"allowed_approvals_reviewers"}, Transform: oneOf("user", "auto_review"),
		},
		{
			Name: "sandbox.profile pin", From: "grok/sandbox.profile", Mode: orgcontract.AgentConfigModeEnforced, To: "grok/system-requirements",
			Path: agentconfig.KeyPath{"sandbox", "profile"}, Transform: same,
		},
	}
}

// webSearchModes maps an enforced Codex web_search mode onto the
// allowed_web_search_modes constraint: "disabled" is the empty list (the
// vendor's spelling of "only disabled"), any other mode a one-entry list.
func webSearchModes(v any) (any, bool) {
	s, ok := v.(string)
	if !ok {
		return nil, false
	}
	if s == "disabled" {
		return []any{}, true
	}
	return []any{s}, true
}

// vendorRailNotes say, for a tool with no managed layer the org policy can
// fill, where its vendor keeps the administrator controls instead.
var vendorRailNotes = map[string]string{
	"cline":        "Cline's enterprise remote configuration is server-side (Cline admin console); no local administrator file. Lever B only (tamper-evident).",
	"cline-cli":    "Cline's enterprise remote configuration is server-side (Cline admin console); no local administrator file. Lever B only (tamper-evident).",
	"mistral-code": "Mistral vibe's admin configuration is server-side; no local administrator file. Lever B only (tamper-evident).",
	"kiro-crew":    "Kiro Crew drives kiro-cli: kiro-cli's managed deny and ask rules apply to it. Its own settings are lever B only (tamper-evident).",
}
