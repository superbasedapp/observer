package managedsettings

import (
	"encoding/base64"
	"errors"
	"fmt"
	"path"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/models"
)

// CodexMCPServerName is the key Codex uses for Observer's MCP server under
// [mcp_servers.<name>] in config.toml / managed_config.toml. It is the shared
// models.ObserverMCPServerName, the name the per-node writer
// (internal/mcpregister) registers too (CX-8), so a node carries one Observer
// server, not two, and a requirements.toml identity rule naming it admits the
// server whichever writer put it there.
const CodexMCPServerName = models.ObserverMCPServerName

// DefaultCodexManagedHookDir and DefaultCodexManagedHookDirWindows are the
// managed hook directories the generator names when the admin gives none:
// beside requirements.toml, so the directory is administrator-owned like the
// file that names it.
const (
	DefaultCodexManagedHookDir        = "/etc/codex/hooks"
	DefaultCodexManagedHookDirWindows = `C:\ProgramData\OpenAI\Codex\hooks`
)

// ErrCodexManagedHooksMissing refuses allow_managed_hooks_only without
// Observer's managed hooks: Codex would then skip every user hook, Observer's
// ~/.codex/hooks.json entries included, and the node would run no Observer
// hook at all (CX-2).
var ErrCodexManagedHooksMissing = errors.New("managedsettings: allow_managed_hooks_only needs Observer's managed hooks (events and both hook scripts), or Codex runs no Observer hook")

// CodexHookScript is one admin-deployed managed hook script: its file name in
// the managed directory and its bytes.
type CodexHookScript struct {
	Name string
	Body string
}

// CodexManagedHooks is Observer's Codex managed-hook set (CX-2, decision D15):
// the requirements.toml [hooks] table plus the script the admin deploys into
// the managed directory. The caller fills Events and the scripts from the
// per-node hook writer (hook.CodexHookEvents, hook.CodexManagedHookScripts),
// so the managed and per-node registrations run the same command.
type CodexManagedHooks struct {
	// Events are the Codex hook events, in order.
	Events []string
	// Dir and WindowsDir are managed_dir and windows_managed_dir: absolute
	// paths, "" for the defaults above.
	Dir, WindowsDir string
	// Script and WindowsScript are the POSIX and Windows scripts.
	Script, WindowsScript CodexHookScript
}

// DefaultCodexProxyBaseURL is the openai_base_url default — Observer's proxy on
// its default port with the /v1 suffix Codex's OpenAI client expects. Codex
// 0.130+ silently drops the launcher's `-c openai_base_url` override, so the
// file-level value is the only one that reaches the inner app-server (V6-2).
const DefaultCodexProxyBaseURL = "http://127.0.0.1:8820/v1"

// CodexOptions configures Codex managed-config artifact generation (Rail B).
//
// Two artifacts mirror Codex's two-layer policy model:
//   - managed_config.toml — DEFAULTS the user may change in-session (reapplied
//     next launch; overrides even CLI --config). The high-confidence artifact.
//   - requirements.toml — ENFORCED rules (a conflicting user value falls back to
//     a compatible one + notifies the user). Conservative in v1: only settings
//     whose exact keys are confirmed from Codex's config-reference are emitted
//     un-commented; keys the Phase-0 findings could not pin down ship as flagged,
//     commented templates rather than invented names.
type CodexOptions struct {
	// OpenAIBaseURL is the proxy route written as managed_config.toml's
	// top-level openai_base_url. Required when IncludeProxyRoute is set.
	OpenAIBaseURL string
	// OTelEndpoint, when non-empty, emits the optional [otel] redirect block
	// (Rail A — points Codex's native OpenTelemetry at Observer's receiver).
	// The exact [otel] nesting needs live confirmation against the
	// config-reference; the block carries a VERIFY note when emitted.
	OTelEndpoint string
	// MCPPackage overrides DefaultMCPPackage (e.g. a pinned version). Optional.
	MCPPackage string
	// TargetOS is the GOOS of the nodes the artifacts deploy to ("linux",
	// "darwin", "windows"). It decides the MCP pin's launch form: on native
	// Windows the pin runs `npx` in the form Codex starts there (see
	// mcpPinLaunch). Empty, or any other value, writes the plain `npx` form.
	TargetOS string
	// IncludeMCP emits the [mcp_servers.observer] pin (+ the
	// requirements MCP-allowlist template). IncludeProxyRoute emits
	// openai_base_url + [features].hooks. At least one must be set.
	IncludeMCP        bool
	IncludeProxyRoute bool
	// EnforceManagedHooksOnly emits `allow_managed_hooks_only = true` in
	// requirements.toml (ignore user/project/session hooks, still run managed
	// hooks). Off by default — it is a strong enforcement that disables a
	// user's own hooks, so it is opt-in. It requires ManagedHooks: the flag
	// switches off Observer's own per-node hooks too (CX-2).
	EnforceManagedHooksOnly bool
	// ManagedHooks, when set with EnforceManagedHooksOnly, emits Observer's
	// hooks as managed [hooks] in requirements.toml plus the two scripts the
	// admin deploys into the managed directory. It is emitted only with the
	// flag: without it Codex also runs the per-node ~/.codex/hooks.json
	// entries, and every event would fire twice.
	ManagedHooks *CodexManagedHooks
	// EnforceProxyProvider emits an ENFORCED provider in requirements.toml:
	// `model_provider = "openai-observer"` plus a complete
	// [model_providers.openai-observer] pointing at OpenAIBaseURL (CX-3,
	// decision D3). Codex ranks a requirements model_provider above a CLI
	// override, a profile and the user's config, so a user value no longer
	// takes the session off the proxy. Off by default: it is opt-in per
	// org, and it also binds Open Interpreter, which reads the same file.
	// It needs IncludeProxyRoute.
	EnforceProxyProvider bool
}

// CodexObserverProviderName is the custom Codex provider id Observer
// registers. It equals proxyroute.ProviderName (the per-node writer), so a
// node routed by `observer init` and a node bound by requirements.toml carry
// the same provider (pinned by TestCodexObserverProviderNameMatchesWriter).
// Codex 0.128+ refuses a redefinition of the built-in `openai` id.
const CodexObserverProviderName = "openai-observer"

// codexObserverProviderDisplay is the provider's display name, the one the
// per-node writer uses.
const codexObserverProviderDisplay = "OpenAI (via Observer)"

// ErrCodexEnforceProviderNeedsRoute refuses EnforceProxyProvider without the
// proxy route: the enforced provider IS the route.
var ErrCodexEnforceProviderNeedsRoute = errors.New("managedsettings: EnforceProxyProvider needs IncludeProxyRoute (the enforced provider is the proxy route)")

// CodexArtifacts is the generated Codex managed-config output: deploy-ready TOML
// bytes (nil when not requested) plus a README describing the enforced-vs-default
// split, the MCP-pin-≠-telemetry distinction, and the deploy paths.
type CodexArtifacts struct {
	ManagedConfigTOML []byte // managed_config.toml (defaults)
	RequirementsTOML  []byte // requirements.toml (enforced)
	Readme            string
	// HookScripts are the managed hook scripts the admin deploys into the
	// managed directory (POSIX first, then Windows); nil unless managed hooks
	// were emitted.
	HookScripts []CodexDeployedScript
}

// CodexDeployedScript is one generated managed hook script and the absolute
// path it deploys to.
type CodexDeployedScript struct {
	Name, DeployPath string
	Body             []byte
}

// GenerateCodex builds the Codex managed-config artifacts. It validates that a
// proxy base URL is present when the proxy route is requested, and that at least
// one artifact section is selected.
func GenerateCodex(opts CodexOptions) (CodexArtifacts, error) {
	if !opts.IncludeMCP && !opts.IncludeProxyRoute {
		return CodexArtifacts{}, fmt.Errorf("managedsettings: nothing to emit (IncludeMCP and IncludeProxyRoute both false)")
	}
	if opts.IncludeProxyRoute && strings.TrimSpace(opts.OpenAIBaseURL) == "" {
		return CodexArtifacts{}, fmt.Errorf("managedsettings: OpenAIBaseURL is required when IncludeProxyRoute is set")
	}
	if opts.EnforceProxyProvider && !opts.IncludeProxyRoute {
		return CodexArtifacts{}, ErrCodexEnforceProviderNeedsRoute
	}
	pkg := opts.MCPPackage
	if pkg == "" {
		pkg = DefaultMCPPackage
	}
	if opts.IncludeMCP {
		if err := validatePinPackage(pkg, opts.TargetOS); err != nil {
			return CodexArtifacts{}, err
		}
	}
	var hooks *codexHookLayout
	if opts.EnforceManagedHooksOnly {
		l, err := resolveCodexHooks(opts.ManagedHooks)
		if err != nil {
			return CodexArtifacts{}, err
		}
		hooks = &l
	}

	var out CodexArtifacts
	out.ManagedConfigTOML = []byte(codexManagedConfig(opts, pkg))
	out.RequirementsTOML = []byte(codexRequirements(opts, pkg, hooks))
	out.Readme = codexReadme(opts, pkg, hooks)
	if hooks != nil {
		out.HookScripts = []CodexDeployedScript{
			{Name: hooks.script.Name, DeployPath: hooks.scriptPath, Body: []byte(hooks.script.Body)},
			{Name: hooks.winScript.Name, DeployPath: hooks.winScriptPath, Body: []byte(hooks.winScript.Body)},
		}
	}
	return out, nil
}

// codexHookLayout is a validated CodexManagedHooks with its paths resolved.
type codexHookLayout struct {
	events                    []string
	dir, winDir               string
	script, winScript         CodexHookScript
	scriptPath, winScriptPath string
}

// resolveCodexHooks validates the managed-hook set and fills the defaults.
// Codex ignores a managed_dir that is not absolute (it falls back to a
// synthetic path), and the command line is written verbatim, so a path a
// shell would re-read is refused rather than quoted.
func resolveCodexHooks(h *CodexManagedHooks) (codexHookLayout, error) {
	if h == nil || len(h.Events) == 0 || h.Script.Body == "" || h.WindowsScript.Body == "" ||
		h.Script.Name == "" || h.WindowsScript.Name == "" {
		return codexHookLayout{}, ErrCodexManagedHooksMissing
	}
	l := codexHookLayout{events: h.Events, dir: h.Dir, winDir: h.WindowsDir, script: h.Script, winScript: h.WindowsScript}
	if l.dir == "" {
		l.dir = DefaultCodexManagedHookDir
	}
	if l.winDir == "" {
		l.winDir = DefaultCodexManagedHookDirWindows
	}
	l.dir = strings.TrimRight(l.dir, "/")
	l.winDir = strings.TrimRight(l.winDir, `\`)
	if !strings.HasPrefix(l.dir, "/") || strings.ContainsAny(l.dir, `\`+codexHookPathUnsafe) {
		return codexHookLayout{}, fmt.Errorf("managedsettings: Codex managed_dir %q must be an absolute POSIX path without quotes, $, `, %% or line breaks", h.Dir)
	}
	if !isAbsWindowsPath(l.winDir) || strings.ContainsAny(l.winDir, "/"+codexHookPathUnsafe) {
		return codexHookLayout{}, fmt.Errorf("managedsettings: Codex windows_managed_dir %q must be an absolute Windows path (C:\\...) without quotes, $, `, %% or line breaks", h.WindowsDir)
	}
	for _, n := range []string{l.script.Name, l.winScript.Name} {
		if strings.ContainsAny(n, `/\ `+codexHookPathUnsafe) {
			return codexHookLayout{}, fmt.Errorf("managedsettings: Codex managed hook script name %q is not a plain file name", n)
		}
	}
	l.scriptPath = path.Join(l.dir, l.script.Name)
	l.winScriptPath = l.winDir + `\` + l.winScript.Name
	return l, nil
}

// codexHookPathUnsafe are the characters a managed hook path may not carry:
// both /bin/sh and cmd.exe would re-read them inside the command line.
const codexHookPathUnsafe = "\"$`%\r\n\x00"

// isAbsWindowsPath reports a drive-absolute Windows path (C:\...).
func isAbsWindowsPath(p string) bool {
	return len(p) >= 3 && p[1] == ':' && p[2] == '\\' &&
		((p[0] >= 'A' && p[0] <= 'Z') || (p[0] >= 'a' && p[0] <= 'z'))
}

// hookCommandPath is a managed hook script path as a command word of the
// POSIX command: wrapped in double quotes when it holds a space, which
// /bin/sh reads as one word (the path carries no character it would expand).
// commandWindows uses hookCommandPathWindows.
func hookCommandPath(p string) string {
	if strings.Contains(p, " ") {
		return `"` + p + `"`
	}
	return p
}

// hookCommandPathWindows is the Windows managed hook script path as the first
// word of commandWindows. Codex on Windows runs every hook command as
// `powershell.exe -NoProfile -Command "<command>"` (FU-162), where a command
// that starts with a quoted string is a string expression, not a program to
// run, so a path PowerShell would read specially (a space, ', ;, & and the
// rest) is a single-quoted literal behind the call operator `&`; a plain
// path stays bare.
func hookCommandPathWindows(p string) string {
	if !strings.ContainsAny(p, " \t'\"`$;&|(){}@#<>,") {
		return p
	}
	return "& '" + strings.ReplaceAll(p, "'", "''") + "'"
}

// RequirementsTOMLBase64 returns the base64 of the requirements.toml artifact,
// the value an MDM pushes as `requirements_toml_base64`. Returns "" when no
// requirements artifact was generated.
func (a CodexArtifacts) RequirementsTOMLBase64() string {
	if len(a.RequirementsTOML) == 0 {
		return ""
	}
	return base64.StdEncoding.EncodeToString(a.RequirementsTOML)
}

// codexManagedConfig builds managed_config.toml (the DEFAULTS layer). Emitted as
// an annotated, stably-ordered string so the file reads cleanly and diffs across
// regenerations — a map encode would lose the comments and the ordering.
func codexManagedConfig(opts CodexOptions, pkg string) string {
	var b strings.Builder
	b.WriteString("# Observer-managed Codex defaults (managed_config.toml).\n")
	b.WriteString("# These are DEFAULTS a user may change in-session; Codex reapplies them on\n")
	b.WriteString("# next launch and they override even CLI --config. Deploy per the README.\n\n")

	if opts.IncludeProxyRoute {
		b.WriteString("# Route Codex's OpenAI traffic through Observer's proxy for accurate token\n")
		b.WriteString("# capture. This MUST live in the file: Codex 0.130+ drops the launcher's\n")
		b.WriteString("# `-c openai_base_url` override before the inner app-server makes the call\n")
		b.WriteString("# (docs/codex-shared-app-server-gotcha.md, V6-2).\n")
		b.WriteString(fmt.Sprintf("openai_base_url = %q\n\n", opts.OpenAIBaseURL))

		b.WriteString("# Enable Codex hooks so Observer captures session/permission/user-prompt rows.\n")
		b.WriteString("[features]\n")
		b.WriteString("hooks = true\n\n")
	}

	if opts.IncludeMCP {
		b.WriteString("# Pin Observer's MCP server for in-session project-knowledge tools. The npx\n")
		b.WriteString("# bootstrap self-installs the matching platform binary per node. NOTE: this\n")
		b.WriteString("# pin delivers in-session TOOLS, NOT telemetry - see the README.\n")
		command, args := mcpPinLaunch(models.ToolCodex, pkg, opts.TargetOS)
		quoted := make([]string, len(args))
		for i, a := range args {
			quoted[i] = tomlString(a)
		}
		b.WriteString(fmt.Sprintf("[mcp_servers.%s]\n", CodexMCPServerName))
		b.WriteString(fmt.Sprintf("command = %s\n", tomlString(command)))
		b.WriteString(fmt.Sprintf("args = [%s]\n\n", strings.Join(quoted, ", ")))
	}

	if strings.TrimSpace(opts.OTelEndpoint) != "" {
		// Emitted COMMENTED on purpose: Rail A is gated on a live OTLP capture,
		// and Observer's Phase-0 research confirmed the [otel] surface exists but
		// not the exact nested key names. Shipping an active block risks invalid
		// TOML / a silently-wrong redirect, so the admin uncomments after
		// confirming the shape against Codex's config-reference. THIS block (not
		// the MCP pin) is what would deliver native per-turn telemetry.
		b.WriteString("# (Rail A, optional - UNCOMMENT after confirming key nesting against Codex's\n")
		b.WriteString("# config-reference) Redirect Codex's native OpenTelemetry to Observer's OTLP\n")
		b.WriteString("# receiver. THIS is what delivers per-turn telemetry (the MCP pin above does not).\n")
		b.WriteString("# [otel]\n")
		b.WriteString("# exporter = \"otlp-http\"\n")
		b.WriteString("# [otel.exporter.otlp-http]\n")
		b.WriteString(fmt.Sprintf("# endpoint = %q\n\n", opts.OTelEndpoint))
	}

	return b.String()
}

// codexRequirements builds requirements.toml (the ENFORCED layer). Conservative:
// only keys confirmed against Codex's source are emitted live; the MCP identity
// rule ships commented, because an mcp_servers table in requirements turns
// every server it does not name off, and that is the admin's call.
func codexRequirements(opts CodexOptions, pkg string, hooks *codexHookLayout) string {
	var b strings.Builder
	b.WriteString("# Observer-managed Codex requirements (requirements.toml) - ENFORCED.\n")
	b.WriteString("# When a user's config/profile/CLI conflicts with a rule here, Codex falls\n")
	b.WriteString("# back to a compatible value and notifies the user. Deploy per the README\n")
	b.WriteString("# (system path /etc/codex/requirements.toml, %ProgramData%\\OpenAI\\Codex\\requirements.toml\n")
	b.WriteString("# on Windows, or MDM requirements_toml_base64 on macOS).\n\n")

	if opts.EnforceManagedHooksOnly {
		b.WriteString("# Run ONLY managed hooks; ignore user/project/session/plugin hooks. Strong - it\n")
		b.WriteString("# disables a user's own hooks, and Observer's per-node ~/.codex/hooks.json too,\n")
		b.WriteString("# so Observer's hooks are declared below as managed hooks (trusted by policy,\n")
		b.WriteString("# no /hooks trust step). Enabled because --enforce-managed-hooks was set.\n")
		b.WriteString("allow_managed_hooks_only = true\n\n")
	} else {
		b.WriteString("# Optional: run only managed hooks (ignore user/project/session hooks).\n")
		b.WriteString("# Do not uncomment by hand: it also switches off Observer's per-node hooks.\n")
		b.WriteString("# Regenerate with --enforce-managed-hooks, which adds Observer's managed hooks.\n")
		b.WriteString("# allow_managed_hooks_only = true\n\n")
	}

	if opts.EnforceProxyProvider {
		codexEnforcedProviderTOML(&b, opts.OpenAIBaseURL)
	}

	if hooks != nil {
		codexManagedHooksTOML(&b, hooks)
	}

	if opts.IncludeMCP {
		command, args := mcpPinLaunch(models.ToolCodex, pkg, opts.TargetOS)
		b.WriteString("# Optional MCP allowlist (Codex [mcp_servers.<name>.identity]). Once this\n")
		b.WriteString("# table exists Codex disables every MCP server it does not name, and a named\n")
		b.WriteString("# server runs only when its launch matches the identity: name AND command.\n")
		b.WriteString("# The identity below is the managed_config.toml pin's exact launch; the string\n")
		b.WriteString("# form (command = \"npx\") would not check the arguments. Add a rule for each\n")
		b.WriteString("# other server your developers may use before uncommenting.\n")
		b.WriteString(fmt.Sprintf("# [mcp_servers.%s.identity]\n", CodexMCPServerName))
		matchers := make([]string, len(args))
		for i, a := range args {
			matchers[i] = fmt.Sprintf("{ match = \"exact\", value = %s }", tomlString(a))
		}
		b.WriteString(fmt.Sprintf("# command = { executable = %s, args = [%s] }\n", tomlString(command), strings.Join(matchers, ", ")))
	}

	return b.String()
}

// codexEnforcedProviderTOML writes the enforced provider selection and its
// complete definition (CX-3). The top-level key comes before any table, as
// TOML requires. The definition must be complete: a requirements
// [model_providers.<id>] entry REPLACES the configured provider of that id
// (codex-rs/config/src/model_provider_requirements.rs), and Open Interpreter
// reads the same file, so a partial table would leave it without a wire API
// or an auth mode. The keys are the four the per-node writer sets.
func codexEnforcedProviderTOML(b *strings.Builder, baseURL string) {
	b.WriteString("# Enforce Observer's proxy provider (--enforce-proxy-provider). A requirements\n")
	b.WriteString("# model_provider outranks a CLI -c model_provider, --oss, a profile and the\n")
	b.WriteString("# user's config, so a user value no longer takes Codex off the proxy. This\n")
	b.WriteString("# file also binds Open Interpreter, which reads it too.\n")
	b.WriteString(fmt.Sprintf("model_provider = %s\n\n", tomlString(CodexObserverProviderName)))
	b.WriteString(fmt.Sprintf("[model_providers.%s]\n", CodexObserverProviderName))
	b.WriteString(fmt.Sprintf("name = %s\n", tomlString(codexObserverProviderDisplay)))
	b.WriteString(fmt.Sprintf("base_url = %s\n", tomlString(baseURL)))
	b.WriteString("wire_api = \"responses\"\n")
	b.WriteString("requires_openai_auth = true\n\n")
}

// codexManagedHooksTOML writes the [hooks] table: the managed directories and
// one [[hooks.<Event>]] group per event whose command runs the managed script
// with the event name (command on Linux and macOS, commandWindows on Windows;
// codex-rs/protocol/src/hooks.rs HookHandlerConfig). The "*" matcher is the
// one the per-node writer uses.
func codexManagedHooksTOML(b *strings.Builder, h *codexHookLayout) {
	b.WriteString("# Observer's hooks as MANAGED hooks. The script each command names is part of\n")
	b.WriteString("# this artifact set: deploy it into the managed directory (see the README).\n")
	b.WriteString("[hooks]\n")
	b.WriteString(fmt.Sprintf("managed_dir = %s\n", tomlString(h.dir)))
	b.WriteString(fmt.Sprintf("windows_managed_dir = %s\n\n", tomlString(h.winDir)))
	for _, ev := range h.events {
		b.WriteString(fmt.Sprintf("[[hooks.%s]]\n", ev))
		b.WriteString("matcher = \"*\"\n\n")
		b.WriteString(fmt.Sprintf("[[hooks.%s.hooks]]\n", ev))
		b.WriteString("type = \"command\"\n")
		b.WriteString(fmt.Sprintf("command = %s\n", tomlString(hookCommandPath(h.scriptPath)+" "+ev)))
		b.WriteString(fmt.Sprintf("commandWindows = %s\n\n", tomlString(hookCommandPathWindows(h.winScriptPath)+" "+ev)))
	}
}

// codexReadme explains the two-artifact deploy + the MCP-vs-telemetry split.
func codexReadme(opts CodexOptions, pkg string, hooks *codexHookLayout) string {
	var b strings.Builder
	b.WriteString("# Observer managed-config for OpenAI Codex\n\n")
	b.WriteString("Two artifacts, two layers of Codex's policy model:\n\n")
	b.WriteString("- **managed_config.toml** - DEFAULTS the user may change in-session (Codex\n")
	b.WriteString("  reapplies them next launch; they override even CLI `--config`). This is the\n")
	b.WriteString("  artifact that wires Observer up.\n")
	b.WriteString("- **requirements.toml** - ENFORCED rules. A conflicting user value falls back\n")
	b.WriteString("  to a compatible one and the user is notified.\n\n")

	if opts.IncludeMCP {
		command, args := mcpPinLaunch(models.ToolCodex, pkg, opts.TargetOS)
		b.WriteString(fmt.Sprintf(
			"## MCP pin ≠ telemetry\n\n"+
				"`managed_config.toml`'s `[mcp_servers.%s]` (`%s`) gives\n"+
				"in-session TOOL presence. It does **NOT** deliver telemetry. `%s` is the\n"+
				"same name `observer init` registers on a node, so a node carries one Observer\n"+
				"server. If your `requirements.toml` declares `[mcp_servers]` identity rules,\n"+
				"keep the `[mcp_servers.%s.identity]` rule (commented in the generated file)\n"+
				"or Codex disables the server.\n\n",
			CodexMCPServerName, launchLine(command, args), CodexMCPServerName, CodexMCPServerName,
		))
		b.WriteString(windowsPinNote(command, args, ""))
	}
	if opts.IncludeProxyRoute {
		b.WriteString(fmt.Sprintf(
			"## Telemetry delivery\n\n"+
				"Per-turn token capture comes from the **proxy route** (`openai_base_url = %q`)\n"+
				"plus `[features].hooks`. The proxy must be running and reachable. (Codex\n"+
				"0.130+ drops the launcher's `-c openai_base_url`; the file value is what works.)\n\n",
			opts.OpenAIBaseURL,
		))
	}
	if strings.TrimSpace(opts.OTelEndpoint) != "" {
		b.WriteString(fmt.Sprintf(
			"An optional `[otel]` block redirects Codex's **native** OpenTelemetry to\n"+
				"Observer's OTLP receiver (%s) - Rail A. VERIFY the exact `[otel]` key nesting\n"+
				"against Codex's config-reference before fleet deploy.\n\n",
			opts.OTelEndpoint,
		))
	}

	if opts.EnforceProxyProvider {
		b.WriteString("## Enforced provider\n\n")
		b.WriteString(fmt.Sprintf("`requirements.toml` sets `model_provider = %q` and its complete\n", CodexObserverProviderName))
		b.WriteString(fmt.Sprintf("`[model_providers.%s]` (base URL `%s`). Codex ranks a\n", CodexObserverProviderName, opts.OpenAIBaseURL))
		b.WriteString("requirements provider above `-c model_provider=...`, `--oss`, a profile and\n")
		b.WriteString("the user's `config.toml`, so the route holds where `openai_base_url` alone\n")
		b.WriteString("is only a default. Three things to know before you deploy it:\n\n")
		b.WriteString("- It binds **Open Interpreter** too: it reads the same `requirements.toml`,\n")
		b.WriteString("  so its sessions also go through Observer's proxy.\n")
		b.WriteString("- The proxy must be running on every node: with it down, Codex and Open\n")
		b.WriteString("  Interpreter calls fail instead of going direct.\n")
		b.WriteString("- Not live-verified: `codex -c model_provider=openai ...` should still land\n")
		b.WriteString("  an `api_turns` row on a node with this file deployed.\n\n")
	}

	if hooks != nil {
		b.WriteString("## Managed hooks\n\n")
		b.WriteString("`allow_managed_hooks_only = true` makes Codex skip every user, project,\n")
		b.WriteString("session and plugin hook, Observer's per-node `~/.codex/hooks.json` included.\n")
		b.WriteString("So `requirements.toml` declares Observer's hooks as managed `[hooks]`, which\n")
		b.WriteString("Codex trusts by policy (no `/hooks` trust step), and each command runs a\n")
		b.WriteString("script you deploy into the managed directory. Codex installs nothing there.\n\n")
		b.WriteString(fmt.Sprintf("- Linux and macOS: copy `%s` to `%s` (owner root, mode 0755).\n", hooks.script.Name, hooks.scriptPath))
		b.WriteString(fmt.Sprintf("- Windows: copy `%s` to `%s` and lock the directory like\n", hooks.winScript.Name, hooks.winScriptPath))
		b.WriteString("  `requirements.toml` (administrators write, users read and execute).\n\n")
		b.WriteString("The scripts run the node's `observer hook codex <Event>`, the command\n")
		b.WriteString("`observer init` registers per node, so `observer` must resolve on the node\n")
		b.WriteString("(or regenerate with `--hook-binary` / `--hook-binary-windows`). Declare the\n")
		b.WriteString("hooks in ONE requirements source: Codex takes `[hooks]` from the highest\n")
		b.WriteString("source that sets it and does not merge lower ones.\n\n")
	}

	b.WriteString("## Deploy\n\n")
	b.WriteString("- **Single node (no license):** write `requirements.toml` to\n")
	b.WriteString("  `/etc/codex/requirements.toml` (Linux and macOS) or\n")
	b.WriteString("  `%ProgramData%\\OpenAI\\Codex\\requirements.toml` (Windows; an HKLM\n")
	b.WriteString("  `SOFTWARE\\Policies\\OpenAI\\Codex` `RequirementsPath` value can relocate it).\n")
	b.WriteString("  Write `managed_config.toml` to `/etc/codex/managed_config.toml` (Linux and\n")
	b.WriteString("  macOS) or the user's `%USERPROFILE%\\.codex\\managed_config.toml` (Windows,\n")
	b.WriteString("  where the user can edit it). Verify Codex picks them up on launch.\n")
	b.WriteString("- **Fleet (MDM, macOS):** push `requirements.toml` as the `requirements_toml_base64`\n")
	b.WriteString("  value - base64 of the file (the CLI prints it with `--print-mdm-base64`).\n")
	b.WriteString("- **Requirements precedence (highest→lowest):** macOS MDM\n")
	b.WriteString("  `requirements_toml_base64` → legacy `/etc/codex/managed_config.toml` read as\n")
	b.WriteString("  requirements (Unix) → cloud-managed requirements → system `requirements.toml`.\n")
	b.WriteString("  A higher source's value wins; a lower one only fills what is unset.\n")
	return b.String()
}
