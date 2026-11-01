package managedsettings

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/models"
)

// DefaultMCPPackage is the npm package the managed-mcp.json pin bootstraps via
// npx; its optionalDependencies platform binaries self-install per node.
const DefaultMCPPackage = "@superbased/observer"

// MCPServerName is the key Claude Code (and the Cortex generator) uses for
// Observer's MCP server in the opt-in managed-mcp.json pin. It is the one
// shared name every writer uses (surface-gap CX-8), so a managed pin and the
// entry `observer init` writes never leave a node with two Observer servers.
// Read it through claudeMCPServerName.
const MCPServerName = models.ObserverMCPServerName

// claudeMCPServerName is the one place this generator names Observer's MCP
// server.
func claudeMCPServerName() string { return MCPServerName }

// DefaultMCPServerCommand is the command Observer's user-scope MCP entry
// runs when `observer init` resolves the binary as a bare `observer` on
// PATH. A node whose init wrote an absolute path runs that path instead, and
// an allowedMcpServers serverCommand entry must match it exactly
// (ClaudeCodeOptions.MCPServerCommand).
var DefaultMCPServerCommand = []string{"observer", "serve"}

// DefaultClaudeCodeProxyBaseURL is Claude Code's ANTHROPIC_BASE_URL default
// for the node-proxy deployment — the proxy's default port with NO /v1
// suffix, unlike Codex's OpenAI-shaped DefaultCodexProxyBaseURL. Claude
// Code's Anthropic client appends its own path segments.
const DefaultClaudeCodeProxyBaseURL = "http://127.0.0.1:8820"

// ClaudeCodeOptions configures artifact generation.
type ClaudeCodeOptions struct {
	// OTelGRPCEndpoint is the URL Claude Code's OTLP exporter targets, e.g.
	// "http://127.0.0.1:4317". Required when IncludeTelemetry is set.
	OTelGRPCEndpoint string
	// AnthropicBaseURL is written into the managed settings.json `env` block
	// as ANTHROPIC_BASE_URL so the tool routes through a node proxy (:8820)
	// or, in thin mode, straight at the org AI Gateway. Empty ⇒ no base-URL
	// override (today's behavior).
	AnthropicBaseURL string
	// MCPPackage overrides DefaultMCPPackage (e.g. a pinned version). Optional.
	MCPPackage string
	// TargetOS is the GOOS of the nodes the artifacts deploy to ("linux",
	// "darwin", "windows"). It decides the MCP pin's launch form: on native
	// Windows the pin runs `npx` in the form Claude Code starts there (see
	// mcpPinLaunch). Empty, or any other value, writes the plain `npx` form.
	TargetOS string
	// IncludeMCP / IncludeTelemetry select which artifacts to emit. Both
	// default on at the CLI; either can be suppressed. IncludeMCP covers
	// Observer's MCP server: by default the allowedMcpServers entry for the
	// server `observer init` registers on each node, and with ExclusiveMCP
	// the managed-mcp.json pin instead.
	IncludeMCP       bool
	IncludeTelemetry bool
	// ExclusiveMCP emits managed-mcp.json, which takes EXCLUSIVE control of
	// MCP on every node: developers can no longer add, change or use any
	// other MCP server (plugin servers and --mcp-config included), and
	// claude.ai connectors and Claude in Chrome are blocked unless
	// allowAllClaudeAiMcps / allowClaudeInChromeWithManagedMcp are set
	// (https://code.claude.com/docs/en/managed-mcp). OFF by default
	// (surface-gap decision D2); the org admin turns it on.
	ExclusiveMCP bool
	// MCPServerCommand is the exact command and arguments Observer's
	// user-scope MCP entry runs on the nodes (what `observer init` wrote,
	// shown by `claude mcp get observer` on one node). The allowedMcpServers
	// serverCommand entry must match it argument for argument. Empty means
	// DefaultMCPServerCommand.
	MCPServerCommand []string
}

// Artifacts is the generated output: each *.json field is pretty-printed,
// deploy-ready bytes (nil when that artifact was not requested), plus a README
// describing how to deploy them and the MCP-vs-telemetry distinction.
type Artifacts struct {
	ManagedSettingsJSON []byte // managed-settings.json (env block)
	ManagedMCPJSON      []byte // managed-mcp.json (only with ExclusiveMCP)
	// AllowedMCPServerEntryJSON is one allowedMcpServers list entry, a
	// serverCommand matching Observer's user-scope server (IncludeMCP
	// without ExclusiveMCP). It is an entry to add to an allowlist the org
	// already deploys, never a list on its own: deploying allowedMcpServers
	// with only this entry would block every other MCP server.
	AllowedMCPServerEntryJSON []byte
	Readme                    string
}

// GenerateClaudeCode builds the managed-settings artifacts. It validates that a
// telemetry endpoint is present when telemetry is requested, and that at least
// one artifact is selected.
func GenerateClaudeCode(opts ClaudeCodeOptions) (Artifacts, error) {
	hasBaseURL := strings.TrimSpace(opts.AnthropicBaseURL) != ""
	if !opts.IncludeMCP && !opts.IncludeTelemetry && !hasBaseURL {
		return Artifacts{}, fmt.Errorf("managedsettings: nothing to emit (IncludeMCP, IncludeTelemetry, and AnthropicBaseURL all unset)")
	}
	if opts.IncludeTelemetry && strings.TrimSpace(opts.OTelGRPCEndpoint) == "" {
		return Artifacts{}, fmt.Errorf("managedsettings: OTelGRPCEndpoint is required when IncludeTelemetry is set")
	}
	pkg := opts.MCPPackage
	if pkg == "" {
		pkg = DefaultMCPPackage
	}
	if opts.IncludeMCP && opts.ExclusiveMCP {
		if err := validatePinPackage(pkg, opts.TargetOS); err != nil {
			return Artifacts{}, err
		}
	}
	serverCommand := mcpServerCommand(opts)
	if opts.IncludeMCP && !opts.ExclusiveMCP {
		for _, a := range serverCommand {
			if strings.TrimSpace(a) == "" {
				return Artifacts{}, fmt.Errorf("managedsettings: MCPServerCommand %q has an empty argument", serverCommand)
			}
		}
	}

	var out Artifacts

	// The settings.json env block is emitted whenever there's SOMETHING to put
	// in it — telemetry keys, a base-URL override, or (typically) both.
	if opts.IncludeTelemetry || hasBaseURL {
		env := map[string]string{}
		if opts.IncludeTelemetry {
			env["CLAUDE_CODE_ENABLE_TELEMETRY"] = "1"
			env["OTEL_METRICS_EXPORTER"] = "otlp"
			env["OTEL_LOGS_EXPORTER"] = "otlp"
			env["OTEL_EXPORTER_OTLP_PROTOCOL"] = "grpc"
			env["OTEL_EXPORTER_OTLP_ENDPOINT"] = opts.OTelGRPCEndpoint
		}
		if hasBaseURL {
			env["ANTHROPIC_BASE_URL"] = opts.AnthropicBaseURL
		}
		settings := map[string]any{"env": env}
		b, err := marshalIndent(settings)
		if err != nil {
			return Artifacts{}, err
		}
		out.ManagedSettingsJSON = b
	}

	if opts.IncludeMCP && !opts.ExclusiveMCP {
		b, err := marshalIndent(map[string]any{"serverCommand": serverCommand})
		if err != nil {
			return Artifacts{}, err
		}
		out.AllowedMCPServerEntryJSON = b
	}

	if opts.IncludeMCP && opts.ExclusiveMCP {
		command, args := mcpPinLaunch(models.ToolClaudeCode, pkg, opts.TargetOS)
		mcp := map[string]any{
			"mcpServers": map[string]any{
				claudeMCPServerName(): map[string]any{
					"type":    "stdio",
					"command": command,
					"args":    args,
				},
			},
		}
		b, err := marshalIndent(mcp)
		if err != nil {
			return Artifacts{}, err
		}
		out.ManagedMCPJSON = b
	}

	out.Readme = readme(opts, pkg)
	return out, nil
}

// mcpServerCommand is the serverCommand Observer's user-scope entry runs.
func mcpServerCommand(opts ClaudeCodeOptions) []string {
	if len(opts.MCPServerCommand) > 0 {
		return append([]string(nil), opts.MCPServerCommand...)
	}
	return append([]string(nil), DefaultMCPServerCommand...)
}

// claudeManagedSettingsPath is the managed-settings.json path for goos,
// from the agentconfig FileRow claude-code/managed-settings.
func claudeManagedSettingsPath(goos string) string {
	f, ok := fileRow("claude-code/managed-settings")
	if !ok {
		return ""
	}
	return osPaths(f)[goos]
}

// marshalIndent renders deploy-ready, stable JSON (2-space indent, trailing
// newline) so generated files diff cleanly across regenerations.
func marshalIndent(v any) ([]byte, error) {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("managedsettings: marshal: %w", err)
	}
	return append(b, '\n'), nil
}

func readme(opts ClaudeCodeOptions, pkg string) string {
	var b strings.Builder
	b.WriteString("# Observer managed-settings for Claude Code\n\n")
	b.WriteString("Each artifact has a DIFFERENT job:\n\n")
	if opts.IncludeMCP && opts.ExclusiveMCP {
		command, args := mcpPinLaunch(models.ToolClaudeCode, pkg, opts.TargetOS)
		b.WriteString(fmt.Sprintf(
			"- **managed-mcp.json** pins Observer's MCP server (`%s`) for in-session\n"+
				"  tool presence via `%s`. It does **NOT** deliver telemetry:\n"+
				"  Claude Code does not pass OTEL_* to MCP subprocesses.\n"+
				"  **It takes exclusive control of MCP:** developers can no longer add,\n"+
				"  change or use any other MCP server (plugin servers and `--mcp-config`\n"+
				"  included), and claude.ai connectors and Claude in Chrome are blocked\n"+
				"  unless you also set `allowAllClaudeAiMcps` /\n"+
				"  `allowClaudeInChromeWithManagedMcp`. You asked for it with\n"+
				"  `--exclusive-mcp`; without that flag no managed-mcp.json is generated.\n\n",
			claudeMCPServerName(), launchLine(command, args),
		))
		b.WriteString(windowsPinNote(command, args, "  "))
	}
	if opts.IncludeMCP && !opts.ExclusiveMCP {
		entry, _ := json.Marshal(map[string]any{"serverCommand": mcpServerCommand(opts)})
		b.WriteString(fmt.Sprintf(
			"- **allowed-mcp-server.json** is ONE `allowedMcpServers` entry,\n"+
				"  `%s`, matching the MCP server `observer init` registers per node in\n"+
				"  `~/.claude.json` (no managed-mcp.json is generated, so developers keep\n"+
				"  their own servers). Add it to the `allowedMcpServers` list your\n"+
				"  managed settings already deploy; if they deploy none, deploy nothing:\n"+
				"  an `allowedMcpServers` list holding only this entry blocks every\n"+
				"  other MCP server. Claude Code matches it exactly, every argument in\n"+
				"  order, so it must equal the command on the nodes (check one with\n"+
				"  `claude mcp get observer`; regenerate with `--mcp-binary <path>` when\n"+
				"  init wrote an absolute path, or when it added `--config <file>`, and\n"+
				"  add that pair to the entry). An org-managed Linux or macOS node that\n"+
				"  opts in with `[observer.mcp] stable_command = true` (off until its live\n"+
				"  check passes) registers the bare `observer` whenever PATH runs that same\n"+
				"  install, so the default entry matches it. `observer doctor` reports a managed\n"+
				"  allowlist that refuses Observer's server.\n\n",
			entry,
		))
	}
	if opts.IncludeTelemetry {
		b.WriteString(fmt.Sprintf(
			"- **managed-settings.json** (env block) points Claude Code's native OTel\n"+
				"  exporter at Observer's OTLP receiver (`%s`). **THIS** is what delivers\n"+
				"  telemetry. The receiver must be running (`[ingest.otel].enabled = true`)\n"+
				"  and reachable from each node.\n\n",
			opts.OTelGRPCEndpoint,
		))
	}
	if strings.TrimSpace(opts.AnthropicBaseURL) != "" {
		b.WriteString(fmt.Sprintf(
			"- **managed-settings.json** (env block) also sets `ANTHROPIC_BASE_URL=%s`,\n"+
				"  routing Claude Code's traffic through that endpoint - either a node's\n"+
				"  Observer proxy (`%s` by default) or, in Gateway-Mode thin deployments, a\n"+
				"  direct org AI Gateway URL. Switching between the two is a pure base-URL\n"+
				"  swap: no other tool/MCP registration changes.\n\n",
			opts.AnthropicBaseURL, DefaultClaudeCodeProxyBaseURL,
		))
	}
	b.WriteString("## Deploy\n\n")
	b.WriteString("- **File channel (single node, no license):** write to\n")
	b.WriteString("  `/etc/claude-code/managed-settings.json` (Linux/WSL). Verify with\n")
	b.WriteString("  `/status` → expect `(file)`. On WSL, write inside the distro or set\n")
	b.WriteString("  `wslInheritsWindowsSettings: true`.\n")
	if opts.TargetOS == "windows" {
		// The path is the agentconfig FileRow's (CC-5): Claude Code reads
		// C:\Program Files\ClaudeCode, never the legacy C:\ProgramData one.
		settings := claudeManagedSettingsPath("windows")
		dir := settings[:max(strings.LastIndex(settings, `\`), 0)]
		b.WriteString("- **Native Windows nodes:** write managed-settings.json to\n")
		b.WriteString(fmt.Sprintf("  `%s`", settings))
		if opts.IncludeMCP && opts.ExclusiveMCP {
			b.WriteString(fmt.Sprintf(" and managed-mcp.json to\n  `%s`", dir+`\managed-mcp.json`))
		}
		b.WriteString(" (administrator-writable; the legacy\n  `C:\\ProgramData\\ClaudeCode` path is not read).\n")
	}
	b.WriteString("- **Server channel (fleet):** upload the same payload in your\n")
	b.WriteString("  Teams/Enterprise admin console's managed-settings section.\n")
	return b.String()
}
