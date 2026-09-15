package managedsettings

import (
	"encoding/json"
	"fmt"
	"strings"
)

// DefaultMCPPackage is the npm package the managed-mcp.json pin bootstraps via
// npx; its optionalDependencies platform binaries self-install per node.
const DefaultMCPPackage = "@superbased/observer"

// MCPServerName is the key Claude Code uses for Observer's MCP server. If the
// customer's managed settings use an allowedMcpServers allowlist, this name
// must be whitelisted or Claude Code silently refuses to start it.
const MCPServerName = "superbased-observer"

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
	// IncludeMCP / IncludeTelemetry select which artifacts to emit. Both
	// default on at the CLI; either can be suppressed.
	IncludeMCP       bool
	IncludeTelemetry bool
}

// Artifacts is the generated output: each *.json field is pretty-printed,
// deploy-ready bytes (nil when that artifact was not requested), plus a README
// describing how to deploy them and the MCP-vs-telemetry distinction.
type Artifacts struct {
	ManagedSettingsJSON []byte // managed-settings.json (env block)
	ManagedMCPJSON      []byte // managed-mcp.json
	Readme              string
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

	if opts.IncludeMCP {
		mcp := map[string]any{
			"mcpServers": map[string]any{
				MCPServerName: map[string]any{
					"type":    "stdio",
					"command": "npx",
					"args":    []string{"-y", pkg, "serve"},
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
	b.WriteString("Two artifacts, two DIFFERENT jobs — deploy both:\n\n")
	if opts.IncludeMCP {
		b.WriteString(fmt.Sprintf(
			"- **managed-mcp.json** pins Observer's MCP server (`%s`) for in-session\n"+
				"  tool presence via `npx -y %s serve`. It does **NOT** deliver telemetry —\n"+
				"  Claude Code does not pass OTEL_* to MCP subprocesses. If your managed\n"+
				"  settings use an `allowedMcpServers` allowlist, add `%s` to it or Claude\n"+
				"  Code will silently refuse to start it.\n\n",
			MCPServerName, pkg, MCPServerName,
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
				"  routing Claude Code's traffic through that endpoint — either a node's\n"+
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
	b.WriteString("- **Server channel (fleet):** upload the same payload in your\n")
	b.WriteString("  Teams/Enterprise admin console's managed-settings section.\n")
	return b.String()
}
