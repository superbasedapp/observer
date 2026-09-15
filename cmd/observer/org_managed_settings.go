package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/managedsettings"
)

// newOrgEmitManagedSettingsCmd generates the managed-config artifacts an admin
// deploys to point an AI-tool fleet at this Observer install (native-console
// Workstream B / Phase 4). --provider selects Claude Code (managed-settings.json
// + managed-mcp.json, the default) or Codex (managed_config.toml +
// requirements.toml).
func newOrgEmitManagedSettingsCmd() *cobra.Command {
	var (
		provider     string
		configPath   string
		scope        string
		outDir       string
		noMCP        bool
		noTelemetry  bool
		noProxyRoute bool
		enforceHooks bool
		printMDM     bool
		mcpPackage   string
		endpointFlag string
		gatewayURL   string
	)
	cmd := &cobra.Command{
		Use:   "emit-managed-settings",
		Short: "Generate managed-config artifacts (Claude Code or Codex) for fleet deployment",
		Long: "Generates the managed-config artifacts an admin deploys via the provider's\n" +
			"managed configuration channel.\n\n" +
			"  --provider claude-code (default): managed-mcp.json (pins Observer's MCP\n" +
			"    server) + a managed-settings env block (points Claude Code's native OTel\n" +
			"    at Observer's receiver).\n" +
			"  --provider codex: managed_config.toml (defaults: proxy route + MCP pin +\n" +
			"    hooks) + requirements.toml (enforced rules).\n\n" +
			"The generated README explains each provider's MCP-pin-≠-telemetry split.\n" +
			"With --out, writes the files to a directory; otherwise prints them to stdout.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if scope != "file" && scope != "server" {
				return fmt.Errorf("--scope must be file or server, got %q", scope)
			}
			switch provider {
			case "claude-code":
				return runEmitClaudeCode(cmd, emitCCArgs{
					configPath: configPath, scope: scope, outDir: outDir,
					noMCP: noMCP, noTelemetry: noTelemetry,
					mcpPackage: mcpPackage, endpointFlag: endpointFlag,
					gatewayBaseURL: gatewayURL,
				})
			case "codex":
				return runEmitCodex(cmd, emitCodexArgs{
					configPath: configPath, scope: scope, outDir: outDir,
					noMCP: noMCP, noProxyRoute: noProxyRoute, enforceHooks: enforceHooks,
					printMDM: printMDM, mcpPackage: mcpPackage, endpointFlag: endpointFlag,
					gatewayBaseURL: gatewayURL,
				})
			default:
				return fmt.Errorf("--provider must be claude-code or codex, got %q", provider)
			}
		},
	}
	cmd.Flags().StringVar(&provider, "provider", "claude-code", "AI tool: claude-code or codex")
	cmd.Flags().StringVar(&configPath, "config", "", "Path to config.toml (defaults to ~/.observer/config.toml)")
	cmd.Flags().StringVar(&scope, "scope", "file", "deploy target: file (single node) or server (admin console / MDM)")
	cmd.Flags().StringVar(&outDir, "out", "", "directory to write the artifacts to (default: print to stdout)")
	cmd.Flags().BoolVar(&noMCP, "no-mcp", false, "omit the MCP pin")
	cmd.Flags().BoolVar(&noTelemetry, "no-telemetry", false, "[claude-code] omit the managed-settings telemetry env block")
	cmd.Flags().BoolVar(&noProxyRoute, "no-proxy-route", false, "[codex] omit the openai_base_url proxy route + hooks default")
	cmd.Flags().BoolVar(&enforceHooks, "enforce-managed-hooks", false, "[codex] emit allow_managed_hooks_only=true in requirements.toml")
	cmd.Flags().BoolVar(&printMDM, "print-mdm-base64", false, "[codex] also print requirements.toml as the MDM requirements_toml_base64 value")
	cmd.Flags().StringVar(&mcpPackage, "mcp-package", "", "npm package for the MCP pin (default @superbased/observer)")
	cmd.Flags().StringVar(&endpointFlag, "otel-endpoint", "", "override the OTLP endpoint (default derived from [ingest.otel].grpc_addr)")
	cmd.Flags().StringVar(&gatewayURL, "gateway-base-url", "",
		"Gateway-Mode thin deployments: base URL of the org AI Gateway to route through instead of\n"+
			"the node proxy. claude-code: written verbatim as ANTHROPIC_BASE_URL. codex: written verbatim\n"+
			"as openai_base_url (include the /v1 suffix). Default: today's node-proxy behavior (:8820).")
	return cmd
}

type emitCCArgs struct {
	configPath, scope, outDir, mcpPackage, endpointFlag, gatewayBaseURL string
	noMCP, noTelemetry                                                  bool
}

// runEmitClaudeCode preserves the original (pre-Codex) behavior byte-for-byte
// when --gateway-base-url is unset; setting it adds an ANTHROPIC_BASE_URL
// override to the managed-settings.json env block (node-proxy → thin-mode
// Gateway swap, Luna L19 — no other artifact changes).
func runEmitClaudeCode(cmd *cobra.Command, a emitCCArgs) error {
	endpoint := a.endpointFlag
	if endpoint == "" {
		cfg, err := config.Load(config.LoadOptions{GlobalPath: a.configPath})
		if err != nil {
			return fmt.Errorf("load config: %w", err)
		}
		endpoint = otelEndpointURL(cfg.Ingest.OTel.GRPCAddr)
	}

	arts, err := managedsettings.GenerateClaudeCode(managedsettings.ClaudeCodeOptions{
		OTelGRPCEndpoint: endpoint,
		AnthropicBaseURL: a.gatewayBaseURL,
		MCPPackage:       a.mcpPackage,
		IncludeMCP:       !a.noMCP,
		IncludeTelemetry: !a.noTelemetry,
	})
	if err != nil {
		return err
	}

	if a.outDir == "" {
		return printArtifacts(cmd, a.scope, arts)
	}
	return writeArtifacts(cmd, a.outDir, arts)
}

type emitCodexArgs struct {
	configPath, scope, outDir, mcpPackage, endpointFlag, gatewayBaseURL string
	noMCP, noProxyRoute, enforceHooks, printMDM                         bool
}

// runEmitCodex generates the Codex managed_config.toml + requirements.toml
// pair. --gateway-base-url, when set, overrides the derived node-proxy
// openai_base_url with a direct thin-mode Gateway URL (Luna L19).
func runEmitCodex(cmd *cobra.Command, a emitCodexArgs) error {
	cfg, err := config.Load(config.LoadOptions{GlobalPath: a.configPath})
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	baseURL := a.gatewayBaseURL
	if baseURL == "" {
		baseURL = codexProxyBaseURL(cfg)
	}
	opts := managedsettings.CodexOptions{
		OpenAIBaseURL:           baseURL,
		OTelEndpoint:            a.endpointFlag,
		MCPPackage:              a.mcpPackage,
		IncludeMCP:              !a.noMCP,
		IncludeProxyRoute:       !a.noProxyRoute,
		EnforceManagedHooksOnly: a.enforceHooks,
	}
	arts, err := managedsettings.GenerateCodex(opts)
	if err != nil {
		return err
	}

	if a.outDir == "" {
		if err := printCodexArtifacts(cmd, a.scope, arts); err != nil {
			return err
		}
	} else if err := writeCodexArtifacts(cmd, a.outDir, arts); err != nil {
		return err
	}
	if a.printMDM {
		fmt.Fprintf(cmd.OutOrStdout(), "===== requirements_toml_base64 (MDM) =====\n%s\n", arts.RequirementsTOMLBase64())
	}
	return nil
}

// codexProxyBaseURL derives the openai_base_url default from the proxy config:
// http://127.0.0.1:<proxy.port>/v1, matching the codex launcher's default.
func codexProxyBaseURL(cfg config.Config) string {
	port := cfg.Proxy.Port
	if port <= 0 {
		port = 8820
	}
	return "http://127.0.0.1:" + strconv.Itoa(port) + "/v1"
}

// otelEndpointURL turns a bare host:port receiver bind into the URL Claude
// Code's exporter targets. An addr already carrying a scheme is left as-is.
func otelEndpointURL(addr string) string {
	if addr == "" {
		addr = config.DefaultIngestOTelGRPCAddr
	}
	if strings.Contains(addr, "://") {
		return addr
	}
	return "http://" + addr
}

func printArtifacts(cmd *cobra.Command, scope string, arts managedsettings.Artifacts) error {
	out := cmd.OutOrStdout()
	fmt.Fprintf(out, "# scope: %s\n\n", scope)
	if arts.ManagedMCPJSON != nil {
		fmt.Fprintf(out, "===== managed-mcp.json =====\n%s\n", arts.ManagedMCPJSON)
	}
	if arts.ManagedSettingsJSON != nil {
		fmt.Fprintf(out, "===== managed-settings.json =====\n%s\n", arts.ManagedSettingsJSON)
	}
	fmt.Fprintf(out, "===== README.md =====\n%s\n", arts.Readme)
	return nil
}

func writeArtifacts(cmd *cobra.Command, dir string, arts managedsettings.Artifacts) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("mkdir %s: %w", dir, err)
	}
	files := []struct {
		name string
		data []byte
	}{
		{"managed-mcp.json", arts.ManagedMCPJSON},
		{"managed-settings.json", arts.ManagedSettingsJSON},
		{"README.md", []byte(arts.Readme)},
	}
	var written []string
	for _, f := range files {
		if f.data == nil {
			continue
		}
		p := filepath.Join(dir, f.name)
		if err := os.WriteFile(p, f.data, 0o644); err != nil { //nolint:gosec // G306: MDM-distributed managed-settings must be readable by every user's agent on the host; policy config, not secrets.
			return fmt.Errorf("write %s: %w", p, err)
		}
		written = append(written, f.name)
	}
	fmt.Fprintf(cmd.OutOrStdout(), "wrote %s to %s\n", strings.Join(written, ", "), dir)
	return nil
}

func printCodexArtifacts(cmd *cobra.Command, scope string, arts managedsettings.CodexArtifacts) error {
	out := cmd.OutOrStdout()
	fmt.Fprintf(out, "# scope: %s\n\n", scope)
	if arts.ManagedConfigTOML != nil {
		fmt.Fprintf(out, "===== managed_config.toml =====\n%s\n", arts.ManagedConfigTOML)
	}
	if arts.RequirementsTOML != nil {
		fmt.Fprintf(out, "===== requirements.toml =====\n%s\n", arts.RequirementsTOML)
	}
	fmt.Fprintf(out, "===== README.md =====\n%s\n", arts.Readme)
	return nil
}

func writeCodexArtifacts(cmd *cobra.Command, dir string, arts managedsettings.CodexArtifacts) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("mkdir %s: %w", dir, err)
	}
	files := []struct {
		name string
		data []byte
	}{
		{"managed_config.toml", arts.ManagedConfigTOML},
		{"requirements.toml", arts.RequirementsTOML},
		{"README.md", []byte(arts.Readme)},
	}
	var written []string
	for _, f := range files {
		if f.data == nil {
			continue
		}
		p := filepath.Join(dir, f.name)
		if err := os.WriteFile(p, f.data, 0o644); err != nil { //nolint:gosec // G306: MDM-distributed managed-config must be readable by every user's agent on the host; policy config, not secrets.
			return fmt.Errorf("write %s: %w", p, err)
		}
		written = append(written, f.name)
	}
	fmt.Fprintf(cmd.OutOrStdout(), "wrote %s to %s\n", strings.Join(written, ", "), dir)
	return nil
}
