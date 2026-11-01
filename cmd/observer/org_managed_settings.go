package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/hook"
	"github.com/marmutapp/superbased-observer/internal/managedsettings"
)

// newOrgEmitManagedSettingsCmd generates the managed-config artifacts an admin
// deploys to point an AI-tool fleet at this Observer install (native-console
// Workstream B / Phase 4). --provider selects Claude Code (managed-settings.json
// + an allowedMcpServers entry, the default; managed-mcp.json only with
// --exclusive-mcp) or Codex (managed_config.toml + requirements.toml).
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
		enforceProv  bool
		printMDM     bool
		mcpPackage   string
		endpointFlag string
		gatewayURL   string
		targetOS     string
		banner       string
		otlpProtocol string
		withContent  bool
		exclusiveMCP bool
		mcpBinary    string
		bob          emitBobFlags
		desktop      emitDesktopFlags
		allOS        bool
		hookDir      string
		hookDirWin   string
	)
	cmd := &cobra.Command{
		Use:   "emit-managed-settings",
		Short: "Generate managed-config artifacts (Claude Code, Codex, Cortex Code, IBM Bob, Claude Desktop, Cursor or Devin) for fleet deployment",
		Long: "Generates the managed-config artifacts an admin deploys via the provider's\n" +
			"managed configuration channel.\n\n" +
			"  --provider claude-code (default): a managed-settings env block (points\n" +
			"    Claude Code's native OTel at Observer's receiver) + the allowedMcpServers\n" +
			"    entry for the MCP server `observer init` registers per node, to add to an\n" +
			"    allowlist you already deploy. --exclusive-mcp emits managed-mcp.json\n" +
			"    instead, which pins Observer's server and takes exclusive MCP control\n" +
			"    from developers (off by default).\n" +
			"  --provider codex: managed_config.toml (defaults: proxy route + MCP pin +\n" +
			"    hooks) + requirements.toml (enforced rules). --enforce-managed-hooks adds\n" +
			"    allow_managed_hooks_only plus Observer's hooks as managed [hooks] and the\n" +
			"    two scripts to deploy into the Codex managed directory.\n" +
			"    --enforce-proxy-provider enforces the proxy route as the requirements.toml\n" +
			"    model_provider (opt-in; it binds Open Interpreter too).\n" +
			"  --provider cortex-code: managed-settings.json (files.mcpFile pins Observer's\n" +
			"    MCP server; optional managed banner) + the admin mcp.json it names.\n" +
			"  --provider ibm-bob: the administrator policy as policy.json, .reg and\n" +
			"    .mobileconfig: OtelConfiguration (Bob's OTLP traces to Observer's receiver)\n" +
			"    and EnforcedHooks (Observer's Bob hooks; the per-node registration stands\n" +
			"    down) by default; --disable-vendor-telemetry adds EnableTelemetry=false and\n" +
			"    needs --no-otel-config (Bob gates the OTLP export on the same setting).\n" +
			"  --provider claude-desktop: Claude Desktop's gateway route (inferenceProvider\n" +
			"    gateway, inferenceGatewayBaseUrl, a helper-script credential) as the Desktop\n" +
			"    policy file, .mobileconfig and .reg. An explicit admin option\n" +
			"    (--desktop-gateway-route with --credential-helper); not live-verified (LC2).\n" +
			"  --provider cursor | devin: Observer's hooks as the administrator hooks file\n" +
			"    (Cursor enterprise hooks.json, Devin Desktop's Cascade system hooks.json),\n" +
			"    which the tool merges with the user's; a node whose file carries them\n" +
			"    stands its per-node registration down. --all-os emits every OS.\n\n" +
			"The generated README explains each provider's MCP-pin-≠-telemetry split.\n" +
			"With --out, writes the files to a directory; otherwise prints them to stdout.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if scope != "file" && scope != "server" {
				return fmt.Errorf("--scope must be file or server, got %q", scope)
			}
			if !validEmitTargetOS(targetOS) {
				return fmt.Errorf("--target-os must be linux, darwin or windows, got %q", targetOS)
			}
			switch provider {
			case "claude-code":
				return runEmitClaudeCode(cmd, emitCCArgs{
					configPath: configPath, scope: scope, outDir: outDir,
					noMCP: noMCP, noTelemetry: noTelemetry,
					mcpPackage: mcpPackage, endpointFlag: endpointFlag,
					gatewayBaseURL: gatewayURL, targetOS: targetOS,
					exclusiveMCP: exclusiveMCP, mcpBinary: mcpBinary,
				})
			case "codex":
				return runEmitCodex(cmd, emitCodexArgs{
					configPath: configPath, scope: scope, outDir: outDir,
					noMCP: noMCP, noProxyRoute: noProxyRoute, enforceHooks: enforceHooks,
					enforceProvider: enforceProv, printMDM: printMDM, mcpPackage: mcpPackage, endpointFlag: endpointFlag,
					gatewayBaseURL: gatewayURL, targetOS: targetOS,
					hookBinary: bob.hookBinary, hookBinaryWin: bob.hookBinWin,
					hookDir: hookDir, hookDirWin: hookDirWin,
				})
			case "cortex-code":
				return runEmitCortex(cmd, emitCortexArgs{
					scope: scope, outDir: outDir, noMCP: noMCP, mcpPackage: mcpPackage,
					targetOS: targetOS, banner: banner,
				})
			case "cursor", "devin":
				return runEmitManagedHooksFile(cmd, emitHooksFileArgs{
					provider: provider, scope: scope, outDir: outDir, targetOS: targetOS,
					hookBinary: bob.hookBinary, hookBinaryWin: bob.hookBinWin, allOS: allOS,
				})
			case "claude-desktop":
				return runEmitClaudeDesktop(cmd, emitDesktopArgs{
					scope: scope, outDir: outDir, gatewayBaseURL: gatewayURL, flags: desktop,
				})
			case "ibm-bob":
				return runEmitBob(cmd, emitBobArgs{
					configPath: configPath, scope: scope, outDir: outDir, endpointFlag: endpointFlag,
					protocol: otlpProtocol, includeContent: withContent, flags: bob,
				})
			default:
				return fmt.Errorf("--provider must be claude-code, codex, cortex-code, ibm-bob, claude-desktop, cursor or devin, got %q", provider)
			}
		},
	}
	cmd.Flags().StringVar(&provider, "provider", "claude-code", "AI tool: claude-code, codex, cortex-code, ibm-bob, claude-desktop, cursor or devin")
	cmd.Flags().StringVar(&configPath, "config", "", "Path to config.toml (defaults to ~/.observer/config.toml)")
	cmd.Flags().StringVar(&scope, "scope", "file", "deploy target: file (single node) or server (admin console / MDM)")
	cmd.Flags().StringVar(&outDir, "out", "", "directory to write the artifacts to (default: print to stdout)")
	cmd.Flags().BoolVar(&noMCP, "no-mcp", false, "omit the MCP pin")
	cmd.Flags().BoolVar(&exclusiveMCP, "exclusive-mcp", false,
		"[claude-code] emit managed-mcp.json, which pins Observer's MCP server and takes EXCLUSIVE MCP control:\n"+
			"developers can no longer add or use any other MCP server (off by default)")
	cmd.Flags().StringVar(&mcpBinary, "mcp-binary", "",
		"[claude-code] observer command the nodes' user-scope MCP entry runs, for the allowedMcpServers\n"+
			"serverCommand entry (default: observer); it must equal what `observer init` wrote on the nodes")
	cmd.Flags().BoolVar(&noTelemetry, "no-telemetry", false, "[claude-code] omit the managed-settings telemetry env block")
	cmd.Flags().BoolVar(&noProxyRoute, "no-proxy-route", false, "[codex] omit the openai_base_url proxy route + hooks default")
	cmd.Flags().BoolVar(&enforceHooks, "enforce-managed-hooks", false, "[codex] emit allow_managed_hooks_only=true in requirements.toml, with Observer's hooks as managed [hooks] and the scripts they run")
	cmd.Flags().BoolVar(&enforceProv, "enforce-proxy-provider", false,
		"[codex] ENFORCE the proxy route: requirements.toml sets model_provider = \"openai-observer\" with a complete\n"+
			"[model_providers.openai-observer], which outranks a user -c model_provider, --oss or profile (opt-in per\n"+
			"org; it binds Open Interpreter too, and needs the proxy route)")
	cmd.Flags().StringVar(&hookDir, "codex-managed-dir", "", "[codex] managed_dir for --enforce-managed-hooks: where the Linux / macOS hook script deploys (default "+managedsettings.DefaultCodexManagedHookDir+")")
	cmd.Flags().StringVar(&hookDirWin, "codex-windows-managed-dir", "", "[codex] windows_managed_dir for --enforce-managed-hooks (default "+managedsettings.DefaultCodexManagedHookDirWindows+")")
	cmd.Flags().BoolVar(&printMDM, "print-mdm-base64", false, "[codex] also print requirements.toml as the MDM requirements_toml_base64 value")
	cmd.Flags().StringVar(&mcpPackage, "mcp-package", "", "npm package for the MCP pin (default @superbased/observer)")
	cmd.Flags().StringVar(&endpointFlag, "otel-endpoint", "", "override the OTLP endpoint (default derived from [ingest.otel].grpc_addr)")
	cmd.Flags().StringVar(&banner, "banner", "", "[cortex-code] also turn on the managed-installation banner with this text")
	cmd.Flags().StringVar(&otlpProtocol, "otlp-protocol", "http/json", "[ibm-bob] OTLP protocol for the OtelConfiguration policy: http/json, http/protobuf or grpc")
	cmd.Flags().BoolVar(&withContent, "include-content", false, "[ibm-bob] set OTEL_INCLUDE_* = 1 so Bob exports prompts, responses and tool output")
	addEmitBobFlags(cmd, &bob)
	addEmitDesktopFlags(cmd, &desktop)
	cmd.Flags().BoolVar(&allOS, "all-os", false, "[cursor, devin] emit the administrator hooks file for linux, darwin and windows (default: --target-os only)")
	cmd.Flags().StringVar(&gatewayURL, "gateway-base-url", "",
		"Gateway-Mode thin deployments: base URL of the org AI Gateway to route through instead of\n"+
			"the node proxy. claude-code: written verbatim as ANTHROPIC_BASE_URL. codex: written verbatim\n"+
			"as openai_base_url (include the /v1 suffix). claude-desktop: inferenceGatewayBaseUrl.\n"+
			"Default: today's node-proxy behavior (:8820).")
	cmd.Flags().StringVar(&targetOS, "target-os", defaultEmitTargetOS(),
		"OS of the nodes the artifacts deploy to: linux, darwin or windows. On windows the MCP pin\n"+
			"runs npx in the form the client starts there (claude-code: cmd /c npx, codex: npx.cmd);\n"+
			"cortex-code: the OS whose managed file paths are written.\n"+
			"Default: this host's OS. From WSL, pass windows when the fleet runs the client natively.")
	return cmd
}

// emitTargetOSes is the closed set --target-os accepts.
var emitTargetOSes = []string{"linux", "darwin", "windows"}

// defaultEmitTargetOS is this host's OS when it is one --target-os names,
// else linux (the POSIX form every non-Windows OS shares).
func defaultEmitTargetOS() string {
	if validEmitTargetOS(runtime.GOOS) {
		return runtime.GOOS
	}
	return "linux"
}

// validEmitTargetOS reports whether goos is a --target-os value.
func validEmitTargetOS(goos string) bool {
	for _, o := range emitTargetOSes {
		if goos == o {
			return true
		}
	}
	return false
}

type emitCCArgs struct {
	configPath, scope, outDir, mcpPackage, endpointFlag, gatewayBaseURL, targetOS string
	noMCP, noTelemetry                                                            bool
	// exclusiveMCP opts into managed-mcp.json (surface-gap decision D2:
	// off by default); mcpBinary is the observer command the nodes' MCP
	// entry runs ("" = bare observer).
	exclusiveMCP bool
	mcpBinary    string
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
		TargetOS:         a.targetOS,
		IncludeMCP:       !a.noMCP,
		IncludeTelemetry: !a.noTelemetry,
		ExclusiveMCP:     a.exclusiveMCP,
		MCPServerCommand: emitMCPServerCommand(a.mcpBinary),
	})
	if err != nil {
		return err
	}

	if a.outDir == "" {
		return printArtifacts(cmd, a.scope, arts)
	}
	return writeArtifacts(cmd, a.outDir, arts)
}

// emitMCPServerCommand is the serverCommand for --mcp-binary: the binary
// plus `serve`, the argv `observer init` writes (nil keeps the default).
func emitMCPServerCommand(binary string) []string {
	binary = strings.TrimSpace(binary)
	if binary == "" {
		return nil
	}
	return []string{binary, "serve"}
}

type emitCodexArgs struct {
	configPath, scope, outDir, mcpPackage, endpointFlag, gatewayBaseURL, targetOS string
	noMCP, noProxyRoute, enforceHooks, printMDM                                   bool
	// enforceProvider opts into the enforced requirements.toml provider
	// (CX-3, decision D3).
	enforceProvider bool
	// hookBinary / hookBinaryWin are the observer commands the managed hook
	// scripts run; hookDir / hookDirWin the managed directories.
	hookBinary, hookBinaryWin, hookDir, hookDirWin string
}

// codexManagedHooks builds Observer's Codex managed-hook set from the
// per-node hook writer (one owner of the command text, the Bob
// EnforcedHooks precedent): its events and its `hook codex` scripts.
func codexManagedHooks(a emitCodexArgs) (*managedsettings.CodexManagedHooks, error) {
	posix, win, err := hook.CodexManagedHookScripts(a.hookBinary, a.hookBinaryWin)
	if err != nil {
		return nil, err
	}
	return &managedsettings.CodexManagedHooks{
		Events: hook.CodexHookEvents(),
		Dir:    a.hookDir, WindowsDir: a.hookDirWin,
		Script:        managedsettings.CodexHookScript{Name: hook.CodexManagedHookScriptPOSIX, Body: posix},
		WindowsScript: managedsettings.CodexHookScript{Name: hook.CodexManagedHookScriptWindows, Body: win},
	}, nil
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
		TargetOS:                a.targetOS,
		IncludeMCP:              !a.noMCP,
		IncludeProxyRoute:       !a.noProxyRoute,
		EnforceManagedHooksOnly: a.enforceHooks,
		EnforceProxyProvider:    a.enforceProvider,
	}
	if a.enforceHooks {
		if opts.ManagedHooks, err = codexManagedHooks(a); err != nil {
			return err
		}
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
	if arts.AllowedMCPServerEntryJSON != nil {
		fmt.Fprintf(out, "===== %s =====\n%s\n", allowedMCPServerFile, arts.AllowedMCPServerEntryJSON)
	}
	fmt.Fprintf(out, "===== README.md =====\n%s\n", arts.Readme)
	return nil
}

// allowedMCPServerFile names the allowedMcpServers entry artifact.
const allowedMCPServerFile = "allowed-mcp-server.json"

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
		{allowedMCPServerFile, arts.AllowedMCPServerEntryJSON},
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
	for _, sc := range arts.HookScripts {
		fmt.Fprintf(out, "===== %s (deploy to %s) =====\n%s\n", sc.Name, sc.DeployPath, sc.Body)
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
	for _, sc := range arts.HookScripts {
		p := filepath.Join(dir, sc.Name)
		if err := os.WriteFile(p, sc.Body, 0o755); err != nil { //nolint:gosec // G306: a managed hook script every user's Codex must execute; it holds no secret.
			return fmt.Errorf("write %s: %w", p, err)
		}
		written = append(written, sc.Name+" (deploy to "+sc.DeployPath+")")
	}
	fmt.Fprintf(cmd.OutOrStdout(), "wrote %s to %s\n", strings.Join(written, ", "), dir)
	return nil
}
