package managedsettings

import (
	"fmt"
	"strings"
)

// Cortex Code managed settings (AP-135, Rail B; docs/plans/
// native-console-cortex-code-instance-2026-10-23.md). Snowflake's
// managed-settings.json (schema "version": "1.0") is a root-owned file read
// by the Cortex Code CLI and Desktop; it has NO telemetry key (Cortex's own
// OTel export goes only to the customer's Snowflake account, and by operator
// ruling AP-132 Observer does not read it) and no hooks key. What Observer
// can usefully place there is its MCP server, through files.mcpFile: an
// absolute path to an admin-provided mcp.json. So the generator emits two
// files: managed-settings.json (version, files.mcpFile, an optional managed
// banner) and the mcp.json it points at.

// cortexOSPaths is the documented managed-settings.json directory per target
// OS (https://docs.snowflake.com/en/user-guide/cortex-code/managed-settings);
// the admin mcp.json is placed beside it.
var cortexOSPaths = map[string]struct{ dir, sep string }{
	"linux":   {"/etc/cortex", "/"},
	"darwin":  {"/Library/Application Support/Cortex", "/"},
	"windows": {`C:\ProgramData\Cortex`, `\`},
}

// CortexOptions configures Cortex Code managed-settings generation.
type CortexOptions struct {
	// OS is the target OS of the fleet ("linux" default, "darwin",
	// "windows"); it picks the absolute files.mcpFile path, which must exist
	// on the node.
	OS string
	// MCPFilePath overrides the per-OS mcp.json path. Optional.
	MCPFilePath string
	// MCPPackage overrides DefaultMCPPackage. Optional.
	MCPPackage string
	// IncludeMCP emits files.mcpFile and the mcp.json pin.
	IncludeMCP bool
	// Banner, when non-empty, turns on ui.showManagedBanner with this text.
	Banner string
}

// CortexArtifacts is the generated Cortex Code output.
type CortexArtifacts struct {
	ManagedSettingsJSON []byte // managed-settings.json
	MCPJSON             []byte // the admin mcp.json files.mcpFile names (nil without IncludeMCP)
	ManagedSettingsPath string // where managed-settings.json goes on the target OS
	MCPPath             string // where mcp.json goes on the target OS
	Readme              string
}

// GenerateCortex builds the Cortex Code managed-settings artifacts.
func GenerateCortex(opts CortexOptions) (CortexArtifacts, error) {
	osName := strings.ToLower(strings.TrimSpace(opts.OS))
	if osName == "" {
		osName = "linux"
	}
	p, ok := cortexOSPaths[osName]
	if !ok {
		return CortexArtifacts{}, fmt.Errorf("managedsettings: unknown Cortex target OS %q (want linux|darwin|windows)", opts.OS)
	}
	banner := strings.TrimSpace(opts.Banner)
	if !opts.IncludeMCP && banner == "" {
		return CortexArtifacts{}, fmt.Errorf("managedsettings: nothing to emit for Cortex Code (no MCP pin, no banner)")
	}
	mcpPath := strings.TrimSpace(opts.MCPFilePath)
	if mcpPath == "" {
		mcpPath = p.dir + p.sep + "mcp.json"
	}
	if !cortexAbsolute(mcpPath) {
		return CortexArtifacts{}, fmt.Errorf("managedsettings: files.mcpFile must be an absolute path, got %q", mcpPath)
	}
	pkg := opts.MCPPackage
	if pkg == "" {
		pkg = DefaultMCPPackage
	}
	settings := map[string]any{"version": "1.0"}
	out := CortexArtifacts{ManagedSettingsPath: p.dir + p.sep + "managed-settings.json"}
	if opts.IncludeMCP {
		settings["files"] = map[string]any{"mcpFile": mcpPath}
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
			return CortexArtifacts{}, err
		}
		out.MCPJSON = b
		out.MCPPath = mcpPath
	}
	if banner != "" {
		settings["ui"] = map[string]any{"showManagedBanner": true, "bannerText": banner}
	}
	b, err := marshalIndent(settings)
	if err != nil {
		return CortexArtifacts{}, err
	}
	out.ManagedSettingsJSON = b
	out.Readme = cortexReadme(out, osName, pkg)
	return out, nil
}

// cortexAbsolute accepts a POSIX absolute path or a Windows drive path.
func cortexAbsolute(p string) bool {
	if strings.HasPrefix(p, "/") {
		return true
	}
	return len(p) > 2 && p[1] == ':' && (p[2] == '\\' || p[2] == '/')
}

func cortexReadme(a CortexArtifacts, osName, pkg string) string {
	var b strings.Builder
	b.WriteString("# Observer managed settings for Snowflake Cortex Code\n\n")
	b.WriteString(fmt.Sprintf("Target OS: %s.\n\n", osName))
	b.WriteString(fmt.Sprintf("- `managed-settings.json` goes to `%s`. The directory must be writable only by\n", a.ManagedSettingsPath))
	b.WriteString("  root / Administrators: Cortex Code refuses a file that is not root-owned or is\n")
	b.WriteString("  group- or other-writable, and a file that fails validation puts the CLI in a\n")
	b.WriteString("  restricted mode (\"Enforcement config error - restricted mode\"). Deploy it\n")
	b.WriteString("  with MDM or configuration management; Snowflake recommends MDM for\n")
	b.WriteString("  tamper-resistant account, auth and version controls.\n")
	if a.MCPJSON != nil {
		b.WriteString(fmt.Sprintf("- `mcp.json` goes to `%s` (the `files.mcpFile` path). It pins Observer's MCP\n", a.MCPPath))
		b.WriteString(fmt.Sprintf("  server (`npx -y %s serve`), so npx must be on every node's PATH.\n", pkg))
		b.WriteString("  On an org-managed fleet MCP servers are managed centrally: treat this file as\n")
		b.WriteString("  the org's MCP list and add every server the org approves to `mcpServers`,\n")
		b.WriteString("  because the reference does not say whether it replaces or merges with a\n")
		b.WriteString("  user's own `~/.snowflake/cortex/mcp.json` (check one node before a rollout).\n")
		b.WriteString("  If your managed `permissions.onlyAllow` restricts MCP servers, allow this one.\n")
		b.WriteString("  Pass `--no-mcp` to leave MCP out entirely. Nodes this file is not deployed\n")
		b.WriteString("  to (individual installs) are not affected.\n")
	}
	b.WriteString("\n## What this does NOT do\n\n")
	b.WriteString("- Telemetry. Cortex Code's managed settings have no telemetry key, and its own\n")
	b.WriteString("  OTel export goes only to your Snowflake account (Observer does not read it).\n")
	b.WriteString("  Per-session capture comes from Observer's local adapter on each node; org\n")
	b.WriteString("  usage comes from the org server's [cortex_analytics] poller over your\n")
	b.WriteString("  CORTEX_CODE_*_USAGE_HISTORY views.\n")
	b.WriteString("- Spend caps. Cortex Code's daily credit cap is the Snowflake parameter\n")
	b.WriteString("  CORTEX_CODE_CLI_DAILY_EST_CREDIT_LIMIT_PER_USER, set in Snowflake, not here.\n")
	b.WriteString("\nThe file is otherwise yours: add `permissions`, `tenant`, `auth`, `required` or\n")
	b.WriteString("`sql` sections per Snowflake's managed-settings reference before deploying.\n")
	return b.String()
}
