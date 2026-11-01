package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/hook"
	"github.com/marmutapp/superbased-observer/internal/managedsettings"
)

// AP-135 Rail B providers of `observer org emit-managed-settings`: Snowflake
// Cortex Code (managed-settings.json + the admin mcp.json it names) and IBM
// Bob (OtelConfiguration + EnforcedHooks, optionally EnableTelemetry=false,
// as policy.json, .reg and .mobileconfig).

type emitCortexArgs struct {
	scope, outDir, mcpPackage, targetOS, banner string
	noMCP                                       bool
}

func runEmitCortex(cmd *cobra.Command, a emitCortexArgs) error {
	arts, err := managedsettings.GenerateCortex(managedsettings.CortexOptions{
		OS: a.targetOS, MCPPackage: a.mcpPackage, IncludeMCP: !a.noMCP, Banner: a.banner,
	})
	if err != nil {
		return err
	}
	files := []emittedFile{
		{"managed-settings.json", arts.ManagedSettingsJSON, arts.ManagedSettingsPath},
		{"mcp.json", arts.MCPJSON, arts.MCPPath},
		{"README.md", []byte(arts.Readme), ""},
	}
	return emitFiles(cmd, a.scope, a.outDir, files)
}

type emitBobArgs struct {
	configPath, scope, outDir, endpointFlag, protocol string
	includeContent                                    bool
	flags                                             emitBobFlags
}

// emitBobFlags are the ibm-bob-only switches of emit-managed-settings
// (AP-135 decisions of 2026-10-24).
type emitBobFlags struct {
	noEnforcedHooks        bool
	hookBinary, hookBinWin string
	disableVendorTelemetry bool
	noOTelConfig           bool
}

func addEmitBobFlags(cmd *cobra.Command, f *emitBobFlags) {
	cmd.Flags().BoolVar(&f.noEnforcedHooks, "no-enforced-hooks", false, "[ibm-bob] omit the EnforcedHooks policy (Observer's Bob hooks; a node whose policy carries them stands its per-node registration down)")
	cmd.Flags().StringVar(&f.hookBinary, "hook-binary", "", "[ibm-bob, codex, cursor, devin] observer command the Linux / macOS EnforcedHooks (ibm-bob) or managed hook script (codex) run (default: observer, resolved on PATH)")
	cmd.Flags().StringVar(&f.hookBinWin, "hook-binary-windows", "", "[ibm-bob, codex, cursor, devin] observer command the Windows (.reg) EnforcedHooks or the Windows managed hook script run (default: --hook-binary, else observer on PATH)")
	cmd.Flags().BoolVar(&f.disableVendorTelemetry, "disable-vendor-telemetry", false, "[ibm-bob] write EnableTelemetry=false (Bob's telemetry to IBM). Bob gates its OTLP export on the same setting, so this needs --no-otel-config")
	cmd.Flags().BoolVar(&f.noOTelConfig, "no-otel-config", false, "[ibm-bob] omit the OtelConfiguration policy (Bob's OTLP export to Observer)")
}

// bobEnforcedHooks builds the EnforcedHooks values from the per-node Bob
// hook writer (one owner of the command text). The Windows value differs
// only when the admin names a different binary for it.
func bobEnforcedHooks(f emitBobFlags) (posix, windows string, err error) {
	if f.noEnforcedHooks {
		return "", "", nil
	}
	if posix, err = hook.IBMBobEnforcedHooks(f.hookBinary); err != nil {
		return "", "", err
	}
	winBin := f.hookBinWin
	if winBin == "" {
		winBin = f.hookBinary
	}
	if windows, err = hook.IBMBobEnforcedHooks(winBin); err != nil {
		return "", "", err
	}
	return posix, windows, nil
}

func runEmitBob(cmd *cobra.Command, a emitBobArgs) error {
	if a.flags.disableVendorTelemetry && !a.flags.noOTelConfig {
		return fmt.Errorf("--disable-vendor-telemetry: %w", managedsettings.ErrBobTelemetryKillsExport)
	}
	posixHooks, winHooks, err := bobEnforcedHooks(a.flags)
	if err != nil {
		return err
	}
	endpoint := a.endpointFlag
	if endpoint == "" && !a.flags.noOTelConfig {
		cfg, err := config.Load(config.LoadOptions{GlobalPath: a.configPath})
		if err != nil {
			return fmt.Errorf("load config: %w", err)
		}
		addr := cfg.Ingest.OTel.HTTPAddr
		if addr == "" {
			addr = config.DefaultIngestOTelHTTPAddr
		}
		if a.protocol == "grpc" {
			addr = cfg.Ingest.OTel.GRPCAddr
		}
		endpoint = otelEndpointURL(addr)
	}
	arts, err := managedsettings.GenerateBob(managedsettings.BobOptions{
		OTLPEndpoint: endpoint, Protocol: a.protocol, IncludeContent: a.includeContent,
		OmitOTel: a.flags.noOTelConfig, EnforcedHooks: posixHooks, EnforcedHooksWindows: winHooks,
		DisableVendorTelemetry: a.flags.disableVendorTelemetry,
	})
	if err != nil {
		return err
	}
	files := []emittedFile{
		{"policy.json", arts.PolicyJSON, "/etc/bob/policy.json"},
		{"ibm-bob-policy.reg", managedsettings.EncodeUTF16LE(arts.Registry), `HKLM\SOFTWARE\Policies\IBM\Bob`},
		{"ibm-bob.mobileconfig", []byte(arts.MobileConfig), "com.ibm.bob (MDM)"},
		{"README.md", []byte(arts.Readme), ""},
	}
	if a.outDir == "" {
		// Print the registry text, not its UTF-16 bytes.
		files[1].data = []byte(arts.Registry)
	}
	return emitFiles(cmd, a.scope, a.outDir, files)
}

// emittedFile is one generated artifact and where it deploys.
type emittedFile struct {
	name   string
	data   []byte
	deploy string
}

// emitFiles prints the artifacts to stdout or writes them to dir, skipping
// nil ones (an artifact the options did not request).
func emitFiles(cmd *cobra.Command, scope, dir string, files []emittedFile) error {
	out := cmd.OutOrStdout()
	if dir == "" {
		fmt.Fprintf(out, "# scope: %s\n\n", scope)
		for _, f := range files {
			if f.data == nil {
				continue
			}
			if f.deploy != "" {
				fmt.Fprintf(out, "===== %s (deploy: %s) =====\n%s\n", f.name, f.deploy, f.data)
			} else {
				fmt.Fprintf(out, "===== %s =====\n%s\n", f.name, f.data)
			}
		}
		return nil
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("mkdir %s: %w", dir, err)
	}
	var written []string
	for _, f := range files {
		if f.data == nil {
			continue
		}
		p := filepath.Join(dir, f.name)
		if err := os.WriteFile(p, f.data, 0o644); err != nil { //nolint:gosec // G306: MDM-distributed policy must be readable by every user's agent on the host; policy config, not secrets.
			return fmt.Errorf("write %s: %w", p, err)
		}
		written = append(written, f.name)
	}
	fmt.Fprintf(out, "wrote %s to %s\n", strings.Join(written, ", "), dir)
	return nil
}
