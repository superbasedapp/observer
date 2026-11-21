//go:build !sbo_omit_ingest_otlp

package main

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/clientwire"
	"github.com/marmutapp/superbased-observer/internal/cloudsession"
	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/telemetrywire"
)

// init_otlp.go is `observer init --otlp-export <tool,...>` (T-537, operator
// ruling D-343 "exporter wiring, opt-in per tool"): point each named tool's
// own OpenTelemetry exporter at this node's OTLP receiver. Strictly opt-in:
// never implied by --all, never run by `observer start`, every tool named
// explicitly. --dry-run previews the exact edit; --uninstall removes it (as
// `observer uninstall` also does). The write is clientwire.WireTelemetry,
// the same seam the dashboard's Telemetry export step calls.

// otlpExportTools lists the tools `--otlp-export` accepts, sorted.
func otlpExportTools() []string {
	var out []string
	for _, c := range integration.Capabilities() {
		if clientwire.TelemetrySupported(c.Tool) {
			out = append(out, c.Tool)
		}
	}
	sort.Strings(out)
	return out
}

// runOTLPExportInit applies (or, with uninstall, removes) the exporter
// wiring for each tool. It returns an error when any tool failed, after
// reporting every tool.
func runOTLPExportInit(out io.Writer, configPath string, tools []string, dryRun, uninstall bool) error {
	cfg, err := config.Load(config.LoadOptions{GlobalPath: configPath})
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	op := telemetrywire.OpApply
	if uninstall {
		op = telemetrywire.OpRemove
	} else if !cfg.Ingest.OTel.Enabled || strings.TrimSpace(cfg.Ingest.OTel.HTTPAddr) == "" {
		return fmt.Errorf("--otlp-export: this node's OTLP receiver is off; set [ingest.otel] enabled = true (with http_addr) or turn it on in the dashboard Settings first, so the exporter has somewhere to send")
	}
	failed := false
	for _, raw := range tools {
		tool := strings.TrimSpace(raw)
		if tool == "" {
			continue
		}
		if !clientwire.TelemetrySupported(tool) {
			fmt.Fprintf(out, "%-12s otlp ✗ no exporter writer for this tool (supported: %s)\n", tool, strings.Join(otlpExportTools(), ", "))
			failed = true
			continue
		}
		res := clientwire.WireTelemetry(tool, op, clientwire.TelemetryOptions{
			Addr: cfg.Ingest.OTel.HTTPAddr, DryRun: dryRun,
			ReceiverRequiresToken: cfg.Ingest.OTel.AllowNonLoopback,
		})
		printTelemetryResult(out, res)
		if res.Error != nil || res.Conflict != "" {
			failed = true
		}
	}
	if failed {
		return fmt.Errorf("--otlp-export completed with errors; see above")
	}
	return nil
}

// runOTLPCloudEnvironment prints the Settings text that points Claude Code
// cloud sessions' own exporter at this node (cloud-agents lane CA-B4,
// reworked by CA-C7: telemetrywire.CloudEnvironment). The whole export goes
// in the organization's server-managed settings, never a cloud environment's
// variables, because it carries a credential. It writes nothing and never
// prints a token (operator ruling D-359): the header placeholder names
// `observer cloud-session token mint`, the ship token the receiver accepts,
// and the shared receiver token's file is named only to warn it off. A node
// whose receiver is off or loopback-only gets the text plus a warning that
// it cannot receive yet.
func runOTLPCloudEnvironment(out io.Writer, configPath, endpoint string) error {
	cfg, err := config.Load(config.LoadOptions{GlobalPath: configPath})
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	text, err := telemetrywire.CloudEnvironment(telemetrywire.CloudEnvironmentInput{
		Endpoint: endpoint, TokenFile: otlpIngestTokenPath(cfg),
	})
	if err != nil {
		return fmt.Errorf("--otlp-cloud-endpoint: %w", err)
	}
	if !cfg.Ingest.OTel.Enabled || !cfg.Ingest.OTel.AllowNonLoopback || strings.TrimSpace(cfg.Ingest.OTel.HTTPAddr) == "" {
		fmt.Fprintln(out, "warning: this node's OTLP receiver is not open to the network yet ([ingest.otel] enabled, http_addr and allow_non_loopback); step 1 below does that.")
	}
	fmt.Fprintln(out, "Claude Code cloud sessions -> this node (Rail T telemetry, via server-managed settings). Nothing was written.")
	fmt.Fprintln(out)
	for i, step := range text.Steps {
		fmt.Fprintf(out, "%d. %s\n", i+1, step)
	}
	fmt.Fprintln(out)
	fmt.Fprintln(out, "Server-managed settings (merge into the env block; never a cloud environment's variables):")
	fmt.Fprint(out, text.ManagedSettingsJSON())
	fmt.Fprintln(out)
	fmt.Fprintln(out, "Network access: "+fmt.Sprintf(cloudsession.ClaudeCodeNetwork.Summary, text.NetworkHost))
	fmt.Fprintln(out)
	for _, n := range text.Notes {
		fmt.Fprintln(out, "note: "+n)
	}
	return nil
}
