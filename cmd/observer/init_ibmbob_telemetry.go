package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"

	"github.com/marmutapp/superbased-observer/internal/hook"
)

// runIBMBobVendorTelemetryInit is `observer init
// --ibm-bob-disable-vendor-telemetry` (AP-135, DECIDED 2026-10-24: opt-in on
// an individual node). It turns IBM Bob's own telemetry off in each Bob
// settings file this host can see (the native ~/.bob and, from WSL, the
// Windows user's .bob), or with --uninstall hands the setting back to Bob's
// default. The setting and the refusal rule are the hook package's
// (internal/hook/ibmbob_telemetry.go), which already owns that file.
func runIBMBobVendorTelemetryInit(out io.Writer, binary string, dryRun, uninstall bool) error {
	reg, err := hook.NewRegistry(hook.Options{BinaryPath: binary, DryRun: dryRun})
	if err != nil {
		return err
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("--ibm-bob-disable-vendor-telemetry: %w", err)
	}
	var targets []string
	if fi, err := os.Stat(filepath.Join(home, ".bob")); err == nil && fi.IsDir() {
		targets = append(targets, "ibm-bob")
	}
	if runtime.GOOS != "windows" {
		// The Windows user's .bob seen from WSL (a Windows host's own .bob
		// is the native target above).
		targets = append(targets, "ibm-bob-windows")
	}
	failed, wrote := false, false
	for _, t := range targets {
		res := reg.IBMBobVendorTelemetry(t, !uninstall)
		switch {
		case res.Error != nil:
			fmt.Fprintf(out, "%-12s telemetry ✗ %v\n", t, res.Error)
			failed = true
			continue
		case res.Skipped:
			if t == "ibm-bob" || res.Reason != "no Windows-side .bob detected" {
				fmt.Fprintf(out, "%-12s telemetry skipped - %s\n", t, res.Reason)
			}
			continue
		}
		for _, w := range res.Warnings {
			fmt.Fprintf(out, "%-12s telemetry ! %s\n", t, w)
		}
		wrote = true
		verb := map[bool]string{true: "turned IBM Bob's own telemetry off", false: "handed telemetry.enabled back to Bob's default"}[!uninstall]
		switch {
		case !res.Changed:
			fmt.Fprintf(out, "%-12s telemetry ✓ already as asked (%s)\n", t, res.ConfigPath)
		case res.DryRun:
			fmt.Fprintf(out, "%-12s telemetry ✓ would have %s (%s)\n", t, verb, res.ConfigPath)
		default:
			fmt.Fprintf(out, "%-12s telemetry ✓ %s (%s)\n", t, verb, res.ConfigPath)
		}
	}
	if !wrote && !failed {
		fmt.Fprintln(out, "ibm-bob      telemetry: no IBM Bob settings found on this host (~/.bob)")
	}
	if !uninstall && wrote {
		fmt.Fprintln(out, "             Note: Bob gates every telemetry client on this setting, so an OTLP export\n"+
			"             (OTEL_EXPORTER_OTLP_ENDPOINT) stops too, and Bobalytics loses this node.")
	}
	if failed {
		return exitErr(1)
	}
	return nil
}
