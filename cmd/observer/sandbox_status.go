//go:build !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/dashapi"
	"github.com/marmutapp/superbased-observer/internal/diag"
	"github.com/marmutapp/superbased-observer/internal/sandbox"
	"github.com/marmutapp/superbased-observer/internal/sandboxbackend"
	"github.com/marmutapp/superbased-observer/internal/sandboximage"
	vocab "github.com/marmutapp/superbased-observer/internal/sandboxvocab"
)

// sandbox_status.go is `observer sandbox status` (sandbox plan v2 section 9,
// phase P1a): the same per-backend drop list the dashboard's probe API
// renders, from the one selection table, with each row's verification
// ("beta" when not live) and its computed capture level per tier. The verb
// belongs to terminals.sandbox (catalog Verbs), so the component gate
// refuses it with exit 3 while the module is not active, and an omit build
// registers it as not in this build.

func newSandboxCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "sandbox",
		Short: "Sandboxes and VMs: backends, availability and capture",
	}
	cmd.AddCommand(newSandboxStatusCmd(), newSandboxRelayGateCmd())
	for _, sub := range sandboxSubcommands {
		cmd.AddCommand(sub())
	}
	return cmd
}

// sandboxSubcommands are the per-driver subcommands a driver's own
// build-tagged file registers from init (`observer sandbox oci`), so this
// file never names a driver.
var sandboxSubcommands []func() *cobra.Command

func newSandboxStatusCmd() *cobra.Command {
	var (
		cfgPath string
		backend string
		asJSON  bool
	)
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show every isolation backend, why it is or is not available here, and the capture each network tier gives",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, gov, err := config.LoadGovernance(config.LoadOptions{GlobalPath: cfgPath})
			if err != nil {
				return fmt.Errorf("sandbox status: load config: %w", err)
			}
			// The managed pull's state, and the effective config it gives
			// (sandbox_managed.go), composed with the pins cfg was loaded
			// under; a stored read, no request.
			managed := sandboxManagedStatus(cmd.Context(), cfg, gov.PinsInForce)
			cfg.Terminal.Sandbox = cliEffectiveSandboxConfig(cmd.Context(), cfg, gov.PinsInForce)
			st := sandboxStatus(cmd.Context(), cfg)
			st.Managed = &managed
			if backend != "" {
				var keep []dashapi.SandboxBackendAvail
				for _, b := range st.Backends {
					if b.ID == backend {
						keep = append(keep, b)
					}
				}
				if len(keep) == 0 {
					return fmt.Errorf("sandbox status: no backend %q (backends: %s)", backend, strings.Join(backendIDs(st.Backends), ", "))
				}
				st.Backends = keep
			}
			if asJSON {
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				return enc.Encode(st)
			}
			return renderSandboxStatus(cmd.OutOrStdout(), st)
		},
	}
	cmd.Flags().StringVar(&cfgPath, "config", "", "config file (default ~/.observer/config.toml)")
	cmd.Flags().StringVar(&backend, "backend", "", "show one backend only")
	cmd.Flags().BoolVar(&asJSON, "json", false, "print JSON")
	return cmd
}

// sandboxStatusReport is the status the verb prints.
type sandboxStatusReport struct {
	Enabled  bool                          `json:"enabled"`
	Egress   string                        `json:"egress"`
	Host     string                        `json:"host"`
	Verdict  string                        `json:"verdict"`
	Reason   string                        `json:"reason,omitempty"`
	Backends []dashapi.SandboxBackendAvail `json:"backends"`
	// LiveRunUpdatePolicy is [terminal.sandbox].live_run_update_policy in
	// force (lane SBX-UPD): how soon an update waiting for live sandboxed
	// runs asks.
	LiveRunUpdatePolicy string `json:"live_run_update_policy"`
	// Managed is the org's managed pull on this node (`observer sandbox
	// status` only; nil in doctor).
	Managed *sandboxManagedRailStatus `json:"managed,omitempty"`
}

// sandboxStatus probes this host the way the dashboard does and renders
// every registry row through the selection table.
func sandboxStatus(ctx context.Context, cfg config.Config) sandboxStatusReport {
	if ctx == nil {
		ctx = context.Background()
	}
	tcfg := cfg.Terminal.Sandbox
	egress, err := sandbox.ResolveEgress(tcfg.Egress)
	if err != nil {
		egress = sandbox.EgressProfile{Mode: sandbox.Egress(tcfg.Egress)}
	}
	exe, _ := os.Executable()
	home, _ := os.UserHomeDir()
	r := &sandboxRuntime{cfg: tcfg, egress: egress, observerDir: filepath.Join(home, ".observer"), observerBin: exe}
	// The drivers this node selects (lane SBX-P3A); a driver whose backend
	// is not listed answers without probing.
	r.buildSandboxDrivers(cfg)
	pctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	av := sandbox.Probe(r.sandboxEnv(pctx))
	backends := sandboxBackendListWith(tcfg, av, sourceIDs(r.sources()), vocab.Tier(egress.Mode), r.driverProbes(pctx))
	av = reconcileLegacyProbe(av, backends)
	// The overall verdict follows the drivers this platform registers, the
	// way the probe API's does (macOS live run 2026-10-22, D2: a Mac with
	// Seatbelt available printed bwrap's unsupported_platform).
	av = r.preferDriverInLegacy(av, backends)
	av = sandboxPlatformOverall(av, backends, sandboxHostKind())
	return sandboxStatusReport{
		Enabled:  tcfg.Enabled,
		Egress:   string(egress.Mode),
		Host:     string(sandboxHostKind()),
		Verdict:  av.Verdict,
		Reason:   av.Reason,
		Backends: backends,

		LiveRunUpdatePolicy: normalizeLiveRunPolicy(tcfg.LiveRunUpdatePolicy),
	}
}

// liveRunPolicyLine is the status and doctor line for the policy.
func liveRunPolicyLine(policy string) string {
	if policy == liveRunPolicyAskImmediately {
		return "Updates while sandboxed runs are live: ask_immediately (an update waiting for them asks at once; it never ends them on its own)"
	}
	return "Updates while sandboxed runs are live: defer (an update waiting for them asks in the dashboard banner; it never ends them on its own)"
}

// renderSandboxStatus prints the report as a table plus one detail line per
// unavailable or beta backend.
func renderSandboxStatus(w io.Writer, st sandboxStatusReport) error {
	state := "on"
	if !st.Enabled {
		state = "off ([terminal.sandbox] enabled = false)"
	}
	fmt.Fprintf(w, "Sandboxes and VMs on %s: %s, network tier %s\n", st.Host, state, st.Egress)
	// The overall verdict, which used to be printed only with --json (live
	// check macOS 2026-10-22, D1: an honest unsupported_platform appeared
	// nowhere in the text).
	if st.Enabled && st.Verdict != "" {
		switch {
		case st.Verdict == sandbox.VerdictAvailable:
			fmt.Fprintln(w, "Overall: available")
		case st.Reason != "":
			fmt.Fprintf(w, "Overall: %s: %s\n", st.Verdict, st.Reason)
		default:
			fmt.Fprintf(w, "Overall: %s\n", st.Verdict)
		}
	}
	if st.Enabled && st.LiveRunUpdatePolicy != "" {
		fmt.Fprintln(w, liveRunPolicyLine(st.LiveRunUpdatePolicy))
	}
	if st.Managed != nil {
		fmt.Fprintln(w, sandboxManagedStatusLine(*st.Managed))
	}
	fmt.Fprintln(w)
	tw := tabwriter.NewWriter(w, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "BACKEND\tCLASS\tLOCATION\tSTATUS\tCAPTURE ("+st.Egress+")")
	for _, b := range st.Backends {
		status := sandboxStatusWord(b)
		if b.Beta && b.Maturity != "planned" {
			status += " (beta)"
		}
		if b.Maturity == "planned" {
			status = "planned (" + b.Phase + ")"
		}
		capture := b.CaptureByTier[st.Egress]
		if capture == "" {
			capture = "-"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", b.ID, b.Class, b.Location, status, capture)
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	fmt.Fprintln(w)
	for _, b := range st.Backends {
		if b.Maturity == "planned" {
			continue
		}
		if !b.Available {
			fmt.Fprintf(w, "%s: not available (rule %s, %s): %s\n", b.ID, b.Rule, b.Verdict, b.Reason)
		}
		if b.Beta {
			ref := ""
			if b.RegisterRef != "" {
				ref = "; register row " + b.RegisterRef
			}
			fmt.Fprintf(w, "%s: beta: built from the vendor's documentation or outside its tested versions, not yet proven on this host%s\n", b.ID, ref)
		}
		if b.Hint != "" {
			fmt.Fprintf(w, "%s: note: %s\n", b.ID, b.Hint)
		}
		tiers := make([]string, 0, len(b.CaptureByTier))
		for t := range b.CaptureByTier {
			tiers = append(tiers, t)
		}
		sort.Strings(tiers)
		var parts []string
		for _, t := range tiers {
			parts = append(parts, t+" "+b.CaptureByTier[t])
		}
		if len(parts) > 0 {
			fmt.Fprintf(w, "%s: capture per tier for a proxy-routed tool holding its own login: %s\n", b.ID, strings.Join(parts, ", "))
		}
	}
	return nil
}

// sandboxStatusWord is a backend's STATUS cell: available, the drop's
// verdict, or "revoked" when the drop is a revoked signed content set
// (R-015), whose detail line names the revoking manifest.
func sandboxStatusWord(b dashapi.SandboxBackendAvail) string {
	switch {
	case b.Available:
		return "available"
	case sandboximage.IsRevokedRefusal(b.Reason):
		return "revoked"
	}
	return b.Verdict
}

func backendIDs(bs []dashapi.SandboxBackendAvail) []string {
	out := make([]string, 0, len(bs))
	for _, b := range bs {
		out = append(out, b.ID)
	}
	return out
}

// sandboxDoctorChecks is the sandbox module's doctor section (sandbox plan
// v2 section 11.6): one `sandbox.<backend>` check per offered backend this
// build compiles, from the same probe and selection drops as `observer
// sandbox status`. With the module not active it is one line and runs no
// probe.
func sandboxDoctorChecks(ctx context.Context, cfg config.Config) []diag.Check {
	checks, _ := sandboxDoctorSection(ctx, cfg, "")
	return checks
}

// sandboxDoctorSection is sandboxDoctorChecks plus whether this node can
// build a sandbox right now (the module is active, the master switch is on
// and the overall probe verdict is available), from the same one probe.
// Doctor passes it to the hook_block lines, so a node where no sandbox
// exists (macOS today) never reads sandbox_enforce (live check macOS
// 2026-10-22, D2). configPath is doctor's config file ("" for the default),
// from which the skip_repo_scan line reads the governance pins in force.
func sandboxDoctorSection(ctx context.Context, cfg config.Config, configPath string) ([]diag.Check, bool) {
	if !sandboxModuleActive(componentSnapshotForConfig(cfg)) {
		return []diag.Check{{
			Name: "sandbox", Status: diag.StatusOK,
			Message: "Sandboxes and VMs: not active; Settings > Components",
		}}, false
	}
	st := sandboxStatus(ctx, cfg)
	var out []diag.Check
	for _, b := range st.Backends {
		if b.Maturity == "planned" {
			continue
		}
		// A row that never runs on this host (the macOS rows on Linux, lane
		// SBX-P5) is listed by `observer sandbox status`, not checked here.
		if row, ok := sandboxbackend.Get(b.ID); ok && !row.RunsOn(sandboxHostKind()) {
			continue
		}
		out = append(out, sandboxDoctorCheck(st, b))
	}
	pins, pinsKnown := sandboxDoctorGovernancePins(configPath)
	out = append(out, sandboxSkipRepoScanDoctorChecks(ctx, cfg, pins, pinsKnown)...)
	eff := cliEffectiveSandboxConfig(ctx, cfg, pins)
	out = append(out, sandboxInstallScriptsDoctorChecks(eff)...)
	out = append(out, sandboxSignInDoctorChecks(eff)...)
	if st.Enabled {
		out = append(out, diag.Check{Name: "sandbox.live_run_update_policy", Status: diag.StatusOK, Message: liveRunPolicyLine(st.LiveRunUpdatePolicy)})
	}
	return out, st.Enabled && st.Verdict == sandbox.VerdictAvailable
}

// sandboxDoctorCheck renders one backend row as a doctor check: available
// is OK (beta is said, never shown as a plain pass), the master switch off
// is OK and says so, anything else is a warning naming the rule and the
// reason.
func sandboxDoctorCheck(st sandboxStatusReport, b dashapi.SandboxBackendAvail) diag.Check {
	c := diag.Check{Name: "sandbox." + b.ID}
	switch {
	case b.Available:
		c.Status = diag.StatusOK
		c.Message = b.Label + " available (" + b.Class + ", network tier " + st.Egress + ", capture " + b.CaptureByTier[st.Egress] + ")"
	case !st.Enabled:
		c.Status = diag.StatusOK
		c.Message = b.Label + " off: [terminal.sandbox] enabled = false"
	default:
		c.Status = diag.StatusWarn
		c.Message = b.Label + " not available: " + b.Reason
		c.Details = append(c.Details, "selection rule "+b.Rule+" ("+b.Verdict+")")
	}
	if b.Beta {
		c.Details = append(c.Details, "beta: built from the vendor's documentation or outside its tested versions, not yet proven on this host")
	}
	if b.Hint != "" {
		c.Details = append(c.Details, "note: "+b.Hint)
	}
	return c
}
