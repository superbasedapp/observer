package main

import (
	"fmt"
	"log/slog"

	"github.com/spf13/cobra"
)

// obs_egress.go is the `observer obs egress` CLI (G22 Plane-A policy egress
// routing). Like the admission + alerts CLIs it funnels every obs access
// through the build-tagged wrappers in obs_wire.go (obsEgressStatusCLI /
// obsEgressLintCLI), so this file imports NO internal/obs package — the
// separability boundary (obs plan §2.3/§11, tests/invariant/obs_boundary_test.go).
//
// Egress is Plane-A governance of an admin-hosted app's END-USER traffic
// (distinct from the Plane-B internal/guard egress policy over the developer's
// OWN coding-agent tool calls). The node dashboard's Egress page (/egress,
// backed by GET /api/obs/egress/*) is this CLI's read-only peer — the audit
// log is NODE-LOCAL (never pushed, design §8), so the node surfaces are its
// only view; web2 carries no egress page.

// newObsEgressCmd is `observer obs egress`: bare invocation prints status
// (mode / targets / rules / recent decisions + hash-chain verify); the `lint`
// subcommand validates the [observability.egress] config.
func newObsEgressCmd() *cobra.Command {
	var configPath string
	var limit int
	cmd := &cobra.Command{
		Use:   "egress",
		Short: "AI Apps egress routing: status, recent decisions, and config lint",
		Long: "Show the AI Apps policy egress-routing config ([observability.egress]) -\n" +
			"mode (off/advise/enforce), typed upstream targets, and rules - plus the\n" +
			"most-recent recorded egress decisions with the realized outcome the proxy\n" +
			"reported back, and a tamper-evident hash-chain verification of the\n" +
			"obs_egress_decisions audit log (requires [observability] enabled).\n\n" +
			"Egress composes the admission verdict with a routing action: route a\n" +
			"flagged request to an on-prem model, swap a budget-pressured end-user to a\n" +
			"cheaper model, or deny. advise evaluates + records but never applies;\n" +
			"enforce applies on the proxy path. This governs your AI apps' end-user\n" +
			"traffic - distinct from `observer guard` (the developer's own\n" +
			"coding-agent tool calls). The audit log is NODE-LOCAL, never pushed.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, database, cleanup, err := loadConfigAndDB(cmd.Context(), configPath)
			if err != nil {
				return err
			}
			defer cleanup()
			if err := requireObsEnabled(cfg); err != nil {
				return err
			}
			st, err := obsEgressStatusCLI(cmd.Context(), cfg, database, slog.Default(), limit)
			if err != nil {
				return err
			}
			printObsEgressStatus(cmd, st)
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "path to config.toml")
	cmd.Flags().IntVar(&limit, "limit", 20, "max recent egress decisions to show")

	lint := &cobra.Command{
		Use:   "lint",
		Short: "Validate the [observability.egress] policy (compile + static lint)",
		Long: "Compile the [observability.egress] policy the way the daemon does\n" +
			"(enforce-strict) and run the static lint, reporting every finding. A\n" +
			"FATAL finding means the policy would fail to install - the daemon then\n" +
			"disables egress and keeps admission running (fail-safe). Exit is non-zero\n" +
			"when any finding is fatal.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, _, cleanup, err := loadConfigAndDB(cmd.Context(), configPath)
			if err != nil {
				return err
			}
			defer cleanup()
			issues, fatal := obsEgressLintCLI(cfg)
			out := cmd.OutOrStdout()
			if len(issues) == 0 {
				fmt.Fprintln(out, "egress policy: OK (no lint findings)")
				return nil
			}
			for _, is := range issues {
				fmt.Fprintf(out, "  %s\n", is)
			}
			if fatal {
				return fmt.Errorf("egress policy has fatal lint findings")
			}
			return nil
		},
	}
	lint.Flags().StringVar(&configPath, "config", "", "path to config.toml")
	cmd.AddCommand(lint)
	return cmd
}

// printObsEgressStatus renders the egress status.
func printObsEgressStatus(cmd *cobra.Command, st obsEgressStatus) {
	out := cmd.OutOrStdout()
	fmt.Fprintf(out, "egress:           %s\n", enabledLabel(st.Enabled))
	fmt.Fprintf(out, "mode:             %s\n", st.Mode)
	if st.PolicyHash != "" {
		short := st.PolicyHash
		if len(short) > 12 {
			short = short[:12]
		}
		fmt.Fprintf(out, "policy hash:      %s\n", short)
	}
	if st.CompileErr != "" {
		fmt.Fprintf(out, "compile:          ERROR - %s\n", st.CompileErr)
	}

	fmt.Fprintf(out, "\ntargets (%d):\n", len(st.Targets))
	if len(st.Targets) == 0 {
		fmt.Fprintln(out, "  (none - enforce-mode route_to_upstream needs a typed target)")
	}
	for _, t := range st.Targets {
		fmt.Fprintf(out, "  %-16s %-10s %s\n", t.ID, t.Shape, t.URL)
	}

	fmt.Fprintf(out, "\nrules (%d):\n", len(st.Rules))
	if len(st.Rules) == 0 {
		fmt.Fprintln(out, "  (none configured - add [[observability.egress.rules]] entries)")
	}
	for _, r := range st.Rules {
		unavail := r.OnUnavailable
		if unavail == "" {
			unavail = "fail_open"
		}
		fmt.Fprintf(out, "  %-20s %-32s on_unavailable=%s\n", r.Name, r.Action, unavail)
	}

	if len(st.Counts) > 0 {
		fmt.Fprintf(out, "\ndecisions by action:\n")
		for action, n := range st.Counts {
			fmt.Fprintf(out, "  %-16s %d\n", action, n)
		}
	}

	fmt.Fprintf(out, "\naudit chain:      %d rows, %s", st.ChainRows, chainLabel(st.ChainOK))
	if !st.ChainOK && st.ChainDetail != "" {
		fmt.Fprintf(out, " (%s)", st.ChainDetail)
	}
	fmt.Fprintln(out)

	fmt.Fprintf(out, "\nrecent decisions (%d):\n", len(st.Recent))
	if len(st.Recent) == 0 {
		fmt.Fprintln(out, "  (none)")
	}
	for _, d := range st.Recent {
		realized := d.RealizedOutcome
		if realized == "" {
			realized = "-"
		}
		fmt.Fprintf(out, "  %s  %-8s %-20s %-28s verdict=%s applied=%t fail_closed=%t realized=%s\n",
			d.TS, d.Mode, d.RuleName, d.Action, d.VerdictDecision, d.Applied, d.FailClosed, realized)
	}
}

// chainLabel renders the hash-chain verification state.
func chainLabel(ok bool) string {
	if ok {
		return "intact"
	}
	return "BROKEN"
}
