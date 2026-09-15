package main

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"
)

// newKillSwitchCmd is the incident-response CLI surface for the kill_switches
// table (gap 5.3, docs/plans/next-session-kickoff-2026-09-12-paddle-signin-production.md).
// The switches already exist in the database (internal/cloudserver/store/control.go:
// KillSwitches, GlobalKillSwitchActive, SetKillSwitch) and are re-validated
// inside every submission and execution lease — but before this command the
// ONLY way to flip one in an incident was raw SQL against production Postgres
// through a temporary firewall rule (docs/cloud-intelligence-staging-launch-runbook.md
// §5a). This command uses the existing store seam only; it adds no new SQL.
func newKillSwitchCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "kill-switch",
		Short: "read or flip a Cloud Intelligence kill switch (incident response)",
		Long: "Kill switches gate both new job submissions (the API) and the execution\n" +
			"lease (the worker) — internal/cloudserver/store/control.go. A MISSING\n" +
			"switch row is treated as active (paused) — fail closed — never as open.\n\n" +
			"With no --route, `on`/`off` flips the GLOBAL free-tier switch\n" +
			"(scope='global', key='all'). With --route <route-id>, it flips that\n" +
			"route's own switch (scope='route', key=<route-id>) instead — the global\n" +
			"switch is untouched.",
	}
	cmd.AddCommand(newKillSwitchStatusCmd(), newKillSwitchSetCmd(true), newKillSwitchSetCmd(false))
	return cmd
}

func newKillSwitchStatusCmd() *cobra.Command {
	var route string
	cmd := &cobra.Command{
		Use:   "status",
		Short: "print the current kill-switch state",
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			s, err := openStore(ctx)
			if err != nil {
				return err
			}
			defer s.Pool().Close()

			r := strings.TrimSpace(route)
			if r == "" {
				active, err := s.GlobalKillSwitchActive(ctx)
				if err != nil {
					return err
				}
				fmt.Fprintf(cmd.OutOrStdout(), "global: %s\n", killSwitchLabel(active))
				return nil
			}
			st, err := s.KillSwitches(ctx, r)
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "global: %s (generation %d)\n",
				killSwitchLabel(st.GlobalActive), st.GlobalGeneration)
			fmt.Fprintf(cmd.OutOrStdout(), "route %q: %s (generation %d)\n",
				r, killSwitchLabel(st.RouteActive), st.RouteGeneration)
			return nil
		},
	}
	cmd.Flags().StringVar(&route, "route", "", "also report this route id's own switch (default: global only)")
	return cmd
}

func killSwitchLabel(active bool) string {
	if active {
		return "PAUSED (active=true)"
	}
	return "open (active=false)"
}

// newKillSwitchSetCmd builds the `on` (active=true, pause) / `off`
// (active=false, resume) verb. Both REQUIRE --yes, so a bare invocation never
// flips live state. kill_switches (migration 0002) carries no reason column
// and this command adds none (the D4 scope forbids a new migration for this);
// the --reason text is instead recorded in a content-free security_audit_events
// row (RecordAudit — the same seam every other auth/billing outcome uses) and
// printed to stdout, so the "who/when/why" trail lives in the existing audit
// table plus the operator's own incident log, never in a new column.
func newKillSwitchSetCmd(on bool) *cobra.Command {
	var (
		route  string
		reason string
		yes    bool
	)
	verb := "off"
	help := "resume submissions/execution for the scope"
	activeAfter := false
	if on {
		verb = "on"
		help = "pause submissions/execution for the scope"
		activeAfter = true
	}
	cmd := &cobra.Command{
		Use:   verb,
		Short: fmt.Sprintf("turn the kill switch %s (%s)", verb, help),
		RunE: func(cmd *cobra.Command, _ []string) error {
			if !yes {
				return fmt.Errorf("kill-switch %s requires --yes to confirm (this changes live incident-response state)", verb)
			}
			ctx := cmd.Context()
			s, err := openStore(ctx)
			if err != nil {
				return err
			}
			defer s.Pool().Close()

			scope, key := "global", "all"
			if r := strings.TrimSpace(route); r != "" {
				scope, key = "route", r
			}
			if err := s.SetKillSwitch(ctx, scope, key, activeAfter); err != nil {
				return fmt.Errorf("kill-switch %s: %w", verb, err)
			}

			reasonText := strings.TrimSpace(reason)
			if reasonText == "" {
				reasonText = "(no --reason given)"
			}
			detail := fmt.Sprintf(`{"scope":%q,"key":%q,"active":%v,"reason":%q}`,
				scope, key, activeAfter, reasonText)
			if auditErr := s.RecordAudit(ctx, "", "kill_switch_changed", detail); auditErr != nil {
				// The switch already flipped — the state change is real. Surface the
				// audit failure loudly instead of silently dropping the trail, but
				// don't pretend the flip itself didn't happen.
				fmt.Fprintf(cmd.ErrOrStderr(),
					"observer-cloud: kill-switch %s applied, but recording the audit row failed: %v\n", verb, auditErr)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "observer-cloud: kill-switch scope=%s key=%s -> active=%v (reason: %s)\n",
				scope, key, activeAfter, reasonText)
			return nil
		},
	}
	cmd.Flags().StringVar(&route, "route", "", "route id (default: the GLOBAL free-tier switch)")
	cmd.Flags().StringVar(&reason, "reason", "", "why (recorded in the security audit log + printed)")
	cmd.Flags().BoolVar(&yes, "yes", false, "required to confirm a live state change")
	return cmd
}
