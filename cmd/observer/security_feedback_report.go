//go:build !sbo_omit_security

package main

import (
	"fmt"
	"slices"
	"strings"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/components"
	"github.com/marmutapp/superbased-observer/internal/componentstate"
	"github.com/marmutapp/superbased-observer/internal/secframework"
)

// security_feedback_report.go is `observer security report` (security
// pillar plan sections 5.12 and 7.8; lane sec-h): the node-local framework
// coverage report. Read-only and runs nothing: it reads the config's
// component selection and this binary's catalog, opens no database and
// starts no process. The fleet report waits for security Phase E.

// securityFrameworkFacts are the report's predicates over snap.
func securityFrameworkFacts(snap componentstate.Snapshot) secframework.Facts {
	return secframework.Facts{
		Built: func(id string) bool {
			// In the catalog AND compiled into this binary: a component an
			// omit tag compiled out is not built, whatever its decision.
			if _, ok := components.Get(id); !ok || !slices.Contains(snap.Compiled, id) {
				return false
			}
			d, ok := snap.Decision(id)
			return !ok || d.State != components.StateAbsent
		},
		Selected: func(id string) bool { return securitySelected(snap, id) },
	}
}

// statusWords renders a status for the text report.
var statusWords = map[secframework.Status]string{
	secframework.StatusCovered:     "covered",
	secframework.StatusPartial:     "partial",
	secframework.StatusNotSelected: "not selected",
	secframework.StatusNotBuilt:    "not built",
}

func newSecurityReportCmd() *cobra.Command {
	var configPath, framework string
	var asJSON bool
	names := make([]string, 0, 4)
	for _, f := range secframework.Frameworks() {
		names = append(names, string(f))
	}
	cmd := &cobra.Command{
		Use:   "report",
		Short: "Show which of Observer's controls address the framework ids of the security plan (read-only)",
		Long: "A node-local coverage report: for OWASP Agentic Top 10 2026 (ASI02, ASI04, ASI05),\n" +
			"OWASP LLM Top 10 2026 (LLM03) and MITRE ATLAS v2026.09 (AML.T0081, AML.T0083, AML.M0029,\n" +
			"AML.M0030), which Observer controls address the id and whether they are built into this\n" +
			"binary and selected here. The mapping is Observer's own, in its own words; it is not the\n" +
			"frameworks' text and not a compliance claim. It reads the config only and runs nothing.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			pick, ok := secframework.ParseFramework(framework)
			if !ok {
				return fmt.Errorf("unknown --framework %q (all, %s)", framework, strings.Join(names, ", "))
			}
			rows := secframework.Report(securityFrameworkFacts(componentSnapshotFor(configPath)), pick...)
			if asJSON {
				return writeSecurityJSON(cmd.OutOrStdout(), map[string]any{"rows": rows, "scope": "node"})
			}
			w := cmd.OutOrStdout()
			fmt.Fprintln(w, "Framework coverage on this node (Observer's mapping; not the frameworks' text, not a compliance claim)")
			last := secframework.Framework("")
			for _, r := range rows {
				if r.Framework != last {
					fmt.Fprintf(w, "\n%s\n", r.Framework)
					last = r.Framework
				}
				fmt.Fprintf(w, "  %-10s %-13s %s\n", r.ID, statusWords[r.Status], r.Scope)
				for _, g := range r.Groups {
					state := "not built"
					switch {
					case len(g.Selected) > 0:
						state = "selected: " + strings.Join(g.Selected, ", ")
					case len(g.Built) > 0:
						state = "not selected: " + strings.Join(g.Built, ", ")
					}
					fmt.Fprintf(w, "             - %s (%s)\n", g.What, state)
				}
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "path to config.toml")
	cmd.Flags().StringVar(&framework, "framework", "all", "all, "+strings.Join(names, ", "))
	cmd.Flags().BoolVar(&asJSON, "json", false, "print JSON")
	return cmd
}
