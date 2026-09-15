package main

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/intelligence/modelvalue"
	"github.com/marmutapp/superbased-observer/internal/routing"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// `observer routing savings|explain|advise` (§R17.3, §R17.6): the
// decision-log transparency surfaces. Savings honesty: "realized" is
// the decision-time estimate on APPLIED rewrites (the calibration loop
// §R18.3 grades the estimator against outcomes); "would-have" is the
// same estimate on unapplied advise decisions. Both carry §R7.2 error
// bars (mean per decision ± 95% CI) — never a bare point claim.

func parseWindowDays(window string) (int, error) {
	w := strings.TrimSuffix(strings.TrimSpace(window), "d")
	days, err := strconv.Atoi(w)
	if err != nil || days <= 0 {
		return 0, fmt.Errorf("invalid --window %q (use e.g. 30d)", window)
	}
	return days, nil
}

func newRoutingSavingsCmd() *cobra.Command {
	var (
		configPath string
		window     string
		jsonOut    bool
	)
	cmd := &cobra.Command{
		Use:   "savings",
		Short: "Routing savings report: realized + would-have, by project/tool/tier, with error bars (§R17.3)",
		Long: "Groups the window's routing decisions by project, tool, and the original\n" +
			"model's tier. 'realized' sums decision-time estimates on APPLIED rewrites\n" +
			"(enforce mode); 'would-have' sums the same estimates on unapplied advise\n" +
			"decisions. Both are estimates graded by the §R18.3 calibration loop, not\n" +
			"provider-invoice deltas.\n\n" +
			"Reading the error bars: '$/decision = m ± c' is the group's mean\n" +
			"per-decision saving with a 95% confidence interval over the per-decision\n" +
			"distribution (§R7.2 error-bar discipline — never a bare point claim).\n" +
			"A wide interval means few or noisy decisions: treat the mean as noise\n" +
			"until the interval tightens, and treat overlapping intervals between\n" +
			"groups as 'no detectable difference'.",
		RunE: func(cmd *cobra.Command, args []string) error {
			days, err := parseWindowDays(window)
			if err != nil {
				return err
			}
			_, database, cleanup, err := loadConfigAndDB(cmd.Context(), configPath)
			if err != nil {
				return err
			}
			defer cleanup()
			s := store.New(database)
			rows, err := s.SelectRouterDecisions(cmd.Context(), time.Now().AddDate(0, 0, -days), 0)
			if err != nil {
				return err
			}
			rep := store.BuildRouterSavingsReport(rows, days, routing.NewTierResolver().Table())
			if jsonOut {
				body, _ := json.MarshalIndent(rep, "", "  ")
				fmt.Fprintln(cmd.OutOrStdout(), string(body))
				return nil
			}
			out := cmd.OutOrStdout()
			fmt.Fprintf(out, "Routing savings — last %dd: %d decisions, realized $%.2f (est.), would-have $%.2f\n",
				rep.WindowDays, rep.Decisions, rep.RealizedUSD, rep.WouldHaveUSD)
			printGroups(out, "by project", rep.ByProject)
			printGroups(out, "by tool", rep.ByTool)
			printGroups(out, "by tier", rep.ByTier)
			fmt.Fprintf(out, "\nnote: %s\n", rep.Note)
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "Path to config.toml")
	cmd.Flags().StringVar(&window, "window", "30d", "Lookback window (e.g. 30d)")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "Emit JSON")
	return cmd
}

func printGroups(out interface{ Write([]byte) (int, error) }, title string, groups []store.RouterSavingsGroup) {
	fmt.Fprintf(out, "\n%s:\n", title)
	if len(groups) == 0 {
		fmt.Fprintln(out, "  (no decisions)")
		return
	}
	for _, g := range groups {
		fmt.Fprintf(out, "  %-28s n=%-5d reroutes=%-5d realized=$%-9.2f would-have=$%-9.2f $/decision=%.4f ± %.4f\n",
			g.Key, g.Decisions, g.Reroutes, g.RealizedUSD, g.WouldHaveUSD, g.MeanPerDecision, g.CI95PerDecision)
	}
}

func newRoutingExplainCmd() *cobra.Command {
	var configPath string
	cmd := &cobra.Command{
		Use:   "explain <decision-id>",
		Short: "Explain one routing decision: why, counterfactual dollars, cache math (§R17.6)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			id, err := strconv.ParseInt(args[0], 10, 64)
			if err != nil {
				return fmt.Errorf("invalid decision id %q", args[0])
			}
			_, database, cleanup, err := loadConfigAndDB(cmd.Context(), configPath)
			if err != nil {
				return err
			}
			defer cleanup()
			s := store.New(database)
			d, ok, err := s.SelectRouterDecisionByID(cmd.Context(), id)
			if err != nil {
				return err
			}
			if !ok {
				return fmt.Errorf("decision %d not found", id)
			}
			out := cmd.OutOrStdout()
			fmt.Fprintf(out, "decision %d  (%s, channel %s, %s)\n", d.ID, d.Mode, d.Channel, d.Timestamp.Format(time.RFC3339))
			fmt.Fprintf(out, "  session     %s\n", d.SessionID)
			if d.ProjectRoot != "" {
				fmt.Fprintf(out, "  project     %s (%s)\n", filepath.Base(d.ProjectRoot), d.Tool)
			}
			fmt.Fprintf(out, "  turn kind   %s\n", d.TurnKind)
			fmt.Fprintf(out, "  model       %s -> %s (applied=%v)\n", d.OriginalModel, d.SelectedModel, d.Applied)
			fmt.Fprintf(out, "  why         %s\n", strings.Join(d.ReasonCodes, ", "))
			fmt.Fprintf(out, "  policy      %s @ %s\n", d.PolicyName, d.PolicyHash)
			fmt.Fprintf(out, "  cache math  est. savings $%.4f net of cache forfeit $%.4f (%s)\n",
				d.EstSavingsUSD, d.CacheForfeitUSD, d.EstimateVersion)
			if d.APITurnID != nil {
				fmt.Fprintf(out, "  api turn    %d\n", *d.APITurnID)
			} else {
				fmt.Fprintln(out, "  api turn    (none — the turn never landed or predates linkage)")
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "Path to config.toml")
	return cmd
}

func newRoutingAdviseCmd() *cobra.Command {
	var (
		configPath string
		limit      int
		jsonOut    bool
	)
	cmd := &cobra.Command{
		Use:   "advise",
		Short: "Recent routing decisions feed — what the router did or would have done (§R17.6)",
		RunE: func(cmd *cobra.Command, args []string) error {
			_, database, cleanup, err := loadConfigAndDB(cmd.Context(), configPath)
			if err != nil {
				return err
			}
			defer cleanup()
			s := store.New(database)
			rows, err := s.SelectRouterDecisions(cmd.Context(), time.Now().AddDate(0, 0, -30), limit)
			if err != nil {
				return err
			}
			if jsonOut {
				body, _ := json.MarshalIndent(rows, "", "  ")
				fmt.Fprintln(cmd.OutOrStdout(), string(body))
				return nil
			}
			out := cmd.OutOrStdout()
			if len(rows) == 0 {
				fmt.Fprintln(out, "no routing decisions in the last 30d — enable [routing] and route traffic through the proxy")
				return nil
			}
			for _, d := range rows {
				marker := "would"
				if d.Applied {
					marker = "APPLIED"
				}
				fmt.Fprintf(out, "%6d  %s  %-12s %-8s %s -> %s  $%.4f  [%s]\n",
					d.ID, d.Timestamp.Format("01-02 15:04"), d.TurnKind, marker,
					d.OriginalModel, d.SelectedModel, d.EstSavingsUSD, strings.Join(d.ReasonCodes, ","))
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "Path to config.toml")
	cmd.Flags().IntVar(&limit, "limit", 20, "Max decisions to show")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "Emit JSON")
	return cmd
}

func newRoutingShadowCmd() *cobra.Command {
	var (
		configPath string
		window     string
		jsonOut    bool
	)
	cmd := &cobra.Command{
		Use:   "shadow",
		Short: "Advise-shadow report: would-have savings vs quality flags — the §R18.2 promotion surface",
		RunE: func(cmd *cobra.Command, args []string) error {
			days, err := parseWindowDays(window)
			if err != nil {
				return err
			}
			cfg, database, cleanup, err := loadConfigAndDB(cmd.Context(), configPath)
			if err != nil {
				return err
			}
			defer cleanup()
			s := store.New(database)
			rows, err := s.SelectRouterDecisions(cmd.Context(), time.Now().AddDate(0, 0, -days), 0)
			if err != nil {
				return err
			}
			// Parity evidence from the Model Value Report over the same
			// window — the §R18.1 quality-risk definition.
			facts, err := s.LoadModelValueFacts(cmd.Context(), modelvalue.LoadOptions{WindowDays: days})
			if err != nil {
				return err
			}
			facts.Price = routingPriceFn(acquireProcessCostEngine(cmd.Context(), cfg, database, slog.Default()))
			evidence := modelvalue.Build(facts, modelvalue.Options{}).EvidenceByKindTier()

			rep := store.BuildAdviseShadowReport(rows, evidence, routing.NewTierResolver().Table(), days)
			if jsonOut {
				body, _ := json.MarshalIndent(rep, "", "  ")
				fmt.Fprintln(cmd.OutOrStdout(), string(body))
				return nil
			}
			out := cmd.OutOrStdout()
			fmt.Fprintf(out, "Advise shadow — last %dd: %d advise decisions, %d would reroute\n",
				rep.WindowDays, rep.AdviseDecisions, rep.WouldReroute)
			fmt.Fprintf(out, "  would have saved   $%.2f (net of $%.2f cache forfeits)\n", rep.WouldSaveUSD, rep.CacheForfeitUSD)
			fmt.Fprintf(out, "  quality flags      %d (%d moves evidence-backed)\n", rep.QualityFlags, rep.EvidenceBackedMoves)
			for kind, n := range rep.QualityByKind {
				fmt.Fprintf(out, "    %-14s %d\n", kind, n)
			}
			if len(rep.HoldsByReason) > 0 {
				fmt.Fprintln(out, "  holds by reason:")
				for reason, n := range rep.HoldsByReason {
					fmt.Fprintf(out, "    %-22s %d\n", reason, n)
				}
			}
			if rep.ReadyToPromote {
				fmt.Fprintln(out, "  gate read: savings with ZERO quality flags — promotion evidence present (operator-judged, §R22)")
			} else {
				fmt.Fprintln(out, "  gate read: not yet — needs ≥50 decisions, positive savings, zero quality flags (§R22)")
			}
			fmt.Fprintf(out, "\nnote: %s\n", rep.Note)
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "Path to config.toml")
	cmd.Flags().StringVar(&window, "window", "30d", "Lookback window (e.g. 30d)")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "Emit JSON")
	return cmd
}

func newRoutingImportBenchmarkCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "import-benchmark <file>",
		Short: "Validate a §R7.3 benchmark file and print the tier placements it derives (dry-run)",
		Long: "Parses a versioned RouterBench/RouterEval-format coding-score file and\n" +
			"prints the tier placements it would derive. To ACTIVATE an import, add\n" +
			"the file to [routing] benchmark_files in config.toml — placements load\n" +
			"at daemon start with provenance logged; explicit [routing.tiers]\n" +
			"overrides always win.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			data, err := os.ReadFile(args[0])
			if err != nil {
				return err
			}
			imp, err := routing.ImportBenchmarks(data)
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			fmt.Fprintf(out, "benchmark import OK: %s\n\n", imp.Provenance())
			models := make([]string, 0, len(imp.Overrides))
			for m := range imp.Overrides {
				models = append(models, m)
			}
			sort.Strings(models)
			for _, m := range models {
				fmt.Fprintf(out, "  %-32s -> %s\n", m, imp.Overrides[m])
			}
			fmt.Fprintln(out, "\nactivate via [routing] benchmark_files in config.toml; explicit [routing.tiers] overrides win.")
			return nil
		},
	}
}
