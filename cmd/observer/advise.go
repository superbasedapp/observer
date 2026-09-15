package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/intelligence/advisor"
	"github.com/marmutapp/superbased-observer/internal/selfobs/conformance"
	"github.com/marmutapp/superbased-observer/internal/selfobs/run"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// newAdviseCmd wires `observer advise` — the suggestions engine (spec
// §15.7): prescriptive, dollar-quantified recommendations computed locally
// from captured data. Distinct from `observer suggest`, which writes
// instruction-file blocks.
func newAdviseCmd() *cobra.Command {
	var (
		configPath  string
		projectRoot string
		days        int
		jsonOut     bool
		digest      bool
	)
	cmd := &cobra.Command{
		Use:   "advise",
		Short: "Prescriptive cost/quality suggestions from captured activity",
		Long: "Runs the advisor engine over the captured corpus and prints ranked,\n" +
			"evidence-backed suggestions with estimated avoidable spend. Detector\n" +
			"thresholds are Phase-0 calibrated (docs/plans/advisor-calibration-\n" +
			"2026-06-10.md); all math is shown in each suggestion's evidence.",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, database, cleanup, err := loadConfigAndDB(cmd.Context(), configPath)
			if err != nil {
				return err
			}
			defer cleanup()
			if !cfg.Advisor.Enabled {
				return fmt.Errorf("advisor is disabled ([advisor] enabled = false in config)")
			}
			if days <= 0 {
				days = cfg.Advisor.WindowDays
			}
			guardMode, routingMode, shadow := advisorPostureInputs(cmd.Context(), cfg, store.New(database), days)
			rep, err := advisor.Run(cmd.Context(), database, advisor.Options{
				WindowDays:    days,
				ProjectRoot:   projectRoot,
				MinConfidence: cfg.Advisor.MinConfidence,
				MinSavingsUSD: cfg.Advisor.MinSavingsUSD,
				CostEngine:    acquireProcessCostEngine(cmd.Context(), cfg, database, slog.Default()),
				GuardMode:     guardMode,
				RoutingMode:   routingMode,
				RoutingShadow: shadow,
			})
			if err != nil {
				return err
			}
			if cfg.SelfObs.Enabled {
				sink, cleanup, serr := buildSelfObsSink(cfg, slog.Default())
				if serr == nil {
					emitSelfObsRun(sink, run.DecisionRun{
						RunID: fmt.Sprintf("advisor-%d", days),
						// The --project filter is a RAW filesystem path. It must
						// never travel as sbo.run.trace_id, which the gateway
						// classify tier retains verbatim as operational metadata
						// at every capture level (finding B-B5). Hash it: runs
						// over the same project still correlate, the path itself
						// never leaves the node. Empty stays empty.
						TraceID:   run.CorrelationID(projectRoot),
						Trigger:   "manual",
						Component: conformance.ComponentAdvisor,
						Decisions: []string{
							fmt.Sprintf("suggestions:%d", len(rep.Suggestions)),
							fmt.Sprintf("sessions:%d", rep.SessionsScanned),
						},
						CostUSD: rep.TotalSavingsUSD,
						Outcome: "verified",
					})
					cleanup()
				}
			}
			if jsonOut {
				body, _ := json.MarshalIndent(rep, "", "  ")
				fmt.Fprintln(cmd.OutOrStdout(), string(body))
				return nil
			}
			if digest {
				printAdviseDigest(cmd.OutOrStdout(), rep)
				return nil
			}
			printAdvise(cmd.OutOrStdout(), rep)
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "Path to config.toml")
	cmd.Flags().StringVar(&projectRoot, "project", "", "Filter to a project root path")
	cmd.Flags().IntVar(&days, "days", 0, "Evidence window in days (0 = config default)")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "Emit JSON")
	cmd.Flags().BoolVar(&digest, "digest", false, "Weekly-digest markdown rollup (totals by category + top suggestions)")
	return cmd
}

func printAdvise(w io.Writer, r advisor.Report) {
	fmt.Fprintf(w, "== Suggestions ==\n")
	fmt.Fprintf(w, "window: last %d day(s)   sessions scanned: %d   total avoidable: $%.2f\n\n",
		r.WindowDays, r.SessionsScanned, r.TotalSavingsUSD)
	if len(r.Suggestions) == 0 {
		fmt.Fprintln(w, "No suggestions above the confidence/savings floors. Nice.")
		return
	}
	tw := tabwriter.NewWriter(w, 2, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "SAVINGS\tCONF\tDETECTOR\tSCOPE\tTITLE")
	for _, s := range r.Suggestions {
		scope := s.Scope
		if s.ScopeID != "" {
			id := s.ScopeID
			if len(id) > 8 {
				id = id[:8]
			}
			scope = scope + ":" + id
		}
		fmt.Fprintf(tw, "$%.2f\t%.0f%%\t%s\t%s\t%s\n", s.SavingsUSD, s.Confidence*100, s.Detector, scope, s.Title)
	}
	tw.Flush()
	fmt.Fprintln(w)
	for i, s := range r.Suggestions {
		if i >= 5 {
			fmt.Fprintf(w, "… and %d more (use --json for all, with evidence)\n", len(r.Suggestions)-5)
			break
		}
		fmt.Fprintf(w, "[%d] %s\n    %s\n", i+1, s.Title, s.Nudge)
		if s.Evidence.Math != "" {
			fmt.Fprintf(w, "    math: %s\n", s.Evidence.Math)
		}
		fmt.Fprintln(w)
	}
}

// printAdviseDigest renders the weekly-digest markdown rollup ("you could
// save $X; here is how") — plan Phase 4. Pull-based: pipe it wherever a
// scheduler wants it.
func printAdviseDigest(w io.Writer, r advisor.Report) {
	fmt.Fprintf(w, "# Observer advisor digest — last %d day(s)\n\n", r.WindowDays)
	fmt.Fprintf(w, "**Avoidable spend: $%.2f** across %d suggestions (%d sessions scanned).\n\n",
		r.TotalSavingsUSD, len(r.Suggestions), r.SessionsScanned)
	byCat := map[string]float64{}
	for _, s := range r.Suggestions {
		byCat[s.Category] += s.SavingsUSD
	}
	for _, c := range []string{"cost", "latency", "quality", "hygiene"} {
		if byCat[c] > 0 {
			fmt.Fprintf(w, "- %s: $%.2f\n", c, byCat[c])
		}
	}
	fmt.Fprintln(w)
	for i, s := range r.Suggestions {
		if i >= 10 {
			fmt.Fprintf(w, "\n…and %d more (`observer advise --json`).\n", len(r.Suggestions)-10)
			break
		}
		fmt.Fprintf(w, "## %d. %s ($%.2f)\n\n%s\n\n", i+1, s.Title, s.SavingsUSD, s.Nudge)
	}
}

// advisorPostureInputs assembles the X3.1 posture-detector inputs: the
// effective guard/routing modes from config ("off" when disabled — the
// advisor never reads config files itself) and the §R22 shadow signal
// through the one gate owner (store.AdviseShadowSignal). Best-effort:
// a shadow read failure returns nil and the advisor run proceeds — the
// posture nudge is never worth failing the report for.
func advisorPostureInputs(ctx context.Context, cfg config.Config, st *store.Store, days int) (guardMode, routingMode string, shadow *advisor.ShadowSignal) {
	guardMode, routingMode = "off", "off"
	if cfg.Guard.Enabled {
		guardMode = cfg.Guard.Mode
	}
	if cfg.Routing.Enabled {
		routingMode = cfg.Routing.Mode
	}
	rep, err := st.AdviseShadowSignal(ctx, days, routingPriceFn(acquireProcessCostEngine(ctx, cfg, nil, slog.Default())))
	if err != nil {
		return guardMode, routingMode, nil
	}
	return guardMode, routingMode, &advisor.ShadowSignal{
		AdviseDecisions: rep.AdviseDecisions,
		WouldReroute:    rep.WouldReroute,
		WouldSaveUSD:    rep.WouldSaveUSD,
		QualityFlags:    rep.QualityFlags,
		MinDecisions:    rep.MinDecisions,
		Ready:           rep.ReadyToPromote,
	}
}
