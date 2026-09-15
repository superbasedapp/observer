package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/intelligence/modelvalue"
	"github.com/marmutapp/superbased-observer/internal/store"
)

func newModelValueCmd() *cobra.Command {
	var (
		configPath      string
		days            int
		projectRoot     string
		minSample       int64
		jsonOut         bool
		saveCalibration bool
		showProjects    bool
	)
	cmd := &cobra.Command{
		Use:   "model-value",
		Short: "Model Value Report — observed cost/latency/outcome per model × turn-kind (§R7.2/§R17)",
		Long: "Aggregates the deduped proxy∪JSONL substrate into per model × turn-kind\n" +
			"× project cells (volume, cost/turn, latency p50/p95, error rate,\n" +
			"tool-failure rate) and grades pairwise deltas against the highest-tier\n" +
			"baseline with sample sizes and 95% confidence bands.\n\n" +
			"Attribution is correlational — the report says so on every output.\n\n" +
			"--save-calibration persists the cells into the node-local\n" +
			"model_calibration table (migration 042) for the routing surfaces.",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, database, cleanup, err := loadConfigAndDB(cmd.Context(), configPath)
			if err != nil {
				return err
			}
			defer cleanup()
			st := store.New(database)

			facts, err := st.LoadModelValueFacts(cmd.Context(), modelvalue.LoadOptions{
				WindowDays: days, ProjectRoot: projectRoot,
			})
			if err != nil {
				return err
			}
			facts.Price = routingPriceFn(acquireProcessCostEngine(cmd.Context(), cfg, database, slog.Default()))
			rep := modelvalue.Build(facts, modelvalue.Options{MinSample: minSample})

			if saveCalibration {
				rows := calibrationRows(rep)
				if err := st.UpsertModelCalibrations(cmd.Context(), rows); err != nil {
					return err
				}
				fmt.Fprintf(cmd.ErrOrStderr(), "saved %d calibration cells (window %dd)\n", len(rows), rep.WindowDays)
			}

			if jsonOut {
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				return enc.Encode(rep)
			}
			printModelValue(cmd.OutOrStdout(), rep, showProjects)
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "Path to config.toml (defaults to ~/.observer/config.toml)")
	cmd.Flags().IntVar(&days, "days", 30, "Evidence window in days")
	cmd.Flags().StringVar(&projectRoot, "project", "", "Filter to a project root path")
	cmd.Flags().Int64Var(&minSample, "min-sample", 0, "Evidence floor for delta verdicts (default 50)")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "Emit JSON")
	cmd.Flags().BoolVar(&saveCalibration, "save-calibration", false, "Persist cells into the node-local model_calibration table")
	cmd.Flags().BoolVar(&showProjects, "per-project", false, "Show per-project cells in addition to the global roll-up")
	return cmd
}

// calibrationRows converts a report's cells (global + per-project) into
// store rows — the single boundary where modelvalue shapes become
// model_calibration writes (one owner: the store seam).
func calibrationRows(rep modelvalue.Report) []store.ModelCalibrationRow {
	cells := make([]modelvalue.Cell, 0, len(rep.GlobalCells)+len(rep.Cells))
	cells = append(cells, rep.GlobalCells...)
	cells = append(cells, rep.Cells...)
	rows := make([]store.ModelCalibrationRow, 0, len(cells))
	for _, c := range cells {
		rows = append(rows, store.ModelCalibrationRow{
			Model:            c.Model,
			TurnKind:         string(c.TurnKind),
			ProjectID:        c.ProjectID,
			WindowDays:       rep.WindowDays,
			ComputedAt:       rep.GeneratedAt,
			N:                c.Turns,
			CostUSDTotal:     c.CostUSD,
			LatencyP50Ms:     c.LatencyP50Ms,
			LatencyP95Ms:     c.LatencyP95Ms,
			LatencyGraded:    c.LatencyGraded,
			ErrorCount:       c.ErrorCount,
			ErrorGraded:      c.ErrorGraded,
			ToolFailureCount: c.ToolFailures,
			ToolActionCount:  c.ToolActions,
		})
	}
	return rows
}

// printModelValue renders the human report: caveat first, then the
// global cells, deltas with verdicts, and optionally per-project cells.
func printModelValue(w io.Writer, rep modelvalue.Report, showProjects bool) {
	fmt.Fprintf(w, "Model Value Report — last %d days (generated %s)\n\n",
		rep.WindowDays, rep.GeneratedAt.Format("2006-01-02 15:04:05Z07:00"))
	fmt.Fprintf(w, "NOTE: %s\n\n", rep.Caveat)

	if len(rep.GlobalCells) == 0 {
		fmt.Fprintln(w, "No turns in the window — nothing to report.")
		return
	}

	fmt.Fprintln(w, "Global cells (all projects):")
	printCellTable(w, rep.GlobalCells)

	if len(rep.Deltas) > 0 {
		fmt.Fprintln(w, "Deltas vs highest-tier baseline (per turn-kind group):")
		tw := tabwriter.NewWriter(w, 2, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "  SCOPE\tKIND\tBASELINE\tCANDIDATE\tN(b/c)\tΔERR pp ±CI\tΔTOOLFAIL pp ±CI\t$/TURN (b→c)\tVERDICT")
		for _, d := range rep.Deltas {
			scope := "global"
			if d.ProjectID != 0 {
				if !showProjects {
					continue
				}
				scope = d.ProjectRoot
			}
			verdict := d.Verdict
			if d.VerdictBasis != "" {
				verdict = fmt.Sprintf("%s (%s)", d.Verdict, d.VerdictBasis)
			}
			fmt.Fprintf(tw, "  %s\t%s\t%s\t%s\t%d/%d\t%+.1f ±%.1f\t%+.1f ±%.1f\t$%.4f→$%.4f\t%s\n",
				scope, d.TurnKind, d.BaselineModel, d.CandidateModel,
				d.NBaseline, d.NCandidate,
				d.DeltaErrorRate, d.ErrorCI95,
				d.DeltaToolFailureRate, d.ToolFailureCI95,
				d.CostPerTurnBaseline, d.CostPerTurnCandidate, verdict)
		}
		_ = tw.Flush()
		fmt.Fprintln(w)
	}

	if len(rep.Subagents) > 0 {
		fmt.Fprintln(w, "Sub-agent recommendations (§R10.3 — read-only, nothing is written):")
		tw := tabwriter.NewWriter(w, 2, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "  SUBAGENT\tCURRENT\tTIER\tSUGGESTED\tREASON\tEVIDENCE")
		for _, s := range rep.Subagents {
			suggested := "(keep)"
			if s.SuggestedModel != "" {
				suggested = fmt.Sprintf("%s (%s)", s.SuggestedModel, s.SuggestedTier)
			}
			fmt.Fprintf(tw, "  %s\t%s\t%s\t%s\t%s\t%s\n",
				s.Name, s.CurrentModel, s.CurrentTier, suggested, s.Reason, s.Rationale)
		}
		_ = tw.Flush()
		fmt.Fprintln(w)
	}

	if showProjects && len(rep.Cells) > 0 {
		fmt.Fprintln(w, "Per-project cells:")
		printCellTable(w, rep.Cells)
	}
}

func printCellTable(w io.Writer, cells []modelvalue.Cell) {
	tw := tabwriter.NewWriter(w, 2, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "  KIND\tMODEL\tTIER\tTURNS\t$/TURN\tP50 ms\tP95 ms\tERR (graded)\tTOOLFAIL (graded)\tPROJECT")
	for _, c := range cells {
		project := "-"
		if c.ProjectRoot != "" {
			project = c.ProjectRoot
		}
		fmt.Fprintf(tw, "  %s\t%s\t%s\t%d\t$%.4f\t%d\t%d\t%.1f%% (%d)\t%.1f%% (%d)\t%s\n",
			c.TurnKind, c.Model, c.Tier, c.Turns, c.CostPerTurn,
			c.LatencyP50Ms, c.LatencyP95Ms,
			c.ErrorRate*100, c.ErrorGraded,
			c.ToolFailureRate*100, c.ToolActions, project)
	}
	_ = tw.Flush()
	fmt.Fprintln(w)
}
