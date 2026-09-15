package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/benchmark"
	"github.com/marmutapp/superbased-observer/internal/intelligence/cost"
	"github.com/marmutapp/superbased-observer/internal/scrub"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// newBenchmarkCmd is the CLI surface for the Benchmarks Harness
// (docs/plans/benchmarks-harness-plan-2026-07-11.md). CLI-driven, budget-gated.
// Harnesses: codex + claude-code (the latter Preflight-gated on an isolated
// benchmark daemon, per docs/plans/benchmarks-claude-code-respike-findings-
// 2026-07-12.md §6). The dashboard page is DEFERRED from this wave.
func newBenchmarkCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "benchmark",
		Short: "Run + report harness×model benchmarks on billed-token truth (codex + claude-code)",
		Long: "Drives a declarative task corpus across a {harness × model} matrix through\n" +
			"the proxy-routing launcher verbs, so every attempt lands in observer.db with\n" +
			"billed-token accuracy, then scores success and reports an honest comparison\n" +
			"(Wilson CIs + paired analysis + non-inferiority verdicts). Real spend is\n" +
			"bounded by a dry-run estimate + confirmation gate + per-attempt/per-run caps.\n\n" +
			"Harnesses: codex, claude-code. claude-code requires an ISOLATED benchmark\n" +
			"daemon (own --config db_path, small DB) — its Preflight refuses the operator\n" +
			"default ~/.observer/observer.db (the 2026-07-12 re-spike's large-DB stall).",
	}
	cmd.AddCommand(newBenchmarkRunCmd())
	cmd.AddCommand(newBenchmarkReportCmd())
	cmd.AddCommand(newBenchmarkListCmd())
	cmd.AddCommand(newBenchmarkExportCmd())
	cmd.AddCommand(newBenchmarkDeleteCmd())
	return cmd
}

func newBenchmarkRunCmd() *cobra.Command {
	var (
		configPath      string
		proxyURL        string
		rootDir         string
		judgeModel      string
		confirmSpend    bool
		allowUnpriced   bool
		keepWorkspaces  bool
		ephemeralDaemon bool
	)
	cmd := &cobra.Command{
		Use:   "run <spec.toml>",
		Short: "Run a benchmark spec (DRY RUN by default; --confirm-spend to spend)",
		Long: "Estimates the matrix cost and prints the plan. By DEFAULT this is a dry run\n" +
			"that launches nothing and persists nothing. Pass --confirm-spend to actually\n" +
			"drive the harnesses — this spends real API budget, bounded by the spec's\n" +
			"[budget] caps.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			// Catch ctrl-c so the deferred ephemeral-daemon teardown (temp DB +
			// dir removal, port release) always runs on interrupt, not just on
			// a normal return — cobra's default context is not signal-aware.
			ctx, cancel := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
			defer cancel()

			specBytes, err := os.ReadFile(args[0])
			if err != nil {
				return fmt.Errorf("read spec: %w", err)
			}
			spec, err := benchmark.ParseSpec(string(specBytes))
			if err != nil {
				return err
			}
			// Preserve the originating node identity before an ephemeral
			// benchmark daemon replaces configPath with its isolated config.
			budgetConfigPath := configPath
			if confirmSpend {
				if err := enforceBenchmarkBudget(ctx, budgetConfigPath); err != nil {
					return err
				}
			}
			exe, err := os.Executable()
			if err != nil {
				return fmt.Errorf("resolve observer binary: %w", err)
			}

			// Auto-engage an isolated ephemeral daemon so a claude-code first
			// run "just works" (backlog #10). Engage when the operator asked
			// (--ephemeral-daemon) OR gave no --config AND the spec uses a
			// harness whose Preflight needs daemon isolation (claude-code). With
			// no --config the claude-code driver would resolve the operator's
			// real ~/.observer/observer.db and fail Preflight; the ephemeral
			// daemon gives it a fresh temp DB instead — the real data untouched.
			// When engaged, its config path threads everywhere (store, driver
			// Preflight, and the claude-code hooks that write the isolated DB).
			engage := shouldEngageEphemeralDaemon(ephemeralDaemon, configPath, spec, newBenchmarkDrivers(exe, ""))
			if engage {
				eph, derr := startEphemeralDaemon(ctx)
				if derr != nil {
					return fmt.Errorf("start ephemeral benchmark daemon: %w", derr)
				}
				defer eph.Close()
				announceEphemeralDaemon(cmd.OutOrStdout(), eph)
				configPath = eph.ConfigPath
				if proxyURL == "" {
					proxyURL = eph.ProxyURL
				}
			}

			cfg, database, cleanup, err := loadConfigAndDB(ctx, configPath)
			if err != nil {
				return err
			}
			defer cleanup()
			st := store.New(database)

			engine := acquireProcessCostEngine(ctx, cfg, database, slog.Default())
			resolved := resolveProxyURL(cfg.Proxy.Port, proxyURL)
			if rootDir == "" {
				rootDir, err = os.MkdirTemp("", "sbo-benchmark-")
				if err != nil {
					return fmt.Errorf("scratch dir: %w", err)
				}
			}

			runner := &benchmarkRunner{
				store:       st,
				drivers:     budgetControlledBenchmarkDrivers(exe, cfg.Observer.DBPath, budgetConfigPath),
				provisioner: gitCloneProvisioner{},
				homePrep:    attemptHomePrep{binaryPath: exe, configPath: configPath},
				scorer: budgetControlledBenchmarkScorer{
					inner:      benchmarkScorer{judgeModel: judgeModel, evalScore: newBenchmarkEvalScoreFn(cfg)},
					configPath: budgetConfigPath,
				},
				scrubber: scrub.New(),
				estimateTurnUSD: func(ctx context.Context, model string) (float64, bool) {
					return st.AvgTurnCostUSD(ctx, model, 30)
				},
				pricingSnapshot: func(models []string) (string, error) {
					return buildPricingSnapshot(engine, models)
				},
				now: func() time.Time { return time.Now().UTC() },
				out: cmd.OutOrStdout(),
			}
			opts := RunOptions{
				DryRun:          !confirmSpend,
				Confirmed:       confirmSpend,
				ProxyURL:        resolved,
				RootDir:         rootDir,
				ObserverVersion: version,
				AllowUnpriced:   allowUnpriced,
				KeepWorkspaces:  keepWorkspaces,
			}
			runID, err := runner.Run(ctx, spec, opts)
			if err != nil {
				return err
			}
			if runID != "" {
				fmt.Fprintf(cmd.OutOrStdout(), "\nReport it with: observer benchmark report %s\n", runID)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "Path to config.toml")
	cmd.Flags().StringVar(&proxyURL, "proxy", "", "Proxy base URL override (default from config)")
	cmd.Flags().StringVar(&rootDir, "root-dir", "", "Scratch dir for per-attempt workspaces (default: a temp dir)")
	cmd.Flags().StringVar(&judgeModel, "judge-model", "", "Judge model id for llm_judge score provenance")
	cmd.Flags().BoolVar(&confirmSpend, "confirm-spend", false, "Actually run (spends real API budget); omit for a dry run")
	cmd.Flags().BoolVar(&allowUnpriced, "allow-unpriced", false, "Permit spending on a config whose model has no billed history to estimate cost from (default: refuse rather than show a false $0.00)")
	cmd.Flags().BoolVar(&keepWorkspaces, "keep-workspaces", false, "Retain every per-attempt workspace for inspection (failed attempts are always retained)")
	cmd.Flags().BoolVar(&ephemeralDaemon, "ephemeral-daemon", false, "Stand up a throwaway isolated observer daemon (temp DB, free port) for this run instead of using your real ~/.observer daemon. Auto-engaged for a claude-code spec when no --config is given, so first-run just works; your real Observer data is never touched.")
	return cmd
}

func newBenchmarkReportCmd() *cobra.Command {
	var (
		configPath string
		jsonOut    bool
	)
	cmd := &cobra.Command{
		Use:   "report <run-id>",
		Short: "Print the honest comparison matrix (success ± Wilson CI, verdicts, cost)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			runID := args[0]
			_, database, cleanup, err := loadConfigAndDB(cmd.Context(), configPath)
			if err != nil {
				return err
			}
			defer cleanup()
			st := store.New(database)

			run, ok, err := st.LoadBenchmarkRun(cmd.Context(), runID)
			if err != nil {
				return err
			}
			if !ok {
				return fmt.Errorf("no benchmark run %q", runID)
			}
			var spec benchmark.Spec
			if err := json.Unmarshal([]byte(run.SpecJSON), &spec); err != nil {
				return fmt.Errorf("decode stored spec: %w", err)
			}
			facts, err := st.LoadBenchmarkFacts(cmd.Context(), runID)
			if err != nil {
				return err
			}
			rep := benchmark.ComputeReport(spec, runID, facts)
			if jsonOut {
				exp := buildBenchmarkExport(run, rep, time.Now().UTC().Format(time.RFC3339))
				body, _ := json.MarshalIndent(exp, "", "  ")
				fmt.Fprintln(cmd.OutOrStdout(), string(body))
				return nil
			}
			renderBenchmarkReport(cmd.OutOrStdout(), run, rep)
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "Path to config.toml")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "Emit the canonical JSON export instead of the table")
	return cmd
}

func newBenchmarkListCmd() *cobra.Command {
	var (
		configPath string
		jsonOut    bool
		limit      int
	)
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List benchmark runs (sanitized: no prompts/paths)",
		RunE: func(cmd *cobra.Command, args []string) error {
			_, database, cleanup, err := loadConfigAndDB(cmd.Context(), configPath)
			if err != nil {
				return err
			}
			defer cleanup()
			st := store.New(database)
			runs, err := st.ListBenchmarkRuns(cmd.Context(), limit)
			if err != nil {
				return err
			}
			if jsonOut {
				type row struct {
					RunID, SpecName, Status string
					Planned, Completed      int
					SpendUSD                float64
					StartedAt               string
				}
				out := make([]row, 0, len(runs))
				for _, r := range runs {
					out = append(out, row{r.RunID, r.SpecName, r.Status, r.PlannedCells, r.CompletedCells, r.SpendUSD, r.StartedAt.Format(time.RFC3339)})
				}
				body, _ := json.MarshalIndent(out, "", "  ")
				fmt.Fprintln(cmd.OutOrStdout(), string(body))
				return nil
			}
			w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 4, 2, ' ', 0)
			fmt.Fprintln(w, "RUN\tSPEC\tSTATUS\tCELLS\tSPEND\tSTARTED")
			for _, r := range runs {
				fmt.Fprintf(w, "%s\t%s\t%s\t%d/%d\t$%.4f\t%s\n",
					r.RunID, r.SpecName, r.Status, r.CompletedCells, r.PlannedCells, r.SpendUSD,
					r.StartedAt.Format("2006-01-02 15:04"))
			}
			return w.Flush()
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "Path to config.toml")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "Emit JSON")
	cmd.Flags().IntVar(&limit, "limit", 50, "Max runs to list")
	return cmd
}

func newBenchmarkExportCmd() *cobra.Command {
	var configPath string
	cmd := &cobra.Command{
		Use:   "export <run-id>",
		Short: "Emit the canonical JSON results card (redaction-allowlisted)",
		Long: "Emits the canonical, redaction-allowlisted JSON results card: it carries the\n" +
			"qualifier tuple (model · workload · date · N · CI · 'estimated list price')\n" +
			"and EXCLUDES prompts, repo/workspace paths, answer excerpts, and judge\n" +
			"rationale by default.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			runID := args[0]
			_, database, cleanup, err := loadConfigAndDB(cmd.Context(), configPath)
			if err != nil {
				return err
			}
			defer cleanup()
			st := store.New(database)
			run, ok, err := st.LoadBenchmarkRun(cmd.Context(), runID)
			if err != nil {
				return err
			}
			if !ok {
				return fmt.Errorf("no benchmark run %q", runID)
			}
			var spec benchmark.Spec
			if err := json.Unmarshal([]byte(run.SpecJSON), &spec); err != nil {
				return fmt.Errorf("decode stored spec: %w", err)
			}
			facts, err := st.LoadBenchmarkFacts(cmd.Context(), runID)
			if err != nil {
				return err
			}
			rep := benchmark.ComputeReport(spec, runID, facts)
			exp := buildBenchmarkExport(run, rep, time.Now().UTC().Format(time.RFC3339))
			body, _ := json.MarshalIndent(exp, "", "  ")
			fmt.Fprintln(cmd.OutOrStdout(), string(body))
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "Path to config.toml")
	return cmd
}

func newBenchmarkDeleteCmd() *cobra.Command {
	var configPath string
	cmd := &cobra.Command{
		Use:   "delete <run-id>",
		Short: "Delete a benchmark run and all its attempts/scores",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			runID := args[0]
			_, database, cleanup, err := loadConfigAndDB(cmd.Context(), configPath)
			if err != nil {
				return err
			}
			defer cleanup()
			st := store.New(database)
			if _, ok, err := st.LoadBenchmarkRun(cmd.Context(), runID); err != nil {
				return err
			} else if !ok {
				return fmt.Errorf("no benchmark run %q", runID)
			}
			if err := st.DeleteBenchmarkRun(cmd.Context(), runID); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "deleted benchmark run %s\n", runID)
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "Path to config.toml")
	return cmd
}

// renderBenchmarkReport prints the honest matrix + verdicts. Every config is
// shown; CI width is prominent; verdicts use the non-inferiority vocabulary.
func renderBenchmarkReport(w interface{ Write([]byte) (int, error) }, run benchmark.RunRecord, rep benchmark.Report) {
	fmt.Fprintf(w, "Benchmark: %s  (run %s, status %s)\n", rep.SpecName, rep.RunID, run.Status)
	fmt.Fprintf(w, "Baseline: %s   Non-inferiority margin: %.3f   Sample floor: %d\n", rep.Baseline, rep.Margin, rep.MinSample)
	fmt.Fprintf(w, "Total spend: $%.4f   (%s)\n\n", run.SpendUSD, priceDisclaimer)

	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "CONFIG\tMODEL\tSUCCESS (95% CI)\tN(pl/ex/sc/pass)\tCOST/SUCCESS\tMEAN$\tCACHE%\tWALLms")
	for _, c := range rep.Configs {
		cps := "n/a"
		if c.CostPerSuccessDefined {
			cps = fmt.Sprintf("$%.4f", c.CostPerSuccessUSD)
		}
		fmt.Fprintf(tw, "%s\t%s\t%.0f%% [%.0f–%.0f]\t%d/%d/%d/%d\t%s\t$%.4f\t%.0f%%\t%.0f\n",
			c.ConfigID, c.Model,
			c.SuccessRate*100, c.SuccessCI.Lo*100, c.SuccessCI.Hi*100,
			c.Planned, c.Executed, c.Scored, c.Passed,
			cps, c.MeanCostPerAttempt, c.CacheReadPct, c.MeanWallMS)
	}
	_ = tw.Flush()

	if len(rep.Comparisons) > 0 {
		fmt.Fprintln(w, "\nComparisons vs baseline:")
		ctw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
		fmt.Fprintln(ctw, "  CANDIDATE\tVERDICT\tΔSUCCESS (95% CI)\tPAIRED Δ\tCHEAPER\tΔ$/SUCCESS")
		for _, cmp := range rep.Comparisons {
			fmt.Fprintf(ctw, "  %s\t%s\t%+.2f [%+.2f,%+.2f]\t%+.2f\t%v\t$%+.4f\n",
				cmp.Candidate, cmp.Verdict,
				cmp.DiffCI.Point, cmp.DiffCI.Lo, cmp.DiffCI.Hi,
				cmp.PairedDelta.Point, cmp.Cheaper, cmp.CostDeltaUSD)
		}
		_ = ctw.Flush()
	}

	fmt.Fprintln(w, "\nStatus census (all attempts counted):")
	for _, s := range benchmark.TerminalStatuses() {
		if n := rep.StatusCensus[s]; n > 0 {
			fmt.Fprintf(w, "  %-20s %d\n", s, n)
		}
	}
	for _, warn := range rep.Warnings {
		fmt.Fprintf(w, "  WARN: %s\n", warn)
	}
}

// buildPricingSnapshot captures the pricing-table entries for the run's models
// plus a hash of them, so a later price change can't silently rewrite history
// (plan §3.11). Content-free (model ids + rates only).
func buildPricingSnapshot(engine *cost.Engine, models []string) (string, error) {
	type entry struct {
		Model   string       `json:"model"`
		Pricing cost.Pricing `json:"pricing"`
		Found   bool         `json:"found"`
	}
	snap := struct {
		CapturedAt string  `json:"captured_at"`
		Entries    []entry `json:"entries"`
		Hash       string  `json:"hash"`
	}{CapturedAt: time.Now().UTC().Format(time.RFC3339)}
	for _, m := range models {
		p, ok := engine.Lookup(m)
		snap.Entries = append(snap.Entries, entry{Model: m, Pricing: p, Found: ok})
	}
	raw, err := json.Marshal(snap.Entries)
	if err != nil {
		return "", err
	}
	snap.Hash = hashString(string(raw))
	out, err := json.Marshal(snap)
	if err != nil {
		return "", err
	}
	return string(out), nil
}
