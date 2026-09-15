package main

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/intelligence/dashboard"
)

// newExperimentCmd is the `observer experiment` group (usability arc
// P6.4): productized profile A/B. Start/stop write [[experiments]]
// through config.WriteToml — the same owner as every config writer —
// and poke a running daemon so the split applies to NEW sessions
// immediately. Reports recompute arm membership from the session-ID
// hash; the same function the dashboard uses, so the two surfaces
// can never disagree.
func newExperimentCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "experiment",
		Short: "A/B test compression profiles on live traffic",
		Long: "Split one traffic class between two profiles by a deterministic\n" +
			"session hash, then report per-arm evidence ($/session, CV, turns,\n" +
			"cache causes, compression savings). ADVISORY measurement tooling:\n" +
			"experiments select profiles exactly like assignments do — the master\n" +
			"compression switch and every safety invariant stay untouched.\n\n" +
			"Methodology (docs/plans/profile-content-refresh-ab-plan-2026-06-10.md):\n" +
			"single-variable candidates, n>=8 sessions per arm before believing a\n" +
			"delta, and a candidate that wins on $ but degrades cache health fails.",
	}
	cmd.AddCommand(newExperimentStartCmd(), newExperimentStopCmd(), newExperimentListCmd(), newExperimentReportCmd())
	return cmd
}

func newExperimentStartCmd() *cobra.Command {
	var (
		configPath string
		class      string
		control    string
		candidate  string
		note       string
	)
	cmd := &cobra.Command{
		Use:   "start <name>",
		Short: "Start an experiment (one running per traffic class)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			resolvedPath, err := config.ResolveGlobalPath(configPath)
			if err != nil {
				return fmt.Errorf("resolve config path: %w", err)
			}
			exp := config.ExperimentConfig{
				Name:      args[0],
				Class:     class,
				Control:   control,
				Candidate: candidate,
				StartedAt: time.Now().UTC().Format(time.RFC3339),
				Note:      note,
			}
			if err := config.ValidateExperiment(exp); err != nil {
				return err
			}
			store := config.ProfileStore{Dir: config.DefaultProfilesDir(resolvedPath)}
			for _, p := range []string{exp.Control, exp.Candidate} {
				if err := store.Validate(p); err != nil {
					return err
				}
			}
			cfg, err := config.Load(config.LoadOptions{GlobalPath: resolvedPath})
			if err != nil {
				return fmt.Errorf("load config: %w", err)
			}
			for _, e := range cfg.Experiments {
				if e.Name == exp.Name {
					return fmt.Errorf("experiment %q already exists (records persist; pick a new name)", exp.Name)
				}
				if e.Running() && e.Class == exp.Class {
					return fmt.Errorf("experiment %q is already running on class %q — stop it first", e.Name, e.Class)
				}
			}
			cfg.Experiments = append(cfg.Experiments, exp)
			if err := config.WriteToml(resolvedPath, cfg); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "experiment %s started: class=%s control=%s candidate=%s\n",
				exp.Name, exp.Class, exp.Control, exp.Candidate)
			if pokeReload() {
				fmt.Fprintln(cmd.OutOrStdout(), "daemon reloaded — new sessions split between the arms now")
			} else {
				fmt.Fprintln(cmd.OutOrStdout(), "no running daemon detected on the dashboard port — splits on next start")
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "Path to config.toml (defaults to ~/.observer/config.toml)")
	cmd.Flags().StringVar(&class, "class", "", "Traffic class: anthropic, openai, or tool:<name> (required)")
	cmd.Flags().StringVar(&control, "control", "", "Control profile (required)")
	cmd.Flags().StringVar(&candidate, "candidate", "", "Candidate profile (required)")
	cmd.Flags().StringVar(&note, "note", "", "Free-form context for the record")
	_ = cmd.MarkFlagRequired("class")
	_ = cmd.MarkFlagRequired("control")
	_ = cmd.MarkFlagRequired("candidate")
	return cmd
}

func newExperimentStopCmd() *cobra.Command {
	var configPath string
	cmd := &cobra.Command{
		Use:   "stop <name>",
		Short: "Stop a running experiment (freezes its reporting window)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			resolvedPath, err := config.ResolveGlobalPath(configPath)
			if err != nil {
				return fmt.Errorf("resolve config path: %w", err)
			}
			cfg, err := config.Load(config.LoadOptions{GlobalPath: resolvedPath})
			if err != nil {
				return fmt.Errorf("load config: %w", err)
			}
			found := false
			for i := range cfg.Experiments {
				if cfg.Experiments[i].Name == args[0] {
					if !cfg.Experiments[i].Running() {
						return fmt.Errorf("experiment %q is not running", args[0])
					}
					cfg.Experiments[i].StoppedAt = time.Now().UTC().Format(time.RFC3339)
					found = true
					break
				}
			}
			if !found {
				return fmt.Errorf("unknown experiment %q", args[0])
			}
			if err := config.WriteToml(resolvedPath, cfg); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "experiment %s stopped\n", args[0])
			if pokeReload() {
				fmt.Fprintln(cmd.OutOrStdout(), "daemon reloaded — new sessions resolve per the assignment table again")
			}
			fmt.Fprintf(cmd.OutOrStdout(), "report: observer experiment report %s\n", args[0])
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "Path to config.toml (defaults to ~/.observer/config.toml)")
	return cmd
}

func newExperimentListCmd() *cobra.Command {
	var configPath string
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List experiments and their status",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			resolvedPath, err := config.ResolveGlobalPath(configPath)
			if err != nil {
				return fmt.Errorf("resolve config path: %w", err)
			}
			cfg, err := config.Load(config.LoadOptions{GlobalPath: resolvedPath})
			if err != nil {
				return fmt.Errorf("load config: %w", err)
			}
			if len(cfg.Experiments) == 0 {
				fmt.Fprintln(cmd.OutOrStdout(), "no experiments recorded — start one with: observer experiment start <name> --class <class> --control <p> --candidate <p>")
				return nil
			}
			exps := append([]config.ExperimentConfig{}, cfg.Experiments...)
			sort.Slice(exps, func(i, j int) bool { return exps[i].StartedAt > exps[j].StartedAt })
			for _, e := range exps {
				status := "stopped " + e.StoppedAt
				if e.Running() {
					status = "RUNNING"
				}
				fmt.Fprintf(cmd.OutOrStdout(), "%-24s %-12s control=%s candidate=%s since=%s %s\n",
					e.Name, e.Class, e.Control, e.Candidate, e.StartedAt, status)
				if e.Note != "" {
					fmt.Fprintf(cmd.OutOrStdout(), "%-24s note: %s\n", "", e.Note)
				}
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "Path to config.toml (defaults to ~/.observer/config.toml)")
	return cmd
}

func newExperimentReportCmd() *cobra.Command {
	var (
		configPath string
		jsonOut    bool
	)
	cmd := &cobra.Command{
		Use:   "report <name>",
		Short: "Per-arm evidence: $/session, CV, turns, cache causes, compression",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, database, cleanup, err := loadConfigAndDB(cmd.Context(), configPath)
			if err != nil {
				return err
			}
			defer cleanup()
			var exp *config.ExperimentConfig
			for i := range cfg.Experiments {
				if cfg.Experiments[i].Name == args[0] {
					exp = &cfg.Experiments[i]
					break
				}
			}
			if exp == nil {
				return fmt.Errorf("unknown experiment %q", args[0])
			}
			rep, err := dashboard.ComputeExperimentReport(cmd.Context(), database, acquireProcessCostEngine(cmd.Context(), cfg, database, slog.Default()), *exp)
			if err != nil {
				return err
			}
			if jsonOut {
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				return enc.Encode(rep)
			}
			printExperimentReport(cmd, rep)
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "Path to config.toml (defaults to ~/.observer/config.toml)")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "Emit the report as JSON")
	return cmd
}

// printExperimentReport renders the evidence table plus the §2.4
// decision-rule guidance — numbers first, verdicts left to the
// operator.
func printExperimentReport(cmd *cobra.Command, rep *dashboard.ExperimentReport) {
	out := cmd.OutOrStdout()
	status := "stopped"
	if rep.Running {
		status = "running"
	}
	fmt.Fprintf(out, "experiment %s (%s)  class=%s  window %s .. %s\n",
		rep.Experiment.Name, status, rep.Experiment.Class, rep.WindowFrom, rep.WindowTo)
	if rep.Experiment.Note != "" {
		fmt.Fprintf(out, "note: %s\n", rep.Experiment.Note)
	}
	fmt.Fprintf(out, "\n%-11s %-20s %8s %10s %8s %7s %10s %12s\n",
		"arm", "profile", "sessions", "mean $", "CV", "turns", "cache r:w", "comp saved")
	for _, ar := range []dashboard.ExperimentArmReport{rep.Control, rep.Candidate} {
		rw := "—"
		if ar.CacheWriteTokens > 0 {
			rw = fmt.Sprintf("%.1fx", float64(ar.CacheReadTokens)/float64(ar.CacheWriteTokens))
		}
		fmt.Fprintf(out, "%-11s %-20s %8d %10.3f %7.1f%% %7.1f %10s %11dB\n",
			ar.Arm, ar.Profile, ar.Sessions, ar.MeanCostUSD, ar.CVPct, ar.MeanTurns, rw, ar.CompressionSavedBytes)
	}
	if rep.Candidate.Sessions > 0 && rep.Control.Sessions > 0 {
		fmt.Fprintf(out, "\ncandidate vs control: %+.1f%% $/session, %+.1f%% turns\n",
			rep.DeltaCostPct, rep.DeltaTurnsPct)
	}
	causes := func(m map[string]int64) string {
		if len(m) == 0 {
			return "(none)"
		}
		keys := make([]string, 0, len(m))
		for k := range m {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		parts := make([]string, 0, len(keys))
		for _, k := range keys {
			parts = append(parts, fmt.Sprintf("%s=%d", k, m[k]))
		}
		return strings.Join(parts, " ")
	}
	fmt.Fprintf(out, "cache events  control: %s\n", causes(rep.Control.CacheEventsByCause))
	fmt.Fprintf(out, "cache events  candidate: %s\n", causes(rep.Candidate.CacheEventsByCause))
	fmt.Fprintln(out, "\ndecision guidance (A/B plan §2-3): believe deltas at n>=8 per arm and")
	fmt.Fprintln(out, "CV <= ~10-13%; a candidate that wins on $ but adds invalidation-class")
	fmt.Fprintln(out, "cache events (tools_changed, system_changed) or inflates turns fails.")
}
