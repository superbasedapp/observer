package main

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/intelligence/modelvalue"
	"github.com/marmutapp/superbased-observer/internal/routing"
	"github.com/marmutapp/superbased-observer/internal/routingapply"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// Channel A writer (§R10): `observer routing apply --tool X` turns the
// §R10.3 evidence into each tool's NATIVE configuration. The apply
// mechanics — planning, backup-before-write, revert, advisory
// snippets — live in internal/routingapply (one owner; the dashboard's
// /api/routing/apply endpoints are the other thin frontend). Per the
// §R10.2 support matrix:
//
//   - claude-code (the flagship): per-subagent `model:` frontmatter in
//     ~/.claude/agents/*.md and ./.claude/agents/*.md — mechanical and
//     reversible. Diff-shown-first (dry-run is the default; --yes
//     writes), backup-before-write (<file>.bak-observer-<stamp>),
//     idempotent (already-at-target = no-op), --revert restores the
//     newest backups.
//   - codex / aider / zed / kilo-code / cline / opencode: exact native
//     config snippets printed for the operator to paste (the spec's
//     third emission mode — instructions, not writes).
//   - cursor / copilot: advisory only (§R10.2 — config not reliably
//     file-addressable / org-side policy).
//
// --show-evidence prints the §R7.2 basis under each change: the
// persona's observed profile plus the Model Value Report's global
// parity deltas for the target model (n, error-delta ± CI95, verdict).
func newRoutingApplyCmd() *cobra.Command {
	var (
		configPath   string
		tool         string
		days         int
		yes          bool
		revert       bool
		showEvidence bool
		history      bool
	)
	cmd := &cobra.Command{
		Use:   "apply --tool <tool>",
		Short: "Write (or print) per-tool native routing config from observed evidence (§R10)",
		RunE: func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()
			if history {
				return printApplyHistory(cmd, configPath)
			}
			mode, ok := routingapply.ToolMode(tool)
			if !ok {
				return fmt.Errorf("--tool must be one of: %s", strings.Join(routingapply.Tools(), ", "))
			}
			switch mode {
			case routingapply.ModeWritable:
				if revert {
					return revertClaudeCodeApply(cmd, configPath, agentDirs())
				}
				return applyClaudeCode(cmd, configPath, days, yes, showEvidence)
			case routingapply.ModeSnippet:
				return printAdvisorySnippet(cmd, configPath, tool, days, showEvidence)
			default: // advisory
				fmt.Fprintf(out, "%s is advisory-only (§R10.2): its model picker is not reliably file-addressable.\n", tool)
				fmt.Fprintln(out, "Use `observer model-value` for the evidence and set the picker manually;")
				fmt.Fprintln(out, "the Routing dashboard's router-vs-router view shows how its Auto mode compares.")
				return nil
			}
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "Path to config.toml")
	cmd.Flags().StringVar(&tool, "tool", "", "Target tool (required unless --history)")
	cmd.Flags().IntVar(&days, "days", 30, "Evidence window")
	cmd.Flags().BoolVar(&yes, "yes", false, "Write the changes (default: dry-run diff only)")
	cmd.Flags().BoolVar(&revert, "revert", false, "Restore the most recent observer backups (claude-code)")
	cmd.Flags().BoolVar(&showEvidence, "show-evidence", false, "Show the §R7.2 basis under each change (sample sizes, error-delta ± CI95)")
	cmd.Flags().BoolVar(&history, "history", false, "Print the apply audit trail (every Channel A write + revert, both CLI and dashboard)")
	return cmd
}

// applyLedger resolves the R2.5 audit ledger from config — the same
// node-local file the dashboard frontend appends to.
func applyLedger(configPath string) (*routingapply.Ledger, error) {
	cfg, err := config.Load(config.LoadOptions{GlobalPath: configPath})
	if err != nil {
		return nil, fmt.Errorf("load config: %w", err)
	}
	return routingapply.NewLedger(routingapply.DefaultLedgerPath(cfg.Observer.DBPath)), nil
}

// printApplyHistory renders the audit trail (`apply --history`).
func printApplyHistory(cmd *cobra.Command, configPath string) error {
	out := cmd.OutOrStdout()
	ledger, err := applyLedger(configPath)
	if err != nil {
		return err
	}
	events, skipped, err := ledger.Read()
	if err != nil {
		return err
	}
	if len(events) == 0 {
		fmt.Fprintln(out, "no Channel A writes recorded — the ledger starts with the first `routing apply --yes` (or dashboard apply).")
		return nil
	}
	fmt.Fprintf(out, "Channel A apply history (%s):\n\n", ledger.Path())
	for _, ev := range events {
		switch ev.Kind {
		case "write":
			fmt.Fprintf(out, "  %s  write  %s  %s -> %s  (%s; backup %s)\n",
				ev.Time.Format(time.RFC3339), ev.Path, orInherited(ev.FromModel), ev.ToModel, ev.Source, ev.Backup)
		case "revert":
			fmt.Fprintf(out, "  %s  revert %s  restored from %s  (%s)\n",
				ev.Time.Format(time.RFC3339), ev.Path, ev.Backup, ev.Source)
		default:
			fmt.Fprintf(out, "  %s  %s %s\n", ev.Time.Format(time.RFC3339), ev.Kind, ev.Path)
		}
	}
	if skipped > 0 {
		fmt.Fprintf(out, "\n  note: %d unparseable line(s) skipped (a crashed process can leave a torn append).\n", skipped)
	}
	return nil
}

func orInherited(model string) string {
	if model == "" {
		return "(inherited)"
	}
	return model
}

// applyModelValueReport loads the Model Value Report the apply evidence
// comes from (§R10.3 recommendations + the global parity deltas
// --show-evidence prints).
func applyModelValueReport(cmd *cobra.Command, configPath string, days int) (*modelvalue.Report, error) {
	cfg, database, cleanup, err := loadConfigAndDB(cmd.Context(), configPath)
	if err != nil {
		return nil, err
	}
	defer cleanup()
	st := store.New(database)
	facts, err := st.LoadModelValueFacts(cmd.Context(), modelvalue.LoadOptions{WindowDays: days})
	if err != nil {
		return nil, err
	}
	facts.Price = routingPriceFn(acquireProcessCostEngine(cmd.Context(), cfg, database, slog.Default()))
	rep := modelvalue.Build(facts, modelvalue.Options{})
	return &rep, nil
}

func applyClaudeCode(cmd *cobra.Command, configPath string, days int, write, showEvidence bool) error {
	out := cmd.OutOrStdout()
	rep, err := applyModelValueReport(cmd, configPath, days)
	if err != nil {
		return err
	}
	changes, skipped := routingapply.Plan(agentDirs(), rep.Subagents)
	if len(changes) == 0 {
		fmt.Fprintln(out, "no actionable per-subagent changes — every evidence-backed persona is already at its target (or no evidence yet).")
		for _, s := range skipped {
			fmt.Fprintf(out, "  note: %s\n", s)
		}
		return nil
	}
	recsByName := map[string]routing.SubagentRecommendation{}
	for _, rec := range rep.Subagents {
		recsByName[rec.Name] = rec
	}
	fmt.Fprintf(out, "%d per-subagent model change(s) (claude-code, §R10.3):\n\n", len(changes))
	for _, c := range changes {
		from := c.FromModel
		if from == "" {
			from = "(inherited)"
		}
		fmt.Fprintf(out, "  %s\n    model: %s -> %s\n    why:   %s\n", c.Path, from, c.ToModel, c.Rationale)
		if showEvidence {
			printChangeEvidence(out, recsByName[c.Agent], rep)
		}
	}
	for _, s := range skipped {
		fmt.Fprintf(out, "  note: %s\n", s)
	}
	if !write {
		fmt.Fprintln(out, "\ndry run — pass --yes to write (a .bak-observer-<stamp> backup lands next to each file; --revert restores).")
		return nil
	}
	stamp := routingapply.Stamp(time.Now())
	ledger, ledgerErr := applyLedger(configPath)
	for _, c := range changes {
		if err := routingapply.Write(c, stamp); err != nil {
			return fmt.Errorf("write %s: %w", c.Path, err)
		}
		fmt.Fprintf(out, "wrote %s (backup %s%s)\n", c.Path, c.Path+routingapply.BackupPrefix, stamp)
		// Audit trail (R2.5): best-effort — the write already landed
		// with its backup; a ledger failure is reported, never fatal.
		if ledgerErr == nil {
			ledgerErr = ledger.RecordWrite(c, stamp, "cli")
		}
	}
	if ledgerErr != nil {
		fmt.Fprintf(out, "warn: apply ledger not updated: %v\n", ledgerErr)
	}
	return nil
}

// printChangeEvidence renders the --show-evidence block for one change:
// the persona's observed profile, then the global parity deltas for the
// target model. Honest about absence — no graded rows means the profile
// is the whole basis, stated as such.
func printChangeEvidence(out io.Writer, rec routing.SubagentRecommendation, rep *modelvalue.Report) {
	ev := rec.Evidence
	fmt.Fprintf(out, "    evidence: %d sidechain actions / %d session(s) — %d reads, %d mutations, %d commands, %.0f%% failures\n",
		ev.Actions, ev.Sessions, ev.Reads, ev.Mutations, ev.Commands, ev.FailureRate()*100)
	printModelDeltas(out, rep, rec.SuggestedModel)
}

// printModelDeltas prints the §R7.2 global parity rows for a candidate
// model: error-delta ± CI95 with both sample sizes and the verdict.
func printModelDeltas(out io.Writer, rep *modelvalue.Report, candidate string) {
	if candidate == "" {
		return
	}
	deltas := rep.GlobalDeltasFor(candidate)
	if len(deltas) == 0 {
		fmt.Fprintf(out, "    parity: no graded deltas for %s in this window — the observed profile above is the whole basis\n", candidate)
		return
	}
	for _, d := range deltas {
		basis := ""
		if d.VerdictBasis != "" {
			basis = ", " + d.VerdictBasis
		}
		fmt.Fprintf(out, "    parity[%s]: Δerr %+.1fpp ± %.1fpp vs %s (n %d vs %d; %s%s)\n",
			d.TurnKind, d.DeltaErrorRate, d.ErrorCI95, d.BaselineModel,
			d.NCandidate, d.NBaseline, d.Verdict, basis)
	}
}

// agentDirs lists the claude-code subagent directories the CLI probes:
// user-level and the working directory's project level. (The dashboard
// frontend probes user-level + every known project root instead — it
// has no meaningful CWD.)
func agentDirs() []string {
	var dirs []string
	if home, err := os.UserHomeDir(); err == nil {
		dirs = append(dirs, filepath.Join(home, ".claude", "agents"))
	}
	if cwd, err := os.Getwd(); err == nil {
		dirs = append(dirs, filepath.Join(cwd, ".claude", "agents"))
	}
	return dirs
}

// revertClaudeCodeApply restores each agent file from its NEWEST
// observer backup and records the reverts in the audit ledger.
func revertClaudeCodeApply(cmd *cobra.Command, configPath string, dirs []string) error {
	out := cmd.OutOrStdout()
	restored, err := routingapply.Revert(dirs)
	ledger, ledgerErr := applyLedger(configPath)
	for _, r := range restored {
		fmt.Fprintf(out, "restored %s from %s\n", r.Path, filepath.Base(r.Backup))
		if ledgerErr == nil {
			ledgerErr = ledger.RecordRevert(r, "cli")
		}
	}
	if ledgerErr != nil {
		fmt.Fprintf(out, "warn: apply ledger not updated: %v\n", ledgerErr)
	}
	if err != nil {
		return err
	}
	if len(restored) == 0 {
		fmt.Fprintln(out, "no observer backups found to restore.")
	}
	return nil
}

// printAdvisorySnippet emits the exact native-config snippet for tools
// we don't write directly (§R10.2 matrix).
func printAdvisorySnippet(cmd *cobra.Command, configPath, tool string, days int, showEvidence bool) error {
	out := cmd.OutOrStdout()
	rep, err := applyModelValueReport(cmd, configPath, days)
	if err != nil {
		return err
	}
	weak := routingapply.WeakModel(rep.Subagents)
	snippet, _ := routingapply.AdvisorySnippet(tool, weak)
	fmt.Fprintf(out, "%s native-config snippet (paste into the tool's own config; §R10.2):\n\n", tool)
	for _, line := range strings.Split(strings.TrimRight(snippet, "\n"), "\n") {
		fmt.Fprintf(out, "  %s\n", line)
	}
	if showEvidence {
		fmt.Fprintln(out)
		printModelDeltas(out, rep, weak)
	}
	fmt.Fprintln(out, "\nEvidence: observer model-value (per-persona sample sizes + parity verdicts).")
	return nil
}
