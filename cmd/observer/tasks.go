package main

import (
	"encoding/json"
	"fmt"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/intelligence/cost"
	"github.com/marmutapp/superbased-observer/internal/store"
	"github.com/marmutapp/superbased-observer/internal/taskflow"
	"github.com/marmutapp/superbased-observer/internal/taskreport"
)

// newTasksCmd is the CLI surface for session-level task/todo/plan
// checklist tracking (docs/task-tracking.md "Phase 2"). Two modes:
//
//	observer tasks <session-id>   — one session's per-task report
//	observer tasks --rollup       — project/tool/window aggregate
//
// Both are read-only, built entirely on top of
// taskreport.LoadSessionTaskReport / taskreport.LoadTaskRollup — the
// same functions GET /api/session/<id>/tasks and GET /api/tasks serve.
func newTasksCmd() *cobra.Command {
	var (
		configPath  string
		jsonOut     bool
		rollup      bool
		days        int
		projectID   int64
		projectRoot string
		tool        string
	)
	cmd := &cobra.Command{
		Use:   "tasks [session-id]",
		Short: "Session-level task/todo/plan tracking: per-task tokens, cost, elapsed, and status",
		Long: "Reports what a session's todo/plan tool calls (claude-code TaskCreate/\n" +
			"TaskUpdate/TodoWrite, codex update_plan, kiro-cli todo_list, …) actually\n" +
			"cost — per task tokens/cost/elapsed/action-count, plus the between_tasks\n" +
			"and shared buckets §R2.3.2 requires as first-class rows (only ~52% of a\n" +
			"session's tokens are attributable to one specific task on average). A\n" +
			"pure re-read of already-captured actions/token_usage rows — no new\n" +
			"capture surface, gated by [tasks].enabled. Use --rollup for a project/\n" +
			"tool/window aggregate across every session instead of one session's detail.",
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, database, cleanup, err := loadConfigAndDB(cmd.Context(), configPath)
			if err != nil {
				return err
			}
			defer cleanup()

			if !cfg.Tasks.Enabled {
				fmt.Fprintln(cmd.OutOrStdout(), "session-level task tracking is disabled ([tasks].enabled = false)")
				return nil
			}

			st := store.New(database)
			engine := cost.NewEngine(cfg.Intelligence)
			// [tasks].match_mode/.concurrent_attribution/.include_sidechains,
			// passed explicitly rather than read off st.TasksOptions() —
			// this st is a fresh store.New(database) that never had
			// SetTasksOptions called on it (see taskreport.
			// LoadSessionTaskReport's doc comment for why that store-
			// instance dependency was the FIX-A bug).
			taskOpts := taskflow.Options{
				MatchMode:             cfg.Tasks.MatchMode,
				ConcurrentAttribution: cfg.Tasks.ConcurrentAttribution,
				IncludeSidechains:     cfg.Tasks.IncludeSidechains,
			}

			if rollup {
				var since time.Time
				if days > 0 {
					since = time.Now().UTC().AddDate(0, 0, -days)
				}
				rep, rerr := taskreport.LoadTaskRollup(cmd.Context(), st, engine, since, time.Time{}, projectID, projectRoot, tool, taskOpts)
				if rerr != nil {
					return fmt.Errorf("load task rollup: %w", rerr)
				}
				if jsonOut {
					enc := json.NewEncoder(cmd.OutOrStdout())
					enc.SetIndent("", "  ")
					return enc.Encode(rep)
				}
				printTaskRollup(cmd, rep, days)
				return nil
			}

			if len(args) != 1 {
				return fmt.Errorf("a session id is required unless --rollup is set (observer tasks <session-id>, or observer tasks --rollup)")
			}
			sessionID := args[0]
			rep, rerr := taskreport.LoadSessionTaskReport(cmd.Context(), st, engine, sessionID, taskOpts)
			if rerr != nil {
				return fmt.Errorf("load task report for %q: %w", sessionID, rerr)
			}
			if jsonOut {
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				return enc.Encode(rep)
			}
			printSessionTaskReport(cmd, rep)
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "Path to config.toml (defaults to ~/.observer/config.toml)")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "Emit JSON instead of a table")
	cmd.Flags().BoolVar(&rollup, "rollup", false, "Project/tool/window aggregate instead of one session's detail")
	cmd.Flags().IntVar(&days, "days", 0, "--rollup only: limit to sessions started in the last N days (0 = no bound)")
	cmd.Flags().Int64Var(&projectID, "project-id", 0, "--rollup only: limit to one project id (0 = every project)")
	cmd.Flags().StringVar(&projectRoot, "project", "", "--rollup only: limit to sessions under this project root path (empty = every project); composes with --project-id")
	cmd.Flags().StringVar(&tool, "tool", "", "--rollup only: limit to sessions from this AI tool (empty = every tool)")
	return cmd
}

func printSessionTaskReport(cmd *cobra.Command, rep taskreport.SessionTaskReport) {
	w := cmd.OutOrStdout()
	if !rep.HasTasks {
		fmt.Fprintf(w, "session %s never used a task/todo/plan tool — nothing to report.\n", rep.SessionID)
		fmt.Fprintln(w, "(most sessions don't — this is the normal case, not an error.)")
		return
	}

	fmt.Fprintf(w, "Task tracking — session %s (match_mode=%s, concurrent_attribution=%s)\n\n",
		rep.SessionID, taskOrDefault(rep.MatchMode, "exact"), taskOrDefault(rep.ConcurrentAttribution, "shared"))

	tw := tabwriter.NewWriter(w, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "TASK\tSTATUS\tELAPSED\tACTIONS\tTOKENS(IN/OUT)\tCOST")
	for _, it := range rep.Items {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%d\t%s/%s\t%s\n",
			truncate(it.Content, 40), taskStatusLabel(it), fmtElapsed(it.ElapsedSeconds), it.ActionsCount,
			fmtTokens(it.Tokens.InputTokens), fmtTokens(it.Tokens.OutputTokens), fmtCostCell(it.CostUSD, it.Unpriced))
	}
	tw.Flush()

	fmt.Fprintln(w)
	fmt.Fprintf(w, "between_tasks:  %d actions, %s/%s tok, %s\n",
		rep.BetweenTasks.ActionsCount, fmtTokens(rep.BetweenTasks.Tokens.InputTokens), fmtTokens(rep.BetweenTasks.Tokens.OutputTokens),
		fmtCostCell(rep.BetweenTasks.CostUSD, rep.BetweenTasks.Unpriced))
	fmt.Fprintf(w, "shared:         %d actions, %s/%s tok, %s\n",
		rep.Shared.ActionsCount, fmtTokens(rep.Shared.Tokens.InputTokens), fmtTokens(rep.Shared.Tokens.OutputTokens),
		fmtCostCell(rep.Shared.CostUSD, rep.Shared.Unpriced))
	if rep.Sidechain != nil {
		fmt.Fprintf(w, "sidechain:      %d actions, %s/%s tok, %s (sub-agent usage, reported separately — include_sidechains=false)\n",
			rep.Sidechain.ActionsCount, fmtTokens(rep.Sidechain.Tokens.InputTokens), fmtTokens(rep.Sidechain.Tokens.OutputTokens),
			fmtCostCell(rep.Sidechain.CostUSD, rep.Sidechain.Unpriced))
	}
	if rep.UnmatchedCount > 0 && !rep.AllKeysNative {
		fmt.Fprintf(w, "\n%d item(s) could not be matched across updates (content changed between snapshots) — see 'unmatched' above.\n", rep.UnmatchedCount)
	}
	if rep.CostNote != "" {
		fmt.Fprintf(w, "\n%s\n", rep.CostNote)
	}
}

func printTaskRollup(cmd *cobra.Command, rep taskreport.TaskRollup, days int) {
	w := cmd.OutOrStdout()
	if rep.SessionsWithTasks == 0 {
		fmt.Fprintln(w, "no sessions with task/todo/plan tracking in this window.")
		return
	}
	windowLabel := "all time"
	if days > 0 {
		windowLabel = fmt.Sprintf("last %d days", days)
	}
	fmt.Fprintf(w, "Task tracking rollup — %s, %d session(s) with tasks\n\n", windowLabel, rep.SessionsWithTasks)

	tw := tabwriter.NewWriter(w, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "TOOL\tSESSIONS\tTASKS\tCOST")
	for _, t := range rep.ByTool {
		fmt.Fprintf(tw, "%s\t%d\t%d\t%s\n", t.Tool, t.Sessions, t.Tasks, fmtCostCell(t.CostUSD, t.Unpriced))
	}
	tw.Flush()

	fmt.Fprintln(w)
	fmt.Fprintf(w, "created %d · completed %d · cancelled %d · never activated %d · still open %d\n",
		rep.Counts.Created, rep.Counts.Completed, rep.Counts.Cancelled, rep.Counts.NeverActivated, rep.Counts.StillOpen)
	fmt.Fprintf(w, "attributed_single: %s (%s), between_tasks: %s (%s), shared: %s (%s)\n",
		fmtCostCell(rep.AttributedSingle.CostUSD, rep.AttributedSingle.Unpriced), fmtTokens(rep.AttributedSingle.Tokens.InputTokens+rep.AttributedSingle.Tokens.OutputTokens),
		fmtCostCell(rep.BetweenTasks.CostUSD, rep.BetweenTasks.Unpriced), fmtTokens(rep.BetweenTasks.Tokens.InputTokens+rep.BetweenTasks.Tokens.OutputTokens),
		fmtCostCell(rep.Shared.CostUSD, rep.Shared.Unpriced), fmtTokens(rep.Shared.Tokens.InputTokens+rep.Shared.Tokens.OutputTokens))
	if rep.Counts.Unmatched > 0 && !rep.Counts.AllSessionsKeysNative {
		fmt.Fprintf(w, "%d item(s) across all sessions could not be matched across updates.\n", rep.Counts.Unmatched)
	}
	if rep.CostNote != "" {
		fmt.Fprintf(w, "\n%s\n", rep.CostNote)
	}
}

func taskStatusLabel(it taskreport.ReportItem) string {
	switch {
	case it.NeverActivated:
		// NeverActivated means "closed without ever passing through
		// in_progress" — the CLOSING status can be completed,
		// cancelled, deleted, OR the synthetic vanished (taskflow.
		// Summarize sets NeverActivated whenever a terminal transition
		// exists with no prior in_progress one, independent of WHICH
		// terminal status closed it). Render the real terminal_status
		// rather than hardcoding "completed" — a cancelled-before-
		// started or vanished-before-started task previously lied and
		// said "completed (never activated)".
		status := it.TerminalStatus
		if status == "" {
			status = it.Status
		}
		return status + " (never activated)"
	case it.StillOpen:
		return it.Status + " (open)"
	default:
		return it.Status
	}
}

func fmtElapsed(seconds float64) string {
	if seconds <= 0 {
		return "-"
	}
	d := time.Duration(seconds * float64(time.Second))
	if d < time.Minute {
		return fmt.Sprintf("%ds", int(d.Seconds()))
	}
	if d < time.Hour {
		return fmt.Sprintf("%dm", int(d.Minutes()))
	}
	return fmt.Sprintf("%dh%dm", int(d.Hours()), int(d.Minutes())%60)
}

func fmtCostCell(usd float64, unpriced bool) string {
	if unpriced {
		return "unpriced"
	}
	return fmt.Sprintf("$%.4f", usd)
}

func taskOrDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}
