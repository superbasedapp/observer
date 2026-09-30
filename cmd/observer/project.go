package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"path/filepath"
	"strconv"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/intelligence/dashboard"
	"github.com/marmutapp/superbased-observer/internal/projectroi"
	"github.com/marmutapp/superbased-observer/internal/store"
	"github.com/marmutapp/superbased-observer/internal/taskflow"
)

// newProjectCmd is the CLI surface for the Projects-page ROI + commit-
// alignment summary (docs/projects-page.md; plan of record
// docs/plans/projects-page-roi-and-commit-alignment-plan-2026-09-21.md
// §3.7, wave W6). It composes through the exact same seam GET
// /api/project/{id} uses — internal/intelligence/dashboard.
// ComposeProjectDetail — so the CLI and the dashboard page can never
// disagree about a project's spend/commit/ROI picture. Read-only: it
// opens the node's own database, never the network.
func newProjectCmd() *cobra.Command {
	var (
		configPath string
		jsonOut    bool
		days       int
		skills     bool
	)
	cmd := &cobra.Command{
		Use:   "project <id|root>",
		Short: "Show a project's spend, commits, LOC and ROI proxies",
		Long: "Prints the Projects page's summary for one project: spend by tool/\n" +
			"model/day/session, the commit ledger's totals, lines-of-code capture,\n" +
			"tasks, and every ROI proxy with its formula and honesty caveat. The\n" +
			"argument is either a numeric project id (as shown by `observer\n" +
			"projects` or the dashboard's /projects page) or a project root path.\n" +
			"Composed through the same seam GET /api/project/{id} uses, so this\n" +
			"command and the dashboard page never disagree.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if days <= 0 {
				return fmt.Errorf("--days must be > 0, got %d", days)
			}
			cfg, database, cleanup, err := loadConfigAndDB(cmd.Context(), configPath)
			if err != nil {
				return err
			}
			defer cleanup()
			st := store.New(database)

			projectID, err := resolveProjectArg(cmd.Context(), st, args[0])
			if err != nil {
				return err
			}

			until := time.Now().UTC()
			since := until.Add(-time.Duration(days) * 24 * time.Hour)
			if skills {
				// S10-SKILLS: the Skills tab's own composition seam, the
				// one GET /api/project/{id}/skills uses.
				return runProjectSkills(cmd, st, cfg.Projects.SkillHistorySkewSeconds, projectID, days, since, until, jsonOut)
			}
			linkWindow := projectroi.DefaultLinkWindow
			if cfg.Projects.CommitLinkWindowDays > 0 {
				linkWindow = time.Duration(cfg.Projects.CommitLinkWindowDays) * 24 * time.Hour
			}
			taskOpts := taskflow.Options{
				MatchMode:             cfg.Tasks.MatchMode,
				ConcurrentAttribution: cfg.Tasks.ConcurrentAttribution,
				IncludeSidechains:     cfg.Tasks.IncludeSidechains,
			}
			engine := acquireProcessCostEngine(cmd.Context(), cfg, database, slog.Default())

			detail, err := dashboard.ComposeProjectDetail(cmd.Context(), st, dashboard.ProjectDetailInput{
				ProjectID: projectID, Days: days, Since: since, Until: until,
				LinkWindow: linkWindow, CostEngine: engine, Taskflow: taskOpts,
			})
			if err != nil {
				return fmt.Errorf("compose project detail: %w", err)
			}

			if jsonOut {
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				return enc.Encode(detail)
			}
			printProjectDetail(cmd.OutOrStdout(), detail)
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "Path to config.toml (defaults to ~/.observer/config.toml)")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "Emit JSON instead of a table")
	cmd.Flags().IntVar(&days, "days", 30, "Window size in days")
	cmd.Flags().BoolVar(&skills, "skills", false, "Show the project's skills: versions across commits and per-session availability")
	return cmd
}

// resolveProjectArg resolves the `observer project <id|root>` positional
// argument to a project id. An argument that parses as a positive int64
// is used as-is (its existence is checked downstream by
// dashboard.ComposeProjectDetail, which errors on an unknown id); any
// other argument is treated as a project root path — made absolute and
// cleaned the same way a shell would resolve it — and looked up via
// store.ProjectIDForRoot, the SAME root-to-id resolver the loc-tracking
// editor-save path and the dashboard's own root-keyed routes use. A root
// that resolves to no project returns a clear, actionable error rather
// than a bare "not found".
func resolveProjectArg(ctx context.Context, st *store.Store, arg string) (int64, error) {
	if id, err := strconv.ParseInt(arg, 10, 64); err == nil && id > 0 {
		return id, nil
	}
	root, err := filepath.Abs(arg)
	if err != nil {
		return 0, fmt.Errorf("resolve root %q: %w", arg, err)
	}
	root = filepath.Clean(root)
	id, err := st.ProjectIDForRoot(ctx, root)
	if err != nil {
		return 0, fmt.Errorf("look up project root %q: %w", root, err)
	}
	if id == 0 {
		return 0, fmt.Errorf("project %q not found (run 'observer projects' or open /projects)", arg)
	}
	return id, nil
}

// printProjectDetail renders the dashboard.ProjectDetail summary as
// plain text tables — the same fields the /projects page's OverviewTab/
// SpendTab render, in the same units, with every ROI tile's formula and
// caveat printed verbatim (plan §2 R10: no metric renders without its
// formula, and nothing here invents a judgement word the tile itself
// doesn't carry).
//
// It ranges directly over dashboard.ProjectDetail's exported slice
// fields (Spend.ByTool, Spend.ByModel, Spend.ByDay, Spend.BySession)
// rather than through a shared named-parameter helper: their element
// types are declared in internal/intelligence/dashboard as unexported
// structs with exported fields (apiProjectCostBucketRow etc.) — a value
// of that type is fully usable from here (field access, ranging), it
// just cannot be named in a signature, so each block is written inline.
func printProjectDetail(w io.Writer, d dashboard.ProjectDetail) {
	fmt.Fprintf(w, "Project %d — %s\n", d.Project.ID, d.Project.RootPath)
	if d.Project.Name != "" {
		fmt.Fprintf(w, "  name: %s\n", d.Project.Name)
	}
	if d.Project.GitRemote != "" {
		fmt.Fprintf(w, "  remote: %s\n", d.Project.GitRemote)
	}
	if len(d.Project.Tools) > 0 {
		fmt.Fprintf(w, "  tools: %v\n", d.Project.Tools)
	}
	if d.Project.FirstSeen != "" || d.Project.LastSeen != "" {
		fmt.Fprintf(w, "  first seen %s, last seen %s\n", d.Project.FirstSeen, d.Project.LastSeen)
	}
	fmt.Fprintf(w, "  window: last %d days\n", d.WindowDays)
	fmt.Fprintf(w, "  capture: commits=%s human_loc=%s\n", d.Capture.Commits, d.Capture.HumanLOC)
	if d.Truncated {
		fmt.Fprintln(w, "  (row caps hit: only the newest 10,000 prompts, 5,000 commits and 100,000 AI edits of this window feed the")
		fmt.Fprintln(w, "   prompt-to-commit figures - spend and per-session prompt counts are complete; commits linked / AI code lines are not)")
	}
	fmt.Fprintln(w)

	fmt.Fprintf(w, "Spend: $%.2f total\n", d.Spend.TotalUSD)
	if d.Spend.UnpricedTurns > 0 {
		fmt.Fprintf(w, "  (%d turns unpriced: no recorded cost and no pricing entry for their model - the total excludes them)\n", d.Spend.UnpricedTurns)
	}

	fmt.Fprintln(w, "  by tool:")
	tw := tabwriter.NewWriter(w, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "    KEY\tUSD\tTURNS")
	for _, r := range d.Spend.ByTool {
		fmt.Fprintf(tw, "    %s\t$%.2f\t%d\n", r.Key, r.CostUSD, r.Turns)
	}
	tw.Flush()

	fmt.Fprintln(w, "  by model:")
	tw = tabwriter.NewWriter(w, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "    KEY\tUSD\tTURNS")
	for _, r := range d.Spend.ByModel {
		fmt.Fprintf(tw, "    %s\t$%.2f\t%d\n", r.Key, r.CostUSD, r.Turns)
	}
	tw.Flush()

	fmt.Fprintln(w, "  by day:")
	byDay := d.Spend.ByDay
	shownDays := byDay
	extraDays := 0
	if len(byDay) > 14 {
		shownDays = byDay[len(byDay)-14:]
		extraDays = len(byDay) - 14
	}
	tw = tabwriter.NewWriter(w, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "    DAY\tUSD")
	for _, r := range shownDays {
		fmt.Fprintf(tw, "    %s\t$%.2f\n", r.Day, r.CostUSD)
	}
	tw.Flush()
	if extraDays > 0 {
		fmt.Fprintf(w, "    (+%d more days)\n", extraDays)
	}

	// by_session is already sorted cost-descending by
	// dashboard.buildBySession; show only the top 20.
	fmt.Fprintln(w, "  by session (top 20 by cost):")
	bySession := d.Spend.BySession
	if len(bySession) > 20 {
		bySession = bySession[:20]
	}
	tw = tabwriter.NewWriter(w, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "    ID\tTOOL\tSTARTED\tUSD\tTURNS\tPROMPTS\tAI CODE LINES\tAI COMMENT LINES\tCOMMITS LINKED")
	for _, r := range bySession {
		fmt.Fprintf(tw, "    %s\t%s\t%s\t$%.2f\t%d\t%d\t%d\t%d\t%d\n",
			r.ID, r.Tool, r.StartedAt, r.CostUSD, r.Turns, r.Prompts, r.AILines, r.AISplit.CommentLines, r.CommitsLinked)
	}
	tw.Flush()
	fmt.Fprintln(w)

	fmt.Fprintln(w, "Lines of code:")
	fmt.Fprintf(w, "  AI code lines added: %d, modified: %d (code files only)\n", d.LOC.AIAdded, d.LOC.AIModified)
	fmt.Fprintf(w, "  AI comment lines added: %d%s\n", d.LOC.AIComment, commentShareSuffix(d.LOC.AISplit.CommentShare))
	if d.LOC.HumanCapture == "none" {
		fmt.Fprintln(w, "  human lines unmeasured")
	} else {
		fmt.Fprintf(w, "  human capture: %s\n", d.LOC.HumanCapture)
	}
	fmt.Fprintln(w)

	fmt.Fprintln(w, "Commits:")
	fmt.Fprintf(w, "  count: %d, ai-touched: %d, spend attributed: $%.2f\n",
		d.Commits.Count, d.Commits.AITouched, d.Commits.WithSpendUSD)
	fmt.Fprintln(w)

	fmt.Fprintln(w, "Tasks:")
	if !d.Tasks.Available {
		// 2026-09-22 rework finding #11: the task-lifecycle rollup failed
		// to load, so Total/Done/CostUSD hold only the raw task_items
		// fallback (see ComposeProjectDetail's doc comment) — printing
		// them here would look like a real, exact count next to the
		// dashboard's own KPI, which already hides behind this same
		// Available flag (OverviewTab.tsx).
		fmt.Fprintln(w, "  tasks: unavailable (rollup failed)")
	} else {
		fmt.Fprintf(w, "  total: %d, done: %d, cost: $%.2f\n", d.Tasks.Total, d.Tasks.Done, d.Tasks.CostUSD)
	}
	fmt.Fprintln(w)

	fmt.Fprintln(w, "ROI proxies:")
	for _, tile := range d.ROI {
		fmt.Fprintf(w, "  %s: %s\n", tile.Key, tile.Label)
		if !tile.Available {
			fmt.Fprintf(w, "    (not available)\n")
		} else {
			fmt.Fprintf(w, "    value: %s\n", formatROIValue(tile.Value, tile.Unit))
		}
		fmt.Fprintf(w, "    formula: %s\n", tile.Formula)
		if tile.Caveat != "" {
			fmt.Fprintf(w, "    caveat: %s\n", tile.Caveat)
		}
	}
}

// formatROIValue renders one ROI tile's Value per its Unit, matching the
// web tile's fmtRoiValue convention exactly: "pct" values are the raw
// [0,1] fraction (multiplied by 100 here for display, never pre-
// multiplied upstream — see toRoiTiles' doc comment in
// internal/intelligence/dashboard/projects.go).
func formatROIValue(v float64, unit string) string {
	switch unit {
	case "usd":
		return fmt.Sprintf("$%.2f", v)
	case "pct":
		return fmt.Sprintf("%.1f%%", v*100)
	case "count":
		return fmt.Sprintf("%d", int64(v))
	case "usd_per_line":
		return fmt.Sprintf("$%.4f/line", v)
	case "usd_per_commit":
		return fmt.Sprintf("$%.2f/commit", v)
	default:
		return fmt.Sprintf("%g %s", v, unit)
	}
}

// commentShareSuffix renders the comment share of AI-authored lines
// (internal/loc.SplitAuthored's precomputed share) as " (N% of authored
// lines are comments)", or "" when there were no authored lines - an empty
// scope is never printed as "0% comments".
func commentShareSuffix(share *float64) string {
	if share == nil {
		return ""
	}
	return fmt.Sprintf(" (%.0f%% of AI-authored lines are comments)", *share*100)
}
