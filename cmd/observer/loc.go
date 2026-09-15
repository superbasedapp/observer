package main

import (
	"context"
	"database/sql"
	"fmt"
	"io"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/loc"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// Lines-of-code CLI surfaces (docs/plans/lines-of-code-tracking-plan-2026-09-07.md
// §3.2): the `backfill --loc` pass and `observer loc reconcile`.

// locBackfillArgs carries the --loc-* flags into the pass.
type locBackfillArgs struct {
	Since    string
	Rescan   bool
	DryRun   bool
	Limit    int
	Sessions []string
}

// LOCBackfillReport is the JSON-shaped summary of one --loc run.
type LOCBackfillReport struct {
	ActionsScanned int  `json:"actions_scanned"`
	FileRows       int  `json:"file_rows"`
	RowsWritten    int  `json:"rows_written"`
	DryRun         bool `json:"dry_run"`
	// Sessions holds the per-session totals for the ids named by
	// --loc-session, so an operator can eyeball a specific session
	// without writing anything.
	Sessions map[string]loc.Stats `json:"sessions,omitempty"`
	// ClassifierVersion is the version the pass counted at.
	ClassifierVersion int `json:"classifier_version"`
}

// backfillLOC runs the lines-of-code counting pass over historical
// actions.
func backfillLOC(
	ctx context.Context, database *sql.DB, args locBackfillArgs, out io.Writer,
) (LOCBackfillReport, error) {
	rep := LOCBackfillReport{DryRun: args.DryRun, ClassifierVersion: loc.Version}
	s := store.New(database)

	since, err := parseLOCSince(args.Since)
	if err != nil {
		return rep, err
	}

	wanted := map[string]bool{}
	for _, id := range args.Sessions {
		if id = strings.TrimSpace(id); id != "" {
			wanted[id] = true
		}
	}

	opts := store.BackfillLOCOptions{
		Since:  since,
		Limit:  args.Limit,
		Rescan: args.Rescan,
		DryRun: args.DryRun,
	}
	if out != nil {
		last := time.Now()
		opts.Progress = func(actions, rows int) {
			// Throttled so a 51k-row corpus does not scroll a hundred
			// screens of progress past the operator.
			if time.Since(last) < 2*time.Second {
				return
			}
			last = time.Now()
			fmt.Fprintf(out, "  loc: %d actions, %d file rows…\n", actions, rows)
		}
	}

	res, err := s.BackfillLOC(ctx, opts)
	if err != nil {
		return rep, fmt.Errorf("backfillLOC: %w", err)
	}
	rep.ActionsScanned = res.ActionsScanned
	rep.FileRows = res.FilesSeen
	rep.RowsWritten = res.RowsWritten
	if len(wanted) > 0 {
		rep.Sessions = map[string]loc.Stats{}
		for id := range wanted {
			rep.Sessions[id] = res.PerSession[id]
		}
	}

	if out != nil {
		verb := "wrote"
		if args.DryRun {
			verb = "would write"
		}
		fmt.Fprintf(out,
			"loc: scanned %d actions → %d file rows, %s %d (classifier v%d)\n",
			res.ActionsScanned, res.FilesSeen, verb, res.RowsWritten, loc.Version)
		for _, id := range sortedLOCKeys(rep.Sessions) {
			st := rep.Sessions[id]
			fmt.Fprintf(out, "  session %s: %s\n", id, formatLOCStats(st))
		}
	}
	return rep, nil
}

// sortedLOCKeys returns a map's keys in a stable order so output never
// flaps between runs.
func sortedLOCKeys(m map[string]loc.Stats) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// formatLOCStats renders a bucket set on one line.
func formatLOCStats(st loc.Stats) string {
	return fmt.Sprintf(
		"code +%d ~%d -%d | comment +%d -%d | whitespace %d | blank %d | unknown %d",
		st.AddedCode, st.ModifiedCode, st.DeletedCode,
		st.AddedComment, st.DeletedComment,
		st.Whitespace, st.Blank, st.Unknown,
	)
}

// parseLOCSince accepts an RFC3339 timestamp or a bare YYYY-MM-DD date.
func parseLOCSince(s string) (time.Time, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, nil
	}
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC(), nil
		}
	}
	return time.Time{}, fmt.Errorf("backfillLOC: --loc-since %q: want RFC3339 or YYYY-MM-DD", s)
}

// newLOCCmd builds `observer loc`.
func newLOCCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "loc",
		Short: "Lines-of-code authorship counts (AI vs human, code only)",
		Long: `Reports how many lines of CODE — comments, blank lines and
whitespace-only reflows counted separately — an AI agent wrote, and how
many a human did.

Counts come from the before/after text the editing tool already recorded,
never from tokens or chat text, and never from git blame (agents commit as
the developer, so git cannot attribute them).

Populate historical counts with ` + "`observer backfill --loc`" + `.`,
	}
	cmd.AddCommand(newLOCShowCmd(), newLOCReconcileCmd())
	return cmd
}

// newLOCShowCmd builds `observer loc show <session-id>`.
func newLOCShowCmd() *cobra.Command {
	var configPath string
	cmd := &cobra.Command{
		Use:   "show <session-id>",
		Short: "Show one session's line counts",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			database, cleanup, err := openLOCDatabase(cmd.Context(), configPath)
			if err != nil {
				return err
			}
			defer cleanup()

			res, err := store.New(database).LoadSessionLOC(cmd.Context(), args[0])
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			fmt.Fprintf(out, "session %s — %d files, classifier v%d\n",
				res.SessionID, res.Files, res.ClassifierVersion)
			if res.HumanCapture == "none" {
				// The plan forbids rendering an AI SHARE with no human
				// capture: with nothing measuring the developer's own
				// typing, every share would read as 100% AI.
				fmt.Fprintln(out,
					"human capture: none — no editor is reporting saves, so no AI share is shown")
			} else {
				fmt.Fprintf(out, "human capture: %s (editor-reported)\n", res.HumanCapture)
			}
			for _, b := range res.Buckets {
				scope := "main"
				if b.Sidechain {
					scope = "sidechain"
				}
				fmt.Fprintf(out, "  %-7s %-9s %-9s %2d files  %s\n",
					b.Actor, scope, b.Category, b.Files, formatLOCStats(b.Stats))
				if b.Overwrites > 0 {
					fmt.Fprintf(out,
						"           %d counted as added (before-image from the prior read, or none)\n",
						b.Overwrites)
				}
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "Path to config.toml")
	return cmd
}

// newLOCReconcileCmd builds `observer loc reconcile`.
func newLOCReconcileCmd() *cobra.Command {
	var (
		configPath string
		project    string
		rev        string
	)
	cmd := &cobra.Command{
		Use:   "reconcile",
		Short: "Sanity-check counted lines against git diff --numstat (report only)",
		Long: `Compares what Observer counted against what git says changed in the
working tree.

THIS IS A SANITY CHECK, NEVER AN ATTRIBUTION. Agents commit as the
developer, so git can say WHAT changed but never WHO changed it — that is
exactly why the counts are derived from tool inputs instead. A large
divergence means the counter missed a shape or the developer edited
outside any captured tool, and either is worth knowing; it never means
git's number is the true authorship split.

git's numstat is also a NET, surviving-lines measure over a whole range,
while Observer counts GROSS authorship per change, so the two disagree by
construction whenever a line was written and later rewritten. Read the
comparison as an order-of-magnitude check.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			database, cleanup, err := openLOCDatabase(cmd.Context(), configPath)
			if err != nil {
				return err
			}
			defer cleanup()
			if project == "" {
				return fmt.Errorf("observer loc reconcile: --project is required")
			}
			added, deleted, err := gitNumstat(cmd.Context(), project, rev)
			if err != nil {
				return err
			}
			s := store.New(database)
			var pid int64
			if err := database.QueryRowContext(cmd.Context(),
				`SELECT id FROM projects WHERE root_path = ?`, project).Scan(&pid); err != nil {
				return fmt.Errorf("observer loc reconcile: project %q not known to observer: %w", project, err)
			}
			sum, err := s.LoadLOCSummary(cmd.Context(), 3650, pid)
			if err != nil {
				return err
			}
			var counted loc.Stats
			for _, b := range sum.Buckets {
				counted.Add(b.Stats)
			}
			out := cmd.OutOrStdout()
			fmt.Fprintf(out, "project %s (%s)\n", project, rev)
			fmt.Fprintf(out, "  git numstat        : +%d / -%d lines (net, surviving)\n", added, deleted)
			fmt.Fprintf(out, "  observer counted   : %s\n", formatLOCStats(counted))
			fmt.Fprintln(out,
				"  (gross vs net: a line written then rewritten counts twice here and once in git)")
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "Path to config.toml")
	cmd.Flags().StringVar(&project, "project", "", "Project root path (must match a known project)")
	cmd.Flags().StringVar(&rev, "rev", "HEAD", "Git revision range to compare against")
	return cmd
}

// gitNumstat runs `git diff --numstat <rev>` in a repository and sums the
// added/deleted columns. Binary files report "-" and are skipped.
func gitNumstat(ctx context.Context, dir, rev string) (int, int, error) {
	if rev == "" {
		rev = "HEAD"
	}
	out, err := exec.CommandContext(ctx, "git", "-C", dir, "diff", "--numstat", rev).Output()
	if err != nil {
		return 0, 0, fmt.Errorf("gitNumstat: %w", err)
	}
	var added, deleted int
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		a, aerr := strconv.Atoi(fields[0])
		d, derr := strconv.Atoi(fields[1])
		if aerr != nil || derr != nil {
			continue // binary file
		}
		added += a
		deleted += d
	}
	return added, deleted, nil
}

// openLOCDatabase opens the observer database for a read-only LOC
// surface.
func openLOCDatabase(ctx context.Context, configPath string) (*sql.DB, func(), error) {
	cfg, err := config.Load(config.LoadOptions{GlobalPath: configPath})
	if err != nil {
		return nil, nil, fmt.Errorf("openLOCDatabase: config: %w", err)
	}
	database, err := db.Open(ctx, db.Options{Path: cfg.Observer.DBPath})
	if err != nil {
		return nil, nil, fmt.Errorf("openLOCDatabase: %w", err)
	}
	return database, func() { _ = database.Close() }, nil
}
