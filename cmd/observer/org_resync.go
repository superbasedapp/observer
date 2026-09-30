package main

import (
	"errors"
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/retention"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// resyncMaxLimit bounds one `observer org resync` invocation. The push loop
// drains the queue at a capped rate either way; this keeps a single command
// from queueing an unbounded corpus.
const resyncMaxLimit = 200000

// retentionOptions is the retention configuration the ageing horizon is read
// from - the same fields runRetention passes to the pruner.
func retentionOptions(cfg config.Config) retention.Options {
	return retention.Options{
		MaxAgeDays:  cfg.Observer.Retention.MaxAgeDays,
		MaxDBSizeMB: cfg.Observer.Retention.MaxDBSizeMB,
	}
}

// newOrgResyncCmd is the one-shot HEAL for rows that changed on the node after
// they were pushed, before re-send tracking existed (agent migration 140) -
// e.g. the org showing a session with fewer tokens than the node, or without
// the ended_at the node has. It queues a bounded, recent window of already-
// pushed rows; the normal push loop re-sends them in capped batches and the
// org keeps the newest version of each (newer-wins by node version). Nothing
// is sent by this command itself, and nothing from before enrolment is ever
// queued.
func newOrgResyncCmd() *cobra.Command {
	var (
		configPath string
		since      time.Duration
		limit      int
		confirm    bool
		deletions  bool
	)
	cmd := &cobra.Command{
		Use:   "resync",
		Short: "Re-send recently pushed rows that changed on this node, so the org converges (bounded)",
		Long: `Queues already-pushed rows from a recent window for a re-send, so the org
converges on this node's current values for rows that changed after they were
pushed (token totals upgraded by a later parse, action outcomes, subagent
turns moved to their own session, a session's end time, a project's git
identity).

Since agent migration 140 such changes re-send automatically; this command
heals rows that diverged before that. It also recomputes each window
session's end time from its stored session_end / session_start / user_prompt
actions.

It also reconciles DELETIONS (--deletions, on by default): rows this node
removed as corrections after pushing them - a duplicate token row a dedup
repair dropped, a row a backfill replaced - before agent migration 141 made
such deletes propagate. For each session in the window it queues a manifest of
every row the node still holds there; the org removes the rows it holds for
that session that the node no longer has. Rows older than this node's
retention horizon are never touched (a row the node aged out is not a
correction), and neither is a row the org received in a newer version than
the manifest. Caveat: if two machines push the SAME session under the same
member (a shared home directory), one machine's manifest can remove the
other's extra rows; pass --deletions=false on such nodes.

Bounded and safe to repeat: --since limits the window (default 30 days),
--limit caps the rows queued (default 20000, most recent first) and the
sessions reconciled, rows from before this node enrolled are never queued,
and the push loop drains the queues at a capped rate per push. Dry-run is the
default; --confirm queues.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if limit <= 0 || limit > resyncMaxLimit {
				return fmt.Errorf("observer org resync: --limit must be between 1 and %d", resyncMaxLimit)
			}
			if since <= 0 {
				return errors.New("observer org resync: --since must be positive")
			}
			b, err := buildOrgBundle(cmd.Context(), configPath)
			if err != nil {
				return err
			}
			defer b.cleanup()
			rep, err := b.store.EnqueuePushResync(cmd.Context(), store.PushResyncOptions{
				Since: time.Now().Add(-since), Limit: limit, DryRun: !confirm,
			})
			if errors.Is(err, store.ErrPushNotTracked) {
				return errors.New("not enrolled; run `observer enroll <org-url> <token>` first")
			}
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			fmt.Fprintf(out, "%-12s  %12s  %12s  %10s\n", "Table", "floor", "cursor", "queued")
			var total int64
			for _, l := range rep.Tables {
				floor := fmt.Sprintf("%d", l.FloorAfter)
				if l.FloorAfter != l.FloorBefore {
					floor = fmt.Sprintf("%d->%d", l.FloorBefore, l.FloorAfter)
				}
				fmt.Fprintf(out, "%-12s  %12s  %12d  %10d\n", l.Table, floor, l.Cursor, l.Queued)
				total += l.Queued
			}
			fmt.Fprintf(out, "sessions checked for end time: %d\n", rep.EndedAtChecked)
			var man store.PushManifestReport
			if deletions {
				man, err = b.store.EnqueuePushManifests(cmd.Context(), store.PushManifestOptions{
					Since:     time.Now().Add(-since),
					NotBefore: retention.AgeingHorizon(retentionOptions(b.cfg), time.Now()),
					Limit:     limit,
					DryRun:    !confirm,
				})
				if err != nil {
					return err
				}
				fmt.Fprintf(out, "sessions to reconcile deletions: %d (of %d; %d too large to reconcile)\n",
					man.Queued, man.Checked, man.TooBig)
				fmt.Fprintf(out, "  the org removes only rows it holds for those sessions that this node no longer has,\n"+
					"  timestamped at or after %s (inside this node's retention horizon)\n", man.NotBefore.Format(time.RFC3339))
			}
			if !confirm {
				fmt.Fprintf(out, "\nDRY RUN - pass --confirm to queue %d rows for a re-send and %d session manifests.\n", total, man.Queued)
				return nil
			}
			fmt.Fprintf(out, "\nqueued %d rows and %d session manifests; the push loop ships them over the next pushes (`observer org status` shows what is pending).\n", total, man.Queued)
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "Path to config.toml (defaults to ~/.observer/config.toml)")
	cmd.Flags().DurationVar(&since, "since", 30*24*time.Hour, "only rows whose own time is within this window")
	cmd.Flags().IntVar(&limit, "limit", 20000, "maximum rows to queue across all tables (most recent first)")
	cmd.Flags().BoolVar(&confirm, "confirm", false, "actually queue (omit for dry-run)")
	cmd.Flags().BoolVar(&deletions, "deletions", true, "also reconcile rows this node deleted before agent migration 141 (per-session manifests)")
	return cmd
}
