// org_pushstatus.go — `observer org push-status` + the shared
// eligible=0 diagnosis (Phase C of the teams one-command UX plan).

package main

import (
	"fmt"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/diag"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// eligibleTotal sums the post-cursor (push-eligible) row counts across
// the five pushable tables.
func eligibleTotal(cur, maxIDs store.PushCursor) int64 {
	return (maxIDs.Sessions - cur.Sessions) +
		(maxIDs.Actions - cur.Actions) +
		(maxIDs.APITurns - cur.APITurns) +
		(maxIDs.TokenUsage - cur.TokenUsage) +
		(maxIDs.GuardEvents - cur.GuardEvents)
}

// historicalTotal sums all captured rows across the pushable tables.
func historicalTotal(maxIDs store.PushCursor) int64 {
	return maxIDs.Sessions + maxIDs.Actions + maxIDs.APITurns +
		maxIDs.TokenUsage + maxIDs.GuardEvents
}

// pushEligibilityReason explains an eligible==0 state in plain language.
// It needs no timestamp query: the cursor + last-push state already
// encode WHY nothing is eligible (enrol seeds the cursor at the
// high-water mark, so pre-enrolment rows never become eligible; a prior
// push advances it past shipped rows). Returns "" when eligible>0.
func pushEligibilityReason(eligible, historical int64, lastPush *store.PushLogEntry) string {
	if eligible > 0 {
		return ""
	}
	switch {
	case historical == 0:
		return "no captured activity yet — run an agent session (through the proxy or any watched tool) to create rows."
	case lastPush != nil:
		return fmt.Sprintf("cursor is up to date — nothing new since the last push (%s). New activity ships on the next loop.", lastPush.PushedAt)
	default:
		return fmt.Sprintf("all %d historical row(s) predate enrolment — the cursor is seeded at the high-water mark at enrol time so only POST-enrolment activity ships. Start a fresh agent session, or run `observer org backfill --all --confirm` to share the history.", historical)
	}
}

// newOrgPushStatusCmd implements `observer org push-status` — a single
// view of whether the auto-push loop is running, its cadence, the next
// attempt, and how many rows are eligible (with the eligible=0 reason).
func newOrgPushStatusCmd() *cobra.Command {
	var configPath string
	cmd := &cobra.Command{
		Use:   "push-status",
		Short: "Show auto-push loop state, cadence, next attempt, and eligible rows",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			b, err := buildOrgBundle(cmd.Context(), configPath)
			if err != nil {
				return err
			}
			defer b.cleanup()

			st, err := b.client.Status(cmd.Context())
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			if !st.Enrolled {
				fmt.Fprintln(out, "Not enrolled — push is inactive. Run `observer enroll <url> <token>`.")
				return nil
			}

			fmt.Fprintf(out, "Pushing enabled:   %t\n", b.cfg.OrgClient.Enabled)

			// The auto-push loop runs INSIDE `observer start`; detect a
			// live daemon via its lockfile in the DB dir (LiveLocks drops
			// dead pids).
			dbDir := filepath.Dir(b.cfg.Observer.DBPath)
			locks, _ := diag.LiveLocks(dbDir)
			running := b.cfg.OrgClient.Enabled && len(locks) > 0
			switch {
			case !b.cfg.OrgClient.Enabled:
				fmt.Fprintln(out, "Auto-push loop:    not running ([org_client].enabled = false)")
			case len(locks) == 0:
				fmt.Fprintln(out, "Auto-push loop:    not running (no `observer start` daemon detected)")
			default:
				fmt.Fprintf(out, "Auto-push loop:    running (%d daemon(s))\n", len(locks))
			}

			interval := b.cfg.OrgClient.PushIntervalSeconds
			if interval <= 0 {
				interval = 900
			}
			fmt.Fprintf(out, "Push interval:     %ds\n", interval)

			cur, err := b.store.LoadPushCursor(cmd.Context())
			if err != nil {
				return fmt.Errorf("load cursor: %w", err)
			}
			maxIDs, err := b.store.CurrentMaxIDs(cmd.Context())
			if err != nil {
				return fmt.Errorf("current max ids: %w", err)
			}
			eligible := eligibleTotal(cur, maxIDs)
			fmt.Fprintf(out, "Eligible rows:     %d\n", eligible)

			if st.LastPush == nil {
				fmt.Fprintln(out, "Last attempt:      (none yet)")
			} else {
				lp := st.LastPush
				fmt.Fprintf(out, "Last attempt:      %s — %s, %d rows%s\n",
					lp.PushedAt, lp.Status, lp.RowCount, errSuffix(lp.Error))
			}
			fmt.Fprintf(out, "Next attempt:      %s\n", nextAttempt(running, st.LastPush, interval))

			// An open oversized-batch circuit overrides the cadence above:
			// nothing is shipping, and the reason is a local payload problem the
			// operator can actually fix. Say so instead of leaving them to infer
			// it from a 'failed' row in the history.
			if p := st.PushPaused; p != nil {
				fmt.Fprintln(out)
				fmt.Fprintln(out, "PUSHES PAUSED — the composed rollup is larger than the accepted push limit,")
				fmt.Fprintln(out, "so no telemetry is reaching the org server right now.")
				fmt.Fprintf(out, "  Resumes:  %s\n", p.Until.Local().Format(time.RFC3339))
				if p.Reason != "" {
					fmt.Fprintf(out, "  Detail:   %s\n", p.Reason)
				}
				fmt.Fprintln(out, "  Fix:      raise [org_client].max_push_bytes, narrow [org_client.scope],")
				fmt.Fprintln(out, "            or turn off a large [org_client.share] tier. The org server")
				fmt.Fprintln(out, "            enforces its own body limit too, so a node-side raise alone")
				fmt.Fprintln(out, "            may not be enough.")
			}

			if reason := pushEligibilityReason(eligible, historicalTotal(maxIDs), st.LastPush); reason != "" {
				fmt.Fprintln(out)
				fmt.Fprintln(out, "Why eligible = 0:")
				fmt.Fprintf(out, "  %s\n", reason)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "Path to config.toml (defaults to ~/.observer/config.toml)")
	return cmd
}

// nextAttempt estimates the next push time from the last push + interval.
// Honest about the unknowns: "n/a" when the loop isn't running, and a
// "within Ns of daemon start" hint when no push has happened yet.
func nextAttempt(running bool, lastPush *store.PushLogEntry, intervalSec int) string {
	if !running {
		return "n/a — auto-push loop not running"
	}
	if lastPush == nil {
		return fmt.Sprintf("within %ds of daemon start (no push yet)", intervalSec)
	}
	t, err := time.Parse(time.RFC3339, lastPush.PushedAt)
	if err != nil {
		return fmt.Sprintf("~%ds after the last attempt", intervalSec)
	}
	return t.Add(time.Duration(intervalSec) * time.Second).UTC().Format(time.RFC3339)
}
