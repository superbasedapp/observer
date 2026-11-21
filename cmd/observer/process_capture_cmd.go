//go:build !sbo_omit_processobs

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/proccapture"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// `observer process stats` and `observer process compact` (process capture
// budget plan, docs/plans/process-capture-budget-plan-2026-11-04.md §9.4;
// docs/process-observability.md §11.3). Both read the stored rows through
// the store seams; compact is the ONLY path that rewrites stored history, and
// it runs only when the operator invokes it (never from the daemon).

// defaultStatsSessions is how many sessions `process stats` lists (largest
// first) without --session.
const defaultStatsSessions = 20

// captureStatsJSON is proccapture.Stats with wire names.
type captureStatsJSON struct {
	Observed        int64 `json:"observed"`
	Kept            int64 `json:"kept"`
	Folded          int64 `json:"folded"`
	RolledUp        int64 `json:"rolled_up"`
	ServiceKept     int64 `json:"service_kept"`
	ServiceRolledUp int64 `json:"service_rolled_up"`
	Dropped         int64 `json:"dropped"`
	BudgetHits      int64 `json:"budget_hits"`
}

func statsJSON(s proccapture.Stats) captureStatsJSON {
	return captureStatsJSON{
		Observed: s.Observed, Kept: s.Kept, Folded: s.Folded, RolledUp: s.RolledUp,
		ServiceKept: s.ServiceKept, ServiceRolledUp: s.ServiceRolledUp, Dropped: s.Dropped, BudgetHits: s.BudgetHits,
	}
}

// processReplayJSON is what the current capture config would store for a
// session if its rows were captured (or compacted) under it.
type processReplayJSON struct {
	RowsKept      int              `json:"rows_kept"`
	RowsRemoved   int              `json:"rows_removed"`
	RollupGroups  int              `json:"rollup_groups"`
	BytesEstimate int64            `json:"bytes_estimate"`
	Stats         captureStatsJSON `json:"stats"`
}

// processStatsSession is one session row of `process stats`.
type processStatsSession struct {
	SessionID     string               `json:"session_id"`
	Rows          int64                `json:"rows"`
	RollupRows    int64                `json:"rollup_rows"`
	BytesEstimate int64                `json:"bytes_estimate"`
	MetricBytes   int64                `json:"metric_ring_bytes"`
	LastActivity  string               `json:"last_activity,omitempty"`
	Legacy        bool                 `json:"legacy"`
	Stats         captureStatsJSON     `json:"stats"`
	IfReplayed    *processReplayJSON   `json:"if_replayed,omitempty"`
	ReplayError   string               `json:"replay_error,omitempty"`
	BySource      []store.ProcessCount `json:"by_attribution_source,omitempty"`
	ByExe         []store.ProcessCount `json:"top_executables,omitempty"`
	byCounter     map[proccapture.Counter]int64
}

// processStatsReport is `process stats`'s whole output.
type processStatsReport struct {
	CaptureEnabled   bool                  `json:"capture_enabled"`
	Budget           map[string]int        `json:"budget"`
	TotalRows        int64                 `json:"total_rows"`
	UnattributedRows int64                 `json:"unattributed_rows"`
	MachineStats     *captureStatsJSON     `json:"machine_stats,omitempty"`
	Sessions         []processStatsSession `json:"sessions"`
}

func newProcessStatsCmd() *cobra.Command {
	var configPath, sessionID string
	var jsonOut bool
	var limit int
	cmd := &cobra.Command{
		Use:   "stats",
		Short: "Show process capture volume per session and what the capture limits would keep",
		Long: "Per session: the stored process rows, their size, the capture counters\n" +
			"(observed / kept / folded / rolled up / service / dropped) and what the\n" +
			"CURRENT [observer.process.capture] limits would keep if the session's\n" +
			"stored rows were replayed through them (what `process compact` would do).\n" +
			"Read-only.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, database, cleanup, err := loadConfigAndDB(cmd.Context(), configPath)
			if err != nil {
				return err
			}
			defer cleanup()
			rep, err := buildProcessStats(cmd.Context(), store.New(database), cfg.Observer.Process.Capture.CaptureConfig(), sessionID, limit)
			if err != nil {
				return err
			}
			if jsonOut {
				return writeJSON(cmd.OutOrStdout(), rep)
			}
			renderProcessStats(cmd.OutOrStdout(), rep)
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "Path to config.toml")
	cmd.Flags().StringVar(&sessionID, "session", "", "One session id (adds the attribution and executable breakdown)")
	cmd.Flags().IntVar(&limit, "limit", defaultStatsSessions, "Sessions to list, largest first (0 = all)")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "Emit JSON")
	return cmd
}

// buildProcessStats assembles the stats report. The replay is
// proccapture.PlanCompaction over the session's stored rows, the same plan
// `process compact` applies, so the two commands always agree.
func buildProcessStats(ctx context.Context, st *store.Store, cfg proccapture.Config, sessionID string, limit int) (processStatsReport, error) {
	rep := processStatsReport{
		CaptureEnabled: cfg.Enabled,
		Budget:         map[string]int{"per_tool_call": cfg.PerToolCall, "per_session": cfg.PerSession, "per_minute": cfg.PerMinute},
		Sessions:       []processStatsSession{},
	}
	totals, err := st.ProcessStats(ctx)
	if err != nil {
		return rep, err
	}
	rep.TotalRows, rep.UnattributedRows = totals.Total, totals.Unattributed
	if ms, ok, err := st.ProcessCaptureStatsForSession(ctx, ""); err != nil {
		return rep, err
	} else if ok {
		j := statsJSON(ms)
		rep.MachineStats = &j
	}
	if sessionID != "" {
		limit = 0
	}
	acts, err := st.ProcessSessionActivities(ctx, sessionID, limit)
	if err != nil {
		return rep, err
	}
	for _, a := range acts {
		row := processStatsSession{
			SessionID:     a.SessionID,
			Rows:          a.Rows,
			BytesEstimate: a.Rows*proccapture.RowOverheadBytes + a.StoredBytes,
			MetricBytes:   a.MetricBytes,
			LastActivity:  startedISO(a.LastActivity()),
		}
		if row.RollupRows, err = st.ProcessRollupRowCount(ctx, a.SessionID); err != nil {
			return rep, err
		}
		stats, ok, err := st.ProcessCaptureStatsForSession(ctx, a.SessionID)
		if err != nil {
			return rep, err
		}
		row.Legacy = !ok
		row.Stats = statsJSON(stats)
		if !ok {
			// A legacy session has no counters: every stored row was kept.
			row.Stats = statsJSON(proccapture.Stats{Observed: a.Rows, Kept: a.Rows})
		}
		rows, err := st.LoadSessionCaptureRows(ctx, a.SessionID)
		if err != nil {
			return rep, err
		}
		plan, err := proccapture.PlanCompaction(a.SessionID, rows, stats, ok, cfg)
		if err != nil {
			row.ReplayError = err.Error()
		} else {
			row.IfReplayed = replayJSON(plan, rows, cfg)
			row.byCounter = plan.Removed
		}
		if sessionID != "" {
			if row.BySource, row.ByExe, err = st.ProcessSessionBreakdown(ctx, a.SessionID, 10); err != nil {
				return rep, err
			}
		}
		rep.Sessions = append(rep.Sessions, row)
	}
	return rep, nil
}

// replayJSON summarises a compaction plan as "what the config would keep".
func replayJSON(plan proccapture.CompactionPlan, rows []proccapture.StoredRun, cfg proccapture.Config) *processReplayJSON {
	deleted := make(map[int64]bool, len(plan.Delete))
	for _, id := range plan.Delete {
		deleted[id] = true
	}
	var bytes int64
	for _, r := range rows {
		if !deleted[r.ID] {
			bytes += int64(proccapture.RowBytes(r.Facts, cfg))
		}
	}
	for _, ru := range plan.Rollups {
		bytes += int64(proccapture.RollupRowOverheadBytes + len(ru.ExampleArgvPreview) + len(ru.ExampleProcessKey) +
			len(ru.Key.SessionID) + len(ru.Key.ParentProcessKey) + len(ru.Key.ServiceRootKey) +
			len(ru.Key.ExeBasename) + len(ru.Key.ArgvTemplateHash))
	}
	return &processReplayJSON{
		RowsKept:      plan.Kept(),
		RowsRemoved:   len(plan.Delete),
		RollupGroups:  len(plan.Rollups),
		BytesEstimate: bytes,
		Stats:         statsJSON(plan.After),
	}
}

func startedISO(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

func statsLine(s captureStatsJSON) string {
	return fmt.Sprintf("observed %d · kept %d · folded %d · rolled up %d · service kept %d · service rolled up %d · dropped %d",
		s.Observed, s.Kept, s.Folded, s.RolledUp, s.ServiceKept, s.ServiceRolledUp, s.Dropped)
}

func renderProcessStats(w io.Writer, rep processStatsReport) {
	state := "on"
	if !rep.CaptureEnabled {
		state = "OFF (every captured run is stored)"
	}
	fmt.Fprintf(w, "process capture limits: %s · per tool call %d · per session %d · per minute %d\n",
		state, rep.Budget["per_tool_call"], rep.Budget["per_session"], rep.Budget["per_minute"])
	fmt.Fprintf(w, "process_runs: %d rows · %d without a session\n", rep.TotalRows, rep.UnattributedRows)
	if rep.MachineStats != nil {
		fmt.Fprintf(w, "  machine (unattributed policy): %s\n", statsLine(*rep.MachineStats))
	}
	if len(rep.Sessions) == 0 {
		fmt.Fprintln(w, "no session has process rows")
		return
	}
	for _, s := range rep.Sessions {
		legacy := ""
		if s.Legacy {
			legacy = " · legacy (stored before the capture budget; no capture stats)"
		}
		fmt.Fprintf(w, "\nsession %s · %d rows (~%s, metric rings %s) · %d rollup rows · last active %s%s\n",
			s.SessionID, s.Rows, fmtBytesIEC(s.BytesEstimate), fmtBytesIEC(s.MetricBytes), s.RollupRows, orDash(s.LastActivity), legacy)
		fmt.Fprintf(w, "  stats: %s\n", statsLine(s.Stats))
		switch {
		case s.ReplayError != "":
			fmt.Fprintf(w, "  replay: %s\n", s.ReplayError)
		case s.IfReplayed != nil:
			r := s.IfReplayed
			fmt.Fprintf(w, "  under the current limits: keeps %d rows (~%s); %d rows would become %d rollup groups%s\n",
				r.RowsKept, fmtBytesIEC(r.BytesEstimate), r.RowsRemoved, r.RollupGroups, removedBreakdown(s.byCounter))
		}
		if len(s.BySource) > 0 {
			fmt.Fprintf(w, "  by attribution: %s\n", countsLine(s.BySource))
		}
		if len(s.ByExe) > 0 {
			fmt.Fprintf(w, "  top executables: %s\n", countsLine(s.ByExe))
		}
	}
}

func removedBreakdown(m map[proccapture.Counter]int64) string {
	if len(m) == 0 {
		return ""
	}
	var parts []string
	for _, c := range []proccapture.Counter{
		proccapture.CounterFolded, proccapture.CounterRolledUp,
		proccapture.CounterServiceRolledUp, proccapture.CounterDropped,
	} {
		if n := m[c]; n > 0 {
			parts = append(parts, fmt.Sprintf("%s %d", strings.ReplaceAll(string(c), "_", " "), n))
		}
	}
	return " (" + strings.Join(parts, " · ") + ")"
}

func countsLine(cs []store.ProcessCount) string {
	parts := make([]string, 0, len(cs))
	for _, c := range cs {
		parts = append(parts, fmt.Sprintf("%s %d", orDash(c.Key), c.Count))
	}
	return strings.Join(parts, " · ")
}

// processCompactOptions are `process compact`'s flags.
type processCompactOptions struct {
	SessionID string
	Before    time.Time
	DryRun    bool
	Now       time.Time
}

// processCompactSummary totals one compaction run.
type processCompactSummary struct {
	Considered    int
	Compacted     int
	Unchanged     int
	SkippedActive int
	SkippedBefore int
	Failed        int
	RowsBefore    int64
	RowsAfter     int64
	RollupGroups  int
}

func newProcessCompactCmd() *cobra.Command {
	var configPath, sessionID, before string
	var dryRun bool
	cmd := &cobra.Command{
		Use:   "compact",
		Short: "Apply the capture limits to stored process rows (rollups, then delete), per idle session",
		Long: "Replays each idle session's STORED process rows through the current\n" +
			"[observer.process.capture] decision table and, for the rows it would\n" +
			"not keep, writes their rollups and capture stats and deletes them:\n" +
			"copy-then-delete in one transaction per session. Findings, failures,\n" +
			"side effects and tool-linked runs are never deleted, and a row that\n" +
			"already carries a capture class is left as it is. Only sessions idle\n" +
			"for services.tail_minutes are touched, and a service the session\n" +
			"started does not count as activity; --dry-run writes nothing.\n" +
			"Never automatic. Reclaiming the file space is `observer archive reclaim`.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			opts := processCompactOptions{SessionID: sessionID, DryRun: dryRun, Now: time.Now()}
			if before != "" {
				t, err := parseCompactBefore(before)
				if err != nil {
					return err
				}
				opts.Before = t
			}
			cfg, database, cleanup, err := loadConfigAndDB(cmd.Context(), configPath)
			if err != nil {
				return err
			}
			defer cleanup()
			_, err = runProcessCompact(cmd.Context(), store.New(database), cfg.Observer.Process.Capture.CaptureConfig(), opts, cmd.OutOrStdout())
			return err
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "Path to config.toml")
	cmd.Flags().StringVar(&sessionID, "session", "", "Compact one session only")
	cmd.Flags().StringVar(&before, "before", "", "Only sessions whose last activity is before this date (YYYY-MM-DD or RFC3339)")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "Print what would be compacted and write nothing")
	return cmd
}

// parseCompactBefore accepts a date (UTC midnight) or an RFC3339 instant.
func parseCompactBefore(v string) (time.Time, error) {
	if t, err := time.Parse(time.RFC3339, v); err == nil {
		return t.UTC(), nil
	}
	if t, err := time.Parse("2006-01-02", v); err == nil {
		return t.UTC(), nil
	}
	return time.Time{}, fmt.Errorf("--before %q: want YYYY-MM-DD or RFC3339", v)
}

// compactIdle is how long a session must be idle before compact touches it:
// services.tail_minutes, or the default 30 minutes when that is 0 (unbounded
// tracking), so a session the live capture may still be writing is never
// compacted under it.
func compactIdle(cfg proccapture.Config) time.Duration {
	if cfg.ServiceTail > 0 {
		return cfg.ServiceTail
	}
	return proccapture.DefaultConfig().ServiceTail
}

// runProcessCompact plans (and unless DryRun applies) the compaction of every
// matching idle session, printing one line per session and a summary. A
// session whose plan fails the protected-run guard is reported and skipped;
// the run then returns an error after finishing the others.
func runProcessCompact(ctx context.Context, st *store.Store, cfg proccapture.Config, opts processCompactOptions, w io.Writer) (processCompactSummary, error) {
	var sum processCompactSummary
	if !cfg.Enabled {
		return sum, errors.New("process compact: the capture limits are off ([observer.process.capture] enabled = false), so there is nothing to compact against")
	}
	now := opts.Now
	if now.IsZero() {
		now = time.Now()
	}
	idle := compactIdle(cfg)
	acts, err := st.ProcessSessionActivities(ctx, opts.SessionID, 0)
	if err != nil {
		return sum, err
	}
	if opts.SessionID != "" && len(acts) == 0 {
		fmt.Fprintf(w, "session %s has no process rows\n", opts.SessionID)
		return sum, nil
	}
	mode := "compact"
	if opts.DryRun {
		mode = "dry run"
	}
	fmt.Fprintf(w, "process compact (%s): sessions idle %s or more", mode, idle)
	if !opts.Before.IsZero() {
		fmt.Fprintf(w, ", last active before %s", opts.Before.Format(time.RFC3339))
	}
	fmt.Fprintln(w)

	var failures []string
	for _, a := range acts {
		sum.Considered++
		last := a.LastActivity()
		if now.Sub(last) < idle {
			sum.SkippedActive++
			fmt.Fprintf(w, "  %s: skipped, active %s ago\n", a.SessionID, now.Sub(last).Truncate(time.Second))
			continue
		}
		if !opts.Before.IsZero() && !last.Before(opts.Before) {
			sum.SkippedBefore++
			continue
		}
		rows, err := st.LoadSessionCaptureRows(ctx, a.SessionID)
		if err != nil {
			return sum, err
		}
		stats, ok, err := st.ProcessCaptureStatsForSession(ctx, a.SessionID)
		if err != nil {
			return sum, err
		}
		plan, err := proccapture.PlanCompaction(a.SessionID, rows, stats, ok, cfg)
		if err != nil {
			sum.Failed++
			failures = append(failures, a.SessionID)
			fmt.Fprintf(w, "  %s: NOT compacted: %v\n", a.SessionID, err)
			continue
		}
		sum.RowsBefore += int64(plan.Rows)
		if plan.Empty() {
			sum.Unchanged++
			sum.RowsAfter += int64(plan.Rows)
			fmt.Fprintf(w, "  %s: %d rows, nothing to compact\n", a.SessionID, plan.Rows)
			continue
		}
		verb := "would keep"
		if !opts.DryRun {
			if _, err := st.CompactProcessSession(ctx, plan, a.CompactionMark()); err != nil {
				if errors.Is(err, store.ErrProcessCompactionStale) {
					sum.SkippedActive++
					sum.RowsAfter += int64(plan.Rows)
					fmt.Fprintf(w, "  %s: skipped, its rows changed while planning (active)\n", a.SessionID)
					continue
				}
				return sum, err
			}
			verb = "kept"
		}
		sum.Compacted++
		sum.RowsAfter += int64(plan.Kept())
		sum.RollupGroups += len(plan.Rollups)
		fmt.Fprintf(w, "  %s: %d rows, %s %d; %d rows into %d rollup groups%s; stats %s\n",
			a.SessionID, plan.Rows, verb, plan.Kept(), len(plan.Delete), len(plan.Rollups),
			removedBreakdown(plan.Removed), statsLine(statsJSON(plan.After)))
	}
	label := "compacted"
	if opts.DryRun {
		label = "would compact"
	}
	fmt.Fprintf(w, "sessions: %d considered · %s %d · unchanged %d · skipped as active %d", sum.Considered, label, sum.Compacted, sum.Unchanged, sum.SkippedActive)
	if !opts.Before.IsZero() {
		fmt.Fprintf(w, " · skipped by --before %d", sum.SkippedBefore)
	}
	if sum.Failed > 0 {
		fmt.Fprintf(w, " · failed %d", sum.Failed)
	}
	written := "written"
	if opts.DryRun {
		written = "to write"
	}
	fmt.Fprintf(w, "\nrows: %d before -> %d after · %d rollup groups %s\n", sum.RowsBefore, sum.RowsAfter, sum.RollupGroups, written)
	if opts.DryRun {
		fmt.Fprintln(w, "dry run: nothing was written")
	} else if sum.Compacted > 0 {
		fmt.Fprintln(w, "the freed pages stay in the database file; `observer archive reclaim` returns them to the disk")
	}
	if len(failures) > 0 {
		return sum, fmt.Errorf("process compact: %d session(s) not compacted: %s", len(failures), strings.Join(failures, ", "))
	}
	return sum, nil
}
