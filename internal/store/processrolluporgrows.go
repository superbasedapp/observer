package store

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/marmutapp/superbased-observer/internal/orgcontract"
)

// The process capture budget's org wire (docs/plans/
// process-capture-budget-plan-2026-11-04.md §4.8, layer O1). This file — NOT
// orgpush.go — owns the read of the two node-local capture tables
// process_rollups and process_capture_stats (agent migration 212): the
// privacy sentinel forbids those names in orgpush.go, which composes these
// rows by function call exactly like SelectSessionProcessRows
// (processorgrows.go).
//
// Both wires ship under the same tier as SessionProcesses: orgpush.go calls
// them only inside its shipsRawContent() block. SelectSessionProcessRollupRows
// additionally re-applies the gate itself (the SelectSessionCacheEvents
// pattern) and empties the one content-bearing column, example_argv_preview,
// when the options do not ship raw content, so a future caller outside that
// block cannot leak it. Counts are content-free and always ship with the row.
//
// The machine-level rollup (process_rollups.session_id NULL) and the machine
// stats row (process_capture_stats.session_id '') never ship: this is a
// session-scoped wire, and the machine rows carry the unattributed runs of
// every session-less process on the box.

// sessionProcessRollupCap is the per-session cap on rollup rows (one per
// bucket and group) a push recomputes, the most recent buckets first,
// enforced in SQL like sessionProcessRunCap. The capture budget bounds how
// many runs a session KEEPS, not how many buckets its rollups span, so a
// long noisy session (a service subtree over hours) can hold thousands of
// buckets; 2,000 keeps a day of one-minute buckets for one busy group while
// bounding the push. The per-session totals are exact regardless: they ride
// the stats row, which is never capped.
const sessionProcessRollupCap = 2000

// sessionProcessRollupRowsQuery is the SelectSessionProcessRollupRows read.
// Placeholders are (since, cap). The window is on bucket_start (served by
// idx_process_rollups_bucket); the cap is ROW_NUMBER() per session, newest
// bucket first, then the biggest group.
const sessionProcessRollupRowsQuery = `
		WITH ranked AS (
			SELECT session_id, bucket_start, group_kind, parent_process_key, action_id,
			       service_root_key, exe_basename, argv_template_hash,
			       example_argv_preview, example_process_key,
			       count, failed_count, duration_sum_ms, duration_max_ms, cpu_sum_ms, peak_rss_bytes,
			       first_seen, last_seen, id,
			       ROW_NUMBER() OVER (PARTITION BY session_id ORDER BY bucket_start DESC, count DESC, id DESC) AS rn
			  FROM process_rollups
			 WHERE session_id IS NOT NULL AND session_id != '' AND bucket_start >= ?
		)
		SELECT session_id, bucket_start, group_kind, parent_process_key, action_id,
		       service_root_key, exe_basename, argv_template_hash,
		       example_argv_preview, example_process_key,
		       count, failed_count, duration_sum_ms, duration_max_ms, cpu_sum_ms, peak_rss_bytes,
		       first_seen, last_seen
		  FROM ranked
		 WHERE rn <= ?
		 ORDER BY session_id, bucket_start DESC, count DESC, id DESC`

// SelectSessionProcessRollupRows reads the process capture rollups of every
// session with a bucket in the trailing sessionProcessWindowDays window,
// capped to sessionProcessRollupCap rows per session. example_argv_preview
// ships only when share.shipsRawContent().
func (s *Store) SelectSessionProcessRollupRows(ctx context.Context, share ShareOptions) ([]orgcontract.SessionProcessRollupRow, error) {
	since := time.Now().UTC().AddDate(0, 0, -sessionProcessWindowDays)
	rows, err := s.db.QueryContext(ctx, sessionProcessRollupRowsQuery, bucketStamp(since), sessionProcessRollupCap)
	if err != nil {
		return nil, fmt.Errorf("store.SelectSessionProcessRollupRows: %w", err)
	}
	defer func() { _ = rows.Close() }()

	raw := share.shipsRawContent()
	out := []orgcontract.SessionProcessRollupRow{}
	for rows.Next() {
		var (
			r                    orgcontract.SessionProcessRollupRow
			actionID             sql.NullInt64
			argv, exampleKey     sql.NullString
			firstSeen, lastSeen  sql.NullString
			parentKey, rootKey   sql.NullString
			exeBasename, argvTpl sql.NullString
		)
		if err := rows.Scan(&r.SessionID, &r.BucketStart, &r.GroupKind, &parentKey, &actionID,
			&rootKey, &exeBasename, &argvTpl,
			&argv, &exampleKey,
			&r.Count, &r.FailedCount, &r.DurationSumMs, &r.DurationMaxMs, &r.CPUSumMs, &r.PeakRSSBytes,
			&firstSeen, &lastSeen); err != nil {
			return nil, fmt.Errorf("store.SelectSessionProcessRollupRows: scan: %w", err)
		}
		r.ParentProcessKey = parentKey.String
		r.ServiceRootKey = rootKey.String
		r.ExeBasename = exeBasename.String
		r.ArgvTemplateHash = argvTpl.String
		r.ActionID = actionID.Int64
		r.ExampleProcessKey = exampleKey.String
		if raw {
			r.ExampleArgvPreview = argv.String
		}
		r.FirstSeen = firstSeen.String
		r.LastSeen = lastSeen.String
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store.SelectSessionProcessRollupRows: %w", err)
	}
	return out, nil
}

// SelectSessionProcessCaptureStatsRows reads the capture counters of every
// session whose stats row changed in the trailing sessionProcessWindowDays
// window (served by idx_process_capture_stats_updated), oldest change first.
// The machine row (session_id ”) is excluded. Never capped: one row per
// session, and the counters are what keeps the org's totals exact when the
// rollup rows are.
func (s *Store) SelectSessionProcessCaptureStatsRows(ctx context.Context) ([]orgcontract.SessionProcessCaptureStatsRow, error) {
	since := time.Now().UTC().AddDate(0, 0, -sessionProcessWindowDays)
	rows, err := s.db.QueryContext(ctx, `
		SELECT session_id, observed, kept, folded, rolled_up, service_kept, service_rolled_up,
		       dropped, budget_hits, updated_at
		  FROM process_capture_stats
		 WHERE session_id != '' AND updated_at >= ?
		 ORDER BY updated_at ASC, session_id ASC`, timestamp(since))
	if err != nil {
		return nil, fmt.Errorf("store.SelectSessionProcessCaptureStatsRows: %w", err)
	}
	defer func() { _ = rows.Close() }()

	out := []orgcontract.SessionProcessCaptureStatsRow{}
	for rows.Next() {
		var r orgcontract.SessionProcessCaptureStatsRow
		if err := rows.Scan(&r.SessionID, &r.Observed, &r.Kept, &r.Folded, &r.RolledUp,
			&r.ServiceKept, &r.ServiceRolledUp, &r.Dropped, &r.BudgetHits, &r.UpdatedAt); err != nil {
			return nil, fmt.Errorf("store.SelectSessionProcessCaptureStatsRows: scan: %w", err)
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store.SelectSessionProcessCaptureStatsRows: %w", err)
	}
	return out, nil
}

// probeProcessCapture is the Track R2 change-detection probe of the capture
// wire (snapFamSessionProcessCapture): MAX(process_rollups.id) and
// MAX(process_capture_stats.updated_at), an index-endpoint seek each. Every
// capture flush that adds to an existing rollup group (an UPDATE, which moves
// no id) also upserts the same session's stats row in the same transaction
// (processrollups.go PersistCapture), so updated_at moves whenever any
// counter does. A retention prune that deletes old rows can leave both maxima
// unchanged; those rows are outside the window and the server keeps its copy
// until its own retention, so nothing owed is missed.
func (s *Store) probeProcessCapture(ctx context.Context) (string, error) {
	return s.snapProbeScalar(ctx, `
		SELECT 'ro' || (SELECT COALESCE(MAX(id), 0) FROM process_rollups) ||
		       ':cs' || (SELECT COALESCE(MAX(updated_at), '') FROM process_capture_stats)`)
}
